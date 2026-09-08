/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! accept 循环与 hyper 服务模型（完整流程闭环核心，说明书 4.1-4.3）。
//!
//! 双协议首字节嗅探（2026-09-01 用户决策，方案 B）：每连接 peek 1 字节
//! 分流——`0x16`（TLS ClientHello record type）→ MITM TLS 路径；
//! ASCII 大写字母（HTTP 方法名首字符）→ 明文 HTTP 路径（TCP 流直接交
//! hyper，domain 取请求级 Host 头，目标同协议透传 :80）；其余关闭
//! （fail-closed）。peek 不消费缓冲——嗅探后字节流完整交给对应协议层。
//!
//! 统一服务路径（双场景合并：端口监听 + 当前全局配置）：
//!
//! ```text
//! accept（Semaphore(16) 并发上限）→ 连接身份解析（resolver 回调：
//!   source/target/protocol → container_id + binary_path，连接级缓存）
//!   → 首字节嗅探 → MITM TLS 终止（SNI 捕获/动态证书/ALPN[h2,http/1.1]）
//!   → hyper auto server → 每请求/每流：
//!   域名解析（TLS=SNI / 明文=Host 头）
//!     ├─ 命中推理路由列表（host+url 精确匹配，AR-005）→ 旁通过滤引擎：
//!     │    body 全量缓冲 → 外部库裁决 → Block:403 / Forward(Modified):
//!     │    重建缓冲请求 → 转发 + 审计（reason=inference_route）
//!     │    （Upgrade 请求不参与——修改语义与隧道不兼容，走原管道）
//!     ├─ 未命中 → current_global() 配置快照（热更新天然生效）
//!     │    ├─ 配置缺失 → 503 + 审计 config_not_found
//!     │    ├─ [规则含 binary 条件] binary_path 未解析 → 403 binary_not_found
//!     │    ├─ evaluate()（黑>白>默认，四维 AND 短路）
//!     │    │    └─ deny → 403/503 阻断响应 + 审计
//!     │    ├─ allow → 懒建目标连接（按协商 ALPN，D5）→ hyper client 转发
//!     │    │    → 流式回传响应 → 审计（真实 status_code——Q6 修复）
//!     │    └─ Upgrade(h1) → on_upgrade 双向流 → relay_with_idle_timeout 隧道
//! ```
//!
//! 身份解析失败（未注册回调/None/container_id 空）：container_id 占位
//! "-"——下游查表 miss fail-closed（配置 503 / TLS CA 拒握手）；规则含
//! binary 条件且 binary_path 未解析 → binary_not_found。
//!
//! 关键语义：
//! - **逐请求/逐流求值**（Q3 闭环）：hyper service 每请求/每流回调一次；
//! - **真实 status_code**（Q6 修复）：目标响应状态码可观测；审计先于响应
//!   回传发起方（fail-closed 排序保留：审计 Err 时无流量通过）；
//! - **阻断响应**：403（策略）/502（目标失败）/503（配置缺失），
//!   `Connection: close`；
//! - **连接级超时**：初始请求头读取、目标出站（单一 deadline）与隧道
//!   空闲均受 connection_timeout 约束（D3）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agentsandbox_inference::{InferenceDecision, InferenceRequest, InferenceRouter, MockInferenceRouter};
use http::{Method, Request, Response, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::block_response::block_response;
use crate::filter::engine::evaluate;
use crate::forward::{relay_with_idle_timeout, AsyncReadWrite, TargetConnector};
use crate::logging;
use crate::mitm::{self, SniResolvingCert};
use crate::model::{Action, AuditLogEntry, Protocol, Reason, SCENARIO_LIB};
use crate::registry::Registry;

/// 阻断响应体类型（服务层统一 body 形态：Full 或目标流式 body 装箱）。
type B = http_body_util::combinators::BoxBody<bytes::Bytes, std::io::Error>;

/// 转发请求体类型（出站统一 body 形态：流式 Incoming 包装或缓冲 Full
/// 装箱——推理路由缓冲 body 与普通流式 body 共用转发路径）。
type ReqBody = http_body_util::combinators::BoxBody<bytes::Bytes, std::io::Error>;

/// Full body → 服务层统一 body 形态装箱。
fn box_body(resp: Response<Full<bytes::Bytes>>) -> Response<B> {
    resp.map(|b| b.map_err(|never| match never {}).boxed())
}

/// serve 运行上下文（进程内共享单份；构造于 facade/runtime 装配层）。
pub struct ServeContext {
    /// 注册面（容器键控配置 / CA / 身份解析回调取用）。
    pub registry: Arc<Registry>,
    /// 容器键控证书服务持有器（MITM 动态供证——按连接容器取）。
    pub cert_services: Arc<crate::cert::ContainerCertServices>,
    /// 目标出站连接器（ALPN 按连接传入）。
    pub connector: Arc<TargetConnector>,
    /// 审计条目 scenario 标签（默认 "lib"，K4 契约字段）。
    pub scenario: &'static str,
    /// 目标端口覆盖（测试注入本地 fake 目标；生产 None = 443）。
    pub target_port_override: Option<u16>,
    /// 目标主机覆盖（测试注入本地 fake 目标地址；生产 None = SNI 域名）。
    pub target_host_override: Option<String>,
    /// 推理路由列表（host+url 精确匹配；空列表 = 无推理路由分流）。
    pub inference_routes: Vec<crate::model::InferenceRoute>,
    /// 推理路由外部库（crate 引入；默认 mock 空实现——真实库落地后替换）。
    pub inference_router: Arc<dyn InferenceRouter>,
}

impl ServeContext {
    /// 以默认参数构造（target timeout 30s，scenario "lib"，无推理路由）。
    pub fn new(
        registry: Arc<Registry>,
        cert_services: Arc<crate::cert::ContainerCertServices>,
        connector: Arc<TargetConnector>,
    ) -> Self {
        Self {
            registry,
            cert_services,
            connector,
            scenario: SCENARIO_LIB,
            target_port_override: None,
            target_host_override: None,
            inference_routes: Vec::new(),
            inference_router: Arc::new(MockInferenceRouter),
        }
    }

    /// 目标端口（覆盖或生产默认——协议相关：TLS 443 / 明文 80）。
    fn target_port(&self) -> u16 {
        self.target_port_override.unwrap_or(443)
    }

    /// 明文路径目标端口（覆盖或生产默认 80）。
    fn target_port_plain(&self) -> u16 {
        self.target_port_override.unwrap_or(80)
    }

    /// 目标主机（覆盖或 SNI 域名；SNI 校验名恒为 SNI）。
    fn target_host(&self, sni: &str) -> std::borrow::Cow<'_, str> {
        self.target_host_override
            .as_deref()
            .map(std::borrow::Cow::Borrowed)
            .unwrap_or_else(|| std::borrow::Cow::Owned(sni.to_string()))
    }
}

/// accept 循环：并发上限 16（D3），每连接身份解析 + MITM + hyper 服务。
///
/// 由 [`crate::facade`] 的 proxy_init 自动 spawn。返回 ()——serve 循环
/// 仅因 listener 关闭/致命错误退出。
pub async fn serve(listener: TcpListener, ctx: Arc<ServeContext>) {
    // 并发上限 16（D3：Semaphore 许可）。
    let permits = Arc::new(tokio::sync::Semaphore::new(16));
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                crate::log_warn!("server", "accept failed: {e}");
                continue;
            }
        };
        let _ = tcp.set_nodelay(true);
        // 本地地址（身份解析 target 入参）。
        let Ok(local) = tcp.local_addr() else {
            continue;
        };
        let permit = match permits.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return,
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_connection(tcp, peer, local, ctx).await;
        });
    }
}

/// 连接身份解析（resolver 回调：source/target/protocol → 容器 + 二进制
/// 路径；**每连接一次**，结果连接级缓存）。
///
/// 未注册回调 / 返回 None / container_id 空串 → 未解析占位
/// （container_id `"-"`、binary_path None）——fail-closed 由下游查表
/// miss 承接：配置 503 / TLS CA 缺失拒握手 / binary_not_found。
fn resolve_identity(
    ctx: &ServeContext,
    peer: SocketAddr,
    local: SocketAddr,
) -> (String, Option<String>) {
    let Some(resolver) = ctx.registry.binary_resolver() else {
        return (group_id_stub(), None);
    };
    match resolver(peer, local, Protocol::Tcp) {
        Some(out) if !out.container_id.is_empty() => {
            let binary_path = if out.binary_path.is_empty() {
                None
            } else {
                Some(out.binary_path)
            };
            (out.container_id, binary_path)
        }
        _ => (group_id_stub(), None),
    }
}

/// 连接协议判定（首字节嗅探，2026-09-01 方案 B）。
///
/// 与 [`crate::model::Protocol`]（传输层协议，resolver 入参）区分：
/// 本枚举为嗅探出的应用层承载形态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SniffedProtocol {
    /// TLS（首字节 0x16——ClientHello record type，TLS 1.0-1.3 恒定）。
    Tls,
    /// 明文 HTTP（首字节为 ASCII 大写字母——HTTP 方法名首字符）。
    Http,
}

/// 首字节嗅探：peek 1 字节判定协议（**peek 不消费缓冲**——嗅探后流
/// 完整交给对应协议层，对下游透明）。EOF/超时/未知首字节 → None（关闭）。
async fn sniff_protocol(
    tcp: &tokio::net::TcpStream,
    timeout: Duration,
) -> Option<SniffedProtocol> {
    let mut probe = [0u8; 1];
    match tokio::time::timeout(timeout, tcp.peek(&mut probe)).await {
        Ok(Ok(1)) => match probe[0] {
            0x16 => Some(SniffedProtocol::Tls),
            b if b.is_ascii_uppercase() => Some(SniffedProtocol::Http),
            _ => None,
        },
        _ => None,
    }
}

/// 单连接服务：连接级身份解析 → 首字节嗅探分流 → TLS 走 MITM 终止 /
/// 明文直连 hyper。
///
/// TLS 层失败（CA 缺失/无 SNI/签发失败/握手失败）发生在 HTTP 之前——
/// 关闭连接（经日志观测，无 HTTP 响应可发）。
async fn serve_connection(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    ctx: Arc<ServeContext>,
) {
    let timeout = ctx.connector.timeout();
    // 连接级身份解析（resolver 回调一次；结果连接级缓存）。
    let (container_id, binary_path) = resolve_identity(&ctx, peer, local);
    if container_id == group_id_stub() {
        crate::log_warn!("server", "connection identity unresolved; fail-closed downstream");
    }
    // 首字节嗅探分流（peek 不消费；未知/超时 → 关闭，fail-closed）。
    match sniff_protocol(&tcp, timeout).await {
        Some(SniffedProtocol::Http) => {
            // 明文 HTTP：CA 仅 MITM 需要——未注入照常服务（2026-09-01
            // 决策 3）；TCP 流直接交 hyper（无 ALPN → h1）。
            serve_plaintext(tcp, peer, container_id, binary_path, ctx).await;
            return;
        }
        Some(SniffedProtocol::Tls) => { /* 落入下方 TLS 路径 */ }
        None => {
            crate::log_debug!("server", "connection closed: unknown protocol/timeout");
            return;
        }
    }
    serve_tls(tcp, peer, container_id, binary_path, ctx).await;
}

/// 明文 HTTP 连接服务：TCP 流直接交 hyper auto（h1；h2c 不支持——
/// 解析失败即关闭）+ 复用统一 service 闭包（求值/审计/阻断/转发全链）。
async fn serve_plaintext(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    container_id: String,
    binary_path: Option<String>,
    ctx: Arc<ServeContext>,
) {
    crate::log_info!("server", "plaintext http connection: container={container_id}");
    let conn_ctx = Arc::new(ConnContext {
        container_id,
        binary_path,
        sni: None,
        plaintext: true,
        peer,
    });
    serve_hyper(TokioIo::new(tcp), conn_ctx, ctx).await;
}

/// TLS 连接服务：CA 前置 → MITM 终止（SNI 捕获/动态证书/ALPN）→ hyper。
async fn serve_tls(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    container_id: String,
    binary_path: Option<String>,
    ctx: Arc<ServeContext>,
) {
    let timeout = ctx.connector.timeout();
    // 前置：该容器 CA 未设置 → TLS 流量 fail-closed（ca_error）。
    let Some(cert_service) = ctx.cert_services.service_for(&container_id) else {
        crate::log_error!("server", "connection rejected: ca_error (container={container_id})");
        return;
    };
    // MITM TLS 终止（含 deadline：慢握手客户端不得无限占用连接任务）。
    let resolver = Arc::new(SniResolvingCert::new(cert_service));
    let tls_config = mitm::server_config(resolver.clone());
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let tls = match tokio::time::timeout(timeout, acceptor.accept(tcp)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(_)) => {
            // 握手失败：无 SNI（config_not_found 语义）/ 签发失败（cert_error）
            // / 客户端中止——无法返回 HTTP（TLS 未建立），仅日志。
            crate::log_debug!("server", "mitm handshake rejected (no sni / cert_error / aborted)");
            return;
        }
        Err(_) => {
            crate::log_debug!("server", "mitm handshake timeout");
            return;
        }
    };
    // SNI + ALPN（协商协议分发依据，D5）。
    let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let Ok(handshake) = mitm::handshake_context(&resolver, alpn.as_deref()) else {
        return;
    };
    let sni = handshake.sni;
    crate::log_info!("server", "mitm established: sni={sni} alpn={:?}", alpn.as_deref());

    // 连接级上下文（每请求共享：SNI/对端/本地地址/身份缓存）。
    let conn_ctx = Arc::new(ConnContext {
        container_id,
        binary_path,
        sni: Some(sni.clone()),
        plaintext: false,
        peer,
    });

    serve_hyper(TokioIo::new(tls), conn_ctx, ctx).await;
}

/// hyper 服务装配（TLS/明文共用）：service 闭包 + auto Builder
/// （按 ALPN 协商 h2/h1；明文无 ALPN → h1）。
async fn serve_hyper<I>(
    io: TokioIo<I>,
    conn_ctx: Arc<ConnContext>,
    ctx: Arc<ServeContext>,
) where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service_ctx = ctx.clone();
    let conn_ctx_ref = conn_ctx.clone();
    let service = service_fn(move |req: Request<Incoming>| {
        let ctx = service_ctx.clone();
        let conn = conn_ctx_ref.clone();
        async move { handle_request(req, ctx, conn).await }
    });

    // hyper auto：按 ALPN 协商协议（h2/h1）分发达层；with_upgrades 启用
    // h1 升级流交付（Upgrade 隧道必需——否则 on_upgrade 报
    // "upgrade expected but low level API in use"）。
    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor);
    let serve_result = builder
        .serve_connection_with_upgrades(io, service)
        .await;
    match serve_result {
        Ok(()) => {}
        Err(e) => {
            // 常见：客户端在 Upgrade 前中断/非 HTTP 字节——debug 级观测。
            crate::log_debug!("server", "connection closed: {e}");
        }
    }
}

/// 每连接共享上下文（身份/SNI 按连接缓存——resolver 一次解析全连接
/// 复用）。
struct ConnContext {
    /// 容器标识（连接级 resolver 解析；未解析占位 "-"——下游查表 miss
    /// fail-closed）。
    container_id: String,
    /// 进程二进制路径（连接级 resolver 解析；None = 未解析——规则含
    /// binary 条件时 binary_not_found fail-closed）。
    binary_path: Option<String>,
    /// MITM 捕获的 SNI 域名（TLS 路径必有；明文路径为 None——domain
    /// 降级为请求级 Host 头，见 [`resolve_domain`]）。
    sni: Option<String>,
    /// 是否明文 HTTP 连接（目标透传协议与端口依据：明文→TCP :80）。
    plaintext: bool,
    /// 发起方对端地址。
    peer: SocketAddr,
}

/// hyper executor（tokio 任务的薄包装）。
#[derive(Clone, Copy)]
struct TokioExecutor;

impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::spawn(fut);
    }
}

/// 单请求处理（每请求/每流回调——Q3 逐请求求值闭环）。
///
/// 返回 `Err` 仅用于 hyper 内部错误（连接层）；业务阻断统一为 `Ok(响应)`。
async fn handle_request(
    req: Request<Incoming>,
    ctx: Arc<ServeContext>,
    conn: Arc<ConnContext>,
) -> Result<Response<B>, std::convert::Infallible> {
    // 0. 域名解析（TLS=SNI 连接级；明文=Host 头请求级——缺失即 503，
    //    与无 SNI 对齐 fail-closed）。
    let Some(domain) = resolve_domain(&conn, &req) else {
        return Ok(config_missing_response(&ctx, &conn, &req, "-"));
    };

    // 0.5 推理路由分流（AR-005）：命中路由列表（host+url 精确匹配）即
    //     完全旁通过滤引擎（不查容器配置/binary/求值——容器未配置也可
    //     路由），交推理路由外部库裁决；Upgrade 请求不参与（修改语义
    //     与隧道不兼容——走原管道）。
    if !is_upgrade_request(&req)
        && inference_route_matched(&ctx, &domain, req.uri().path())
    {
        return handle_inference(req, ctx, conn, domain).await;
    }

    // 1. 容器配置快照（端点静态绑定 container_id；热更新天然生效：
    //    每请求实时查表；未注册容器 → 503 拒绝——fail-closed）。
    let container_id = conn.container_id.clone();
    let Some(fc) = ctx.registry.config_for(&container_id) else {
        return Ok(config_missing_response(&ctx, &conn, &req, &domain));
    };

    // 2. binary 维度（连接级已解析——resolver 一次解析全连接复用；
    //    规则含 binary 条件且未解析 → binary_not_found fail-closed）。
    if fc.has_binary_condition() && conn.binary_path.is_none() {
        let meta = ReqMeta { container_id: &container_id, domain: &domain, method: req.method(), uri: req.uri() };
        let entry = deny_entry(&ctx, &conn, &meta, Reason::BinaryNotFound);
        return Ok(audit_deny(&entry, Reason::BinaryNotFound));
    }

    // 3. 求值（K3：黑>白>默认，四维 AND 短路；binary 维度取连接级
    //    resolver 输出的 binary_path）。
    let (action, reason) = evaluate(
        &container_id,
        &domain,
        req.method().as_str(),
        req.uri().path(),
        conn.binary_path.as_deref(),
        &fc,
    );
    if action == Action::Deny {
        crate::log_debug!("server", "deny: domain={} reason={:?}", domain, reason);
        let meta = ReqMeta { container_id: &container_id, domain: &domain, method: req.method(), uri: req.uri() };
        let entry = deny_entry(&ctx, &conn, &meta, reason);
        return Ok(audit_deny(&entry, reason));
    }

    // 4. Upgrade（h1）：101 升级后转纯隧道（本函数在 upgrade 前返回
    //    101 响应骨架——隧道由 on_upgrade 任务承接）。
    if is_upgrade_request(&req) {
        return handle_upgrade(req, ctx, conn, domain, container_id, reason).await;
    }

    // 5. allow：目标连接 + 转发 + 流式回传 + 审计（真实 status_code——Q6 修复）。
    //    body 装箱为统一出站形态（流式透传——零缓冲；与推理路由缓冲
    //    body 共用转发路径）。
    let req = req.map(|b| {
        b.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            .boxed()
    });
    forward_request(req, ctx, conn, domain, container_id, reason).await
}

/// Upgrade 请求判定（h1：GET + 非空 Upgrade 头——隧道分支判别器）。
fn is_upgrade_request(req: &Request<Incoming>) -> bool {
    req.method() == Method::GET
        && req
            .headers()
            .get(http::header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| !v.trim().is_empty())
}

// ===== 推理路由（AR-005：命中即旁通过滤引擎，交外部库裁决）=====

/// 推理路由条目匹配：host 精确（大小写不敏感——DNS 语义）AND url 精确
///（区分大小写，不含 query string）；任一条目命中即分流。
fn inference_route_matched(ctx: &ServeContext, domain: &str, path: &str) -> bool {
    ctx.inference_routes
        .iter()
        .any(|r| r.host.eq_ignore_ascii_case(domain) && r.url == path)
}

/// 推理路由请求处理：缓冲 body → 交外部库裁决 → 决策分发。
///
/// 三态决策（[`InferenceDecision`]）：
/// - Block → 403 + 审计 deny（status=0，reason=inference_route）；
/// - Forward / ForwardModified → 重建缓冲请求（覆写 Content-Length、剥
///   Transfer-Encoding）→ 复用统一转发路径（审计 allow + 真实 status）。
///
/// body 缓冲失败/超时：运行日志 warn + 503 关闭，不产出审计（无流量
/// 通过——与 TLS 层失败仅日志的先例一致）。
async fn handle_inference(
    req: Request<Incoming>,
    ctx: Arc<ServeContext>,
    conn: Arc<ConnContext>,
    domain: String,
) -> Result<Response<B>, std::convert::Infallible> {
    let timeout = ctx.connector.timeout();
    let container_id = conn.container_id.clone();
    let (parts, incoming) = req.into_parts();

    // 1. body 全量缓冲（deadline 约束——慢客户端不得无限占用连接任务）。
    let body = match tokio::time::timeout(timeout, incoming.collect()).await {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(_)) | Err(_) => {
            crate::log_warn!("server", "inference route: request body collect failed/timeout");
            // ConfigNotFound 仅取其 503 映射（不审计——无流量通过）。
            return Ok(box_body(block_response(Reason::ConfigNotFound)));
        }
    };

    // 2. 外部库裁决（同步调用——body 已缓冲；Bytes clone 为引用计数拷贝）。
    let decision = ctx.inference_router.route(InferenceRequest {
        method: parts.method.clone(),
        uri: parts.uri.clone(),
        headers: parts.headers.clone(),
        body: body.clone(),
    });

    // 3. 决策分发：Block → 403 + 审计 deny；Forward/Modified → 缓冲请求
    //    重建（原文 parts 或库改写形态）→ 统一转发。
    let (method, uri, headers, body) = match decision {
        InferenceDecision::Block => {
            let meta = ReqMeta {
                container_id: &container_id,
                domain: &domain,
                method: &parts.method,
                uri: &parts.uri,
            };
            let entry = deny_entry(&ctx, &conn, &meta, Reason::InferenceRoute);
            return Ok(audit_deny(&entry, Reason::InferenceRoute));
        }
        InferenceDecision::Forward => (parts.method, parts.uri, parts.headers, body),
        InferenceDecision::ForwardModified(new_req) => {
            (new_req.method, new_req.uri, new_req.headers, new_req.body)
        }
    };
    let body_len = body.len();
    let mut fwd_req = match build_buffered_request(method, uri, headers, body) {
        Ok(r) => r,
        // 程序不变量破坏（已解析类型 + Full body 理论不可失败）——防御性 502。
        Err(_) => return Ok(box_body(block_response(Reason::TargetTlsError))),
    };
    normalize_buffered_request(&mut fwd_req, body_len);

    // 4. 统一转发路径（目标连接 + 转发 + 审计 allow + 真实 status +
    //    流式回传；reason=inference_route）。
    forward_request(fwd_req, ctx, conn, domain, container_id, Reason::InferenceRoute).await
}

/// 缓冲请求重建（method/uri/headers/body → 统一出站 body 形态请求）。
///
/// Err 仅在程序不变量破坏时出现（入参均为已解析类型 + Full body）。
fn build_buffered_request(
    method: Method,
    uri: Uri,
    headers: http::HeaderMap,
    body: bytes::Bytes,
) -> Result<Request<ReqBody>, ()> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Full::new(body).map_err(|never| match never {}).boxed())
        .map_err(|_| ())?;
    *req.headers_mut() = headers;
    Ok(req)
}

/// 缓冲请求规范化：剥 Transfer-Encoding、覆写 Content-Length（body 已
/// 全量缓冲定长——原文 chunked/过期长度不得残留）。
fn normalize_buffered_request(req: &mut Request<ReqBody>, body_len: usize) {
    let headers = req.headers_mut();
    headers.remove(http::header::TRANSFER_ENCODING);
    if let Ok(v) = http::HeaderValue::from_str(&body_len.to_string()) {
        headers.insert(http::header::CONTENT_LENGTH, v);
    }
}

/// 目标连接/转发：懒建 h1 目标连接（按 MITM ALPN——h2 目标连接暂以 h1
/// 承载出站，见 doc 尾注）→ 转发请求 → 流式回传响应 → 审计。
///
/// 请求体为统一出站形态 [`ReqBody`]（普通路径流式 Incoming 包装零缓冲；
/// 推理路由路径缓冲 Full 装箱——库可能改写 body）。
async fn forward_request(
    req: Request<ReqBody>,
    ctx: Arc<ServeContext>,
    conn: Arc<ConnContext>,
    domain: String,
    container_id: String,
    reason: Reason,
) -> Result<Response<B>, std::convert::Infallible> {
    let timeout = ctx.connector.timeout();
    let (method, uri) = (req.method().clone(), req.uri().clone());
    let meta = ReqMeta { container_id: &container_id, domain: &domain, method: &method, uri: &uri };

    // 懒建目标连接（单一 deadline；K9 三类错误 → 502 + 审计 deny）。
    let (sender, conn_handle) = match connect_target(&ctx, &conn, &domain, timeout).await {
        Ok(x) => x,
        Err(e) => {
            let entry = deny_entry(&ctx, &conn, &meta, e.reason());
            return Ok(audit_deny(&entry, e.reason()));
        }
    };

    // 转发请求（重建 URI 为 absolute-form 或 authority 形态——目标侧
    // hyper client 要求；重写 Host 保持原语义）。
    let mut sender = sender;
    let response = match send_forwarded(&mut sender, req, timeout).await {
        Ok(resp) => resp,
        Err(_) => {
            conn_handle.abort();
            return Ok(box_body(block_response(Reason::TargetTlsError)));
        }
    };
    let status = response.status();

    // 审计（真实 status_code——Q6 修复；先于响应回传发起方：审计 Err
    // 时不回传，无未审计流量）。
    if let Some(blocked) = audit_allow(&allow_entry(&ctx, &conn, &meta, reason, status.as_u16())) {
        conn_handle.abort();
        return Ok(blocked);
    }
    crate::log_debug!(
        "server",
        "forward: domain={} status={} reason={:?}",
        domain,
        status.as_u16(),
        reason
    );

    // 流式回传（body 透传——不缓冲不解析，审计不含响应体）。
    Ok(passthrough_response(response))
}

/// 重建并发送转发请求：头部逐条复制 + body 透传 → 目标 → 接收响应
/// （deadline 约束；Err 统一 TargetTlsError 语义由调用方映射 502）。
async fn send_forwarded(
    sender: &mut hyper::client::conn::http1::SendRequest<ReqBody>,
    req: Request<ReqBody>,
    timeout: Duration,
) -> Result<Response<Incoming>, ()> {
    let mut fwd = Request::builder()
        .method(req.method().clone())
        .uri(req.uri().to_string());
    for (name, value) in req.headers().iter() {
        fwd = fwd.header(name, value);
    }
    let fwd = fwd.body(req.into_body()).map_err(|_| ())?;
    tokio::time::timeout(timeout, sender.send_request(fwd))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

/// 建立目标连接（h1；按连接协议分流——TLS 走 MITM 协商 ALPN 与 :443，
/// 明文走纯 TCP :80 同协议透传，2026-09-01 决策 1）。
async fn connect_target(
    ctx: &ServeContext,
    conn: &ConnContext,
    domain: &str,
    timeout: Duration,
) -> Result<
    (
        hyper::client::conn::http1::SendRequest<ReqBody>,
        tokio::task::JoinHandle<()>,
    ),
    crate::forward::TargetConnectError,
> {
    let stream = if conn.plaintext {
        // 明文：纯 TCP 连接目标 :80（同协议透传；无 TLS 包装）。
        let tcp = tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect((ctx.target_host(domain).as_ref(), ctx.target_port_plain())),
        )
        .await
        .map_err(|_| crate::forward::TargetConnectError::Timeout)?
        .map_err(map_plain_connect_error)?;
        let _ = tcp.set_nodelay(true);
        TargetStream::Plain(tcp)
    } else {
        // TLS：经 TargetConnector（K9 三类错误映射 + 单一 deadline；
        // ALPN 与 MITM 协商一致，D5）。
        let alpn = if ctx.connector_alpn_h2() {
            vec!["h2".to_string(), "http/1.1".to_string()]
        } else {
            vec!["http/1.1".to_string()]
        };
        let tls = ctx
            .connector
            .connect(&ctx.target_host(domain), ctx.target_port(), domain, &alpn)
            .await?;
        TargetStream::Tls(Box::new(tls))
    };
    hyper_handshake(TokioIo::new(stream), timeout).await
}

/// 目标连接流双形态（协议分流：TLS rustls 流 / 明文 TCP 流）。
///
/// 经 [`TokioIo`] 桥接为 hyper 的 Read/Write；poll 委派到具体变体。
enum TargetStream {
    /// TLS 目标（rustls 客户端流；装箱——变体大小差异收敛）。
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
    /// 明文 TCP 目标（同协议透传）。
    Plain(tokio::net::TcpStream),
}

impl tokio::io::AsyncRead for TargetStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            TargetStream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            TargetStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for TargetStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            TargetStream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            TargetStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            TargetStream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
            TargetStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            TargetStream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            TargetStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// 明文 TCP 连接错误映射（K9 复用：拒绝/超时精确归类；TargetTls 变体
/// 在明文语境为「目标侧连接失败」兜底——审计 reason 枚举不变）。
fn map_plain_connect_error(e: std::io::Error) -> crate::forward::TargetConnectError {
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused => crate::forward::TargetConnectError::Refused,
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            crate::forward::TargetConnectError::Timeout
        }
        _ => crate::forward::TargetConnectError::TargetTls,
    }
}

/// 目标流 → hyper h1 client 连接（handshake + 连接任务持有）。
async fn hyper_handshake(
    io: TokioIo<TargetStream>,
    timeout: Duration,
) -> Result<
    (
        hyper::client::conn::http1::SendRequest<ReqBody>,
        tokio::task::JoinHandle<()>,
    ),
    crate::forward::TargetConnectError,
> {
    let (sender, connection) = match tokio::time::timeout(
        timeout,
        hyper::client::conn::http1::handshake::<TokioIo<TargetStream>, ReqBody>(io),
    )
    .await
    {
        Ok(Ok(x)) => x,
        Ok(Err(_)) | Err(_) => {
            return Err(crate::forward::TargetConnectError::TargetTls);
        }
    };
    let conn_handle = tokio::spawn(async move {
        if let Err(e) = connection.await {
            crate::log_debug!("server", "target connection ended: {e}");
        }
    });
    Ok((sender, conn_handle))
}

impl ServeContext {
    /// 目标侧是否请求 h2（与 MITM 协商一致，D5）——由 serve 装配时按
    /// 连接协商结果动态决定；此处经连接上下文传递（见 serve_connection）。
    fn connector_alpn_h2(&self) -> bool {
        // 连接级 ALPN 已传入 connect_target 调用点；此方法保留给非连接
        // 路径的默认（false = http/1.1）。实际 h2 判定在 handle 层完成。
        false
    }
}

/// h1 Upgrade 处理：升级握手透传 + 双侧原始流纯隧道。
///
/// 流程（避免依赖 hyper client 的 upgrade 语义）：
/// 1. 经 [`TargetConnector`] 建目标 TLS 连接（K9 三类错误 → 502）；
/// 2. **手工写出**原始升级请求头（客户端原文，不经过 hyper client 改写）；
/// 3. 读取目标 101 响应头并原样回传发起方；
/// 4. 审计（status=101，先于 101 回传——fail-closed 排序）；
/// 5. 双侧原始流（发起方经 hyper `on_upgrade()`，目标即该 TLS 流）交
///    [`relay_with_idle_timeout`]（连接级空闲超时 + 半关闭传播）。
///
/// Upgrade 求值已在 handle_request 上游完成（基于初始请求元数据，4.3.2）。
async fn handle_upgrade(
    req: Request<Incoming>,
    ctx: Arc<ServeContext>,
    conn: Arc<ConnContext>,
    domain: String,
    container_id: String,
    reason: Reason,
) -> Result<Response<B>, std::convert::Infallible> {
    let timeout = ctx.connector.timeout();
    // 元数据先行提取（on_upgrade 消耗原始请求——升级 receiver 在其
    // extensions 中，重建实例无效）。
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers: Vec<(http::HeaderName, http::HeaderValue)> = req
        .headers()
        .iter()
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect();
    let client_upgrade = hyper::upgrade::on(req);
    let meta = ReqMeta { container_id: &container_id, domain: &domain, method: &method, uri: &uri };

    // 1. 目标连接（协议分流：TLS→rustls 流；明文→纯 TCP；K9 → 502）。
    let mut target = match connect_upgrade_target(&ctx, &conn, &domain, timeout).await {
        Ok(t) => t,
        Err(e) => {
            let entry = deny_entry(&ctx, &conn, &meta, e.reason());
            return Ok(audit_deny(&entry, e.reason()));
        }
    };

    // 2. 手工写出原始升级请求 → 3. 读目标响应头。
    if write_upgrade_request(&mut target, &method, &uri, &headers).await.is_err() {
        return Ok(box_body(block_response(Reason::TargetTlsError)));
    }
    let resp_buf = match read_target_head(&mut target, timeout).await {
        Ok(buf) => buf,
        Err(_) => return Ok(box_body(block_response(Reason::TargetTlsError))),
    };
    let status = parse_status_line(&resp_buf);

    // 4. 审计（升级连接 status；先于 101 回传发起方——fail-closed）。
    if let Some(blocked) = audit_allow(&allow_entry(&ctx, &conn, &meta, reason, status)) {
        return Ok(blocked);
    }

    // 5. 隧道：发起方升级流 ↔ 目标 TLS 流（残留字节先行写出）。
    spawn_upgrade_tunnel(client_upgrade, target, split_leftover(&resp_buf), timeout);

    // 6. 回传 101 响应（原状态码 + 原升级响应头）。
    Ok(build_upgrade_response(&resp_buf, status))
}

/// 建立 Upgrade 目标原始流（协议分流：TLS→rustls 流 :443；明文→纯
/// TCP :80——同协议透传；复用 [`TargetStream`] 双形态；K9 映射复用）。
async fn connect_upgrade_target(
    ctx: &ServeContext,
    conn: &ConnContext,
    domain: &str,
    timeout: Duration,
) -> Result<TargetStream, crate::forward::TargetConnectError> {
    if conn.plaintext {
        let tcp = tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect((ctx.target_host(domain).as_ref(), ctx.target_port_plain())),
        )
        .await
        .map_err(|_| crate::forward::TargetConnectError::Timeout)?
        .map_err(map_plain_connect_error)?;
        let _ = tcp.set_nodelay(true);
        Ok(TargetStream::Plain(tcp))
    } else {
        let tls = ctx
            .connector
            .connect(
                &ctx.target_host(domain),
                ctx.target_port(),
                domain,
                &["http/1.1".to_string()],
            )
            .await?;
        Ok(TargetStream::Tls(Box::new(tls)))
    }
}

/// 手工写出原始升级请求（请求行 + 头部原文；Upgrade 请求无 body——
/// 客户端尚未发送升级后帧）。
async fn write_upgrade_request<T>(
    target: &mut T,
    method: &Method,
    uri: &Uri,
    headers: &[(http::HeaderName, http::HeaderValue)],
) -> Result<(), std::io::Error>
where
    T: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt as _;
    let mut raw = Vec::new();
    raw.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method, uri).as_bytes());
    for (name, value) in headers {
        raw.extend_from_slice(format!("{name}: ").as_bytes());
        raw.extend_from_slice(value.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"\r\n");
    target.write_all(&raw).await
}

/// 读取目标响应头（至 `\r\n\r\n` 终结符；16KB 上限防异常目标；
/// 超时/EOF/超限统一 Err）。
async fn read_target_head<T>(
    target: &mut T,
    timeout: Duration,
) -> Result<Vec<u8>, ()>
where
    T: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    loop {
        let n = tokio::time::timeout(timeout, target.read(&mut chunk))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > 16 * 1024 {
            return Err(());
        }
    }
}

/// 解析目标响应状态行（"HTTP/1.1 101 ..." → 101；失败归 502）。
fn parse_status_line(buf: &[u8]) -> u16 {
    String::from_utf8_lossy(buf)
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(502)
}

/// 切分 101 头后的残留字节（读头时同批到达的隧道首包，不丢弃）。
fn split_leftover(buf: &[u8]) -> Vec<u8> {
    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(buf.len());
    buf[head_end..].to_vec()
}

/// 启动升级隧道任务：发起方 hyper 升级流 ↔ 目标 TLS 流（残留字节先行
/// 写出后交 [`relay_with_idle_timeout`]——连接级空闲超时 + 半关闭传播）。
fn spawn_upgrade_tunnel<T>(
    client_upgrade: hyper::upgrade::OnUpgrade,
    target: T,
    leftover: Vec<u8>,
    idle: Duration,
) where
    T: AsyncReadWrite + Send + 'static,
{
    use tokio::io::AsyncWriteExt as _;
    tokio::spawn(async move {
        if let Ok(client_upgraded) = client_upgrade.await {
            let mut client_io = TokioIo::new(client_upgraded);
            // 首包残留写出（目标已收到的隧道字节不丢）。
            if !leftover.is_empty() && client_io.write_all(&leftover).await.is_err() {
                return;
            }
            relay_with_idle_timeout(client_io, target, idle).await;
        }
    });
}

/// 审计条目组装（完整字段）。
#[allow(clippy::too_many_arguments)]
fn build_entry(
    scenario: &str,
    container_id: &str,
    domain: &str,
    method: &Method,
    uri: &Uri,
    action: Action,
    reason: Reason,
    status_code: u16,
    source_ip: Option<&str>,
    target_ip: Option<&str>,
) -> AuditLogEntry {
    AuditLogEntry {
        timestamp: crate::model::utc_now_iso8601(),
        container_id: container_id.to_string(),
        scenario: scenario.to_string(),
        domain: domain.to_string(),
        url_path: uri.path().to_string(),
        method: method.as_str().to_string(),
        status_code,
        action,
        reason,
        source_ip: source_ip.map(str::to_string),
        target_ip: target_ip.map(str::to_string),
    }
}

// ===== 审计与阻断样板辅助（deny/allow 分支的共性收敛；纯提取，行为不变）=====

/// 请求元数据摘要（审计条目组装的 deny 路径入参形态）。
struct ReqMeta<'a> {
    container_id: &'a str,
    /// 求值/审计域名（TLS=SNI；明文=Host 头——见 [`resolve_domain`]）。
    domain: &'a str,
    method: &'a Method,
    uri: &'a Uri,
}

/// deny 路径审计条目（status=0、source_ip=None、target_ip=None——
/// 求值拒绝/binary 缺失/目标连接失败的统一字段形态）。
fn deny_entry(
    ctx: &ServeContext,
    conn: &ConnContext,
    meta: &ReqMeta<'_>,
    reason: Reason,
) -> AuditLogEntry {
    let _ = conn;
    build_entry(
        ctx.scenario,
        meta.container_id,
        meta.domain,
        meta.method,
        meta.uri,
        Action::Deny,
        reason,
        0,
        None,
        None,
    )
}

/// allow 路径审计条目（source_ip=发起方对端 IP；status 为目标响应码——
/// 普通转发为真实 status_code，Upgrade 为 101）。
fn allow_entry(
    ctx: &ServeContext,
    conn: &ConnContext,
    meta: &ReqMeta<'_>,
    reason: Reason,
    status: u16,
) -> AuditLogEntry {
    build_entry(
        ctx.scenario,
        meta.container_id,
        meta.domain,
        meta.method,
        meta.uri,
        Action::Allow,
        reason,
        status,
        Some(&conn.peer.ip().to_string()),
        None,
    )
}

/// deny 出口：尽力审计（Err 仅告警——deny 语义本即关闭，审计失败不改变
/// 行为）+ 阻断响应（403/502/503 按 reason 映射）。
fn audit_deny(entry: &AuditLogEntry, reason: Reason) -> Response<B> {
    if let Err(e) = logging::audit(entry) {
        crate::log_error!("server", "audit delivery failed: {e}");
    }
    box_body(block_response(reason))
}

/// allow 出口（fail-closed）：审计 Err 时返回 Some(503 阻断响应)——
/// 调用方直接 return（无未审计流量通过，SR TC-005）。
fn audit_allow(entry: &AuditLogEntry) -> Option<Response<B>> {
    match logging::audit(entry) {
        Ok(()) => None,
        Err(e) => {
            crate::log_error!("server", "audit delivery failed: {e}");
            Some(box_body(block_response(Reason::LogWriteError)))
        }
    }
}

/// 配置缺失/域名缺失/容器未注册分支整体（503 + 审计 config_not_found；
/// source_ip=Some(peer)——该路径原字段形态，与其余 deny 的 None 差异保留）。
///
/// `domain`：配置缺失时（明文路径可能尚未解析 Host）取 SNI 或占位 "-"；
/// 明文 Host 缺失复用本分支（与无 SNI 对齐拒绝）。
fn config_missing_response(
    ctx: &ServeContext,
    conn: &ConnContext,
    req: &Request<Incoming>,
    domain: &str,
) -> Response<B> {
    let entry = build_entry(
        ctx.scenario,
        &group_id_stub(),
        domain,
        req.method(),
        req.uri(),
        Action::Deny,
        Reason::ConfigNotFound,
        0,
        Some(&conn.peer.ip().to_string()),
        None,
    );
    audit_deny(&entry, Reason::ConfigNotFound)
}

/// 求值/审计域名解析（每请求一次——明文路径 Host 可变，不缓存于连接级）。
///
/// TLS：连接级 SNI（握手期捕获）；明文：请求级 Host 头（剥端口；
/// `[::1]:80` IPv6 形态剥端口保留裸地址）。缺失/空 → None（调用方按
/// config_not_found 语义 503 拒绝——2026-09-01 决策 2，与无 SNI 对齐）。
fn resolve_domain<T>(conn: &ConnContext, req: &Request<T>) -> Option<String> {
    if let Some(sni) = &conn.sni {
        return Some(sni.clone());
    }
    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())?
        .trim();
    if host.is_empty() {
        return None;
    }
    // 剥端口：IPv6 [::1]:80 形态保留括号内地址；域名/IPv4 host:port 剥后缀。
    if host.starts_with('[') {
        host.split(']')
            .next()
            .map(|bare| format!("{bare}]"))
    } else {
        host.rsplit_once(':').map(|(h, _)| h.to_string()).or(Some(host.to_string()))
    }
}

// ===== 响应构建辅助 =====

/// 目标响应流式回传（状态码+头部逐条复制；body 装箱透传——零缓冲零解析）。
fn passthrough_response(response: Response<Incoming>) -> Response<B> {
    let status = response.status();
    let mut outbound = Response::builder().status(status);
    for (name, value) in response.headers().iter() {
        outbound = outbound.header(name, value);
    }
    match outbound.body(http_body_util::combinators::BoxBody::new(
        response.into_body().map_err(|e| {
            crate::log_warn!("server", "target body error: {e}");
            std::io::Error::new(std::io::ErrorKind::Other, "target body error")
        }),
    )) {
        // 已解析头部复制回 builder 理论不可失败；失败（程序不变量破坏）
        // 时降级 502——拒绝优先于崩溃。
        Ok(resp) => resp,
        Err(e) => {
            crate::log_error!("server", "response build failed: {e}");
            box_body(block_response(Reason::TargetTlsError))
        }
    }
}

/// 101 升级响应重建（原状态码 + 目标响应头逐行透传，跳过状态行；空 body）。
fn build_upgrade_response(buf: &[u8], status: u16) -> Response<B> {
    let text = String::from_utf8_lossy(buf);
    let code = http::StatusCode::from_u16(status)
        .unwrap_or(http::StatusCode::SWITCHING_PROTOCOLS);
    let mut outbound = Response::builder().status(code);
    for line in text.lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            outbound = outbound.header(name.trim(), value.trim());
        }
    }
    match outbound.body(Full::new(bytes::Bytes::new())) {
        Ok(r) => box_body(r),
        Err(_) => box_body(block_response(Reason::TargetTlsError)),
    }
}

/// 配置缺失路径的占位 group_id（审计 group_id 字段非空约束）。
fn group_id_stub() -> String {
    "-".to_string()
}


#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_routes(routes: &[(&str, &str)]) -> ServeContext {
        let registry = Arc::new(Registry::new());
        let cert_services = Arc::new(crate::cert::ContainerCertServices::new());
        let connector = Arc::new(TargetConnector::new(
            Arc::new(rustls::RootCertStore::empty()),
            Duration::from_secs(30),
        ));
        let mut ctx = ServeContext::new(registry, cert_services, connector);
        ctx.inference_routes = routes
            .iter()
            .map(|(host, url)| crate::model::InferenceRoute {
                host: host.to_string(),
                url: url.to_string(),
            })
            .collect();
        ctx
    }

    // 推理路由条目匹配：host 精确（大小写不敏感）/ url 精确（区分
    // 大小写）/ 空列表不命中。
    #[test]
    fn inference_route_matching_semantics() {
        let ctx = ctx_with_routes(&[("api.example.com", "/v1/chat")]);
        // 精确命中。
        assert!(inference_route_matched(&ctx, "api.example.com", "/v1/chat"));
        // host 大小写不敏感（DNS 语义）。
        assert!(inference_route_matched(&ctx, "API.Example.COM", "/v1/chat"));
        // path 不匹配（精确——非前缀）。
        assert!(!inference_route_matched(&ctx, "api.example.com", "/v1/chat/extra"));
        assert!(!inference_route_matched(&ctx, "api.example.com", "/v1"));
        // path 区分大小写。
        assert!(!inference_route_matched(&ctx, "api.example.com", "/V1/CHAT"));
        // host 不匹配。
        assert!(!inference_route_matched(&ctx, "other.example.com", "/v1/chat"));
        // 多条目任一命中。
        let ctx2 = ctx_with_routes(&[("a.com", "/x"), ("b.com", "/y")]);
        assert!(inference_route_matched(&ctx2, "b.com", "/y"));
        // 空列表永不命中。
        let empty = ctx_with_routes(&[]);
        assert!(!inference_route_matched(&empty, "api.example.com", "/v1/chat"));
    }

    // 缓冲请求规范化：剥 Transfer-Encoding、覆写 Content-Length。
    #[test]
    fn normalize_buffered_request_headers() {
        let req = build_buffered_request(
            Method::POST,
            "/v1/chat".parse().unwrap(),
            {
                let mut h = http::HeaderMap::new();
                h.insert(
                    http::header::TRANSFER_ENCODING,
                    http::HeaderValue::from_static("chunked"),
                );
                h
            },
            bytes::Bytes::from_static(b"hello"),
        )
        .unwrap();
        let mut req = req;
        normalize_buffered_request(&mut req, 5);
        assert!(req.headers().get(http::header::TRANSFER_ENCODING).is_none());
        assert_eq!(
            req.headers().get(http::header::CONTENT_LENGTH).unwrap(),
            "5"
        );
    }

    // 嗅探判定：0x16→Tls；HTTP 方法首字符→Http；其他→None。
    #[tokio::test]
    async fn sniff_classifies_protocols() {
        let pairs: [([u8; 3], Option<SniffedProtocol>); 7] = [
            ([0x16, 0x03, 0x01], Some(SniffedProtocol::Tls)),  // TLS ClientHello
            ([b'G', b'E', b'T'], Some(SniffedProtocol::Http)), // GET
            ([b'P', b'O', b'S'], Some(SniffedProtocol::Http)), // POST
            ([b'C', b'O', b'N'], Some(SniffedProtocol::Http)), // CONNECT
            ([0x00, 0x01, 0x02], None),                 // 二进制非 TLS
            ([0x80, 0x01, 0x02], None),                 // SSLv2 旧客户端
            ([b'a', b'b', b'c'], None),                 // 小写（非方法）
        ];
        for (payload, expected) in pairs {
            // 真实回环 socket：对端写入首字节后 peek 判定。
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let mut writer = std::net::TcpStream::connect(addr).unwrap();
            use std::io::Write as _;
            writer.write_all(&payload).unwrap();
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_nonblocking(true).unwrap();
            let tcp = tokio::net::TcpStream::from_std(tcp).unwrap();
            let got = sniff_protocol(&tcp, Duration::from_secs(2)).await;
            assert_eq!(got, expected, "payload={payload:?}");
            drop(writer);
        }
    }

    // 嗅探超时：静默对端 → None（fail-closed）。
    #[tokio::test]
    async fn sniff_timeout_returns_none() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _writer = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (tcp, _) = listener.accept().await.unwrap();
        let got = sniff_protocol(&tcp, Duration::from_millis(100)).await;
        assert_eq!(got, None);
    }

    // Host 解析：纯域名/带端口/IPv6 带端口/缺失/空值。
    #[test]
    fn resolve_domain_from_host_header() {
        let conn_tls = |sni: &str| ConnContext {
            container_id: "c-test".to_string(),
            binary_path: None,
            sni: Some(sni.to_string()),
            plaintext: false,
            peer: "127.0.0.1:9000".parse().unwrap(),
        };
        let conn_plain = || ConnContext {
            container_id: "c-test".to_string(),
            binary_path: None,
            sni: None,
            plaintext: true,
            peer: "127.0.0.1:9000".parse().unwrap(),
        };

        // TLS：SNI 优先（Host 头不参与）。
        let req = http::Request::builder()
            .header("host", "other.com:8080")
            .body(()).unwrap();
        assert_eq!(resolve_domain(&conn_tls("sni.com"), &req), Some("sni.com".to_string()));

        // 明文：Host 剥端口。
        let req = http::Request::builder()
            .header("host", "api.example.com:8080")
            .body(()).unwrap();
        assert_eq!(resolve_domain(&conn_plain(), &req), Some("api.example.com".to_string()));

        // 明文：纯域名（无端口）。
        let req = http::Request::builder()
            .header("host", "api.example.com")
            .body(()).unwrap();
        assert_eq!(resolve_domain(&conn_plain(), &req), Some("api.example.com".to_string()));

        // 明文：IPv6 [::1]:80 形态剥端口保留地址。
        let req = http::Request::builder()
            .header("host", "[::1]:8080")
            .body(()).unwrap();
        assert_eq!(resolve_domain(&conn_plain(), &req), Some("[::1]".to_string()));

        // 明文：Host 缺失 → None（503 路径，决策 2）。
        let req = http::Request::builder().body(()).unwrap();
        assert_eq!(resolve_domain(&conn_plain(), &req), None);

        // 明文：Host 空值 → None。
        let req = http::Request::builder()
            .header("host", "  ")
            .body(()).unwrap();
        assert_eq!(resolve_domain(&conn_plain(), &req), None);
    }
}
