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

use agentsandbox_inference::{
    InferenceModification, InferenceRequest, InferenceResult, InferenceRouteResult,
    InferenceRouter, ModifyAction, ModifyTarget,
};
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
use crate::model::{
    Action, AuditEntryType, AuditLogEntry, Protocol, Reason, SCENARIO_LIB,
};
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
    /// 推理路由裁决器（默认 [`crate::inference_uds::UdsRouteDispatcher`]
    /// 双模式：env `UDS_PATH` → UDS 远程 / 未设 → 本地真实库
    /// （`agentsandbox_inference::default_router`——init 过则 AgentRouter，
    /// 否则 mock Forward））。
    pub inference_router: Arc<dyn InferenceRouter>,
}

impl ServeContext {
    /// 以默认参数构造（target timeout 30s，scenario "lib"，无推理路由；
    /// 裁决器 = UDS 双模式分发，本地实现 = 真实库优先（init 过则
    /// AgentRouter，未设则 mock 空实现——2026-09-17 真实库落地））。
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
            inference_router: Arc::new(crate::inference_uds::UdsRouteDispatcher::new(
                agentsandbox_inference::default_router(),
            )),
        }
    }

    /// 目标主机（覆盖或 SNI 域名；SNI 校验名恒为 SNI）。
    fn target_host(&self, sni: &str) -> std::borrow::Cow<'_, str> {
        self.target_host_override
            .as_deref()
            .map(std::borrow::Cow::Borrowed)
            .unwrap_or_else(|| std::borrow::Cow::Owned(sni.to_string()))
    }

    /// 解析目标端口（协议相关；2026-09-15 提取——连接逻辑与转发日志共用）。
    ///
    /// 优先级：测试注入 override > 请求级端口（h1 Host 头 / h2 authority，
    /// 2026-09-12）> 协议默认（明文 80 / TLS 443）。
    fn resolved_target_port(&self, conn: &ConnContext, host_port: Option<u16>) -> u16 {
        if conn.plaintext {
            self.target_port_override.or(host_port).unwrap_or(80)
        } else {
            self.target_port_override.or(host_port).unwrap_or(443)
        }
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
    // 0. 域名与端口解析（TLS=SNI 连接级、端口恒 443；明文=Host 头请求级
    //    ——缺失即 503，与无 SNI 对齐 fail-closed；Host 头可带端口——
    //    2026-09-09 目标端口维度输入与明文转发端口依据）。
    let Some((domain, host_port)) = resolve_host(&conn, &req) else {
        return Ok(config_missing_response(&ctx, &conn, &req, "-"));
    };
    // 目标端口：明文 = Host 显式端口缺省 80；TLS = 请求级端口（h1 Host
    // 头 / h2 authority——非默认端口客户端必携带）缺省 443（2026-09-12）。
    let target_port = if conn.plaintext {
        host_port.unwrap_or(80)
    } else {
        host_port.unwrap_or(443)
    };

    // 0.5 推理路由分流（AR-005）：命中路由列表（host+url 精确匹配）即
    //     完全旁通过滤引擎（不查容器配置/binary/求值——容器未配置也可
    //     路由），交推理路由外部库裁决；Upgrade 请求不参与（修改语义
    //     与隧道不兼容——走原管道）。
    if !is_upgrade_request(&req)
        && inference_route_matched(&ctx, &domain, req.uri().path())
    {
        return handle_inference(req, ctx, conn, domain, host_port).await;
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
        let meta = ReqMeta { container_id: &container_id, domain: &domain, method: req.method(), uri: req.uri(), target_ips: &None };
        let entry = deny_entry(&ctx, &conn, &meta, Reason::BinaryNotFound, None);
        return Ok(audit_deny(&entry, Reason::BinaryNotFound));
    }

    // 2.5 目标 IP 预解析（2026-09-09：条件性激活——仅含 IP 条件的配置
    //     触发 DNS 解析，带缓存；失败 → dns_resolve_error fail-closed）。
    let target_ips: Arc<Vec<std::net::IpAddr>> = if fc.has_ip_condition() {
        match resolve_target_ips(&domain, ctx.connector.timeout()).await {
            Some(ips) => ips,
            None => {
                crate::log_warn!("server", "dns resolve failed; blocked (fail-closed)");
                let meta = ReqMeta { container_id: &container_id, domain: &domain, method: req.method(), uri: req.uri(), target_ips: &None };
                let entry = deny_entry(&ctx, &conn, &meta, Reason::DnsResolveError, None);
                return Ok(audit_deny(&entry, Reason::DnsResolveError));
            }
        }
    } else {
        Arc::new(Vec::new())
    };
    let target_ip_str = if target_ips.is_empty() {
        None
    } else {
        // 审计 target_ip 字段（现状恒 None——2026-09-09 起填充解析集，
        // 逗号连接多 IP 完整记录）。
        Some(
            target_ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(","),
        )
    };

    // 3. 求值（K3，2026-09-16 Decision 返回：ruleset 链式——prio 降序
    //    host 匹配 → binaryrules（deny/alert 即决策）→ targetrules
    //    （首中即决策）→ default_policy；alert 标记随 Decision 携带）。
    let decision = evaluate(
        &container_id,
        &domain,
        req.method().as_str(),
        req.uri().path(),
        conn.binary_path.as_deref(),
        &target_ips,
        target_port,
        &fc,
    );
    let (action, reason, alert) = (decision.action, decision.reason, decision.alert);
    // 命中规则集标识（规则命中决策携带——随审计/告警条目输出）。
    let rule_id = decision.rule_id.as_deref();
    if action == Action::Deny {
        // 策略拒绝观测（info 级——release 可见；debug→info 升级，
        // 2026-09-15）。
        crate::log_info!(
            "server",
            "deny: host={} method={} path={} reason={:?} container={}",
            domain,
            req.method(),
            req.uri().path(),
            reason,
            container_id
        );
        let meta = ReqMeta { container_id: &container_id, domain: &domain, method: req.method(), uri: req.uri(), target_ips: &target_ip_str };
        let entry = deny_entry(&ctx, &conn, &meta, reason, rule_id);
        return Ok(audit_deny(&entry, reason));
    }

    // 4. Upgrade（h1）：101 升级后转纯隧道（本函数在 upgrade 前返回
    //    101 响应骨架——隧道由 on_upgrade 任务承接）。
    if is_upgrade_request(&req) {
        return handle_upgrade(
            req,
            ctx,
            conn,
            domain,
            container_id,
            reason,
            alert,
            rule_id,
            host_port,
            target_ip_str,
        )
        .await;
    }

    // 5. allow：目标连接 + 转发 + 流式回传 + 审计（真实 status_code——Q6 修复）。
    //    body 装箱为统一出站形态（流式透传——零缓冲；与推理路由缓冲
    //    body 共用转发路径）。
    let req = req.map(|b| {
        b.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            .boxed()
    });
    forward_request(
        req,
        ctx,
        conn,
        domain,
        container_id,
        reason,
        alert,
        rule_id,
        host_port,
        target_ip_str,
    )
    .await
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
/// 裁决三态（[`InferenceResult`]）：
/// - Block → 403 + 审计 deny（status=0，reason=inference_route）；
/// - Forward → 原样重建缓冲请求（修改列表忽略）→ 统一转发；
/// - Modified → 应用修改列表（header 添加/修改 + body 整体替换，见
///   [`apply_inference_modifications`]）→ 重建 → 统一转发
///   （Content-Length 按最终 body 覆写，审计 allow + 真实 status）。
///
/// body 缓冲失败/超时：运行日志 warn + 503 关闭，不产出审计（无流量
/// 通过——与 TLS 层失败仅日志的先例一致）。
async fn handle_inference(
    req: Request<Incoming>,
    ctx: Arc<ServeContext>,
    conn: Arc<ConnContext>,
    domain: String,
    host_port: Option<u16>,
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

    // 2. 外部库裁决——spawn_blocking 承载（本地实现可能重计算；UDS
    //    模式为阻塞 I/O——均不得占用 async worker 线程）。
    //    外部库不构造请求——返回决策码 + 修改列表，proxy 统一应用。
    //    入参 body 为 lossy UTF-8 文本（仅库可见性；Forward 路径转发
    //    原始 Bytes 保真，二进制 body 不被 U+FFFD 破坏）。
    let route_req = InferenceRequest {
        headers: parts.headers.clone(),
        body: String::from_utf8_lossy(&body).into_owned(),
    };
    // 调试观测（debug 级——release 构建过滤）：推理路由输入全量
    //（headers + body；body 为库可见的 lossy 文本）。
    crate::log_debug!(
        "server",
        "inference route input: headers={} body={}",
        format_headers_for_log(&route_req.headers),
        route_req.body
    );
    let router = ctx.inference_router.clone();
    let decision = tokio::task::spawn_blocking(move || router.route(route_req)).await.unwrap_or_else(|_| {
        crate::log_warn!("server", "inference route task panicked; blocked");
        InferenceRouteResult {
            result: InferenceResult::Block,
            modifications: Vec::new(),
        }
    });

    // 调试观测（debug 级）：裁决返回全量——决策码 + 逐条修改项
    //（action/target/key/value；鉴权头含凭据明文，仅限 debug 构建）。
    crate::log_debug!(
        "server",
        "inference route output: result={:?} modifications={}",
        decision.result,
        decision
            .modifications
            .iter()
            .map(|m| {
                format!(
                    "[action={:?} target={:?} key={} value={}]",
                    m.action, m.target, m.key, m.value
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    );

    // 裁决结果观测（2026-09-15 info 级——release 可见；辅助定位推理
    // 路由分流：决策码 + 修改条数（Forward 忽略列表/Block 阻断/Modified
    // 应用——经 forward_request 的 reason=inference_route 完成日志闭环）。
    crate::log_info!(
        "server",
        "inference decision: result={} modifications={} container={} host={}",
        match decision.result {
            InferenceResult::Forward => "forward",
            InferenceResult::Modified => "modified",
            InferenceResult::Block => "block",
        },
        decision.modifications.len(),
        container_id,
        domain
    );

    // 3. 决策分发：Block → 403 + 审计 deny；Forward → 原样；Modified →
    //    应用修改列表（method/uri 不可改——新契约收敛为仅 header/body）。
    let (headers, body) = match decision.result {
        InferenceResult::Block => {
            let meta = ReqMeta {
                container_id: &container_id,
                domain: &domain,
                method: &parts.method,
                uri: &parts.uri,
                target_ips: &None,
            };
            let entry = deny_entry(&ctx, &conn, &meta, Reason::InferenceRoute, None);
            return Ok(audit_deny(&entry, Reason::InferenceRoute));
        }
        // Forward：修改列表忽略（防御性——外部库应为空列表）。
        InferenceResult::Forward => (parts.headers, body),
        InferenceResult::Modified => {
            let applied = apply_inference_modifications(parts.headers, body, &decision.modifications);
            // 调试观测（debug 级）：应用修改后的最终请求形态（headers +
            // body——转发到目标的实际内容）。
            crate::log_debug!(
                "server",
                "inference request after modifications: headers={} body={}",
                format_headers_for_log(&applied.0),
                String::from_utf8_lossy(&applied.1)
            );
            // 修改应用观测（2026-09-15）：应用后 body 长度（info 级不打印
            // 内容——日志安全；全量内容观测见上方 debug 级）。
            crate::log_info!(
                "server",
                "inference modifications applied: entries={} body_len={} container={}",
                decision.modifications.len(),
                applied.1.len(),
                container_id
            );
            applied
        }
    };
    let body_len = body.len();
    let mut fwd_req = match build_buffered_request(parts.method, parts.uri, headers, body) {
        Ok(r) => r,
        // 程序不变量破坏（已解析类型 + Full body 理论不可失败）——防御性 502。
        Err(_) => return Ok(box_body(block_response(Reason::TargetTlsError))),
    };
    normalize_buffered_request(&mut fwd_req, body_len);

    // 4. 统一转发路径（目标连接 + 转发 + 审计 allow + 真实 status +
    //    流式回传；reason=inference_route；host_port 透传——与非推理
    //    路径端口语义一致，2026-09-15 日志观测暴露的传递缺失修复）。
    forward_request(fwd_req, ctx, conn, domain, container_id, Reason::InferenceRoute, false, None, host_port, None).await
}

/// 调试日志用请求头格式化：`[name: value; ...]`（多值头逐值展开；
/// 非 UTF-8 头值以 `<binary>` 占位）。
fn format_headers_for_log(headers: &http::HeaderMap) -> String {
    let pairs: Vec<String> = headers
        .iter()
        .map(|(name, value)| {
            format!(
                "{}: {}",
                name.as_str(),
                value.to_str().unwrap_or("<binary>")
            )
        })
        .collect();
    format!("[{}]", pairs.join("; "))
}

/// 应用外部库修改列表（仅 result=Modified 路径调用）。
///
/// 语义（2026-09-05 契约）：
/// - **Header + Add(1)**：key 已存在 → **跳过**（只加新头）；
/// - **Header + Modify(2)**：key 不存在 → **补写**（upsert）；存在 → 替换；
/// - **Header 非法项**（头名/头值构造失败，如值含 `\n`）：防御性跳过
///   + warn 日志（单条失败不阻断整体——其余条目继续应用）；
/// - **Body（任意 action）**：**整体替换**（key 忽略；多条按列表序覆盖，
///   最后一条生效）。
fn apply_inference_modifications(
    mut headers: http::HeaderMap,
    mut body: bytes::Bytes,
    modifications: &[InferenceModification],
) -> (http::HeaderMap, bytes::Bytes) {
    for m in modifications {
        match m.target {
            ModifyTarget::Header => {
                let (Ok(name), Ok(value)) = (
                    http::HeaderName::from_bytes(m.key.as_bytes()),
                    http::HeaderValue::from_str(&m.value),
                ) else {
                    // 非法头名/头值（外部库产出缺陷）——跳过该条并告警
                    //（不含 key/value 内容——日志安全）。
                    crate::log_warn!("server", "inference route: invalid header modification skipped");
                    continue;
                };
                match m.action {
                    // Add：已存在跳过（只加新头）。
                    ModifyAction::Add => {
                        if !headers.contains_key(&name) {
                            headers.insert(name, value);
                        }
                    }
                    // Modify：upsert（不存在补写）。
                    ModifyAction::Modify => {
                        headers.insert(name, value);
                    }
                }
            }
            ModifyTarget::Body => {
                // key 与 action 均忽略——整体替换，最后一条生效。
                body = bytes::Bytes::from(m.value.clone());
            }
        }
    }
    (headers, body)
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
///
/// `alert`：default_policy=alert 的放行——审计条目标记告警（type=1）。
#[allow(clippy::too_many_arguments)] // 转发管道上下文（请求/连接/决策/维度产物传递）。
async fn forward_request(
    req: Request<ReqBody>,
    ctx: Arc<ServeContext>,
    conn: Arc<ConnContext>,
    domain: String,
    container_id: String,
    reason: Reason,
    alert: bool,
    rule_id: Option<&str>,
    host_port: Option<u16>,
    target_ip_str: Option<String>,
) -> Result<Response<B>, std::convert::Infallible> {
    let timeout = ctx.connector.timeout();
    let (method, uri) = (req.method().clone(), req.uri().clone());
    let meta = ReqMeta { container_id: &container_id, domain: &domain, method: &method, uri: &uri, target_ips: &target_ip_str };
    // 转发观测辅助（2026-09-15）：host/port 与连接逻辑同源
    //（resolved_target_port——测试 override > 请求级端口 > 协议默认）。
    let fwd_port = ctx.resolved_target_port(&conn, host_port);
    let fwd_host = ctx.target_host(&domain).into_owned();

    // 懒建目标连接（单一 deadline；K9 三类错误 → 502 + 审计 deny）。
    let (sender, conn_handle) = match connect_target(&ctx, &conn, &domain, host_port, timeout).await {
        Ok(x) => x,
        Err(e) => {
            crate::log_warn!(
                "server",
                "target connect failed: host={} port={} reason={:?} container={}",
                fwd_host,
                fwd_port,
                e.reason(),
                container_id
            );
            let entry = deny_entry(&ctx, &conn, &meta, e.reason(), rule_id);
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
            crate::log_warn!(
                "server",
                "target send failed: host={} port={} container={}",
                fwd_host,
                fwd_port,
                container_id
            );
            return Ok(box_body(block_response(Reason::TargetTlsError)));
        }
    };
    let status = response.status();

    // 审计（真实 status_code——Q6 修复；先于响应回传发起方：审计 Err
    // 时不回传，无未审计流量）。
    if let Some(blocked) = audit_allow(&allow_entry(
        &ctx,
        &conn,
        &meta,
        reason,
        status.as_u16(),
        alert,
        rule_id,
    )) {
        conn_handle.abort();
        return Ok(blocked);
    }
    // 转发完成观测（info 级——release 构建可见；辅助定位主链路：
    // host/port/响应码/决策原因/容器。debug→info 升级 + 字段扩展，
    // 2026-09-15）。
    crate::log_info!(
        "server",
        "forward: host={} port={} method={} path={} status={} reason={:?} container={}",
        fwd_host,
        fwd_port,
        method,
        uri.path(),
        status.as_u16(),
        reason,
        container_id
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
    host_port: Option<u16>,
    timeout: Duration,
) -> Result<
    (
        hyper::client::conn::http1::SendRequest<ReqBody>,
        tokio::task::JoinHandle<()>,
    ),
    crate::forward::TargetConnectError,
> {
    let stream = if conn.plaintext {
        // 明文：纯 TCP 连接目标（端口优先级见 resolved_target_port）。
        let port = ctx.resolved_target_port(conn, host_port);
        let tcp = tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect((ctx.target_host(domain).as_ref(), port)),
        )
        .await
        .map_err(|_| crate::forward::TargetConnectError::Timeout)?
        .map_err(map_plain_connect_error)?;
        let _ = tcp.set_nodelay(true);
        TargetStream::Plain(tcp)
    } else {
        // TLS：经 TargetConnector（K9 三类错误映射 + 单一 deadline；
        // ALPN 与 MITM 协商一致，D5）。端口优先级见 resolved_target_port。
        let port = ctx.resolved_target_port(conn, host_port);
        let alpn = if ctx.connector_alpn_h2() {
            vec!["h2".to_string(), "http/1.1".to_string()]
        } else {
            vec!["http/1.1".to_string()]
        };
        let tls = ctx
            .connector
            .connect(&ctx.target_host(domain), port, domain, &alpn)
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
#[allow(clippy::too_many_arguments)] // 升级管道上下文（同 forward_request）。
async fn handle_upgrade(
    req: Request<Incoming>,
    ctx: Arc<ServeContext>,
    conn: Arc<ConnContext>,
    domain: String,
    container_id: String,
    reason: Reason,
    alert: bool,
    rule_id: Option<&str>,
    host_port: Option<u16>,
    target_ip_str: Option<String>,
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
    let meta = ReqMeta { container_id: &container_id, domain: &domain, method: &method, uri: &uri, target_ips: &target_ip_str };
    let up_port = ctx.resolved_target_port(&conn, host_port);
    let up_host = ctx.target_host(&domain).into_owned();

    // 1. 目标连接（协议分流：TLS→rustls 流；明文→纯 TCP；K9 → 502）。
    let mut target = match connect_upgrade_target(&ctx, &conn, &domain, host_port, timeout).await {
        Ok(t) => t,
        Err(e) => {
            crate::log_warn!(
                "server",
                "upgrade target connect failed: host={} port={} reason={:?} container={}",
                up_host,
                up_port,
                e.reason(),
                container_id
            );
            let entry = deny_entry(&ctx, &conn, &meta, e.reason(), rule_id);
            return Ok(audit_deny(&entry, e.reason()));
        }
    };

    // 2. 手工写出原始升级请求 → 3. 读目标响应头。
    if write_upgrade_request(&mut target, &method, &uri, &headers).await.is_err() {
        crate::log_warn!(
            "server",
            "upgrade target write failed: host={} port={} container={}",
            up_host,
            up_port,
            container_id
        );
        return Ok(box_body(block_response(Reason::TargetTlsError)));
    }
    let resp_buf = match read_target_head(&mut target, timeout).await {
        Ok(buf) => buf,
        Err(_) => {
            crate::log_warn!(
                "server",
                "upgrade target read failed: host={} port={} container={}",
                up_host,
                up_port,
                container_id
            );
            return Ok(box_body(block_response(Reason::TargetTlsError)));
        }
    };
    let status = parse_status_line(&resp_buf);

    // 4. 审计（升级连接 status；先于 101 回传发起方——fail-closed）。
    if let Some(blocked) = audit_allow(&allow_entry(
        &ctx, &conn, &meta, reason, status, alert, rule_id,
    )) {
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
    host_port: Option<u16>,
    timeout: Duration,
) -> Result<TargetStream, crate::forward::TargetConnectError> {
    if conn.plaintext {
        let port = ctx.resolved_target_port(conn, host_port);
        let tcp = tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect((ctx.target_host(domain).as_ref(), port)),
        )
        .await
        .map_err(|_| crate::forward::TargetConnectError::Timeout)?
        .map_err(map_plain_connect_error)?;
        let _ = tcp.set_nodelay(true);
        Ok(TargetStream::Plain(tcp))
    } else {
        // TLS：端口优先级见 resolved_target_port。
        let port = ctx.resolved_target_port(conn, host_port);
        let tls = ctx
            .connector
            .connect(
                &ctx.target_host(domain),
                port,
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

/// 审计条目组装（完整字段；entry_type 见 [`crate::model::AuditEntryType`]）。
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
    entry_type: crate::model::AuditEntryType,
    rule_id: Option<&str>,
) -> AuditLogEntry {
    AuditLogEntry {
        timestamp: crate::model::utc_now_millis(),
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
        entry_type,
        rule_id: rule_id.map(str::to_string),
    }
}

// ===== 审计与阻断样板辅助（deny/allow 分支的共性收敛；纯提取，行为不变）=====

/// 请求元数据摘要（审计条目组装的通用入参形态）。
struct ReqMeta<'a> {
    container_id: &'a str,
    /// 求值/审计域名（TLS=SNI；明文=Host 头——见 [`resolve_host`]）。
    domain: &'a str,
    method: &'a Method,
    uri: &'a Uri,
    /// 目标 IP 审计串（解析集逗号连接；未解析 None——2026-09-09 起
    /// 填充，此前恒 None）。
    target_ips: &'a Option<String>,
}

/// deny 路径审计条目（status=0、source_ip=None、type=Audit——
/// 求值拒绝/binary 缺失/目标连接失败的统一字段形态）。
fn deny_entry(
    ctx: &ServeContext,
    conn: &ConnContext,
    meta: &ReqMeta<'_>,
    reason: Reason,
    rule_id: Option<&str>,
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
        meta.target_ips.as_deref(),
        crate::model::AuditEntryType::Audit,
        rule_id,
    )
}

/// allow 路径审计条目（source_ip=发起方对端 IP；status 为目标响应码——
/// 普通转发为真实 status_code，Upgrade 为 101）。
///
/// `alert`：default_policy=alert 且黑白未命中的放行——条目标记告警
///（type=1，2026-09-09）；其余常规审计（type=0）。`rule_id`：命中
/// 规则集的语义标识（规则命中决策携带；默认策略/旁路类 None）。
fn allow_entry(
    ctx: &ServeContext,
    conn: &ConnContext,
    meta: &ReqMeta<'_>,
    reason: Reason,
    status: u16,
    alert: bool,
    rule_id: Option<&str>,
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
        meta.target_ips.as_deref(),
        if alert {
            crate::model::AuditEntryType::Alert
        } else {
            crate::model::AuditEntryType::Audit
        },
        rule_id,
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
        AuditEntryType::Audit,
        None,
    );
    audit_deny(&entry, Reason::ConfigNotFound)
}

/// 求值/审计域名解析（每请求一次——明文路径 Host 可变，不缓存于连接级）。
///
/// 返回 `(域名, 显式端口)`：
/// - **TLS** = (SNI 域名, 请求级端口)——域名取 SNI（连接级权威）；
///   端口取解密后 HTTP 层（2026-09-12）：h1 的 `Host: host:port` 头显式
///   端口 ∪ h2 的 `:authority` 归一化结果（`req.uri().port_u16()`——
///   h2 无 Host 头、h1 无 authority，互补覆盖）。RFC 9110 §7.2：非默认
///   端口客户端 MUST 在 host/:authority 携带——默认端口省略（调用方
///   兜底 443），规范客户端下覆盖完备；
///
/// - **明文** = (Host 域名, 显式端口)——`Host: api.example.com:8443` 的
///   端口提取为求值目标端口维度输入与明文转发端口依据（缺省由调用方
///   补 80）。
///
/// 域名缺失/空 → None（调用方按 config_not_found 语义 503 拒绝——
/// 2026-09-01 决策 2，与无 SNI 对齐）。
fn resolve_host<T>(conn: &ConnContext, req: &Request<T>) -> Option<(String, Option<u16>)> {
    if let Some(sni) = &conn.sni {
        // TLS：域名取 SNI；端口取解密后请求层（h1 Host 头 / h2 authority
        // ——二者至多其一存在，均无则 None）。
        let port = tls_request_port(req);
        return Some((sni.clone(), port));
    }
    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())?
        .trim();
    if host.is_empty() {
        return None;
    }
    // 剥端口：IPv6 [::1]:80 形态保留括号内地址；域名/IPv4 host:port 剥
    // 后缀（端口非数字时不视为端口——域名含非数字冒号仅 IPv6 形态）。
    if host.starts_with('[') {
        // [::1]:8080 → ([::1], 8080)；[::1] → ([::1], None)。
        let (bare, port) = match host.split_once(']') {
            Some((bare, rest)) => {
                let port = rest.strip_prefix(':').and_then(|p| p.parse().ok());
                (format!("{bare}]"), port)
            }
            None => (host.to_string(), None),
        };
        Some((bare, port))
    } else {
        match host.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(port) => Some((h.to_string(), Some(port))),
                // 端口段非数字（如裸 IPv6 无括号——畸形 Host）：整串为
                // 域名处理。
                Err(_) => Some((host.to_string(), None)),
            },
            None => Some((host.to_string(), None)),
        }
    }
}

/// TLS 路径请求级端口提取（h1 Host 头 ∪ h2 URI authority 互补）。
///
/// h2 经 hyper 归一化：`:authority: host:port` → `req.uri()` 的 authority
/// 部分（Host 头为空）——从 `port_u16()` 取；h1 无 authority，从 Host 头
/// 剥端口。二者至多其一存在；均无（默认端口省略）→ None。
fn tls_request_port<T>(req: &Request<T>) -> Option<u16> {
    // h2（或显式 absolute-form URI）：authority 携带端口。
    if let Some(port) = req.uri().port_u16() {
        return Some(port);
    }
    let host = req
        .headers()
        .get(http::header::HOST)?
        .to_str()
        .ok()?
        .trim();
    if host.starts_with('[') {
        // IPv6 [::1]:8443 → 闭括号后端口段直接解析（已是纯端口串）。
        let rest = host.strip_prefix('[')?;
        let (_, tail) = rest.split_once(']')?;
        return tail.strip_prefix(':').and_then(|p| p.parse().ok());
    }
    // 域名/IPv4 `host:port` 剥后缀。
    host.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok())
}

/// DNS 预解析（2026-09-09：目标 IP 维度条件性激活）。
///
/// 仅当配置含 IP 条件（[`FilterConfig::has_ip_condition`]）时调用——
/// 无 IP 条件的配置零解析开销。带域名→IP 集缓存（容量 1024，满时整体
/// 清空——容器内域名变更低频，避免 LRU 复杂度）；deadline 约束。
/// 失败（超时/无记录/空结果）→ None → 调用方 fail-closed
///（`Reason::DnsResolveError`）。
async fn resolve_target_ips(domain: &str, timeout: Duration) -> Option<Arc<Vec<std::net::IpAddr>>> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, Arc<Vec<std::net::IpAddr>>>>,
    > = std::sync::OnceLock::new();
    const CACHE_CAP: usize = 1024;

    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let cached = {
        let guard = cache.lock().unwrap_or_else(|p| p.into_inner());
        guard.get(domain).cloned()
    };
    if let Some(hit) = cached {
        return Some(hit);
    }
    // 解析（deadline 约束；lookup_host 需要端口形式——用 0 端口仅取 IP）。
    let lookup = tokio::time::timeout(
        timeout,
        tokio::net::lookup_host((domain, 0)),
    )
    .await
    .ok()?;
    let ips: Vec<std::net::IpAddr> = lookup
        .ok()?
        .map(|addr| addr.ip())
        .collect();
    if ips.is_empty() {
        return None;
    }
    let ips = Arc::new(ips);
    let mut guard = cache.lock().unwrap_or_else(|p| p.into_inner());
    if guard.len() >= CACHE_CAP {
        guard.clear(); // 容量上限整体清空（简单策略）。
    }
    guard.insert(domain.to_string(), ips.clone());
    Some(ips)
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

    // 修改列表应用语义（2026-09-05 契约）：header add 跳过/modify 补写、
    // 非法头跳过、body 整体替换最后一条生效。
    //（串行锁：非法条目分支发出全局日志——与 logging 计数测试互斥。）
    #[test]
    fn inference_modifications_application() {
        let _serial = crate::logging::testing::serial_guard();

        let header_mod = |action: ModifyAction, key: &str, value: &str| InferenceModification {
            action,
            target: ModifyTarget::Header,
            key: key.to_string(),
            value: value.to_string(),
        };
        let body_mod = |value: &str| InferenceModification {
            action: ModifyAction::Modify, // action 对 body 无区分。
            target: ModifyTarget::Body,
            key: String::new(),
            value: value.to_string(),
        };

        // 基础 headers：x-test 已存在。
        let mut headers = http::HeaderMap::new();
        headers.insert("x-test", http::HeaderValue::from_static("orig"));
        let body = bytes::Bytes::from_static(b"orig-body");

        // Add 已存在 → 跳过；Add 新头 → 写入。
        let (h, _) = apply_inference_modifications(
            headers.clone(),
            body.clone(),
            &[
                header_mod(ModifyAction::Add, "x-test", "must-skip"),
                header_mod(ModifyAction::Add, "x-trace", "t1"),
            ],
        );
        assert_eq!(h.get("x-test").unwrap(), "orig");
        assert_eq!(h.get("x-trace").unwrap(), "t1");

        // Modify 不存在 → 补写；存在 → 替换。
        let (h, _) = apply_inference_modifications(
            headers.clone(),
            body.clone(),
            &[
                header_mod(ModifyAction::Modify, "x-test", "replaced"),
                header_mod(ModifyAction::Modify, "x-new", "upserted"),
            ],
        );
        assert_eq!(h.get("x-test").unwrap(), "replaced");
        assert_eq!(h.get("x-new").unwrap(), "upserted");

        // 非法头值（含 \n）→ 跳过该条，其余条目继续应用。
        let (h, _) = apply_inference_modifications(
            headers.clone(),
            body.clone(),
            &[
                header_mod(ModifyAction::Add, "x-bad", "bad\nvalue"),
                header_mod(ModifyAction::Add, "x-good", "ok"),
            ],
        );
        assert!(h.get("x-bad").is_none());
        assert_eq!(h.get("x-good").unwrap(), "ok");

        // Body 整体替换：多条按序覆盖，最后一条生效；key 忽略。
        let (_, b) = apply_inference_modifications(
            headers.clone(),
            body.clone(),
            &[body_mod("first"), body_mod("second")],
        );
        assert_eq!(b, bytes::Bytes::from_static(b"second"));

        // 空修改列表：headers/body 原样。
        let (h, b) = apply_inference_modifications(headers, body.clone(), &[]);
        assert_eq!(h.get("x-test").unwrap(), "orig");
        assert_eq!(b, body);
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

    // 审计条目类型组装：alert 标记 → type=Alert(1)；常规 allow/deny →
    // Audit(0)（2026-09-09 default_policy=alert 场景）。
    #[test]
    fn audit_entry_type_assembly() {
        let registry = Arc::new(Registry::new());
        let cert_services = Arc::new(crate::cert::ContainerCertServices::new());
        let connector = Arc::new(TargetConnector::new(
            Arc::new(rustls::RootCertStore::empty()),
            Duration::from_secs(30),
        ));
        let ctx = ServeContext::new(registry, cert_services, connector);
        let conn = ConnContext {
            container_id: "c-test".to_string(),
            binary_path: None,
            sni: Some("a.com".to_string()),
            plaintext: false,
            peer: "127.0.0.1:9000".parse().unwrap(),
        };
        let method = Method::GET;
        let uri: Uri = "/x".parse().unwrap();
        let meta = ReqMeta {
            container_id: "c-test",
            domain: "a.com",
            method: &method,
            uri: &uri,
            target_ips: &None,
        };

        // alert 标记 → type=Alert + action=allow。
        let entry = allow_entry(&ctx, &conn, &meta, Reason::DefaultPolicy, 200, true, None);
        assert_eq!(entry.entry_type, AuditEntryType::Alert);
        assert_eq!(entry.action, Action::Allow);
        assert_eq!(entry.reason, Reason::DefaultPolicy);
        assert_eq!(entry.status_code, 200);

        // 常规 allow → type=Audit。
        let entry = allow_entry(&ctx, &conn, &meta, Reason::WhitelistMatch, 200, false, None);
        assert_eq!(entry.entry_type, AuditEntryType::Audit);

        // deny 路径恒 Audit。
        let entry = deny_entry(&ctx, &conn, &meta, Reason::BlacklistMatch, None);
        assert_eq!(entry.entry_type, AuditEntryType::Audit);
        assert_eq!(entry.action, Action::Deny);
    }

    // Host 解析：纯域名/带端口/IPv6 带端口/缺失/空值（域名 + 端口——
    // 2026-09-09 端口保留）。
    #[test]
    fn resolve_host_from_host_header() {
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

        // TLS：SNI 域名（连接级权威）+ h1 Host 头显式端口（2026-09-12
        // ——TLS 端口从解密后请求层提取；Host 域名不参与）。
        let req = http::Request::builder()
            .header("host", "other.com:8080")
            .body(()).unwrap();
        assert_eq!(
            resolve_host(&conn_tls("sni.com"), &req),
            Some(("sni.com".to_string(), Some(8080)))
        );

        // TLS：h2 authority 端口（URI absolute-form——hyper 将
        // :authority 归一化到 uri；Host 头缺省）。
        let req = http::Request::builder()
            .uri("https://sni.com:8443/v1/chat")
            .body(()).unwrap();
        assert_eq!(
            resolve_host(&conn_tls("sni.com"), &req),
            Some(("sni.com".to_string(), Some(8443)))
        );

        // TLS：URI authority 与 Host 头并存时 URI 优先（h2 形态归一）。
        let req = http::Request::builder()
            .uri("https://sni.com:9000/x")
            .header("host", "other.com:7000")
            .body(()).unwrap();
        assert_eq!(
            resolve_host(&conn_tls("sni.com"), &req),
            Some(("sni.com".to_string(), Some(9000)))
        );

        // TLS：默认端口省略（无 Host 端口、无 authority 端口）→ None
        //（调用方兜底 443——RFC 9110 §7.2 规范客户端覆盖完备）。
        let req = http::Request::builder()
            .uri("/v1/chat")
            .header("host", "sni.com")
            .body(()).unwrap();
        assert_eq!(
            resolve_host(&conn_tls("sni.com"), &req),
            Some(("sni.com".to_string(), None))
        );

        // TLS：Host 头 IPv6 带端口形态。
        let req = http::Request::builder()
            .header("host", "[::1]:8443")
            .body(()).unwrap();
        assert_eq!(
            resolve_host(&conn_tls("sni.com"), &req),
            Some(("sni.com".to_string(), Some(8443)))
        );

        // 明文：Host 带端口（域名 + 端口提取——端口维度输入）。
        let req = http::Request::builder()
            .header("host", "api.example.com:8080")
            .body(()).unwrap();
        assert_eq!(
            resolve_host(&conn_plain(), &req),
            Some(("api.example.com".to_string(), Some(8080)))
        );

        // 明文：纯域名（无端口 → None）。
        let req = http::Request::builder()
            .header("host", "api.example.com")
            .body(()).unwrap();
        assert_eq!(
            resolve_host(&conn_plain(), &req),
            Some(("api.example.com".to_string(), None))
        );

        // 明文：IPv6 [::1]:8080 形态（保留地址 + 端口）。
        let req = http::Request::builder()
            .header("host", "[::1]:8080")
            .body(()).unwrap();
        assert_eq!(
            resolve_host(&conn_plain(), &req),
            Some(("[::1]".to_string(), Some(8080)))
        );

        // 明文：IPv6 裸地址（无端口）。
        let req = http::Request::builder()
            .header("host", "[::1]")
            .body(()).unwrap();
        assert_eq!(
            resolve_host(&conn_plain(), &req),
            Some(("[::1]".to_string(), None))
        );

        // 明文：Host 缺失 → None（503 路径，决策 2）。
        let req = http::Request::builder().body(()).unwrap();
        assert_eq!(resolve_host(&conn_plain(), &req), None);

        // 明文：Host 空值 → None。
        let req = http::Request::builder()
            .header("host", "  ")
            .body(()).unwrap();
        assert_eq!(resolve_host(&conn_plain(), &req), None);
    }
}
