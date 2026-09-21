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

//! 公共 API 门面（容器端点模型，2026-09-01 API 重设计：单容器实现 +
//! 多容器扩展预留）。
//!
//! 4 个配置 API + 1 个初始化 API：
//! - [`set_container_config`] / [`remove_container_policy`]：按容器键控的
//!   过滤配置（同 id 覆盖 / 按 id 删除）；
//! - [`set_container_ca`]：按容器键控的 MITM CA（双 PEM 结构体）；
//! - [`proxy_init`]：一次性初始化——绑定 forwarding 端点（接入完整服务
//!   管道；容器身份经 [`register_binary_resolver`] 回调连接级运行时解析）；
//! - [`register_binary_resolver`] / [`register_log_sink`]：进程级回调注册。
//!
//! 配置与 CA 均可独立调用（每请求实时查表）；未 set 配置或 CA 的容器
//! 流量 fail-closed 拒绝（503 / TLS 层关闭）。
//!
//! K10 结构校验：filter_config 合法性由门面层承接（uri 模式等，
//! `validate_filter_config`——crate 内部面）。

use std::sync::{Arc, RwLock};

use agentsandbox_inference::ApiKeyError;

use crate::error::{BindError, CaError, ConfigError};
use crate::logging::LogSink;
use crate::model::{CaCert, FilterConfig, ProxyConfig};
use crate::registry::{Registry, Resolver};

/// 内部运行态抽象（委托分发面；生产=Registry 委托实现，
/// 测试=fake 注入——测试注入缝）。
#[doc(hidden)]
pub trait RuntimeRegistry: Send + Sync {
    /// 设置容器过滤配置。
    fn set_container_config(&self, container_id: &str, fc: FilterConfig) -> Result<(), ConfigError>;
    /// 清除容器过滤配置。
    fn remove_container_policy(&self, container_id: &str) -> Result<(), ConfigError>;
    /// 设置容器 CA。
    fn set_container_ca(&self, container_id: &str, ca: CaCert) -> Result<(), CaError>;
    /// 注册 binary 解析回调。
    fn register_binary_resolver(&self, resolver: Resolver);
    /// 注册日志回调。
    fn register_log_sink(&self, sink: LogSink);
}

/// 全局运行态（惰性初始化；测试注入缝见 `testing` 模块——feature 门禁）。
static RUNTIME: RwLock<Option<Arc<dyn RuntimeRegistry>>> = RwLock::new(None);

/// 生产组件单例（set_container_* 与 proxy_init 的 serve 装配**共享同一份**
/// 运行态——proxy_init 前注入的配置/CA 状态在 serve 启动后连续生效）。
fn production_components() -> (Arc<Registry>, Arc<crate::cert::ContainerCertServices>) {
    static REGISTRY: std::sync::OnceLock<Arc<Registry>> = std::sync::OnceLock::new();
    static CERTS: std::sync::OnceLock<Arc<crate::cert::ContainerCertServices>> =
        std::sync::OnceLock::new();
    (
        REGISTRY.get_or_init(|| {
            Arc::new(Registry::new().with_config_validator(Arc::new(validate_filter_config)))
        })
        .clone(),
        CERTS.get_or_init(|| Arc::new(crate::cert::ContainerCertServices::new())).clone(),
    )
}

/// 取当前运行态（未初始化时惰性创建生产实现）。
fn runtime() -> Arc<dyn RuntimeRegistry> {
    let mut guard = crate::lock_util::recovered(RUNTIME.write(), "runtime");
    guard.get_or_insert_with(production_runtime).clone()
}

/// 生产运行态：Registry 委托 + 容器键控 CA 持有器。
struct RegistryRuntime {
    registry: Arc<Registry>,
    cert_services: Arc<crate::cert::ContainerCertServices>,
}

impl RuntimeRegistry for RegistryRuntime {
    fn set_container_config(
        &self,
        container_id: &str,
        fc: FilterConfig,
    ) -> Result<(), ConfigError> {
        self.registry.set_container_config(container_id, fc)
    }

    fn remove_container_policy(&self, container_id: &str) -> Result<(), ConfigError> {
        self.registry.remove_container_policy(container_id)
    }

    fn set_container_ca(&self, container_id: &str, ca: CaCert) -> Result<(), CaError> {
        // registry 记账 + cert_services 供证面同步（同一调用内更新——
        // serve 装配从 production_components() 读取，状态即时生效）。
        self.registry.set_container_ca(container_id, ca.clone())?;
        self.cert_services
            .set_ca(container_id, &ca)
            .map_err(|_| CaError::Invalid)
    }

    fn register_binary_resolver(&self, resolver: Resolver) {
        self.registry.register_binary_resolver(resolver);
    }

    fn register_log_sink(&self, sink: LogSink) {
        // 统一日志回调：安装到 logging 模块（激活回调路径——
        // 审计/运行日志全部经回调交付）。
        crate::logging::install_callback(sink);
    }
}

/// 生产运行态装配（共享组件单例——状态连续性）。
fn production_runtime() -> Arc<dyn RuntimeRegistry> {
    let (registry, cert_services) = production_components();
    Arc::new(RegistryRuntime {
        registry,
        cert_services,
    })
}

/// 设置容器过滤配置（同 id 覆盖）。
///
/// 参数校验：container_id 非空；结构经 K10 校验（uri 模式等）——非法返回
/// `ConfigError::Format` 且保持该容器旧配置（fail-closed）。
pub fn set_container_config(
    container_id: &str,
    fc: FilterConfig,
) -> Result<(), ConfigError> {
    if container_id.is_empty() {
        return Err(ConfigError::Format);
    }
    validate_filter_config(&fc)?;
    runtime().set_container_config(container_id, fc)
}

/// 清除容器过滤配置：无该容器配置返回 `ConfigError::NotFound`（幂等语义，
/// 调用方可忽略）；清除后该容器流量 fail-closed（config_not_found）。
pub fn remove_container_policy(container_id: &str) -> Result<(), ConfigError> {
    runtime().remove_container_policy(container_id)
}

/// 设置容器 CA（MITM 动态证书签发的 CA 来源；同 id 覆盖并清该容器
/// 证书缓存）。格式非法（PEM/X.509/PKCS#8 解析失败）返回
/// `CaError::Invalid`；未设置的容器 TLS 流量被拒（ca_error）。
pub fn set_container_ca(container_id: &str, ca: CaCert) -> Result<(), CaError> {
    runtime().set_container_ca(container_id, ca)
}

/// 注册连接身份解析回调（K7，2026-09-05 重定义）：重复注册覆盖。
///
/// 回调签名 `(source, target, protocol) -> Option<ResolverOutput>`：
/// - **source**：发起方地址（连接对端）；
/// - **target**：本地监听地址（流量到达的端点）；
/// - **protocol**：连接协议（当前统一 `Protocol::Tcp`）；
/// - 输出 `ResolverOutput { container_id, binary_path }`——容器身份
///   （配置/CA 查表键）+ 进程二进制路径（规则 binary 维度求值输入）。
///
/// 调用语义：**每连接一次**（accept 后同步调用，连接级缓存）；
/// 未注册 / 返回 None / container_id 空串 → 身份未解析——该连接
/// fail-closed（配置 503 / TLS 拒握手 / binary_not_found）。
pub fn register_binary_resolver(resolver: Resolver) {
    runtime().register_binary_resolver(resolver);
}

/// 注册统一日志回调（K13）：重复注册覆盖。回调承接全部日志类别
/// （审计 + 运行日志四级），由集成方自行处理（落盘/转发）。审计回调
/// 返回 Err 时转发管道 fail-closed 关闭连接（无未审计流量通过）。
pub fn register_log_sink(handler: LogSink) {
    runtime().register_log_sink(handler);
}

/// 设置/删除推理服务的 API key（2026-09-17，AR-005 配套管理面）。
///
/// 入参形态（serde）：
/// `{"action":"set|delete","items":[{"model_id":"GLM_53","api_key":"sk-112"}]}`
///
/// - **set**：有则更新、无则添加（upsert）；**delete**：按 `model_id`
///   删除（`api_key` 字段忽略；不存在幂等成功）；空 `items` = no-op；
/// - **双模式分发**（与推理路由裁决同模式，每调用读 env
///   [`ROUTE_ENV_VAR`](crate::inference_uds::ROUTE_ENV_VAR)）：
///   env 设置 → UDS 远程（`msg_type=1`，失败返回
///   [`ApiKeyError::Delivery`]——**可重试**，管理面操作不做流量面
///   fail-closed）；env 未设 → 本地打桩存储
///   （[`apply_api_key`](agentsandbox_inference::apply_api_key)——真实
///   外部库落地后替换）。
pub fn set_api_key(req: agentsandbox_inference::ApiKeyRequest) -> Result<(), ApiKeyError> {
    // 参数校验：set → model_id/api_key 均非空；delete → model_id 非空
    //（api_key 忽略）；空 items 短路成功。
    if !req.items.is_empty() {
        for item in &req.items {
            match req.action {
                agentsandbox_inference::ApiKeyAction::Set => {
                    if item.model_id.is_empty() || item.api_key.is_empty() {
                        return Err(ApiKeyError::Invalid);
                    }
                }
                agentsandbox_inference::ApiKeyAction::Delete => {
                    if item.model_id.is_empty() {
                        return Err(ApiKeyError::Invalid);
                    }
                }
            }
        }
    }
    let path = std::env::var_os(crate::inference_uds::ROUTE_ENV_VAR).filter(|v| !v.is_empty());
    match path {
        Some(path) => {
            let path = path.to_string_lossy().into_owned();
            crate::inference_uds::uds_api_key(&path, &req)
                .ok_or(ApiKeyError::Delivery)
        }
        None => agentsandbox_inference::apply_api_key(&req),
    }
}

/// proxy 初始化错误。
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ProxyInitError {
    /// proxy_init 已初始化（单容器模型下仅可调用一次）。
    #[error("already initialized")]
    AlreadyInitialized,
    /// forwarding 端点绑定失败（占用等）。
    #[error("forwarding bind: {0}")]
    ForwardingBind(BindError),
    /// 配置非法（container_id 空 / 端口 0 / 路由条目 host 或 url 空）。
    #[error("invalid endpoint")]
    InvalidEndpoint,
    /// 推理路由库初始化失败（目录不存在/配置非法等——细节仅运行日志，
    /// 不含路径；发生于一次性 guard 之前，修正配置后可重调）。
    #[error("inference init failed")]
    InferenceInit,
}

/// 全局初始化标记（proxy_init 一次性）。
static INITIALIZED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// proxy 初始化（一次性调用）。
///
/// - **forwarding 端点**：绑定并自动启动完整服务（MITM/过滤/审计/转发）；
///   容器身份经 [`register_binary_resolver`] 回调**连接级运行时解析**
///   （source/target/protocol → container_id + binary_path）；
/// - **inference_routes**：推理路由列表（host+url 精确匹配；命中即旁通
///   过滤引擎，交推理路由外部库裁决——AR-005；空列表 = 无分流）；
/// - **router_config_dir**：推理路由真实库初始化（AR-005）——
///   `Some(dir)` → `init(dir)`；`None` → 内嵌默认配置（`init_default`）。
///   初始化先于服务装配（`ServeContext::new` 的 `default_router()` 拾取
///   `AgentRouter`）。
///
/// 前置校验：端口非 0，路由条目 host/url 非空；推理库初始化失败返回
/// `ProxyInitError::InferenceInit`（guard 未消耗——修正后可重调）；重复
/// 调用返回 `ProxyInitError::AlreadyInitialized`。
pub fn proxy_init(config: &ProxyConfig) -> Result<(), ProxyInitError> {
    validate_endpoint(&config.forwarding)?;
    validate_inference_routes(&config.inference_routes)?;
    init_inference_router(config)?;
    if INITIALIZED.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return Err(ProxyInitError::AlreadyInitialized);
    }

    // forwarding 端点：绑定 + spawn serve。三阶段（bind / nonblocking /
    // tokio 注册）独立失败日志辅助定位（端口可打印——日志安全豁免；
    // io 错误消息不含路径）。注意：from_std 隐式要求当前线程处于
    // tokio runtime 上下文（含 IO driver）——缺失时 panic 而非返回 Err。
    let forward_addr = std::net::SocketAddr::new(config.forwarding.ip, config.forwarding.port);
    let forward_listener = match std::net::TcpListener::bind(forward_addr) {
        Ok(l) => l,
        Err(e) => {
            crate::log_error!(
                "facade",
                "forwarding bind failed on port {}: kind={:?} msg={e}",
                config.forwarding.port,
                e.kind()
            );
            return Err(map_forward_bind(e));
        }
    };
    // TcpListener 默认阻塞——转 tokio 需 nonblocking（serve 在 async 上下文）。
    if let Err(e) = forward_listener.set_nonblocking(true) {
        crate::log_error!(
            "facade",
            "forwarding listener set_nonblocking failed: kind={:?} msg={e}",
            e.kind()
        );
        return Err(ProxyInitError::InvalidEndpoint);
    }
    let forward_listener = match tokio::net::TcpListener::from_std(forward_listener) {
        Ok(l) => l,
        Err(e) => {
            crate::log_error!(
                "facade",
                "forwarding listener tokio registration failed: kind={:?} msg={e}",
                e.kind()
            );
            return Err(map_forward_bind(e));
        }
    };

    // 装配 ServeContext（共享生产组件单例——proxy_init 前注入的
    // set_container_* 状态连续生效）并启动 serve 任务。
    spawn_serve(forward_listener, config);
    Ok(())
}

/// spawn serve 任务（共享生产组件单例装配）。
fn spawn_serve(forward_listener: tokio::net::TcpListener, config: &ProxyConfig) {
    let (registry, cert_services) = production_components();

    // 目标信任锚：系统根（生产——真实目标站点验证）；连接超时 30s。
    let mut roots = rustls::RootCertStore::empty();
    if let Err(e) = load_system_roots(&mut roots) {
        crate::log_error!("facade", "system roots load failed: {e}");
    }
    let connector = Arc::new(crate::forward::TargetConnector::new(
        Arc::new(roots),
        std::time::Duration::from_secs(30),
    ));
    let mut serve_ctx = crate::server::ServeContext::new(registry, cert_services, connector);
    // 推理路由列表装配（router 默认装配在 ServeContext::new——真实库
    // 优先：crate init 过则 AgentRouter，否则 mock——2026-09-17）。
    serve_ctx.inference_routes = config.inference_routes.clone();
    let ctx = Arc::new(serve_ctx);
    tokio::spawn(async move {
        crate::server::serve(forward_listener, ctx).await;
    });
    crate::log_info!(
        "facade",
        "serve started on {}: {}",
        config.forwarding.ip,
        config.forwarding.port
    );
}

/// 端点参数校验。
fn validate_endpoint(endpoint: &crate::model::ContainerEndpoint) -> Result<(), ProxyInitError> {
    if endpoint.port == 0 {
        return Err(ProxyInitError::InvalidEndpoint);
    }
    Ok(())
}

/// 推理路由条目校验（host/url 非空——空条目无法命中任何请求，
/// 配置面拒绝防静默失效）。
fn validate_inference_routes(
    routes: &[crate::model::InferenceRoute],
) -> Result<(), ProxyInitError> {
    if routes.iter().any(|r| r.host.is_empty() || r.url.is_empty()) {
        return Err(ProxyInitError::InvalidEndpoint);
    }
    Ok(())
}

/// 推理路由真实库初始化（proxy_init 期，一次性 guard 之前）。
///
/// `Some(dir)` → `init(dir)`；`None` → 内嵌默认配置（`init_default`）。
/// 失败仅运行日志记录错误类别（Display 不含路径——日志安全），返回
/// [`ProxyInitError::InferenceInit`]；guard 未消耗，修正配置后可重调。
fn init_inference_router(config: &ProxyConfig) -> Result<(), ProxyInitError> {
    let result = match &config.router_config_dir {
        Some(dir) => agentsandbox_inference::init(dir),
        None => agentsandbox_inference::init_default(),
    };
    if let Err(e) = result {
        crate::log_error!("facade", "inference router init failed: {}", e);
        return Err(ProxyInitError::InferenceInit);
    }
    Ok(())
}

/// bind 错误映射（forwarding）。
fn map_forward_bind(e: std::io::Error) -> ProxyInitError {
    match e.kind() {
        std::io::ErrorKind::AddrInUse => ProxyInitError::ForwardingBind(BindError::PortInUse),
        _ => ProxyInitError::ForwardingBind(BindError::InvalidPort),
    }
}

/// K10 filter_config 结构校验（AR-002 说明书 4.3.2 规则——权威实现
/// 归 AR-002 T3，落地前由门面承接；crate 内部面，公共契约不含此项）。
///
/// 规则（2026-09-16 结构重设计）：每个规则集——name 非空；host 按类型
/// 校验（ip → addr 为合法 IP/CIDR；host → context 为合法 glob）；
/// targetrules 的 method/path 与 binaryrules 的 path 均为合法 glob
///（非空且星号数 ≤ 1）；port 预留（不校验）；action 取值由类型系统
/// 保证；default_policy 取值由类型系统保证。
pub(crate) fn validate_filter_config(fc: &FilterConfig) -> Result<(), ConfigError> {
    for rs in &fc.rule_list {
        validate_ruleset(rs)?;
    }
    Ok(())
}

/// 单规则集校验（K10 规则逐条）。
fn validate_ruleset(rs: &crate::model::RuleSet) -> Result<(), ConfigError> {
    if rs.name.is_empty() {
        return Err(ConfigError::Format);
    }
    // host 按类型校验（字段存在性 + 模式合法性）。
    let host_ok = match rs.host.host_type {
        crate::model::HostType::Ip => rs
            .host
            .addr
            .as_deref()
            .is_some_and(is_valid_ip_pattern),
        crate::model::HostType::Host => rs
            .host
            .context
            .as_deref()
            .is_some_and(is_valid_glob_pattern),
    };
    if !host_ok {
        return Err(ConfigError::Format);
    }
    // targetrules：method + path 均为合法 glob。
    if rs
        .targetrules
        .iter()
        .any(|t| !is_valid_glob_pattern(&t.method) || !is_valid_glob_pattern(&t.path))
    {
        return Err(ConfigError::Format);
    }
    // binaryrules：path 为合法 glob。
    if rs
        .binaryrules
        .iter()
        .any(|b| !is_valid_glob_pattern(&b.path))
    {
        return Err(ConfigError::Format);
    }
    Ok(())
}

/// 通配模式合法性（K10：非空且星号数 ≤ 1——host context / targetrule
/// method·path / binaryrule path 统一规则；多星语义应拆分表达，
/// 配置面拒绝防歧义）。
fn is_valid_glob_pattern(pattern: &str) -> bool {
    !pattern.is_empty() && pattern.matches('*').count() <= 1
}

/// IP 模式合法性（K10，host.type=ip 的 addr）：精确 IP（IPv4/IPv6）
/// 或 CIDR（`a.b.c.d/n` / `x::y/n`，前缀 ≤ 族上限）。
fn is_valid_ip_pattern(pattern: &str) -> bool {
    let (addr_str, prefix_str) = match pattern.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (pattern, None),
    };
    let Ok(ip) = addr_str.parse::<std::net::IpAddr>() else {
        return false;
    };
    match prefix_str {
        None => true, // 精确 IP（/32 或 /128）。
        Some(p) => match p.parse::<u8>() {
            Ok(prefix) => match ip {
                std::net::IpAddr::V4(_) => prefix <= 32,
                std::net::IpAddr::V6(_) => prefix <= 128,
            },
            Err(_) => false,
        },
    }
}

/// 加载系统信任锚（platform certs；失败时返回错误由调用方告警）。
fn load_system_roots(roots: &mut rustls::RootCertStore) -> Result<(), String> {
    let certs = rustls_native_roots(roots)?;
    let _ = certs;
    Ok(())
}

/// 平台根证书加载（UNIX 标准路径；无三方依赖的最小实现）。
fn rustls_native_roots(roots: &mut rustls::RootCertStore) -> Result<usize, String> {
    use std::io::Read as _;
    let mut count = 0usize;
    for path in [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
    ] {
        let Ok(mut file) = std::fs::File::open(path) else {
            continue;
        };
        let mut buf = Vec::new();
        if file.read_to_end(&mut buf).is_err() {
            continue;
        }
        for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(&buf)).flatten() {
            if roots.add(cert).is_ok() {
                count += 1;
            }
        }
        if count > 0 {
            return Ok(count);
        }
    }
    Err("no system root store found".to_string())
}

/// 测试注入缝（集成测试 fake registry；**仅测试构建可达**——`test-util`
/// feature 门禁，经自引用 dev-dependency 启用，生产构建完全编译排除）。
///
/// guard 持有期间独占全局运行态（测试间串行化），丢弃时恢复先前运行态。
#[cfg(feature = "test-util")]
#[doc(hidden)]
pub mod testing {
    use super::*;

    /// 注入互斥锁（测试间串行化，防并行交叉污染全局态）。
    static INSTALL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// 已注入运行态 guard（Drop 恢复先前运行态并释放锁）。
    pub struct InstalledRuntime {
        _guard: std::sync::MutexGuard<'static, ()>,
        previous: Option<Arc<dyn RuntimeRegistry>>,
    }

    impl Drop for InstalledRuntime {
        fn drop(&mut self) {
            *crate::lock_util::recovered(RUNTIME.write(), "runtime") = self.previous.take();
        }
    }

    /// 清空运行态为未初始化（后续 API 调用惰性重装生产运行态；
    /// 恢复于 guard 丢弃——TC9 惰性初始化路径测试用）。
    pub fn clear() -> InstalledRuntime {
        let guard = INSTALL_LOCK.lock().expect("install lock poisoned");
        let previous = crate::lock_util::recovered(RUNTIME.write(), "runtime").take();
        InstalledRuntime {
            _guard: guard,
            previous,
        }
    }

    /// 注入 fake 运行态（恢复于 guard 丢弃）。
    pub fn install(registry: Arc<dyn RuntimeRegistry>) -> InstalledRuntime {
        let guard = INSTALL_LOCK.lock().expect("install lock poisoned");
        let previous = crate::lock_util::recovered(RUNTIME.write(), "runtime").replace(registry);
        InstalledRuntime {
            _guard: guard,
            previous,
        }
    }

    /// 注入恒 Ok / 忽略的 fake 运行态（lib_api 契约测试全局态隔离）。
    pub fn install_fake_noop() -> InstalledRuntime {
        struct Noop;
        impl RuntimeRegistry for Noop {
            fn set_container_config(&self, _: &str, _: FilterConfig) -> Result<(), ConfigError> {
                Ok(())
            }
            fn remove_container_policy(&self, _: &str) -> Result<(), ConfigError> {
                Ok(())
            }
            fn set_container_ca(&self, _: &str, _: CaCert) -> Result<(), CaError> {
                Ok(())
            }
            fn register_binary_resolver(&self, _: Resolver) {}
            fn register_log_sink(&self, sink: LogSink) {
                // 与生产语义一致：回调真实装进 logging 模块（audit 路径
                // 可测——契约测试断言 fail-closed 传播依赖此行为）。
                crate::logging::install_callback(sink);
            }
        }
        install(Arc::new(Noop))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HostRule, HostType, RuleAction, RuleSet, TargetRule};

    // K10 IP 模式判定（host.type=ip 的 addr）：精确/CIDR 合法；非 IP、
    // 前缀越界/非数字非法。
    #[test]
    fn ip_pattern_validity() {
        assert!(is_valid_ip_pattern("1.2.3.4"));
        assert!(is_valid_ip_pattern("10.0.0.0/8"));
        assert!(is_valid_ip_pattern("2001:db8::/32"));
        assert!(is_valid_ip_pattern("::1/128"));
        assert!(!is_valid_ip_pattern("not-an-ip"));
        assert!(!is_valid_ip_pattern("10.0.0.0/33"));
        assert!(!is_valid_ip_pattern("2001:db8::/129"));
        assert!(!is_valid_ip_pattern("10.0.0.0/abc"));
        assert!(!is_valid_ip_pattern(""));
    }

    // K10 通配模式判定（非空 + 星号数 ≤ 1——host context / targetrule
    // method·path / binaryrule path 统一规则）。
    #[test]
    fn glob_pattern_validity() {
        assert!(is_valid_glob_pattern("/v1/chat"));
        assert!(is_valid_glob_pattern("/v1/*"));
        assert!(is_valid_glob_pattern("*.js"));
        assert!(is_valid_glob_pattern("/one/box/*/v1"));
        assert!(is_valid_glob_pattern("*"));
        assert!(is_valid_glob_pattern("api.*.example.com"));
        // 多星 / 空——非法。
        assert!(!is_valid_glob_pattern("*v1*"));
        assert!(!is_valid_glob_pattern("a*b*c"));
        assert!(!is_valid_glob_pattern("**"));
        assert!(!is_valid_glob_pattern(""));
    }

    /// 构造规则集（host 型 + 单 targetrule + 可选 binaryrules）。
    fn rs_host(name: &str, context: &str, method: &str, path: &str) -> RuleSet {
        RuleSet {
            name: name.to_string(),
            host: HostRule {
                host_type: HostType::Host,
                addr: None,
                context: Some(context.to_string()),
                prio: 100,
            },
            targetrules: vec![TargetRule {
                method: method.to_string(),
                path: path.to_string(),
                action: RuleAction::Allow,
            }],
            binaryrules: vec![],
            port: None,
        }
    }

    // K10 规则集校验：name 空 / host 字段缺失或非法 / 规则 glob 多星
    // → Format；合法结构通过；port 预留不校验。
    #[test]
    fn ruleset_validation_rules() {
        // 合法：host 型完整结构（含 port 预留字段）。
        let ok = RuleSet {
            port: Some(8843),
            ..rs_host("allow-trusted", "*.trusted.com", "*", "*")
        };
        assert!(validate_ruleset(&ok).is_ok());

        // name 空。
        let bad_name = rs_host("", "*.trusted.com", "*", "*");
        assert_eq!(validate_ruleset(&bad_name), Err(ConfigError::Format));

        // host 型缺 context。
        let mut missing_ctx = rs_host("rs", "*.trusted.com", "*", "*");
        missing_ctx.host.context = None;
        assert_eq!(validate_ruleset(&missing_ctx), Err(ConfigError::Format));

        // host context 多星。
        let bad_ctx = rs_host("rs", "*a**b.com", "*", "*");
        assert_eq!(validate_ruleset(&bad_ctx), Err(ConfigError::Format));

        // ip 型缺 addr。
        let mut ip_missing = rs_host("rs", "a.com", "*", "*");
        ip_missing.host.host_type = HostType::Ip;
        assert_eq!(validate_ruleset(&ip_missing), Err(ConfigError::Format));

        // ip 型 addr 非法 CIDR。
        let mut ip_bad = rs_host("rs", "a.com", "*", "*");
        ip_bad.host.host_type = HostType::Ip;
        ip_bad.host.addr = Some("10.0.0.0/33".to_string());
        assert_eq!(validate_ruleset(&ip_bad), Err(ConfigError::Format));

        // targetrule method 多星。
        let bad_method = rs_host("rs", "a.com", "G*T*", "*");
        assert_eq!(validate_ruleset(&bad_method), Err(ConfigError::Format));

        // targetrule path 空。
        let bad_path = rs_host("rs", "a.com", "*", "");
        assert_eq!(validate_ruleset(&bad_path), Err(ConfigError::Format));

        // binaryrule path 多星。
        let mut bad_bin = rs_host("rs", "a.com", "*", "*");
        bad_bin.binaryrules = vec![crate::model::BinaryRule {
            path: "/a/*/b/*".to_string(),
            action: RuleAction::Deny,
        }];
        assert_eq!(validate_ruleset(&bad_bin), Err(ConfigError::Format));
    }
}

