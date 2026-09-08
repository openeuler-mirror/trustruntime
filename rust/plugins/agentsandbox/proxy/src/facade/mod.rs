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
//!   管道；容器身份由 `ProxyConfig::container_id` 静态绑定端点：accept
//!   即知 container_id，零运行时反查）；
//! - [`register_binary_resolver`] / [`register_log_sink`]：进程级回调注册。
//!
//! 配置与 CA 均可独立调用（每请求实时查表）；未 set 配置或 CA 的容器
//! 流量 fail-closed 拒绝（503 / TLS 层关闭）。
//!
//! K10 结构校验：filter_config 合法性由门面层承接（uri 模式等，
//! `validate_filter_config`——crate 内部面）。

use std::sync::{Arc, RwLock};

use crate::error::{BindError, CaError, ConfigError};
use crate::logging::LogSink;
use crate::model::{CaCert, FilterConfig, ProxyConfig, RuleEntry};
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
/// - **测试期 CA 兜底（临时）**：读取固定目录 CA 材料
///   （`/etc/agentsandbox/cert/` 下 `ca_root.crt` + `private.key`）注入
///   [`DEFAULT_CONTAINER_ID`] 容器——集成方证书获取链路完成前的过渡
///   行为，届时移除；读取或注入失败仅告警放行（不阻断 init）。
///
/// 前置校验：端口非 0，路由条目 host/url 非空；重复调用返回
/// `ProxyInitError::AlreadyInitialized`。
pub fn proxy_init(config: &ProxyConfig) -> Result<(), ProxyInitError> {
    validate_endpoint(&config.forwarding)?;
    validate_inference_routes(&config.inference_routes)?;
    if INITIALIZED.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return Err(ProxyInitError::AlreadyInitialized);
    }

    // 测试期 CA 兜底（临时）：固定目录双 PEM 读取注入——仅告警语义。
    load_ca_fallback(DEFAULT_CONTAINER_ID, TEST_CA_CERT_FILE, TEST_CA_KEY_FILE);

    // forwarding 端点：绑定 + spawn serve（携带 container_id）。
    let forward_addr = std::net::SocketAddr::new(config.forwarding.ip, config.forwarding.port);
    let forward_listener = std::net::TcpListener::bind(forward_addr)
        .map_err(map_forward_bind)?;
    // TcpListener 默认阻塞——转 tokio 需 nonblocking（serve 在 async 上下文）。
    forward_listener
        .set_nonblocking(true)
        .map_err(|_| ProxyInitError::InvalidEndpoint)?;
    let forward_listener =
        tokio::net::TcpListener::from_std(forward_listener).map_err(map_forward_bind)?;

    // 装配 ServeContext（共享生产组件单例——proxy_init 前注入的
    // set_container_* 状态连续生效）并启动 serve 任务。
    spawn_serve(forward_listener, config);
    Ok(())
}

// ===== 测试期 CA 兜底（临时——集成方证书获取链路完成后移除）=====

/// 测试期默认容器标识（单容器测试形态：CA 兜底注入目标；集成方
/// resolver 测试期应返回同值——真实多容器身份由 resolver 按连接解析）。
pub const DEFAULT_CONTAINER_ID: &str = "default";

/// 测试期 CA 证书文件（固定目录；日志中不出现路径——日志安全约束）。
const TEST_CA_CERT_FILE: &str = "/etc/agentsandbox/cert/ca_root.crt";
/// 测试期 CA 私钥文件。
const TEST_CA_KEY_FILE: &str = "/etc/agentsandbox/cert/private.key";

/// 测试期 CA 兜底：双 PEM 读取并经 [`set_container_ca`] 注入当前容器。
///
/// 语义：**尽力而为**——文件不可读或材料非法仅运行日志告警并放行
/// （不阻断 init；该容器 CA 保持未注入状态，后续仍可经公共 API 补注入；
/// 未注入 CA 的容器 TLS 流量 fail-closed 拒绝，与兜底缺失时行为一致）。
/// 路径参数化供测试注入（生产固定目录）。
fn load_ca_fallback(container_id: &str, cert_path: &str, key_path: &str) {
    let (cert_pem, key_pem) = match (std::fs::read(cert_path), std::fs::read(key_path)) {
        (Ok(c), Ok(k)) => (c, k),
        _ => {
            // 不含路径与错误详情（日志安全——固定描述）。
            crate::log_warn!("facade", "test ca fallback: material files not readable; skipped");
            return;
        }
    };
    match set_container_ca(
        container_id,
        crate::model::CaCert { cert_pem, key_pem },
    ) {
        Ok(()) => crate::log_info!("facade", "test ca fallback: container ca injected"),
        Err(_) => {
            crate::log_warn!("facade", "test ca fallback: ca material invalid; skipped");
        }
    }
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
    // 推理路由列表装配（router 默认 mock——crate 引入，真实库落地后替换）。
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
/// 规则：domain/method 非空；domain/method/uri 三维通配模式统一为
/// 「非空且星号数 ≤ 1」（2026-09-05 统一 glob 决策——`*` 唯一通配符、
/// 单星任意位置、裸 `*` 全匹配；多星非法）；binary 若声明非空；
/// default_policy 取值由类型系统保证。
pub(crate) fn validate_filter_config(fc: &FilterConfig) -> Result<(), ConfigError> {
    for entry in fc.whitelist.iter().chain(fc.blacklist.iter()) {
        validate_entry(entry)?;
    }
    Ok(())
}

/// 单条目校验（K10 规则逐条）。
fn validate_entry(entry: &RuleEntry) -> Result<(), ConfigError> {
    if entry.domain.is_empty() || entry.method.is_empty() {
        return Err(ConfigError::Format);
    }
    // 三维通配模式校验（非空 + 单星；uri 仅声明时校验）。
    if !is_valid_glob_pattern(&entry.domain)
        || !is_valid_glob_pattern(&entry.method)
        || entry.uri.as_deref().is_some_and(|u| !is_valid_glob_pattern(u))
    {
        return Err(ConfigError::Format);
    }
    if entry.binary.as_deref().is_some_and(str::is_empty) {
        return Err(ConfigError::Format);
    }
    // default_policy 合法性由枚举类型保证（值域即类型）。
    Ok(())
}

/// 通配模式合法性（K10：非空且星号数 ≤ 1——domain/method/uri 三维
/// 统一规则；多星语义应拆分为多条目表达，配置面拒绝防歧义）。
fn is_valid_glob_pattern(pattern: &str) -> bool {
    !pattern.is_empty() && pattern.matches('*').count() <= 1
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

    // K10 通配模式判定（三维统一：非空 + 星号数 ≤ 1）。
    #[test]
    fn glob_pattern_validity() {
        // 裸值 / 前缀 / 后缀 / 中间星 / 裸星全匹配。
        assert!(is_valid_glob_pattern("/v1/chat"));
        assert!(is_valid_glob_pattern("/v1/*"));
        assert!(is_valid_glob_pattern("*.js"));
        assert!(is_valid_glob_pattern("/one/box/*/v1")); // 中间星（2026-09-05 放开）
        assert!(is_valid_glob_pattern("a*b"));
        assert!(is_valid_glob_pattern("*")); // 裸 * = 全匹配（2026-09-05 翻转）
        assert!(is_valid_glob_pattern("api.*.example.com"));
        assert!(is_valid_glob_pattern("/")); // 裸值合法
        // 多星 / 空——非法。
        assert!(!is_valid_glob_pattern("*v1*"));
        assert!(!is_valid_glob_pattern("a*b*c"));
        assert!(!is_valid_glob_pattern("**"));
        assert!(!is_valid_glob_pattern(""));
    }

    // K10 条目校验：domain/method 空、binary 空、三维多星 → Format；
    // 裸 * 与单星形态合法。
    #[test]
    fn entry_validation_rules() {
        let ok = RuleEntry {
            domain: "a.com".to_string(),
            method: "GET".to_string(),
            uri: Some("/one/box/*/v1".to_string()),
            binary: Some("python3".to_string()),
        };
        assert!(validate_entry(&ok).is_ok());

        let bad_domain = RuleEntry {
            domain: String::new(),
            method: "GET".to_string(),
            uri: None,
            binary: None,
        };
        assert_eq!(validate_entry(&bad_domain), Err(ConfigError::Format));

        // 三维多星拒绝（统一规则）。
        let multi_star_domain = RuleEntry {
            domain: "a*b*c.com".to_string(),
            method: "GET".to_string(),
            uri: None,
            binary: None,
        };
        assert_eq!(validate_entry(&multi_star_domain), Err(ConfigError::Format));

        let multi_star_method = RuleEntry {
            domain: "a.com".to_string(),
            method: "G*T*".to_string(),
            uri: None,
            binary: None,
        };
        assert_eq!(validate_entry(&multi_star_method), Err(ConfigError::Format));

        let multi_star_uri = RuleEntry {
            domain: "a.com".to_string(),
            method: "GET".to_string(),
            uri: Some("/a/*/b/*".to_string()),
            binary: None,
        };
        assert_eq!(validate_entry(&multi_star_uri), Err(ConfigError::Format));

        let bad_uri = RuleEntry {
            domain: "a.com".to_string(),
            method: "GET".to_string(),
            uri: Some("*v1*".to_string()),
            binary: None,
        };
        assert_eq!(validate_entry(&bad_uri), Err(ConfigError::Format));

        let bad_binary = RuleEntry {
            domain: "a.com".to_string(),
            method: "GET".to_string(),
            uri: None,
            binary: Some(String::new()),
        };
        assert_eq!(validate_entry(&bad_binary), Err(ConfigError::Format));

        // 裸 * 三维全匹配（合法形态）。
        let bare_star_ok = RuleEntry {
            domain: "*".to_string(),
            method: "*".to_string(),
            uri: Some("*".to_string()),
            binary: None,
        };
        assert!(validate_entry(&bare_star_ok).is_ok());
    }

    // 测试期 CA 兜底：文件双读 → set_container_ca 注入；缺失 → 跳过；
    // 注入失败（材料非法语义）→ 告警放行不 panic。
    //
    // 串行锁：load_ca_fallback 发出全局日志事件，须与 logging 测试
    // 互斥（共享 serial_guard——防回调计数断言交叉污染）。
    #[test]
    fn test_ca_fallback_dispatch() {
        use std::sync::Mutex;
        let _serial = crate::logging::testing::serial_guard();

        /// 记录型 fake（记录 set_container_ca 入参；accept 控制返回）。
        type RecordedCa = (String, Vec<u8>, Vec<u8>);
        struct CaRecorder {
            calls: Mutex<Vec<RecordedCa>>,
            accept: bool,
        }
        impl RuntimeRegistry for CaRecorder {
            fn set_container_config(
                &self,
                _: &str,
                _: FilterConfig,
            ) -> Result<(), ConfigError> {
                Ok(())
            }
            fn remove_container_policy(&self, _: &str) -> Result<(), ConfigError> {
                Ok(())
            }
            fn set_container_ca(&self, id: &str, ca: CaCert) -> Result<(), CaError> {
                self.calls
                    .lock()
                    .unwrap()
                    .push((id.to_string(), ca.cert_pem, ca.key_pem));
                if self.accept {
                    Ok(())
                } else {
                    Err(CaError::Invalid)
                }
            }
            fn register_binary_resolver(&self, _: Resolver) {}
            fn register_log_sink(&self, _: LogSink) {}
        }

        // 1. 文件缺失：跳过（无注入、不 panic）。
        {
            let fake = Arc::new(CaRecorder {
                calls: Mutex::new(Vec::new()),
                accept: true,
            });
            let _rt = testing::install(fake.clone());
            load_ca_fallback("c-t", "/nonexistent/a.crt", "/nonexistent/b.key");
            assert!(
                fake.calls.lock().unwrap().is_empty(),
                "文件缺失不得注入"
            );
        }

        // 2/3 共用：临时目录双 PEM 文件（dir 存活至用例末尾——读取时
        // 文件必须存在）。
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("ca_root.crt");
        let key_path = dir.path().join("private.key");
        std::fs::write(&cert_path, b"cert-pem-bytes").unwrap();
        std::fs::write(&key_path, b"key-pem-bytes").unwrap();
        let cert_path = cert_path.to_string_lossy().into_owned();
        let key_path = key_path.to_string_lossy().into_owned();

        // 2. 文件可读：内容原样透传 set_container_ca（container_id + 双 PEM）。
        {
            let fake = Arc::new(CaRecorder {
                calls: Mutex::new(Vec::new()),
                accept: true,
            });
            let _rt = testing::install(fake.clone());
            load_ca_fallback("c-t", &cert_path, &key_path);
            let calls = fake.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, "c-t");
            assert_eq!(calls[0].1, b"cert-pem-bytes".to_vec());
            assert_eq!(calls[0].2, b"key-pem-bytes".to_vec());
        }

        // 3. 注入失败（材料非法语义）：告警放行不 panic（调用已发生）。
        {
            let fake = Arc::new(CaRecorder {
                calls: Mutex::new(Vec::new()),
                accept: false,
            });
            let _rt = testing::install(fake.clone());
            load_ca_fallback("c-t", &cert_path, &key_path);
            assert_eq!(fake.calls.lock().unwrap().len(), 1);
        }
    }
}

