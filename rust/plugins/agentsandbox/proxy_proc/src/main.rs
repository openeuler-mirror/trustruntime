use agentsandbox_proxy::facade::{proxy_init, register_binary_resolver, register_log_sink};
use agentsandbox_proxy::logging::{LogEvent, LogSinkError};
use agentsandbox_proxy::model::{CaCert, ContainerEndpoint, InferenceRoute, ProxyConfig};
use agentsandbox_proxy::registry::Resolver;
use agentsandbox_proxy_proc::{create_ebpf_resolver, set_global_ca, ConfigReceiver};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("[FATAL] proxy_proc startup failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn run() -> anyhow::Result<()> {
    // tokio runtime（multi-thread，IO + time driver）：`proxy_init` 的
    // `TcpListener::from_std` 注册与 `tokio::spawn`（serve 任务）隐式
    // 要求当前线程处于 runtime 上下文——缺失时 from_std 直接 panic
    //（"must be called from the context of a Tokio 1.x runtime"，
    // 2026-09-12 修复的 startup panic）。enter guard 使下方 sync 启动链
    // 获得上下文；主线程随后阻塞于 UDS 配置监听，serve 任务在 runtime
    // worker 线程运转。
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("tokio runtime init failed: {}", e))?;
    let _rt_guard = rt.enter();

    let config = ProxyProcConfig::from_env()?;
    load_ca(&config)?;
    register_ebpf_resolver()?;
    setup_log_sink();
    // 启动顺序（AR-005，2026-09-18）：start_proxy（内含推理库初始化）
    // 先于 apply_startup_api_key——key 交付依赖已初始化的全局状态
    //（"先 init 再 set key"）。serve 已启动而 key 尚未落库的窗口内，
    // 推理流量按未配置模型语义处理（Bearer EMPTY——与 UDS 远程模式
    // 服务延迟就绪的既有语义一致）。
    // 容器策略不经启动装配——HC 经 UDS refresh_policy 下发
    //（未下发容器 fail-closed 503，生产语义；self-test 打桩已移除）。
    start_proxy(&config)?;
    apply_startup_api_key(&config);
    start_config_receiver(&config)
}

/// 启动期 API key 配置应用（2026-09-17）：AGENTSANDBOX_API_KEY 解析
/// 结果（parse 期已 FATAL 校验）经 facade `set_api_key` 下发——
/// 双模式自动生效（env UDS_PATH → msg_type=1 远程 / 未设 → 本地
/// 真实库加密存储）。
///
/// 时序：后于 `start_proxy`（推理库已初始化——本地分支可用）。
/// 交付失败（Delivery）→ WARN 继续（远程服务可能未就绪；HC 可经
/// `set_api_key` 管理消息后续补发）——管理面操作不做流量面 fail-closed。
fn apply_startup_api_key(config: &ProxyProcConfig) {
    if let Some(req) = &config.api_key {
        if let Err(e) = agentsandbox_proxy::facade::set_api_key(req.clone()) {
            eprintln!("[WARN] proxy_proc: startup set_api_key delivery failed: {:?}", e);
        }
    }
}

// ---- CA loading ----

fn load_ca(config: &ProxyProcConfig) -> anyhow::Result<()> {
    let cert_pem = read_cert_file(&config.ca_cert_path)?;
    let key_pem = read_key_file(&config.ca_key_path)?;
    set_global_ca(CaCert { cert_pem, key_pem });
    Ok(())
}

fn read_cert_file(path: &str) -> anyhow::Result<Vec<u8>> {
    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("CA cert file not accessible {}: {}", path, e))?;
    if !meta.is_file() {
        anyhow::bail!("CA cert must be a regular file: {}", path);
    }
    if meta.len() == 0 {
        anyhow::bail!("CA cert file is empty: {}", path);
    }
    std::fs::read(path).map_err(|e| anyhow::anyhow!("failed to read CA cert {}: {}", path, e))
}

fn read_key_file(path: &str) -> anyhow::Result<Vec<u8>> {
    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("CA key file not accessible {}: {}", path, e))?;
    if !meta.is_file() {
        anyhow::bail!("CA key must be a regular file: {}", path);
    }
    if meta.len() == 0 {
        anyhow::bail!("CA key file is empty: {}", path);
    }
    let mode = meta.permissions().mode();
    if mode & (libc::S_IRGRP | libc::S_IROTH) != 0 {
        anyhow::bail!(
            "CA key file is group/world readable (mode {:o}); require 0o600 or stricter",
            mode & 0o777
        );
    }
    std::fs::read(path).map_err(|e| anyhow::anyhow!("failed to read CA key {}: {}", path, e))
}

// ---- eBPF resolver registration ----

fn register_ebpf_resolver() -> anyhow::Result<()> {
    let loader = Arc::new(agentsandbox_security::EbpfLoader::new());
    if let Err(e) = loader.load_programs(Some(&["sockops"])) {
        eprintln!("[WARN] eBPF sockops load failed (running in stub mode): {}", e);
    }
    let resolver: Resolver = create_ebpf_resolver(loader);
    register_binary_resolver(resolver);
    Ok(())
}

// ---- Log sink registration ----

fn setup_log_sink() {
    let sink: agentsandbox_proxy::logging::LogSink = Arc::new(|event: &LogEvent| -> Result<(), LogSinkError> {
        eprintln!("[AUDIT] {}", event.message);
        Ok(())
    });
    register_log_sink(sink);
}

// ---- Proxy serve startup ----

fn start_proxy(config: &ProxyProcConfig) -> anyhow::Result<()> {
    match config.listen_ip {
        std::net::IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                anyhow::bail!("listen address must not be 0.0.0.0 (bind to loopback)");
            }
            if v4.is_broadcast() {
                anyhow::bail!("listen address must not be broadcast");
            }
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                anyhow::bail!("listen address must not be :: (bind to loopback)");
            }
        }
    }
    let proxy_config = ProxyConfig {
        forwarding: ContainerEndpoint {
            ip: config.listen_ip,
            port: config.listen_port,
        },
        inference_routes: config.inference_route.iter().cloned().collect(),
        // 推理库初始化载体（AR-005）：env AGENT_ROUTER_CONFIG_DIR → 指定
        // 目录；未设 → None（proxy_init 内 init_default——内嵌默认配置）。
        router_config_dir: config.agent_router_config_dir.clone(),
    };
    proxy_init(&proxy_config).map_err(|e| anyhow::anyhow!("proxy_init failed: {:?}", e))?;
    eprintln!(
        "[INFO] proxy_proc started, forwarding on {}:{}, config socket: {}",
        config.listen_ip, config.listen_port, config.proxy_sock
    );
    Ok(())
}

// ---- Config receiver (blocks) ----

fn start_config_receiver(config: &ProxyProcConfig) -> anyhow::Result<()> {
    if !config.proxy_sock.starts_with('/') {
        anyhow::bail!("AGENTSANDBOX_PROXY_SOCK must be an absolute path: {}", config.proxy_sock);
    }
    let parent = std::path::Path::new(&config.proxy_sock)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("AGENTSANDBOX_PROXY_SOCK has no parent directory"))?;
    if !parent.exists() {
        anyhow::bail!("AGENTSANDBOX_PROXY_SOCK parent directory does not exist: {}", parent.display());
    }
    let receiver = ConfigReceiver::new(&config.proxy_sock);
    receiver.listen().map_err(|e| {
        anyhow::anyhow!("config receiver listen on {} failed: {}", config.proxy_sock, e)
    })
}

// ---- Config struct ----

struct ProxyProcConfig {
    proxy_sock: String,
    ca_cert_path: String,
    ca_key_path: String,
    listen_ip: std::net::IpAddr,
    listen_port: u16,
    inference_route: Option<InferenceRoute>,
    /// 启动期 API key 配置（AGENTSANDBOX_API_KEY——2026-09-17）。
    api_key: Option<agentsandbox_proxy::ApiKeyRequest>,
    /// 推理路由真实库配置目录（AGENT_ROUTER_CONFIG_DIR——可选）：
    /// 装配进 `ProxyConfig.router_config_dir`，由 `proxy_init` 统一
    /// 初始化（未设 → 内嵌默认配置）。
    agent_router_config_dir: Option<String>,
}

impl ProxyProcConfig {
    fn from_env() -> anyhow::Result<Self> {
        let listen_addr = require_env("AGENTSANDBOX_PROXY_LISTEN_ADDR")?;
        let listen_port: u16 = std::env::var("AGENTSANDBOX_PROXY_LISTEN_PORT")
            .map_err(|_| anyhow::anyhow!("AGENTSANDBOX_PROXY_LISTEN_PORT is required"))?
            .parse()
            .map_err(|_| anyhow::anyhow!("AGENTSANDBOX_PROXY_LISTEN_PORT must be a valid u16"))?;
        let listen_ip: std::net::IpAddr = listen_addr
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid listen address: {}", listen_addr))?;

        let proxy_sock = require_env("AGENTSANDBOX_PROXY_SOCK")?;
        if proxy_sock.starts_with("tcp://") || proxy_sock.starts_with("http") {
            anyhow::bail!("AGENTSANDBOX_PROXY_SOCK must be a Unix socket path, not a network URL");
        }

        let ca_cert_path = require_env("AGENTSANDBOX_CA_CERT_PATH")?;
        if !ca_cert_path.starts_with('/') {
            anyhow::bail!("AGENTSANDBOX_CA_CERT_PATH must be an absolute path: {}", ca_cert_path);
        }

        let ca_key_path = require_env("AGENTSANDBOX_CA_KEY_PATH")?;
        if !ca_key_path.starts_with('/') {
            anyhow::bail!("AGENTSANDBOX_CA_KEY_PATH must be an absolute path: {}", ca_key_path);
        }

        let inference_route = parse_inference_route()?;
        let api_key = parse_api_key()?;
        let agent_router_config_dir = parse_agent_router_config_dir()?;

        Ok(Self {
            proxy_sock,
            ca_cert_path,
            ca_key_path,
            listen_ip,
            listen_port,
            inference_route,
            api_key,
            agent_router_config_dir,
        })
    }
}

/// Parses the agent router config directory from AGENT_ROUTER_CONFIG_DIR
/// env var (optional).
///
/// Set (absolute path) → ProxyConfig.router_config_dir (custom config dir
/// init at proxy_init); unset/empty → None (embedded default configs).
/// Non-absolute value → Err (FATAL — consistent with CA path rules).
/// Log carries no path content (security).
fn parse_agent_router_config_dir() -> anyhow::Result<Option<String>> {
    match std::env::var("AGENT_ROUTER_CONFIG_DIR") {
        Ok(raw) => {
            let trimmed = raw.trim().to_string();
            if trimmed.is_empty() {
                return Ok(None);
            }
            if !trimmed.starts_with('/') {
                anyhow::bail!("AGENT_ROUTER_CONFIG_DIR must be an absolute path");
            }
            eprintln!("[INFO] agent router config dir configured");
            Ok(Some(trimmed))
        }
        Err(_) => Ok(None),
    }
}

/// Parses the API key config from AGENTSANDBOX_API_KEY env var (optional,
/// 2026-09-17).
///
/// Format: simplified `model_id:api_key` pairs, comma-separated
/// (first-colon split — api_key may contain colons):
/// `GLM_53:sk-112` / `GLM_53:sk-112,M2:sk2`.
/// Empty/unset → no api key config (Ok(None)).
/// Malformed pairs (missing colon / empty fields) → Err (FATAL —
/// consistent with inference_route).
/// Log carries item count only (no key content — security).
fn parse_api_key() -> anyhow::Result<Option<agentsandbox_proxy::ApiKeyRequest>> {
    use agentsandbox_proxy::{ApiKeyAction, ApiKeyItem, ApiKeyRequest};

    let raw = match std::env::var("AGENTSANDBOX_API_KEY") {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let mut items = Vec::new();
    for pair in trimmed.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue; // Trailing/duplicate commas — tolerant skip.
        }
        let (model_id, api_key) = pair.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("AGENTSANDBOX_API_KEY: pair missing ':' separator: use model_id:api_key")
        })?;
        let (model_id, api_key) = (model_id.trim(), api_key.trim());
        if model_id.is_empty() || api_key.is_empty() {
            anyhow::bail!("AGENTSANDBOX_API_KEY: model_id and api_key must be non-empty");
        }
        items.push(ApiKeyItem {
            model_id: model_id.to_string(),
            api_key: api_key.to_string(),
        });
    }
    if items.is_empty() {
        return Ok(None);
    }
    eprintln!("[INFO] loaded api key config: items={}", items.len());
    Ok(Some(ApiKeyRequest {
        action: ApiKeyAction::Set,
        items,
    }))
}

/// Parses a single inference route from AGENTSANDBOX_INFERENCE_ROUTE env var (optional).
///
/// Format: JSON object `{"host":"...","url":"..."}`.
/// Example: {"host":"api.openai.com","url":"/v1/chat/completions"}
/// Empty or unset → no inference route.
fn parse_inference_route() -> anyhow::Result<Option<InferenceRoute>> {
    match std::env::var("AGENTSANDBOX_INFERENCE_ROUTE") {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            let route: InferenceRoute = serde_json::from_str(trimmed)
                .map_err(|e| anyhow::anyhow!("AGENTSANDBOX_INFERENCE_ROUTE parse error: {}", e))?;
            if route.host.is_empty() || route.url.is_empty() {
                anyhow::bail!("AGENTSANDBOX_INFERENCE_ROUTE: host and url must be non-empty");
            }
            eprintln!("[INFO] loaded inference route: {} {}", route.host, route.url);
            Ok(Some(route))
        }
        Err(_) => Ok(None),
    }
}

// ---- Helpers ----

fn require_env(key: &str) -> anyhow::Result<String> {
    let val = std::env::var(key)
        .map_err(|_| anyhow::anyhow!("environment variable {} is required", key))?;
    let trimmed = val.trim().to_string();
    if trimmed.is_empty() {
        anyhow::bail!("environment variable {} must not be empty", key);
    }
    Ok(trimmed)
}
