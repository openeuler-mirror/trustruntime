use crate::config_monitor::ConfigMonitor;
use crate::messaging::{ManagementMessage, MessageSender, MSG_REFRESH_POLICY};
use crate::sock_listener::SockListener;
use agentsandbox_config::{FilterConfig, SecurityPolicy, parse_security_policy, parse_proxy_policy, parse_container_port};
use agentsandbox_security::{ContainerIntegration, EbpfLoader, PolicySnapshot};
use agentsandbox_log::LogConfig;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Global proxy address for eBPF network redirect (hardcoded, not from TOML).
/// 127.0.0.1 in network byte order (big-endian).
const PROXY_IP: u32 = 0x7F000001;
const PROXY_PORT: u16 = 8443;

/// Proxy inference routing listen port (hardcoded, not from TOML).
const MODEL_ROUTE_LISTEN_PORT: u16 = 9090;

/// Container loopback IP for inference routing match (hardcoded, not from TOML).
/// 127.0.0.1 in network byte order (big-endian).
const CONTAINER_IP: u32 = 0x7F000001;

#[derive(Debug, Error)]
pub enum MgmtError {
    #[error("register failed: {0}")]
    RegisterError(String),
    #[error("unregister failed: {0}")]
    UnregisterError(String),
    #[error("config error: {0}")]
    ConfigError(String),
    #[error("sock error: {0}")]
    SockError(String),
    #[error("eBPF error: {0}")]
    EbpfError(String),
}

/// HiController management facade: eBPF integration, config monitoring, container lifecycle.
pub struct Management {
    cm: ConfigMonitor,
    integration: ContainerIntegration,
    registered_cgroups: Arc<Mutex<HashSet<u64>>>,
    sock_path: String,
}

impl Management {
    /// Creates a Management instance, loads eBPF programs, and initializes container integration.
    pub fn new(config_dir: &str, log_config: LogConfig, sock_path: &str) -> Result<Self, MgmtError> {
        let loader = EbpfLoader::new();
        loader.load_programs().map_err(|e| MgmtError::EbpfError(e.to_string()))?;

        loader.set_proxy(PROXY_IP, PROXY_PORT, MODEL_ROUTE_LISTEN_PORT, CONTAINER_IP)
            .map_err(|e| MgmtError::EbpfError(e.to_string()))?;

        let integration = ContainerIntegration::new(loader, log_config);
        Ok(Self {
            cm: ConfigMonitor::new(config_dir),
            integration,
            registered_cgroups: Arc::new(Mutex::new(HashSet::new())),
            sock_path: sock_path.to_string(),
        })
    }

    /// Starts config file monitoring in a background thread. On TOML change, atomically applies config per cgroup.
    pub fn start_config_monitor(&self, sender: &dyn MessageSender) -> Result<(), MgmtError> {
        let integration = self.integration.clone();
        let cm = self.cm.clone_for_watch();
        let registered = self.registered_cgroups.clone();
        let sender_box: Box<dyn MessageSender + Send> = sender.clone_box();

        thread::spawn(move || {
            let cm_inner = cm.clone();
            cm.watch(move |path| {
                let (fc, sp, cp) = match cm_inner.parse_file(path) {
                    Ok(parsed) => parsed,
                    Err(e) => {
                        eprintln!("config parse failed for {}: {}", path, e);
                        return;
                    }
                };
                apply_config_per_cgroup(&fc, &sp, cp, &registered, &integration, &sender_box);
            }).ok();
        });
        Ok(())
    }

    /// Runs the main event loop: config monitoring + sock listener for container lifecycle.
    pub async fn run(self: Arc<Self>, sock_listener: SockListener, sender: &dyn MessageSender) -> Result<(), MgmtError> {
        self.start_config_monitor(sender)?;
        let mgmt = self.clone();
        let sender_box: Box<dyn MessageSender + Send> = sender.clone_box();

        tokio::task::spawn_blocking(move || {
            sock_listener.listen(move |msg| {
                apply_container_config(&msg.config_path, msg.cgroup_id, &mgmt, &sender_box);
            }).ok();
        }).await.map_err(|e| MgmtError::SockError(e.to_string()))?;
        Ok(())
    }

    /// Graceful shutdown: unloads eBPF programs and releases resources.
    pub async fn shutdown(&self) -> Result<(), MgmtError> {
        self.integration.unload()
            .map_err(|e| MgmtError::EbpfError(e.to_string()))?;
        eprintln!("eBPF programs unloaded");
        Ok(())
    }
}

/// Applies both eBPF security policy and proxy filter_config from the same toml for a single container.
/// Reads TOML content from config_path (HiController has filesystem access, container does not).
fn apply_container_config(config_path: &str, cgroup_id: u64, mgmt: &Arc<Management>, sender: &Box<dyn MessageSender + Send>) {
    let toml_content = match std::fs::read_to_string(config_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("container register: failed to read config {} for cgroup {}: {}", config_path, cgroup_id, e);
            return;
        }
    };

    let security_policy = parse_security_policy(&toml_content).ok();
    let filter_config = parse_proxy_policy(&toml_content).ok();
    let container_port = parse_container_port(&toml_content).unwrap_or(0);

    if security_policy.is_none() && filter_config.is_none() {
        eprintln!("container register: no security policy or filter_config found for cgroup {}", cgroup_id);
        return;
    }

    let old_policy = mgmt.integration.get_policy_value(cgroup_id);

    if let Some(policy) = &security_policy {
        if let Err(e) = mgmt.integration.register_with_rollback(cgroup_id, policy.clone(), container_port) {
            eprintln!("container register: eBPF policy failed for cgroup {}: {}", cgroup_id, e);
            return;
        }
    }

    if let Some(cfg) = &filter_config {
        if !send_filter_config_to_proxy(sender, cgroup_id, cfg) {
            rollback_ebpf(&mgmt.integration, cgroup_id, &old_policy);
            return;
        }
    }

    if let Ok(mut s) = mgmt.registered_cgroups.lock() {
        s.insert(cgroup_id);
    } else {
        eprintln!("container register: cgroup tracking failed for {}, rolling back eBPF", cgroup_id);
        rollback_ebpf(&mgmt.integration, cgroup_id, &old_policy);
        return;
    }

    if let Err(e) = mgmt.integration.block_sock_access(cgroup_id, &mgmt.sock_path) {
        eprintln!("container register: failed to block sock access for cgroup {}: {}", cgroup_id, e);
    }
}

/// Per-cgroup config apply. Each cgroup is applied independently: failure rolls back only that cgroup.
fn apply_config_per_cgroup(fc: &Option<FilterConfig>, sp: &Option<SecurityPolicy>, container_port: u16, registered: &Arc<Mutex<HashSet<u64>>>, integration: &ContainerIntegration, sender: &Box<dyn MessageSender + Send>) {
    let cgroups: Vec<u64> = registered.lock()
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();

    for cgroup_id in &cgroups {
        let old_policy = integration.get_policy_value(*cgroup_id);

        if let Some(security_policy) = sp {
            if let Err(e) = integration.register_with_rollback(*cgroup_id, security_policy.clone(), container_port) {
                eprintln!("config apply: eBPF refresh failed for cgroup {}: {}, skipping", cgroup_id, e);
                continue;
            }
        }

        if let Some(cfg) = fc {
            if !send_filter_config_to_proxy(sender, *cgroup_id, cfg) {
                rollback_ebpf(integration, *cgroup_id, &old_policy);
                continue;
            }
        }
    }
}

/// Sends filter_config bound to cgroup_id to proxy. Returns true on success.
fn send_filter_config_to_proxy(sender: &Box<dyn MessageSender + Send>, cgroup_id: u64, cfg: &FilterConfig) -> bool {
    let rid = format!("config-{}-{}", cgroup_id, SystemTime::now()
        .duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0));
    let payload = serde_json::json!({ "cgroup_id": cgroup_id, "filter_config": cfg });

    match sender.send(&ManagementMessage {
        msg_type: MSG_REFRESH_POLICY.to_string(),
        payload,
        request_id: rid,
    }) {
        Ok(resp) if resp.status == "ok" => true,
        Ok(resp) => {
            eprintln!("config apply: proxy rejected filter_config for cgroup {}: status={}", cgroup_id, resp.status);
            false
        }
        Err(e) => {
            eprintln!("config apply: send filter_config to proxy failed for cgroup {}: {}", cgroup_id, e);
            false
        }
    }
}

/// Rolls back eBPF policy to the previous value; logs error if rollback also fails.
fn rollback_ebpf(integration: &ContainerIntegration, cgroup_id: u64, old_policy: &PolicySnapshot) {
    if let Err(e) = integration.restore_policy(cgroup_id, old_policy.clone()) {
        eprintln!("rollback failed for cgroup {}: {}", cgroup_id, e);
    }
}
