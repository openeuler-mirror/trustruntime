use crate::config_monitor::ConfigMonitor;
use crate::messaging::{ManagementMessage, MessageSender, MSG_REFRESH_POLICY, MSG_REMOVE_CONTAINER};
use crate::sock_listener::{ContainerAction, ContainerMessage, SockListener};
use agentsandbox_config::{ContainerId, FilterConfig, SecurityPolicy, parse_security_policy, parse_proxy_policy, parse_container_port};
use agentsandbox_security::{ContainerIntegration, EbpfLoader, PolicySnapshot};
use agentsandbox_log::LogConfig;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Loopback IP (127.0.0.1) in network byte order for proxy and container.
const LOOPBACK_IP_BE: u32 = libc::INADDR_LOOPBACK.to_be();
/// Proxy transparent redirect listen port.
const PROXY_PORT: u16 = 8443;
/// Proxy inference routing listen port.
const MODEL_ROUTE_LISTEN_PORT: u16 = 9090;

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
    registered_containers: Arc<Mutex<HashSet<ContainerId>>>,
    sock_path: String,
}

impl Management {
    /// Creates a Management instance, loads eBPF programs, and initializes container integration.
    pub fn new(config_dir: &str, log_config: LogConfig, sock_path: &str) -> Result<Self, MgmtError> {
        let loader = EbpfLoader::new();
        loader.load_programs(None).map_err(|e| MgmtError::EbpfError(e.to_string()))?;

        loader.set_proxy(LOOPBACK_IP_BE, PROXY_PORT, MODEL_ROUTE_LISTEN_PORT, LOOPBACK_IP_BE)
            .map_err(|e| MgmtError::EbpfError(e.to_string()))?;

        let integration = ContainerIntegration::new(loader, log_config);
        Ok(Self {
            cm: ConfigMonitor::new(config_dir),
            integration,
            registered_containers: Arc::new(Mutex::new(HashSet::new())),
            sock_path: sock_path.to_string(),
        })
    }

    /// Starts config file monitoring in a background thread. On TOML change, atomically applies config per cgroup.
    pub fn start_config_monitor(&self, sender: &dyn MessageSender) -> Result<(), MgmtError> {
        let integration = self.integration.clone();
        let cm = self.cm.clone_for_watch();
        let registered = self.registered_containers.clone();
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
                apply_config_per_container(&fc, &sp, cp, &registered, &integration, &sender_box);
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
                match msg.action {
                    ContainerAction::Register => {
                        if let Some(config_path) = &msg.config_path {
                            apply_container_config(config_path, msg.container_id, &mgmt, &sender_box);
                        }
                    }
                    ContainerAction::Unregister => {
                        unregister_container(msg.container_id, &mgmt, &sender_box);
                    }
                }
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
fn apply_container_config(config_path: &str, container_id: ContainerId, mgmt: &Arc<Management>, sender: &Box<dyn MessageSender + Send>) {
    let toml_content = match std::fs::read_to_string(config_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("container register: failed to read config {} for {}: {}", config_path, container_id, e);
            return;
        }
    };
    let security_policy = parse_security_policy(&toml_content).ok();
    let filter_config = parse_proxy_policy(&toml_content).ok();
    let container_port = parse_container_port(&toml_content).unwrap_or(0);
    if security_policy.is_none() && filter_config.is_none() {
        eprintln!("container register: no policy found for {}", container_id);
        return;
    }
    let old_policy = mgmt.integration.get_policy_value(container_id.cgroup_id);
    if let Some(policy) = &security_policy {
        if let Err(e) = mgmt.integration.register_with_rollback(container_id.cgroup_id, policy.clone(), container_port) {
            eprintln!("container register: eBPF failed for {}: {}", container_id, e);
            return;
        }
    }
    if let Some(cfg) = &filter_config {
        if !send_filter_config_to_proxy(sender, &container_id, cfg) {
            rollback_ebpf(&mgmt.integration, &container_id, &old_policy);
            return;
        }
    }
    if let Ok(mut s) = mgmt.registered_containers.lock() {
        s.insert(container_id.clone());
    } else {
        eprintln!("container register: tracking failed for {}, rolling back eBPF", container_id);
        rollback_ebpf(&mgmt.integration, &container_id, &old_policy);
        return;
    }
    if let Err(e) = mgmt.integration.block_sock_access(container_id.cgroup_id, &mgmt.sock_path) {
        eprintln!("container register: block sock failed for {}: {}", container_id, e);
    }
}

/// Per-container config apply on TOML hot-reload. Each container is applied independently.
fn apply_config_per_container(fc: &Option<FilterConfig>, sp: &Option<SecurityPolicy>, container_port: u16, registered: &Arc<Mutex<HashSet<ContainerId>>>, integration: &ContainerIntegration, sender: &Box<dyn MessageSender + Send>) {
    let containers: Vec<ContainerId> = registered.lock()
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();
    for cid in &containers {
        let old_policy = integration.get_policy_value(cid.cgroup_id);
        if let Some(security_policy) = sp {
            if let Err(e) = integration.register_with_rollback(cid.cgroup_id, security_policy.clone(), container_port) {
                eprintln!("config apply: eBPF refresh failed for {}: {}, skipping", cid, e);
                continue;
            }
        }
        if let Some(cfg) = fc {
            if !send_filter_config_to_proxy(sender, cid, cfg) {
                rollback_ebpf(integration, cid, &old_policy);
                continue;
            }
        }
    }
}

/// Sends filter_config bound to container_id to proxy. Returns true on success.
fn send_filter_config_to_proxy(sender: &Box<dyn MessageSender + Send>, container_id: &ContainerId, cfg: &FilterConfig) -> bool {
    let rid = format!("config-{}-{}", container_id, SystemTime::now()
        .duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0));
    let payload = serde_json::json!({ "container_id": container_id, "filter_config": cfg });
    match sender.send(&ManagementMessage {msg_type: MSG_REFRESH_POLICY.to_string(), payload, request_id: rid}) {
        Ok(resp) if resp.status == "ok" => true,
        Ok(resp) => {
            eprintln!("config apply: proxy rejected for {}: status={}", container_id, resp.status);
            false
        }
        Err(e) => {
            eprintln!("config apply: send to proxy failed for {}: {}", container_id, e);
            false
        }
    }
}

/// Rolls back eBPF policy to the previous value.
fn rollback_ebpf(integration: &ContainerIntegration, container_id: &ContainerId, old_policy: &PolicySnapshot) {
    if let Err(e) = integration.restore_policy(container_id.cgroup_id, old_policy.clone()) {
        eprintln!("rollback failed for {}: {}", container_id, e);
    }
}

/// Removes all eBPF and proxy state for a container (called on container destruction).
fn unregister_container(container_id: ContainerId, mgmt: &Arc<Management>, sender: &Box<dyn MessageSender + Send>) {
    if let Err(e) = mgmt.integration.unregister(container_id.cgroup_id) {
        eprintln!("container unregister: eBPF cleanup failed for {}: {}", container_id, e);
    }
    send_remove_container_to_proxy(sender, &container_id);
    if let Ok(mut s) = mgmt.registered_containers.lock() {
        s.remove(&container_id);
    }
    eprintln!("container unregistered: {}", container_id);
}

/// Sends remove_container message to proxy_proc.
fn send_remove_container_to_proxy(sender: &Box<dyn MessageSender + Send>, container_id: &ContainerId) {
    let rid = format!("remove-{}-{}", container_id, SystemTime::now()
        .duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0));
    let payload = serde_json::json!({ "container_id": container_id });
    match sender.send(&ManagementMessage {msg_type: MSG_REMOVE_CONTAINER.to_string(), payload, request_id: rid}) {
        Ok(resp) if resp.status == "ok" => {}
        Ok(resp) => eprintln!("container unregister: proxy rejected for {}: status={}", container_id, resp.status),
        Err(e) => eprintln!("container unregister: send to proxy failed for {}: {}", container_id, e),
    }
}
