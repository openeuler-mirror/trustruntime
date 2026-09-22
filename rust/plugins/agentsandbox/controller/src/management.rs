use crate::config_monitor::ConfigMonitor;
use crate::messaging::{ManagementMessage, MessageSender, MSG_REFRESH_POLICY, MSG_REMOVE_CONTAINER};
use crate::sock_listener::{ContainerAction, SockListener};
use agentsandbox_config::{ContainerId, FilterConfig, SecurityPolicy, parse_security_policy, parse_proxy_policy, parse_container_port};
use agentsandbox_security::{ContainerIntegration, EbpfLoader, PolicySnapshot};
use agentsandbox_log::LogConfig;
use std::collections::{HashSet, HashMap};
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
    container_configs: Arc<Mutex<HashMap<ContainerId, String>>>,
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
        let cm = ConfigMonitor::new(config_dir);
        cm.start().map_err(|e| MgmtError::ConfigError(e.to_string()))?;
        Ok(Self {
            cm,
            integration,
            registered_containers: Arc::new(Mutex::new(HashSet::new())),
            container_configs: Arc::new(Mutex::new(HashMap::new())),
            sock_path: sock_path.to_string(),
        })
    }

    /// Starts config file monitoring in a background thread. On TOML change, applies config to the associated container only.
    pub fn start_config_monitor(&self, sender: &dyn MessageSender) -> Result<(), MgmtError> {
        let integration = self.integration.clone();
        let cm = self.cm.clone_for_watch();
        let container_configs = self.container_configs.clone();
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
                let target_cid = container_configs.lock()
                    .ok()
                    .and_then(|m| m.iter().find(|(_, p)| *p == path).map(|(c, _)| c.clone()));
                match target_cid {
                    Some(cid) => apply_config_to_container(&fc, &sp, cp, &cid, &integration, &sender_box),
                    None => eprintln!("config change for unregistered path: {}", path),
                }
            }).ok();
        });
        Ok(())
    }

    /// Periodically drains eBPF ring buffer events and writes them to security.log.
    fn start_event_poller(&self) {
        let integration = self.integration.clone();
        thread::spawn(move || loop {
            if let Err(e) = integration.process_events() {
                eprintln!("security event poll failed: {}", e);
            }
            thread::sleep(std::time::Duration::from_millis(100));
        });
    }

    /// Runs the main event loop: config monitoring + sock listener for container lifecycle.
    pub async fn run(self: Arc<Self>, sock_listener: SockListener, sender: &dyn MessageSender) -> Result<(), MgmtError> {
        self.start_config_monitor(sender)?;
        self.start_event_poller();
        let mgmt = self.clone();
        let sender_box: Box<dyn MessageSender + Send> = sender.clone_box();

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
    if let Ok(mut m) = mgmt.container_configs.lock() {
        m.insert(container_id.clone(), config_path.to_string());
    }
    if let Err(e) = mgmt.cm.add_watch(config_path) {
        eprintln!("container register: failed to watch config {} for {}: {}", config_path, container_id, e);
    }
    if let Err(e) = mgmt.integration.block_sock_access(container_id.cgroup_id, &mgmt.sock_path) {
        eprintln!("container register: block sock failed for {}: {}", container_id, e);
    }
}

/// Applies config to a single container on TOML hot-reload.
fn apply_config_to_container(fc: &Option<FilterConfig>, sp: &Option<SecurityPolicy>, container_port: u16, cid: &ContainerId, integration: &ContainerIntegration, sender: &Box<dyn MessageSender + Send>) {
    let old_policy = integration.get_policy_value(cid.cgroup_id);
    if let Some(security_policy) = sp {
        if let Err(e) = integration.register_with_rollback(cid.cgroup_id, security_policy.clone(), container_port) {
            eprintln!("config apply: eBPF refresh failed for {}: {}, skipping", cid, e);
            return;
        }
    }
    if let Some(cfg) = fc {
        if !send_filter_config_to_proxy(sender, cid, cfg) {
            rollback_ebpf(integration, cid, &old_policy);
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
    if let Some(config_path) = mgmt.container_configs.lock().ok()
        .and_then(|mut m| m.remove(&container_id)) {
        mgmt.cm.remove_watch(&config_path);
    }
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
