use crate::ca::CaProvider;
use crate::error::ProxyError;
use crate::filter_engine::{FilterEngine, FilterResult};
use crate::group_config::GroupConfigMap;
use crate::handler::HandlerRegistry;
use crate::mitm::MitmHandler;
use crate::response_action::{FlowCtx, ResponseAction, ResponseActionRegistry};
use crate::audit;
use agentsandbox_config::FilterConfig;
use agentsandbox_log::{AuditLogEntry, LogConfig};
use std::collections::HashMap;
use std::sync::Arc;

/// Scenario 1 proxy: TCP + SO_PEERCRED pid → /proc cgroup_id → virtio-fs mapping → group_id.
pub struct ProxyServer {
    cfg: Arc<GroupConfigMap>,
    mitm: MitmHandler,
    actions: Arc<ResponseActionRegistry>,
    handlers: Arc<HandlerRegistry>,
    log_cfg: LogConfig,
    cgroup_path: String,
}

impl ProxyServer {
    pub fn new(ca: CaProvider, cfg: Arc<GroupConfigMap>, actions: Arc<ResponseActionRegistry>,
               handlers: Arc<HandlerRegistry>, log_cfg: LogConfig, cgroup_path: &str) -> Self {
        Self { mitm: MitmHandler::new(ca), cfg, actions, handlers, log_cfg, cgroup_path: cgroup_path.to_string() }
    }

    /// Reads /proc/<pid>/cgroup and extracts cgroup_id path.
    pub fn read_cgroup_id(pid: u32) -> Result<String, ProxyError> {
        let path = format!("/proc/{}/cgroup", pid);
        let content = std::fs::read_to_string(&path).map_err(|_| ProxyError::GroupIdNotFound)?;
        for line in content.lines() {
            if let Some(p) = line.split("::").nth(1) {
                return Ok(p.to_string());
            }
        }
        Err(ProxyError::GroupIdNotFound)
    }

    /// Looks up group_id from virtio-fs shared mapping file by cgroup_id.
    pub fn lookup_group_id(&self, cid: &str) -> Result<String, ProxyError> {
        let content = std::fs::read_to_string(&self.cgroup_path).map_err(|_| ProxyError::GroupIdNotFound)?;
        let map: HashMap<String, String> = serde_json::from_str(&content).map_err(|_| ProxyError::GroupIdNotFound)?;
        map.get(cid).cloned().ok_or(ProxyError::GroupIdNotFound)
    }

    /// Evaluates filter rules and response action for an incoming request.
    pub fn evaluate(&self, gid: &str, domain: &str, method: &str, uri: &str) -> (bool, String) {
        let fc = match self.cfg.get(gid) {
            Some(fc) => fc,
            None => return (false, "config_not_found".to_string()),
        };
        match FilterEngine::evaluate(&fc, domain, method, uri) {
            FilterResult::Deny(r) => (false, r),
            FilterResult::Allow(r) => {
                let ctx = FlowCtx {
                    flow_id: format!("flow-{}", std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)),
                    group_id: gid.to_string(), domain: domain.to_string(),
                    method: method.to_string(), url_path: uri.to_string(),
                    source_ip: None, scenario: "kata".to_string(),
                };
                match self.actions.evaluate(&ctx) {
                    ResponseAction::Allow => (true, r),
                    ResponseAction::Bypass => (true, "bypass".to_string()),
                    ResponseAction::Cache => (true, "cache".to_string()),
                    ResponseAction::Block { reason: br, .. } => (false, br),
                }
            }
        }
    }

    /// Writes audit log for a request decision.
    pub fn audit(&self, fc: &FilterConfig, entry: &AuditLogEntry) {
        let _ = audit::write_audit_if_enabled(fc, entry, &self.log_cfg);
    }
}
