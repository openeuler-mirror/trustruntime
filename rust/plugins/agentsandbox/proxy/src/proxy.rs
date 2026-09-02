use crate::ca::CaProvider;
use crate::error::ProxyError;
use crate::filter_engine::{FilterEngine, FilterResult};
use crate::group_config::GroupConfigMap;
use crate::handler::{HandlerRegistry, HandlerResult};
use crate::mitm::MitmHandler;
use crate::response_action::{FlowCtx, ResponseAction, ResponseActionRegistry};
use crate::audit;
use agentsandbox_config::FilterConfig;
use agentsandbox_log::{AuditLogEntry, LogConfig};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Result of full request evaluation: rules → response action → handler chain.
#[derive(Debug, Clone)]
pub enum EvaluateResult {
    /// Request fully allowed, ready to forward.
    Allow { reason: String, modified_header: Option<Vec<u8>>, modified_body: Option<Vec<u8>> },
    /// Request allowed but bypass handler chain, forward as-is.
    Bypass { reason: String },
    /// Request blocked.
    Block { reason: String },
    /// Request forwarded to alternative target (handler Forward result).
    Forward { reason: String, target_url: String },
}

/// Scenario 1 proxy: TCP + SO_PEERCRED pid → /proc cgroup_id → filter_config by cgroup_id.
pub struct ProxyServer {
    cfg: Arc<GroupConfigMap>,
    #[allow(dead_code)]
    mitm: MitmHandler,
    actions: Arc<ResponseActionRegistry>,
    handlers: Arc<HandlerRegistry>,
    log_cfg: LogConfig,
}

impl ProxyServer {
    /// Creates a new ProxyServer with CA provider, config map, response action registry, handler registry, and log config.
    pub fn new(ca: CaProvider, cfg: Arc<GroupConfigMap>, actions: Arc<ResponseActionRegistry>, handlers: Arc<HandlerRegistry>, log_cfg: LogConfig) -> Self {
        Self { mitm: MitmHandler::new(ca), cfg, actions, handlers, log_cfg }
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

    /// Full evaluation: filter rules → response action → handler chain.
    /// Returns EvaluateResult with final decision and any modified content.
    pub fn evaluate_full(&self, cid: &str, domain: &str, method: &str, uri: &str, header: &[u8], body: &[u8]) -> EvaluateResult {
        let fc = match self.cfg.get(cid) {
            Some(fc) => fc,
            None => return EvaluateResult::Block { reason: "config_not_found".to_string() },
        };

        let rule_result = FilterEngine::evaluate(&fc, domain, method, uri);
        let rule_reason = match rule_result {
            FilterResult::Deny(r) => return EvaluateResult::Block { reason: r },
            FilterResult::Allow(r) => r,
        };

        let ctx = self.build_flow_ctx(cid, domain, method, uri);
        match self.actions.evaluate(&ctx) {
            ResponseAction::Allow => {
                let result = self.handlers.run_request_chain(header, body, cid);
                match result {
                    HandlerResult::Allow => EvaluateResult::Allow { reason: rule_reason, modified_header: None, modified_body: None },
                    HandlerResult::Deny => EvaluateResult::Block { reason: "handler_deny".to_string() },
                    HandlerResult::Modify { content } => EvaluateResult::Allow { reason: rule_reason, modified_header: Some(content), modified_body: None },
                    HandlerResult::Forward { target_url } => EvaluateResult::Forward { reason: rule_reason, target_url },
                }
            }
            ResponseAction::Bypass => EvaluateResult::Bypass { reason: rule_reason },
            ResponseAction::Cache => EvaluateResult::Bypass { reason: "cache".to_string() },
            ResponseAction::Block { reason, .. } => EvaluateResult::Block { reason },
        }
    }

    /// Simple evaluation without handler chain (compat with old API).
    pub fn evaluate(&self, cid: &str, domain: &str, method: &str, uri: &str) -> (bool, String) {
        let fc = match self.cfg.get(cid) {
            Some(fc) => fc,
            None => return (false, "config_not_found".to_string()),
        };
        match FilterEngine::evaluate(&fc, domain, method, uri) {
            FilterResult::Deny(r) => (false, r),
            FilterResult::Allow(r) => {
                let ctx = self.build_flow_ctx(cid, domain, method, uri);
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

    fn build_flow_ctx(&self, cid: &str, domain: &str, method: &str, uri: &str) -> FlowCtx {
        FlowCtx {
            flow_id: format!("flow-{}", SystemTime::now()
                .duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)),
            group_id: cid.to_string(),
            domain: domain.to_string(),
            method: method.to_string(),
            url_path: uri.to_string(),
            source_ip: None,
            scenario: "kata".to_string(),
        }
    }
}
