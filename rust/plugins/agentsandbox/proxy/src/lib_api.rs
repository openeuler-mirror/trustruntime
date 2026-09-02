use crate::ca::CaProvider;
use crate::error::ForwardError;
use crate::filter_engine::{FilterEngine, FilterResult};
use crate::group_config::GroupConfigMap;
use crate::handler::{HandlerRegistry, HandlerResult, Phase, Target};
use crate::log_sink::LogSinkRegistry;
use crate::response_action::{FlowCtx, ResponseAction, ResponseActionRegistry};
use crate::proxy::EvaluateResult;
use agentsandbox_config::FilterConfig;
use agentsandbox_log::AuditLogEntry;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Scenario 2 lib API: public interface for integration partners.
pub struct ProxyLib {
    cfg: Arc<GroupConfigMap>,
    handlers: Arc<HandlerRegistry>,
    actions: Arc<ResponseActionRegistry>,
    sink: Arc<LogSinkRegistry>,
}

impl ProxyLib {
    /// Creates a new ProxyLib with CA provider for dynamic certificate signing.
    pub fn new(_ca: CaProvider) -> Self {
        Self {
            cfg: Arc::new(GroupConfigMap::new()),
            handlers: Arc::new(HandlerRegistry::new()),
            actions: Arc::new(ResponseActionRegistry::new()),
            sink: Arc::new(LogSinkRegistry::new()),
        }
    }

    /// Injects filter_config for a group_id.
    pub fn set_filter_config(&self, gid: &str, fc: FilterConfig) {
        self.cfg.set(gid, fc);
    }

    /// Removes filter_config for a group_id.
    pub fn remove_filter_config(&self, gid: &str) {
        self.cfg.remove(gid);
    }

    /// Registers a handler for the given (phase, target).
    pub fn register_handler<F>(&self, p: Phase, t: Target, h: F)
    where F: Fn(&[u8], &str) -> HandlerResult + Send + Sync + 'static {
        self.handlers.register(p, t, h);
    }

    /// Registers a response action handler for a group_id.
    pub fn register_response_action<F>(&self, gid: &str, h: F)
    where F: Fn(&FlowCtx) -> ResponseAction + Send + Sync + 'static {
        self.actions.register(gid, h);
    }

    /// Registers a log sink callback for audit log output.
    pub fn register_log_sink<F>(&self, h: F)
    where F: Fn(&AuditLogEntry) -> Result<(), String> + Send + Sync + 'static {
        self.sink.register(h);
    }

    /// Full evaluation with handler chain: rules → response action → handler chain.
    pub fn evaluate(&self, gid: &str, domain: &str, method: &str, uri: &str, header: &[u8], body: &[u8]) -> EvaluateResult {
        let fc = match self.cfg.get(gid) {
            Some(fc) => fc,
            None => return EvaluateResult::Block { reason: "config_not_found".to_string() },
        };

        let rule_result = FilterEngine::evaluate(&fc, domain, method, uri);
        let rule_reason = match rule_result {
            FilterResult::Deny(r) => return EvaluateResult::Block { reason: r },
            FilterResult::Allow(r) => r,
        };

        let ctx = FlowCtx {
            flow_id: format!("flow-{}", SystemTime::now()
                .duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)),
            group_id: gid.to_string(),
            domain: domain.to_string(),
            method: method.to_string(),
            url_path: uri.to_string(),
            source_ip: None,
            scenario: "lib".to_string(),
        };

        match self.actions.evaluate(&ctx) {
            ResponseAction::Allow => {
                let result = self.handlers.run_request_chain(header, body, gid);
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

    /// Simple forward request with rule evaluation (compat with old API).
    pub fn forward_request(&self, gid: &str, domain: &str, method: &str, uri: &str) -> Result<(), ForwardError> {
        let fc = self.cfg.get(gid).ok_or(ForwardError::GroupNotFound)?;
        match FilterEngine::evaluate(&fc, domain, method, uri) {
            FilterResult::Deny(_) => Err(ForwardError::RuleDeny),
            FilterResult::Allow(_) => Ok(()),
        }
    }
}
