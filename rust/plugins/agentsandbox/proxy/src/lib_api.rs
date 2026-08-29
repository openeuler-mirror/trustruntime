use crate::ca::CaProvider;
use crate::error::ForwardError;
use crate::filter_engine::{FilterEngine, FilterResult};
use crate::group_config::GroupConfigMap;
use crate::handler::{HandlerRegistry, HandlerResult, Phase, Target};
use crate::log_sink::LogSinkRegistry;
use agentsandbox_config::FilterConfig;
use agentsandbox_log::AuditLogEntry;
use std::sync::Arc;

/// Scenario 2 lib API: public interface for integration partners.
pub struct ProxyLib {
    cfg: Arc<GroupConfigMap>,
    handlers: Arc<HandlerRegistry>,
    sink: Arc<LogSinkRegistry>,
}

impl ProxyLib {
    pub fn new(_ca: CaProvider) -> Self {
        Self {
            cfg: Arc::new(GroupConfigMap::new()),
            handlers: Arc::new(HandlerRegistry::new()),
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

    /// Registers a log sink callback for audit log output.
    pub fn register_log_sink<F>(&self, h: F)
    where F: Fn(&AuditLogEntry) -> Result<(), String> + Send + Sync + 'static {
        self.sink.register(h);
    }

    /// Forwards an HTTPS request with rule evaluation.
    pub fn forward_request(&self, gid: &str, domain: &str, method: &str, uri: &str) -> Result<(), ForwardError> {
        let fc = self.cfg.get(gid).ok_or(ForwardError::GroupNotFound)?;
        match FilterEngine::evaluate(&fc, domain, method, uri) {
            FilterResult::Deny(_) => Err(ForwardError::RuleDeny),
            FilterResult::Allow(_) => Ok(()),
        }
    }
}
