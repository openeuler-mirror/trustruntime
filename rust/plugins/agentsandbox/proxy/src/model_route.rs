use crate::handler::{HandlerRegistry, HandlerResult, Phase, Target};

/// Model route handler (AR.005): container-local HTTPS entry → proxy routes to real model.
pub struct ModelRouter {
    handlers: HandlerRegistry,
}

impl ModelRouter {
    pub fn new(h: HandlerRegistry) -> Self {
        Self { handlers: h }
    }

    /// Returns modified target domain if handler modifies Host header, otherwise original.
    pub fn resolve_target(&self, orig_domain: &str, gid: &str) -> String {
        let r = self.handlers.invoke(Phase::Request, Target::Header, orig_domain.as_bytes(), gid);
        match r {
            Some(HandlerResult::Modify { content }) => String::from_utf8_lossy(&content).to_string(),
            _ => orig_domain.to_string(),
        }
    }
}
