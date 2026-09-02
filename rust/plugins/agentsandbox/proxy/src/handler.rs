use std::collections::HashMap;
use std::sync::Mutex;

/// Phase of handler invocation: Request or Response stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase { Request, Response }

/// Target of handler modification: Header or Body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target { Header, Body }

/// Result returned by a registered handler.
/// Allow: pass through unchanged. Deny: block. Modify: replace content (Host header modification
/// causes proxy to connect to new target). Forward: redirect to specified URL.
#[derive(Debug, Clone)]
pub enum HandlerResult {
    Allow,
    Deny,
    Modify { content: Vec<u8> },
    Forward { target_url: String },
}

type HandlerFn = Box<dyn Fn(&[u8], &str) -> HandlerResult + Send + Sync>;

/// Registry for handler functions, keyed by (Phase, Target).
/// Handlers are global (not per-group); handler receives group_id as context to branch internally.
pub struct HandlerRegistry {
    handlers: Mutex<HashMap<(Phase, Target), HandlerFn>>,
}

impl HandlerRegistry {
    /// Creates an empty HandlerRegistry.
    pub fn new() -> Self {
        Self { handlers: Mutex::new(HashMap::new()) }
    }

    /// Registers a handler for the given (phase, target). Overwrites previous handler if any.
    pub fn register<F>(&self, p: Phase, t: Target, h: F)
    where F: Fn(&[u8], &str) -> HandlerResult + Send + Sync + 'static {
        if let Ok(mut m) = self.handlers.lock() {
            m.insert((p, t), Box::new(h));
        }
    }

    /// Invokes the handler for (phase, target) if registered. Returns None if no handler.
    pub fn invoke(&self, p: Phase, t: Target, content: &[u8], gid: &str) -> Option<HandlerResult> {
        let h = self.handlers.lock().ok()?;
        h.get(&(p, t)).map(|f| f(content, gid))
    }

    /// Returns true if a handler is registered for (phase, target).
    pub fn has_handler(&self, p: Phase, t: Target) -> bool {
        self.handlers.lock().map(|m| m.contains_key(&(p, t))).unwrap_or(false)
    }

    /// Runs the full request handler chain: Request/Header → Request/Body.
    /// Returns final HandlerResult (Allow if no handlers, Deny wins over Modify).
    pub fn run_request_chain(&self, header: &[u8], body: &[u8], gid: &str) -> HandlerResult {
        let header_result = self.invoke(Phase::Request, Target::Header, header, gid);
        if let Some(HandlerResult::Deny) = header_result {
            return HandlerResult::Deny;
        }
        if let Some(HandlerResult::Forward { target_url }) = header_result {
            return HandlerResult::Forward { target_url };
        }
        let body_result = self.invoke(Phase::Request, Target::Body, body, gid);
        if let Some(HandlerResult::Deny) = body_result {
            return HandlerResult::Deny;
        }
        if let Some(HandlerResult::Forward { target_url }) = body_result {
            return HandlerResult::Forward { target_url };
        }
        let modified_header = match header_result {
            Some(HandlerResult::Modify { content }) => Some(content),
            _ => None,
        };
        let modified_body = match body_result {
            Some(HandlerResult::Modify { content }) => Some(content),
            _ => None,
        };
        match (modified_header, modified_body) {
            (Some(h), Some(b)) => HandlerResult::Modify { content: [h, b].concat() },
            (Some(h), None) => HandlerResult::Modify { content: h },
            (None, Some(b)) => HandlerResult::Modify { content: b },
            (None, None) => HandlerResult::Allow,
        }
    }

    /// Runs the full response handler chain: Response/Header → Response/Body.
    pub fn run_response_chain(&self, header: &[u8], body: &[u8], gid: &str) -> HandlerResult {
        self.run_request_chain(header, body, gid)
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}
