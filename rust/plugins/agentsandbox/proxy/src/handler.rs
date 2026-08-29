use std::collections::HashMap;
use std::sync::Mutex;

/// Phase of handler invocation: Request or Response stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase { Request, Response }

/// Target of handler modification: Header or Body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target { Header, Body }

/// Result returned by a registered handler.
/// Allow: pass through. Deny: block. Modify: replace content (Host header modification
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
pub struct HandlerRegistry {
    handlers: Mutex<HashMap<(Phase, Target), HandlerFn>>,
}

impl HandlerRegistry {
    pub fn new() -> Self {
        Self { handlers: Mutex::new(HashMap::new()) }
    }

    /// Registers a handler for the given (phase, target).
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
}
