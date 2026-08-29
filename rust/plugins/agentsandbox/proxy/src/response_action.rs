use std::collections::HashMap;
use std::sync::Mutex;

/// Flow context passed to response action handler.
#[derive(Debug, Clone)]
pub struct FlowCtx {
    pub flow_id: String,
    pub group_id: String,
    pub domain: String,
    pub method: String,
    pub url_path: String,
    pub source_ip: Option<String>,
    pub scenario: String,
}

/// Response action returned by handler determining traffic flow after rule evaluation.
#[derive(Debug, Clone)]
pub enum ResponseAction {
    Allow,
    Bypass,
    Cache,
    Block { reason: String, message: Option<String> },
}

type ActionFn = Box<dyn Fn(&FlowCtx) -> ResponseAction + Send + Sync>;

/// Registry for response action handlers. Called after rule passes, before handler chain.
pub struct ResponseActionRegistry {
    handlers: Mutex<HashMap<String, ActionFn>>,
}

impl ResponseActionRegistry {
    pub fn new() -> Self {
        Self { handlers: Mutex::new(HashMap::new()) }
    }

    /// Registers a response action handler for a group_id.
    pub fn register<F>(&self, gid: &str, h: F)
    where F: Fn(&FlowCtx) -> ResponseAction + Send + Sync + 'static {
        if let Ok(mut m) = self.handlers.lock() {
            m.insert(gid.to_string(), Box::new(h));
        }
    }

    /// Evaluates the response action for a flow. Returns Allow if no handler registered.
    pub fn evaluate(&self, ctx: &FlowCtx) -> ResponseAction {
        let h = self.handlers.lock().ok();
        if let Some(h) = h {
            if let Some(f) = h.get(&ctx.group_id) {
                return f(ctx);
            }
        }
        ResponseAction::Allow
    }
}
