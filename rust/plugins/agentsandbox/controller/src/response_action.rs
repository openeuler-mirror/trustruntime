use std::collections::HashMap;
use std::sync::Mutex;

/// Manages response action handlers registered via management message.
/// Each handler is identified by msg_type="register_response_action".
pub struct ResponseActionManager {
    handlers: Mutex<HashMap<String, serde_json::Value>>,
}

impl ResponseActionManager {
    pub fn new() -> Self {
        Self { handlers: Mutex::new(HashMap::new()) }
    }

    /// Registers a response action handler for a group_id.
    pub fn register(&self, group_id: &str, handler_config: serde_json::Value) {
        if let Ok(mut h) = self.handlers.lock() {
            h.insert(group_id.to_string(), handler_config);
        }
    }

    /// Removes a registered handler for a group_id.
    pub fn unregister(&self, group_id: &str) {
        if let Ok(mut h) = self.handlers.lock() {
            h.remove(group_id);
        }
    }

    /// Returns the handler config for a group_id, if registered.
    pub fn get(&self, group_id: &str) -> Option<serde_json::Value> {
        self.handlers.lock().ok()?.get(group_id).cloned()
    }
}
