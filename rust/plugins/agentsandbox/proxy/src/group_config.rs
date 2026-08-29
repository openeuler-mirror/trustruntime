use agentsandbox_config::FilterConfig;
use std::collections::HashMap;
use std::sync::Mutex;

/// Per-group versioned filter_config store. Supports drain mode (old connections keep
/// previous config until drained) and reset mode (immediate disconnect of old connections).
pub struct GroupConfigMap {
    inner: Mutex<HashMap<String, ConfigEntry>>,
}

struct ConfigEntry {
    current: FilterConfig,
    previous: Option<FilterConfig>,
    pending_drain: usize,
}

impl GroupConfigMap {
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    /// Sets a new filter_config for a group. If drain mode, preserves previous config.
    pub fn set(&self, group_id: &str, fc: FilterConfig) {
        if let Ok(mut m) = self.inner.lock() {
            let entry = m.entry(group_id.to_string()).or_insert(ConfigEntry {
                current: fc.clone(), previous: None, pending_drain: 0,
            });
            if fc.policy_change_strategy == "drain" && entry.pending_drain > 0 {
                entry.previous = Some(entry.current.clone());
            }
            entry.current = fc;
        }
    }

    /// Returns the current filter_config for a group. None if group not registered.
    pub fn get(&self, group_id: &str) -> Option<FilterConfig> {
        let m = self.inner.lock().ok()?;
        m.get(group_id).map(|e| e.current.clone())
    }

    /// Removes a group's config entry.
    pub fn remove(&self, group_id: &str) {
        if let Ok(mut m) = self.inner.lock() { m.remove(group_id); }
    }

    /// Increments drain counter for a group.
    pub fn drain_inc(&self, group_id: &str) {
        if let Ok(mut m) = self.inner.lock() {
            if let Some(e) = m.get_mut(group_id) { e.pending_drain += 1; }
        }
    }

    /// Decrements drain counter and releases previous config if drained to zero.
    pub fn drain_dec(&self, group_id: &str) {
        if let Ok(mut m) = self.inner.lock() {
            if let Some(e) = m.get_mut(group_id) {
                if e.pending_drain > 0 { e.pending_drain -= 1; }
                if e.pending_drain == 0 { e.previous = None; }
            }
        }
    }
}
