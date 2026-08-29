use std::collections::HashMap;
use std::sync::Mutex;

/// Maps cgroup_id to group_id for proxy group resolution.
/// Written to virtio-fs shared file so proxy can read it via SO_PEERCRED flow.
pub struct CgroupMapping {
    inner: Mutex<HashMap<String, String>>,
}

impl CgroupMapping {
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    /// Adds or updates a cgroup_id→group_id mapping entry.
    pub fn add(&self, cgroup_id: &str, group_id: &str) {
        if let Ok(mut m) = self.inner.lock() {
            m.insert(cgroup_id.to_string(), group_id.to_string());
        }
    }

    /// Removes a mapping entry by cgroup_id.
    pub fn remove(&self, cgroup_id: &str) {
        if let Ok(mut m) = self.inner.lock() {
            m.remove(cgroup_id);
        }
    }

    /// Looks up group_id by cgroup_id. Returns None if not found.
    pub fn lookup(&self, cgroup_id: &str) -> Option<String> {
        self.inner.lock().ok()?.get(cgroup_id).cloned()
    }

    /// Writes all mappings to a file as JSON (key=cgroup_id, value=group_id).
    /// Used to share mappings with proxy via virtio-fs.
    pub fn flush_to_file(&self, path: &str) -> Result<(), std::io::Error> {
        let m = self.inner.lock()
            .unwrap_or_else(|e| e.into_inner());
        let json = serde_json::to_string_pretty(&*m)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }
}
