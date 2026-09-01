use crate::cgroup_mapping::CgroupMapping;
use crate::config_monitor::ConfigMonitor;
use crate::messaging::{ManagementMessage, MessageSender, MSG_REFRESH_POLICY};
use std::sync::Arc;
/// HiController management facade: lifecycle, health check, config distribution.
pub struct Management {
    cgm: Arc<CgroupMapping>,
    cm: ConfigMonitor,
}

impl Management {
    pub fn new(cgm: Arc<CgroupMapping>, cm: ConfigMonitor) -> Self {
        Self { cgm, cm }
    }

    /// Starts config monitoring loop. On TOML change, distributes filter_config to proxy.
    /// Blocks the calling thread; spawn in a dedicated task.
    pub fn start_config_monitor(&self, sender: Arc<dyn MessageSender>) -> Result<(), String> {
        let cm = self.cm.clone();
        let cm_inner = cm.clone();
        cm.watch(move |path| {
            if let Ok((fc, _)) = cm_inner.parse_file(path) {
                if let Some(cfg) = fc {
                    let rid = format!("config-{}", std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0));
                    let _ = sender.send(&ManagementMessage {
                        msg_type: MSG_REFRESH_POLICY.to_string(),
                        payload: serde_json::to_value(&cfg).unwrap_or(serde_json::Value::Null),
                        request_id: rid,
                    });
                }
            }
        }).map_err(|e| e.to_string())
    }

    /// Registers a cgroup_id→group_id mapping (called on container creation).
    pub fn register_container(&self, cid: &str, gid: &str) {
        self.cgm.add(cid, gid);
    }

    /// Removes a cgroup_id→group_id mapping (called on container destruction).
    pub fn unregister_container(&self, cid: &str) {
        self.cgm.remove(cid);
    }
}
