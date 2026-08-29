use agentsandbox_config::SecurityPolicy;
use crate::ebpf::EbpfLoader;

/// Manages security policy table and config library integration.
pub struct SecurityPolicyManager {
    loader: EbpfLoader,
}

impl SecurityPolicyManager {
    pub fn new(loader: EbpfLoader) -> Self {
        Self { loader }
    }

    /// Updates security policy for a cgroup_id.
    pub fn update(&self, cgroup_id: &str, policy: SecurityPolicy) {
        self.loader.update_policy(cgroup_id, policy);
    }

    /// Removes policy for a cgroup_id.
    pub fn remove(&self, cgroup_id: &str) {
        self.loader.remove_policy(cgroup_id);
    }
}
