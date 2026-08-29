use crate::policy::SecurityPolicyManager;
use crate::ebpf::EbpfLoader;
use agentsandbox_config::SecurityPolicy;

/// Container lifecycle integration: register/unregister on container create/destroy.
pub struct ContainerIntegration {
    policy_mgr: SecurityPolicyManager,
}

impl ContainerIntegration {
    pub fn new(loader: EbpfLoader) -> Self {
        Self { policy_mgr: SecurityPolicyManager::new(loader) }
    }

    /// Registers a container: updates BPF map with security policy.
    pub fn register(&self, cgroup_id: &str, policy: SecurityPolicy) {
        self.policy_mgr.update(cgroup_id, policy);
    }

    /// Unregisters a container: removes BPF map entry.
    pub fn unregister(&self, cgroup_id: &str) {
        self.policy_mgr.remove(cgroup_id);
    }
}
