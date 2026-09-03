use crate::policy::{SecurityPolicyManager, PolicyError};
use crate::ebpf::{EbpfLoader, PolicySnapshot};
use agentsandbox_config::SecurityPolicy;
use agentsandbox_log::LogConfig;
use std::sync::Arc;

/// Container lifecycle integration: register/unregister on container create/destroy.
#[derive(Clone)]
pub struct ContainerIntegration {
    policy_mgr: Arc<SecurityPolicyManager>,
}

impl ContainerIntegration {
    /// Creates a new ContainerIntegration with the given eBPF loader and log config.
    pub fn new(loader: EbpfLoader, log_config: LogConfig) -> Self {
        Self { policy_mgr: Arc::new(SecurityPolicyManager::new(loader, log_config)) }
    }

    /// Registers a container: updates all BPF maps with security policy.
    pub fn register(&self, cgroup_id: u64, policy: SecurityPolicy, container_port: u16) -> Result<(), PolicyError> {
        self.policy_mgr.update(cgroup_id, policy, container_port)
    }

    /// Registers a container and returns the previous snapshot for rollback.
    pub fn register_with_rollback(&self, cgroup_id: u64, policy: SecurityPolicy, container_port: u16) -> Result<PolicySnapshot, PolicyError> {
        self.policy_mgr.update_with_rollback(cgroup_id, policy, container_port)
    }

    /// Unregisters a container: removes all BPF map entries.
    pub fn unregister(&self, cgroup_id: u64) -> Result<(), PolicyError> {
        self.policy_mgr.remove(cgroup_id)
    }

    /// Refreshes security policy for a cgroup_id (config change).
    pub fn refresh(&self, cgroup_id: u64, policy: SecurityPolicy, container_port: u16) -> Result<(), PolicyError> {
        self.policy_mgr.refresh(cgroup_id, policy, container_port)
    }

    /// Returns the current policy snapshot for a cgroup_id (for rollback).
    pub fn get_policy_value(&self, cgroup_id: u64) -> PolicySnapshot {
        self.policy_mgr.get_policy_value(cgroup_id)
    }

    /// Restores a previous policy snapshot for a cgroup_id (rollback after proxy failure).
    pub fn restore_policy(&self, cgroup_id: u64, snapshot: PolicySnapshot) -> Result<(), PolicyError> {
        self.policy_mgr.restore_policy(cgroup_id, snapshot)
    }

    /// Blocks a cgroup's access to the HiController socket via eBPF sock_block_map.
    pub fn block_sock_access(&self, cgroup_id: u64, sock_path: &str) -> Result<(), PolicyError> {
        self.policy_mgr.block_sock_access(cgroup_id, sock_path)
    }

    /// Removes the sock block for a cgroup.
    pub fn unblock_sock_access(&self, cgroup_id: u64) -> Result<(), PolicyError> {
        self.policy_mgr.unblock_sock_access(cgroup_id)
    }

    /// Polls and processes security events from eBPF ring buffer.
    pub fn process_events(&self) -> Result<(), PolicyError> {
        self.policy_mgr.process_events()
    }

    /// Returns the count of active (registered) containers.
    pub fn active_count(&self) -> usize {
        self.policy_mgr.active_count()
    }

    /// Unloads eBPF programs and clears all policies.
    pub fn unload(&self) -> Result<(), PolicyError> {
        self.policy_mgr.unload()
    }
}
