use agentsandbox_config::SecurityPolicy;
use agentsandbox_log::{LogConfig, write_security_log};
use crate::ebpf::{EbpfLoader, EbpfError, PolicySnapshot};
use std::sync::Arc;
use thiserror::Error;

/// Policy management errors.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy update failed: {0}")]
    UpdateError(String),
    #[error("policy remove failed: {0}")]
    RemoveError(String),
    #[error("policy refresh failed: {0}")]
    RefreshError(String),
    #[error("event processing failed: {0}")]
    EventProcessError(String),
    #[error("log write failed: {0}")]
    LogWriteError(String),
    #[error("eBPF not loaded")]
    NotLoadedError,
}

impl From<EbpfError> for PolicyError {
    fn from(e: EbpfError) -> Self {
        match e {
            EbpfError::MapError(msg) => PolicyError::UpdateError(msg),
            EbpfError::RingBufferError(msg) => PolicyError::EventProcessError(msg),
            EbpfError::NotFoundError => PolicyError::UpdateError("not found".to_string()),
            EbpfError::NotLoadedError => PolicyError::NotLoadedError,
            other => PolicyError::UpdateError(other.to_string()),
        }
    }
}

/// Manages security policy table and log library integration.
pub struct SecurityPolicyManager {
    loader: Arc<EbpfLoader>,
    log_config: LogConfig,
}

impl SecurityPolicyManager {
    /// Creates a new SecurityPolicyManager wrapping the given EbpfLoader.
    pub fn new(loader: EbpfLoader, log_config: LogConfig) -> Self {
        Self { loader: Arc::new(loader), log_config }
    }

    /// Updates security policy for a cgroup_id in BPF map.
    pub fn update(&self, cgroup_id: u64, policy: SecurityPolicy, container_port: u16) -> Result<(), PolicyError> {
        self.loader.update_from_security_policy(cgroup_id, &policy, container_port).map_err(PolicyError::from)
    }

    /// Updates policy and returns the previous snapshot for rollback.
    pub fn update_with_rollback(&self, cgroup_id: u64, policy: SecurityPolicy, container_port: u16) -> Result<PolicySnapshot, PolicyError> {
        let snapshot = self.loader.snapshot_policy(cgroup_id);
        self.loader.update_from_security_policy(cgroup_id, &policy, container_port).map_err(PolicyError::from)?;
        Ok(snapshot)
    }

    /// Removes policy for a cgroup_id from BPF map.
    pub fn remove(&self, cgroup_id: u64) -> Result<(), PolicyError> {
        self.loader.remove_policy(cgroup_id).map_err(PolicyError::from)
    }

    /// Refreshes (replaces) security policy for a cgroup_id. Alias for update.
    pub fn refresh(&self, cgroup_id: u64, policy: SecurityPolicy, container_port: u16) -> Result<(), PolicyError> {
        self.update(cgroup_id, policy, container_port)
    }

    /// Returns the current policy snapshot for a cgroup_id.
    pub fn get_policy_value(&self, cgroup_id: u64) -> PolicySnapshot {
        self.loader.snapshot_policy(cgroup_id)
    }

    /// Restores a previous policy snapshot for a cgroup_id (rollback).
    pub fn restore_policy(&self, cgroup_id: u64, snapshot: PolicySnapshot) -> Result<(), PolicyError> {
        self.loader.restore_snapshot(cgroup_id, snapshot).map_err(PolicyError::from)
    }

    /// Blocks a cgroup's access to the HiController socket via dedicated sock_block_map.
    pub fn block_sock_access(&self, cgroup_id: u64, sock_path: &str) -> Result<(), PolicyError> {
        self.loader.block_sock_access(cgroup_id, sock_path).map_err(PolicyError::from)
    }

    /// Removes the sock block for a cgroup.
    pub fn unblock_sock_access(&self, cgroup_id: u64) -> Result<(), PolicyError> {
        self.loader.unblock_sock_access(cgroup_id).map_err(PolicyError::from)
    }

    /// Polls ring buffer for events and writes them to security.log via log library.
    pub fn process_events(&self) -> Result<(), PolicyError> {
        let events = self.loader.poll_events().map_err(PolicyError::from)?;
        for event in &events {
            if let Err(e) = write_security_log(event, &self.log_config) {
                return Err(PolicyError::LogWriteError(e.to_string()));
            }
        }
        Ok(())
    }

    /// Returns the count of active policy entries.
    pub fn active_count(&self) -> usize {
        self.loader.policy_count()
    }

    /// Unloads eBPF programs and clears all policies.
    pub fn unload(&self) -> Result<(), PolicyError> {
        self.loader.unload_programs().map_err(PolicyError::from)
    }
}
