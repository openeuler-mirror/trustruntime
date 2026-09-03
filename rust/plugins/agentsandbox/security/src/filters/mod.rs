/// Rust-side filter evaluation utilities.
/// These mirror the kernel-side eBPF enforcement logic for testing and user-space re-evaluation.
pub mod capability;
pub mod filesystem;
pub mod network;

/// Result of filter evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum FilterDecision {
    /// Operation allowed.
    Allow,
    /// Operation blocked.
    Block,
    /// Operation allowed but logged.
    Alert,
    /// Network connection redirected to proxy.
    Redirect,
}
