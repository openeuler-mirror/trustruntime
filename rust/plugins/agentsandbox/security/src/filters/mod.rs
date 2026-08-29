/// BPF filter implementations: capability, filesystem, network.
/// These are Rust-side policy evaluation stubs; actual enforcement is in eBPF C programs.

pub mod capability;
pub mod filesystem;
pub mod network;
