/// Embedded BPF bytecode compiled at build time by build.rs.
/// The .bpf.o files are generated from src/bpf/*.bpf.c via clang -target bpf,
/// output to OUT_DIR (target/...) and embedded via include_bytes!.

const CAPABILITY_BPF_O: &[u8] = include_bytes!(concat!(env!("BPF_OUT_DIR"), "/capability.bpf.o"));
const FILESYSTEM_BPF_O: &[u8] = include_bytes!(concat!(env!("BPF_OUT_DIR"), "/filesystem.bpf.o"));
const NETWORK_BPF_O: &[u8] = include_bytes!(concat!(env!("BPF_OUT_DIR"), "/network.bpf.o"));
const SOCKOPS_BPF_O: &[u8] = include_bytes!(concat!(env!("BPF_OUT_DIR"), "/sockops.bpf.o"));

/// Available BPF program names.
pub const ALL_PROGRAM_NAMES: &[&str] = &["capability", "filesystem", "network", "sockops"];

/// Returns the embedded bytecode for all BPF programs.
pub fn all_programs() -> &'static [(&'static str, &'static [u8])] {
    &[
        ("capability", CAPABILITY_BPF_O),
        ("filesystem", FILESYSTEM_BPF_O),
        ("network", NETWORK_BPF_O),
        ("sockops", SOCKOPS_BPF_O),
    ]
}

/// Returns bytecode for a single program by name, or None if not found.
pub fn program_by_name(name: &str) -> Option<&'static [u8]> {
    all_programs().iter()
        .find(|(n, _)| *n == name)
        .map(|(_, b)| *b)
}
