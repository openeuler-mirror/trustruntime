/// Embedded BPF bytecode compiled at build time by build.rs.
/// The .bpf.o files are generated from src/bpf/*.bpf.c via clang -target bpf.

const CAPABILITY_BPF_O: &[u8] = include_bytes!("../src/bpf/capability.bpf.o");
const FILESYSTEM_BPF_O: &[u8] = include_bytes!("../src/bpf/filesystem.bpf.o");
const NETWORK_BPF_O: &[u8] = include_bytes!("../src/bpf/network.bpf.o");

/// Returns the embedded bytecode for all BPF programs.
pub fn all_programs() -> &'static [(&'static str, &'static [u8])] {
    &[
        ("capability", CAPABILITY_BPF_O),
        ("filesystem", FILESYSTEM_BPF_O),
        ("network", NETWORK_BPF_O),
    ]
}
