use std::process::Command;
use std::path::PathBuf;

fn main() {
    let bpf_dir = PathBuf::from("src/bpf");
    let bpf_progs = ["capability.bpf.c", "filesystem.bpf.c", "network.bpf.c"];

    let clang = std::env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    let bpftool = std::env::var("BPFTOOL").unwrap_or_else(|_| "bpftool".to_string());
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| std::env::consts::ARCH.to_string());

    let have_clang = Command::new(&clang).arg("--version").output().map(|o| o.status.success()).unwrap_or(false);
    let have_bpftool = Command::new(&bpftool).arg("version").output().map(|o| o.status.success()).unwrap_or(false);

    if have_clang {
        if have_bpftool {
            let vmlinux_h = bpf_dir.join("vmlinux.h");
            if !vmlinux_h.exists() {
                let _ = Command::new(&bpftool).args(["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"]).stdout(std::fs::File::create(&vmlinux_h).unwrap()).status();
            }
        }
        for prog in &bpf_progs {
            let src = bpf_dir.join(prog);
            let obj = bpf_dir.join(prog.replace(".bpf.c", ".bpf.o"));
            println!("cargo:rerun-if-changed={}", src.display());
            let status = Command::new(&clang).args(["-O2", "-g", "-target", "bpf", &format!("-D__TARGET_ARCH_{}", arch), "-I/usr/include", "-Isrc/bpf", "-Wall", "-Wno-unused-variable", "-c", &src.to_string_lossy(), "-o", &obj.to_string_lossy()]).status();
            if !status.map(|s| s.success()).unwrap_or(false) {
                eprintln!("cargo:warning=Failed to compile BPF program: {}, generating empty object", prog);
                std::fs::write(&obj, []).ok();
            }
        }
    } else {
        eprintln!("cargo:warning=clang not found, generating empty BPF object files");
        for prog in &bpf_progs {
            let obj = bpf_dir.join(prog.replace(".bpf.c", ".bpf.o"));
            std::fs::write(&obj, []).ok();
        }
    }
    println!("cargo:rerun-if-changed=src/bpf/common.bpf.h");
}
