use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::os::unix::fs::MetadataExt;

use serde::{Deserialize, Serialize};
use agentsandbox_config::ContainerId;

/// Registration message sent to HiController.
#[derive(Debug, Serialize)]
struct RegisterMessage {
    msg_type: String,
    container_id: ContainerId,
    config_path: String,
}

/// Response from HiController.
#[derive(Debug, Deserialize)]
struct RegisterResponse {
    status: String,
}

/// Reads cgroup_id from /proc/self/cgroup.
fn read_cgroup_id() -> anyhow::Result<u64> {
    let content = fs::read_to_string("/proc/self/cgroup")?;
    let line = content.lines().next().ok_or_else(|| anyhow::anyhow!("empty cgroup file"))?;

    let line_vec:Vec<&str> = line.split(':').collect();
    let (hier, subsys, path) = match line_vec.as_slice() {
        [hier, subsys, path] => (hier, subsys, path),
        _ => return Err(anyhow::anyhow!("invalid cgroup file")),
    };

    let full = if *hier == "0" && *subsys == "" {
        // cgroup v2: 0::/
        format!("/sys/fs/cgroup{}", path)
    } else {
        // cgroup v1: hier:subsys:path
        format!("/sys/fs/cgroup/{}{}", subsys, path)
    };

    let meta = fs::metadata(full)?;
    Ok(meta.ino())
}

/// Sends registration message to HiController and receives response.
fn send_registration(sock_path: &str, container_id: ContainerId, config_path: &str) -> anyhow::Result<RegisterResponse> {
    let mut stream = UnixStream::connect(sock_path)?;
    let msg = RegisterMessage { msg_type: "register".to_string(), container_id, config_path: config_path.to_string() };
    let json = serde_json::to_string(&msg)?;
    stream.write_all(json.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    stream.shutdown(Shutdown::Write)?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let resp: RegisterResponse = serde_json::from_slice(&buf)?;
    Ok(resp)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("agentsandbox-hook: {}", e);
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let sock_path = env::var("AGENTSANDBOX_SOCK_PATH")
        .map_err(|_| anyhow::anyhow!("AGENTSANDBOX_SOCK_PATH not set"))?;
    let config_path = env::var("AGENTSANDBOX_CONFIG_PATH")
        .map_err(|_| anyhow::anyhow!("AGENTSANDBOX_CONFIG_PATH not set"))?;

    let cgroup_id = read_cgroup_id()?;

    let resp = send_registration(&sock_path, ContainerId::new(cgroup_id), &config_path)?;

    if resp.status != "ok" {
        anyhow::bail!("HiController rejected registration: status={}", resp.status);
    }

    Ok(())
}
