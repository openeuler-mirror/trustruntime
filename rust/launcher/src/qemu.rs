/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

use crate::{
    cli::{PortForwardValue, VirtiofsBind, VolumeValue},
    utils::{ExecutablePaths, create_vm_work_dir},
};
use anyhow::{Context, Result};
use log::{error, info, warn};
use std::error::Error;
use std::fmt::Write;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::fs;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

#[derive(Debug, Clone)]
pub struct QemuLaunchOpts {
    pub virtiofs_vols: Vec<VirtiofsBind>,
    pub published_ports: Vec<PortForwardValue>,
    pub image_path: PathBuf,
    pub qemu_args: Option<String>,
    pub payload: Option<PathBuf>,
    pub cert_dir: Option<PathBuf>,
    pub vol_9p_paths: Vec<VolumeValue>,
    pub mem: u32,
    pub smp: u32,
    pub cid: u32,
}

pub fn command_as_string(cmd: &Command) -> String {
    let program_str = cmd.as_std().get_program().to_string_lossy();
    let args_str = cmd
        .as_std()
        .get_args()
        .map(|x| x.to_string_lossy())
        .map(|x| escape_arg(&x))
        .collect::<Vec<_>>()
        .join(" ");

    format!("{program_str} {args_str}")
}

fn escape_arg(arg: &str) -> String {
    let needs_escape = arg.contains(|c: char| {
        c.is_whitespace() || c == '\\' || c == '"' || c == '$' || c == '`' || c == '|'
    });

    if needs_escape {
        let escaped: String = arg
            .chars()
            .map(|c| match c {
                '\\' | '"' => format!("\\{}", c),
                _ => c.to_string(),
            })
            .collect();
        format!("\"{}\"", escaped)
    } else {
        arg.to_string()
    }
}

pub async fn launch_virtiofsd(
    virtiofsd_path: &Path,
    run_dir: &Path,
    virtiofs_vols: &VirtiofsBind,
) -> Result<Child, Box<dyn Error>> {
    let socket_path = run_dir.join("virtiofs.sock");
    let mut virtiofsd_cmd = Command::new("unshare");
    virtiofsd_cmd
        .arg("-r")
        .arg("--")
        .arg(virtiofsd_path)
        .args(["--socket-path", &socket_path.to_string_lossy()])
        .args(["--shared-dir", &virtiofs_vols.host_path])
        .args(["--cache=auto"]);
    let virtiofsd_cmd_str = command_as_string(&virtiofsd_cmd);

    info!("Running virtiofsd, cmd is: {}", virtiofsd_cmd_str);

    let mut virtiofsd_child = virtiofsd_cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    tokio::select! {
        _ = tokio::time::sleep(Duration::from_millis(250)) => {},
        _ = virtiofsd_child.wait() => {
            error!("virtiofsd process exited early, that's usually a bad sign");
            let virtiofsd_output = virtiofsd_child.wait_with_output().await?;
            return Err(format!("Virtiofsd failed: {}", String::from_utf8(virtiofsd_output.stderr)?).into());
        }
    }
    Ok(virtiofsd_child)
}

fn configure_basic_qemu_command(qemu_cmd: &mut Command, qemu_launch_opts: &QemuLaunchOpts) {
    let mem_size = qemu_launch_opts.mem;
    let smp_cores = qemu_launch_opts.smp;
    let cid = qemu_launch_opts.cid;
    qemu_cmd
        .args(["-machine", "virt,acpi=on,accel=kvm,gic-version=3,confidential-guest-support=rme0",])
        .args(["-enable-kvm"])
        .args(["-cpu", "host"])
        .args(["-m", &format!("size={mem_size}M")])
        .args(["-overcommit", "mem-lock=off"])
        .args(["-smp", &format!("{smp_cores}")])
        .args(["-append", "rdinit=init console=ttyAMA0 rodata=full nosoftlockup rcupdate.rcu_cpu_stall_timeout=3000"])
        .args(["-nographic"])
        .args(["-object", "rme-guest,id=rme0,measurement-algorithm=sha512,hisi-cca-enable=off"])
        .args(["-device", &format!("vhost-vsock-pci,guest-cid={cid}")]);
}

fn configure_kernel_and_payload(qemu_cmd: &mut Command, qemu_launch_opts: &QemuLaunchOpts) {
    let image_str = qemu_launch_opts.image_path.to_string_lossy();
    info!("using kernel path: {}", image_str);
    qemu_cmd.args(["-kernel", &image_str]);
    if let Some(initrd_path) = &qemu_launch_opts.payload {
        let initrd_path = initrd_path.to_string_lossy();
        info!("using initrd_path: {}", initrd_path);
        qemu_cmd.args(["-initrd", &initrd_path]);
    } else {
        qemu_cmd.args(["-initrd", "/mnt/out-br/images/rootfs.cpio"]);
    }
}

async fn configure_virtio_9p_single(
    qemu_cmd: &mut Command,
    vol_9p_path: &PathBuf,
    mount_tag: String,
    fsdev_id: usize,
) -> Result<(), Box<dyn Error>> {
    let vol_9p_meta = match fs::metadata(&vol_9p_path).await {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "Could not access target path{}, error:{}",
                vol_9p_path.display(),
                e
            )
            .into());
        }
    };
    if !vol_9p_meta.is_dir() {
        return Err(format!(
            "virtio9p sharing directory {} is not a folder \n",
            vol_9p_path.display()
        )
        .into());
    }
    let vol_9p_path_str = vol_9p_path.to_string_lossy();
    qemu_cmd
        .args([
            "-fsdev",
            &format!("local,security_model=passthrough,id=fsdev{fsdev_id},path={vol_9p_path_str}"),
        ])
        .args([
            "-device",
            &format!("virtio-9p-pci,fsdev=fsdev{fsdev_id},mount_tag={mount_tag}"),
        ]);

    Ok(())
}

fn configure_port_forwarding(qemu_cmd: &mut Command, qemu_launch_opts: &QemuLaunchOpts) {
    let hostfwd = qemu_launch_opts
        .published_ports
        .iter()
        .fold(String::new(), |mut output, p| {
            let _ = write!(
                output,
                ",hostfwd=:{}:{}-:{}",
                p.host_ip, p.host_port, p.guest_port
            );
            output
        });
    qemu_cmd.args(["-netdev", &format!("user,id=net0{hostfwd}")]);
    qemu_cmd.args(["-device", "virtio-net-pci,netdev=net0,rombar=0"]);
}

async fn configure_virtiofsd(
    qemu_cmd: &mut Command,
    tool_paths: &ExecutablePaths,
    run_dir: &Path,
    qemu_launch_opts: &QemuLaunchOpts,
) -> Result<Vec<Child>, Box<dyn Error>> {
    let mut virtiofsd_handles = vec![];
    let mut fstab_entries = vec![];

    for (i, vol) in qemu_launch_opts.virtiofs_vols.iter().enumerate() {
        if let Some(virtiofsd_path) = &tool_paths.virtiofsd_path {
            let virtiofsd_child = launch_virtiofsd(virtiofsd_path, run_dir, vol)
                .await
                .map_err(|e| format!("Failed to launch virtiofsd_path for {vol}: {}", e))?;
            virtiofsd_handles.push(virtiofsd_child);
            let socket_path = run_dir.join(vol.socket_name());
            let socket_path_str = socket_path.to_string_lossy();
            let tag = vol.tag();
            let dest_path = &vol.guest_path;
            let fstab_entry = format!("{tag} {dest_path} virtiofs defaults 0 0");
            fstab_entries.push(fstab_entry);
            qemu_cmd
                .args([
                    "-chardev",
                    &format!("socket,id=char{i},path={socket_path_str}"),
                ])
                .args([
                    "-device",
                    &format!("vhost-user-fs-pci,chardev=char{i},tag={tag},iommu_platform=false"),
                ]);
        } else {
            warn!("Could not launch virtiofsd_path for {vol}");
            break;
        }
    }
    Ok(virtiofsd_handles)
}

fn configure_custom_qemu_args(qemu_cmd: &mut Command, qemu_launch_opts: &QemuLaunchOpts) {
    if let Some(qemu_args_str) = &qemu_launch_opts.qemu_args {
        let custom_args: Vec<&str> = qemu_args_str
            .split_whitespace()
            .filter(|s| !s.is_empty())
            .collect();
        if !custom_args.is_empty() {
            info!("appending user define QEMU args: {:?}", custom_args);
            qemu_cmd.args(custom_args);
        }
    }
}

async fn configure_9p_volumes(
    qemu_cmd: &mut Command,
    qemu_launch_opts: &QemuLaunchOpts,
    run_dir: &Path,
) -> Result<(), Box<dyn Error>> {
    let file_path = run_dir.join("fstab");
    let mut mount_config = String::new();
    for (i, vol_9p_path) in qemu_launch_opts.vol_9p_paths.iter().enumerate() {
        mount_config.push_str(&format!(
            "usrshare{}  {}  9p  trans=virtio,version=9p2000.L,_netdev,noatime,nodiratime 0 0\n",
            i, vol_9p_path.guest_dir
        ));
        configure_virtio_9p_single(
            qemu_cmd,
            &PathBuf::from(&vol_9p_path.host_dir),
            format!("usrshare{}", i),
            i + 2,
        )
        .await?;
    }
    fs::write(&file_path, mount_config).await?;
    Ok(())
}

async fn configure_qemu_all(
    qemu_cmd: &mut Command,
    qemu_launch_opts: &QemuLaunchOpts,
    tool_paths: &ExecutablePaths,
) -> Result<(), Box<dyn Error>> {
    let run_dir = create_vm_work_dir()?;
    let cert_dir = qemu_launch_opts.cert_dir.clone();
    configure_basic_qemu_command(qemu_cmd, qemu_launch_opts);
    configure_kernel_and_payload(qemu_cmd, qemu_launch_opts);
    configure_virtio_9p_single(qemu_cmd, &run_dir, "ccashare".to_string(), 0).await?;

    if let Some(cert_dir_path) = &cert_dir {
        configure_virtio_9p_single(qemu_cmd, cert_dir_path, "certshare".to_string(), 1).await?;
    }
    configure_9p_volumes(qemu_cmd, qemu_launch_opts, &run_dir).await?;
    configure_port_forwarding(qemu_cmd, qemu_launch_opts);
    let _virtiofsd_handles =
        configure_virtiofsd(qemu_cmd, tool_paths, &run_dir, qemu_launch_opts).await?;
    configure_custom_qemu_args(qemu_cmd, qemu_launch_opts);
    Ok(())
}

pub async fn launch_qemu(
    tool_paths: ExecutablePaths,
    qemu_launch_opts: QemuLaunchOpts,
) -> Result<(), Box<dyn Error>> {
    let mut qemu_cmd = Command::new(tool_paths.qemu_path.clone());
    configure_qemu_all(&mut qemu_cmd, &qemu_launch_opts, &tool_paths).await?;
    info!(
        "Starting vm, qemu_cmd_str: {}",
        command_as_string(&qemu_cmd)
    );
    let mut qemu_child = qemu_cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let stderr = qemu_child
        .stderr
        .take()
        .context("Failed to take QEMU stderr")?;
    let mut stderr_reader = BufReader::new(stderr).lines();
    let stderr_task = tokio::spawn(async move {
        loop {
            match stderr_reader.next_line().await {
                Ok(Some(line)) if !line.is_empty() => {
                    eprintln!("{}", line);
                    error!("QEMU error: {}", line);
                }
                Ok(None) => {
                    // 流结束(qemu 关闭 stderr 输出)， 退出循环
                    info!("QEMU stderr stream closed normally");
                    break;
                }
                Ok(Some(_)) => {
                    // 空行忽略
                    continue;
                }
                Err(e) => {
                    error!("Failed to read QEMU stderr line: {}", e);
                    break;
                }
            }
        }
    });

    tokio::select! {
        exit_status = qemu_child.wait() => {
            let exit_status = exit_status.context("QEMU process wait failed")?;
            if exit_status.success() {
                info!("QEMU process exited normally");
            } else {
                error!("QEMU exited with abnormal (code: {:?})", exit_status.code());
            }
        }
        _ = stderr_task => {
            error!("QEMU stderr reading task exited unexpectedly");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{PortForwardValue, VirtiofsBind, VolumeValue};
    use crate::utils::{ExecutablePaths, create_vm_work_dir};
    use mockrs::mock;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    fn default_qemu_opts() -> QemuLaunchOpts {
        QemuLaunchOpts {
            virtiofs_vols: vec![],
            published_ports: vec![],
            image_path: PathBuf::from("/path/to/kernel"),
            qemu_args: None,
            payload: Some(PathBuf::from("/path/to/payload")),
            cert_dir: None,
            vol_9p_paths: vec![],
            mem: 2176,
            smp: 2,
            cid: 3,
        }
    }

    fn default_tool_paths() -> ExecutablePaths {
        ExecutablePaths {
            qemu_path: PathBuf::from("/usr/bin/qemu-system-aarch64"),
            virtiofsd_path: None,
        }
    }

    #[test]
    fn command_as_string_simple() {
        let mut cmd = Command::new("qemu-system-aarch64");
        cmd.arg("-m").arg("2048");
        let result = command_as_string(&cmd);
        assert!(result.contains("qemu-system-aarch64"));
        assert!(result.contains("-m"));
        assert!(result.contains("2048"));
    }

    #[test]
    fn escape_arg_simple() {
        assert_eq!(escape_arg("simple"), "simple");
    }

    #[test]
    fn escape_arg_spaces() {
        let result = escape_arg("arg with spaces");
        assert!(result.starts_with('"'));
        assert!(result.ends_with('"'));
    }

    #[test]
    fn escape_arg_backslash() {
        let result = escape_arg("path\\file");
        assert!(result.contains("\\\\"));
    }

    #[test]
    fn escape_arg_quote() {
        let result = escape_arg("arg\"value");
        assert!(result.contains("\\\""));
    }

    #[test]
    fn escape_arg_dollar() {
        let result = escape_arg("$var");
        assert!(result.starts_with('"'));
    }

    #[test]
    fn test_configure_basic_qemu_command() {
        let opts = default_qemu_opts();
        let mut cmd = Command::new("qemu-system-aarch64");
        configure_basic_qemu_command(&mut cmd, &opts);
        let cmd_str = command_as_string(&cmd);
        assert!(cmd_str.contains("-machine"));
        assert!(cmd_str.contains("size=2176M"));
        assert!(cmd_str.contains("-smp 2"));
        assert!(cmd_str.contains("guest-cid=3"));
    }

    #[test]
    fn configure_kernel_payload_with() {
        let opts = default_qemu_opts();
        let mut cmd = Command::new("qemu-system-aarch64");
        configure_kernel_and_payload(&mut cmd, &opts);
        let cmd_str = command_as_string(&cmd);
        assert!(cmd_str.contains("-kernel"));
        assert!(cmd_str.contains("-initrd"));
        assert!(cmd_str.contains("/path/to/payload"));
    }

    #[test]
    fn configure_kernel_payload_without() {
        let mut opts = default_qemu_opts();
        opts.payload = None;
        let mut cmd = Command::new("qemu-system-aarch64");
        configure_kernel_and_payload(&mut cmd, &opts);
        let cmd_str = command_as_string(&cmd);
        assert!(cmd_str.contains("-initrd"));
        assert!(cmd_str.contains("/mnt/out-br/images/rootfs.cpio"));
    }

    #[tokio::test]
    async fn configure_virtio_9p_dir_exists() {
        let dir = tempfile::TempDir::new().unwrap();
        let opts = default_qemu_opts();
        let mut cmd = Command::new("qemu-system-aarch64");
        configure_basic_qemu_command(&mut cmd, &opts);

        let result = configure_virtio_9p_single(
            &mut cmd,
            &PathBuf::from(dir.path()),
            "testtag".to_string(),
            0,
        )
        .await;
        assert!(result.is_ok());
        let cmd_str = command_as_string(&cmd);
        assert!(cmd_str.contains("-fsdev"));
        assert!(cmd_str.contains("testtag"));
    }

    #[tokio::test]
    async fn configure_virtio_9p_not_exists() {
        let mut cmd = Command::new("qemu-system-aarch64");
        let result = configure_virtio_9p_single(
            &mut cmd,
            &PathBuf::from("/nonexistent/path"),
            "tag".to_string(),
            0,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn configure_virtio_9p_not_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let file_path = dir.path().join("not_a_dir.txt");
        std::fs::write(&file_path, "data").unwrap();

        let mut cmd = Command::new("qemu-system-aarch64");
        let result =
            configure_virtio_9p_single(&mut cmd, &PathBuf::from(&file_path), "tag".to_string(), 0)
                .await;
        assert!(result.is_err());
    }

    #[test]
    fn configure_port_forward_single() {
        let mut opts = default_qemu_opts();
        opts.published_ports = vec![PortForwardValue {
            host_ip: Ipv4Addr::new(0, 0, 0, 0),
            host_port: 8080,
            guest_port: 80,
        }];
        let mut cmd = Command::new("qemu-system-aarch64");
        configure_port_forwarding(&mut cmd, &opts);
        let cmd_str = command_as_string(&cmd);
        assert!(cmd_str.contains("hostfwd"));
        assert!(cmd_str.contains("8080"));
        assert!(cmd_str.contains("net0"));
    }

    #[test]
    fn configure_port_forward_multiple() {
        let mut opts = default_qemu_opts();
        opts.published_ports = vec![
            PortForwardValue {
                host_ip: Ipv4Addr::new(0, 0, 0, 0),
                host_port: 8080,
                guest_port: 80,
            },
            PortForwardValue {
                host_ip: Ipv4Addr::new(192, 168, 1, 1),
                host_port: 9090,
                guest_port: 90,
            },
        ];
        let mut cmd = Command::new("qemu-system-aarch64");
        configure_port_forwarding(&mut cmd, &opts);
        let cmd_str = command_as_string(&cmd);
        assert!(cmd_str.contains("8080"));
        assert!(cmd_str.contains("9090"));
    }

    #[test]
    fn configure_custom_args_none() {
        let opts = default_qemu_opts();
        let mut cmd = Command::new("qemu-system-aarch64");
        configure_custom_qemu_args(&mut cmd, &opts);
        let cmd_str = command_as_string(&cmd);
        assert!(cmd_str.starts_with("qemu-system-aarch64"));
    }

    #[test]
    fn configure_custom_args_valid() {
        let mut opts = default_qemu_opts();
        opts.qemu_args = Some("--extra-arg1 --extra-arg2".to_string());
        let mut cmd = Command::new("qemu-system-aarch64");
        configure_custom_qemu_args(&mut cmd, &opts);
        let cmd_str = command_as_string(&cmd);
        assert!(cmd_str.contains("--extra-arg1"));
        assert!(cmd_str.contains("--extra-arg2"));
    }

    #[test]
    fn configure_custom_args_empty() {
        let mut opts = default_qemu_opts();
        opts.qemu_args = Some("   ".to_string());
        let mut cmd = Command::new("qemu-system-aarch64");
        configure_custom_qemu_args(&mut cmd, &opts);
        let cmd_str = command_as_string(&cmd);
        assert!(cmd_str.starts_with("qemu-system-aarch64"));
    }

    #[tokio::test]
    async fn configure_virtiofsd_no_virtiofsd_path() {
        let mut opts = default_qemu_opts();
        opts.virtiofs_vols = vec![VirtiofsBind {
            host_path: "/host/path".to_string(),
            guest_path: "/guest/path".to_string(),
        }];

        let tool_paths = ExecutablePaths {
            qemu_path: PathBuf::from("/usr/bin/qemu-system-aarch64"),
            virtiofsd_path: None,
        };

        let dir = tempfile::TempDir::new().unwrap();
        let mut cmd = Command::new("qemu-system-aarch64");

        let result = configure_virtiofsd(&mut cmd, &tool_paths, dir.path(), &opts).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn configure_virtiofsd_empty_vols() {
        let opts = default_qemu_opts();
        let tool_paths = ExecutablePaths {
            qemu_path: PathBuf::from("/usr/bin/qemu-system-aarch64"),
            virtiofsd_path: Some(PathBuf::from("/usr/bin/virtiofsd")),
        };

        let dir = tempfile::TempDir::new().unwrap();
        let mut cmd = Command::new("qemu-system-aarch64");

        let result = configure_virtiofsd(&mut cmd, &tool_paths, dir.path(), &opts).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn configure_9p_volumes_with_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let host_dir1 = dir.path().join("host1");
        std::fs::create_dir(&host_dir1).unwrap();

        let mut opts = default_qemu_opts();
        opts.vol_9p_paths = vec![VolumeValue {
            host_dir: host_dir1.to_string_lossy().to_string(),
            guest_dir: "/guest1".to_string(),
        }];

        let mut cmd = Command::new("qemu-system-aarch64");
        configure_basic_qemu_command(&mut cmd, &opts);

        let result = configure_9p_volumes(&mut cmd, &opts, dir.path()).await;
        assert!(result.is_ok());
        let cmd_str = command_as_string(&cmd);
        assert!(cmd_str.contains("-fsdev"));
        assert!(cmd_str.contains("usrshare0"));

        let fstab_path = dir.path().join("fstab");
        assert!(fstab_path.exists());
    }

    #[tokio::test]
    async fn configure_9p_volumes_with_multiple_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let host_dir1 = dir.path().join("host1");
        let host_dir2 = dir.path().join("host2");
        std::fs::create_dir(&host_dir1).unwrap();
        std::fs::create_dir(&host_dir2).unwrap();

        let mut opts = default_qemu_opts();
        opts.vol_9p_paths = vec![
            VolumeValue {
                host_dir: host_dir1.to_string_lossy().to_string(),
                guest_dir: "/guest1".to_string(),
            },
            VolumeValue {
                host_dir: host_dir2.to_string_lossy().to_string(),
                guest_dir: "/guest2".to_string(),
            },
        ];

        let mut cmd = Command::new("qemu-system-aarch64");
        configure_basic_qemu_command(&mut cmd, &opts);

        let result = configure_9p_volumes(&mut cmd, &opts, dir.path()).await;
        assert!(result.is_ok());
        let cmd_str = command_as_string(&cmd);
        assert!(cmd_str.contains("usrshare0"));
        assert!(cmd_str.contains("usrshare1"));
    }

    #[tokio::test]
    async fn configure_9p_volumes_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        let opts = default_qemu_opts();
        let mut cmd = Command::new("qemu-system-aarch64");

        let result = configure_9p_volumes(&mut cmd, &opts, dir.path()).await;
        assert!(result.is_ok());

        let fstab_path = dir.path().join("fstab");
        assert!(fstab_path.exists());
        let content = std::fs::read_to_string(&fstab_path).unwrap();
        assert!(content.is_empty());
    }

    #[tokio::test]
    async fn configure_qemu_all_direct() {
        let opts = default_qemu_opts();
        let tool_paths = default_tool_paths();

        let mut cmd = Command::new("qemu-system-aarch64");
        let result = configure_qemu_all(&mut cmd, &opts, &tool_paths).await;
        assert!(result.is_ok());
        let cmd_str = command_as_string(&cmd);
        assert!(cmd_str.contains("-machine"));
        assert!(cmd_str.contains("-kernel"));
        assert!(cmd_str.contains("-initrd"));
        assert!(cmd_str.contains("ccashare"));
    }

    #[tokio::test]
    async fn configure_qemu_all_with_cert_dir_direct() {
        let cert_dir = tempfile::TempDir::new().unwrap();
        let mut opts = default_qemu_opts();
        opts.cert_dir = Some(PathBuf::from(cert_dir.path()));

        let tool_paths = default_tool_paths();

        let mut cmd = Command::new("qemu-system-aarch64");
        let result = configure_qemu_all(&mut cmd, &opts, &tool_paths).await;
        assert!(result.is_ok());
        let cmd_str = command_as_string(&cmd);
        assert!(cmd_str.contains("certshare"));
    }

    #[tokio::test]
    #[cfg(not(feature = "coverage"))]
    async fn configure_qemu_all_mocked_create_vm_dir() {
        fn mock_create_vm_dir() -> Result<PathBuf, Box<dyn Error>> {
            Ok(std::env::temp_dir())
        }

        let opts = default_qemu_opts();
        let tool_paths = default_tool_paths();

        let _m1 = mock!(create_vm_work_dir, mock_create_vm_dir);

        let mut cmd = Command::new("qemu-system-aarch64");
        let result = configure_qemu_all(&mut cmd, &opts, &tool_paths).await;
        assert!(result.is_ok());
        let cmd_str = command_as_string(&cmd);
        assert!(cmd_str.contains("-machine"));
        assert!(cmd_str.contains("-kernel"));
        assert!(cmd_str.contains("-initrd"));
        assert!(cmd_str.contains("ccashare"));
    }

    #[tokio::test]
    #[cfg(not(feature = "coverage"))]
    async fn configure_qemu_all_with_cert_dir_mocked() {
        fn mock_create_vm_dir() -> Result<PathBuf, Box<dyn Error>> {
            Ok(std::env::temp_dir())
        }

        let cert_dir = tempfile::TempDir::new().unwrap();
        let mut opts = default_qemu_opts();
        opts.cert_dir = Some(PathBuf::from(cert_dir.path()));

        let tool_paths = default_tool_paths();

        let _m1 = mock!(create_vm_work_dir, mock_create_vm_dir);

        let mut cmd = Command::new("qemu-system-aarch64");
        let result = configure_qemu_all(&mut cmd, &opts, &tool_paths).await;
        assert!(result.is_ok());
        let cmd_str = command_as_string(&cmd);
        assert!(cmd_str.contains("certshare"));
    }
}
