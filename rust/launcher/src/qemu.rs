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
        .args(["-append", "rdinit=init console=ttyAMA0 rodata=full nosoftlockup rcupdate.rcu_cpu_stall_timeout=3000 ubfabric_addr=0x30200FF000"])
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
