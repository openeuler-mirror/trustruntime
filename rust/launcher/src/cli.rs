use crate::utils::escape_path;
use log::{error, warn};
use std::env;
use std::error::Error;
use std::fmt;
use std::fmt::Display;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum HelpType {
    Global,
    Run,
}

#[derive(Debug, Clone)]
pub enum SubCommand {
    Run(RunArgs),
    Help(HelpType),
}

#[derive(Debug, Default, Clone)]
pub struct RunArgs {
    pub help: bool,
    pub runtime: Option<String>,
    pub kernel: Option<String>,
    pub payload: Option<String>,
    pub volume: Vec<VolumeValue>,
    pub virtiofs: Vec<VirtiofsBind>,
    pub app_conf: Option<String>,
    pub port_forward: Vec<PortForwardValue>,
    pub qemu_args: Option<String>,
    pub mem: Option<u64>,
    pub smp: Option<u16>,
    pub cid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VirtiofsBind {
    pub host_path: String,
    pub guest_path: String,
}

impl VirtiofsBind {
    pub fn tag(&self) -> String {
        escape_path(&self.guest_path.to_string())
    }

    pub fn socket_name(&self) -> String {
        format!("{}.sock", self.tag())
    }
}

impl Display for VirtiofsBind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = &self.host_path;
        let dest = &self.guest_path;
        write!(f, "{source}:{dest}")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PortForwardValue {
    pub host_ip: Ipv4Addr,
    pub host_port: u16,
    pub guest_port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VolumeValue {
    pub host_dir: String,
    pub guest_dir: String,
}

#[derive(Debug)]
pub enum CliError {
    UnknownSubCommand(String),
    UnknownOption(String),
    MissingValue(String),
    EmptyValue(String),
    InvalidVirtiofsFormat(String),
    InvalidPortForwardFormat(String),
    InvalidIp(String),
    InvalidPort(String),
    InvalidMemValue(String),
    InvalidSmpValue(String),
    InvalidCidValue(String),
    InvalidVolumeFormat(String),
    InvalidVolumeGuestPath(String),
    InvalidVolumeHostPath(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::UnknownSubCommand(cmd) => write!(f, "Unknown subcommand: {}", cmd),
            CliError::UnknownOption(opt) => write!(f, "Unknown option: {}", opt),
            CliError::MissingValue(opt) => write!(f, "Option '{}' missing required value", opt),
            CliError::EmptyValue(opt) => write!(f, "Option '{}' cannot have an empty value", opt),
            CliError::InvalidVirtiofsFormat(fmt) => {
                write!(f, "Invalid --virtiofs format (expected xxx:xxx): {}", fmt)
            }
            CliError::InvalidPortForwardFormat(fmt) => {
                write!(
                    f,
                    "Invalid --port-forward format (expected [hostip:]hostport:guestport): {}",
                    fmt
                )
            }
            CliError::InvalidIp(ip) => write!(f, "Invalid IPv4 address for --port-forward: {}", ip),
            CliError::InvalidPort(port) => write!(f, "Invalid port (must be 0-65535):{}", port),
            CliError::InvalidMemValue(mem) => write!(
                f,
                "Invalid --mem value (must be a positive integer, e.g., 2048): {}",
                mem
            ),
            CliError::InvalidSmpValue(val) => write!(
                f,
                "Invalid --smp value (must be integer ≥ 1, e.g., 2): {}",
                val
            ),
            CliError::InvalidCidValue(cid) => write!(
                f,
                "Invalid --cid value (must be integer ≥ 3, e.g., 3): {}",
                cid
            ),
            CliError::InvalidVolumeFormat(val) => write!(
                f,
                "Invalid --volume-format (expected hostdir:guestdir): {}",
                val
            ),
            CliError::InvalidVolumeHostPath(val) => write!(
                f,
                "Invalid hostdir path (expected absolute directory path of the existence.): {}",
                val
            ),
            CliError::InvalidVolumeGuestPath(val) => write!(
                f,
                "Invalid guestdir path (expected absolute directory path.): {}",
                val
            ),
        }
    }
}

impl Error for CliError {}

impl CliError {
    pub fn log(&self) {
        error!("CLI Error: {}", self);
    }
}

fn validate_non_empty<'a>(val: &'a str, opt_name: &str) -> Result<&'a str, CliError> {
    if val.is_empty() {
        Err(CliError::EmptyValue(opt_name.to_string()))
    } else {
        Ok(val)
    }
}

fn validate_mem(mem_str: &str) -> Result<u64, CliError> {
    mem_str
        .parse::<u64>()
        .map_err(|_| CliError::InvalidMemValue(mem_str.to_string()))
        .and_then(|mem| {
            if mem > 0 {
                Ok(mem)
            } else {
                Err(CliError::InvalidMemValue(mem_str.to_string()))
            }
        })
}

fn validate_smp(smp_str: &str) -> Result<u16, CliError> {
    smp_str
        .parse::<u16>()
        .map_err(|_| CliError::InvalidSmpValue(smp_str.to_string()))
        .and_then(|smp| {
            if smp >= 1 {
                Ok(smp)
            } else {
                Err(CliError::InvalidSmpValue(smp_str.to_string()))
            }
        })
}

fn validate_cid(cid_str: &str) -> Result<u32, CliError> {
    cid_str
        .parse::<u32>()
        .map_err(|_| CliError::InvalidCidValue(cid_str.to_string()))
        .and_then(|cid| {
            if cid >= 3 {
                Ok(cid)
            } else {
                Err(CliError::InvalidCidValue(cid_str.to_string()))
            }
        })
}

fn validate_port(port_str: &str) -> Result<u16, CliError> {
    u16::from_str(port_str).map_err(|_| CliError::InvalidPort(port_str.to_string()))
}

fn parse_virtiofs(val: &str) -> Result<VirtiofsBind, CliError> {
    let parts: Vec<&str> = val.split(':').filter(|s| !s.is_empty()).collect();
    if parts.len() != 2 {
        return Err(CliError::InvalidVirtiofsFormat(val.to_string()));
    }
    Ok(VirtiofsBind {
        host_path: parts[0].to_string(),
        guest_path: parts[1].to_string(),
    })
}

fn parse_port_forward(val: &str) -> Result<PortForwardValue, CliError> {
    let parts: Vec<&str> = val.split(':').filter(|s| !s.is_empty()).collect();
    match parts.len() {
        2 => {
            let host_port = validate_port(parts[0])?;
            let guest_port = validate_port(parts[1])?;
            Ok(PortForwardValue {
                host_ip: Ipv4Addr::new(0, 0, 0, 0),
                host_port,
                guest_port,
            })
        }
        3 => {
            let host_ip = parts[0]
                .parse::<Ipv4Addr>()
                .map_err(|_| CliError::InvalidIp(parts[0].to_string()))?;
            let host_port = validate_port(parts[1])?;
            let guest_port = validate_port(parts[2])?;
            Ok(PortForwardValue {
                host_ip,
                host_port,
                guest_port,
            })
        }
        _ => Err(CliError::InvalidPortForwardFormat(val.to_string())),
    }
}

fn validate_host_dir(dir_str: &str) -> Result<String, CliError> {
    let path = Path::new(dir_str);
    if path.is_absolute() && path.exists() && path.is_dir() {
        if dir_str.contains(' ') {
            warn!("The host directory '{}' contains a space", dir_str);
        }
        Ok(dir_str.to_string())
    } else {
        Err(CliError::InvalidVolumeHostPath(dir_str.to_string()))
    }
}

fn validate_guest_dir(dir_str: &str) -> Result<String, CliError> {
    let path = Path::new(dir_str);
    if path.is_absolute() {
        if dir_str.contains(' ') {
            warn!("The guest directory '{}' contains a space", dir_str);
        }
        Ok(dir_str.to_string())
    } else {
        Err(CliError::InvalidVolumeGuestPath(dir_str.to_string()))
    }
}

fn parse_volume(val: &str) -> Result<VolumeValue, CliError> {
    let parts: Vec<&str> = val.split(':').filter(|s| !s.is_empty()).collect();

    match parts.len() {
        2 => {
            let host_dir = validate_host_dir(parts[0])?;
            let guest_dir = validate_guest_dir(parts[1])?;
            Ok(VolumeValue {
                host_dir,
                guest_dir,
            })
        }
        _ => Err(CliError::InvalidVolumeFormat(val.to_string())),
    }
}

fn parse_subcmd_args(args_vec: Vec<String>) -> Result<SubCommand, CliError> {
    let mut args_iter: Box<dyn Iterator<Item = String>> = Box::new(args_vec.into_iter());
    let Some(sub_cmd_str) = args_iter.next() else {
        return Ok(SubCommand::Help(HelpType::Global));
    };

    match sub_cmd_str.as_str() {
        "help" => Ok(SubCommand::Help(HelpType::Global)),
        "run" => parse_run_args(args_iter),
        _ => Err(CliError::UnknownSubCommand(sub_cmd_str)),
    }
}

pub fn parse_args() -> Result<SubCommand, CliError> {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.len() == 1 {
        let arg = args[0].clone();
        if arg == "-h" || arg == "--help" {
            return Ok(SubCommand::Help(HelpType::Global));
        }
    }
    parse_subcmd_args(args)
}

// 处理 --option=value 和 --option value
macro_rules! handle_option {
    ($arg:ident,$iter:ident, $args:ident,$cmd_line_name:literal, $option:ident,$handler:expr) => {
        if $arg.starts_with(&format!("--{}", $cmd_line_name)) {
            let val = if let Some(_) = $arg.find('=') {
                $arg.split_once('=').map(|(_, v)| v.to_string())
            } else {
                $iter.next().map(|v| v.to_string())
            }
            .ok_or_else(|| CliError::MissingValue(format!("--{}", $cmd_line_name)))?;
            $args.$option = Some($handler(&val)?);
            continue;
        }
    };
}

// 处理 --option=value 和 --option value 用于vec类型
macro_rules! handle_option_vec {
    ($arg:ident,$iter:ident,$args:ident,$cmd_line_name:literal,$option:ident,$handler:expr) => {
        if $arg.starts_with(&format!("--{}", $cmd_line_name)) {
            let val = if let Some(_) = $arg.find('=') {
                $arg.split_once('=').map(|(_, v)| v.to_string())
            } else {
                $iter.next().map(|v| v.to_string())
            }
            .ok_or_else(|| CliError::MissingValue(format!("--{}", $cmd_line_name)))?;
            $args.$option.push($handler(&val)?);
            continue;
        }
    };
}

fn parse_run_args(mut iter: Box<dyn Iterator<Item = String>>) -> Result<SubCommand, CliError> {
    let mut args = RunArgs {
        help: false,
        runtime: None,
        kernel: None,
        payload: None,
        volume: vec![],
        virtiofs: vec![],
        app_conf: None,
        port_forward: vec![],
        qemu_args: None,
        mem: None,
        smp: None,
        cid: None,
    };
    if let Some(next_arg) = iter.next() {
        if next_arg == "-h" || next_arg == "--help" {
            return Ok(SubCommand::Help(HelpType::Run));
        }

        // 把取出的参数放回迭代器，继续解析其他参数
        iter = Box::new(std::iter::once(next_arg).chain(iter));
    }

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => args.help = true,
            s if s.starts_with("--") => {
                handle_option!(s, iter, args, "runtime", runtime, |v| validate_non_empty(
                    v,
                    "--runtime"
                )
                .map(|s| s.to_string()));
                handle_option!(s, iter, args, "kernel", kernel, |v| validate_non_empty(
                    v, "--kernel"
                )
                .map(|s| s.to_string()));
                handle_option!(s, iter, args, "payload", payload, |v| validate_non_empty(
                    v,
                    "--payload"
                )
                .map(|s| s.to_string()));
                handle_option_vec!(s, iter, args, "volume", volume, parse_volume);
                handle_option!(s, iter, args, "app-conf", app_conf, |v| validate_non_empty(
                    v,
                    "--app-conf"
                )
                .map(|s| s.to_string()));
                handle_option_vec!(s, iter, args, "virtiofs", virtiofs, parse_virtiofs);
                handle_option_vec!(
                    s,
                    iter,
                    args,
                    "port-forward",
                    port_forward,
                    parse_port_forward
                );
                handle_option!(s, iter, args, "qemu-args", qemu_args, |v| {
                    validate_non_empty(v, "--qemu-args").map(|s| s.to_string())
                });
                handle_option!(s, iter, args, "mem", mem, validate_mem);
                handle_option!(s, iter, args, "smp", smp, validate_smp);
                handle_option!(s, iter, args, "cid", cid, validate_cid);
            }
            _ => return Err(CliError::UnknownOption(arg)),
        }
    }
    Ok(SubCommand::Run(args))
}

pub fn print_help(help_type: &HelpType) {
    match help_type {
        HelpType::Global => {
            println!("Usage: trt_launcher <subcommand> [OPTIONS]");
            println!("Subcommands:");
            println!("  run     Start a virtual machine (requires --kernel, --payload, etc.)");
            println!("Options:");
            println!("  -h, --help  Print this help message or subcommand-specific help");
            println!("\nExamples:");
            println!("./trt_launcher run --kernel ./Image --payload ./rootfs.cpio");
            println!("./trt_launcher run --app-conf attest.conf");
            println!("  trt_launcher run -h  # Print run subcommand help");
        }

        HelpType::Run => {
            println!("Usage:");
            println!("  ./trt_launcher run --kernel <path> --payload <path> [OPTIONS]");
            println!("  ./trt_launcher run --app-conf <path> [OPTIONS]");
            println!("\nRequired/Optional Options:");
            println!("  -h, --help                  Show this help message");
            println!("  --kernel <path>             Path to kernel image (e.g., ./Image)");
            println!("  --payload <path>            Path to payload image (e.g., abc.img)");
            println!("  --app-conf <path>           Path to app config file (e.g., launch.conf)");
            println!(
                "  --volume <hostdir:guestdir> (Optional) Shared directory for vm (e.g., /root/workspace/:/root/app/)"
            );
            println!(
                "  --virtiofs <host:guest>     (Optional) VirtioFS mapping (supports multiple instances)"
            );
            println!(
                "                              Example: --virtiofs xxx:xxx --virtiofs yyy:yyy"
            );
            println!(
                "  --port-forward <spec>       (Optional) Port forwarding spec (supports multiple instances)"
            );
            println!("                              Format: [hostip:]hostport:guestport");
            println!(
                "                              Example: --port-forward 8080:80 --port-forward 192.168.1.1:9090:90"
            );
            println!(
                "  --qemu-args <quoted-args>   (Optional) Extra QEMU arguments (use quotes for spaces)"
            );
            println!("                              Example: --qemu-args=\"--arg1=c1 --arg2=c2\"");
            println!(
                "  --mem <num>                 (Optional) Memory size in MB (positive integer, e.g., 2048)"
            );
            println!(
                "  --smp <num>                 (Optional) Number of CPU cores (integer ≥1, e.g., 2)"
            );
            println!(
                "  --cid <num>                 (Optional) CID for vhost-vsock (integer ≥3, e.g., 3)"
            );
            println!(
                "  --runtime <string>          (Optional) Runtime type (e.g., qemu, default: qemu)"
            );
        }
    }
}
