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

#[derive(Debug, PartialEq)]
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

fn get_args() -> Vec<String> {
    env::args().skip(1).collect()
}

pub fn parse_args() -> Result<SubCommand, CliError> {
    let args = get_args();

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

#[cfg(test)]
mod tests {
    use super::*;
    use mockrs::mock;
    use std::net::Ipv4Addr;

    #[test]
    fn validate_non_empty_empty() {
        let result = validate_non_empty("", "--test");
        assert!(result.is_err());
        if let Err(CliError::EmptyValue(opt)) = result {
            assert_eq!(opt, "--test");
        }
    }

    #[test]
    fn validate_non_empty_ok() {
        assert_eq!(validate_non_empty("value", "--test"), Ok("value"));
    }

    #[test]
    fn validate_mem_positive() {
        assert_eq!(validate_mem("2048"), Ok(2048));
    }

    #[test]
    fn validate_mem_zero() {
        assert!(validate_mem("0").is_err());
    }

    #[test]
    fn validate_mem_invalid() {
        assert!(validate_mem("abc").is_err());
    }

    #[test]
    fn validate_smp_valid() {
        assert_eq!(validate_smp("2"), Ok(2));
        assert_eq!(validate_smp("1"), Ok(1));
    }

    #[test]
    fn validate_smp_zero() {
        assert!(validate_smp("0").is_err());
    }

    #[test]
    fn validate_smp_invalid() {
        assert!(validate_smp("abc").is_err());
    }

    #[test]
    fn validate_cid_valid() {
        assert_eq!(validate_cid("3"), Ok(3));
        assert_eq!(validate_cid("100"), Ok(100));
    }

    #[test]
    fn validate_cid_below_min() {
        assert!(validate_cid("2").is_err());
        assert!(validate_cid("0").is_err());
    }

    #[test]
    fn validate_cid_invalid() {
        assert!(validate_cid("abc").is_err());
    }

    #[test]
    fn validate_port_valid() {
        assert_eq!(validate_port("8080"), Ok(8080));
        assert_eq!(validate_port("0"), Ok(0));
        assert_eq!(validate_port("65535"), Ok(65535));
    }

    #[test]
    fn validate_port_invalid() {
        assert!(validate_port("abc").is_err());
    }

    #[test]
    fn parse_virtiofs_valid() {
        let result = parse_virtiofs("/host:/guest").unwrap();
        assert_eq!(result.host_path, "/host");
        assert_eq!(result.guest_path, "/guest");
    }

    #[test]
    fn parse_virtiofs_no_colon() {
        assert!(parse_virtiofs("hostonly").is_err());
    }

    #[test]
    fn parse_virtiofs_empty_parts() {
        assert!(parse_virtiofs(":guest").is_err());
        assert!(parse_virtiofs("host:").is_err());
    }

    #[test]
    fn parse_port_forward_2parts() {
        let result = parse_port_forward("8080:80").unwrap();
        assert_eq!(result.host_ip, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(result.host_port, 8080);
        assert_eq!(result.guest_port, 80);
    }

    #[test]
    fn parse_port_forward_3parts() {
        let result = parse_port_forward("1.2.3.4:9090:90").unwrap();
        assert_eq!(result.host_ip, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(result.host_port, 9090);
        assert_eq!(result.guest_port, 90);
    }

    #[test]
    fn parse_port_forward_invalid_ip() {
        assert!(parse_port_forward("abc:80:90").is_err());
    }

    #[test]
    fn parse_port_forward_too_many() {
        assert!(parse_port_forward("1:2:3:4").is_err());
    }

    #[test]
    fn parse_port_forward_invalid_port() {
        assert!(parse_port_forward("abc:80").is_err());
        assert!(parse_port_forward("8080:abc").is_err());
    }

    #[test]
    fn validate_guest_dir_absolute() {
        assert_eq!(validate_guest_dir("/root/app"), Ok("/root/app".to_string()));
    }

    #[test]
    fn validate_guest_dir_relative() {
        assert!(validate_guest_dir("relative/path").is_err());
    }

    #[test]
    fn validate_host_dir_existing() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().to_string_lossy().to_string();
        assert_eq!(validate_host_dir(&path), Ok(path));
    }

    #[test]
    fn validate_host_dir_nonexistent() {
        assert!(validate_host_dir("/nonexistent/path").is_err());
    }

    #[test]
    fn validate_host_dir_relative() {
        assert!(validate_host_dir("relative/path").is_err());
    }

    #[test]
    fn parse_subcmd_args_help() {
        let result = parse_subcmd_args(vec!["help".to_string()]).unwrap();
        assert!(matches!(result, SubCommand::Help(HelpType::Global)));
    }

    #[test]
    fn parse_subcmd_args_empty() {
        let result = parse_subcmd_args(vec![]).unwrap();
        assert!(matches!(result, SubCommand::Help(HelpType::Global)));
    }

    #[test]
    fn parse_subcmd_args_unknown() {
        assert!(parse_subcmd_args(vec!["unknown".to_string()]).is_err());
    }

    #[test]
    fn parse_subcmd_args_run() {
        let result = parse_subcmd_args(vec![
            "run".to_string(),
            "--kernel".to_string(),
            "/path".to_string(),
        ]);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_run_args_help_flag() {
        let result = parse_run_args(Box::new(vec!["-h".to_string()].into_iter())).unwrap();
        assert!(matches!(result, SubCommand::Help(HelpType::Run)));
    }

    #[test]
    fn parse_run_args_equals_syntax() {
        let result =
            parse_run_args(Box::new(vec!["--runtime=qemu".to_string()].into_iter())).unwrap();
        if let SubCommand::Run(args) = result {
            assert_eq!(args.runtime, Some("qemu".to_string()));
        } else {
            panic!("Expected Run");
        }
    }

    #[test]
    fn parse_run_args_space_syntax() {
        let result = parse_run_args(Box::new(
            vec!["--runtime".to_string(), "qemu".to_string()].into_iter(),
        ))
        .unwrap();
        if let SubCommand::Run(args) = result {
            assert_eq!(args.runtime, Some("qemu".to_string()));
        } else {
            panic!("Expected Run");
        }
    }

    #[test]
    fn parse_run_args_unknown_positional() {
        assert!(
            parse_run_args(Box::new(
                vec!["unknown_positional".to_string(),].into_iter()
            ))
            .is_err()
        );
    }

    #[test]
    fn parse_run_args_mem_option() {
        let result = parse_run_args(Box::new(
            vec!["--mem".to_string(), "2048".to_string()].into_iter(),
        ))
        .unwrap();
        if let SubCommand::Run(args) = result {
            assert_eq!(args.mem, Some(2048));
        }
    }

    #[test]
    fn parse_run_args_missing_value() {
        assert!(parse_run_args(Box::new(vec!["--runtime".to_string(),].into_iter())).is_err());
    }

    #[test]
    fn parse_run_args_full_options() {
        let dir = tempfile::TempDir::new().unwrap();
        let dir_path = dir.path().to_string_lossy().to_string();
        let result = parse_run_args(Box::new(
            vec![
                "--kernel".to_string(),
                "/path".to_string(),
                "--payload".to_string(),
                "/payload".to_string(),
                "--runtime".to_string(),
                "qemu".to_string(),
                "--mem".to_string(),
                "2048".to_string(),
                "--smp".to_string(),
                "2".to_string(),
                "--cid".to_string(),
                "3".to_string(),
                "--app-conf".to_string(),
                "/conf".to_string(),
                "--qemu-args".to_string(),
                "--extra".to_string(),
                "--virtiofs".to_string(),
                "/host:/guest".to_string(),
                "--port-forward".to_string(),
                "8080:80".to_string(),
                "--volume".to_string(),
                format!("{}:/guest", dir_path),
            ]
            .into_iter(),
        ))
        .unwrap();
        if let SubCommand::Run(args) = result {
            assert_eq!(args.runtime, Some("qemu".to_string()));
            assert_eq!(args.mem, Some(2048));
            assert_eq!(args.smp, Some(2));
            assert_eq!(args.cid, Some(3));
            assert_eq!(args.kernel, Some("/path".to_string()));
            assert_eq!(args.payload, Some("/payload".to_string()));
            assert_eq!(args.app_conf, Some("/conf".to_string()));
            assert_eq!(args.qemu_args, Some("--extra".to_string()));
            assert_eq!(args.virtiofs.len(), 1);
            assert_eq!(args.port_forward.len(), 1);
            assert_eq!(args.volume.len(), 1);
        }
    }

    #[test]
    #[cfg(not(feature = "coverage"))]
    fn parse_args_help_shortcut() {
        fn mock_get_args_h() -> Vec<String> {
            vec!["-h".to_string()]
        }
        let _mocker = mock!(get_args, mock_get_args_h);
        let result = parse_args().unwrap();
        assert!(matches!(result, SubCommand::Help(HelpType::Global)));
    }

    #[test]
    #[cfg(not(feature = "coverage"))]
    fn parse_args_help_long() {
        fn mock_get_args_help() -> Vec<String> {
            vec!["--help".to_string()]
        }
        let _mocker = mock!(get_args, mock_get_args_help);
        let result = parse_args().unwrap();
        assert!(matches!(result, SubCommand::Help(HelpType::Global)));
    }

    #[test]
    #[cfg(not(feature = "coverage"))]
    fn parse_args_normal() {
        fn mock_get_args_run() -> Vec<String> {
            vec![
                "run".to_string(),
                "--kernel".to_string(),
                "/path".to_string(),
            ]
        }
        let _mocker = mock!(get_args, mock_get_args_run);
        let result = parse_args().unwrap();
        assert!(matches!(result, SubCommand::Run(_)));
    }

    #[test]
    fn print_help_global() {
        print_help(&HelpType::Global);
    }

    #[test]
    fn print_help_run() {
        print_help(&HelpType::Run);
    }

    #[test]
    fn virtiofs_bind_tag() {
        let bind = VirtiofsBind {
            host_path: "/host/path".to_string(),
            guest_path: "/guest/path".to_string(),
        };
        assert_eq!(bind.tag(), "guest-path");
    }

    #[test]
    fn virtiofs_bind_socket_name() {
        let bind = VirtiofsBind {
            host_path: "/host".to_string(),
            guest_path: "/guest".to_string(),
        };
        assert_eq!(bind.socket_name(), "guest.sock");
    }

    #[test]
    fn virtiofs_bind_display() {
        let bind = VirtiofsBind {
            host_path: "/host".to_string(),
            guest_path: "/guest".to_string(),
        };
        assert_eq!(format!("{}", bind), "/host:/guest");
    }

    #[test]
    fn cli_error_display_all() {
        let errors: Vec<CliError> = vec![
            CliError::UnknownSubCommand("foo".to_string()),
            CliError::UnknownOption("--bar".to_string()),
            CliError::MissingValue("--opt".to_string()),
            CliError::EmptyValue("--opt".to_string()),
            CliError::InvalidVirtiofsFormat("bad".to_string()),
            CliError::InvalidPortForwardFormat("bad".to_string()),
            CliError::InvalidIp("bad".to_string()),
            CliError::InvalidPort("bad".to_string()),
            CliError::InvalidMemValue("bad".to_string()),
            CliError::InvalidSmpValue("bad".to_string()),
            CliError::InvalidCidValue("bad".to_string()),
            CliError::InvalidVolumeFormat("bad".to_string()),
            CliError::InvalidVolumeHostPath("bad".to_string()),
            CliError::InvalidVolumeGuestPath("bad".to_string()),
        ];
        for err in errors {
            let msg = format!("{}", err);
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn cli_error_log() {
        let err = CliError::UnknownSubCommand("test".to_string());
        err.log();
    }

    #[test]
    fn parse_volume_valid() {
        let dir = tempfile::TempDir::new().unwrap();
        let host_path = dir.path().to_string_lossy().to_string();
        let result = parse_volume(&format!("{}:/guest/path", host_path)).unwrap();
        assert_eq!(result.host_dir, host_path);
        assert_eq!(result.guest_dir, "/guest/path".to_string());
    }

    #[test]
    fn parse_volume_invalid_format() {
        assert!(parse_volume("onlyonepart").is_err());
        assert!(parse_volume("a:b:c").is_err());
    }
}
