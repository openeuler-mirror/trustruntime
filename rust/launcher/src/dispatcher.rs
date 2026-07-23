use crate::{
    cli::{CliError, HelpType, RunArgs, print_help},
    qemu::{QemuLaunchOpts, launch_qemu},
    utils::find_required_tools,
};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::runtime::Runtime;

const DEFAULT_MEM: u64 = 2048 + 128;

const DEFAULT_SMP: u16 = 2;

const DEFAULT_CID: u32 = 3;

#[derive(Deserialize, Serialize, Debug)]
pub struct LauncherConfig {
    #[serde(rename = "certdir")]
    pub certdir: String,
    #[serde(rename = "image")]
    pub image: String,
    #[serde(rename = "payload")]
    pub payload: String,
    #[serde(rename = "memory")]
    pub memory: u64,
    #[serde(rename = "cid")]
    pub cid: u32,
}

pub fn validate_config(config: &LauncherConfig) -> Result<(), Box<dyn Error>> {
    let required_files = vec![&config.image, &config.payload];
    for file_path in required_files {
        if !Path::new(file_path).exists() {
            return Err(format!("Config required file not found: {}", file_path).into());
        }
    }
    let cert_dir = Path::new(&config.certdir);
    if !cert_dir.exists() || !cert_dir.is_dir() {
        return Err(format!(
            "Certificate required directory not found or not a directory: {}",
            config.certdir
        )
        .into());
    }

    Ok(())
}

fn check_param_exists(opt_str: Option<String>, arg_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let str_val = opt_str.ok_or_else(|| {
        let err = CliError::MissingValue(arg_name.to_string());
        err.log();
        err
    })?;
    let path = PathBuf::from(str_val);
    if !path.exists() {
        return Err(format!("File does not exist for {}: {}", arg_name, path.display()).into());
    }
    Ok(path)
}

type ConfigResult = (PathBuf, PathBuf, u32, PathBuf, u32);
type AnalyzeResult = (PathBuf, PathBuf, Option<PathBuf>, u32, u32);

fn config_custom(config_path: &PathBuf) -> Result<ConfigResult, Box<dyn Error>> {
    let content = fs::read_to_string(config_path)?;
    let config: LauncherConfig = serde_json::from_str(&content)?;
    validate_config(&config)?;
    let memory = config.memory as u32;

    Ok((
        PathBuf::from(config.image),
        PathBuf::from(config.payload),
        memory,
        PathBuf::from(config.certdir),
        config.cid,
    ))
}

fn analyze_required_args(cli_args: &RunArgs) -> Result<AnalyzeResult, Box<dyn Error>> {
    match &cli_args.app_conf {
        Some(conf) => {
            info!("--app-conf is exists, using conf file");
            let config_path = PathBuf::from(conf);
            if !config_path.exists() {
                return Err(format!(
                    "Config file not found for --app-conf: {}",
                    config_path.display()
                )
                .into());
            }
            let (image_path, payload_path, mem, cert_dir, cid) = config_custom(&config_path)?;
            Ok((image_path, payload_path, Some(cert_dir), mem, cid))
        }
        None => {
            info!("--app-conf is not exists, using cmd line");
            let payload_path = check_param_exists(cli_args.payload.clone(), "--payload")?;
            let image_path = check_param_exists(cli_args.kernel.clone(), "--kernel")?;
            let mem = cli_args.mem.unwrap_or(DEFAULT_MEM) as u32;
            let cid = cli_args.cid.unwrap_or(DEFAULT_CID);
            Ok((image_path, payload_path, None, mem, cid))
        }
    }
}

fn cli_args_to_qemu_opts(cli_args: &RunArgs) -> Result<QemuLaunchOpts, Box<dyn Error>> {
    let (image_path, payload_path, cert_dir, mem, cid) = analyze_required_args(cli_args)?;

    Ok(QemuLaunchOpts {
        virtiofs_vols: cli_args.virtiofs.clone(),
        published_ports: cli_args.port_forward.clone(),
        image_path,
        qemu_args: cli_args.qemu_args.clone(),
        payload: Some(payload_path),
        cert_dir: cert_dir.clone(),
        vol_9p_paths: cli_args.volume.clone(),
        mem,
        smp: cli_args.smp.unwrap_or(DEFAULT_SMP) as u32,
        cid,
    })
}

fn dispatch_to_qemu(args: &RunArgs) -> Result<(), Box<dyn Error>> {
    let tool_paths = find_required_tools()?;
    let qemu_opts = match cli_args_to_qemu_opts(args) {
        Ok(opts) => opts,
        Err(e) => {
            error!("qemu startup options error: {}", e);
            print_help(&HelpType::Run);
            return Ok(());
        }
    };
    let rt = Runtime::new()?;
    let launch_result = rt.block_on(async {
        launch_qemu(tool_paths, qemu_opts).await?;
        Ok::<(), Box<dyn Error>>(())
    });
    if let Err(e) = launch_result {
        error!("qemu launch error: {}", e);
        return Ok(());
    }
    Ok(())
}

pub fn run(args: &RunArgs) -> Result<(), Box<dyn Error>> {
    let runtime = args
        .runtime
        .as_ref()
        .ok_or(CliError::MissingValue("--runtime".to_string()))?;
    match runtime.as_str() {
        "qemu" => dispatch_to_qemu(args),
        _ => Err(CliError::UnknownOption(format!("Unsupported runtime: {}", runtime)).into()),
    }
}
