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

fn config_custom(
    config_path: &PathBuf,
) -> Result<(PathBuf, PathBuf, u32, PathBuf, u32), Box<dyn Error>> {
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

fn analyze_required_args(
    cli_args: &RunArgs,
) -> Result<(PathBuf, PathBuf, Option<PathBuf>, u32, u32), Box<dyn Error>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ExecutablePaths;
    use mockrs::mock;
    use std::fs;
    use std::path::PathBuf;

    fn create_launcher_config_json(
        image_path: &str,
        payload_path: &str,
        certdir: &str,
        memory: u64,
        cid: u32,
    ) -> String {
        serde_json::json!({
            "certdir": certdir,
            "image": image_path,
            "payload": payload_path,
            "memory": memory,
            "cid": cid
        })
        .to_string()
    }

    #[test]
    fn validate_config_all_valid() {
        let dir = tempfile::TempDir::new().unwrap();
        let image_path = dir.path().join("image.bin");
        let payload_path = dir.path().join("payload.cpio");
        let cert_dir = dir.path().join("certs");
        fs::write(&image_path, "").unwrap();
        fs::write(&payload_path, "").unwrap();
        fs::create_dir(&cert_dir).unwrap();

        let config = LauncherConfig {
            certdir: cert_dir.to_string_lossy().to_string(),
            image: image_path.to_string_lossy().to_string(),
            payload: payload_path.to_string_lossy().to_string(),
            memory: 2048,
            cid: 3,
        };
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_missing_image() {
        let dir = tempfile::TempDir::new().unwrap();
        let payload_path = dir.path().join("payload.cpio");
        let cert_dir = dir.path().join("certs");
        fs::write(&payload_path, "").unwrap();
        fs::create_dir(&cert_dir).unwrap();

        let config = LauncherConfig {
            certdir: cert_dir.to_string_lossy().to_string(),
            image: "/nonexistent/image.bin".to_string(),
            payload: payload_path.to_string_lossy().to_string(),
            memory: 2048,
            cid: 3,
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_missing_certdir() {
        let dir = tempfile::TempDir::new().unwrap();
        let image_path = dir.path().join("image.bin");
        let payload_path = dir.path().join("payload.cpio");
        fs::write(&image_path, "").unwrap();
        fs::write(&payload_path, "").unwrap();

        let config = LauncherConfig {
            certdir: "/nonexistent/certs".to_string(),
            image: image_path.to_string_lossy().to_string(),
            payload: payload_path.to_string_lossy().to_string(),
            memory: 2048,
            cid: 3,
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_certdir_not_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let image_path = dir.path().join("image.bin");
        let payload_path = dir.path().join("payload.cpio");
        let cert_file = dir.path().join("certs.txt");
        fs::write(&image_path, "").unwrap();
        fs::write(&payload_path, "").unwrap();
        fs::write(&cert_file, "").unwrap();

        let config = LauncherConfig {
            certdir: cert_file.to_string_lossy().to_string(),
            image: image_path.to_string_lossy().to_string(),
            payload: payload_path.to_string_lossy().to_string(),
            memory: 2048,
            cid: 3,
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn check_param_exists_none() {
        let result = check_param_exists(None, "--test");
        assert!(result.is_err());
    }

    #[test]
    fn check_param_exists_missing_file() {
        let result = check_param_exists(Some("/nonexistent/file".to_string()), "--test");
        assert!(result.is_err());
    }

    #[test]
    fn check_param_exists_valid() {
        let dir = tempfile::TempDir::new().unwrap();
        let file_path = dir.path().join("test_file");
        fs::write(&file_path, "").unwrap();
        let result = check_param_exists(Some(file_path.to_string_lossy().to_string()), "--test");
        assert!(result.is_ok());
    }

    #[test]
    fn config_custom_valid() {
        let dir = tempfile::TempDir::new().unwrap();
        let image_path = dir.path().join("image.bin");
        let payload_path = dir.path().join("payload.cpio");
        let cert_dir = dir.path().join("certs");
        fs::write(&image_path, "").unwrap();
        fs::write(&payload_path, "").unwrap();
        fs::create_dir(&cert_dir).unwrap();

        let config_path = dir.path().join("config.json");
        let json = create_launcher_config_json(
            &image_path.to_string_lossy(),
            &payload_path.to_string_lossy(),
            &cert_dir.to_string_lossy(),
            2048,
            3,
        );
        fs::write(&config_path, &json).unwrap();

        let result = config_custom(&PathBuf::from(config_path.to_string_lossy().to_string()));
        assert!(result.is_ok());
        let (_image, _payload, mem, _certdir, cid) = result.unwrap();
        assert_eq!(mem, 2048);
        assert_eq!(cid, 3);
    }

    #[test]
    fn config_custom_invalid_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join("config.json");
        fs::write(&config_path, "not json").unwrap();

        let result = config_custom(&PathBuf::from(config_path.to_string_lossy().to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn analyze_required_args_with_app_conf() {
        let dir = tempfile::TempDir::new().unwrap();
        let image_path = dir.path().join("image.bin");
        let payload_path = dir.path().join("payload.cpio");
        let cert_dir = dir.path().join("certs");
        fs::write(&image_path, "").unwrap();
        fs::write(&payload_path, "").unwrap();
        fs::create_dir(&cert_dir).unwrap();

        let config_path = dir.path().join("config.json");
        let json = create_launcher_config_json(
            &image_path.to_string_lossy(),
            &payload_path.to_string_lossy(),
            &cert_dir.to_string_lossy(),
            2048,
            3,
        );
        fs::write(&config_path, &json).unwrap();

        let cli_args = RunArgs {
            app_conf: Some(config_path.to_string_lossy().to_string()),
            ..Default::default()
        };
        let result = analyze_required_args(&cli_args);
        assert!(result.is_ok());
        let (_, _, cert_dir_opt, _, _) = result.unwrap();
        assert!(cert_dir_opt.is_some());
    }

    #[test]
    fn analyze_required_args_cli_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let kernel_path = dir.path().join("kernel");
        let payload_path = dir.path().join("payload.cpio");
        fs::write(&kernel_path, "").unwrap();
        fs::write(&payload_path, "").unwrap();

        let cli_args = RunArgs {
            kernel: Some(kernel_path.to_string_lossy().to_string()),
            payload: Some(payload_path.to_string_lossy().to_string()),
            mem: Some(2048),
            cid: Some(3),
            ..Default::default()
        };
        let result = analyze_required_args(&cli_args);
        assert!(result.is_ok());
        let (_, _, cert_dir_opt, mem, cid) = result.unwrap();
        assert!(cert_dir_opt.is_none());
        assert_eq!(mem, 2048);
        assert_eq!(cid, 3);
    }

    #[test]
    fn analyze_required_args_missing_payload() {
        let dir = tempfile::TempDir::new().unwrap();
        let kernel_path = dir.path().join("kernel");
        fs::write(&kernel_path, "").unwrap();

        let cli_args = RunArgs {
            kernel: Some(kernel_path.to_string_lossy().to_string()),
            payload: None,
            ..Default::default()
        };
        assert!(analyze_required_args(&cli_args).is_err());
    }

    #[test]
    fn analyze_required_args_missing_kernel() {
        let dir = tempfile::TempDir::new().unwrap();
        let payload_path = dir.path().join("payload.cpio");
        fs::write(&payload_path, "").unwrap();

        let cli_args = RunArgs {
            kernel: None,
            payload: Some(payload_path.to_string_lossy().to_string()),
            ..Default::default()
        };
        assert!(analyze_required_args(&cli_args).is_err());
    }

    #[test]
    fn analyze_required_args_default_mem_cid() {
        let dir = tempfile::TempDir::new().unwrap();
        let kernel_path = dir.path().join("kernel");
        let payload_path = dir.path().join("payload.cpio");
        fs::write(&kernel_path, "").unwrap();
        fs::write(&payload_path, "").unwrap();

        let cli_args = RunArgs {
            kernel: Some(kernel_path.to_string_lossy().to_string()),
            payload: Some(payload_path.to_string_lossy().to_string()),
            ..Default::default()
        };
        let result = analyze_required_args(&cli_args).unwrap();
        assert_eq!(result.3, DEFAULT_MEM as u32);
        assert_eq!(result.4, DEFAULT_CID);
    }

    #[test]
    fn cli_args_to_qemu_opts_with_paths() {
        let dir = tempfile::TempDir::new().unwrap();
        let kernel_path = dir.path().join("kernel");
        let payload_path = dir.path().join("payload.cpio");
        fs::write(&kernel_path, "").unwrap();
        fs::write(&payload_path, "").unwrap();

        let cli_args = RunArgs {
            kernel: Some(kernel_path.to_string_lossy().to_string()),
            payload: Some(payload_path.to_string_lossy().to_string()),
            mem: Some(2048),
            cid: Some(3),
            smp: Some(2),
            ..Default::default()
        };
        let result = cli_args_to_qemu_opts(&cli_args);
        assert!(result.is_ok());
        let opts = result.unwrap();
        assert_eq!(opts.mem, 2048);
        assert_eq!(opts.cid, 3);
        assert_eq!(opts.smp, 2);
        assert!(opts.cert_dir.is_none());
    }

    #[test]
    fn cli_args_to_qemu_opts_with_app_conf() {
        let dir = tempfile::TempDir::new().unwrap();
        let image_path = dir.path().join("image.bin");
        let payload_path = dir.path().join("payload.cpio");
        let cert_dir = dir.path().join("certs");
        fs::write(&image_path, "").unwrap();
        fs::write(&payload_path, "").unwrap();
        fs::create_dir(&cert_dir).unwrap();

        let config_path = dir.path().join("config.json");
        let json = create_launcher_config_json(
            &image_path.to_string_lossy(),
            &payload_path.to_string_lossy(),
            &cert_dir.to_string_lossy(),
            2048,
            3,
        );
        fs::write(&config_path, &json).unwrap();

        let cli_args = RunArgs {
            app_conf: Some(config_path.to_string_lossy().to_string()),
            ..Default::default()
        };
        let result = cli_args_to_qemu_opts(&cli_args);
        assert!(result.is_ok());
        let opts = result.unwrap();
        assert!(opts.cert_dir.is_some());
    }

    #[test]
    fn analyze_required_args_app_conf_missing_file() {
        let cli_args = RunArgs {
            app_conf: Some("/nonexistent/config.json".to_string()),
            ..Default::default()
        };
        assert!(analyze_required_args(&cli_args).is_err());
    }

    #[test]
    #[cfg(not(feature = "coverage"))]
    fn run_qemu_runtime() {
        fn mock_dispatch(_args: &RunArgs) -> Result<(), Box<dyn Error>> {
            Ok(())
        }
        let _mocker = mock!(dispatch_to_qemu, mock_dispatch);
        let args = RunArgs {
            runtime: Some("qemu".to_string()),
            ..Default::default()
        };
        assert!(run(&args).is_ok());
    }

    #[test]
    fn run_unsupported_runtime() {
        let args = RunArgs {
            runtime: Some("other".to_string()),
            ..Default::default()
        };
        assert!(run(&args).is_err());
    }

    #[test]
    fn run_missing_runtime() {
        let args = RunArgs {
            runtime: None,
            ..Default::default()
        };
        assert!(run(&args).is_err());
    }

    #[test]
    #[cfg(not(feature = "coverage"))]
    fn dispatch_to_qemu_opts_error() {
        fn mock_find_tools() -> Result<ExecutablePaths, Box<dyn Error>> {
            Ok(ExecutablePaths {
                qemu_path: PathBuf::from("/usr/bin/qemu-system-aarch64"),
                virtiofsd_path: None,
            })
        }
        let _m1 = mock!(find_required_tools, mock_find_tools);

        let args = RunArgs {
            runtime: Some("qemu".to_string()),
            kernel: None,
            payload: None,
            ..Default::default()
        };
        let result = dispatch_to_qemu(&args);
        assert!(result.is_ok());
    }
}
