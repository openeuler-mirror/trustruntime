use agentsandbox_controller::{Management, SockListener, UnixSocketSender};
use agentsandbox_log::LogConfig;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const VALID_LOG_LEVELS: &[&str] = &["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];
const SECURE_DIR_MODE: u32 = 0o750;

struct Config {
    config_dir: String,
    sock_path: String,
    proxy_sock: String,
    log_dir: String,
    log_level: String,
}

impl Config {
    /// Reads and validates all required environment variables, resolving paths via realpath.
    fn from_env() -> Result<Self, anyhow::Error> {
        let config_dir = require_env("AGENTSANDBOX_CONFIG_DIR")?;
        let config_dir = resolve_dir("AGENTSANDBOX_CONFIG_DIR", &config_dir, true, false)?;

        let sock_path = require_env("AGENTSANDBOX_SOCK_PATH")?;
        let sock_path = resolve_file_path("AGENTSANDBOX_SOCK_PATH", &sock_path)?;

        let proxy_sock = require_env("AGENTSANDBOX_PROXY_SOCK")?;
        let proxy_sock = resolve_file_path("AGENTSANDBOX_PROXY_SOCK", &proxy_sock)?;

        let log_dir = require_env("AGENTSANDBOX_LOG_DIR")?;
        let log_dir = resolve_dir("AGENTSANDBOX_LOG_DIR", &log_dir, true, true)?;

        let log_level = require_env("AGENTSANDBOX_LOG_LEVEL")?;
        validate_log_level("AGENTSANDBOX_LOG_LEVEL", &log_level)?;

        Ok(Self { config_dir, sock_path, proxy_sock, log_dir, log_level })
    }
}

/// Reads a required environment variable, trimming whitespace. Errors if missing or empty.
fn require_env(key: &str) -> Result<String, anyhow::Error> {
    let val = env::var(key).map_err(|_| anyhow::anyhow!("environment variable {} is required", key))?;
    let trimmed = val.trim().to_string();
    if trimmed.is_empty() {
        anyhow::bail!("environment variable {} must not be empty", key);
    }
    Ok(trimmed)
}

/// Canonicalizes a path via realpath, resolving symlinks and relative components.
fn realpath(path: &str) -> Result<PathBuf, anyhow::Error> {
    fs::canonicalize(path).map_err(|e| anyhow::anyhow!("realpath failed for {}: {}", path, e))
}

/// Validates and resolves a directory path. Creates with secure permissions if create_if_missing.
fn resolve_dir(key: &str, path: &str, must_exist: bool, create_if_missing: bool) -> Result<String, anyhow::Error> {
    let p = PathBuf::from(path);
    if !p.exists() {
        if create_if_missing {
            create_secure_dir(key, &p)?;
        } else if must_exist {
            anyhow::bail!("{}: directory does not exist: {}", key, path);
        }
    }
    if p.exists() && !p.is_dir() {
        anyhow::bail!("{}: path is not a directory: {}", key, path);
    }
    let resolved = realpath(path)?;
    if !resolved.is_dir() {
        anyhow::bail!("{}: realpath is not a directory: {}", key, resolved.display());
    }
    Ok(resolved.to_string_lossy().into_owned())
}

/// Creates a directory and all parents, then sets secure permissions (0750).
fn create_secure_dir(key: &str, path: &PathBuf) -> Result<(), anyhow::Error> {
    fs::create_dir_all(path)
        .map_err(|e| anyhow::anyhow!("{}: cannot create directory {}: {}", key, path.display(), e))?;
    set_dir_permissions(key, path)?;
    Ok(())
}

/// Sets directory permissions to SECURE_DIR_MODE (0750: owner rwx, group r-x, other none).
fn set_dir_permissions(key: &str, path: &PathBuf) -> Result<(), anyhow::Error> {
    fs::set_permissions(path, fs::Permissions::from_mode(SECURE_DIR_MODE))
        .map_err(|e| anyhow::anyhow!("{}: cannot set permissions on {}: {}", key, path.display(), e))?;
    Ok(())
}

/// Validates a file path: parent directory must exist. Returns realpath-joined absolute path.
fn resolve_file_path(key: &str, path: &str) -> Result<String, anyhow::Error> {
    let p = PathBuf::from(path);
    let parent = p.parent().unwrap_or_else(|| Path::new("/"));
    if !parent.is_dir() {
        anyhow::bail!("{}: parent directory does not exist or not a dir: {}", key, parent.display());
    }
    let resolved_parent = realpath(&parent.to_string_lossy())?;
    if p.exists() && !p.is_file() {
        anyhow::bail!("{}: path exists but is not a regular file: {}", key, path);
    }
    match p.file_name() {
        Some(name) => Ok(resolved_parent.join(name).to_string_lossy().into_owned()),
        None => anyhow::bail!("{}: cannot extract file name from path: {}", key, path),
    }
}

/// Validates that log level is one of TRACE/DEBUG/INFO/WARN/ERROR.
fn validate_log_level(key: &str, val: &str) -> Result<(), anyhow::Error> {
    let upper = val.to_uppercase();
    if !VALID_LOG_LEVELS.contains(&upper.as_str()) {
        anyhow::bail!("environment variable {} must be one of {:?}, got: {}", key, VALID_LOG_LEVELS, val);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cfg = Config::from_env()?;
    eprintln!("HiController starting: config_dir={}, sock={}, log_dir={}, log_level={}",
        cfg.config_dir, cfg.sock_path, cfg.log_dir, cfg.log_level);

    let mgmt = init_management(&cfg)?;
    let sock_listener = SockListener::new(&cfg.sock_path);
    eprintln!("SockListener bound to {}", cfg.sock_path);
    let sender = UnixSocketSender::new(&cfg.proxy_sock);

    let run_mgmt = mgmt.clone();
    tokio::spawn(async move {
        if let Err(e) = run_mgmt.run(sock_listener, &sender).await {
            eprintln!("management run error: {}", e);
        }
    });

    await_shutdown().await;

    eprintln!("unloading eBPF programs...");
    if let Err(e) = mgmt.shutdown().await {
        eprintln!("shutdown error: {}", e);
    }
    eprintln!("HiController stopped");
    Ok(())
}

/// Initializes Management: loads eBPF programs and creates ContainerIntegration.
fn init_management(cfg: &Config) -> Result<Arc<Management>, anyhow::Error> {
    let log_config = LogConfig {
        log_dir: cfg.log_dir.clone(),
        debug_level: cfg.log_level.clone(),
    };
    let mgmt = Arc::new(Management::new(&cfg.config_dir, log_config, &cfg.sock_path).map_err(|e| {
        eprintln!("FATAL: management init failed: {}", e);
        e
    })?);
    eprintln!("eBPF programs loaded successfully");
    Ok(mgmt)
}

/// Awaits SIGINT or SIGTERM signal for graceful shutdown.
async fn await_shutdown() {
    let int_handle = tokio::spawn(async {
        tokio::signal::ctrl_c().await.ok();
        eprintln!("SIGINT received, shutting down...");
    });

    let term_handle = tokio::spawn(async {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            term.recv().await;
            eprintln!("SIGTERM received, shutting down...");
        }
    });

    tokio::select! {
        _ = int_handle => eprintln!("shutdown via SIGINT"),
        _ = term_handle => eprintln!("shutdown via SIGTERM"),
    }
}
