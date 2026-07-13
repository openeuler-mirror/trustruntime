//! trustruntime 主程序入口
//!
//! 本程序是可信运行时的核心守护进程，负责提供基于vsock的安全通信服务。
//! 主要功能：
//! - 基于vsock的安全通信（TLS over vsock）
//! - CMS数字签名服务（通过trustring插件提供）
//! - CMS验签服务（通过trustring插件提供）
//! - 证书生命周期管理（定期巡检、过期预警）
//!
//! 启动流程（共13步）：
//! 1. 配置加载：从文件加载应用配置
//! 2. 日志初始化：初始化日志系统
//! 3. 证书检查：检查通信证书和CMS证书状态
//! 4. 创建Transport：创建VsockTransport实例
//! 5. 创建插件：创建TrustringPlugin实例
//! 6. 初始化插件：调用插件init方法注册消息处理器
//! 7. 证书巡检：启动后台证书巡检任务
//! 8. 启动Transport：启动vsock监听服务
//! 9. 通知systemd就绪：向systemd发送READY=1
//! 10. 等待信号：等待SIGTERM/SIGINT退出信号
//! 11. 关闭Transport：停止vsock监听服务
//! 12. 关闭插件：调用插件shutdown方法
//! 13. 通知systemd停止：向systemd发送STOPPING=1
//!
//! 优雅关闭：
//! - 先停止Transport（不再接收新连接）
//! - 再关闭插件（清理资源）
//! - 最后通知systemd（通知systemd服务已停止）

use std::sync::Arc;
use std::time::Duration;
use trustring::TrustringPlugin;
use trustruntime_framework::communication::{TlsConfig, VsockTransport};
use trustruntime_framework::config::AppConfig;
use trustruntime_framework::core::{
    cert_checker::CertificateChecker,
    daemon::Daemon,
    signal::SignalHandler,
};
use trustruntime_framework::logger;
use trustruntime_framework::plugin_manager::{PluginContext, PluginManager};
use trustruntime_framework::transport::TransportLayer;

const EXIT_CODE_GENERAL_ERROR: i32 = 1;

fn parse_args(args: &[String]) -> Result<String, i32> {
    if args.len() < 3 || args[1] != "--config" {
        eprintln!("Usage: trustruntime --config <path>");
        return Err(EXIT_CODE_GENERAL_ERROR);
    }
    Ok(args[2].clone())
}

fn load_config(path: &str) -> Result<Arc<AppConfig>, i32> {
    match AppConfig::from_file(path) {
        Ok(c) => {
            if let Err(e) = c.validate() {
                eprintln!("Invalid config: {}", e);
                return Err(EXIT_CODE_GENERAL_ERROR);
            }
            Ok(Arc::new(c))
        }
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            Err(EXIT_CODE_GENERAL_ERROR)
        }
    }
}

fn init_logger(config: &AppConfig) -> Result<(), i32> {
    match logger::init_logger(&config.log) {
        Ok(_) => {
            log::info!("Logger initialized");
            Ok(())
        }
        Err(e) => {
            eprintln!("Failed to init logger: {}", e);
            Err(EXIT_CODE_GENERAL_ERROR)
        }
    }
}

async fn check_certificates(config: &AppConfig, daemon: &mut Daemon) -> Result<CertificateChecker, ()> {
    let cert_checker = CertificateChecker::new(vec![
        config.certificate.comm_cert.clone(),
        config.certificate.signer_cert.clone(),
    ]);

    let statuses = cert_checker.check_all();

    let comm_expired = statuses
        .iter()
        .find(|s| s.path == config.certificate.comm_cert && s.expired);

    if let Some(expired) = comm_expired {
        log::error!("通信证书已过期: {}", expired.path);
        daemon.notify_status("通信证书已过期").ok();
        daemon.notify_ready().ok();

        let signal_handler = SignalHandler::new();
        signal_handler.wait_for_shutdown_signal().await;
        daemon.notify_stopping().ok();
        return Err(());
    }

    for status in &statuses {
        if status.expired && status.path != config.certificate.comm_cert {
            log::warn!("证书已过期: {}", status.path);
        }
    }

    Ok(cert_checker)
}

fn create_transport(config: &AppConfig) -> Result<Arc<VsockTransport>, String> {
    let tls_config = TlsConfig {
        cert_path: config.certificate.comm_cert.clone(),
        key_path: config.certificate.comm_key.clone(),
        key_password: config.certificate.comm_key_pwd.clone(),
        ca_cert_path: config.certificate.comm_ca_root.clone(),
        crl_path: config.certificate.comm_crl.clone(),
    };

    VsockTransport::new(&tls_config, config.vsock.port, config.vsock.max_connections)
        .map(Arc::new)
        .map_err(|e| format!("Failed to create vsock transport: {}", e))
}

fn setup_plugins(
    config: Arc<AppConfig>,
    transport: &Arc<VsockTransport>,
) -> Result<PluginManager, String> {
    let mut plugin_manager = PluginManager::new();

    let trustring_plugin = TrustringPlugin::new(
        &config.certificate.signer_cert,
        &config.certificate.signer_key,
        &config.certificate.ca_root_cert,
        config.certificate.cms_crl.as_deref(),
    )
    .map_err(|e| format!("Failed to create trustring plugin: {}", e))?;

    plugin_manager.add_plugin(Box::new(trustring_plugin) as Box<dyn trustruntime_framework::plugin_manager::Plugin>);

    let ctx = PluginContext::new(config, transport.clone());
    plugin_manager
        .init_all(&ctx)
        .map_err(|e| format!("Failed to init plugins: {}", e))?;

    Ok(plugin_manager)
}

async fn handle_startup_failure(daemon: &mut Daemon, status: &str) {
    daemon.notify_status(status).ok();
    daemon.notify_ready().ok();
    SignalHandler::new().wait_for_shutdown_signal().await;
    daemon.notify_stopping().ok();
}

async fn graceful_shutdown(
    transport: Arc<VsockTransport>,
    mut plugin_manager: PluginManager,
    daemon: &mut Daemon,
    cert_checker_handle: tokio::task::JoinHandle<()>,
) {
    transport.stop().await;

    if let Err(e) = plugin_manager.shutdown_all() {
        log::error!("Plugin shutdown error: {}", e);
    }

    daemon.notify_stopping().ok();
    cert_checker_handle.abort();
    log::info!("Shutdown complete");
}

/// 主程序入口
///
/// 执行trustruntime守护进程的完整启动和关闭流程。
/// 关键设计点：
/// - 使用tokio异步运行时支持并发连接处理（固定4 worker threads）
/// - 所有错误场景都通知systemd并优雅退出
/// - 通信证书过期会导致服务不可用（阻塞启动）
/// - CMS证书过期仅警告（不影响启动）
///
/// 性能配置：
/// - tokio worker threads: 4（足够处理最大16并发连接）
/// - 并发连接上限: Semaphore(16)
#[tokio::main(worker_threads = 4)]
async fn main() {
    // ==================== 步骤1：配置加载 ====================
    let args: Vec<String> = std::env::args().collect();
    let config_path = match parse_args(&args) {
        Ok(path) => path,
        Err(code) => std::process::exit(code),
    };

    let config = match load_config(&config_path) {
        Ok(c) => c,
        Err(code) => std::process::exit(code),
    };

    // ==================== 步骤2：日志初始化 ====================
    if let Err(code) = init_logger(&config) {
        std::process::exit(code);
    }

    log::info!("trustruntime starting...");

    // ==================== 步骤3：证书检查 ====================
    let mut daemon = Daemon::new();
    let cert_checker = match check_certificates(&config, &mut daemon).await {
        Ok(c) => c,
        Err(()) => return,
    };

    // ==================== 步骤4：创建Transport ====================
    let transport = match create_transport(&config) {
        Ok(t) => t,
        Err(e) => {
            log::error!("{}", e);
            handle_startup_failure(&mut daemon, "vsock传输层创建失败").await;
            return;
        }
    };

    // ==================== 步骤5-6：创建并初始化插件 ====================
    let plugin_manager = match setup_plugins(config.clone(), &transport) {
        Ok(m) => m,
        Err(e) => {
            log::error!("{}", e);
            handle_startup_failure(&mut daemon, "插件初始化失败").await;
            return;
        }
    };

    // ==================== 步骤7：启动证书巡检 ====================
    let cert_checker_handle = cert_checker
        .with_interval(Duration::from_secs(config.cert_check.interval_hours * 3600))
        .start_periodic_check();

    // ==================== 步骤8：启动Transport ====================
    if let Err(e) = transport.start().await {
        log::error!("Failed to start transport: {}", e);
        handle_startup_failure(&mut daemon, "transport启动失败").await;
        cert_checker_handle.abort();
        return;
    }

    // ==================== 步骤9：通知systemd就绪 ====================
    daemon.notify_ready().ok();
    log::info!("trustruntime started on port {}", config.vsock.port);

    // ==================== 步骤10：等待退出信号 ====================
    let signal_handler = SignalHandler::new();
    signal_handler.wait_for_shutdown_signal().await;
    log::info!("Shutting down...");

    // ==================== 步骤11-13：优雅关闭 ====================
    graceful_shutdown(transport, plugin_manager, &mut daemon, cert_checker_handle).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_valid() {
        let args = vec![
            "trustruntime".to_string(),
            "--config".to_string(),
            "/etc/trustruntime/agent.toml".to_string(),
        ];
        let result = parse_args(&args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/etc/trustruntime/agent.toml");
    }

    #[test]
    fn parse_args_missing_config_flag() {
        let args = vec!["trustruntime".to_string()];
        let result = parse_args(&args);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), 1);
    }

    #[test]
    fn parse_args_missing_config_path() {
        let args = vec!["trustruntime".to_string(), "--config".to_string()];
        let result = parse_args(&args);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), 1);
    }

    #[test]
    fn parse_args_wrong_flag() {
        let args = vec![
            "trustruntime".to_string(),
            "--wrong".to_string(),
            "/etc/trustruntime/agent.toml".to_string(),
        ];
        let result = parse_args(&args);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), 1);
    }

    #[test]
    fn load_config_invalid_path() {
        let result = load_config("/nonexistent/path/config.toml");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), 1);
    }

    #[test]
    fn load_config_invalid_toml() {
        use std::io::Write;
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, "invalid toml content [[[[").unwrap();
        temp_file.flush().unwrap();

        let result = load_config(temp_file.path().to_str().unwrap());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), 1);
    }
}