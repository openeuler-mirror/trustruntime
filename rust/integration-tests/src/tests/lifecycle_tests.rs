//! 进程生命周期测试模块
//!
//! 测试范围：
//! - L01: 正常启动关闭流程
//! - L03: 配置文件缺失退出
//! - L04: 配置格式错误退出
//! - L05: 命令行参数缺失退出
//!
//! 重点验证：进程启动参数验证、配置加载、优雅关闭

use integration_tests::proc_manager::{NodeConfig, ProcessManager};
use integration_tests::test_helpers::TestPaths;
use std::process::Command;
use std::time::Duration;

/// L01: 正常启动关闭流程
///
/// 测试场景：启动trustruntime进程，等待2秒后关闭
///
/// 预期结果：进程正常启动，正常关闭
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn l01_normal_startup_shutdown() {
    let paths = TestPaths::new();
    let manager = ProcessManager::new(paths.binary_path.clone(), paths.cert_base.clone());

    let node_config = NodeConfig {
        name: "node-a".to_string(),
        port: 12345,
        cms_cert_path: paths.node_cms_cert("node-a"),
        cms_key_path: paths.node_cms_key("node-a"),
        tls_cert_path: paths.node_tls_cert("node-a"),
        tls_key_path: paths.node_tls_key("node-a"),
        tls_client_crl: None,
    };

    manager.start_node(node_config).expect("Failed to start node");

    std::thread::sleep(Duration::from_secs(2));

    manager.stop_all().expect("Failed to stop processes");
}

/// L03: 配置文件缺失退出
///
/// 测试场景：启动trustruntime，指定不存在的配置文件路径
///
/// 预期结果：进程非零退出，stderr包含错误信息
/// 原因：配置文件加载失败
///
/// 测试依赖：编译后的二进制文件
#[test]
fn l03_config_missing_exit() {
    let binary_path = std::env::var("TEST_BINARY_PATH")
        .unwrap_or_else(|_| "target/release/trustruntime".to_string());

    if !std::path::Path::new(&binary_path).exists() {
        return;  // Skip test if binary not found
    }

    let result = Command::new(&binary_path)
        .arg("--config")
        .arg("/nonexistent/config.toml")
        .output()
        .expect("Failed to execute process");

    assert!(!result.status.success(), "Process should exit with non-zero status for missing config");
    assert!(result.stderr.len() > 0, "Should have error message in stderr");
}

/// L04: 配置格式错误退出
///
/// 测试场景：启动trustruntime，指定无效TOML格式的配置文件
///
/// 预期结果：进程非零退出
/// 原因：配置文件解析失败
///
/// 测试依赖：编译后的二进制文件
#[test]
fn l04_invalid_config_format_exit() {
    let binary_path = std::env::var("TEST_BINARY_PATH")
        .unwrap_or_else(|_| "target/release/trustruntime".to_string());

    if !std::path::Path::new(&binary_path).exists() {
        return;  // Skip test if binary not found
    }

    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("invalid.toml");
    std::fs::write(&config_path, "invalid config content").expect("Failed to write config");

    let result = Command::new(&binary_path)
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("Failed to execute process");

    assert!(!result.status.success(), "Process should exit with non-zero status for invalid config format");
}

/// L05: 命令行参数缺失退出
///
/// 测试场景：启动trustruntime，不提供任何参数
///
/// 预期结果：进程非零退出，stderr包含Usage信息
/// 原因：缺少必需的--config参数
///
/// 测试依赖：编译后的二进制文件
#[test]
fn l05_missing_argument_exit() {
    let binary_path = std::env::var("TEST_BINARY_PATH")
        .unwrap_or_else(|_| "target/release/trustruntime".to_string());

    if !std::path::Path::new(&binary_path).exists() {
        return;  // Skip test if binary not found
    }

    let result = Command::new(&binary_path)
        .output()
        .expect("Failed to execute process");

    assert!(!result.status.success(), "Process should exit with non-zero status for missing arguments");
    assert!(String::from_utf8_lossy(&result.stderr).contains("Usage"));
}