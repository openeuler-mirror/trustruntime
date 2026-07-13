//! 进程调试测试模块
//!
//! 测试目的：
//! - 验证二进制文件路径
//! - 验证进程可执行性
//! - 调试进程启动问题
//!
//! 用途：问题诊断，非生产测试
//! 状态：仅调试时运行

use integration_tests::proc_manager::{NodeConfig, ProcessManager};
use integration_tests::test_helpers::TestPaths;

/// 进程二进制路径调试测试
///
/// 测试内容：
/// 1. 打印binary_path和cert_base路径
/// 2. 检查二进制文件是否存在
/// 3. 尝试执行--help命令
///
/// 用途：验证测试环境配置是否正确
#[test]
#[ignore = "Debug test for binary path verification"]
fn debug_binary_path() {
    let paths = TestPaths::new();

    eprintln!("DEBUG: binary_path = {:?}", paths.binary_path);
    eprintln!("DEBUG: cert_base = {:?}", paths.cert_base);

    // Check if binary exists
    if paths.binary_path.exists() {
        eprintln!("DEBUG: Binary file exists");
    } else {
        eprintln!("DEBUG: Binary file DOES NOT exist");
    }

    // Try to spawn the process with minimal config
    let manager = ProcessManager::new(paths.binary_path.clone(), paths.cert_base.clone());

    eprintln!("DEBUG: ProcessManager created");

    // This should fail if binary cannot be spawned
    let result = std::process::Command::new(&paths.binary_path)
        .arg("--help")
        .output();

    match result {
        Ok(output) => {
            eprintln!("DEBUG: Binary executed successfully");
            eprintln!("DEBUG: stdout = {}", String::from_utf8_lossy(&output.stdout));
            eprintln!("DEBUG: stderr = {}", String::from_utf8_lossy(&output.stderr));
        }
        Err(e) => {
            eprintln!("DEBUG: Binary execution failed: {}", e);
        }
    }
}