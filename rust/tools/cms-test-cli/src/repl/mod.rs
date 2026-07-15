//! REPL（Read-Eval-Print Loop）交互式命令行模块
//!
//! 提供交互式命令行界面，支持用户输入命令并执行测试操作。
//! 主要功能：
//! - 连接/断开 CMS 签名服务
//! - 执行签名、验签操作
//! - 运行性能测试、并发测试、安全测试
//! - 执行预定义测试场景

mod commands;
mod parser;

pub use commands::{CommandRouter, ExecuteResult};
pub use parser::parse;

use crate::config::CmsTestConfig;
use std::io::{self, Write};

/// 启动 REPL 交互式命令行
///
/// # 参数
/// - `config`: 全局配置（包含默认端口、证书目录等）
///
/// # 行为
/// 循环读取用户输入，解析命令并执行，直到用户输入 `quit` 或 `exit`。
///
/// # 命令格式
/// - `connect <port>`: 连接服务
/// - `sign <data>`: 签名数据
/// - `verify <data> <signed_data> <id>`: 验证签名
/// - `perf sign --count <n>`: 性能测试
/// - `concurrent sign --threads <n>`: 并发测试
/// - `security protocol`: 安全测试
/// - `scenario <name>`: 运行场景
/// - `help`: 显示帮助
/// - `quit`: 退出
pub fn run_repl(config: CmsTestConfig) {
    let mut router = CommandRouter::new(config);

    // 显示欢迎信息
    println!("cms-test-cli v0.1.0");
    println!("Type 'help' for available commands.\n");

    // 主循环：读取 -> 解析 -> 执行
    loop {
        // 显示提示符
        print!("> ");
        io::stdout().flush().unwrap();

        // 读取用户输入
        let mut input = String::new();
        let bytes = io::stdin().read_line(&mut input).unwrap();
        if bytes == 0 {
            break; // EOF - 退出循环
        }

        // 跳过空行
        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }

        // 解析并执行命令
        match parse(trimmed) {
            Ok(cmd) => {
                // 记录命令历史
                router
                    .config
                    .lock()
                    .unwrap()
                    .history
                    .push(trimmed.to_string());

                // 执行命令并处理结果
                match router.execute(cmd) {
                    Ok(ExecuteResult::Quit) => {
                        println!("Goodbye.");
                        break;
                    }
                    Ok(ExecuteResult::Output(msg)) => println!("{}", msg),
                    Ok(ExecuteResult::Continue) => {}
                    Err(e) => println!("Error: {}", e),
                }
            }
            Err(e) => println!("Parse error: {}", e),
        }
    }
}
