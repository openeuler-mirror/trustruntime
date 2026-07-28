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

//! CMS签名服务测试工具
//!
//! 提供两种使用模式：
//! - 交互式REPL：手动输入命令，适合探索性测试
//! - 命令行单次执行：执行单条命令后退出，适合脚本化测试
//!
//! 功能模块：
//! - [`config`][]: 配置管理，从TOML文件加载配置
//! - [`repl`][]: REPL交互界面，提供命令行交互
//! - [`stats`][]: 统计报告生成，收集测试指标
//! - [`testers`][]: 测试执行器，实现各类测试模式

mod config;
mod repl;
mod stats;
mod testers;

use clap::Parser;
use config::CmsTestConfig;
use repl::{parse, CommandRouter, ExecuteResult};

/// CMS签名服务测试工具
#[derive(Parser)]
#[command(name = "cms-test-cli")]
#[command(about = "Interactive testing tool for CMS signing service")]
struct Args {
    /// 配置文件路径（必填）
    #[arg(short, long)]
    config: String,

    /// 单次执行命令（可选，不指定则进入交互式REPL）
    #[arg(short, long)]
    command: Option<String>,
}

fn main() {
    let args = Args::parse();

    let config = CmsTestConfig::from_file(&args.config).expect("Failed to load config file");

    if let Some(cmd) = args.command {
        execute_single_command(config, &cmd);
    } else {
        repl::run_repl(config);
    }
}

/// 单次执行命令
///
/// # 参数
/// - `config`: 全局配置
/// - `cmd`: 命令字符串（与REPL命令格式一致）
///
/// # 行为
/// - 自动连接服务器（使用配置文件中的端口）
/// - 执行单条命令后退出
/// - 成功返回退出码0，失败返回退出码1
fn execute_single_command(config: CmsTestConfig, cmd: &str) {
    let mut router = CommandRouter::new(config);

    // 自动连接服务器
    let connect_cmd = parse("connect").expect("Failed to parse connect command");
    if let Err(e) = router.execute(connect_cmd) {
        eprintln!("Failed to connect to server: {}", e);
        std::process::exit(1);
    }

    // 执行用户命令
    match parse(cmd) {
        Ok(parsed_cmd) => match router.execute(parsed_cmd) {
            Ok(ExecuteResult::Output(msg)) => {
                println!("{}", msg);
                std::process::exit(0);
            }
            Ok(ExecuteResult::Continue) => {
                std::process::exit(0);
            }
            Ok(ExecuteResult::Quit) => {
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Parse error: {}", e);
            std::process::exit(1);
        }
    }
}
