//! CMS签名服务测试工具
//!
//! 提供REPL交互界面，支持多种测试模式：
//! - interactive: 交互式测试，手动执行单个命令
//! - concurrent: 并发测试，验证多连接场景
//! - performance: 性能测试，测量吞吐量和延迟
//! - security: 安全测试，验证TLS证书校验
//! - scenarios: 场景测试，执行预定义测试用例集
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

/// CMS签名服务测试工具
#[derive(Parser)]
#[command(name = "cms-test-cli")]
#[command(about = "Interactive testing tool for CMS signing service")]
struct Args {
    /// 配置文件路径（必填）
    #[arg(short, long)]
    config: String,
}

fn main() {
    let args = Args::parse();

    let config = CmsTestConfig::from_file(&args.config).expect("Failed to load config file");

    repl::run_repl(config);
}
