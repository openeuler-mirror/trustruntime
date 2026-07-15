//! CMS测试器模块
//!
//! 本模块提供多种测试器实现，用于验证CMS签名服务的不同方面：
//!
//! - [`InteractiveTester`]：交互式测试器，支持手动输入测试命令
//! - [`ConcurrentTester`]：并发测试器，支持多线程并发测试
//! - [`PerformanceTester`]：性能测试器，测试吞吐量和延迟
//! - [`ProtocolSecurityTester`]：安全测试器，测试协议安全性
//! - [`ScenarioRunner`]：场景测试运行器，运行预定义测试场景
//!
//! ## 测试场景分类
//!
//! | 场景类型 | 编号范围 | 说明 |
//! |---------|---------|------|
//! | 正常场景 | N01-N03 | 标准签名验证流程 |
//! | 错误场景 | E01-E20 | 错误处理和异常情况 |
//! | 边界场景 | B01-B07 | 边界条件和极限值测试 |

mod concurrent;
mod interactive;
mod performance;
mod scenarios;
mod security;

pub use concurrent::ConcurrentTester;
pub use interactive::InteractiveTester;
pub use performance::PerformanceTester;
pub use scenarios::ScenarioRunner;
pub use security::ProtocolSecurityTester;
