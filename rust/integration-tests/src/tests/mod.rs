//! 集成测试模块
//!
//! 模块组织结构：
//! - normal_scenarios: 正常场景测试（N01-N03）
//! - error_scenarios: 错误场景测试（E01-E20）
//! - boundary_scenarios: 边界场景测试（B01-B07）
//! - handler_tests: DataHandler处理器测试
//! - lifecycle_tests: 进程生命周期测试（启动、关闭）
//! - communication_tests: vsock通信测试（TLS握手、并发连接）
//! - cert_check_tests: 证书状态检查测试（过期检测、周期检查）
//! - tls_debug_test: TLS证书链调试测试（问题诊断）
//! - proc_debug_test: 进程调试测试（问题诊断）
//!
//! 测试场景编码规范：
//! - N系列：正常业务流程测试
//! - E系列：错误处理测试
//! - B系列：边界条件测试
//! - L系列：生命周期测试
//! - C系列：通信层测试
//! - CC系列：证书检查测试
//!
//! 注意：tls_debug_test和proc_debug_test为调试测试，仅手动运行

pub mod normal_scenarios;
pub mod error_scenarios;
pub mod boundary_scenarios;
pub mod communication_tests;
pub mod lifecycle_tests;
pub mod cert_check_tests;
pub mod handler_tests;
pub mod tls_debug_test;
pub mod proc_debug_test;