//! 核心模块 - 提供进程生命周期管理和基础设施组件
//!
//! 该模块包含运行时核心功能的子模块：
//! - `daemon`：守护进程管理，负责进程后台化和生命周期控制
//! - `cert_checker`：证书检查器，监控证书有效期并触发更新
//! - `signal`：信号处理，处理系统信号（如 SIGTERM、SIGINT）的注册与分发

pub mod cert_checker;
pub mod daemon;
pub mod signal;
