//! 通信模块 - 提供安全传输层和通信基础设施
//!
//! 该模块封装了 vsock 通信相关功能：
//! - `vsock_server`：基于 vsock 的 TLS 安全传输实现，用于与 Enclave 内部服务通信
//!
//! 公开导出的类型：
//! - `VsockTransport`：vsock 传输层实现
//! - `TlsConfig`：TLS 配置（证书、密钥等）
//! - `VsockError`：vsock 通信错误类型

pub(crate) mod vsock_server;

pub use vsock_server::{TlsConfig, VsockError, VsockTransport};
