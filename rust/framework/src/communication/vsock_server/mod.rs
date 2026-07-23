//! vsock传输层实现模块
//!
//! 职责：
//! - 实现TransportLayer trait，提供基于vsock的TLS安全传输层
//! - 管理并发连接（信号量限流）
//! - 分发消息到业务处理器（DataHandler）
//! - 处理协议层错误响应
//!
//! 架构决策：
//! - 统一OpenSSL处理TLS和CMS（ADR-0004）
//!   - 消除双加密栈问题（rustls + OpenSSL）
//!   - 证书类型一致（openssl::X509 和 openssl::PKey）
//!   - 错误处理统一
//! - TransportLayer抽象解耦通信层与插件框架层（ADR-0005）
//!   - Transport职责：协议层（报文解析、校验、错误响应）
//!   - DataHandler职责：业务层（JSON解析、签名验签）
//!
//! 依赖：
//! - crate::message::VsockMessage: 消息编解码
//! - crate::transport: TransportLayer trait 和 DataHandler trait
//! - openssl: TLS实现
//! - vsock: Linux vsock通信

mod connection;
mod error;
mod listener;
mod tls;

#[cfg(test)]
mod tests;

pub use error::VsockError;
pub use tls::TlsConfig;

use crate::transport::{DataHandler, TransportError, TransportLayer};
use async_trait::async_trait;
use listener::listener_loop_async;
use openssl::ssl::SslAcceptor;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::time::Duration;
use tls::{configure_tls_builder, load_tls_certificates, set_socket_timeout};
use tokio::sync::Semaphore;

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

/// vsock传输层实现
///
/// 实现TransportLayer trait，提供基于vsock的TLS安全传输层
///
/// 核心组件：
/// - ssl_acceptor: TLS服务端接收器（OpenSSL）
/// - semaphore: 并发连接限制信号量（MAX_CONCURRENT_CONNECTIONS个许可）
/// - handlers: 消息处理器映射（msg_type -> DataHandler）
/// - shutdown_signal: 优雅关闭信号
/// - listener_handle: 监听线程句柄（用于优雅关闭）
pub struct VsockTransport {
    /// TLS服务端接收器
    /// 用于执行TLS握手和建立安全连接
    ssl_acceptor: Arc<SslAcceptor>,
    /// 并发连接限制信号量
    /// 数量由配置项max_connections决定（默认MAX_CONCURRENT_CONNECTIONS）
    semaphore: Arc<Semaphore>,
    /// 消息处理器映射
    /// Key: 消息类型（msg_type）
    /// Value: 业务处理器（DataHandler trait对象）
    handlers: Arc<RwLock<HashMap<u32, Box<dyn DataHandler>>>>,
    /// vsock监听端口
    port: u32,
    /// 优雅关闭信号
    /// 设置为true时，监听线程停止接收新连接
    shutdown_signal: Arc<AtomicBool>,
    /// 监听任务句柄
    /// 用于在stop()时等待任务优雅退出
    listener_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl VsockTransport {
    pub fn new(
        tls_config: &TlsConfig,
        port: u32,
        max_connections: u32,
    ) -> Result<Self, VsockError> {
        let mut builder = configure_tls_builder()?;
        let ca_cert = load_tls_certificates(&mut builder, tls_config)?;

        if let Some(crl_path) = &tls_config.crl_path {
            tls::configure_crl_verification(&mut builder, crl_path, &ca_cert)?;
        }

        let ssl_acceptor = builder.build();

        Ok(Self {
            ssl_acceptor: Arc::new(ssl_acceptor),
            semaphore: Arc::new(Semaphore::new(max_connections as usize)),
            handlers: Arc::new(RwLock::new(HashMap::new())),
            port,
            shutdown_signal: Arc::new(AtomicBool::new(false)),
            listener_handle: Arc::new(Mutex::new(None)),
        })
    }

    pub fn ssl_acceptor(&self) -> &Arc<SslAcceptor> {
        &self.ssl_acceptor
    }

    pub fn handlers(&self) -> &Arc<RwLock<HashMap<u32, Box<dyn DataHandler>>>> {
        &self.handlers
    }
}

#[async_trait]
impl TransportLayer for VsockTransport {
    fn register_handler(&self, msg_type: u32, handler: Box<dyn DataHandler>) {
        let mut handlers = self.handlers.write().unwrap();
        if handlers.contains_key(&msg_type) {
            log::warn!(
                "Handler for msg_type 0x{:02X} already registered, will be overwritten",
                msg_type
            );
        }
        handlers.insert(msg_type, handler);
    }

    #[cfg(target_os = "linux")]
    async fn start(&self) -> Result<(), TransportError> {
        use vsock::VsockListener;

        let cid: u32 = 0xFFFFFFFF;
        let addr = vsock::VsockAddr::new(cid, self.port);

        let listener =
            VsockListener::bind(&addr).map_err(|e| TransportError::StartFailed(e.to_string()))?;

        set_socket_timeout(listener.as_raw_fd(), Duration::from_secs(1))
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;

        log::info!(
            "vsock listener bound on cid=ANY, port={} (backlog=128, accept_timeout=1s)",
            self.port
        );

        self.shutdown_signal.store(false, Ordering::SeqCst);

        let handlers = self.handlers.clone();
        let semaphore = self.semaphore.clone();
        let shutdown_signal = self.shutdown_signal.clone();
        let ssl_acceptor = self.ssl_acceptor.clone();

        let task_handle = tokio::spawn(listener_loop_async(
            listener,
            handlers,
            semaphore,
            shutdown_signal,
            ssl_acceptor,
        ));

        *self.listener_handle.lock().unwrap() = Some(task_handle);

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    async fn start(&self) -> Result<(), TransportError> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn stop(&self) -> Result<(), TransportError> {
        self.shutdown_signal.store(true, Ordering::SeqCst);
        log::info!("vsock shutdown signal sent");

        let handle = self.listener_handle.lock().unwrap().take();

        if let Some(handle) = handle {
            let result = tokio::time::timeout(Duration::from_secs(5), handle).await;

            match result {
                Ok(Ok(_)) => {
                    log::info!("vsock listener task stopped gracefully");
                    Ok(())
                }
                Ok(Err(e)) => {
                    log::warn!("vsock listener task error: {}", e);
                    Err(TransportError::StopFailed(e.to_string()))
                }
                Err(_) => {
                    log::warn!("vsock shutdown timeout (5s), listener task may still running");
                    Err(TransportError::StopFailed(
                        "shutdown timeout (5s)".to_string(),
                    ))
                }
            }
        } else {
            Ok(())
        }
    }

    #[cfg(not(target_os = "linux"))]
    async fn stop(&self) -> Result<(), TransportError> {
        log::info!("vsock shutdown (non-linux platform)");
        Ok(())
    }
}
