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

/// 通用错误响应码定义（根据 interface.md 第5节）
const ERROR_HANDLER_PANIC: u32 = 0x00;     // 服务端内部异常（插件崩溃、证书加载失败等）
const ERROR_PROTOCOL: u32 = 0x01;          // 报文格式异常（版本不匹配、消息解析失败、无处理器等）
const ERROR_MESSAGE_TOO_LONG: u32 = 0x02;  // 请求报文过长（超过10KB）
const ERROR_CONNECTION_CLOSED: u32 = 0xFF; // 连接关闭（内部错误码，不发送给客户端）

/// 协议层配置常量
const PROTOCOL_VERSION: u32 = 0xFFFF0400;              // 协议版本号（interface.md 第2.2节）
const MAX_MESSAGE_SIZE: u32 = 10240;                   // 最大消息长度（10KB，interface.md 第2.1节）
const MAX_CONCURRENT_CONNECTIONS: usize = 16;          // 最大并发连接数（AGENTS.md 第63节）
const HEADER_SIZE: usize = 16;                         // 消息头长度（seq + version + msg_type + len）

use crate::message::VsockMessage;
use crate::transport::{DataHandler, TransportError, TransportLayer};
use async_trait::async_trait;
use openssl::ssl::{SslAcceptor, SslMethod, SslVerifyMode};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::Mutex;
use tokio::sync::Semaphore;

/// vsock传输层错误类型
///
/// 架构决策：错误类型细分便于定位问题
/// - TlsConfigError: TLS配置错误（证书、私钥、密码套件等）
/// - IoError: 文件I/O错误（文件不存在、权限不足等）
/// - BindError: vsock绑定错误（端口占用、权限不足等）
#[derive(Debug)]
pub enum VsockError {
    /// TLS配置错误（证书加载、密码套件配置、CRL加载等）
    TlsConfigError(String),
    /// 文件I/O错误（证书/私钥/CRL文件不存在、权限不足等）
    IoError(std::io::Error),
    /// vsock绑定错误（端口占用、权限不足等）
    BindError(String),
}

impl std::fmt::Display for VsockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VsockError::TlsConfigError(s) => write!(f, "TLS config error: {}", s),
            VsockError::IoError(e) => write!(f, "IO error: {}", e),
            VsockError::BindError(s) => write!(f, "Bind error: {}", s),
        }
    }
}

impl From<openssl::error::ErrorStack> for VsockError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        VsockError::TlsConfigError(e.to_string())
    }
}

impl From<std::io::Error> for VsockError {
    fn from(e: std::io::Error) -> Self {
        VsockError::IoError(e)
    }
}

/// TLS配置参数
///
/// 封装TLS服务端所需的证书和密钥路径
pub struct TlsConfig {
    /// 服务端证书路径（PEM格式）
    pub cert_path: String,
    /// 服务端私钥路径（PEM格式）
    pub key_path: String,
    /// 私钥密码（可选）
    pub key_password: Option<String>,
    /// CA根证书路径（用于客户端证书验证）
    pub ca_cert_path: String,
    /// CRL吊销列表路径（可选）
    pub crl_path: Option<String>,
}

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
    /// 创建vsock传输层实例
    ///
    /// 架构决策：统一OpenSSL处理TLS和CMS（ADR-0004）
    /// 使用OpenSSL SslAcceptor实现TLS服务端
    ///
    /// # Arguments
    /// * `tls_config` - TLS配置参数（证书、私钥、CA、CRL路径）
    /// * `port` - vsock监听端口
    /// * `max_connections` - 最大并发连接数（默认 MAX_CONCURRENT_CONNECTIONS）
    ///
    /// # Returns
    /// * `Ok(VsockTransport)` - 传输层实例
    /// * `Err(VsockError::TlsConfigError)` - TLS配置错误
    ///
    /// # Example
    /// ```text
    /// let config = TlsConfig {
    ///     cert_path: "/path/to/server.crt".to_string(),
    ///     key_path: "/path/to/server.key".to_string(),
    ///     ...
    /// };
    /// let transport = VsockTransport::new(&config, 12345, MAX_CONCURRENT_CONNECTIONS)?;
    /// ```
    pub fn new(tls_config: &TlsConfig, port: u32, max_connections: u32) -> Result<Self, VsockError> {
        let mut builder = Self::configure_tls_builder()?;
        Self::load_tls_certificates(&mut builder, tls_config)?;

        if let Some(crl_path) = &tls_config.crl_path {
            Self::configure_crl_verification(&mut builder, crl_path)?;
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

    /// 配置TLS安全参数
    ///
    /// 架构决策（ADR-0004）：
    /// - 仅允许TLS 1.2和TLS 1.3
    /// - 强密码套件（AES-256/128-GCM, CHACHA20-POLY1305）
    /// - 前向保密（ECDHE密钥交换）
    /// - 禁用重协商和Session Ticket
    ///
    /// # Returns
    /// * `Ok(SslAcceptorBuilder)` - TLS配置构建器
    /// * `Err(VsockError::TlsConfigError)` - 配置错误
    fn configure_tls_builder() -> Result<openssl::ssl::SslAcceptorBuilder, VsockError> {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;

        builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;
        builder.set_max_proto_version(None)?;

        builder.set_ciphersuites("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256")?;
        builder.set_cipher_list("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256")?;

        builder.set_options(
            openssl::ssl::SslOptions::NO_RENEGOTIATION |
            openssl::ssl::SslOptions::NO_TICKET
        );

        Ok(builder)
    }

    /// 加载TLS证书和私钥
    ///
    /// 加载服务端证书、私钥、CA证书，配置双向认证
    /// 使用framework::cert模块支持PEM/DER双格式
    ///
    /// # Arguments
    /// * `builder` - TLS配置构建器
    /// * `tls_config` - TLS配置参数
    ///
    /// # Returns
    /// * `Ok(())` - 加载成功
    /// * `Err(VsockError::TlsConfigError)` - 证书加载失败
    fn load_tls_certificates(
        builder: &mut openssl::ssl::SslAcceptorBuilder,
        tls_config: &TlsConfig,
    ) -> Result<(), VsockError> {
        let cert = crate::cert::load_x509(&tls_config.cert_path)
            .map_err(|e| VsockError::TlsConfigError(e.to_string()))?;
        builder.set_certificate(&cert)?;

        let key = crate::cert::load_private_key(&tls_config.key_path, tls_config.key_password.as_deref())
            .map_err(|e| VsockError::TlsConfigError(e.to_string()))?;
        builder.set_private_key(&key)?;

        let ca_cert = crate::cert::load_x509(&tls_config.ca_cert_path)
            .map_err(|e| VsockError::TlsConfigError(e.to_string()))?;
        builder.cert_store_mut().add_cert(ca_cert)?;

        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);

        Ok(())
    }

    /// 配置CRL吊销检查
    ///
    /// 验证客户端证书是否在吊销列表中
    /// 使用证书序列号匹配
    ///
    /// # Arguments
    /// * `builder` - TLS配置构建器
    /// * `crl_path` - CRL文件路径
    ///
    /// # Returns
    /// * `Ok(())` - 配置成功
    /// * `Err(VsockError::TlsConfigError)` - CRL加载失败
    fn configure_crl_verification(
        builder: &mut openssl::ssl::SslAcceptorBuilder,
        crl_path: &str,
    ) -> Result<(), VsockError> {
        let crl = crate::cert::load_crl(crl_path)
            .map_err(|e| VsockError::TlsConfigError(e.to_string()))?;

        builder.set_verify_callback(
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            move |ok, ctx| Self::verify_cert_with_crl(ok, ctx, &crl),
        );

        Ok(())
    }

    /// 使用CRL验证证书是否被吊销
    ///
    /// # Arguments
    /// * `ok` - OpenSSL基础验证结果
    /// * `ctx` - SSL验证上下文
    /// * `crl` - CRL吊销列表
    ///
    /// # Returns
    /// * `true` - 证书有效（未被吊销）
    /// * `false` - 证书无效（已被吊销或基础验证失败）
    fn verify_cert_with_crl(
        ok: bool,
        ctx: &mut openssl::x509::X509StoreContextRef,
        crl: &openssl::x509::X509Crl,
    ) -> bool {
        if !ok {
            return false;
        }

        ctx.current_cert()
            .map(|cert| !Self::is_cert_revoked(cert, crl))
            .unwrap_or(true)
    }

    /// 检查证书是否在CRL吊销列表中
    ///
    /// # Arguments
    /// * `cert` - 待检查的证书
    /// * `crl` - CRL吊销列表
    ///
    /// # Returns
    /// * `true` - 证书已被吊销
    /// * `false` - 证书未被吊销
    fn is_cert_revoked(cert: &openssl::x509::X509Ref, crl: &openssl::x509::X509Crl) -> bool {
        let serial = cert.serial_number();
        crl.get_revoked()
            .map(|revoked_stack| revoked_stack.iter().any(|revoked| revoked.serial_number() == serial))
            .unwrap_or(false)
    }

    /// 获取TLS接收器引用
    ///
    /// 用于测试和调试场景
    pub fn ssl_acceptor(&self) -> &Arc<SslAcceptor> {
        &self.ssl_acceptor
    }

    /// 获取消息处理器映射引用
    ///
    /// 用于测试和调试场景
    pub fn handlers(&self) -> &Arc<RwLock<HashMap<u32, Box<dyn DataHandler>>>> {
        &self.handlers
    }

    /// 处理单个vsock连接（阻塞模式）
    ///
    /// 错误码定义：
    /// - ERROR_HANDLER_PANIC: Handler panic（业务处理器崩溃）
    /// - ERROR_PROTOCOL: 协议错误（版本不匹配、消息格式错误、Handler返回None、无处理器）
    /// - ERROR_MESSAGE_TOO_LONG: 消息过长（len > MAX_MESSAGE_SIZE字节）
    ///
    /// 消息格式（小端序）：
    /// - Header (HEADER_SIZE字节): seq(4) + version(4) + msg_type(4) + len(4)
    /// - Body (len字节): 业务数据
    ///
    /// # Arguments
    /// * `ssl_stream` - TLS安全连接流
    /// * `handlers` - 消息处理器映射（msg_type -> DataHandler）
    #[cfg(target_os = "linux")]
    fn handle_connection_blocking(
        mut ssl_stream: openssl::ssl::SslStream<vsock::VsockStream>,
        handlers: Arc<RwLock<HashMap<u32, Box<dyn DataHandler>>>>,
    ) {
        use std::io::Write;

        log::debug!("New vsock connection established");

        loop {
            match Self::read_message(&mut ssl_stream) {
                Ok(msg) => {
                    match Self::process_message(&msg, &handlers) {
                        Ok(resp_data) => {
                            let resp = VsockMessage::new(msg.header.seq, msg.header.version, msg.header.msg_type + 1, resp_data);
                            ssl_stream.write_all(&resp.serialize()).ok();
                        }
                        Err(error_code) => {
                            Self::send_error_response(&mut ssl_stream, msg.header.seq, msg.header.version, error_code);
                        }
                    }
                }
                Err(error_code) => {
                    if error_code == ERROR_CONNECTION_CLOSED {
                        break;
                    }
                }
            }
        }

        log::debug!("Connection closed");
    }

    /// 读取并解析消息
    ///
    /// 从TLS流读取消息头和消息体，执行协议校验
    ///
    /// # Returns
    /// * `Ok(VsockMessage)` - 成功解析的消息
    /// * `Err(ERROR_PROTOCOL)` - 协议错误（版本不匹配、格式错误、读取失败）
    /// * `Err(ERROR_MESSAGE_TOO_LONG)` - 消息过长
    /// * `Err(ERROR_CONNECTION_CLOSED)` - 连接关闭
    #[cfg(target_os = "linux")]
    fn read_message(
        ssl_stream: &mut openssl::ssl::SslStream<vsock::VsockStream>,
    ) -> Result<VsockMessage, u32> {
        use std::io::Read;

        let mut header_buf = [0u8; HEADER_SIZE];
        if ssl_stream.read_exact(&mut header_buf).is_err() {
            return Err(ERROR_CONNECTION_CLOSED);
        }

        let seq = u32::from_le_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);
        let version = u32::from_le_bytes([header_buf[4], header_buf[5], header_buf[6], header_buf[7]]);
        let len = u32::from_le_bytes([header_buf[12], header_buf[13], header_buf[14], header_buf[15]]);

        if version != PROTOCOL_VERSION {
            Self::send_error_response(ssl_stream, seq, version, ERROR_PROTOCOL);
            return Err(ERROR_PROTOCOL);
        }

        if len > MAX_MESSAGE_SIZE {
            Self::send_error_response(ssl_stream, seq, version, ERROR_MESSAGE_TOO_LONG);
            return Err(ERROR_MESSAGE_TOO_LONG);
        }

        let mut body_buf = vec![0u8; len as usize];
        if len > 0 {
            if ssl_stream.read_exact(&mut body_buf).is_err() {
                Self::send_error_response(ssl_stream, seq, version, ERROR_PROTOCOL);
                return Err(ERROR_PROTOCOL);
            }
        }

        let mut full_buf = Vec::with_capacity(HEADER_SIZE + len as usize);
        full_buf.extend_from_slice(&header_buf);
        full_buf.extend_from_slice(&body_buf);

        if VsockMessage::parse(&full_buf).is_err() {
            Self::send_error_response(ssl_stream, seq, version, ERROR_PROTOCOL);
            return Err(ERROR_PROTOCOL);
        }

        Ok(VsockMessage::parse(&full_buf).unwrap())
    }

    /// 处理消息并调用业务处理器
    ///
    /// 查找消息类型对应的处理器并执行，处理panic恢复
    ///
    /// # Arguments
    /// * `msg` - 待处理的消息
    /// * `handlers` - 消息处理器映射
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - 处理成功，返回响应数据
    /// * `Err(ERROR_HANDLER_PANIC)` - Handler panic
    /// * `Err(ERROR_PROTOCOL)` - 无处理器或Handler返回None
    #[cfg(target_os = "linux")]
    fn process_message(
        msg: &VsockMessage,
        handlers: &Arc<RwLock<HashMap<u32, Box<dyn DataHandler>>>>,
    ) -> Result<Vec<u8>, u32> {
        let handlers_guard = handlers.read().unwrap();
        match handlers_guard.get(&msg.header.msg_type) {
            Some(handler) => {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    handler.handle(&msg.data)
                }));

                match result {
                    Ok(Some(resp_data)) => Ok(resp_data),
                    Ok(None) => {
                        log::warn!("Handler returned None for msg_type {}", msg.header.msg_type);
                        Err(ERROR_PROTOCOL)
                    }
                    Err(_) => {
                        log::error!("Handler panic for msg_type {}", msg.header.msg_type);
                        Err(ERROR_HANDLER_PANIC)
                    }
                }
            }
            None => {
                log::warn!("No handler for msg_type {}", msg.header.msg_type);
                Err(ERROR_PROTOCOL)
            }
        }
    }

    /// 发送错误响应消息
    ///
    /// # Arguments
    /// * `ssl_stream` - TLS连接流
    /// * `seq` - 消息序列号
    /// * `version` - 协议版本
    /// * `error_type` - 错误类型码
    #[cfg(target_os = "linux")]
    fn send_error_response(
        ssl_stream: &mut openssl::ssl::SslStream<vsock::VsockStream>,
        seq: u32,
        version: u32,
        error_type: u32,
    ) {
        use std::io::Write;
        let err = Self::create_error_response(seq, version, error_type);
        ssl_stream.write_all(&err.serialize()).ok();
    }

    /// vsock监听循环（异步版本）
    ///
    /// 使用tokio::spawn运行，spawn_blocking包装阻塞的accept操作
    ///
    /// # Arguments
    /// * `listener` - vsock监听器
    /// * `handlers` - 消息处理器映射
    /// * `semaphore` - 并发连接限制信号量
    /// * `shutdown_signal` - 关闭信号
    /// * `ssl_acceptor` - TLS接收器
    #[cfg(target_os = "linux")]
    async fn listener_loop_async(
        listener: vsock::VsockListener,
        handlers: Arc<RwLock<HashMap<u32, Box<dyn DataHandler>>>>,
        semaphore: Arc<Semaphore>,
        shutdown_signal: Arc<AtomicBool>,
        ssl_acceptor: Arc<SslAcceptor>,
    ) {
        log::info!("vsock listener task started (backlog=128)");

        while !shutdown_signal.load(Ordering::SeqCst) {
            let listener_clone = listener.try_clone().ok();
            if listener_clone.is_none() {
                log::error!("Failed to clone listener");
                break;
            }

            let result = tokio::task::spawn_blocking(move || {
                listener_clone.unwrap().accept()
            }).await;

            match result {
                Ok(Ok((stream, addr))) => {
                    log::debug!("Accepted connection from {:?}", addr);
                    Self::spawn_connection_task(
                        stream,
                        handlers.clone(),
                        semaphore.clone(),
                        ssl_acceptor.clone(),
                    );
                }
                Ok(Err(e)) => {
                    log::error!("vsock accept error: {}", e);
                }
                Err(e) => {
                    log::error!("spawn_blocking panic: {}", e);
                }
            }
        }

        log::info!("vsock listener task stopped");
    }

    /// 启动连接处理任务（异步版本）
    ///
    /// 使用tokio::spawn创建异步任务，spawn_blocking包装阻塞的TLS握手和消息处理
    ///
    /// # Arguments
    /// * `stream` - vsock连接流
    /// * `handlers` - 消息处理器映射
    /// * `semaphore` - 并发连接限制信号量
    /// * `ssl_acceptor` - TLS接收器
    #[cfg(target_os = "linux")]
    fn spawn_connection_task(
        stream: vsock::VsockStream,
        handlers: Arc<RwLock<HashMap<u32, Box<dyn DataHandler>>>>,
        semaphore: Arc<Semaphore>,
        ssl_acceptor: Arc<SslAcceptor>,
    ) {
        tokio::spawn(async move {
            let _permit = semaphore.acquire().await.ok();
            if _permit.is_none() {
                log::warn!("Failed to acquire semaphore permit");
                return;
            }

            log::debug!("Semaphore permit acquired, starting TLS handshake");

            let handlers_clone = handlers.clone();
            let result = tokio::task::spawn_blocking(move || {
                ssl_acceptor.accept(stream)
            }).await;

            match result {
                Ok(Ok(ssl_stream)) => {
                    log::debug!("TLS handshake successful");
                    tokio::task::spawn_blocking(move || {
                        Self::handle_connection_blocking(ssl_stream, handlers_clone);
                    }).await.ok();
                }
                Ok(Err(e)) => {
                    log::warn!("TLS handshake failed: {}", e);
                }
                Err(e) => {
                    log::warn!("spawn_blocking error during TLS handshake: {}", e);
                }
            }

            log::debug!("Connection task completed, semaphore permit released");
        });
    }

    /// 创建错误响应消息
    ///
    /// # Arguments
    /// * `seq` - 消息序列号（与请求相同）
    /// * `version` - 协议版本
    /// * `error_type` - 错误类型（ERROR_HANDLER_PANIC / ERROR_PROTOCOL / ERROR_MESSAGE_TOO_LONG）
    ///
    /// # Returns
    /// 错误响应消息（data为空，len为0）
    pub fn create_error_response(seq: u32, version: u32, error_type: u32) -> VsockMessage {
        VsockMessage::new(seq, version, error_type, vec![])
    }
}

#[async_trait]
impl TransportLayer for VsockTransport {
    /// 注册消息处理器
    ///
    /// 架构决策：TransportLayer抽象解耦通信层与插件框架层（ADR-0005）
    /// - Transport职责：协议层（报文解析、校验、错误响应）
    /// - DataHandler职责：业务层（JSON解析、签名验签）
    ///
    /// 插件在init()中通过ctx.register_handler()注册处理器
    ///
    /// **重复注册行为**：同一 msg_type 重复注册时，后注册覆盖先注册，并输出警告日志。
    /// 设计依据：docs/detailed-design/05-communication.md 第290行
    ///
    /// # Arguments
    /// * `msg_type` - 消息类型（如0x10签名请求、0x12验签+签名请求、0x14验签请求）
    /// * `handler` - 业务处理器（实现DataHandler trait）
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

    /// 启动vsock监听（仅Linux平台）
    ///
    /// 架构决策：
    /// - 使用tokio::spawn启动异步监听任务
    /// - spawn_blocking包装阻塞的accept操作
    /// - 并发连接限制（信号量机制，最多MAX_CONCURRENT_CONNECTIONS个并发连接）
    /// - TLS握手失败不中断服务（记录警告日志）
    ///
    /// 并发控制：
    /// - 使用Semaphore限制并发连接数为MAX_CONCURRENT_CONNECTIONS
    /// - 每个连接异步任务处理（spawn_blocking包装阻塞操作）
    /// - backlog=128（由vsock crate v0.4.0内部设置）
    ///
    /// # Returns
    /// * `Ok(())` - 监听任务已启动
    /// * `Err(TransportError::StartFailed)` - vsock绑定失败
    #[cfg(target_os = "linux")]
    async fn start(&self) -> Result<(), TransportError> {
        use vsock::VsockListener;

        let cid: u32 = 0xFFFFFFFF;
        let addr = vsock::VsockAddr::new(cid, self.port);

        let listener = VsockListener::bind(&addr)
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;

        log::info!("vsock listener bound on cid=ANY, port={} (backlog=128)", self.port);

        self.shutdown_signal.store(false, Ordering::SeqCst);

        let handlers = self.handlers.clone();
        let semaphore = self.semaphore.clone();
        let shutdown_signal = self.shutdown_signal.clone();
        let ssl_acceptor = self.ssl_acceptor.clone();

        let task_handle = tokio::spawn(Self::listener_loop_async(
            listener,
            handlers,
            semaphore,
            shutdown_signal,
            ssl_acceptor,
        ));

        *self.listener_handle.lock().unwrap() = Some(task_handle);

        Ok(())
    }

    /// 非Linux平台空实现
    #[cfg(not(target_os = "linux"))]
    async fn start(&self) -> Result<(), TransportError> {
        Ok(())
    }

    /// 优雅关闭vsock监听（仅Linux平台）
    ///
    /// 关闭流程：
    /// 1. 设置shutdown_signal=true，通知监听任务停止接收新连接
    /// 2. 等待监听任务退出（超时5秒）
    /// 3. 超时后记录警告，不强制中断
    ///
    /// 优雅关闭保证：
    /// - 已建立的连接继续处理完毕
    /// - 不中断正在处理的请求
    #[cfg(target_os = "linux")]
    async fn stop(&self) {
        use std::time::Duration;

        // 设置关闭信号
        self.shutdown_signal.store(true, Ordering::SeqCst);
        log::info!("vsock shutdown signal sent");

        // 等待监听任务退出
        let handle = self.listener_handle.lock().unwrap().take();

        if let Some(handle) = handle {
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                handle
            ).await;

            match result {
                Ok(Ok(_)) => log::info!("vsock listener task stopped gracefully"),
                Ok(Err(e)) => log::warn!("vsock listener task error: {}", e),
                Err(_) => log::warn!("vsock shutdown timeout (5s), listener task may still running"),
            }
        }
    }

    /// 非Linux平台空实现
    #[cfg(not(target_os = "linux"))]
    async fn stop(&self) {
        log::info!("vsock shutdown (non-linux platform)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::extension::{BasicConstraints, SubjectKeyIdentifier};
    use openssl::x509::{X509Builder, X509NameBuilder};
    use std::fs;

    /// 创建测试用CA证书、服务器证书和私钥
    ///
    /// 使用ECC-256曲线生成自签名CA证书和服务器证书
    /// 用于单元测试，不用于生产环境
    fn create_test_cert_and_key() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let (ca_cert, ca_pkey) = create_test_ca_cert();
        let (server_cert, server_pkey) = create_test_server_cert(&ca_cert, &ca_pkey);

        (
            ca_cert.to_pem().unwrap(),
            server_cert.to_pem().unwrap(),
            server_pkey.private_key_to_pem_pkcs8().unwrap(),
        )
    }

    /// 创建测试用CA证书
    ///
    /// 生成自签名CA证书和私钥，用于签发服务器证书
    fn create_test_ca_cert() -> (openssl::x509::X509, PKey<openssl::pkey::Private>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ca_key = EcKey::generate(&group).unwrap();
        let ca_pkey = PKey::from_ec_key(ca_key.clone()).unwrap();

        let mut ca_name = X509NameBuilder::new().unwrap();
        ca_name.append_entry_by_text("CN", "Test CA").unwrap();
        let ca_name = ca_name.build();

        let mut ca_builder = X509Builder::new().unwrap();
        ca_builder.set_version(2).unwrap();
        ca_builder.set_subject_name(&ca_name).unwrap();
        ca_builder.set_issuer_name(&ca_name).unwrap();
        ca_builder.set_pubkey(&ca_pkey).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(3650).unwrap();
        ca_builder.set_not_before(&not_before).unwrap();
        ca_builder.set_not_after(&not_after).unwrap();

        let serial = BigNum::from_u32(1).unwrap();
        ca_builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();

        let bc = BasicConstraints::new().critical().ca().build().unwrap();
        ca_builder.append_extension(bc).unwrap();

        let context = ca_builder.x509v3_context(None, None);
        let ski = SubjectKeyIdentifier::new().build(&context).unwrap();
        ca_builder.append_extension(ski).unwrap();

        ca_builder.sign(&ca_pkey, MessageDigest::sha256()).unwrap();
        let ca_cert = ca_builder.build();

        (ca_cert, ca_pkey)
    }

    /// 创建测试用服务器证书
    ///
    /// 使用CA证书签发服务器证书
    fn create_test_server_cert(ca_cert: &openssl::x509::X509, ca_pkey: &PKey<openssl::pkey::Private>) -> (openssl::x509::X509, PKey<openssl::pkey::Private>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let server_key = EcKey::generate(&group).unwrap();
        let server_pkey = PKey::from_ec_key(server_key.clone()).unwrap();

        let mut server_name = X509NameBuilder::new().unwrap();
        server_name
            .append_entry_by_text("CN", "Test Server")
            .unwrap();
        let server_name = server_name.build();

        let mut server_builder = X509Builder::new().unwrap();
        server_builder.set_version(2).unwrap();
        server_builder.set_subject_name(&server_name).unwrap();
        server_builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        server_builder.set_pubkey(&server_pkey).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(3650).unwrap();
        server_builder.set_not_before(&not_before).unwrap();
        server_builder.set_not_after(&not_after).unwrap();

        let serial2 = BigNum::from_u32(2).unwrap();
        server_builder
            .set_serial_number(&serial2.to_asn1_integer().unwrap())
            .unwrap();

        let context2 = server_builder.x509v3_context(Some(ca_cert), None);
        let ski2 = SubjectKeyIdentifier::new().build(&context2).unwrap();
        server_builder.append_extension(ski2).unwrap();

        server_builder
            .sign(ca_pkey, MessageDigest::sha256())
            .unwrap();
        let server_cert = server_builder.build();

        (server_cert, server_pkey)
    }

    /// 模拟业务处理器
    ///
    /// 实现DataHandler trait，用于测试处理器注册机制
    struct MockHandler;

    impl DataHandler for MockHandler {
        fn handle(&self, data: &[u8]) -> Option<Vec<u8>> {
            Some(data.to_vec())
        }
    }

    /// 测试VsockTransport创建
    ///
    /// 场景：使用有效的TLS配置创建VsockTransport实例
    /// 预期：创建成功，无错误
    #[test]
    fn vsock_transport_can_be_created() {
        let temp_dir = std::env::temp_dir().join("vsock_transport_test");
        fs::create_dir_all(&temp_dir).unwrap();

        let (ca_pem, server_pem, server_key_pem) = create_test_cert_and_key();
        let ca_path = temp_dir.join("ca.crt");
        let server_path = temp_dir.join("server.crt");
        let server_key_path = temp_dir.join("server.key");

        fs::write(&ca_path, &ca_pem).unwrap();
        fs::write(&server_path, &server_pem).unwrap();
        fs::write(&server_key_path, &server_key_pem).unwrap();

        let config = TlsConfig {
            cert_path: server_path.to_str().unwrap().to_string(),
            key_path: server_key_path.to_str().unwrap().to_string(),
            key_password: None,
            ca_cert_path: ca_path.to_str().unwrap().to_string(),
            crl_path: None,
        };

        let transport = VsockTransport::new(&config, 12345, MAX_CONCURRENT_CONNECTIONS as u32);
        assert!(transport.is_ok());

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    /// 测试处理器注册机制
    ///
    /// 场景：注册多个消息处理器
    /// 预期：处理器映射包含所有注册的处理器
    #[test]
    fn vsock_transport_registers_handlers() {
        let temp_dir = std::env::temp_dir().join("vsock_handler_test");
        fs::create_dir_all(&temp_dir).unwrap();

        let (ca_pem, server_pem, server_key_pem) = create_test_cert_and_key();
        let ca_path = temp_dir.join("ca.crt");
        let server_path = temp_dir.join("server.crt");
        let server_key_path = temp_dir.join("server.key");

        fs::write(&ca_path, &ca_pem).unwrap();
        fs::write(&server_path, &server_pem).unwrap();
        fs::write(&server_key_path, &server_key_pem).unwrap();

        let config = TlsConfig {
            cert_path: server_path.to_str().unwrap().to_string(),
            key_path: server_key_path.to_str().unwrap().to_string(),
            key_password: None,
            ca_cert_path: ca_path.to_str().unwrap().to_string(),
            crl_path: None,
        };

        let transport = VsockTransport::new(&config, 12345, MAX_CONCURRENT_CONNECTIONS as u32).unwrap();
        transport.register_handler(0x10, Box::new(MockHandler));
        transport.register_handler(0x12, Box::new(MockHandler));

        let handlers = transport.handlers.read().unwrap();
        assert_eq!(handlers.len(), 2);
        assert!(handlers.contains_key(&0x10));
        assert!(handlers.contains_key(&0x12));

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    /// 测试处理器注册覆盖行为
    ///
    /// 场景：同一消息类型注册两次
    /// 预期：第二次注册覆盖第一次，handlers数量仍为1
    /// 设计依据：docs/detailed-design/05-communication.md 第290行
    #[test]
    fn vsock_transport_handler_registration_overwrites() {
        let temp_dir = std::env::temp_dir().join("vsock_overwrite_test");
        fs::create_dir_all(&temp_dir).unwrap();

        let (ca_pem, server_pem, server_key_pem) = create_test_cert_and_key();
        let ca_path = temp_dir.join("ca.crt");
        let server_path = temp_dir.join("server.crt");
        let server_key_path = temp_dir.join("server.key");

        fs::write(&ca_path, &ca_pem).unwrap();
        fs::write(&server_path, &server_pem).unwrap();
        fs::write(&server_key_path, &server_key_pem).unwrap();

        let config = TlsConfig {
            cert_path: server_path.to_str().unwrap().to_string(),
            key_path: server_key_path.to_str().unwrap().to_string(),
            key_password: None,
            ca_cert_path: ca_path.to_str().unwrap().to_string(),
            crl_path: None,
        };

        let transport = VsockTransport::new(&config, 12345, MAX_CONCURRENT_CONNECTIONS as u32).unwrap();

        transport.register_handler(0x10, Box::new(MockHandler));
        transport.register_handler(0x10, Box::new(MockHandler));

        let handlers = transport.handlers.read().unwrap();
        assert_eq!(handlers.len(), 1);
        assert!(handlers.contains_key(&0x10));

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    /// 测试vsock监听启动（Linux平台）
    ///
    /// 场景：启动vsock监听
    /// 预期：start()返回Ok(())
    ///
    /// 注意：此测试需要vsock环境支持，默认忽略
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires vsock environment"]
    async fn vsock_transport_start_returns_ok() {
        let temp_dir = std::env::temp_dir().join("vsock_start_test");
        fs::create_dir_all(&temp_dir).unwrap();

        let (ca_pem, server_pem, server_key_pem) = create_test_cert_and_key();
        let ca_path = temp_dir.join("ca.crt");
        let server_path = temp_dir.join("server.crt");
        let server_key_path = temp_dir.join("server.key");

        fs::write(&ca_path, &ca_pem).unwrap();
        fs::write(&server_path, &server_pem).unwrap();
        fs::write(&server_key_path, &server_key_pem).unwrap();

        let config = TlsConfig {
            cert_path: server_path.to_str().unwrap().to_string(),
            key_path: server_key_path.to_str().unwrap().to_string(),
            key_password: None,
            ca_cert_path: ca_path.to_str().unwrap().to_string(),
            crl_path: None,
        };

        let transport = VsockTransport::new(&config, 12345, MAX_CONCURRENT_CONNECTIONS as u32).unwrap();
        let result = transport.start().await;
        assert!(result.is_ok());

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    /// 测试错误响应消息构造
    ///
    /// 场景：构造错误响应消息
    /// 预期：消息字段正确，data为空，len为0
    #[test]
    fn create_error_response_has_zero_len() {
        let resp = VsockTransport::create_error_response(123, PROTOCOL_VERSION, ERROR_PROTOCOL);
        assert_eq!(resp.header.seq, 123);
        assert_eq!(resp.header.version, PROTOCOL_VERSION);
        assert_eq!(resp.header.msg_type, ERROR_PROTOCOL);
        assert_eq!(resp.header.len, 0);
        assert!(resp.data.is_empty());
    }
}
