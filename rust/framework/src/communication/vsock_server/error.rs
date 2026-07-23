//! 错误类型和常量定义

/// 通用错误响应码定义（根据 interface.md 第5节）
pub const ERROR_HANDLER_PANIC: u32 = 0x00; // 服务端内部异常（插件崩溃、证书加载失败等）
pub const ERROR_PROTOCOL: u32 = 0x01; // 报文格式异常（版本不匹配、消息解析失败、无处理器等）
pub const ERROR_MESSAGE_TOO_LONG: u32 = 0x02; // 请求报文过长（超过10KB）
pub const ERROR_CONNECTION_CLOSED: u32 = 0xFF; // 连接关闭（内部错误码，不发送给客户端）

/// 协议层配置常量
pub const PROTOCOL_VERSION: u32 = 0xFFFF0400; // 协议版本号（interface.md 第2.2节）
pub const MAX_MESSAGE_SIZE: u32 = 10240; // 最大消息长度（10KB，interface.md 第2.1节）
#[cfg(test)]
pub const MAX_CONCURRENT_CONNECTIONS: usize = 16; // 最大并发连接数（AGENTS.md 第63节）
pub const HEADER_SIZE: usize = 16; // 消息头长度（seq + version + msg_type + len）

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
