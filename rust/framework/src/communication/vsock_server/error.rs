//! 错误类型和常量定义

/// 通用错误响应码定义（根据 interface.md 第5节）
pub const ERROR_HANDLER_PANIC: u32 = 0x00;
pub const ERROR_PROTOCOL: u32 = 0x01;
pub const ERROR_MESSAGE_TOO_LONG: u32 = 0x02;
pub const ERROR_CONNECTION_CLOSED: u32 = 0xFF;

/// 协议层配置常量
pub const PROTOCOL_VERSION: u32 = 0xFFFF0400;
pub const MAX_MESSAGE_SIZE: u32 = 10240;
#[cfg(test)]
pub const MAX_CONCURRENT_CONNECTIONS: usize = 16;
pub const HEADER_SIZE: usize = 16;

#[derive(Debug)]
pub enum VsockError {
    TlsConfigError(String),
    IoError(std::io::Error),
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
