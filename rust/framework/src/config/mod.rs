//! 应用配置模块
//!
//! 职责：
//! - 定义应用配置结构（vsock、日志、证书等）
//! - 提供TOML配置文件加载和解析功能
//! - 管理配置项默认值
//!
//! 配置文件格式：
//! - 使用TOML格式
//! - 默认路径：/etc/trustruntime/agent.toml（参见ADR-0006）
//! - 必需字段：vsock.port、log.path、certificate.*
//! - 可选字段：vsock.max_connections（默认16）、log.level（默认info）、cert_check.interval_hours（默认24）
//!
//! 与其他模块的关系：
//! - 被 vsock_server 模块调用以获取vsock配置
//! - 被 main.rs 调用以加载应用配置
//! - 证书配置传递给 cert_loader 模块加载证书

use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

use log::LevelFilter;

/// 配置加载错误类型
#[derive(Error, Debug)]
pub enum ConfigError {
    /// TOML解析错误
    ///
    /// 场景：配置文件格式错误、字段类型不匹配、缺少必需字段
    #[error("parse error: {0}")]
    ParseError(String),

    /// 文件I/O错误
    ///
    /// 场景：配置文件不存在、无读取权限
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    /// 配置验证错误
    ///
    /// 场景：字段值超出有效范围（如零值、超限值）
    #[error("validation error: {0}")]
    ValidationError(String),
}

/// 应用配置根结构
///
/// 包含应用运行所需的全部配置项：
/// - vsock：vsock通信配置
/// - log：日志配置
/// - certificate：证书配置（CMS签名证书、TLS通信证书）
/// - cert_check：证书检查配置
#[derive(Debug, Deserialize, PartialEq)]
pub struct AppConfig {
    /// vsock通信配置
    pub vsock: VsockConfig,

    /// 日志配置
    pub log: LogConfig,

    /// 证书配置（包含CMS签名证书和TLS通信证书）
    pub certificate: CertificateConfig,

    /// 证书检查配置（可选，默认每24小时检查一次）
    #[serde(default)]
    pub cert_check: CertCheckConfig,
}

/// vsock通信配置
///
/// vsock是虚拟机与宿主机之间的通信机制，用于机密VM与宿主机的安全通信。
#[derive(Debug, Deserialize, PartialEq)]
pub struct VsockConfig {
    /// vsock端口号
    ///
    /// 机密VM监听的vsock端口，宿主机通过此端口与VM通信
    pub port: u32,

    /// 最大并发连接数（默认16）
    ///
    /// 限制同时处理的vsock连接数量，防止资源耗尽
    /// 默认值：16（参见 default_max_connections）
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

/// 默认最大连接数：16
fn default_max_connections() -> u32 {
    16
}

impl VsockConfig {
    /// 验证vsock配置参数有效性
    ///
    /// # 验证规则
    /// - `port` 不能为0（0是保留端口）
    /// - `max_connections` 必须在1-1024范围内
    ///
    /// # Returns
    /// - `Ok(())` - 验证通过
    /// - `Err(ConfigError::ValidationError)` - 参数超出有效范围
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::ValidationError(
                "vsock.port must not be 0".into()
            ));
        }
        if self.max_connections == 0 || self.max_connections > 1024 {
            return Err(ConfigError::ValidationError(
                format!("vsock.max_connections must be 1-1024, got {}", self.max_connections)
            ));
        }
        Ok(())
    }
}

/// 日志级别枚举
///
/// 定义支持的日志级别，使用强类型避免无效输入。
/// 配置文件中使用小写字符串表示（如 `"trace"`, `"info"`）。
#[derive(Debug, Deserialize, PartialEq, Clone, Copy, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    #[default]
    Info,
    Trace,
    Debug,
    Warn,
    Error,
}

impl LogLevel {
    pub fn to_level_filter(self) -> LevelFilter {
        match self {
            LogLevel::Trace => LevelFilter::Trace,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Error => LevelFilter::Error,
        }
    }
}

/// 日志配置
///
/// 使用log4rs实现日志滚动，限制日志文件大小和数量。
/// 日志文件路径通常为 /var/log/trustruntime/trustring.log（参见ADR-0006）
#[derive(Debug, Deserialize, PartialEq)]
pub struct LogConfig {
    /// 日志文件路径
    ///
    /// 例如：/var/log/trustruntime/trustring.log
    pub path: String,

    /// 日志级别（默认info）
    ///
    /// 可选值：trace、debug、info、warn、error
    /// 使用强类型枚举，配置文件中用小写字符串表示（如 `"trace"`）
    #[serde(default)]
    pub level: LogLevel,

    /// 单个日志文件最大大小（MB）
    ///
    /// 超过此大小后滚动创建新文件
    pub max_file_size: u64,

    /// 最大滚动日志文件数量
    ///
    /// 超过此数量后删除最旧的日志文件
    pub max_roll_count: u32,
}

impl LogConfig {
    /// 验证日志配置参数有效性
    ///
    /// # 验证规则
    /// - `max_file_size` 必须在1-100 MB范围内
    /// - `max_roll_count` 必须在1-100范围内
    ///
    /// # Returns
    /// - `Ok(())` - 验证通过
    /// - `Err(ConfigError::ValidationError)` - 参数超出有效范围
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_file_size == 0 || self.max_file_size > 100 {
            return Err(ConfigError::ValidationError(
                format!("log.max_file_size must be 1-100 MB, got {}", self.max_file_size)
            ));
        }
        if self.max_roll_count == 0 || self.max_roll_count > 100 {
            return Err(ConfigError::ValidationError(
                format!("log.max_roll_count must be 1-100, got {}", self.max_roll_count)
            ));
        }
        Ok(())
    }
}

/// 证书配置
///
/// 包含CMS签名证书和TLS通信证书两类证书：
///
/// 1. CMS签名证书（用于CMS签名验签）：
///    - signer_cert: CMS签名证书
///    - signer_key: CMS签名私钥
///    - ca_root_cert: CMS CA根证书
///    - cms_crl: CMS CRL吊销列表（可选）
///
/// 2. TLS通信证书（用于vsock TLS通信）：
///    - comm_cert: TLS通信证书
///    - comm_key: TLS通信私钥
///    - comm_key_pwd: TLS私钥密码文件路径（可选）
///    - comm_ca_root: TLS CA根证书
///    - comm_crl: TLS CRL吊销列表（可选）
///
/// 架构决策：统一使用OpenSSL处理TLS和CMS证书
/// 详见 ADR-0004: Unified OpenSSL for TLS and CMS
#[derive(Debug, Deserialize, PartialEq)]
pub struct CertificateConfig {
    /// CMS签名证书路径
    pub signer_cert: String,

    /// CMS签名私钥路径
    pub signer_key: String,

    /// CMS CA根证书路径
    pub ca_root_cert: String,

    /// CMS CRL吊销列表路径（可选）
    ///
    /// 用于验证签名方证书是否被吊销
    pub cms_crl: Option<String>,

    /// TLS通信证书路径
    pub comm_cert: String,

    /// TLS通信私钥路径
    pub comm_key: String,

    /// TLS私钥密码文件路径（可选）
    ///
    /// 如果私钥加密，从此文件读取密码
    pub comm_key_pwd: Option<String>,

    /// TLS CA根证书路径
    pub comm_ca_root: String,

    /// TLS CRL吊销列表路径（可选）
    pub comm_crl: Option<String>,
}

/// 证书检查配置
///
/// 定期检查证书有效性的配置项。
/// 检查内容包括证书过期时间、CRL状态等。
#[derive(Debug, Deserialize, PartialEq)]
pub struct CertCheckConfig {
    /// 证书检查间隔时间（小时，默认24）
    ///
    /// 每 interval_hours 小时检查一次证书状态
    /// 默认值：24小时（参见 default_interval_hours）
    #[serde(default = "default_interval_hours")]
    pub interval_hours: u64,
}

impl Default for CertCheckConfig {
    fn default() -> Self {
        Self {
            interval_hours: default_interval_hours(),
        }
    }
}

impl CertCheckConfig {
    /// 验证证书检查配置参数有效性
    ///
    /// # 验证规则
    /// - `interval_hours` 必须在1-720小时范围内（最长30天）
    ///
    /// # Returns
    /// - `Ok(())` - 验证通过
    /// - `Err(ConfigError::ValidationError)` - 参数超出有效范围
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.interval_hours == 0 || self.interval_hours > 720 {
            return Err(ConfigError::ValidationError(
                format!("cert_check.interval_hours must be 1-720 hours, got {}", self.interval_hours)
            ));
        }
        Ok(())
    }
}

/// 默认证书检查间隔：24小时
fn default_interval_hours() -> u64 {
    24
}

impl AppConfig {
    /// 从TOML字符串解析配置
    ///
    /// # Arguments
    /// * `content` - TOML格式的配置字符串
    ///
    /// # Returns
    /// * `Ok(AppConfig)` - 解析成功，返回配置对象
    /// * `Err(ConfigError::ParseError)` - TOML格式错误或字段类型不匹配
    ///
    /// # Example
    /// ```text
    /// let toml = r#"
    /// [vsock]
    /// port = 12345
    /// ...
    /// "#;
    /// let config = AppConfig::from_toml(toml)?;
    /// ```
    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// 从文件加载配置
    ///
    /// 读取指定路径的TOML配置文件并解析。
    ///
    /// # Arguments
    /// * `path` - 配置文件路径（如 /etc/trustruntime/agent.toml）
    ///
    /// # Returns
    /// * `Ok(AppConfig)` - 加载成功，返回配置对象
    /// * `Err(ConfigError::IoError)` - 文件不存在或读取失败
    /// * `Err(ConfigError::ParseError)` - TOML解析失败
    ///
    /// # Example
    /// ```text
    /// let config = AppConfig::from_file("/etc/trustruntime/agent.toml")?;
    /// ```
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(Path::new(path))?;
        Self::from_toml(&content)
    }

    /// 验证应用配置参数有效性
    ///
    /// 遍历验证所有子配置（vsock、log、cert_check），
    /// 任一子配置验证失败则返回错误。
    ///
    /// # Returns
    /// - `Ok(())` - 所有配置验证通过
    /// - `Err(ConfigError::ValidationError)` - 任一配置项超出有效范围
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.vsock.validate()?;
        self.log.validate()?;
        self.cert_check.validate()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT_CONFIG: &str = r#"
[certificate]
signer_cert = "/etc/cert/cms/signer.crt"
signer_key = "/etc/cert/cms/signer.key"
ca_root_cert = "/etc/cert/cms/ca_root.crt"
comm_cert = "/etc/cert/cms/communication/certificate.crt"
comm_key = "/etc/cert/cms/communication/private.key"
comm_ca_root = "/etc/cert/cms/communication/ca_root.crt"
"#;

    fn make_test_config(port: u32, max_conn: u32, level: &str, max_file: u64, max_roll: u32, interval: u64) -> String {
        format!(r#"
[vsock]
port = {}
max_connections = {}

[log]
path = "/var/log/test.log"
level = "{}"
max_file_size = {}
max_roll_count = {}
{}
[cert_check]
interval_hours = {}
"#, port, max_conn, level, max_file, max_roll, CERT_CONFIG, interval)
    }

    #[test]
    fn parsing_valid_toml_returns_correct_app_config() {
        let toml = make_test_config(12345, 16, "info", 10, 10, 24);
        let config = AppConfig::from_toml(&toml).unwrap();
        assert_eq!(config.vsock.port, 12345);
        assert_eq!(config.vsock.max_connections, 16);
        assert_eq!(config.log.level, LogLevel::Info);
        assert_eq!(config.log.max_file_size, 10);
        assert_eq!(config.log.max_roll_count, 10);
        assert_eq!(config.cert_check.interval_hours, 24);
    }

    #[test]
    fn parsing_minimal_toml_uses_default_values() {
        let toml = format!(r#"
[vsock]
port = 12345

[log]
path = "/var/log/test.log"
max_file_size = 10
max_roll_count = 10
{}
"#, CERT_CONFIG);
        let config = AppConfig::from_toml(&toml).unwrap();
        assert_eq!(config.vsock.max_connections, 16);
        assert_eq!(config.log.level, LogLevel::Info);
        assert_eq!(config.cert_check.interval_hours, 24);
    }

    #[test]
    fn parsing_toml_with_missing_required_field_returns_error() {
        let incomplete = r#"
[vsock]
port = 12345

[log]
path = "/var/log/test.log"
max_file_size = 10
max_roll_count = 10
"#;
        assert!(AppConfig::from_toml(incomplete).is_err());
    }

    #[test]
    fn loading_config_from_file_path_works() {
        let toml = make_test_config(12345, 16, "info", 10, 10, 24);
        let dir = std::env::temp_dir().join("trustruntime_config_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent.toml");
        std::fs::write(&path, &toml).unwrap();
        let config = AppConfig::from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(config.vsock.port, 12345);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn valid_config_passes_validation() {
        let toml = make_test_config(12345, 16, "info", 10, 10, 24);
        let config = AppConfig::from_toml(&toml).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validation_rejects_zero_values() {
        let cases = [
            ("port=0", make_test_config(0, 16, "info", 10, 10, 24)),
            ("max_conn=0", make_test_config(12345, 0, "info", 10, 10, 24)),
            ("max_file=0", make_test_config(12345, 16, "info", 0, 10, 24)),
            ("max_roll=0", make_test_config(12345, 16, "info", 10, 0, 24)),
            ("interval=0", make_test_config(12345, 16, "info", 10, 10, 0)),
        ];
        for (name, toml) in cases {
            let config = AppConfig::from_toml(&toml).unwrap();
            assert!(config.validate().is_err(), "{} should fail validation", name);
        }
    }

    #[test]
    fn validation_rejects_exceeded_limits() {
        let cases = [
            ("max_conn>1024", make_test_config(12345, 1025, "info", 10, 10, 24)),
            ("max_file>100", make_test_config(12345, 16, "info", 101, 10, 24)),
            ("max_roll>100", make_test_config(12345, 16, "info", 10, 101, 24)),
            ("interval>720", make_test_config(12345, 16, "info", 10, 10, 721)),
        ];
        for (name, toml) in cases {
            let config = AppConfig::from_toml(&toml).unwrap();
            assert!(config.validate().is_err(), "{} should fail validation", name);
        }
    }

    #[test]
    fn validation_accepts_boundary_values() {
        let cases = [
            ("min values", make_test_config(1, 1, "info", 1, 1, 1)),
            ("max values", make_test_config(12345, 1024, "info", 100, 100, 720)),
        ];
        for (name, toml) in cases {
            let config = AppConfig::from_toml(&toml).unwrap();
            assert!(config.validate().is_ok(), "{} should pass validation", name);
        }
    }

    #[test]
    fn all_log_levels_accepted() {
        for level in ["trace", "debug", "info", "warn", "error"] {
            let toml = make_test_config(12345, 16, level, 10, 10, 24);
            let config = AppConfig::from_toml(&toml).unwrap();
            assert!(config.validate().is_ok(), "level={} should be valid", level);
        }
    }

    #[test]
    fn invalid_log_level_parse_fails() {
        let toml = make_test_config(12345, 16, "foobar", 10, 10, 24);
        assert!(AppConfig::from_toml(&toml).is_err());
    }
}
