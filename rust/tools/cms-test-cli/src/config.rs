//! 配置管理模块
//!
//! 管理 CMS 测试工具的运行时配置，通过 TOML 配置文件加载。
//! 支持配置验证，确保所有必需的证书文件存在。
//!
//! ## 配置文件格式
//!
//! ```toml
//! [connection]
//! port = 12345
//!
//! [tls_client]
//! ca_cert = "/path/to/tls/ca.crt"
//! client_cert = "/path/to/tls/client/client.crt"
//! client_key = "/path/to/tls/client/client.key"
//! client_key_pwd = "/path/to/tls/key_pwd.txt"  # 可选
//!
//! [cms_certs]
//! ca_cert = "/path/to/cms/ca.crt"
//! signer_cert = "/path/to/cms/node-a/signer.crt"
//! signer_key = "/path/to/cms/node-a/signer.key"
//! expired_cert = "/path/to/cms/expired/signer.crt"  # 可选
//! expired_key = "/path/to/cms/expired/signer.key"   # 可选
//! revoked_cert = "/path/to/cms/revoked/signer.crt"  # 可选
//! revoked_key = "/path/to/cms/revoked/signer.key"   # 可选
//!
//! [server]
//! binary_path = "trustruntime"
//! ```

use serde::Deserialize;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// 配置加载错误类型
#[derive(Error, Debug)]
pub enum ConfigError {
    /// 文件 I/O 错误
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// TOML 解析错误
    #[error("parse error: {0}")]
    Parse(String),

    /// 配置验证错误
    #[error("validation error: {0}")]
    Validation(String),
}

/// CMS 测试工具配置
#[derive(Debug, Deserialize)]
pub struct CmsTestConfig {
    /// 连接配置
    pub connection: ConnectionConfig,

    /// TLS 客户端证书配置
    pub tls_client: TlsClientConfig,

    /// CMS 证书配置
    pub cms_certs: CmsCertsConfig,

    /// 服务器配置
    #[serde(default)]
    pub server: ServerConfig,

    /// 命令历史（运行时使用）
    #[serde(default)]
    pub history: Vec<String>,
}

/// 连接配置
#[derive(Debug, Deserialize)]
pub struct ConnectionConfig {
    /// vsock 端口号
    pub port: u32,
}

/// TLS 客户端证书配置
#[derive(Debug, Deserialize, Clone)]
pub struct TlsClientConfig {
    /// CA 证书路径，用于验证服务端证书
    pub ca_cert: PathBuf,

    /// 客户端证书路径
    pub client_cert: PathBuf,

    /// 客户端私钥路径
    pub client_key: PathBuf,

    /// 私钥密码文件路径（可选）
    pub client_key_pwd: Option<PathBuf>,
}

/// CMS 证书配置
#[derive(Debug, Deserialize, Clone)]
pub struct CmsCertsConfig {
    /// CA 根证书路径，用于验签测试
    pub ca_cert: PathBuf,

    /// 签名者证书路径
    pub signer_cert: PathBuf,

    /// 签名者私钥路径
    pub signer_key: PathBuf,

    /// 过期证书路径（可选，用于安全测试）
    pub expired_cert: Option<PathBuf>,

    /// 过期私钥路径（可选）
    pub expired_key: Option<PathBuf>,

    /// 已吊销证书路径（可选，用于安全测试）
    pub revoked_cert: Option<PathBuf>,

    /// 已吊销私钥路径（可选）
    pub revoked_key: Option<PathBuf>,
}

/// 服务器配置
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// trustruntime 二进制路径
    #[serde(default = "default_binary_path")]
    pub binary_path: PathBuf,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            binary_path: default_binary_path(),
        }
    }
}

fn default_binary_path() -> PathBuf {
    PathBuf::from("trustruntime")
}

impl CmsTestConfig {
    /// 从文件加载配置
    ///
    /// # 参数
    /// - `path`: 配置文件路径
    ///
    /// # 返回
    /// - `Ok(CmsTestConfig)`: 加载并验证成功
    /// - `Err(ConfigError)`: 加载或验证失败
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(Path::new(path))?;
        let config: Self =
            toml::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// 验证配置有效性
    ///
    /// 检查：
    /// - 端口号范围
    /// - 所有必需证书文件是否存在
    pub fn validate(&self) -> Result<(), ConfigError> {
        // 端口范围验证
        if self.connection.port == 0 || self.connection.port > 65535 {
            return Err(ConfigError::Validation(format!(
                "connection.port must be 1-65535, got {}",
                self.connection.port
            )));
        }

        // TLS 证书文件存在性验证
        Self::validate_path_exists(&self.tls_client.ca_cert, "tls_client.ca_cert")?;
        Self::validate_path_exists(&self.tls_client.client_cert, "tls_client.client_cert")?;
        Self::validate_path_exists(&self.tls_client.client_key, "tls_client.client_key")?;

        // 私钥密码文件（可选）
        if let Some(ref pwd_path) = self.tls_client.client_key_pwd {
            Self::validate_path_exists(pwd_path, "tls_client.client_key_pwd")?;
        }

        // CMS 证书文件存在性验证
        Self::validate_path_exists(&self.cms_certs.ca_cert, "cms_certs.ca_cert")?;
        Self::validate_path_exists(&self.cms_certs.signer_cert, "cms_certs.signer_cert")?;
        Self::validate_path_exists(&self.cms_certs.signer_key, "cms_certs.signer_key")?;

        // 可选特殊证书验证
        if let Some(ref path) = self.cms_certs.expired_cert {
            Self::validate_path_exists(path, "cms_certs.expired_cert")?;
        }
        if let Some(ref path) = self.cms_certs.expired_key {
            Self::validate_path_exists(path, "cms_certs.expired_key")?;
        }
        if let Some(ref path) = self.cms_certs.revoked_cert {
            Self::validate_path_exists(path, "cms_certs.revoked_cert")?;
        }
        if let Some(ref path) = self.cms_certs.revoked_key {
            Self::validate_path_exists(path, "cms_certs.revoked_key")?;
        }

        Ok(())
    }

    /// 验证路径是否存在
    fn validate_path_exists(path: &Path, field: &str) -> Result<(), ConfigError> {
        if !path.exists() {
            Err(ConfigError::Validation(format!(
                "{} path does not exist: {}",
                field,
                path.display()
            )))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_cert_file() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "dummy cert content").unwrap();
        file
    }

    fn create_valid_config_content(
        ca_cert: &str,
        client_cert: &str,
        client_key: &str,
        cms_ca: &str,
        signer_cert: &str,
        signer_key: &str,
    ) -> String {
        format!(
            r#"
[connection]
port = 12345

[tls_client]
ca_cert = "{}"
client_cert = "{}"
client_key = "{}"

[cms_certs]
ca_cert = "{}"
signer_cert = "{}"
signer_key = "{}"

[server]
binary_path = "trustruntime"
"#,
            ca_cert, client_cert, client_key, cms_ca, signer_cert, signer_key
        )
    }

    #[test]
    fn parsing_valid_toml_returns_correct_config() {
        let ca = create_test_cert_file();
        let client_cert = create_test_cert_file();
        let client_key = create_test_cert_file();
        let cms_ca = create_test_cert_file();
        let signer_cert = create_test_cert_file();
        let signer_key = create_test_cert_file();

        let content = create_valid_config_content(
            ca.path().to_str().unwrap(),
            client_cert.path().to_str().unwrap(),
            client_key.path().to_str().unwrap(),
            cms_ca.path().to_str().unwrap(),
            signer_cert.path().to_str().unwrap(),
            signer_key.path().to_str().unwrap(),
        );

        let config: CmsTestConfig = toml::from_str(&content).unwrap();
        assert_eq!(config.connection.port, 12345);
        assert!(config.tls_client.client_key_pwd.is_none());
    }

    #[test]
    fn loading_config_from_file_works() {
        let ca = create_test_cert_file();
        let client_cert = create_test_cert_file();
        let client_key = create_test_cert_file();
        let cms_ca = create_test_cert_file();
        let signer_cert = create_test_cert_file();
        let signer_key = create_test_cert_file();

        let content = create_valid_config_content(
            ca.path().to_str().unwrap(),
            client_cert.path().to_str().unwrap(),
            client_key.path().to_str().unwrap(),
            cms_ca.path().to_str().unwrap(),
            signer_cert.path().to_str().unwrap(),
            signer_key.path().to_str().unwrap(),
        );

        let mut config_file = NamedTempFile::new().unwrap();
        write!(config_file, "{}", content).unwrap();

        let config = CmsTestConfig::from_file(config_file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.connection.port, 12345);
    }

    #[test]
    fn missing_cert_path_returns_validation_error() {
        let content = r#"
[connection]
port = 12345

[tls_client]
ca_cert = "/nonexistent/path/ca.crt"
client_cert = "/nonexistent/path/client.crt"
client_key = "/nonexistent/path/client.key"

[cms_certs]
ca_cert = "/nonexistent/path/cms_ca.crt"
signer_cert = "/nonexistent/path/signer.crt"
signer_key = "/nonexistent/path/signer.key"
"#;

        let config: CmsTestConfig = toml::from_str(content).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        assert!(matches!(result, Err(ConfigError::Validation(_))));
    }

    #[test]
    fn invalid_port_returns_validation_error() {
        let content = r#"
[connection]
port = 0

[tls_client]
ca_cert = "/tmp/ca.crt"
client_cert = "/tmp/client.crt"
client_key = "/tmp/client.key"

[cms_certs]
ca_cert = "/tmp/cms_ca.crt"
signer_cert = "/tmp/signer.crt"
signer_key = "/tmp/signer.key"
"#;

        let config: CmsTestConfig = toml::from_str(content).unwrap();
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn optional_fields_are_handled() {
        let ca = create_test_cert_file();
        let client_cert = create_test_cert_file();
        let client_key = create_test_cert_file();
        let cms_ca = create_test_cert_file();
        let signer_cert = create_test_cert_file();
        let signer_key = create_test_cert_file();

        let content = format!(
            r#"
[connection]
port = 12345

[tls_client]
ca_cert = "{}"
client_cert = "{}"
client_key = "{}"

[cms_certs]
ca_cert = "{}"
signer_cert = "{}"
signer_key = "{}"
"#,
            ca.path().to_str().unwrap(),
            client_cert.path().to_str().unwrap(),
            client_key.path().to_str().unwrap(),
            cms_ca.path().to_str().unwrap(),
            signer_cert.path().to_str().unwrap(),
            signer_key.path().to_str().unwrap()
        );

        let config: CmsTestConfig = toml::from_str(&content).unwrap();
        assert!(config.validate().is_ok());
        assert!(config.cms_certs.expired_cert.is_none());
        assert!(config.server.binary_path == Path::new("trustruntime"));
    }
}
