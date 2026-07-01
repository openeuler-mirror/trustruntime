//! 证书加载工具模块
//!
//! 主要职责：
//! - 加载X.509证书（支持PEM/DER双格式）
//! - 加载私钥（支持加密私钥）
//! - 加载CRL吊销列表
//! - 提取证书Subject Key Identifier（SKI）
//! - 检测证书是否过期
//!
//! 架构决策：
//! - PEM/DER双格式支持（ADR-0004）
//! - 统一使用OpenSSL处理证书加载
//!
//! 依赖：openssl crate

use openssl::pkey::{PKey, Private};
use openssl::x509::{X509Crl, X509};
use std::fs;
use std::path::Path;
use thiserror::Error;

/// 证书加载错误类型
///
/// 架构决策：统一错误处理映射到结果码
/// 详见 ADR-0001: Unified Result Code Encoding
#[derive(Error, Debug)]
pub enum CertLoadError {
    /// 文件I/O错误（文件不存在、权限不足等）
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    /// OpenSSL内部错误（解析失败、密码错误等）
    #[error("openssl error: {0}")]
    OpenSslError(#[from] openssl::error::ErrorStack),
    /// 格式错误：PEM和DER格式均解析失败
    #[error("invalid format: PEM and DER both failed")]
    InvalidFormat,
}

/// 加载X.509证书
///
/// 架构决策：PEM/DER双格式支持
/// 详见 ADR-0004: Unified OpenSSL for TLS and CMS
///
/// 加载策略：先尝试PEM格式，失败后尝试DER格式，均失败则返回InvalidFormat错误
///
/// # Arguments
/// * `path` - 证书文件路径
///
/// # Returns
/// * `Ok(X509)` - 加载成功的OpenSSL X509证书对象
/// * `Err(CertLoadError::IoError)` - 文件读取失败
/// * `Err(CertLoadError::InvalidFormat)` - PEM和DER格式均解析失败
///
/// # Example
/// ```text
/// let cert = load_x509("/path/to/cert.pem")?;
/// let cert = load_x509("/path/to/cert.der")?;
/// ```
pub fn load_x509(path: &str) -> Result<X509, CertLoadError> {
    let data = fs::read(Path::new(path))?;
    // ADR-0004: PEM/DER双格式支持 - 先尝试PEM，失败后尝试DER
    X509::from_pem(&data)
        .or_else(|_| X509::from_der(&data))
        .map_err(|_| CertLoadError::InvalidFormat)
}

/// 加载私钥
///
/// 架构决策：PEM/DER双格式支持 + 加密私钥密码支持
/// 详见 ADR-0004: Unified OpenSSL for TLS and CMS
///
/// 加载策略：
/// - 有密码：尝试PEM加密格式，失败后尝试PKCS8加密格式
/// - 无密码：尝试PEM格式，失败后尝试DER格式
///
/// # Arguments
/// * `path` - 私钥文件路径
/// * `password` - 私钥密码（可选，用于加密私钥）
///
/// # Returns
/// * `Ok(PKey<Private>)` - 加载成功的OpenSSL私钥对象
/// * `Err(CertLoadError::IoError)` - 文件读取失败
/// * `Err(CertLoadError::OpenSslError)` - 密码错误或解析失败
/// * `Err(CertLoadError::InvalidFormat)` - 无密码时PEM和DER格式均解析失败
///
/// # Example
/// ```text
/// // 无密码私钥
/// let pkey = load_private_key("/path/to/key.pem", None)?;
/// // 加密私钥
/// let pkey = load_private_key("/path/to/key.pem", Some("password"))?;
/// ```
pub fn load_private_key(
    path: &str,
    password: Option<&str>,
) -> Result<PKey<Private>, CertLoadError> {
    let data = fs::read(Path::new(path))?;
    match password {
        Some(pass) => {
            // 加密私钥：尝试PEM加密格式，失败后尝试PKCS8加密格式
            PKey::private_key_from_pem_passphrase(&data, pass.as_bytes())
                .or_else(|_| PKey::private_key_from_pkcs8_passphrase(&data, pass.as_bytes()))
                .map_err(CertLoadError::OpenSslError)
        }
        None => {
            // ADR-0004: PEM/DER双格式支持 - 无密码私钥
            PKey::private_key_from_pem(&data)
                .or_else(|_| PKey::private_key_from_der(&data))
                .map_err(|_| CertLoadError::InvalidFormat)
        }
    }
}

/// 加载CRL吊销列表
///
/// 架构决策：PEM/DER双格式支持
/// 详见 ADR-0004: Unified OpenSSL for TLS and CMS
///
/// 加载策略：先尝试PEM格式，失败后尝试DER格式，均失败则返回InvalidFormat错误
///
/// # Arguments
/// * `path` - CRL文件路径
///
/// # Returns
/// * `Ok(X509Crl)` - 加载成功的OpenSSL CRL对象
/// * `Err(CertLoadError::IoError)` - 文件读取失败
/// * `Err(CertLoadError::InvalidFormat)` - PEM和DER格式均解析失败
///
/// # Example
/// ```text
/// let crl = load_crl("/path/to/crl.pem")?;
/// ```
pub fn load_crl(path: &str) -> Result<X509Crl, CertLoadError> {
    let data = fs::read(Path::new(path))?;
    // ADR-0004: PEM/DER双格式支持 - 先尝试PEM，失败后尝试DER
    X509Crl::from_pem(&data)
        .or_else(|_| X509Crl::from_der(&data))
        .map_err(|_| CertLoadError::InvalidFormat)
}

/// 提取证书的Subject Key Identifier（SKI）
///
/// SKI用于唯一标识证书公钥，在CMS签名中用于证书身份判定。
///
/// 算法说明：
/// - SKI是证书扩展字段，由CA生成
/// - 通常为20字节的SHA-1哈希值（RFC 5280 §4.2.1.2）
/// - 用于签名时与数据拼接：sign(data + cert_id)
///
/// # Arguments
/// * `cert` - OpenSSL X509证书对象
///
/// # Returns
/// * `Ok(Vec<u8>)` - SKI字节数组（通常20字节）
/// * `Err(CertLoadError::InvalidFormat)` - 证书缺少SKI扩展
///
/// # Example
/// ```text
/// let cert = load_x509("/path/to/cert.pem")?;
/// let ski = extract_subject_key_id(&cert)?;
/// assert_eq!(ski.len(), 20); // SHA-1哈希值
/// ```
pub fn extract_subject_key_id(cert: &X509) -> Result<Vec<u8>, CertLoadError> {
    cert.subject_key_id()
        .map(|ski| ski.as_slice().to_vec())
        .ok_or(CertLoadError::InvalidFormat)
}

/// 检测证书是否已过期
///
/// 算法说明：
/// - 比较证书的not_after时间戳与当前时间
/// - not_after < 当前时间 → 证书已过期
///
/// # Arguments
/// * `cert` - OpenSSL X509证书对象
///
/// # Returns
/// * `true` - 证书已过期（not_after < 当前时间）
/// * `false` - 证书仍在有效期内
///
/// # Example
/// ```text
/// let cert = load_x509("/path/to/cert.pem")?;
/// if is_expired(&cert) {
///     println!("证书已过期");
/// }
/// ```
pub fn is_expired(cert: &X509) -> bool {
    // 过期检测：not_after < 当前时间
    cert.not_after() < openssl::asn1::Asn1Time::days_from_now(0).unwrap()
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
    use openssl::symm::Cipher;
    use openssl::x509::extension::SubjectKeyIdentifier;
    use openssl::x509::{X509Builder, X509CrlBuilder, X509NameBuilder};
    use std::fs;

    /// 生成测试用的有效期证书（ECC-256，有效期365天）
    fn generate_test_cert() -> (X509, PKey<Private>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "Test Cert")
            .unwrap();
        let name = name_builder.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        let serial = BigNum::from_u32(1).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();

        // 添加SKI扩展（SHA-1哈希，20字节）
        let context = builder.x509v3_context(None, None);
        let ski = SubjectKeyIdentifier::new().build(&context).unwrap();
        builder.append_extension(ski).unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        (builder.build(), pkey)
    }

    /// 生成测试用的已过期证书（ECC-256，2001年过期）
    fn generate_expired_cert() -> (X509, PKey<Private>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "Expired Cert")
            .unwrap();
        let name = name_builder.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();

        // 设置已过期的时间范围（2000-2001年）
        let not_before = Asn1Time::from_unix(946684800).unwrap();
        let not_after = Asn1Time::from_unix(1000000000).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        let serial = BigNum::from_u32(2).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        (builder.build(), pkey)
    }

    #[test]
    fn load_x509_pem_format_succeeds() {
        // 场景：加载PEM格式的X.509证书
        // 预期：成功解析证书对象

        let temp_dir = std::env::temp_dir().join("framework_cert_x509_pem");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let (cert, _) = generate_test_cert();
        let path = temp_dir.join("test.crt");
        fs::write(&path, cert.to_pem().unwrap()).unwrap();

        let result = load_x509(path.to_str().unwrap());
        assert!(result.is_ok());

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn load_x509_der_format_succeeds() {
        // 场景：加载DER格式的X.509证书
        // 预期：成功解析证书对象（ADR-0004: PEM/DER双格式支持）

        let temp_dir = std::env::temp_dir().join("framework_cert_x509_der");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let (cert, _) = generate_test_cert();
        let path = temp_dir.join("test.der");
        fs::write(&path, cert.to_der().unwrap()).unwrap();

        let result = load_x509(path.to_str().unwrap());
        assert!(result.is_ok());

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn load_x509_invalid_format_returns_error() {
        // 场景：加载无效格式的文件
        // 预期：返回InvalidFormat错误

        let temp_dir = std::env::temp_dir().join("framework_cert_x509_invalid");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let path = temp_dir.join("garbage.crt");
        fs::write(&path, b"this is not a certificate").unwrap();

        let result = load_x509(path.to_str().unwrap());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CertLoadError::InvalidFormat));

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    /// 生成测试用的CRL吊销列表
    fn generate_test_crl() -> X509Crl {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("CN", "Test CRL").unwrap();
        let name = name_builder.build();

        let mut cert_builder = X509Builder::new().unwrap();
        cert_builder.set_version(2).unwrap();
        cert_builder.set_subject_name(&name).unwrap();
        cert_builder.set_issuer_name(&name).unwrap();
        cert_builder.set_pubkey(&pkey).unwrap();
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        cert_builder.set_not_before(&not_before).unwrap();
        cert_builder.set_not_after(&not_after).unwrap();
        let serial = BigNum::from_u32(1).unwrap();
        cert_builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        let ctx = cert_builder.x509v3_context(None, None);
        let ski = SubjectKeyIdentifier::new().build(&ctx).unwrap();
        cert_builder.append_extension(ski).unwrap();
        cert_builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let issuer_cert = cert_builder.build();

        let mut builder = X509CrlBuilder::new().unwrap();
        builder.set_issuer_name(&name).unwrap();

        let last_update = Asn1Time::days_from_now(0).unwrap();
        let next_update = Asn1Time::days_from_now(365).unwrap();
        builder.set_last_update(&last_update).unwrap();
        builder.set_next_update(&next_update).unwrap();

        let mut temp_builder = X509Builder::new().unwrap();
        temp_builder.set_version(2).unwrap();
        temp_builder.set_subject_name(&name).unwrap();
        temp_builder.set_issuer_name(&name).unwrap();
        temp_builder.set_pubkey(&pkey).unwrap();
        temp_builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        temp_builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        let temp_serial = BigNum::from_u32(99).unwrap();
        temp_builder
            .set_serial_number(&temp_serial.to_asn1_integer().unwrap())
            .unwrap();
        let ctx = temp_builder.x509v3_context(Some(&issuer_cert), None);
        let aki = openssl::x509::extension::AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&ctx)
            .unwrap();
        builder.append_extension(aki).unwrap();

        let crl_number =
            openssl::x509::extension::CrlNumber::new(BigNum::from_u32(1).unwrap()).unwrap();
        let crl_num_ext = crl_number.build().unwrap();
        builder.append_extension(crl_num_ext).unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        builder.build().unwrap()
    }

    #[test]
    fn load_crl_pem_format_succeeds() {
        // 场景：加载PEM格式的CRL
        // 预期：成功解析CRL对象

        let temp_dir = std::env::temp_dir().join("framework_cert_crl_pem");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let crl = generate_test_crl();
        let path = temp_dir.join("test.crl");
        fs::write(&path, crl.to_pem().unwrap()).unwrap();

        let result = load_crl(path.to_str().unwrap());
        assert!(result.is_ok());

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn load_crl_der_format_succeeds() {
        // 场景：加载DER格式的CRL
        // 预期：成功解析CRL对象（ADR-0004: PEM/DER双格式支持）

        let temp_dir = std::env::temp_dir().join("framework_cert_crl_der");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let crl = generate_test_crl();
        let path = temp_dir.join("test.crl");
        fs::write(&path, crl.to_der().unwrap()).unwrap();

        let result = load_crl(path.to_str().unwrap());
        assert!(result.is_ok());

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn load_private_key_pem_no_password_succeeds() {
        // 场景：加载无密码保护的PEM格式私钥
        // 预期：成功解析私钥对象

        let temp_dir = std::env::temp_dir().join("framework_cert_pkey_nopass");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let (_, pkey) = generate_test_cert();
        let path = temp_dir.join("test.key");
        fs::write(&path, pkey.private_key_to_pem_pkcs8().unwrap()).unwrap();

        let result = load_private_key(path.to_str().unwrap(), None);
        assert!(result.is_ok());

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn load_private_key_pem_with_password_succeeds() {
        // 场景：加载有密码保护的PEM格式私钥
        // 预期：使用正确密码成功解析私钥对象

        let temp_dir = std::env::temp_dir().join("framework_cert_pkey_pass");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let (_, pkey) = generate_test_cert();
        let path = temp_dir.join("test_enc.key");
        let passphrase = b"test_password_123";
        fs::write(
            &path,
            pkey.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), passphrase)
                .unwrap(),
        )
        .unwrap();

        let result = load_private_key(path.to_str().unwrap(), Some("test_password_123"));
        assert!(result.is_ok());

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn extract_subject_key_id_returns_correct_bytes() {
        // 场景：提取证书的SKI
        // 预期：返回20字节的SHA-1哈希值

        let (cert, _) = generate_test_cert();
        let result = extract_subject_key_id(&cert);
        assert!(result.is_ok());
        let ski_bytes = result.unwrap();
        assert_eq!(ski_bytes.len(), 20);
    }

    #[test]
    fn is_expired_returns_true_for_expired_cert() {
        // 场景：检测已过期证书
        // 预期：返回true

        let (cert, _) = generate_expired_cert();
        assert!(is_expired(&cert));
    }

    #[test]
    fn is_expired_returns_false_for_valid_cert() {
        // 场景：检测有效期内的证书
        // 预期：返回false

        let (cert, _) = generate_test_cert();
        assert!(!is_expired(&cert));
    }

    #[test]
    fn load_x509_missing_file_returns_io_error() {
        // 场景：加载不存在的证书文件
        // 预期：返回IoError错误

        let result = load_x509("/tmp/framework_cert_nonexistent_file.crt");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CertLoadError::IoError(_)));
    }
}
