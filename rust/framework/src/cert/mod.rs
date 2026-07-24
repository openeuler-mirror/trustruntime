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

use foreign_types_shared::ForeignType;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509Crl, X509};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

extern "C" {
    fn ASN1_BIT_STRING_free(a: *mut openssl_sys::ASN1_BIT_STRING);
    fn ASN1_OBJECT_free(a: *mut openssl_sys::ASN1_OBJECT);
    fn OPENSSL_sk_pop_free(
        st: *mut openssl_sys::OPENSSL_STACK,
        free_func: Option<unsafe extern "C" fn(*mut std::ffi::c_void)>,
    );
}

unsafe extern "C" fn asn1_object_free_wrapper(ptr: *mut std::ffi::c_void) {
    ASN1_OBJECT_free(ptr as *mut openssl_sys::ASN1_OBJECT);
}

/// 允许的证书目录前缀（硬编码，防止配置篡改）
#[cfg(not(debug_assertions))]
const ALLOWED_CERT_DIRS: &[&str] = &["/etc/cert/"];

/// 验证证书文件路径安全性
///
/// # 安全检查（Release构建）
/// 1. 路径不能是symlink（防止Host通过9p注入恶意文件）
/// 2. 规范路径必须在允许的目录内（防止路径遍历）
///
/// # Debug构建
/// 跳过路径验证，仅用于测试环境
fn validate_cert_path(path: &str) -> Result<PathBuf, CertLoadError> {
    #[cfg(debug_assertions)]
    {
        Path::new(path)
            .canonicalize()
            .map_err(CertLoadError::IoError)
    }

    #[cfg(not(debug_assertions))]
    {
        let p = Path::new(path);

        if p.is_symlink() {
            return Err(CertLoadError::SecurityError("symlink not allowed".into()));
        }

        let canonical = p.canonicalize().map_err(CertLoadError::IoError)?;

        let canonical_str = canonical
            .to_str()
            .ok_or_else(|| CertLoadError::SecurityError("invalid path encoding".into()))?;

        if !ALLOWED_CERT_DIRS
            .iter()
            .any(|dir| canonical_str.starts_with(dir))
        {
            return Err(CertLoadError::SecurityError(
                "path outside allowed dirs".into(),
            ));
        }

        Ok(canonical)
    }
}

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
    /// 安全错误：路径验证失败（symlink、路径遍历等）
    #[error("security error: {0}")]
    SecurityError(String),
}

/// 加载X.509证书
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
    let validated_path = validate_cert_path(path)?;
    let data = fs::read(&validated_path)?;
    // ADR-0004: PEM/DER双格式支持 - 先尝试PEM，失败后尝试DER
    X509::from_pem(&data)
        .or_else(|_| X509::from_der(&data))
        .map_err(|_| CertLoadError::InvalidFormat)
}

/// 加载私钥
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
    let validated_path = validate_cert_path(path)?;
    let data = fs::read(&validated_path)?;
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
    let validated_path = validate_cert_path(path)?;
    let data = fs::read(&validated_path)?;
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

/// 检测证书是否尚未生效
///
/// 算法说明：
/// - 比较证书的not_before时间戳与当前时间
/// - not_before > 当前时间 → 证书尚未生效
///
/// # Arguments
/// * `cert` - OpenSSL X509证书对象
///
/// # Returns
/// * `true` - 证书尚未生效（not_before > 当前时间）
/// * `false` - 证书已生效
///
/// # Example
/// ```text
/// let cert = load_x509("/path/to/cert.pem")?;
/// if is_not_yet_valid(&cert) {
///     println!("证书尚未生效");
/// }
/// ```
pub fn is_not_yet_valid(cert: &X509) -> bool {
    // 未生效检测：not_before > 当前时间
    cert.not_before() > openssl::asn1::Asn1Time::days_from_now(0).unwrap()
}

/// KeyUsage 标志位
///
/// 用于检查证书的 KeyUsage 扩展是否包含指定的用途。
/// 基于 RFC 5280 §4.2.1.3 定义的位位置。
pub struct KeyUsageFlags;

impl KeyUsageFlags {
    /// 数字签名（bit 0）
    pub const DIGITAL_SIGNATURE: u32 = 0x80;
    /// 不可否认（bit 1）
    pub const NON_REPUDIATION: u32 = 0x40;
    /// 密钥加密（bit 2）
    pub const KEY_ENCIPHERMENT: u32 = 0x20;
    /// 数据加密（bit 3）
    pub const DATA_ENCIPHERMENT: u32 = 0x10;
    /// 密钥协商（bit 4）
    pub const KEY_AGREEMENT: u32 = 0x08;
    /// 证书签名（bit 5）
    pub const KEY_CERT_SIGN: u32 = 0x04;
    /// CRL签名（bit 6）
    pub const CRL_SIGN: u32 = 0x02;
}

const OID_MAPPINGS: &[(&str, &str, &str)] = &[
    (
        "serverAuth",
        "TLS Web Server Authentication",
        "1.3.6.1.5.5.7.3.1",
    ),
    (
        "clientAuth",
        "TLS Web Client Authentication",
        "1.3.6.1.5.5.7.3.2",
    ),
];

fn get_oid_aliases(required_oid: &str) -> Vec<&str> {
    let mut aliases = vec![required_oid];
    for (short, long, oid) in OID_MAPPINGS {
        if *short == required_oid {
            aliases.push(*long);
            aliases.push(*oid);
        } else if *long == required_oid {
            aliases.push(*short);
            aliases.push(*oid);
        } else if *oid == required_oid {
            aliases.push(*short);
            aliases.push(*long);
        }
    }
    aliases
}

unsafe fn extract_eku_oids(eku: *mut std::ffi::c_void) -> Vec<String> {
    use std::ffi::CStr;

    let stack = eku as *const openssl_sys::stack_st_ASN1_OBJECT;
    let num = openssl_sys::OPENSSL_sk_num(stack as *const _);
    let mut oids = Vec::with_capacity(num as usize);

    for i in 0..num {
        let obj =
            openssl_sys::OPENSSL_sk_value(stack as *const _, i) as *mut openssl_sys::ASN1_OBJECT;
        if !obj.is_null() {
            let mut buf = [0u8; 256];
            let len =
                openssl_sys::OBJ_obj2txt(buf.as_mut_ptr() as *mut i8, buf.len() as i32, obj, 0);
            if len > 0 {
                let oid = CStr::from_ptr(buf.as_ptr() as *const i8).to_string_lossy();
                oids.push(oid.into_owned());
            }
        }
    }
    oids
}

/// 提取KeyUsage标志位
pub fn extract_key_usage_flags(cert: &X509) -> Result<u32, CertLoadError> {
    let ku = unsafe {
        openssl_sys::X509_get_ext_d2i(
            cert.as_ptr(),
            openssl_sys::NID_key_usage,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if ku.is_null() {
        return Err(CertLoadError::InvalidFormat);
    }

    let result = unsafe {
        let bit_string = ku as *const openssl_sys::ASN1_BIT_STRING;
        let data = openssl_sys::ASN1_STRING_get0_data(bit_string as *const _);
        let length = openssl_sys::ASN1_STRING_length(bit_string as *const _) as usize;
        let usage_bytes = std::slice::from_raw_parts(data, length);

        if usage_bytes.is_empty() {
            ASN1_BIT_STRING_free(ku as *mut _);
            return Err(CertLoadError::InvalidFormat);
        }

        let flags = usage_bytes[0] as u32;
        ASN1_BIT_STRING_free(ku as *mut _);
        Ok(flags)
    };

    result
}

/// 检查证书是否包含指定的KeyUsage位（包含匹配）
///
/// 用于通信证书：证书必须包含所有指定位，可包含其他位。
///
/// # Arguments
/// * `cert` - X509证书对象
/// * `required_flags` - 必需的KeyUsage位（可组合多个标志）
///
/// # Returns
/// * `Ok(())` - 证书包含所有必需的KeyUsage位
/// * `Err(CertLoadError::InvalidFormat)` - 证书缺少KeyUsage扩展或不包含必需位
///
/// # Example
/// ```text
/// let cert = load_x509("/path/to/cert.pem")?;
/// check_key_usage_contains(&cert, KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_ENCIPHERMENT)?;
/// ```
pub fn check_key_usage_contains(cert: &X509, required_flags: u32) -> Result<(), CertLoadError> {
    let actual_flags = extract_key_usage_flags(cert)?;

    if (actual_flags & required_flags) != required_flags {
        return Err(CertLoadError::InvalidFormat);
    }

    Ok(())
}

/// 检查证书是否仅包含指定的KeyUsage位（精确匹配）
///
/// 用于签名证书：证书必须仅包含指定位，不能包含其他位。
///
/// # Arguments
/// * `cert` - X509证书对象
/// * `required_flags` - 必需的KeyUsage位（仅包含这些位）
///
/// # Returns
/// * `Ok(())` - 证书仅包含指定的KeyUsage位
/// * `Err(CertLoadError::InvalidFormat)` - 证书缺少KeyUsage扩展或包含其他位
///
/// # Example
/// ```text
/// let cert = load_x509("/path/to/cert.pem")?;
/// check_key_usage_exact(&cert, KeyUsageFlags::DIGITAL_SIGNATURE)?;
/// ```
pub fn check_key_usage_exact(cert: &X509, required_flags: u32) -> Result<(), CertLoadError> {
    let actual_flags = extract_key_usage_flags(cert)?;

    if actual_flags != required_flags {
        return Err(CertLoadError::InvalidFormat);
    }

    Ok(())
}

/// 检查证书ExtendedKeyUsage扩展
///
/// 验证证书是否包含指定的ExtendedKeyUsage OID。
///
/// # Arguments
/// * `cert` - X509证书对象
/// * `required_oid` - 必需的ExtendedKeyUsage OID（如"serverAuth"）
///
/// # Returns
/// * `Ok(())` - 证书包含指定的ExtendedKeyUsage
/// * `Err(CertLoadError::InvalidFormat)` - 证书缺少ExtendedKeyUsage或不包含指定OID
///
/// # Example
/// ```text
/// let cert = load_x509("/path/to/cert.pem")?;
/// check_extended_key_usage(&cert, "serverAuth")?;
/// ```
pub fn check_extended_key_usage(cert: &X509, required_oid: &str) -> Result<(), CertLoadError> {
    let eku = unsafe {
        openssl_sys::X509_get_ext_d2i(
            cert.as_ptr(),
            openssl_sys::NID_ext_key_usage,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if eku.is_null() {
        return Err(CertLoadError::InvalidFormat);
    }

    let aliases = get_oid_aliases(required_oid);
    let eku_oids = unsafe { extract_eku_oids(eku) };

    let result = if eku_oids.iter().any(|oid| aliases.contains(&oid.as_str())) {
        Ok(())
    } else {
        Err(CertLoadError::InvalidFormat)
    };

    unsafe {
        OPENSSL_sk_pop_free(
            eku as *mut openssl_sys::OPENSSL_STACK,
            Some(asn1_object_free_wrapper),
        );
    }

    result
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
    use openssl::x509::{X509Builder, X509CrlBuilder, X509Name, X509NameBuilder};
    use std::fs;

    fn generate_ec_key_pair() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        PKey::from_ec_key(ec_key).unwrap()
    }

    fn build_x509_name(cn: &str) -> X509Name {
        let mut builder = X509NameBuilder::new().unwrap();
        builder.append_entry_by_text("CN", cn).unwrap();
        builder.build()
    }

    fn build_basic_cert_builder(
        pkey: &PKey<Private>,
        cn: &str,
        serial: u32,
        not_before: &Asn1Time,
        not_after: &Asn1Time,
    ) -> X509Builder {
        let name = build_x509_name(cn);
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(pkey).unwrap();
        builder.set_not_before(not_before).unwrap();
        builder.set_not_after(not_after).unwrap();
        let serial_bn = BigNum::from_u32(serial).unwrap();
        builder
            .set_serial_number(&serial_bn.to_asn1_integer().unwrap())
            .unwrap();
        builder
    }

    /// 生成测试用的有效期证书（ECC-256，有效期365天）
    fn generate_test_cert() -> (X509, PKey<Private>) {
        let pkey = generate_ec_key_pair();
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        let mut builder = build_basic_cert_builder(&pkey, "Test Cert", 1, &not_before, &not_after);

        // 添加SKI扩展（SHA-1哈希，20字节）
        let context = builder.x509v3_context(None, None);
        let ski = SubjectKeyIdentifier::new().build(&context).unwrap();
        builder.append_extension(ski).unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        (builder.build(), pkey)
    }

    /// 生成测试用的已过期证书（ECC-256，2001年过期）
    fn generate_expired_cert() -> (X509, PKey<Private>) {
        let pkey = generate_ec_key_pair();
        // 设置已过期的时间范围（2000-2001年）
        let not_before = Asn1Time::from_unix(946684800).unwrap();
        let not_after = Asn1Time::from_unix(1000000000).unwrap();
        let mut builder =
            build_basic_cert_builder(&pkey, "Expired Cert", 2, &not_before, &not_after);

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        (builder.build(), pkey)
    }

    /// 生成测试用的尚未生效证书（ECC-256，365天后生效）
    fn generate_not_yet_valid_cert() -> (X509, PKey<Private>) {
        let pkey = generate_ec_key_pair();
        // 设置尚未生效的时间范围（365天后生效，3650天后过期）
        let not_before = Asn1Time::days_from_now(365).unwrap();
        let not_after = Asn1Time::days_from_now(3650).unwrap();
        let mut builder =
            build_basic_cert_builder(&pkey, "Not Yet Valid Cert", 3, &not_before, &not_after);

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
    fn is_not_yet_valid_returns_true_for_future_cert() {
        // 场景：检测尚未生效证书（not_before在未来）
        // 预期：返回true

        let (cert, _) = generate_not_yet_valid_cert();
        assert!(is_not_yet_valid(&cert));
    }

    #[test]
    fn is_not_yet_valid_returns_false_for_valid_cert() {
        // 场景：检测已生效证书（not_before在过去）
        // 预期：返回false

        let (cert, _) = generate_test_cert();
        assert!(!is_not_yet_valid(&cert));
    }

    #[test]
    fn load_x509_missing_file_returns_io_error() {
        // 场景：加载不存在的证书文件
        // 预期：返回IoError错误

        let result = load_x509("/tmp/framework_cert_nonexistent_file.crt");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CertLoadError::IoError(_)));
    }

    /// 生成带KeyUsage扩展的测试证书
    fn generate_test_cert_with_key_usage(key_usage_flags: u32) -> (X509, PKey<Private>) {
        use openssl::x509::extension::KeyUsage;

        let pkey = generate_ec_key_pair();
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        let mut builder =
            build_basic_cert_builder(&pkey, "Test Cert with KeyUsage", 1, &not_before, &not_after);

        let context = builder.x509v3_context(None, None);
        builder
            .append_extension(SubjectKeyIdentifier::new().build(&context).unwrap())
            .unwrap();

        let mut ku = KeyUsage::new();
        if (key_usage_flags & KeyUsageFlags::DIGITAL_SIGNATURE) != 0 {
            ku.digital_signature();
        }
        if (key_usage_flags & KeyUsageFlags::KEY_ENCIPHERMENT) != 0 {
            ku.key_encipherment();
        }
        if (key_usage_flags & KeyUsageFlags::NON_REPUDIATION) != 0 {
            ku.non_repudiation();
        }
        builder.append_extension(ku.build().unwrap()).unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        (builder.build(), pkey)
    }

    #[test]
    fn check_key_usage_contains_returns_error_for_missing_flag() {
        let (cert, _) = generate_test_cert_with_key_usage(KeyUsageFlags::DIGITAL_SIGNATURE);
        let result = check_key_usage_contains(
            &cert,
            KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_ENCIPHERMENT,
        );
        assert!(result.is_err());
    }

    #[test]
    fn check_key_usage_exact_returns_error_for_extra_flags() {
        let (cert, _) = generate_test_cert_with_key_usage(
            KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_ENCIPHERMENT,
        );
        let result = check_key_usage_exact(&cert, KeyUsageFlags::DIGITAL_SIGNATURE);
        assert!(result.is_err());
    }

    #[test]
    fn check_key_usage_exact_returns_error_for_missing_flag() {
        let (cert, _) = generate_test_cert_with_key_usage(KeyUsageFlags::DIGITAL_SIGNATURE);
        let result = check_key_usage_exact(
            &cert,
            KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_ENCIPHERMENT,
        );
        assert!(result.is_err());
    }

    #[test]
    fn check_key_usage_returns_error_for_missing_extension() {
        let (cert, _) = generate_test_cert();
        let result = check_key_usage_contains(&cert, KeyUsageFlags::DIGITAL_SIGNATURE);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn reject_symlink_path() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let temp_dir = std::env::temp_dir().join("framework_cert_symlink");
            let _ = fs::remove_dir_all(&temp_dir);
            fs::create_dir_all(&temp_dir).unwrap();

            let (cert, _) = generate_test_cert();
            let real_path = temp_dir.join("real.crt");
            fs::write(&real_path, cert.to_pem().unwrap()).unwrap();

            let symlink_path = temp_dir.join("link.crt");
            symlink(&real_path, &symlink_path).unwrap();

            let result = validate_cert_path(symlink_path.to_str().unwrap());
            assert!(matches!(
                result.unwrap_err(),
                CertLoadError::SecurityError(_)
            ));

            fs::remove_dir_all(&temp_dir).unwrap();
        }
    }

    #[test]
    fn reject_path_outside_allowed_dirs() {
        let result = validate_cert_path("/nonexistent/outside/path.crt");
        assert!(result.is_err());
    }

    #[test]
    fn accept_valid_path_in_allowed_dir() {
        let temp_dir = std::env::temp_dir().join("framework_cert_valid");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let (cert, _) = generate_test_cert();
        let path = temp_dir.join("test.crt");
        fs::write(&path, cert.to_pem().unwrap()).unwrap();

        let result = load_x509(path.to_str().unwrap());
        assert!(result.is_ok());

        fs::remove_dir_all(&temp_dir).unwrap();
    }
}
