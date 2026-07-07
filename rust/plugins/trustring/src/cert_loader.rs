//! 证书加载模块
//!
//! 职责：
//! - 加载CMS签名证书（含私钥）
//! - 加载CA根证书
//! - 加载CRL吊销列表
//! - 提取证书ID（Subject Key Identifier）
//!
//! 架构决策：
//! - PEM/DER双格式支持（ADR-0004）
//! - 统一使用OpenSSL处理证书（ADR-0004: Unified OpenSSL for TLS and CMS）
//!
//! 依赖：
//! - openssl::x509 证书类型
//! - openssl::pkey 私钥类型
//! - trustruntime_framework::cert 证书加载工具

use openssl::pkey::PKey;
use openssl::x509::{X509Crl, X509};
use trustruntime_framework::cert::{self, CertLoadError};

/// CMS签名证书（含私钥）
///
/// 封装签名证书和私钥，用于CMS签名操作。
///
/// 优势：
/// - 与TLS层使用相同证书类型，无需格式转换
/// - 私钥类型统一为openssl::PKey<Private>
/// - cert_id通过SKI扩展提取，用于签名时与数据拼接
///
/// Clone实现：
/// - X509和PKey的clone是引用计数浅拷贝（性能开销极小）
/// - cert_id是Vec<u8>深拷贝（20字节，开销可忽略）
/// - 用于TrustringPlugin避免重复加载签名证书
pub(crate) struct CmsCertificate {
    /// 签名证书
    cert: X509,
    /// 签名私钥
    key: PKey<openssl::pkey::Private>,
    /// 证书ID（Subject Key Identifier，20字节SHA-1哈希）
    cert_id: Vec<u8>,
}

impl Clone for CmsCertificate {
    fn clone(&self) -> Self {
        Self {
            cert: self.cert.clone(),
            key: self.key.clone(),
            cert_id: self.cert_id.clone(),
        }
    }
}

impl CmsCertificate {
    /// 加载CMS签名证书和私钥
    ///
    /// 从文件路径加载证书和私钥，支持PEM和DER双格式。
    ///
    /// # Arguments
    /// * `cert_path` - 证书文件路径（支持.pem或.der格式）
    /// * `key_path` - 私钥文件路径（支持.pem或.der格式，可选密码）
    ///
    /// # Returns
    /// * `Ok(CmsCertificate)` - 加载成功
    /// * `Err(CertLoadError)` - 加载失败（文件不存在、格式错误、密码错误等）
    ///
    /// # Format Support
    /// - PEM格式：Base64编码，带-----BEGIN CERTIFICATE-----头部
    /// - DER格式：二进制ASN.1编码
    /// - 自动检测格式（基于文件内容）
    pub(crate) fn load(cert_path: &str, key_path: &str) -> Result<Self, CertLoadError> {
        // PEM/DER双格式加载，由framework::cert模块自动检测格式
        let cert = cert::load_x509(cert_path)?;
        let key = cert::load_private_key(key_path, None)?;
        // 提取证书ID：从SKI扩展中获取20字节SHA-1哈希
        let cert_id = cert::extract_subject_key_id(&cert)?;
        Ok(Self { cert, key, cert_id })
    }

    /// 获取证书引用
    #[allow(dead_code)]
    pub(crate) fn cert(&self) -> &X509 {
        &self.cert
    }

    /// 获取私钥引用
    #[allow(dead_code)]
    pub(crate) fn key(&self) -> &PKey<openssl::pkey::Private> {
        &self.key
    }

    /// 获取证书ID
    ///
    /// 返回Subject Key Identifier（SKI），用于签名时与数据拼接。
    /// SKI是20字节的SHA-1哈希值，唯一标识证书公钥。
    pub(crate) fn cert_id(&self) -> &[u8] {
        &self.cert_id
    }

    /// 解构证书，获取所有权
    ///
    /// 返回证书、私钥和证书ID的所有权，用于需要转移所有权的场景。
    pub(crate) fn take(self) -> (X509, PKey<openssl::pkey::Private>, Vec<u8>) {
        (self.cert, self.key, self.cert_id)
    }

    /// 转换为内部证书
    pub(crate) fn into_inner(self) -> X509 {
        self.cert
    }
}

/// CA根证书
///
/// 封装CA根证书，用于验签时验证证书链。
pub(crate) struct CaCertificate {
    /// CA根证书
    cert: X509,
}

impl CaCertificate {
    /// 加载CA根证书
    ///
    /// 从文件路径加载CA根证书，支持PEM和DER双格式。
    ///
    /// 架构决策：PEM/DER双格式支持（ADR-0004）
    ///
    /// # Arguments
    /// * `path` - 证书文件路径（支持.pem或.der格式）
    ///
    /// # Returns
    /// * `Ok(CaCertificate)` - 加载成功
    /// * `Err(CertLoadError)` - 加载失败
    pub(crate) fn load(path: &str) -> Result<Self, CertLoadError> {
        let cert = cert::load_x509(path)?;
        Ok(Self { cert })
    }

    /// 获取证书引用
    pub(crate) fn cert(&self) -> &X509 {
        &self.cert
    }

    /// 转换为内部证书
    #[allow(dead_code)]
    pub(crate) fn into_cert(self) -> X509 {
        self.cert
    }
}

/// CRL吊销列表
///
/// 封装证书吊销列表（Certificate Revocation List），用于验签时检查证书是否被吊销。
///
/// 架构决策：统一使用OpenSSL处理CRL
/// 详见 ADR-0004: Unified OpenSSL for TLS and CMS
///
/// 用途：
/// - 验签时检查签名证书是否在吊销列表中
/// - TLS握手时验证客户端证书状态
pub(crate) struct CertificateRevocationList {
    /// CRL吊销列表
    crl: X509Crl,
}

impl CertificateRevocationList {
    /// 加载CRL吊销列表
    ///
    /// 从文件路径加载CRL，支持PEM和DER双格式。
    ///
    /// 架构决策：PEM/DER双格式支持（ADR-0004）
    ///
    /// # Arguments
    /// * `path` - CRL文件路径（支持.pem或.der格式）
    ///
    /// # Returns
    /// * `Ok(CertificateRevocationList)` - 加载成功
    /// * `Err(CertLoadError)` - 加载失败
    pub(crate) fn load(path: &str) -> Result<Self, CertLoadError> {
        let crl = cert::load_crl(path)?;
        Ok(Self { crl })
    }

    /// 获取CRL引用
    #[allow(dead_code)]
    pub(crate) fn crl(&self) -> &X509Crl {
        &self.crl
    }

    /// 转换为内部CRL
    pub(crate) fn into_inner(self) -> X509Crl {
        self.crl
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
    use openssl::x509::extension::SubjectKeyIdentifier;
    use openssl::x509::{X509Builder, X509NameBuilder};
    use std::fs;

    /// 创建测试用的ECC-256证书和私钥
    ///
    /// 生成自签名证书用于单元测试：
    /// - 算法：ECC-256（P-256曲线）
    /// - 有效期：365天
    /// - 包含SKI扩展（用于cert_id提取）
    fn create_test_certificate_and_key() -> (Vec<u8>, Vec<u8>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "Test Certificate")
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

        // 添加SKI扩展，用于cert_id提取
        let context = builder.x509v3_context(None, None);
        let ski = SubjectKeyIdentifier::new().build(&context).unwrap();
        builder.append_extension(ski).unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        (
            cert.to_pem().unwrap(),
            pkey.private_key_to_pem_pkcs8().unwrap(),
        )
    }

    /// 场景：加载PEM格式证书
    /// 预期：成功加载并提取cert_id
    #[test]
    fn loading_pem_certificate_succeeds() {
        let temp_dir = std::env::temp_dir().join("cert_loader_pem_test");
        fs::create_dir_all(&temp_dir).unwrap();

        let (cert_pem, key_pem) = create_test_certificate_and_key();
        let cert_path = temp_dir.join("test.crt");
        let key_path = temp_dir.join("test.key");
        fs::write(&cert_path, &cert_pem).unwrap();
        fs::write(&key_path, &key_pem).unwrap();

        let result = CmsCertificate::load(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
        assert!(result.is_ok());

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    /// 场景：加载DER格式证书
    /// 预期：成功加载（ADR-0004 PEM/DER双格式支持）
    #[test]
    fn loading_der_certificate_succeeds() {
        let temp_dir = std::env::temp_dir().join("cert_loader_der_test");
        fs::create_dir_all(&temp_dir).unwrap();

        let (cert_pem, key_pem) = create_test_certificate_and_key();
        // 将PEM转换为DER格式
        let cert = X509::from_pem(&cert_pem).unwrap();
        let cert_der = cert.to_der().unwrap();

        let cert_path = temp_dir.join("test.der");
        let key_path = temp_dir.join("test.key");
        fs::write(&cert_path, &cert_der).unwrap();
        fs::write(&key_path, &key_pem).unwrap();

        let result = CmsCertificate::load(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
        assert!(result.is_ok());

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    /// 场景：验证cert_id提取
    /// 预期：cert_id为20字节SHA-1哈希（SKI算法）
    #[test]
    fn cms_certificate_contains_cert_id() {
        let temp_dir = std::env::temp_dir().join("cert_loader_ski_test");
        fs::create_dir_all(&temp_dir).unwrap();

        let (cert_pem, key_pem) = create_test_certificate_and_key();
        let cert_path = temp_dir.join("test.crt");
        let key_path = temp_dir.join("test.key");
        fs::write(&cert_path, &cert_pem).unwrap();
        fs::write(&key_path, &key_pem).unwrap();

        let cms_cert =
            CmsCertificate::load(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap();

        // SKI是20字节的SHA-1哈希值
        assert!(!cms_cert.cert_id().is_empty());
        assert_eq!(cms_cert.cert_id().len(), 20);

        fs::remove_dir_all(&temp_dir).unwrap();
    }
}
