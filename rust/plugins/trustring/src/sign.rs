//! CMS签名器模块
//!
//! 职责：
//! - 封装ECC-256签名逻辑
//! - 生成CMS签名数据（DER编码）
//! - 管理签名证书和私钥
//!
//! 架构决策：
//! - 统一使用OpenSSL处理CMS签名（ADR-0004: Unified OpenSSL for TLS and CMS）
//! - 优势：消除双加密栈问题、证书类型一致、错误处理统一
//!
//! 依赖：
//! - cert_loader模块：证书加载
//! - openssl库：CMS签名实现

use crate::cert_loader::CmsCertificate;
use openssl::cms::CMSOptions;
use openssl::pkey::PKey;
use openssl::x509::X509;
use thiserror::Error;

/// 签名错误类型
///
/// 封装OpenSSL签名过程中的错误
#[derive(Error, Debug)]
pub(crate) enum SignError {
    /// OpenSSL错误（证书格式、私钥、签名算法等）
    #[error("openssl error: {0}")]
    OpenSslError(#[from] openssl::error::ErrorStack),
}

/// CMS签名器
///
/// 封装ECC-256签名逻辑，管理签名证书和私钥。
///
/// 优势：
/// - 消除双加密栈问题（rustls + OpenSSL）
/// - 证书类型一致（openssl::X509 和 openssl::PKey）
/// - 错误处理统一
pub(crate) struct Signer {
    /// 签名证书
    cert: X509,
    /// 签名私钥
    key: PKey<openssl::pkey::Private>,
    /// 证书ID（Subject Key Identifier，20字节SHA-1哈希）
    cert_id: Vec<u8>,
}

impl Signer {
    /// 从CmsCertificate创建签名器
    ///
    /// # Arguments
    /// * `cms_cert` - CMS证书对象（包含证书、私钥、证书ID）
    ///
    /// # Returns
    /// 签名器实例
    pub(crate) fn new(cms_cert: CmsCertificate) -> Self {
        let (cert, key, cert_id) = cms_cert.take();
        Self { cert, key, cert_id }
    }

    /// 获取证书ID
    ///
    /// # Returns
    /// 证书ID（Subject Key Identifier，20字节SHA-1哈希）
    pub(crate) fn cert_id(&self) -> &[u8] {
        &self.cert_id
    }

    /// 签名数据
    ///
    /// 对数据+证书ID进行CMS签名，返回DER编码的签名数据。
    ///
    /// 签名算法：
    /// 1. 拼接输入：data || cert_id
    /// 2. 使用OpenSSL CMS签名（BINARY模式）
    /// 3. 返回DER编码的CMS结构
    ///
    /// 架构决策：统一使用OpenSSL CMS签名（ADR-0004）
    /// 原因：符合RFC 5652标准，支持证书链验证
    ///
    /// # Arguments
    /// * `data` - 待签名的原始数据
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - DER编码的CMS签名数据
    /// * `Err(SignError)` - 签名失败（OpenSSL错误）
    pub(crate) fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignError> {
        self.sign_with_input(data, &self.cert_id)
    }

    /// 使用外部证书ID签名数据
    ///
    /// 对数据+外部证书ID进行CMS签名，用于验签+签名场景。
    ///
    /// 签名算法：
    /// 1. 拼接输入：data || external_id
    /// 2. 使用OpenSSL CMS签名（BINARY模式）
    /// 3. 返回DER编码的CMS结构
    ///
    /// 用途：
    /// - 验签+签名场景（0x12消息类型）
    /// - 保持签名数据的连续性（外部证书ID来自验签方）
    ///
    /// # Arguments
    /// * `data` - 待签名的原始数据
    /// * `external_id` - 外部证书ID（来自验签方）
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - DER编码的CMS签名数据
    /// * `Err(SignError)` - 签名失败（OpenSSL错误）
    pub(crate) fn sign_with_id(
        &self,
        data: &[u8],
        external_id: &[u8],
    ) -> Result<Vec<u8>, SignError> {
        self.sign_with_input(data, external_id)
    }

    /// 私有辅助方法：使用指定ID签名数据
    ///
    /// # Arguments
    /// * `data` - 待签名的原始数据
    /// * `id` - 证书ID（内部或外部）
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - DER编码的CMS签名数据
    /// * `Err(SignError)` - 签名失败（OpenSSL错误）
    fn sign_with_input(&self, data: &[u8], id: &[u8]) -> Result<Vec<u8>, SignError> {
        let mut input = data.to_vec();
        input.extend_from_slice(id);

        let cms = openssl::cms::CmsContentInfo::sign(
            Some(&self.cert),
            Some(&self.key),
            None,
            Some(&input),
            CMSOptions::BINARY,
        )?;

        Ok(cms.to_der()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_loader::CmsCertificate;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::extension::{KeyUsage, SubjectKeyIdentifier};
    use openssl::x509::{X509Builder, X509NameBuilder};
    use std::fs;

    /// 创建测试用的ECC-256证书和私钥
    ///
    /// 生成自签名证书，包含Subject Key Identifier扩展和KeyUsage扩展
    fn create_test_cert_and_key() -> (Vec<u8>, Vec<u8>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "Test Signer")
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
        let serial = serial.to_asn1_integer().unwrap();
        builder.set_serial_number(&serial).unwrap();

        let mut ku_builder = KeyUsage::new();
        ku_builder.digital_signature();
        let ku = ku_builder.build().unwrap();
        builder.append_extension(ku).unwrap();

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

    /// 测试：从CmsCertificate创建Signer
    ///
    /// 场景：正常加载证书和私钥创建签名器
    /// 预期：签名器成功创建，cert_id为20字节SHA-1哈希
    #[test]
    fn signer_new_from_cms_certificate() {
        let temp_dir = tempfile::tempdir().unwrap();

        let (cert_pem, key_pem) = create_test_cert_and_key();
        let cert_path = temp_dir.path().join("signer.crt");
        let key_path = temp_dir.path().join("signer.key");
        fs::write(&cert_path, &cert_pem).unwrap();
        fs::write(&key_path, &key_pem).unwrap();

        let cms_cert =
            CmsCertificate::load(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap();

        let signer = Signer::new(cms_cert);
        assert!(!signer.cert_id().is_empty());
        assert_eq!(signer.cert_id().len(), 20);
    }

    /// 测试：签名返回DER编码数据
    ///
    /// 场景：对测试数据进行签名
    /// 预期：返回有效的DER编码CMS数据
    #[test]
    fn sign_returns_der_bytes() {
        let temp_dir = tempfile::tempdir().unwrap();

        let (cert_pem, key_pem) = create_test_cert_and_key();
        let cert_path = temp_dir.path().join("signer.crt");
        let key_path = temp_dir.path().join("signer.key");
        fs::write(&cert_path, &cert_pem).unwrap();
        fs::write(&key_path, &key_pem).unwrap();

        let cms_cert =
            CmsCertificate::load(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap();
        let _cert_id = cms_cert.cert_id().to_vec();

        let signer = Signer::new(cms_cert);

        let data = b"test data to sign";
        let result = signer.sign(data);
        assert!(result.is_ok());

        let der_bytes = result.unwrap();
        assert!(!der_bytes.is_empty());

        // 验证DER编码可被OpenSSL解析
        let cms = openssl::cms::CmsContentInfo::from_der(&der_bytes);
        assert!(cms.is_ok());
    }

    /// 测试：sign_with_id使用外部证书ID
    ///
    /// 场景：使用外部证书ID进行签名（验签+签名场景）
    /// 预期：返回有效的DER编码CMS数据
    #[test]
    fn sign_with_id_uses_external_cert_id() {
        let temp_dir = tempfile::tempdir().unwrap();

        let (cert_pem, key_pem) = create_test_cert_and_key();
        let cert_path = temp_dir.path().join("signer.crt");
        let key_path = temp_dir.path().join("signer.key");
        fs::write(&cert_path, &cert_pem).unwrap();
        fs::write(&key_path, &key_pem).unwrap();

        let cms_cert =
            CmsCertificate::load(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap();

        let signer = Signer::new(cms_cert);

        let data = b"test data";
        let external_id = vec![1u8; 20];

        let result = signer.sign_with_id(data, &external_id);
        assert!(result.is_ok());

        let der_bytes = result.unwrap();
        assert!(!der_bytes.is_empty());
    }

    /// 测试：cert_id返回Subject Key Identifier
    ///
    /// 场景：获取签名器的证书ID
    /// 预期：返回与CmsCertificate相同的证书ID
    #[test]
    fn cert_id_returns_subject_key_id() {
        let temp_dir = tempfile::tempdir().unwrap();

        let (cert_pem, key_pem) = create_test_cert_and_key();
        let cert_path = temp_dir.path().join("signer.crt");
        let key_path = temp_dir.path().join("signer.key");
        fs::write(&cert_path, &cert_pem).unwrap();
        fs::write(&key_path, &key_pem).unwrap();

        let cms_cert =
            CmsCertificate::load(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap();
        let expected_id = cms_cert.cert_id().to_vec();

        let signer = Signer::new(cms_cert);
        assert_eq!(signer.cert_id(), expected_id.as_slice());
    }
}
