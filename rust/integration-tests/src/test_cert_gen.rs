//! 测试证书生成模块
//!
//! 复用 cert-gen 库，提供 PEM 格式的便捷包装函数。
//!
//! ## 功能
//! - CA证书和签名者证书生成
//! - 过期证书包生成
//! - 未生效证书包生成
//! - 已吊销证书包生成
//! - 自签名证书生成
//!
//! 所有证书使用 ECC-256 曲线（X9_62_PRIME256V1），与生产环境一致。

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::EcGroup;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::extension::{AuthorityKeyIdentifier, SubjectKeyIdentifier};
use openssl::x509::{X509Builder, X509NameBuilder};

use cert_gen::certificate::{
    create_ca_cert, create_expired_cert, create_not_yet_valid_cert, create_self_signed_cert,
    create_signer_cert,
};

/// 证书包类型
///
/// 包含5个元素的元组：
/// 1. CA证书PEM
/// 2. 有效签名者证书PEM
/// 3. 有效签名者私钥PEM
/// 4. 测试用特殊证书PEM（过期/吊销/未生效）
/// 5. 测试用特殊私钥PEM
pub type CertBundle = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// 吊销证书包类型（包含CA私钥用于签名CRL）
///
/// 包含6个元素的元组：
/// 1. CA证书PEM
/// 2. 有效签名者证书PEM
/// 3. 有效签名者私钥PEM
/// 4. 已吊销签名者证书PEM（序列号101）
/// 5. 已吊销签名者私钥PEM
/// 6. CA私钥PEM（用于签名CRL）
#[allow(clippy::type_complexity)]
pub type RevokedCertBundle = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn get_group() -> EcGroup {
    EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()
}

/// 生成CA证书和签名者证书
///
/// 使用 ECC-256 曲线生成测试用的证书链：
/// 1. 自签名CA证书（有效期10年）
/// 2. CA签发的签名者证书（有效期10年）
///
/// # Returns
/// 元组包含：
/// - CA证书PEM
/// - 签名者证书PEM
/// - 签名者私钥PEM（PKCS8格式）
pub fn generate_ca_and_signer() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let group = get_group();
    let (ca_cert, ca_pkey, _ca_id) = create_ca_cert(&group, "Test CA");
    let (signer_cert, signer_pkey, _signer_id) =
        create_signer_cert(&group, &ca_cert, &ca_pkey, "Test Signer".to_string());
    (
        ca_cert.to_pem().unwrap(),
        signer_cert.to_pem().unwrap(),
        signer_pkey.private_key_to_pem_pkcs8().unwrap(),
    )
}

/// 生成过期证书包
///
/// 用于测试错误场景 E07-E08（证书过期验签失败）。
/// 生成两个签名者证书：
/// - 有效签名者证书（有效期10年）
/// - 过期签名者证书（2000-01-01至2010-01-01）
///
/// # Returns
/// CertBundle元组：
/// - CA证书PEM
/// - 有效签名者证书PEM
/// - 有效签名者私钥PEM
/// - 过期签名者证书PEM
/// - 过期签名者私钥PEM
pub fn generate_expired_signer_cert() -> CertBundle {
    let group = get_group();
    let (ca_cert, ca_pkey, _) = create_ca_cert(&group, "Test CA");
    let (valid_cert, valid_pkey, _) =
        create_signer_cert(&group, &ca_cert, &ca_pkey, "Test Valid Signer".to_string());
    let (expired_cert, expired_pkey, _) =
        create_expired_cert(&group, &ca_cert, &ca_pkey, "Test Expired Signer");
    (
        ca_cert.to_pem().unwrap(),
        valid_cert.to_pem().unwrap(),
        valid_pkey.private_key_to_pem_pkcs8().unwrap(),
        expired_cert.to_pem().unwrap(),
        expired_pkey.private_key_to_pem_pkcs8().unwrap(),
    )
}

/// 生成未生效证书包
///
/// 用于测试边界场景（证书尚未生效）。
/// 签名者证书生效日期为365天后，当前无法使用。
///
/// # Returns
/// CertBundle元组：
/// - CA证书PEM
/// - 有效签名者证书PEM
/// - 有效签名者私钥PEM
/// - 未生效签名者证书PEM
/// - 未生效签名者私钥PEM
pub fn generate_not_yet_valid_signer_cert() -> CertBundle {
    let group = get_group();
    let (ca_cert, ca_pkey, _) = create_ca_cert(&group, "Test CA");
    let (valid_cert, valid_pkey, _) =
        create_signer_cert(&group, &ca_cert, &ca_pkey, "Test Valid Signer".to_string());
    let (not_yet_valid_cert, not_yet_valid_pkey, _) =
        create_not_yet_valid_cert(&group, &ca_cert, &ca_pkey, "Test Not Yet Valid Signer");
    (
        ca_cert.to_pem().unwrap(),
        valid_cert.to_pem().unwrap(),
        valid_pkey.private_key_to_pem_pkcs8().unwrap(),
        not_yet_valid_cert.to_pem().unwrap(),
        not_yet_valid_pkey.private_key_to_pem_pkcs8().unwrap(),
    )
}

/// 生成已吊销证书包
///
/// 用于测试错误场景 E09-E10（证书吊销验签失败）。
/// 生成一个将被CRL吊销的签名者证书（序列号固定为101）。
///
/// 注意：此函数仅生成证书，CRL需单独生成（使用 test_crl_gen 模块）。
/// CRL生成时需使用序列号 101。
///
/// # Returns
/// 6元素元组：
/// - CA证书PEM
/// - 有效签名者证书PEM
/// - 有效签名者私钥PEM
/// - 已吊销签名者证书PEM（序列号101）
/// - 已吊销签名者私钥PEM
/// - CA私钥PEM（用于签名CRL）
pub fn generate_revoked_signer_cert() -> RevokedCertBundle {
    let group = get_group();
    let (ca_cert, ca_pkey, _) = create_ca_cert(&group, "Test CA");
    let (valid_cert, valid_pkey, _) =
        create_signer_cert(&group, &ca_cert, &ca_pkey, "Test Valid Signer".to_string());

    let revoked_signer_key = openssl::ec::EcKey::generate(&group).unwrap();
    let revoked_signer_pkey = PKey::from_ec_key(revoked_signer_key.clone()).unwrap();

    let mut revoked_signer_name = X509NameBuilder::new().unwrap();
    revoked_signer_name
        .append_entry_by_text("CN", "Test Revoked Signer")
        .unwrap();
    let revoked_signer_name = revoked_signer_name.build();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(3650).unwrap();

    let mut revoked_signer_builder = X509Builder::new().unwrap();
    revoked_signer_builder.set_version(2).unwrap();
    revoked_signer_builder
        .set_subject_name(&revoked_signer_name)
        .unwrap();
    revoked_signer_builder
        .set_issuer_name(ca_cert.subject_name())
        .unwrap();
    revoked_signer_builder
        .set_pubkey(&revoked_signer_pkey)
        .unwrap();
    revoked_signer_builder.set_not_before(&not_before).unwrap();
    revoked_signer_builder.set_not_after(&not_after).unwrap();

    let serial_revoked = BigNum::from_u32(101).unwrap();
    revoked_signer_builder
        .set_serial_number(&serial_revoked.to_asn1_integer().unwrap())
        .unwrap();

    let context_revoked = revoked_signer_builder.x509v3_context(Some(&ca_cert), None);
    let ski_revoked = SubjectKeyIdentifier::new().build(&context_revoked).unwrap();
    let aki_revoked = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&context_revoked)
        .unwrap();

    revoked_signer_builder
        .append_extension(ski_revoked)
        .unwrap();
    revoked_signer_builder
        .append_extension(aki_revoked)
        .unwrap();

    revoked_signer_builder
        .sign(&ca_pkey, MessageDigest::sha256())
        .unwrap();
    let revoked_signer_cert = revoked_signer_builder.build();

    (
        ca_cert.to_pem().unwrap(),
        valid_cert.to_pem().unwrap(),
        valid_pkey.private_key_to_pem_pkcs8().unwrap(),
        revoked_signer_cert.to_pem().unwrap(),
        revoked_signer_pkey.private_key_to_pem_pkcs8().unwrap(),
        ca_pkey.private_key_to_pem_pkcs8().unwrap(),
    )
}

/// 生成自签名证书
///
/// 用于测试错误场景 E11-E12（自签名证书验签失败）。
/// 证书主体和颁发者相同，无CA签发链。
///
/// # Returns
/// 元组：
/// - 自签名证书PEM（前两个元素相同）
/// - 自签名证书PEM
/// - 私钥PEM
pub fn generate_self_signed_signer_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let group = get_group();
    let (cert, pkey, _) = create_self_signed_cert(&group, "Test Self-Signed Signer");
    (
        cert.to_pem().unwrap(),
        cert.to_pem().unwrap(),
        pkey.private_key_to_pem_pkcs8().unwrap(),
    )
}

/// 从PEM证书中提取证书ID
///
/// # Arguments
/// * `cert_pem` - 证书PEM数据
///
/// # Returns
/// Subject Key Identifier 原始字节，无 SKI 时返回空 Vec
pub fn extract_cert_id_from_pem(cert_pem: &[u8]) -> Vec<u8> {
    let cert = openssl::x509::X509::from_pem(cert_pem).unwrap();
    cert.subject_key_id()
        .map(|ski| ski.as_slice().to_vec())
        .unwrap_or_default()
}
