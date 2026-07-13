//! 测试证书生成模块
//!
//! 使用OpenSSL动态生成各类测试证书：
//! - CA证书和签名者证书（有效期10年）
//! - 过期签名者证书（2000-01-01至2001-09-09）
//! - 未生效签名者证书（365天后生效）
//! - 已吊销签名者证书（被CRL吊销）
//! - 自签名证书（无CA签发链）
//!
//! 所有证书使用ECC-256曲线（X9_62_PRIME256V1），与生产环境一致。

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, CrlNumber, SubjectKeyIdentifier};
use openssl::x509::{X509Builder, X509CrlBuilder, X509NameBuilder};

/// 证书包类型
///
/// 包含5个元素的元组：
/// 1. CA证书PEM
/// 2. 有效签名者证书PEM
/// 3. 有效签名者私钥PEM
/// 4. 测试用特殊证书PEM（过期/吊销/未生效）
/// 5. 测试用特殊私钥PEM
pub type CertBundle = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// 生成CA证书和签名者证书
///
/// 使用ECC-256曲线生成测试用的证书链：
/// 1. 自签名CA证书（有效期10年）
/// 2. CA签发的签名者证书（有效期10年）
///
/// # Returns
/// 元组包含：
/// - CA证书PEM
/// - 签名者证书PEM
/// - 签名者私钥PEM（PKCS8格式）
pub fn generate_ca_and_signer() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
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

    let signer_key = EcKey::generate(&group).unwrap();
    let signer_pkey = PKey::from_ec_key(signer_key.clone()).unwrap();

    let mut signer_name = X509NameBuilder::new().unwrap();
    signer_name
        .append_entry_by_text("CN", "Test Signer")
        .unwrap();
    let signer_name = signer_name.build();

    let mut signer_builder = X509Builder::new().unwrap();
    signer_builder.set_version(2).unwrap();
    signer_builder.set_subject_name(&signer_name).unwrap();
    signer_builder.set_issuer_name(&ca_name).unwrap();
    signer_builder.set_pubkey(&signer_pkey).unwrap();
    signer_builder.set_not_before(&not_before).unwrap();
    signer_builder.set_not_after(&not_after).unwrap();

    let serial2 = BigNum::from_u32(2).unwrap();
    signer_builder
        .set_serial_number(&serial2.to_asn1_integer().unwrap())
        .unwrap();

    let context2 = signer_builder.x509v3_context(Some(&ca_cert), None);
    let ski2 = SubjectKeyIdentifier::new().build(&context2).unwrap();
    signer_builder.append_extension(ski2).unwrap();

    signer_builder
        .sign(&ca_pkey, MessageDigest::sha256())
        .unwrap();
    let signer_cert = signer_builder.build();

    (
        ca_cert.to_pem().unwrap(),
        signer_cert.to_pem().unwrap(),
        signer_pkey.private_key_to_pem_pkcs8().unwrap(),
    )
}

/// 生成过期证书包
///
/// 用于测试错误场景E07-E08（证书过期验签失败）。
/// 生成两个签名者证书：
/// - 有效签名者证书（有效期10年）
/// - 过期签名者证书（2000-01-01至2001-09-09）
///
/// # Returns
/// CertBundle元组：
/// - CA证书PEM
/// - 有效签名者证书PEM
/// - 有效签名者私钥PEM
/// - 过期签名者证书PEM
/// - 过期签名者私钥PEM
pub fn generate_expired_signer_cert() -> CertBundle {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ca_key = EcKey::generate(&group).unwrap();
    let ca_pkey = PKey::from_ec_key(ca_key.clone()).unwrap();

    let mut ca_name = X509NameBuilder::new().unwrap();
    ca_name.append_entry_by_text("CN", "Test CA").unwrap();
    let ca_name = ca_name.build();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(3650).unwrap();

    let mut ca_builder = X509Builder::new().unwrap();
    ca_builder.set_version(2).unwrap();
    ca_builder.set_subject_name(&ca_name).unwrap();
    ca_builder.set_issuer_name(&ca_name).unwrap();
    ca_builder.set_pubkey(&ca_pkey).unwrap();
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

    let valid_signer_key = EcKey::generate(&group).unwrap();
    let valid_signer_pkey = PKey::from_ec_key(valid_signer_key.clone()).unwrap();

    let mut valid_signer_name = X509NameBuilder::new().unwrap();
    valid_signer_name
        .append_entry_by_text("CN", "Test Valid Signer")
        .unwrap();
    let valid_signer_name = valid_signer_name.build();

    let mut valid_signer_builder = X509Builder::new().unwrap();
    valid_signer_builder.set_version(2).unwrap();
    valid_signer_builder
        .set_subject_name(&valid_signer_name)
        .unwrap();
    valid_signer_builder.set_issuer_name(&ca_name).unwrap();
    valid_signer_builder.set_pubkey(&valid_signer_pkey).unwrap();
    valid_signer_builder.set_not_before(&not_before).unwrap();
    valid_signer_builder.set_not_after(&not_after).unwrap();

    let serial_valid = BigNum::from_u32(100).unwrap();
    valid_signer_builder
        .set_serial_number(&serial_valid.to_asn1_integer().unwrap())
        .unwrap();

    let context_valid = valid_signer_builder.x509v3_context(Some(&ca_cert), None);
    let ski_valid = SubjectKeyIdentifier::new().build(&context_valid).unwrap();
    valid_signer_builder.append_extension(ski_valid).unwrap();

    valid_signer_builder
        .sign(&ca_pkey, MessageDigest::sha256())
        .unwrap();
    let valid_signer_cert = valid_signer_builder.build();

    let expired_signer_key = EcKey::generate(&group).unwrap();
    let expired_signer_pkey = PKey::from_ec_key(expired_signer_key.clone()).unwrap();

    let mut expired_signer_name = X509NameBuilder::new().unwrap();
    expired_signer_name
        .append_entry_by_text("CN", "Test Expired Signer")
        .unwrap();
    let expired_signer_name = expired_signer_name.build();

    let mut expired_signer_builder = X509Builder::new().unwrap();
    expired_signer_builder.set_version(2).unwrap();
    expired_signer_builder
        .set_subject_name(&expired_signer_name)
        .unwrap();
    expired_signer_builder.set_issuer_name(&ca_name).unwrap();
    expired_signer_builder
        .set_pubkey(&expired_signer_pkey)
        .unwrap();

    let expired_not_before = Asn1Time::from_unix(946684800).unwrap();
    let expired_not_after = Asn1Time::from_unix(1000000000).unwrap();
    expired_signer_builder
        .set_not_before(&expired_not_before)
        .unwrap();
    expired_signer_builder
        .set_not_after(&expired_not_after)
        .unwrap();

    let serial_expired = BigNum::from_u32(101).unwrap();
    expired_signer_builder
        .set_serial_number(&serial_expired.to_asn1_integer().unwrap())
        .unwrap();

    let context_expired = expired_signer_builder.x509v3_context(Some(&ca_cert), None);
    let ski_expired = SubjectKeyIdentifier::new().build(&context_expired).unwrap();
    expired_signer_builder
        .append_extension(ski_expired)
        .unwrap();

    expired_signer_builder
        .sign(&ca_pkey, MessageDigest::sha256())
        .unwrap();
    let expired_signer_cert = expired_signer_builder.build();

    (
        ca_cert.to_pem().unwrap(),
        valid_signer_cert.to_pem().unwrap(),
        valid_signer_pkey.private_key_to_pem_pkcs8().unwrap(),
        expired_signer_cert.to_pem().unwrap(),
        expired_signer_pkey.private_key_to_pem_pkcs8().unwrap(),
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
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ca_key = EcKey::generate(&group).unwrap();
    let ca_pkey = PKey::from_ec_key(ca_key.clone()).unwrap();

    let mut ca_name = X509NameBuilder::new().unwrap();
    ca_name.append_entry_by_text("CN", "Test CA").unwrap();
    let ca_name = ca_name.build();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(3650).unwrap();

    let mut ca_builder = X509Builder::new().unwrap();
    ca_builder.set_version(2).unwrap();
    ca_builder.set_subject_name(&ca_name).unwrap();
    ca_builder.set_issuer_name(&ca_name).unwrap();
    ca_builder.set_pubkey(&ca_pkey).unwrap();
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

    let valid_signer_key = EcKey::generate(&group).unwrap();
    let valid_signer_pkey = PKey::from_ec_key(valid_signer_key.clone()).unwrap();

    let mut valid_signer_name = X509NameBuilder::new().unwrap();
    valid_signer_name
        .append_entry_by_text("CN", "Test Valid Signer")
        .unwrap();
    let valid_signer_name = valid_signer_name.build();

    let mut valid_signer_builder = X509Builder::new().unwrap();
    valid_signer_builder.set_version(2).unwrap();
    valid_signer_builder
        .set_subject_name(&valid_signer_name)
        .unwrap();
    valid_signer_builder.set_issuer_name(&ca_name).unwrap();
    valid_signer_builder.set_pubkey(&valid_signer_pkey).unwrap();
    valid_signer_builder.set_not_before(&not_before).unwrap();
    valid_signer_builder.set_not_after(&not_after).unwrap();

    let serial_valid = BigNum::from_u32(100).unwrap();
    valid_signer_builder
        .set_serial_number(&serial_valid.to_asn1_integer().unwrap())
        .unwrap();

    let context_valid = valid_signer_builder.x509v3_context(Some(&ca_cert), None);
    let ski_valid = SubjectKeyIdentifier::new().build(&context_valid).unwrap();
    valid_signer_builder.append_extension(ski_valid).unwrap();

    valid_signer_builder
        .sign(&ca_pkey, MessageDigest::sha256())
        .unwrap();
    let valid_signer_cert = valid_signer_builder.build();

    let not_yet_valid_signer_key = EcKey::generate(&group).unwrap();
    let not_yet_valid_signer_pkey = PKey::from_ec_key(not_yet_valid_signer_key.clone()).unwrap();

    let mut not_yet_valid_signer_name = X509NameBuilder::new().unwrap();
    not_yet_valid_signer_name
        .append_entry_by_text("CN", "Test Not Yet Valid Signer")
        .unwrap();
    let not_yet_valid_signer_name = not_yet_valid_signer_name.build();

    let mut not_yet_valid_signer_builder = X509Builder::new().unwrap();
    not_yet_valid_signer_builder.set_version(2).unwrap();
    not_yet_valid_signer_builder
        .set_subject_name(&not_yet_valid_signer_name)
        .unwrap();
    not_yet_valid_signer_builder
        .set_issuer_name(&ca_name)
        .unwrap();
    not_yet_valid_signer_builder
        .set_pubkey(&not_yet_valid_signer_pkey)
        .unwrap();

    let not_yet_valid_not_before = Asn1Time::days_from_now(365).unwrap();
    let not_yet_valid_not_after = Asn1Time::days_from_now(3650).unwrap();
    not_yet_valid_signer_builder
        .set_not_before(&not_yet_valid_not_before)
        .unwrap();
    not_yet_valid_signer_builder
        .set_not_after(&not_yet_valid_not_after)
        .unwrap();

    let serial_not_yet_valid = BigNum::from_u32(102).unwrap();
    not_yet_valid_signer_builder
        .set_serial_number(&serial_not_yet_valid.to_asn1_integer().unwrap())
        .unwrap();

    let context_not_yet_valid = not_yet_valid_signer_builder.x509v3_context(Some(&ca_cert), None);
    let ski_not_yet_valid = SubjectKeyIdentifier::new()
        .build(&context_not_yet_valid)
        .unwrap();
    not_yet_valid_signer_builder
        .append_extension(ski_not_yet_valid)
        .unwrap();

    not_yet_valid_signer_builder
        .sign(&ca_pkey, MessageDigest::sha256())
        .unwrap();
    let not_yet_valid_signer_cert = not_yet_valid_signer_builder.build();

    (
        ca_cert.to_pem().unwrap(),
        valid_signer_cert.to_pem().unwrap(),
        valid_signer_pkey.private_key_to_pem_pkcs8().unwrap(),
        not_yet_valid_signer_cert.to_pem().unwrap(),
        not_yet_valid_signer_pkey
            .private_key_to_pem_pkcs8()
            .unwrap(),
    )
}

/// 生成已吊销证书包
///
/// 用于测试错误场景E09-E10（证书吊销验签失败）。
/// 生成一个被CRL吊销的签名者证书。
///
/// # Returns
/// CertBundle元组：
/// - CA证书PEM
/// - 有效签名者证书PEM
/// - 有效签名者私钥PEM
/// - 已吊销签名者证书PEM
/// - 已吊销签名者私钥PEM
///
/// 注意：同时生成包含已吊销证书的CRL（未返回，需单独生成）
pub fn generate_revoked_signer_cert() -> CertBundle {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ca_key = EcKey::generate(&group).unwrap();
    let ca_pkey = PKey::from_ec_key(ca_key.clone()).unwrap();

    let mut ca_name = X509NameBuilder::new().unwrap();
    ca_name.append_entry_by_text("CN", "Test CA").unwrap();
    let ca_name = ca_name.build();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(3650).unwrap();

    let mut ca_builder = X509Builder::new().unwrap();
    ca_builder.set_version(2).unwrap();
    ca_builder.set_subject_name(&ca_name).unwrap();
    ca_builder.set_issuer_name(&ca_name).unwrap();
    ca_builder.set_pubkey(&ca_pkey).unwrap();
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

    let valid_signer_key = EcKey::generate(&group).unwrap();
    let valid_signer_pkey = PKey::from_ec_key(valid_signer_key.clone()).unwrap();

    let mut valid_signer_name = X509NameBuilder::new().unwrap();
    valid_signer_name
        .append_entry_by_text("CN", "Test Valid Signer")
        .unwrap();
    let valid_signer_name = valid_signer_name.build();

    let mut valid_signer_builder = X509Builder::new().unwrap();
    valid_signer_builder.set_version(2).unwrap();
    valid_signer_builder
        .set_subject_name(&valid_signer_name)
        .unwrap();
    valid_signer_builder.set_issuer_name(&ca_name).unwrap();
    valid_signer_builder.set_pubkey(&valid_signer_pkey).unwrap();
    valid_signer_builder.set_not_before(&not_before).unwrap();
    valid_signer_builder.set_not_after(&not_after).unwrap();

    let serial_valid = BigNum::from_u32(100).unwrap();
    valid_signer_builder
        .set_serial_number(&serial_valid.to_asn1_integer().unwrap())
        .unwrap();

    let context_valid = valid_signer_builder.x509v3_context(Some(&ca_cert), None);
    let ski_valid = SubjectKeyIdentifier::new().build(&context_valid).unwrap();
    valid_signer_builder.append_extension(ski_valid).unwrap();

    valid_signer_builder
        .sign(&ca_pkey, MessageDigest::sha256())
        .unwrap();
    let valid_signer_cert = valid_signer_builder.build();

    let revoked_signer_key = EcKey::generate(&group).unwrap();
    let revoked_signer_pkey = PKey::from_ec_key(revoked_signer_key.clone()).unwrap();

    let mut revoked_signer_name = X509NameBuilder::new().unwrap();
    revoked_signer_name
        .append_entry_by_text("CN", "Test Revoked Signer")
        .unwrap();
    let revoked_signer_name = revoked_signer_name.build();

    let mut revoked_signer_builder = X509Builder::new().unwrap();
    revoked_signer_builder.set_version(2).unwrap();
    revoked_signer_builder
        .set_subject_name(&revoked_signer_name)
        .unwrap();
    revoked_signer_builder.set_issuer_name(&ca_name).unwrap();
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
    revoked_signer_builder
        .append_extension(ski_revoked)
        .unwrap();

    revoked_signer_builder
        .sign(&ca_pkey, MessageDigest::sha256())
        .unwrap();
    let revoked_signer_cert = revoked_signer_builder.build();

    let mut crl_builder = X509CrlBuilder::new().unwrap();
    crl_builder.set_issuer_name(&ca_name).unwrap();
    crl_builder.set_last_update(&not_before).unwrap();
    crl_builder.set_next_update(&not_after).unwrap();

    let crl_number = CrlNumber::new(BigNum::from_u32(1).unwrap()).unwrap();
    let crl_num_ext = crl_number.build().unwrap();
    crl_builder.append_extension(crl_num_ext).unwrap();

    let mut temp_builder = X509Builder::new().unwrap();
    temp_builder.set_subject_name(ca_cert.subject_name()).unwrap();
    let context = temp_builder.x509v3_context(Some(&ca_cert), None);
    let aki = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&context)
        .unwrap();
    crl_builder.append_extension(aki).unwrap();

    let mut revoked_entry = openssl::x509::X509RevokedBuilder::new().unwrap();
    revoked_entry
        .set_serial_number(&serial_revoked.to_asn1_integer().unwrap())
        .unwrap();
    revoked_entry.set_revocation_date(&not_before).unwrap();
    let revoked = revoked_entry.build();

    crl_builder.add_revoked(revoked).unwrap();

    crl_builder.sort().unwrap();
    crl_builder.sign(&ca_pkey, MessageDigest::sha256()).unwrap();
    let _crl = crl_builder.build().unwrap();

    (
        ca_cert.to_pem().unwrap(),
        valid_signer_cert.to_pem().unwrap(),
        valid_signer_pkey.private_key_to_pem_pkcs8().unwrap(),
        revoked_signer_cert.to_pem().unwrap(),
        revoked_signer_pkey.private_key_to_pem_pkcs8().unwrap(),
    )
}

/// 生成自签名证书
///
/// 用于测试错误场景E11-E12（自签名证书验签失败）。
/// 证书主体和颁发者相同，无CA签发链。
///
/// # Returns
/// 元组：
/// - 自签名证书PEM（前两个元素相同）
/// - 自签名证书PEM
/// - 私钥PEM
pub fn generate_self_signed_signer_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let signer_key = EcKey::generate(&group).unwrap();
    let signer_pkey = PKey::from_ec_key(signer_key.clone()).unwrap();

    let mut signer_name = X509NameBuilder::new().unwrap();
    signer_name
        .append_entry_by_text("CN", "Test Self-Signed Signer")
        .unwrap();
    let signer_name = signer_name.build();

    let mut signer_builder = X509Builder::new().unwrap();
    signer_builder.set_version(2).unwrap();
    signer_builder.set_subject_name(&signer_name).unwrap();
    signer_builder.set_issuer_name(&signer_name).unwrap();
    signer_builder.set_pubkey(&signer_pkey).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(3650).unwrap();
    signer_builder.set_not_before(&not_before).unwrap();
    signer_builder.set_not_after(&not_after).unwrap();

    let serial = BigNum::from_u32(1).unwrap();
    signer_builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();

    let context = signer_builder.x509v3_context(None, None);
    let ski = SubjectKeyIdentifier::new().build(&context).unwrap();
    signer_builder.append_extension(ski).unwrap();

    signer_builder
        .sign(&signer_pkey, MessageDigest::sha256())
        .unwrap();
    let signer_cert = signer_builder.build();

    (
        signer_cert.to_pem().unwrap(),
        signer_cert.to_pem().unwrap(),
        signer_pkey.private_key_to_pem_pkcs8().unwrap(),
    )
}

/// 从PEM证书中提取证书ID
///
/// # Arguments
/// * `cert_pem` - 证书PEM数据
///
/// # Returns
/// Subject Key Identifier原始字节，无SKI时返回空Vec
pub fn extract_cert_id_from_pem(cert_pem: &[u8]) -> Vec<u8> {
    let cert = openssl::x509::X509::from_pem(cert_pem).unwrap();
    cert.subject_key_id()
        .map(|ski| ski.as_slice().to_vec())
        .unwrap_or_default()
}