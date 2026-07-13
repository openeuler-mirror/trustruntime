//! 测试CRL生成模块
//!
//! 提供CRL吊销列表动态生成功能，用于测试证书吊销场景。

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::x509::extension::{AuthorityKeyIdentifier, CrlNumber};
use openssl::x509::{X509Builder, X509CrlBuilder};

/// 为指定证书生成CRL
///
/// 用于动态创建吊销指定序列号证书的CRL。
///
/// # Arguments
/// * `ca_pem` - CA证书PEM
/// * `ca_key_pem` - CA私钥PEM
/// * `serial_to_revoke` - 待吊销证书的序列号
///
/// # Returns
/// CRL PEM数据
pub fn generate_crl_for_cert(ca_pem: &[u8], ca_key_pem: &[u8], serial_to_revoke: u32) -> Vec<u8> {
    let ca_cert = openssl::x509::X509::from_pem(ca_pem).unwrap();
    let ca_key = PKey::private_key_from_pem(ca_key_pem).unwrap();

    let mut crl_builder = X509CrlBuilder::new().unwrap();
    crl_builder.set_issuer_name(ca_cert.subject_name()).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(3650).unwrap();
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
    let serial = BigNum::from_u32(serial_to_revoke).unwrap();
    revoked_entry
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    revoked_entry.set_revocation_date(&not_before).unwrap();
    let revoked = revoked_entry.build();

    crl_builder.add_revoked(revoked).unwrap();

    crl_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    crl_builder.build().unwrap().to_pem().unwrap()
}