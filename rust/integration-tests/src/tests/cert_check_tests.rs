//! 证书状态检查测试模块
//!
//! 测试范围：
//! - CC03: 周期检查间隔默认值
//! - CC04: 周期检查间隔自定义值
//! - CC05: 证书过期检测
//! - CC06: 证书有效检测
//! - CC07: 证书未生效检测
//! - CC08-CC13: 证书用途校验（KeyUsage、ExtendedKeyUsage）
//!
//! 重点验证：证书检查器功能、配置解析、证书用途校验

use integration_tests::test_cert_gen::generate_expired_signer_cert;
use std::fs;
use tempfile::TempDir;

/// CC03: 周期检查间隔默认值
///
/// 测试场景：解析不包含cert_check配置的TOML
///
/// 预期结果：interval_hours默认为24
/// 说明：未配置时使用默认值
#[test]
fn cc03_periodic_check_interval_default() {
    use trustruntime_framework::config::AppConfig;

    let config_content = r#"
[vsock]
port = 12345

[log]
path = "/tmp/test.log"
max_file_size = 10
max_roll_count = 10

[certificate]
signer_cert = "/tmp/signer.crt"
signer_key = "/tmp/signer.key"
ca_root_cert = "/tmp/ca.crt"
comm_cert = "/tmp/comm.crt"
comm_key = "/tmp/comm.key"
comm_ca_root = "/tmp/comm_ca.crt"
"#;

    let config = AppConfig::from_toml(config_content).expect("Failed to parse config");
    assert_eq!(config.cert_check.interval_hours, 24);
}

/// CC04: 周期检查间隔自定义值
///
/// 测试场景：解析包含interval_hours=48的配置
///
/// 预期结果：interval_hours为48
/// 说明：配置文件可自定义检查间隔
#[test]
fn cc04_periodic_check_interval_custom() {
    use trustruntime_framework::config::AppConfig;

    let config_content = r#"
[vsock]
port = 12345

[log]
path = "/tmp/test.log"
max_file_size = 10
max_roll_count = 10

[certificate]
signer_cert = "/tmp/signer.crt"
signer_key = "/tmp/signer.key"
ca_root_cert = "/tmp/ca.crt"
comm_cert = "/tmp/comm.crt"
comm_key = "/tmp/comm.key"
comm_ca_root = "/tmp/comm_ca.crt"

[cert_check]
interval_hours = 48
"#;

    let config = AppConfig::from_toml(config_content).expect("Failed to parse config");
    assert_eq!(config.cert_check.interval_hours, 48);
}

/// CC05: 证书检查器检测过期证书
///
/// 测试场景：使用CertificateChecker检查已过期证书
///
/// 预期结果：status.expired=true
/// 说明：检查器正确识别过期状态
#[test]
fn cc05_certificate_checker_detects_expired() {
    use trustruntime_framework::core::cert_checker::CertificateChecker;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    let (_ca_pem, _, _, expired_pem, _expired_key_pem) = generate_expired_signer_cert();

    let cert_path = temp_dir.path().join("expired.crt");
    fs::write(&cert_path, &expired_pem).expect("Failed to write expired cert");

    let checker = CertificateChecker::new(vec![cert_path.to_str().unwrap().to_string()]);
    let statuses = checker.check_all();

    assert_eq!(statuses.len(), 1);
    assert!(statuses[0].expired);
}

/// CC06: 证书检查器检测有效证书
///
/// 测试场景：使用CertificateChecker检查有效证书（365天有效期）
///
/// 预期结果：expired=false, not_yet_valid=false
/// 说明：检查器正确识别有效状态
#[test]
fn cc06_certificate_checker_detects_valid() {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::extension::SubjectKeyIdentifier;
    use openssl::x509::{X509Builder, X509NameBuilder};
    use trustruntime_framework::core::cert_checker::CertificateChecker;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("Failed to create EC group");
    let key = EcKey::generate(&group).expect("Failed to generate key");
    let pkey = PKey::from_ec_key(key).expect("Failed to create PKey");

    let mut name = X509NameBuilder::new().expect("Failed to create name builder");
    name.append_entry_by_text("CN", "Valid Test Cert")
        .expect("Failed to append CN");
    let name = name.build();

    let mut builder = X509Builder::new().expect("Failed to create builder");
    builder.set_version(2).expect("Failed to set version");
    builder
        .set_subject_name(&name)
        .expect("Failed to set subject");
    builder
        .set_issuer_name(&name)
        .expect("Failed to set issuer");
    builder.set_pubkey(&pkey).expect("Failed to set pubkey");

    let not_before = Asn1Time::days_from_now(0).expect("Failed to create not_before");
    let not_after = Asn1Time::days_from_now(365).expect("Failed to create not_after");
    builder
        .set_not_before(&not_before)
        .expect("Failed to set not_before");
    builder
        .set_not_after(&not_after)
        .expect("Failed to set not_after");

    let serial = BigNum::from_u32(1).expect("Failed to create serial");
    builder
        .set_serial_number(&serial.to_asn1_integer().expect("Failed to convert serial"))
        .expect("Failed to set serial");

    let context = builder.x509v3_context(None, None);
    let ski = SubjectKeyIdentifier::new()
        .build(&context)
        .expect("Failed to build SKI");
    builder.append_extension(ski).expect("Failed to append SKI");

    builder
        .sign(&pkey, MessageDigest::sha256())
        .expect("Failed to sign cert");
    let cert = builder.build();

    let cert_path = temp_dir.path().join("valid.crt");
    fs::write(&cert_path, cert.to_pem().expect("Failed to PEM encode"))
        .expect("Failed to write cert");

    let checker = CertificateChecker::new(vec![cert_path.to_str().unwrap().to_string()]);
    let statuses = checker.check_all();

    assert_eq!(statuses.len(), 1);
    assert!(!statuses[0].expired);
    assert!(!statuses[0].not_yet_valid);
}

/// CC07: 证书检查器检测尚未生效证书
///
/// 测试场景：使用CertificateChecker检查尚未生效证书（not_before在未来365天）
///
/// 预期结果：not_yet_valid=true, expired=false
/// 说明：检查器正确识别未生效状态
#[test]
fn cc07_certificate_checker_detects_not_yet_valid() {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::extension::SubjectKeyIdentifier;
    use openssl::x509::{X509Builder, X509NameBuilder};
    use trustruntime_framework::core::cert_checker::CertificateChecker;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("Failed to create EC group");
    let key = EcKey::generate(&group).expect("Failed to generate key");
    let pkey = PKey::from_ec_key(key).expect("Failed to create PKey");

    let mut name = X509NameBuilder::new().expect("Failed to create name builder");
    name.append_entry_by_text("CN", "Not Yet Valid Cert")
        .expect("Failed to append CN");
    let name = name.build();

    let mut builder = X509Builder::new().expect("Failed to create builder");
    builder.set_version(2).expect("Failed to set version");
    builder
        .set_subject_name(&name)
        .expect("Failed to set subject");
    builder
        .set_issuer_name(&name)
        .expect("Failed to set issuer");
    builder.set_pubkey(&pkey).expect("Failed to set pubkey");

    let not_before = Asn1Time::days_from_now(365).expect("Failed to create not_before");
    let not_after = Asn1Time::days_from_now(3650).expect("Failed to create not_after");
    builder
        .set_not_before(&not_before)
        .expect("Failed to set not_before");
    builder
        .set_not_after(&not_after)
        .expect("Failed to set not_after");

    let serial = BigNum::from_u32(1).expect("Failed to create serial");
    builder
        .set_serial_number(&serial.to_asn1_integer().expect("Failed to convert serial"))
        .expect("Failed to set serial");

    let context = builder.x509v3_context(None, None);
    let ski = SubjectKeyIdentifier::new()
        .build(&context)
        .expect("Failed to build SKI");
    builder.append_extension(ski).expect("Failed to append SKI");

    builder
        .sign(&pkey, MessageDigest::sha256())
        .expect("Failed to sign cert");
    let cert = builder.build();

    let cert_path = temp_dir.path().join("not_yet_valid.crt");
    fs::write(&cert_path, cert.to_pem().expect("Failed to PEM encode"))
        .expect("Failed to write cert");

    let checker = CertificateChecker::new(vec![cert_path.to_str().unwrap().to_string()]);
    let statuses = checker.check_all();

    assert_eq!(statuses.len(), 1);
    assert!(statuses[0].not_yet_valid);
    assert!(!statuses[0].expired);
}

/// CC08: 签名证书KeyUsage精确匹配
///
/// 测试场景：签名证书仅含digitalSignature
///
/// 预期结果：check_key_usage_exact 返回 Ok(())
/// 说明：签名证书必须精确匹配，仅允许digitalSignature
#[test]
fn cc08_signer_cert_key_usage_exact_match() {
    use integration_tests::test_cert_gen::generate_signer_cert_exact_match;
    use trustruntime_framework::cert::{
        check_key_usage_exact, extract_subject_key_id, KeyUsageFlags,
    };

    let (_ca_pem, _valid_pem, _valid_key_pem, test_pem, _test_key_pem) =
        generate_signer_cert_exact_match();

    let cert = openssl::x509::X509::from_pem(&test_pem).unwrap();

    // Debug: print certificate info
    println!("Certificate subject: {:?}", cert.subject_name());
    println!("Certificate PEM length: {}", test_pem.len());

    // Check if SKI can be extracted (this proves the certificate is valid)
    let ski_result = extract_subject_key_id(&cert);
    println!("SKI extraction result: {:?}", ski_result.is_ok());

    let result = check_key_usage_exact(&cert, KeyUsageFlags::DIGITAL_SIGNATURE);
    println!("check_key_usage_exact result: {:?}", result);
    assert!(result.is_ok());
}

/// CC09: 签名证书KeyUsage包含额外位
///
/// 测试场景：签名证书含digitalSignature+keyEncipherment
///
/// 预期结果：check_key_usage_exact 返回 Err
/// 说明：签名证书不能包含额外用途位
#[test]
fn cc09_signer_cert_key_usage_extra_flags() {
    use integration_tests::test_cert_gen::generate_signer_cert_with_extra_usage;
    use trustruntime_framework::cert::{check_key_usage_exact, KeyUsageFlags};

    let (_ca_pem, _valid_pem, _valid_key_pem, test_pem, _test_key_pem) =
        generate_signer_cert_with_extra_usage();

    let cert = openssl::x509::X509::from_pem(&test_pem).unwrap();
    let result = check_key_usage_exact(&cert, KeyUsageFlags::DIGITAL_SIGNATURE);
    assert!(result.is_err());
}

/// CC10: 通信证书KeyUsage包含匹配
///
/// 测试场景：通信证书含digitalSignature+keyEncipherment
///
/// 预期结果：check_key_usage_contains 返回 Ok(())
/// 说明：通信证书必须包含所有必需位，可包含其他位
#[test]
fn cc10_comm_cert_key_usage_contains_match() {
    use integration_tests::test_cert_gen::generate_comm_cert_full_usage;
    use trustruntime_framework::cert::{check_key_usage_contains, KeyUsageFlags};

    let (_ca_pem, _valid_pem, _valid_key_pem, test_pem, _test_key_pem) =
        generate_comm_cert_full_usage();

    let cert = openssl::x509::X509::from_pem(&test_pem).unwrap();
    let result = check_key_usage_contains(
        &cert,
        KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_ENCIPHERMENT,
    );
    assert!(result.is_ok());
}

/// CC11: 通信证书ExtendedKeyUsage校验
///
/// 测试场景：通信证书含serverAuth
///
/// 预期结果：check_extended_key_usage 返回 Ok(())
/// 说明：通信证书必须包含serverAuth
#[test]
fn cc11_comm_cert_extended_key_usage_check() {
    use integration_tests::test_cert_gen::generate_comm_cert_full_usage;
    use trustruntime_framework::cert::check_extended_key_usage;

    let (_ca_pem, _valid_pem, _valid_key_pem, test_pem, _test_key_pem) =
        generate_comm_cert_full_usage();

    let cert = openssl::x509::X509::from_pem(&test_pem).unwrap();
    let result = check_extended_key_usage(&cert, "serverAuth");
    assert!(result.is_ok());
}

/// CC12: 通信证书缺少必需KeyUsage位
///
/// 测试场景：通信证书仅含digitalSignature（缺少keyEncipherment）
///
/// 预期结果：check_key_usage_contains 返回 Err
/// 说明：通信证书必须同时包含digitalSignature和keyEncipherment
#[test]
fn cc12_comm_cert_missing_required_key_usage() {
    use integration_tests::test_cert_gen::generate_comm_cert_missing_key_usage;
    use trustruntime_framework::cert::{check_key_usage_contains, KeyUsageFlags};

    let (_ca_pem, _valid_pem, _valid_key_pem, test_pem, _test_key_pem) =
        generate_comm_cert_missing_key_usage();

    let cert = openssl::x509::X509::from_pem(&test_pem).unwrap();
    let result = check_key_usage_contains(
        &cert,
        KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_ENCIPHERMENT,
    );
    assert!(result.is_err());
}

/// CC13: 通信证书缺少ExtendedKeyUsage
///
/// 测试场景：通信证书不含ExtendedKeyUsage扩展
///
/// 预期结果：check_extended_key_usage 返回 Err
/// 说明：通信证书必须包含ExtendedKeyUsage扩展
#[test]
fn cc13_comm_cert_missing_extended_key_usage() {
    use integration_tests::test_cert_gen::generate_comm_cert_missing_eku;
    use trustruntime_framework::cert::check_extended_key_usage;

    let (_ca_pem, _valid_pem, _valid_key_pem, test_pem, _test_key_pem) =
        generate_comm_cert_missing_eku();

    let cert = openssl::x509::X509::from_pem(&test_pem).unwrap();
    let result = check_extended_key_usage(&cert, "serverAuth");
    assert!(result.is_err());
}
