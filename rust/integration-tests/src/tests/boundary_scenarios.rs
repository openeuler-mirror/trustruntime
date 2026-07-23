//! 边界场景测试模块（B01-B09）
//!
//! 测试范围：
//! - B01-B02: 过期签名者证书场景（签名、验签）
//! - B03-B04: 数据边界（空数据、特殊字符）
//! - B05: Base64解码边界
//! - B06: 尚未生效证书验签失败
//! - B07: 无KeyUsage扩展证书
//! - B08: CRL吊销证书验签
//! - B09: 过期CA证书验签失败
//!
//! 重点验证：证书时间有效性、数据边界、证书扩展字段

use base64::{engine::general_purpose, Engine as _};
use integration_tests::test_cert_gen::{
    extract_cert_id_from_pem, generate_expired_ca_cert, generate_expired_signer_cert,
    generate_not_yet_valid_signer_cert, generate_revoked_signer_cert,
};
use integration_tests::test_crl_gen::generate_crl_for_cert;
use integration_tests::test_helpers::{
    build_sign_request, build_verify_request, build_verify_sign_request,
    handle_verify_sign_and_parse, setup_plugin_test_context, PluginTestContext,
};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::cms::CmsContentInfo;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::extension::{BasicConstraints, SubjectKeyIdentifier};
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use std::fs;
use tempfile::TempDir;

/// 使用OpenSSL直接生成CMS签名（用于边界测试）
///
/// 用途：生成测试签名数据，绕过trustring插件验证
/// 签名格式：原始数据 + 证书ID（附加在末尾）
fn sign_with_openssl_directly(
    cert_pem: &[u8],
    key_pem: &[u8],
    data: &[u8],
    cert_id: &[u8],
) -> Vec<u8> {
    let cert = X509::from_pem(cert_pem).unwrap();
    let key = load_private_key_from_pem(key_pem);
    let mut input = data.to_vec();
    input.extend_from_slice(cert_id);

    let cms = CmsContentInfo::sign(
        Some(&cert),
        Some(&key),
        None,
        Some(&input),
        openssl::cms::CMSOptions::BINARY,
    )
    .unwrap();
    cms.to_der().unwrap()
}

/// 从PEM格式加载私钥
///
/// 用途：辅助函数，用于签名操作
fn load_private_key_from_pem(key_pem: &[u8]) -> PKey<openssl::pkey::Private> {
    PKey::private_key_from_pem(key_pem).unwrap()
}

/// B01: 过期签名证书签名
///
/// 测试场景：使用已过期证书进行签名操作
///
/// 预期结果：签名成功返回result=0
/// 说明：签名时不检查证书有效期（业务允许过期证书签名）
///
/// 测试依赖：无（插件API测试）
#[test]
fn b01_expired_signer_cert_sign() {
    let temp_dir = TempDir::new().unwrap();

    let (ca_pem, _valid_pem, _valid_key_pem, expired_pem, expired_key_pem) =
        generate_expired_signer_cert();

    let ca_path = temp_dir.path().join("ca.crt");
    let expired_path = temp_dir.path().join("expired.crt");
    let expired_key_path = temp_dir.path().join("expired.key");

    fs::write(&ca_path, &ca_pem).unwrap();
    fs::write(&expired_path, &expired_pem).unwrap();
    fs::write(&expired_key_path, &expired_key_pem).unwrap();

    let ctx = PluginTestContext::new(&ca_path, &expired_path, &expired_key_path, None)
        .expect("Failed to create plugin context with expired cert");

    let request = build_sign_request("test data");
    let result = ctx.sign(&request);
    assert!(result.is_some());

    let resp: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(resp["result"], 0);
}

/// B02: 验签过期签名证书
///
/// 测试场景：验证由过期证书生成的签名
///
/// 预期结果：验签返回result=1（其他节点签名）
/// 说明：忽略签名方证书过期错误，正常验签并返回身份判断结果
///
/// 测试依赖：无（插件API测试）
#[test]
fn b02_verify_expired_signer_cert() {
    let temp_dir = TempDir::new().unwrap();

    let (ca_pem, valid_pem, valid_key_pem, expired_pem, expired_key_pem) =
        generate_expired_signer_cert();

    let ca_path = temp_dir.path().join("ca.crt");
    let expired_path = temp_dir.path().join("expired.crt");
    let expired_key_path = temp_dir.path().join("expired.key");
    let valid_path = temp_dir.path().join("valid.crt");
    let valid_key_path = temp_dir.path().join("valid.key");

    fs::write(&ca_path, &ca_pem).unwrap();
    fs::write(&expired_path, &expired_pem).unwrap();
    fs::write(&expired_key_path, &expired_key_pem).unwrap();
    fs::write(&valid_path, &valid_pem).unwrap();
    fs::write(&valid_key_path, &valid_key_pem).unwrap();

    let expired_id = extract_cert_id_from_pem(&expired_pem);
    let expired_id_b64 = general_purpose::STANDARD.encode(&expired_id);

    let signed_der =
        sign_with_openssl_directly(&expired_pem, &expired_key_pem, b"test data", &expired_id);
    let signed_b64 = general_purpose::STANDARD.encode(&signed_der);

    let ctx = PluginTestContext::new(&ca_path, &valid_path, &valid_key_path, None)
        .expect("Failed to create plugin context");

    let verify_req = build_verify_request("test data", &signed_b64, &expired_id_b64);
    let result = ctx.verify(&verify_req);
    assert!(result.is_some());

    let resp: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(resp["result"], 1);
}

/// B03: 空数据签名
///
/// 测试场景：对空字符串数据进行签名
///
/// 预期结果：签名成功返回result=0，signed_data非空
/// 说明：空数据仍可正常签名
///
/// 测试依赖：无（插件API测试）
#[test]
fn b03_empty_data_sign() {
    let temp_dir = TempDir::new().unwrap();
    let ctx = setup_plugin_test_context(&temp_dir);

    let request = build_sign_request("");
    let result = ctx.sign(&request);
    assert!(result.is_some());

    let resp: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(resp["result"], 0);
    assert!(!resp["signed_data"].as_str().unwrap().is_empty());
}

/// B04: 特殊字符数据签名
///
/// 测试场景：对包含中文和emoji的数据进行签名
///
/// 预期结果：签名成功返回result=0，signed_data非空
/// 说明：UTF-8特殊字符支持正常
///
/// 测试依赖：无（插件API测试）
#[test]
fn b04_special_characters_data_sign() {
    let temp_dir = TempDir::new().unwrap();
    let ctx = setup_plugin_test_context(&temp_dir);

    let special_data = "中文测试数据 \u{1F600} emoji";
    let request = build_sign_request(special_data);
    let result = ctx.sign(&request);
    assert!(result.is_some());

    let resp: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(resp["result"], 0);
    assert!(!resp["signed_data"].as_str().unwrap().is_empty());
}

/// B05: verify-sign中ID无效Base64
///
/// 测试场景：verify-sign请求中to-verify.id字段无效
///
/// 预期结果：返回result=21，signed_data=""，id=""
/// 原因：无法解码Base64字符串
///
/// 测试依赖：无（插件API测试）
#[test]
fn b05_invalid_base64_in_id() {
    let temp_dir = TempDir::new().unwrap();
    let ctx = setup_plugin_test_context(&temp_dir);

    let (signed_b64, cert_id_b64) = {
        let request = build_sign_request("test data");
        let result = ctx.sign(&request).unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&result).unwrap();
        (
            resp["signed_data"].as_str().unwrap().to_string(),
            resp["id"].as_str().unwrap().to_string(),
        )
    };

    let req = build_verify_sign_request(
        "test data",
        &signed_b64,
        "!!!invalid-base64!!!",
        "new data",
        &cert_id_b64,
    );
    let resp = handle_verify_sign_and_parse(&ctx, &req);

    assert_eq!(resp["result"], 21);
    assert_eq!(resp["signed_data"], "");
    assert_eq!(resp["id"], "");
}

/// B06: 尚未生效证书验签
///
/// 测试场景：验证由未来生效证书生成的签名
///
/// 预期结果：验签返回result=5（签名不匹配）
/// 说明：证书尚未生效时验签必须失败，防止伪造"未来签名"攻击
///
/// 测试依赖：无（插件API测试）
#[test]
fn b06_verify_not_yet_valid_cert() {
    let temp_dir = TempDir::new().unwrap();

    let (ca_pem, valid_pem, valid_key_pem, not_yet_valid_pem, not_yet_valid_key_pem) =
        generate_not_yet_valid_signer_cert();

    let ca_path = temp_dir.path().join("ca.crt");
    let not_yet_valid_path = temp_dir.path().join("not_yet_valid.crt");
    let not_yet_valid_key_path = temp_dir.path().join("not_yet_valid.key");
    let valid_path = temp_dir.path().join("valid.crt");
    let valid_key_path = temp_dir.path().join("valid.key");

    fs::write(&ca_path, &ca_pem).unwrap();
    fs::write(&not_yet_valid_path, &not_yet_valid_pem).unwrap();
    fs::write(&not_yet_valid_key_path, &not_yet_valid_key_pem).unwrap();
    fs::write(&valid_path, &valid_pem).unwrap();
    fs::write(&valid_key_path, &valid_key_pem).unwrap();

    let not_yet_valid_id = extract_cert_id_from_pem(&not_yet_valid_pem);
    let not_yet_valid_id_b64 = general_purpose::STANDARD.encode(&not_yet_valid_id);

    let signed_der = sign_with_openssl_directly(
        &not_yet_valid_pem,
        &not_yet_valid_key_pem,
        b"test data",
        &not_yet_valid_id,
    );
    let signed_b64 = general_purpose::STANDARD.encode(&signed_der);

    let ctx = PluginTestContext::new(&ca_path, &valid_path, &valid_key_path, None)
        .expect("Failed to create plugin context");

    let verify_req = build_verify_request("test data", &signed_b64, &not_yet_valid_id_b64);
    let result = ctx.verify(&verify_req);
    assert!(result.is_some());

    let resp: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(resp["result"], 5);
}

/// B07: 无KeyUsage扩展证书验签
///
/// 测试场景：验证由无KeyUsage扩展证书生成的签名
///
/// 预期结果：验签返回result=6（InvalidKeyUsage）
/// 原因：证书缺少必要的KeyUsage扩展（digitalSignature或nonRepudiation）
///
/// 测试依赖：无（插件API测试）
#[test]
fn b07_verify_cert_without_key_usage() {
    let temp_dir = TempDir::new().unwrap();

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

    let signer_without_ku_key = EcKey::generate(&group).unwrap();
    let signer_without_ku_pkey = PKey::from_ec_key(signer_without_ku_key.clone()).unwrap();

    let mut signer_without_ku_name = X509NameBuilder::new().unwrap();
    signer_without_ku_name
        .append_entry_by_text("CN", "Signer Without KU")
        .unwrap();
    let signer_without_ku_name = signer_without_ku_name.build();

    let mut signer_without_ku_builder = X509Builder::new().unwrap();
    signer_without_ku_builder.set_version(2).unwrap();
    signer_without_ku_builder
        .set_subject_name(&signer_without_ku_name)
        .unwrap();
    signer_without_ku_builder.set_issuer_name(&ca_name).unwrap();
    signer_without_ku_builder
        .set_pubkey(&signer_without_ku_pkey)
        .unwrap();
    signer_without_ku_builder
        .set_not_before(&not_before)
        .unwrap();
    signer_without_ku_builder.set_not_after(&not_after).unwrap();

    let serial2 = BigNum::from_u32(2).unwrap();
    signer_without_ku_builder
        .set_serial_number(&serial2.to_asn1_integer().unwrap())
        .unwrap();

    let context2 = signer_without_ku_builder.x509v3_context(Some(&ca_cert), None);
    let ski2 = SubjectKeyIdentifier::new().build(&context2).unwrap();
    signer_without_ku_builder.append_extension(ski2).unwrap();

    signer_without_ku_builder
        .sign(&ca_pkey, MessageDigest::sha256())
        .unwrap();
    let signer_without_ku_cert = signer_without_ku_builder.build();

    let valid_signer_key = EcKey::generate(&group).unwrap();
    let valid_signer_pkey = PKey::from_ec_key(valid_signer_key.clone()).unwrap();

    let mut valid_signer_name = X509NameBuilder::new().unwrap();
    valid_signer_name
        .append_entry_by_text("CN", "Valid Signer")
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

    let serial3 = BigNum::from_u32(3).unwrap();
    valid_signer_builder
        .set_serial_number(&serial3.to_asn1_integer().unwrap())
        .unwrap();

    use openssl::x509::extension::KeyUsage;
    let mut ku_builder = KeyUsage::new();
    ku_builder.digital_signature();
    let ku = ku_builder.build().unwrap();
    valid_signer_builder.append_extension(ku).unwrap();

    let context3 = valid_signer_builder.x509v3_context(Some(&ca_cert), None);
    let ski3 = SubjectKeyIdentifier::new().build(&context3).unwrap();
    valid_signer_builder.append_extension(ski3).unwrap();

    valid_signer_builder
        .sign(&ca_pkey, MessageDigest::sha256())
        .unwrap();
    let valid_signer_cert = valid_signer_builder.build();

    let ca_path = temp_dir.path().join("ca.crt");
    let signer_without_ku_path = temp_dir.path().join("signer_without_ku.crt");
    let signer_without_ku_key_path = temp_dir.path().join("signer_without_ku.key");
    let valid_path = temp_dir.path().join("valid.crt");
    let valid_key_path = temp_dir.path().join("valid.key");

    fs::write(&ca_path, ca_cert.to_pem().unwrap()).unwrap();
    fs::write(
        &signer_without_ku_path,
        signer_without_ku_cert.to_pem().unwrap(),
    )
    .unwrap();
    fs::write(
        &signer_without_ku_key_path,
        signer_without_ku_pkey.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();
    fs::write(&valid_path, valid_signer_cert.to_pem().unwrap()).unwrap();
    fs::write(
        &valid_key_path,
        valid_signer_pkey.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();

    let signer_without_ku_id = extract_cert_id_from_pem(&signer_without_ku_cert.to_pem().unwrap());
    let signer_without_ku_id_b64 = general_purpose::STANDARD.encode(&signer_without_ku_id);

    let signed_der = sign_with_openssl_directly(
        &signer_without_ku_cert.to_pem().unwrap(),
        &signer_without_ku_pkey.private_key_to_pem_pkcs8().unwrap(),
        b"test data",
        &signer_without_ku_id,
    );
    let signed_b64 = general_purpose::STANDARD.encode(&signed_der);

    let ctx = PluginTestContext::new(&ca_path, &valid_path, &valid_key_path, None)
        .expect("Failed to create plugin context");

    let verify_req = build_verify_request("test data", &signed_b64, &signer_without_ku_id_b64);
    let result = ctx.verify(&verify_req);
    assert!(result.is_some());

    let resp: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(resp["result"], 6);
}

/// B08: CRL吊销证书验签
///
/// 测试场景：验证由已吊销证书生成的签名，提供CRL文件
///
/// 预期结果：验签返回result=4（证书已吊销）
/// 原因：证书在CRL吊销列表中
///
/// 测试依赖：无（插件API测试）
#[test]
fn b08_verify_revoked_cert_with_crl() {
    let temp_dir = TempDir::new().unwrap();

    let (ca_pem, valid_pem, valid_key_pem, revoked_pem, revoked_key_pem, ca_key_pem) =
        generate_revoked_signer_cert();

    let ca_path = temp_dir.path().join("ca.crt");
    let valid_path = temp_dir.path().join("valid.crt");
    let valid_key_path = temp_dir.path().join("valid.key");
    let revoked_path = temp_dir.path().join("revoked.crt");
    let revoked_key_path = temp_dir.path().join("revoked.key");

    fs::write(&ca_path, &ca_pem).unwrap();
    fs::write(&valid_path, &valid_pem).unwrap();
    fs::write(&valid_key_path, &valid_key_pem).unwrap();
    fs::write(&revoked_path, &revoked_pem).unwrap();
    fs::write(&revoked_key_path, &revoked_key_pem).unwrap();

    let revoked_id = extract_cert_id_from_pem(&revoked_pem);
    let revoked_id_b64 = general_purpose::STANDARD.encode(&revoked_id);

    let signed_der =
        sign_with_openssl_directly(&revoked_pem, &revoked_key_pem, b"test data", &revoked_id);
    let signed_b64 = general_purpose::STANDARD.encode(&signed_der);

    let crl_pem = generate_crl_for_cert(&ca_pem, &ca_key_pem, 101);
    let crl_path = temp_dir.path().join("crl.crl");
    fs::write(&crl_path, &crl_pem).unwrap();

    let ctx = PluginTestContext::new(&ca_path, &valid_path, &valid_key_path, Some(&crl_path))
        .expect("Failed to create plugin context");

    let verify_req = build_verify_request("test data", &signed_b64, &revoked_id_b64);
    let result = ctx.verify(&verify_req);
    assert!(result.is_some());

    let resp: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(resp["result"], 4);
}

/// B09: 过期CA证书验签
///
/// 测试场景：验证由过期CA证书签发的签名者证书生成的签名
///
/// 预期结果：验签返回result=5（签名不匹配）
/// 说明：CA证书过期时验签必须失败，维护信任链有效性
///
/// 测试依赖：无（插件API测试）
#[test]
fn b09_verify_expired_ca_cert() {
    let temp_dir = TempDir::new().unwrap();

    let (expired_ca_pem, signer_pem, signer_key_pem) = generate_expired_ca_cert();

    let ca_path = temp_dir.path().join("ca.crt");
    let signer_path = temp_dir.path().join("signer.crt");
    let signer_key_path = temp_dir.path().join("signer.key");

    fs::write(&ca_path, &expired_ca_pem).unwrap();
    fs::write(&signer_path, &signer_pem).unwrap();
    fs::write(&signer_key_path, &signer_key_pem).unwrap();

    let signer_id = extract_cert_id_from_pem(&signer_pem);
    let signer_id_b64 = general_purpose::STANDARD.encode(&signer_id);

    let signed_der =
        sign_with_openssl_directly(&signer_pem, &signer_key_pem, b"test data", &signer_id);
    let signed_b64 = general_purpose::STANDARD.encode(&signed_der);

    let ctx = PluginTestContext::new(&ca_path, &signer_path, &signer_key_path, None)
        .expect("Failed to create plugin context");

    let verify_req = build_verify_request("test data", &signed_b64, &signer_id_b64);
    let result = ctx.verify(&verify_req);
    assert!(result.is_some());

    let resp: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(resp["result"], 5);
}
