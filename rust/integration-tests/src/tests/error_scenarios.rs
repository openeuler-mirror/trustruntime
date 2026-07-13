//! 错误场景测试模块（E01-E20）
//!
//! 测试范围：
//! - E01-E06: 验签失败场景（签名不匹配、证书链无效、CRL吊销等）
//! - E07-E08: 证书/密钥文件缺失
//! - E09-E20: verify-sign组合操作错误场景
//!
//! result码定义（详见ADR-0001）：
//! - 0: 成功
//! - 1: 其他节点签名
//! - 2: 证书身份冲突
//! - 3: 证书链无效
//! - 4: 证书已吊销
//! - 5: 签名验证失败
//! - 6: CMS格式错误
//! - 10: JSON解析错误
//! - 11: Base64解码错误

use base64::{engine::general_purpose, Engine as _};
use integration_tests::proc_manager::{NodeConfig, ProcessManager};
use integration_tests::test_cert_gen::generate_ca_and_signer;
use integration_tests::test_helpers::{
    assert_sign_success, assert_verify_failed, build_sign_request, build_verify_sign_request,
    handle_verify_sign_and_parse, setup_plugin_test_context, setup_test_certificates,
    PluginTestContext, TestPaths, TEST_DATA_A, TEST_DATA_B,
};
use integration_tests::vsock_client::VsockClient;
use openssl::cms::CmsContentInfo;
use openssl::pkey::PKey;
use std::fs;
use tempfile::TempDir;
use trustring::TrustringPlugin;

/// 使用OpenSSL直接生成CMS签名（绕过trustring插件）
///
/// 用途：生成测试用的签名数据，用于验证场景测试
/// 签名数据格式：原始数据 + 证书ID（附加在末尾）
fn sign_with_openssl_directly(
    cert_pem: &[u8],
    key_pem: &[u8],
    data: &[u8],
    cert_id: &[u8],
) -> Vec<u8> {
    let cert = openssl::x509::X509::from_pem(cert_pem).unwrap();
    let key = PKey::private_key_from_pem(key_pem).unwrap();
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

/// E01: 签名数据不匹配
///
/// 测试场景：node-a签名数据A，node-b使用数据B验证签名
///
/// 预期结果：验签返回result=5（签名验证失败）
/// 原因：签名数据与原始数据不匹配
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn e01_signature_mismatch() {
    let paths = TestPaths::new();

    let manager = ProcessManager::new(paths.binary_path.clone(), paths.cert_base.clone());

    let node_a_config = NodeConfig {
        name: "node-a".to_string(),
        port: 12345,
        cms_cert_path: paths.node_cms_cert("node-a"),
        cms_key_path: paths.node_cms_key("node-a"),
        tls_cert_path: paths.node_tls_cert("node-a"),
        tls_key_path: paths.node_tls_key("node-a"),
        tls_client_crl: None,
    };

    let node_b_config = NodeConfig {
        name: "node-b".to_string(),
        port: 12346,
        cms_cert_path: paths.node_cms_cert("node-b"),
        cms_key_path: paths.node_cms_key("node-b"),
        tls_cert_path: paths.node_tls_cert("node-b"),
        tls_key_path: paths.node_tls_key("node-b"),
        tls_client_crl: None,
    };

    manager
        .start_node(node_a_config)
        .expect("Failed to start node-a");
    manager
        .start_node(node_b_config)
        .expect("Failed to start node-b");

    let mut client_a = VsockClient::connect(
        12345,
        &paths.tls_ca_cert(),
        &paths.tls_client_cert(),
        &paths.tls_client_key(),
    )
    .expect("Failed to connect to node-a");

    let mut client_b = VsockClient::connect(
        12346,
        &paths.tls_ca_cert(),
        &paths.tls_client_cert(),
        &paths.tls_client_key(),
    )
    .expect("Failed to connect to node-b");

    let sign_resp_a = client_a
        .sign(TEST_DATA_A)
        .expect("Sign request to node-a failed");
    assert_sign_success(
        sign_resp_a.result,
        &sign_resp_a.signed_data,
        &sign_resp_a.id,
    );

    let verify_resp = client_b
        .verify(TEST_DATA_B, &sign_resp_a.signed_data, &sign_resp_a.id)
        .expect("Verify request to node-b failed");

    assert_verify_failed(verify_resp.result, 5);

    client_a.close().expect("Failed to close client_a");
    client_b.close().expect("Failed to close client_b");

    manager.stop_all().expect("Failed to stop processes");
}

/// E02: 证书链无效（自签名证书）
///
/// 测试场景：使用自签名证书签名，node-b验证签名
///
/// 预期结果：验签返回result=3（证书链无效）
/// 原因：签名证书不是由可信CA签发
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn e02_certificate_chain_invalid() {
    let paths = TestPaths::new();

    let manager = ProcessManager::new(paths.binary_path.clone(), paths.cert_base.clone());

    let self_signed_config = NodeConfig {
        name: "self-signed".to_string(),
        port: 12350,
        cms_cert_path: paths.self_signed_cms_cert(),
        cms_key_path: paths.self_signed_cms_key(),
        tls_cert_path: paths.node_tls_cert("node-a"),
        tls_key_path: paths.node_tls_key("node-a"),
        tls_client_crl: None,
    };

    let node_b_config = NodeConfig {
        name: "node-b".to_string(),
        port: 12346,
        cms_cert_path: paths.node_cms_cert("node-b"),
        cms_key_path: paths.node_cms_key("node-b"),
        tls_cert_path: paths.node_tls_cert("node-b"),
        tls_key_path: paths.node_tls_key("node-b"),
        tls_client_crl: None,
    };

    manager
        .start_node(self_signed_config)
        .expect("Failed to start self-signed node");
    manager
        .start_node(node_b_config)
        .expect("Failed to start node-b");

    let mut client_self_signed = VsockClient::connect(
        12350,
        &paths.tls_ca_cert(),
        &paths.tls_client_cert(),
        &paths.tls_client_key(),
    )
    .expect("Failed to connect to self-signed node");

    let mut client_b = VsockClient::connect(
        12346,
        &paths.tls_ca_cert(),
        &paths.tls_client_cert(),
        &paths.tls_client_key(),
    )
    .expect("Failed to connect to node-b");

    let sign_resp = client_self_signed
        .sign(TEST_DATA_A)
        .expect("Sign request to self-signed node failed");
    assert_sign_success(sign_resp.result, &sign_resp.signed_data, &sign_resp.id);

    let verify_resp = client_b
        .verify(TEST_DATA_A, &sign_resp.signed_data, &sign_resp.id)
        .expect("Verify request to node-b failed");

    assert_verify_failed(verify_resp.result, 3);

    client_self_signed
        .close()
        .expect("Failed to close client_self_signed");
    client_b.close().expect("Failed to close client_b");

    manager.stop_all().expect("Failed to stop processes");
}

/// E03: CRL证书吊销
///
/// 测试场景：使用已吊销证书签名，node-b验证签名
///
/// 预期结果：验签返回result=4（证书已吊销）
/// 原因：签名证书在CRL列表中
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn e03_crl_revoked() {
    let paths = TestPaths::new();

    let manager = ProcessManager::new(paths.binary_path.clone(), paths.cert_base.clone());

    let revoked_config = NodeConfig {
        name: "revoked".to_string(),
        port: 12351,
        cms_cert_path: paths.revoked_cms_cert(),
        cms_key_path: paths.revoked_cms_key(),
        tls_cert_path: paths.node_tls_cert("node-a"),
        tls_key_path: paths.node_tls_key("node-a"),
        tls_client_crl: None,
    };

    let node_b_config = NodeConfig {
        name: "node-b".to_string(),
        port: 12346,
        cms_cert_path: paths.node_cms_cert("node-b"),
        cms_key_path: paths.node_cms_key("node-b"),
        tls_cert_path: paths.node_tls_cert("node-b"),
        tls_key_path: paths.node_tls_key("node-b"),
        tls_client_crl: None,
    };

    manager
        .start_node(revoked_config)
        .expect("Failed to start revoked node");
    manager
        .start_node(node_b_config)
        .expect("Failed to start node-b");

    let mut client_revoked = VsockClient::connect(
        12351,
        &paths.tls_ca_cert(),
        &paths.tls_client_cert(),
        &paths.tls_client_key(),
    )
    .expect("Failed to connect to revoked node");

    let mut client_b = VsockClient::connect(
        12346,
        &paths.tls_ca_cert(),
        &paths.tls_client_cert(),
        &paths.tls_client_key(),
    )
    .expect("Failed to connect to node-b");

    let sign_resp = client_revoked
        .sign(TEST_DATA_A)
        .expect("Sign request to revoked node failed");
    assert_sign_success(sign_resp.result, &sign_resp.signed_data, &sign_resp.id);

    let verify_resp = client_b
        .verify(TEST_DATA_A, &sign_resp.signed_data, &sign_resp.id)
        .expect("Verify request to node-b failed");

    assert_verify_failed(verify_resp.result, 4);

    client_revoked
        .close()
        .expect("Failed to close client_revoked");
    client_b.close().expect("Failed to close client_b");

    manager.stop_all().expect("Failed to stop processes");
}

/// E04: CMS格式错误
///
/// 测试场景：发送非CMS DER结构的签名数据
///
/// 预期结果：验签返回result=6（CMS格式错误）
/// 原因：无法解析签名数据结构
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn e04_cms_format_error() {
    let paths = TestPaths::new();

    let manager = ProcessManager::new(paths.binary_path.clone(), paths.cert_base.clone());

    let node_b_config = NodeConfig {
        name: "node-b".to_string(),
        port: 12346,
        cms_cert_path: paths.node_cms_cert("node-b"),
        cms_key_path: paths.node_cms_key("node-b"),
        tls_cert_path: paths.node_tls_cert("node-b"),
        tls_key_path: paths.node_tls_key("node-b"),
        tls_client_crl: None,
    };

    manager
        .start_node(node_b_config)
        .expect("Failed to start node-b");

    let mut client_b = VsockClient::connect(
        12346,
        &paths.tls_ca_cert(),
        &paths.tls_client_cert(),
        &paths.tls_client_key(),
    )
    .expect("Failed to connect to node-b");

    let invalid_signed_data = general_purpose::STANDARD.encode(b"not a cms der structure");
    let fake_id = general_purpose::STANDARD.encode(b"fakeid");

    let verify_resp = client_b
        .verify(TEST_DATA_A, &invalid_signed_data, &fake_id)
        .expect("Verify request to node-b failed");

    assert_verify_failed(verify_resp.result, 6);

    client_b.close().expect("Failed to close client_b");

    manager.stop_all().expect("Failed to stop processes");
}

/// E05: JSON解析错误
///
/// 测试场景：发送不完整的JSON请求（缺少必要字段）
///
/// 预期结果：验签返回result=10（JSON解析错误）
/// 原因：请求格式不符合协议规范
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn e05_json_parse_error() {
    let paths = TestPaths::new();

    let manager = ProcessManager::new(paths.binary_path.clone(), paths.cert_base.clone());

    let node_b_config = NodeConfig {
        name: "node-b".to_string(),
        port: 12346,
        cms_cert_path: paths.node_cms_cert("node-b"),
        cms_key_path: paths.node_cms_key("node-b"),
        tls_cert_path: paths.node_tls_cert("node-b"),
        tls_key_path: paths.node_tls_key("node-b"),
        tls_client_crl: None,
    };

    manager
        .start_node(node_b_config)
        .expect("Failed to start node-b");

    let mut client_b = VsockClient::connect(
        12346,
        &paths.tls_ca_cert(),
        &paths.tls_client_cert(),
        &paths.tls_client_key(),
    )
    .expect("Failed to connect to node-b");

    let incomplete_req = serde_json::json!({
        "to-verify": {
            "data": TEST_DATA_A
        }
    });
    let verify_resp = client_b
        .verify_raw(incomplete_req.to_string())
        .expect("Verify request to node-b failed");

    assert_verify_failed(verify_resp.result, 10);

    client_b.close().expect("Failed to close client_b");

    manager.stop_all().expect("Failed to stop processes");
}

/// E06: Base64解码错误
///
/// 测试场景：发送无效Base64编码的ID字段
///
/// 预期结果：验签返回result=11（Base64解码错误）
/// 原因：ID字段包含非法Base64字符
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn e06_base64_decode_error() {
    let paths = TestPaths::new();

    let manager = ProcessManager::new(paths.binary_path.clone(), paths.cert_base.clone());

    let node_b_config = NodeConfig {
        name: "node-b".to_string(),
        port: 12346,
        cms_cert_path: paths.node_cms_cert("node-b"),
        cms_key_path: paths.node_cms_key("node-b"),
        tls_cert_path: paths.node_tls_cert("node-b"),
        tls_key_path: paths.node_tls_key("node-b"),
        tls_client_crl: None,
    };

    manager
        .start_node(node_b_config)
        .expect("Failed to start node-b");

    let mut client_b = VsockClient::connect(
        12346,
        &paths.tls_ca_cert(),
        &paths.tls_client_cert(),
        &paths.tls_client_key(),
    )
    .expect("Failed to connect to node-b");

    let invalid_base64 = "!!!invalid-base64!!!";
    let verify_resp = client_b
        .verify(TEST_DATA_A, "validlookingbase64", invalid_base64)
        .expect("Verify request to node-b failed");

    assert_verify_failed(verify_resp.result, 11);

    client_b.close().expect("Failed to close client_b");

    manager.stop_all().expect("Failed to stop processes");
}

/// E07: 签名证书文件缺失
///
/// 测试场景：尝试创建插件，签名证书文件不存在
///
/// 预期结果：插件创建失败，返回IO错误
/// 原因：证书文件路径不存在
///
/// 测试依赖：无（本地文件操作）
#[test]
fn e07_signer_cert_missing() {
    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().join("ca.crt");
    let key_path = temp_dir.path().join("signer.key");

    let (ca_pem, _, _) = generate_ca_and_signer();
    fs::write(&ca_path, &ca_pem).unwrap();
    fs::write(&key_path, "dummy key").unwrap();

    let missing_cert_path = temp_dir.path().join("nonexistent.crt");

    let result = TrustringPlugin::new(
        missing_cert_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
        ca_path.to_str().unwrap(),
        None,
    );

    assert!(result.is_err());
    if let Err(e) = result {
        let err_msg = e.to_string();
        assert!(
            err_msg.contains("io error") || err_msg.contains("No such file"),
            "Expected IO error for missing cert, got: {}",
            err_msg
        );
    }
}

/// E08: 签名私钥文件缺失
///
/// 测试场景：尝试创建插件，签名私钥文件不存在
///
/// 预期结果：插件创建失败，返回IO错误
/// 原因：私钥文件路径不存在
///
/// 测试依赖：无（本地文件操作）
#[test]
fn e08_signer_key_missing() {
    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().join("ca.crt");
    let cert_path = temp_dir.path().join("signer.crt");

    let (ca_pem, signer_pem, _) = generate_ca_and_signer();
    fs::write(&ca_path, &ca_pem).unwrap();
    fs::write(&cert_path, &signer_pem).unwrap();

    let missing_key_path = temp_dir.path().join("nonexistent.key");

    let result = TrustringPlugin::new(
        cert_path.to_str().unwrap(),
        missing_key_path.to_str().unwrap(),
        ca_path.to_str().unwrap(),
        None,
    );

    assert!(result.is_err());
    if let Err(e) = result {
        let err_msg = e.to_string();
        assert!(
            err_msg.contains("io error") || err_msg.contains("No such file"),
            "Expected IO error for missing key, got: {}",
            err_msg
        );
    }
}

/// E09: verify-sign签名不匹配
///
/// 测试场景：verify-sign操作中，验签数据与签名不匹配
///
/// 预期结果：返回result=5，signed_data=""，id=""
/// 原因：签名验证失败
///
/// 测试依赖：无（插件API测试）
#[test]
fn e09_verify_sign_signature_mismatch() {
    let temp_dir = TempDir::new().unwrap();
    let ctx = setup_plugin_test_context(&temp_dir);

    let (signed_b64, cert_id_b64) = {
        let request = build_sign_request("original data");
        let result = ctx.sign(&request).unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&result).unwrap();
        (
            resp["signed_data"].as_str().unwrap().to_string(),
            resp["id"].as_str().unwrap().to_string(),
        )
    };

    let req = build_verify_sign_request(
        "different data",
        &signed_b64,
        &cert_id_b64,
        "new data",
        &cert_id_b64,
    );
    let resp = handle_verify_sign_and_parse(&ctx, &req);

    assert_eq!(resp["result"], 5);
    assert_eq!(resp["signed_data"], "");
    assert_eq!(resp["id"], "");
}

/// E10: verify-sign证书链无效
///
/// 测试场景：verify-sign操作中，签名证书链无效
///
/// 预期结果：返回result=3，signed_data=""，id=""
///
/// 测试依赖：需要正确生成CRL（包含Authority Key Identifier）
/// 当前状态：待实现
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn e10_verify_sign_cert_chain_invalid() {}

/// E11: verify-sign证书已吊销
///
/// 测试场景：verify-sign操作中，签名证书在CRL中
///
/// 预期结果：返回result=4，signed_data=""，id=""
///
/// 测试依赖：需要正确生成CRL（包含Authority Key Identifier）
/// 当前状态：待实现
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn e11_verify_sign_crl_revoked() {}

/// E12: verify-sign CMS格式错误
///
/// 测试场景：verify-sign操作中，签名数据格式无效
///
/// 预期结果：返回result=6，signed_data=""，id=""
/// 原因：无法解析CMS结构
///
/// 测试依赖：无（插件API测试）
#[test]
fn e12_verify_sign_cms_format_error() {
    let temp_dir = TempDir::new().unwrap();
    let ctx = setup_plugin_test_context(&temp_dir);

    let invalid_cms = general_purpose::STANDARD.encode(b"not a valid cms structure");
    let cert_id_b64 = ctx.cert_id_b64();

    let req = build_verify_sign_request(
        "test data",
        &invalid_cms,
        &cert_id_b64,
        "new data",
        &cert_id_b64,
    );
    let resp = handle_verify_sign_and_parse(&ctx, &req);

    assert_eq!(resp["result"], 6);
    assert_eq!(resp["signed_data"], "");
    assert_eq!(resp["id"], "");
}

/// E15: verify-sign签名者证书缺失（但验签仍成功）
///
/// 测试场景：verify-sign操作中，使用外部生成的签名，签名者证书不在本地
///
/// 预期结果：返回result=0（验签成功，签名成功）
/// 说明：验签不依赖本地签名者证书，只需要CA证书验证证书链
///
/// 测试依赖：无（插件API测试）
#[test]
fn e15_verify_sign_signer_cert_missing() {
    let temp_dir = TempDir::new().unwrap();
    let certs = setup_test_certificates(&temp_dir);

    let cert_id = certs.cert_id.clone();
    let cert_id_b64 = general_purpose::STANDARD.encode(&cert_id);

    let signed_der = sign_with_openssl_directly(
        &fs::read(&certs.signer_path).unwrap(),
        &fs::read(&certs.signer_key_path).unwrap(),
        b"original data",
        &cert_id,
    );
    let signed_b64 = general_purpose::STANDARD.encode(&signed_der);

    let ctx = PluginTestContext::new(
        &certs.ca_path,
        &certs.signer_path,
        &certs.signer_key_path,
        None,
    )
    .expect("Failed to create plugin context");

    let req = build_verify_sign_request(
        "original data",
        &signed_b64,
        &cert_id_b64,
        "new data",
        &cert_id_b64,
    );

    let resp = handle_verify_sign_and_parse(&ctx, &req);

    assert_eq!(resp["result"], 0);
}

/// E16: verify-sign签名者密钥缺失（但验签仍成功）
///
/// 测试场景：verify-sign操作中，使用外部生成的签名，签名者密钥不在本地
///
/// 预期结果：返回result=0（验签成功，签名成功）
/// 说明：验签不依赖本地签名者密钥，签名操作使用本地配置的密钥
///
/// 测试依赖：无（插件API测试）
#[test]
fn e16_verify_sign_signer_key_missing() {
    let temp_dir = TempDir::new().unwrap();
    let certs = setup_test_certificates(&temp_dir);

    let cert_id = certs.cert_id.clone();
    let cert_id_b64 = general_purpose::STANDARD.encode(&cert_id);

    let signed_der = sign_with_openssl_directly(
        &fs::read(&certs.signer_path).unwrap(),
        &fs::read(&certs.signer_key_path).unwrap(),
        b"original data",
        &cert_id,
    );
    let signed_b64 = general_purpose::STANDARD.encode(&signed_der);

    let ctx = PluginTestContext::new(
        &certs.ca_path,
        &certs.signer_path,
        &certs.signer_key_path,
        None,
    )
    .expect("Failed to create plugin context");

    let req = build_verify_sign_request(
        "original data",
        &signed_b64,
        &cert_id_b64,
        "new data",
        &cert_id_b64,
    );

    let resp = handle_verify_sign_and_parse(&ctx, &req);

    assert_eq!(resp["result"], 0);
}

/// E17: verify-sign缺少to-sign字段
///
/// 测试场景：verify-sign请求中缺少to-sign字段
///
/// 预期结果：返回result=10（JSON解析错误）
/// 原因：请求格式不完整
///
/// 测试依赖：无（插件API测试）
#[test]
fn e17_missing_to_sign_field() {
    let temp_dir = TempDir::new().unwrap();
    let ctx = setup_plugin_test_context(&temp_dir);

    let req = serde_json::to_vec(&serde_json::json!({
        "to-verify": {
            "data": "test data",
            "signed_data": "validlookingb64",
            "id": "valididb64"
        }
    }))
    .unwrap();

    let resp = handle_verify_sign_and_parse(&ctx, &req);
    assert_eq!(resp["result"], 10);
}

/// E18: verify-sign缺少to-verify字段
///
/// 测试场景：verify-sign请求中缺少to-verify字段
///
/// 预期结果：返回result=10（JSON解析错误）
/// 原因：请求格式不完整
///
/// 测试依赖：无（插件API测试）
#[test]
fn e18_missing_to_verify_field() {
    let temp_dir = TempDir::new().unwrap();
    let ctx = setup_plugin_test_context(&temp_dir);

    let req = serde_json::to_vec(&serde_json::json!({
        "to-sign": {
            "data": "new data",
            "id": "valididb64"
        }
    }))
    .unwrap();

    let resp = handle_verify_sign_and_parse(&ctx, &req);
    assert_eq!(resp["result"], 10);
}

/// E19: verify-sign中to-sign.id无效Base64
///
/// 测试场景：verify-sign请求中to-sign.id字段包含非法Base64字符
///
/// 预期结果：返回result=11，signed_data=""，id=""
/// 原因：无法解码Base64字符串
///
/// 测试依赖：无（插件API测试）
#[test]
fn e19_invalid_base64_in_to_sign_id() {
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
        &cert_id_b64,
        "new data",
        "!!!invalid-base64!!!",
    );
    let resp = handle_verify_sign_and_parse(&ctx, &req);

    assert_eq!(resp["result"], 11);
    assert_eq!(resp["signed_data"], "");
    assert_eq!(resp["id"], "");
}

/// E20: verify-sign中signed_data无效Base64
///
/// 测试场景：verify-sign请求中signed_data字段包含非法Base64字符
///
/// 预期结果：返回result=11，signed_data=""，id=""
/// 原因：无法解码Base64字符串
///
/// 测试依赖：无（插件API测试）
#[test]
fn e20_invalid_base64_in_signed_data() {
    let temp_dir = TempDir::new().unwrap();
    let ctx = setup_plugin_test_context(&temp_dir);

    let cert_id_b64 = ctx.cert_id_b64();

    let req = build_verify_sign_request(
        "test data",
        "!!!invalid-base64!!!",
        &cert_id_b64,
        "new data",
        &cert_id_b64,
    );
    let resp = handle_verify_sign_and_parse(&ctx, &req);

    assert_eq!(resp["result"], 11);
    assert_eq!(resp["signed_data"], "");
    assert_eq!(resp["id"], "");
}
