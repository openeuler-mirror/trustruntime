//! 正常场景测试模块（N01-N03）
//!
//! 测试范围：
//! - N01: 两节点签名验签流程
//! - N02: 三节点签名验签流程（验证OtherNode状态）
//! - N03: 单节点签名验签流程（验证IdentityConflict状态）
//!
//! 测试前提条件：
//! - Linux环境（vsock支持）
//! - TLS证书链完整
//! - CMS签名证书配置正确

use integration_tests::proc_manager::{NodeConfig, ProcessManager};
use integration_tests::test_helpers::{
    assert_sign_success, assert_verify_identity_conflict, assert_verify_other_node,
    assert_verify_success, TestPaths, TEST_DATA_A, TEST_DATA_B,
};
use integration_tests::vsock_client::{build_verify_sign_request, VsockClient};

/// N01: 两节点签名验签流程
///
/// 测试场景：
/// 1. node-a签名数据A，返回签名结果和节点ID
/// 2. node-b验证签名后签名数据B，返回新的签名结果
/// 3. node-a验证node-b的签名，期望result=0（SameNode）
///
/// 预期结果：
/// - 签名操作返回result=0，signed_data非空，id非空
/// - 验签操作返回result=0（同节点验证成功）
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn n01_two_node_sign_verify() {
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
    eprintln!(
        "DEBUG: sign_resp_a = result={}, signed_data_len={}, id_len={}",
        sign_resp_a.result,
        sign_resp_a.signed_data.len(),
        sign_resp_a.id.len()
    );
    assert_sign_success(
        sign_resp_a.result,
        &sign_resp_a.signed_data,
        &sign_resp_a.id,
    );

    let verify_sign_req = build_verify_sign_request(
        TEST_DATA_A,
        &sign_resp_a.signed_data,
        &sign_resp_a.id,
        TEST_DATA_B,
        &sign_resp_a.id,
    );

    let verify_sign_resp = client_b
        .verify_and_sign(verify_sign_req)
        .expect("Verify-sign request to node-b failed");
    eprintln!(
        "DEBUG: verify_sign_resp = result={}, signed_data_len={}, id_len={}",
        verify_sign_resp.result,
        verify_sign_resp.signed_data.len(),
        verify_sign_resp.id.len()
    );
    assert_sign_success(
        verify_sign_resp.result,
        &verify_sign_resp.signed_data,
        &verify_sign_resp.id,
    );

    let verify_resp_a = client_a
        .verify(TEST_DATA_B, &verify_sign_resp.signed_data, &sign_resp_a.id)
        .expect("Verify request to node-a failed");

    assert_verify_success(verify_resp_a.result);

    client_a.close().expect("Failed to close client_a");
    client_b.close().expect("Failed to close client_b");

    manager.stop_all().expect("Failed to stop processes");
}

/// N02: 三节点签名验签流程
///
/// 测试场景：
/// 1. node-a签名数据A
/// 2. node-b验证签名后签名数据B
/// 3. node-c验证node-b的签名，期望result=1（OtherNode）
///
/// 预期结果：
/// - node-c验签返回result=1（其他节点签名，非冲突）
/// - 签名数据由node-b生成，节点ID为node-a
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn n02_three_node_sign_verify() {
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

    let node_c_config = NodeConfig {
        name: "node-c".to_string(),
        port: 12347,
        cms_cert_path: paths.node_cms_cert("node-c"),
        cms_key_path: paths.node_cms_key("node-c"),
        tls_cert_path: paths.node_tls_cert("node-c"),
        tls_key_path: paths.node_tls_key("node-c"),
        tls_client_crl: None,
    };

    manager
        .start_node(node_a_config)
        .expect("Failed to start node-a");
    manager
        .start_node(node_b_config)
        .expect("Failed to start node-b");
    manager
        .start_node(node_c_config)
        .expect("Failed to start node-c");

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

    let mut client_c = VsockClient::connect(
        12347,
        &paths.tls_ca_cert(),
        &paths.tls_client_cert(),
        &paths.tls_client_key(),
    )
    .expect("Failed to connect to node-c");

    let sign_resp_a = client_a
        .sign(TEST_DATA_A)
        .expect("Sign request to node-a failed");
    eprintln!(
        "DEBUG: sign_resp_a = result={}, signed_data_len={}, id_len={}",
        sign_resp_a.result,
        sign_resp_a.signed_data.len(),
        sign_resp_a.id.len()
    );
    assert_sign_success(
        sign_resp_a.result,
        &sign_resp_a.signed_data,
        &sign_resp_a.id,
    );

    let verify_sign_req = build_verify_sign_request(
        TEST_DATA_A,
        &sign_resp_a.signed_data,
        &sign_resp_a.id,
        TEST_DATA_B,
        &sign_resp_a.id,
    );

    let verify_sign_resp = client_b
        .verify_and_sign(verify_sign_req)
        .expect("Verify-sign request to node-b failed");
    eprintln!(
        "DEBUG: verify_sign_resp = result={}, signed_data_len={}, id_len={}",
        verify_sign_resp.result,
        verify_sign_resp.signed_data.len(),
        verify_sign_resp.id.len()
    );
    assert_sign_success(
        verify_sign_resp.result,
        &verify_sign_resp.signed_data,
        &verify_sign_resp.id,
    );

    let verify_resp_c = client_c
        .verify(TEST_DATA_B, &verify_sign_resp.signed_data, &sign_resp_a.id)
        .expect("Verify request to node-c failed");
    eprintln!("DEBUG: verify_resp_c = result={}", verify_resp_c.result);
    assert_verify_other_node(verify_resp_c.result);

    client_a.close().expect("Failed to close client_a");
    client_b.close().expect("Failed to close client_b");
    client_c.close().expect("Failed to close client_c");

    manager.stop_all().expect("Failed to stop processes");
}

/// N03: 单节点签名验签流程
///
/// 测试场景：
/// 1. node-a签名数据A
/// 2. node-a验证签名后签名数据B（同节点操作）
/// 3. node-a验证自己的签名，期望result=2（IdentityConflict）
///
/// 预期结果：
/// - 验签返回result=2（证书身份冲突：公钥相同但ID不同）
/// - 原因：node-a签名数据A后，再用node-a的ID签名数据B，
///   验证时发现签名者ID（node-a）与验签节点ID（node-a）相同
///
/// 业务规则：result=2优先级高于result=1
/// - result=1: 其他节点签名（ID不同）
/// - result=2: 证书身份冲突（公钥相同但ID不同）
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn n03_single_node_sign_verify() {
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

    manager
        .start_node(node_a_config)
        .expect("Failed to start node-a");

    let mut client_a = VsockClient::connect(
        12345,
        &paths.tls_ca_cert(),
        &paths.tls_client_cert(),
        &paths.tls_client_key(),
    )
    .expect("Failed to connect to node-a");

    let sign_resp_a = client_a
        .sign(TEST_DATA_A)
        .expect("Sign request to node-a failed");
    eprintln!(
        "DEBUG: sign_resp_a = result={}, signed_data_len={}, id_len={}",
        sign_resp_a.result,
        sign_resp_a.signed_data.len(),
        sign_resp_a.id.len()
    );
    assert_sign_success(
        sign_resp_a.result,
        &sign_resp_a.signed_data,
        &sign_resp_a.id,
    );

    let verify_sign_req = build_verify_sign_request(
        TEST_DATA_A,
        &sign_resp_a.signed_data,
        &sign_resp_a.id,
        TEST_DATA_B,
        &sign_resp_a.id,
    );

    let verify_sign_resp = client_a
        .verify_and_sign(verify_sign_req)
        .expect("Verify-sign request to node-a failed");
    eprintln!(
        "DEBUG: verify_sign_resp = result={}, signed_data_len={}, id_len={}",
        verify_sign_resp.result,
        verify_sign_resp.signed_data.len(),
        verify_sign_resp.id.len()
    );
    assert_sign_success(
        verify_sign_resp.result,
        &verify_sign_resp.signed_data,
        &verify_sign_resp.id,
    );

    let verify_resp_a = client_a
        .verify(TEST_DATA_B, &verify_sign_resp.signed_data, &sign_resp_a.id)
        .expect("Verify request to node-a failed");
    eprintln!("DEBUG: verify_resp_a = result={}", verify_resp_a.result);
    assert_verify_identity_conflict(verify_resp_a.result);

    client_a.close().expect("Failed to close client_a");

    manager.stop_all().expect("Failed to stop processes");
}
