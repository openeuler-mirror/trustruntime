//! vsock通信测试模块
//!
//! 测试范围：
//! - C01: TLS双向认证成功
//! - C02-C04: TLS客户端证书错误（CRL吊销、错误CA、无效格式）
//! - C05: 消息长度超限
//! - C06: 协议版本不匹配
//! - C07: 字节序一致性（Little-Endian）
//! - C08: 版本不匹配拒绝
//! - C09-C11: 并发连接测试（16连接、信号量限制、释放后重连）
//!
//! 重点验证：TLS握手、消息协议、并发连接管理

use integration_tests::proc_manager::{NodeConfig, ProcessManager};
use integration_tests::test_helpers::TestPaths;
use integration_tests::vsock_client::VsockClient;
use std::fs;

/// 协议版本号（当前版本）
const VSOCK_VERSION: u32 = 0xFFFF0400;
/// 签名请求消息类型
const MSG_TYPE_SIGN_REQ: u32 = 0x10;
/// 通用错误消息类型
const MSG_TYPE_GENERIC_ERROR: u32 = 0x01;
/// 协议错误消息类型
const MSG_TYPE_PROTOCOL_ERROR: u32 = 0x02;

/// C01: TLS双向认证成功
///
/// 测试场景：客户端使用有效证书进行TLS握手，发送签名请求
///
/// 预期结果：TLS握手成功，签名请求返回result=0
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Linux environment (vsock) and certificates"]
fn c01_tls_mutual_auth_success() {
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

    let mut client = VsockClient::connect(
        12345,
        &paths.tls_ca_cert(),
        &paths.tls_client_cert(),
        &paths.tls_client_key(),
        paths.tls_key_password().as_deref(),
    )
    .expect("Failed to connect with TLS");

    let sign_resp = client
        .sign("test data for c01")
        .expect("Sign request failed");
    assert_eq!(sign_resp.result, 0, "Expected successful sign result");
    assert!(
        !sign_resp.signed_data.is_empty(),
        "signed_data should not be empty"
    );
    assert!(!sign_resp.id.is_empty(), "id should not be empty");

    client.close().expect("Failed to close client");
    manager.stop_all().expect("Failed to stop processes");
}

/// C02: 客户端证书CRL吊销
///
/// 测试场景：客户端使用已吊销证书进行TLS握手
///
/// 预期结果：TLS握手失败，返回TLS错误
/// 原因：客户端证书在服务端CRL列表中
///
/// 测试依赖：Linux环境、vsock、TLS证书链、CRL文件
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Linux environment (vsock) and certificates"]
fn c02_client_cert_crl_revoked() {
    let paths = TestPaths::new();
    let manager = ProcessManager::new(paths.binary_path.clone(), paths.cert_base.clone());

    let node_a_config = NodeConfig {
        name: "node-a".to_string(),
        port: 12345,
        cms_cert_path: paths.node_cms_cert("node-a"),
        cms_key_path: paths.node_cms_key("node-a"),
        tls_cert_path: paths.node_tls_cert("node-a"),
        tls_key_path: paths.node_tls_key("node-a"),
        tls_client_crl: Some(paths.tls_client_crl()),
    };

    manager
        .start_node(node_a_config)
        .expect("Failed to start node-a");

    let result = VsockClient::connect(
        12345,
        &paths.tls_ca_cert(),
        &paths.tls_client_revoked_cert(),
        &paths.tls_client_revoked_key(),
        paths.tls_key_password().as_deref(),
    );

    assert!(
        result.is_err(),
        "Expected TLS handshake failure with revoked cert"
    );
    if let Err(e) = result {
        let err_msg = e.to_string();
        assert!(
            err_msg.contains("tls handshake") || err_msg.contains("TLS"),
            "Expected TLS handshake error, got: {}",
            err_msg
        );
    }

    manager.stop_all().expect("Failed to stop processes");
}

/// C03: 客户端证书错误CA
///
/// 测试场景：客户端使用其他CA签发的证书进行TLS握手
///
/// 预期结果：TLS握手失败，返回TLS错误
/// 原因：证书签发CA与服务端信任CA不匹配
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Linux environment (vsock) and certificates"]
fn c03_client_cert_wrong_ca() {
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

    let result = VsockClient::connect(
        12345,
        &paths.tls_ca_cert(),
        &paths.tls_client_wrong_ca_cert(),
        &paths.tls_client_wrong_ca_key(),
        paths.tls_key_password().as_deref(),
    );

    assert!(
        result.is_err(),
        "Expected TLS handshake failure with wrong CA cert"
    );
    if let Err(e) = result {
        let err_msg = e.to_string();
        assert!(
            err_msg.contains("tls handshake") || err_msg.contains("TLS"),
            "Expected TLS handshake error, got: {}",
            err_msg
        );
    }

    manager.stop_all().expect("Failed to stop processes");
}

/// C04: 客户端证书无效格式
///
/// 测试场景：客户端使用无效格式的证书文件进行TLS握手
///
/// 预期结果：TLS握手失败，返回TLS错误
/// 原因：无法解析证书文件
///
/// 测试依赖：Linux环境、vsock
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Linux environment (vsock) and certificates"]
fn c04_client_cert_invalid() {
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

    let temp_dir = tempfile::TempDir::new().expect("Failed to create temp dir");
    let invalid_cert_path = temp_dir.path().join("invalid.crt");
    let invalid_key_path = temp_dir.path().join("invalid.key");

    fs::write(&invalid_cert_path, "not a valid certificate").expect("Failed to write invalid cert");
    fs::write(&invalid_key_path, "not a valid key").expect("Failed to write invalid key");

    let result = VsockClient::connect(
        12345,
        &paths.tls_ca_cert(),
        &invalid_cert_path,
        &invalid_key_path,
        None,
    );

    assert!(
        result.is_err(),
        "Expected TLS handshake failure with invalid cert"
    );
    if let Err(e) = result {
        let err_msg = e.to_string();
        assert!(
            err_msg.contains("tls handshake") || err_msg.contains("TLS"),
            "Expected TLS handshake error, got: {}",
            err_msg
        );
    }

    manager.stop_all().expect("Failed to stop processes");
}

/// C05: 消息长度超限
///
/// 测试场景：发送长度超过协议限制（>10KB）的消息
///
/// 预期结果：服务端返回协议错误（msg_type=0x02），len=0
/// 原因：消息长度超出单次传输上限
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Linux environment (vsock) and certificates"]
fn c05_message_too_long() {
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

    let mut client = VsockClient::connect(
        12345,
        &paths.tls_ca_cert(),
        &paths.tls_client_cert(),
        &paths.tls_client_key(),
        paths.tls_key_password().as_deref(),
    )
    .expect("Failed to connect with TLS");

    let large_len: u32 = 12000;
    let result = client.send_raw_header(VSOCK_VERSION, MSG_TYPE_SIGN_REQ, large_len);

    assert!(result.is_ok(), "send_raw_header should succeed");
    let raw_resp = result.expect("Expected raw response");

    assert_eq!(
        raw_resp.msg_type, MSG_TYPE_PROTOCOL_ERROR,
        "Expected protocol error (type=0x02) for message too long"
    );
    assert_eq!(raw_resp.len, 0, "Expected len=0 for protocol error");

    client.close().expect("Failed to close client");
    manager.stop_all().expect("Failed to stop processes");
}

/// C06: 协议版本不匹配
///
/// 测试场景：发送错误协议版本号（0xFFFF0000）
///
/// 预期结果：服务端返回通用错误（msg_type=0x01），len=0
/// 原因：协议版本验证失败
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Linux environment (vsock) and certificates"]
fn c06_version_mismatch() {
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

    let mut client = VsockClient::connect(
        12345,
        &paths.tls_ca_cert(),
        &paths.tls_client_cert(),
        &paths.tls_client_key(),
        paths.tls_key_password().as_deref(),
    )
    .expect("Failed to connect with TLS");

    let wrong_version: u32 = 0xFFFF0000;
    let result = client.send_raw_header(wrong_version, MSG_TYPE_SIGN_REQ, 10);

    assert!(result.is_ok(), "send_raw_header should succeed");
    let raw_resp = result.expect("Expected raw response");

    assert_eq!(
        raw_resp.msg_type, MSG_TYPE_GENERIC_ERROR,
        "Expected generic error (type=0x01) for version mismatch"
    );
    assert_eq!(raw_resp.len, 0, "Expected len=0 for generic error");

    client.close().expect("Failed to close client");
    manager.stop_all().expect("Failed to stop processes");
}

/// C07: 字节序一致性验证（Little-Endian）
///
/// 测试场景：验证消息头使用Little-Endian字节序
///
/// 预期结果：签名请求成功返回result=0
/// 说明：vsock消息协议统一使用LE字节序（见AGENTS.md）
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn c07_byte_order_le_consistency() {
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

    let mut client = VsockClient::connect(
        12345,
        &paths.tls_ca_cert(),
        &paths.tls_client_cert(),
        &paths.tls_client_key(),
        paths.tls_key_password().as_deref(),
    )
    .expect("Failed to connect with TLS");

    // Test that LE byte order works correctly
    let sign_resp = client
        .sign("test data for byte order consistency")
        .expect("Sign request with LE byte order should succeed");

    assert_eq!(
        sign_resp.result, 0,
        "Expected successful sign result with LE byte order"
    );
    assert!(
        !sign_resp.signed_data.is_empty(),
        "signed_data should not be empty"
    );
    assert!(!sign_resp.id.is_empty(), "id should not be empty");

    client.close().expect("Failed to close client");
    manager.stop_all().expect("Failed to stop processes");
}

/// C08: 版本不匹配拒绝
///
/// 测试场景：发送完全无效的版本号（0xDEADBEEF）
///
/// 预期结果：服务端返回通用错误（msg_type=0x01）
/// 说明：验证服务端对无效版本的拒绝处理
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn c08_version_mismatch_rejection() {
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

    let mut client = VsockClient::connect(
        12345,
        &paths.tls_ca_cert(),
        &paths.tls_client_cert(),
        &paths.tls_client_key(),
        paths.tls_key_password().as_deref(),
    )
    .expect("Failed to connect with TLS");

    // Test version mismatch (wrong version number)
    // Note: This test uses send_raw_header which allows sending wrong version
    // to verify server rejects it with type=0x01
    let wrong_version: u32 = 0xDEADBEEF; // Invalid version
    let result = client.send_raw_header(wrong_version, MSG_TYPE_SIGN_REQ, 10);

    assert!(result.is_ok(), "send_raw_header should succeed");
    let raw_resp = result.expect("Expected raw response");

    // Server should reject wrong version with type=0x01 (generic error)
    assert_eq!(
        raw_resp.msg_type, MSG_TYPE_GENERIC_ERROR,
        "Server should reject wrong version with type=0x01"
    );
    assert_eq!(raw_resp.len, 0, "Expected len=0 for error response");

    client.close().expect("Failed to close client");
    manager.stop_all().expect("Failed to stop processes");
}

/// C09: 并发16连接测试
///
/// 测试场景：同时建立16个并发连接，每个连接发送签名请求
///
/// 预期结果：所有连接成功，所有签名请求返回result=0
/// 说明：验证并发连接处理能力（信号量上限16，见AGENTS.md）
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn c09_concurrent_16_connections() {
    use std::sync::mpsc;
    use std::thread;

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

    // Spawn 16 concurrent connections
    let (tx, rx) = mpsc::channel();
    let mut handles = vec![];

    for i in 0..16 {
        let tx_clone = tx.clone();
        let tls_ca = paths.tls_ca_cert();
        let tls_cert = paths.tls_client_cert();
        let tls_key = paths.tls_client_key();
        let key_pwd = paths.tls_key_password();

        let handle = thread::spawn(move || {
            let mut client =
                VsockClient::connect(12345, &tls_ca, &tls_cert, &tls_key, key_pwd.as_deref())
                    .unwrap_or_else(|e| panic!("Failed to connect client {}: {}", i, e));

            let resp = client
                .sign(&format!("test data {}", i))
                .unwrap_or_else(|e| panic!("Sign request {} failed: {}", i, e));

            tx_clone
                .send((i, resp.result))
                .expect("Failed to send result");
            client
                .close()
                .unwrap_or_else(|e| panic!("Failed to close client {}: {}", i, e));
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Verify all requests succeeded
    let mut results = vec![];
    for _ in 0..16 {
        results.push(rx.recv().expect("Failed to receive result"));
    }

    for (i, result) in results {
        assert_eq!(result, 0, "Client {} should have successful result", i);
    }

    manager.stop_all().expect("Failed to stop processes");
}

/// C10: 信号量限制等待测试
///
/// 测试场景：
/// 1. 建立16个长连接（保持活跃）
/// 2. 尝试建立第17个连接
///
/// 预期结果：第17个连接等待后成功（10秒内）
/// 说明：Semaphore with 16 permits，超限连接需等待许可释放
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn c10_semaphore_limit_wait() {
    use std::thread;
    use std::time::Duration;

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

    // Spawn 16 connections that hold permits (keep them alive)
    let mut long_handles = vec![];
    let key_pwd = paths.tls_key_password();
    for i in 0..16 {
        let tls_ca = paths.tls_ca_cert();
        let tls_cert = paths.tls_client_cert();
        let tls_key = paths.tls_client_key();
        let key_pwd_clone = key_pwd.clone();

        let handle = thread::spawn(move || {
            let mut client = VsockClient::connect(
                12345,
                &tls_ca,
                &tls_cert,
                &tls_key,
                key_pwd_clone.as_deref(),
            )
            .unwrap_or_else(|e| panic!("Failed to connect long client {}: {}", i, e));

            // Keep connection alive by doing multiple requests
            for _ in 0..5 {
                thread::sleep(Duration::from_millis(100));
                client.sign("keep alive data").ok();
            }

            client
                .close()
                .unwrap_or_else(|e| panic!("Failed to close long client {}: {}", i, e));
        });

        long_handles.push(handle);
    }

    // Wait a bit to ensure all 16 connections are established
    thread::sleep(Duration::from_millis(200));

    // Try to create 17th connection (should wait for semaphore)
    let tls_ca = paths.tls_ca_cert();
    let tls_cert = paths.tls_client_cert();
    let tls_key = paths.tls_client_key();

    let start_time = std::time::Instant::now();
    let mut client_17 =
        VsockClient::connect(12345, &tls_ca, &tls_cert, &tls_key, key_pwd.as_deref())
            .expect("Failed to connect client 17");

    // Connection should eventually succeed (after one of the 16 releases)
    let elapsed = start_time.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "Connection 17 should succeed within 10s"
    );

    let resp = client_17
        .sign("test data 17")
        .expect("Sign request 17 failed");
    assert_eq!(resp.result, 0, "Client 17 should have successful result");

    client_17.close().expect("Failed to close client 17");

    // Wait for all long connections to finish
    for handle in long_handles {
        handle.join().expect("Long thread panicked");
    }

    manager.stop_all().expect("Failed to stop processes");
}

/// C11: 信号量释放后重连测试
///
/// 测试场景：
/// 1. 建立16个连接后立即关闭
/// 2. 再建立16个新连接
///
/// 预期结果：新连接全部成功
/// 说明：验证连接关闭后信号量许可正确释放
///
/// 测试依赖：Linux环境、vsock、TLS证书链
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Linux environment (vsock) and certificates, TLS certificate chain issue pending fix"]
fn c11_semaphore_release_after_disconnect() {
    use std::thread;

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

    // Create 16 connections and immediately close them
    let mut handles = vec![];
    let key_pwd = paths.tls_key_password();
    for i in 0..16 {
        let tls_ca = paths.tls_ca_cert();
        let tls_cert = paths.tls_client_cert();
        let tls_key = paths.tls_client_key();
        let key_pwd_clone = key_pwd.clone();

        let handle = thread::spawn(move || {
            let mut client = VsockClient::connect(
                12345,
                &tls_ca,
                &tls_cert,
                &tls_key,
                key_pwd_clone.as_deref(),
            )
            .unwrap_or_else(|e| panic!("Failed to connect client {}: {}", i, e));

            client.sign(&format!("test data {}", i)).ok();
            // Immediately close to release semaphore
            client
                .close()
                .unwrap_or_else(|e| panic!("Failed to close client {}: {}", i, e));
        });

        handles.push(handle);
    }

    // Wait for all connections to close
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Now create 16 new connections (should succeed immediately because permits were released)
    let mut new_handles = vec![];
    for i in 0..16 {
        let tls_ca = paths.tls_ca_cert();
        let tls_cert = paths.tls_client_cert();
        let tls_key = paths.tls_client_key();
        let key_pwd_clone = key_pwd.clone();

        let handle = thread::spawn(move || {
            let mut client = VsockClient::connect(
                12345,
                &tls_ca,
                &tls_cert,
                &tls_key,
                key_pwd_clone.as_deref(),
            )
            .unwrap_or_else(|e| panic!("Failed to connect new client {}: {}", i, e));

            let resp = client
                .sign(&format!("new test data {}", i))
                .unwrap_or_else(|e| panic!("Sign request new {} failed: {}", i, e));

            assert_eq!(
                resp.result, 0,
                "New client {} should have successful result",
                i
            );
            client
                .close()
                .unwrap_or_else(|e| panic!("Failed to close new client {}: {}", i, e));
        });

        new_handles.push(handle);
    }

    // All new connections should succeed quickly
    for handle in new_handles {
        handle.join().expect("New thread panicked");
    }

    manager.stop_all().expect("Failed to stop processes");
}

/// 非Linux平台通信测试禁用提示
///
/// 说明：非Linux平台不支持vsock，TCP回退模式不验证TLS
#[cfg(not(target_os = "linux"))]
#[test]
fn communication_tests_disabled_on_non_linux() {
    println!("Communication tests are disabled on non-Linux platforms (TCP fallback without TLS validation)");
}
