//! TLS证书链调试测试模块
//!
//! 测试目的：
//! - 调试TLS握手失败问题
//! - 验证证书链构建是否正确
//! - 分析OpenSSL验证回调行为
//!
//! 用途：问题诊断，非生产测试
//! 状态：ignore标记，仅调试时手动运行

use std::process::Command;
use std::thread;
use std::time::Duration;
use std::path::PathBuf;
use std::cmp::Ordering;
use tempfile::TempDir;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;

/// 生成测试证书
///
/// 用途：调用cert-gen工具生成TLS和CMS证书
/// 输出：证书目录结构
fn generate_test_certs(cert_dir: &PathBuf) {
    let cert_gen = std::env::var("CERT_GEN_PATH")
        .unwrap_or_else(|_| "../../../target/release/cert-gen".to_string());

    println!("Using cert-gen at: {}", cert_gen);
    println!("Generating certs to: {}", cert_dir.display());

    let status = Command::new(&cert_gen)
        .arg("--output")
        .arg(cert_dir)
        .arg("--server-count")
        .arg("1")
        .status()
        .expect("Failed to run cert-gen");

    assert!(status.success(), "cert-gen failed");
}

/// 查找并构建证书链文件
///
/// 用途：将服务器证书和CA证书合并为链文件
/// 返回：服务器证书、密钥、CA证书、链文件、客户端证书路径
fn find_cert_files(cert_dir: &PathBuf) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let server_cert = cert_dir.join("tls/server/node-a/node.crt");
    let server_key = cert_dir.join("tls/server/node-a/node.key");
    let ca_cert = cert_dir.join("tls/ca.crt");
    let chain_file = cert_dir.join("tls/server/node-a/node-chain.crt");

    // Copy server cert + CA cert to chain file
    let server_pem = std::fs::read(&server_cert).expect("Failed to read server cert");
    let ca_pem = std::fs::read(&ca_cert).expect("Failed to read CA cert");

    let mut chain = server_pem.clone();
    chain.extend_from_slice(&ca_pem);
    std::fs::write(&chain_file, &chain).expect("Failed to write chain file");

    (server_cert, server_key, ca_cert, chain_file, cert_dir.join("tls/client/node-a/node.crt"))
}

/// TLS证书链验证调试测试
///
/// 测试步骤：
/// 1. 生成测试证书
/// 2. 加载并验证证书结构
/// 3. 构建TLS客户端connector
/// 4. 启动trustruntime服务端
/// 5. 观察TLS握手过程
///
/// 用途：诊断证书链问题，非自动化测试
#[test]
#[ignore = "Debug test for TLS certificate chain issue"]
fn debug_tls_chain_verification() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let cert_dir = temp_dir.path().to_path_buf();

    println!("=== Step 1: Generate test certificates ===");
    generate_test_certs(&cert_dir);

    println!("=== Step 2: Find certificate files ===");
    let (server_cert, server_key, ca_cert, chain_file, client_cert) = find_cert_files(&cert_dir);

    println!("Server cert: {:?}", server_cert);
    println!("Server key: {:?}", server_key);
    println!("CA cert: {:?}", ca_cert);
    println!("Chain file: {:?}", chain_file);
    println!("Client cert: {:?}", client_cert);

    // Verify certificates can be loaded
    println!("\n=== Step 3: Load and verify certificates ===");

    let server_x509 = X509::from_pem(&std::fs::read(&server_cert).unwrap()).unwrap();
    println!("Server cert subject: {:?}", server_x509.subject_name());
    println!("Server cert issuer: {:?}", server_x509.issuer_name());

    let ca_x509 = X509::from_pem(&std::fs::read(&ca_cert).unwrap()).unwrap();
    println!("CA cert subject: {:?}", ca_x509.subject_name());
    println!("CA cert issuer: {:?}", ca_x509.issuer_name());

    // Verify CA is self-signed
    let ca_self_signed = ca_x509.issuer_name().try_cmp(ca_x509.subject_name()).unwrap_or(Ordering::Equal) == Ordering::Equal;
    println!("CA is self-signed: {}", ca_self_signed);

    // Verify server cert is signed by CA
    let server_issuer = server_x509.issuer_name();
    let ca_subject = ca_x509.subject_name();
    let issuer_matches = server_issuer.try_cmp(ca_subject).unwrap_or(Ordering::Equal) == Ordering::Equal;
    println!("Server issuer matches CA subject: {}", issuer_matches);

    // Build client connector
    println!("\n=== Step 4: Build TLS client connector ===");
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();

    // Load CA cert
    let ca_data = std::fs::read(&ca_cert).unwrap();
    let ca_x509 = X509::from_pem(&ca_data).unwrap();
    builder.cert_store_mut().add_cert(ca_x509).unwrap();
    println!("CA cert loaded into trust store");

    // Set verification callback
    builder.set_verify_callback(SslVerifyMode::PEER, |preverify_ok, x509_ctx| {
        println!("verify_callback called: preverify_ok={}", preverify_ok);
        if let Some(cert) = x509_ctx.current_cert() {
            println!("  Current cert: {:?}", cert.subject_name());
        }
        println!("  Error: {:?}", x509_ctx.error());
        println!("  Error depth: {}", x509_ctx.error_depth());
        true  // Always return true to skip verification
    });

    let connector = builder.build();
    println!("Client connector built successfully");

    // Start server
    println!("\n=== Step 5: Start server process ===");
    let binary_path = std::env::var("TEST_BINARY_PATH")
        .unwrap_or_else(|_| "../target/release/trustruntime".to_string());

    let config_content = format!(r#"
[vsock]
port = 12345

[log]
path = "{}/trustring.log"
max_file_size = 10
max_roll_count = 10

[certificate]
signer_cert = "{}/cms/node-a/signer.crt"
signer_key = "{}/cms/node-a/signer.key"
ca_root_cert = "{}/cms/ca.crt"

comm_cert = "{}"
comm_key = "{}"
comm_ca_root = "{}"
"#,
        cert_dir.display(),
        cert_dir.display(),
        cert_dir.display(),
        cert_dir.display(),
        chain_file.display(),
        server_key.display(),
        ca_cert.display()
    );

    let config_path = cert_dir.join("config.toml");
    std::fs::write(&config_path, &config_content).unwrap();
    println!("Server config written to: {:?}", config_path);
    println!("Config:\n{}", config_content);

    let mut server = Command::new(&binary_path)
        .arg("--config")
        .arg(&config_path)
        .env("RUST_LOG", "debug")
        .spawn()
        .expect("Failed to start server");

    println!("Server started with PID: {}", server.id());

    // Wait for server to start
    thread::sleep(Duration::from_secs(2));

    // Check if server is still running
    match server.try_wait() {
        Ok(Some(status)) => {
            println!("Server exited with status: {:?}", status);
            let output = server.wait_with_output().unwrap();
            println!("Server stdout: {}", String::from_utf8_lossy(&output.stdout));
            println!("Server stderr: {}", String::from_utf8_lossy(&output.stderr));
            return;  // Server already exited
        }
        Ok(None) => {
            println!("Server is still running");
        }
        Err(e) => {
            println!("Error checking server status: {}", e);
        }
    }

    // Cleanup
    server.kill().expect("Failed to kill server");
}