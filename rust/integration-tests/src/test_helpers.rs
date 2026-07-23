//! 测试辅助工具模块
//!
//! 提供集成测试所需的各种辅助功能：
//! - **路径管理**: 统一管理测试证书文件路径
//! - **插件测试上下文**: 模拟TransportLayer进行插件单元测试
//! - **断言辅助函数**: 简化结果码验证
//! - **请求构建**: 构建签名/验签请求JSON
//!
//! ## 使用示例
//! ```text
//! let temp_dir = TempDir::new().unwrap();
//! let ctx = setup_plugin_test_context(&temp_dir);
//! let (signed_data, id) = sign_and_encode(&ctx, b"test data");
//! ```
//!
//! ## 相关模块
//! - `test_cert_gen`: 证书生成工具
//! - `test_crl_gen`: CRL生成工具

use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tempfile::TempDir;
use trustring::TrustringPlugin;
use trustruntime_framework::cert::{extract_subject_key_id, load_x509};
use trustruntime_framework::config::AppConfig;
use trustruntime_framework::plugin_manager::{Plugin, PluginContext};
use trustruntime_framework::transport::{DataHandler, TransportError, TransportLayer};

use crate::test_cert_gen::generate_ca_and_signer;

/// 测试数据A - 常用测试字符串
pub const TEST_DATA_A: &str = "test-string-A";

/// 测试数据B - 常用测试字符串
pub const TEST_DATA_B: &str = "test-string-B";

/// 测试数据C - 常用测试字符串
pub const TEST_DATA_C: &str = "test-string-C";

// 消息类型常量 - 与消息模块定义一致
const MSG_TYPE_SIGN_REQ: u32 = 0x10;
const MSG_TYPE_VERIFY_SIGN_REQ: u32 = 0x12;
const MSG_TYPE_VERIFY_REQ: u32 = 0x14;

/// 测试路径配置
///
/// 管理测试所需的证书目录和二进制文件路径。
/// 支持通过环境变量覆盖默认路径：
/// - `TEST_CERT_DIR`: 测试证书目录
/// - `TEST_BINARY_PATH`: trustruntime可执行文件路径
pub struct TestPaths {
    /// 证书基础目录
    pub cert_base: PathBuf,
    /// trustruntime二进制文件路径
    pub binary_path: PathBuf,
}

impl Default for TestPaths {
    fn default() -> Self {
        Self::new()
    }
}

impl TestPaths {
    /// 创建新的测试路径配置
    ///
    /// 默认值：
    /// - cert_base: `$HOME/test-certs` 或 `TEST_CERT_DIR` 环境变量
    /// - binary_path: `target/debug/trustruntime` 或 `TEST_BINARY_PATH` 环境变量
    pub fn new() -> Self {
        let cert_base = std::env::var("TEST_CERT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(std::env::var("HOME").unwrap_or("/home".to_string()))
                    .join("test-certs")
            });

        let binary_path = std::env::var("TEST_BINARY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("target/debug/trustruntime"));

        Self {
            cert_base,
            binary_path,
        }
    }

    /// CMS CA证书路径
    pub fn cms_ca_cert(&self) -> PathBuf {
        self.cert_base.join("cms/ca.crt")
    }

    /// CMS CRL吊销列表路径
    pub fn cms_crl(&self) -> PathBuf {
        self.cert_base.join("cms/cms.crl")
    }

    /// 节点CMS签名证书路径
    pub fn node_cms_cert(&self, node: &str) -> PathBuf {
        self.cert_base.join(format!("cms/{}/signer.crt", node))
    }

    /// 节点CMS私钥路径
    pub fn node_cms_key(&self, node: &str) -> PathBuf {
        self.cert_base.join(format!("cms/{}/signer.key", node))
    }

    /// TLS CA证书路径
    pub fn tls_ca_cert(&self) -> PathBuf {
        self.cert_base.join("tls/ca.crt")
    }

    /// TLS客户端证书路径
    pub fn tls_client_cert(&self) -> PathBuf {
        self.cert_base.join("tls/client/client.crt")
    }

    /// TLS客户端私钥路径
    pub fn tls_client_key(&self) -> PathBuf {
        self.cert_base.join("tls/client/client.key")
    }

    /// 节点TLS服务端证书路径
    pub fn node_tls_cert(&self, node: &str) -> PathBuf {
        self.cert_base.join(format!("tls/server/{}/node.crt", node))
    }

    /// 节点TLS服务端私钥路径
    pub fn node_tls_key(&self, node: &str) -> PathBuf {
        self.cert_base.join(format!("tls/server/{}/node.key", node))
    }

    /// 自签名CMS证书路径（错误场景测试用）
    pub fn self_signed_cms_cert(&self) -> PathBuf {
        self.cert_base.join("cms/self-signed/signer.crt")
    }

    /// 自签名CMS私钥路径
    pub fn self_signed_cms_key(&self) -> PathBuf {
        self.cert_base.join("cms/self-signed/signer.key")
    }

    /// 已吊销CMS证书路径（错误场景测试用）
    pub fn revoked_cms_cert(&self) -> PathBuf {
        self.cert_base.join("cms/revoked/signer.crt")
    }

    /// 已吊销CMS私钥路径
    pub fn revoked_cms_key(&self) -> PathBuf {
        self.cert_base.join("cms/revoked/signer.key")
    }

    /// 已过期CMS证书路径（错误场景测试用）
    pub fn expired_cms_cert(&self) -> PathBuf {
        self.cert_base.join("cms/expired/signer.crt")
    }

    /// 已过期CMS私钥路径
    pub fn expired_cms_key(&self) -> PathBuf {
        self.cert_base.join("cms/expired/signer.key")
    }

    /// TLS客户端CRL路径
    pub fn tls_client_crl(&self) -> PathBuf {
        self.cert_base.join("tls/client-crl.crt")
    }

    /// 已吊销TLS客户端证书路径
    pub fn tls_client_revoked_cert(&self) -> PathBuf {
        self.cert_base.join("tls/client/revoked.crt")
    }

    /// 已吊销TLS客户端私钥路径
    pub fn tls_client_revoked_key(&self) -> PathBuf {
        self.cert_base.join("tls/client/revoked.key")
    }

    /// 错误CA签发的TLS客户端证书路径（错误场景测试用）
    pub fn tls_client_wrong_ca_cert(&self) -> PathBuf {
        self.cert_base.join("tls/client/wrong-ca.crt")
    }

    /// 错误CA签发的TLS客户端私钥路径
    pub fn tls_client_wrong_ca_key(&self) -> PathBuf {
        self.cert_base.join("tls/client/wrong-ca.key")
    }

    /// TLS私钥密码
    pub fn tls_key_password(&self) -> Option<String> {
        let pwd_path = self.cert_base.join("tls/key_pwd.txt");
        if pwd_path.exists() {
            std::fs::read_to_string(pwd_path)
                .map(|s| s.trim().to_string())
                .ok()
        } else {
            None
        }
    }
}

/// 断言结果码匹配预期值
///
/// # Arguments
/// * `actual` - 实际结果码
/// * `expected` - 预期结果码
pub fn assert_result_code(actual: u32, expected: u32) {
    assert_eq!(
        actual, expected,
        "Result code mismatch: expected {}, got {}",
        expected, actual
    );
}

/// 断言签名操作成功
///
/// 验证结果码为0，且返回的签名数据和证书ID非空。
///
/// # Arguments
/// * `result` - 签名结果码
/// * `signed_data` - Base64编码的签名数据
/// * `id` - Base64编码的证书ID
pub fn assert_sign_success(result: u32, signed_data: &str, id: &str) {
    assert_result_code(result, 0);
    assert!(
        !signed_data.is_empty(),
        "signed_data should not be empty on success"
    );
    assert!(!id.is_empty(), "id should not be empty on success");
}

/// 断言验签成功（result=0）
pub fn assert_verify_success(result: u32) {
    assert_result_code(result, 0);
}

/// 断言验签结果为其他节点签名（result=1）
///
/// 场景：签名数据有效，但证书ID与当前节点不同
pub fn assert_verify_other_node(result: u32) {
    assert_result_code(result, 1);
}

/// 断言验签结果为证书身份冲突（result=2）
///
/// 场景：签名数据有效，但证书公钥与ID不匹配
pub fn assert_verify_identity_conflict(result: u32) {
    assert_result_code(result, 2);
}

/// 断言验签失败
///
/// # Arguments
/// * `result` - 实际结果码
/// * `expected` - 预期错误结果码（3-9）
pub fn assert_verify_failed(result: u32, expected: u32) {
    assert_result_code(result, expected);
}

/// 测试证书集合
///
/// 包含动态生成的测试证书路径和证书ID。
pub struct TestCertificates {
    /// CA证书路径
    pub ca_path: PathBuf,
    /// 签名者证书路径
    pub signer_path: PathBuf,
    /// 签名者私钥路径
    pub signer_key_path: PathBuf,
    /// 证书ID（Subject Key Identifier原始字节）
    pub cert_id: Vec<u8>,
}

/// 在临时目录中设置测试证书
///
/// 生成CA和签名者证书，保存到临时目录，返回证书路径和ID。
///
/// # Arguments
/// * `temp_dir` - 临时目录引用
///
/// # Returns
/// TestCertificates结构体，包含证书路径和ID
pub fn setup_test_certificates(temp_dir: &TempDir) -> TestCertificates {
    let (ca_pem, signer_pem, signer_key_pem) = generate_ca_and_signer();

    let ca_path = temp_dir.path().join("ca.crt");
    let signer_path = temp_dir.path().join("signer.crt");
    let signer_key_path = temp_dir.path().join("signer.key");

    fs::write(&ca_path, &ca_pem).unwrap();
    fs::write(&signer_path, &signer_pem).unwrap();
    fs::write(&signer_key_path, &signer_key_pem).unwrap();

    let cert = load_x509(signer_path.to_str().unwrap()).unwrap();
    let cert_id = extract_subject_key_id(&cert).unwrap();

    TestCertificates {
        ca_path,
        signer_path,
        signer_key_path,
        cert_id,
    }
}

/// 将证书ID编码为Base64字符串
///
/// # Arguments
/// * `cert_id` - Subject Key Identifier原始字节
///
/// # Returns
/// Base64编码字符串
pub fn make_cert_id_b64(cert_id: &[u8]) -> String {
    general_purpose::STANDARD.encode(cert_id)
}

/// Mock传输层实现
///
/// 用于插件单元测试，模拟TransportLayer行为。
/// 不涉及实际的vsock/TLS连接，仅通过HashMap分发消息到处理器。
struct MockTransport {
    /// 消息处理器映射表（消息类型 -> 处理器）
    handlers: RwLock<HashMap<u32, Box<dyn DataHandler>>>,
}

impl MockTransport {
    /// 创建新的Mock传输层
    fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
        }
    }

    /// 调用指定消息类型的处理器
    ///
    /// # Arguments
    /// * `msg_type` - 消息类型（如0x10签名请求）
    /// * `data` - 消息体数据
    ///
    /// # Returns
    /// 处理器返回的响应数据，若无处理器则返回None
    fn call_handler(&self, msg_type: u32, data: &[u8]) -> Option<Vec<u8>> {
        let guard = self.handlers.read().unwrap();
        guard.get(&msg_type).and_then(|h| h.handle(data))
    }
}

#[async_trait]
impl TransportLayer for MockTransport {
    /// 注册消息处理器
    ///
    /// 将处理器绑定到指定消息类型。
    fn register_handler(&self, msg_type: u32, handler: Box<dyn DataHandler>) {
        self.handlers.write().unwrap().insert(msg_type, handler);
    }

    /// 启动传输层（Mock实现为空操作）
    async fn start(&self) -> Result<(), TransportError> {
        Ok(())
    }

    /// 停止传输层（Mock实现为空操作）
    async fn stop(&self) -> Result<(), TransportError> {
        Ok(())
    }
}

/// 插件测试上下文
///
/// 用于插件单元测试，封装了MockTransport和TrustringPlugin，
/// 提供简化的签名/验签接口。
///
/// ## 使用方式
/// ```text
/// let temp_dir = TempDir::new().unwrap();
/// let ctx = setup_plugin_test_context(&temp_dir);
/// // 发送签名请求
/// let request = build_sign_request("test data");
/// let result = ctx.sign(&request);
/// ```
pub struct PluginTestContext {
    /// Mock传输层
    transport: Arc<MockTransport>,
    /// 签名者证书ID
    cert_id: Vec<u8>,
}

impl PluginTestContext {
    /// 创建新的插件测试上下文
    ///
    /// 初始化TrustringPlugin并注册到MockTransport。
    ///
    /// # Arguments
    /// * `ca_path` - CA证书路径
    /// * `signer_path` - 签名者证书路径
    /// * `signer_key_path` - 签名者私钥路径
    /// * `crl_path` - CRL路径（可选）
    ///
    /// # Returns
    /// 插件测试上下文实例
    ///
    /// # Errors
    /// 证书加载或插件初始化失败时返回错误
    pub fn new(
        ca_path: &Path,
        signer_path: &Path,
        signer_key_path: &Path,
        crl_path: Option<&Path>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let transport = Arc::new(MockTransport::new());

        let mut plugin = TrustringPlugin::new(
            signer_path.to_str().unwrap(),
            signer_key_path.to_str().unwrap(),
            ca_path.to_str().unwrap(),
            crl_path.map(|p| p.to_str().unwrap()),
        )?;

        let config = Arc::new(
            AppConfig::from_toml(
                r#"
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
"#,
            )
            .unwrap(),
        );

        let ctx = PluginContext::new(config, transport.clone());
        plugin.init(&ctx)?;

        let cert = load_x509(signer_path.to_str().unwrap())?;
        let cert_id = extract_subject_key_id(&cert)?;

        Ok(Self { transport, cert_id })
    }

    /// 发送签名请求
    ///
    /// # Arguments
    /// * `data` - JSON格式的签名请求消息体
    ///
    /// # Returns
    /// JSON格式的签名响应，失败返回None
    pub fn sign(&self, data: &[u8]) -> Option<Vec<u8>> {
        self.transport.call_handler(MSG_TYPE_SIGN_REQ, data)
    }

    /// 发送验签+签名组合请求
    ///
    /// # Arguments
    /// * `data` - JSON格式的验签+签名请求消息体
    ///
    /// # Returns
    /// JSON格式的响应，失败返回None
    pub fn verify_sign(&self, data: &[u8]) -> Option<Vec<u8>> {
        self.transport.call_handler(MSG_TYPE_VERIFY_SIGN_REQ, data)
    }

    /// 发送验签请求
    ///
    /// # Arguments
    /// * `data` - JSON格式的验签请求消息体
    ///
    /// # Returns
    /// JSON格式的验签响应，失败返回None
    pub fn verify(&self, data: &[u8]) -> Option<Vec<u8>> {
        self.transport.call_handler(MSG_TYPE_VERIFY_REQ, data)
    }

    /// 获取证书ID原始字节
    pub fn cert_id(&self) -> &[u8] {
        &self.cert_id
    }

    /// 获取证书ID的Base64编码
    pub fn cert_id_b64(&self) -> String {
        make_cert_id_b64(&self.cert_id)
    }
}

/// 设置插件测试上下文（不使用CRL）
///
/// 便捷函数，创建临时目录和测试证书，初始化插件测试上下文。
pub fn setup_plugin_test_context(temp_dir: &TempDir) -> PluginTestContext {
    let certs = setup_test_certificates(temp_dir);
    PluginTestContext::new(
        &certs.ca_path,
        &certs.signer_path,
        &certs.signer_key_path,
        None,
    )
    .expect("Failed to create plugin test context")
}

/// 设置插件测试上下文（带CRL）
///
/// 用于测试证书吊销场景（如错误场景E09-E10）。
///
/// # Arguments
/// * `temp_dir` - 临时目录
/// * `crl_path` - CRL文件路径
pub fn setup_plugin_test_context_with_crl(
    temp_dir: &TempDir,
    crl_path: &Path,
) -> PluginTestContext {
    let certs = setup_test_certificates(temp_dir);
    PluginTestContext::new(
        &certs.ca_path,
        &certs.signer_path,
        &certs.signer_key_path,
        Some(crl_path),
    )
    .expect("Failed to create plugin test context")
}

/// 构建签名请求JSON
///
/// # Arguments
/// * `data` - 待签名数据
///
/// # Returns
/// JSON格式的签名请求字节数组
pub fn build_sign_request(data: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "to-sign": {
            "data": data
        }
    }))
    .unwrap()
}

/// 构建验签请求JSON
///
/// # Arguments
/// * `data` - 原始数据
/// * `signed_b64` - Base64编码的签名数据
/// * `cert_id_b64` - Base64编码的证书ID
///
/// # Returns
/// JSON格式的验签请求字节数组
pub fn build_verify_request(data: &str, signed_b64: &str, cert_id_b64: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "to-verify": {
            "data": data,
            "signed_data": signed_b64,
            "id": cert_id_b64
        }
    }))
    .unwrap()
}

/// 构建验签+签名组合请求JSON
///
/// 用于原子性的验签+签名操作。
///
/// # Arguments
/// * `verify_data` - 待验证的原始数据
/// * `signed_b64` - Base64编码的签名数据
/// * `cert_id_b64` - Base64编码的签名者证书ID
/// * `sign_data` - 待签名的新数据
/// * `sign_id_b64` - 期望的签名者证书ID
///
/// # Returns
/// JSON格式的组合请求字节数组
pub fn build_verify_sign_request(
    verify_data: &str,
    signed_b64: &str,
    cert_id_b64: &str,
    sign_data: &str,
    sign_id_b64: &str,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "to-verify": {
            "data": verify_data,
            "signed_data": signed_b64,
            "id": cert_id_b64
        },
        "to-sign": {
            "data": sign_data,
            "id": sign_id_b64
        }
    }))
    .unwrap()
}

/// 执行签名并返回编码结果
///
/// 便捷函数，执行签名请求并解析响应。
///
/// # Returns
/// 元组：(signed_data, id)，均为Base64编码字符串
pub fn sign_and_encode(ctx: &PluginTestContext, data: &[u8]) -> (String, String) {
    let request = build_sign_request(std::str::from_utf8(data).unwrap_or(TEST_DATA_A));
    let result = ctx.sign(&request).expect("Sign failed");
    let resp: serde_json::Value = serde_json::from_slice(&result).unwrap();

    (
        resp["signed_data"].as_str().unwrap().to_string(),
        resp["id"].as_str().unwrap().to_string(),
    )
}

/// 执行签名请求并解析JSON响应
pub fn handle_sign_and_parse(ctx: &PluginTestContext, request: &[u8]) -> serde_json::Value {
    let result = ctx.sign(request);
    assert!(result.is_some());
    serde_json::from_slice(&result.unwrap()).unwrap()
}

/// 执行验签+签名请求并解析JSON响应
pub fn handle_verify_sign_and_parse(ctx: &PluginTestContext, request: &[u8]) -> serde_json::Value {
    let result = ctx.verify_sign(request);
    assert!(result.is_some());
    serde_json::from_slice(&result.unwrap()).unwrap()
}

/// 执行验签请求并解析JSON响应
pub fn handle_verify_and_parse(ctx: &PluginTestContext, request: &[u8]) -> serde_json::Value {
    let result = ctx.verify(request);
    assert!(result.is_some());
    serde_json::from_slice(&result.unwrap()).unwrap()
}
