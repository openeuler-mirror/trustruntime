//! CMS签名验签业务处理器模块
//!
//! 职责：
//! - 处理三种业务请求：签名(0x10)、验签+签名(0x12)、验签(0x14)
//! - JSON请求解析与响应构造
//! - 错误码映射
//!
//! 架构决策：
//! - DataHandler抽象解耦业务层（ADR-0005: Transport Layer Abstraction）
//! - 统一OpenSSL处理CMS（ADR-0004: Unified OpenSSL for TLS and CMS）
//! - 统一结果码编码（ADR-0001: Unified Result Code Encoding）
//!
//! 依赖：
//! - sign模块：CMS签名功能
//! - verify模块：CMS验签功能
//! - cert_loader模块：证书加载功能
//! - error_code_mapper模块：错误码映射功能

use crate::cert_loader::{CaCertificate, CertificateRevocationList, CmsCertificate};
use crate::error_code_mapper::{map_sign_error, map_verify_error, BusinessError};
use crate::sign::Signer;
use crate::verify::{Verifier, VerifyOutcome};
use base64::{engine::general_purpose, Engine as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::sync::Arc;
use trustruntime_framework::plugin_manager::{Plugin, PluginContext, PluginError};
use trustruntime_framework::transport::DataHandler;

/// vsock消息类型：签名请求
///
/// 客户端发送待签名数据，服务端返回CMS签名数据和签名证书ID
const MSG_TYPE_SIGN_REQ: u32 = 0x10;

/// vsock消息类型：验签+签名请求
///
/// 先验签sign(data+输入证书id)，验签通过后再签名sign(新data+输入证书id)
const MSG_TYPE_VERIFY_SIGN_REQ: u32 = 0x12;

/// vsock消息类型：验签请求
///
/// 验证sign(data+输入证书id)并判断证书身份
const MSG_TYPE_VERIFY_REQ: u32 = 0x14;

/// 签名请求结构
///
/// JSON格式：{"to-sign": {"data": "待签名数据"}}
#[derive(Serialize, Deserialize)]
struct SignRequest {
    #[serde(rename = "to-sign")]
    to_sign: ToSign,
}

/// 待签名数据
#[derive(Serialize, Deserialize)]
struct ToSign {
    data: String,
}

/// 签名响应结构
///
/// JSON格式：{"signed_data": "Base64编码的签名数据", "id": "Base64编码的证书ID", "result": 0}
#[derive(Serialize, Deserialize)]
struct SignResponse {
    /// Base64编码的DER格式CMS签名数据
    signed_data: String,
    /// Base64编码的证书ID（Subject Key Identifier）
    id: String,
    /// 结果码（0=成功，7-9=签名失败）
    result: u32,
}

/// 验签请求结构
///
/// JSON格式：{"to-verify": {"data": "原始数据", "signed_data": "签名数据", "id": "证书ID"}}
#[derive(Serialize, Deserialize)]
struct VerifyRequest {
    #[serde(rename = "to-verify")]
    to_verify: ToVerify,
}

/// 待验签数据
#[derive(Serialize, Deserialize)]
struct ToVerify {
    /// 原始数据
    data: String,
    /// Base64编码的DER格式CMS签名数据
    signed_data: String,
    /// Base64编码的证书ID（Subject Key Identifier）
    id: String,
}

/// 验签+签名请求结构
///
/// JSON格式：{"to-verify": {...}, "to-sign": {"data": "新数据", "id": "外部证书ID"}}
#[derive(Serialize, Deserialize)]
struct VerifySignRequest {
    #[serde(rename = "to-verify")]
    to_verify: ToVerify,
    #[serde(rename = "to-sign")]
    to_sign: ToSignWithId,
}

/// 待签名数据（带外部证书ID）
#[derive(Serialize, Deserialize)]
struct ToSignWithId {
    /// 新数据
    data: String,
    /// Base64编码的外部证书ID
    id: String,
}

/// 验签+签名响应结构
///
/// JSON格式：{"signed_data": "新签名数据", "id": "外部证书ID", "result": 0}
#[derive(Serialize, Deserialize)]
struct VerifySignResponse {
    /// Base64编码的新签名数据
    signed_data: String,
    /// 外部证书ID（Base64）
    id: String,
    /// 结果码（0=成功，1/2=验签通过但未签名，3-6=验签失败，7-9=签名失败）
    result: u32,
}

/// 验签响应结构
///
/// JSON格式：{"result": 0}
#[derive(Serialize, Deserialize)]
struct VerifyResponse {
    /// 结果码
    /// - 0: 本节点签名（SameNode）- 公钥不同且ID相同
    /// - 1: 其他节点签名（OtherNode）- 公钥不同且ID不同
    /// - 2: 证书身份冲突（IdentityConflict）- 公钥相同
    /// - 3-6: 验签失败
    result: u32,
}

/// 处理器上下文
///
/// 封装公共的请求处理逻辑：
/// - JSON 解析
/// - Base64 编解码
/// - 错误响应构造（由调用方决定）
///
/// 架构决策：
/// - 提取公共逻辑减少重复（DRY原则）
/// - 使用闭包实现灵活的错误响应构造
/// - 使用 ? 操作符简化错误处理
struct HandlerContext<'a, F>
where
    F: Fn(BusinessError) -> Option<Vec<u8>>,
{
    data: &'a [u8],
    error_response_builder: F,
}

impl<'a, F> HandlerContext<'a, F>
where
    F: Fn(BusinessError) -> Option<Vec<u8>>,
{
    fn new(data: &'a [u8], error_response_builder: F) -> Self {
        Self {
            data,
            error_response_builder,
        }
    }

    fn parse_json<T: DeserializeOwned>(&self) -> Result<T, Option<Vec<u8>>> {
        let json_str = std::str::from_utf8(self.data)
            .map_err(|_| (self.error_response_builder)(BusinessError::JsonParseError))?;
        serde_json::from_str(json_str)
            .map_err(|_| (self.error_response_builder)(BusinessError::JsonParseError))
    }

    fn decode_base64(&self, s: &str) -> Result<Vec<u8>, Option<Vec<u8>>> {
        general_purpose::STANDARD
            .decode(s)
            .map_err(|_| (self.error_response_builder)(BusinessError::Base64DecodeError))
    }
}

fn encode_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// 构造 SignResponse 错误响应
fn build_sign_error_response(error: BusinessError) -> Option<Vec<u8>> {
    serde_json::to_vec(&SignResponse {
        signed_data: String::new(),
        id: String::new(),
        result: error.to_result_code(),
    })
    .ok()
}

/// 构造 VerifySignResponse 错误响应
fn build_verify_sign_error_response(error: BusinessError) -> Option<Vec<u8>> {
    serde_json::to_vec(&VerifySignResponse {
        signed_data: String::new(),
        id: String::new(),
        result: error.to_result_code(),
    })
    .ok()
}

/// 构造 VerifyResponse 错误响应
fn build_verify_error_response(error: BusinessError) -> Option<Vec<u8>> {
    serde_json::to_vec(&VerifyResponse {
        result: error.to_result_code(),
    })
    .ok()
}

/// 签名请求处理器
///
/// 处理0x10类型请求，执行CMS签名操作
///
/// 架构决策：DataHandler抽象解耦业务层
/// 详见 ADR-0005: Transport Layer Abstraction
///
/// 职责划分：
/// - Transport：协议层（报文解析、校验、错误响应）
/// - DataHandler：业务层（JSON解析、签名验签）
pub(crate) struct SignHandler {
    /// CMS签名器（Arc共享以支持并发）
    pub(crate) signer: Arc<Signer>,
}

impl DataHandler for SignHandler {
    /// 处理签名请求
    ///
    /// 流程：
    /// 1. 解析JSON请求
    /// 2. 执行CMS签名
    /// 3. Base64编码响应
    ///
    /// 错误码映射（参见ADR-0001）：
    /// - 0: 签名成功
    /// - 6: JSON解析失败
    /// - 7: 证书加载失败
    /// - 8: 私钥不可用
    /// - 9: 签名算法错误
    fn handle(&self, data: &[u8]) -> Option<Vec<u8>> {
        let ctx = HandlerContext::new(data, build_sign_error_response);
        let req: SignRequest = match ctx.parse_json() {
            Ok(r) => r,
            Err(e) => return e,
        };

        let data_bytes = req.to_sign.data.as_bytes();
        let signed_der = match self.signer.sign(data_bytes) {
            Ok(der) => der,
            Err(e) => return build_sign_error_response(map_sign_error(&e)),
        };

        let resp = SignResponse {
            signed_data: encode_base64(&signed_der),
            id: encode_base64(self.signer.cert_id()),
            result: 0,
        };

        serde_json::to_vec(&resp).ok()
    }
}

/// 验签+签名请求处理器
///
/// 处理0x12类型请求，先验签再签名
///
/// 业务流程（详见CONTEXT.md）：
/// 1. 验证输入签名数据
/// 2. 验签通过后执行签名
/// 3. 验签失败返回错误响应
///
/// 注意：
/// - 使用 verify_signature_only 方法，仅验证签名有效性
/// - 不判断证书身份（SameNode/OtherNode/IdentityConflict）
/// - 验签通过即执行签名，不区分 result=0/1/2
///
/// 架构决策：
/// - 统一OpenSSL处理CMS（ADR-0004）
/// - 统一结果码编码（ADR-0001）
pub(crate) struct VerifySignHandler {
    /// CMS签名器
    pub(crate) signer: Arc<Signer>,
    /// CMS验签器
    pub(crate) verifier: Arc<Verifier>,
}

impl VerifySignHandler {
    /// 处理验签部分（to_verify）
    ///
    /// 包括：
    /// - Base64 解码 signed_data 和 id
    /// - 执行验签（仅验证签名有效性，不判断证书身份）
    ///
    /// 返回：
    /// - Ok(()): 验签成功
    /// - Err(error_response): 验签失败或解码失败
    ///
    /// 注意：
    /// - 使用 verify_signature_only 方法
    /// - 不返回 VerifyOutcome（SameNode/OtherNode/IdentityConflict）
    /// - 验签通过即返回 Ok(())，由调用方决定是否签名
    #[allow(clippy::type_complexity)]
    fn handle_verify_part(
        &self,
        to_verify: &ToVerify,
        decode_fn: &dyn Fn(&str) -> Result<Vec<u8>, Option<Vec<u8>>>,
    ) -> Result<(), Option<Vec<u8>>> {
        let data_bytes = to_verify.data.as_bytes();
        let signed_der = decode_fn(&to_verify.signed_data)?;
        let signer_id = decode_fn(&to_verify.id)?;

        self.verifier
            .verify_signature_only(&signed_der, data_bytes, &signer_id)
            .map_err(|e| build_verify_sign_error_response(map_verify_error(&e)))?;

        Ok(())
    }

    /// 处理签名部分（to_sign）
    ///
    /// 包括：
    /// - Base64 解码 id
    /// - 执行签名
    ///
    /// 返回：
    /// - Ok(signed_data): 签名成功
    /// - Err(error_response): 签名失败或解码失败
    #[allow(clippy::type_complexity)]
    fn handle_sign_part(
        &self,
        to_sign: &ToSignWithId,
        decode_fn: &dyn Fn(&str) -> Result<Vec<u8>, Option<Vec<u8>>>,
    ) -> Result<Vec<u8>, Option<Vec<u8>>> {
        let external_id = decode_fn(&to_sign.id)?;

        let new_signed = self
            .signer
            .sign_with_id(to_sign.data.as_bytes(), &external_id)
            .map_err(|e| build_verify_sign_error_response(map_sign_error(&e)))?;

        Ok(new_signed)
    }
}

impl DataHandler for VerifySignHandler {
    /// 处理验签+签名请求
    ///
    /// 流程：
    /// 1. 解析JSON请求
    /// 2. Base64解码签名数据
    /// 3. 验签（仅验证签名有效性）
    /// 4. 验签通过后执行签名
    ///
    /// 错误码映射（参见ADR-0001）：
    /// - 0: 验签通过并签名成功
    /// - 3: 证书链无效
    /// - 4: CRL吊销
    /// - 5: 签名不匹配
    /// - 6: 格式错误
    /// - 7-9: 签名失败
    /// - 10: JSON解析错误
    /// - 11: Base64解码错误
    ///
    /// 注意：
    /// - 不返回 result=1/2（不判断证书身份）
    /// - 验签通过即执行签名，result 固定为 0
    fn handle(&self, data: &[u8]) -> Option<Vec<u8>> {
        let ctx = HandlerContext::new(data, build_verify_sign_error_response);
        let req: VerifySignRequest = match ctx.parse_json() {
            Ok(r) => r,
            Err(e) => return e,
        };

        // 处理验签部分
        match self.handle_verify_part(&req.to_verify, &|s| ctx.decode_base64(s)) {
            Ok(_) => {}
            Err(e) => return e,
        }

        // 处理签名部分
        let new_signed = match self.handle_sign_part(&req.to_sign, &|s| ctx.decode_base64(s)) {
            Ok(s) => s,
            Err(e) => return e,
        };

        // 构造响应
        let resp = VerifySignResponse {
            signed_data: encode_base64(&new_signed),
            id: req.to_sign.id,
            result: 0,
        };

        serde_json::to_vec(&resp).ok()
    }
}

/// 验签请求处理器
///
/// 处理0x14类型请求，验证CMS签名并判断证书身份
///
/// 架构决策：
/// - 统一OpenSSL处理CMS（ADR-0004）
/// - 统一结果码编码（ADR-0001）
/// - DataHandler抽象解耦业务层（ADR-0005）
struct VerifyHandler {
    verifier: Arc<Verifier>,
}

impl DataHandler for VerifyHandler {
    /// 处理验签请求
    ///
    /// 流程：
    /// 1. 解析JSON请求
    /// 2. Base64解码签名数据
    /// 3. 验签并判断证书身份
    ///
    /// 结果码（参见ADR-0001）：
    /// - 0: 本节点签名（SameNode）- 公钥不同且ID相同
    /// - 1: 其他节点签名（OtherNode）- 公钥不同且ID不同
    /// - 2: 证书身份冲突（IdentityConflict）- 公钥相同
    /// - 3-6: 验签失败
    ///
    /// 注意：result=1/2为验签通过的合法结果，不表示失败
    fn handle(&self, data: &[u8]) -> Option<Vec<u8>> {
        let ctx = HandlerContext::new(data, build_verify_error_response);
        let req: VerifyRequest = match ctx.parse_json() {
            Ok(r) => r,
            Err(e) => return e,
        };

        let data_bytes = req.to_verify.data.as_bytes();
        let signed_der = match ctx.decode_base64(&req.to_verify.signed_data) {
            Ok(d) => d,
            Err(e) => return e,
        };
        let signer_id = match ctx.decode_base64(&req.to_verify.id) {
            Ok(d) => d,
            Err(e) => return e,
        };

        let result_code = match self.verifier.verify(&signed_der, data_bytes, &signer_id) {
            Ok(VerifyOutcome::SameNode) => 0,
            Ok(VerifyOutcome::OtherNode) => 1,
            Ok(VerifyOutcome::IdentityConflict) => 2,
            Err(e) => map_verify_error(&e).to_result_code(),
        };

        let resp = VerifyResponse {
            result: result_code,
        };
        serde_json::to_vec(&resp).ok()
    }
}

/// CMS签名验签插件
///
/// 架构决策：采用静态编译时集成而非动态运行时加载
/// 详见 ADR-0003: Plugin Integration Pattern
///
/// 原因：
/// - 安全性：避免在机密VM中动态加载任意共享库
/// - 简洁性：无需abi_stable或C ABI封装
/// - 内存占用：单二进制文件避免共享库开销（符合30MB cgroup限制）
///
/// 插件集成方式：
/// - trustruntime二进制直接实例化TrustringPlugin
/// - 通过Plugin trait与框架解耦
/// - 编译时链接，运行时无插件发现机制
pub struct TrustringPlugin {
    /// CMS签名器
    signer: Arc<Signer>,
    /// CMS验签器
    verifier: Arc<Verifier>,
}

impl TrustringPlugin {
    /// 创建插件实例
    ///
    /// # Arguments
    /// * `signer_cert_path` - 签名证书路径
    /// * `signer_key_path` - 签名私钥路径
    /// * `ca_cert_path` - CA根证书路径
    /// * `crl_path` - CRL吊销列表路径（可选）
    ///
    /// # Returns
    /// * `Ok(TrustringPlugin)` - 插件实例
    /// * `Err` - 证书加载失败
    ///
    /// # Errors
    /// - 证书文件不存在或格式错误
    /// - 私钥与证书不匹配
    /// - CRL格式错误
    pub fn new(
        signer_cert_path: &str,
        signer_key_path: &str,
        ca_cert_path: &str,
        crl_path: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // 只加载一次签名证书，clone后分别给Signer和Verifier使用
        // 避免重复加载：X509/PKey的clone是引用计数浅拷贝，性能开销极小
        let cms_cert = CmsCertificate::load(signer_cert_path, signer_key_path)?;
        let signer = Signer::new(cms_cert.clone());

        let ca_cert = CaCertificate::load(ca_cert_path)?;
        let crl = crl_path.map(CertificateRevocationList::load).transpose()?;
        let verifier = Verifier::new(ca_cert, crl, cms_cert);

        Ok(Self {
            signer: Arc::new(signer),
            verifier: Arc::new(verifier),
        })
    }
}

impl Plugin for TrustringPlugin {
    /// 返回插件名称
    fn name(&self) -> &str {
        "trustring"
    }

    /// 初始化插件，注册消息处理器
    ///
    /// 架构决策：插件注册消息处理器（ADR-0005）
    /// Transport负责协议层，DataHandler负责业务层
    ///
    /// 注册的处理器：
    /// - 0x10: SignHandler - 签名请求
    /// - 0x12: VerifySignHandler - 验签+签名请求
    /// - 0x14: VerifyHandler - 验签请求
    fn init(&mut self, ctx: &PluginContext) -> Result<(), PluginError> {
        ctx.transport.register_handler(
            MSG_TYPE_SIGN_REQ,
            Box::new(SignHandler {
                signer: self.signer.clone(),
            }),
        );

        ctx.transport.register_handler(
            MSG_TYPE_VERIFY_SIGN_REQ,
            Box::new(VerifySignHandler {
                signer: self.signer.clone(),
                verifier: self.verifier.clone(),
            }),
        );

        ctx.transport.register_handler(
            MSG_TYPE_VERIFY_REQ,
            Box::new(VerifyHandler {
                verifier: self.verifier.clone(),
            }),
        );

        Ok(())
    }

    /// 关闭插件
    ///
    /// 当前无资源需要释放
    fn shutdown(&mut self) -> Result<(), PluginError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::extension::{BasicConstraints, SubjectKeyIdentifier};
    use openssl::x509::{X509Builder, X509NameBuilder};
    use std::fs;
    use trustruntime_framework::transport::{TransportError, TransportLayer};

    /// Mock传输层实现
    ///
    /// 用于测试插件注册处理器
    struct MockTransport {
        handlers: std::sync::RwLock<std::collections::HashMap<u32, Box<dyn DataHandler>>>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                handlers: std::sync::RwLock::new(std::collections::HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl TransportLayer for MockTransport {
        fn register_handler(&self, msg_type: u32, handler: Box<dyn DataHandler>) {
            self.handlers.write().unwrap().insert(msg_type, handler);
        }

        async fn start(&self) -> Result<(), TransportError> {
            Ok(())
        }

        async fn stop(&self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// 创建测试用的CA证书和签名证书
    ///
    /// 生成自签名CA证书和由CA签名的签名证书
    fn create_ca_and_signer() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ca_key = EcKey::generate(&group).unwrap();
        let ca_pkey = PKey::from_ec_key(ca_key.clone()).unwrap();

        // 创建CA证书
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

        // 创建签名证书
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

    /// 测试环境
    ///
    /// 封装测试所需的证书、签名器、验签器
    struct TestEnv {
        _temp_dir: tempfile::TempDir,
        signer: Arc<Signer>,
        verifier: Arc<Verifier>,
        cert_id: Vec<u8>,
    }

    impl TestEnv {
        /// 创建测试环境
        fn new() -> Self {
            let temp_dir = tempfile::tempdir().unwrap();
            let (ca_pem, signer_pem, signer_key_pem) = create_ca_and_signer();

            let ca_path = temp_dir.path().join("ca.crt");
            let signer_path = temp_dir.path().join("signer.crt");
            let signer_key_path = temp_dir.path().join("signer.key");

            fs::write(&ca_path, &ca_pem).unwrap();
            fs::write(&signer_path, &signer_pem).unwrap();
            fs::write(&signer_key_path, &signer_key_pem).unwrap();

            let cms_cert = CmsCertificate::load(
                signer_path.to_str().unwrap(),
                signer_key_path.to_str().unwrap(),
            )
            .unwrap();

            let signer = Arc::new(Signer::new(cms_cert.clone()));
            let cert_id = signer.cert_id().to_vec();

            let ca_cert = CaCertificate::load(ca_path.to_str().unwrap()).unwrap();
            let verifier = Arc::new(Verifier::new(ca_cert, None, cms_cert));

            Self {
                _temp_dir: temp_dir,
                signer,
                verifier,
                cert_id,
            }
        }

        /// 签名数据
        fn sign(&self, data: &[u8]) -> Vec<u8> {
            self.signer.sign(data).unwrap()
        }

        /// Base64 编码
        fn encode_base64(&self, data: &[u8]) -> String {
            general_purpose::STANDARD.encode(data)
        }

        /// 获取证书 ID（Base64）
        fn cert_id_b64(&self) -> String {
            self.encode_base64(&self.cert_id)
        }
    }

    /// 创建测试配置
    fn make_config() -> std::sync::Arc<trustruntime_framework::config::AppConfig> {
        std::sync::Arc::new(
            trustruntime_framework::config::AppConfig::from_toml(
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
        )
    }

    /// 测试：插件初始化时注册处理器
    ///
    /// 场景：创建插件实例并初始化
    /// 预期：初始化成功，无错误
    #[test]
    fn trustring_plugin_registers_handlers_on_init() {
        let temp_dir = tempfile::tempdir().unwrap();

        let (ca_pem, signer_pem, signer_key_pem) = create_ca_and_signer();
        let ca_path = temp_dir.path().join("ca.crt");
        let signer_path = temp_dir.path().join("signer.crt");
        let signer_key_path = temp_dir.path().join("signer.key");

        fs::write(&ca_path, &ca_pem).unwrap();
        fs::write(&signer_path, &signer_pem).unwrap();
        fs::write(&signer_key_path, &signer_key_pem).unwrap();

        let mut plugin = TrustringPlugin::new(
            signer_path.to_str().unwrap(),
            signer_key_path.to_str().unwrap(),
            ca_path.to_str().unwrap(),
            None,
        )
        .unwrap();

        let config = make_config();
        let transport = std::sync::Arc::new(MockTransport::new());
        let ctx = PluginContext::new(config, transport);

        let result = plugin.init(&ctx);
        assert!(result.is_ok());
    }

    /// 测试：签名处理器处理请求
    ///
    /// 场景：发送有效签名请求
    /// 预期：返回签名数据和证书ID，result=0
    #[test]
    fn sign_handler_processes_request() {
        let env = TestEnv::new();
        let handler = SignHandler {
            signer: env.signer.clone(),
        };

        let req = SignRequest {
            to_sign: ToSign {
                data: "test data".to_string(),
            },
        };
        let req_bytes = serde_json::to_vec(&req).unwrap();

        let result = handler.handle(&req_bytes);
        assert!(result.is_some());

        let resp: SignResponse = serde_json::from_slice(&result.unwrap()).unwrap();
        assert_eq!(resp.result, 0);
        assert!(!resp.signed_data.is_empty());
        assert!(!resp.id.is_empty());
    }

    /// 测试：验签处理器处理请求
    ///
    /// 场景：发送有效验签请求（签名方证书与本地证书相同）
    /// 预期：result=2（证书身份冲突，因为公钥相同但ID不同）
    #[test]
    fn verify_handler_processes_request() {
        let env = TestEnv::new();
        let handler = VerifyHandler {
            verifier: env.verifier.clone(),
        };

        let signed_der = env.sign(b"test data");
        let signed_b64 = env.encode_base64(&signed_der);
        let cert_id_b64 = env.cert_id_b64();

        let req = VerifyRequest {
            to_verify: ToVerify {
                data: "test data".to_string(),
                signed_data: signed_b64,
                id: cert_id_b64,
            },
        };
        let req_bytes = serde_json::to_vec(&req).unwrap();

        let result = handler.handle(&req_bytes);
        assert!(result.is_some());

        let resp: VerifyResponse = serde_json::from_slice(&result.unwrap()).unwrap();
        assert_eq!(resp.result, 2);
    }

    /// 测试：验签+签名处理器处理请求（成功）
    ///
    /// 场景：验签成功后执行签名
    /// 预期：result=0，返回新的签名数据
    #[test]
    fn verify_sign_handler_processes_request_successfully() {
        let env = TestEnv::new();
        let handler = VerifySignHandler {
            signer: env.signer.clone(),
            verifier: env.verifier.clone(),
        };

        let signed_der = env.sign(b"test data");
        let signed_b64 = env.encode_base64(&signed_der);
        let cert_id_b64 = env.cert_id_b64();

        let req = VerifySignRequest {
            to_verify: ToVerify {
                data: "test data".to_string(),
                signed_data: signed_b64,
                id: cert_id_b64.clone(),
            },
            to_sign: ToSignWithId {
                data: "new data".to_string(),
                id: cert_id_b64,
            },
        };
        let req_bytes = serde_json::to_vec(&req).unwrap();

        let result = handler.handle(&req_bytes);
        assert!(result.is_some());

        let resp: VerifySignResponse = serde_json::from_slice(&result.unwrap()).unwrap();
        assert_eq!(resp.result, 0);
        assert!(!resp.signed_data.is_empty());
    }

    /// 测试：验签+签名处理器处理请求（验签失败）
    ///
    /// 场景：验签失败（数据不匹配）
    /// 预期：result=5（签名不匹配），不执行签名
    #[test]
    fn verify_sign_handler_returns_error_when_verify_fails() {
        let env = TestEnv::new();
        let handler = VerifySignHandler {
            signer: env.signer.clone(),
            verifier: env.verifier.clone(),
        };

        let signed_der = env.sign(b"test data");
        let signed_b64 = env.encode_base64(&signed_der);
        let cert_id_b64 = env.cert_id_b64();

        let req = VerifySignRequest {
            to_verify: ToVerify {
                data: "wrong data".to_string(), // 数据不匹配
                signed_data: signed_b64,
                id: cert_id_b64.clone(),
            },
            to_sign: ToSignWithId {
                data: "new data".to_string(),
                id: cert_id_b64,
            },
        };
        let req_bytes = serde_json::to_vec(&req).unwrap();

        let result = handler.handle(&req_bytes);
        assert!(result.is_some());

        let resp: VerifySignResponse = serde_json::from_slice(&result.unwrap()).unwrap();
        assert_eq!(resp.result, 5); // 签名不匹配
        assert!(resp.signed_data.is_empty()); // 未执行签名
    }

    /// 测试：验签+签名处理器处理请求（Base64解码失败）
    ///
    /// 场景：signed_data 包含无效的 Base64
    /// 预期：result=21（Base64解码错误）
    #[test]
    fn verify_sign_handler_returns_error_when_base64_decode_fails() {
        let env = TestEnv::new();
        let handler = VerifySignHandler {
            signer: env.signer.clone(),
            verifier: env.verifier.clone(),
        };

        let cert_id_b64 = env.cert_id_b64();

        let req = VerifySignRequest {
            to_verify: ToVerify {
                data: "test data".to_string(),
                signed_data: "!!!invalid-base64!!!".to_string(), // 无效的 Base64
                id: cert_id_b64.clone(),
            },
            to_sign: ToSignWithId {
                data: "new data".to_string(),
                id: cert_id_b64,
            },
        };
        let req_bytes = serde_json::to_vec(&req).unwrap();

        let result = handler.handle(&req_bytes);
        assert!(result.is_some());

        let resp: VerifySignResponse = serde_json::from_slice(&result.unwrap()).unwrap();
        assert_eq!(resp.result, 21); // Base64 解码错误
        assert!(resp.signed_data.is_empty());
    }
}
