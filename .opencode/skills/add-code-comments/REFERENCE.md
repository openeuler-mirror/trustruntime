# 代码注释详细参考

## 注释类型

### 1. 模块级注释

每个模块文件顶部添加模块注释，说明模块职责和依赖关系。

**格式：**
```rust
//! 模块功能说明
//!
//! 主要职责：
//! - 职责1
//! - 职责2
//!
//! 与其他模块关系：依赖/被依赖说明
```

**示例：**
```rust
//! CMS签名验签业务处理器模块
//!
//! 职责：
//! - 处理三种业务请求：签名(0x10)、验签+签名(0x12)、验签(0x14)
//! - JSON请求解析与响应构造
//! - 错误码映射
//!
//! 架构决策：
//! - DataHandler抽象解耦业务层（ADR-0005）
//! - 统一OpenSSL处理CMS（ADR-0004）
//!
//! 依赖：sign模块、verify模块、cert_loader模块
```

### 2. 公共接口注释

**原则**：所有公共API必须有文档注释

#### 函数注释

```rust
/// 验签并返回证书身份判定结果
///
/// 验证CMS签名，并判断签名方证书身份：
/// - SameNode: 签名方证书ID == 本地证书ID（确认是本节点签名）
/// - OtherNode: 签名方证书ID != 本地证书ID（其他节点签名）
/// - IdentityConflict: 证书公钥相同但ID不同（证书身份冲突）
///
/// # Arguments
/// * `signed_der` - DER编码的CMS签名数据
/// * `data` - 原始数据
/// * `signer_id` - 签名方证书ID（Subject Key Identifier）
///
/// # Returns
/// * `Ok(VerifyOutcome)` - 验签通过，返回身份判定结果
/// * `Err(VerifyError)` - 验签失败（证书链无效、CRL吊销、签名不匹配等）
///
/// # Errors
/// - `VerifyError::CertificateChainInvalid` - 证书链验证失败
/// - `VerifyError::CrlRevoked` - 证书被CRL吊销
/// - `VerifyError::SignatureMismatch` - 签名不匹配
///
/// # Example
/// ```
/// let outcome = verifier.verify(&signed_der, b"test data", &signer_id)?;
/// match outcome {
///     VerifyOutcome::SameNode => println!("本节点签名"),
///     VerifyOutcome::OtherNode => println!("其他节点签名"),
///     VerifyOutcome::IdentityConflict => println!("证书身份冲突"),
/// }
/// ```
pub fn verify(
    &self,
    signed_der: &[u8],
    data: &[u8],
    signer_id: &[u8],
) -> Result<VerifyOutcome, VerifyError> {
    // ...
}
```

#### 结构体注释

```rust
/// CMS签名器
///
/// 封装ECC-256签名逻辑，管理签名证书和私钥。
///
/// 架构决策：统一使用OpenSSL处理CMS签名
/// 详见 ADR-0004: Unified OpenSSL for TLS and CMS
///
/// 优势：
/// - 消除双加密栈问题（rustls + OpenSSL）
/// - 证书类型一致（openssl::X509 和 openssl::PKey）
/// - 错误处理统一
pub struct Signer {
    /// 签名证书（含私钥）
    cert: CmsCertificate,
    /// 证书ID（Subject Key Identifier，20字节SHA-1哈希）
    cert_id: Vec<u8>,
}
```

#### 枚举注释

```rust
/// 验签结果
///
/// 架构决策：统一结果码编码（ADR-0001）
///
/// 编码规则：
/// - result=0: 本节点签名（SameNode）
/// - result=1: 其他节点签名（OtherNode）
/// - result=2: 证书身份冲突（IdentityConflict）
///
/// 注意：result=1/2为验签通过的合法结果，不表示失败
#[derive(Debug, PartialEq)]
pub enum VerifyOutcome {
    /// 验签通过，签名方证书ID == 本地证书ID
    SameNode,
    /// 验签通过，签名方证书ID != 本地证书ID
    OtherNode,
    /// 证书身份冲突：签名方证书公钥 == 本地证书公钥，但ID不同
    IdentityConflict,
}
```

### 3. 业务逻辑注释

**原则**：复杂逻辑、算法、业务规则必须注释

#### 业务规则注释

```rust
// 业务规则：result=2优先级高于result=1
// 详见 CONTEXT.md §业务流程 - 验签流程
// - result=1: 其他节点签名（ID不同）
// - result=2: 证书身份冲突（公钥相同但ID不同）
let result_code = match self.verifier.verify(&signed_der, data_bytes, &signer_id) {
    Ok(VerifyOutcome::SameNode) => 0,
    Ok(VerifyOutcome::OtherNode) => 1,
    Ok(VerifyOutcome::IdentityConflict) => 2, // 优先级高于result=1
    Err(e) => map_verify_error(&e).to_result_code(),
};
```

#### 错误处理注释

```rust
// 错误码映射（参见ADR-0001）：
// - 3: 证书链无效
// - 4: CRL吊销
// - 5: 签名不匹配
// - 6: 格式错误
let result_code = map_verify_error(&error).to_result_code();
```

#### 算法注释

```rust
// 证书ID提取算法：
// 1. 从证书扩展中提取Subject Key Identifier（SKI）
// 2. SKI是20字节的SHA-1哈希值
// 3. 用于签名时与数据拼接：sign(data + cert_id)
let cert_id = cert.x509()
    .subject_key_id()
    .ok_or(CertError::MissingSubjectKeyId)?
    .as_slice()
    .to_vec();
```

### 4. 常量注释

```rust
/// vsock消息类型：签名请求
/// 详见 CONTEXT.md §vsock类型编码
const MSG_TYPE_SIGN_REQ: u32 = 0x10;

/// vsock消息类型：验签+签名请求
/// 先验签sign(data+输入证书id)，再签名sign(新data+输入证书id)
const MSG_TYPE_VERIFY_SIGN_REQ: u32 = 0x12;

/// vsock消息类型：验签请求
/// 验证sign(data+输入证书id)并判断证书身份
const MSG_TYPE_VERIFY_REQ: u32 = 0x14;
```

### 5. 测试函数注释

```rust
#[test]
fn sign_handler_processes_request() {
    // 场景：正常签名请求流程
    // 预期：返回signed_data、cert_id，result=0

    let handler = create_test_handler();
    let result = handler.handle(&valid_request);

    assert!(result.is_some());
    let response = parse_response(result.unwrap());
    assert_eq!(response.result, 0);
}
```

### 6. ADR引用注释

#### 格式1：模块/结构体注释（架构级决策）

```rust
/// CMS签名验签插件
///
/// 架构决策：采用静态编译时集成而非动态运行时加载
/// 详见 ADR-0003: Plugin Integration Pattern
///
/// 原因：
/// - 安全性：避免在机密VM中动态加载任意共享库
/// - 简洁性：无需abi_stable或C ABI封装
/// - 内存占用：单二进制文件避免共享库开销（符合30MB cgroup限制）
pub struct TrustringPlugin {
    // ...
}
```

#### 格式2：函数注释（实现细节决策）

```rust
/// 注册消息处理器到传输层
///
/// 架构决策：TransportLayer trait解耦通信层与插件框架层
/// 详见 ADR-0005: Transport Layer Abstraction
///
/// 职责划分：
/// - Transport：协议层（报文解析、校验、错误响应）
/// - DataHandler：业务层（JSON解析、签名验签）
pub fn register_handler(&mut self, msg_type: u32, handler: Box<dyn DataHandler>) {
    // ...
}
```

#### 格式3：行内注释（特定逻辑决策）

```rust
// ADR-0001: result=2优先级高于result=1（公钥比较优先）
let result_code = match outcome {
    VerifyOutcome::IdentityConflict => 2,
    VerifyOutcome::OtherNode => 1,
    // ...
};
```

#### 格式4：多ADR引用

```rust
/// CMS验签处理器
///
/// 架构决策：
/// - 统一OpenSSL处理TLS和CMS（ADR-0004）
/// - 统一结果码编码（ADR-0001）
/// - DataHandler抽象解耦业务层（ADR-0005）
pub(crate) struct VerifyHandler {
    verifier: Arc<Verifier>,
}
```

---

## 注释风格指南

### ✅ 推荐风格

- 使用中文注释（符合项目文档风格）
- 注释说明"为什么"而非"是什么"（代码应自解释）
- 使用 `///` 文档注释标记公共API
- 使用 `//` 行内注释说明复杂逻辑
- 引用CONTEXT.md和ADR文档中的术语

### ❌ 避免做法

- 显而易见的注释（如 `// 设置name为name`）
- 过时或错误的注释
- 注释掉的代码（应删除）
- 注释中包含实现细节（应在文档中说明）
- 英文注释（除非引用外部库文档）

---

## 完整示例

### 示例1：业务处理器（含ADR引用）

```rust
//! CMS签名验签业务处理器模块
//!
//! 职责：
//! - 处理三种业务请求：签名(0x10)、验签+签名(0x12)、验签(0x14)
//! - JSON请求解析与响应构造
//! - 错误码映射
//!
//! 架构决策：
//! - DataHandler抽象解耦业务层（ADR-0005）
//! - 统一OpenSSL处理CMS（ADR-0004）
//! - 统一结果码编码（ADR-0001）
//!
//! 依赖：sign模块、verify模块、cert_loader模块

use crate::cert_loader::{CaCertificate, CertificateRevocationList, CmsCertificate};
use crate::error_code_mapper::{map_sign_error, map_verify_error, BusinessError};
use crate::sign::Signer;
use crate::verify::{Verifier, VerifyOutcome};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use trustruntime_framework::plugin_manager::{DataHandler, Plugin, PluginContext, PluginError};

/// vsock消息类型：签名请求
const MSG_TYPE_SIGN_REQ: u32 = 0x10;
/// vsock消息类型：验签+签名请求
const MSG_TYPE_VERIFY_SIGN_REQ: u32 = 0x12;
/// vsock消息类型：验签请求
const MSG_TYPE_VERIFY_REQ: u32 = 0x14;

/// 签名请求处理器
///
/// 处理0x10类型请求，执行CMS签名操作
pub(crate) struct SignHandler {
    /// CMS签名器（Arc共享以支持并发）
    pub(crate) signer: Arc<Signer>,
}

impl DataHandler for SignHandler {
    fn handle(&self, data: &[u8]) -> Option<Vec<u8>> {
        // 解析JSON请求
        let json_str = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => {
                // 错误码6：格式错误（参见ADR-0001）
                return serde_json::to_vec(&SignResponse {
                    signed_data: String::new(),
                    id: String::new(),
                    result: BusinessError::JsonParseError.to_result_code(),
                })
                .ok();
            }
        };

        let req: SignRequest = match serde_json::from_str(json_str) {
            Ok(r) => r,
            Err(_) => {
                return serde_json::to_vec(&SignResponse {
                    signed_data: String::new(),
                    id: String::new(),
                    result: BusinessError::JsonParseError.to_result_code(),
                })
                .ok();
            }
        };

        // 执行签名
        let data_bytes = req.to_sign.data.as_bytes();
        let (signed_der, result_code) = match self.signer.sign(data_bytes) {
            Ok(der) => (der, 0), // result=0: 签名成功
            Err(e) => (Vec::new(), map_sign_error(&e).to_result_code()),
        };

        // Base64编码响应
        let signed_b64 = general_purpose::STANDARD.encode(&signed_der);
        let cert_id_b64 = general_purpose::STANDARD.encode(self.signer.cert_id());

        let resp = SignResponse {
            signed_data: signed_b64,
            id: cert_id_b64,
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
pub struct TrustringPlugin {
    signer: Arc<Signer>,
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
    pub fn new(
        signer_cert_path: &str,
        signer_key_path: &str,
        ca_cert_path: &str,
        crl_path: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let signer = Signer::new(CmsCertificate::load(signer_cert_path, signer_key_path)?);

        let ca_cert = CaCertificate::load(ca_cert_path)?;
        let local_cert = CmsCertificate::load(signer_cert_path, signer_key_path)?;
        let crl = crl_path.map(CertificateRevocationList::load).transpose()?;
        let verifier = Verifier::new(ca_cert, crl, local_cert);

        Ok(Self {
            signer: Arc::new(signer),
            verifier: Arc::new(verifier),
        })
    }
}

impl Plugin for TrustringPlugin {
    fn name(&self) -> &str {
        "trustring"
    }

    fn init(&mut self, ctx: &PluginContext) -> Result<(), PluginError> {
        // 架构决策：插件注册消息处理器（ADR-0005）
        // Transport负责协议层，DataHandler负责业务层
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

    fn shutdown(&mut self) -> Result<(), PluginError> {
        Ok(())
    }
}
```

### 示例2：错误码映射（含ADR引用）

```rust
//! 错误码映射模块
//!
//! 将OpenSSL错误映射为业务结果码（0-9）
//!
//! 架构决策：统一结果码编码
//! 详见 ADR-0001: Unified Result Code Encoding
//!
//! 编码规则：
//! - 0: 成功
//! - 1/2: 验签身份判定（仅0x13/0x15）
//! - 3-6: 验签失败
//! - 7-9: 签名失败
//! - ≥10: 其他错误

use thiserror::Error;

/// 业务错误类型
#[derive(Error, Debug, Clone, Copy, PartialEq)]
pub enum BusinessError {
    #[error("JSON解析失败")]
    JsonParseError,

    #[error("Base64解码失败")]
    Base64DecodeError,

    #[error("证书链无效")]
    CertificateChainInvalid,

    #[error("证书被CRL吊销")]
    CrlRevoked,

    #[error("签名不匹配")]
    SignatureMismatch,

    #[error("格式错误")]
    FormatError,

    #[error("证书加载失败")]
    CertificateLoadFailed,

    #[error("私钥不可用")]
    PrivateKeyUnavailable,

    #[error("签名算法错误")]
    SigningAlgorithmError,
}

impl BusinessError {
    /// 转换为业务结果码
    ///
    /// 架构决策：三种接口统一使用一份结果码表
    /// 详见 ADR-0001: Unified Result Code Encoding
    ///
    /// 编码错开原则：每个数值全局唯一含义，客户端无需按接口类型切换解读逻辑
    pub fn to_result_code(&self) -> u32 {
        match self {
            BusinessError::JsonParseError => 6,
            BusinessError::Base64DecodeError => 6,
            BusinessError::CertificateChainInvalid => 3,
            BusinessError::CrlRevoked => 4,
            BusinessError::SignatureMismatch => 5,
            BusinessError::FormatError => 6,
            BusinessError::CertificateLoadFailed => 7,
            BusinessError::PrivateKeyUnavailable => 8,
            BusinessError::SigningAlgorithmError => 9,
        }
    }
}

/// 将签名错误映射为业务错误
///
/// 架构决策：OpenSSL错误栈统一映射为结果码
/// 详见 ADR-0004: Unified OpenSSL for TLS and CMS
pub(crate) fn map_sign_error(error: &SignError) -> BusinessError {
    match error {
        SignError::CertificateLoad(_) => BusinessError::CertificateLoadFailed,
        SignError::PrivateKeyUnavailable(_) => BusinessError::PrivateKeyUnavailable,
        SignError::SigningFailed(_) => BusinessError::SigningAlgorithmError,
    }
}

/// 将验签错误映射为业务错误
///
/// 架构决策：统一结果码编码（ADR-0001）
///
/// 映射规则：
/// - 3: 证书链无效
/// - 4: CRL吊销
/// - 5: 签名不匹配
/// - 6: 格式错误
pub(crate) fn map_verify_error(error: &VerifyError) -> BusinessError {
    match error {
        VerifyError::CertificateChainInvalid => BusinessError::CertificateChainInvalid,
        VerifyError::CrlRevoked => BusinessError::CrlRevoked,
        VerifyError::SignatureMismatch => BusinessError::SignatureMismatch,
        VerifyError::InvalidFormat => BusinessError::FormatError,
    }
}
```

---

## 注释质量检查清单

完成注释添加后，使用此清单验证质量：

### 模块级
- [ ] 模块文件顶部有 `//!` 注释
- [ ] 说明模块职责
- [ ] 说明依赖关系
- [ ] 引用相关ADR（如适用）

### 公共API
- [ ] 所有 `pub fn` 有文档注释
- [ ] 所有 `pub struct` 有文档注释
- [ ] 所有 `pub enum` 有文档注释
- [ ] 包含参数说明（`# Arguments`）
- [ ] 包含返回值说明（`# Returns`）
- [ ] 包含错误说明（`# Errors`，如适用）
- [ ] 包含示例（`# Example`，如适用）

### 业务逻辑
- [ ] 复杂算法有注释说明
- [ ] 业务规则有注释说明
- [ ] 错误处理逻辑有注释说明原因
- [ ] 非显而易见的设计决策有注释

### ADR引用
- [ ] 架构级决策引用对应ADR
- [ ] ADR引用格式正确（ADR-XXXX: 标题）
- [ ] 关键理由或后果有说明

### 测试函数
- [ ] 测试函数有注释说明场景
- [ ] 测试函数有注释说明预期结果

### 风格一致性
- [ ] 使用中文注释
- [ ] 注释说明"为什么"而非"是什么"
- [ ] 无过时或错误注释
- [ ] 无注释掉的代码