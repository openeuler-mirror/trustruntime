# 签名验签层 详细设计

## 1. 职责与边界

### 负责

- **sign**: CMS 签名计算——将 data 与证书 id 拼接后执行 ECC-256 CMS 签名
- **verify**: CMS 验签 + 证书链校验 + CRL 校验 + 证书身份判定（result 0/1/2）
- **error_code_mapper**: 将 sign/verify 的领域错误类型转换为业务 result code（验签3-9、签名10-19、解析20-29）

### 不负责

- JSON 报文解析/构造（由 handler 负责）
- Base64 编码/解码（由 handler 负责）
- 证书加载（由 cert_loader 负责）
- result code 的最终赋值（由 handler 调用 error_code_mapper 完成）
- vsock 报文构造（由通信层负责）

---

## 2. 公开 API

trustring crate 仅公开 `TrustringPlugin` 类型，用于主程序加载插件：

```rust
pub struct TrustringPlugin {
    signer: Arc<Signer>,
    verifier: Arc<Verifier>,
}

impl TrustringPlugin {
    pub fn new(
        signer_cert_path: &str,
        signer_key_path: &str,
        ca_cert_path: &str,
        crl_path: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>>;
}

impl Plugin for TrustringPlugin {
    fn name(&self) -> &str;
    fn init(&mut self, ctx: &PluginContext) -> Result<(), PluginError>;
    fn shutdown(&mut self) -> Result<(), PluginError>;
}
```

---

## 3. 内部实现（pub(crate)）

以下模块为 trustring 插件内部实现，不对外公开：

### sign 模块

```rust
pub(crate) struct Signer {
    cert: X509,
    key: PKey<Private>,
    cert_id: Vec<u8>,       // 本地签名证书的 Subject Key ID
}

impl Signer {
    /// 从 CmsCertificate 构造 Signer
    pub(crate) fn new(cms_cert: CmsCertificate) -> Self;

    /// 签名：计算 CMS sign(data + 本地 cert_id)
    /// 返回：CMS DER 格式的签名数据（未 Base64 编码）
    pub(crate) fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignError>;

    /// 签名（外部 id）：计算 CMS sign(data + external_id)
    /// 用于验签+签名（0x12）流程，使用输入的证书 id 而非本地 cert_id
    pub(crate) fn sign_with_id(&self, data: &[u8], external_id: &[u8]) -> Result<Vec<u8>, SignError>;

    /// 获取本地 cert_id（用于响应中返回）
    pub(crate) fn cert_id(&self) -> &[u8];
}

pub(crate) enum SignError {
    OpenSslError(openssl::error::ErrorStack),  // CMS 签名操作失败
}
```

### verify 模块

```rust
pub(crate) struct Verifier {
    ca_cert: X509,
    crl: Option<X509Crl>,
    local_cert: X509,           // 本地签名证书（用于公钥比较）
    local_cert_id: Vec<u8>,     // 本地证书的 Subject Key ID
}

impl Verifier {
    pub(crate) fn new(
        ca_cert: CaCertificate,
        crl: Option<CertificateRevocationList>,
        local_cert: CmsCertificate,
    ) -> Self;

    /// 验签：验证 signed_data 是否为 sign(data + signer_cert_id) 的有效签名
    /// 返回：验签结果（含身份判定）——用于 0x14 验签接口
    pub(crate) fn verify(
        &self,
        signed_data: &[u8],     // CMS DER 格式（未 Base64 解码前的原始字节）
        data: &[u8],
        signer_cert_id: &[u8],  // 输入的外部证书 id
    ) -> Result<VerifyOutcome, VerifyError>;

    /// 仅验证签名有效性（不执行身份判定）——用于 0x12 验签+签名接口
    /// 返回：验签成功返回 Ok(())，失败返回 VerifyError
    pub(crate) fn verify_signature_only(
        &self,
        signed_data: &[u8],
        data: &[u8],
        signer_cert_id: &[u8],
    ) -> Result<(), VerifyError>;
}

/// 验签通过后的身份判定结果
pub(crate) enum VerifyOutcome {
    SameNode,           // 公钥不同，输入 id == 本地 id → result=0
    OtherNode,          // 公钥不同，输入 id != 本地 id → result=1
    IdentityConflict,   // 公钥相同 → result=2（优先级最高）
}

pub(crate) enum VerifyError {
    OpenSslError(String),                     // OpenSSL内部错误（转换为String便于序列化）
    CertificateChainInvalid,                    // 证书链校验失败
    CertificateRevoked,                         // CRL 吊销
    SignatureMismatch,                          // 签名不匹配
    FormatError,                                // signed_data 格式错误（非有效 CMS DER）
}
```

### error_code_mapper 模块

```rust
/// 业务错误码（按错误类型分组，预留扩展空间）
pub(crate) enum BusinessError {
    // 验签失败（result 3-9，预留7个位置）
    CertificateChainInvalid,    // result=3
    CertificateRevoked,         // result=4
    SignatureMismatch,          // result=5
    InvalidKeyUsage,            // result=6
    FormatError,                // result=7
    // result=8-9: 预留扩展

    // 签名失败（result 10-19，预留10个位置）
    CertificateLoadFailed,      // result=10
    PrivateKeyUnavailable,      // result=11
    SigningAlgorithmError,      // result=12
    // result=13-19: 预留扩展

    // 数据解析错误（result 20-29，预留10个位置）
    JsonParseError,             // result=20（JSON解析失败）
    Base64DecodeError,          // result=21（Base64解码失败）
    // result=22-29: 预留扩展

    Other(u32),                 // result>=30（透传错误码）
}

impl BusinessError {
    pub(crate) fn to_result_code(&self) -> u32;
}

/// 将 SignError 映射为 BusinessError
pub(crate) fn map_sign_error(err: &SignError) -> BusinessError;

/// 将 VerifyError 映射为 BusinessError
pub(crate) fn map_verify_error(err: &VerifyError) -> BusinessError;

/// 将 OpenSSL ErrorStack 映射为 BusinessError（基于错误码映射）
pub(crate) fn map_openssl_error(error: &openssl::error::ErrorStack) -> BusinessError;
```

---

## 4. 内部状态

| 结构体 | 状态 | 生命周期 |
|--------|------|---------|
| Signer | cert + key + cert_id（预加载） | 进程级，handler 持有 |
| Verifier | ca_cert + crl + local_cert + local_cert_id（预加载） | 进程级，handler 持有 |
| error_code_mapper | 无状态，纯函数 | 无 |

---

## 5. 关键场景

### 签名流程（0x10）

```
handler                     Signer
  |                            |
  |-- sign(data) ------------->|
  |                            |  1. 拼接 input = data + cert_id
  |                            |  2. CmsContentInfo::sign(cert, key, input)
  |                            |  3. 输出 CMS DER 字节
  |<-- Result<Vec<u8>> --------|
```

### 验签+签名流程（0x12）

```
handler                     Verifier                  Signer
  |                            |                         |
  |-- verify_signature_only(signed, data, id)->|        |
  |                            |  1. 解析 CMS DER       |
  |                            |  2. 构建 X509Store(CA) |
  |                            |  3. 添加 CRL 到 Store  |
  |                            |  4. 拼接 input = data + signer_cert_id
  |                            |  5. cms.verify(store, input)
  |                            |  [不执行身份判定]
  |<-- Result<(), VerifyError> --|                       |
  |                            |                         |
  |  [验签成功（无VerifyError）即执行签名]               |
  |                            |                         |
  |-- sign_with_id(data, id) ---------------------------->|
  |                            |                         |  拼接 data + external_id
  |                            |                         |  CMS 签名
  |<-- Result<Vec<u8>> ----------------------------------|
```

### 验签流程（0x14）——身份判定

```
Verifier::verify() 内部判定逻辑：

1. CMS 验签（证书链 + CRL + 签名匹配）
   ↓ 失败 → 若为签名方证书过期错误，忽略并视为验签通过
   ↓ 其他失败 → 返回 VerifyError（由 error_code_mapper 映射为 result≥3）

2. 验签通过，从 CMS signed_data 提取签名方实际证书的公钥

3. 公钥比较（优先级最高）：
   签名方公钥 == 本地证书公钥
     → IdentityConflict (result=2)

4. 公钥不同，比较 cert ID：
   输入 signer_cert_id == 本地 cert_id
     → SameNode (result=0)
   输入 signer_cert_id != 本地 cert_id
     → OtherNode (result=1)
```

### 0x12 与 0x14 验签严格度差异

| 接口 | 验签通过条件 | 说明 |
|------|------------|------|
| 0x12（验签+签名） | 验签成功（无 VerifyError） | 仅验证签名有效性（证书链+CRL+签名匹配），验签通过即继续签名，不执行身份判定 |
| 0x14（验签） | SameNode/OtherNode/IdentityConflict 均为通过 | 验签通过后执行身份判定，result=0/1/2 都是验签通过的合法结果 |

### 异常场景与 result code 映射

| 错误 | VerifyError/SignError | BusinessError | result |
|------|----------------------|---------------|--------|
| 证书链无效 | CertificateChainInvalid | CertificateChainInvalid | 3 |
| CRL 吊销 | CertificateRevoked | CertificateRevoked | 4 |
| 签名不匹配 | SignatureMismatch | SignatureMismatch | 5 |
| CMS DER 格式错误 | FormatError | FormatError | 6 |
| 证书加载失败 | OpenSslError（加载阶段） | CertificateLoadFailed | 7 |
| 私钥不可用 | OpenSslError（签名阶段） | PrivateKeyUnavailable | 8 |
| 签名算法错误 | OpenSslError（算法阶段） | SigningAlgorithmError | 9 |
| 签名方证书过期 | — | — | 忽略该 OpenSSL 错误，视为验签通过（证书过期由 cert_checker 巡检 warn） |
| CA证书过期/证书尚未生效 | — | — | 验签失败，返回 result≥3 |

---

## 6. 依赖关系

### 上游依赖

| 依赖 | 用途 |
|------|------|
| `openssl::cms::CmsContentInfo` | CMS 签名/验签核心 API |
| `openssl::x509::X509Store` | 验签时构建证书链 |
| `trustring::cert_loader` | CmsCertificate、CaCertificate、CRL |

### 下游消费者

| 消费者 | 使用方式 |
|--------|---------|
| handler（插件框架层） | 调用 sign/verify，通过 error_code_mapper 转换错误 |

---

## 7. 测试策略

### sign 必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| 正常签名 | 输出有效 CMS DER，可被 verify 验证 |
| sign_with_id 使用外部 id | 输出可被 verify(data, external_id) 验证 |
| 私钥不匹配 | 返回 SignError::OpenSslError |

### verify 必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| 有效签名 + 同节点 | VerifyOutcome::SameNode |
| 有效签名 + 不同节点 | VerifyOutcome::OtherNode |
| 有效签名 + 公钥相同（身份冲突） | VerifyOutcome::IdentityConflict |
| 签名被篡改 | VerifyError::SignatureMismatch |
| 证书链无效（非 CA 签发） | VerifyError::CertificateChainInvalid |
| CRL 吊销 | VerifyError::CertificateRevoked |
| signed_data 格式错误 | VerifyError::FormatError |
| 签名方证书过期 | 忽略 OpenSSL 过期错误，验签仍通过（证书过期由 cert_checker 巡检） |
| CA证书过期/证书尚未生效 | 验签失败，返回 VerifyError |
| CRL 未配置 | 跳过 CRL 校验，验签正常执行 |

### error_code_mapper 必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| SignError → BusinessError 映射 | 每个变体正确映射 |
| VerifyError → BusinessError 映射 | 每个变体正确映射 |
| OpenSSL 错误码映射 | 常见错误库ID正确映射 |
| 未知 OpenSSL 错误 | 签名映射为 Other(10)，验签映射为 Other(99) |

### mock 策略

- sign/verify: 使用 OpenSSL 编程生成 ECC-256 自签证书链（CA → signer），生成测试用 CRL
- error_code_mapper: 构造各类错误码验证映射逻辑（验签使用X509错误码，签名使用错误库ID）
