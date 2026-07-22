# 证书管理层 详细设计

## 1. 职责与边界

### 负责

- **framework::cert**（新增模块）：通用证书加载能力——X509 证书、私钥、CRL 的 PEM/DER 双格式解析，证书时间有效性判断（过期、未生效）
- **trustring::cert_loader**：业务层证书组合加载——将签名证书+私钥+CA+CRL 组合为业务上下文，提取 Subject Key ID
- **framework::core::cert_checker**：证书状态定时巡检——每 24h 检查所有证书有效期（过期、未生效），异常时 warn 日志

### 不负责

- **framework::cert 不负责**：证书过期/未生效判断的业务策略（由 cert_checker 和 vsock_server 各自决定）、证书路径管理（由 config 提供）
- **cert_loader 不负责**：CMS 签名/验签操作（由 sign/verify 模块负责）、通信证书加载（由 vsock_server 通过 framework::cert 加载）
- **cert_checker 不负责**：任何通知/关闭/退出动作。检测到过期或未生效仅打印 warn 日志，不触发 vsock 关闭或进程退出

---

## 2. 公开 API

### framework::cert

```rust
/// 通用证书加载：PEM/DER 双格式自动识别
pub fn load_x509(path: &str) -> Result<X509, CertLoadError>;

/// 通用私钥加载：PEM/DER 双格式，支持可选密码
pub fn load_private_key(path: &str, password: Option<&str>) -> Result<PKey<Private>, CertLoadError>;

/// 通用 CRL 加载：PEM/DER 双格式
pub fn load_crl(path: &str) -> Result<X509Crl, CertLoadError>;

/// 提取证书的 Subject Key ID（20 字节 SHA-1 哈希）
pub fn extract_subject_key_id(cert: &X509) -> Result<Vec<u8>, CertLoadError>;

/// 检查证书是否过期
pub fn is_expired(cert: &X509) -> bool;

/// 检查证书是否尚未生效
pub fn is_not_yet_valid(cert: &X509) -> bool;

pub enum CertLoadError {
    IoError(std::io::Error),
    OpenSslError(openssl::error::ErrorStack),
    InvalidFormat,  // PEM 和 DER 均解析失败
}

/// KeyUsage 标志位
pub struct KeyUsageFlags;

impl KeyUsageFlags {
    pub const DIGITAL_SIGNATURE: u32 = 0x80;
    pub const KEY_ENCIPHERMENT: u32 = 0x20;
    pub const NON_REPUDIATION: u32 = 0x40;
    pub const DATA_ENCIPHERMENT: u32 = 0x10;
    pub const KEY_AGREEMENT: u32 = 0x08;
    pub const KEY_CERT_SIGN: u32 = 0x04;
    pub const CRL_SIGN: u32 = 0x02;
}

/// 检查证书是否包含指定的KeyUsage位（包含匹配）
/// 用于通信证书：证书必须包含所有指定位，可包含其他位
pub fn check_key_usage_contains(cert: &X509, required_flags: u32) -> Result<(), CertLoadError>;

/// 检查证书是否仅包含指定的KeyUsage位（精确匹配）
/// 用于签名证书：证书必须仅包含指定位，不能包含其他位
pub fn check_key_usage_exact(cert: &X509, required_flags: u32) -> Result<(), CertLoadError>;

/// 检查证书ExtendedKeyUsage扩展
pub fn check_extended_key_usage(cert: &X509, required_oid: &str) -> Result<(), CertLoadError>;
```

### framework::core::cert_checker

```rust
pub struct CertificateChecker {
    cert_paths: Vec<String>,
    interval: Duration,              // 检查间隔，默认24小时
}

impl CertificateChecker {
    pub fn new(cert_paths: Vec<String>) -> Self;
    
    /// 设置检查间隔（Builder模式）
    pub fn with_interval(self, interval: Duration) -> Self;

    /// 检查所有证书，返回每个证书的状态
    pub fn check_all(&self) -> Vec<CertificateStatus>;

    /// 启动定时巡检任务（tokio spawn），按配置间隔执行 check_all()
    /// 过期时通过 log::warn! 打印 warn 日志，不做其他动作
    pub fn start_periodic_check(self) -> JoinHandle<()>;
}

pub struct CertificateStatus {
    pub path: String,
    pub expired: bool,
    pub not_yet_valid: bool,
    pub not_after: Option<String>,   // 过期时间，解析失败时为 None
    pub not_before: Option<String>,  // 生效时间，解析失败时为 None
}
```

---

## 3. 内部实现（pub(crate)）

以下模块为 trustring 插件内部实现，不对外公开：

### trustring::cert_loader

```rust
/// CMS 签名证书上下文（证书 + 私钥 + cert_id）
pub(crate) struct CmsCertificate {
    cert: X509,
    key: PKey<Private>,
    cert_id: Vec<u8>,  // Subject Key ID 原始字节
}

impl CmsCertificate {
    /// 加载签名证书 + 私钥，提取 Subject Key ID
    pub(crate) fn load(cert_path: &str, key_path: &str) -> Result<Self, CertLoadError>;

    pub(crate) fn cert(&self) -> &X509;
    pub(crate) fn key(&self) -> &PKey<Private>;
    pub(crate) fn cert_id(&self) -> &[u8];
    pub(crate) fn take(self) -> (X509, PKey<Private>, Vec<u8>);
}

/// CA 根证书
pub(crate) struct CaCertificate {
    cert: X509,
}

impl CaCertificate {
    pub(crate) fn load(path: &str) -> Result<Self, CertLoadError>;
    pub(crate) fn cert(&self) -> &X509;
}

/// 证书吊销列表
pub(crate) struct CertificateRevocationList {
    crl: X509Crl,
}

impl CertificateRevocationList {
    pub(crate) fn load(path: &str) -> Result<Self, CertLoadError>;
    pub(crate) fn crl(&self) -> &X509Crl;
}
```

---

## 4. 内部状态

| 结构体 | 状态 | 生命周期 |
|--------|------|---------|
| CmsCertificate | cert + key + cert_id（进程级预加载） | 进程级，init 时加载，`Arc` 共享 |
| CaCertificate | cert（进程级预加载） | 进程级 |
| CertificateRevocationList | crl（进程级预加载） | 进程级 |
| CertificateChecker | cert_paths | 进程级，后台 task 持有 |

---

## 5. 关键场景

### PEM/DER 双格式加载

```
调用方                    framework::cert
  |                          |
  |-- load_x509(path) ------>|
  |                          |  1. 读取文件字节
  |                          |  2. 尝试 X509::from_pem()
  |                          |  3. PEM 失败 → 尝试 X509::from_der()
  |                          |  4. DER 也失败 → InvalidFormat
  |<-- Result<X509> ---------|
```

### 证书状态巡检

```
cert_checker (后台 task)
   |
   |  [每 24h 触发]
   |
   |-- 遍历 cert_paths
   |   |-- load_x509(path)
   |   |-- is_expired(cert)
   |   |   |-- true  → log::warn!("证书已过期: {path}, not_after: {time}")
   |   |   |-- false → 跳过
   |   |-- is_not_yet_valid(cert)
   |   |   |-- true  → log::warn!("证书尚未生效: {path}, not_before: {time}")
   |   |   |-- false → 跳过
   |
   |  [巡检结束，等待下一个 24h]
```

### 异常场景

| 场景 | 模块 | 处理方式 |
|------|------|---------|
| 证书文件不存在 | framework::cert | 返回 IoError |
| PEM/DER 均解析失败 | framework::cert | 返回 InvalidFormat |
| 私钥密码错误 | framework::cert | 返回 OpenSslError |
| 巡检时证书文件被删除 | cert_checker | warn 日志（IO 错误），继续检查其他证书 |
| 签名证书过期 | cert_checker | warn 日志，不影响签名业务 |
| 签名证书未生效 | cert_checker | warn 日志，不影响签名业务 |
| 通信证书运行中过期 | cert_checker | warn 日志，不关闭 vsock，不触发进程退出 |
| 通信证书运行中变为未生效 | cert_checker | warn 日志（理论上不存在此场景）|

---

## 6. 依赖关系

### 上游依赖

| 依赖 | 用途 |
|------|------|
| `openssl` crate | X509、PKey、X509Crl 类型及解析 |
| `framework::cert` | cert_loader 和 cert_checker 的底层加载能力 |
| `config::CertificateConfig` | cert_checker 获取所有证书路径 |
| `log` crate | cert_checker 通过 `log::warn!` 输出日志 |

### 下游消费者

| 消费者 | 使用方式 |
|--------|---------|
| sign（签名验签层） | 通过 CmsCertificate 获取签名证书和私钥 |
| verify（签名验签层） | 通过 CaCertificate + CRL + CmsCertificate 构建验签上下文 |
| vsock_server（通信层） | 通过 framework::cert 加载通信证书配置 TLS |
| core（进程生命周期） | 启动 cert_checker 定时巡检 |

---

## 7. 测试策略

### framework::cert 必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| PEM 格式证书加载 | 正确解析 X509 |
| DER 格式证书加载 | 正确解析 X509 |
| 非法格式文件 | 返回 InvalidFormat |
| 文件不存在 | 返回 IoError |
| PEM 格式私钥加载（无密码） | 正确解析 PKey |
| PEM 格式私钥加载（有密码） | 正确解析 PKey |
| PEM/DER 格式 CRL 加载 | 正确解析 X509Crl |
| Subject Key ID 提取 | 返回正确的 20 字节哈希 |
| 过期证书 is_expired() | 返回 true |
| 有效证书 is_expired() | 返回 false |
| 未生效证书 is_not_yet_valid() | 返回 true |
| 已生效证书 is_not_yet_valid() | 返回 false |

### 证书用途校验必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| KeyUsage包含匹配 | 证书包含所有必需位，返回Ok |
| KeyUsage包含匹配（额外位） | 证书包含必需位+额外位，返回Ok |
| KeyUsage包含匹配失败 | 证书缺少必需位，返回Err |
| KeyUsage精确匹配 | 证书仅包含指定位，返回Ok |
| KeyUsage精确匹配失败（额外位） | 证书包含额外位，返回Err |
| KeyUsage精确匹配失败（缺少位） | 证书缺少必需位，返回Err |
| ExtendedKeyUsage匹配 | 证书包含指定OID，返回Ok |
| ExtendedKeyUsage匹配失败 | 证书缺少指定OID，返回Err |

### cert_loader 必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| CmsCertificate 完整加载 | cert + key + cert_id 均正确 |
| cert_id 为 Subject Key ID | 与 OpenSSL 命令行提取结果一致 |

### cert_checker 必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| 全部证书有效 | check_all() 返回全部 expired=false, not_yet_valid=false |
| 部分证书过期 | 对应项 expired=true，not_after 有值 |
| 部分证书未生效 | 对应项 not_yet_valid=true，not_before 有值 |
| 证书文件缺失 | 对应项 expired=false, not_yet_valid=false, not_after=None, not_before=None |
| 定时巡检触发 | 可配置间隔（测试时设为秒级），验证周期性执行 |

### mock 策略

- framework::cert: 测试用 OpenSSL 编程生成临时证书（ECC-256 自签），无需文件系统 mock
- cert_checker: 验证 `CertificateStatus` 返回值（expired/not_yet_valid/not_after/not_before）；可配置巡检间隔加速测试
