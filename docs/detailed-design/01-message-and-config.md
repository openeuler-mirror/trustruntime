# 报文与配置层 详细设计

## 1. 职责与边界

### 负责

- **message**: vsock 报文的结构定义、序列化（结构体 → 字节流）、反序列化（字节流 → 结构体）
- **config**: TOML 配置文件的解析、结构体映射、配置项校验

### 不负责

- **message 不负责**：协议版本校验（version == 0xFFFF0400）、报文长度校验（len ≤ 10240）、data 与 header.len 一致性校验、错误响应构造。这些职责归属 **vsock_server**（通信层）
- **config 不负责**：配置文件的存在性检查、文件权限校验、配置热更新。这些由调用方（main.rs）决定

---

## 2. 公开 API

### message 模块

```rust
// 报文头，固定 16 字节，小端序
#[repr(C)]
pub struct VsockHeader {
    pub seq: u32,       // 消息序列号，请求-响应配对标识
    pub version: u32,   // 消息格式版本号，约定值 0xFFFF0400
    pub msg_type: u32,  // 消息类型（0x00-0x15）
    pub len: u32,       // data 字段字节长度
}

// 完整报文
pub struct VsockMessage {
    pub header: VsockHeader,
    pub data: Vec<u8>,  // JSON 格式业务报文
}

impl VsockMessage {
    /// 构造报文。data 长度不做限制（由通信层校验）
    pub fn new(seq: u32, version: u32, msg_type: u32, data: Vec<u8>) -> Self;

    /// 序列化为字节流：16 字节头（LE） + data
    pub fn serialize(&self) -> Vec<u8>;

    /// 从字节流反序列化。仅做结构解析，不做业务校验
    /// 失败条件：字节数 < 16（头不完整）、字节数 != 16 + header.len（数据不完整）
    pub fn parse(bytes: &[u8]) -> Result<Self, MessageError>;
}

pub enum MessageError {
    IncompleteHeader,   // 字节数不足 16
    IncompleteData,     // 实际数据长度与 header.len 不一致
}
```

### config 模块

```rust
pub struct AppConfig {
    pub vsock: VsockConfig,
    pub log: LogConfig,
    pub certificate: CertificateConfig,
    pub cert_check: CertCheckConfig,  // 可选 section，缺省时使用默认值
}

pub struct VsockConfig {
    pub port: u32,              // vsock 端口号（必填）
    pub max_connections: u32,   // 最大并发连接数（可选，默认 16）
}

pub struct LogConfig {
    pub path: String,           // 日志文件路径（必填）
    pub level: String,          // 日志级别（可选，默认 "info"）
    pub max_file_size: u64,     // 单个日志文件最大大小 (MB)（必填）
    pub max_roll_count: u32,    // 日志回滚文件个数（必填）
}

pub struct CertificateConfig {
    // 签名验签证书
    pub signer_cert: String,
    pub signer_key: String,
    pub ca_root_cert: String,
    pub cms_crl: Option<String>,        // 可选，不配置则跳过 CRL 校验
    // 通信证书
    pub comm_cert: String,
    pub comm_key: String,
    pub comm_key_pwd: Option<String>,   // 可选，私钥未加密时不填
    pub comm_ca_root: String,
    pub comm_crl: Option<String>,       // 可选，不配置则跳过 CRL 校验
}

pub struct CertCheckConfig {
    pub interval_hours: u64,    // 巡检间隔，单位小时（可选，默认 24）
}

impl AppConfig {
    /// 从 TOML 字符串解析
    pub fn from_toml(content: &str) -> Result<Self, ConfigError>;

    /// 从文件路径加载并解析
    pub fn from_file(path: &str) -> Result<Self, ConfigError>;
}

pub enum ConfigError {
    IoError(std::io::Error),        // 文件读取失败
    ParseError(String),              // TOML 解析失败或缺少必填字段（错误描述字符串）
}
```

---

## 3. 内部状态

| 结构体 | 状态 | 生命周期 |
|--------|------|---------|
| VsockMessage | 无状态，纯数据载体 | 请求级（单次请求-响应后丢弃） |
| AppConfig | 无状态，解析后不可变 | 进程级（启动时加载，`Arc<AppConfig>` 共享） |

---

## 4. 关键场景

### message 序列化/反序列化

```
调用方                    message
  |                          |
  |-- VsockMessage::new() -->|  构造报文
  |-- serialize() ---------->|  输出: [seq|version|type|len|data...] (LE)
  |                          |
  |-- parse(bytes) --------->|  输入: 原始字节流
  |                          |  1. 检查 bytes.len() >= 16
  |                          |  2. 解析 16 字节头
  |                          |  3. 检查 bytes.len() == 16 + header.len
  |                          |  4. 提取 data 字段
  |<-- Result<VsockMessage> -|
```

### config 加载

```
main.rs                   config
  |                          |
  |-- from_file(path) ------>|  读取文件 → 解析 TOML → 映射结构体
  |<-- Result<AppConfig> ----|
  |                          |
  |  [失败场景]              |
  |  文件不存在 → IoError    |
  |  TOML 格式错误 → ParseError
  |  缺少必填字段 → ParseError
```

### 异常场景

| 场景 | 模块 | 错误类型 | 说明 |
|------|------|---------|------|
| 字节流 < 16 字节 | message | IncompleteHeader | 报文头不完整 |
| 字节流长度 != 16 + header.len | message | IncompleteData | data 字段不完整 |
| TOML 文件不存在 | config | IoError | 配置文件路径错误 |
| TOML 缺少必填字段 | config | ParseError | 配置不完整 |

---

## 5. 依赖关系

### 上游依赖

| 依赖 | 用途 |
|------|------|
| `serde` + `serde_json` | config 的 TOML 反序列化（通过 `toml` crate） |
| `toml` | TOML 解析 |
| 无外部依赖 | message 纯手工字节操作 |

### 下游消费者

| 消费者 | 使用方式 |
|--------|---------|
| vsock_server（通信层） | 调用 message::parse() 解析报文、message::serialize() 构造响应 |
| handler（插件框架层） | 从 VsockMessage.data 中提取 JSON 业务报文 |
| main.rs（进程生命周期） | 调用 config::from_file() 加载配置 |
| 所有模块 | 通过 `Arc<AppConfig>` 读取配置项 |

---

## 6. 测试策略

### message 必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| 正常序列化 + 反序列化 | roundtrip 一致性 |
| 空 data（len=0） | 正确序列化 16 字节头 |
| 最大 data（10240 字节） | 正确序列化/反序列化 |
| 字节流 < 16 字节 | 返回 IncompleteHeader |
| 字节流长度与 header.len 不匹配 | 返回 IncompleteData |
| 各字段边界值（seq=0, seq=u32::MAX） | 正确解析 |

### config 必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| 完整 TOML 解析 | 所有字段正确映射（含可选字段） |
| 最小 TOML 解析 | 仅必填字段，可选字段使用默认值（max_connections=16, level="info", cms_crl=None, comm_key_pwd=None, comm_crl=None, interval_hours=24） |
| 缺少必填字段 | 返回 ParseError |
| 文件不存在 | 返回 IoError |
| 额外字段（TOML 中有未定义字段） | 忽略或报错（取决于 serde 配置） |

### mock 策略

- message: 无需 mock，纯数据结构
- config: 测试用 TOML 字符串内联，无需文件系统 mock
