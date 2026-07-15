# 插件框架层 详细设计

## 1. 职责与边界

### 负责

- **plugin_manager**: 定义 Plugin trait 和 PluginContext，管理插件生命周期（init → shutdown），**不负责消息分发**
- **transport**: 定义 TransportLayer trait 和 DataHandler trait，提供通用通信抽象，支持插件注册业务处理器
- **handler**: 实现 DataHandler trait，处理 JSON 业务报文，调用 sign/verify 模块，构造 JSON 响应

### 不负责

- **plugin_manager 不负责**：消息分发（由 TransportLayer 负责）、vsock 通信（由通信层实现）、具体业务逻辑（由插件实现）
- **transport 不负责**：具体通信协议实现（由 VsockTransport 等实现类负责）
- **handler 不负责**：CMS 签名/验签计算（由 sign/verify 负责）、证书加载（由 cert_loader 负责）、错误码到 result code 的最终映射（由 error_code_mapper 提供，handler 调用）

---

## 2. 公开 API

### framework::transport

```rust
/// 通用通信抽象 trait：插件通过此 trait 注册业务处理器，不依赖具体通信机制
/// 注：已改为 async 版本（使用 async-trait）
#[async_trait]
pub trait TransportLayer: Send + Sync {
    /// 注册业务处理器：type → handler
    /// Transport 在收到消息后，按 type 查找并调用对应的 handler
    fn register_handler(&self, msg_type: u32, handler: Box<dyn DataHandler>);

    /// 启动通信（async）
    async fn start(&self) -> Result<(), TransportError>;

    /// 停止通信（async）
    async fn stop(&self);
}

/// 业务数据处理 trait
/// Transport 已解析完报文协议（header、version、len 校验），handler 只处理业务 data
/// 输入：业务 data 字节（JSON）
/// 输出：响应 data 字节（JSON），None 表示处理失败
pub trait DataHandler: Send + Sync {
    fn handle(&self, data: &[u8]) -> Option<Vec<u8>>;
}

pub enum TransportError {
    StartFailed(String),
    StopFailed(String),
}
```

### framework::plugin_manager

/// 插件 trait：框架与插件的标准交互接口
pub trait Plugin: Send + Sync {
    /// 插件名称
    fn name(&self) -> &str;

    /// 插件初始化。通过 ctx 获取配置和 TransportLayer 引用
    /// 插件在 init 中调用 ctx.transport.register_handler() 注册业务处理器
    fn init(&mut self, ctx: &PluginContext) -> Result<(), PluginError>;

    /// 插件关闭
    fn shutdown(&mut self) -> Result<(), PluginError>;
}

/// 插件初始化上下文：向插件传递框架配置和通信层引用
pub struct PluginContext {
    pub config: Arc<AppConfig>,
    pub transport: Arc<dyn TransportLayer>,
}

impl PluginContext {
    pub fn new(config: Arc<AppConfig>, transport: Arc<dyn TransportLayer>) -> Self;
}

/// 插件管理器：持有所有插件实例，管理生命周期
pub struct PluginManager {
    plugins: Vec<Box<dyn Plugin>>,
}

impl PluginManager {
    pub fn new() -> Self;

    /// 注册插件（init 前调用）
    pub fn add_plugin(&mut self, plugin: Box<dyn Plugin>);

    /// 初始化所有插件
    /// 遍历插件调用 init()，插件在 init 中向 transport 注册 handler
    pub fn init_all(&mut self, ctx: &PluginContext) -> Result<(), PluginError>;

    /// 关闭所有插件（逆序调用 shutdown()）
    pub fn shutdown_all(&mut self) -> Result<(), PluginError>;
}

pub enum PluginError {
    InitFailed(String),
    ShutdownFailed(String),
}
```

### trustring 插件

```rust
/// trustring 插件：实现 Plugin trait，在 init 中注册业务处理器
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
    fn name(&self) -> &str { "trustring" }

    fn init(&mut self, ctx: &PluginContext) -> Result<(), PluginError> {
        // 注册签名处理器 (0x10)
        ctx.transport.register_handler(0x10, Box::new(SignHandler {
            signer: self.signer.clone(),
        }));

        // 注册验签+签名处理器 (0x12)
        ctx.transport.register_handler(0x12, Box::new(VerifySignHandler {
            signer: self.signer.clone(),
            verifier: self.verifier.clone(),
        }));

        // 注册验签处理器 (0x14)
        ctx.transport.register_handler(0x14, Box::new(VerifyHandler {
            verifier: self.verifier.clone(),
        }));

        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), PluginError> { Ok(()) }
}
```

---

## 3. 内部实现（pub(crate)）

以下模块为 trustring 插件内部实现，不对外公开：

### handler 模块

```rust
/// 签名处理器 (0x10)
pub(crate) struct SignHandler {
    pub(crate) signer: Arc<Signer>,
}

impl DataHandler for SignHandler {
    fn handle(&self, data: &[u8]) -> Option<Vec<u8>>;
}

/// 验签+签名处理器 (0x12)
pub(crate) struct VerifySignHandler {
    pub(crate) signer: Arc<Signer>,
    pub(crate) verifier: Arc<Verifier>,
}

impl DataHandler for VerifySignHandler {
    fn handle(&self, data: &[u8]) -> Option<Vec<u8>>;
}

/// 验签处理器 (0x14)
pub(crate) struct VerifyHandler {
    verifier: Arc<Verifier>,
}

impl DataHandler for VerifyHandler {
    fn handle(&self, data: &[u8]) -> Option<Vec<u8>>;
}
```

### handler 内部 JSON 结构体

```rust
// 签名请求 (0x10)
#[derive(Serialize, Deserialize)]
struct SignRequest {
    #[serde(rename = "to-sign")]
    to_sign: ToSign,
}
#[derive(Serialize, Deserialize)]
struct ToSign {
    data: String,
}

// 签名响应 (0x11)
#[derive(Serialize, Deserialize)]
struct SignResponse {
    signed_data: String,  // Base64(CMS DER)
    id: String,           // Base64(Subject Key ID)
    result: u32,
}

// 验签+签名请求 (0x12)
#[derive(Deserialize)]
struct VerifySignRequest {
    #[serde(rename = "to-verify")]
    to_verify: ToVerify,
    #[serde(rename = "to-sign")]
    to_sign: ToSignWithId,
}
#[derive(Serialize, Deserialize)]
struct ToVerify {
    data: String,
    signed_data: String,  // Base64(CMS DER)
    id: String,           // Base64(Subject Key ID)
}
#[derive(Deserialize)]
struct ToSignWithId {
    data: String,
    id: String,           // Base64(Subject Key ID)
}

// 验签+签名响应 (0x13)
#[derive(Serialize)]
struct VerifySignResponse {
    signed_data: String,
    id: String,
    result: u32,
}

// 验签请求 (0x14)
#[derive(Serialize, Deserialize)]
struct VerifyRequest {
    #[serde(rename = "to-verify")]
    to_verify: ToVerify,
}

// 验签响应 (0x15)
#[derive(Serialize, Deserialize)]
struct VerifyResponse {
    result: u32,
}
```

---

## 4. 内部状态

| 结构体 | 状态 | 生命周期 |
|--------|------|---------|
| PluginManager | plugins（插件实例列表） | 进程级 |
| PluginContext | config + transport（只读共享） | init 阶段创建，传递给插件 |
| TrustringPlugin | signer + verifier（Arc 包裹，预加载） | 进程级 |
| SignHandler / VerifySignHandler / VerifyHandler | signer / verifier（Arc clone） | 注册到 Transport，进程级 |

---

## 5. 关键场景

### 插件注册与启动

```
main.rs              VsockTransport         PluginManager        TrustringPlugin
  |                      |                      |                      |
  |-- new() ------------>|                      |                      |
  |<-- transport --------|                      |                      |
  |                      |                      |                      |
  |-- new() ------------------------------------>|                      |
  |<-- pm ---------------------------------------|                      |
  |                      |                      |                      |
  |-- ctx = {config, transport}                 |                      |
  |-- pm.init_all(ctx) ------------------------>|                      |
  |                      |                      |-- init(ctx) -------->|
  |                      |                      |                      |-- ctx.transport.register_handler(0x10, SignHandler)
  |                      |<-- register_handler --|----------------------|
  |                      |                      |                      |-- ctx.transport.register_handler(0x12, VerifySignHandler)
  |                      |<-- register_handler --|----------------------|
  |                      |                      |                      |-- ctx.transport.register_handler(0x14, VerifyHandler)
  |                      |<-- register_handler --|----------------------|
  |                      |                      |<-- Ok(()) -----------|
  |                      |                      |                      |
  |-- transport.start() ->|                      |                      |
  |                      |  开始接受连接和消息    |                      |
```

### 运行时消息分发

```
VsockTransport 内部
  |
  |-- 收到字节流
  |-- 解析 header（seq, version, type, len）
  |-- 校验 version == 0xFFFF0400, len <= 10240
  |-- 查 handler 表[type]
  |   ↓ 未命中 → 构造 type=0x01 错误响应
  |   ↓ 命中 → handler.handle(data_bytes)
  |       ↓ None → 构造 type=0x01 错误响应
  |       ↓ Some(resp_bytes) → 拼装 VsockMessage(seq, version, response_type, resp_bytes)
  |-- 发送响应
```

### handler 签名处理 (0x10)

```
SignHandler.handle(data)
  |
  |-- 解析 data → SignRequest JSON
  |   ↓ 解析失败 → 返回 None（Transport 构造 type=0x01）
  |
  |-- Base64 解码 to-sign.data（如果需要）
  |
  |-- signer.sign(data)
  |   ↓ 成功 → Base64 编码 signed_data + cert_id
  |   ↓ 失败 → error_code_mapper::map_openssl_error() → result code
  |
  |-- 构造 SignResponse { signed_data, id, result }
  |-- 序列化为 JSON → 返回 Some(bytes)
```

### handler 验签+签名处理 (0x12)

```
VerifySignHandler.handle(data)
  |
  |-- 解析 data → VerifySignRequest JSON
  |
  |-- [步骤1: 验签]
  |   |-- Base64 解码 to-verify.signed_data, to-verify.id
  |   |-- verifier.verify(signed_data, data, signer_cert_id)
  |   |   ↓ VerifyOutcome::SameNode (result=0) → 继续签名
  |   |   ↓ 其他 VerifyOutcome → 不执行签名，返回对应 result
  |   |   ↓ VerifyError → error_code_mapper → result≥3
  |
  |-- [步骤2: 签名（仅 result=0 时）]
  |   |-- Base64 解码 to-sign.id
  |   |-- signer.sign_with_id(data, external_id)
  |   |   ↓ 成功 → Base64 编码
  |   |   ↓ 失败 → error_code_mapper → result≥7
  |
  |-- 构造 VerifySignResponse { signed_data, id, result }
  |-- 序列化为 JSON → 返回 Some(bytes)
```

### handler 验签处理 (0x14)

```
VerifyHandler.handle(data)
  |
  |-- 解析 data → VerifyRequest JSON
  |
  |-- Base64 解码 to-verify.signed_data, to-verify.id
  |-- verifier.verify(signed_data, data, signer_cert_id)
  |   ↓ VerifyOutcome::SameNode → result=0
  |   ↓ VerifyOutcome::OtherNode → result=1
  |   ↓ VerifyOutcome::IdentityConflict → result=2
  |   ↓ VerifyError → error_code_mapper → result≥3
  |
  |-- 构造 VerifyResponse { result }
  |-- 序列化为 JSON → 返回 Some(bytes)
```

### 多插件注册

```
多个插件向同一 Transport 注册 handler：

  插件 A.init(ctx):
    ctx.transport.register_handler(0x10, HandlerA1)
    ctx.transport.register_handler(0x12, HandlerA2)

  插件 B.init(ctx):
    ctx.transport.register_handler(0x20, HandlerB1)
    ctx.transport.register_handler(0x21, HandlerB2)

  Transport 内部 handler 表:
    {0x10→HandlerA1, 0x12→HandlerA2, 0x20→HandlerB1, 0x21→HandlerB2}

  收到 type=0x20 → 查表 → HandlerB1.handle()
  收到 type=0x99 → 查表 → 未命中 → 构造 type=0x01 错误响应
```

同一 type 被多个插件注册时，后注册的覆盖先注册的（Transport 内部 HashMap 语义）。

### 异常场景

| 场景 | 处理方 | 行为 |
|------|--------|------|
| JSON 解析失败 | DataHandler | 返回 None → Transport 构造 type=0x01 |
| Base64 解码失败 | DataHandler | 返回 result=6（FormatError） |
| 插件 init 失败 | PluginManager | 返回 PluginError::InitFailed，进程启动失败 |
| DataHandler.handle panic | Transport | catch_unwind → 构造 type=0x00 |
| 未知 type | Transport | handler 表未命中 → 构造 type=0x01 |

---

## 6. 依赖关系

### 上游依赖

| 依赖 | 用途 |
|------|------|
| `transport::TransportLayer` | 插件通过 PluginContext 获取引用，注册 DataHandler |
| `transport::DataHandler` | handler 实现此 trait 处理业务逻辑 |
| `config::AppConfig` | 通过 PluginContext 传递给插件 |
| `sign::Signer`（内部） | handler 调用签名（Arc 包裹） |
| `verify::Verifier`（内部） | handler 调用验签（Arc 包裹） |
| `error_code_mapper`（内部） | handler 调用错误映射 |
| `cert_loader`（内部） | TrustringPlugin 构造时加载证书初始化 Signer/Verifier |

### 下游消费者

| 消费者 | 使用方式 |
|--------|---------|
| main.rs（进程生命周期） | 创建 Transport 和 PluginManager，构造 PluginContext，调用 init_all/shutdown_all |
| Transport 实现（如 VsockTransport） | 实现 TransportLayer trait，接收插件注册的 handler |
| integration-tests | 使用 framework 公开 API 进行测试（不依赖 trustring 内部实现） |

---

## 7. 测试策略

### plugin_manager 必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| init_all 成功 | 所有插件 init 返回 Ok |
| init 失败 | 返回 PluginError::InitFailed，后续插件不初始化 |
| shutdown_all 逆序调用 | 插件按注册逆序关闭 |
| 插件通过 ctx.transport 注册 handler | MockTransport 验证 register_handler 被调用 |

### handler 必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| 0x10 正常签名 | SignHandler.handle 返回 Some(bytes)，解析后 result=0 |
| 0x12 验签通过 + 签名 | VerifySignHandler.handle 返回 Some(bytes)，解析后 result=0 |
| 0x12 验签失败（result≠0） | 不执行签名，返回对应 result |
| 0x14 验签通过 + 同节点 | VerifyHandler.handle 返回 result=0 |
| 0x14 验签通过 + 不同节点 | 返回 result=1 |
| 0x14 验签通过 + 身份冲突 | 返回 result=2 |
| JSON 格式错误 | 返回 None |
| Base64 解码失败 | 返回 result=6 |
| 签名失败 | error_code_mapper 映射后返回 result≥7 |

### mock 策略

- plugin_manager: 使用 MockTransport 实现 TransportLayer trait，验证插件注册行为
- handler: 使用真实 OpenSSL 证书做端到端测试，直接调用 DataHandler.handle()
