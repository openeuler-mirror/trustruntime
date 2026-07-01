# 通信层 详细设计

## 1. 职责与边界

### 负责

- **TransportLayer trait**: 定义通用通信抽象（register_handler / start / stop）
- **VsockTransport**: TransportLayer 的 vsock 实现
  - vsock listener 创建与连接接受
  - TLS 双向认证握手（OpenSSL SslAcceptor）
  - 连接并发管理（Semaphore 限 16 连接）
  - 报文收发与协议校验（version、len、size）
  - 通用错误响应构造（type=0x00/0x01/0x02）
  - 按 type 分发到已注册的 DataHandler

### 不负责

- 业务报文内容解析（由 DataHandler 实现类负责）
- 证书加载（由 framework::cert 提供）
- 插件生命周期管理（由 plugin_manager 负责）
- 证书过期巡检（由 cert_checker 负责）

---

## 2. 公开 API

### TransportLayer trait（定义在 plugin_manager 模块）

```rust
/// 通用通信抽象 trait
/// 注：已改为 async 版本（使用 async-trait）
#[async_trait]
pub trait TransportLayer: Send + Sync {
    /// 注册业务处理器：type → handler
    fn register_handler(&self, msg_type: u32, handler: Box<dyn DataHandler>);

    /// 启动通信（async）
    async fn start(&self) -> Result<(), TransportError>;

    /// 停止通信（async）
    async fn stop(&self);
}

/// 业务数据处理 trait
pub trait DataHandler: Send + Sync {
    fn handle(&self, data: &[u8]) -> Option<Vec<u8>>;
}
```

### VsockTransport（TransportLayer 的 vsock 实现）

```rust
pub struct VsockTransport {
    ssl_acceptor: Arc<SslAcceptor>,         // Arc包装，支持跨线程共享
    semaphore: Arc<Semaphore>,               // 16 permits
    handlers: Arc<RwLock<HashMap<u32, Box<dyn DataHandler>>>>,  // Arc包装，跨线程共享
    port: u32,
    shutdown_signal: Arc<AtomicBool>,        // 关闭信号
    listener_handle: Arc<Mutex<Option<JoinHandle<()>>>>,  // listener task handle
}

impl VsockTransport {
    /// 构造 VsockTransport
    /// 1. 通过 framework::cert 加载通信证书（PEM/DER）
    /// 2. 构建 SslAcceptor（TLS 配置 + 双向认证 + CRL）
    /// 3. 初始化 Semaphore(16)
    pub fn new(tls_config: &TlsConfig, port: u32) -> Result<Self, VsockError>;
}

#[async_trait]
impl TransportLayer for VsockTransport {
    /// 注册业务处理器
    /// 内部使用 RwLock<HashMap> 存储，支持并发读
    fn register_handler(&self, msg_type: u32, handler: Box<dyn DataHandler>);

    /// 启动 vsock listener，进入连接接受循环（async）
    /// 每个连接 spawn 一个 tokio task，Semaphore 限流
    /// 设置 shutdown_signal = false，启动 listener task
    async fn start(&self) -> Result<(), TransportError>;

    /// 停止接受新连接（async）
    /// 设置 shutdown_signal = true，等待 listener task 结束（5s timeout）
    async fn stop(&self);
}

/// TLS 配置参数
pub struct TlsConfig {
    pub cert_path: String,       // 通信证书
    pub key_path: String,        // 通信私钥
    pub key_password: Option<String>,  // 私钥密码（可选）
    pub ca_cert_path: String,    // 通信 CA 根证书
    pub crl_path: Option<String>,      // 通信 CRL（可选，不配置则跳过CRL校验）
}

pub enum VsockError {
    TlsConfigError(String),                 // TLS 配置失败（含证书过期）
    IoError(std::io::Error),                // 文件I/O错误（证书/私钥/CRL文件不存在、权限不足等）
    BindError,                                // vsock 绑定失败
}
```

### 内部辅助函数

```rust
/// 构造通用错误响应（header only, len=0）
/// seq 和 version 与请求一致
fn create_error_response(seq: u32, version: u32, error_type: u32) -> VsockMessage;

/// 单个连接的消息处理循环（内部私有方法）
/// 注：改为 VsockTransport 的内部私有方法，不再作为独立函数
async fn handle_connection_with_params(
    stream: SslStream<VsockStream>,
    handlers: Arc<RwLock<HashMap<u32, Box<dyn DataHandler>>>>,
    semaphore: Arc<Semaphore>,
);
```

---

## 3. 内部状态

| 结构体 | 状态 | 生命周期 |
|--------|------|---------|
| VsockTransport | ssl_acceptor + semaphore + handlers + port | 进程级 |
| SslAcceptor | TLS 配置 + 通信证书（预加载） | 进程级 |
| Semaphore | 16 permits，运行时动态 acquire/release | 进程级 |
| handlers | RwLock<HashMap<u32, Box<dyn DataHandler>>> | 进程级，插件 init 时注册 |
| listener | vsock listener（start 时创建） | start 期间 |

---

## 4. 关键场景

### TLS 配置

```
VsockTransport::new()
  |
  |-- framework::cert::load_x509(comm_cert)     // PEM/DER 双格式
  |-- framework::cert::load_private_key(comm_key, password)
  |-- framework::cert::load_x509(comm_ca_root)
  |-- framework::cert::load_crl(comm_crl)
  |
  |-- 构建 SslAcceptor:
  |   |-- SslMethod::tls()
  |   |-- 设置证书 + 私钥
  |   |-- 设置 CA 证书（客户端验证）
  |   |-- 设置 CRL
  |   |-- 设置 verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
  |   |-- 设置协议版本：仅 TLS 1.2 + TLS 1.3
  |   |-- 设置算法套件白名单
  |   |-- 禁用 renegotiation
  |
  |-- 任何步骤失败 → VsockError::TlsConfigError
```

### 连接接受循环

```
start()
  |
  |-- 创建 vsock listener，绑定端口
  |   ↓ 失败 → TransportError::StartFailed
  |
  |-- 循环:
  |   |-- semaphore.acquire()          // 等待可用连接槽位
  |   |-- listener.accept()            // 接受新连接
  |   |   ↓ 失败 → warn 日志，继续循环
  |   |
  |   |-- SslAcceptor.accept(stream)   // TLS 握手
  |   |   ↓ 失败 → warn 日志，关闭连接，继续循环
  |   |
  |   |-- tokio::spawn(handle_connection(stream, handlers, semaphore))
  |       |-- semaphore 在 task 结束时自动 release
```

### 消息处理流水线（handle_connection 内部）

```
handle_connection(stream, handlers, semaphore)
  |
  |-- 循环读取消息:
  |   |
  |   |-- 读取 16 字节报文头
  |   |   ↓ 读取失败/不完整 → type=0x01（报文格式异常）→ 发送错误响应 → 继续
  |   |
  |   |-- 解析 header（seq, version, type, len）
  |   |
  |   |-- 校验 header.len ≤ 10240
  |   |   ↓ 超限 → type=0x02（报文过长）→ 发送错误响应 → 继续
  |   |
  |   |-- 读取 header.len 字节 data
  |   |   ↓ 读取长度不一致 → type=0x01 → 发送错误响应 → 继续
  |   |
  |   |-- 校验 version == 0xFFFF0400
  |   |   ↓ 不匹配 → type=0x01 → 发送错误响应 → 继续
  |   |
  |   |-- 查 handlers 表[type]
  |   |   ↓ 未命中 → type=0x01 → 发送错误响应 → 继续
  |   |   ↓ 命中 → handler.handle(data)
  |   |       ↓ None → type=0x01 → 发送错误响应 → 继续
  |   |       ↓ Some(resp_bytes) → 构造 VsockMessage(seq, version, response_type, resp_bytes)
  |   |       ↓ panic（catch_unwind）→ type=0x00（服务端异常）→ 发送错误响应 → 继续
  |   |
  |   |-- response.serialize() → TLS 加密 → vsock 发送
  |   |   ↓ 发送失败 → 关闭连接 → 退出循环
  |   |
  |   |-- 继续读取下一条消息（连接内串行）
  |
  |-- 连接关闭（客户端断开或 IO 错误）
```

### 通用错误响应格式

| type | 触发条件 | 响应内容 |
|------|---------|---------|
| 0x00 | DataHandler.handle panic | header(seq=请求seq, version=请求version, type=0x00, len=0)，无 data |
| 0x01 | 报文头不完整 / data 长度不一致 / version 不匹配 / 未知 type / handler 返回 None | header(seq=请求seq, version=请求version, type=0x01, len=0)，无 data |
| 0x02 | header.len > 10240 | header(seq=请求seq, version=请求version, type=0x02, len=0)，无 data |

注：当报文头本身无法解析时（如字节数 < 16），seq 和 version 取 0。

### 异常场景

| 场景 | 处理方式 |
|------|---------|
| TLS 握手失败（证书过期/无效） | warn 日志，关闭连接，继续接受新连接 |
| 客户端断开连接 | 正常退出 handle_connection task |
| IO 读取错误 | 关闭连接，退出 task |
| DataHandler 处理超时 | 无超时机制（签名验签为毫秒级操作） |

---

## 5. 依赖关系

### 上游依赖

| 依赖 | 用途 |
|------|------|
| `openssl::ssl::SslAcceptor` | TLS 服务端配置 |
| `framework::cert` | 加载通信证书（PEM/DER） |
| `message::VsockMessage` | 报文解析/构造 |
| `plugin_manager::TransportLayer` | 实现此 trait，提供通信抽象 |
| `plugin_manager::DataHandler` | 接收插件注册的业务处理器 |
| `log` crate | 通过 `log::warn!`/`log::error!` 输出日志 |
| `tokio` | 异步运行时、Semaphore |

### 下游消费者

| 消费者 | 使用方式 |
|--------|---------|
| main.rs（进程生命周期） | 创建 VsockTransport，传递给 PluginContext，调用 start/stop |
| 插件（通过 PluginContext） | 调用 transport.register_handler() 注册业务处理器 |

---

## 6. 测试策略

### TLS 配置必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| 有效证书 TLS 配置 | SslAcceptor 构建成功 |
| 通信证书过期 | VsockError::TlsConfigError |
| 通信证书文件不存在 | VsockError::TlsConfigError |
| PEM 格式证书 | 正确加载 |
| DER 格式证书 | 正确加载 |
| 加密私钥 + 正确密码 | 正确加载 |
| 加密私钥 + 错误密码 | VsockError::TlsConfigError |

### 消息处理流水线必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| 正常消息（合法头 + 合法 data + 已注册 handler） | handler.handle 被调用，响应正确发送 |
| 报文头 < 16 字节 | 返回 type=0x01 |
| header.len > 10240 | 返回 type=0x02 |
| data 实际长度 != header.len | 返回 type=0x01 |
| version != 0xFFFF0400 | 返回 type=0x01 |
| 未注册 type | 返回 type=0x01 |
| handler.handle 返回 None | 返回 type=0x01 |
| handler.handle panic | catch_unwind，返回 type=0x00 |
| 错误响应 seq/version | 与请求一致 |

### handler 注册必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| register_handler 成功 | handlers 表正确存储 |
| 同一 type 重复注册 | 后注册覆盖先注册 |
| 多 type 注册 | handlers 表正确存储多个 |

### 并发管理必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| 16 并发连接 | 全部正常处理 |
| 第 17 个连接 | 等待 Semaphore，不拒绝 |
| 连接断开后释放 | Semaphore permit 释放，新连接可进入 |

### mock 策略

- VsockListener: 抽象 `trait VsockListener`，测试用 mock 实现（或 TCP listener 模拟）
- TlsAcceptor: 抽象 `trait TlsAcceptor`，测试用本地 TCP + 自签证书模拟 TLS 握手
- DataHandler: 使用 MockDataHandler 验证分发调用
