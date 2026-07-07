# CMS签名验签服务 手工测试工具设计文档

| 文档版本 | V1.0 |
| 编写日期 | 2026-06-27 |

---

## 1. 概述

### 1.1 工具定位

CMS签名验签服务已实现完整的集成测试覆盖（正常场景、异常场景、边界场景），但缺少支持人工交互式测试的工具。本设计文档定义 `cms-test-cli` 工具，用于：

- **手工交互测试**：人工输入参数，验证接口正确性
- **性能测试**：测量单接口响应时间、吞吐量
- **并发测试**：验证16连接并发限制、测量并发吞吐量
- **安全测试**：协议层攻击、证书层攻击、TLS层攻击测试

### 1.2 与现有测试体系的关系

| 测试类型 | 实现方式 | 用途 |
|----------|----------|------|
| 单元测试 | `#[test]` in source crates | 验证单个模块逻辑 |
| Handler层集成测试 | `integration-tests` crate | 验证签名验签业务逻辑 |
| 通信层集成测试 | `integration-tests` crate (WSL) | 验证vsock+TLS双向认证 |
| 手工交互测试 | `cms-test-cli` (本工具) | 人工探索性测试、调试辅助 |
| 性能/并发测试 | `cms-test-cli` (本工具) | 性能指标采集、并发边界验证 |
| 安全测试 | `cms-test-cli` (本工具) | 协议/证书/TLS三层安全攻击测试 |

### 1.3 设计原则

- **复用优先**：复用 `integration-tests` 的 `VsockClient`、`test_utils`、`ProcessManager`
- **交互式优先**：主界面为 REPL 模式，支持单次 CLI 执行作为补充
- **基础指标优先**：性能测试输出总数、成功数、平均响应时间、吞吐量(QPS)
- **安全测试全覆盖**：覆盖协议层、证书层、TLS层三类安全攻击场景

---

## 2. 目录结构

### 2.1 工具位置

| 项目 | 路径 |
|------|------|
| 工具代码 | `rust/tools/cms-test-cli/` |
| 设计文档 | `docs/cms-test-cli-design.md` |
| 工作空间注册 | `rust/Cargo.toml` 添加 `tools/cms-test-cli` |

### 2.2 工具内部结构

```
rust/tools/cms-test-cli/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs                 # 入口 + REPL循环
    ├── repl/
    │   ├── mod.rs              # REPL引擎
    │   ├── commands.rs         # 命令路由器
    │   └── parser.rs           # 输入解析器
    ├── testers/
    │   ├── mod.rs              # 测试器模块导出
    │   ├── interactive.rs      # 手工交互测试器
    │   ├── performance.rs      # 性能测试器
    │   ├── concurrent.rs       # 并发测试器
    │   ├── security.rs         # 安全测试器
    │   └── scenarios.rs        # 预置场景执行器
    ├── stats/
    │   ├── mod.rs              # 统计收集器
    │   └── reporter.rs         # 报告格式化
    └── config.rs               # 配置管理
```

---

## 3. REPL 命令设计

### 3.1 连接管理命令

| 命令 | 参数 | 说明 |
|------|------|------|
| `connect` | `<port> [--cert-dir <path>]` | 连接到指定端口的服务，cert-dir默认 `/tmp/test-certs` |
| `disconnect` | — | 断开当前连接 |
| `status` | — | 显示当前连接状态、证书路径 |
| `set` | `<key> <value>` | 设置配置参数（port、cert-dir、default-data） |

**示例**：

```
> connect 12345 --cert-dir /tmp/test-certs
Connected to vsock://1:12345 via TLS

> status
Connected: vsock://1:12345
TLS CA: /tmp/test-certs/tls/ca.crt
Client Cert: /tmp/test-certs/tls/client/client.crt
```

---

### 3.2 手工交互测试命令

| 命令 | 参数 | 接口类型 | 说明 |
|------|------|----------|------|
| `sign` | `<data>` | 0x10 | 调用签名接口 |
| `verify` | `<data> <signed_data> <id>` | 0x14 | 调用验签接口 |
| `verify-sign` | `<verify-json> <sign-json>` | 0x12 | 调用验签+签名接口，JSON格式输入 |
| `raw` | `<type> <json-body>` | — | 发送原始请求，手动指定type |

**示例**：

```
> sign "test message"
{"signed_data": "MIIM...", "id": "abc123...", "result": 0}

> verify "test message" "MIIM..." "abc123..."
{"result": 0}
```

---

### 3.3 性能测试命令

| 命令 | 参数 | 说明 |
|------|------|------|
| `perf sign` | `--count <n> [--data <text>] [--interval <ms>]` | 签名接口性能测试 |
| `perf verify` | `--count <n> --signed-data <b64> --id <b64> [--interval <ms>]` | 验签接口性能测试 |
| `perf report` | — | 显示最近性能测试统计 |

**输出指标**：

| 指标 | 说明 |
|------|------|
| Total | 请求总数 |
| Success | 成功数（result=0） |
| Failed | 失败数 |
| Avg Response Time | 平均响应时间（ms） |
| Min/Max Response Time | 最小/最大响应时间（ms） |
| Throughput (QPS) | 吞吐量（请求/秒） |
| Error Distribution | 错误码分布（result≠0的统计） |

**示例**：

```
> perf sign --count 100 --data "test"
Running 100 sign requests...
Progress: 100/100 [====================] 100%

Performance Report:
  Total: 100 requests
  Success: 100, Failed: 0
  Avg Response Time: 12.5ms (min: 8.0ms, max: 25.0ms)
  Throughput: 80.0 QPS
```

---

### 3.4 并发测试命令

| 命令 | 参数 | 说明 |
|------|------|------|
| `concurrent sign` | `--threads <n> --count <n> [--data <text>]` | 签名接口并发测试 |
| `concurrent verify` | `--threads <n> --count <n> --signed-data <b64> --id <b64>` | 验签接口并发测试 |
| `concurrent report` | — | 显示最近并发测试统计 |

**并发模型**：每个线程建立独立的 TLS over vsock 连接，主线程收集统计。

**测试范围建议**：

| 线程数 | 测试目的 |
|--------|----------|
| 1-8 | 基础并发测试 |
| 16 | 验证并发上限（服务端 Semaphore=16） |
| 17-20 | 验证超限排队行为 |

**示例**：

```
> concurrent sign --threads 16 --count 50 --data "test"
Running concurrent test with 16 threads, 50 requests each...

Concurrent Test Report:
  Threads: 16, Total Requests: 800
  Success: 800, Failed: 0
  Avg Response Time: 15.2ms
  Throughput: 52.6 QPS
```

---

### 3.5 安全测试命令

#### 3.5.1 协议层安全测试

| 命令 | 测试项 | 预期服务端行为 |
|------|--------|----------------|
| `security protocol version-mismatch` | 发送错误版本号（非0xFFFF0400） | 返回 type=0x01, len=0 |
| `security protocol oversized-message` | 发送超过10KB的消息 | 返回 type=0x02, len=0 |
| `security protocol unknown-type` | 发送未注册的type（如0xFF） | 返回 type=0x01, len=0 |
| `security protocol malformed-header` | 发送不完整header（<16字节） | 返回 type=0x01, len=0 |
| `security protocol` | 运行全部协议层测试 | 输出测试报告 |

#### 3.5.2 证书层安全测试

| 命令 | 测试项 | 预期服务端行为 |
|------|--------|----------------|
| `security cert expired-cert` | 使用过期证书签名 | 签名成功（result=0，仅日志warn） |
| `security cert revoked-cert` | 验签被吊销证书签名 | 验签失败（result=4） |
| `security cert self-signed` | 验签自签名证书签名 | 验签失败（result=3，证书链无效） |
| `security cert wrong-ca` | 验签错误CA签发证书签名 | 验签失败（result=3） |
| `security cert` | 运行全部证书层测试 | 输出测试报告 |

#### 3.5.3 TLS层安全测试

| 命令 | 测试项 | 预期服务端行为 |
|------|--------|----------------|
| `security tls no-client-cert` | 无客户端证书连接 | TLS握手失败 |
| `security tls wrong-ca-client` | 使用wrong-ca.crt连接 | TLS握手失败 |
| `security tls weak-algorithm` | 尝试弱算法套件 | TLS握手失败（服务端禁用弱算法） |
| `security tls` | 运行全部TLS层测试 | 输出测试报告 |

#### 3.5.4 综合命令

| 命令 | 说明 |
|------|------|
| `security all` | 运行全部安全测试（协议+证书+TLS） |
| `security report` | 显示最近安全测试报告 |

**示例输出**：

```
> security protocol
Testing protocol layer attacks...

[PASS] version-mismatch
  Expected: Server returns type=0x01, len=0
  Actual: type=0x01, len=0

[PASS] oversized-message
[PASS] unknown-type
[PASS] malformed-header

Protocol layer tests: 4/4 passed

> security all
Protocol layer: 4/4 passed
Certificate layer: 4/4 passed
TLS layer: 3/3 passed
Total: 11/11 tests passed
```

---

### 3.6 预置场景命令

| 命令 | 说明 |
|------|------|
| `scenario two-node` | 两节点签名验签链路测试（N01） |
| `scenario three-node` | 三节点签名验签链路测试（N02） |
| `scenario error-chain` | 错误场景全链路测试（E01-E06） |
| `scenario boundary` | 边界场景测试（B01-B05） |

**实现方式**：复用 `integration-tests` 的 `ProcessManager` 和测试用例逻辑。

---

### 3.7 辅助命令

| 命令 | 说明 |
|------|------|
| `help [command]` | 显示命令帮助 |
| `history` | 显示命令历史 |
| `clear` | 清屏 |
| `quit` | 退出工具 |

---

## 4. 功能模块详细设计

### 4.1 REPL 引擎 (`repl/`)

#### 4.1.1 命令解析器 (`parser.rs`)

**职责**：将用户输入字符串解析为 `Command` 枚举。

```rust
pub enum Command {
    // 连接管理
    Connect { port: u32, cert_dir: Option<PathBuf> },
    Disconnect,
    Status,
    Set { key: String, value: String },

    // 手工交互
    Sign { data: String },
    Verify { data: String, signed_data: String, id: String },
    VerifySign { verify_json: String, sign_json: String },
    Raw { msg_type: u32, body: String },

    // 性能测试
    PerfSign { count: u32, data: Option<String>, interval: Option<u32> },
    PerfVerify { count: u32, signed_data: String, id: String, interval: Option<u32> },
    PerfReport,

    // 并发测试
    ConcurrentSign { threads: u32, count: u32, data: Option<String> },
    ConcurrentVerify { threads: u32, count: u32, signed_data: String, id: String },
    ConcurrentReport,

    // 安全测试
    SecurityProtocol { test: Option<String> },
    SecurityCert { test: Option<String> },
    SecurityTls { test: Option<String> },
    SecurityAll,
    SecurityReport,

    // 预置场景
    Scenario { name: String },

    // 辅助
    Help { cmd: Option<String> },
    History,
    Clear,
    Quit,
}

pub fn parse(input: &str) -> Result<Command, ParseError>;
```

**解析规则**：
- 使用空格分隔参数
- 支持 `--key value` 格式的可选参数
- JSON参数支持单引号包裹（避免双引号转义）

#### 4.1.2 命令路由器 (`commands.rs`)

**职责**：接收解析后的 `Command`，调用对应测试器，返回执行结果。

```rust
pub struct CommandRouter {
    config: Arc<Mutex<Config>>,
    client: Option<Arc<Mutex<VsockClient>>>,
    perf_stats: Arc<Mutex<Option<PerfResult>>>,
    concurrent_stats: Arc<Mutex<Option<ConcurrentResult>>>,
    security_results: Arc<Mutex<Vec<SecurityTestResult>>>,
}

impl CommandRouter {
    pub fn new(config: Config) -> Self;
    pub fn execute(&self, cmd: Command) -> Result<ExecuteResult, CommandError>;
}

pub enum ExecuteResult {
    Continue,
    Quit,
    Output(String),
}

pub enum CommandError {
    NotConnected,
    InvalidPort,
    CertificateNotFound,
    VsockError(VsockError),
    TestError(TestError),
}
```

---

### 4.2 交互测试器 (`testers/interactive.rs`)

**职责**：封装手工交互测试逻辑，调用 `VsockClient` 接口。

```rust
pub struct InteractiveTester {
    client: Arc<Mutex<VsockClient>>,
}

impl InteractiveTester {
    pub fn new(client: Arc<Mutex<VsockClient>>) -> Self;
    pub fn sign(&self, data: &str) -> Result<SignResponse, TestError>;
    pub fn verify(&self, data: &str, signed_data: &str, id: &str) -> Result<VerifyResponse, TestError>;
    pub fn verify_and_sign(&self, req: VerifySignRequest) -> Result<VerifySignResponse, TestError>;
    pub fn raw_request(&self, msg_type: u32, body: String) -> Result<RawResponse, TestError>;
}
```

---

### 4.3 性能测试器 (`testers/performance.rs`)

**职责**：执行单接口性能测试，收集响应时间统计。

```rust
pub struct PerfConfig {
    pub count: u32,
    pub data: String,
    pub interval_ms: Option<u32>,
}

pub struct PerfResult {
    pub total: u32,
    pub success: u32,
    pub failed: u32,
    pub avg_latency_ms: f64,
    pub min_latency_ms: f64,
    pub max_latency_ms: f64,
    pub throughput_qps: f64,
    pub errors: HashMap<u32, u32>,
}

pub struct PerformanceTester {
    client: Arc<Mutex<VsockClient>>,
}

impl PerformanceTester {
    pub fn new(client: Arc<Mutex<VsockClient>>) -> Self;
    pub fn run_sign_test(&self, config: PerfConfig) -> PerfResult;
    pub fn run_verify_test(&self, config: PerfConfig, signed_data: &str, id: &str) -> PerfResult;
}
```

**实现要点**：
- 显示进度条（每10%更新一次）
- 计算平均/最小/最大响应时间
- 统计错误码分布

---

### 4.4 并发测试器 (`testers/concurrent.rs`)

**职责**：执行多线程并发测试，验证并发上限和吞吐量。

```rust
pub struct ConcurrentConfig {
    pub threads: u32,
    pub requests_per_thread: u32,
    pub data: String,
}

pub struct ConcurrentResult {
    pub threads: u32,
    pub total_requests: u32,
    pub success: u32,
    pub failed: u32,
    pub avg_latency_ms: f64,
    pub throughput_qps: f64,
}

pub struct ConcurrentTester {
    cert_dir: PathBuf,
    port: u32,
}

impl ConcurrentTester {
    pub fn new(cert_dir: PathBuf, port: u32) -> Self;
    pub async fn run_sign_test(&self, config: ConcurrentConfig) -> ConcurrentResult;
    pub async fn run_verify_test(&self, config: ConcurrentConfig, signed_data: &str, id: &str) -> ConcurrentResult;
}
```

**并发模型**：
- 每线程独立连接（避免单连接串行限制）
- 使用 `tokio::spawn` 创建异步任务
- 使用 `Arc<Mutex<StatsCollector>>` 安全收集统计

---

### 4.5 安全测试器 (`testers/security.rs`)

**职责**：执行协议层、证书层、TLS层三类安全攻击测试。

#### 4.5.1 测试类型定义

```rust
pub enum SecurityTestCategory {
    Protocol,
    Certificate,
    Tls,
}

pub enum SecurityTestType {
    // 协议层
    VersionMismatch,
    OversizedMessage,
    UnknownType,
    MalformedHeader,

    // 证书层
    ExpiredCert,
    RevokedCert,
    SelfSignedCert,
    WrongCaCert,

    // TLS层
    NoClientCert,
    WrongCaClient,
    WeakAlgorithm,
}

pub struct SecurityTestResult {
    pub category: SecurityTestCategory,
    pub test_type: SecurityTestType,
    pub passed: bool,
    pub expected_behavior: String,
    pub actual_behavior: String,
    pub details: String,
}
```

#### 4.5.2 协议层安全测试器

```rust
pub struct ProtocolSecurityTester {
    client: Arc<Mutex<VsockClient>>,
}

impl ProtocolSecurityTester {
    pub fn new(client: Arc<Mutex<VsockClient>>) -> Self;
    pub fn test_version_mismatch(&self) -> SecurityTestResult;
    pub fn test_oversized_message(&self) -> SecurityTestResult;
    pub fn test_unknown_type(&self) -> SecurityTestResult;
    pub fn test_malformed_header(&self) -> SecurityTestResult;
    pub fn run_all(&self) -> Vec<SecurityTestResult>;
}
```

**测试用例**：见第 3.5.1 节表格。

#### 4.5.3 证书层安全测试器

```rust
pub struct CertSecurityTester {
    cert_dir: PathBuf,
    binary_path: PathBuf,
}

impl CertSecurityTester {
    pub fn new(cert_dir: PathBuf, binary_path: PathBuf) -> Self;
    pub fn test_expired_cert(&self, port: u32) -> SecurityTestResult;
    pub fn test_revoked_cert(&self, port: u32) -> SecurityTestResult;
    pub fn test_self_signed_cert(&self, port: u32) -> SecurityTestResult;
    pub fn test_wrong_ca_cert(&self, port: u32) -> SecurityTestResult;
    pub fn run_all(&self, port: u32) -> Vec<SecurityTestResult>;
}
```

**测试用例**：见第 3.5.2 节表格。

**实现要点**：
- 复用 `integration-tests::test_utils` 的证书生成函数
- 复用 `integration-tests::proc_manager` 启动临时节点

#### 4.5.4 TLS层安全测试器

```rust
pub struct TlsSecurityTester {
    cert_dir: PathBuf,
    port: u32,
}

impl TlsSecurityTester {
    pub fn new(cert_dir: PathBuf, port: u32) -> Self;
    pub fn test_no_client_cert(&self) -> SecurityTestResult;
    pub fn test_wrong_ca_client(&self) -> SecurityTestResult;
    pub fn test_weak_algorithm(&self) -> SecurityTestResult;
    pub fn run_all(&self) -> Vec<SecurityTestResult>;
}
```

**测试用例**：见第 3.5.3 节表格。

---

### 4.6 统计模块 (`stats/`)

#### 4.6.1 统计收集器 (`mod.rs`)

```rust
pub struct StatsCollector {
    latencies: Vec<f64>,
    successes: u32,
    failures: u32,
    error_codes: HashMap<u32, u32>,
    start_time: Instant,
}

impl StatsCollector {
    pub fn new() -> Self;
    pub fn record_success(&mut self, latency_ms: f64, result_code: u32);
    pub fn record_failure(&mut self, latency_ms: f64);
    pub fn finalize(&self) -> PerfResult;
}
```

#### 4.6.2 报告格式化 (`reporter.rs`)

```rust
pub struct Reporter;

impl Reporter {
    pub fn format_perf_report(result: &PerfResult) -> String;
    pub fn format_concurrent_report(result: &ConcurrentResult) -> String;
    pub fn format_security_report(results: &[SecurityTestResult]) -> String;
    pub fn format_response<T: serde::Serialize>(resp: &T) -> String;
}
```

---

### 4.7 配置管理 (`config.rs`)

```rust
pub struct Config {
    pub default_port: u32,
    pub default_cert_dir: PathBuf,
    pub default_data: String,
    pub binary_path: PathBuf,
    pub history: Vec<String>,
}

impl Config {
    pub fn default() -> Self;
    pub fn from_env() -> Self;
    pub fn set(&mut self, key: &str, value: &str) -> Result<(), ConfigError>;
}
```

**环境变量**：
- `CMS_TEST_PORT`：默认端口
- `CMS_TEST_CERT_DIR`：默认证书目录

---

### 4.8 预置场景执行器 (`testers/scenarios.rs`)

```rust
pub struct ScenarioRunner {
    cert_dir: PathBuf,
    binary_path: PathBuf,
}

impl ScenarioRunner {
    pub fn new(cert_dir: PathBuf, binary_path: PathBuf) -> Self;
    pub fn run_two_node(&self) -> Result<String, ScenarioError>;
    pub fn run_three_node(&self) -> Result<String, ScenarioError>;
    pub fn run_error_chain(&self) -> Result<String, ScenarioError>;
    pub fn run_boundary(&self) -> Result<String, ScenarioError>;
}
```

**实现方式**：复用 `integration-tests` 的 `ProcessManager` 和测试用例逻辑，输出详细执行过程。

---

## 5. 依赖关系

### 5.1 Cargo.toml

```toml
[package]
name = "cms-test-cli"
version.workspace = true
edition.workspace = true

[dependencies]
integration-tests = { path = "../integration-tests" }
openssl.workspace = true
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true
anyhow.workspace = true
thiserror.workspace = true
base64.workspace = true
clap.workspace = true
```

### 5.2 复用策略

| 模块 | 复用来源 | 复用内容 |
|------|----------|----------|
| `VsockClient` | `integration-tests::vsock_client` | TLS over vsock 连接、请求发送、响应解析 |
| `ProcessManager` | `integration-tests::proc_manager` | 进程启动/停止、配置管理 |
| `test_utils` | `integration-tests::test_utils` | 证书生成辅助函数 |
| `SignResponse` | `integration-tests::vsock_client` | 签名响应结构 |
| `VerifyResponse` | `integration-tests::vsock_client` | 验签响应结构 |
| `VerifySignRequest` | `integration-tests::vsock_client` | 验签+签名请求结构 |

### 5.3 新增扩展

| 扩展位置 | 扩展内容 |
|----------|----------|
| `VsockClient` | 新增 `send_raw_request()` 方法支持安全测试 |
| `StatsCollector` | 新建统计收集模块 |
| `Reporter` | 新建报告格式化模块 |
| `CommandRouter` | 新建 REPL 命令路由模块 |

---

## 6. 执行环境

### 6.1 环境要求

| 项目 | 要求 |
|------|------|
| 执行环境 | WSL（Windows Subsystem for Linux）或 Linux |
| vsock模块 | `vmw_vsock` 或 `vsock_loopback` 内核模块已加载 |
| Rust工具链 | 1.70+（通过rustup安装） |
| OpenSSL | 3.0+（TLS握手、证书生成） |
| 证书 | `cert-gen` 工具预生成测试证书 |

### 6.2 执行方式

**方式一：WSL执行**

```bash
wsl bash -c "source ~/.cargo/env && cd <PROJECT_ROOT>/rust && cargo run -p cms-test-cli"
```

**方式二：Linux执行**

```bash
cd <PROJECT_ROOT>/rust
cargo run -p cms-test-cli
```

### 6.3 证书准备

测试前需生成测试证书：

```bash
wsl bash -c "source ~/.cargo/env && cd <PROJECT_ROOT>/rust && cargo run -p cert-gen -- --output-dir /tmp/test-certs --force"
```

---

## 7. 使用示例

### 7.1 连接与手工测试

```
cms-test-cli v0.1.0
Type 'help' for available commands.

> connect 12345 --cert-dir /tmp/test-certs
Connected to vsock://1:12345 via TLS

> sign "hello world"
{"signed_data": "MIIM...", "id": "abc123...", "result": 0}

> verify "hello world" "MIIM..." "abc123..."
{"result": 0}
```

### 7.2 性能测试

```
> perf sign --count 100 --data "test"
Running 100 sign requests...
Progress: 100/100 [====================] 100%

Performance Report:
  Total: 100 requests
  Success: 100, Failed: 0
  Avg Response Time: 12.5ms (min: 8.0ms, max: 25.0ms)
  Throughput: 80.0 QPS
```

### 7.3 并发测试

```
> concurrent sign --threads 16 --count 50
Running concurrent test with 16 threads, 50 requests each...

Concurrent Test Report:
  Threads: 16, Total Requests: 800
  Success: 800, Failed: 0
  Avg Response Time: 15.2ms
  Throughput: 52.6 QPS
```

### 7.4 安全测试

```
> security all
Running all security tests...

Protocol layer: 4/4 passed
Certificate layer: 4/4 passed
TLS layer: 3/3 passed

Total: 11/11 tests passed
```

---

## 8. 文件清单

| 文件 | 行数估算 | 说明 |
|------|----------|------|
| `main.rs` | ~50 | 入口 + REPL循环调用 |
| `repl/mod.rs` | ~30 | 模块导出 + REPL函数 |
| `repl/parser.rs` | ~80 | 命令解析器 |
| `repl/commands.rs` | ~100 | 命令路由器 |
| `testers/mod.rs` | ~20 | 测试器模块导出 |
| `testers/interactive.rs` | ~50 | 交互测试器 |
| `testers/performance.rs` | ~100 | 性能测试器 |
| `testers/concurrent.rs` | ~150 | 并发测试器 |
| `testers/security.rs` | ~250 | 安全测试器（协议+证书+TLS） |
| `testers/scenarios.rs` | ~100 | 预置场景执行器 |
| `stats/mod.rs` | ~80 | 统计收集器 |
| `stats/reporter.rs` | ~100 | 报告格式化 |
| `config.rs` | ~50 | 配置管理 |
| `Cargo.toml` | ~20 | 依赖声明 |
| `README.md` | ~100 | 使用说明 |

**总代码量估算**：~1100行

---

## 修订历史

| 版本 | 日期 | 修订内容 |
|------|------|----------|
| V1.0 | 2026-06-27 | 初始版本：定义工具定位、目录结构、REPL命令设计、功能模块详细设计、依赖关系、执行环境、使用示例 |