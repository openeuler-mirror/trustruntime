# CMS签名验签服务 手工测试工具设计文档

| 文档版本 | V1.1 |
| 编写日期 | 2026-06-27 |
| 更新日期 | 2026-07-15 |

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

- **复用优先**：复用 `integration-tests` 的 `VsockClient`、`test_cert_gen`、`test_helpers`、`ProcessManager`
- **交互式优先**：主界面为 REPL 模式，支持单次 CLI 执行作为补充
- **基础指标优先**：性能测试输出总数、成功数、平均响应时间、吞吐量(QPS)
- **安全测试全覆盖**：覆盖协议层、证书层、TLS层三类安全攻击场景

---

## 2. 目录结构

```
rust/tools/cms-test-cli/
├── Cargo.toml
├── README.md
├── config.example.toml         # 示例配置文件
└── src/
    ├── main.rs                 # 入口 + REPL循环
    ├── config.rs               # 配置管理（TOML加载）
    ├── repl/                   # REPL交互模块
    ├── testers/                # 测试执行器
    └── stats/                  # 统计收集与报告
```

### 2.2 模块组成

| 模块 | 文件 | 职责 |
|------|------|------|
| REPL引擎 | `repl/mod.rs` | 交互循环、命令分发 |
| 命令解析器 | `repl/parser.rs` | 输入解析、参数提取 |
| 命令路由器 | `repl/commands.rs` | 命令执行、状态管理 |
| 配置管理 | `config.rs` | TOML加载、配置验证 |
| 交互测试器 | `testers/interactive.rs` | 手工签名验签测试 |
| 性能测试器 | `testers/performance.rs` | 单接口性能测试 |
| 并发测试器 | `testers/concurrent.rs` | 多线程并发测试 |
| 安全测试器 | `testers/security.rs` | 协议/证书/TLS安全测试 |
| 场景执行器 | `testers/scenarios.rs` | 预置场景运行 |
| 统计收集器 | `stats/mod.rs` | 响应时间、吞吐量统计 |
| 报告格式化 | `stats/reporter.rs` | 测试报告输出 |

---

## 3. REPL 命令设计

### 3.1 连接管理命令

| 命令 | 参数 | 说明 |
|------|------|------|
| `connect` | `[port]` | 连接服务，端口可选，默认使用配置文件中的端口 |
| `disconnect` | — | 断开当前连接 |
| `status` | — | 显示当前连接状态、证书路径 |

```
> connect
Connected to vsock://1:12345

> connect 12346
Connected to vsock://1:12346
```

### 3.2 手工交互测试命令

| 命令 | 参数 | 接口类型 | 说明 |
|------|------|----------|------|
| `sign` | `<data>` | 0x10 | 调用签名接口 |
| `verify` | `<data> <signed_data> <id>` | 0x14 | 调用验签接口 |
| `verify-sign` | `<verify-json> <sign-json>` | 0x12 | 调用验签+签名接口 |
| `raw` | `<type> <json-body>` | — | 发送原始请求 |

### 3.3 性能测试命令

| 命令 | 参数 | 说明 |
|------|------|------|
| `perf sign` | `--count <n> [--data <text>] [--interval <ms>]` | 签名接口性能测试 |
| `perf verify` | `--count <n> --signed-data <b64> --id <b64>` | 验签接口性能测试 |
| `perf report` | — | 显示最近性能测试统计 |

**输出指标**：Total、Success、Failed、Avg/Min/Max Response Time、Throughput (QPS)、Error Distribution

### 3.4 并发测试命令

| 命令 | 参数 | 说明 |
|------|------|------|
| `concurrent sign` | `--threads <n> --count <n> [--data <text>]` | 签名接口并发测试 |
| `concurrent verify` | `--threads <n> --count <n> --signed-data <b64> --id <b64>` | 验签接口并发测试 |
| `concurrent report` | — | 显示最近并发测试统计 |

**并发模型**：每个线程建立独立的 TLS over vsock 连接，主线程收集统计。

**测试范围建议**：
- 1-8 线程：基础并发测试
- 16 线程：验证并发上限（服务端 Semaphore=16）
- 17-20 线程：验证超限排队行为

### 3.5 安全测试命令

#### 协议层测试

| 测试项 | 说明 | 预期行为 |
|--------|------|----------|
| `version-mismatch` | 发送错误版本号 | 返回 type=0x01, len=0 |
| `oversized-message` | 发送超过10KB的消息 | 返回 type=0x02, len=0 |
| `unknown-type` | 发送未注册的type | 返回 type=0x01, len=0 |
| `malformed-header` | 发送不完整header | 返回 type=0x01, len=0 |

#### 证书层测试

| 测试项 | 说明 | 预期行为 |
|--------|------|----------|
| `expired-cert` | 使用过期证书签名 | 签名成功（仅日志warn） |
| `revoked-cert` | 验签被吊销证书签名 | 验签失败（result=4） |
| `self-signed` | 验签自签名证书签名 | 验签失败（result=3） |
| `wrong-ca` | 验签错误CA签发证书签名 | 验签失败（result=3） |

#### TLS层测试

| 测试项 | 说明 | 预期行为 |
|--------|------|----------|
| `no-client-cert` | 无客户端证书连接 | TLS握手失败 |
| `wrong-ca-client` | 使用wrong-ca.crt连接 | TLS握手失败 |
| `weak-algorithm` | 尝试弱算法套件 | TLS握手失败 |

#### 综合命令

| 命令 | 说明 |
|------|------|
| `security protocol` | 运行全部协议层测试 |
| `security cert` | 运行全部证书层测试 |
| `security tls` | 运行全部TLS层测试 |
| `security all` | 运行全部安全测试 |
| `security report` | 显示最近安全测试报告 |

### 3.6 预置场景命令

| 命令 | 说明 |
|------|------|
| `scenario two-node` | 两节点签名验签链路测试（N01） |
| `scenario three-node` | 三节点签名验签链路测试（N02） |
| `scenario error-chain` | 错误场景全链路测试（E01-E06） |
| `scenario boundary` | 边界场景测试（B01-B05） |

### 3.7 辅助命令

| 命令 | 说明 |
|------|------|
| `help [command]` | 显示命令帮助 |
| `history` | 显示命令历史 |
| `clear` | 清屏 |
| `quit` | 退出工具 |

---

## 4. 功能模块详细设计

### 4.1 REPL 引擎

#### 命令解析器 (`repl/parser.rs`)

```rust
pub enum Command {
    // 连接管理
    Connect { port: Option<u32> },
    Disconnect,
    Status,

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
```

#### 命令路由器 (`repl/commands.rs`)

```rust
pub struct CommandRouter {
    pub config: Arc<Mutex<CmsTestConfig>>,
    client: Option<Arc<Mutex<VsockClient>>>,
    perf_stats: Arc<Mutex<Option<PerfResult>>>,
    concurrent_stats: Arc<Mutex<Option<ConcurrentResult>>>,
    security_results: Arc<Mutex<Vec<SecurityTestResult>>>,
}

pub enum ExecuteResult {
    Continue,
    Quit,
    Output(String),
}
```

### 4.2 配置管理 (`config.rs`)

```rust
pub struct CmsTestConfig {
    pub connection: ConnectionConfig,
    pub tls_client: TlsClientConfig,
    pub cms_certs: CmsCertsConfig,
    pub server: ServerConfig,
    pub history: Vec<String>,
}

pub struct ConnectionConfig {
    pub port: u32,
}

pub struct TlsClientConfig {
    pub ca_cert: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
    pub client_key_pwd: Option<PathBuf>,
}

pub struct CmsCertsConfig {
    pub ca_cert: PathBuf,
    pub signer_cert: PathBuf,
    pub signer_key: PathBuf,
    pub expired_cert: Option<PathBuf>,
    pub expired_key: Option<PathBuf>,
    pub revoked_cert: Option<PathBuf>,
    pub revoked_key: Option<PathBuf>,
}

pub struct ServerConfig {
    pub binary_path: PathBuf,
}

impl CmsTestConfig {
    pub fn from_file(path: &str) -> Result<Self, ConfigError>;
    pub fn validate(&self) -> Result<(), ConfigError>;
}
```

### 4.3 测试器

#### 并发测试器 (`testers/concurrent.rs`)

```rust
pub struct ConcurrentTester {
    tls_config: TlsClientConfig,
    port: u32,
}

pub struct ConcurrentResult {
    pub threads: u32,
    pub total_requests: u32,
    pub success: u32,
    pub failed: u32,
    pub avg_latency_ms: f64,
    pub throughput_qps: f64,
}
```

#### 性能测试器 (`testers/performance.rs`)

```rust
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
```

#### 场景执行器 (`testers/scenarios.rs`)

```rust
pub struct ScenarioRunner {
    tls_config: TlsClientConfig,
    cms_certs: CmsCertsConfig,
    binary_path: PathBuf,
}
```

### 4.4 统计模块 (`stats/`)

```rust
pub struct StatsCollector {
    latencies: Vec<f64>,
    successes: u32,
    failures: u32,
    error_codes: HashMap<u32, u32>,
}

impl StatsCollector {
    pub fn new() -> Self;
    pub fn record_success(&mut self, latency_ms: f64, result_code: u32);
    pub fn record_failure(&mut self, latency_ms: f64);
    pub fn finalize(&self) -> PerfResult;
}

pub struct Reporter;

impl Reporter {
    pub fn format_perf_report(result: &PerfResult) -> String;
    pub fn format_concurrent_report(result: &ConcurrentResult) -> String;
    pub fn format_security_report(results: &[SecurityTestResult]) -> String;
    pub fn format_response<T: serde::Serialize>(resp: &T) -> String;
}
```

---

## 5. 配置文件格式

### 4.1 配置文件结构

```toml
[connection]
port = 12345

[tls_client]
ca_cert = "/tmp/test-certs/tls/ca.crt"
client_cert = "/tmp/test-certs/tls/client/client.crt"
client_key = "/tmp/test-certs/tls/client/client.key"
client_key_pwd = "/tmp/test-certs/tls/key_pwd.txt"  # 可选

[cms_certs]
ca_cert = "/tmp/test-certs/cms/ca.crt"
signer_cert = "/tmp/test-certs/cms/node-a/signer.crt"
signer_key = "/tmp/test-certs/cms/node-a/signer.key"
expired_cert = "/tmp/test-certs/cms/expired/signer.crt"  # 可选
expired_key = "/tmp/test-certs/cms/expired/signer.key"   # 可选
revoked_cert = "/tmp/test-certs/cms/revoked/signer.crt"  # 可选
revoked_key = "/tmp/test-certs/cms/revoked/signer.key"   # 可选

[server]
binary_path = "trustruntime"
```

### 4.2 配置验证规则

| 字段 | 验证规则 |
|------|----------|
| `connection.port` | 必填，范围 1-65535 |
| `tls_client.ca_cert` | 必填，文件必须存在 |
| `tls_client.client_cert` | 必填，文件必须存在 |
| `tls_client.client_key` | 必填，文件必须存在 |
| `tls_client.client_key_pwd` | 可选，如配置则文件必须存在 |
| `cms_certs.*` | 必填字段必须存在，可选字段如配置则文件必须存在 |

---

## 6. 依赖关系

### 5.1 Cargo.toml

```toml
[dependencies]
integration-tests = { path = "../integration-tests" }
openssl.workspace = true
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
clap = { workspace = true, features = ["derive"] }
toml.workspace = true
```

### 5.2 复用策略

| 模块 | 复用来源 | 复用内容 |
|------|----------|----------|
| `VsockClient` | `integration-tests::vsock_client` | TLS over vsock 连接、请求发送、响应解析 |
| `ProcessManager` | `integration-tests::proc_manager` | 进程启动/停止、配置管理 |
| `test_cert_gen` | `integration-tests::test_cert_gen` | 测试证书生成（CA、签名者、过期、吊销） |
| `test_helpers` | `integration-tests::test_helpers` | 测试辅助工具（路径管理、断言辅助） |

---

## 7. 执行环境

### 6.1 环境要求

| 项目 | 要求 |
|------|------|
| 执行环境 | WSL 或 Linux |
| vsock模块 | `vmw_vsock` 或 `vsock_loopback` 已加载 |
| Rust工具链 | 1.70+ |
| OpenSSL | 3.0+ |

### 6.2 执行方式

```bash
# 准备配置文件
cp rust/tools/cms-test-cli/config.example.toml my-config.toml
# 编辑配置文件，设置证书路径

# WSL执行
wsl bash -c "source ~/.cargo/env && cd rust && cargo run -p cms-test-cli -- --config /path/to/config.toml"

# Linux执行
cargo run -p cms-test-cli -- --config /path/to/config.toml
```

---

## 8. 使用示例

```
cms-test-cli v0.1.0
Type 'help' for available commands.

> connect
Connected to vsock://1:12345

> sign "hello world"
{"signed_data": "MIIM...", "id": "abc123...", "result": 0}

> perf sign --count 100
Running 100 sign requests...
Total: 100, Success: 100, Avg: 12.5ms, QPS: 80.0

> concurrent sign --threads 16 --count 50
Threads: 16, Total: 800, Success: 800, QPS: 52.6

> security all
Protocol layer: 4/4 passed
Certificate layer: 4/4 passed
TLS layer: 3/3 passed
Total: 11/11 tests passed
```

---

## 修订历史

| 版本 | 日期 | 修订内容 |
|------|------|----------|
| V1.0 | 2026-06-27 | 初始版本 |
| V1.1 | 2026-07-15 | 配置管理重构：采用TOML配置文件，解耦cert-gen目录结构依赖 |