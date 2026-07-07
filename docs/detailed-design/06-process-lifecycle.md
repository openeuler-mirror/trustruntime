# 进程生命周期 详细设计

## 1. 职责与边界

### 负责

- **core::daemon**: 进程状态机管理、systemd sd_notify 通知（READY/STOPPING）
- **core::signal**: SIGTERM/SIGINT 信号捕获、优雅退出触发
- **core::cert_checker**: 证书过期定时巡检（每 24h，仅 warn 日志）
- **main.rs**: 启动编排（配置→日志→证书→vsock→插件→巡检→READY）、关闭编排（信号→停连接→关插件→STOPPING→退出）

### 不负责

- vsock 通信细节（由通信层负责）
- 业务逻辑（由插件负责）
- 证书加载（由证书管理层负责）
- 日志写入（由日志层负责，本层只初始化）

---

## 2. 公开 API

### core::daemon

```rust
pub enum DaemonState {
    Initializing,
    Ready,
    Stopping,
    Stopped,
}

pub struct Daemon {
    state: DaemonState,
}

impl Daemon {
    pub fn new() -> Self;  // 初始状态: Initializing

    /// 通知 systemd 服务就绪
    /// 状态: Initializing → Ready
    /// 若 NOTIFY_SOCKET 环境变量不存在，跳过 sd_notify（非 systemd 环境）
    pub fn notify_ready(&mut self) -> Result<(), String>;

    /// 通知 systemd 服务正在停止
    /// 状态: Ready → Stopping → Stopped
    pub fn notify_stopping(&mut self);

    /// 通知 systemd 自定义状态信息
    /// 显示在 systemctl status 输出中，用于运维可观测性
    /// 例: daemon.notify_status("通信证书已过期")
    pub fn notify_status(&mut self, status: &str);

    pub fn state(&self) -> &DaemonState;
}
```

### core::signal

```rust
pub struct SignalHandler {
    shutdown_requested: Arc<AtomicBool>,
}

impl SignalHandler {
    pub fn new() -> Self;

    /// 异步等待 SIGTERM 或 SIGINT
    /// 返回后设置 shutdown flag 为 true
    pub async fn wait_for_shutdown_signal(&self);

    /// 查询是否已收到退出信号
    pub fn is_shutdown_requested(&self) -> bool;
}
```

### core::cert_checker

```rust
pub struct CertificateChecker {
    cert_paths: Vec<String>,
}

impl CertificateChecker {
    pub fn new(cert_paths: Vec<String>) -> Self;

    /// 检查所有证书有效期，返回状态列表
    pub fn check_all(&self) -> Vec<CertificateStatus>;

    /// 启动定时巡检（tokio::spawn），每 24h 执行 check_all()
    /// 过期时 warn 日志，不做其他动作
    pub fn start_periodic_check(self) -> JoinHandle<()>;
}
```

### main.rs 启动编排

```rust
#[tokio::main(worker_threads = 4)]
async fn main() {
    // 1. 加载配置
    // 2. 初始化日志
    // 3. 检查所有证书有效期（启动时检查）
    //    - 通信证书过期 → error 日志，跳过步骤 4-10
    //    - CMS 证书过期 → warn 日志，继续
    // 4. 创建 VsockTransport（TLS 配置）
    //    - TLS 配置失败 → error 日志，跳过步骤 5-10
    // 5. 加载 CMS 证书，构建 Signer + Verifier
    // 6. 创建 TrustringHandler，注册到 PluginManager
    // 7. 创建 PluginContext{config, transport}
    // 8. pm.init_all(ctx) — 插件在 init 中向 transport 注册 handler
    // 9. 启动证书过期巡检后台 task
    // 10. transport.start() — 启动 vsock listener
    // 11. daemon.notify_ready()
    // 12. signal_handler.wait_for_shutdown_signal()
    // 13. 关闭编排（见下方）
}
```

---

## 3. 内部状态

| 结构体 | 状态 | 生命周期 |
|--------|------|---------|
| Daemon | state（状态机） | 进程级 |
| SignalHandler | shutdown_requested: Arc<AtomicBool> | 进程级，信号 task 和主 task 共享 |
| CertificateChecker | cert_paths | 进程级，后台 task 持有 |

---

## 4. 关键场景

### 正常启动流程

```
main.rs
  |
  |-- [1] config::from_file("/etc/trustruntime/agent.toml")
  |   ↓ 失败 → 打印 stderr，进程退出(1)
  |
  |-- [2] logger::init_logger(&config.log)
  |   ↓ 失败 → 打印 stderr，进程退出(1)
  |
  |-- [3] cert_checker::check_all()（启动时一次性检查）
  |   |-- 通信证书过期 → log::error!("通信证书已过期: {path}")
  |   |   → 跳过步骤 4-10，直接到步骤 11
  |   |-- CMS 证书过期 → log::warn!("CMS证书已过期: {path}")
  |   |   → 继续（不影响启动）
  |
  |-- [4] VsockTransport::new(tls_config, port)
  |   ↓ TLS 配置失败 → log::error!("vsock启动失败")
  |       → 跳过步骤 5-10，直接到步骤 11
  |
  |-- [5] 加载 CMS 证书：
  |   |-- CmsCertificate::load(signer_cert, signer_key)
  |   |-- CaCertificate::load(ca_root_cert)
  |   |-- CertificateRevocationList::load(cms_crl)（可选）
  |   |-- 构造 Signer + Verifier
  |   ↓ 失败 → log::error!，进程退出(1)
  |
  |-- [6] 创建 TrustringHandler(signer, verifier)
  |   |-- PluginManager::new()
  |   |-- add_plugin(handler)
  |
  |-- [7] ctx = PluginContext::new(config, transport)
  |
  |-- [8] pm.init_all(ctx)
  |   → 插件在 init 中调用 ctx.transport.register_handler()
  |   ↓ 失败 → log::error!，进程退出(1)
  |
  |-- [9] transport.start()（tokio::spawn）
  |   → 开始接受连接和消息
  |
  |-- [10] cert_checker.start_periodic_check()（tokio::spawn）
  |
  |-- [11] daemon.notify_ready()
  |   → systemd 收到 READY=1
  |
  |-- [12] signal_handler.wait_for_shutdown_signal()
  |   → 阻塞等待 SIGTERM/SIGINT
```

### 通信证书过期时的启动行为

```
通信证书过期 → error 日志 → daemon.notify_status("通信证书已过期") → 跳过 vsock/插件/巡检 → daemon.notify_ready() → 等待信号

结果：
- systemd 认为服务启动成功（收到 READY=1）
- systemctl status 显示 "Status: 通信证书已过期"
- 进程保持运行，但不提供业务服务（无 vsock listener）
- 等待运维人员更新证书后手动 systemctl restart
- systemd 不会无限重启（因为进程没有退出）
```

### 优雅关闭流程

```
signal_handler.wait_for_shutdown_signal() 返回
  |
  |-- [1] 信号接收（SIGTERM 或 SIGINT）
  |-- [2] transport.stop()              // 停止接受新连接
  |-- [3] 等待当前连接处理完成（5s 超时）
  |       tokio::select! {
  |           _ = 等待所有 handle_connection task 完成 => {},
  |           _ = tokio::time::sleep(5s) => { warn("关闭超时，强制退出") },
  |       }
  |-- [4] plugin_manager.shutdown_all()  // 逆序调用插件 shutdown()
  |-- [5] daemon.notify_stopping()       // systemd STOPPING=1
  |-- [6] 进程退出(0)
  |
  |-- [systemd] 5s 后自动重启（Restart=always, RestartSec=5）
```

### 异常场景

| 场景 | 处理方式 |
|------|---------|
| 配置文件不存在 | stderr 输出错误，进程退出(1) |
| 日志目录不可写 | stderr 输出错误，进程退出(1) |
| CMS 证书加载失败 | error 日志，进程退出(1) |
| vsock 端口被占用 | error 日志，进程不退出（等待手动处理） |
| 插件 init 失败 | error 日志，进程退出(1) |
| 关闭超时（5s） | warn 日志，强制退出 |

---

## 5. 依赖关系

### 上游依赖

| 依赖 | 用途 |
|------|------|
| `config::AppConfig` | 启动时加载配置 |
| `logger::init_logger` | 启动时初始化日志（log4rs） |
| `cert_loader` | 加载 CMS 证书构建 Signer/Verifier |
| `plugin_manager::PluginManager` | 管理插件生命周期 |
| `plugin_manager::PluginContext` | 传递 config 和 transport 给插件 |
| `transport::TransportLayer` | 通信层抽象接口 |
| `communication::VsockTransport` | 实现 TransportLayer，启动 vsock listener |
| `cert_checker::CertificateChecker` | 启动定时巡检 |
| `sd_notify` crate | systemd 通知 |
| `nix` crate | 信号处理 |
| `tokio` | 异步运行时 |

### 下游消费者

| 消费者 | 使用方式 |
|--------|---------|
| systemd | 通过 sd_notify 协议交互（READY/STOPPING） |

---

## 6. 测试策略

### daemon 必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| 初始状态 | DaemonState::Initializing |
| notify_ready() | 状态转为 Ready |
| notify_stopping() | 状态转为 Stopped |
| notify_status() | sd_notify 收到 STATUS 消息 |
| 非 systemd 环境 | NOTIFY_SOCKET 不存在时跳过 sd_notify，不报错 |
| 状态转换非法 | 如 Stopped → Ready 应拒绝（或忽略） |

### signal 必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| SIGTERM | wait_for_shutdown_signal() 返回，is_shutdown() == true |
| SIGINT | wait_for_shutdown_signal() 返回，is_shutdown() == true |

### 启动编排必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| 正常启动全流程 | 所有步骤成功，READY 通知发送 |
| 通信证书过期启动 | 跳过 vsock/插件，READY 仍发送，进程存活 |
| 配置文件缺失 | 进程退出(1) |
| CMS 证书加载失败 | 进程退出(1) |

### 关闭编排必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| 正常关闭 | vsock 停止 → 插件关闭 → STOPPING → 退出 |
| 关闭超时 | 5s 后强制退出，warn 日志 |

### mock 策略

- daemon: 抽象 `trait DaemonService { fn notify(&self, msg: &str); }`，测试用 mock 验证调用
- signal: 测试中通过 `nix::sys::signal::raise(SIGTERM)` 触发
- 启动/关闭编排: 抽象各模块为 trait，测试用 mock 验证调用顺序和错误处理
