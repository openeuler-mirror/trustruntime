# CMS 签名验签服务 功能设计文档

## 文档信息

| 项目名称 | CMS 签名验签服务（trustring） |
|---------|-------------------------------|
| 文档版本 | V2.0 |
| 编写日期 | 2026-06-29 |

---

## 1. 目录规划与模块职责

### 1.1 三层 crate 结构概述

系统采用 Rust Cargo workspace 组织，分为三个 crate：

| Crate | 类型 | 核心职责 |
|-------|------|---------|
| framework | library | 通用进程框架：进程管理、配置解析、日志、插件管理、vsock通信、报文处理 |
| trustring | library | 签名验签业务插件：CMS签名/验签、证书加载、handler回调、错误码映射 |
| trustruntime | binary | 二进制入口：组装启动 framework + trustring |

框架与插件通过 Plugin trait 解耦，插件在 init 中注册 DataHandler 回调处理业务消息。

### 1.2 framework crate 目录结构

```
rust/framework/
├── Cargo.toml
├── src/
│   ├── lib.rs                    # 模块导出汇总
│   ├── core/                     # 进程管理、信号处理、daemon化、证书过期巡检
│   │   ├── mod.rs
│   │   ├── daemon.rs             # daemon初始化、systemd notify
│   │   ├── signal.rs             # SIGTERM/SIGINT处理、优雅退出
│   │   ├── cert_checker.rs       # 证书过期定时巡检（每24h）
│   ├── cert/                     # PEM/DER证书格式识别与加载
│   │   ├── mod.rs
│   ├── config/                   # TOML配置解析与分发
│   │   ├── mod.rs
│   ├── logger/                   # 日志初始化
│   │   ├── mod.rs                # log + log4rs，按大小滚动，gzip 归档
│   ├── message/                  # 报文解析/构造
│   │   ├── mod.rs                # VsockHeader、VsockMessage结构定义
│   ├── plugin_manager/           # 插件生命周期管理
│   │   ├── mod.rs
│   │   ├── plugin_trait.rs       # Plugin trait、PluginError
│   │   ├── context.rs            # PluginContext定义
│   ├── transport/                # TransportLayer trait、DataHandler trait
│   │   ├── mod.rs
│   ├── communication/            # 通信层
│   │   ├── mod.rs
│   │   ├── vsock_server/         # vsock listener + TLS封装（实现 TransportLayer）
│   │   │   ├── mod.rs
│   │   │   ├── tls.rs            # TLS配置（OpenSSL SslAcceptor）、双向认证、CRL校验
│   │   │   ├── listener.rs       # vsock listener、并发管理（Semaphore=16）
├── tests/                        # 独立集成测试
│   ├── fixtures/                 # 测试配置/证书
```

**framework 模块职责边界**：

| 模块 | 职责 | 不负责 | 边界说明 |
|------|------|--------|----------|
| core::daemon | 进程 daemon 化、systemd notify、启动编排顺序 | 信号捕获、证书巡检 | 仅编排启动流程，不处理具体信号 |
| core::signal | SIGTERM/SIGINT 捕获、触发优雅退出 | 实际关闭逻辑、资源释放 | 仅触发退出事件，关闭由 daemon 协调 |
| core::cert_checker | 定时巡检所有证书有效期、输出 warn 日志 | 证书加载解析、业务决策 | 仅检查有效期并日志，不阻止业务 |
| cert | PEM/DER 格式识别、证书解析 | 证书有效期判断、CRL 校验 | 仅格式转换和解析，有效期由 cert_checker 判断 |
| config | TOML 解析、结构体映射 | 配置文件存在性校验、热更新 | 解析成功即返回结构体，文件问题由调用方处理 |
| message | 报文序列化/反序列化（结构体↔字节流） | 协议版本校验、长度校验、业务解析 | 纯数据转换，校验归属 vsock_server |
| logger | 初始化日志系统、配置回滚策略 | 各模块日志内容 | 仅初始化，日志内容由调用方决定 |
| plugin_manager | Plugin trait 定义、生命周期管理 | 业务 handler 实现 | 仅管理生命周期，业务由 trustring 实现 |
| transport | TransportLayer trait、DataHandler trait 定义 | 具体通信实现 | 定义通信抽象，实现由 communication 模块提供 |
| communication::tls | TLS 双向认证配置、算法白名单 | vsock 连接管理 | 仅 TLS 配置，连接由 vsock_server 管理 |
| communication::vsock_server | vsock listener、连接并发、消息分发 | TLS 配置细节 | 实现 TransportLayer，依赖 tls 模块 |

### 1.3 trustring crate 目录结构

```
rust/plugins/trustring/
├── Cargo.toml                    # dependencies: framework, openssl
├── src/
│   ├── lib.rs                    # 模块导出、Plugin实现注册
│   ├── handler.rs                # vsock type回调注册与业务路由（0x10/0x12/0x14）
│   ├── sign.rs                   # CMS签名实现（ECC-256）
│   ├── verify.rs                 # CMS验签 + 证书链校验 + CRL校验 + 身份判定
│   ├── cert_loader.rs            # 签名/验签证书加载与管理
│   ├── error_code_mapper.rs      # OpenSSL ErrorStack → 业务result code映射
├── tests/                        # 独立集成测试
│   ├── fixtures/                 # 测试证书/密钥
│   │   ├── cms/                  # CMS签名验签测试证书
│   │   ├── communication/        # TLS测试证书
│   ├── sign_test.rs
│   ├── verify_test.rs
│   ├── verify_and_sign_test.rs
│   ├── cert_loader_test.rs
│   ├── handler_test.rs
```

**trustring 模块职责边界**：

| 模块 | 职责 | 不负责 | 边界说明 |
|------|------|--------|----------|
| cert_loader | 加载签名验签证书、PEM/DER 识别、提取证书 ID | 证书有效期巡检、通信证书加载 | 加载证书供 sign/verify 使用，有效期由 cert_checker 判断 |
| sign | CMS 签名（ECC-256）、拼接 data+证书ID | 证书加载、验签 | 仅签名计算，证书由 cert_loader 提供 |
| verify | CMS 验签、证书链校验、CRL 校验、身份判定 | 证书加载、签名计算 | 仅验签逻辑，证书由 cert_loader 提供 |
| handler | DataHandler 实现、type 回调路由、JSON 解析/构造 | 签名验签算法细节、错误码映射 | 仅路由分发，算法由 sign/verify 实现，错误码由 mapper 映射 |
| error_code_mapper | OpenSSL ErrorStack → result code 映射 | 业务错误类型定义 | 仅映射底层错误码，业务错误由 handler 定义 |

### 1.4 trustruntime 二进制 crate

```
rust/trustruntime/
├── Cargo.toml                    # dependencies: framework, trustring
├── src/
│   ├── main.rs                   # 入口：加载配置→初始化日志→加载证书→启动vsock→加载trustring插件→READY通知
```

**main.rs 职责**：

| 职责 | 不负责 | 边界说明 |
|------|--------|----------|
| 启动编排顺序调用各模块 | 具体模块实现细节 | 仅调用框架和插件 API，不实现具体逻辑 |

### 1.5 crate 依赖关系

```
trustruntime (binary) ──→ framework (library)
                       ──→ trustring (library)
trustring (library)  ──→ framework (library)
```

- `framework`：定义 Plugin trait、PluginContext、TransportLayer trait、DataHandler trait（transport 模块）、VsockMessage 等基础设施
- `trustring`：依赖 framework，实现 Plugin trait 和 DataHandler trait，提供签名验签业务
- `trustruntime`：依赖 framework + trustring，组装启动

---

## 2. 需求到模块映射

### 2.1 功能需求映射

将 requirements.md 的功能需求（FR-01~FR-10）拆解到参与模块，明确数据流转和方案选择原因。

| 需求 | 参与模块链 | 数据流转 | 方案选择原因 |
|------|-----------|----------|-------------|
| FR-01 签名接口 | handler → cert_loader → sign → handler | 收 0x10 → cert_loader 提取本地证书 ID → sign 计算 CMS 签名 → handler 构造 0x11 响应 | 证书 ID 与 data 拼签确保签名唯一标识发起者身份，防止 ID 被单独篡改 |
| FR-02 验签+签名接口 | handler → cert_loader → verify → sign → handler | 收 0x12 → cert_loader 加载 CA+CRL → verify 验签 → sign 签名(使用输入 ID) → handler 构造 0x13 响应 | 验签仅验证有效性不判定身份，签名用输入 ID 支持多节点协作链式签名 |
| FR-03 验签接口 | handler → cert_loader → verify → handler | 收 0x14 → cert_loader 加载 CA+CRL → verify 验签 → 身份判定(ID匹配/证书匹配) → handler 构造 0x15 响应 | result=0/1/2 区分本节点签名/其他节点签名/证书冲突，支持身份确认场景 |
| FR-04 vsock通信 | vsock_server → tls → vsock_server → handler | vsock_server 建连接 → tls 双向认证 → vsock_server 分发消息 → handler 处理 | TLS over vsock 确保传输安全，双向认证防止伪造客户端 |
| FR-05 进程管理 | daemon → signal → daemon | systemd 启动 → daemon 编排 → signal 捕获 SIGTERM/SIGINT → daemon 协调优雅退出 → notify STOPPING | systemd notify 实现服务状态同步，优雅退出确保资源释放 |
| FR-06 插件管理 | plugin_manager → trustring(Plugin impl) | 框架加载插件 → plugin_manager 调用 init → trustring 注册 handler → plugin_manager 管理生命周期 | Plugin trait 解耦框架与业务，静态编译简化部署，避免动态加载复杂性 |
| FR-07 日志管理 | logger → 各模块 | logger 初始化 log4rs → 各模块用 log 宏写日志 → logger 配置回滚和归档 | log4rs 提供按大小回滚和 gzip 归档，log 宏统一接口降低耦合 |
| FR-08 配置管理 | config → main.rs → 各模块 | config 解析 TOML → main.rs 创建 Arc<AppConfig> → 通过 PluginContext 分发至各模块 | TOML 人机友好，Arc 共享避免重复解析，配置一次加载全局共享 |
| FR-09 RPM打包 | packaging (非 Rust 模块) | cargo-generate-rpm 生成 RPM → systemd 自动注册服务 → 安装即启动 | RPM 自动化部署，systemd 管理服务生命周期和资源限制 |
| FR-10 证书巡检 | cert_checker → cert → logger | cert_checker 定时触发 → cert 解析有效期 → cert_checker 判断过期 → logger 输出 warn | 独立线程不阻塞业务，warn 提醒运维更新证书，不影响业务处理 |

### 2.2 非功能需求映射

将 requirements.md 的非功能需求拆解到参与模块，明确实现方式和方案选择原因。

| 需求类型 | 需求描述 | 参与模块 | 实现方式 | 方案选择原因 |
|----------|---------|---------|----------|-------------|
| 性能 | 16 并发连接 | vsock_server | tokio async runtime (4 worker threads) + Semaphore(16) | 4线程足够处理16并发；Semaphore 精确控制并发数，防止资源耗尽 |
| 性能 | 10KB 消息上限 | vsock_server + message | vsock_server 校验 header.len，超限返回 type=0x02 | 10KB 满足签名数据需求，防止大报文攻击；框架层统一处理避免业务层负担 |
| 安全 | TLS 双向认证 | tls | OpenSSL SslAcceptor + 白名单算法套件 + CRL 校验 | 双向认证防伪造客户端；白名单禁用弱算法；CRL 防止吊销证书连接 |
| 安全 | PEM/DER 双格式 | cert + cert_loader | 自动识别 PEM/DER 格式解析 | 支持两种常见格式，降低运维门槛；统一接口避免格式转换 |
| 安全 | 通信证书过期阻止启动 | tls + daemon | daemon 启动时调用 tls 加载证书 → 过期则 vsock 不启动 → 进程存活等待重启 | 通信证书过期无法建立安全连接，阻止服务暴露风险；进程存活便于运维感知状态 |
| 安全 | 签名证书过期不影响业务 | cert_checker + verify | cert_checker 巡检 warn → verify 验签时忽略 OpenSSL 过期错误 | 业务优先原则，过期证书仍可验签（签名有效性不受过期影响）；运维负责定期更新 |
| 可用性 | 证书每日巡检 | cert_checker | 后台线程每 24h 检查所有证书有效期 | 定时巡检提醒运维，不影响业务性能；独立线程避免阻塞主流程 |
| 安全 | 文件权限最小化 | packaging (RPM spec) | 定义 600/640/750 权限 → 安装时设置 | 最小权限原则，防止敏感文件泄露；RPM 自动设置避免手动配置 |
| 可用性 | 进程 5s 自动重启 | packaging (systemd unit) | Restart=on-failure, RestartSec=5 | 快速恢复服务，避免长时间不可用；systemd 自动管理无需外部监控 |
| 资源 | CPU/内存限制 | packaging (systemd unit) | CPUQuota=10%, MemoryMax=30M, CPUWeight 低优先级 | cgroup 防止资源失控，兜底限制高于实际规格（5% CPU）预留缓冲 |
| 安全 | 签名私钥无密码 | trustring::cert_loader | 直接读取 signer.key，无密码解密 | 由 trt_launcher 注入保护，进程无需处理密码；简化部署 |
| 安全 | 通信私钥支持密码 | tls | 读取 key_pwd.txt 解密私钥（可选） | 支持加密存储，灵活应对不同安全要求；密码文件由 trt_launcher 注入 |
| 兼容性 | 仅 ECC-256 算法 | sign + verify | OpenSSL ECC-256 签名验签 | ECC-256 性能好安全性高；避免多算法增加复杂度；单一算法降低测试成本 |

---

## 3. 内部接口设计

框架与插件通过 trait 解耦，定义核心接口。

### 3.1 Plugin trait

插件生命周期管理接口，由 trustring 实现。

```rust
pub trait Plugin: Send + Sync {
    /// 插件名称，用于日志和调试
    fn name(&self) -> &str;

    /// 初始化插件，注册业务处理器
    /// ctx 提供 config 和 transport，插件通过 transport.register_handler() 注册 DataHandler
    fn init(&mut self, ctx: &PluginContext) -> Result<(), PluginError>;

    /// 关闭插件，释放资源
    fn shutdown(&mut self) -> Result<(), PluginError>;
}
```

### 3.2 PluginContext

插件初始化上下文，注入配置和通信层。

```rust
pub struct PluginContext {
    pub config: Arc<AppConfig>,              // 配置引用，进程级共享
    pub transport: Arc<dyn TransportLayer>,  // 通信层引用，用于注册 handler
}
```

### 3.3 TransportLayer trait

通信层抽象接口，由 vsock_server 实现。

```rust
#[async_trait]
pub trait TransportLayer: Send + Sync {
    /// 注册业务处理器
    /// msg_type: vsock 报文 type（0x10/0x12/0x14）
    /// handler: DataHandler 实现
    fn register_handler(&self, msg_type: u32, handler: Box<dyn DataHandler>);

    /// 启动通信层（vsock listener + TLS）
    async fn start(&self) -> Result<(), TransportError>;

    /// 停止通信层，优雅关闭连接
    async fn stop(&self);
}
```

### 3.4 DataHandler trait

业务数据处理接口，由 trustring::handler 实现。

```rust
pub trait DataHandler: Send + Sync {
    /// 处理业务数据
    /// data: VsockMessage.data 字段（JSON 格式业务报文）
    /// 返回: 响应 data（JSON 格式），None 表示框架层错误响应
    fn handle(&self, data: &[u8]) -> Option<Vec<u8>>;
}
```

### 3.5 Handler 回调注册表

trustring 在 init 中注册的 DataHandler：

| type | DataHandler 实现 | 处理逻辑 |
|------|-----------------|----------|
| 0x10 | SignHandler | 提取本地证书 ID → cert_loader 加载证书 → sign 计算 CMS 签名 → 构造 0x11 响应 |
| 0x12 | VerifySignHandler | cert_loader 加载 CA+CRL → verify 验签 → sign 签名(使用输入 ID) → 构造 0x13 响应 |
| 0x14 | VerifyHandler | cert_loader 加载 CA+CRL → verify 验签 → 身份判定 → 构造 0x15 响应 |

框架收到 vsock 消息后，根据 header.type 查找已注册的 handler 并调用 handle()。
type=0x00/0x01/0x02 由 vsock_server 直接处理（框架层通用错误），不经过 DataHandler。

---

## 4. 配置设计

### 4.1 TOML 配置格式

配置文件路径：`/etc/trustruntime/agent.toml`

```toml
[vsock]
port = 12345                # vsock 端口号（必填）
max_connections = 16        # 最大并发连接数（可选）

[log]
path = "/var/log/trustruntime/trustring.log"  # 日志文件路径（必填）
level = "info"              # 日志级别（可选）
max_file_size = 10          # 单文件最大大小 MB（必填）
max_roll_count = 10         # 回滚文件个数（必填）

[certificate]
# 签名验签证书
signer_cert = "/etc/cert/cms/signer.crt"       # 签名证书（必填）
signer_key = "/etc/cert/cms/signer.key"        # 签名私钥（必填）
ca_root_cert = "/etc/cert/cms/ca_root.crt"     # CA 根证书（必填）
cms_crl = "/etc/cert/cms/cms.crl"              # CMS CRL（可选）

# 通信证书
comm_cert = "/etc/cert/cms/communication/certificate.crt"   # 通信证书（必填）
comm_key = "/etc/cert/cms/communication/private.key"        # 通信私钥（必填）
comm_key_pwd = "/etc/cert/cms/communication/key_pwd.txt"    # 私钥密码文件（可选）
comm_ca_root = "/etc/cert/cms/communication/ca_root.crt"    # 通信 CA 根证书（必填）
comm_crl = "/etc/cert/cms/communication/cert.crl"           # 通信 CRL（可选）

[cert_check]
interval_hours = 24         # 证书巡检间隔（可选）
```

### 4.2 配置项定义

| Section | 配置项 | 类型 | 必填 | 默认值 | 说明 |
|---------|--------|------|------|--------|------|
| [vsock] | port | u32 | 是 | — | vsock 端口号 |
| [vsock] | max_connections | u32 | 否 | 16 | 最大并发连接数 |
| [log] | path | String | 是 | — | 日志文件路径 |
| [log] | level | String | 否 | "info" | 日志级别（debug/info/warn/error），RUST_LOG 环境变量可覆盖 |
| [log] | max_file_size | u64 | 是 | — | 单文件最大大小 (MB) |
| [log] | max_roll_count | u32 | 是 | — | 回滚文件个数 |
| [certificate] | signer_cert | String | 是 | — | 签名证书路径（PEM/DER） |
| [certificate] | signer_key | String | 是 | — | 签名私钥路径（无密码） |
| [certificate] | ca_root_cert | String | 是 | — | CMS CA 根证书路径 |
| [certificate] | cms_crl | String | 否 | None | CMS CRL 路径，不配置则跳过校验 |
| [certificate] | comm_cert | String | 是 | — | 通信证书路径（PEM/DER） |
| [certificate] | comm_key | String | 是 | — | 通信私钥路径 |
| [certificate] | comm_key_pwd | String | 否 | None | 通信私钥密码文件路径 |
| [certificate] | comm_ca_root | String | 是 | — | 通信 CA 根证书路径 |
| [certificate] | comm_crl | String | 否 | None | 通信 CRL 路径 |
| [cert_check] | interval_hours | u64 | 否 | 24 | 证书巡检间隔（小时） |

### 4.3 配置项与模块归属

| 配置项 | 消费模块 | 用途 |
|--------|---------|------|
| vsock.port | vsock_server | vsock listener 绑定端口 |
| vsock.max_connections | vsock_server | Semaphore 并发限制 |
| log.path | logger | 日志文件路径 |
| log.level | logger | 日志级别过滤 |
| log.max_file_size | logger | 回滚触发阈值 |
| log.max_roll_count | logger | 回滚文件数量 |
| signer_cert / signer_key / ca_root_cert / cms_crl | trustring::cert_loader | 加载签名验签证书和 CA |
| comm_cert / comm_key / comm_key_pwd / comm_ca_root / comm_crl | tls | 加载通信证书和 CA |
| cert_check.interval_hours | cert_checker | 定时巡检间隔 |

---

## 5. 数据设计

### 5.1 数据实体

| 实体 | 所属模块 | 生命周期 | 说明 |
|------|---------|----------|------|
| VsockHeader | message | 单次请求 | 报文头，固定 16 字节（seq/version/type/len） |
| VsockMessage | message | 单次请求 | 完整报文，header + data（JSON 业务报文） |
| AppConfig | config | 进程级 | 配置解析结果，Arc 共享，启动时加载 |
| SignerContext | trustring::cert_loader | 进程级 | 签名证书+私钥加载对象，init 时加载 |
| VerifyContext | trustring::cert_loader | 进程级 | CA+CRL 加载对象，init 时加载 |
| TlsContext | tls | 进程级 | TLS 配置+通信证书，init 时加载 |
| PluginInstance | plugin_manager | 进程级 | 业务插件实例（trustring），框架管理生命周期 |
| TransportLayer | transport | 进程级 | 通信层抽象接口（由 VsockTransport 实现） |

### 5.2 数据在各模块间的流转

**请求路径**：

```
vsock 字节流
  → vsock_server 接收
  → tls 解密
  → message::parse() 解析为 VsockMessage
  → vsock_server 校验 version/len
  → vsock_server 按 header.type 查找 handler
  → handler.handle(VsockMessage.data)
  → cert_loader 加载证书
  → sign/verify 处理
  → handler 构造响应 JSON
  → message::serialize() 序列化
  → tls 加密
  → vsock 发送
```

**配置路径**：

```
TOML 文件
  → config::from_file() 解析为 AppConfig
  → main.rs 创建 Arc<AppConfig>
  → main.rs 创建 PluginContext { config, transport }
  → plugin_manager 调用 plugin.init(ctx)
  → trustring 通过 ctx.config 访问配置项
  → trustring::cert_loader 加载证书路径指向的证书文件
```

**证书巡检路径**：

```
cert_checker 定时触发
  → cert 解析各证书文件有效期
  → cert_checker 判断是否过期
  → logger 输出 warn 日志（证书路径 + 过期时间）
```

---

## 6. 已确认的架构决策

| 决策 | 选项 | 来源 |
|------|------|------|
| CMS签名验签库 | OpenSSL（动态链接系统 libssl.so/libcrypto.so） | ADR-0002 |
| TLS通信层 | OpenSSL SslAcceptor（统一密码栈，移除rustls） | ADR-0004 |
| 框架与trustring集成方式 | 静态编译时集成（Plugin trait为逻辑解耦边界） | ADR-0003 |
| OpenSSL链接方式 | 动态链接系统库；RPM Requires: openssl-libs >= 1.1.1；OS负责安全更新 | 会话决策 |
| 错误码映射 | 独立 ErrorCodeMapper 模块（OpenSSL ErrorStack → result code 0-11） | 会话决策 |
| 内存限制 | MemoryMax=30M（原10M，已调整） | 需求设计文档 |
| Cargo项目组织 | Workspace模式（framework + trustring + trustruntime三个crate） | 会话决策 |
| 测试fixture证书 | OpenSSL脚本生成（script/gen_test_certs.sh） | 会话决策 |
| 开发环境 | Windows编写代码，WSL Ubuntu编译测试 | 会话决策 |

---

## 修订历史

| 版本 | 日期 | 修订内容 |
|------|------|----------|
| V2.0 | 2026-06-29 | 重构文档：新增第2章"需求到模块映射"、第3章"内部接口设计"、第4章"配置设计"、第5章"数据设计"；扩充第1章模块职责边界表格；删除"子功能详细设计文档"和"待补充项"章节；重新编号原有章节 |
| V1.0 | 2026-06-18 | 初始版本：目录规划、TDD流程、架构决策 |