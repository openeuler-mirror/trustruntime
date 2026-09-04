# proxy lib API 接口文档

AgentSandbox HTTPS 透明代理库（crate 名 `proxy`，版本 0.1.0）。

对 Agent 出站流量做 MITM 解密（HTTPS）/同协议透传（HTTP）、规则集链式过滤（2026-09-16 ruleset 结构：host 匹配 → binaryrules → targetrules）、审计与动态证书签发，统一服务路径：**端口监听 + 当前全局配置**。**本 crate 仅以库形态交付**（集成方经 Cargo 引入，不作为独立进程——无二进制目标、无文件日志后端）。每连接按**首字节嗅探**分流双协议：`0x16` → HTTPS（MITM 全链）；ASCII 方法名首字符 → 明文 HTTP（domain 取 Host 头、目标同协议透传 :80）。集成方经 Cargo 引入本 crate，调用 6 个公共 API 完成初始化，随后自行重定向应用流量到监听端口。

- 契约来源：`.sdd/SR.IR20260711000103.001/SR-design.md`（v2.4）
- 交付约束：不带 TOML 解析依赖（配置解析在集成方进程）；审计/告警/调试统一经 [`logging`](#日志接口) 交付

## 目录

- [快速开始](#快速开始)
- [初始化 API（6 个）](#初始化-api)
- [数据类型](#数据类型)
- [日志接口](#日志接口)
- [错误类型](#错误类型)
- [高级模块（非契约面）](#高级模块)
- [Feature 说明](#feature-说明)
- [行为语义](#行为语义)

---

## 快速开始

```rust
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use proxy::{BinaryRule, CaCert, ContainerEndpoint, FilterConfig, HostRule, HostType, InferenceRoute, LogEvent, LogKind, LogLevel, Policy, Protocol, ProxyConfig, ResolverOutput, RuleAction, RuleSet, TargetRule};

// 1. 注册日志回调（审计 + 运行日志统一接收）
proxy::register_log_sink(Arc::new(|event: &LogEvent| {
    match event.kind {
        LogKind::Audit => println!("[AUDIT] {}", event.message), // JSON 行
        LogKind::Run => match event.level {
            LogLevel::Error | LogLevel::Warn => eprintln!("[{:?}] {}", event.level, event.message),
            _ => {}
        },
    }
    Ok(())
}));

// 2. 注册连接身份解析回调（必需——容器身份 + binary_path 来源）
proxy::register_binary_resolver(Arc::new(|source: SocketAddr, target: SocketAddr, protocol: Protocol| {
    // 由 (发起方地址, 本地监听地址, 协议) 解析容器身份与进程二进制路径；
    // 返回 None → 该连接身份未解析，fail-closed（503 / TLS 拒握手）
    Some(ResolverOutput {
        container_id: "container-1".to_string(),
        binary_path: "/usr/bin/python3".to_string(),
    })
}));

// 3. 设置容器 CA（MITM 动态证书签发来源；双 PEM 结构体）
proxy::set_container_ca("container-1", CaCert {
    cert_pem: ca_cert_pem,
    key_pem: ca_key_pem,
})?;

// 4. 设置容器过滤配置（按容器键控；同 id 覆盖——2026-09-16 ruleset 结构）
let fc = FilterConfig {
    default_policy: Policy::Deny,
    rule_list: vec![
        RuleSet {
            name: "block-metadata-service".to_string(),
            host: HostRule {
                host_type: HostType::Ip,
                addr: Some("169.254.169.254".to_string()),
                context: None,
                prio: 50,
            },
            targetrules: vec![TargetRule {
                method: "*".to_string(),
                path: "*".to_string(),
                action: RuleAction::Deny,
            }],
            binaryrules: vec![],
            port: Some(8843),   // 预留——暂不参与匹配
        },
        RuleSet {
            name: "allow-trusted".to_string(),
            host: HostRule {
                host_type: HostType::Host,
                addr: None,
                context: Some("*.trusted.com".to_string()),
                prio: 300,
            },
            targetrules: vec![TargetRule {
                method: "GET".to_string(),
                path: "/v1/*".to_string(),
                action: RuleAction::Allow,
            }],
            binaryrules: vec![BinaryRule {
                path: "/usr/bin/python3".to_string(),
                action: RuleAction::Alert,
            }],
            port: None,
        },
    ],
};
proxy::set_container_config("container-1", fc)?;

// 5. 初始化（一次性）——forwarding 端点接入完整服务；inference_routes
//    为推理路由列表（host+url 精确匹配——命中即旁通过滤引擎，交推理
//    路由外部库裁决；空列表 = 无分流）
let mk = |port: u16| ContainerEndpoint {
    ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
    port,
};
proxy::proxy_init(&ProxyConfig {
    forwarding: mk(19443),
    inference_routes: vec![InferenceRoute {
        host: "api.model.example.com".to_string(),
        url: "/v1/chat/completions".to_string(),
    }],
})?;

// 6. 集成方将容器流量重定向到 127.0.0.1:19443
//    （容器身份 = resolver 回调按连接运行时解析——source/target/protocol
//    → container_id + binary_path，每连接一次连接级缓存）
```

典型初始化顺序：`register_log_sink` → `register_binary_resolver`（必需）
→ `set_container_ca` → `set_container_config` → `proxy_init`。
配置/CA 与 init 的调用顺序不敏感（每请求实时查表）；resolver 未注册时
全部连接身份未解析——fail-closed（503 / TLS 拒握手）。

---

## 初始化 API

容器键控模型：配置与 CA 按 `container_id` 键控（单容器实现 + 多容器扩展
预留——内部结构为 HashMap）；容器身份经 `register_binary_resolver`
回调**连接级运行时解析**（source/target/protocol → container_id +
binary_path，每连接一次缓存）——未注册/解析失败该连接 fail-closed。

### `set_container_config` — 设置容器过滤配置

```rust
pub fn set_container_config(container_id: &str, fc: FilterConfig) -> Result<(), ConfigError>
```

- 按 `container_id` 键控存储；**同 id 覆盖**；`container_id` 空或结构经
  K10 校验非法 → `Err(ConfigError::Format)` 且保持旧配置（fail-closed）
- 热更新即时生效（每请求实时查表）
- 未设置配置的容器流量 → 503 `config_not_found`

### `remove_container_policy` — 清除容器过滤配置

```rust
pub fn remove_container_policy(container_id: &str) -> Result<(), ConfigError>
```

- 按 id 删除；无该容器配置 → `Err(ConfigError::NotFound)`（幂等可忽略）
- 清除后该容器流量 fail-closed

### `set_container_ca` — 设置容器 CA

```rust
pub fn set_container_ca(container_id: &str, ca: CaCert) -> Result<(), CaError>
```

- `CaCert { cert_pem, key_pem }` 双 PEM 结构体（PEM X.509 + PKCS#8）
- MITM 动态证书签发的 CA 来源；**同 id 覆盖**并清该容器证书缓存
- 格式非法 → `Err(CaError::Invalid)`；未设置的容器 TLS 流量被拒（ca_error，连接层关闭）

### `proxy_init` — 初始化（一次性）

```rust
pub fn proxy_init(config: &ProxyConfig) -> Result<(), ProxyInitError>
```

- **forwarding 端点**：绑定并自动启动完整服务（嗅探 → MITM → hyper
  逐请求过滤/审计/转发）；容器身份经 resolver 回调连接级运行时解析
- **inference_routes**：推理路由列表（AR-005）；条目 `{host, url}` 匹配
  语义见 [推理路由](#推理路由) 小节
- 前置校验：端口非 0，路由条目 host/url 非空
  → 否则 `ProxyInitError::InvalidEndpoint`；重复调用 → `AlreadyInitialized`；
  端口占用 → `ForwardingBind(PortInUse)`
- `ProxyConfig { forwarding: ContainerEndpoint, inference_routes: Vec<InferenceRoute> }`
  （`ContainerEndpoint { ip, port }` 支持 IPv4/IPv6）

CA 不经 init 注入——经 [`set_container_ca`] 按容器注入（proxy_proc
进程形态经环境变量路径加载后注入全局）。（测试期固定目录兜底已移除。）

### 推理路由（AR-005）

命中推理路由列表的请求**完全旁通过滤引擎**（不查容器过滤配置——容器
未配置也可路由；不触发 binary 反查与求值），交推理路由外部库裁决：

- **匹配语义**：host 对请求域名（TLS=SNI / 明文=Host 头）精确匹配
  （大小写不敏感，DNS 语义）；url 对请求路径精确匹配（区分大小写，
  不含 query string）；任一条目命中即分流。Upgrade 请求不参与分流
  （修改语义与隧道不兼容——走原管道）。
- **外部库**：crate 依赖引入（`agentsandbox-inference`）+ **双模式分发**
  （`UdsRouteDispatcher` 默认装配）：环境变量 `HISEC_ROUT_PORT`
  存在且非空（值 = UDS socket 文件路径）→ **UDS 远程裁决**
  （NDJSON 协议——详见 `inference/API.md`「UDS socket 协议」章节；
  通道失败 fail-closed Block）；不存在/空 → 本地直调 crate 内实现
  （当前 mock 空实现——恒 Forward + 空修改列表；真实库落地后同契约
  替换）。
  proxy 将**全量缓冲**的请求（headers/body）传入
  `InferenceRouter::route`（body 为 UTF-8 文本——非 UTF-8 请求体经
  lossy 转换后仅作库检查入参，`Forward` 无修改时仍转发**原始字节**
  保真）；外部库**不构造/改写请求**，返回决策码 + 修改列表，由 proxy
  统一应用：

```rust
pub struct InferenceRouteResult {
    pub result: InferenceResult,            // 0=Forward / 1=Modified / 2=Block
    pub modifications: Vec<InferenceModification>, // 仅 Modified 生效
}

pub struct InferenceModification {
    pub action: ModifyAction,               // 1=添加 / 2=修改
    pub target: ModifyTarget,               // 1=header / 2=body（协议字段 type）
    pub key: String,                        // Header：头名；Body：忽略
    pub value: String,                      // Header：头值；Body：替换后完整请求体
}
```

- **应用语义**（proxy 侧统一执行）：
  - Header + 添加(1)：key 已存在 → **跳过**（只加新头）；
  - Header + 修改(2)：key 不存在 → **补写**（upsert）；存在 → 替换；
  - Header 非法项（头名/头值不合法）：跳过该条 + 告警，其余条目继续；
  - Body（任意 action）：**整体替换**（key/action 忽略；多条按序覆盖，
    最后一条生效）；
  - method/uri **不可修改**（修改面收敛为仅 header/body）。
- **审计**：三态均产出审计条目（reason=`inference_route`）——
  Forward/Modified 为 `action=allow` + 目标真实 status_code；Block 为
  `action=deny` + status 0。请求体缓冲失败/超时不产出审计（无流量
  通过），503 关闭。

### `register_binary_resolver` — 注册连接身份解析回调（K7，必需）

```rust
pub type Resolver = Arc<dyn Fn(SocketAddr, SocketAddr, Protocol) -> Option<ResolverOutput> + Send + Sync>;
pub fn register_binary_resolver(resolver: Resolver)

pub enum Protocol { Tcp }                    // 连接协议（当前统一 TCP）

pub struct ResolverOutput {
    pub container_id: String,                // 容器标识（配置/CA 查表键）
    pub binary_path: String,                 // 进程二进制路径（规则 binary 维度求值输入）
}
```

- 回调签名 `(source, target, protocol) -> Option<ResolverOutput>`：
  source=发起方地址（连接对端）、target=本地监听地址、protocol=连接协议
- **每连接一次**（accept 后同步调用，连接级缓存——同连接多请求复用）
- **必需注册**：未注册 / 返回 None / container_id 空串 → 身份未解析，
  该连接 fail-closed（配置查表 miss → 503；TLS 侧 CA 查表 miss →
  拒绝握手）
- `binary_path` 空串视为未解析：规则含 binary 条件 → 该请求
  `binary_not_found` 403；规则 binary 维度与 binary_path **精确全等**
  比较（如 `/usr/bin/python3`）

### `register_log_sink` — 注册统一日志回调（K13，必需）

```rust
pub fn register_log_sink(handler: LogSink)
```

- 全部日志（审计 + 运行日志四级）以 `LogEvent` 转发；重复注册覆盖
- **必需注册**：未注册时审计交付失败 → 转发流量 503（fail-closed：
  无未审计流量通过）；运行日志丢弃
- 审计回调返回 `Err` → 该请求转发取消（**fail-closed**：无未审计流量）

---

## 数据类型

### `ProxyConfig` / `InferenceRoute` — 初始化配置

```rust
pub struct ProxyConfig {
    pub forwarding: ContainerEndpoint,      // 转发端点
    pub inference_routes: Vec<InferenceRoute>, // 推理路由列表（空 = 无分流）
}

pub struct ContainerEndpoint {
    pub ip: std::net::IpAddr,   // IPv4/IPv6
    pub port: u16,              // 1-65535
}

pub struct InferenceRoute {
    pub host: String,           // 非空；对请求域名精确匹配（大小写不敏感）
    pub url: String,            // 非空；对请求路径精确匹配（区分大小写，不含 query）
}
```

`InferenceRoute` 实现 `Serialize`/`Deserialize`（serde，字段名小写下划线）。
容器身份不经初始化配置——经 `register_binary_resolver` 回调连接级解析。

### `FilterConfig` — 过滤策略配置（2026-09-16 ruleset 结构重设计）

```rust
pub struct FilterConfig {
    pub default_policy: Policy,        // 无规则命中时默认策略
    pub rule_list: Vec<RuleSet>,       // 规则集列表（按 host.prio 降序求值）
}
```

**求值顺序**（链式——首个**规则**命中即决策，效率优先）：

```text
for rs in rule_list（host.prio 降序）:
    host 不匹配 → continue 下一规则集
    for br in rs.binaryrules:            // deny/alert 命中即决策；allow 透传
    for tr in rs.targetrules:            // 首中即决策（deny/alert/allow）
    （本规则集无命中 → 链式继续下一规则集）
全部未命中 → default_policy（Alert → 放行 + 告警标记）
```

- **排序归一化**：`set_container_config` 存储时由 registry 自动完成——
  rule_list 按 `host.prio` 降序（稳定排序）、各规则集内 targetrules/
  binaryrules 按 action rank（`deny > alert > allow`）排序。集成方
  **无需自行排序**（任意顺序注入均可，存储层保证求值序）
- **prio 越大越优先**：高 prio 规则集先被评估；规则集内 deny（黑名单
  阻断）先于 alert（黑名单告警）先于 allow（白名单放行）——与原
  黑名单优先的安全语义一致（deny-overrides-allow）
- **链式回退**：高 prio 规则集 host 命中但其规则全未命中时，继续评估
  低 prio 规则集（不同粒度的规则集可叠加）

`Serialize`/`Deserialize` 实现（serde，字段名小写下划线），可从集成方侧
JSON 反序列化构造（UDS `refresh_policy` 通道同构）。

### `RuleSet` — 规则集

```rust
pub struct RuleSet {
    pub name: String,                    // 非空；观测/审计定位
    pub host: HostRule,                  // 主机匹配条件（含 prio）
    pub targetrules: Vec<TargetRule>,    // 目标规则（method+path → action）
    pub binaryrules: Vec<BinaryRule>,    // binary 规则（path → action）
    pub port: Option<u16>,               // 预留——暂不参与匹配
}

pub struct HostRule {
    pub host_type: HostType,             // Ip / Host（TOML 字段名 "type"）
    pub addr: Option<String>,            // type=ip：目标 IP 或 CIDR
    pub context: Option<String>,         // type=host：域名通配
    pub prio: u32,                       // 优先级（越大越优先）
}

pub struct TargetRule {
    pub method: String,                  // 单星 glob（大小写敏感）
    pub path: String,                    // 单星 glob（不含 query）
    pub action: RuleAction,
}

pub struct BinaryRule {
    pub path: String,                    // 单星 glob（进程二进制路径）
    pub action: RuleAction,              // allow = 透传（继续 targetrules）
}
```

**TOML 形态**（`[[proxy.ruleset]]`——config crate 解析后转换，HC 下发通道）：

```toml
[[proxy.ruleset]]
name = "block-metadata-service"
host = { type = "ip", addr = "169.254.169.254", prio = 50 }
targetrules = [
  { method = "*", path = "*", action = "block" },
]
binaryrules = [
  { path = "*", action = "block" },
]
port = 8843
```

**匹配语义**：

| 匹配层 | 规则 |
|---|---|
| `host.type=host`（context） | 域名单星 glob，**ASCII 大小写不敏感**（DNS 等价类）；`*.example.com` 不匹配裸域（字面 `.` 分隔）；裸 `*` 全匹配 |
| `host.type=ip`（addr） | 精确 IP（IPv4/IPv6）或 CIDR（`10.0.0.0/8`）；求值输入 = 域名 DNS 预解析全部 IP——**任一命中即命中**（deny 保守）；预解析失败 → `dns_resolve_error` 502 fail-closed；**仅配置含 ip 型 host 才触发解析**（零 ip 条件零开销，带缓存）；空解析集不命中 |
| `targetrules.method` | 单星 glob，大小写敏感（RFC 9110）：`GET` / `*` / `G*T` |
| `targetrules.path` | 单星 glob，大小写敏感：`/v1/*`（前缀）/ `*.js`（后缀）/ `/one/box/*/v1`（中间星——`*` 匹配任意序列含 `/` 与空串）；裸 `*` 全匹配；**不含 query string**（首个 `?` 截断）；`?`/`[`/`]`/`{`/`}`/`\` 一律字面 |
| `binaryrules.path` | 进程二进制路径单星 glob（与 resolver 输出的 `binary_path` 匹配，如 `/usr/bin/curl` / `*`）；`binary_path` 未解析不命中 |
| `port` | **预留字段**——暂不参与匹配（透传保留，未来启用） |

**决策映射**（rule action → 审计条目）：

| action | 流量 | 审计 action | reason | type |
|---|---|---|---|---|
| `deny`（alias `block`） | 403 阻断 | deny | `blacklist_match` | 0 |
| `alert` | **放行** + 告警 | allow | `blacklist_match` | **1** |
| `allow` | 放行 | allow | `whitelist_match` | 0 |
| （无命中→default `alert`） | 放行 + 告警 | allow | `default_policy` | **1** |

**K10 结构校验规则**（`set_container_config` 注入时执行，非法整体拒绝保持旧配置）：

- `name` 非空
- `host`：type=ip → `addr` 为合法 IP/CIDR；type=host → `context` 为合法 glob
- `targetrules` 的 `method`/`path`、`binaryrules` 的 `path`：**非空且星号数 ≤ 1**（裸 `*` 合法=全匹配；多星如 `*v1*`/`a*b*c` 非法——语义复合应拆分为多条规则表达）
- `port` 预留不校验；`action`/`default_policy` 取值由类型系统保证

**`Decision` — 求值返回**（evaluate 输出，服务层消费）：

```rust
pub struct Decision {
    pub action: Action,   // 流量动作（allow=转发 / deny=阻断）
    pub reason: Reason,   // 审计 reason
    pub alert: bool,      // 告警标记（alert 规则命中或 default=alert）→ 审计 type=1
}
```

### `RuleAction` — 规则动作

```rust
pub enum RuleAction { Deny, Alert, Allow }   // serde 小写；deny 接受别名 "block"
```

- **Deny**（黑名单阻断）：403 + 审计 deny（`blacklist_match`）
- **Alert**（黑名单告警）：**放行** + 审计 `type=1`（`blacklist_match`）——不阻断，与 security 模块 `enforcement_mode=alert` 语义一致
- **Allow**（白名单放行）：放行 + 审计（`whitelist_match`）；binaryrules 中的 allow 为**透传**（不决策——继续评估 targetrules）

### `Policy` / `Action`

```rust
pub enum Policy { Allow, Deny, Alert }  // 默认策略（FilterConfig 字段）
pub enum Action { Allow, Deny }          // 决策动作（审计条目字段）
```

serde 序列化为小写 `"allow"` / `"deny"` / `"alert"`。

**`Policy::Alert`**（2026-09-09，2026-09-16 语义并入 ruleset 模型）：全部
规则集未命中时——流量**放行** + 审计条目标记告警（`type=1`）；规则命中
不受影响。与 `RuleAction::Alert`（规则级告警——`blacklist_match` +
type=1）共同构成告警语义：**default=alert 是"未命中告警"，alert 规则
是"命中告警"**——两者审计 reason 不同（`default_policy` vs
`blacklist_match`），type 同为 1。

### `Reason` — 决策原因（14 值）

```rust
pub enum Reason {
    WhitelistMatch,     // whitelist_match
    BlacklistMatch,     // blacklist_match
    DefaultPolicy,      // default_policy
    ConfigNotFound,     // config_not_found
    GroupIdNotFound,    // group_id_not_found
    CaError,            // ca_error
    CertError,          // cert_error
    LogWriteError,      // log_write_error
    TargetTlsError,     // target_tls_error
    ConnectionRefused,  // connection_refused
    ConnectionTimeout,  // connection_timeout
    BinaryNotFound,     // binary_not_found
    InferenceRoute,     // inference_route（推理路由三态决策统一 reason）
    DnsResolveError,    // dns_resolve_error（目标 IP 预解析失败 fail-closed）
}
```

serde 序列化为 snake_case（注释中标注的值即审计 JSON 中的字面值）。

### `AuditLogEntry` — 审计日志条目（12 字段）

```rust
pub struct AuditLogEntry {
    pub timestamp: String,           // UTC ISO-8601 秒精度："2026-08-26T01:42:59Z"
    pub container_id: String,        // 容器标识（连接级 resolver 解析）
    pub scenario: String,            // "kata" / "lib"（默认 "lib"）
    pub domain: String,              // SNI 域名
    pub url_path: String,            // 请求路径（不含 query）
    pub method: String,              // HTTP 方法
    pub status_code: u16,            // 目标响应码；拒绝路径为 0
    pub action: Action,              // allow / deny
    pub reason: Reason,              // 见上
    pub source_ip: Option<String>,   // 发起方 IP；可空
    pub target_ip: Option<String>,   // 目标 IP（解析集逗号连接；无 IP 条件/未解析时为空）
    pub entry_type: AuditEntryType,  // 条目类型（JSON 字段名 "type"）
}

pub enum AuditEntryType { Audit = 0, Alert = 1 }   // serde 数值映射
```

- 经 `register_log_sink` 回调交付时：`LogEvent.message` 为该结构的 **JSON 行**序列化（`None` 字段输出 `null` 不省略）；`LogEvent.audit` 携带结构化实例。
- 允许路径 `status_code` 为**真实目标响应码**（透传响应可观测）；拒绝路径恒 `0`。
- `type` 字段（2026-09-09）：`0`=审计（常规）/ `1`=告警——仅
  `default_policy=alert` 且黑白名单均未命中的放行流量产出 `1`；其余
  条目恒 `0`。**向后兼容**：旧条目（无 `type` 字段）反序列化为 `Audit(0)`；
  消费方按 `type` 值区分审计流与告警流。

**reason → HTTP 阻断响应状态码映射**（拒绝时返回给发起方）：

| 类别 | reason | 状态码 |
|---|---|---|
| 策略拒绝 | whitelist_match / blacklist_match / default_policy / binary_not_found / inference_route（Block） | **403 Forbidden** |
| 目标出站失败 | target_tls_error / connection_refused / connection_timeout / dns_resolve_error | **502 Bad Gateway** |
| 配置/服务缺失 | config_not_found / group_id_not_found / log_write_error | **503 Service Unavailable** |

TLS 层失败（无 SNI、CA 缺失、证书签发失败、MITM 握手失败）发生在 HTTP 之前——连接直接关闭，无法返回 HTTP 响应。

### `SCENARIO_LIB`

```rust
pub const SCENARIO_LIB: &str = "lib";     // 默认场景标识（crate 根导出）
```

审计条目 `scenario` 字段的取值常量。当前统一服务路径下固定 `"lib"`（`SCENARIO_KATA` 常量保留于 `model` 模块内，根部不再导出）。

---

## 日志接口

日志分两类：**审计日志**（结构化条目，fail-closed）与**运行日志**（四级
debug/info/warn/error，fire-and-forget）。

### `LogKind` — 日志类别

```rust
#[non_exhaustive]
pub enum LogKind { Audit, Run }
```

### `LogLevel` — 运行日志级别（四级）

```rust
#[non_exhaustive]
pub enum LogLevel { Debug, Info, Warn, Error }
```

| 级别 | 语义 | 典型事件 |
|---|---|---|
| `Debug` | 高频细节 | 请求级决策、连接收尾、握手拒绝 |
| `Info` | 关键运行事件 | serve 启动、MITM/明文连接建立、策略拒绝（deny）、转发完成（forward： host/port/响应码/reason） |
| `Warn` | 可继续的运行异常 | 目标不可达、校验器缺失、端口占用 |
| `Error` | 需立即关注 | 不变量破坏、审计交付失败、启动失败 |

### `LogEvent` — 统一日志事件

```rust
pub struct LogEvent {
    pub kind: LogKind,               // Audit / Run
    pub level: LogLevel,             // 运行日志级别（Audit 事件约定 Info）
    pub subsystem: String,           // 来源子系统："server"/"forward"/"listener"/"registry"/"binary"/"audit"
    pub message: String,             // Audit 类别 = 审计条目 JSON 行；Run = 文本
    pub audit: Option<AuditLogEntry>,// 仅 kind == Audit 时存在
}
```

### `LogSink` / `LogSinkError`

```rust
pub type LogSink = Arc<dyn Fn(&LogEvent) -> Result<(), LogSinkError> + Send + Sync>;

#[non_exhaustive]
pub enum LogSinkError { Sink }       // 集成方侧处理失败（语义不透明）
```

**回调失败语义**：

| 事件类别 | 回调返回 Err 的后果 |
|---|---|
| `Audit` | 该请求转发取消、连接关闭（**fail-closed**：无未审计流量通过），并返回 503 给发起方 |
| `Run`（任一级别） | 忽略（丢弃），不影响业务流 |

### 交付路径（单回调）

| 路径 | 启用方式 | 交付 |
|---|---|---|
| **统一回调**（唯一路径——必需注册） | `register_log_sink(handler)` | 全部类别经 `LogEvent` 回调（kind + level 分流） |

**未注册回调**：审计事件返回 `Err` → 转发流量 fail-closed 503（无未审计
流量通过）；运行日志直接丢弃。`register_log_sink` 为与
`register_binary_resolver` 同级的**必需 API**。

两路径对 proxy 内部代码透明；注册回调后回调路径优先。

---

## 错误类型

全部 `#[non_exhaustive]`（演进兼容：新增变体不破坏集成方匹配）。

### `ConfigError`

```rust
pub enum ConfigError {
    Format,    // "config_format_error"：结构非法（含 K10 校验失败），旧策略保持
    NotFound,  // "config_not_found"：无生效配置（remove 幂等语义）
}
```

### `BindError`

```rust
pub enum BindError {
    PortInUse,   // "port_in_use"：端口被占用
    InvalidPort, // "invalid_port"：端口号非法（0）
}
```

### `CaError`

```rust
pub enum CaError {
    Invalid,    // "ca_invalid"：PEM/X.509/PKCS#8 解析失败或密钥不匹配
}
```

### `ProxyInitError`

```rust
pub enum ProxyInitError {
    AlreadyInitialized,                  // proxy_init 已初始化（仅可调用一次）
    ForwardingBind(BindError),           // forwarding 端点绑定失败
    InvalidEndpoint,                     // 端口 0 / 路由条目 host 或 url 空
}
```

---

## 高级模块

以下模块为 `pub`（crate 组织需要），但**不属于集成契约面**——形态可能随内部演进调整：

| 模块 | 内容 | 典型使用方 |
|---|---|---|
| `cert` | `parse_ca` / `CertIssuer` / `CertCache` / `CertService` / `ParsedCa` | 测试构造证书；生产经 `inject_ca` 间接使用 |
| `server` | `serve` / `ServeContext` | facade 自动拉起；测试直接装配 |
| `forward` | `TargetConnector` / `relay_with_idle_timeout` | server 内部消费 |
| `mitm` | SNI 捕获 + TLS 终止 | server 内部消费 |
| `filter` | ruleset 求值引擎（prio 链式 → `Decision`）+ 匹配器（domain/method/uri/ip/glob） | server 内部消费 |
| `registry` | 运行态注册面（`Registry`/`Resolver`——含存储时规则排序归一化） | facade 间接消费 |
| `model` | 契约类型（`RuleSet` 系 + `Decision` + `utc_now_iso8601` / `SCENARIO_*` 常量） | 类型经 crate 根重导出 |

集成方仅需消费 crate 根部的重导出（`proxy::xxx`），无需深入模块路径。

---

## Feature 说明

```toml
[dependencies]
proxy = { path = "..." }                          # 唯一形态：lib 集成（无额外 feature）
```

| Feature | 默认 | 作用 |
|---|---|---|
| `test-util` | 关 | 测试注入缝（`facade::testing` / `logging::testing`）；仅经 dev-dependency 自引用对测试构建启用，**生产构建完全编译排除** |

（`file-logging` 文件日志后端已随独立进程形态移除——日志唯一交付路径为
`register_log_sink` 回调。）

---

## 行为语义

### fail-closed 原则

全部异常路径均拒绝流量、不留旁路：

| 场景 | 行为 |
|---|---|
| 未设置配置 | HTTP 503 + 审计 `config_not_found` |
| 求值 deny 规则命中 | HTTP 403 + 审计 `blacklist_match` |
| 规则集含 binaryrules 且 binary_path 未解析 | HTTP 403 + 审计 `binary_not_found` |
| 身份未解析（resolver 未注册/None/container_id 空） | 配置查表 miss → 503；TLS 侧拒握手（ca_error 语义） |
| 推理路由库决策 `Block` | HTTP 403 + 审计 `inference_route`（deny） |
| 推理路由请求体缓冲失败/超时 | HTTP 503 关闭（不产出审计——无流量通过） |
| 目标连接失败（TLS/拒绝/超时） | HTTP 502 + 审计（reason 对应三类） |
| DNS 预解析失败（含 ip 型 host 规则集的配置） | HTTP 502 + 审计 `dns_resolve_error`（fail-closed） |
| 审计回调失败 | HTTP 503 + 关闭（**先审计后转发**：无未审计流量通过） |
| 日志回调未注册 | 审计交付失败 → HTTP 503（同上 fail-closed）；运行日志丢弃 |
| 未注入 CA / 无 SNI / 证书签发失败 | TLS 层关闭连接（HTTP 之前，无法返回响应） |

### 流量处理模型

每连接**首字节嗅探**（peek 不消费）：`0x16`（TLS ClientHello record type）→ HTTPS 路径；ASCII 大写字母（HTTP 方法名首字符）→ 明文 HTTP 路径；其余关闭（fail-closed）。

```
proxy_init 的 forwarding 端点监听（ip:port，自动 serve，≤16 并发）→ accept 后连接身份解析（resolver 回调：source/target/protocol → container_id + binary_path，连接级缓存）→ peek 1 字节分流
  ├─ HTTPS（0x16）：
  │    MITM TLS 终止（SNI 捕获 → 动态证书[LRU 缓存] → ALPN [h2, http/1.1]）
  │    → hyper 逐请求/逐流：domain = 连接级 SNI
  │    → 推理路由分流 → 命中：外部库裁决（Block 403 / Forward[Modified] 转发）
  │    → 未命中：求值 → deny 403 / allow 转发（目标 TLS :443，ALPN 与协商一致）
  │    → 流式回传 → 审计（真实 status_code）
  │    → Upgrade → 101 后纯字节隧道（不参与推理路由分流）
  └─ 明文 HTTP（ASCII）：
       TCP 流直接交 hyper（h1；h2c 不支持——解析失败关闭）
       → 同一逐请求全链：domain = 请求级 Host 头（剥端口；缺失 → 503）
       → 推理路由分流（同上）→ 求值 → deny 403 / allow 转发（目标纯 TCP :80，同协议透传）
       → 流式回传 → 审计 → Upgrade（ws://）→ 101 隧道

 逐请求共通（两路径同一 service 闭包）：
   域名解析（SNI / Host 头）
     → [命中推理路由列表（host+url 精确）] body 缓冲 → 外部库三态裁决
       （旁通下方引擎链——容器配置缺失不拦截）
     → 未命中：当前全局配置快照（热更新即时生效）
      → 配置缺失 503
      → [任一规则集含 binaryrules] binary_path 未解析 → 403 binary_not_found
      → [任一规则集 host.type=ip] DNS 预解析（缓存；失败 → 502 dns_resolve_error）
      → 求值（ruleset 链式：prio 降序 → binaryrules → targetrules
        → 首中即决策；deny 403 / alert·allow 转发[alert 审计 type=1]）
      → 30s 单一预算 / 连接级空闲超时 + 半关闭传播
```

**明文路径语义**（2026-09-01 决策）：Host 头缺失（如 HTTP/1.0）→ 503 + 审计 `config_not_found`（与无 SNI 对齐，fail-closed）；CA 未注入时明文照常服务（CA 仅 MITM 需要），同端口 TLS 流量仍被拒。

### 超时

- 目标出站（DNS + TCP + TLS）：合计 30s（单一 deadline 预算）
- 初始请求头读取 / MITM 握手：30s
- Upgrade 隧道：连接级空闲超时 30s（任一方向有活动即重置；双向静默超时才拆除）

### 审计语义

- **所有过滤决策（允许 + 拒绝 + 告警）均产生审计条目**；请求头解析失败（无可审计元数据）除外
- 告警条目（alert 规则命中 / default=alert 未命中）：`action=allow` + `type=1`（放行但标记）
- 审计先于响应回传发起方（fail-closed 排序）
- 审计/告警/调试**均不含请求/响应体**内容

---

*文档生成时间：2026-08-31；与 crate 实现（git 工作区）一致。*
