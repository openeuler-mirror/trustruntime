# inference lib API 接口文档

AgentSandbox 推理路由外部库（crate 名 `agentsandbox-inference`，版本 0.1.0）。

AR-005 推理路由裁决库。**当前为 mock 空实现**（恒返回 Forward + 空修改列表）——真实外部库落地后在本 crate 内替换实现，契约面不变。

- 消费方：`agentsandbox-proxy`（crate 依赖引入，命中推理路由列表的请求逐请求调用）
- 职责边界：外部库**不构造、不修改请求对象**——仅返回决策码 + 修改列表，修改由 proxy 统一应用

---

## `InferenceRouter::route` — 裁决入口

```rust
pub trait InferenceRouter: Send + Sync {
    /// 对命中推理路由列表的请求做裁决。
    fn route(&self, req: InferenceRequest) -> InferenceRouteResult;
}
```

- **调用时机**：proxy 收到命中推理路由列表（host+url 精确匹配，经
  `proxy_init` 配置）的请求时，**每请求调用一次**
- **调用形态**：同步调用（请求体已全量缓冲在 proxy 侧，无 I/O 等待语义）；
  实现方若需阻塞式重计算应自行控制耗时（调用发生在 proxy 异步线程上）

---

## 输入参数：`InferenceRequest`

```rust
pub struct InferenceRequest {
    pub headers: HeaderMap,   // 请求头集合（http crate HeaderMap）
    pub body: String,         // 请求体（全量缓冲的 UTF-8 文本）
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `headers` | `http::HeaderMap` | 全部请求头（可多值） |
| `body` | `String` | 完整请求体文本（推理流量 JSON） |

**裁决面收敛**：method/uri 不在裁决面——外部库仅可见/可作用于请求头与
请求体（proxy 转发时保持原 method/uri）。

**body 文本语义**：非 UTF-8 请求体（如二进制 multipart）经 proxy 侧
**lossy 转换**（非法字节序列替换为 U+FFFD）后传入——**仅影响本库可见性**：
`Forward`（无 body 修改）时 proxy 仍转发**原始字节**，转发保真不受损。

---

## 返回值：`InferenceRouteResult`

```rust
pub struct InferenceRouteResult {
    pub result: InferenceResult,                    // 裁决结果码
    pub modifications: Vec<InferenceModification>,  // 修改列表（仅 Modified 生效）
}
```

### `InferenceResult` — 裁决结果码

| 变体 | 协议值 | 含义 | proxy 行为 |
|---|---|---|---|
| `Forward` | **0** | 原样转发 | 忽略修改列表，按原文转发 |
| `Modified` | **1** | 修改后转发 | 逐条应用修改列表后转发 |
| `Block` | **2** | 阻断 | 返回 403 + 审计 deny（status=0，reason=inference_route） |

> `modifications` 仅在 `result == Modified` 时被应用——其余结果码下忽略
> （外部库应返回空列表，proxy 不做强制约束）。

### `InferenceModification` — 单条修改项

```rust
pub struct InferenceModification {
    pub action: ModifyAction,   // 修改动作（协议字段 action）
    pub target: ModifyTarget,   // 修改目标类型（协议字段 type）
    pub key: String,            // key
    pub value: String,          // value
}
```

**`ModifyAction`** — 修改动作：

| 变体 | 协议值 | 含义 |
|---|---|---|
| `Add` | **1** | 添加 |
| `Modify` | **2** | 修改 |

**`ModifyTarget`** — 修改目标类型（协议字段名 `type`，Rust 侧命名 `target`）：

| 变体 | 协议值 | 含义 |
|---|---|---|
| `Header` | **1** | 请求头 |
| `Body` | **2** | 请求体 |

**字段语义矩阵**：

| target | key | value | action 的作用 |
|---|---|---|---|
| `Header(1)` | 请求头名（如 `x-trace-id`） | 对应的头值 | 见冲突语义表 |
| `Body(2)` | **忽略**（约定空串） | 替换后的**完整请求体** | **忽略**（整体替换） |

---

## proxy 侧应用语义（外部库产出后由 proxy 执行）

### Header 修改冲突语义

| 场景 | 行为 |
|---|---|
| `Add(1)` + key **已存在** | **跳过**（只加新头，不覆盖原值） |
| `Add(1)` + key 不存在 | 写入新头 |
| `Modify(2)` + key **不存在** | **补写**（upsert 语义） |
| `Modify(2)` + key 已存在 | 替换原值 |
| 头名/头值非法（如值含 `\n`） | 跳过该条 + 运行日志告警，**其余条目继续应用** |

### Body 修改语义

- **整体替换**：value 即替换后的完整请求体（非 patch/局部修改）
- `action` 与 `key` 均忽略
- 多条 body 修改按列表序依次覆盖，**最后一条生效**
- 替换后 `Content-Length` 由 proxy 按最终 body 长度自动覆写、
  `Transfer-Encoding` 剥除

### 不可修改项

- **method / uri 不可修改、不可见**——裁决面收敛为仅 header/body（URI
  属于请求行而非请求头，如需支持须扩展契约新增 target 类型）
- proxy 转发时保持原 method/uri

---

## 数值映射总表（FFI / 外部协议对接）

| Rust 枚举 | 协议字段 | 数值 |
|---|---|---|
| `InferenceResult::Forward` | result | 0 |
| `InferenceResult::Modified` | result | 1 |
| `InferenceResult::Block` | result | 2 |
| `ModifyAction::Add` | action | 1 |
| `ModifyAction::Modify` | action | 2 |
| `ModifyTarget::Header` | type | 1 |
| `ModifyTarget::Body` | type | 2 |

---

## 使用示例

```rust
use agentsandbox_inference::*;

struct MyRouter;
impl InferenceRouter for MyRouter {
    fn route(&self, req: InferenceRequest) -> InferenceRouteResult {
        // 检查请求（只读——不修改 req）...
        if req.body.contains("forbidden") {
            // 阻断。
            return InferenceRouteResult {
                result: InferenceResult::Block,
                modifications: Vec::new(),
            };
        }
        // 修改后转发：改既有头 + 加新头 + 整体替换 body。
        InferenceRouteResult {
            result: InferenceResult::Modified,
            modifications: vec![
                InferenceModification {
                    action: ModifyAction::Modify,
                    target: ModifyTarget::Header,
                    key: "authorization".to_string(),
                    value: "Bearer new-token".to_string(),
                },
                InferenceModification {
                    action: ModifyAction::Add,
                    target: ModifyTarget::Header,
                    key: "x-trace-id".to_string(),
                    value: "abc-123".to_string(),
                },
                InferenceModification {
                    action: ModifyAction::Modify,        // action 对 body 无效
                    target: ModifyTarget::Body,
                    key: String::new(),                  // key 忽略
                    value: "{\"rewritten\":true}".to_string(),
                },
            ],
        }
    }
}
```

---

## 审计行为（proxy 侧）

| 结果 | 审计 |
|---|---|
| `Forward` / `Modified` | `action=allow` + 目标真实 status_code，reason=`inference_route` |
| `Block` | `action=deny` + status 0，reason=`inference_route` |

---

## UDS socket 协议（远程裁决通道，2026-09-09）

推理路由支持**双模式分发**（proxy 侧 `UdsRouteDispatcher` 默认装配）：

| 环境变量 `HISEC_ROUT_PORT` | 分发 |
|---|---|
| 存在且非空（值 = UDS socket **文件路径**，如 `/var/run/agentsandbox/route.sock`） | **UDS 远程裁决**：每请求一连接（connect → 写请求行 → 读响应行 → 关闭） |
| 不存在 / 空串 | **本地直调**：crate 内 `InferenceRouter` 实现（当前 mock——恒 Forward + 空列表） |

env 每请求读取（运行时可切换）。

### 传输与分帧

- **传输**：Unix stream socket（SOCK_STREAM）；路径 = env 值
- **分帧**：NDJSON——每帧单行 JSON + `\n`（UTF-8）；JSON 转义保证
  body/头值中的换行不破坏分帧
- **连接模型**：每请求一连接，无会话/无多路复用；连接关闭由 proxy 侧发起

### 请求帧（proxy → 服务）

```json
{"headers":[["host","api.example.com"],["x-multi","a"],["x-multi","b"]],"body":"{\"q\":\"hi\"}"}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `headers` | `[name, value]` 二元组数组 | 全部请求头**逐项展开**（多值头多元素、保序） |
| `body` | string | 完整请求体（lossy UTF-8 文本——同本地契约） |

### 响应帧（服务 → proxy）

```json
{"result":1,"modifications":[{"action":2,"type":1,"key":"authorization","value":"Bearer x"},{"action":1,"type":2,"key":"","value":"{...}"}]}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `result` | number | **0**=Forward / **1**=Modified / **2**=Block（值域外 = 协议错误） |
| `modifications` | array（**可缺省** = 空列表） | 仅 result=1 时应用 |
| `modifications[].action` | number | **1**=添加 / **2**=修改 |
| `modifications[].type` | number | **1**=header / **2**=body（线格式字段名 `type`） |
| `modifications[].key` | string | Header：头名；Body：忽略（空串） |
| `modifications[].value` | string | Header：头值；Body：替换后完整请求体 |

修改应用语义（冲突/整体替换/非法跳过）与本地契约完全一致（见前文）。
**未知字段容忍**（前向兼容）；**枚举值域外不容忍**（协议错误）。

### 失败语义（fail-closed）

| 场景 | 裁决 |
|---|---|
| 连接拒绝（服务未启/socket 路径无效） | **Block**（403） |
| 读/写超时（单请求 5s：read/write timeout） | **Block** |
| EOF（响应不完整） | **Block** |
| 响应非 JSON / 字段缺失 / 枚举值域外 / 帧超 16 MiB | **Block** |

推理服务不可用时拒绝推理流量（与 proxy 全库 fail-closed 哲学一致）；
warn 日志不含 socket 路径与请求内容（日志安全约束）。

### 参考服务实现（测试）

`proxy/tests/inference_route_uds_e2e.rs` 内嵌完整参考服务（UnixListener
线程：读请求行 → 记录 → 回写响应行）——外部服务实现可对照。

---

*文档生成时间：2026-09-09；与 crate 实现（git 工作区）一致。*
