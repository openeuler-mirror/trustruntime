# CMS 签名验签服务 接口文档

| 文档版本 | V1.1 |
| 编写日期 | 2026-06-27 |

---

## 1. 概述

CMS签名验签服务部署于机密计算虚机（Confidential VM）中，以 systemd 托管进程形式运行，通过 vsock 对外提供签名、验签+签名、验签三类安全通信接口。通信层采用 TLS over vsock 双向认证，确保传输链路安全。服务为无状态签名服务，不持久化业务数据。

---

## 2. 通信协议

### 2.1 报文头结构

所有 vsock 报文由固定长度的 header + 可变长度的 data 组成：

| 字段 | 类型 | 长度 | 说明 |
|------|------|------|------|
| seq | uint32 | 4B | 消息序列号，请求-响应配对标识 |
| version | uint32 | 4B | 消息格式版本号，当前唯一值 0xFFFF0400 |
| type | uint32 | 4B | 消息类型编码 |
| len | uint32 | 4B | data 字段字节长度（0~10240） |
| data | byte[] | 0~10240B | JSON 格式业务报文 |

**字节序**：所有多字节字段（seq、version、type、len）均采用**小端序（Little-Endian）**编码。

### 2.2 版本号协商

严格匹配：客户端发送的 version 必须为 0xFFFF0400，不匹配时服务端返回 type=0x01（报文格式异常），len=0。

### 2.3 连接模型

- 客户端通过 TLS over vsock 与服务端建立双向认证连接
- 连接支持复用：同一连接上可发送多对请求-响应，直到客户端主动关闭
- 实际场景中绝大多数为短连接（一请求一响应），但服务端设计为支持连接复用
- 服务端无请求超时机制，客户端自行管理超时
- **SSL 握手超时**：客户端发起 socket connect 后，应在 5 秒内完成 TLS 握手，否则服务端主动断开连接

### 2.4 并发管理

- 最大 16 个并发连接（tokio Semaphore 限流）
- 超出 16 个的新连接排队等待
- 单条消息最大 10KB，超过返回 type=0x02

---

## 3. TLS 配置

### 3.1 协议与算法

| 配置项 | 值 |
|--------|-----|
| 协议版本 | 仅 TLS 1.2 + TLS 1.3 |
| 禁用协议 | TLS 1.0, TLS 1.1, SSL 3.0, SSL 2.0 |
| TLS 1.3 算法套件 | TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256 |
| TLS 1.2 算法套件 | ECDHE_RSA_AES_256_GCM_SHA384, ECDHE_RSA_AES_128_GCM_SHA256, ECDHE_ECDSA_AES_256_GCM_SHA384, ECDHE_ECDSA_AES_128_GCM_SHA256 |
| 禁用算法 | RSA密钥交换, RC4, DES, 3DES, SHA1, MD5 |
| 重协商 | 禁用 TLS renegotiation |
| 会话重用（票据） | 禁用会话票据（Session Ticket） |
| 会话重用（ID） | 禁用会话 ID（Session ID）重用 |
| 压缩 | 禁用 TLS 压缩 |
| 双向认证 | 客户端与服务端均需出示有效证书 |
| 证书格式 | PEM / DER 双格式自动识别 |
| CRL 校验 | 通信证书吊销检查 |

### 3.2 证书路径

| 文件 | 路径 | 用途 | 必选 |
|------|------|------|------|
| 通信证书 | `/etc/cert/cms/communication/certificate.crt` | TLS 服务端证书 | 是 |
| 通信私钥 | `/etc/cert/cms/communication/private.key` | TLS 服务端私钥 | 是 |
| 私钥密码 | `/etc/cert/cms/communication/key_pwd.txt` | 加密私钥的密码文件 | 否 |
| 通信 CA 根证书 | `/etc/cert/cms/communication/ca_root.crt` | TLS 客户端证书验证 CA | 是 |
| 通信 CRL | `/etc/cert/cms/communication/cert.crl` | 通信证书吊销列表 | 否 |

---

## 4. 数据编码规范

| 字段 | 编码方式 | 说明 |
|------|----------|------|
| signed_data | Base64 | Base64 编码的 CMS DER 结构 |
| id | Base64 | Base64 编码的 Subject Key ID（20 字节 SHA-1 哈希） |

**data 字段**：vsock 报文中的 data 字段为 JSON 格式字符串，服务端不感知其是否为 Base64 编码，不对 data 字段做 Base64 解码操作。data 字段的编码格式由调用方自行约定。

**证书 ID 定义**：Subject Key ID（20 字节 SHA-1 哈希），与公钥绑定，稳定不变，从签名证书提取。

---

## 5. 通用错误响应

框架层直接构造返回，不经过插件回调。

| type | 触发条件 | body |
|------|----------|------|
| 0x00 | 服务端内部异常（插件崩溃、证书加载失败等） | len=0，无 data |
| 0x01 | 报文格式异常（version 不匹配、消息头解析失败、body 长度不一致、未知 type） | len=0，无 data |
| 0x02 | 请求报文过长（超过 10KB） | len=0，无 data |

**注意**：通用错误响应的 seq/version 字段与对应请求报文一致。

---

## 6. 结果码

三种接口（0x11、0x13、0x15）统一使用以下结果码表。编码错开设计：每个数值全局唯一含义，无需按接口类型切换解读逻辑。决策依据见 [ADR-0001](./adr/0001-unified-result-code-encoding.md)。

| result | 含义 | 适用接口 |
|--------|------|----------|
| 0 | 成功 | 0x11: 签名成功；0x13: 验签通过且签名完成；0x15: 验签通过，本节点签名 |
| 1 | 其他节点签名（验签有效，id != 本地证书id） | 0x15 |
| 2 | 证书身份冲突（验签有效，签名方证书公钥 == 本地证书公钥） | 0x15 |
| 3 | 证书链无效 | 0x13、0x15 |
| 4 | CRL吊销 | 0x13、0x15 |
| 5 | 签名不匹配 | 0x13、0x15 |
| 6 | 格式错误（CMS DER解析失败） | 0x13、0x15 |
| 7 | 证书加载失败 | 0x11、0x13、0x15 |
| 8 | 私钥不可用 | 0x11、0x13 |
| 9 | 签名算法错误 | 0x11、0x13 |
| 10 | JSON解析失败 | 0x11、0x13、0x15 |
| 11 | Base64解码失败 | 0x11、0x13、0x15 |
| ≥12 | 其他错误 | 0x11、0x13、0x15 |

**重要说明**：
- result=1/2 为验签接口（0x15）通过的合法结果，不表示失败
- result=2 优先级高于 result=1：公钥比较相同时，无论输入 id 值如何，均返回 result=2
- 0x13 中验签步骤仅验证签名有效性（证书链+CRL+签名匹配），不执行身份判定
- 0x13 中验签通过后执行签名，验签失败（result≥3）不执行签名步骤（signed_data=""、id=""）
- 0x13 中验签通过后签名失败，返回签名失败码（7/8/9/≥10）
- result=1/2 不适用于验签+签名接口（0x13）
- result=10/11 由 handler 层在解析请求时返回，框架层不处理

---

## 7. 业务接口定义

### 7.1 签名接口（0x10 → 0x11）

**请求**

```json
{
  "to-sign": {
    "data": "<原始报文>"
  }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| to-sign.data | string | 待签名的原始报文内容 |

**响应**

```json
{
  "signed_data": "<Base64编码的CMS签名值>",
  "id": "<Base64编码的本地证书Subject Key ID>",
  "result": 0
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| signed_data | string (Base64) | sign(data + 本地证书 id) 的 CMS 签名值 |
| id | string (Base64) | 本地签名证书 Subject Key ID |
| result | int | 结果码（见 6.1） |

**流程**：输入 data → 提取本地签名证书 Subject Key ID → 计算 sign(data + 本地证书 id) → 返回签名值和本地证书 id。签名证书过期由 cert_checker 定时巡检 warn，不影响签名结果。

---

### 7.2 验签+签名接口（0x12 → 0x13）

**请求**

```json
{
  "to-verify": {
    "data": "<原始报文>",
    "signed_data": "<Base64编码的签名数据>",
    "id": "<Base64编码的签名方证书Subject Key ID>"
  },
  "to-sign": {
    "data": "<新原始报文>",
    "id": "<Base64编码的输入证书Subject Key ID>"
  }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| to-verify.data | string | 待验签的原始报文 |
| to-verify.signed_data | string (Base64) | 待验证的签名数据（来自 0x10 输出） |
| to-verify.id | string (Base64) | 签名方证书 Subject Key ID |
| to-sign.data | string | 新待签名的原始报文 |
| to-sign.id | string (Base64) | 外部输入的证书 Subject Key ID |

**响应**

```json
{
  "signed_data": "<Base64编码的CMS签名值>",
  "id": "<Base64编码的输入证书id>",
  "result": 0
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| signed_data | string (Base64) | sign(data + to-sign.id) 的 CMS 签名值 |
| id | string (Base64) | 输入的证书 id（即 to-sign.id） |
| result | int | 结果码（见 6.2） |

**流程**：先验签 sign(data + to-verify.id) → 验签仅验证签名有效性（证书链+CRL+签名匹配），不执行身份判定，验签成功（result=0）即执行签名步骤 sign(新 data + to-sign.id) → 返回签名值和输入证书 id。验签失败（result≥3）时不执行签名步骤，signed_data=""、id=""，直接返回对应 result。

---

### 7.3 验签接口（0x14 → 0x15）

**请求**

```json
{
  "to-verify": {
    "data": "<原始报文>",
    "signed_data": "<Base64编码的签名数据>",
    "id": "<Base64编码的签名方证书Subject Key ID>"
  }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| to-verify.data | string | 待验签的原始报文 |
| to-verify.signed_data | string (Base64) | 待验证的签名数据（来自 0x13 输出） |
| to-verify.id | string (Base64) | 签名方证书 Subject Key ID |

**响应**

```json
{
  "result": 0
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| result | int | 结果码（见 6） |

**流程**：验证 signed_data 是否为 sign(data + 输入 id) → 验签通过后判断证书身份 → 返回 result。验签时忽略对端证书过期/尚未生效的 OpenSSL 错误，视为验签通过。证书过期由 cert_checker 定时巡检 warn。

---

## 8. 链路对应关系

签名数据的产生与消费形成链路：

- **0x10 输出**的 signed_data → **0x12 的 to-verify.signed_data** 输入（验签+签名接口验签步骤）
- **0x13 输出**的 signed_data → **0x14 的 to-verify.signed_data** 输入（验签接口验签步骤）

---

## 9. 证书过期处理

| 证书类型 | 启动时 | 运行中 |
|----------|--------|--------|
| 通信证书（TLS） | 过期 → vsock 启动失败，进程不退出，仅日志告警等待手动重启 | 仅记录 warn 日志，不关闭 vsock listener，不触发进程重启。客户端可通过 TLS 握手失败感知服务端证书过期 |
| 签名验签证书（CMS） | 检测到过期打印 warn 日志 | 仅 warn 日志，不影响业务处理 |
| 验签时签名方证书过期/尚未生效 | — | 忽略 OpenSSL 过期错误，视为验签通过（result 仍返回 0/1/2）；证书过期由 cert_checker 巡检 warn |

---

## 10. 内部接口定义

### 10.1 VsockHeader

```rust
#[repr(C)]
pub struct VsockHeader {
    seq: u32,
    version: u32,
    msg_type: u32,
    len: u32,
}
```

### 10.2 VsockMessage

```rust
pub struct VsockMessage {
    header: VsockHeader,
    data: Vec<u8>,
}
```

### 10.3 Plugin trait

```rust
pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    fn init(&mut self, ctx: &PluginContext) -> Result<(), PluginError>;
    fn shutdown(&mut self) -> Result<(), PluginError>;
}
```

### 10.4 PluginContext

```rust
pub struct PluginContext {
    pub config: Arc<AppConfig>,
    pub transport: Arc<dyn TransportLayer>,
}
```

### 10.5 TransportLayer trait

定义于 `framework::transport` 模块。

```rust
#[async_trait]
pub trait TransportLayer: Send + Sync {
    fn register_handler(&self, msg_type: u32, handler: Box<dyn DataHandler>);
    async fn start(&self) -> Result<(), TransportError>;
    async fn stop(&self);
}
```

### 10.6 DataHandler trait

定义于 `framework::transport` 模块。

```rust
pub trait DataHandler: Send + Sync {
    fn handle(&self, data: &[u8]) -> Option<Vec<u8>>;
}
```

### 10.7 日志

各模块直接使用 `log` crate 宏写日志，无 trait 封装：

```rust
log::info!("message");
log::warn!("message");
log::error!("message");
log::debug!("message");
```

日志系统由 `logger::init_logger(&config.log)` 在启动时初始化（基于 `log4rs`）。

### 10.8 Handler 回调注册

| type | DataHandler 实现 | 说明 |
|------|------------------|------|
| 0x10 | SignHandler | 签名请求 |
| 0x12 | VerifySignHandler | 验签+签名请求 |
| 0x14 | VerifyHandler | 验签请求 |

插件在 init 中通过 ctx.transport.register_handler() 注册 DataHandler。Transport 收到 vsock 消息后，根据 header.type 查找已注册的 handler 并调用 handle()。type=0x00/0x01/0x02 由 Transport 层直接处理，不经过 DataHandler。

---

## 11. 附录

| 项目 | 说明 |
|------|------|
| 签名算法 | 仅支持 ECC-256 |
| 签名密钥保护 | 签名私钥无密码保护，由 trt_launcher 映射注入，进程直接读取 |
| 通信私钥密码 | 通信私钥支持密码保护（key_pwd.txt），由 trt_launcher 映射注入 |
| 证书格式 | 所有证书支持 PEM / DER 双格式自动识别 |
| 证书注入方式 | trt_launcher 拉起机密虚机时通过目录映射注入 |
| 证书热更新 | 不支持热更新，需更新证书时通过重启进程生效 |
| 证书过期巡检 | 后台线程每 24h 检查所有证书有效期，过期时打印 warn 日志 |

---

## 修订历史

| 版本 | 日期 | 修订内容 |
|------|------|----------|
| V1.2 | 2026-06-30 | 1. 报文头增加小端序说明；2. 连接模型增加SSL握手超时（5秒）；3. TLS配置增加禁用会话票据、会话ID重用、压缩；4. 证书路径增加必选列；5. result=1/2仅适用于0x15接口；6. 删除错误处理汇总章节 |
| V1.1 | 2026-06-27 | 补充错误码10/11定义（JSON解析失败、Base64解码失败） |
| V1.0 | 2026-06-17 | 初始版本：基于 grill-with-docs 会话确认的决策编写，涵盖通信协议、TLS 配置、数据编码、结果码体系（三套独立体系）、业务接口定义、内部接口定义、错误处理等完整规范 |
