# CMS 签名验签服务 - 通用术语

## 通信层

### vsock 类型编码

| 值 | 类型 | 说明 |
|---|------|------|
| 0x00 | 通用错误：服务端异常 | 内部错误，如插件崩溃、证书加载失败 |
| 0x01 | 通用错误：报文格式异常 | 消息头解析失败或body长度与header不一致 |
| 0x02 | 通用错误：请求报文过长 | 单条消息超过10KB |
| 0x10 | 业务：签名请求 | 输入data，输出sign(data+证书id) |
| 0x11 | 业务：签名响应 | signed_data + 本地证书id |
| 0x12 | 业务：验签+签名请求 | 先验签sign(data+输入证书id)，再签名sign(新data+输入证书id) |
| 0x13 | 业务：验签+签名响应 | signed_data + 输入证书id |
| 0x14 | 业务：验签请求 | 验证sign(data+输入证书id)并判断证书身份 |
| 0x15 | 业务：验签响应 | result码 |

### vsock 报文头

- **seq**: 消息序列号，请求-响应配对标识
- **version**: 消息格式版本号，初始值 0xFFFF0400
- **type**: 消息类型
- **len**: data字段字节长度（0-10240）
- **data**: JSON格式业务报文

## 证书类型

### 通信证书（TLS）

- **用途**: TLS双向认证握手
- **路径**: `/etc/cert/cms/communication/`
- **私钥**: 支持密码保护（key_pwd.txt）
- **CRL**: `/etc/cert/cms/communication/cert.crl`
- **过期处理（启动时）**: 过期则vsock启动失败，进程不退出，仅日志告警等待手动重启
- **过期处理（运行中）**: 仅warn日志，不关闭vsock listener，不触发进程重启；客户端可通过TLS握手失败感知证书过期

### 签名验签证书（CMS）

- **用途**: CMS签名/验签操作
- **路径**: `/etc/cert/cms/`
- **私钥**: 无密码保护
- **CRL**: `/etc/cert/cms/cms.crl`
- **过期处理**: 启动时检测warn；运行中仅日志warn，不影响业务处理
- **验签时签名方证书过期**: 仅warn日志提醒，不影响验签结果（result仍返回0/1/2）

## 数据编码

- **signed_data**: Base64编码的CMS DER结构
- **id**: Base64编码的Subject Key ID（20字节SHA-1哈希）
- **data**: vsock层不感知编码格式，直接透传至签名/验签模块

## 证书标识符

### 证书ID（Certificate ID）

- **类型**: Subject Key ID（20字节SHA-1哈希）
- **作用**: 签名时与数据拼接（sign(data+证书id)）
- **唯一性**: 与公钥绑定，稳定不变
- **来源**: 从签名证书提取

## 业务流程

### 签名流程（0x10→0x11）

1. 输入data
2. 提取本地签名证书的Subject Key ID
3. 计算sign(data+本地证书id)，使用ECC-256算法
4. 返回{signed_data, id:本地证书id, result:0}

### 验签+签名流程（0x12→0x13）

1. 验证输入的signed_data是否为sign(data+输入证书id)
2. 若验签通过，计算sign(新data+输入证书id)
3. 返回{signed_data, id:输入证书id, result:0}

### 验签流程（0x14→0x15）

1. 验证signed_data是否为sign(data+输入证书id)
2. 若验签通过，判断证书身份：
   - result=0: 输入id==本地证书id（确认是本节点签名）
   - result=1: 输入id!=本地证书id（其他节点签名，验签有效）
   - result=2: 签名方证书==本地证书（证书身份冲突）
3. 若验签不通过，result≥3（证书链无效、CRL吊销、签名不匹配等）

**注意**：result=1 特指"其他节点签名"，不表示证书冲突（result=2），仅表示验签通过且id不同。

## 结果码

### 通用错误响应（框架层构造，len=0，seq/version与请求一致）

- **0x00**: 服务端内部异常（插件崩溃、证书加载失败等）
- **0x01**: 报文格式异常（version不匹配、消息头解析失败、body长度不一致）
- **0x02**: 请求报文过长（>10KB）

### 业务结果码（0x11/0x13/0x15统一，编码错开）

| result | 含义 | 适用接口 |
|--------|------|----------|
| 0 | 成功 | 0x11: 签名成功；0x13: 验签通过且签名完成；0x15: 本节点签名 |
| 1 | 其他节点签名（验签有效） | 0x13、0x15 |
| 2 | 证书身份冲突（公钥比较） | 0x13、0x15 |
| 3 | 证书链无效 | 0x13、0x15 |
| 4 | CRL吊销 | 0x13、0x15 |
| 5 | 签名不匹配 | 0x13、0x15 |
| 6 | 格式错误 | 0x13、0x15 |
| 7 | 证书加载失败 | 0x11、0x13、0x15 |
| 8 | 私钥不可用 | 0x11、0x13 |
| 9 | 签名算法错误 | 0x11、0x13 |
| ≥10 | 其他错误 | 全部接口 |

**注意**：result=1/2为验签通过的合法结果（0x13/0x15），不表示失败。result=2优先级高于result=1（公钥比较）。0x12验签步骤仅result=0视为通过，其他均不执行签名。

## 模块架构

### framework（通用进程框架）

- **core**: 进程daemon化、信号处理、证书过期巡检
- **config**: TOML配置解析与分发
- **transport**: TransportLayer trait、DataHandler trait（传输层抽象）
- **plugin-manager**: 插件生命周期管理、Plugin trait
- **communication**: vsock listener + TLS封装、报文收发（实现 TransportLayer）
- **logger**: 统一日志管理（tracing）
- **message**: 报文解析/构造

### trustring（签名验签业务插件）

- **sign**: CMS签名实现（ECC-256）
- **verify**: CMS验签实现 + 证书链校验 + CRL校验
- **cert-loader**: 签名/验签证书加载与管理
- **handler**: vsock type回调注册与业务路由（原设计文档中称 plugin-cms，现统一为 trustring）
- **error_code_mapper**: OpenSSL ErrorStack → 业务result code 0-9 映射层

## 配置文件

### 路径

- **配置文件**: `/etc/trustruntime/agent.toml`
- **通信证书**: `/etc/cert/cms/communication/`
- **签名证书**: `/etc/cert/cms/`
- **日志目录**: `/var/log/trustruntime/`

### 证书路径

```toml
[certificate]
# 签名验签证书
signer_cert = "/etc/cert/cms/signer.crt"
signer_key = "/etc/cert/cms/signer.key"
ca_root_cert = "/etc/cert/cms/ca_root.crt"
cms_crl = "/etc/cert/cms/cms.crl"

# 通信证书
comm_cert = "/etc/cert/cms/communication/certificate.crt"
comm_key = "/etc/cert/cms/communication/private.key"
comm_key_pwd = "/etc/cert/cms/communication/key_pwd.txt"
comm_ca_root = "/etc/cert/cms/communication/ca_root.crt"
comm_crl = "/etc/cert/cms/communication/cert.crl"
```

## 部署

### systemd配置

- **服务名**: trustruntime
- **重启策略**: Restart=always, RestartSec=5
- **资源限制**: CPUQuota=10%, MemoryMax=30M
- **切片**: trustruntime.slice

### 文件权限

- **配置文件**: 640 (root:root)
- **服务二进制**: 750 (root:root)
- **systemd unit**: 644 (root:root)
- **日志目录**: 750 (root:root)

## 证书用途要求

### 通信证书（TLS）

- **KeyUsage**: 必须包含 `digitalSignature` 和 `keyEncipherment`
- **ExtendedKeyUsage**: 必须包含 `serverAuth`
- **校验时机**: TLS配置加载时（启动时）
- **校验失败**: 启动失败，记录错误日志

### 签名证书（CMS）

- **KeyUsage**: 仅允许 `digitalSignature`（不能包含其他用途）
- **ExtendedKeyUsage**: 不指定
- **校验时机**: 插件初始化时
- **校验失败**: 初始化失败，记录错误日志
