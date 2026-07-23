# CMS签名验签服务 需求分析设计文档

## 文档信息

| 项目名称 | CMS签名验签服务（CMS Signer/Verifier Service） |
|---------|-----------------------------------------------|
| 文档版本 | V2.0 |
| 编写日期 | 2026-06-29 |

---

## 1. 引言

### 1.1 编写目的

本文档对CMS签名验签服务进行需求分析，对系统各层面需求进行设计规划，明确如何满足功能与非功能需求，为后续功能设计和详细设计提供依据。

### 1.2 参考文档

- RFC 5652 — CMS (Cryptographic Message Syntax)
- RFC 6066 / RFC 8446 — TLS 协议相关
- vsock (VM Socket) — Linux 内核虚拟机套接字规范

### 1.3 项目概述

CMS签名验签服务部署于机密计算虚机（Confidential VM）中，以 systemd 托管进程形式运行，通过 vsock 对外提供签名、验签+签名、验签三类安全通信接口。通信层采用 TLS over vsock 双向认证，确保传输链路安全。项目采用 Rust 语言开发，架构上分为**通用进程框架**与**签名业务插件**两层，通过 trait 定义框架与插件接口，框架管理插件生命周期、vsock通信、日志等基础设施能力，业务插件在框架约束下注册回调处理签名验签业务消息。最终以 RPM 包形式交付，安装即自动注册 systemd 服务并配置资源管控。

---

## 2. 需求映射

### 2.1 功能需求映射

| 需求编号 | 需求名称 | 设计方案 |
|---------|---------|---------|
| FR-01 | 签名接口 | 输入 data，计算 sign(data + 本地签名证书id)，输出签名值和本地签名证书id（证书id用于表示发起者身份） |
| FR-02 | 验签+签名接口 | 先验签（验证签名有效性：证书链+CRL+签名匹配，不执行身份判定），验签成功后计算 sign(data + 输入身份id)，输出签名值和身份id；验签失败直接返回错误码 |
| FR-03 | 验签接口 | 验证验签+签名接口输出的签名，验签通过后判断：公钥相同→result=2（安全告警）；公钥不同且ID相同→result=0；公钥不同且ID不同→result=1 |
| FR-04 | vsock 通信 | 框架层实现 vsock listener，TLS 双向认证握手后分发消息至插件回调；框架层直接处理通用错误响应 |
| FR-05 | 进程管理 | 框架层实现 daemon 进程初始化、信号处理、优雅退出 |
| FR-06 | 插件管理 | 框架层定义 Plugin trait，管理插件生命周期 |
| FR-07 | 日志管理 | 框架层初始化日志系统，各模块直接使用 log 宏写日志 |
| FR-08 | 配置管理 | TOML 配置文件，框架层统一解析并分发配置项至各模块 |
| FR-09 | RPM打包交付 | RPM 安装自动注册 systemd 服务、配置 cgroup 资源限制 |
| FR-10 | 证书过期巡检 | 框架启动后台定时线程，每日检查所有证书有效期；通信证书启动时过期则 vsock 启动失败（进程不退出） |

### 2.2 非功能需求映射

| 需求类型 | 需求描述 | 设计方案 |
|---------|---------|---------|
| 性能 | vsock 支持 16 并发连接 | tokio 异步 runtime (4 worker threads)，vsock listener 多连接并发处理 |
| 性能 | 单条消息最大 10KB | 框架层 vsock 读取缓冲区上限 10KB，超限返回错误响应 |
| 安全 | TLS 双向认证，禁用不安全协议/算法/重协商 | OpenSSL 配置：仅允许 TLS 1.2/1.3，白名单算法套件，禁 renegotiation |
| 安全 | 通信证书支持 PEM/DER 双格式 | 证书加载模块自动识别格式 |
| 安全 | 签名验签证书支持 PEM/DER 双格式 | 签名验签证书加载模块同样自动识别 PEM/DER 格式 |
| 安全 | 通信证书过期阻止 vsock 启动 | 启动时检测通信证书有效性，过期则 vsock TLS 启动失败（进程不退出，仅 vsock 服务不可用，等待证书更新后手动重启） |
| 安全 | 签名验签证书过期不影响业务 | cert_checker 定时巡检 warn；验签时忽略对端证书过期错误，正常执行返回 result=0/1/2 |
| 可用性 | 证书过期每日巡检 | 框架启动后台线程每日检查所有证书有效期，过期时打印 warn 日志 |
| 安全 | 设备文件权限最小化 | RPM spec 定义严格文件权限（600/640/750），安装后 chmod 校验 |
| 可用性 | 进程退出 5s 内自动重启 | systemd unit: Restart=on-failure, RestartSec=5 |
| 资源 | cgroup 兜底 10% CPU / 30MB 内存，实际规格 5% CPU | systemd unit: CPUQuota=10%, MemoryMax=30M, CPUWeight 低优先级 |
| 安全 | 签名密钥保护 | 签名私钥无密码保护，由 trt_launcher 映射注入；通信私钥支持密码保护（key_pwd.txt） |
| 兼容性 | 签名验签算法仅支持 ECC-256 | cms 签名模块使用 ECC-256 算法，按证书类型执行签名 |

---

## 3. 业务流程设计

### 3.1 核心业务流程

#### 签名流程（type 0x10 → 0x11）

```
客户端                        CMS签名验签服务
  |                               |
  |-- vsock connect ------------->|
  |    (TLS双向认证握手)           |
  |<------------ TLS handshake --->|
  |                               |
  |-- type=0x10 ----------------->|
  |   {"to-sign":{"data":"xxx"}}  |
  |                               | 提取本地签名证书 subject ID
  |                               | 计算 sign(data + 本地签名证书id)
  |                               | 签名证书过期由 cert_checker 定时巡检 warn，不影响签名结果
  |<-- type=0x11 -----------------|
  |   {"signed_data":"sign(data+本地id)","id":"本地签名证书id","result":0}
  |                               |
  |-- vsock close --------------->|
```

#### 验签+签名流程（type 0x12 → 0x13）

```
客户端                        CMS签名验签服务
  |                               |
  |-- type=0x12 ----------------->|
  |   {"to-verify":{"data":"...", |
  |    "signed_data":"sign(data+A_id)","id":"A_id"},
  |    "to-sign":{"data":"xxx","id":"B_id"}}
|                               | 步骤1: 验签 — 验证 sign(data+A_id)
|                               |   用 ca_root.crt + cms.crl 验证签名方证书（仅验证签名有效性，不执行身份判定）
|                               |   验签时仅忽略签名方证书过期错误，CA证书过期和证书尚未生效时验签失败
|                               |   验签失败 → 返回 result≥3（不执行签名步骤）
  |                               | 步骤2: 签名 — 计算 sign(data + B_id)
  |<-- type=0x13 -----------------|
  |   {"signed_data":"sign(data+B_id)","id":"B_id","result":0}
```

注：to-verify 中的 signed_data 来自签名接口(type=0x10)的输出格式。验签通过后签名使用输入的证书id（to-sign.id），而非本地证书id。

#### 验签流程（type 0x14 → 0x15）

```
客户端                        CMS签名验签服务
  |                               |
  |-- type=0x14 ----------------->|
  |   {"to-verify":{"data":"...", |
  |    "signed_data":"sign(data+C_id)","id":"C_id"}}
|                               | 构建证书链: ca_root.crt，校验 CRL: cms.crl
|                               | 执行 CMS 验签，验证 sign(data+C_id)
|                               | 验签时仅忽略签名方证书过期错误，CA证书过期和证书尚未生效时验签失败
|                               | 验签通过后判断：
|                               |   公钥相同 → result=2（优先级最高）
|                               |   公钥不同 且 C_id == 本地证书id → result=0
|                               |   公钥不同 且 C_id != 本地证书id → result=1
  |<-- type=0x15 -----------------|
  |   {"result":0/1/2}            |
```

注：to-verify 中的 signed_data 来自验签+签名接口(type=0x12)的输出格式 sign(data+输入证书id)。

### 3.2 流程图

```
┌─────────────────────────────────────────────────────────┐
│                    服务启动流程                           │
│                                                         │
│  systemd start → 框架初始化 → 读取 TOML 配置            │
│       → 初始化日志模块 → 加载通信证书 (TLS)              │
│       → 检查通信证书有效期(过期→vsock启动失败,进程不退出) │
│       → 启动 vsock listener (TLS over vsock)            │
│       → 加载业务插件 → 插件 init() → 注册回调            │
│       → 启动证书过期巡检线程(每24h检查所有证书)           │
│       → systemd notify READY → 进入消息循环              │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                    消息处理流程                           │
│                                                         │
│  vsock 接收 → TLS 解密 → 解析报文头 (seq/version/       │
│       type/len) → 按 type 查找插件回调 → 回调执行        │
│       → 构造响应报文 → TLS 加密 → vsock 发送             │
│                                                         │
│  异常: 报文超10KB → type=0x02; 报文格式异常 → type=0x01;   │
│       服务端内部错误 → type=0x00; 未知type → type=0x01     │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                    服务退出流程                           │
│                                                         │
│  SIGTERM/SIGINT → 框架通知插件 shutdown()               │
│       → 关闭 vsock listener → 等待连接处理完毕           │
│       → 关闭日志 → systemd notify STOPPING → 退出        │
│       → systemd 5s 后自动重启                            │
└─────────────────────────────────────────────────────────┘
```

---

## 4. 模块概述

系统采用 Rust Cargo workspace 组织，分为三个 crate：

| Crate | 类型 | 核心职责 |
|-------|------|---------|
| framework | library | 通用进程框架：进程管理、配置解析、日志、插件管理、vsock通信、报文处理 |
| trustring | library | 签名验签业务插件：CMS签名/验签、证书加载、handler回调、错误码映射 |
| trustruntime | binary | 二进制入口：组装启动 framework + trustring |

框架与插件通过 Plugin trait 解耦，插件在 init 中注册 DataHandler 回调处理业务消息。

---

## 5. 安全设计

### 5.1 认证与授权

**TLS 双向认证**

- 服务端验证：客户端必须出示由通信 CA 根证书签发的有效证书
- 客户端验证：服务端出示通信证书，客户端验证其有效性
- CRL 校验：双方证书均需通过通信 CRL 吊销检查

**CMS 签名认证**

- 签名使用签名证书 + 签名私钥
- 验签构建证书链：端证书 → CA 根证书
- 验签 CRL 校验：CMS CRL

### 5.2 数据安全

| 安全项 | 设计方案 |
|-------|---------|
| 签名私钥 | 无密码保护，由 trt_launcher 映射注入，服务直接读取使用 |
| 通信私钥 | 支持密码加密，密码文件由 trt_launcher 映射注入 |
| 传输加密 | TLS over vsock 加密所有通信数据 |
| 报文安全 | 签名后报文经 CMS 加密封装，防篡改 |

### 5.3 安全策略

**TLS 安全策略**

| 策略项 | 配置 |
|-------|------|
| 协议版本 | 仅 TLS 1.2 + TLS 1.3 |
| 禁用协议 | TLS 1.0, TLS 1.1, SSL 3.0, SSL 2.0 |
| 算法套件 | 白名单模式，仅允许 ECDHE + AES/CHACHA20 套件 |
| 禁用算法 | RSA密钥交换、RC4、DES、3DES、SHA1、MD5 |
| 重协商 | 禁用 TLS renegotiation |
| 证书格式 | 支持 PEM 和 DER 双格式自动识别 |

**文件权限最小化策略**

证书文件由 trt_launcher 拉起机密虚机时通过目录映射注入，不在 CMS 服务 RPM 包内管理，因此以下仅列出 CMS 服务自身文件的权限要求：

| 文件类别 | 路径 | 权限 | 属主 |
|---------|------|------|------|
| 配置文件 | /etc/trustruntime/agent.toml | 640 | root:root |
| 服务二进制 | /usr/bin/trustruntime | 550 | root:root |
| systemd unit | /usr/lib/systemd/system/trustruntime.service | 644 | root:root |
| 日志目录 | /var/log/trustruntime | 750 | root:root |

---

## 6. 性能设计

### 6.1 性能指标

| 指标名称 | 目标值 | 设计方案 |
|---------|-------|---------|
| vsock 并发连接数 | 16 | tokio Semaphore(16) 限流 |
| 单消息最大长度 | 10KB | 框架层读取缓冲区上限检查 |
| 进程重启时间 | ≤5s | systemd RestartSec=5 |
| 签名吞吐量 | 待测试 | 异步处理 + 证书预加载 |
| CPU 资源占用 | ≤5% 实际 | cgroup CPUQuota 限制 |
| 内存占用 | ≤30MB | cgroup MemoryMax 限制 |

### 6.2 性能优化策略

- 证书预加载：进程启动时一次性加载签名/验签/通信证书至内存，避免请求时重复 IO
- 异步消息处理：tokio 异步 runtime，vsock 连接并发处理不阻塞
- 零拷贝报文：vsock 读取直接进入 VsockMessage 结构体，减少内存拷贝
- 日志非阻塞：log4rs RollingFileAppender 写入，不影响业务线程

---

## 7. 可扩展性设计

### 7.1 扩展点识别

| 扩展点 | 说明 |
|-------|------|
| 新签名算法 | 当前仅支持 ECC-256，可通过扩展 Plugin 签名模块支持新算法（如 RSA4096 等） |
| 新业务插件 | 框架 Plugin trait 支持注册多个插件，可扩展新的业务处理逻辑 |
| 新 vsock 消息类型 | 插件注册 type 回调，新增 type 仅需插件添加回调 |
| 配置项扩展 | TOML 配置结构可随模块增加自然扩展 |

### 7.2 扩展策略

- 框架层通过 trait 接口与插件解耦，新增业务只需实现 Plugin trait
- 算法路由表设计：按证书 OID 自动选择签名实现，新增算法只需扩展路由表
- 证书由外部预置，不支持热更新；需更新证书时通过重启进程生效

---

## 8. 部署与运维设计

### 8.1 RPM 打包

- 构建：cargo build --release + cargo-generate-rpm（或使用 packaging/build-rpm.sh）
- RPM 内容：
  - `/usr/bin/trustruntime` — 服务二进制（权限 550）
  - `/etc/trustruntime/agent.toml` — 默认配置文件（权限 640，config=noreplace）
  - `/usr/lib/systemd/system/trustruntime.service` — systemd unit（权限 644）
  - `/var/log/trustruntime/` — 日志目录（权限 750，%post 创建）
- 依赖：openssl-libs, systemd
- `%post` 脚本：创建日志目录、systemctl enable trustruntime.service、systemctl start trustruntime.service
- `%postun` 脚本：systemctl stop trustruntime.service、systemctl disable trustruntime.service
- 证书目录由 trt_launcher 创建，不在 RPM 包内管理
- 文件权限在 Cargo.toml 的 [package.metadata.generate-rpm] 中定义

### 8.2 systemd 服务配置

```ini
[Unit]
Description=TrustRuntime Agent
After=network.target

[Service]
Type=notify
ExecStart=/usr/bin/trustruntime --config /etc/trustruntime/agent.toml
Restart=on-failure
RestartPreventExitStatus=1
RestartSec=5
TimeoutStartSec=30s
TimeoutStopSec=10s
StandardOutput=journal
StandardError=journal
CPUQuota=10%
MemoryMax=30M
ProtectSystem=strict
ReadWritePaths=/var/log/trustruntime
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

- 配置说明：
  - CPUQuota=10%：兜底 CPU 上限 10%，实际使用规格 5%
  - MemoryMax=30M：内存硬上限 30MB
  - Restart=on-failure + RestartSec=5：进程异常退出后 5s 自动重启
  - RestartPreventExitStatus=1：退出码为1时不重启（正常退出）
  - ProtectSystem=strict + ReadWritePaths：仅允许写入日志目录
  - NoNewPrivileges=yes：禁止进程获取新权限

---

## 修订历史

| 版本 | 日期 | 修订人 | 修订内容 |
|-----|-----|-------|---------|
| V2.0 | 2026-06-29 | — | 重构文档结构：删除第4章详细设计、第5章数据设计、第6章接口设计；新增简短第4章"模块概述"；简化第2章需求映射表格；重新编号第7-10章为第5-8章 |
| V1.1 | 2026-06-16 | — | 业务逻辑细化：签名覆盖data+证书id；验签+签名使用输入证书id签名；验签result重新定义(0=id同/1=id异/2=证书同)；证书过期仅日志提醒；签名验签证书仅支持ECC-256；新增通用错误响应type 0x00/0x01/0x02 |
| V1.0 | 2026-06-16 | — | 初始版本，基于用户需求整理结构与细化内容 |