# TrustRuntime 架构设计

| 文档版本 | V1.0 |
| 编写日期 | 2026-06-29 |

---

## 1. 系统架构概览

### 1.1 整体架构图

```mermaid
graph TB
    subgraph "机密计算虚机 (Confidential VM)"
        subgraph "TrustRuntime Service"
            MAIN[main.rs<br/>进程入口]

            subgraph "Framework Layer"
                CORE[core<br/>进程管理]
                CONFIG[config<br/>配置解析]
                LOG[logger<br/>日志系统]
                PM[plugin_manager<br/>插件管理]
                TR[transport<br/>传输层抽象]
                COMM[communication<br/>通信层]
                MSG[message<br/>报文处理]
                CERT[cert<br/>证书工具]
            end

            subgraph "Trustring Plugin"
                HANDLER[handler<br/>业务路由]
                SIGN[sign<br/>CMS签名]
                VERIFY[verify<br/>CMS验签]
                CERTLD[cert_loader<br/>证书加载]
                ERRMAP[error_code_mapper<br/>错误码映射]
            end
        end

        subgraph "系统依赖"
            OPENSSL[OpenSSL<br/>TLS/CMS]
            SYSTEMD[systemd<br/>服务管理]
            VSOCK[vsock<br/>虚拟机通信]
        end

        subgraph "文件系统"
            CERTS[/etc/cert/cms/<br/>证书目录]
            CFG[/etc/trustruntime/<br/>配置目录]
            LOGDIR[/var/log/trustruntime/<br/>日志目录]
        end
    end

    subgraph "外部客户端"
        CLIENT[Client Application<br/>业务应用]
    end

    MAIN --> CORE
    MAIN --> CONFIG
    MAIN --> LOG
    MAIN --> PM
    MAIN --> COMM

    PM --> HANDLER
    HANDLER --> SIGN
    HANDLER --> VERIFY
    HANDLER --> CERTLD

    SIGN --> OPENSSL
    VERIFY --> OPENSSL
    CERTLD --> CERT
    CERTLD --> CERTS

    COMM --> VSOCK
    COMM --> OPENSSL
    COMM --> MSG

    CORE --> SYSTEMD
    LOG --> LOGDIR
    CONFIG --> CFG

    CLIENT -->|TLS over vsock| COMM
```

### 1.2 部署架构图

```mermaid
graph LR
    subgraph "宿主机"
        LAUNCHER[trt_launcher<br/>机密虚机启动器]
    end

    subgraph "机密计算虚机"
        TRUST[TrustRuntime<br/>签名验签服务]
        APP[业务应用<br/>客户端]
    end

    LAUNCHER -->|映射注入证书| TRUST
    APP -->|vsock CID:3| TRUST

    TRUST -->|返回签名结果| APP
```

---

## 2. 模块说明

### 2.1 Framework 层（通用进程框架）

| 模块 | 职责 | 关键 trait/结构体 |
|------|------|------------------|
| `core` | 进程生命周期管理、信号处理、证书巡检 | `Daemon`, `SignalHandler`, `CertificateChecker` |
| `config` | TOML 配置解析 | `AppConfig` |
| `logger` | 日志初始化与管理 | `init_logger()` |
| `plugin_manager` | 插件生命周期管理 | `Plugin`, `PluginContext`, `PluginManager` |
| `transport` | 传输层抽象接口 | `TransportLayer`, `DataHandler`, `TransportError` |
| `communication` | vsock 通信 + TLS | `VsockTransport`（实现 TransportLayer） |
| `message` | 报文解析/构造 | `VsockHeader`, `VsockMessage` |
| `cert` | 证书加载工具 | PEM/DER 双格式支持 |

### 2.2 Trustring 插件（业务实现）

| 模块 | 职责 | 关键功能 |
|------|------|----------|
| `handler` | 业务路由 | 注册 0x10/0x12/0x14 handler |
| `sign` | CMS 签名 | ECC-256 签名实现 |
| `verify` | CMS 验签 | 验签 + 证书链校验 + CRL 校验 |
| `cert_loader` | 证书管理 | 加载签名/验签证书 |
| `error_code_mapper` | 错误映射 | OpenSSL ErrorStack → result code |

### 2.3 模块依赖关系

```mermaid
graph TB
    MAIN[trustruntime<br/>binary]
    FW[framework<br/>library]
    TS[trustring<br/>library]

    MAIN --> FW
    MAIN --> TS
    TS --> FW

    subgraph framework
        CORE[core]
        CONFIG[config]
        LOG[logger]
        PM[plugin_manager]
        TR[transport]
        COMM[communication]
        MSG[message]
        CERT[cert]
    end

    subgraph trustring
        HDL[handler]
        SGN[sign]
        VRF[verify]
        CLD[cert_loader]
        ECM[error_code_mapper]
    end

    COMM --> MSG
    COMM --> CERT
    COMM --> TR
    PM --> TR
    CORE --> PM
    CORE --> LOG
    CORE --> CONFIG

    HDL --> SGN
    HDL --> VRF
    HDL --> CLD
    SGN --> CLD
    VRF --> CLD
    CLD --> CERT
    VRF --> ECM
    SGN --> ECM
```

---

## 3. 数据流图

### 3.1 签名流程（0x10 → 0x11）

```mermaid
sequenceDiagram
    participant C as Client
    participant VS as VsockTransport
    participant HD as SignHandler
    participant SG as Sign模块
    participant CL as CertLoader
    participant SSL as OpenSSL

    C->>VS: TLS握手
    VS->>C: 双向认证成功

    C->>VS: 请求报文 (type=0x10)
    Note over VS: 校验version/len
    VS->>HD: handle(data)

    HD->>HD: 解析JSON
    HD->>CL: 获取签名证书+私钥
    CL-->>HD: CertPair
    HD->>CL: 获取证书ID (SKID)
    CL-->>HD: SubjectKeyID

    HD->>SG: sign(data + cert_id)
    SG->>SSL: CMS_sign()
    SSL-->>SG: signed_data (DER)
    SG-->>HD: Base64编码

    HD-->>VS: JSON响应
    VS-->>C: 响应报文 (type=0x11)
```

### 3.2 验签+签名流程（0x12 → 0x13）

```mermaid
sequenceDiagram
    participant C as Client
    participant VS as VsockTransport
    participant HD as VerifySignHandler
    participant VF as Verify模块
    participant SG as Sign模块
    participant CL as CertLoader
    participant SSL as OpenSSL

    C->>VS: TLS握手
    VS->>C: 双向认证成功

    C->>VS: 请求报文 (type=0x12)
    VS->>HD: handle(data)

    HD->>HD: 解析JSON
    rect rgb(200, 230, 200)
        Note over HD: 验签步骤
        HD->>VF: verify(to-verify)
        VF->>SSL: CMS_verify()
        SSL-->>VF: 验签结果
        VF->>VF: 证书链校验
        VF->>VF: CRL校验
        VF-->>HD: result=0 (通过)
    end

    rect rgb(230, 200, 200)
        Note over HD: 签名步骤
        HD->>CL: 获取签名证书
        HD->>SG: sign(new_data + to-sign.id)
        SG->>SSL: CMS_sign()
        SSL-->>SG: signed_data
        SG-->>HD: Base64编码
    end

    HD-->>VS: JSON响应
    VS-->>C: 响应报文 (type=0x13)
```

### 3.3 验签流程（0x14 → 0x15）

```mermaid
sequenceDiagram
    participant C as Client
    participant VS as VsockTransport
    participant HD as VerifyHandler
    participant VF as Verify模块
    participant CL as CertLoader
    participant SSL as OpenSSL

    C->>VS: TLS握手
    VS->>C: 双向认证成功

    C->>VS: 请求报文 (type=0x14)
    VS->>HD: handle(data)

    HD->>HD: 解析JSON
    HD->>VF: verify(to-verify)
    VF->>SSL: CMS_verify()
    SSL-->>VF: 验签结果

    VF->>VF: 证书链校验
    VF->>VF: CRL校验

    VF->>CL: 获取本地证书ID
    CL-->>VF: LocalSKID
    VF->>VF: 判断证书身份

    alt 公钥相同
        VF-->>HD: result=2 (证书身份冲突)
    else 公钥不同 且 id匹配
        VF-->>HD: result=0 (本节点签名)
    else 公钥不同 且 id不匹配
        VF-->>HD: result=1 (其他节点签名)
    end

    HD-->>VS: JSON响应
    VS-->>C: 响应报文 (type=0x15)
```

---

## 4. 时序图

### 4.1 服务启动时序

```mermaid
sequenceDiagram
    participant SYS as systemd
    participant MAIN as main.rs
    participant CFG as config
    participant LOG as logger
    participant CHK as cert_checker
    participant VS as VsockTransport
    participant PM as PluginManager
    participant TS as trustring
    participant DAEMON as Daemon

    SYS->>MAIN: 启动进程
    MAIN->>CFG: 加载配置文件
    CFG-->>MAIN: AppConfig

    MAIN->>LOG: 初始化日志
    LOG-->>MAIN: OK

    MAIN->>CHK: 启动时证书检查
    CHK->>CHK: check_all()
    alt 通信证书过期
        CHK-->>MAIN: warn
        MAIN->>DAEMON: notify_status("通信证书已过期")
        MAIN->>DAEMON: notify_ready()
        MAIN->>MAIN: 等待信号（不启动vsock）
    else 正常
        CHK-->>MAIN: OK

        MAIN->>VS: 创建VsockTransport
        VS->>VS: TLS配置
        VS-->>MAIN: OK

        MAIN->>TS: 创建TrustringHandler
        MAIN->>PM: add_plugin(handler)

        MAIN->>PM: init_all(ctx)
        PM->>TS: init()
        TS->>VS: register_handler(0x10)
        TS->>VS: register_handler(0x12)
        TS->>VS: register_handler(0x14)
        TS-->>PM: OK

        MAIN->>VS: start()
        VS-->>MAIN: listener启动

        MAIN->>CHK: start_periodic_check()

        MAIN->>DAEMON: notify_ready()
        SYS->>SYS: 服务就绪

        MAIN->>MAIN: 等待关闭信号
    end
```

### 4.2 服务关闭时序

```mermaid
sequenceDiagram
    participant SYS as systemd
    participant MAIN as main.rs
    participant SIG as SignalHandler
    participant VS as VsockTransport
    participant PM as PluginManager
    participant DAEMON as Daemon

    SYS->>SIG: SIGTERM
    SIG->>SIG: is_shutdown=true
    SIG-->>MAIN: wait返回

    MAIN->>VS: stop()
    VS->>VS: shutdown_signal=true
    VS->>VS: 等待连接关闭（5s超时）
    VS-->>MAIN: OK

    MAIN->>PM: shutdown_all()
    PM->>PM: 调用各插件shutdown()
    PM-->>MAIN: OK

    MAIN->>DAEMON: notify_stopping()
    MAIN->>MAIN: exit(0)
    SYS->>SYS: 服务停止
```

### 4.3 TLS 握手时序

```mermaid
sequenceDiagram
    participant C as Client
    participant VS as VsockTransport
    participant SSL as OpenSSL

    C->>VS: vsock连接请求
    VS->>VS: 获取permit (Semaphore)
    VS->>C: 连接接受

    C->>VS: TLS ClientHello
    VS->>SSL: SslAcceptor.accept()

    VS->>C: TLS ServerHello + Certificate
    C->>C: 验证服务端证书
    C->>C: CRL检查

    C->>VS: TLS Client Certificate
    VS->>SSL: 验证客户端证书
    VS->>VS: CRL检查

    alt 双向认证成功
        VS->>C: TLS Finished
        C->>VS: TLS Finished
        Note over VS,C: TLS连接建立
    else 认证失败
        VS->>C: TLS Alert
        VS->>VS: 关闭连接
    end
```

---

## 5. 接口协议

### 5.1 vsock 报文结构

```mermaid
graph LR
    subgraph "报文结构 (16B header + data)"
        SEQ[seq: u32<br/>4B LE]
        VER[version: u32<br/>4B LE]
        TYPE[msg_type: u32<br/>4B LE]
        LEN[len: u32<br/>4B LE]
        DATA[data: bytes<br/>0-10240B]
    end

    SEQ --> VER --> TYPE --> LEN --> DATA
```

### 5.2 消息类型编码

```mermaid
graph TB
    subgraph "通用错误 (框架层)"
        E00[0x00: 服务端异常]
        E01[0x01: 报文格式异常]
        E02[0x02: 请求报文过长]
    end

    subgraph "签名 (0x10→0x11)"
        R10[0x10: 签名请求]
        R11[0x11: 签名响应]
    end

    subgraph "验签+签名 (0x12→0x13)"
        R12[0x12: 验签+签名请求]
        R13[0x13: 验签+签名响应]
    end

    subgraph "验签 (0x14→0x15)"
        R14[0x14: 验签请求]
        R15[0x15: 验签响应]
    end

    R10 --> R11
    R12 --> R13
    R14 --> R15
```

---

## 6. 错误处理流程

### 6.1 通用错误处理

```mermaid
graph TB
    MSG[接收消息]

    MSG --> V1{version检查}
    V1 -->|不匹配| E01[返回 0x01]

    V1 -->|匹配| LEN{长度检查}
    LEN -->|header不完整| E01
    LEN -->|len与data不一致| E01
    LEN -->|超过10KB| E02[返回 0x02]

    LEN -->|正常| TYPE{type检查}
    TYPE -->|未注册| E01
    TYPE -->|已注册| HDL[调用Handler]

    HDL -->|panic| E00[返回 0x00]
    HDL -->|None| E00
    HDL -->|Some| RES[正常响应]
```

### 6.2 业务错误处理

```mermaid
graph TB
    REQ[业务请求]

    REQ --> JSON{JSON解析}
    JSON -->|失败| R20[result=20]

    JSON -->|成功| B64{Base64解码}
    B64 -->|失败| R21[result=21]

    B64 -->|成功| CERT{证书加载}
    CERT -->|失败| R10[result=10]

    CERT -->|成功| OP{签名/验签操作}
    OP -->|私钥不可用| R11[result=11]
    OP -->|算法错误| R12[result=12]
    OP -->|证书链无效| R03[result=3]
    OP -->|CRL吊销| R04[result=4]
    OP -->|签名不匹配| R05[result=5]
    OP -->|KeyUsage无效| R06[result=6]
    OP -->|格式错误| R07[result=7]

    OP -->|成功| R00[result=0/1/2]
```

---

## 7. 配置结构

```mermaid
graph TB
    subgraph "agent.toml"
        VSOCK[vsock配置]
        LOGC[log配置]
        CERTC[certificate配置]
    end

    subgraph "vsock"
        PORT[port: u32]
        MAX[max_connections: u16]
    end

    subgraph "log"
        LPATH[path: String]
        LLEV[level: String]
        LSIZE[max_file_size: u32]
        LROLL[max_roll_count: u32]
    end

    subgraph "certificate"
        CMS[CMS证书]
        TLS[TLS证书]
    end

    subgraph "CMS证书"
        SCERT[signer_cert]
        SKEY[signer_key]
        CA[ca_root_cert]
        CRL[cms_crl]
    end

    subgraph "TLS证书"
        CCERT[comm_cert]
        CKEY[comm_key]
        CPWD[comm_key_pwd]
        CCA[comm_ca_root]
        CCRL[comm_crl]
    end

    VSOCK --> PORT
    VSOCK --> MAX
    LOGC --> LPATH
    LOGC --> LLEV
    LOGC --> LSIZE
    LOGC --> LROLL
    CERTC --> CMS
    CERTC --> TLS
    CMS --> SCERT
    CMS --> SKEY
    CMS --> CA
    CMS --> CRL
    TLS --> CCERT
    TLS --> CKEY
    TLS --> CPWD
    TLS --> CCA
    TLS --> CCRL
```

---

## 8. 相关文档

- [详细设计文档](detailed-design/)
- [架构决策记录](adr/)
- [接口文档](interface.md)
- [术语表](../CONTEXT.md)