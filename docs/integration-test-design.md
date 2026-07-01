# CMS签名验签服务 集成测试设计文档

| 文档版本 | V1.2 |
| 编写日期 | 2026-06-27 |

---

## 1. 概述

### 1.1 测试目标

本文档定义CMS签名验签服务的集成测试方案，覆盖正常场景、异常场景和边界场景，验证：
- 业务逻辑正确性（签名、验签、验签+签名流程）
- 通信层可靠性（vsock+TLS双向认证）
- 错误处理完整性（错误码返回、边界条件处理）

### 1.2 测试范围

| 范围 | 说明 |
|------|------|
| 正常场景 | 三种典型业务流程（双节点、三节点、单节点） |
| 异常场景 | 验签失败类、签名失败类、验签+签名失败类、请求格式类 |
| 边界场景 | 证书过期、通信层限制、数据边界 |
| 未覆盖范围 | 性能测试、压力测试、安全渗透测试（另设专项） |

### 1.3 测试环境

| 项目 | 要求 |
|------|------|
| 执行环境 | WSL（Windows Subsystem for Linux） |
| 编译环境 | Rust工具链（通过WSL执行cargo命令） |
| 通信层 | vsock内核模块（`vmw_vsock`）、TLS证书体系 |
| 进程管理 | 测试框架自动启动/停止多进程实例 |

---

## 2. 测试架构

### 2.1 分层测试策略

采用分层测试方案，核心业务逻辑通过handler层模块集成测试验证，通信层通过实际连接测试验证：

| 层级 | 测试方式 | 关注点 | 环境 |
|------|----------|--------|------|
| Handler层 | 模块集成测试 | 签名/验签业务逻辑、错误码映射 | WSL，无需vsock |
| 通信层 | 实际连接测试 | vsock连接、TLS双向认证、报文收发 | WSL，需要vsock+真实证书 |

### 2.2 测试crate结构

创建独立测试crate：

```
rust/
├── integration-tests/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs                 # 公共模块导出
│   │   ├── proc_manager.rs        # 进程启动管理
│   │   ├── vsock_client.rs        # vsock客户端封装
│   │   ├── test_utils.rs          # 测试辅助函数（含证书生成）
│   │   └── tests/
│   │       ├── normal_scenarios.rs    # 正常场景测试
│   │       ├── error_scenarios.rs     # 异常场景测试
│   │       ├── boundary_scenarios.rs  # 边界场景测试
│   │       └── communication_tests.rs # 通信层测试
```

### 2.3 证书生成策略

测试证书在 `test_utils.rs` 中通过 OpenSSL 编程生成，无需独立工具：

- 正常证书（CA、节点A/B/C）：运行时生成临时证书
- 过期证书：使用固定时间戳（Unix epoch）构造
- 被吊销证书：生成 CRL 并加入对应证书序列号
- 自签名证书：issuer 与 subject 相同

**证书生成函数**（test_utils.rs）：

```rust
pub fn generate_ca_and_signer() -> (Vec<u8>, Vec<u8>, Vec<u8>);
pub fn generate_expired_signer_cert() -> CertBundle;
pub fn generate_revoked_signer_cert() -> CertBundle;
pub fn generate_self_signed_signer_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>);
pub fn generate_crl_for_cert(ca_pem, ca_key_pem, serial_to_revoke) -> Vec<u8>;
```

---

## 3. 测试环境

### 3.1 WSL环境要求

| 项目 | 要求 |
|------|------|
| WSL版本 | WSL2（支持Linux内核模块） |
| 发行版 | Ubuntu 22.04或更高 |
| vsock模块 | `vmw_vsock`内核模块已加载 |
| Rust工具链 | 1.70+（通过rustup安装） |
| OpenSSL | 3.0+（用于证书生成、TLS握手） |

**vsock模块检查命令**：

```bash
lsmod | grep vsock
# 应显示：vmw_vsock 或 vsock
```

### 3.2 证书体系

#### 3.2.1 CMS签名验签证书

| 证书 | 用途 | 有效期 | 特殊配置 |
|------|------|--------|----------|
| CMS CA根证书 | 签发所有节点签名证书 | 10年 | ECC-256，BasicConstraints: CA |
| 节点A签名证书 | 正常签名测试 | 10年 | SubjectKeyIdentifier扩展 |
| 节点B签名证书 | 正常签名测试 | 10年 | SubjectKeyIdentifier扩展 |
| 节点C签名证书 | 正常签名测试 | 10年 | SubjectKeyIdentifier扩展 |
| 过期签名证书 | 证书过期边界测试 | 已过期（-1天） | 有效期已结束 |
| 被吊销签名证书 | CRL吊销测试 | 10年 | 已加入cms.crl |
| 自签名证书 | 证书链无效测试 | 10年 | 自签名，无CA签发 |

#### 3.2.2 TLS通信证书

| 证书 | 用途 | 有效期 | 特殊配置 |
|------|------|--------|----------|
| TLS CA根证书 | 签发所有TLS证书（除wrong-ca） | 10年 | ECC-256 |
| 另一个TLS CA根证书 | 签发wrong-ca客户端证书 | 10年 | ECC-256，与主CA独立 |
| 节点A/B/C TLS服务端证书 | vsock TLS服务端 | 10年 | 正常证书 |
| 正常客户端TLS证书 | 正常通信测试 | 10年 | 正常证书 |
| 被吊销客户端TLS证书 | CRL吊销测试 | 10年 | 已加入client-crl.crt |
| wrong-ca客户端证书 | CA链不匹配测试 | 10年 | 由other-ca签发，非主CA签发 |
| TLS客户端CRL | 吊销客户端证书校验 | — | 包含revoked.crt |

### 3.3 进程启动管理

测试框架自动管理多进程实例：

| 进程 | vsock端口 | 配置文件 | 证书目录 |
|------|-----------|----------|----------|
| 节点A | 12345 | `/tmp/test-node-a/config.toml` | `test-certs/cms/node-a/`, `test-certs/tls/server/node-a/` |
| 节点B | 12346 | `/tmp/test-node-b/config.toml` | `test-certs/cms/node-b/`, `test-certs/tls/server/node-b/` |
| 节点C | 12347 | `/tmp/test-node-c/config.toml` | `test-certs/cms/node-c/`, `test-certs/tls/server/node-c/` |

**进程管理流程**：

```
启动 → 等待就绪（检测vsock端口） → 执行测试 → 停止进程 → 清理临时文件
```

### 3.4 配置文件模板

**节点配置文件模板**（`config.toml`）：

```toml
[vsock]
port = {{PORT}}

[log]
path = "/tmp/{{NODE_NAME}}/trustring.log"
max_file_size = 10
max_roll_count = 10

[certificate]
signer_cert = "{{CMS_DIR}}/signer.crt"
signer_key = "{{CMS_DIR}}/signer.key"
ca_root_cert = "test-certs/cms/ca.crt"
cms_crl = "test-certs/cms/cms.crl"

comm_cert = "{{TLS_DIR}}/node.crt"
comm_key = "{{TLS_DIR}}/node.key"
comm_ca_root = "test-certs/tls/ca.crt"
```

---

## 4. 测试场景设计

### 4.1 正常场景

| 编号 | 场景名称 | 涉及节点 | 发起者标识传递 | 验证点 |
|------|----------|----------|---------------|--------|
| N01 | 双节点签名验证认证通信 | A、B | idA作为发起者标识，全程传递 | B验签A签名（验签通过即签名），A验签B签名（身份判定） |
| N02 | 三节点签名验证认证通信 | A、B、C | idA作为发起者标识，全程传递 | B验签A签名（验签通过即签名），C验签B签名（身份判定：其他节点） |
| N03 | 单节点签名验证认证通信 | A | idA作为发起者标识，全程传递 | A验签自己签名（身份判定：证书身份冲突） |

**发起者标识**：首次签名者的证书Subject Key ID，在多节点通信链路中始终传递此id，用于追溯签名请求的原始发起者身份。实际签名方可为后续节点（B、C），使用发起者ID签名表示"代签"语义。

**验签职责差异**：
- 验签+签名接口(0x12)：仅验证签名有效性，验签通过即继续签名，不执行身份判定
- 验签接口(0x14)：验签通过后执行身份判定，返回result=0/1/2

### 4.2 异常场景

#### 4.2.1 验签失败类（单独验签接口）

| 编号 | 场景名称 | 错误类型 | 预期result | 说明 |
|------|----------|----------|------------|------|
| E01 | 签名不匹配 | 签名篡改 | 5 | data被篡改，签名验证失败 |
| E02 | 证书链无效 | 证书链 | 3 | 使用自签名证书签名，CA无法验证 |
| E03 | CRL吊销 | CRL | 4 | 签名方证书已加入CMS CRL |
| E04 | CMS格式错误 | 格式 | 6 | signed_data非CMS DER结构 |
| E05 | 请求JSON解析失败 | JSON | 10 | 请求报文字段缺失或类型错误 |
| E06 | Base64解码失败 | Base64 | 11 | signed_data或id非有效Base64 |

#### 4.2.2 签名失败类（单独签名接口）

| 编号 | 场景名称 | 错误类型 | 预期result | 说明 |
|------|----------|----------|------------|------|
| E07 | 签名证书加载失败 | 证书 | 7 | signer.crt文件不存在或损坏 |
| E08 | 签名私钥不可用 | 私钥 | 8 | signer.key文件不存在或损坏 |

#### 4.2.3 验签+签名失败类（验签步骤失败）

| 编号 | 场景名称 | to-verify | to-sign | 验签result | 最终result | signed_data | id |
|------|----------|-----------|---------|------------|------------|-------------|-----|
| E09 | 验签-签名不匹配 | data篡改 | 正常 | 5 | 5 | "" | "" |
| E10 | 验签-证书链无效 | 自签名证书签名 | 正常 | 3 | 3 | "" | "" |
| E11 | 验签-CRL吊销 | 被吊销证书签名 | 正常 | 4 | 4 | "" | "" |
| E12 | 验签-CMS格式错误 | 非CMS结构 | 正常 | 6 | 6 | "" | "" |

**注意**：验签+签名接口(0x12)仅验证签名有效性，验签失败类(result≥3)不执行签名。result=1/2（身份判定结果）不适用于验签+签名接口。

#### 4.2.4 验签+签名失败类（验签通过但签名失败）

| 编号 | 场景名称 | to-verify | to-sign | 验签result | 签名result | 最终result | signed_data | id |
|------|----------|-----------|---------|------------|------------|------------|-------------|-----|
| E15 | 签名-证书加载失败 | 正常（本节点签名） | 本节点证书缺失 | 0 | 7 | 7 | "" | "" |
| E16 | 签名-私钥不可用 | 正常（本节点签名） | 本节点私钥缺失 | 0 | 8 | 8 | "" | "" |

#### 4.2.5 请求格式类错误

| 编号 | 场景名称 | 错误类型 | 预期result | 说明 |
|------|----------|----------|------------|------|
| E17 | to-sign缺失 | JSON | 10 | VerifySignRequest缺少to-sign字段 |
| E18 | to-verify缺失 | JSON | 10 | VerifySignRequest缺少to-verify字段 |
| E19 | to-sign.id格式错误 | Base64 | 11 | to-sign.id非有效Base64 |
| E20 | to-verify.signed_data格式错误 | Base64 | 11 | to-verify.signed_data非有效Base64 |

### 4.3 边界场景

#### 4.3.1 证书过期场景

| 编号 | 场景名称 | 描述 | 预期result | 说明 |
|------|----------|------|------------|------|
| B01 | 签名证书过期 | 使用过期证书签名 | 0 | 签名证书过期不影响签名结果（仅日志warn） |
| B02 | 验签-签名方证书过期 | 验签时签名方证书已过期 | 0/1/2 | 忽略过期错误，正常验签并返回身份判断结果 |

#### 4.3.2 数据边界场景

| 编号 | 场景名称 | 描述 | 预期result | 说明 |
|------|----------|------|------------|------|
| B03 | data为空字符串 | to-sign.data = "" | 0 | 正常签名空数据 |
| B04 | data含特殊字符 | 含中文、UTF-8字符 | 0 | 正常签名 |
| B05 | id为空字符串 | to-verify.id = ""（非Base64） | 11 | Base64解码失败 |

---

### 4.4 通信层测试场景

通信层测试验证vsock连接建立、TLS双向认证握手、报文收发的完整链路。

**执行环境**：仅在WSL（Linux）环境执行，使用 `#[cfg(target_os = "linux")]` 条件编译。Windows环境的TCP fallback不执行TLS验证，不适用于通信层测试。

#### 4.4.1 正常通信场景

| 编号 | 场景名称 | 描述 | 验证点 |
|------|----------|------|--------|
| C01 | TLS双向认证成功 | 正常客户端连接服务端，TLS握手成功，报文收发正常 | 连接成功、收到响应报文 |

#### 4.4.2 TLS认证失败场景

| 编号 | 场景名称 | 客户端证书 | 预期结果 | 说明 |
|------|----------|------------|----------|------|
| C02 | 客户端证书被CRL吊销 | revoked.crt | TLS握手失败 | 客户端证书已加入client-crl.crt，服务端拒绝连接 |
| C03 | CA链不匹配 | wrong-ca.crt | TLS握手失败 | 客户端证书由other-ca签发，服务端CA无法验证 |
| C04 | 客户端证书无效 | 损坏/格式错误的证书 | TLS握手失败 | 证书文件损坏，OpenSSL无法加载 |

**验证方式**：TLS握手失败时，客户端收到 `VsockError::TlsHandshake` 错误，不区分具体失败原因（OpenSSL错误信息不可靠，服务端日志会记录具体原因）。

#### 4.4.3 报文边界场景

| 编号 | 场景名称 | 描述 | 预期type | len | 说明 |
|------|----------|------|----------|-----|------|
| C05 | 报文超长 | vsock报文data > 10KB | 0x02 | 0 | 框架层拦截，返回通用错误 |
| C06 | version不匹配 | version ≠ 0xFFFF0400 | 0x01 | 0 | 框架层拦截，返回通用错误 |

**实现方式**：VsockClient扩展 `send_raw_header()` 方法，测试代码可手动构造非法报文头。

---

## 5. 测试用例详细设计

### 5.1 正常场景用例表

#### N01: 双节点签名验证认证通信

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| N01-1 | 调用A节点签名接口 | `{"to-sign":{"data":"字符串A"}}` | result=0, id=idA, signed_data=signA |
| N01-2 | 调用B节点验签并签名接口 | `{"to-verify":{"data":"字符串A","signed_data":"signA","id":"idA"},"to-sign":{"data":"字符串B","id":"idA"}}` | result=0, id=idA, signed_data=signB |
| N01-3 | 调用A节点验签接口 | `{"to-verify":{"data":"字符串B","signed_data":"signB","id":"idA"}}` | result=0 |

**验证点**：
- 步骤1：签名成功，id为A节点本地证书id
- 步骤2：B验签A签名通过（仅验证签名有效性，不做身份判定），B签名使用idA（代签语义），返回result=0
- 步骤3：A验签B签名，验签通过后执行身份判定：输入id=idA，A本地id=idA，id相同，签名方证书=B证书（公钥不同），返回result=0（id相同优先）

#### N02: 三节点签名验证认证通信

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| N02-1 | 调用A节点签名接口 | `{"to-sign":{"data":"字符串A"}}` | result=0, id=idA, signed_data=signA |
| N02-2 | 调用B节点验签并签名接口 | `{"to-verify":{"data":"字符串A","signed_data":"signA","id":"idA"},"to-sign":{"data":"字符串B","id":"idA"}}` | result=0, id=idA, signed_data=signB |
| N02-3 | 调用C节点验签接口 | `{"to-verify":{"data":"字符串B","signed_data":"signB","id":"idA"}}` | result=1 |

**验证点**：
- 步骤2：B验签A签名通过（仅验证签名有效性，不做身份判定），B签名使用idA（代签语义），返回result=0
- 步骤3：C验签B签名，验签通过后执行身份判定：输入id=idA，C本地id=idC，id不同，签名方证书=B证书（公钥不同），返回result=1（其他节点签名）

#### N03: 单节点签名验证认证通信

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| N03-1 | 调用A节点签名接口 | `{"to-sign":{"data":"字符串A"}}` | result=0, id=idA, signed_data=signA |
| N03-2 | 调用A节点验签并签名接口 | `{"to-verify":{"data":"字符串A","signed_data":"signA","id":"idA"},"to-sign":{"data":"字符串B","id":"idA"}}` | result=0, id=idA, signed_data=signB |
| N03-3 | 调用A节点验签接口 | `{"to-verify":{"data":"字符串B","signed_data":"signB","id":"idA"}}` | result=2 |

**验证点**：
- 步骤2：A验签A签名通过（仅验证签名有效性，不做身份判定），A签名使用idA，返回result=0
- 步骤3：A验签A签名，验签通过后执行身份判定：输入id=idA，A本地id=idA，id相同，签名方证书=A证书（公钥相同），返回result=2（证书身份冲突，优先级高于result=0）

### 5.2 异常场景用例表

#### E01: 签名不匹配（验签接口）

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| E01-1 | 调用A节点签名接口 | `{"to-sign":{"data":"字符串A"}}` | result=0, id=idA, signed_data=signA |
| E01-2 | 调用B节点验签接口 | `{"to-verify":{"data":"字符串B","signed_data":"signA","id":"idA"}}` | result=5 |

**验证点**：签名时data为"字符串A"，验签时传入"字符串B"，签名不匹配。

#### E02: 证书链无效（验签接口）

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| E02-1 | 使用自签名证书签名 | data="字符串A" | signed_data=signSelfSigned |
| E02-2 | 调用B节点验签接口 | `{"to-verify":{"data":"字符串A","signed_data":"signSelfSigned","id":"idSelfSigned"}}` | result=3 |

**验证点**：自签名证书无CA签发，验签方CA无法验证证书链。

#### E03: CRL吊销（验签接口）

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| E03-1 | 使用被吊销证书签名 | data="字符串A" | signed_data=signRevoked |
| E03-2 | 调用B节点验签接口 | `{"to-verify":{"data":"字符串A","signed_data":"signRevoked","id":"idRevoked"}}` | result=4 |

**验证点**：被吊销证书已加入cms.crl，验签时CRL校验失败。

#### E04: CMS格式错误（验签接口）

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| E04-1 | 调用B节点验签接口 | `{"to-verify":{"data":"字符串A","signed_data":"invalid_random_bytes","id":"idA"}}` | result=6 |

**验证点**：signed_data为随机字节，非CMS DER结构。

#### E05: 请求JSON解析失败（验签接口）

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| E05-1 | 调用B节点验签接口 | `{"to-verify":{"data":"字符串A"}}`（缺少signed_data和id字段） | result=10 |

**验证点**：请求报文缺少必填字段，JSON解析失败。

#### E06: Base64解码失败（验签接口）

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| E06-1 | 调用B节点验签接口 | `{"to-verify":{"data":"字符串A","signed_data":"validSign","id":"!!!invalidBase64!!!"}}` | result=11 |

**验证点**：id字段非有效Base64编码。

#### E07-E08: 签名失败类

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| E07-1 | 删除A节点signer.crt | — | — |
| E07-2 | 调用A节点签名接口 | `{"to-sign":{"data":"字符串A"}}` | result=7 |
| E08-1 | 删除A节点signer.key | — | — |
| E08-2 | 调用A节点签名接口 | `{"to-sign":{"data":"字符串A"}}` | result=8 |

#### E09-E14: 验签+签名失败类（验签步骤失败）

**E09: 验签-签名不匹配**

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| E09-1 | 调用A节点签名接口 | `{"to-sign":{"data":"字符串A"}}` | result=0, id=idA, signed_data=signA |
| E09-2 | 调用B节点验签并签名接口 | `{"to-verify":{"data":"字符串B","signed_data":"signA","id":"idA"},"to-sign":{"data":"字符串C","id":"idA"}}` | result=5, signed_data="", id="" |

**验证点**：验签步骤data篡改，验签失败（result=5），不执行签名步骤。

**E10-E14类似，略（见4.2.3表格）**

#### E15-E16: 验签+签名失败类（验签通过但签名失败）

**E15: 签名-证书加载失败**

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| E15-1 | 调用A节点签名接口 | `{"to-sign":{"data":"字符串A"}}` | result=0, id=idA, signed_data=signA |
| E15-2 | 删除B节点signer.crt | — | — |
| E15-3 | 调用B节点验签并签名接口 | `{"to-verify":{"data":"字符串A","signed_data":"signA","id":"idA"},"to-sign":{"data":"字符串B","id":"idA"}}` | result=7, signed_data="", id="" |

**验证点**：验签通过（result=0），签名步骤证书缺失，签名失败（result=7）。

**E16类似，略（见4.2.4表格）**

#### E17-E20: 请求格式类错误

**E17: to-sign缺失**

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| E17-1 | 调用B节点验签并签名接口 | `{"to-verify":{"data":"字符串A","signed_data":"signA","id":"idA"}}`（缺少to-sign） | result=10 |

**验证点**：VerifySignRequest缺少to-sign字段，JSON解析失败。

**E18-E20类似，略（见4.2.5表格）**

### 5.3 边界场景用例表

#### B01: 签名证书过期

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| B01-1 | 使用过期证书配置启动临时进程 | — | — |
| B01-2 | 调用临时进程签名接口 | `{"to-sign":{"data":"字符串A"}}` | result=0 |

**验证点**：签名证书过期不影响签名结果（仅日志warn）。

#### B02: 验签-签名方证书过期

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| B02-1 | 使用过期证书签名 | data="字符串A" | signed_data=signExpired |
| B02-2 | 调用B节点验签接口 | `{"to-verify":{"data":"字符串A","signed_data":"signExpired","id":"idExpired"}}` | result=1 |

**验证点**：忽略签名方证书过期错误，正常验签并返回身份判断结果（其他节点签名）。

#### B03-B05: 数据边界场景

**B03: data为空字符串**

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| B03-1 | 调用A节点签名接口 | `{"to-sign":{"data":""}}` | result=0, signed_data有效 |

**验证点**：正常签名空数据。

**B04-B05类似，略（见4.3.2表格）**

---

### 5.4 通信层场景用例表

**环境要求**：仅WSL（Linux），需vsock模块和真实TLS证书。

#### C01: TLS双向认证成功

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| C01-1 | 启动节点A | 正常TLS证书配置 | 进程启动成功 |
| C01-2 | 客户端连接 | client.crt + client.key | TLS握手成功 |
| C01-3 | 发送签名请求 | `{"to-sign":{"data":"test"}}` | type=0x11, len>0 |

**验证点**：TLS双向认证成功，报文收发正常。不验证业务逻辑（业务逻辑由N01-N03覆盖）。

#### C02: 客户端证书被CRL吊销

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| C02-1 | 启动节点A | 配置client-crl.crt | 进程启动成功 |
| C02-2 | 客户端连接 | revoked.crt + revoked.key | TLS握手失败 |

**验证点**：客户端证书已加入CRL，服务端拒绝TLS连接。

#### C03: CA链不匹配

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| C03-1 | 启动节点A | 正常TLS CA配置 | 进程启动成功 |
| C03-2 | 客户端连接 | wrong-ca.crt + wrong-ca.key | TLS握手失败 |

**验证点**：客户端证书由other-ca签发，服务端CA无法验证，拒绝TLS连接。

#### C04: 客户端证书无效

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| C04-1 | 启动节点A | 正常TLS证书配置 | 进程启动成功 |
| C04-2 | 客户端连接 | 损坏的证书文件 | TLS握手失败 |

**验证点**：证书文件损坏/格式错误，OpenSSL无法加载，TLS握手失败。

#### C05: 报文超长

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| C05-1 | 启动节点A | 正常配置 | 进程启动成功 |
| C05-2 | 客户端连接 | 正常TLS证书 | TLS握手成功 |
| C05-3 | 发送超长报文 | header.len=12000, data>10KB | type=0x02, len=0 |

**验证点**：报文超过10KB上限，框架层拦截返回通用错误（type=0x02）。

**实现方式**：使用 `VsockClient.send_raw_header()` 手动构造非法报文头。

#### C06: version不匹配

| 步骤 | 操作 | 输入 | 预期输出 |
|------|------|------|----------|
| C06-1 | 启动节点A | 正常配置 | 进程启动成功 |
| C06-2 | 客户端连接 | 正常TLS证书 | TLS握手成功 |
| C06-3 | 发送version错误报文 | version=0xFFFF0000 | type=0x01, len=0 |

**验证点**：version不匹配，框架层拦截返回通用错误（type=0x01）。

**实现方式**：使用 `VsockClient.send_raw_header()` 手动构造非法报文头。

---

## 6. 测试执行流程

### 6.1 测试执行命令

```bash
# 1. 进入WSL（Windows环境需要）
wsl

# 2. 进入测试crate目录
cd <PROJECT_ROOT>/rust/integration-tests

# 3. 编译测试
cargo build --release

# 4. 运行全部测试
cargo test --release

# 或运行特定场景
cargo test --release normal_scenarios
cargo test --release error_scenarios
cargo test --release boundary_scenarios
cargo test --release communication_tests
```

**注意**：测试证书由 `test_utils.rs` 在运行时自动生成，无需预生成。

### 6.2 进程启动流程（测试代码内部）

```rust
// 1. 创建临时配置目录
let temp_dir = TempDir::new()?;

// 2. 生成测试证书（运行时生成）
let certs = setup_test_certificates(&temp_dir);

// 3. 写入配置文件
let config = NodeConfig {
    name: "node-a",
    port: 12345,
    cms_cert_path: certs.signer_path,
    cms_key_path: certs.signer_key_path,
    tls_cert_path: ...,
    tls_key_path: ...,
};

// 4. 启动进程
let pm = ProcessManager::new(binary_path, cert_base_path);
pm.start_node(config)?;

// 5. 等待就绪（ProcessManager内部自动检测vsock端口）

// 6. 执行测试
// ...

// 7. 清理（ProcessManager::drop 自动调用 stop_all）
```

### 6.3 清理流程

测试结束后自动清理：

- ProcessManager 的 Drop 实现：自动停止所有进程实例
- TempDir 的 Drop 实现：自动删除临时目录和配置文件
- 测试证书：随临时目录一起删除

---

## 7. 测试代码结构

### 7.1 证书生成辅助函数

**文件**：`rust/integration-tests/src/test_utils.rs`

**功能**：
- 生成CA根证书和签名证书
- 生成过期签名证书（固定时间戳）
- 生成被吊销签名证书（并生成CRL）
- 生成自签名证书
- 构造测试请求JSON
- 解析测试响应

**主要函数**：

```rust
// 证书生成
pub fn generate_ca_and_signer() -> (Vec<u8>, Vec<u8>, Vec<u8>);
pub fn generate_expired_signer_cert() -> CertBundle;
pub fn generate_not_yet_valid_signer_cert() -> CertBundle;
pub fn generate_revoked_signer_cert() -> CertBundle;
pub fn generate_self_signed_signer_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>);
pub fn generate_crl_for_cert(ca_pem, ca_key_pem, serial) -> Vec<u8>;

// 测试辅助
pub fn setup_test_certificates(temp_dir: &TempDir) -> TestCertificates;
pub fn setup_plugin_test_context(temp_dir: &TempDir) -> PluginTestContext;
pub fn build_sign_request(data: &str) -> Vec<u8>;
pub fn build_verify_request(data, signed_b64, cert_id_b64) -> Vec<u8>;
pub fn build_verify_sign_request(verify_data, signed_b64, cert_id_b64, sign_data, sign_id_b64) -> Vec<u8>;
```

### 7.2 进程管理模块

**文件**：`rust/integration-tests/src/proc_manager.rs`

**接口**：

```rust
pub struct NodeConfig {
    pub name: String,
    pub port: u32,
    pub cms_cert_path: PathBuf,
    pub cms_key_path: PathBuf,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub tls_client_crl: Option<PathBuf>,
}

pub struct ProcessInstance {
    pub name: String,
    pub port: u32,
    pub child: Child,
    pub temp_dir: TempDir,
}

pub struct ProcessManager {
    processes: Arc<Mutex<HashMap<String, ProcessInstance>>,
    binary_path: PathBuf,
    cert_base_path: PathBuf,
}

impl ProcessManager {
    pub fn new(binary_path: PathBuf, cert_base_path: PathBuf) -> Self;
    pub fn start_node(&self, config: NodeConfig) -> Result<(), ProcessError>;
    pub fn start_multiple(&self, configs: Vec<NodeConfig>) -> Result<(), ProcessError>;
    pub fn stop_node(&self, name: &str) -> Result<(), ProcessError>;
    pub fn stop_all(&self) -> Result<(), ProcessError>;
}

impl Drop for ProcessManager {
    fn drop(&mut self); // 自动清理所有进程
}
```

### 7.3 vsock客户端模块

**文件**：`rust/integration-tests/src/vsock_client.rs`

**接口**：

```rust
pub struct VsockClient {
    stream: Box<dyn VsockStream>,
}

impl VsockClient {
    pub fn connect(
        port: u32,
        tls_ca_cert: &PathBuf,
        tls_client_cert: &PathBuf,
        tls_client_key: &PathBuf,
    ) -> Result<Self, VsockError>;

    pub fn sign(&mut self, data: &str) -> Result<SignResponse, VsockError>;
    pub fn verify_and_sign(&mut self, req: VerifySignRequest) -> Result<VerifySignResponse, VsockError>;
    pub fn verify(&mut self, data: &str, signed_data: &str, id: &str) -> Result<VerifyResponse, VsockError>;
    pub fn verify_raw(&mut self, raw_json: String) -> Result<VerifyResponse, VsockError>;
    pub fn close(&mut self) -> Result<(), VsockError>;

    // 用于边界测试：手动构造报文头
    pub fn send_raw_header(&mut self, version: u32, msg_type: u32, len: u32) -> Result<RawResponse, VsockError>;
}
```

### 7.4 测试用例代码结构

**文件**：`rust/integration-tests/src/tests/normal_scenarios.rs`

```rust
#[test]
fn n01_two_node_sign_verify() {
    // 启动节点A、B
    // 执行N01-1/2/3步骤
    // 验证结果
    // 清理进程
}

#[test]
fn n02_three_node_sign_verify() {
    // 启动节点A、B、C
    // 执行N02-1/2/3步骤
    // 验证结果
    // 清理进程
}

#[test]
fn n03_single_node_sign_verify() {
    // 启动节点A
    // 执行N03-1/2/3步骤
    // 验证结果
    // 清理进程
}
```

**文件**：`rust/integration-tests/src/tests/error_scenarios.rs`

```rust
#[test]
fn e01_signature_mismatch() { ... }

#[test]
fn e02_certificate_chain_invalid() { ... }

// ... 其他异常场景测试
```

**文件**：`rust/integration-tests/src/tests/boundary_scenarios.rs`

```rust
#[test]
fn b01_expired_signer_cert() { ... }

#[test]
fn b03_message_too_long() { ... }

// ... 其他边界场景测试
```

---

## 修订历史

| 版本 | 日期 | 修订内容 |
|------|------|----------|
| V1.2 | 2026-06-27 | 修正测试代码结构：移除独立证书生成工具，改为test_utils.rs运行时生成；更新进程管理和vsock_client接口描述与实际代码一致 |
| V1.1 | 2026-06-24 | 新增通信层测试设计：4.4通信层测试场景（C01-C06）、5.4通信层场景用例表、扩展TLS异常测试证书、调整边界场景编号 |
| V1.0 | 2026-06-23 | 初始版本：定义集成测试架构、场景设计、用例详细设计、执行流程 |