# TrustRuntime 使用指南

| 文档版本 | V1.0 |
| 编写日期 | 2026-06-29 |

---

## 1. 概述

TrustRuntime 是 CMS 签名验签服务，部署于机密计算虚机中，通过 vsock 提供签名、验签+签名、验签三类安全接口。通信层采用 TLS over vsock 双向认证，确保传输链路安全。

---

## 2. 系统要求

### 2.1 操作系统

- Linux 内核版本 >= 4.8（vsock 支持）
- systemd 服务管理器
- glibc >= 2.17

### 2.2 依赖

| 依赖 | 版本要求 | 说明 |
|------|----------|------|
| OpenSSL | >= 1.1.1 | TLS 通信、CMS 签名验签 |
| systemd | 任意版本 | 服务管理 |

### 2.3 硬件资源

| 资源 | 限制 | 说明 |
|------|------|------|
| CPU | 10% | systemd CPUQuota 限制 |
| 内存 | 30MB | systemd MemoryMax 限制 |

---

## 3. 安装

### 3.1 前置准备

安装前需完成以下准备：

**1. 准备证书文件**

参见 [4.3 证书配置](#43-证书配置)，确保证书文件已放置到正确路径。

**2. 准备配置文件**

RPM 安装会在 `/etc/trustruntime/agent.toml` 创建配置模板。请根据实际证书路径修改配置文件。

参见 [第4章 配置](#4-配置) 了解配置项详情。

### 3.2 RPM 安装

```bash
rpm -ivh trustruntime-*.rpm
```

RPM 安装自动执行：

- 复制二进制到 `/usr/bin/trustruntime`
- 安装配置模板到 `/etc/trustruntime/agent.toml`
- 创建日志目录 `/var/log/trustruntime`
- 安装 systemd 服务

安装完成后，需根据实际证书路径修改配置文件，然后手动启动服务：

```bash
systemctl enable trustruntime
systemctl start trustruntime
```

### 3.3 验证安装

```bash
systemctl status trustruntime
```

输出示例：

```
● trustruntime.service - TrustRuntime CMS Signing Service
   Loaded: loaded (/usr/lib/systemd/system/trustruntime.service; enabled)
   Active: active (running) since Mon 2026-06-29 10:00:00 UTC; 1min ago
 Main PID: 1234 (trustruntime)
```

---

## 4. 配置

### 4.1 配置文件

配置文件路径：`/etc/trustruntime/agent.toml`

文件权限要求：`640 (root:root)`

### 4.2 配置项说明

#### vsock 通信配置

```toml
[vsock]
port = 12345              # vsock 端口号（必填）
max_connections = 16      # 最大并发连接数（可选，默认 16）
```

#### 日志配置

```toml
[log]
path = "/var/log/trustruntime/trustring.log"  # 日志文件路径（必填）
level = "info"            # 日志级别（可选，默认 info）
max_file_size = 10        # 单个日志文件最大大小，单位 MB（必填）
max_roll_count = 10       # 日志回滚文件个数（必填）
```

日志级别可选值：`trace`, `debug`, `info`, `warn`, `error`

#### 证书路径配置

```toml
[certificate]
# --- 签名验签证书（CMS）---
signer_cert = "/etc/cert/cms/signer.crt"       # 签名证书（必填）
signer_key = "/etc/cert/cms/signer.key"        # 签名私钥（必填，无密码）
ca_root_cert = "/etc/cert/cms/ca_root.crt"     # CA 根证书（必填）
cms_crl = "/etc/cert/cms/cms.crl"              # CRL（可选）

# --- 通信证书（TLS）---
comm_cert = "/etc/cert/cms/communication/certificate.crt"  # 通信证书（必填）
comm_key = "/etc/cert/cms/communication/private.key"       # 通信私钥（必填）
comm_key_pwd = "/etc/cert/cms/communication/key_pwd.txt"   # 私钥密码（可选）
comm_ca_root = "/etc/cert/cms/communication/ca_root.crt"  # CA 根证书（必填）
comm_crl = "/etc/cert/cms/communication/cert.crl"          # CRL（可选）
```

### 4.3 证书配置

#### 证书类型

| 证书类型 | 用途 | 路径 |
|----------|------|------|
| 通信证书（TLS） | TLS 双向认证 | `/etc/cert/cms/communication/` |
| 签名证书（CMS） | CMS 签名验签 | `/etc/cert/cms/` |

#### 证书格式

支持 PEM 和 DER 格式，服务端自动识别。

#### 私钥保护

| 私钥类型 | 密码保护 |
|----------|----------|
| 签名私钥 | 无密码保护 |
| 通信私钥 | 支持密码保护（key_pwd.txt） |

#### CRL 配置

CRL（证书吊销列表）为可选配置，不配置时跳过 CRL 校验。

### 4.4 配置示例

最小配置：

```toml
[vsock]
port = 12345

[log]
path = "/var/log/trustruntime/trustring.log"
max_file_size = 10
max_roll_count = 10

[certificate]
signer_cert = "/etc/cert/cms/signer.crt"
signer_key = "/etc/cert/cms/signer.key"
ca_root_cert = "/etc/cert/cms/ca_root.crt"
comm_cert = "/etc/cert/cms/communication/certificate.crt"
comm_key = "/etc/cert/cms/communication/private.key"
comm_ca_root = "/etc/cert/cms/communication/ca_root.crt"
```

---

## 5. 运维

### 5.1 服务管理

#### 启动服务

```bash
systemctl start trustruntime
```

#### 停止服务

```bash
systemctl stop trustruntime
```

#### 重启服务

```bash
systemctl restart trustruntime
```

#### 查看服务状态

```bash
systemctl status trustruntime
```

#### 查看服务日志

```bash
journalctl -u trustruntime -f
```

### 5.2 日志查看

#### 日志文件位置

```
/var/log/trustruntime/trustring.log
/var/log/trustruntime/trustring.log.1
/var/log/trustruntime/trustring.log.2.gz
...
```

#### 日志格式

```
2026-06-29T10:00:00.000Z INFO trustruntime::core: Service started
2026-06-29T10:00:00.100Z INFO trustruntime::vsock: Listening on vsock port 12345
```

#### 日志轮转

- 单文件最大 10MB（可配置）
- 保留 10 个回滚文件（可配置）
- 旧文件自动 gzip 压缩

### 5.3 证书管理

#### 证书更新流程

1. 替换证书文件

```bash
# 备份旧证书
cp /etc/cert/cms/signer.crt /etc/cert/cms/signer.crt.bak
cp /etc/cert/cms/signer.key /etc/cert/cms/signer.key.bak

# 复制新证书
cp new-signer.crt /etc/cert/cms/signer.crt
cp new-signer.key /etc/cert/cms/signer.key
```

2. 重启服务

```bash
systemctl restart trustruntime
```

**注意**：证书不支持热更新，必须重启服务才能生效。

#### 证书过期巡检

服务启动后台线程每 24 小时检查所有证书有效期：

- 证书即将过期或已过期时打印 warn 日志
- 不影响业务处理，仅告警

查看证书过期告警：

```bash
grep "certificate.*expired" /var/log/trustruntime/trustring.log
```

#### 通信证书过期处理

| 时机 | 行为 |
|------|------|
| 启动时过期 | vsock 启动失败，进程保持运行，systemd status 显示告警 |
| 运行中过期 | 仅 warn 日志，不关闭 vsock listener |

客户端可通过 TLS 握手失败感知服务端证书过期。

### 5.4 监控

#### systemd 状态

```bash
systemctl status trustruntime
```

输出示例：

```
● trustruntime.service - TrustRuntime CMS Signing Service
   Loaded: loaded (/usr/lib/systemd/system/trustruntime.service; enabled)
   Active: active (running) since Mon 2026-06-29 10:00:00 UTC; 1h ago
 Main PID: 1234 (trustruntime)
    Tasks: 5 (limit: 4915)
   Memory: 15M (max: 30M)
   CGroup: /system.slice/trustruntime.service
           └─1234 /usr/bin/trustruntime --config /etc/trustruntime/agent.toml
```

#### 资源限制

服务受 systemd 资源限制：

- CPUQuota=10%
- MemoryMax=30M

超出限制时 systemd 会自动重启服务。

---

## 6. 故障排查

### 6.1 服务无法启动

#### 检查配置文件

```bash
# 检查配置文件是否存在
ls -la /etc/trustruntime/agent.toml

# 检查配置文件权限（应为 640）
stat /etc/trustruntime/agent.toml
```

#### 检查证书文件

```bash
# 检查所有证书文件是否存在
ls -la /etc/cert/cms/signer.crt
ls -la /etc/cert/cms/signer.key
ls -la /etc/cert/cms/ca_root.crt
ls -la /etc/cert/cms/communication/certificate.crt
ls -la /etc/cert/cms/communication/private.key
ls -la /etc/cert/cms/communication/ca_root.crt
```

#### 检查日志

```bash
journalctl -u trustruntime -n 50
```

常见错误：

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `配置文件不存在` | agent.toml 缺失 | 创建配置文件 |
| `证书加载失败` | 证书文件缺失或格式错误 | 检查证书路径和格式 |
| `通信证书已过期` | TLS 证书过期 | 更新通信证书并重启 |

### 6.2 vsock 连接失败

#### 检查 vsock 模块

```bash
# 检查 vsock 模块是否加载
lsmod | grep vsock

# 手动加载 vsock 模块
modprobe vhost_vsock
```

#### 检查端口占用

```bash
# 查看当前 vsock 端口使用情况（需要 root）
ss -p | grep vsock
```

#### 检查防火墙

vsock 是虚拟机内部通信，通常不受防火墙限制。

### 6.3 TLS 握手失败

#### 检查通信证书

```bash
# 检查证书有效期
openssl x509 -in /etc/cert/cms/communication/certificate.crt -noout -dates

# 检查证书链
openssl verify -CAfile /etc/cert/cms/communication/ca_root.crt \
  /etc/cert/cms/communication/certificate.crt
```

#### 检查 CRL

```bash
# 检查 CRL 格式
openssl crl -in /etc/cert/cms/communication/cert.crl -noout -text
```

### 6.4 签名/验签失败

#### 检查结果码

参见 [接口文档](interface.md#6-结果码) 了解结果码含义。

常见结果码：

| result | 含义 | 解决方案 |
|--------|------|----------|
| 0 | 成功 | - |
| 7 | 证书加载失败 | 检查签名证书路径 |
| 8 | 私钥不可用 | 检查私钥文件权限 |
| 9 | 签名算法错误 | 仅支持 ECC-256 |

### 6.5 调试模式

启用详细日志：

```toml
[log]
level = "debug"  # 或 "trace"
```

或通过环境变量：

```bash
RUST_LOG=debug systemctl restart trustruntime
```

---

## 7. 安全建议

### 7.1 证书管理

- 定期检查证书有效期
- 建议证书过期前 30 天更新
- 更新证书后及时重启服务
- 备份私钥文件到安全位置

### 7.2 日志管理

- 定期清理或归档旧日志
- 监控日志中的异常告警

---

## 8. 相关文档

- [接口文档](interface.md)
- [架构设计](architecture.md)
- [FAQ](faq.md)
- [术语表](../CONTEXT.md)