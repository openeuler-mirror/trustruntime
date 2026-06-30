# TrustRuntime FAQ

| 文档版本 | V1.0 |
| 编写日期 | 2026-06-29 |

---

## 证书相关

### Q: 证书过期怎么办？

**A**: 根据证书类型处理方式不同：

| 证书类型 | 启动时过期 | 运行中过期 |
|----------|------------|------------|
| 通信证书（TLS） | vsock 启动失败，进程保持运行 | 仅 warn 日志，不影响业务 |
| 签名证书（CMS） | warn 日志，服务正常启动 | 仅 warn 日志，不影响签名 |

**处理步骤**：

1. 替换过期证书文件
2. 重启服务：`systemctl restart trustruntime`

---

### Q: 如何更新证书？

**A**: 证书不支持热更新，必须重启服务。

**更新流程**：

```bash
# 1. 备份旧证书
cp /etc/cert/cms/signer.crt /etc/cert/cms/signer.crt.bak
cp /etc/cert/cms/signer.key /etc/cert/cms/signer.key.bak

# 2. 复制新证书（保持文件名不变）
cp new-signer.crt /etc/cert/cms/signer.crt
cp new-signer.key /etc/cert/cms/signer.key

# 3. 重启服务
systemctl restart trustruntime

# 4. 验证服务状态
systemctl status trustruntime
```

---

### Q: CRL 校验失败如何排查？

**A**: CRL（证书吊销列表）校验失败返回 result=4。

**排查步骤**：

1. 检查 CRL 文件是否存在

```bash
ls -la /etc/cert/cms/cms.crl
ls -la /etc/cert/cms/communication/cert.crl
```

2. 检查 CRL 格式

```bash
openssl crl -in /etc/cert/cms/cms.crl -noout -text
```

3. 检查证书是否在 CRL 中

```bash
openssl crl -in /etc/cert/cms/cms.crl -noout -text | grep "Serial Number"
```

4. 如果不需要 CRL 校验，在配置中注释掉：

```toml
[certificate]
# cms_crl = "/etc/cert/cms/cms.crl"  # 注释掉跳过 CRL 校验
```

---

### Q: 证书格式错误怎么办？

**A**: 服务支持 PEM 和 DER 格式自动识别。

常见错误：

- 文件内容损坏
- 文件编码问题（如 UTF-8 BOM）
- 证书链不完整

**排查命令**：

```bash
# 检查证书格式和内容
openssl x509 -in /etc/cert/cms/signer.crt -noout -text

# 检查私钥
openssl ec -in /etc/cert/cms/signer.key -noout -text

# 检查证书链
openssl verify -CAfile /etc/cert/cms/ca_root.crt /etc/cert/cms/signer.crt
```

---

## 连接相关

### Q: vsock 连接失败怎么办？

**A**: 可能原因：

| 原因 | 解决方案 |
|------|----------|
| vsock 模块未加载 | `modprobe vhost_vsock` |
| 服务未启动 | `systemctl start trustruntime` |
| 端口配置错误 | 检查 agent.toml 中 vsock.port |
| 并发连接超限（>16） | 等待现有连接释放 |

**排查步骤**：

```bash
# 检查 vsock 模块
lsmod | grep vsock

# 检查服务状态
systemctl status trustruntime

# 查看服务日志
journalctl -u trustruntime -n 50
```

---

### Q: TLS 握手失败怎么办？

**A**: TLS 握手失败可能原因：

| 原因 | 解决方案 |
|------|----------|
| 客户端证书无效 | 检查客户端证书链 |
| 服务端证书过期 | 更新通信证书 |
| CRL 校验失败 | 检查通信 CRL |
| TLS 版本不兼容 | 确保客户端支持 TLS 1.2/1.3 |

**排查命令**：

```bash
# 检查服务端证书有效期
openssl x509 -in /etc/cert/cms/communication/certificate.crt -noout -dates

# 检查证书链
openssl verify -CAfile /etc/cert/cms/communication/ca_root.crt \
  /etc/cert/cms/communication/certificate.crt

# 检查 CRL
openssl crl -in /etc/cert/cms/communication/cert.crl -CAfile \
  /etc/cert/cms/communication/ca_root.crt -noout
```

---

### Q: 连接超时怎么办？

**A**: 服务端无请求超时机制，由客户端管理超时。

可能原因：

- 服务端处理耗时过长
- 网络延迟
- 服务端资源受限（CPU/Memory）

**建议**：

- 客户端设置合理超时时间（如 30s）
- 监控服务端资源使用情况
- 检查服务日志是否有异常

---

## 签名/验签相关

### Q: 签名返回 result=7（证书加载失败）？

**A**: 原因：签名证书或私钥加载失败。

**排查步骤**：

```bash
# 检查证书文件
ls -la /etc/cert/cms/signer.crt /etc/cert/cms/signer.key

# 检查证书格式
openssl x509 -in /etc/cert/cms/signer.crt -noout -text

# 检查私钥（ECC-256）
openssl ec -in /etc/cert/cms/signer.key -noout -text

# 检查私钥权限
stat /etc/cert/cms/signer.key  # 应为 600 或 400
```

---

### Q: 签名返回 result=8（私钥不可用）？

**A**: 原因：签名私钥无法使用。

可能原因：

- 私钥文件损坏
- 私钥与证书不匹配
- 私钥权限问题（无法读取）
- 私钥加密但未提供密码（签名私钥不支持密码）

**注意**：签名私钥不支持密码保护，如需加密私钥应解密后使用。

---

### Q: 签名返回 result=9（签名算法错误）？

**A**: 服务仅支持 ECC-256 签名算法。

可能原因：

- 证书使用非 ECC-256 算法
- 私钥算法与证书不匹配

**检查证书算法**：

```bash
openssl x509 -in /etc/cert/cms/signer.crt -noout -text | grep "Public Key Algorithm"
# 应显示: Public Key Algorithm: id-ecPublicKey
# ASN1 OID: prime256v1 (ECC-256)
```

---

### Q: 验签返回 result=3（证书链无效）？

**A**: 原因：签名方证书链验证失败。

**排查步骤**：

1. 检查 CA 根证书是否正确

```bash
openssl verify -CAfile /etc/cert/cms/ca_root.crt signer.crt
```

2. 确保验签时提供的证书 ID 对应的证书链完整

3. 检查中间证书是否缺失

---

### Q: 验签返回 result=4（CRL 吊销）？

**A**: 原因：签名方证书已被吊销。

**处理方式**：

- 如不需要 CRL 校验，在配置中注释掉 `cms_crl`
- 更新 CRL 文件以移除已恢复的证书
- 联系证书管理员确认证书状态

---

### Q: 验签返回 result=5（签名不匹配）？

**A**: 原因：签名值与数据不匹配。

可能原因：

- data 字段与签名时使用的 data 不一致
- signed_data 被篡改或损坏
- 签名方证书 ID 不正确

---

### Q: 验签返回 result=6（格式错误）？

**A**: 原因：CMS DER 结构解析失败。

可能原因：

- signed_data 不是有效的 CMS DER 结构
- Base64 解码失败（返回 result=11）
- signed_data 被篡改

---

### Q: 签名/验签返回 result=10（JSON解析失败）？

**A**: 原因：请求消息 JSON 格式错误。

可能原因：

- JSON 字段缺失（如缺少 `to-sign`、`to-verify`）
- JSON 格式不符合规范（如字段类型错误）
- JSON 语法错误（如括号不匹配、引号错误）

**排查步骤**：

```bash
# 检查请求 JSON 格式
cat request.json | jq .  # 使用 jq 验证 JSON 格式

# 检查必需字段
# 签名接口需要：to-sign.data
# 验签接口需要：to-verify.data, to-verify.signed_data, to-verify.id
```

---

### Q: 签名/验签返回 result=11（Base64解码失败）？

**A**: 原因：Base64 字段解码失败。

可能原因：

- signed_data 不是有效的 Base64 编码
- id 字段包含无效 Base64 字符
- Base64 字符串格式错误（如缺少填充字符）

**排查命令**：

```bash
# 验证 Base64 编码是否有效
echo "your_base64_string" | base64 -d

# 检查证书 Subject Key ID 格式
openssl x509 -in cert.pem -noout -text | grep "Subject Key Identifier"
```

---

### Q: result=1 和 result=2 的区别？

**A**: 两者都是验签通过的合法结果：

| result | 含义 | 说明 |
|--------|------|------|
| 1 | 其他节点签名 | 验签有效，签名方证书 ID ≠ 本地证书 ID |
| 2 | 证书身份冲突 | 验签有效，签名方公钥 == 本地公钥（但 ID 不同） |

**优先级**：result=2 > result=1

- result=2 是安全告警，表示三次请求（0x10,0x12,0x14）均在一个上节点完成
- result=1 是正常结果，表示三次请求（0x10,0x12,0x14）分别在三个节点上完成，首次签名请求和最后一次验签请求不是同一节点

---

## 部署相关

### Q: RPM 安装后服务无法启动？

**A**: 常见原因：

| 原因 | 解决方案 |
|------|----------|
| 配置文件缺失 | 检查 `/etc/trustruntime/agent.toml` |
| 证书文件缺失 | 检查 `/etc/cert/cms/` 目录 |
| 证书路径配置错误 | 检查配置文件中 certificate 部分 |
| vsock 模块未加载 | `modprobe vhost_vsock` |

**排查命令**：

```bash
# 查看详细日志
journalctl -u trustruntime -n 100

# 检查配置文件
cat /etc/trustruntime/agent.toml

# 检查证书目录
ls -laR /etc/cert/cms/
```

---

### Q: 日志文件在哪里？

**A**: 日志文件路径配置在 `agent.toml`：

```toml
[log]
path = "/var/log/trustruntime/trustring.log"
```

默认路径：`/var/log/trustruntime/trustring.log`

**查看日志**：

```bash
# 查看最新日志
tail -f /var/log/trustruntime/trustring.log

# 查看历史日志
ls -la /var/log/trustruntime/

# systemd 日志
journalctl -u trustruntime -f
```

---

### Q: 如何调试？

**A**: 启用详细日志级别：

**方式一**：修改配置文件

```toml
[log]
level = "debug"  # 或 "trace"
```

**方式二**：环境变量

```bash
RUST_LOG=debug systemctl restart trustruntime
```

**方式三**：手动启动（开发环境）

```bash
cd rust
cargo build
./target/debug/trustruntime --config ../conf/agent.toml
```

---

### Q: 服务内存超限被重启？

**A**: systemd 配置 MemoryMax=30M。

超出内存限制时 systemd 会自动重启服务。

**排查步骤**：

```bash
# 查看服务状态
systemctl status trustruntime

# 查看内存使用
systemctl show trustruntime --property=MemoryCurrent

# 查看重启历史
journalctl -u trustruntime | grep "restart"
```

**可能原因**：

- 并发连接过多
- 单次请求数据过大
- 内存泄漏

---

### Q: 如何监控服务状态？

**A**: 使用 systemd 命令：

```bash
# 服务状态
systemctl status trustruntime

# 资源使用
systemctl show trustruntime --property=MemoryCurrent,CPUUsageNSec

# 日志监控
journalctl -u trustruntime -f

# 检查证书过期告警
grep "expired" /var/log/trustruntime/trustring.log
```

---

## 相关文档

- [使用指南](user-guide.md)
- [接口文档](interface.md) - 完整结果码定义
- [术语表](../CONTEXT.md) - 术语解释
- [架构设计](architecture.md)