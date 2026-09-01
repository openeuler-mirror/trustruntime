# TrustRuntime

CMS签名验签服务，部署于机密计算虚机中，通过vsock提供签名、验签+签名、验签三类安全接口。

## 架构

```
trustruntime/
├── rust/                    # Cargo workspace
│   ├── framework/           # 通用进程框架 (trustruntime-framework)
│   ├── trustruntime/        # 主程序入口
│   ├── plugins/trustring/   # 签名验签业务插件
│   ├── integration-tests/   # 集成测试
│   ├── tools/cert-gen/      # 测试证书生成工具
│   └── scripts/             # 开发测试脚本
├── docs/                    # 文档
│   ├── interface.md         # 接口文档
│   ├── user-guide.md        # 使用指南
│   ├── faq.md               # FAQ
│   └── contributing.md      # 开发指南
├── conf/                    # 默认配置
├── packaging/               # RPM打包
├── CONTEXT.md               # 术语表
├── AGENTS.md                # Agent指令
└── .opencode/               # opencode配置
```

## 快速开始

### 1. 生成测试证书

使用 cert-gen 工具快速生成测试证书：

```bash
cd rust
cargo run -p cert-gen -- --output-dir /tmp/test-certs --force
```

### 2. 放置证书文件

将生成的证书放置到系统路径：

```bash
# 创建证书目录
sudo mkdir -p /etc/cert/cms /etc/cert/server

# 复制 CMS 证书
sudo cp /tmp/test-certs/cms/node-a/signer.crt /etc/cert/cms/signer.crt
sudo cp /tmp/test-certs/cms/node-a/signer.key /etc/cert/cms/signer.key
sudo cp /tmp/test-certs/cms/node-a/ca_root.crt /etc/cert/cms/ca_root.crt

# 复制 TLS 证书
sudo cp /tmp/test-certs/tls/server/node-a/certificate.crt /etc/cert/server/certificate.crt
sudo cp /tmp/test-certs/tls/server/node-a/private.key /etc/cert/server/private.key
sudo cp /tmp/test-certs/tls/server/node-a/key_pwd.txt /etc/cert/server/key_pwd.txt
sudo cp /tmp/test-certs/tls/server/node-a/ca_root.crt /etc/cert/server/ca_root.crt

# 设置权限
sudo chmod 600 /etc/cert/cms/signer.key
sudo chmod 600 /etc/cert/server/private.key
sudo chmod 600 /etc/cert/server/key_pwd.txt
```

### 3. 准备配置文件

```bash
sudo mkdir -p /etc/trustruntime
sudo cp conf/agent.toml /etc/trustruntime/agent.toml
```

### 4. 构建项目

```bash
cd rust
cargo build --release
```

### 5. 启动服务（后台运行）

```bash
nohup ./target/release/trustruntime --config /etc/trustruntime/agent.toml > /tmp/trustruntime.log 2>&1 &
```

查看服务日志：

```bash
tail -f /tmp/trustruntime.log
```

或查看默认日志文件：

```bash
tail -f /var/log/trustruntime/trustruntime.log
```

### 6. 测试服务连接

#### 6.1 准备测试配置文件

创建文件 `/tmp/cms-test-config.toml`，内容如下：

```toml
[connection]
port = 6174

[tls_client]
ca_cert = "/tmp/test-certs/tls/lcne/node-a/ca_root.crt"
client_cert = "/tmp/test-certs/tls/lcne/node-a/certificate.crt"
client_key = "/tmp/test-certs/tls/lcne/node-a/private.key"
client_key_pwd = "/tmp/test-certs/tls/lcne/node-a/key_pwd.txt"

[cms_certs]
ca_cert = "/tmp/test-certs/cms/node-a/ca_root.crt"
signer_cert = "/tmp/test-certs/cms/node-a/signer.crt"
signer_key = "/tmp/test-certs/cms/node-a/signer.key"

[server]
binary_path = "trustruntime"
```

#### 6.2 编译并运行测试工具

```bash
# 编译 cms-test-cli
cargo build --release -p cms-test-cli

# 运行测试
./target/release/cms-test-cli --config /tmp/cms-test-config.toml
```

#### 6.3 测试签名接口

在 cms-test-cli REPL 界面中执行：

```
> connect
Connected to vsock://1:6174

> sign '{"to-sign":{"data":"hello world"}}'
Response:
{
  "signed_data": "MIIM...",
  "id": "abc123...",
  "result": 0
}

> quit
```

服务连接成功，项目可用性验证完成。

### 7. 停止服务

```bash
pkill -f trustruntime
```

> **Windows用户替代方案**：使用WSL执行上述命令，参见 `.opencode/skills/wsl-cargo/SKILL.md`。

## 接口

| 类型 | 功能 |
|------|------|
| 0x10→0x11 | 签名：sign(data + 本地证书id) |
| 0x12→0x13 | 验签+签名：先验签，再签名 |
| 0x14→0x15 | 验签：验证签名并判断证书身份 |

## 文档

### 使用者

- [使用指南](docs/user-guide.md) - 安装、配置、运维
- [接口文档](docs/interface.md) - API 参考
- [FAQ](docs/faq.md) - 常见问题

### 开发者

- [开发指南](docs/contributing.md) - 贡献流程、编码规范

### 其他

- [术语表](CONTEXT.md) - 项目术语
- [变更日志](CHANGELOG.md) - 版本历史
- [示例代码](rust/examples/) - 使用示例

## 部署

参见 [packaging/README.md](packaging/README.md)