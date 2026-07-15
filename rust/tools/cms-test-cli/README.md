# cms-test-cli

CMS签名验签服务手工测试工具，提供交互式 REPL 界面，支持手工交互测试、性能测试、并发测试、安全测试。

## 功能

- **手工交互测试**: 人工输入参数，验证签名(0x10)、验签(0x14)、验签+签名(0x12)接口
- **性能测试**: 测量单接口响应时间、吞吐量(QPS)
- **并发测试**: 验证16连接并发限制、测量并发吞吐量
- **安全测试**: 协议层攻击、证书层攻击、TLS层攻击测试
- **预置场景**: 执行两节点/三节点/错误链路/边界测试场景

## 环境要求

| 项目 | 要求 |
|------|------|
| 执行环境 | WSL 或 Linux |
| vsock模块 | `vmw_vsock` 或 `vsock_loopback` 已加载 |
| Rust | 1.70+ |
| OpenSSL | 3.0+ |

## 快速开始

### 1. 准备配置文件

复制示例配置文件并修改证书路径：

```bash
cp rust/tools/cms-test-cli/config.example.toml my-config.toml
# 编辑 my-config.toml，设置正确的证书路径
```

### 2. 启动测试工具

```bash
wsl bash -c "source ~/.cargo/env && cd rust && cargo run -p cms-test-cli -- --config /path/to/my-config.toml"
```

## 配置文件格式

```toml
[connection]
port = 12345

[tls_client]
ca_cert = "/tmp/test-certs/tls/ca.crt"
client_cert = "/tmp/test-certs/tls/client/client.crt"
client_key = "/tmp/test-certs/tls/client/client.key"
client_key_pwd = "/tmp/test-certs/tls/key_pwd.txt"  # 可选

[cms_certs]
ca_cert = "/tmp/test-certs/cms/ca.crt"
signer_cert = "/tmp/test-certs/cms/node-a/signer.crt"
signer_key = "/tmp/test-certs/cms/node-a/signer.key"

[server]
binary_path = "trustruntime"
```

## REPL 命令

### 连接管理

```
connect [port]                       # 连接服务（不指定端口时使用配置文件中的端口）
disconnect                           # 断开连接
status                               # 显示连接状态
```

### 手工交互测试

```
sign <data>                          # 签名接口 (0x10)
verify <data> <signed_data> <id>     # 验签接口 (0x14)
verify-sign <verify-json> <sign-json> # 验签+签名接口 (0x12)
raw <type> <json-body>               # 发送原始请求
```

### 性能测试

```
perf sign --count <n> [--data <text>] [--interval <ms>]
perf verify --count <n> --signed-data <b64> --id <b64>
perf report                          # 显示性能统计
```

**输出指标**: 总数、成功数、失败数、平均响应时间、吞吐量(QPS)

### 并发测试

```
concurrent sign --threads <n> --count <n> [--data <text>]
concurrent verify --threads <n> --count <n> --signed-data <b64> --id <b64>
concurrent report                    # 显示并发统计
```

### 安全测试

```
security protocol [test-name]        # 协议层攻击测试
security cert [test-name]            # 证书层攻击测试
security tls [test-name]             # TLS层攻击测试
security all                         # 全部安全测试
security report                      # 显示安全测试报告
```

### 预置场景

```
scenario two-node                    # 两节点链路测试 (N01)
scenario three-node                  # 三节点链路测试 (N02)
scenario error-chain                 # 错误场景测试 (E01-E06)
scenario boundary                    # 边界场景测试 (B01-B05)
```

### 辅助命令

```
help [command]                       # 显示帮助
history                              # 命令历史
clear                                # 清屏
quit                                 # 退出
```

## 使用示例

### 连接与手工测试

```
cms-test-cli v0.1.0
Type 'help' for available commands.

> connect
Connected to vsock://1:12345

> sign "hello world"
Response:
{
  "signed_data": "MIIM...",
  "id": "abc123...",
  "result": 0
}

> verify "hello world" "MIIM..." "abc123..."
Response:
{
  "result": 0
}
```

### 性能测试

```
> perf sign --count 100
Running 100 sign requests...

Performance Report:
  Total: 100 requests
  Success: 100
  Failed: 0
  Avg Response Time: 12.5ms
  Throughput: 80.0 QPS
```

### 并发测试

```
> concurrent sign --threads 16 --count 50
Running concurrent test with 16 threads...

Concurrent Test Report:
  Threads: 16
  Total Requests: 800
  Success: 800
  Throughput: 52.6 QPS
```

## 详细设计

参见 `docs/cms-test-cli-design.md`。

## 依赖

- `integration-tests`: 复用 VsockClient、ProcessManager、test_utils
- `openssl`: TLS连接、证书生成
- `tokio`: 异步并发测试
- `serde_json`: JSON解析
- `clap`: 命令行参数
- `toml`: 配置文件解析