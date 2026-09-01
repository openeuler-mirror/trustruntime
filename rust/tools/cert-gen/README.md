# cert-gen

ECC-256 测试证书生成工具，用于 CMS 集成测试和 TLS 测试。

## 用法

```bash
cargo run -p cert-gen -- --output-dir <OUTPUT_DIR> [--force]
```

**参数**：
- `--output-dir`: 证书输出目录
- `--force`: 强制覆盖已存在的目录

## 生成的证书

### CMS 证书（签名测试）

```
cms/
├── ca_root.crt, ca.key          # CA 根证书和私钥
├── cms.crl                     # CRL（含吊销证书）
├── node-a/, node-b/, node-c/   # 有效节点证书
│   ├── signer.crt              # 签名证书
│   ├── signer.key              # 签名私钥
│   ├── ca_root.crt             # CA 根证书副本
│   └── cms.crl                 # CRL 副本
├── expired/                    # 过期证书（2000-2010年）
│   ├── signer.crt, signer.key
│   ├── ca_root.crt
│   └── cms.crl
├── revoked/                    # 被吊销证书
│   ├── signer.crt, signer.key
│   ├── ca_root.crt
│   └── cms.crl
└── self-signed/                # 自签名证书
    ├── signer.crt, signer.key
    └── ca_root.crt
```

**每个节点目录都包含完整的证书集**：
- 签名证书和私钥
- CA 根证书副本
- CRL 文件副本

### TLS 证书（mTLS 测试）

```
tls/
├── ca/
│   ├── ca.crt                  # TLS CA 根证书
│   └── ca.key                  # TLS CA 私钥
├── server/node-a/, node-b/, node-c/  # 服务端证书
│   ├── certificate.crt         # 服务端证书
│   ├── private.key             # 服务端私钥（加密）
│   ├── key_pwd.txt             # 私钥密码文件
│   ├── ca_root.crt             # CA 根证书副本
│   └── cert.crl                # CRL 文件
├── ubse/node-a/, node-b/, node-c/    # ubse 服务端+客户端证书
│   ├── server.pem              # 证书（serverAuth+clientAuth）
│   ├── server_key.pem          # 私钥（加密）
│   ├── key_pwd.txt             # 私钥密码文件
│   └── trust.pem               # CA 根证书副本
├── lcne/node-a/, node-b/, node-c/    # lcne 服务端+客户端证书
│   ├── certificate.crt         # 证书（serverAuth+clientAuth）
│   ├── private.key             # 私钥（加密）
│   ├── key_pwd.txt             # 私钥密码文件
│   ├── ca_root.crt             # CA 根证书副本
│   └── communication.crl       # CRL 文件
└── test-clients/               # 测试用特殊客户端证书
    ├── other-ca.crt            # 其他 CA 证书
    ├── revoked.crt, revoked.key  # 被吊销的客户端证书
    ├── wrong-ca.crt, wrong-ca.key  # 错误 CA 签发的证书
    └── client-crl.crt          # 客户端 CRL
```

**每个节点目录都包含完整的证书集**：
- 证书和私钥（加密）
- 私钥密码文件
- CA 根证书副本
- CRL 文件（如适用）

## 技术规格

| 项目 | 规格 |
|------|------|
| 密钥算法 | ECC-256（P-256 曲线） |
| 签名算法 | SHA256withECDSA |
| 有效期 | 3650 天（约 10 年） |
| TLS 私钥加密 | AES-256-CBC |
| 统一密码 | MyPasswd123 |

## 使用示例

### 生成测试证书

```bash
# 生成到默认位置
cargo run -p cert-gen -- --output-dir /tmp/test-certs --force

# 生成到自定义位置
cargo run -p cert-gen -- --output-dir ~/my-certs --force
```

### 使用生成的证书

**CMS 签名证书**：
```bash
# 使用 node-a 的签名证书
signer_cert=/tmp/test-certs/cms/node-a/signer.crt
signer_key=/tmp/test-certs/cms/node-a/signer.key
ca_cert=/tmp/test-certs/cms/node-a/ca_root.crt
```

**TLS 客户端证书**：
```bash
# 使用 lcne 客户端证书
client_cert=/tmp/test-certs/tls/lcne/node-a/certificate.crt
client_key=/tmp/test-certs/tls/lcne/node-a/private.key
key_pwd=/tmp/test-certs/tls/lcne/node-a/key_pwd.txt
ca_cert=/tmp/test-certs/tls/lcne/node-a/ca_root.crt
```

## 作为库使用

```rust
use cert_gen::create_cert_with_usage;

let (cert, key) = create_cert_with_usage(
    &group,      // EcGroup
    &ca_cert,    // CA 证书
    &ca_key,     // CA 私钥
    "subject",   // Subject 名称
    true,        // 是否 CA 证书
    None,        // 有效期（None 使用默认）
)?;
```

## 依赖

- `openssl`: 证书生成
- `clap`: 命令行参数解析