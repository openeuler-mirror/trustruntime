# cert-gen

ECC-256测试证书生成工具，用于CMS集成测试和TLS测试。

## 用法

```bash
cargo run -p cert-gen -- --output-dir <OUTPUT_DIR> [--force]
```

**参数**：
- `--output-dir`: 证书输出目录
- `--force`: 强制覆盖已存在的目录

## 生成的证书

### CMS证书（签名测试）

```
cms/
├── ca.crt, ca.key          # CA根证书和私钥
├── cms.crl                 # CRL（含吊销证书）
├── node-{a,b,c}/           # 有效节点证书
├── expired/                # 过期证书（2000-2010年）
├── revoked/                # 被吊销证书
└── self-signed/            # 自签名证书
```

### TLS证书（mTLS测试）

```
tls/
├── ca/ca.crt, ca.key       # TLS CA根证书
├── server/node-{a,b,c}/    # 服务端证书
├── ubse/node-{a,b,c}/      # ubse客户端证书
├── lcne/node-{a,b,c}/      # lcne客户端证书
└── test-clients/           # 测试用特殊客户端证书
```

## 技术规格

| 项目 | 规格 |
|------|------|
| 密钥算法 | ECC-256（P-256曲线） |
| 签名算法 | SHA256withECDSA |
| 有效期 | 3650天（约10年） |
| TLS私钥加密 | AES-256-CBC |
| 统一密码 | MyPasswd123 |

## 作为库使用

```rust
use cert_gen::create_cert_with_usage;

let (cert, key) = create_cert_with_usage(
    &group,      // EcGroup
    &ca_cert,    // CA证书
    &ca_key,     // CA私钥
    "subject",   // Subject名称
    true,        // 是否CA证书
    None,        // 有效期（None使用默认）
)?;
```

## 依赖

- `openssl`: 证书生成
- `clap`: 命令行参数解析