# 0004-unified-openssl-for-tls-and-cms

OpenSSL 同时用于 TLS（vsock-server 通信层）和 CMS（trustring 业务层），替代原计划的 rustls 用于 TLS。这消除了双重加密栈问题。

## Considered Options

1. **Unified OpenSSL** — 使用 openssl crate 进行 TLS 服务（通过 openssl::ssl::SslConnector/SslAcceptor）和 CMS 签名/验签；单一加密依赖；所有层证书/密钥类型一致
2. **Dual stack** (rustls + OpenSSL) — 使用 rustls 进行 TLS 通信层，OpenSSL 进行 CMS 业务层；不同证书类型（rustls 内部类型 vs openssl::X509）；需要为相同证书文件分离加载路径

## Decision

**选择方案 1：Unified OpenSSL。**

理由：

1. **No dual crypto stack** — 消除两个不兼容证书/密钥类型系统（rustls 内部类型 vs openssl::X509/PKey）的架构复杂性。证书文件加载一次，在 TLS 和 CMS 中一致使用。
2. **Stability priority** — OpenSSL 有 25 年以上的 TLS 生产历史；rustls 近期版本（0.x）的 CRL 支持不够成熟，对于安全关键服务难以验证
3. **Consistent error handling** — OpenSSL ErrorStack 可统一映射到 result codes，覆盖 TLS 握手失败和 CMS 验证失败
4. **Build simplicity** — 单一 openssl crate 依赖；无需管理两个具有不同更新节奏的独立加密 crate 生态系统
5. **TDD simplification** — 通过 openssl::X509 加载的测试固件同时用于 TLS 和 CMS 测试；无需分离的 rustls 兼容证书加载

权衡：TLS 使用 OpenSSL 在现代 Rust 项目中不够惯用（rustls 越来越受青睐），且 openssl crate 的 TLS API 比 rustls 更低级。然而，对于机密虚拟机中的安全关键服务，稳定性和一致性比惯用纯粹性更重要。

## Consequences

- vsock-server 使用 openssl::ssl 进行 TLS 服务配置（SslAcceptor、SslMethod、密码套件白名单、CRL 验证）
- trustring 使用 openssl::cms 进行 CMS 签名/验签
- 所有证书/密钥类型为 openssl::X509 和 openssl::PKey —— 各层一致
- 单一 RPM 依赖：openssl-libs >= 1.1.1
- TLS 配置（密码白名单、仅 TLS 1.2/1.3、无重协商）通过 openssl::ssl::SslAcceptor builder 实现
- 通信私钥密码由 openssl PKey 回调处理
- Cargo.toml 中无 rustls 依赖
- 从架构中移除：ADR-0002 中提到的"双重加密栈"风险