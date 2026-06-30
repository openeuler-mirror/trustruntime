# 0002-cms-library-selection

为 trustring 插件的 CMS 签名/验签功能选择通过 openssl crate（C FFI）使用 OpenSSL cms 模块，而非 RustCrypto cms crate（纯 Rust），优先考虑功能完整性和生产成熟度，而非纯 Rust TCB 最小化。

## Considered Options

1. **RustCrypto cms crate** (v0.2.3) — RustCrypto/formats 项目的纯 Rust CMS 库；提供 SignedDataBuilder/SignerInfoBuilder 用于签名，ASN.1 解析模型用于验签，但无高级 verify API，无证书链验证器，无 CRL 检查器
2. **OpenSSL cms via openssl crate** (v0.10.81) — OpenSSL C 库 CMS_sign/CMS_verify 的 Rust FFI 封装；提供一站式 sign() 和 verify()，内置 X509Store 链 + CRL 验证

---

## Comparison: Functionality

| Dimension | RustCrypto cms | OpenSSL cms |
|-----------|-------------------|---------------|
| CMS signing (SignedData) | SignedDataBuilder + SignerInfoBuilder；通过 p256/ecdsa 集成支持 ECC-256；builder 模式提供细粒度属性控制 | CmsContentInfo::sign() — 一步调用；接受 signcert + pkey + certs stack + CMSOptions flags |
| CMS verification (SignedData) | 仅解析：可解码 SignedData/SignerInfo 结构；需手动提取签名、重算摘要、用 ecdsa crate 验证；无 verify() 函数 | CmsContentInfo::verify() — 内置；接受 X509Store（含 CRL）、detached data、CMSOptions；返回 Ok/Err |
| Certificate chain validation | 无内置路径构建器或验证器；需自行实现链构建和有效期检查 | 通过 X509Store 内置：OpenSSL 执行完整链构建、过期检查和策略执行 |
| CRL checking | 无内置 CRL 查找/吊销状态验证；需自行实现匹配序列号 + 检查吊销日期逻辑 | 通过 X509Store 内置：向 store 添加 CRL，OpenSSL 在 verify() 时检查吊销状态 |
| Subject Key ID extraction | x509-cert TbsCertificate extensions 包含 SubjectKeyIdentifier；直接访问 20 字节 SHA-1 值 | X509Ref 提供 subject_key_id() 方法；简单直接 |
| PEM/DER dual format | 需自行实现自动检测逻辑；分离的 PEM/DER 解码路径 | CmsContentInfo::from_der() 和 from_pem()；X509::from_der() 和 from_pem()；内置双格式支持 |
| Encrypted private key support | 使用 pkcs5 crate 处理 PKCS#5/PKCS#8 加密密钥解密；需手动集成 | PKey::private_key_from_pem() 自动处理加密 PKCS#8；通过回调读取密码 |
| Signing algorithm control | 显式：选择摘要算法 + 签名者密钥对类型；完全控制 | 隐式：OpenSSL 根据证书密钥类型 + CMSOptions 选择算法 |

---

## Comparison: Maturity

| Dimension | RustCrypto cms | OpenSSL cms |
|-----------|-------------------|---------------|
| Crate version | 0.2.3（1.0 前；API 可能在无 semver 保证下变更） | 0.10.81（稳定；semver 管理） |
| Underlying library maturity | RustCrypto/formats 项目；cms crate 首次发布于 2022 年；早期阶段 | OpenSSL C 库：25 年以上生产使用；在各大操作系统和浏览器中经过实战检验 |
| Breaking change risk | 高：0.x crate 保留在任何版本中变更 API 的权利 | 低：openssl crate 遵循 semver；OpenSSL C API 实际上已冻结 |
| Production deployments | 有限：主要用于 RustCrypto 内部测试和实验性项目 | 大规模：OpenSSL CMS 用于 S/MIME、代码签名、时间戳、文档签名，全球范围 |

---

## Comparison: Security

| Dimension | RustCrypto cms | OpenSSL cms |
|-----------|-------------------|---------------|
| Memory safety | 完全 Rust 内存安全；无 unsafe 代码；零缓冲区溢出风险 | FFI 边界：openssl-sys 封装 C 代码；本质上是 unsafe；OpenSSL 历史上有内存安全 CVE |
| Auditability | 小型代码库（约 1k 行）；完整源码审查可行 | 大型 C 代码库（约 500k 行）；FFI 层增加间接性；难以完全审计 |
| CVE history | 无（太新/太小，攻击者未关注） | 历史上多个高危 CVE（Heartbleed、缓冲区溢出等） |
| Confidential VM suitability | 理想：纯 Rust；最小 TCB | 有问题：OpenSSL C 库增加 TCB 大小 |

---

## Comparison: Performance

| Dimension | RustCrypto cms | OpenSSL cms |
|-----------|-------------------|---------------|
| Signing latency (ECC-256) | 约 50-100us；相当 | 约 50-100us；类似 |
| Cold-start cost | 低：Rust 静态链接；启动约 1ms | 较高：OpenSSL 共享库初始化；约 5-10ms |
| Memory footprint (runtime) | 约 2-5MB | 约 8-15MB |
| Binary size (total deploy) | 约 1-2MB 单一二进制 | 约 500KB 二进制 + 约 5-7MB 共享库 |
| CPU quota fit (5% actual / 10% cgroup) | 轻松适应 | 负载下处于边缘 |

---

## Comparison: Dependencies

| Dimension | RustCrypto cms | OpenSSL cms |
|-----------|-------------------|---------------|
| C library dependency | 无：纯 Rust | 必需：OpenSSL（libssl + libcrypto） |
| Build complexity | 仅 cargo build；无需 C 编译器 | 需要 C 编译器 + OpenSSL 开发头文件；pkg-config |
| RPM packaging impact | 简单：单一二进制 RPM；无共享库依赖 | 必须 Require：openssl-libs >= 1.1.1；ABI 兼容性问题 |
| Conflict with TLS stack | 无：共享 rustls 生态系统 | 无：OpenSSL 同时服务 TLS 层（ADR-0004）；统一加密栈 |

---

## Comparison: API Ergonomics

| Dimension | RustCrypto cms | OpenSSL cms |
|-----------|-------------------|---------------|
| Signing API style | Builder 模式；显式逐步 | 一步调用：CmsContentInfo::sign()；一站式 |
| Verification API style | 手动：多步解析 + 验证；无 verify() 函数 | 一步调用：cms.verify()；一站式 |
| Result code mapping | 直接：应用控制验证逻辑 → 精确 result codes 0-9 | 间接：verify() 返回 Ok/Err；需解析 ErrorStack 映射到 result codes 3/4/5/6 |
| Certificate type interop | x509-cert::Certificate；仅 RustCrypto 生态系统 | openssl::X509；与 TLS 层统一（ADR-0004） |

---

## Comparison: Documentation

| Dimension | RustCrypto cms | OpenSSL cms |
|-----------|-------------------|---------------|
| Crate doc coverage | 100% | 55%（CMS 模块部分文档化） |
| RFC alignment | 直接：将类型映射到 RFC 5652 章节 | 间接：实现导向；RFC 对齐在 C man pages 中 |

---

## Comparison: Cross-Platform

| Dimension | RustCrypto cms | OpenSSL cms |
|-----------|-------------------|---------------|
| Confidential VM compatibility | 优秀：纯 Rust；最小 TCB | 需要 OpenSSL C 库；较大 TCB |
| RPM target (x86_64-linux) | 单一二进制 | 可行；需要 openssl-libs 依赖 |

---

## Decision

**选择方案 2：OpenSSL cms via openssl crate。**

主要决定因素是**成熟度和功能完整性**：

1. **生产成熟度** — OpenSSL CMS 有 25 年以上的生产历史；RustCrypto cms crate 版本为 v0.2.3（1.0 前，探索阶段）。对于安全关键服务，不成熟库的 API 不稳定性和未知 bug 风险超过了纯 Rust 的理论安全优势。
2. **功能完整性** — OpenSSL 提供一站式 sign+verify+chain+CRL 流程。RustCrypto cms 无 verify() 函数、无链验证器、无 CRL 检查器 —— 需要约 500-1100 行自定义验证代码，这些代码本身需要全面测试和审查。这些自定义代码成为最安全关键路径中新 bug 的来源。
3. **TDD 加速** — OpenSSL 的一步调用 API 允许立即针对已知可工作的实现编写测试。使用 RustCrypto，TDD 必须先构建验证基础设施才能运行业务测试，增加数周开发时间。

**已接受的风险和缓解措施：**

- **统一加密栈**（TLS 和 CMS 都使用 OpenSSL）：通过 ADR-0004 解决 —— OpenSSL 同时服务 vsock-server TLS 层和 trustring CMS 层。无双重加密栈；证书/密钥类型在所有层一致（openssl::X509、openssl::PKey）。
- **内存占用**（约 8-15MB vs 30MB cgroup 限制）：轻松适应并有余量。静态链接进一步减少开销。30MB 限制为 OpenSSL 运行时提供充足空间。
- **TCB 大小**在机密虚拟机中：确认为权衡。机密虚拟机的隔离边界已经保护服务；OpenSSL 的 C 代码在该边界内运行，而非边界外。
- **Result code 映射**从 OpenSSL ErrorStack：在 trustring 的 handler.rs 中实现专用错误映射层，将 OpenSSL 错误分类到项目的 0-9 result code 系统。

## Consequences

- trustring 插件使用 openssl::CmsContentInfo::sign() 进行 CMS 签名（一步调用）
- trustring 插件使用 openssl::cms::CmsContentInfo::verify() 配合 X509Store 进行 CMS 验签（内置链 + CRL）
- 证书链验证和 CRL 检查由 OpenSSL 的 X509Store 处理 —— 无需自定义验证代码
- Subject Key ID 通过 openssl::X509Ref::subject_key_id() 提取
- PEM/DER 双格式由 OpenSSL API 原生处理
- 通信私钥密码由 PKey::private_key_from_pem() 通过回调原生处理
- 统一加密栈：TLS（ADR-0004）和 CMS 都使用 OpenSSL —— 证书/密钥类型在所有层一致（openssl::X509、openssl::PKey）
- RPM 包 Requires：openssl-libs >= 1.1.1；必须跟踪 ABI 兼容性
- Result code 映射：trustring 中独立的 ErrorCodeMapper 模块将 OpenSSL ErrorStack 映射到 result codes 0-9
- 内存占用：约 8-15MB 轻松适应 30MB cgroup 限制；无超限风险
- Plugin trait 边界隔离 CMS 实现选择 —— 未来切换到 RustCrypto 仅是 trustring crate 内的局部变更