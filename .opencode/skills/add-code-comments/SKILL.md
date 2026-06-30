---
name: add-code-comments
description: 为Rust代码添加规范注释，包含模块、公共API、业务逻辑和ADR决策引用。Use when adding comments to Rust code, reviewing code documentation, or when user mentions "注释", "comments", "文档", "documentation".
---

# 添加代码注释规范

## 快速开始

为Rust代码添加注释时遵循以下核心原则：

1. **公共API必须有文档注释** (`///`)
2. **架构决策引用ADR文档**
3. **业务规则说明"为什么"而非"是什么"**
4. **使用中文注释（符合项目文档风格）**

## 工作流程

### 第一步：识别代码类型

判断需要添加注释的代码属于哪一类：
- 模块文件（`mod.rs`, `lib.rs`）
- 公共接口（`pub fn`, `pub struct`, `pub enum`）
- 业务逻辑实现
- 测试函数

### 第二步：应用对应规范

#### 模块级注释
```rust
//! 模块功能说明
//!
//! 主要职责：
//! - 职责1
//! - 职责2
//!
//! 与其他模块关系：依赖/被依赖说明
```

#### 公共接口注释
```rust
/// 简短描述（一行）
///
/// 详细说明（可选）
///
/// # Arguments
/// * `param1` - 参数说明
///
/// # Returns
/// 返回值说明
///
/// # Errors
/// 可能的错误情况
///
/// # Example
/// ```
/// let result = function_name(arg);
/// ```
pub fn function_name(param1: Type) -> Result<T, E> {
```

#### ADR引用格式
```rust
/// 结构体/模块名称
///
/// 架构决策：<一句话概述>
/// 详见 ADR-XXXX: <ADR标题>
///
/// <关键理由或后果，可选>
```

#### 业务逻辑注释
```rust
// 业务规则：result=2优先级高于result=1
// - result=1: 其他节点签名（ID不同）
// - result=2: 证书身份冲突（公钥相同但ID不同）
let result_code = match self.verifier.verify(...) {
    Ok(VerifyOutcome::SameNode) => 0,
    Ok(VerifyOutcome::OtherNode) => 1,
    Ok(VerifyOutcome::IdentityConflict) => 2,
    Err(e) => map_verify_error(&e).to_result_code(),
};
```

### 第三步：验证质量

检查清单：
- [ ] 所有 `pub` 函数、结构体、枚举有文档注释
- [ ] 架构关键决策引用对应ADR文档
- [ ] 业务规则和决策逻辑有注释说明
- [ ] 错误处理逻辑有注释说明原因
- [ ] 测试函数说明测试场景和预期结果

## 分阶段实施

### 阶段1：核心模块（高优先级）
- `plugins/trustring/handler.rs` - 业务处理器
- `plugins/trustring/sign.rs` - 签名实现
- `plugins/trustring/verify.rs` - 验签实现
- `plugins/trustring/cert_loader.rs` - 证书加载
- `framework/message/mod.rs` - 消息协议
- `framework/communication/vsock_server/mod.rs` - vsock服务端

### 阶段2：框架层（中优先级）
- `framework/core/daemon.rs` - 进程守护
- `framework/core/cert_checker.rs` - 证书检查
- `framework/plugin_manager/mod.rs` - 插件管理

### 阶段3：工具和测试（低优先级）
- `tools/cms-test-cli/` - 测试工具
- `integration-tests/` - 集成测试

## ADR映射表

| 代码文件 | 相关ADR | 关键决策点 |
|---------|---------|-----------|
| `plugins/trustring/src/lib.rs` | ADR-0003 | 静态集成模式 |
| `framework/src/plugin_manager/mod.rs` | ADR-0003, ADR-0005 | Plugin trait逻辑边界，TransportLayer解耦 |
| `framework/src/communication/vsock_server/mod.rs` | ADR-0004, ADR-0005 | OpenSSL统一TLS/CMS，TransportLayer抽象 |
| `plugins/trustring/src/sign.rs` | ADR-0004 | OpenSSL CMS签名 |
| `plugins/trustring/src/verify.rs` | ADR-0004, ADR-0001 | OpenSSL CMS验签，result码映射 |
| `plugins/trustring/src/error_code_mapper.rs` | ADR-0001 | 统一结果码编码 |
| `framework/src/cert/mod.rs` | ADR-0004 | OpenSSL证书加载（PEM/DER） |

## 详细规则和示例

参见 [REFERENCE.md](REFERENCE.md) 获取完整的注释规则、示例和风格指南。