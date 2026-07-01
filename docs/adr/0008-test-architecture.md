# 0008-test-architecture

集成测试设计确定测试架构为分层测试方案，核心业务逻辑通过handler层模块集成测试验证（无需vsock/TLS），通信层通过实际连接测试验证（WSL内执行）。测试代码组织为独立crate（`rust/integration-tests/`），测试用例按场景分类（正常场景、异常场景、边界场景）。证书生成采用独立命令行工具（`rust/tools/cert-gen/`），进程启动由测试框架管理（自动启动/停止/清理）。

## Considered Options

1. **端到端测试**：启动真实进程，通过vsock+TLS调用，验证完整链路
2. **模块集成测试**：跳过vsock/TLS层，直接测试handler，快速验证业务逻辑
3. **分层测试**：handler层模块集成 + vsock通信层独立测试，分层验证
4. **测试代码位置**：crate内tests目录（`rust/trustruntime/tests/`）vs 独立测试crate
5. **证书生成方式**：OpenSSL命令脚本 vs Rust代码生成工具
6. **进程启动方式**：测试框架管理 vs Shell脚本管理 vs Docker容器
7. **测试用例组织**：按场景分类（normal/error/boundary）vs 按功能分类（sign/verify/vsock）

## Decision

组合决策：
- **测试架构**：分层测试（方案3）
- **测试crate**：独立crate `rust/integration-tests/`（方案4独立）
- **证书生成**：Rust代码生成工具（方案5 Rust工具）
- **进程启动**：测试框架管理（方案6框架管理）
- **用例组织**：按场景分类（方案7场景分类）

理由：
- 分层测试隔离关注点：handler层快速验证业务逻辑（无需vsock环境），通信层验证真实连接场景
- 独立crate便于维护：测试代码与业务代码分离，避免循环依赖
- Rust工具类型安全：复用现有测试代码中的证书生成函数，避免Shell脚本复杂参数
- 框架管理自动化：测试代码可控进程生命周期，便于并发测试和清理
- 场景分类便于扩展：正常/异常/边界场景清晰，新增场景只需扩展对应测试文件

## Consequences

- 测试环境要求WSL2（支持vsock内核模块）
- 通信层测试需要真实证书体系（CMS证书+TLS证书）
- 测试crate依赖trustruntime-framework和trustring crate（通过公开接口测试）
- 证书生成工具一次性输出所有测试证书到指定目录
- 进程管理模块需实现：启动进程、等待就绪（检测vsock端口）、停止进程、清理临时文件
- 测试执行流程：生成证书 → 编译测试crate → 运行测试 → 自动清理