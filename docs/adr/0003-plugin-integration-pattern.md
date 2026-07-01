# 0003-plugin-integration-pattern

为 trustring 插件选择静态编译时集成而非动态运行时加载，将 Plugin trait 视为逻辑解耦边界而非物理隔离机制。

## Considered Options

1. **Static integration** — trustruntime 二进制的 main.rs 直接实例化 TrustringPlugin 并传递给框架；单一编译二进制；Plugin trait 仅提供逻辑解耦
2. **Dynamic loading** — 框架在运行时通过 libloading crate 发现并从共享库（.so）加载 trustring；真正的物理隔离；分离的二进制文件

## Decision

**选择方案 1：Static integration。**

理由：

1. **Security** — 在机密虚拟机中动态加载任意共享库是安全风险；静态链接生成内容已知的单一不可变二进制
2. **Simplicity** — Rust 动态加载需要 abi_stable crate 或 C ABI 封装，为此项目增加显著复杂度而无实际收益；静态集成在 main.rs 中仅需一个 `use` 语句
3. **Memory** — 单一二进制避免共享库开销（PLT/GOT 表、分离的分配器区域）；更容易适应 30MB cgroup 限制
4. **RPM packaging** — 单一二进制 RPM；无插件路径配置；无框架和插件共享对象版本不匹配
5. **TDD** — 所有代码在同一 workspace；cargo test --workspace 运行所有测试；无需分离的插件发现测试
6. **Plugin trait purpose** — Plugin trait 提供逻辑解耦（框架代码不导入 trustring 业务逻辑），而非物理隔离；这足以满足项目的可扩展性需求（未来插件可作为额外 crate 添加到 workspace，仍静态链接）

CONTEXT.md 和设计文档中的"插件"术语指实现 Plugin trait 的**逻辑模块**，而非动态加载的二进制。架构分离在编译时通过 trait 边界强制，而非运行时通过共享库边界。

## Consequences

- trustruntime 二进制 crate（rust/trustruntime/）同时依赖 framework 和 trustring crate
- trustring crate 依赖 framework crate（用于 Plugin trait 和 PluginContext 类型）
- 所有三个 crate 在同一 Cargo workspace；cargo test --workspace 测试完整系统
- RPM 包是单一二进制，无插件发现机制
- 添加新业务插件意味着向 workspace 添加新 crate 并在 main.rs 中添加新 `use` —— 而非将 .so 文件放入目录
- Plugin trait 仍有价值：框架代码独立于任何特定插件的业务逻辑；插件可独立开发和测试
- 无 abi_stable 或 libloading 依赖；无需 C ABI 封装代码