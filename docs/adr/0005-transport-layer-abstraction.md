# Transport Layer Abstraction

通信层与插件框架层需要解耦，以支持未来切换通信机制（如从 vsock 切换到 HTTPS）。我们决定引入 `TransportLayer` trait 作为通用通信抽象，`DataHandler` trait 作为业务处理抽象。Transport 负责协议层（报文解析、校验、错误响应），DataHandler 负责业务层（JSON 解析、签名验签）。PluginManager 只管生命周期，不管分发。Transport 不感知 Plugin，Plugin 通过 PluginContext 获取 Transport 引用并注册 DataHandler。

## Status

accepted

## Considered Options

- **方案 A: PluginManager 持有 dispatch table** — PluginManager 和 Transport 紧耦合，切换通信机制需要修改 PluginManager
- **方案 B: Channel 解耦** — Transport 和 PluginManager 通过 channel 通信，引入额外复杂度和 ConnectionId 管理
- **方案 C: 字节级通用 handler** — Transport 只处理字节，handler 需要自己解析报文协议，职责不清
- **方案 Z: TransportLayer + DataHandler（选定）** — Transport 处理协议层，DataHandler 处理业务层，职责清晰，解耦彻底

## Consequences

- Transport 实现（VsockTransport）可以独立替换，不影响插件代码
- 插件通过 `DataHandler` trait 注册业务逻辑，不依赖具体通信机制
- `PluginContext` 需要传递 `&dyn TransportLayer` 给插件
- 插件内部状态需要 `Arc` 包裹以支持并发 handler 调用
- main.rs 负责接线：创建 Transport → 创建 PluginManager → init_all(ctx{transport}) → transport.start()

## Implementation Notes

2026-07-06: 为避免反向依赖问题（communication 模块依赖 plugin_manager），将 `TransportLayer` trait、`DataHandler` trait 和 `TransportError` 从 `plugin_manager` 模块移动到独立的 `transport` 模块。

新的依赖方向：
```
communication/vsock_server → transport ← plugin_manager
```

模块位置：
- `framework/src/transport/mod.rs`: 定义 `TransportLayer` trait、`DataHandler` trait、`TransportError`
- `framework/src/communication/vsock_server/mod.rs`: `VsockTransport` 实现 `TransportLayer`
- `framework/src/plugin_manager/mod.rs`: `PluginContext` 引用 `transport::TransportLayer`
