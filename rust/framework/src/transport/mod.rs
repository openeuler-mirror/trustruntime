//! 传输层抽象模块
//!
//! 定义通用通信接口，与具体传输实现（vsock/TCP/HTTPS）解耦。
//!
//! 主要职责：
//! - 定义TransportLayer trait作为传输层抽象接口
//! - 定义DataHandler trait作为业务数据处理器接口
//! - 定义TransportError作为传输层错误类型
//!
//! 架构决策：
//! - TransportLayer trait解耦通信层与插件框架层（ADR-0005）
//!   - Transport：处理协议层（报文解析、校验、错误响应）
//!   - DataHandler：处理业务层（JSON解析、签名验签）
//!   - Transport不感知Plugin，Plugin通过PluginContext获取Transport引用并注册DataHandler
//!
//! 扩展性：
//! - 可替换为VsockTransport、HttpsTransport等不同实现
//! - 不影响插件代码和PluginManager
//!
//! 依赖：
//! - async_trait：异步trait支持
//! - thiserror：错误类型定义

use async_trait::async_trait;
use thiserror::Error;

/// 传输层错误
///
/// 传输层启动或停止过程中可能发生的错误
#[derive(Error, Debug)]
pub enum TransportError {
    /// 传输层启动失败
    #[error("start failed: {0}")]
    StartFailed(String),
    /// 传输层停止失败
    #[error("stop failed: {0}")]
    StopFailed(String),
}

/// 业务数据处理器接口
///
/// 架构决策：DataHandler抽象解耦业务层与传输层
/// 详见 ADR-0005: Transport Layer Abstraction
///
/// 职责：
/// - 处理业务数据（JSON解析、签名验签等）
/// - 返回Some(Vec<u8>)表示成功处理，None表示处理失败
/// - 与具体通信机制解耦，不感知vsock/TCP/HTTP等协议
///
/// 线程安全：
/// - 必须实现Send + Sync以支持并发调用
pub trait DataHandler: Send + Sync {
    /// 处理业务数据
    ///
    /// # Arguments
    /// * `data` - 原始业务数据（通常是JSON请求）
    ///
    /// # Returns
    /// * `Some(Vec<u8>)` - 处理成功，返回响应数据
    /// * `None` - 处理失败
    fn handle(&self, data: &[u8]) -> Option<Vec<u8>>;
}

/// 传输层抽象接口
///
/// 架构决策：TransportLayer trait解耦通信层与插件框架层
/// 详见 ADR-0005: Transport Layer Abstraction
///
/// 职责：
/// - 协议层处理（报文解析、校验、错误响应）
/// - 消息类型分发（通过register_handler注册不同类型的处理器）
/// - 不感知Plugin，由Plugin通过PluginContext注册DataHandler
///
/// 扩展性：
/// - 可替换为VsockTransport、HttpsTransport等不同实现
/// - 不影响插件代码和PluginManager
#[async_trait]
pub trait TransportLayer: Send + Sync {
    /// 注册消息处理器
    ///
    /// 架构决策：Transport负责协议层，DataHandler负责业务层
    /// 详见 ADR-0005: Transport Layer Abstraction
    ///
    /// # Arguments
    /// * `msg_type` - 消息类型（如0x10签名请求、0x14验签请求）
    /// * `handler` - 业务处理器实现
    fn register_handler(&self, msg_type: u32, handler: Box<dyn DataHandler>);

    /// 启动传输层
    ///
    /// 开始监听连接并处理消息
    ///
    /// # Errors
    /// 启动失败时返回TransportError::StartFailed
    async fn start(&self) -> Result<(), TransportError>;

    /// 停止传输层
    ///
    /// 停止监听并清理资源
    ///
    /// # Errors
    /// 停止失败时返回TransportError::StopFailed
    async fn stop(&self) -> Result<(), TransportError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock数据处理器实现，用于测试
    struct MockDataHandler;

    impl DataHandler for MockDataHandler {
        fn handle(&self, data: &[u8]) -> Option<Vec<u8>> {
            Some(data.to_vec())
        }
    }

    /// 测试：DataHandler trait基本功能
    ///
    /// 场景：使用MockDataHandler处理数据
    /// 预期：返回Some(处理后的数据)
    #[test]
    fn data_handler_trait_works() {
        let handler = MockDataHandler;
        let result = handler.handle(b"test");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"test".to_vec());
    }
}
