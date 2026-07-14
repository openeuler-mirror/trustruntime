//! DataHandler处理器测试模块
//!
//! 测试范围：
//! - handler返回None场景
//! - handler返回数据场景
//! - handler注册覆盖测试
//! - handler注册多类型测试
//! - 消息错误响应格式测试
//!
//! 重点验证：DataHandler trait实现、注册机制、消息格式

use trustruntime_framework::transport::{DataHandler, TransportError, TransportLayer};
use std::collections::HashMap;
use std::sync::RwLock;
use async_trait::async_trait;

/// 测试用Handler：返回None
///
/// 用途：测试handler无返回值场景
struct NoneHandler;

/// NoneHandler实现：返回None
impl DataHandler for NoneHandler {
    fn handle(&self, _data: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// 测试用Handler：返回数据
///
/// 用途：测试echo场景
struct EchoHandler;

/// EchoHandler实现：返回输入数据
impl DataHandler for EchoHandler {
    fn handle(&self, data: &[u8]) -> Option<Vec<u8>> {
        Some(data.to_vec())
    }
}

/// 测试handler返回None
///
/// 预期结果：handler.handle返回None
#[test]
fn test_handler_none_returns_none() {
    let handler = NoneHandler;
    let result = handler.handle(b"test");
    assert!(result.is_none());
}

/// 测试handler返回数据
///
/// 预期结果：handler.handle返回输入数据副本
#[test]
fn test_handler_echo_returns_data() {
    let handler = EchoHandler;
    let result = handler.handle(b"hello");
    assert!(result.is_some());
    assert_eq!(result.unwrap(), b"hello".to_vec());
}

/// 测试handler注册覆盖
///
/// 测试场景：同一消息类型注册两次不同handler
///
/// 预期结果：第二次注册覆盖第一次
/// 说明：TransportLayer.register_handler允许覆盖
#[test]
fn test_handler_registration_overwrite() {
    struct MockTransport {
        handlers: RwLock<HashMap<u32, Box<dyn DataHandler>>>,
    }

    #[async_trait]
    impl TransportLayer for MockTransport {
        fn register_handler(&self, msg_type: u32, handler: Box<dyn DataHandler>) {
            self.handlers.write().unwrap().insert(msg_type, handler);
        }

        async fn start(&self) -> Result<(), TransportError> {
            Ok(())
        }

        async fn stop(&self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    let transport = MockTransport {
        handlers: RwLock::new(HashMap::new()),
    };

    transport.register_handler(0x10, Box::new(EchoHandler));
    transport.register_handler(0x10, Box::new(NoneHandler));

    let handlers = transport.handlers.read().unwrap();
    let handler = handlers.get(&0x10).unwrap();
    let result = handler.handle(b"test");

    assert!(result.is_none(), "Second handler should overwrite first");
}

/// 测试handler注册多类型
///
/// 测试场景：注册多种消息类型的handler
///
/// 预期结果：各类型handler独立存在并正确工作
#[test]
fn test_handler_registration_multiple_types() {
    struct MockTransport {
        handlers: RwLock<HashMap<u32, Box<dyn DataHandler>>>,
    }

    #[async_trait]
    impl TransportLayer for MockTransport {
        fn register_handler(&self, msg_type: u32, handler: Box<dyn DataHandler>) {
            self.handlers.write().unwrap().insert(msg_type, handler);
        }

        async fn start(&self) -> Result<(), TransportError> {
            Ok(())
        }

        async fn stop(&self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    let transport = MockTransport {
        handlers: RwLock::new(HashMap::new()),
    };

    transport.register_handler(0x10, Box::new(EchoHandler));
    transport.register_handler(0x12, Box::new(NoneHandler));
    transport.register_handler(0x14, Box::new(EchoHandler));

    let handlers = transport.handlers.read().unwrap();
    assert_eq!(handlers.len(), 3);

    let handler_10 = handlers.get(&0x10).unwrap();
    assert!(handler_10.handle(b"test").is_some());

    let handler_12 = handlers.get(&0x12).unwrap();
    assert!(handler_12.handle(b"test").is_none());

    let handler_14 = handlers.get(&0x14).unwrap();
    assert!(handler_14.handle(b"test").is_some());
}

/// 测试消息错误响应保留seq和version
///
/// 测试场景：创建错误响应消息
///
/// 预期结果：seq、version字段保持输入值
/// 说明：错误响应需要保留请求的seq/version用于响应匹配
#[test]
fn test_message_error_response_preserves_seq_version() {
    use trustruntime_framework::message::VsockMessage;

    let resp = VsockMessage::new(12345, 0xFFFF0400, 0x01, vec![]);
    assert_eq!(resp.header.seq, 12345);
    assert_eq!(resp.header.version, 0xFFFF0400);
    assert_eq!(resp.header.msg_type, 0x01);
    assert_eq!(resp.header.len, 0);
}