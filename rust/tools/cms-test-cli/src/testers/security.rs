//! 协议安全测试器模块
//!
//! 提供协议层安全测试功能，验证服务端对异常输入的处理能力。
//! 测试包括协议版本不匹配、超大消息、未知消息类型等安全边界场景。
//!
//! ## 测试场景
//!
//! | 测试名称 | 说明 | 期望行为 |
//! |---------|------|---------|
//! | version-mismatch | 版本号错误 | 返回type=0x01, len=0 |
//! | oversized-message | 超大消息体 | 返回type=0x02, len=0 |
//! | unknown-type | 未知消息类型 | 返回type=0x01, len=0 |
//! | malformed-header | 格式错误的头部 | 返回type=0x01, len=0 |

use crate::stats::SecurityTestResult;
use integration_tests::vsock_client::VsockClient;
use std::sync::{Arc, Mutex};

/// vsock协议版本号
const VSOCK_VERSION: u32 = 0xFFFF0400;

/// 协议安全测试器
///
/// 执行协议层安全测试，验证服务端对异常输入的处理是否符合规范。
/// 通过发送构造的异常消息，验证服务端的错误处理和拒绝能力。
pub struct ProtocolSecurityTester {
    /// 共享的vsock客户端实例
    client: Arc<Mutex<VsockClient>>,
}

impl ProtocolSecurityTester {
    /// 创建新的协议安全测试器
    ///
    /// # 参数
    ///
    /// * `client` - 共享的vsock客户端实例
    pub fn new(client: Arc<Mutex<VsockClient>>) -> Self {
        Self { client }
    }

    /// 运行单个安全测试
    ///
    /// 根据测试名称执行对应的安全测试用例。
    ///
    /// # 参数
    ///
    /// * `test_name` - 测试名称，支持：
    ///   - "version-mismatch": 版本不匹配测试
    ///   - "oversized-message": 超大消息测试
    ///   - "unknown-type": 未知类型测试
    ///   - "malformed-header": 格式错误头部测试
    ///
    /// # 返回
    ///
    /// 返回测试结果列表（单个测试返回单元素列表）
    pub fn run_single(&self, test_name: &str) -> Vec<SecurityTestResult> {
        match test_name {
            "version-mismatch" => vec![self.test_version_mismatch()],
            "oversized-message" => vec![self.test_oversized_message()],
            "unknown-type" => vec![self.test_unknown_type()],
            "malformed-header" => vec![self.test_malformed_header()],
            _ => vec![SecurityTestResult {
                test_name: test_name.to_string(),
                passed: false,
                expected_behavior: "Unknown test".to_string(),
                actual_behavior: "Test not found".to_string(),
                details: format!("Unknown protocol test: {}", test_name),
            }],
        }
    }

    /// 运行所有安全测试
    ///
    /// 执行所有预定义的安全测试用例。
    ///
    /// # 返回
    ///
    /// 返回所有测试结果的列表
    pub fn run_all(&self) -> Vec<SecurityTestResult> {
        vec![
            self.test_version_mismatch(),
            self.test_oversized_message(),
            self.test_unknown_type(),
            self.test_malformed_header(),
        ]
    }

    /// 测试版本不匹配场景
    ///
    /// 发送错误版本号的协议消息，验证服务端是否正确拒绝。
    ///
    /// # 测试场景
    ///
    /// - E16: 协议版本错误处理
    ///
    /// # 期望行为
    ///
    /// 服务端应返回type=0x01（错误响应），len=0
    fn test_version_mismatch(&self) -> SecurityTestResult {
        let mut client = self.client.lock().unwrap();

        // 发送错误版本号0xDEADBEEF（正确应为0xFFFF0400）
        let resp = client.send_raw_header(0xDEADBEEF, 0x10, 0);

        match resp {
            Ok(r) => SecurityTestResult {
                test_name: "version-mismatch".to_string(),
                passed: r.msg_type == 0x01 && r.len == 0,
                expected_behavior: "Server returns type=0x01, len=0".to_string(),
                actual_behavior: format!("type=0x{:02x}, len={}", r.msg_type, r.len),
                details: "Sent version=0xDEADBEEF instead of 0xFFFF0400".to_string(),
            },
            Err(e) => SecurityTestResult {
                test_name: "version-mismatch".to_string(),
                passed: false,
                expected_behavior: "Server returns type=0x01, len=0".to_string(),
                actual_behavior: format!("Error: {}", e),
                details: "Connection error during test".to_string(),
            },
        }
    }

    /// 测试超大消息场景
    ///
    /// 发送超过10KB的消息体，验证服务端是否正确拒绝。
    ///
    /// # 测试场景
    ///
    /// - E17: 消息体大小限制测试
    /// - B01: 边界值测试（超过最大消息大小）
    ///
    /// # 期望行为
    ///
    /// 服务端应返回type=0x02（拒绝响应），len=0
    fn test_oversized_message(&self) -> SecurityTestResult {
        // 构造超过10KB的消息体
        let large_data = "x".repeat(11000);
        let body = serde_json::json!({
            "to-sign": { "data": large_data }
        })
        .to_string();

        let mut client = self.client.lock().unwrap();
        let resp = client.send_raw_request_with_response(0x10, body);

        match resp {
            Ok(r) => SecurityTestResult {
                test_name: "oversized-message".to_string(),
                passed: r.msg_type == 0x02 && r.len == 0,
                expected_behavior: "Server returns type=0x02, len=0".to_string(),
                actual_behavior: format!("type=0x{:02x}, len={}", r.msg_type, r.len),
                details: "Sent message with body > 10KB".to_string(),
            },
            Err(e) => SecurityTestResult {
                test_name: "oversized-message".to_string(),
                passed: false,
                expected_behavior: "Server returns type=0x02, len=0".to_string(),
                actual_behavior: format!("Error: {}", e),
                details: "Connection error during test".to_string(),
            },
        }
    }

    /// 测试未知消息类型场景
    ///
    /// 发送未注册的消息类型（0xFF），验证服务端是否正确拒绝。
    ///
    /// # 测试场景
    ///
    /// - E18: 未知消息类型处理
    ///
    /// # 期望行为
    ///
    /// 服务端应返回type=0x01（错误响应），len=0
    fn test_unknown_type(&self) -> SecurityTestResult {
        let mut client = self.client.lock().unwrap();
        // 发送未注册的消息类型0xFF
        let resp = client.send_raw_header(VSOCK_VERSION, 0xFF, 0);

        match resp {
            Ok(r) => SecurityTestResult {
                test_name: "unknown-type".to_string(),
                passed: r.msg_type == 0x01 && r.len == 0,
                expected_behavior: "Server returns type=0x01, len=0".to_string(),
                actual_behavior: format!("type=0x{:02x}, len={}", r.msg_type, r.len),
                details: "Sent msg_type=0xFF (unregistered)".to_string(),
            },
            Err(e) => SecurityTestResult {
                test_name: "unknown-type".to_string(),
                passed: false,
                expected_behavior: "Server returns type=0x01, len=0".to_string(),
                actual_behavior: format!("Error: {}", e),
                details: "Connection error during test".to_string(),
            },
        }
    }

    /// 测试格式错误的头部场景
    ///
    /// 发送不完整的协议头部，验证服务端是否正确处理。
    /// 此测试需要原始流访问能力，当前实现为占位符。
    ///
    /// # 测试场景
    ///
    /// - E19: 格式错误头部处理
    /// - E20: 消息截断处理
    ///
    /// # 期望行为
    ///
    /// 服务端应返回type=0x01（错误响应），len=0
    ///
    /// # 实现说明
    ///
    /// 当前实现为占位符，需要扩展VsockClient以支持部分头部发送
    fn test_malformed_header(&self) -> SecurityTestResult {
        SecurityTestResult {
            test_name: "malformed-header".to_string(),
            passed: false,
            expected_behavior: "Server returns type=0x01, len=0".to_string(),
            actual_behavior: "Test requires raw stream access (not implemented)".to_string(),
            details: "Need VsockClient extension for partial header send".to_string(),
        }
    }
}
