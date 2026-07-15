//! 交互式测试器模块
//!
//! 提供手动交互式测试功能，允许用户输入命令并实时查看结果。
//! 适用于调试和探索性测试场景。
//!
//! ## 功能
//!
//! - 签名操作：对输入数据进行CMS签名
//! - 验证操作：验证签名数据的完整性和有效性
//! - 验证并签名：先验证再签名的复合操作
//! - 原始请求：发送原始协议消息进行底层测试

use integration_tests::vsock_client::{
    RawResponse, SignResponse, VerifyResponse, VerifySignRequest, VerifySignResponse, VsockClient,
};
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// 交互式测试错误类型
#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum TestError {
    /// vsock通信错误
    #[error("vsock error: {0}")]
    Vsock(String),

    /// 数据解析错误
    #[error("parse error: {0}")]
    Parse(String),

    /// 操作超时
    #[error("timeout")]
    Timeout,
}

/// 交互式测试器
///
/// 提供手动交互式测试接口，支持签名、验证等操作的实时测试。
/// 通过共享的VsockClient实例进行通信，支持多线程安全访问。
pub struct InteractiveTester {
    /// 共享的vsock客户端实例
    client: Arc<Mutex<VsockClient>>,
}

impl InteractiveTester {
    /// 创建新的交互式测试器
    ///
    /// # 参数
    ///
    /// * `client` - 共享的vsock客户端实例
    ///
    /// # 返回
    ///
    /// 返回新的InteractiveTester实例
    pub fn new(client: Arc<Mutex<VsockClient>>) -> Self {
        Self { client }
    }

    /// 执行签名操作
    ///
    /// 对输入数据进行CMS签名。
    ///
    /// # 参数
    ///
    /// * `data` - 待签名的数据内容
    ///
    /// # 返回
    ///
    /// 成功返回签名响应，失败返回TestError
    ///
    /// # 测试场景
    ///
    /// - N01: 正常签名流程测试
    /// - E01-E05: 签名错误场景测试
    pub fn sign(&self, data: &str) -> Result<SignResponse, TestError> {
        let mut client = self.client.lock().unwrap();
        client
            .sign(data)
            .map_err(|e| TestError::Vsock(e.to_string()))
    }

    /// 执行验证操作
    ///
    /// 验证签名数据的完整性和签名者身份。
    ///
    /// # 参数
    ///
    /// * `data` - 原始数据内容
    /// * `signed_data` - 签名后的数据
    /// * `id` - 签名者标识
    ///
    /// # 返回
    ///
    /// 成功返回验证响应，失败返回TestError
    ///
    /// # 测试场景
    ///
    /// - N02: 正常验证流程测试
    /// - E06-E10: 验证错误场景测试
    pub fn verify(
        &self,
        data: &str,
        signed_data: &str,
        id: &str,
    ) -> Result<VerifyResponse, TestError> {
        let mut client = self.client.lock().unwrap();
        client
            .verify(data, signed_data, id)
            .map_err(|e| TestError::Vsock(e.to_string()))
    }

    /// 执行验证并签名操作
    ///
    /// 先验证输入数据，然后对验证通过的数据进行签名。
    /// 用于链式签名场景，如三节点签名验证链。
    ///
    /// # 参数
    ///
    /// * `req` - 验证签名请求，包含待验证和签名的数据
    ///
    /// # 返回
    ///
    /// 成功返回验证签名响应，失败返回TestError
    ///
    /// # 测试场景
    ///
    /// - N03: 三节点签名验证链测试
    /// - E11-E15: 验证签名错误场景测试
    pub fn verify_and_sign(&self, req: VerifySignRequest) -> Result<VerifySignResponse, TestError> {
        let mut client = self.client.lock().unwrap();
        client
            .verify_and_sign(req)
            .map_err(|e| TestError::Vsock(e.to_string()))
    }

    /// 发送原始协议请求
    ///
    /// 直接发送原始协议消息，用于底层协议测试和安全测试。
    /// 支持自定义消息类型和消息体。
    ///
    /// # 参数
    ///
    /// * `msg_type` - 消息类型（如0x10签名请求，0x11验证请求）
    /// * `body` - JSON格式的消息体
    ///
    /// # 返回
    ///
    /// 成功返回原始响应，失败返回TestError
    ///
    /// # 测试场景
    ///
    /// - E16-E20: 协议错误场景测试
    /// - B01-B07: 边界条件和安全测试
    pub fn raw_request(&self, msg_type: u32, body: String) -> Result<RawResponse, TestError> {
        let mut client = self.client.lock().unwrap();
        client
            .send_raw_request_with_response(msg_type, body)
            .map_err(|e| TestError::Vsock(e.to_string()))
    }
}
