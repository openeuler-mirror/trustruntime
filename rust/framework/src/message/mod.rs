//! vsock消息协议模块
//!
//! 职责：
//! - 定义vsock消息格式（VsockHeader + VsockMessage）
//! - 提供消息序列化和反序列化功能
//! - 定义消息解析错误类型
//!
//! 协议规范：
//! - VsockHeader：16字节固定长度（seq:4 + version:4 + msg_type:4 + len:4）
//! - VsockMessage：完整消息（header + data）
//! - 字节序：小端序（Little Endian）
//! - version固定值：0xFFFF0400
//! - len最大值：10240字节（业务层限制，本模块不强制）
//!
//! 架构决策：
//! - 纯数据层，无业务验证（参见 AGENTS.md）
//! - 验证逻辑由vsock_server模块负责
//! - 消息类型含义由插件层定义
//!
//! 依赖：无外部模块依赖

use thiserror::Error;

/// 消息解析错误类型
#[derive(Error, Debug, PartialEq)]
pub enum MessageError {
    /// 头部不完整：字节数小于16字节
    ///
    /// 触发条件：parse()接收到少于16字节的数据
    #[error("incomplete header: bytes < 16")]
    IncompleteHeader,
    /// 数据不完整：实际数据长度与header.len不匹配
    ///
    /// 触发条件：parse()接收到的字节数 != 16 + header.len
    #[error("incomplete data: actual length != header.len")]
    IncompleteData,
}

/// vsock消息头
///
/// 16字节固定长度结构体，采用C内存布局以支持网络传输。
///
/// 字段布局（小端序）：
/// ```text
/// | 偏移 | 长度 | 字段       |
/// |------|------|------------|
/// | 0    | 4    | seq        |
/// | 4    | 4    | version    |
/// | 8    | 4    | msg_type   |
/// | 12   | 4    | len        |
/// ```
///
/// 字段说明：
/// - seq：消息序列号，用于请求响应匹配
/// - version：协议版本号，固定值0xFFFF0400
/// - msg_type：消息类型，由业务层定义（如0x10=签名请求）
/// - len：数据部分长度，最大10240字节
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VsockHeader {
    /// 消息序列号（4字节，小端序）
    pub seq: u32,
    /// 协议版本号（4字节，小端序），固定值0xFFFF0400
    pub version: u32,
    /// 消息类型（4字节，小端序），由业务层定义
    pub msg_type: u32,
    /// 数据长度（4字节，小端序），最大10240字节
    pub len: u32,
}

/// vsock完整消息
///
/// 由消息头和数据部分组成，用于vsock通信的完整消息载体。
///
/// 架构决策：
/// - 本模块为纯数据层，不执行业务验证
/// - version、len、msg_type的合法性由vsock_server模块验证
/// - 数据内容格式由插件层解释
///
/// # Example
/// ```
/// use trustruntime_framework::message::{VsockMessage, VsockHeader};
///
/// // 创建消息
/// let msg = VsockMessage::new(1, 0xFFFF0400, 0x10, b"data".to_vec());
///
/// // 序列化
/// let bytes = msg.serialize();
///
/// // 解析
/// let parsed = VsockMessage::parse(&bytes).unwrap();
/// assert_eq!(parsed.header.seq, 1);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct VsockMessage {
    /// 消息头（16字节）
    pub header: VsockHeader,
    /// 数据部分（长度由header.len指定）
    pub data: Vec<u8>,
}

impl VsockMessage {
    /// 创建新的vsock消息
    ///
    /// 根据提供的参数构造消息头和数据部分。
    /// len字段自动从data长度计算。
    ///
    /// # Arguments
    /// * `seq` - 消息序列号
    /// * `version` - 协议版本号（通常为0xFFFF0400）
    /// * `msg_type` - 消息类型（由业务层定义）
    /// * `data` - 数据部分
    ///
    /// # Returns
    /// 返回构造完整的VsockMessage实例
    ///
    /// # Note
    /// 本方法不验证参数合法性：
    /// - version有效性由调用方保证
    /// - data长度限制（≤10240）由vsock_server验证
    pub fn new(seq: u32, version: u32, msg_type: u32, data: Vec<u8>) -> Self {
        let len = data.len() as u32;
        Self {
            header: VsockHeader {
                seq,
                version,
                msg_type,
                len,
            },
            data,
        }
    }

    /// 序列化消息为字节数组
    ///
    /// 将消息头和数据部分序列化为连续字节数组。
    ///
    /// 字节序：小端序（Little Endian）
    ///
    /// # Returns
    /// 字节数组，长度 = 16 + header.len
    ///
    /// # Layout
    /// ```text
    /// | 头部16字节 | 数据部分 |
    /// | seq(4) | version(4) | msg_type(4) | len(4) | data(len) |
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16 + self.data.len());
        // 小端序写入头部字段
        bytes.extend_from_slice(&self.header.seq.to_le_bytes());
        bytes.extend_from_slice(&self.header.version.to_le_bytes());
        bytes.extend_from_slice(&self.header.msg_type.to_le_bytes());
        bytes.extend_from_slice(&self.header.len.to_le_bytes());
        // 写入数据部分
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// 序列化消息为字节数组（serialize的别名）
    ///
    /// # Returns
    /// 字节数组，长度 = 16 + header.len
    pub fn to_bytes(&self) -> Vec<u8> {
        self.serialize()
    }

    /// 从字节数组解析消息
    ///
    /// 将字节数组解析为VsockMessage实例。
    ///
    /// 字节序：小端序（Little Endian）
    ///
    /// # Arguments
    /// * `bytes` - 原始字节数组
    ///
    /// # Returns
    /// * `Ok(VsockMessage)` - 解析成功
    /// * `Err(MessageError::IncompleteHeader)` - 字节数小于16
    /// * `Err(MessageError::IncompleteData)` - 数据长度不匹配
    ///
    /// # Note
    /// 本方法不验证业务规则：
    /// - version有效性不检查（允许任意值）
    /// - msg_type合法性不检查
    /// - len最大值不检查（业务层限制10240）
    pub fn parse(bytes: &[u8]) -> Result<Self, MessageError> {
        // 检查头部完整性：至少需要16字节
        if bytes.len() < 16 {
            return Err(MessageError::IncompleteHeader);
        }

        // 小端序读取头部字段
        let seq = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let msg_type = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);

        // 检查数据完整性：字节数必须等于16 + len
        if bytes.len() != 16 + len as usize {
            return Err(MessageError::IncompleteData);
        }

        // 提取数据部分
        let data = bytes[16..].to_vec();
        let header = VsockHeader {
            seq,
            version,
            msg_type,
            len,
        };

        Ok(Self { header, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试场景：消息序列化和反序列化往返
    /// 预期结果：解析后的消息与原始消息一致
    #[test]
    fn message_can_be_serialized_and_parsed_back() {
        let msg = VsockMessage::new(1, 0xFFFF0400, 0x10, b"hello".to_vec());
        let bytes = msg.serialize();
        let parsed = VsockMessage::parse(&bytes).unwrap();

        assert_eq!(parsed.header.seq, 1);
        assert_eq!(parsed.header.version, 0xFFFF0400);
        assert_eq!(parsed.header.msg_type, 0x10);
        assert_eq!(parsed.header.len, 5);
        assert_eq!(parsed.data, b"hello".to_vec());
    }

    /// 测试场景：空数据消息
    /// 预期结果：header.len=0，总长度16字节，解析成功
    #[test]
    fn message_with_empty_data_serializes_correctly() {
        let msg = VsockMessage::new(42, 0xFFFF0400, 0x11, vec![]);
        let bytes = msg.serialize();

        assert_eq!(bytes.len(), 16);
        assert_eq!(msg.header.len, 0);

        let parsed = VsockMessage::parse(&bytes).unwrap();
        assert_eq!(parsed.header.len, 0);
        assert_eq!(parsed.data, Vec::<u8>::new());
    }

    /// 测试场景：最大数据长度（10240字节）
    /// 预期结果：序列化后长度=16+10240，解析成功
    ///
    /// 说明：10240为业务层限制，本模块不强制
    #[test]
    fn message_with_max_data_size_roundtrips_correctly() {
        let data = vec![0xABu8; 10240];
        let msg = VsockMessage::new(99, 0xFFFF0400, 0x12, data.clone());
        let bytes = msg.serialize();

        assert_eq!(bytes.len(), 16 + 10240);

        let parsed = VsockMessage::parse(&bytes).unwrap();
        assert_eq!(parsed.header.len, 10240);
        assert_eq!(parsed.data, data);
    }

    /// 测试场景：字节数少于16字节
    /// 预期结果：返回IncompleteHeader错误
    #[test]
    fn parsing_fails_when_bytes_less_than_16() {
        let bytes = vec![0u8; 10];
        let result = VsockMessage::parse(&bytes);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), MessageError::IncompleteHeader);
    }

    /// 测试场景：数据长度不匹配（header.len=10，实际数据=5字节）
    /// 预期结果：返回IncompleteData错误
    #[test]
    fn parsing_fails_when_data_length_mismatch() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0xFFFF0400u32.to_le_bytes());
        bytes.extend_from_slice(&0x10u32.to_le_bytes());
        // len=10，但实际只追加5字节数据
        bytes.extend_from_slice(&10u32.to_le_bytes());
        bytes.extend_from_slice(b"hello");

        let result = VsockMessage::parse(&bytes);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), MessageError::IncompleteData);
    }

    /// 测试场景：边界值处理（seq=0, msg_type=0x00 和 seq=u32::MAX）
    /// 预期结果：正确处理最小值和最大值
    #[test]
    fn message_handles_boundary_values() {
        // 测试最小边界值
        let msg = VsockMessage::new(0, 0xFFFF0400, 0x00, vec![]);
        let bytes = msg.serialize();
        let parsed = VsockMessage::parse(&bytes).unwrap();
        assert_eq!(parsed.header.seq, 0);
        assert_eq!(parsed.header.msg_type, 0x00);

        // 测试最大边界值
        let msg = VsockMessage::new(u32::MAX, 0xFFFF0400, 0x15, vec![1, 2, 3]);
        let bytes = msg.serialize();
        let parsed = VsockMessage::parse(&bytes).unwrap();
        assert_eq!(parsed.header.seq, u32::MAX);
        assert_eq!(parsed.header.msg_type, 0x15);
    }

    /// 测试场景：new()方法不检查数据大小限制
    /// 预期结果：可以创建超过10240字节的消息
    ///
    /// 说明：验证本模块为纯数据层，不执行业务验证
    #[test]
    fn new_does_not_check_data_size() {
        let large_data = vec![0u8; 20000];
        let msg = VsockMessage::new(1, 0xFFFF0400, 0x10, large_data.clone());

        assert_eq!(msg.header.len, 20000);
        assert_eq!(msg.data.len(), 20000);
    }

    /// 测试场景：parse()方法不验证version字段
    /// 预期结果：接受任意version值
    ///
    /// 说明：version验证由vsock_server模块负责
    #[test]
    fn parse_does_not_check_version() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        // 使用非标准version值
        bytes.extend_from_slice(&0x12345678u32.to_le_bytes());
        bytes.extend_from_slice(&0x10u32.to_le_bytes());
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(b"hello");

        let result = VsockMessage::parse(&bytes);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().header.version, 0x12345678);
    }
}
