//! vsock客户端模块
//!
//! 提供与trustruntime服务端通信的客户端实现。
//! 通过vsock+TLS建立安全连接，发送签名/验签请求。
//!
//! ## 协议格式
//! 消息格式遵循框架消息协议（小端字节序）：
//! ```text
//! | seq (4B) | version (4B) | msg_type (4B) | len (4B) | body (N bytes) |
//! ```
//!
//! ## 使用示例
//! ```text
//! // 连接服务端
//! let client = VsockClient::connect(port, tls_ca, client_cert, client_key, None)?;
//! // 发送签名请求
//! let response = client.sign("test data")?;
//! ```

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::PathBuf;
use thiserror::Error;

/// vsock客户端错误类型
#[derive(Error, Debug)]
pub enum VsockError {
    /// 连接失败
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    /// TLS握手失败
    #[error("tls handshake failed: {0}")]
    TlsHandshake(String),
    /// 发送失败
    #[error("send failed: {0}")]
    SendFailed(String),
    /// 接收失败
    #[error("receive failed: {0}")]
    ReceiveFailed(String),
    /// 解析失败
    #[error("parse failed: {0}")]
    ParseFailed(String),
    /// Base64解码失败
    #[error("base64 decode failed: {0}")]
    Base64Error(String),
}

/// vsock协议版本号
const VSOCK_VERSION: u32 = 0xFFFF0400;

/// 签名请求消息类型
const MSG_TYPE_SIGN_REQ: u32 = 0x10;

/// 验签+签名组合请求消息类型
const MSG_TYPE_VERIFY_SIGN_REQ: u32 = 0x12;

/// 验签请求消息类型
const MSG_TYPE_VERIFY_REQ: u32 = 0x14;

/// 签名请求结构
#[derive(Serialize, Deserialize)]
pub struct SignRequest {
    #[serde(rename = "to-sign")]
    to_sign: ToSign,
}

/// 待签名数据
#[derive(Serialize, Deserialize)]
struct ToSign {
    data: String,
}

/// 签名响应结构
///
/// 返回Base64编码的签名数据和证书ID。
#[derive(Serialize, Deserialize, Debug)]
pub struct SignResponse {
    /// Base64编码的CMS签名数据
    pub signed_data: String,
    /// Base64编码的证书ID（Subject Key Identifier）
    pub id: String,
    /// 结果码（0=成功，非0=错误）
    pub result: u32,
}

/// 验签+签名组合请求结构
///
/// 用于原子性操作：先验签已签名数据，再签名新数据。
///
/// # 字段说明
/// - `to_verify`: 待验证数据（原始数据、签名数据、证书ID）
/// - `to_sign`: 待签名数据（新数据、期望的证书ID）
#[derive(Serialize, Deserialize)]
pub struct VerifySignRequest {
    #[serde(rename = "to-verify")]
    pub to_verify: ToVerify,
    #[serde(rename = "to-sign")]
    pub to_sign: ToSignWithId,
}

/// 待验证数据
#[derive(Serialize, Deserialize)]
pub struct ToVerify {
    /// 原始数据
    pub data: String,
    /// Base64编码的签名数据
    pub signed_data: String,
    /// Base64编码的签名者证书ID
    pub id: String,
}

/// 待签名数据（带指定ID）
#[derive(Serialize, Deserialize)]
pub struct ToSignWithId {
    /// 待签名数据
    pub data: String,
    /// 期望的签名者证书ID
    pub id: String,
}

/// 验签+签名组合响应结构
#[derive(Serialize, Deserialize, Debug)]
pub struct VerifySignResponse {
    /// Base64编码的新签名数据
    pub signed_data: String,
    /// Base64编码的证书ID
    pub id: String,
    /// 验签结果码（0=成功，非0=错误）
    pub result: u32,
}

/// 验签请求结构
#[derive(Serialize, Deserialize)]
pub struct VerifyRequest {
    #[serde(rename = "to-verify")]
    to_verify: ToVerify,
}

/// 验签响应结构
#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyResponse {
    /// 验签结果码
    pub result: u32,
}

/// 原始响应结构
///
/// 用于调试和边界测试，包含完整的消息头信息。
#[derive(Debug)]
pub struct RawResponse {
    /// 消息类型
    pub msg_type: u32,
    /// 消息体长度
    pub len: u32,
    /// 消息体数据
    pub body: Vec<u8>,
}

/// vsock消息头结构
///
/// 协议格式（16字节，小端字节序）：
/// | seq (4B) | version (4B) | msg_type (4B) | len (4B) |
#[repr(C)]
struct VsockHeader {
    /// 序列号
    seq: u32,
    /// 协议版本
    version: u32,
    /// 消息类型
    msg_type: u32,
    /// 消息体长度
    len: u32,
}

/// vsock客户端
///
/// 提供与服务端的vsock+TLS安全连接，支持签名和验签操作。
pub struct VsockClient {
    /// 底层流（vsock或TCP，可能包装TLS）
    stream: Box<dyn VsockStream>,
}

/// 流抽象trait
///
/// 支持vsock::VsockStream和std::net::TcpStream的统一操作。
trait VsockStream: Read + Write + Send {}

impl<T: Read + Write + Send> VsockStream for T {}

impl VsockClient {
    /// 连接到服务端
    ///
    /// 建立vsock连接并完成TLS握手。
    ///
    /// # Arguments
    /// * `port` - vsock端口
    /// * `tls_ca_cert` - TLS CA证书路径
    /// * `tls_client_cert` - TLS客户端证书路径
    /// * `tls_client_key` - TLS客户端私钥路径
    /// * `key_password` - 私钥密码（可选，用于加密私钥）
    ///
    /// # Returns
    /// 成功返回客户端实例
    ///
    /// # Errors
    /// 连接失败或TLS握手失败时返回错误
    pub fn connect(
        port: u32,
        tls_ca_cert: &PathBuf,
        tls_client_cert: &PathBuf,
        tls_client_key: &PathBuf,
        key_password: Option<&str>,
    ) -> Result<Self, VsockError> {
        // 使用VMADDR_CID_LOCAL (1) 作为连接CID
        let cid: u32 = 1;

        let raw_stream =
            connect_vsock(cid, port).map_err(|e| VsockError::ConnectionFailed(e.to_string()))?;

        let tls_stream = wrap_with_tls(
            raw_stream,
            tls_ca_cert,
            tls_client_cert,
            tls_client_key,
            key_password,
        )
        .map_err(|e| VsockError::TlsHandshake(e.to_string()))?;

        Ok(Self {
            stream: Box::new(tls_stream),
        })
    }

    /// 发送签名请求
    ///
    /// # Arguments
    /// * `data` - 待签名数据
    ///
    /// # Returns
    /// 签名响应
    pub fn sign(&mut self, data: &str) -> Result<SignResponse, VsockError> {
        let req = SignRequest {
            to_sign: ToSign {
                data: data.to_string(),
            },
        };

        let resp_bytes = self.send_request(MSG_TYPE_SIGN_REQ, &req)?;

        serde_json::from_slice(&resp_bytes).map_err(|e| VsockError::ParseFailed(e.to_string()))
    }

    /// 发送验签+签名组合请求
    ///
    /// # Arguments
    /// * `req` - 组合请求结构
    ///
    /// # Returns
    /// 组合响应
    pub fn verify_and_sign(
        &mut self,
        req: VerifySignRequest,
    ) -> Result<VerifySignResponse, VsockError> {
        let resp_bytes = self.send_request(MSG_TYPE_VERIFY_SIGN_REQ, &req)?;

        serde_json::from_slice(&resp_bytes).map_err(|e| VsockError::ParseFailed(e.to_string()))
    }

    /// 发送验签请求
    ///
    /// # Arguments
    /// * `data` - 原始数据
    /// * `signed_data` - Base64编码的签名数据
    /// * `id` - Base64编码的证书ID
    ///
    /// # Returns
    /// 验签响应
    pub fn verify(
        &mut self,
        data: &str,
        signed_data: &str,
        id: &str,
    ) -> Result<VerifyResponse, VsockError> {
        let req = VerifyRequest {
            to_verify: ToVerify {
                data: data.to_string(),
                signed_data: signed_data.to_string(),
                id: id.to_string(),
            },
        };

        let resp_bytes = self.send_request(MSG_TYPE_VERIFY_REQ, &req)?;

        serde_json::from_slice(&resp_bytes).map_err(|e| VsockError::ParseFailed(e.to_string()))
    }

    /// 发送原始验签请求
    ///
    /// 用于边界测试，允许发送自定义格式的JSON。
    ///
    /// # Arguments
    /// * `raw_json` - 原始JSON字符串
    pub fn verify_raw(&mut self, raw_json: String) -> Result<VerifyResponse, VsockError> {
        let resp_bytes = self.send_raw_request(MSG_TYPE_VERIFY_REQ, raw_json)?;

        serde_json::from_slice(&resp_bytes).map_err(|e| VsockError::ParseFailed(e.to_string()))
    }

    /// 发送请求并接收响应
    ///
    /// 内部方法，序列化请求并发送到服务端。
    fn send_request<T: Serialize>(
        &mut self,
        msg_type: u32,
        req: &T,
    ) -> Result<Vec<u8>, VsockError> {
        let body = serde_json::to_vec(req).map_err(|e| VsockError::ParseFailed(e.to_string()))?;

        self.send_raw_request(msg_type, String::from_utf8(body).unwrap())
    }

    /// 发送原始请求
    ///
    /// 用于边界测试，直接发送原始JSON字符串。
    fn send_raw_request(&mut self, msg_type: u32, raw_json: String) -> Result<Vec<u8>, VsockError> {
        let body = raw_json.into_bytes();

        let seq: u32 = 1;
        let version: u32 = VSOCK_VERSION;
        let len: u32 = body.len() as u32;

        // 构建消息头（小端字节序）
        let mut header_bytes = [0u8; 16];
        header_bytes[0..4].copy_from_slice(&seq.to_le_bytes());
        header_bytes[4..8].copy_from_slice(&version.to_le_bytes());
        header_bytes[8..12].copy_from_slice(&msg_type.to_le_bytes());
        header_bytes[12..16].copy_from_slice(&len.to_le_bytes());

        self.stream
            .write_all(&header_bytes)
            .map_err(|e| VsockError::SendFailed(e.to_string()))?;

        self.stream
            .write_all(&body)
            .map_err(|e| VsockError::SendFailed(e.to_string()))?;

        self.stream
            .flush()
            .map_err(|e| VsockError::SendFailed(e.to_string()))?;

        let resp_header = self.read_header()?;

        if resp_header.len == 0 {
            return Ok(Vec::new());
        }

        let resp_body = self.read_body(resp_header.len)?;

        Ok(resp_body)
    }

    /// 发送原始请求并返回完整响应信息
    ///
    /// 用于边界测试和安全测试，返回包含消息头的完整响应。
    ///
    /// # Arguments
    /// * `msg_type` - 消息类型
    /// * `body` - 消息体JSON字符串
    ///
    /// # Returns
    /// RawResponse包含msg_type、len和body
    pub fn send_raw_request_with_response(
        &mut self,
        msg_type: u32,
        body: String,
    ) -> Result<RawResponse, VsockError> {
        let raw_json_bytes = body.into_bytes();

        let seq: u32 = 1;
        let version: u32 = VSOCK_VERSION;
        let len: u32 = raw_json_bytes.len() as u32;

        // 构建消息头（小端字节序）
        let mut header_bytes = [0u8; 16];
        header_bytes[0..4].copy_from_slice(&seq.to_le_bytes());
        header_bytes[4..8].copy_from_slice(&version.to_le_bytes());
        header_bytes[8..12].copy_from_slice(&msg_type.to_le_bytes());
        header_bytes[12..16].copy_from_slice(&len.to_le_bytes());

        self.stream
            .write_all(&header_bytes)
            .map_err(|e| VsockError::SendFailed(e.to_string()))?;

        self.stream
            .write_all(&raw_json_bytes)
            .map_err(|e| VsockError::SendFailed(e.to_string()))?;

        self.stream
            .flush()
            .map_err(|e| VsockError::SendFailed(e.to_string()))?;

        let resp_header = self.read_header()?;
        let resp_body = if resp_header.len > 0 {
            self.read_body(resp_header.len)?
        } else {
            Vec::new()
        };

        Ok(RawResponse {
            msg_type: resp_header.msg_type,
            len: resp_header.len,
            body: resp_body,
        })
    }

    /// 读取响应头
    ///
    /// 解析16字节的响应头，提取消息元信息。
    fn read_header(&mut self) -> Result<VsockHeader, VsockError> {
        let mut header_bytes = [0u8; 16];
        self.stream
            .read_exact(&mut header_bytes)
            .map_err(|e| VsockError::ReceiveFailed(e.to_string()))?;

        // 小端字节序解析
        let seq = u32::from_le_bytes([
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ]);
        let version = u32::from_le_bytes([
            header_bytes[4],
            header_bytes[5],
            header_bytes[6],
            header_bytes[7],
        ]);
        let msg_type = u32::from_le_bytes([
            header_bytes[8],
            header_bytes[9],
            header_bytes[10],
            header_bytes[11],
        ]);
        let len = u32::from_le_bytes([
            header_bytes[12],
            header_bytes[13],
            header_bytes[14],
            header_bytes[15],
        ]);

        Ok(VsockHeader {
            seq,
            version,
            msg_type,
            len,
        })
    }

    /// 读取响应体
    ///
    /// 根据头部长度读取完整消息体。
    fn read_body(&mut self, len: u32) -> Result<Vec<u8>, VsockError> {
        let mut body = vec![0u8; len as usize];
        self.stream
            .read_exact(&mut body)
            .map_err(|e| VsockError::ReceiveFailed(e.to_string()))?;
        Ok(body)
    }

    /// 关闭连接
    pub fn close(&mut self) -> Result<(), VsockError> {
        Ok(())
    }

    /// 发送原始头信息（边界测试用）
    ///
    /// 用于测试服务端对异常消息头的处理。
    /// 可发送指定版本号、消息类型和长度的头信息。
    ///
    /// # Arguments
    /// * `version` - 协议版本（可发送错误版本）
    /// * `msg_type` - 消息类型（可发送未知类型）
    /// * `len` - 消息体长度（可发送错误长度）
    ///
    /// # Returns
    /// RawResponse包含服务端返回的完整响应信息
    pub fn send_raw_header(
        &mut self,
        version: u32,
        msg_type: u32,
        len: u32,
    ) -> Result<RawResponse, VsockError> {
        let seq: u32 = 1;

        let mut header_bytes = [0u8; 16];
        header_bytes[0..4].copy_from_slice(&seq.to_le_bytes());
        header_bytes[4..8].copy_from_slice(&version.to_le_bytes());
        header_bytes[8..12].copy_from_slice(&msg_type.to_le_bytes());
        header_bytes[12..16].copy_from_slice(&len.to_le_bytes());

        self.stream
            .write_all(&header_bytes)
            .map_err(|e| VsockError::SendFailed(e.to_string()))?;

        // 发送指定长度的dummy数据
        if len > 0 {
            let dummy_body = vec![0u8; len as usize];
            self.stream
                .write_all(&dummy_body)
                .map_err(|e| VsockError::SendFailed(e.to_string()))?;
        }

        self.stream
            .flush()
            .map_err(|e| VsockError::SendFailed(e.to_string()))?;

        let resp_header = self.read_header()?;

        let resp_body = if resp_header.len > 0 {
            self.read_body(resp_header.len)?
        } else {
            Vec::new()
        };

        Ok(RawResponse {
            msg_type: resp_header.msg_type,
            len: resp_header.len,
            body: resp_body,
        })
    }
}

/// 连接vsock（Linux平台）
///
/// 使用原生vsock API建立连接。
#[cfg(target_os = "linux")]
fn connect_vsock(cid: u32, port: u32) -> Result<vsock::VsockStream, std::io::Error> {
    use vsock::VsockAddr;
    let addr = VsockAddr::new(cid, port);
    vsock::VsockStream::connect(&addr)
}

/// 连接vsock（非Linux平台）
///
/// Windows等平台不支持vsock，使用TCP作为替代。
#[cfg(not(target_os = "linux"))]
fn connect_vsock(cid: u32, port: u32) -> Result<std::net::TcpStream, std::io::Error> {
    std::net::TcpStream::connect(("127.0.0.1", port as u16))
}

/// 包装TLS层（Linux平台）
///
/// 使用OpenSSL建立TLS连接，验证服务端证书并提供客户端证书。
#[cfg(target_os = "linux")]
fn wrap_with_tls(
    stream: vsock::VsockStream,
    ca_cert: &PathBuf,
    client_cert: &PathBuf,
    client_key: &PathBuf,
    key_password: Option<&str>,
) -> Result<openssl::ssl::SslStream<vsock::VsockStream>, VsockError> {
    use openssl::pkey::PKey;
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use openssl::x509::X509;

    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| VsockError::TlsHandshake(e.to_string()))?;

    // 加载CA证书用于验证服务端
    let ca = X509::from_pem(
        &std::fs::read(ca_cert).map_err(|e| VsockError::TlsHandshake(e.to_string()))?,
    )
    .map_err(|e| VsockError::TlsHandshake(e.to_string()))?;
    builder
        .cert_store_mut()
        .add_cert(ca)
        .map_err(|e| VsockError::TlsHandshake(e.to_string()))?;

    // 加载客户端证书
    builder
        .set_certificate_file(client_cert, openssl::ssl::SslFiletype::PEM)
        .map_err(|e| VsockError::TlsHandshake(e.to_string()))?;

    // 加载客户端私钥（支持加密私钥）
    if let Some(pwd) = key_password {
        let key_data =
            std::fs::read(client_key).map_err(|e| VsockError::TlsHandshake(e.to_string()))?;
        let pkey = PKey::private_key_from_pem_passphrase(&key_data, pwd.as_bytes())
            .or_else(|_| PKey::private_key_from_pkcs8_passphrase(&key_data, pwd.as_bytes()))
            .map_err(|e| VsockError::TlsHandshake(e.to_string()))?;
        builder
            .set_private_key(&pkey)
            .map_err(|e| VsockError::TlsHandshake(e.to_string()))?;
    } else {
        builder
            .set_private_key_file(client_key, openssl::ssl::SslFiletype::PEM)
            .map_err(|e| VsockError::TlsHandshake(e.to_string()))?;
    }

    // 启用服务端证书验证
    builder.set_verify(SslVerifyMode::PEER);

    let connector = builder.build();
    connector
        .connect("localhost", stream)
        .map_err(|e| VsockError::TlsHandshake(e.to_string()))
}

/// 包装TLS层（非Linux平台）
///
/// Windows等平台不支持vsock TLS，直接返回TCP流。
#[cfg(not(target_os = "linux"))]
fn wrap_with_tls(
    stream: std::net::TcpStream,
    _ca_cert: &PathBuf,
    _client_cert: &PathBuf,
    _client_key: &PathBuf,
    _key_password: Option<&str>,
) -> Result<std::net::TcpStream, VsockError> {
    Ok(stream)
}

/// 构建验签+签名组合请求
///
/// 便捷函数，用于构造VerifySignRequest结构。
///
/// # Arguments
/// * `data_to_verify` - 待验证的原始数据
/// * `signed_data` - Base64编码的签名数据
/// * `id` - Base64编码的签名者证书ID
/// * `new_data` - 待签名的新数据
/// * `new_id` - 期望的签名者证书ID
pub fn build_verify_sign_request(
    data_to_verify: &str,
    signed_data: &str,
    id: &str,
    new_data: &str,
    new_id: &str,
) -> VerifySignRequest {
    VerifySignRequest {
        to_verify: ToVerify {
            data: data_to_verify.to_string(),
            signed_data: signed_data.to_string(),
            id: id.to_string(),
        },
        to_sign: ToSignWithId {
            data: new_data.to_string(),
            id: new_id.to_string(),
        },
    }
}
