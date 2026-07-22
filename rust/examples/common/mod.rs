//! 公共模块：TLS连接和消息收发

use std::env;
use std::io::{Read, Write};

pub const VSOCK_CID: u32 = 3;
pub const VSOCK_PORT: u32 = 12345;
pub const VERSION: u32 = 0xFFFF0400;

pub fn get_config() -> (u32, u32) {
    let cid = env::var("TRUSTRUNTIME_CID")
        .map(|v| v.parse().unwrap_or(VSOCK_CID))
        .unwrap_or(VSOCK_CID);
    let port = env::var("TRUSTRUNTIME_PORT")
        .map(|v| v.parse().unwrap_or(VSOCK_PORT))
        .unwrap_or(VSOCK_PORT);
    (cid, port)
}

#[cfg(target_os = "linux")]
pub fn connect_vsock_tls(
    cid: u32,
    port: u32,
) -> Result<openssl::ssl::SslStream<vsock::VsockStream>, String> {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use openssl::x509::X509;
    use vsock::VsockAddr;

    let addr = VsockAddr::new(cid, port);
    let stream = vsock::VsockStream::connect(&addr).map_err(|e| format!("vsock连接失败: {}", e))?;

    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| format!("SSL上下文创建失败: {}", e))?;

    builder.set_verify(SslVerifyMode::PEER);

    let cert_path = env::var("TRUSTRUNTIME_CLIENT_CERT")
        .unwrap_or_else(|_| "/etc/cert/cms/communication/client.crt".to_string());
    let key_path = env::var("TRUSTRUNTIME_CLIENT_KEY")
        .unwrap_or_else(|_| "/etc/cert/cms/communication/client.key".to_string());
    let ca_path = env::var("TRUSTRUNTIME_CA_CERT")
        .unwrap_or_else(|_| "/etc/cert/cms/communication/ca_root.crt".to_string());

    let ca_data = std::fs::read(&ca_path).map_err(|e| format!("CA证书读取失败: {}", e))?;
    let ca = X509::from_pem(&ca_data).map_err(|e| format!("CA证书解析失败: {}", e))?;
    builder
        .cert_store_mut()
        .add_cert(ca)
        .map_err(|e| format!("CA证书添加失败: {}", e))?;

    builder
        .set_certificate_file(&cert_path, openssl::ssl::SslFiletype::PEM)
        .map_err(|e| format!("客户端证书加载失败: {}", e))?;

    builder
        .set_private_key_file(&key_path, openssl::ssl::SslFiletype::PEM)
        .map_err(|e| format!("客户端私钥加载失败: {}", e))?;

    let connector = builder.build();
    connector
        .connect("localhost", stream)
        .map_err(|e| format!("TLS握手失败: {}", e))
}

#[cfg(not(target_os = "linux"))]
pub fn connect_vsock_tls(_cid: u32, _port: u32) -> Result<std::net::TcpStream, String> {
    Err("vsock only supported on Linux".to_string())
}

pub fn send_message(
    stream: &mut impl Write,
    seq: u32,
    msg_type: u32,
    data: &[u8],
) -> Result<(), String> {
    let header = [
        seq.to_le_bytes(),
        VERSION.to_le_bytes(),
        msg_type.to_le_bytes(),
        (data.len() as u32).to_le_bytes(),
    ];
    let header_bytes: Vec<u8> = header.iter().flat_map(|b| b.iter()).copied().collect();

    stream
        .write_all(&header_bytes)
        .map_err(|e| format!("发送header失败: {}", e))?;
    stream
        .write_all(data)
        .map_err(|e| format!("发送data失败: {}", e))?;

    Ok(())
}

pub fn recv_message(stream: &mut impl Read) -> Result<(u32, Vec<u8>), String> {
    let mut header_buf = [0u8; 16];
    stream
        .read_exact(&mut header_buf)
        .map_err(|e| format!("接收header失败: {}", e))?;

    let version = u32::from_le_bytes([header_buf[4], header_buf[5], header_buf[6], header_buf[7]]);
    let msg_type =
        u32::from_le_bytes([header_buf[8], header_buf[9], header_buf[10], header_buf[11]]);
    let len = u32::from_le_bytes([
        header_buf[12],
        header_buf[13],
        header_buf[14],
        header_buf[15],
    ]);

    if version != VERSION {
        return Err(format!("版本不匹配: 0x{:08x}", version));
    }

    if len > 10240 {
        return Err(format!("响应过长: {} bytes", len));
    }

    let mut data_buf = vec![0u8; len as usize];
    if len > 0 {
        stream
            .read_exact(&mut data_buf)
            .map_err(|e| format!("接收data失败: {}", e))?;
    }

    Ok((msg_type, data_buf))
}
