//! 连接处理相关

use super::error::*;
use crate::message::VsockMessage;
use crate::transport::DataHandler;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

#[cfg(target_os = "linux")]
pub fn handle_connection_blocking(
    mut ssl_stream: openssl::ssl::SslStream<vsock::VsockStream>,
    handlers: Arc<RwLock<HashMap<u32, Box<dyn DataHandler>>>>,
) {
    use std::io::Write;

    log::debug!("New vsock connection established");

    loop {
        match read_message(&mut ssl_stream) {
            Ok(msg) => match process_message(&msg, &handlers) {
                Ok(resp_data) => {
                    let resp = VsockMessage::new(
                        msg.header.seq,
                        msg.header.version,
                        msg.header.msg_type + 1,
                        resp_data,
                    );
                    ssl_stream.write_all(&resp.serialize()).ok();
                }
                Err(error_code) => {
                    send_error_response(
                        &mut ssl_stream,
                        msg.header.seq,
                        msg.header.version,
                        error_code,
                    );
                }
            },
            Err(error_code) => {
                if error_code == ERROR_CONNECTION_CLOSED {
                    break;
                }
            }
        }
    }

    log::debug!("Connection closed");
}

#[cfg(target_os = "linux")]
fn read_message(
    ssl_stream: &mut openssl::ssl::SslStream<vsock::VsockStream>,
) -> Result<VsockMessage, u32> {
    use std::io::Read;

    let mut header_buf = [0u8; HEADER_SIZE];
    if ssl_stream.read_exact(&mut header_buf).is_err() {
        return Err(ERROR_CONNECTION_CLOSED);
    }

    let seq = u32::from_le_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);
    let version = u32::from_le_bytes([header_buf[4], header_buf[5], header_buf[6], header_buf[7]]);
    let len = u32::from_le_bytes([
        header_buf[12],
        header_buf[13],
        header_buf[14],
        header_buf[15],
    ]);

    if version != PROTOCOL_VERSION {
        send_error_response(ssl_stream, seq, version, ERROR_PROTOCOL);
        return Err(ERROR_PROTOCOL);
    }

    if len > MAX_MESSAGE_SIZE {
        send_error_response(ssl_stream, seq, version, ERROR_MESSAGE_TOO_LONG);
        return Err(ERROR_MESSAGE_TOO_LONG);
    }

    let mut body_buf = vec![0u8; len as usize];
    if len > 0 && ssl_stream.read_exact(&mut body_buf).is_err() {
        send_error_response(ssl_stream, seq, version, ERROR_PROTOCOL);
        return Err(ERROR_PROTOCOL);
    }

    let mut full_buf = Vec::with_capacity(HEADER_SIZE + len as usize);
    full_buf.extend_from_slice(&header_buf);
    full_buf.extend_from_slice(&body_buf);

    if VsockMessage::parse(&full_buf).is_err() {
        send_error_response(ssl_stream, seq, version, ERROR_PROTOCOL);
        return Err(ERROR_PROTOCOL);
    }

    Ok(VsockMessage::parse(&full_buf).unwrap())
}

#[cfg(target_os = "linux")]
fn process_message(
    msg: &VsockMessage,
    handlers: &Arc<RwLock<HashMap<u32, Box<dyn DataHandler>>>>,
) -> Result<Vec<u8>, u32> {
    let handlers_guard = handlers.read().unwrap();
    match handlers_guard.get(&msg.header.msg_type) {
        Some(handler) => {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handler.handle(&msg.data)
            }));

            match result {
                Ok(Some(resp_data)) => Ok(resp_data),
                Ok(None) => {
                    log::warn!("Handler returned None for msg_type {}", msg.header.msg_type);
                    Err(ERROR_PROTOCOL)
                }
                Err(_) => {
                    log::error!("Handler panic for msg_type {}", msg.header.msg_type);
                    Err(ERROR_HANDLER_PANIC)
                }
            }
        }
        None => {
            log::warn!("No handler for msg_type {}", msg.header.msg_type);
            Err(ERROR_PROTOCOL)
        }
    }
}

#[cfg(target_os = "linux")]
fn send_error_response(
    ssl_stream: &mut openssl::ssl::SslStream<vsock::VsockStream>,
    seq: u32,
    version: u32,
    error_type: u32,
) {
    use std::io::Write;
    let err = create_error_response(seq, version, error_type);
    ssl_stream.write_all(&err.serialize()).ok();
}

pub fn create_error_response(seq: u32, version: u32, error_type: u32) -> VsockMessage {
    VsockMessage::new(seq, version, error_type, vec![])
}
