/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! 连接处理相关
//!
//! 职责：
//! - 处理单个vsock连接的完整生命周期
//! - 消息读取、解析、分发、响应
//!
//! 架构决策：
//! - TransportLayer抽象解耦通信层与插件框架层（ADR-0005）
//! - 统一OpenSSL处理TLS和CMS（ADR-0004）
//!
//! 依赖：error模块、message模块、transport模块

use super::error::*;
use crate::message::VsockMessage;
use crate::transport::DataHandler;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;

/// 处理单个vsock连接的生命周期
///
/// 阻塞式处理连接上的所有消息，直到连接关闭或发生错误
///
/// # 流程
/// 1. 循环读取消息（read_message）
/// 2. 分发到业务处理器（process_message）
/// 3. 发送响应或错误
/// 4. 连接关闭或错误时退出循环
///
/// # Arguments
/// * `ssl_stream` - TLS加密的vsock流
/// * `handlers` - 消息处理器映射（msg_type -> DataHandler）
/// * `shutdown_signal` - 优雅关闭信号
///
/// # 注意
/// socket超时已在TLS握手前设置（listener.rs），此处无需重复设置
#[cfg(target_os = "linux")]
pub fn handle_connection_blocking(
    mut ssl_stream: openssl::ssl::SslStream<vsock::VsockStream>,
    handlers: Arc<RwLock<HashMap<u32, Box<dyn DataHandler>>>>,
    shutdown_signal: Arc<AtomicBool>,
) {
    use std::io::Write;

    log::debug!("New vsock connection established");

    let mut idle_start: Option<Instant> = None;

    loop {
        if shutdown_signal.load(Ordering::SeqCst) {
            log::debug!("Shutdown signal received, closing connection");
            break;
        }
        match read_message(&mut ssl_stream) {
            Ok(msg) => {
                idle_start = None;
                match process_message(&msg, &handlers) {
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
                        log::warn!(
                            "Handler returned error: msg_type 0x{:02X}, error_code 0x{:02X}",
                            msg.header.msg_type,
                            error_code
                        );
                        send_error_response(
                            &mut ssl_stream,
                            msg.header.seq,
                            msg.header.version,
                            error_code,
                        );
                    }
                }
            }
            Err(error_code) => {
                if error_code == ERROR_TIMEOUT {
                    let idle_secs = match idle_start {
                        Some(start) => start.elapsed().as_secs(),
                        None => {
                            idle_start = Some(Instant::now());
                            0
                        }
                    };

                    if idle_secs >= MAX_IDLE_SECS {
                        log::info!("Connection idle timeout: {}s, closing", idle_secs);
                        break;
                    }
                    continue;
                }
                if error_code != ERROR_CONNECTION_CLOSED {
                    log::warn!("Connection error: {}", error_code);
                }
                break;
            }
        }
    }

    log::debug!("Connection closed");
}

/// 从TLS流中读取一条完整消息
///
/// # Returns
/// - `Ok(VsockMessage)` - 成功解析的消息
/// - `Err(ERROR_CONNECTION_CLOSED)` - 连接已关闭
/// - `Err(ERROR_PROTOCOL)` - 协议错误（版本不匹配、解析失败、读取失败）
/// - `Err(ERROR_MESSAGE_TOO_LONG)` - 消息超过10KB限制
///
/// # 内存分配
/// 优化为2次分配：栈上header_buf + 堆上full_buf
#[cfg(target_os = "linux")]
fn read_message(
    ssl_stream: &mut openssl::ssl::SslStream<vsock::VsockStream>,
) -> Result<VsockMessage, u32> {
    use std::io::Read;

    let mut header_buf = [0u8; HEADER_SIZE];
    if let Err(e) = ssl_stream.read_exact(&mut header_buf) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            return Err(ERROR_TIMEOUT);
        }
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
        log::warn!(
            "Protocol version mismatch: expected 0x{:08X}, got 0x{:08X}",
            PROTOCOL_VERSION,
            version
        );
        send_error_response(ssl_stream, seq, version, ERROR_PROTOCOL);
        return Err(ERROR_PROTOCOL);
    }

    if len > MAX_MESSAGE_SIZE {
        log::warn!("Message too long: len {}, max {}", len, MAX_MESSAGE_SIZE);
        send_error_response(ssl_stream, seq, version, ERROR_MESSAGE_TOO_LONG);
        return Err(ERROR_MESSAGE_TOO_LONG);
    }

    let mut full_buf = vec![0u8; HEADER_SIZE + len as usize];
    full_buf[..HEADER_SIZE].copy_from_slice(&header_buf);

    if len > 0 && ssl_stream.read_exact(&mut full_buf[HEADER_SIZE..]).is_err() {
        log::warn!("Failed to read message body");
        send_error_response(ssl_stream, seq, version, ERROR_PROTOCOL);
        return Err(ERROR_PROTOCOL);
    }

    match VsockMessage::parse(&full_buf) {
        Ok(msg) => Ok(msg),
        Err(_) => {
            log::warn!("Message parse failed");
            send_error_response(ssl_stream, seq, version, ERROR_PROTOCOL);
            Err(ERROR_PROTOCOL)
        }
    }
}

/// 处理消息并调用业务处理器
///
/// # Arguments
/// * `msg` - 待处理的消息
/// * `handlers` - 消息处理器映射
///
/// # Returns
/// - `Ok(Vec<u8>)` - 处理成功，返回响应数据
/// - `Err(ERROR_PROTOCOL)` - 处理器不存在或返回None
/// - `Err(ERROR_HANDLER_PANIC)` - 处理器panic
///
/// # 错误处理
/// 使用catch_unwind捕获处理器panic，防止影响其他连接
#[cfg(target_os = "linux")]
fn process_message(
    msg: &VsockMessage,
    handlers: &Arc<RwLock<HashMap<u32, Box<dyn DataHandler>>>>,
) -> Result<Vec<u8>, u32> {
    let handlers_guard = match handlers.read() {
        Ok(guard) => guard,
        Err(_) => {
            log::error!("handlers lock poisoned");
            return Err(ERROR_HANDLER_PANIC);
        }
    };
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

/// 发送错误响应给客户端
///
/// # Arguments
/// * `ssl_stream` - TLS加密的vsock流
/// * `seq` - 消息序列号
/// * `version` - 协议版本
/// * `error_type` - 错误类型码
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

/// 创建错误响应消息
///
/// # Arguments
/// * `seq` - 消息序列号
/// * `version` - 协议版本
/// * `error_type` - 错误类型码
///
/// # Returns
/// 错误响应消息（data字段为空）
pub fn create_error_response(seq: u32, version: u32, error_type: u32) -> VsockMessage {
    VsockMessage::new(seq, version, error_type, vec![])
}
