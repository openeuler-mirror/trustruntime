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

//! 监听循环相关
//!
//! 职责：
//! - 接受新vsock连接
//! - 并发连接限流（信号量）
//! - TLS握手
//!
//! 架构决策：
//! - TransportLayer抽象解耦通信层与插件框架层（ADR-0005）
//! - 并发连接限制防止资源耗尽（AGENTS.md §性能配置）
//!
//! 依赖：connection模块、transport模块

use super::connection::handle_connection_blocking;
use crate::transport::DataHandler;
use openssl::ssl::SslAcceptor;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use tokio::sync::Semaphore;

/// vsock监听循环（异步）
///
/// # 流程
/// 1. 接受新连接（带1秒超时，避免阻塞关闭信号检查）
/// 2. 为每个连接创建独立任务（spawn_connection_task）
/// 3. 收到关闭信号后退出循环
///
/// # Arguments
/// * `listener` - vsock监听器
/// * `handlers` - 消息处理器映射
/// * `semaphore` - 并发连接限制信号量
/// * `shutdown_signal` - 优雅关闭信号
/// * `ssl_acceptor` - TLS服务端接收器
#[cfg(target_os = "linux")]
pub async fn listener_loop_async(
    listener: vsock::VsockListener,
    handlers: Arc<RwLock<HashMap<u32, Box<dyn DataHandler>>>>,
    semaphore: Arc<Semaphore>,
    shutdown_signal: Arc<AtomicBool>,
    ssl_acceptor: Arc<SslAcceptor>,
) {
    log::info!("vsock listener task started (backlog=128)");

    while !shutdown_signal.load(Ordering::SeqCst) {
        let listener_clone = match listener.try_clone() {
            Ok(l) => l,
            Err(e) => {
                log::error!("Failed to clone listener: {}", e);
                break;
            }
        };

        let result = tokio::task::spawn_blocking(move || listener_clone.accept()).await;

        match result {
            Ok(Ok((stream, addr))) => {
                log::debug!("Accepted connection from {:?}", addr);
                spawn_connection_task(
                    stream,
                    handlers.clone(),
                    semaphore.clone(),
                    ssl_acceptor.clone(),
                    shutdown_signal.clone(),
                );
            }
            Ok(Err(ref e))
                if e.raw_os_error() == Some(libc::EAGAIN)
                    || e.raw_os_error() == Some(libc::EWOULDBLOCK) =>
            {
                continue;
            }
            Ok(Err(e)) => {
                log::error!("vsock accept error: {}", e);
            }
            Err(e) => {
                log::error!("spawn_blocking panic: {}", e);
            }
        }
    }

    log::info!("vsock listener task stopped");
}

/// 为新连接创建处理任务
///
/// # 流程
/// 1. 获取信号量许可（限制并发连接数）
/// 2. 执行TLS握手（阻塞操作，使用spawn_blocking）
/// 3. 调用handle_connection_blocking处理连接
///
/// # Arguments
/// * `stream` - vsock流
/// * `handlers` - 消息处理器映射
/// * `semaphore` - 并发连接限制信号量
/// * `ssl_acceptor` - TLS服务端接收器
/// * `shutdown_signal` - 优雅关闭信号
#[cfg(target_os = "linux")]
fn spawn_connection_task(
    stream: vsock::VsockStream,
    handlers: Arc<RwLock<HashMap<u32, Box<dyn DataHandler>>>>,
    semaphore: Arc<Semaphore>,
    ssl_acceptor: Arc<SslAcceptor>,
    shutdown_signal: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        let _permit = semaphore.acquire().await.ok();
        if _permit.is_none() {
            log::warn!("Failed to acquire semaphore permit");
            return;
        }

        log::debug!("Semaphore permit acquired, starting TLS handshake");

        let handlers_clone = handlers.clone();
        let result = tokio::task::spawn_blocking(move || ssl_acceptor.accept(stream)).await;

        match result {
            Ok(Ok(ssl_stream)) => {
                log::debug!("TLS handshake successful");
                let shutdown_signal_clone = shutdown_signal.clone();
                tokio::task::spawn_blocking(move || {
                    handle_connection_blocking(ssl_stream, handlers_clone, shutdown_signal_clone);
                })
                .await
                .ok();
            }
            Ok(Err(e)) => {
                log::warn!("TLS handshake failed: {}", e);
            }
            Err(e) => {
                log::warn!("spawn_blocking error during TLS handshake: {}", e);
            }
        }

        log::debug!("Connection task completed, semaphore permit released");
    });
}
