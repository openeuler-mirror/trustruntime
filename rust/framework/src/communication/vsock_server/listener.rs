//! 监听循环相关

use super::connection::handle_connection_blocking;
use crate::transport::DataHandler;
use openssl::ssl::SslAcceptor;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use tokio::sync::Semaphore;

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
        let listener_clone = listener.try_clone().ok();
        if listener_clone.is_none() {
            log::error!("Failed to clone listener");
            break;
        }

        let result = tokio::task::spawn_blocking(move || listener_clone.unwrap().accept()).await;

        match result {
            Ok(Ok((stream, addr))) => {
                log::debug!("Accepted connection from {:?}", addr);
                spawn_connection_task(
                    stream,
                    handlers.clone(),
                    semaphore.clone(),
                    ssl_acceptor.clone(),
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

#[cfg(target_os = "linux")]
fn spawn_connection_task(
    stream: vsock::VsockStream,
    handlers: Arc<RwLock<HashMap<u32, Box<dyn DataHandler>>>>,
    semaphore: Arc<Semaphore>,
    ssl_acceptor: Arc<SslAcceptor>,
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
                tokio::task::spawn_blocking(move || {
                    handle_connection_blocking(ssl_stream, handlers_clone);
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
