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

//! 目标出站与隧道透传（透明代理管道 T5 重构版，说明书 4.3 / K9）。
//!
//! 完整流程闭环后的职责收敛（hyper 服务模型承接逐请求/逐流解析与转发）：
//! - [`TargetConnector`]：目标 TLS 出站（单一 deadline 预算贯穿 DNS+TCP+TLS；
//!   K9 三类错误语义；**ALPN 按连接传入**——与 MITM 侧协商协议一致，D5，
//!   闭合存疑 Q5）；
//! - [`relay_with_idle_timeout`]：Upgrade 隧道的双向字节透传（连接级空闲
//!   超时 + 半关闭传播 + 写路径独立预算）——hyper `on_upgrade()` 原始流
//!   的消费方。
//!
//! 历史：T5 交付的字节隧道模型（ForwardPipeline/RequestHead/
//! read_request_head 手写 HTTP 解析）已随 hyper 服务模型接线退役——
//! 逐请求求值由 server 模块的 hyper service 闭包承接（存疑 Q3 闭环）。

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::model::Reason;

/// 目标出站连接错误（K9 三类语义，映射审计 reason）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetConnectError {
    /// TLS 握手失败（含握手期连接中断、证书校验失败及无法归类的目标侧连接失败）。
    TargetTls,
    /// 目标拒绝连接（TCP ECONNREFUSED）。
    Refused,
    /// 连接/握手超时（connection_timeout 约束）。
    Timeout,
}

impl TargetConnectError {
    /// 对应审计 reason（K9 映射）。
    pub fn reason(&self) -> Reason {
        match self {
            TargetConnectError::TargetTls => Reason::TargetTlsError,
            TargetConnectError::Refused => Reason::ConnectionRefused,
            TargetConnectError::Timeout => Reason::ConnectionTimeout,
        }
    }
}

/// 目标出站连接器：rustls 客户端侧 TLS 连接。
///
/// `ClientConfig` 在构造期构建一次并共享（热路径零重建）；**ALPN 按连接
/// 传入**（`connect` 参数——MITM 侧协商协议，h2 或 http/1.1，D5；闭合
/// 存疑 Q5：连接器按 ALPN 变体缓存至多两份 ClientConfig）。超时为
/// connection_timeout（单一 deadline 预算贯穿 TCP+TLS）；不重试，
/// fail-closed。
pub struct TargetConnector {
    roots: Arc<rustls::RootCertStore>,
    timeout: Duration,
    /// ALPN 变体 → 已构建连接器（至多两份：h2 / http1.1；无 ALPN 一份）。
    connectors: std::sync::Mutex<Vec<(Vec<Vec<u8>>, tokio_rustls::TlsConnector)>>,
}

impl TargetConnector {
    /// 构造连接器（roots：目标信任锚，生产为系统根/集成方配置；测试注入测试 CA）。
    pub fn new(roots: Arc<rustls::RootCertStore>, timeout: Duration) -> Self {
        Self {
            roots,
            timeout,
            connectors: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// connection_timeout（管道各阶段超时预算同源）。
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// 取（或按 ALPN 变体惰性构建并缓存）TlsConnector。
    fn connector_for(&self, alpn: &[String]) -> tokio_rustls::TlsConnector {
        let key: Vec<Vec<u8>> = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        let mut cache = crate::lock_util::recovered(self.connectors.lock(), "connector cache");
        if let Some((_, connector)) = cache.iter().find(|(k, _)| k == &key) {
            return connector.clone();
        }
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates((*self.roots).clone())
            .with_no_client_auth();
        config.alpn_protocols = key.clone();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        cache.push((key, connector.clone()));
        connector
    }

    /// 建立到 `host:port` 的 TLS 连接（SNI=`sni`，证书按 SNI 校验；ALPN 按
    /// MITM 侧协商协议协商——D5）。
    ///
    /// `host` 可为域名（DNS 解析后连接）或 IP 字符串（测试注入本地 fake 目标）。
    /// TCP 连接与 TLS 握手共享单一 deadline 预算（合计 connection_timeout，
    /// D3「连接级超时」口径）。错误映射：ECONNREFUSED→Refused；
    /// deadline 超时/ETIMEDOUT→Timeout；其余（TLS 握手失败、握手期 IO 中断、
    /// 解析失败等目标侧失败）→TargetTls（K9 三类语义的兜底归类）。
    pub async fn connect(
        &self,
        host: &str,
        port: u16,
        sni: &str,
        alpn: &[String],
    ) -> Result<TlsStream<TcpStream>, TargetConnectError> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        // TCP 连接（含域名解析）：单一 deadline 预算。阶段日志（warn）与
        // server 层枚举日志双层共存——原始错误详情在此层保留（定位辅助）。
        let tcp = match tokio::time::timeout_at(deadline, TcpStream::connect((host, port))).await
        {
            Err(_) => {
                crate::log_warn!(
                    "forward",
                    "target connect deadline exceeded (tcp): host={host} port={port}"
                );
                return Err(TargetConnectError::Timeout);
            }
            Ok(Err(e)) => {
                crate::log_warn!(
                    "forward",
                    "target tcp connect failed: host={host} port={port} err={e}"
                );
                return Err(map_tcp_connect_error(e));
            }
            Ok(Ok(tcp)) => tcp,
        };
        let _ = tcp.set_nodelay(true);
        // TLS 握手（客户端侧，SNI 域名校验）：同一 deadline 剩余预算。
        let name = match rustls::pki_types::ServerName::try_from(sni.to_string()) {
            Ok(n) => n,
            Err(_) => {
                crate::log_warn!("forward", "target sni invalid: sni={sni}");
                return Err(TargetConnectError::TargetTls);
            }
        };
        let connector = self.connector_for(alpn);
        match tokio::time::timeout_at(deadline, connector.connect(name, tcp)).await {
            Err(_) => {
                crate::log_warn!(
                    "forward",
                    "target connect deadline exceeded (tls): host={host} port={port}"
                );
                Err(TargetConnectError::Timeout)
            }
            Ok(Err(e)) => {
                crate::log_warn!("forward", "target tls handshake failed: host={host} err={e}");
                Err(TargetConnectError::TargetTls)
            }
            Ok(Ok(stream)) => {
                crate::log_debug!("forward", "target connected: host={host} port={port}");
                Ok(stream)
            }
        }
    }
}

/// TCP 连接阶段错误映射（K9：拒绝/超时精确归类，其余归目标侧失败）。
fn map_tcp_connect_error(e: std::io::Error) -> TargetConnectError {
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused => TargetConnectError::Refused,
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            TargetConnectError::Timeout
        }
        _ => TargetConnectError::TargetTls,
    }
}

/// 双向透传（连接级空闲超时 + 半关闭传播）。
///
/// 空闲语义为**连接级**（任一方向有传输活动即重置共享 deadline）——单向
/// 活跃流式传输（客户端静默接收长响应）不因对向静默被误杀；双向均无活动
/// 超过 idle 才整体超时拆除。某方向结束（EOF/错误/超时）时关闭对端写侧
///（半关闭传播：客户端半关闭后仍能收完整响应），双向均结束后返回。
/// 写路径独立预算：对端持续不消费（本批超过 idle 未排空）即拆除。
///
/// Upgrade 隧道消费方：hyper `on_upgrade()` 的两侧原始流（client 侧经
/// `Upgraded` 流，target 侧为目标 TLS 流）。
pub async fn relay_with_idle_timeout<S, T>(client: S, target: T, idle: Duration)
where
    S: AsyncReadWrite,
    T: AsyncReadWrite,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut target_read, mut target_write) = tokio::io::split(target);
    let last_activity = Arc::new(std::sync::Mutex::new(tokio::time::Instant::now()));
    let up_clock = last_activity.clone();
    let down_clock = last_activity;
    let up = async {
        let result = pump(&mut client_read, &mut target_write, idle, up_clock).await;
        // 本方向结束 → 关闭目标写侧（目标读侧见 EOF，响应侧可继续）。
        let _ = target_write.shutdown().await;
        result
    };
    let down = async {
        let result = pump(&mut target_read, &mut client_write, idle, down_clock).await;
        let _ = client_write.shutdown().await;
        result
    };
    let _ = tokio::join!(up, down);
}

/// 读写双 trait 别名（Upgrade 流与 TLS 流的共同形态）。
pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite> AsyncReadWrite for T {}

/// 单向泵：读 r 写 w。读侧受**连接级空闲**约束（共享活动时钟：deadline
/// 自最近一次任一方向活动起算；到期重查时钟——对向活动已推进则重新武装，
/// 重查仍到期才是真空闲）；写侧独立预算（本批超过 idle 未排空即返回）；
/// EOF/错误/空闲返回（拆除原因经日志观测——2026-09-17 维护定位辅助）。
async fn pump<R, W>(
    r: &mut R,
    w: &mut W,
    idle: Duration,
    last_activity: Arc<std::sync::Mutex<tokio::time::Instant>>,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        // 读：连接级空闲 deadline（武装后不可延长——到期 Elapsed 重查活动
        // 时钟：对向推进过 → 重新武装；未推进 → 真空闲拆除）。
        let n = loop {
            let deadline = *crate::lock_util::recovered(last_activity.lock(), "activity clock") + idle;
            match tokio::time::timeout_at(deadline, r.read(&mut buf)).await {
                Ok(Ok(n)) => break n,
                Ok(Err(e)) => {
                    crate::log_warn!("forward", "tunnel read failed: {e}");
                    return;
                }
                Err(_elapsed) => {
                    let latest = *crate::lock_util::recovered(last_activity.lock(), "activity clock");
                    if latest + idle <= tokio::time::Instant::now() {
                        crate::log_info!("forward", "tunnel idle timeout (connection-level)");
                        return; // 连接级空闲（双向均无活动超过 idle）。
                    }
                    // 对向活动已推进 deadline → 重新武装继续等待。
                }
            }
        };
        if n == 0 {
            crate::log_debug!("forward", "tunnel eof");
            return; // EOF（半关闭传播由调用方 shutdown 处理）。
        }
        // 写超时：独立预算（对端不消费即拆除，内存有界防滞留）。
        let write_deadline = tokio::time::Instant::now() + idle;
        match tokio::time::timeout_at(write_deadline, w.write_all(&buf[..n])).await {
            Ok(Ok(())) => {}
            _ => {
                crate::log_warn!("forward", "tunnel write timeout: peer not consuming");
                return;
            }
        }
        *crate::lock_util::recovered(last_activity.lock(), "activity clock") = tokio::time::Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // K9 错误映射：reason 常量对齐审计枚举。
    #[test]
    fn target_connect_error_reasons() {
        assert_eq!(
            TargetConnectError::TargetTls.reason(),
            Reason::TargetTlsError
        );
        assert_eq!(
            TargetConnectError::Refused.reason(),
            Reason::ConnectionRefused
        );
        assert_eq!(
            TargetConnectError::Timeout.reason(),
            Reason::ConnectionTimeout
        );
    }

    // 空闲泵：源 EOF 结束（不写也不超时）。
    #[tokio::test]
    async fn pump_source_eof() {
        let mut src = &b"abc"[..];
        let mut sink = Vec::new();
        let clock = Arc::new(std::sync::Mutex::new(tokio::time::Instant::now()));
        pump(&mut src, &mut sink, Duration::from_secs(1), clock).await;
        assert_eq!(sink, b"abc");
    }

    // 空闲泵：静默源在 idle 后返回（连接级空闲超时语义）。
    #[tokio::test]
    async fn pump_idle_timeout() {
        // duplex 的对端从不写入 → 读侧静默 → idle 到期返回。
        let (client, _server) = tokio::io::duplex(64);
        let (mut r, _w) = tokio::io::split(client);
        let mut sink = Vec::new();
        let clock = Arc::new(std::sync::Mutex::new(tokio::time::Instant::now()));
        let start = std::time::Instant::now();
        pump(&mut r, &mut sink, Duration::from_millis(100), clock).await;
        assert!(start.elapsed() >= Duration::from_millis(90));
        assert!(sink.is_empty());
    }

    // 连接级空闲（N1 锁定）：客户端发送后持续静默 > idle，目标流式回包
    //（每片间隔 < idle）——隧道不因对向静默被误杀，全部字节到达。
    // FIN 探针：流式期间目标读侧不得收到伪 EOF（一次武装 deadline 实现会
    // 在客户端静默超过 idle 时向目标注入 FIN）。
    #[tokio::test]
    async fn relay_survives_unidirectional_streaming() {
        let idle = Duration::from_millis(150);
        let (mut client_io, client_relay) = tokio::io::duplex(1024);
        let (target_relay, mut target_io) = tokio::io::duplex(1024);
        tokio::spawn(relay_with_idle_timeout(client_relay, target_relay, idle));
        // 客户端发送初始数据后永久静默（总静默 ~300ms > idle 150ms）。
        client_io.write_all(b"req").await.unwrap();
        // 目标先消费初始请求字节（探针期间读侧应无积压数据）。
        let mut req_buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_millis(500), target_io.read(&mut req_buf))
            .await
            .expect("req must reach target")
            .unwrap();
        assert_eq!(&req_buf[..n], b"req");
        // 目标每 60ms 流式回一片（目标侧活动持续重置连接级 deadline）。
        let mut received = Vec::new();
        let mut buf = [0u8; 64];
        for i in 0..5u8 {
            tokio::time::sleep(Duration::from_millis(60)).await;
            target_io.write_all(&[i]).await.unwrap();
            let n = tokio::time::timeout(Duration::from_millis(200), client_io.read(&mut buf))
                .await
                .expect("chunk must arrive (connection-level idle)")
                .unwrap();
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(received, vec![0, 1, 2, 3, 4]);
        // 伪 FIN 探针：连接双向活跃（目标刚完成发送）——目标读侧此刻
        // 收到 EOF 即为伪 FIN 注入。
        let mut probe = [0u8; 8];
        match tokio::time::timeout(Duration::from_millis(60), target_io.read(&mut probe)).await {
            Ok(Ok(0)) => panic!("spurious FIN: target saw EOF while connection active"),
            Ok(Ok(n)) => panic!("unexpected data from client: {n} bytes"),
            Ok(Err(e)) => panic!("target read error: {e}"),
            Err(_) => {} // 仍等待（无 EOF）——连接级空闲语义正确。
        }
    }

    // 半关闭传播（N2 锁定）：客户端写侧半关闭后，目标完整响应仍可达。
    #[tokio::test]
    async fn relay_half_close_response_preserved() {
        let idle = Duration::from_secs(5);
        let (mut client_io, client_relay) = tokio::io::duplex(1024);
        let (target_relay, mut target_io) = tokio::io::duplex(1024);
        tokio::spawn(relay_with_idle_timeout(client_relay, target_relay, idle));
        client_io.write_all(b"req").await.unwrap();
        // 半关闭：客户端停止发送但保持接收。
        client_io.shutdown().await.unwrap();
        // 目标读得请求（半关闭传播为 EOF）后回写完整响应再关闭。
        let mut b = [0u8; 8];
        let _ = tokio::time::timeout(idle, target_io.read(&mut b)).await;
        target_io.write_all(b"response-bytes").await.unwrap();
        drop(target_io);
        // 客户端应收到完整响应（不被提前拆除）。
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            let n = match tokio::time::timeout(idle, client_io.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => n,
                Ok(Err(_)) => break,
            };
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, b"response-bytes");
    }
}
