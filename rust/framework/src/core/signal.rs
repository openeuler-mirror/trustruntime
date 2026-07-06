//! Unix信号处理模块
//!
//! 职责：
//! - 监听Unix终止信号（SIGTERM、SIGINT）
//! - 提供线程安全的关闭标志查询接口
//! - 支持异步等待关闭信号
//!
//! 与systemd的关系：
//! - systemd在停止服务时发送SIGTERM信号
//! - 用户按Ctrl+C时发送SIGINT信号
//! - 捕获信号后设置关闭标志，触发优雅关闭流程
//!
//! 架构决策：
//! - 使用AtomicBool实现线程安全的状态共享
//! - 使用tokio::select!同时监听多个信号源
//! - Ordering::SeqCst保证多核CPU上的可见性

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};

/// Unix信号处理器
///
/// 监听SIGTERM和SIGINT信号，提供线程安全的关闭状态查询。
///
/// 线程安全：
/// - 使用Arc<AtomicBool>实现跨线程共享
/// - 原子操作保证无锁并发访问
/// - Ordering::SeqCst提供最强内存顺序保证
///
/// 使用场景：
/// - 主循环中定期检查is_shutdown_requested()
/// - 独立任务中await wait_for_shutdown_signal()
pub struct SignalHandler {
    /// 关闭请求标志（Arc共享以支持跨线程访问）
    shutdown_requested: Arc<AtomicBool>,
}

impl Default for SignalHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalHandler {
    /// 创建信号处理器实例
    ///
    /// 初始化关闭标志为false，注册信号处理器。
    ///
    /// # Returns
    /// 返回新的SignalHandler实例，关闭标志初始为false
    pub fn new() -> Self {
        Self {
            shutdown_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 查询是否收到关闭请求
    ///
    /// 线程安全地查询关闭标志状态。
    ///
    /// # Returns
    /// - `true` - 已收到SIGTERM或SIGINT信号
    /// - `false` - 未收到关闭信号
    ///
    /// # 线程安全
    /// 使用Ordering::SeqCst内存顺序，保证：
    /// - 所有线程看到一致的关闭状态
    /// - 信号处理后的状态对所有线程可见
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// 异步等待关闭信号
    ///
    /// 同时监听SIGTERM和SIGINT信号，任一信号到达即返回。
    ///
    /// # 信号处理机制
    /// - SIGTERM: systemd停止服务时发送（systemctl stop）
    /// - SIGINT: 用户按Ctrl+C时发送
    /// - tokio::select!宏实现多信号源监听，任一信号到达即触发
    ///
    /// # 线程安全
    /// 信号到达后设置shutdown_requested为true：
    /// - 使用Ordering::SeqCst保证跨线程可见性
    /// - is_shutdown_requested()可在其他线程查询到此状态
    ///
    /// # Panics
    /// 如果无法注册信号处理器（极少发生），将panic
    pub async fn wait_for_shutdown_signal(&self) {
        // 注册SIGTERM处理器（systemd停止服务信号）
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
        // 注册SIGINT处理器（Ctrl+C中断信号）
        let mut sigint =
            signal(SignalKind::interrupt()).expect("Failed to register SIGINT handler");

        // tokio::select!同时监听两个信号源
        // 任一信号到达即执行对应分支，另一个分支被取消
        tokio::select! {
            _ = sigterm.recv() => {
                log::info!("Received SIGTERM, initiating shutdown");
            }
            _ = sigint.recv() => {
                log::info!("Received SIGINT, initiating shutdown");
            }
        }

        // 设置关闭标志，使用SeqCst保证跨线程可见性
        self.shutdown_requested.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_handler_initializes_with_shutdown_false() {
        // 场景：创建新的信号处理器
        // 预期：关闭标志初始为false
        let handler = SignalHandler::new();
        assert!(!handler.is_shutdown_requested());
    }

    #[tokio::test]
    async fn signal_handler_can_check_shutdown_status() {
        // 场景：手动设置关闭标志
        // 预期：is_shutdown_requested()返回正确的状态
        let handler = SignalHandler::new();
        assert!(!handler.is_shutdown_requested());
        handler.shutdown_requested.store(true, Ordering::SeqCst);
        assert!(handler.is_shutdown_requested());
    }
}
