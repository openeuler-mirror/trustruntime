//! 守护进程生命周期管理模块
//!
//! 职责：
//! - 管理守护进程状态转换（Initializing → Ready → Stopping → Stopped）
//! - 与systemd通知机制集成（sd_notify）
//! - 提供状态查询接口
//!
//! 与systemd的交互：
//! - 通过NOTIFY_SOCKET环境变量检测systemd环境
//! - 使用sd_notify协议向systemd报告状态变化
//! - 支持Type=notify服务类型（systemd等待READY=1通知）
//!
//! 状态转换规则：
//! - Initializing → Ready：服务初始化完成，可接受请求
//! - Ready → Stopping → Stopped：服务开始关闭并最终停止
//! - 状态转换严格顺序，不允许跳跃或回退

use std::env;

/// 守护进程生命周期状态
///
/// 定义守护进程的四种状态，遵循严格的状态转换规则：
///
/// 状态转换图：
/// ```text
/// Initializing → Ready → Stopping → Stopped
/// ```
///
/// 各状态说明：
/// - `Initializing`: 初始化状态，服务启动时的初始状态
/// - `Ready`: 就绪状态，初始化完成，可接受请求
/// - `Stopping`: 停止中状态，正在执行关闭逻辑
/// - `Stopped`: 已停止状态，服务完全关闭
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DaemonState {
    /// 初始化状态：服务启动，正在进行初始化操作
    /// 此时systemd尚未收到READY=1通知
    Initializing,

    /// 就绪状态：初始化完成，服务可接受请求
    /// 已向systemd发送READY=1通知
    Ready,

    /// 停止中状态：服务正在执行关闭逻辑
    /// 已向systemd发送STOPPING=1通知
    Stopping,

    /// 已停止状态：服务完全关闭
    /// 所有资源已释放，不再接受请求
    Stopped,
}

/// 守护进程管理器
///
/// 封装守护进程生命周期管理，与systemd通知机制集成。
///
/// 使用示例：
/// ```text
/// let mut daemon = Daemon::new();  // 状态: Initializing
/// daemon.notify_ready()?;          // 状态: Ready，systemd收到READY=1
/// daemon.notify_status("证书状态正常")?;
/// daemon.notify_stopping()?;       // 状态: Stopped，systemd收到STOPPING=1
/// ```
pub struct Daemon {
    /// 当前守护进程状态
    state: DaemonState,
}

impl Default for Daemon {
    /// 提供默认实现，等同于 `Daemon::new()`
    fn default() -> Self {
        Self::new()
    }
}

impl Daemon {
    /// 创建新的守护进程管理器
    ///
    /// 初始状态为 `Initializing`。
    ///
    /// # Returns
    /// 返回处于 `Initializing` 状态的 `Daemon` 实例
    pub fn new() -> Self {
        Self {
            state: DaemonState::Initializing,
        }
    }

    /// 获取当前守护进程状态
    ///
    /// # Returns
    /// 返回当前状态的不可变引用
    pub fn state(&self) -> &DaemonState {
        &self.state
    }

    /// 私有辅助函数：发送 systemd 通知
    ///
    /// 仅在 NOTIFY_SOCKET 环境变量存在时发送通知。
    /// 非 systemd 环境下静默跳过（不报错）。
    ///
    /// # Arguments
    /// * `unset_env` - 是否清除 NOTIFY_SOCKET 环境变量（READY/STOPPING 时为 true）
    /// * `states` - 要发送的通知状态列表
    ///
    /// # Errors
    /// systemd 通知发送失败时返回错误
    fn send_notify(unset_env: bool, states: &[sd_notify::NotifyState]) -> Result<(), String> {
        if env::var("NOTIFY_SOCKET").is_ok() {
            sd_notify::notify(unset_env, states)
                .map_err(|e| format!("Failed to notify systemd: {}", e))?;
        }
        Ok(())
    }

    /// 私有辅助函数：获取状态名称字符串
    ///
    /// 用于错误消息中的状态显示。
    /// 利用 Debug trait 的格式化输出，无需手动映射。
    ///
    /// # Returns
    /// 返回当前状态的字符串名称
    fn state_name(&self) -> String {
        format!("{:?}", self.state)
    }

    /// 私有辅助函数：执行状态转换
    ///
    /// 验证状态转换合法性并执行转换。
    /// 仅支持单步转换。
    ///
    /// # Arguments
    /// * `target` - 目标状态
    ///
    /// # Errors
    /// 状态转换非法时返回错误（如跳跃转换、回退转换）
    ///
    /// # 状态转换规则
    /// - Initializing → Ready（服务就绪）
    /// - Ready → Stopping（开始关闭）
    /// - Stopping → Stopped（关闭完成）
    fn transition_to(&mut self, target: DaemonState) -> Result<(), String> {
        let valid = matches!(
            (&self.state, target),
            (DaemonState::Initializing, DaemonState::Ready)
                | (DaemonState::Ready, DaemonState::Stopping)
                | (DaemonState::Stopping, DaemonState::Stopped)
        );

        if !valid {
            return Err(format!(
                "Invalid state transition: cannot transition from {} to {:?}",
                self.state_name(),
                target
            ));
        }

        self.state = target;
        Ok(())
    }

    /// 通知systemd服务已就绪
    ///
    /// 将状态从 `Initializing` 转换为 `Ready`，并向systemd发送 `READY=1` 通知。
    ///
    /// # Returns
    /// * `Ok(())` - 状态转换成功，已通知systemd
    /// * `Err(String)` - 状态转换失败（非Initializing状态调用）
    ///
    /// # Errors
    /// - 当前状态非 `Initializing` 时返回错误
    /// - systemd通知失败时返回错误（仅当NOTIFY_SOCKET存在时）
    ///
    /// # systemd通知机制
    /// - 检查 `NOTIFY_SOCKET` 环境变量是否存在
    /// - 若存在，调用 `sd_notify::notify` 发送 `Ready` 状态
    /// - systemd收到通知后结束服务启动等待阶段（Type=notify）
    ///
    /// # Example
    /// ```text
    /// let mut daemon = Daemon::new();
    /// daemon.notify_ready()?;  // systemd结束启动等待
    /// ```
    pub fn notify_ready(&mut self) -> Result<(), String> {
        self.transition_to(DaemonState::Ready)?;
        Self::send_notify(false, &[sd_notify::NotifyState::Ready])?;
        Ok(())
    }

    /// 通知systemd服务正在停止
    ///
    /// 将状态从 `Ready` 转换为 `Stopping` 再到 `Stopped`，并向systemd发送 `STOPPING=1` 通知。
    ///
    /// # Returns
    /// * `Ok(())` - 状态转换成功，已通知systemd
    /// * `Err(String)` - 状态转换失败（非Ready状态调用）
    ///
    /// # Errors
    /// - 当前状态非 `Ready` 时返回错误
    /// - systemd通知失败时返回错误（仅当NOTIFY_SOCKET存在时）
    ///
    /// # systemd通知机制
    /// - 检查 `NOTIFY_SOCKET` 环境变量是否存在
    /// - 若存在，调用 `sd_notify::notify` 发送 `Stopping` 状态
    /// - systemd收到通知后延长服务关闭超时（ExtendingTimeout）
    ///
    /// # Example
    /// ```text
    /// let mut daemon = Daemon::new();
    /// daemon.notify_ready()?;
    /// daemon.notify_stopping()?;  // systemd延长关闭超时
    /// ```
    pub fn notify_stopping(&mut self) -> Result<(), String> {
        // 状态转换规则：仅允许从 Ready 转换到 Stopping
        if self.state != DaemonState::Ready {
            return Err(format!(
                "Invalid state transition: cannot notify_stopping from {}",
                self.state_name()
            ));
        }

        // 第一步：Ready → Stopping（发送 STOPPING=1）
        self.state = DaemonState::Stopping;
        Self::send_notify(true, &[sd_notify::NotifyState::Stopping])?;

        // 第二步：Stopping → Stopped（不发送通知）
        self.state = DaemonState::Stopped;
        Ok(())
    }

    /// 向systemd报告服务状态信息
    ///
    /// 在任意状态下向systemd发送状态字符串，用于报告服务运行状态。
    /// 此方法不会改变守护进程状态。
    ///
    /// # Arguments
    /// * `status` - 状态信息字符串（如"证书过期"、"连接数: 10"）
    ///
    /// # Returns
    /// * `Ok(())` - 状态报告成功
    /// * `Err(String)` - systemd通知失败（仅当NOTIFY_SOCKET存在时）
    ///
    /// # Errors
    /// - systemd通知失败时返回错误
    ///
    /// # systemd通知机制
    /// - 检查 `NOTIFY_SOCKET` 环境变量是否存在
    /// - 若存在，调用 `sd_notify::notify` 发送 `Status` 消息
    /// - systemd将状态信息记录到journal日志（systemd status命令可见）
    ///
    /// # 使用场景
    /// - 报告证书过期状态
    /// - 报告连接数变化
    /// - 报告关键资源状态
    ///
    /// # Example
    /// ```text
    /// let mut daemon = Daemon::new();
    /// daemon.notify_ready()?;
    /// daemon.notify_status("通信证书已过期，请更新")?;
    /// daemon.notify_status("当前活跃连接: 5")?;
    /// ```
    pub fn notify_status(&mut self, status: &str) -> Result<(), String> {
        Self::send_notify(false, &[sd_notify::NotifyState::Status(status)])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_initializes_with_initializing_state() {
        // 场景：创建新的Daemon实例
        // 预期：初始状态为Initializing
        let daemon = Daemon::new();
        assert_eq!(daemon.state(), &DaemonState::Initializing);
    }

    #[test]
    fn daemon_can_transition_to_ready_state() {
        // 场景：从Initializing状态调用notify_ready
        // 预期：状态转换为Ready，方法返回Ok
        let mut daemon = Daemon::new();
        let result = daemon.notify_ready();
        assert!(result.is_ok());
        assert_eq!(daemon.state(), &DaemonState::Ready);
    }

    #[test]
    fn daemon_can_transition_to_stopping_state() {
        // 场景：从Ready状态调用notify_stopping
        // 预期：状态转换为Stopped，方法返回Ok
        let mut daemon = Daemon::new();
        daemon.notify_ready().unwrap();
        let result = daemon.notify_stopping();
        assert!(result.is_ok());
        assert_eq!(daemon.state(), &DaemonState::Stopped);
    }

    #[test]
    fn notify_ready_fails_from_ready_state() {
        // 场景：从Ready状态调用notify_ready（非法转换）
        // 预期：方法返回错误，错误信息包含"Invalid state transition"
        let mut daemon = Daemon::new();
        daemon.notify_ready().unwrap();
        let result = daemon.notify_ready();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid state transition"));
    }

    #[test]
    fn notify_ready_fails_from_stopped_state() {
        // 场景：从Stopped状态调用notify_ready（非法转换）
        // 预期：方法返回错误，错误信息包含"Invalid state transition"
        let mut daemon = Daemon::new();
        daemon.notify_ready().unwrap();
        daemon.notify_stopping().unwrap();
        let result = daemon.notify_ready();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid state transition"));
    }

    #[test]
    fn notify_stopping_fails_from_initializing_state() {
        // 场景：从Initializing状态调用notify_stopping（非法转换）
        // 预期：方法返回错误，错误信息包含"Invalid state transition"
        let mut daemon = Daemon::new();
        let result = daemon.notify_stopping();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid state transition"));
    }

    #[test]
    fn notify_status_works_in_any_state() {
        // 场景：在Initializing、Ready、Stopped三种状态下调用notify_status
        // 预期：所有调用都成功，状态不变
        let mut daemon = Daemon::new();
        assert!(daemon.notify_status("test status").is_ok());

        daemon.notify_ready().unwrap();
        assert!(daemon
            .notify_status("communication certificate expired")
            .is_ok());

        daemon.notify_stopping().unwrap();
        assert!(daemon.notify_status("shutting down").is_ok());
    }

    #[test]
    fn notify_status_without_notify_socket_succeeds() {
        // 场景：NOTIFY_SOCKET环境变量不存在时调用notify_status
        // 预期：方法返回Ok（不发送systemd通知）
        env::remove_var("NOTIFY_SOCKET");
        let mut daemon = Daemon::new();
        let result = daemon.notify_status("test");
        assert!(result.is_ok());
    }
}
