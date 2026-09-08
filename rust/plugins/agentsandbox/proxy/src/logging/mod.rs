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

//! 统一日志入口（审计 + 运行日志；2026-09-01 概念修订：原「告警/调试」
//! 二分收敛为**运行日志**，四级 debug/info/warn/error；2026-09-05 收敛：
//! crate 仅以 lib 形态交付——**单一回调路径**，log 门面兜底与文件后端
//! 已随独立进程形态移除）。
//!
//! # 设计模型
//!
//! crate 内全部日志输出（审计条目、运行日志）单点经本模块分发到集成方
//! 经 [`crate::facade::register_log_sink`] 注册的统一回调（[`LogSink`]）：
//! 全部日志以 [`LogEvent`]（含类别 [`LogKind`]、级别 [`LogLevel`] 与
//! 审计结构化条目）转发，由集成方自行处理（落盘/转发）。
//!
//! # 失败语义（fail-closed）
//!
//! - **审计**：回调未注册 / handler 返回 [`Err`](LogSinkError) →
//!   [`audit`] 返回 `Err` 向上传播——转发管道据此关闭连接（无未审计
//!   流量通过）。**`register_log_sink` 为必需 API**（未注册时全部
//!   转发流量 503）。
//! - **运行日志**：fire-and-forget——回调未注册直接丢弃；handler 失败
//!   同样丢弃（不影响业务流）。
//!
//! # 使用方式
//!
//! ```text
//! proxy::register_log_sink(Arc::new(|event: &LogEvent| { ...; Ok(()) }));
//! ```

use std::sync::{Arc, RwLock};

use crate::model::AuditLogEntry;

/// 日志类别（统一回调的事件分类维度：审计 / 运行日志）。
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    /// 审计条目（结构化 [`AuditLogEntry`]，JSON 行渲染）。
    Audit,
    /// 运行日志（级别见 [`LogEvent::level`]）。
    Run,
}

/// 运行日志级别（四级，对齐 log 生态；2026-09-01 概念修订）。
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// 高频细节（请求级决策/连接收尾等）。
    Debug,
    /// 关键运行事件（启动完成/连接建立等）。
    Info,
    /// 可继续的运行异常（目标不可达/校验缺失等）。
    Warn,
    /// 不变量破坏/审计交付失败/启动失败（需立即关注）。
    Error,
}

/// 统一日志事件（lib 回调入参：单回调承载全部类别，集成方按 `kind`
/// 与 `level` 分流；审计事件 level 约定为 [`LogLevel::Info`]——对齐文件
/// 后端审计 logger 恒 Info 的路由形态）。
#[derive(Debug, Clone)]
pub struct LogEvent {
    /// 日志类别。
    pub kind: LogKind,
    /// 运行日志级别（Audit 事件为 Info）。
    pub level: LogLevel,
    /// 来源子系统（如 "forward"/"listener"/"registry"）。
    pub subsystem: String,
    /// 渲染消息（审计类别为 JSON 行；运行日志为文本）。
    pub message: String,
    /// 审计结构化条目（仅 `kind == Audit` 时存在）。
    pub audit: Option<AuditLogEntry>,
}

/// 统一日志回调错误（K13：handler 返回 Err 表示集成方侧处理失败；
/// 审计路径触发调用方 fail-closed）。
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LogSinkError {
    /// 回调处理失败（集成方侧错误，语义不透明）。
    #[error("log_sink_error")]
    Sink,
}

/// 统一日志回调类型（lib 集成经 `register_log_sink` 注册，重复注册覆盖）。
pub type LogSink = Arc<dyn Fn(&LogEvent) -> Result<(), LogSinkError> + Send + Sync>;

/// 已安装的统一回调（None = 未注册——审计 fail-closed / 运行日志丢弃）。
static CALLBACK: RwLock<Option<LogSink>> = RwLock::new(None);

/// 安装统一回调（lib 集成激活回调路径；重复调用覆盖）。
///
/// 生产入口为 [`crate::facade::register_log_sink`]（门面委托）。
pub fn install_callback(sink: LogSink) {
    *crate::lock_util::recovered(CALLBACK.write(), "logging callback") = Some(sink);
}

/// 当前回调快照（无回调 = None）。
fn callback() -> Option<LogSink> {
    crate::lock_util::recovered(CALLBACK.read(), "logging callback").clone()
}

/// 运行日志是否会有接收方（回调已注册）——宏的惰性格式化前置检查。
pub fn run_enabled() -> bool {
    callback().is_some()
}

/// 输出审计条目（fail-closed：回调未注册 / handler 返回 Err → `Err`
/// 向上传播，调用方据此阻断流量——无未审计流量通过）。
pub fn audit(entry: &AuditLogEntry) -> Result<(), LogSinkError> {
    // 序列化失败回退占位 JSON（当前类型集合 serde 不会失败；防御性兜底）。
    let message = serde_json::to_string(entry).unwrap_or_else(|_| "{}".to_string());
    emit(
        LogKind::Audit,
        LogLevel::Info,
        "audit",
        message,
        Some(entry.clone()),
    )
}

/// 输出运行日志（内部统一入口；fire-and-forget——回调未注册/失败均
/// 丢弃，不影响业务流）。`pub`：运行日志宏在调用方 crate 展开，需经
/// 公共路径 `$crate::logging::run` 可达（不视为契约面——语义化入口为
/// [`debug`]/[`info`]/[`warn`]/[`error`] 四函数与对应宏）。
#[doc(hidden)]
pub fn run(level: LogLevel, subsystem: &str, message: String) {
    let _ = emit(LogKind::Run, level, subsystem, message, None);
}

/// 输出 Debug 级运行日志。
pub fn debug(subsystem: &str, message: String) {
    run(LogLevel::Debug, subsystem, message);
}

/// 输出 Info 级运行日志。
pub fn info(subsystem: &str, message: String) {
    run(LogLevel::Info, subsystem, message);
}

/// 输出 Warn 级运行日志。
pub fn warn(subsystem: &str, message: String) {
    run(LogLevel::Warn, subsystem, message);
}

/// 输出 Error 级运行日志。
pub fn error(subsystem: &str, message: String) {
    run(LogLevel::Error, subsystem, message);
}

/// 统一分发（单回调路径）：回调未注册 → 审计 `Err`（fail-closed）/
/// 运行日志丢弃；回调已注册 → 事件转发，审计 Err 原样传播（fail-closed），
/// 运行日志 Err 丢弃（fire-and-forget）。
fn emit(
    kind: LogKind,
    level: LogLevel,
    subsystem: &str,
    message: String,
    audit: Option<AuditLogEntry>,
) -> Result<(), LogSinkError> {
    let Some(sink) = callback() else {
        return match kind {
            // 审计无接收方：Err 传播——调用方 fail-closed（无未审计流量）。
            LogKind::Audit => Err(LogSinkError::Sink),
            // 运行日志无接收方：丢弃。
            LogKind::Run => Ok(()),
        };
    };
    let event = LogEvent {
        kind,
        level,
        subsystem: subsystem.to_string(),
        message,
        audit,
    };
    match sink(&event) {
        // 运行日志 Err 丢弃（fire-and-forget）；审计 Err 原样传播。
        Ok(()) => Ok(()),
        Err(e) if kind == LogKind::Audit => Err(e),
        Err(_) => Ok(()),
    }
}

/// 运行日志宏（带接收方检查的惰性格式化；回调未注册时零格式化开销）。
///
/// ```text
/// crate::log_info!("server", "serve started on port {port}");
/// crate::log_warn!("forward", "audit delivery failed: {e}");
/// crate::log_error!("registry", "invariant broken: {e}");
/// ```
#[macro_export]
macro_rules! log_run {
    ($level:expr, $subsys:expr, $($arg:tt)+) => {
        if $crate::logging::run_enabled() {
            $crate::logging::run($level, $subsys, format!($($arg)+));
        }
    };
    // 语句位置调用（含尾分号）——吸收分号保持语句形态。
    ($level:expr, $subsys:expr, $($arg:tt)+ ;) => {
        if $crate::logging::run_enabled() {
            $crate::logging::run($level, $subsys, format!($($arg)+));
        }
    };
}

/// Debug 级运行日志宏。
///
/// ```text
/// crate::log_debug!("forward", "deny: domain={} reason={:?}", domain, reason);
/// ```
#[macro_export]
macro_rules! log_debug {
    ($subsys:expr, $($arg:tt)+) => {
        $crate::log_run!($crate::logging::LogLevel::Debug, $subsys, $($arg)+)
    };
}

/// Info 级运行日志宏。
///
/// ```text
/// crate::log_info!("server", "mitm established: sni={sni}");
/// ```
#[macro_export]
macro_rules! log_info {
    ($subsys:expr, $($arg:tt)+) => {
        $crate::log_run!($crate::logging::LogLevel::Info, $subsys, $($arg)+)
    };
}

/// Warn 级运行日志宏。
///
/// ```text
/// crate::log_warn!("server", "accept failed: {e}");
/// ```
#[macro_export]
macro_rules! log_warn {
    ($subsys:expr, $($arg:tt)+) => {
        $crate::log_run!($crate::logging::LogLevel::Warn, $subsys, $($arg)+)
    };
}

/// Error 级运行日志宏。
///
/// ```text
/// crate::log_error!("server", "audit delivery failed: {e}");
/// ```
#[macro_export]
macro_rules! log_error {
    ($subsys:expr, $($arg:tt)+) => {
        $crate::log_run!($crate::logging::LogLevel::Error, $subsys, $($arg)+)
    };
}

/// 测试捕获缝（集成测试断言日志事件；**仅测试构建可达**——`test-util`
/// feature 门禁，与 `facade::testing` 同一自引用 dev-dependency 机制启用）。
///
/// guard 持有期间独占回调槽（测试间串行化），丢弃时恢复先前回调。
#[cfg(feature = "test-util")]
#[doc(hidden)]
pub mod testing {
    use super::*;
    use std::sync::Mutex;

    /// 捕获缝互斥锁（防并行测试交叉污染回调槽）。
    static CAPTURE_LOCK: Mutex<()> = Mutex::new(());

    /// 捕获 guard（Drop 恢复先前回调并释放锁；`events()` 读取已捕获事件）。
    pub struct CaptureGuard {
        events: Arc<Mutex<Vec<LogEvent>>>,
        _lock: std::sync::MutexGuard<'static, ()>,
        previous: Option<LogSink>,
    }

    impl CaptureGuard {
        /// 已捕获事件快照（含审计/运行日志全部类别）。
        pub fn events(&self) -> Vec<LogEvent> {
            self.events.lock().expect("capture events lock").clone()
        }
    }

    impl Drop for CaptureGuard {
        fn drop(&mut self) {
            *CALLBACK.write().expect("logging callback lock poisoned") = self.previous.take();
        }
    }

    /// 安装捕获回调（记录全部日志事件；恢复于 guard 丢弃）。
    pub fn install_capture() -> CaptureGuard {
        let lock = CAPTURE_LOCK.lock().expect("capture lock");
        let events: Arc<Mutex<Vec<LogEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_events = events.clone();
        let sink: LogSink = Arc::new(move |event: &LogEvent| {
            sink_events
                .lock()
                .expect("capture events lock")
                .push(event.clone());
            Ok(())
        });
        let previous = CALLBACK
            .write()
            .expect("logging callback lock poisoned")
            .replace(sink);
        CaptureGuard {
            events,
            _lock: lock,
            previous,
        }
    }

    /// 全局日志测试串行锁（**跨模块共享**：单元测试与门面测试凡触碰
    /// 全局回调槽或发出日志事件者必须持有——防并行交叉污染计数/事件
    /// 断言）。
    static SERIAL: Mutex<()> = Mutex::new(());

    /// 获取测试串行 guard（持有期间其他日志相关测试被排除）。
    pub fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, Reason};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// 全局态测试串行（共享 [`testing::serial_guard`]——含门面等跨模块
    /// 发日志的用例同锁互斥）。
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        testing::serial_guard()
    }

    fn sample_entry() -> AuditLogEntry {
        AuditLogEntry {
            timestamp: "2026-08-31T00:00:00Z".to_string(),
            container_id: "c-test".to_string(),
            scenario: "lib".to_string(),
            domain: "api.example.com".to_string(),
            url_path: "/v1/chat".to_string(),
            method: "POST".to_string(),
            status_code: 0,
            action: Action::Deny,
            reason: Reason::BlacklistMatch,
            source_ip: None,
            target_ip: None,
        }
    }

    // 无回调（未注册 sink）：运行日志丢弃不 panic；审计返回 Err
    //（fail-closed——无未审计流量通过，register_log_sink 为必需 API）。
    //（串行锁：本用例触碰全局回调槽——与其他计数/捕获断言用例互斥。）
    #[test]
    fn no_callback_run_dropped_audit_fails() {
        let _serial = serial();
        // 确保无回调状态（前序用例可能残留）。
        *CALLBACK.write().expect("logging callback lock poisoned") = None;
        assert!(!run_enabled());
        super::warn("test", "warn message".to_string());
        super::debug("test", "debug message".to_string());
        super::info("test", "info message".to_string());
        super::error("test", "error message".to_string());
        assert_eq!(
            super::audit(&sample_entry()),
            Err(LogSinkError::Sink),
            "审计无回调必须 Err（fail-closed）"
        );
    }

    // 回调路径：运行日志事件转发（kind/level/subsystem/message 字段正确）。
    #[test]
    fn callback_receives_run_events() {
        let _serial = serial();
        let capture = testing::install_capture();
        super::warn("listener", "bind failed".to_string());
        super::debug("forward", "decision made".to_string());
        super::info("server", "serve started".to_string());
        super::error("registry", "invariant broken".to_string());
        let events = capture.events();
        assert_eq!(events.len(), 4);
        for e in &events {
            assert_eq!(e.kind, LogKind::Run);
            assert!(e.audit.is_none());
        }
        assert_eq!(events[0].level, LogLevel::Warn);
        assert_eq!(events[0].subsystem, "listener");
        assert_eq!(events[0].message, "bind failed");
        assert_eq!(events[1].level, LogLevel::Debug);
        assert_eq!(events[2].level, LogLevel::Info);
        assert_eq!(events[3].level, LogLevel::Error);
    }

    // 回调路径：审计事件含结构化条目 + JSON 行消息（可解析回等值条目）。
    #[test]
    fn callback_receives_structured_audit_event() {
        let _serial = serial();
        let capture = testing::install_capture();
        let entry = sample_entry();
        super::audit(&entry).unwrap();
        let events = capture.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, LogKind::Audit);
        assert_eq!(events[0].level, LogLevel::Info, "审计事件级别约定 Info");
        assert_eq!(events[0].subsystem, "audit");
        let parsed: AuditLogEntry = serde_json::from_str(&events[0].message).unwrap();
        assert_eq!(parsed, entry);
        assert_eq!(events[0].audit.as_ref().unwrap(), &entry);
    }

    // fail-closed 语义：审计回调 Err 向上传播；运行日志 Err 丢弃
    //（fire-and-forget——不 panic、不返回错误）。
    #[test]
    fn audit_error_propagates_run_error_does_not() {
        let _serial = serial();
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let sink: LogSink = Arc::new(move |_event: &LogEvent| {
            c.fetch_add(1, Ordering::SeqCst);
            Err(LogSinkError::Sink)
        });
        install_callback(sink);
        assert_eq!(
            super::audit(&sample_entry()),
            Err(LogSinkError::Sink),
            "审计回调 Err 必须传播（fail-closed）"
        );
        super::warn("test", "swallowed".to_string()); // 不 panic、不返回错误
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // 清理：恢复无回调状态。
        *CALLBACK.write().expect("logging callback lock poisoned") = None;
    }

    // 捕获 guard Drop 恢复：丢弃后回到先前状态（新装回调接管）。
    #[test]
    fn capture_guard_restores_previous() {
        let _serial = serial();
        {
            let _capture = testing::install_capture();
            super::warn("test", "captured".to_string());
        }
        let seen = Arc::new(AtomicU32::new(0));
        let s = seen.clone();
        install_callback(Arc::new(move |_e: &LogEvent| {
            s.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
        super::warn("test", "after restore".to_string());
        assert_eq!(seen.load(Ordering::SeqCst), 1);
        *CALLBACK.write().expect("logging callback lock poisoned") = None;
    }

    // enabled 检查：回调已装时启用（宏格式化不跳过）；未注册时禁用。
    #[test]
    fn enabled_reflects_callback_presence() {
        let _serial = serial();
        assert!(!run_enabled(), "未注册回调时禁用");
        let _capture = testing::install_capture();
        assert!(run_enabled());
    }
}
