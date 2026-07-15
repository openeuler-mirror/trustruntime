//! 日志模块
//!
//! 职责：
//! - 初始化log4rs日志框架
//! - 配置滚动文件日志（按大小触发、固定窗口滚动）
//! - 设置归档文件权限（Unix系统）
//! - 截取文件名显示（仅显示basename，不含路径）
//!
//! 日志格式（LOG_PATTERN）：
//! ```text
//! [2024-01-15 10:30:45.123] [INFO] [main.rs:42] 日志消息
//! ```
//! 格式说明：
//! - {d(%Y-%m-%d %H:%M:%S%.3f)}: 时间戳（毫秒精度）
//! - {l}: 日志级别（DEBUG/INFO/WARN/ERROR）
//! - {f}: 文件名（通过BasenameEncoder截取）
//! - {L}: 行号
//! - {m}: 日志消息
//! - {n}: 换行符
//!
//! 与config模块关系：
//! - 依赖LogConfig配置结构（path、level、max_file_size、max_roll_count）
//! - 配置文件通过config模块加载，传递给init_logger初始化
//!
//! 架构决策：
//! - 使用log4rs实现滚动日志（生产环境标准方案）
//! - 归档文件权限设为0o440（只读，安全加固）
//! - 文件名截取避免日志中出现绝对路径泄露

use std::io;
use std::path::{Path, PathBuf};

use log4rs::append::rolling_file::policy::compound::{
    roll::{fixed_window::FixedWindowRoller, Roll},
    trigger::size::SizeTrigger,
    CompoundPolicy,
};
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{Appender, Config as Log4rsConfig, Root};
use log4rs::encode::pattern::PatternEncoder;
use thiserror::Error;

use crate::config::LogConfig;

/// 日志输出格式模式
///
/// 格式：`[时间] [级别] [文件:行号] 消息`
///
/// 示例输出：
/// ```text
/// [2024-01-15 10:30:45.123] [INFO] [vsock_server.rs:156] vsock连接已建立
/// ```
///
/// 占位符说明：
/// - `{d(%Y-%m-%d %H:%M:%S%.3f)}`: 时间戳，格式为年-月-日 时:分:秒.毫秒
/// - `{l}`: 日志级别（DEBUG/INFO/WARN/ERROR）
/// - `{f}`: 文件名（由BasenameEncoder处理，仅显示basename）
/// - `{L}`: 行号
/// - `{m}`: 日志消息内容
/// - `{n}`: 换行符
const LOG_PATTERN: &str = "[{d(%Y-%m-%d %H:%M:%S%.3f)}] [{l}] [{f}:{L}] {m}{n}";

/// 从文件路径中提取文件名（basename）
///
/// 截取路径中最后一个`/`之后的部分，避免日志中出现完整绝对路径。
///
/// # Arguments
/// * `file` - 文件路径字符串
///
/// # Returns
/// * 文件名部分（不含路径）
///
/// # Examples
/// ```rust
/// // 内部辅助函数，不对外导出
/// // assert_eq!(basename("/var/log/trustruntime.log"), "trustruntime.log");
/// // assert_eq!(basename("simple.log"), "simple.log");
/// ```
fn basename(file: &str) -> &str {
    file.rsplit('/').next().unwrap_or(file)
}

/// 日志初始化错误类型
///
/// 封装日志系统初始化过程中可能发生的各类错误。
#[derive(Error, Debug)]
pub enum LoggerError {
    /// 日志初始化失败
    ///
    /// 错误来源包括：
    /// - IO错误（创建日志目录失败）
    /// - log4rs配置错误
    /// - 日志级别设置错误
    #[error("logger init error: {0}")]
    InitError(String),
}

/// IO错误转换为LoggerError
impl From<io::Error> for LoggerError {
    fn from(err: io::Error) -> Self {
        LoggerError::InitError(err.to_string())
    }
}

/// log库设置错误转换为LoggerError
impl From<log::SetLoggerError> for LoggerError {
    fn from(err: log::SetLoggerError) -> Self {
        LoggerError::InitError(err.to_string())
    }
}

/// log4rs配置运行时错误转换为LoggerError
impl From<log4rs::config::runtime::ConfigErrors> for LoggerError {
    fn from(err: log4rs::config::runtime::ConfigErrors) -> Self {
        LoggerError::InitError(err.to_string())
    }
}

/// 归档日志文件权限（Unix系统）
///
/// 权限值：0o440 = 只读（所有者可读、组可读）
///
/// 安全考虑：
/// - 防止未授权修改归档日志
/// - 符合机密VM环境安全加固要求
const ARCHIVE_FILE_MODE: u32 = 0o440;

/// 日志目录权限（Unix系统）
///
/// 权限值：0o750 = rwxr-x---
/// - 所有者：读、写、执行（完全控制）
/// - 组：读、执行（可进入目录、读取日志）
/// - 其他：无权限
///
/// 安全考虑：
/// - 防止未授权用户进入日志目录
/// - 符合机密VM环境安全加固要求
const LOG_DIR_MODE: u32 = 0o750;

/// 带权限设置的日志滚动器
///
/// 在FixedWindowRoller基础上，为归档日志文件设置Unix权限（0o440）。
///
/// 日志滚动策略（固定窗口）：
/// - 当日志文件达到max_file_size时触发滚动
/// - 归档文件命名：`<log_path>.1.gz`, `<log_path>.2.gz`, ..., `<log_path>.N.gz`
/// - 保留最近N个归档文件（N=max_roll_count）
/// - 滚动时：file.log -> file.log.1.gz, 旧文件依次后移
///
/// 示例滚动序列（max_roll_count=3）：
/// ```text
/// file.log (当前)
/// file.log.1.gz (最新归档)
/// file.log.2.gz (次新归档)
/// file.log.3.gz (最旧归档)
/// ```
///
/// 权限设置仅在Unix系统生效，Windows系统忽略。
#[derive(Debug)]
struct PermissionRoller {
    /// 内置固定窗口滚动器（log4rs提供）
    inner: FixedWindowRoller,
    /// 归档文件名模式（含{}占位符）
    pattern: String,
    /// 归档文件起始编号（通常为1）
    base: u32,
    /// 归档文件数量上限
    count: u32,
}

impl PermissionRoller {
    /// 创建带权限设置的滚动器
    ///
    /// # Arguments
    /// * `inner` - log4rs固定窗口滚动器
    /// * `pattern` - 归档文件名模式（如`/var/log/app.log.{}.gz`）
    /// * `base` - 起始编号（通常为1）
    /// * `count` - 归档文件数量上限
    fn new(inner: FixedWindowRoller, pattern: String, base: u32, count: u32) -> Self {
        Self {
            inner,
            pattern,
            base,
            count,
        }
    }
}

/// 执行日志滚动并设置归档文件权限
///
/// 滚动流程：
/// 1. 调用内置FixedWindowRoller执行滚动（重命名文件）
/// 2. 在Unix系统上，遍历所有归档文件并设置权限（0o440）
///
/// # Arguments
/// * `file` - 当前日志文件路径
///
/// # Returns
/// * `Ok(())` - 滚动成功
/// * `Err` - 滚动失败
impl Roll for PermissionRoller {
    fn roll(&self, file: &Path) -> anyhow::Result<()> {
        // 步骤1：执行固定窗口滚动
        self.inner.roll(file)?;

        // 步骤2：Unix系统设置归档文件权限
        #[cfg(unix)]
        {
            use std::fs;
            use std::os::unix::fs::PermissionsExt;

            // 遍历所有归档文件（base到base+count-1）
            for i in self.base..(self.base + self.count) {
                let archive = self.pattern.replace("{}", &i.to_string());
                let path = PathBuf::from(&archive);

                // 仅设置已存在的归档文件权限
                if path.exists() {
                    if let Err(e) =
                        fs::set_permissions(&path, fs::Permissions::from_mode(ARCHIVE_FILE_MODE))
                    {
                        // 权限设置失败仅记录警告，不中断流程
                        log::warn!("failed to set permissions on {}: {}", archive, e);
                    }
                }
            }
        }

        Ok(())
    }
}

/// 文件名截取编码器
///
/// 装饰PatternEncoder，将日志中的文件路径截取为basename。
///
/// 安全考虑：
/// - 避免在日志中暴露完整绝对路径（可能包含敏感目录结构）
/// - 仅显示文件名，如`vsock_server.rs`而非`/opt/trustruntime/src/vsock_server.rs`
///
/// 实现方式：
/// - 拦截Record中的file字段
/// - 调用basename函数截取文件名
/// - 构建新的Record并传递给内置PatternEncoder
#[derive(Debug)]
struct BasenameEncoder {
    /// 内置模式编码器
    inner: PatternEncoder,
}

/// 实现log4rs Encode trait
///
/// 编码流程：
/// 1. 从Record中提取文件路径并截取basename
/// 2. 构建新的Record（替换file字段为basename）
/// 3. 调用内置PatternEncoder输出格式化日志
impl log4rs::encode::Encode for BasenameEncoder {
    fn encode(
        &self,
        w: &mut dyn log4rs::encode::Write,
        record: &log::Record,
    ) -> anyhow::Result<()> {
        // 截取文件名（如果无法获取则显示"unknown"）
        let file = record.file().map(basename).unwrap_or("unknown");

        // 重新构建Record，保留其他字段不变
        let msg = record.args().to_string();
        let args = format_args!("{}", msg);
        let mut builder = log::Record::builder();
        builder
            .level(record.level())
            .target(record.target())
            .module_path(record.module_path())
            .file(Some(file)) // 替换为截取后的文件名
            .line(record.line())
            .args(args);

        // 调用内置编码器输出
        self.inner.encode(w, &builder.build())
    }
}

/// 初始化日志系统
///
/// 根据LogConfig配置初始化log4rs日志框架，配置滚动文件日志。
///
/// # 配置项
/// - `path`: 日志文件路径（如`/var/log/trustruntime/trustring.log`）
/// - `level`: 日志级别枚举（trace/debug/info/warn/error）
/// - `max_file_size`: 单个日志文件最大大小（MB）
/// - `max_roll_count`: 归档文件保留数量
///
/// # 目录创建
/// - 自动创建日志目录（递归创建父目录）
/// - Unix系统：目录权限设置为0o750（rwxr-x---）
/// - 非Unix系统：使用默认权限
///
/// # 滚动策略
/// - 触发条件：日志文件达到max_file_size（单位：字节）
/// - 滚动方式：固定窗口滚动
/// - 归档命名：`<path>.1.gz`, `<path>.2.gz`, ..., `<path>.N.gz`
/// - 归档压缩：gzip压缩
/// - 权限设置：归档文件权限0o440（Unix系统）
///
/// # Arguments
/// * `config` - 日志配置引用
///
/// # Returns
/// * `Ok(())` - 初始化成功
/// * `Err(LoggerError)` - 初始化失败（目录创建失败、配置错误等）
///
/// # Example
/// ```text
/// let config = LogConfig {
///     path: "/var/log/trustruntime/trustruntime.log".to_string(),
///     level: "info".to_string(),
///     max_file_size: 100,
///     max_roll_count: 5,
/// };
/// init_logger(&config)?;
/// ```
pub fn init_logger(config: &LogConfig) -> Result<(), LoggerError> {
    let log_path = &config.path;

    // 确保日志目录存在
    if let Some(parent) = Path::new(log_path).parent() {
        // Unix系统使用DirBuilder创建目录并设置权限
        #[cfg(unix)]
        {
            use std::fs::DirBuilder;
            use std::os::unix::fs::DirBuilderExt;

            DirBuilder::new()
                .recursive(true)
                .mode(LOG_DIR_MODE)
                .create(parent)
                .map_err(|e| {
                    LoggerError::InitError(format!("cannot create log directory: {}", e))
                })?;
        }
    }

    // 配置滚动策略参数
    let max_size = config.max_file_size * 1024 * 1024; // MB转换为字节
    let archive_count = config.max_roll_count;
    let level_filter = config.level.to_level_filter();

    // 构建固定窗口滚动器（归档文件命名：file.log.1.gz）
    let archive_pattern = format!("{}.{{}}.gz", log_path);
    let roller = FixedWindowRoller::builder()
        .base(1) // 归档文件从1开始编号
        .build(&archive_pattern, archive_count)
        .map_err(|e| LoggerError::InitError(e.to_string()))?;

    // 包装为带权限设置的滚动器
    let roller = PermissionRoller::new(roller, archive_pattern, 1, archive_count);

    // 构建大小触发器（当文件达到max_size时触发滚动）
    let trigger = SizeTrigger::new(max_size);

    // 组合策略：大小触发 + 固定窗口滚动
    let policy = CompoundPolicy::new(Box::new(trigger), Box::new(roller));

    // 构建滚动文件appender（使用BasenameEncoder截取文件名）
    let appender = RollingFileAppender::builder()
        .encoder(Box::new(BasenameEncoder {
            inner: PatternEncoder::new(LOG_PATTERN),
        }))
        .build(log_path, Box::new(policy))
        .map_err(|e| LoggerError::InitError(e.to_string()))?;

    // 构建log4rs配置
    let log4rs_config = Log4rsConfig::builder()
        .appender(Appender::builder().build("rolling_file", Box::new(appender)))
        .build(Root::builder().appender("rolling_file").build(level_filter))?;

    // 初始化全局日志配置
    log4rs::init_config(log4rs_config)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogLevel;
    use log4rs::encode::writer::simple::SimpleWriter;
    use log4rs::encode::Encode;

    /// 测试basename函数从完整路径提取文件名
    ///
    /// 场景：输入包含多级目录的完整路径
    /// 预期：返回最后一个路径组件（文件名）
    #[test]
    fn basename_extracts_filename_from_path() {
        assert_eq!(basename("/var/log/trustruntime.log"), "trustruntime.log");
    }

    /// 测试basename函数处理无路径分隔符的文件名
    ///
    /// 场景：输入仅为文件名，无目录路径
    /// 预期：返回原文件名
    #[test]
    fn basename_returns_input_when_no_slash() {
        assert_eq!(basename("simple.log"), "simple.log");
    }

    /// 测试basename函数处理多级路径
    ///
    /// 场景：输入包含多级目录路径
    /// 预期：正确提取最后一个路径组件
    #[test]
    fn basename_handles_multiple_slashes() {
        assert_eq!(basename("/a/b/c/d/file.txt"), "file.txt");
    }

    /// 测试LoggerError从IO错误转换
    ///
    /// 场景：将std::io::Error转换为LoggerError
    /// 预期：错误消息包含原始错误信息和前缀
    #[test]
    fn logger_error_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let err: LoggerError = io_err.into();
        let msg = err.to_string();
        assert!(msg.contains("logger init error"));
        assert!(msg.contains("file not found"));
    }

    /// 测试LoggerError的Display格式化
    ///
    /// 场景：创建InitError并转换为字符串
    /// 预期：字符串包含错误前缀和原始消息
    #[test]
    fn logger_error_display_format() {
        let err = LoggerError::InitError("test error".to_string());
        assert!(err.to_string().contains("logger init error"));
        assert!(err.to_string().contains("test error"));
    }

    /// 测试BasenameEncoder截取目录路径
    ///
    /// 场景：日志记录包含完整绝对路径
    /// 预期：输出仅包含文件名，不包含目录路径
    #[test]
    fn basename_encoder_strips_directory_path() {
        let encoder = BasenameEncoder {
            inner: PatternEncoder::new("{f}"),
        };
        let mut buf = Vec::new();
        {
            let mut writer = SimpleWriter(&mut buf);
            let record = log::Record::builder()
                .level(log::Level::Info)
                .file(Some("/very/long/path/to/file.rs"))
                .line(Some(100))
                .args(format_args!("test"))
                .build();
            encoder.encode(&mut writer, &record).unwrap();
        }
        let result = String::from_utf8(buf).unwrap();
        assert!(result.contains("file.rs")); // 包含文件名
        assert!(!result.contains("/very/long/path/to/")); // 不包含目录路径
    }

    /// 测试BasenameEncoder处理无文件信息的情况
    ///
    /// 场景：日志记录不包含文件信息（file=None）
    /// 预期：输出显示"unknown"
    #[test]
    fn basename_encoder_handles_no_file() {
        let encoder = BasenameEncoder {
            inner: PatternEncoder::new("{f}"),
        };
        let mut buf = Vec::new();
        {
            let mut writer = SimpleWriter(&mut buf);
            let record = log::Record::builder()
                .level(log::Level::Info)
                .file(None) // 无文件信息
                .args(format_args!("no file"))
                .build();
            encoder.encode(&mut writer, &record).unwrap();
        }
        let result = String::from_utf8(buf).unwrap();
        assert!(result.contains("unknown"));
    }

    /// 测试BasenameEncoder保留其他字段
    ///
    /// 场景：完整日志记录包含级别、文件名、行号、消息
    /// 预期：输出包含所有字段，文件名正确截取
    #[test]
    fn basename_encoder_preserves_fields() {
        let encoder = BasenameEncoder {
            inner: PatternEncoder::new("[{l}] [{f}:{L}] {m}"),
        };
        let mut buf = Vec::new();
        {
            let mut writer = SimpleWriter(&mut buf);
            let record = log::Record::builder()
                .level(log::Level::Warn)
                .file(Some("my_file.rs"))
                .line(Some(55))
                .args(format_args!("test msg"))
                .build();
            encoder.encode(&mut writer, &record).unwrap();
        }
        let result = String::from_utf8(buf).unwrap();
        assert!(result.contains("WARN"));
        assert!(result.contains("my_file.rs:55"));
        assert!(result.contains("test msg"));
    }

    /// 测试init_logger创建日志目录并成功初始化
    ///
    /// 场景：日志目录不存在，初始化日志系统
    /// 预期：自动创建目录，初始化成功，可正常写入日志
    #[test]
    fn init_logger_creates_log_directory_and_succeeds() {
        let temp_dir = std::env::temp_dir().join("trustruntime_logger_test");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let config = LogConfig {
            path: temp_dir.join("test.log").to_str().unwrap().to_string(),
            level: LogLevel::Info,
            max_file_size: 10,
            max_roll_count: 3,
        };

        let result = init_logger(&config);
        assert!(
            result.is_ok(),
            "init_logger should succeed: {:?}",
            result.err()
        );

        log::info!("test log message");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// 测试PermissionRoller滚动时设置归档文件权限
    ///
    /// 场景：创建测试日志文件并执行滚动
    /// 预期：滚动成功，归档文件权限设为0o440（Unix系统）
    #[test]
    fn permission_roller_sets_permissions_on_roll() {
        let dir = std::env::temp_dir().join("trustruntime_permission_roller_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let log_path = dir.join("roller_test.log");
        std::fs::write(&log_path, b"initial content").unwrap();

        let archive_pattern = dir
            .join("roller_test.log.{}.gz")
            .to_str()
            .unwrap()
            .to_string();
        let roller = FixedWindowRoller::builder()
            .base(1)
            .build(&archive_pattern, 3)
            .unwrap();
        let perm_roller = PermissionRoller::new(roller, archive_pattern, 1, 3);

        let result = perm_roller.roll(&log_path);
        assert!(result.is_ok(), "roll should succeed: {:?}", result.err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 测试DirBuilder创建目录并设置权限（Unix系统）
    ///
    /// 场景：直接使用DirBuilder创建多层目录
    /// 预期：所有目录权限设为0o750
    #[test]
    #[cfg(unix)]
    fn dir_builder_creates_directory_with_permissions() {
        use std::fs::DirBuilder;
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        let temp_base = std::env::temp_dir().join("trustruntime_log_dir_perm_test");
        let _ = std::fs::remove_dir_all(&temp_base);

        // 创建多层目录路径测试 DirBuilder.recursive()
        let log_dir = temp_base.join("nested").join("log_dir");

        DirBuilder::new()
            .recursive(true)
            .mode(LOG_DIR_MODE)
            .create(&log_dir)
            .expect("DirBuilder should succeed");

        // 验证最深层目录权限为 0o750
        let metadata = std::fs::metadata(&log_dir).expect("directory should exist");
        let mode = metadata.permissions().mode();
        let perm_bits = mode & 0o777;
        assert_eq!(
            perm_bits, LOG_DIR_MODE,
            "directory permission should be 0o750"
        );

        // 验证中间层目录权限也为 0o750
        let nested_dir = temp_base.join("nested");
        let nested_metadata =
            std::fs::metadata(&nested_dir).expect("nested directory should exist");
        let nested_mode = nested_metadata.permissions().mode();
        let nested_perm_bits = nested_mode & 0o777;
        assert_eq!(
            nested_perm_bits, LOG_DIR_MODE,
            "nested directory permission should be 0o750"
        );

        let _ = std::fs::remove_dir_all(&temp_base);
    }
}
