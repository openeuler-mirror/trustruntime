# 日志层 详细设计

## 1. 职责与边界

### 负责

- 基于 `log` + `log4rs` 初始化日志系统
- 按文件大小滚动日志文件，归档为 `.gz` 格式
- 归档文件权限收紧为 `0o440`（owner+group 只读）
- 日志格式中仅显示文件名（去除目录前缀）

### 不负责

- 日志内容的格式化（由调用方通过 `log::info!`/`log::warn!` 等宏决定）
- 日志级别过滤的外部配置（通过 `LogConfig.level` 字段控制）
- 各模块的日志调用（各模块直接使用 `log` crate 宏，无需 trait 封装）

---

## 2. 公开 API

```rust
/// 初始化日志系统
/// 1. 创建日志目录（如不存在）
/// 2. 配置 SizeTrigger（按文件大小触发滚动）
/// 3. 配置 FixedWindowRoller + gzip 归档
/// 4. 配置 PermissionRoller（归档后设置 0o440 权限）
/// 5. 配置 BasenameEncoder（日志中仅显示文件名）
/// 6. 初始化 log4rs
pub fn init_logger(config: &LogConfig) -> Result<(), LoggerError>;

#[derive(Error, Debug)]
pub enum LoggerError {
    #[error("logger init error: {0}")]
    InitError(String),
}

// 错误转换便利实现
impl From<std::io::Error> for LoggerError;
impl From<log::SetLoggerError> for LoggerError;
impl From<log4rs::config::runtime::ConfigErrors> for LoggerError;
```

### 内部组件

```rust
/// 日志格式：[时间] [级别] [文件名:行号] 消息
const LOG_PATTERN: &str = "[{d(%Y-%m-%d %H:%M:%S%.3f)}] [{l}] [{f}:{L}] {m}{n}";

/// 从文件路径中提取文件名（去除目录前缀）
fn basename(file: &str) -> &str;

/// 自定义编码器：将日志记录中的文件路径替换为文件名
/// 边界处理：file=None 时返回 "unknown"
struct BasenameEncoder {
    inner: PatternEncoder,
}

/// 自定义滚动器：在 FixedWindowRoller 滚动后，将归档文件权限设为 0o440
/// 跨平台支持：仅 Unix 系统设置权限（#[cfg(unix)]）
struct PermissionRoller {
    inner: FixedWindowRoller,
    pattern: String,
    base: u32,
    count: u32,
}

/// 解析日志级别字符串为 log::LevelFilter
/// 大小写不敏感：自动转换为小写后匹配
/// 默认值：无效输入返回 LevelFilter::Info
fn parse_log_level(level: &str) -> log::LevelFilter;
```

---

## 3. 内部状态

| 结构体 | 状态 | 生命周期 |
|--------|------|---------|
| log4rs（全局） | RollingFileAppender + SizeTrigger + FixedWindowRoller | 进程级，`log4rs::init_config` 后全局持有 |

注：log4rs 初始化后全局单例，无需手动管理生命周期。

---

## 4. 关键场景

### 日志初始化

```
main.rs                    init_logger(config)
  |                            |
  |-- init_logger(config) ---->|
  |                            |  1. 创建日志目录（如不存在）
  |                            |  2. 计算 max_size = config.max_file_size * 1024 * 1024
  |                            |  3. 构建 FixedWindowRoller（.gz 归档，base=1）
  |                            |  4. 包装为 PermissionRoller（归档后 chmod 0o440）
  |                            |  5. 构建 SizeTrigger(max_size)
  |                            |  6. 构建 CompoundPolicy(trigger, roller)
  |                            |  7. 构建 RollingFileAppender + BasenameEncoder
  |                            |  8. 构建 log4rs Config，设置 Root level
  |                            |  9. log4rs::init_config()
  |<-- Result<(), LoggerError>-|
```

### 日志写入

```
调用方                     log crate
  |                            |
  |-- log::info!("msg") ------>|  → log4rs → RollingFileAppender → 文件
  |-- log::warn!("msg") ------>|
  |-- log::error!("msg") ----->|
  |-- log::debug!("msg") ----->|
```

### 日志滚动

```
文件大小达到 max_file_size (MB)
  |
  |-- SizeTrigger 触发
  |-- FixedWindowRoller: 当前文件 → .1.gz, .1.gz → .2.gz, ...（最多 max_roll_count 个）
  |-- PermissionRoller: 对所有归档 .gz 文件设置 0o440 权限
  |-- 创建新的当前文件
  |-- 超过 max_roll_count 的旧归档删除
```

### 异常场景

| 场景 | 处理方式 |
|------|---------|
| 日志目录不存在 | 自动创建；创建失败 → LoggerError::InitError，进程启动失败 |
| 日志目录无写权限 | LoggerError::InitError，进程启动失败 |
| 归档文件权限设置失败 | log::warn! 记录，不影响日志写入 |

---

## 5. 依赖关系

### 上游依赖

| 依赖 | 用途 |
|------|------|
| `log` | 日志宏（info/warn/error/debug） |
| `log4rs` | RollingFileAppender + SizeTrigger + FixedWindowRoller + gzip |
| `anyhow` | log4rs Roll trait 的 Result 类型 |
| `config::LogConfig` | 日志路径、级别、文件大小、滚动数量 |

### 下游消费者

| 消费者 | 使用方式 |
|--------|---------|
| 所有模块 | 直接使用 `log::info!`/`log::warn!`/`log::error!`/`log::debug!` 宏 |
| main.rs | 调用 `logger::init_logger(&config.log)` 初始化 |

---

## 6. 测试策略

### 必须覆盖的场景

| 场景 | 验证点 |
|------|--------|
| 正常初始化 | init_logger 返回 Ok，日志文件创建成功 |
| basename 提取 | 各种路径格式正确提取文件名 |
| BasenameEncoder | 日志记录中文件路径被替换为文件名 |
| BasenameEncoder 无文件 | 显示 "unknown" |
| parse_log_level | 各字符串正确映射为 LevelFilter |
| LoggerError 转换 | io::Error / SetLoggerError / ConfigErrors 正确转换 |
| PermissionRoller | 滚动后归档文件权限为 0o440 |
| 日志目录不存在 | 自动创建目录并初始化成功 |

### mock 策略

- 无需 MockLogger：各模块直接使用 `log` 宏，测试验证行为返回值而非日志调用
- 文件系统测试：使用临时目录验证初始化和滚动行为
- BasenameEncoder：使用 `SimpleWriter` 捕获编码输出验证
