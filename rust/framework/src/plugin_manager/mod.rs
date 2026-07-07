//! 插件管理模块
//!
//! 主要职责：
//! - 定义Plugin trait作为插件生命周期接口（init、shutdown）
//! - PluginManager负责初始化和关闭所有插件
//! - PluginContext提供插件初始化时所需的框架资源
//!
//! 架构决策：
//! - 静态集成模式（ADR-0003）：编译时集成而非运行时动态加载
//!   - 安全性：避免在机密VM中动态加载任意共享库
//!   - 简洁性：无需abi_stable或C ABI封装
//!   - 内存占用：单二进制文件避免共享库开销（符合30MB cgroup限制）
//! - 职责分离（ADR-0005）：PluginManager只管生命周期，不管消息分发
//!   - TransportLayer：由transport模块定义，处理协议层
//!   - DataHandler：由transport模块定义，处理业务层
//!
//! 依赖：
//! - crate::config::AppConfig：应用配置
//! - crate::transport：TransportLayer trait和DataHandler trait
//! - async_trait：异步trait支持
//! - thiserror：错误类型定义

use crate::config::AppConfig;
use std::sync::Arc;
use thiserror::Error;

// Re-export transport types for convenience
pub use crate::transport::{DataHandler, TransportError, TransportLayer};

/// 插件生命周期错误
///
/// 插件初始化或关闭过程中可能发生的错误
#[derive(Error, Debug)]
pub enum PluginError {
    /// 插件初始化失败
    #[error("init failed: {0}")]
    InitFailed(String),
    /// 插件关闭失败
    #[error("shutdown failed: {0}")]
    ShutdownFailed(String),
}

/// 插件上下文
///
/// 在插件初始化时提供框架资源的访问入口
///
/// 包含：
/// - config：应用配置（证书路径、vsock端口等）
/// - transport：传输层引用（用于注册消息处理器）
///
/// 使用方式：
/// ```text
/// fn init(&mut self, ctx: &PluginContext) -> Result<(), PluginError> {
///     ctx.transport.register_handler(MSG_TYPE, handler);
///     Ok(())
/// }
/// ```
pub struct PluginContext {
    /// 应用配置（Arc共享以支持多线程访问）
    pub config: Arc<AppConfig>,
    /// 传输层引用（用于注册消息处理器）
    pub transport: Arc<dyn TransportLayer>,
}

impl PluginContext {
    /// 创建插件上下文
    ///
    /// # Arguments
    /// * `config` - 应用配置
    /// * `transport` - 传输层实现
    ///
    /// # Returns
    /// 插件上下文实例
    pub fn new(config: Arc<AppConfig>, transport: Arc<dyn TransportLayer>) -> Self {
        Self { config, transport }
    }
}

/// 插件生命周期接口
///
/// 架构决策：Plugin trait提供逻辑解耦边界，而非物理隔离
/// 详见 ADR-0003: Plugin Integration Pattern
///
/// 职责：
/// - 定义插件生命周期（init初始化、shutdown关闭）
/// - 在init中注册消息处理器到TransportLayer
/// - 在shutdown中清理资源
///
/// 生命周期：
/// 1. main.rs创建插件实例
/// 2. main.rs调用PluginManager::add_plugin添加插件
/// 3. main.rs调用PluginManager::init_all初始化所有插件
/// 4. 插件在init中调用ctx.transport.register_handler注册处理器
/// 5. main.rs调用transport.start()开始处理消息
/// 6. 程序退出时调用PluginManager::shutdown_all关闭所有插件
///
/// 注意：
/// - Plugin trait是逻辑解耦边界，编译时静态集成
/// - 未来新增插件只需添加新crate并在main.rs中use，无需动态加载
pub trait Plugin: Send + Sync {
    /// 返回插件名称
    ///
    /// 用于日志和调试
    fn name(&self) -> &str;

    /// 初始化插件
    ///
    /// 插件在此注册消息处理器到TransportLayer
    ///
    /// # Arguments
    /// * `ctx` - 插件上下文，提供config和transport
    ///
    /// # Returns
    /// * `Ok(())` - 初始化成功
    /// * `Err(PluginError)` - 初始化失败
    fn init(&mut self, ctx: &PluginContext) -> Result<(), PluginError>;

    /// 关闭插件
    ///
    /// 清理插件资源
    ///
    /// # Returns
    /// * `Ok(())` - 关闭成功
    /// * `Err(PluginError)` - 关闭失败
    fn shutdown(&mut self) -> Result<(), PluginError>;
}

/// 插件管理器
///
/// 负责管理所有插件的生命周期
///
/// 架构决策：PluginManager只管生命周期，不管消息分发
/// 详见 ADR-0005: Transport Layer Abstraction
///
/// 使用流程：
/// 1. PluginManager::new() 创建管理器
/// 2. add_plugin() 添加插件实例
/// 3. init_all() 初始化所有插件
/// 4. shutdown_all() 关闭所有插件（逆序关闭）
pub struct PluginManager {
    /// 插件列表（按添加顺序存储）
    plugins: Vec<Box<dyn Plugin>>,
}

impl PluginManager {
    /// 创建插件管理器
    ///
    /// # Returns
    /// 空的插件管理器实例
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// 添加插件
    ///
    /// # Arguments
    /// * `plugin` - 插件实例（Box<dyn Plugin>）
    pub fn add_plugin(&mut self, plugin: Box<dyn Plugin>) {
        self.plugins.push(plugin);
    }

    /// 初始化所有插件
    ///
    /// 按添加顺序依次调用每个插件的init方法
    ///
    /// # Arguments
    /// * `ctx` - 插件上下文
    ///
    /// # Returns
    /// * `Ok(())` - 所有插件初始化成功
    /// * `Err(PluginError)` - 任一插件初始化失败，立即返回
    ///
    /// # Errors
    /// 某个插件init失败时，停止后续初始化并返回错误
    pub fn init_all(&mut self, ctx: &PluginContext) -> Result<(), PluginError> {
        for plugin in &mut self.plugins {
            plugin.init(ctx)?;
        }
        Ok(())
    }

    /// 关闭所有插件
    ///
    /// 按逆序（后进先出）依次调用每个插件的shutdown方法
    ///
    /// # Returns
    /// * `Ok(())` - 所有插件关闭成功
    /// * `Err(PluginError)` - 任一插件关闭失败，立即返回
    ///
    /// # Errors
    /// 某个插件shutdown失败时，停止后续关闭并返回错误
    ///
    /// # 设计说明
    /// 逆序关闭确保依赖关系正确的清理顺序（后添加的插件可能依赖先添加的插件）
    pub fn shutdown_all(&mut self) -> Result<(), PluginError> {
        while let Some(mut plugin) = self.plugins.pop() {
            plugin.shutdown()?;
        }
        Ok(())
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    /// Mock插件实现，用于测试
    struct MockPlugin {
        /// 插件初始化状态
        initialized: bool,
        /// 插件名称
        name: &'static str,
    }

    impl MockPlugin {
        fn new(name: &'static str) -> Self {
            Self {
                initialized: false,
                name,
            }
        }
    }

    impl Plugin for MockPlugin {
        fn name(&self) -> &str {
            self.name
        }

        fn init(&mut self, _ctx: &PluginContext) -> Result<(), PluginError> {
            self.initialized = true;
            Ok(())
        }

        fn shutdown(&mut self) -> Result<(), PluginError> {
            self.initialized = false;
            Ok(())
        }
    }

    /// Mock传输层实现，用于测试
    struct MockTransport {
        /// 已注册的处理器（msg_type -> 是否注册）
        #[allow(dead_code)]
        handlers: std::collections::HashMap<u32, bool>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                handlers: std::collections::HashMap::new(),
            }
        }
    }

    #[async_trait]
    impl TransportLayer for MockTransport {
        fn register_handler(&self, _msg_type: u32, _handler: Box<dyn DataHandler>) {}

        async fn start(&self) -> Result<(), TransportError> {
            Ok(())
        }

        async fn stop(&self) {}
    }

    /// Mock数据处理器实现，用于测试
    struct MockDataHandler;

    impl DataHandler for MockDataHandler {
        fn handle(&self, data: &[u8]) -> Option<Vec<u8>> {
            Some(data.to_vec())
        }
    }

    /// 创建测试配置
    fn make_config() -> Arc<AppConfig> {
        Arc::new(
            AppConfig::from_toml(
                r#"
[vsock]
port = 12345

[log]
path = "/tmp/test.log"
max_file_size = 10
max_roll_count = 10

[certificate]
signer_cert = "/tmp/signer.crt"
signer_key = "/tmp/signer.key"
ca_root_cert = "/tmp/ca.crt"
comm_cert = "/tmp/comm.crt"
comm_key = "/tmp/comm.key"
comm_ca_root = "/tmp/comm_ca.crt"
"#,
            )
            .unwrap(),
        )
    }

    /// 测试：PluginManager初始化所有插件
    ///
    /// 场景：添加两个插件并调用init_all
    /// 预期：所有插件初始化成功
    #[test]
    fn plugin_manager_initializes_all_plugins() {
        let mut pm = PluginManager::new();
        pm.add_plugin(Box::new(MockPlugin::new("plugin1")));
        pm.add_plugin(Box::new(MockPlugin::new("plugin2")));

        let config = make_config();
        let transport = Arc::new(MockTransport::new());
        let ctx = PluginContext::new(config, transport);

        assert!(pm.init_all(&ctx).is_ok());
    }

    /// 测试：PluginManager逆序关闭插件
    ///
    /// 场景：添加两个插件，初始化后关闭
    /// 预期：所有插件关闭成功，按逆序（后进先出）关闭
    #[test]
    fn plugin_manager_shutdowns_plugins_in_reverse_order() {
        let mut pm = PluginManager::new();
        pm.add_plugin(Box::new(MockPlugin::new("plugin1")));
        pm.add_plugin(Box::new(MockPlugin::new("plugin2")));

        let config = make_config();
        let transport = Arc::new(MockTransport::new());
        let ctx = PluginContext::new(config, transport);

        pm.init_all(&ctx).unwrap();
        assert!(pm.shutdown_all().is_ok());
    }

    /// 测试：PluginContext提供配置和传输层访问
    ///
    /// 场景：创建PluginContext并访问配置
    /// 预期：配置值正确传递
    #[test]
    fn plugin_context_provides_config_and_transport() {
        let config = make_config();
        let transport = Arc::new(MockTransport::new());
        let ctx = PluginContext::new(config, transport);

        assert_eq!(ctx.config.vsock.port, 12345);
    }

    /// 测试：DataHandler trait基本功能
    ///
    /// 场景：使用MockDataHandler处理数据
    /// 预期：返回Some(处理后的数据)
    #[test]
    fn data_handler_trait_works() {
        let handler = MockDataHandler;
        let result = handler.handle(b"test");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"test".to_vec());
    }
}
