//! # TrustringPlugin - CMS签名验签插件
//!
//! 提供基于OpenSSL的CMS签名和验签功能，是trustruntime框架的业务插件实现。
//!
//! ## 架构决策 (ADR-0003)
//!
//! 采用**静态集成模式**：编译时集成到trustruntime二进制文件，而非运行时动态加载。
//!
//! 选择静态集成的理由：
//! - **安全性**：避免在可信VM中动态加载任意共享库的安全风险
//! - **简洁性**：无需abi_stable或C ABI包装器
//! - **内存效率**：单一二进制避免共享库开销，更适合30MB cgroup限制
//! - **RPM打包**：单一二进制包，无需插件路径配置
//!
//! Plugin trait提供**逻辑解耦**而非物理隔离：框架代码不依赖trustring业务逻辑，
//! 但编译为同一二进制文件。
//!
//! ## 子模块
//!
//! - [`cert_loader`] - 证书加载器，支持PEM/DER双格式
//! - [`error_code_mapper`] - 错误码映射，将领域错误转换为结果码(0-9)
//! - [`handler`] - 消息处理器，实现Plugin trait的业务入口
//! - [`sign`] - CMS签名功能
//! - [`verify`] - CMS验签功能
//!
//! ## 公共导出
//!
//! - [`TrustringPlugin`] - 插件主类型，实现framework::Plugin trait

pub(crate) mod cert_loader;
pub(crate) mod error_code_mapper;
pub(crate) mod handler;
pub(crate) mod sign;
pub(crate) mod verify;

pub use handler::TrustringPlugin;
