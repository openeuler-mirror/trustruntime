//! 测试场景运行器模块
//!
//! 提供预定义测试场景的运行入口，指向integration-tests包中的具体实现。
//! 场景分类遵循测试规范，覆盖正常、错误和边界三类场景。

use crate::config::{CmsCertsConfig, TlsClientConfig};
use std::path::PathBuf;
use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum ScenarioError {
    #[error("process start failed: {0}")]
    ProcessStartFailed(String),

    #[error("test failed: {0}")]
    TestFailed(String),
}

pub struct ScenarioRunner {
    tls_config: TlsClientConfig,
    cms_certs: CmsCertsConfig,
    #[allow(dead_code)]
    binary_path: PathBuf,
}

impl ScenarioRunner {
    pub fn new(
        tls_config: TlsClientConfig,
        cms_certs: CmsCertsConfig,
        binary_path: PathBuf,
    ) -> Self {
        Self {
            tls_config,
            cms_certs,
            binary_path,
        }
    }

    pub fn run_two_node(&self) -> Result<String, ScenarioError> {
        Ok(format!(
            "Two-node scenario (N01) requires running integration-tests.\n\
             Use: cargo test -p integration-tests n01_two_node_sign_verify -- --include-ignored\n\
             TLS CA: {}\n\
             CMS CA: {}",
            self.tls_config.ca_cert.display(),
            self.cms_certs.ca_cert.display()
        ))
    }

    pub fn run_three_node(&self) -> Result<String, ScenarioError> {
        Ok(
            "Three-node scenario (N02) requires running integration-tests.\n\
             Use: cargo test -p integration-tests n02_three_node_sign_verify -- --include-ignored"
                .to_string(),
        )
    }

    pub fn run_error_chain(&self) -> Result<String, ScenarioError> {
        Ok(
            "Error chain scenarios (E01-E06) require running integration-tests.\n\
             Use: cargo test -p integration-tests error_scenarios -- --include-ignored"
                .to_string(),
        )
    }

    pub fn run_boundary(&self) -> Result<String, ScenarioError> {
        Ok(
            "Boundary scenarios (B01-B05) require running integration-tests.\n\
             Use: cargo test -p integration-tests boundary_scenarios -- --include-ignored"
                .to_string(),
        )
    }
}
