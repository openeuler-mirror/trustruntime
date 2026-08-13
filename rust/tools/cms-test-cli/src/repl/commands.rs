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

//! 命令路由与执行模块
//!
//! 实现 REPL 命令的路由分发和执行逻辑，支持以下命令类别：
//! - 连接管理：connect、disconnect、status
//! - 核心操作：sign、verify、verify-sign、raw
//! - 性能测试：perf sign、perf verify、perf report
//! - 并发测试：concurrent sign、concurrent verify、concurrent report
//! - 安全测试：security protocol、security cert、security tls、security all
//! - 场景测试：scenario two-node、scenario three-node 等

use super::parser::Command;
pub use crate::config::CmsTestConfig;
use crate::stats::{ConcurrentResult, PerfResult, Reporter, SecurityTestResult};
use crate::testers::{
    ConcurrentTester, InteractiveTester, PerformanceTester, ProtocolSecurityTester, ScenarioRunner,
};
use integration_tests::vsock_client::VsockClient;
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// 命令执行错误类型
#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum CommandError {
    /// 未连接服务器
    #[error("not connected to server")]
    NotConnected,
    /// 无效端口
    #[error("invalid port: {0}")]
    InvalidPort(String),
    /// 证书未找到
    #[error("certificate not found: {0}")]
    CertificateNotFound(String),
    /// 连接失败
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    /// vsock 通信错误
    #[error("vsock error: {0}")]
    VsockError(String),
    /// 测试执行错误
    #[error("test error: {0}")]
    TestError(String),
    /// 解析错误
    #[error("parse error: {0}")]
    ParseError(String),
    /// 配置错误
    #[error("config error: {0}")]
    ConfigError(String),
}

/// 命令执行结果
pub enum ExecuteResult {
    /// 继续执行下一个命令
    Continue,
    /// 退出 REPL
    Quit,
    /// 输出消息到终端
    Output(String),
}

/// 命令路由器
///
/// 维护 REPL 状态（配置、连接、测试结果），分发命令到对应的处理函数。
pub struct CommandRouter {
    pub config: Arc<Mutex<CmsTestConfig>>,
    client: Option<Arc<Mutex<VsockClient>>>,
    perf_stats: Arc<Mutex<Option<PerfResult>>>,
    concurrent_stats: Arc<Mutex<Option<ConcurrentResult>>>,
    security_results: Arc<Mutex<Vec<SecurityTestResult>>>,
}

impl CommandRouter {
    pub fn new(config: CmsTestConfig) -> Self {
        Self {
            config: Arc::new(Mutex::new(config)),
            client: None,
            perf_stats: Arc::new(Mutex::new(None)),
            concurrent_stats: Arc::new(Mutex::new(None)),
            security_results: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// 执行命令
    ///
    /// # 参数
    /// - `cmd`: 解析后的命令
    ///
    /// # 返回
    /// - `Ok(ExecuteResult)`: 命令执行成功
    /// - `Err(CommandError)`: 命令执行失败
    pub fn execute(&mut self, cmd: Command) -> Result<ExecuteResult, CommandError> {
        match cmd {
            // 元命令
            Command::Quit => Ok(ExecuteResult::Quit),
            Command::Help { cmd: ref cmd_name } => {
                Ok(ExecuteResult::Output(self.get_help(cmd_name.as_ref())))
            }
            Command::History => Ok(ExecuteResult::Output(self.get_history())),
            Command::Clear => {
                // ANSI 转义序列：清屏并移动光标到左上角
                print!("\x1B[2J\x1B[1;1H");
                Ok(ExecuteResult::Continue)
            }

            // 连接管理
            Command::Connect { port } => self.handle_connect(port),
            Command::Disconnect => self.handle_disconnect(),
            Command::Status => self.handle_status(),

            // 核心操作
            Command::Sign { request } => self.handle_sign(request),
            Command::Verify { request } => self.handle_verify(request),
            Command::VerifySign { request } => self.handle_verify_sign(request),
            Command::Raw { msg_type, body } => self.handle_raw(msg_type, body),

            // 性能测试
            Command::PerfSign {
                count,
                data,
                interval,
            } => self.handle_perf_sign(count, data, interval),
            Command::PerfVerify {
                count,
                data,
                signed_data,
                id,
                interval,
            } => self.handle_perf_verify(count, data, signed_data, id, interval),
            Command::PerfVerifySign {
                count,
                sign_data,
                sign_id,
                verify_data,
                signed_data,
                verify_id,
                interval,
            } => self.handle_perf_verify_sign(
                count,
                sign_data,
                sign_id,
                verify_data,
                signed_data,
                verify_id,
                interval,
            ),
            Command::PerfReport => self.handle_perf_report(),

            // 并发测试
            Command::ConcurrentSign {
                threads,
                count,
                data,
                interval,
            } => self.handle_concurrent_sign(threads, count, data, interval),
            Command::ConcurrentVerify {
                threads,
                count,
                data,
                signed_data,
                id,
                interval,
            } => self.handle_concurrent_verify(threads, count, data, signed_data, id, interval),
            Command::ConcurrentVerifySign {
                threads,
                count,
                sign_data,
                sign_id,
                verify_data,
                signed_data,
                verify_id,
                interval,
            } => self.handle_concurrent_verify_sign(
                threads,
                count,
                sign_data,
                sign_id,
                verify_data,
                signed_data,
                verify_id,
                interval,
            ),
            Command::ConcurrentReport => self.handle_concurrent_report(),

            // 安全测试
            Command::SecurityProtocol { test } => self.handle_security_protocol(test),
            Command::SecurityCert { test: _ } => self.handle_security_cert(),
            Command::SecurityTls { test: _ } => self.handle_security_tls(),
            Command::SecurityAll => self.handle_security_all(),
            Command::SecurityReport => self.handle_security_report(),

            // 场景测试
            Command::Scenario { name } => self.handle_scenario(name),
        }
    }

    /// 获取帮助信息
    ///
    /// # 参数
    /// - `cmd`: 可选的命令名称，获取该命令的详细帮助
    fn get_help(&self, cmd: Option<&String>) -> String {
        match cmd {
            None => HELP_GENERAL.to_string(),
            Some(c) => match c.as_str() {
                "connect" => HELP_CONNECT.to_string(),
                "sign" => HELP_SIGN.to_string(),
                "verify" => HELP_VERIFY.to_string(),
                "verify-sign" => HELP_VERIFY_SIGN.to_string(),
                "perf" => HELP_PERF.to_string(),
                "concurrent" => HELP_CONCURRENT.to_string(),
                "security" => HELP_SECURITY.to_string(),
                "scenario" => HELP_SCENARIO.to_string(),
                _ => format!("No help available for '{}'", c),
            },
        }
    }

    /// 获取命令历史
    fn get_history(&self) -> String {
        let config = self.config.lock().unwrap();
        if config.history.is_empty() {
            "No command history.".to_string()
        } else {
            config
                .history
                .iter()
                .enumerate()
                .map(|(i, cmd)| format!("{}: {}", i + 1, cmd))
                .collect::<Vec<_>>()
                .join("\n")
        }
    }

    fn handle_connect(&mut self, port: Option<u32>) -> Result<ExecuteResult, CommandError> {
        let config = self.config.lock().unwrap();
        let port = port.unwrap_or(config.connection.port);

        let tls_ca = config.tls_client.ca_cert.clone();
        let tls_client_cert = config.tls_client.client_cert.clone();
        let tls_client_key = config.tls_client.client_key.clone();
        let key_password = config
            .tls_client
            .client_key_pwd
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.trim().to_string());

        let client = VsockClient::connect(
            port,
            &tls_ca,
            &tls_client_cert,
            &tls_client_key,
            key_password.as_deref(),
        )
        .map_err(|e| CommandError::ConnectionFailed(e.to_string()))?;

        self.client = Some(Arc::new(Mutex::new(client)));

        Ok(ExecuteResult::Output(format!(
            "Connected to vsock://1:{}",
            port
        )))
    }

    /// 处理 disconnect 命令
    ///
    /// 关闭当前连接并释放资源。
    fn handle_disconnect(&mut self) -> Result<ExecuteResult, CommandError> {
        if let Some(client) = &self.client {
            client
                .lock()
                .unwrap()
                .close()
                .map_err(|e| CommandError::VsockError(e.to_string()))?;
            self.client = None;
            Ok(ExecuteResult::Output("Disconnected.".to_string()))
        } else {
            Err(CommandError::NotConnected)
        }
    }

    fn handle_status(&self) -> Result<ExecuteResult, CommandError> {
        let config = self.config.lock().unwrap();
        let conn_status = if self.client.is_some() {
            "Connected"
        } else {
            "Not connected"
        };

        Ok(ExecuteResult::Output(format!(
            "Status: {}\nPort: {}\nTLS CA: {}\nClient cert: {}",
            conn_status,
            config.connection.port,
            config.tls_client.ca_cert.display(),
            config.tls_client.client_cert.display()
        )))
    }

    /// 执行测试操作
    ///
    /// # 参数
    /// - `test_fn`: 测试函数，接受 InteractiveTester 并返回结果
    ///
    /// # 返回
    /// 执行结果
    fn execute_test<F, R>(&self, test_fn: F) -> Result<ExecuteResult, CommandError>
    where
        F: FnOnce(InteractiveTester) -> Result<R, crate::testers::TestError>,
        R: serde::Serialize,
    {
        let client = self.get_client()?;
        let tester = InteractiveTester::new(client);
        let resp = test_fn(tester).map_err(|e| CommandError::TestError(e.to_string()))?;
        Ok(ExecuteResult::Output(Reporter::format_response(&resp)))
    }

    /// 处理 sign 命令
    ///
    /// 调用 CMS 签名接口（消息类型 0x10）。
    ///
    /// # 参数
    /// - `request`: 签名请求结构体
    fn handle_sign(
        &self,
        request: integration_tests::vsock_client::SignRequest,
    ) -> Result<ExecuteResult, CommandError> {
        self.execute_test(|tester| tester.sign_with_request(request))
    }

    /// 处理 verify 命令
    ///
    /// 调用 CMS 验签接口（消息类型 0x14）。
    ///
    /// # 参数
    /// - `request`: 验签请求结构体
    fn handle_verify(
        &self,
        request: integration_tests::vsock_client::VerifyRequest,
    ) -> Result<ExecuteResult, CommandError> {
        self.execute_test(|tester| tester.verify_with_request(request))
    }

    /// 处理 verify-sign 命令
    ///
    /// 调用验签+签名组合接口（消息类型 0x12）。
    /// 先验证第一个签名，再对第二个数据签名。
    ///
    /// # 参数
    /// - `request`: 验签+签名请求结构体
    fn handle_verify_sign(
        &self,
        request: integration_tests::vsock_client::VerifySignRequest,
    ) -> Result<ExecuteResult, CommandError> {
        self.execute_test(|tester| tester.verify_and_sign(request))
    }

    /// 处理 raw 命令
    ///
    /// 发送原始消息，用于调试和测试。
    ///
    /// # 参数
    /// - `msg_type`: 消息类型（如 0x10、0x12、0x14）
    /// - `body`: JSON 格式的消息体
    fn handle_raw(&self, msg_type: u32, body: String) -> Result<ExecuteResult, CommandError> {
        let client = self.get_client()?;
        let tester = InteractiveTester::new(client);
        let resp = tester
            .raw_request(msg_type, body)
            .map_err(|e| CommandError::TestError(e.to_string()))?;

        // 格式化原始响应
        let output = if resp.len == 0 {
            format!("Response: type=0x{:02x}, len=0 (no data)", resp.msg_type)
        } else {
            format!(
                "Response: type=0x{:02x}, len={}, body={:?}",
                resp.msg_type,
                resp.len,
                String::from_utf8_lossy(&resp.body)
            )
        };
        Ok(ExecuteResult::Output(output))
    }

    /// 处理 perf sign 命令
    ///
    /// 执行签名性能测试。
    ///
    /// # 参数
    /// - `count`: 请求数量
    /// - `data`: 待签名数据（可选）
    /// - `interval`: 请求间隔毫秒数（可选）
    fn handle_perf_sign(
        &self,
        count: u32,
        data: Option<String>,
        interval: Option<u32>,
    ) -> Result<ExecuteResult, CommandError> {
        let client = self.get_client()?;
        let data = data.unwrap_or_else(|| "test data".to_string());

        let tester = PerformanceTester::new(client);
        println!("Running {} sign requests...", count);

        let result = tester.run_sign_test(count, &data, interval);

        // 缓存结果供后续查看
        *self.perf_stats.lock().unwrap() = Some(result.clone());
        Ok(ExecuteResult::Output(Reporter::format_perf_report(&result)))
    }

    /// 处理 perf verify 命令
    ///
    /// 执行验签性能测试。
    fn handle_perf_verify(
        &self,
        count: u32,
        data: String,
        signed_data: String,
        id: String,
        interval: Option<u32>,
    ) -> Result<ExecuteResult, CommandError> {
        let client = self.get_client()?;
        let tester = PerformanceTester::new(client);
        println!("Running {} verify requests...", count);

        let result = tester.run_verify_test(count, &data, &signed_data, &id, interval);

        *self.perf_stats.lock().unwrap() = Some(result.clone());
        Ok(ExecuteResult::Output(Reporter::format_perf_report(&result)))
    }

    /// 处理 perf verify-sign 命令
    ///
    /// 执行验签+签名性能测试，支持简化模式和完整模式。
    #[allow(clippy::too_many_arguments)]
    fn handle_perf_verify_sign(
        &self,
        count: u32,
        sign_data: String,
        sign_id: Option<String>,
        verify_data: Option<String>,
        signed_data: Option<String>,
        verify_id: Option<String>,
        interval: Option<u32>,
    ) -> Result<ExecuteResult, CommandError> {
        let client = self.get_client()?;
        let tester = PerformanceTester::new(client);
        println!("Running {} verify-sign requests...", count);

        let result = tester.run_verify_sign_test(
            count,
            &sign_data,
            sign_id.as_deref(),
            verify_data.as_deref(),
            signed_data.as_deref(),
            verify_id.as_deref(),
            interval,
        );

        *self.perf_stats.lock().unwrap() = Some(result.clone());
        Ok(ExecuteResult::Output(Reporter::format_perf_report(&result)))
    }

    /// 处理 perf report 命令
    ///
    /// 显示最近一次性能测试结果。
    fn handle_perf_report(&self) -> Result<ExecuteResult, CommandError> {
        let stats = self.perf_stats.lock().unwrap();
        match &*stats {
            Some(result) => Ok(ExecuteResult::Output(Reporter::format_perf_report(result))),
            None => Ok(ExecuteResult::Output(
                "No performance test results available.".to_string(),
            )),
        }
    }

    fn handle_concurrent_sign(
        &self,
        threads: u32,
        count: u32,
        data: Option<String>,
        interval: Option<u32>,
    ) -> Result<ExecuteResult, CommandError> {
        let config = self.config.lock().unwrap();
        let data = data.unwrap_or_else(|| "test data".to_string());
        let tls_config = config.tls_client.clone();
        let port = config.connection.port;

        println!(
            "Running concurrent test with {} threads, {} requests each...",
            threads, count
        );

        let tester = ConcurrentTester::new(tls_config, port);
        let result = tester.run_sign_test(threads, count, &data, interval);

        *self.concurrent_stats.lock().unwrap() = Some(result.clone());
        Ok(ExecuteResult::Output(Reporter::format_concurrent_report(
            &result,
        )))
    }

    fn handle_concurrent_verify(
        &self,
        threads: u32,
        count: u32,
        data: String,
        signed_data: String,
        id: String,
        interval: Option<u32>,
    ) -> Result<ExecuteResult, CommandError> {
        let config = self.config.lock().unwrap();
        let tls_config = config.tls_client.clone();
        let port = config.connection.port;

        println!(
            "Running concurrent verify test with {} threads, {} requests each...",
            threads, count
        );

        let tester = ConcurrentTester::new(tls_config, port);
        let result = tester.run_verify_test(threads, count, &data, &signed_data, &id, interval);

        *self.concurrent_stats.lock().unwrap() = Some(result.clone());
        Ok(ExecuteResult::Output(Reporter::format_concurrent_report(
            &result,
        )))
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_concurrent_verify_sign(
        &self,
        threads: u32,
        count: u32,
        sign_data: String,
        sign_id: Option<String>,
        verify_data: Option<String>,
        signed_data: Option<String>,
        verify_id: Option<String>,
        interval: Option<u32>,
    ) -> Result<ExecuteResult, CommandError> {
        let config = self.config.lock().unwrap();
        let tls_config = config.tls_client.clone();
        let port = config.connection.port;

        println!(
            "Running concurrent verify-sign test with {} threads, {} requests each...",
            threads, count
        );

        let tester = ConcurrentTester::new(tls_config, port);
        let result = tester.run_verify_sign_test(
            threads,
            count,
            &sign_data,
            sign_id.as_deref(),
            verify_data.as_deref(),
            signed_data.as_deref(),
            verify_id.as_deref(),
            interval,
        );

        *self.concurrent_stats.lock().unwrap() = Some(result.clone());
        Ok(ExecuteResult::Output(Reporter::format_concurrent_report(
            &result,
        )))
    }

    /// 处理 concurrent report 命令
    fn handle_concurrent_report(&self) -> Result<ExecuteResult, CommandError> {
        let stats = self.concurrent_stats.lock().unwrap();
        match &*stats {
            Some(result) => Ok(ExecuteResult::Output(Reporter::format_concurrent_report(
                result,
            ))),
            None => Ok(ExecuteResult::Output(
                "No concurrent test results available.".to_string(),
            )),
        }
    }

    /// 处理 security protocol 命令
    ///
    /// 执行协议层安全测试，检测服务端对异常输入的处理。
    ///
    /// # 测试项目
    /// - version-mismatch: 错误版本号
    /// - oversized-message: 超大消息
    /// - unknown-type: 未注册消息类型
    /// - malformed-header: 不完整消息头
    fn handle_security_protocol(
        &self,
        test: Option<String>,
    ) -> Result<ExecuteResult, CommandError> {
        let client = self.get_client()?;
        let tester = ProtocolSecurityTester::new(client);

        println!("Testing protocol layer attacks...");

        // 执行单个或全部测试
        let results = match test {
            None => tester.run_all(),
            Some(name) => tester.run_single(&name),
        };

        // 累积测试结果
        let mut all_results = self.security_results.lock().unwrap();
        all_results.extend(results.clone());

        Ok(ExecuteResult::Output(Reporter::format_security_report(
            &results,
        )))
    }

    /// 处理 security cert 命令
    ///
    /// 证书层安全测试（需独立服务器实例）。
    fn handle_security_cert(&self) -> Result<ExecuteResult, CommandError> {
        Ok(ExecuteResult::Output("Certificate security tests require launching temporary server instances.\nUse 'scenario error-chain' for certificate-related error tests.".to_string()))
    }

    /// 处理 security tls 命令
    ///
    /// TLS 层安全测试（需特殊证书配置）。
    fn handle_security_tls(&self) -> Result<ExecuteResult, CommandError> {
        Ok(ExecuteResult::Output("TLS security tests require special certificate setup.\nUse integration-tests for comprehensive TLS testing.".to_string()))
    }

    /// 处理 security all 命令
    ///
    /// 执行所有可用的安全测试。
    /// 注意：证书层和TLS层测试需要特殊环境，请使用其他命令或集成测试。
    fn handle_security_all(&self) -> Result<ExecuteResult, CommandError> {
        println!("Running all available security tests...\n");

        // 执行协议层测试（已实现）
        self.handle_security_protocol(None)?;

        // 告知用户证书层和TLS层测试的状态
        println!("\n--- Other Security Tests ---");
        println!(
            "Certificate tests: Use 'scenario error-chain' for certificate-related error tests."
        );
        println!("TLS tests: Use integration-tests for comprehensive TLS testing.");

        Ok(ExecuteResult::Continue)
    }

    /// 处理 security report 命令
    fn handle_security_report(&self) -> Result<ExecuteResult, CommandError> {
        let results = self.security_results.lock().unwrap();
        if results.is_empty() {
            Ok(ExecuteResult::Output(
                "No security test results available.".to_string(),
            ))
        } else {
            Ok(ExecuteResult::Output(Reporter::format_security_report(
                &results,
            )))
        }
    }

    fn handle_scenario(&self, name: String) -> Result<ExecuteResult, CommandError> {
        let config = self.config.lock().unwrap();
        let runner = ScenarioRunner::new(
            config.tls_client.clone(),
            config.cms_certs.clone(),
            config.server.binary_path.clone(),
        );

        let output = match name.as_str() {
            "two-node" => runner
                .run_two_node()
                .map_err(|e| CommandError::TestError(e.to_string()))?,
            "three-node" => runner
                .run_three_node()
                .map_err(|e| CommandError::TestError(e.to_string()))?,
            "error-chain" => runner
                .run_error_chain()
                .map_err(|e| CommandError::TestError(e.to_string()))?,
            "boundary" => runner
                .run_boundary()
                .map_err(|e| CommandError::TestError(e.to_string()))?,
            _ => {
                return Err(CommandError::TestError(format!(
                    "Unknown scenario: {}",
                    name
                )))
            }
        };

        Ok(ExecuteResult::Output(output))
    }

    /// 获取当前客户端连接
    ///
    /// # 错误
    /// 如果未连接，返回 `NotConnected` 错误。
    fn get_client(&self) -> Result<Arc<Mutex<VsockClient>>, CommandError> {
        self.client.clone().ok_or(CommandError::NotConnected)
    }
}

// ============================================================================
// 帮助文本常量
// ============================================================================

/// 通用帮助文本：显示所有命令概览
const HELP_GENERAL: &str = "CMS Test CLI - Interactive testing tool for CMS signing service

Commands:
  connect [port]                       Connect to server (uses config port if not specified)
  disconnect                           Disconnect from server
  status                               Show connection status

sign <json>                           Sign data (0x10)
verify <json>                         Verify signature (0x14)
verify-sign <json>                     Verify and sign (0x12)
  raw <type> <json_body>               Send raw request

  perf sign --count <n> [--data <text>]  Performance test (sign)
  perf verify --count <n> ...            Performance test (verify)
  perf report                            Show performance stats

  concurrent sign --threads <n> --count <n>  Concurrent test (sign)
  concurrent verify --threads <n> ...        Concurrent test (verify)
  concurrent report                          Show concurrent stats

  security protocol [test]    Protocol layer security tests
  security cert [test]        Certificate layer security tests
  security tls [test]         TLS layer security tests
  security all                Run all security tests
  security report             Show security test results

  scenario two-node           Run two-node scenario (N01)
  scenario three-node         Run three-node scenario (N02)
  scenario error-chain        Run error scenarios (E01-E06)
  scenario boundary           Run boundary scenarios (B01-B05)

  help [command]              Show help
  history                     Show command history
  clear                       Clear screen
  quit                        Exit

Use 'help <command>' for detailed help on a specific command.";

/// connect 命令帮助文本
const HELP_CONNECT: &str = "connect [port]

Connect to CMS signing service via TLS over vsock.

Arguments:
  port    vsock port number (optional, uses config value if not specified)

Example:
  connect           # Use port from config file
  connect 12345     # Override port";

/// sign 命令帮助文本
const HELP_SIGN: &str = "sign <json>

Call signing interface (0x10).

JSON format:
  {
    \"to-sign\": {
      \"data\": \"<data_to_sign>\"
    }
  }

Arguments:
  json    Complete request in JSON format

Example:
  # Define JSON variable
  JSON='{\"to-sign\":{\"data\":\"hello world\"}}'

  # Execute sign command
  sign '$JSON'

Response:
  signed_data: Base64-encoded CMS signature
  id: Base64-encoded certificate Subject Key ID
  result: 0 (success) or error code";

/// verify 命令帮助文本
const HELP_VERIFY: &str = "verify <json>

Call verify interface (0x14).

JSON format:
  {
    \"to-verify\": {
      \"data\": \"<original_data>\",
      \"signed_data\": \"<Base64_signature>\",
      \"id\": \"<Base64_cert_id>\"
    }
  }

Arguments:
  json    Complete request in JSON format

Example:
  # Step 1: Define JSON variable
  JSON='{\"to-sign\":{\"data\":\"hello\"}}'

  # Step 2: Execute sign command
  sign '$JSON'
  # Output: {\"signed_data\":\"MIIC...\",\"id\":\"ABC123...\",\"result\":0}

  # Step 3: Use the output in verify
  JSON='{\"to-verify\":{\"data\":\"hello\",\"signed_data\":\"MIIC...\",\"id\":\"ABC123...\"}}'
  verify '$JSON'

Response:
  result: 0 (success) or error code";

/// verify-sign 命令帮助文本
const HELP_VERIFY_SIGN: &str = "verify-sign <json>

Call verify-and-sign interface (0x12).
First verify the signature, then sign new data.

JSON format:
  {
    \"to-verify\": {
      \"data\": \"<original_data>\",
      \"signed_data\": \"<Base64_signature>\",
      \"id\": \"<Base64_cert_id>\"
    },
    \"to-sign\": {
      \"data\": \"<new_data>\",
      \"id\": \"<Base64_cert_id>\"
    }
  }

Arguments:
  json    Complete request in JSON format

Example:
  # Step 1: Define JSON variable for sign
  JSON='{\"to-sign\":{\"data\":\"hello\"}}'
  sign '$JSON'
  # Output: {\"signed_data\":\"MIIC...\",\"id\":\"ABC123...\",\"result\":0}

  # Step 2: Define JSON variable for verify-sign
  JSON='{\"to-verify\":{\"data\":\"hello\",\"signed_data\":\"MIIC...\",\"id\":\"ABC123...\"},\"to-sign\":{\"data\":\"world\",\"id\":\"ABC123...\"}}'
  verify-sign '$JSON'

Response:
  signed_data: Base64-encoded new CMS signature
  id: Base64-encoded certificate Subject Key ID (same as to-sign.id)
  result: 0 (success) or error code

Note:
  - Use variable to store JSON, avoid manual escaping
  - to-verify.signed_data must be a valid signature from sign or verify-sign command
  - to-verify.id must match the certificate ID that signed the data
  - to-verify.data must match the original data used for signing
  - to-sign.id is usually the same as to-verify.id";

/// perf 命令帮助文本
const HELP_PERF: &str = "perf sign --count <n> [--data <text>] [--interval <ms>]
perf verify --count <n> --data <text> --signed-data <b64> --id <b64> [--interval <ms>]
perf verify-sign --count <n> --sign-data <text> [--sign-id <id>] [--interval <ms>]
perf verify-sign --count <n> --sign-data <text> --verify-data <text> --signed-data <b64> --verify-id <b64> [--sign-id <id>] [--interval <ms>]
perf report

Run performance tests to measure response time and throughput.

Arguments (sign):
  --count      Number of requests (default: 10)
  --data       Data to sign (default: \"test data\")
  --interval   Interval between requests in ms (optional)

Arguments (verify):
  --count      Number of requests
  --data       Original data that was signed
  --signed-data  Base64-encoded signature to verify
  --id         Base64-encoded certificate ID
  --interval   Interval between requests in ms (optional)

Arguments (verify-sign):
  --count        Number of requests
  --sign-data    Data to sign (required)
  --sign-id      Certificate ID for signing (optional, auto-filled in simple mode)
  --verify-data  Original data for verification (optional, defaults to sign-data)
  --signed-data  Base64-encoded signature (optional, auto-fetched in simple mode)
  --verify-id    Certificate ID for verification (optional, auto-filled in simple mode)
  --interval     Interval between requests in ms (optional)

Simple mode (verify-sign):
  Only provide --sign-data, tool auto-fetches signature via sign interface.

Output:
  Total requests, Success/Failed count
  Avg/Min/Max response time (ms)
  Throughput (QPS)
  Error distribution

Example:
  perf sign --count 100
  perf verify --count 50 --data \"hello\" --signed-data MIIM... --id abc123...
  perf verify-sign --count 100 --sign-data \"test\"
  perf verify-sign --count 50 --sign-data \"new\" --verify-data \"old\" --signed-data MIIM... --verify-id abc123...";

/// concurrent 命令帮助文本
const HELP_CONCURRENT: &str = "concurrent sign --threads <n> --count <n> [--data <text>] [--interval <ms>]
concurrent verify --threads <n> --count <n> --data <text> --signed-data <b64> --id <b64> [--interval <ms>]
concurrent verify-sign --threads <n> --count <n> --sign-data <text> [--sign-id <id>] [--interval <ms>]
concurrent verify-sign --threads <n> --count <n> --sign-data <text> --verify-data <text> --signed-data <b64> --verify-id <b64> [--sign-id <id>] [--interval <ms>]
concurrent report

Run concurrent tests with multiple independent connections.

Arguments (sign):
  --threads    Number of concurrent threads (default: 4)
  --count      Requests per thread (default: 10)
  --data       Data to sign
  --interval   Interval between requests in ms (optional)

Arguments (verify):
  --threads    Number of concurrent threads
  --count      Requests per thread
  --data       Original data that was signed
  --signed-data  Signature to verify
  --id         Certificate ID
  --interval   Interval between requests in ms (optional)

Arguments (verify-sign):
  --threads      Number of concurrent threads
  --count        Requests per thread
  --sign-data    Data to sign (required)
  --sign-id      Certificate ID for signing (optional, auto-filled in simple mode)
  --verify-data  Original data for verification (optional, defaults to sign-data)
  --signed-data  Base64-encoded signature (optional, auto-fetched in simple mode)
  --verify-id    Certificate ID for verification (optional, auto-filled in simple mode)
  --interval     Interval between requests in ms (optional)

Simple mode (verify-sign):
  Only provide --sign-data, tool auto-fetches signature via sign interface.

Note: Each thread creates its own TLS connection.

Example:
  concurrent sign --threads 16 --count 50
  concurrent sign --threads 8 --count 20 --interval 100
  concurrent verify --threads 8 --count 20 --data \"hello\" --signed-data MIIM... --id abc123...
  concurrent verify --threads 4 --count 10 --data \"test\" --signed-data MIIM... --id abc123... --interval 50
  concurrent verify-sign --threads 4 --count 10 --sign-data \"test\"
  concurrent verify-sign --threads 4 --count 10 --sign-data \"test\" --interval 100
  concurrent verify-sign --threads 4 --count 10 --sign-data \"new\" --verify-data \"old\" --signed-data MIIM... --verify-id abc123...";

/// security 命令帮助文本
const HELP_SECURITY: &str = "security protocol [test]
security cert [test]
security tls [test]
security all
security report

Run security tests for protocol, certificate, or TLS layer.

Protocol layer tests:
  version-mismatch    Send wrong version number
  oversized-message   Send message > 10KB
  unknown-type        Send unregistered message type
  malformed-header    Send incomplete header

Certificate layer tests:
  expired-cert        Use expired certificate
  revoked-cert        Use revoked certificate
  self-signed         Use self-signed certificate
  wrong-ca            Use wrong CA certificate

TLS layer tests:
  no-client-cert      Connect without client certificate
  wrong-ca-client     Connect with wrong CA client certificate
  weak-algorithm      Attempt weak cipher suite

Example:
  security protocol
  security protocol version-mismatch
  security all";

/// scenario 命令帮助文本
const HELP_SCENARIO: &str = "scenario <name>

Run pre-configured test scenarios.

Available scenarios:
  two-node      Two-node sign-verify chain (N01)
  three-node    Three-node sign-verify chain (N02)
  error-chain   Error scenarios (E01-E06)
  boundary      Boundary scenarios (B01-B05)

Example:
  scenario two-node
  scenario error-chain";
