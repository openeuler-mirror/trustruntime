//! 进程管理器模块
//!
//! 管理trustruntime进程的生命周期，用于集成测试。
//! 支持启动多个节点实例，自动生成配置文件，等待就绪状态。
//!
//! ## 主要功能
//! - 启动/停止trustruntime进程
//! - 动态生成配置文件
//! - 等待vsock端口就绪
//! - 进程实例跟踪和管理
//!
//! ## 使用示例
//! ```text
//! // 创建进程管理器
//! let manager = ProcessManager::new(binary_path, cert_base_path);
//! // 启动节点
//! manager.start_node(NodeConfig { name: "node1", port: 12345, ... })?;
//! // 停止所有节点
//! manager.stop_all()?;
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use thiserror::Error;

/// 进程管理错误类型
#[derive(Error, Debug)]
pub enum ProcessError {
    /// 进程启动失败
    #[error("failed to start process: {0}")]
    StartFailed(String),
    /// 进程未在超时时间内就绪
    #[error("process not ready within timeout")]
    Timeout,
    /// 进程停止失败
    #[error("failed to stop process: {0}")]
    StopFailed(String),
    /// 配置文件写入失败
    #[error("failed to write config: {0}")]
    ConfigError(String),
}

/// 节点配置
///
/// 定义trustruntime节点实例的启动参数。
#[derive(Default)]
pub struct NodeConfig {
    /// 节点名称（用于标识和管理）
    pub name: String,
    /// vsock监听端口
    pub port: u32,
    /// CMS签名证书路径
    pub cms_cert_path: PathBuf,
    /// CMS签名私钥路径
    pub cms_key_path: PathBuf,
    /// TLS服务端证书路径
    pub tls_cert_path: PathBuf,
    /// TLS服务端私钥路径
    pub tls_key_path: PathBuf,
    /// TLS客户端CRL路径（可选，用于测试吊销场景）
    pub tls_client_crl: Option<PathBuf>,
}

/// 进程实例
///
/// 跟踪正在运行的trustruntime进程及其相关资源。
pub struct ProcessInstance {
    /// 节点名称
    pub name: String,
    /// vsock端口
    pub port: u32,
    /// 子进程句柄
    pub child: Child,
    /// 临时目录（包含配置文件和日志）
    pub temp_dir: TempDir,
}

/// 进程管理器
///
/// 管理多个trustruntime进程实例。
/// 使用Arc<Mutex>支持跨线程共享。
pub struct ProcessManager {
    /// 进程实例映射表（名称 -> 实例）
    processes: Arc<Mutex<HashMap<String, ProcessInstance>>>,
    /// trustruntime二进制文件路径
    binary_path: PathBuf,
    /// 测试证书基础路径
    cert_base_path: PathBuf,
}

impl ProcessManager {
    /// 创建新的进程管理器
    ///
    /// # Arguments
    /// * `binary_path` - trustruntime可执行文件路径
    /// * `cert_base_path` - 测试证书基础路径
    pub fn new(binary_path: PathBuf, cert_base_path: PathBuf) -> Self {
        Self {
            processes: Arc::new(Mutex::new(HashMap::new())),
            binary_path,
            cert_base_path,
        }
    }

    /// 启动单个节点
    ///
    /// 创建临时目录、生成配置文件、启动进程并等待就绪。
    ///
    /// # Arguments
    /// * `config` - 节点配置
    ///
    /// # Returns
    /// 成功返回Ok，失败返回ProcessError
    ///
    /// # Errors
    /// - ConfigError: 配置文件生成失败
    /// - StartFailed: 进程启动失败
    /// - Timeout: 进程未在5秒内就绪
    pub fn start_node(&self, config: NodeConfig) -> Result<(), ProcessError> {
        let temp_dir = TempDir::new().map_err(|e| ProcessError::ConfigError(e.to_string()))?;

        let config_path = temp_dir.path().join("config.toml");
        self.write_config(&config_path, &config, temp_dir.path())?;

        let child = Command::new(&self.binary_path)
            .arg("--config")
            .arg(&config_path)
            .spawn()
            .map_err(|e| ProcessError::StartFailed(e.to_string()))?;

        // 等待进程就绪（vsock端口可连接）
        self.wait_for_ready(config.port, Duration::from_secs(5))?;

        let instance = ProcessInstance {
            name: config.name.clone(),
            port: config.port,
            child,
            temp_dir,
        };

        self.processes
            .lock()
            .unwrap()
            .insert(config.name.clone(), instance);

        Ok(())
    }

    /// 启动多个节点
    ///
    /// 批量启动多个节点实例。
    pub fn start_multiple(&self, configs: Vec<NodeConfig>) -> Result<(), ProcessError> {
        for config in configs {
            self.start_node(config)?;
        }
        Ok(())
    }

    /// 停止指定节点
    ///
    /// 终止进程并等待退出。
    ///
    /// # Arguments
    /// * `name` - 节点名称
    pub fn stop_node(&self, name: &str) -> Result<(), ProcessError> {
        let mut processes = self.processes.lock().unwrap();

        if let Some(mut instance) = processes.remove(name) {
            instance
                .child
                .kill()
                .map_err(|e| ProcessError::StopFailed(e.to_string()))?;
            instance
                .child
                .wait()
                .map_err(|e| ProcessError::StopFailed(e.to_string()))?;
        }

        Ok(())
    }

    /// 停止所有节点
    ///
    /// 终止所有正在运行的进程实例。
    pub fn stop_all(&self) -> Result<(), ProcessError> {
        let mut processes = self.processes.lock().unwrap();

        for (_, mut instance) in processes.drain() {
            instance
                .child
                .kill()
                .map_err(|e| ProcessError::StopFailed(e.to_string()))?;
            instance.child.wait().ok();
        }

        Ok(())
    }

    /// 写入配置文件
    ///
    /// 根据节点配置生成TOML配置文件。
    fn write_config(
        &self,
        path: &Path,
        config: &NodeConfig,
        temp_dir: &Path,
    ) -> Result<(), ProcessError> {
        let log_path = temp_dir.join("trustring.log");

        // 可选的TLS客户端CRL配置行
        let tls_client_crl_line = if let Some(crl_path) = &config.tls_client_crl {
            format!("comm_crl = \"{}\"\n", crl_path.display())
        } else {
            String::new()
        };

        let config_content = format!(
            r#"
[vsock]
port = {}

[log]
path = "{}"
max_file_size = 10
max_roll_count = 10

[certificate]
signer_cert = "{}"
signer_key = "{}"
ca_root_cert = "{}"
cms_crl = "{}"

comm_cert = "{}"
comm_key = "{}"
comm_ca_root = "{}"
{}"#,
            config.port,
            log_path.display(),
            config.cms_cert_path.display(),
            config.cms_key_path.display(),
            self.cert_base_path.join("cms/ca.crt").display(),
            self.cert_base_path.join("cms/cms.crl").display(),
            config.tls_cert_path.display(),
            config.tls_key_path.display(),
            self.cert_base_path.join("tls/ca.crt").display(),
            tls_client_crl_line,
        );

        // 调试输出配置内容
        eprintln!("DEBUG: Config written to {:?}", path);
        eprintln!("DEBUG: Config content:\n{}", config_content);

        std::fs::write(path, config_content)
            .map_err(|e| ProcessError::ConfigError(e.to_string()))?;

        Ok(())
    }

    /// 等待进程就绪
    ///
    /// 循环检测vsock端口直到可连接或超时。
    ///
    /// # Arguments
    /// * `port` - vsock端口
    /// * `timeout` - 超时时间
    fn wait_for_ready(&self, port: u32, timeout: Duration) -> Result<(), ProcessError> {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            eprintln!(
                "DEBUG: Checking vsock port {} (elapsed: {:.2}s)",
                port,
                start.elapsed().as_secs_f32()
            );
            if self.check_vsock_port(port) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        Err(ProcessError::Timeout)
    }

    /// 检测vsock端口是否就绪
    ///
    /// 尝试多个CID值，任一成功即认为就绪。
    ///
    /// ## CID尝试顺序
    /// 1. VMADDR_CID_LOCAL (1) - WSL2本地连接首选
    /// 2. CID=2 - 预留CID
    /// 3. VMADDR_CID_HOST (0xFFFFFFFE) - 连接宿主机
    fn check_vsock_port(&self, port: u32) -> bool {
        // 在WSL2环境中，VMADDR_CID_LOCAL (1) 通常可用于本地连接
        // VMADDR_CID_HOST (0xFFFFFFFE) 用于从guest连接到host
        // 按可能性顺序尝试多个CID
        let cids: [u32; 3] = [1, 2, 0xFFFFFFFE];

        for cid in cids {
            if vsock_stream_connect(cid, port).is_ok() {
                eprintln!(
                    "DEBUG: vsock port {} ready, connected with CID={}",
                    port, cid
                );
                return true;
            }
        }

        false
    }
}

/// vsock连接函数（Linux平台）
///
/// 使用原生vsock API建立连接。
#[cfg(target_os = "linux")]
fn vsock_stream_connect(cid: u32, port: u32) -> Result<vsock::VsockStream, std::io::Error> {
    use vsock::VsockAddr;
    let addr = VsockAddr::new(cid, port);
    vsock::VsockStream::connect(&addr)
}

/// vsock连接函数（非Linux平台）
///
/// Windows等平台不支持vsock，使用TCP作为替代。
#[cfg(not(target_os = "linux"))]
fn vsock_stream_connect(cid: u32, port: u32) -> Result<std::net::TcpStream, std::io::Error> {
    std::net::TcpStream::connect(format!("127.0.0.1:{}", port))
}

/// 进程管理器析构函数
///
/// 确保所有进程在管理器销毁时被停止。
impl Drop for ProcessManager {
    fn drop(&mut self) {
        self.stop_all().ok();
    }
}
