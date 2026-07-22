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

use openssl::pkey::PKey;
use std::collections::HashMap;
use std::fs;
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

macro_rules! wrap_err {
    ($result:expr, $msg:expr) => {
        $result.map_err(|e| ProcessError::ConfigError(format!("{}: {}", $msg, e)))?
    };
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
        self.prepare_hardcoded_cert_paths(&config)?;

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

        self.cleanup_hardcoded_cert_paths();

        Ok(())
    }

    fn run_sudo_command(&self, cmd: &str, args: &[&str], desc: &str) -> Result<(), ProcessError> {
        eprintln!("DEBUG: {}", desc);
        let status = Command::new("sudo")
            .args(std::iter::once(cmd).chain(args.iter().map(|s| *s)))
            .status()
            .map_err(|e| ProcessError::ConfigError(format!("Failed to {}: {}", desc, e)))?;
        if !status.success() {
            return Err(ProcessError::ConfigError(format!(
                "Failed to {}: exit code {:?}",
                desc,
                status.code()
            )));
        }
        Ok(())
    }

    fn copy_file(&self, src: &Path, dst: &str, desc: &str) -> Result<(), ProcessError> {
        eprintln!("DEBUG: Copying {} from {} to {}", desc, src.display(), dst);
        self.run_sudo_command("cp", &[&src.to_string_lossy(), dst], &format!("copy {}", desc))
    }

    fn ensure_cert_dirs(&self) -> Result<(), ProcessError> {
        let dirs = vec!["/etc/cert/server", "/etc/cert/cms"];
        for dir in dirs {
            if Path::new(dir).exists() {
                self.run_sudo_command("rm", &["-rf", dir], &format!("remove {}", dir))?;
            }
            self.run_sudo_command("mkdir", &["-p", dir], &format!("create {}", dir))?;
            self.run_sudo_command("chmod", &["755", dir], &format!("set permissions for {}", dir))?;
        }
        Ok(())
    }

    fn copy_tls_certs(&self, config: &NodeConfig) -> Result<(), ProcessError> {
        self.copy_file(&config.tls_cert_path, "/etc/cert/server/certificate.crt", "TLS cert")?;
        self.copy_file(&config.tls_key_path, "/etc/cert/server/private.key", "TLS key")?;
        self.copy_file(
            &self.cert_base_path.join("tls/ca.crt"),
            "/etc/cert/server/ca_root.crt",
            "TLS CA",
        )?;
        Ok(())
    }

    fn copy_cms_certs(&self, config: &NodeConfig) -> Result<(), ProcessError> {
        self.copy_file(&config.cms_cert_path, "/etc/cert/cms/signer.crt", "CMS cert")?;
        self.copy_file(&config.cms_key_path, "/etc/cert/cms/signer.key", "CMS key")?;
        self.copy_file(
            &self.cert_base_path.join("cms/ca.crt"),
            "/etc/cert/cms/ca_root.crt",
            "CMS CA",
        )?;
        Ok(())
    }

    fn generate_and_copy_empty_crl(
        &self,
        ca_cert_path: &Path,
        dst: &str,
        desc: &str,
    ) -> Result<(), ProcessError> {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;

        eprintln!("DEBUG: Generating empty {} CRL", desc);
        let ca_cert = openssl::x509::X509::from_pem(
            &fs::read(ca_cert_path).map_err(|e| ProcessError::ConfigError(e.to_string()))?,
        )
        .map_err(|e| ProcessError::ConfigError(e.to_string()))?;

        let group =
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                .map_err(|e| ProcessError::ConfigError(format!("Failed to create EC group: {}", e)))?;
        let temp_ca_key = EcKey::generate(&group)
            .map_err(|e| ProcessError::ConfigError(format!("Failed to generate EC key: {}", e)))?;
        let temp_ca_pkey = PKey::from_ec_key(temp_ca_key)
            .map_err(|e| ProcessError::ConfigError(format!("Failed to create PKey: {}", e)))?;

        let empty_crl = Self::generate_empty_crl(&ca_cert, &temp_ca_pkey)
            .map_err(|e| ProcessError::ConfigError(format!("Failed to generate empty CRL: {}", e)))?;

        let temp_crl_path = format!("/tmp/{}_empty_crl.pem", desc.to_lowercase());
        fs::write(&temp_crl_path, empty_crl).map_err(|e| ProcessError::ConfigError(e.to_string()))?;
        self.run_sudo_command("cp", &[&temp_crl_path, dst], &format!("copy empty {} CRL", desc))?;
        fs::remove_file(&temp_crl_path).ok();

        Ok(())
    }

    fn setup_tls_crl(&self, config: &NodeConfig) -> Result<(), ProcessError> {
        if let Some(crl_path) = &config.tls_client_crl {
            self.copy_file(crl_path, "/etc/cert/server/cert.crl", "TLS CRL")?;
        } else {
            self.generate_and_copy_empty_crl(
                &self.cert_base_path.join("tls/ca.crt"),
                "/etc/cert/server/cert.crl",
                "TLS",
            )?;
        }
        Ok(())
    }

    fn setup_cms_crl(&self) -> Result<(), ProcessError> {
        let cms_crl_src = self.cert_base_path.join("cms/cms.crl");
        if cms_crl_src.exists() {
            self.copy_file(&cms_crl_src, "/etc/cert/cms/cms.crl", "CMS CRL")?;
        } else {
            let cms_ca_key_pem = fs::read(self.cert_base_path.join("cms/ca.key"))
                .map_err(|e| ProcessError::ConfigError(e.to_string()))?;
            let cms_ca_pkey = PKey::private_key_from_pem(&cms_ca_key_pem)
                .map_err(|e| ProcessError::ConfigError(e.to_string()))?;
            let cms_ca_cert = openssl::x509::X509::from_pem(
                &fs::read(self.cert_base_path.join("cms/ca.crt"))
                    .map_err(|e| ProcessError::ConfigError(e.to_string()))?,
            )
            .map_err(|e| ProcessError::ConfigError(e.to_string()))?;

            let empty_crl = Self::generate_empty_crl(&cms_ca_cert, &cms_ca_pkey)
                .map_err(|e| {
                    ProcessError::ConfigError(format!("Failed to generate empty CRL: {}", e))
                })?;

            let temp_crl_path = "/tmp/cms_empty_crl.pem";
            fs::write(temp_crl_path, empty_crl)
                .map_err(|e| ProcessError::ConfigError(e.to_string()))?;
            self.run_sudo_command("cp", &[temp_crl_path, "/etc/cert/cms/cms.crl"], "copy empty CMS CRL")?;
            fs::remove_file(temp_crl_path).ok();
        }
        Ok(())
    }

    fn setup_key_password(&self) -> Result<(), ProcessError> {
        let key_pwd_src = self.cert_base_path.join("tls/key_pwd.txt");
        if key_pwd_src.exists() {
            self.copy_file(&key_pwd_src, "/etc/cert/server/key_pwd.txt", "key_pwd.txt")?;
        } else {
            self.run_sudo_command(
                "sh",
                &["-c", "echo -n '' > /etc/cert/server/key_pwd.txt"],
                "create empty key_pwd.txt",
            )?;
        }
        Ok(())
    }

    /// 预置证书到硬编码路径（仅测试环境）
    ///
    /// 创建硬编码路径目录，复制测试证书到生产路径。
    fn prepare_hardcoded_cert_paths(&self, config: &NodeConfig) -> Result<(), ProcessError> {
        eprintln!("DEBUG: prepare_hardcoded_cert_paths called");

        self.ensure_cert_dirs()?;
        self.copy_tls_certs(config)?;
        self.copy_cms_certs(config)?;
        self.setup_tls_crl(config)?;
        self.setup_cms_crl()?;
        self.setup_key_password()?;

        eprintln!("DEBUG: prepare_hardcoded_cert_paths completed successfully");
        Ok(())
    }

    fn build_aki_extension(ca_cert: &openssl::x509::X509) -> Result<openssl::x509::X509Extension, ProcessError> {
        use openssl::x509::extension::AuthorityKeyIdentifier;
        use openssl::x509::X509Builder;

        let mut temp_builder = wrap_err!(X509Builder::new(), "Failed to create X509 builder");
        wrap_err!(temp_builder.set_subject_name(ca_cert.subject_name()), "Failed to set subject name");
        let context = temp_builder.x509v3_context(Some(ca_cert), None);
        AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&context)
            .map_err(|e| ProcessError::ConfigError(format!("Failed to build AKI: {}", e)))
    }

    fn generate_empty_crl(
        ca_cert: &openssl::x509::X509,
        ca_pkey: &PKey<openssl::pkey::Private>,
    ) -> Result<Vec<u8>, ProcessError> {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::x509::extension::CrlNumber;
        use openssl::x509::X509CrlBuilder;

        let mut crl_builder = wrap_err!(X509CrlBuilder::new(), "Failed to create CRL builder");
        wrap_err!(crl_builder.set_issuer_name(ca_cert.subject_name()), "Failed to set issuer name");

        let not_before = wrap_err!(Asn1Time::days_from_now(0), "Failed to create time");
        let not_after = wrap_err!(Asn1Time::days_from_now(3650), "Failed to create time");
        wrap_err!(crl_builder.set_last_update(&not_before), "Failed to set last update");
        wrap_err!(crl_builder.set_next_update(&not_after), "Failed to set next update");

        let bn = wrap_err!(BigNum::from_u32(1), "Failed to create BN");
        let crl_number = wrap_err!(CrlNumber::new(bn), "Failed to create CRL number");
        let crl_number_ext = wrap_err!(crl_number.build(), "Failed to build CRL number");
        wrap_err!(crl_builder.append_extension(crl_number_ext), "Failed to append CRL number");

        let aki = Self::build_aki_extension(ca_cert)?;
        wrap_err!(crl_builder.append_extension(aki), "Failed to append AKI");

        wrap_err!(crl_builder.sign(ca_pkey, MessageDigest::sha256()), "Failed to sign CRL");
        let crl = wrap_err!(crl_builder.build(), "Failed to build CRL");
        crl.to_pem()
            .map_err(|e| ProcessError::ConfigError(format!("Failed to encode CRL: {}", e)))
    }

    /// 清理硬编码路径（测试环境清理）
    fn cleanup_hardcoded_cert_paths(&self) {
        for dir in &["/etc/cert/server", "/etc/cert/cms"] {
            if Path::new(dir).exists() {
                Command::new("sudo").args(["rm", "-rf", dir]).status().ok();
            }
        }
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

        let config_content = format!(
            r#"
[vsock]
port = {}

[log]
path = "{}"
max_file_size = 10
max_roll_count = 10"#,
            config.port,
            log_path.display(),
        );

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
