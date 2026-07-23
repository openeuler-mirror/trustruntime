//! 证书状态检测器模块
//!
//! 职责：
//! - 定时检查证书状态（过期检测、未生效检测、加载状态）
//! - 提供证书状态查询接口
//! - 异步后台任务定期检查
//!
//! 与cert模块关系：
//! - 依赖cert模块的load_x509、is_expired、is_not_yet_valid函数
//! - cert模块负责证书加载和时间判断底层逻辑
//! - 本模块负责调度检查和状态管理
//!
//! 检查机制：
//! - 默认检查间隔：86400秒（24小时）
//! - 检查内容：证书not_after过期时间、证书not_before生效时间、证书加载状态
//! - 检测结果：expired字段标识过期状态，not_yet_valid字段标识未生效状态

use crate::cert;
use std::time::Duration;
use tokio::task::JoinHandle;

/// 证书过期检测器
///
/// 定时检查证书状态，监控证书过期和加载失败情况。
///
/// 架构决策：使用tokio异步任务进行后台定时检查
/// 原因：
/// - 不阻塞主线程，适合长时间运行的服务
/// - 与vsock_server的异步架构一致
/// - 支持优雅停止（通过JoinHandle）
pub struct CertificateChecker {
    /// 待检查的证书文件路径列表
    cert_paths: Vec<String>,
    /// 检查间隔时间
    interval: Duration,
}

impl CertificateChecker {
    /// 创建证书检测器实例
    ///
    /// 使用默认检查间隔（86400秒，即24小时）
    ///
    /// # Arguments
    /// * `cert_paths` - 待检查的证书文件路径列表
    ///
    /// # Returns
    /// * `CertificateChecker` - 检测器实例
    pub fn new(cert_paths: Vec<String>) -> Self {
        Self {
            cert_paths,
            interval: Duration::from_secs(86400),
        }
    }

    /// 设置自定义检查间隔
    ///
    /// 使用Builder模式设置检查间隔
    ///
    /// # Arguments
    /// * `interval` - 检查间隔时间
    ///
    /// # Returns
    /// * `Self` - 检测器实例（支持链式调用）
    ///
    /// # Example
    /// ```text
    /// let checker = CertificateChecker::new(paths)
    ///     .with_interval(Duration::from_secs(3600));
    /// ```
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// 检查所有证书状态
    ///
    /// 遍历证书路径列表，逐个检查证书状态
    ///
    /// # Returns
    /// * `Vec<CertificateStatus>` - 所有证书的状态列表
    ///
    /// # 检查逻辑
    /// 1. 加载证书文件
    /// 2. 提取not_before生效时间
    /// 3. 提取not_after过期时间
    /// 4. 判断是否未生效（当前时间 < not_before）
    /// 5. 判断是否过期（当前时间 > not_after）
    /// 6. 返回状态（成功加载/加载失败）
    pub fn check_all(&self) -> Vec<CertificateStatus> {
        self.cert_paths
            .iter()
            .map(|path| self.check_one(path))
            .collect()
    }

    /// 检查单个证书状态
    ///
    /// 证书状态检测算法：
    /// 1. 使用cert::load_x509加载证书
    /// 2. 提取not_before字段（证书生效时间）
    /// 3. 提取not_after字段（证书过期时间）
    /// 4. 调用cert::is_expired判断是否过期
    /// 5. 调用cert::is_not_yet_valid判断是否未生效
    /// 6. is_expired内部比较：当前系统时间 > not_after则为过期
    /// 7. is_not_yet_valid内部比较：当前系统时间 < not_before则为未生效
    ///
    /// 状态判断：
    /// - 加载成功：expired/not_yet_valid标识状态，not_after/not_before包含时间
    /// - 加载失败：expired=false，not_yet_valid=false，not_after=None，not_before=None
    fn check_one(&self, path: &str) -> CertificateStatus {
        match cert::load_x509(path) {
            Ok(x509) => {
                // 过期检测：比较当前时间与证书not_after时间
                let expired = cert::is_expired(&x509);
                let not_after = x509.not_after().to_string();
                if expired {
                    log::warn!("Certificate has expired");
                }

                // 未生效检测：比较当前时间与证书not_before时间
                let not_yet_valid = cert::is_not_yet_valid(&x509);
                let not_before = x509.not_before().to_string();
                if not_yet_valid {
                    log::warn!("Certificate is not yet valid");
                }

                CertificateStatus {
                    path: path.to_string(),
                    expired,
                    not_yet_valid,
                    not_after: Some(not_after),
                    not_before: Some(not_before),
                }
            }
            Err(_e) => {
                log::warn!("Certificate load failed");
                CertificateStatus {
                    path: path.to_string(),
                    expired: false,
                    not_yet_valid: false,
                    not_after: None,
                    not_before: None,
                }
            }
        }
    }

    /// 启动定时检查任务
    ///
    /// 创建tokio异步任务，定期检查所有证书状态
    ///
    /// # Returns
    /// * `JoinHandle<()>` - 异步任务句柄，可用于停止任务
    ///
    /// # 异步机制
    /// - tokio::spawn创建后台任务
    /// - tokio::time::sleep实现定时等待
    /// - 循环执行检查，直到任务被中止
    ///
    /// # 使用方式
    /// ```text
    /// let handle = checker.start_periodic_check();
    /// // 需要停止时调用：
    /// handle.abort();
    /// ```
    ///
    /// # 注意
    /// - 检查结果通过日志输出（log::warn）
    /// - 调用者需妥善保管JoinHandle以便后续停止任务
    pub fn start_periodic_check(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                // 执行一次全量检查
                self.check_all();
                // 等待指定间隔后继续下一轮检查
                tokio::time::sleep(self.interval).await;
            }
        })
    }
}

/// 证书状态
///
/// 单个证书的检查结果，包含路径、过期状态、未生效状态和时间信息
#[derive(Debug)]
pub struct CertificateStatus {
    /// 证书文件路径
    pub path: String,
    /// 过期标志
    /// - true: 证书已过期（当前时间 > not_after）
    /// - false: 证书未过期或加载失败
    pub expired: bool,
    /// 未生效标志
    /// - true: 证书尚未生效（当前时间 < not_before）
    /// - false: 证书已生效或加载失败
    pub not_yet_valid: bool,
    /// 证书过期时间（not_after字段）
    /// - Some(time): 加载成功，包含过期时间字符串
    /// - None: 加载失败（文件不存在、格式错误等）
    pub not_after: Option<String>,
    /// 证书生效时间（not_before字段）
    /// - Some(time): 加载成功，包含生效时间字符串
    /// - None: 加载失败（文件不存在、格式错误等）
    pub not_before: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509Builder, X509NameBuilder};
    use std::fs;

    /// 创建过期证书（用于测试）
    ///
    /// 生成一个ECC-256证书，not_after设置为过去时间（2001-09-09）
    fn create_expired_certificate() -> Vec<u8> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "Expired Cert")
            .unwrap();
        let name = name_builder.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::from_unix(1000000000).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        let serial = BigNum::from_u32(1).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        cert.to_pem().unwrap()
    }

    /// 创建有效证书（用于测试）
    ///
    /// 生成一个ECC-256证书，not_after设置为未来时间（365天后）
    fn create_valid_certificate() -> Vec<u8> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "Valid Cert")
            .unwrap();
        let name = name_builder.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        let serial = BigNum::from_u32(1).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        cert.to_pem().unwrap()
    }

    /// 创建尚未生效证书（用于测试）
    ///
    /// 生成一个ECC-256证书，not_before设置为未来时间（365天后）
    fn create_not_yet_valid_certificate() -> Vec<u8> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "Not Yet Valid Cert")
            .unwrap();
        let name = name_builder.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();

        let not_before = Asn1Time::days_from_now(365).unwrap();
        let not_after = Asn1Time::days_from_now(3650).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        let serial = BigNum::from_u32(2).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        cert.to_pem().unwrap()
    }

    #[test]
    fn certificate_checker_detects_expired_certificate() {
        // 场景：检测过期证书
        // 预期：expired=true, not_yet_valid=false, not_after=Some, not_before=Some

        let temp_dir = std::env::temp_dir().join("cert_checker_expired_test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let expired_pem = create_expired_certificate();
        let cert_path = temp_dir.join("expired.crt");
        fs::write(&cert_path, &expired_pem).unwrap();

        let checker = CertificateChecker::new(vec![cert_path.to_str().unwrap().to_string()]);
        let statuses = checker.check_all();

        assert_eq!(statuses.len(), 1);
        assert!(statuses[0].expired);
        assert!(!statuses[0].not_yet_valid);
        assert!(statuses[0].not_after.is_some());
        assert!(statuses[0].not_before.is_some());

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn certificate_checker_detects_valid_certificate() {
        // 场景：检测有效证书
        // 预期：expired=false, not_yet_valid=false, not_after=Some, not_before=Some

        let temp_dir = std::env::temp_dir().join("cert_checker_valid_test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let valid_pem = create_valid_certificate();
        let cert_path = temp_dir.join("valid.crt");
        fs::write(&cert_path, &valid_pem).unwrap();

        let checker = CertificateChecker::new(vec![cert_path.to_str().unwrap().to_string()]);
        let statuses = checker.check_all();

        assert_eq!(statuses.len(), 1);
        assert!(!statuses[0].expired);
        assert!(!statuses[0].not_yet_valid);
        assert!(statuses[0].not_after.is_some());
        assert!(statuses[0].not_before.is_some());

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn certificate_checker_detects_not_yet_valid_certificate() {
        // 场景：检测尚未生效证书
        // 预期：expired=false, not_yet_valid=true, not_after=Some, not_before=Some

        let temp_dir = std::env::temp_dir().join("cert_checker_not_yet_valid_test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let not_yet_valid_pem = create_not_yet_valid_certificate();
        let cert_path = temp_dir.join("not_yet_valid.crt");
        fs::write(&cert_path, &not_yet_valid_pem).unwrap();

        let checker = CertificateChecker::new(vec![cert_path.to_str().unwrap().to_string()]);
        let statuses = checker.check_all();

        assert_eq!(statuses.len(), 1);
        assert!(!statuses[0].expired);
        assert!(statuses[0].not_yet_valid);
        assert!(statuses[0].not_after.is_some());
        assert!(statuses[0].not_before.is_some());

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn certificate_checker_handles_missing_file() {
        // 场景：检测不存在的证书文件
        // 预期：expired=false, not_yet_valid=false, not_after=None, not_before=None（加载失败）

        let checker =
            CertificateChecker::new(vec!["/tmp/cert_checker_nonexistent.crt".to_string()]);
        let statuses = checker.check_all();

        assert_eq!(statuses.len(), 1);
        assert!(!statuses[0].expired);
        assert!(!statuses[0].not_yet_valid);
        assert!(statuses[0].not_after.is_none());
        assert!(statuses[0].not_before.is_none());
    }

    #[tokio::test]
    async fn periodic_check_runs_multiple_times() {
        // 场景：定时检查任务运行多次
        // 预期：任务能正常启动和停止
        // 注意：此测试验证异步任务机制，不验证检查结果

        let temp_dir = std::env::temp_dir().join("cert_checker_periodic_test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let expired_pem = create_expired_certificate();
        let cert_path = temp_dir.join("expired.crt");
        fs::write(&cert_path, &expired_pem).unwrap();

        let checker = CertificateChecker::new(vec![cert_path.to_str().unwrap().to_string()])
            .with_interval(Duration::from_millis(100));

        let handle = checker.start_periodic_check();

        tokio::time::sleep(Duration::from_millis(350)).await;
        handle.abort();

        fs::remove_dir_all(&temp_dir).unwrap();
    }
}
