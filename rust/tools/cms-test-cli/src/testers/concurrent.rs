//! 并发测试器模块
//!
//! 提供多线程并发测试功能，用于验证系统在高并发场景下的表现。
//! 每个线程创建独立的连接，模拟多客户端并发访问。
//!
//! ## 测试指标
//!
//! - 并发线程数
//! - 总请求数
//! - 成功/失败数
//! - 平均延迟
//! - 吞吐量（QPS）

use crate::config::TlsClientConfig;
use crate::stats::{ConcurrentResult, StatsCollector};
use integration_tests::vsock_client::VsockClient;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

/// 并发测试器
///
/// 创建多个线程并发执行签名或验证操作，
/// 用于测试系统在高并发负载下的性能和稳定性。
pub struct ConcurrentTester {
    tls_config: TlsClientConfig,
    port: u32,
}

impl ConcurrentTester {
    /// 创建新的并发测试器
    ///
    /// # 参数
    ///
    /// * `tls_config` - TLS 客户端证书配置
    /// * `port` - vsock 服务端口
    pub fn new(tls_config: TlsClientConfig, port: u32) -> Self {
        Self { tls_config, port }
    }

    /// 读取私钥密码（如果配置了密码文件）
    fn read_key_password(&self) -> Option<String> {
        self.tls_config
            .client_key_pwd
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.trim().to_string())
    }

    /// 运行并发签名测试
    ///
    /// 创建多个线程并发执行签名操作，统计成功率和性能指标。
    ///
    /// # 参数
    ///
    /// * `threads` - 并发线程数
    /// * `count` - 每个线程执行的请求数
    /// * `data` - 待签名的数据
    ///
    /// # 返回
    ///
    /// 返回并发测试结果，包含成功数、失败数、延迟和吞吐量
    pub fn run_sign_test(&self, threads: u32, count: u32, data: &str) -> ConcurrentResult {
        let stats = Arc::new(Mutex::new(StatsCollector::new()));
        let mut handles = vec![];

        let total_requests = threads * count;

        for _ in 0..threads {
            let stats_clone = stats.clone();
            let data_clone = data.to_string();
            let port = self.port;
            let tls_ca = self.tls_config.ca_cert.clone();
            let tls_client_cert = self.tls_config.client_cert.clone();
            let tls_client_key = self.tls_config.client_key.clone();
            let requests = count;
            let key_password = self.read_key_password();

            let handle = thread::spawn(move || {
                let mut client = VsockClient::connect(
                    port,
                    &tls_ca,
                    &tls_client_cert,
                    &tls_client_key,
                    key_password.as_deref(),
                )
                .expect("Failed to connect");

                for _ in 0..requests {
                    let start = Instant::now();
                    let result = client.sign(&data_clone);
                    let latency = start.elapsed().as_millis() as f64;

                    match result {
                        Ok(resp) => stats_clone
                            .lock()
                            .unwrap()
                            .record_success(latency, resp.result),
                        Err(_) => stats_clone.lock().unwrap().record_failure(latency),
                    }
                }

                client.close().expect("Failed to close");
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        let finalized = stats.lock().unwrap().finalize();
        ConcurrentResult {
            threads,
            total_requests,
            success: finalized.success,
            failed: finalized.failed,
            avg_latency_ms: finalized.avg_latency_ms,
            throughput_qps: finalized.throughput_qps,
        }
    }

    /// 运行并发验证测试
    ///
    /// 创建多个线程并发执行验证操作，统计成功率和性能指标。
    ///
    /// # 参数
    ///
    /// * `threads` - 并发线程数
    /// * `count` - 每个线程执行的请求数
    /// * `data` - 原始数据
    /// * `signed_data` - 签名后的数据
    /// * `id` - 签名者标识
    ///
    /// # 返回
    ///
    /// 返回并发测试结果，包含成功数、失败数、延迟和吞吐量
    pub fn run_verify_test(
        &self,
        threads: u32,
        count: u32,
        data: &str,
        signed_data: &str,
        id: &str,
    ) -> ConcurrentResult {
        let stats = Arc::new(Mutex::new(StatsCollector::new()));
        let mut handles = vec![];

        let total_requests = threads * count;

        for _ in 0..threads {
            let stats_clone = stats.clone();
            let data_clone = data.to_string();
            let signed_data_clone = signed_data.to_string();
            let id_clone = id.to_string();
            let port = self.port;
            let tls_ca = self.tls_config.ca_cert.clone();
            let tls_client_cert = self.tls_config.client_cert.clone();
            let tls_client_key = self.tls_config.client_key.clone();
            let requests = count;
            let key_password = self.read_key_password();

            let handle = thread::spawn(move || {
                let mut client = VsockClient::connect(
                    port,
                    &tls_ca,
                    &tls_client_cert,
                    &tls_client_key,
                    key_password.as_deref(),
                )
                .expect("Failed to connect");

                for _ in 0..requests {
                    let start = Instant::now();
                    let result = client.verify(&data_clone, &signed_data_clone, &id_clone);
                    let latency = start.elapsed().as_millis() as f64;

                    match result {
                        Ok(resp) => stats_clone
                            .lock()
                            .unwrap()
                            .record_success(latency, resp.result),
                        Err(_) => stats_clone.lock().unwrap().record_failure(latency),
                    }
                }

                client.close().expect("Failed to close");
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        let finalized = stats.lock().unwrap().finalize();
        ConcurrentResult {
            threads,
            total_requests,
            success: finalized.success,
            failed: finalized.failed,
            avg_latency_ms: finalized.avg_latency_ms,
            throughput_qps: finalized.throughput_qps,
        }
    }
}
