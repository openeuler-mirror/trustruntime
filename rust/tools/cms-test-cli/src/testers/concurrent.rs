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
use integration_tests::vsock_client::{ToSignWithId, ToVerify, VerifySignRequest, VsockClient};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// 并发测试器
///
/// 创建多个线程并发执行签名或验证操作，
/// 用于测试系统在高并发负载下的性能和稳定性。
pub struct ConcurrentTester {
    tls_config: TlsClientConfig,
    port: u32,
    cid: u32,
}

impl ConcurrentTester {
    /// 创建新的并发测试器
    ///
    /// # 参数
    ///
    /// * `tls_config` - TLS 客户端证书配置
    /// * `port` - vsock 服务端口
    /// * `cid` - vsock CID
    pub fn new(tls_config: TlsClientConfig, port: u32, cid: u32) -> Self {
        Self {
            tls_config,
            port,
            cid,
        }
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
    /// * `interval` - 请求间隔（毫秒），None表示无间隔
    ///
    /// # 返回
    ///
    /// 返回并发测试结果，包含成功数、失败数、延迟和吞吐量
    pub fn run_sign_test(
        &self,
        threads: u32,
        count: u32,
        data: &str,
        interval: Option<u32>,
    ) -> ConcurrentResult {
        let stats = Arc::new(Mutex::new(StatsCollector::new()));
        let mut handles = vec![];

        let total_requests = threads * count;

        for _ in 0..threads {
            let stats_clone = stats.clone();
            let data_clone = data.to_string();
            let interval_clone = interval;
            let port = self.port;
            let cid = self.cid;
            let tls_ca = self.tls_config.ca_cert.clone();
            let tls_client_cert = self.tls_config.client_cert.clone();
            let tls_client_key = self.tls_config.client_key.clone();
            let requests = count;
            let key_password = self.read_key_password();

            let handle = thread::spawn(move || {
                let mut client = VsockClient::connect(
                    cid,
                    port,
                    &tls_ca,
                    &tls_client_cert,
                    &tls_client_key,
                    key_password.as_deref(),
                )
                .expect("Failed to connect");

                for _ in 0..requests {
                    if let Some(ms) = interval_clone {
                        thread::sleep(Duration::from_millis(ms as u64));
                    }

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
    /// * `interval` - 请求间隔（毫秒），None表示无间隔
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
        interval: Option<u32>,
    ) -> ConcurrentResult {
        let stats = Arc::new(Mutex::new(StatsCollector::new()));
        let mut handles = vec![];

        let total_requests = threads * count;

        for _ in 0..threads {
            let stats_clone = stats.clone();
            let data_clone = data.to_string();
            let signed_data_clone = signed_data.to_string();
            let id_clone = id.to_string();
            let interval_clone = interval;
            let port = self.port;
            let cid = self.cid;
            let tls_ca = self.tls_config.ca_cert.clone();
            let tls_client_cert = self.tls_config.client_cert.clone();
            let tls_client_key = self.tls_config.client_key.clone();
            let requests = count;
            let key_password = self.read_key_password();

            let handle = thread::spawn(move || {
                let mut client = VsockClient::connect(
                    cid,
                    port,
                    &tls_ca,
                    &tls_client_cert,
                    &tls_client_key,
                    key_password.as_deref(),
                )
                .expect("Failed to connect");

                for _ in 0..requests {
                    if let Some(ms) = interval_clone {
                        thread::sleep(Duration::from_millis(ms as u64));
                    }

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

    /// 运行并发验签+签名测试
    ///
    /// 创建多个线程并发执行验签+签名操作，统计成功率和性能指标。
    /// 支持简化模式和完整模式。
    ///
    /// # 参数
    ///
    /// * `threads` - 并发线程数
    /// * `count` - 每个线程执行的请求数
    /// * `sign_data` - 待签名的新数据
    /// * `sign_id` - 签名使用的证书ID（None则使用自动获取的id）
    /// * `verify_data` - 待验证的原始数据（None则使用sign_data）
    /// * `signed_data` - 签名数据（None则自动调用sign获取）
    /// * `verify_id` - 验签证书ID（None则使用sign_id）
    ///
    /// # 返回
    ///
    /// 返回并发测试结果，包含成功数、失败数、延迟和吞吐量
    ///
    /// # 自动获取逻辑
    ///
    /// 在主线程中调用一次 sign 获取 signed_data 和 id，
    /// 然后分发给各工作线程使用。
    #[allow(clippy::too_many_arguments)]
    pub fn run_verify_sign_test(
        &self,
        threads: u32,
        count: u32,
        sign_data: &str,
        sign_id: Option<&str>,
        verify_data: Option<&str>,
        signed_data: Option<&str>,
        verify_id: Option<&str>,
        interval: Option<u32>,
    ) -> ConcurrentResult {
        let stats = Arc::new(Mutex::new(StatsCollector::new()));
        let mut handles = vec![];

        let total_requests = threads * count;

        let params = match self.prepare_verify_sign_params(
            sign_data,
            sign_id,
            verify_data,
            signed_data,
            verify_id,
        ) {
            Some(p) => p,
            None => {
                return ConcurrentResult {
                    threads,
                    total_requests: 0,
                    success: 0,
                    failed: 0,
                    avg_latency_ms: 0.0,
                    throughput_qps: 0.0,
                }
            }
        };

        for _ in 0..threads {
            let stats_clone = stats.clone();
            let sign_data_clone = sign_data.to_string();
            let verify_data_clone = params.verify_data.clone();
            let signed_data_clone = params.signed_data.clone();
            let verify_id_clone = params.verify_id.clone();
            let sign_id_clone = params.sign_id.clone();
            let interval_clone = interval;
            let port = self.port;
            let cid = self.cid;
            let tls_ca = self.tls_config.ca_cert.clone();
            let tls_client_cert = self.tls_config.client_cert.clone();
            let tls_client_key = self.tls_config.client_key.clone();
            let requests = count;
            let key_password = self.read_key_password();

            let handle = thread::spawn(move || {
                let mut client = VsockClient::connect(
                    cid,
                    port,
                    &tls_ca,
                    &tls_client_cert,
                    &tls_client_key,
                    key_password.as_deref(),
                )
                .expect("Failed to connect");

                for _ in 0..requests {
                    if let Some(ms) = interval_clone {
                        thread::sleep(Duration::from_millis(ms as u64));
                    }

                    let request = VerifySignRequest {
                        to_verify: ToVerify {
                            data: verify_data_clone.clone(),
                            signed_data: signed_data_clone.clone(),
                            id: verify_id_clone.clone(),
                        },
                        to_sign: ToSignWithId {
                            data: sign_data_clone.clone(),
                            id: sign_id_clone.clone(),
                        },
                    };

                    let start = Instant::now();
                    let result = client.verify_and_sign(request);
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

    /// 准备验签+签名测试参数
    ///
    /// 处理简化模式和完整模式的参数解析，自动获取签名数据（如需要）。
    fn prepare_verify_sign_params(
        &self,
        sign_data: &str,
        sign_id: Option<&str>,
        verify_data: Option<&str>,
        signed_data: Option<&str>,
        verify_id: Option<&str>,
    ) -> Option<VerifySignParams> {
        let verify_data = verify_data.unwrap_or(sign_data);
        let sign_id = sign_id.map(|s| s.to_string());

        let (signed_data, id) = match signed_data {
            Some(s) => {
                let id = verify_id
                    .map(|s| s.to_string())
                    .or_else(|| sign_id.clone())
                    .expect("verify-id or sign-id required when signed-data is provided");
                (s.to_string(), id)
            }
            None => {
                println!("Auto-fetching signature for verify-sign test...");
                let mut client = VsockClient::connect(
                    self.cid,
                    self.port,
                    &self.tls_config.ca_cert,
                    &self.tls_config.client_cert,
                    &self.tls_config.client_key,
                    self.read_key_password().as_deref(),
                )
                .expect("Failed to connect for auto-fetch");

                let result = client.sign(verify_data);
                client.close().expect("Failed to close");

                match result {
                    Ok(resp) => {
                        println!(
                            "Auto-fetched signature (id: {}...)",
                            &resp.id[..20.min(resp.id.len())]
                        );
                        (resp.signed_data, resp.id)
                    }
                    Err(e) => {
                        println!("Failed to auto-fetch signature: {}", e);
                        return None;
                    }
                }
            }
        };

        let verify_id = verify_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| id.clone());
        let sign_id = sign_id.unwrap_or_else(|| id.clone());

        Some(VerifySignParams {
            verify_data: verify_data.to_string(),
            signed_data,
            verify_id,
            sign_id,
        })
    }
}

/// 验签+签名测试参数
struct VerifySignParams {
    verify_data: String,
    signed_data: String,
    verify_id: String,
    sign_id: String,
}
