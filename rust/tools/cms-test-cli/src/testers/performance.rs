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

//! 性能测试器模块
//!
//! 提供单线程性能测试功能，测量签名和验证操作的吞吐量和延迟。
//! 支持配置请求间隔，用于模拟不同负载模式。
//!
//! ## 测试指标
//!
//! - 请求总数
//! - 成功/失败数
//! - 平均延迟（毫秒）
//! - 吞吐量（QPS）
//! - P50/P95/P99 延迟分位数

use crate::stats::{PerfResult, StatsCollector};
use integration_tests::vsock_client::{ToSignWithId, ToVerify, VerifySignRequest, VsockClient};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::time::Instant;

/// 性能测试器
///
/// 执行单线程性能测试，记录每次操作的延迟和结果，
/// 计算吞吐量和延迟分位数等性能指标。
pub struct PerformanceTester {
    /// 共享的vsock客户端实例
    client: Arc<Mutex<VsockClient>>,
}

impl PerformanceTester {
    /// 创建新的性能测试器
    ///
    /// # 参数
    ///
    /// * `client` - 共享的vsock客户端实例
    pub fn new(client: Arc<Mutex<VsockClient>>) -> Self {
        Self { client }
    }

    /// 运行签名性能测试
    ///
    /// 执行指定次数的签名操作，统计延迟和吞吐量。
    /// 支持配置请求间隔，用于模拟稳定负载或突发负载。
    ///
    /// # 参数
    ///
    /// * `count` - 测试请求总数
    /// * `data` - 待签名的数据
    /// * `interval` - 请求间隔（毫秒），None表示无间隔
    ///
    /// # 返回
    ///
    /// 返回性能测试结果，包含延迟分位数和吞吐量
    ///
    /// # 测试场景
    ///
    /// - N01: 正常签名性能基线测试
    /// - B06: 大数据量签名性能测试
    /// - B07: 高频签名吞吐量测试
    pub fn run_sign_test(&self, count: u32, data: &str, interval: Option<u32>) -> PerfResult {
        let mut stats = StatsCollector::new();

        for i in 0..count {
            // 如果配置了请求间隔，则等待
            if let Some(ms) = interval {
                thread::sleep(Duration::from_millis(ms as u64));
            }

            // 记录操作延迟
            let start = Instant::now();
            let result = self.client.lock().unwrap().sign(data);
            let latency = start.elapsed().as_millis() as f64;

            // 统计结果
            match result {
                Ok(resp) => stats.record_success(latency, resp.result),
                Err(_) => stats.record_failure(latency),
            }

            // 显示进度条
            if count > 10 && i % (count / 10 + 1) == 0 {
                print!(
                    "\rProgress: {}/{} [{}{}] {:.0}%  ",
                    i + 1,
                    count,
                    "=".repeat((i * 20 / count) as usize),
                    " ".repeat(20 - (i * 20 / count) as usize),
                    ((i + 1) * 100 / count)
                );
            }
        }

        // 完成100%
        println!(
            "\rProgress: {}/{} [====================] 100%  ",
            count, count
        );

        stats.finalize()
    }

    /// 运行验证性能测试
    ///
    /// 执行指定次数的验证操作，统计延迟和吞吐量。
    /// 支持配置请求间隔，用于模拟稳定负载或突发负载。
    ///
    /// # 参数
    ///
    /// * `count` - 测试请求总数
    /// * `data` - 原始数据
    /// * `signed_data` - 签名后的数据
    /// * `id` - 签名者标识
    /// * `interval` - 请求间隔（毫秒），None表示无间隔
    ///
    /// # 返回
    ///
    /// 返回性能测试结果，包含延迟分位数和吞吐量
    ///
    /// # 测试场景
    ///
    /// - N02: 正常验证性能基线测试
    /// - B06: 大数据量验证性能测试
    /// - B07: 高频验证吞吐量测试
    pub fn run_verify_test(
        &self,
        count: u32,
        data: &str,
        signed_data: &str,
        id: &str,
        interval: Option<u32>,
    ) -> PerfResult {
        let mut stats = StatsCollector::new();

        for i in 0..count {
            // 如果配置了请求间隔，则等待
            if let Some(ms) = interval {
                thread::sleep(Duration::from_millis(ms as u64));
            }

            // 记录操作延迟
            let start = Instant::now();
            let result = self.client.lock().unwrap().verify(data, signed_data, id);
            let latency = start.elapsed().as_millis() as f64;

            // 统计结果
            match result {
                Ok(resp) => stats.record_success(latency, resp.result),
                Err(_) => stats.record_failure(latency),
            }

            // 显示进度条
            if count > 10 && i % (count / 10 + 1) == 0 {
                print!(
                    "\rProgress: {}/{} [{}{}] {:.0}%  ",
                    i + 1,
                    count,
                    "=".repeat((i * 20 / count) as usize),
                    " ".repeat(20 - (i * 20 / count) as usize),
                    ((i + 1) * 100 / count)
                );
            }
        }

        // 完成100%
        println!(
            "\rProgress: {}/{} [====================] 100%  ",
            count, count
        );

        stats.finalize()
    }

    /// 运行验签+签名性能测试
    ///
    /// 执行指定次数的验签+签名操作，统计延迟和吞吐量。
    /// 支持简化模式和完整模式。
    ///
    /// # 参数
    ///
    /// * `count` - 测试请求总数
    /// * `sign_data` - 待签名的新数据
    /// * `sign_id` - 签名使用的证书ID（None则使用自动获取的id）
    /// * `verify_data` - 待验证的原始数据（None则使用sign_data）
    /// * `signed_data` - 签名数据（None则自动调用sign获取）
    /// * `verify_id` - 验签证书ID（None则使用sign_id）
    /// * `interval` - 请求间隔（毫秒），None表示无间隔
    ///
    /// # 返回
    ///
    /// 返回性能测试结果，包含延迟分位数和吞吐量
    ///
    /// # 自动获取逻辑
    ///
    /// 如果 signed_data 为 None，则：
    /// 1. 调用 sign(verify_data) 获取 signed_data 和 id
    /// 2. 设置 verify_id = sign_id = 返回的 id
    #[allow(clippy::too_many_arguments)]
    pub fn run_verify_sign_test(
        &self,
        count: u32,
        sign_data: &str,
        sign_id: Option<&str>,
        verify_data: Option<&str>,
        signed_data: Option<&str>,
        verify_id: Option<&str>,
        interval: Option<u32>,
    ) -> PerfResult {
        let mut stats = StatsCollector::new();

        let params = match self.prepare_verify_sign_params(
            sign_data,
            sign_id,
            verify_data,
            signed_data,
            verify_id,
        ) {
            Some(p) => p,
            None => return stats.finalize(),
        };

        for i in 0..count {
            if let Some(ms) = interval {
                thread::sleep(Duration::from_millis(ms as u64));
            }

            let request = VerifySignRequest {
                to_verify: ToVerify {
                    data: params.verify_data.clone(),
                    signed_data: params.signed_data.clone(),
                    id: params.verify_id.clone(),
                },
                to_sign: ToSignWithId {
                    data: sign_data.to_string(),
                    id: params.sign_id.clone(),
                },
            };

            let start = Instant::now();
            let result = self.client.lock().unwrap().verify_and_sign(request);
            let latency = start.elapsed().as_millis() as f64;

            match result {
                Ok(resp) => stats.record_success(latency, resp.result),
                Err(_) => stats.record_failure(latency),
            }

            self.print_progress(i, count);
        }

        println!(
            "\rProgress: {}/{} [====================] 100%  ",
            count, count
        );

        stats.finalize()
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
                let result = self.client.lock().unwrap().sign(verify_data);
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

    /// 打印进度条
    fn print_progress(&self, current: u32, total: u32) {
        if total > 10 && current % (total / 10 + 1) == 0 {
            print!(
                "\rProgress: {}/{} [{}{}] {:.0}%  ",
                current + 1,
                total,
                "=".repeat((current * 20 / total) as usize),
                " ".repeat(20 - (current * 20 / total) as usize),
                ((current + 1) * 100 / total)
            );
        }
    }
}

/// 验签+签名测试参数
struct VerifySignParams {
    verify_data: String,
    signed_data: String,
    verify_id: String,
    sign_id: String,
}
