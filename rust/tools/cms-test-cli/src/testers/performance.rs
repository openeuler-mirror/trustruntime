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
use integration_tests::vsock_client::VsockClient;
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
}
