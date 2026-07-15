//! 统计模块
//!
//! 提供测试执行过程中的数据收集、聚合和报告生成功能。
//! 支持性能测试、并发测试和安全测试三种场景的统计。

mod reporter;

pub use reporter::Reporter;

use std::collections::HashMap;
use std::time::Instant;

/// 测试统计数据收集器
///
/// 在测试执行过程中收集延迟、成功/失败次数、错误码分布等指标，
/// 最终生成性能测试结果报告。
///
/// # 示例
/// ```
/// let mut collector = StatsCollector::new();
/// collector.record_success(12.5, 0);  // 记录成功请求，延迟12.5ms
/// collector.record_failure(5.0);      // 记录失败请求
/// let result = collector.finalize();   // 生成统计结果
/// ```
pub struct StatsCollector {
    /// 所有请求的延迟记录（毫秒）
    latencies: Vec<f64>,
    /// 成功请求计数
    successes: u32,
    /// 失败请求计数
    failures: u32,
    /// 错误码分布：错误码 -> 出现次数
    error_codes: HashMap<u32, u32>,
    /// 统计开始时间，用于计算吞吐量
    start_time: Instant,
}

impl StatsCollector {
    /// 创建新的统计收集器
    ///
    /// 初始化所有计数器为0，记录当前时间作为开始时间。
    pub fn new() -> Self {
        Self {
            latencies: Vec::new(),
            successes: 0,
            failures: 0,
            error_codes: HashMap::new(),
            start_time: Instant::now(),
        }
    }

    /// 记录一次成功请求
    ///
    /// # 参数
    /// - `latency_ms`: 请求延迟（毫秒）
    /// - `result_code`: 服务端返回的结果码（0表示成功，非0表示业务错误）
    ///
    /// # 说明
    /// 即使HTTP/TLS层面成功，如果业务逻辑返回非0结果码，仍计入成功次数，
    /// 但同时记录错误码分布用于分析业务错误。
    pub fn record_success(&mut self, latency_ms: f64, result_code: u32) {
        self.latencies.push(latency_ms);
        self.successes += 1;
        if result_code != 0 {
            *self.error_codes.entry(result_code).or_insert(0) += 1;
        }
    }

    /// 记录一次失败请求
    ///
    /// # 参数
    /// - `latency_ms`: 请求延迟（毫秒）
    ///
    /// # 说明
    /// 失败请求指网络错误、TLS握手失败、连接超时等底层错误。
    pub fn record_failure(&mut self, latency_ms: f64) {
        self.latencies.push(latency_ms);
        self.failures += 1;
    }

    /// 完成统计并生成结果
    ///
    /// # 返回
    /// 包含完整统计指标的 [`PerfResult`]：
    /// - 总请求数、成功数、失败数
    /// - 平均/最小/最大/P50/P95/P99 延迟
    /// - 吞吐量（QPS）
    /// - 错误码分布
    pub fn finalize(&self) -> PerfResult {
        // 计算平均延迟
        let avg = if self.latencies.is_empty() {
            0.0
        } else {
            self.latencies.iter().sum::<f64>() / self.latencies.len() as f64
        };

        // 计算最小/最大延迟
        let min = self
            .latencies
            .iter()
            .min_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(&0.0);
        let max = self
            .latencies
            .iter()
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(&0.0);

        // 计算分位数（P50/P95/P99）
        let mut sorted_latencies: Vec<f64> = self.latencies.clone();
        sorted_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p50 = percentile(&sorted_latencies, 50.0);
        let p95 = percentile(&sorted_latencies, 95.0);
        let p99 = percentile(&sorted_latencies, 99.0);

        // 计算吞吐量：总请求数 / 总耗时（秒）
        let total_time_s = self.start_time.elapsed().as_secs_f64();
        let throughput = if total_time_s > 0.0 {
            (self.successes + self.failures) as f64 / total_time_s
        } else {
            0.0
        };

        PerfResult {
            total: self.successes + self.failures,
            success: self.successes,
            failed: self.failures,
            avg_latency_ms: avg,
            min_latency_ms: *min,
            max_latency_ms: *max,
            p50_latency_ms: p50,
            p95_latency_ms: p95,
            p99_latency_ms: p99,
            throughput_qps: throughput,
            errors: self.error_codes.clone(),
        }
    }
}

impl Default for StatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 性能测试结果
///
/// 包含单次性能测试的完整统计指标。
#[derive(Clone)]
pub struct PerfResult {
    /// 总请求数（成功+失败）
    pub total: u32,
    /// 成功请求数
    pub success: u32,
    /// 失败请求数
    pub failed: u32,
    /// 平均响应延迟（毫秒）
    pub avg_latency_ms: f64,
    /// 最小响应延迟（毫秒）
    pub min_latency_ms: f64,
    /// 最大响应延迟（毫秒）
    pub max_latency_ms: f64,
    /// P50响应延迟（毫秒）- 中位数
    pub p50_latency_ms: f64,
    /// P95响应延迟（毫秒）- 95分位数
    pub p95_latency_ms: f64,
    /// P99响应延迟（毫秒）- 99分位数
    pub p99_latency_ms: f64,
    /// 吞吐量（请求/秒）
    pub throughput_qps: f64,
    /// 错误码分布：错误码 -> 出现次数
    pub errors: HashMap<u32, u32>,
}

/// 并发测试结果
///
/// 包含多线程并发测试的统计指标，每个线程独立创建连接执行测试。
#[derive(Clone)]
pub struct ConcurrentResult {
    /// 并发线程数
    pub threads: u32,
    /// 总请求数（所有线程合计）
    pub total_requests: u32,
    /// 成功请求数
    pub success: u32,
    /// 失败请求数
    pub failed: u32,
    /// 平均响应延迟（毫秒）
    pub avg_latency_ms: f64,
    /// 吞吐量（请求/秒）
    pub throughput_qps: f64,
}

/// 安全测试结果
///
/// 单个安全测试用例的执行结果，包含预期行为和实际行为的对比。
#[derive(Clone)]
pub struct SecurityTestResult {
    /// 测试用例名称
    pub test_name: String,
    /// 是否通过（实际行为符合预期）
    pub passed: bool,
    /// 预期行为描述
    pub expected_behavior: String,
    /// 实际行为描述
    pub actual_behavior: String,
    /// 详细信息（如错误消息、响应内容等）
    pub details: String,
}

/// 计算分位数
///
/// # 参数
/// - `sorted_data`: 已排序的数据切片
/// - `p`: 百分位（0.0 - 100.0）
///
/// # 返回
/// 对应分位数的值
///
/// # 算法
/// 使用最近邻方法，适用于性能测试场景
fn percentile(sorted_data: &[f64], p: f64) -> f64 {
    if sorted_data.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted_data.len() - 1) as f64).round() as usize;
    sorted_data[idx.min(sorted_data.len() - 1)]
}
