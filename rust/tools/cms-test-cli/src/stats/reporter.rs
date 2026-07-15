//! 统计报告生成器
//!
//! 提供各类测试结果的格式化输出功能，生成人类可读的测试报告。

use super::{ConcurrentResult, PerfResult, SecurityTestResult};

/// 统计报告生成器
///
/// 静态方法集合，用于格式化不同类型的测试结果为可读文本。
pub struct Reporter;

impl Reporter {
    /// 格式化性能测试报告
    ///
    /// # 参数
    /// - `result`: 性能测试结果
    ///
    /// # 返回
    /// 格式化的性能报告字符串，包含：
    /// - 总请求数、成功/失败数
    /// - 平均/最小/最大响应时间
    /// - 吞吐量（QPS）
    /// - 错误码分布（如有）
    pub fn format_perf_report(result: &PerfResult) -> String {
        // 格式化错误码分布
        let error_dist = if result.errors.is_empty() {
            String::new()
        } else {
            let mut lines = vec!["Error Distribution:".to_string()];
            for (code, count) in result.errors.iter() {
                lines.push(format!("  result={} => {} occurrences", code, count));
            }
            lines.join("\n")
        };

        format!(
            "Performance Report:\n\
             \x20  Total: {} requests\n\
             \x20  Success: {}\n\
             \x20  Failed: {}\n\
             \x20  Avg Response Time: {:.2}ms\n\
             \x20  Min Response Time: {:.2}ms\n\
             \x20  Max Response Time: {:.2}ms\n\
             \x20  P50 Response Time: {:.2}ms\n\
             \x20  P95 Response Time: {:.2}ms\n\
             \x20  P99 Response Time: {:.2}ms\n\
             \x20  Throughput: {:.2} QPS\n\
             {}",
            result.total,
            result.success,
            result.failed,
            result.avg_latency_ms,
            result.min_latency_ms,
            result.max_latency_ms,
            result.p50_latency_ms,
            result.p95_latency_ms,
            result.p99_latency_ms,
            result.throughput_qps,
            error_dist
        )
    }

    /// 格式化并发测试报告
    ///
    /// # 参数
    /// - `result`: 并发测试结果
    ///
    /// # 返回
    /// 格式化的并发测试报告字符串，包含：
    /// - 线程数、总请求数
    /// - 成功/失败数
    /// - 平均响应时间、吞吐量
    pub fn format_concurrent_report(result: &ConcurrentResult) -> String {
        format!(
            "Concurrent Test Report:\n\
             \x20  Threads: {}\n\
             \x20  Total Requests: {}\n\
             \x20  Success: {}\n\
             \x20  Failed: {}\n\
             \x20  Avg Response Time: {:.2}ms\n\
             \x20  Throughput: {:.2} QPS",
            result.threads,
            result.total_requests,
            result.success,
            result.failed,
            result.avg_latency_ms,
            result.throughput_qps
        )
    }

    /// 格式化安全测试报告
    ///
    /// # 参数
    /// - `results`: 安全测试结果数组
    ///
    /// # 返回
    /// 格式化的安全测试报告字符串，包含：
    /// - 通过/总数统计
    /// - 每个测试用例的预期行为和实际行为
    pub fn format_security_report(results: &[SecurityTestResult]) -> String {
        // 统计通过数量
        let passed = results.iter().filter(|r| r.passed).count();
        let total = results.len();

        let mut lines = vec![
            format!("Security Test Report: {} / {} passed", passed, total),
            String::new(),
        ];

        // 逐个输出测试用例结果
        for result in results {
            let status = if result.passed { "PASS" } else { "FAIL" };
            lines.push(format!("[{}] {}", status, result.test_name));
            lines.push(format!("  Expected: {}", result.expected_behavior));
            lines.push(format!("  Actual: {}", result.actual_behavior));
            lines.push(format!("  Details: {}", result.details));
            lines.push(String::new());
        }

        lines.join("\n")
    }

    /// 格式化JSON响应
    ///
    /// # 参数
    /// - `resp`: 可序列化的响应对象
    ///
    /// # 返回
    /// 格式化的JSON字符串，带缩进美化
    ///
    /// # 泛型
    /// - `T`: 实现 `serde::Serialize` 的类型
    pub fn format_response<T: serde::Serialize>(resp: &T) -> String {
        let json = serde_json::to_string_pretty(resp).unwrap();
        format!("Response:\n{}", json)
    }
}
