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

//! 命令解析模块
//!
//! 将用户输入字符串解析为 Command 枚举，支持：
//! - 引号包裹的参数（单引号或双引号）
//! - 长选项参数（如 --count、--threads）
//! - 命令缩写和别名

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("unknown command: {0}")]
    UnknownCommand(String),
    #[error("missing argument: {0}")]
    MissingArgument(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("parse error: {0}")]
    Other(String),
}

#[derive(Debug)]
pub enum Command {
    Connect {
        port: Option<u32>,
    },
    Disconnect,
    Status,

    // 核心操作
    /// 签名：sign <json>
    Sign {
        request: integration_tests::vsock_client::SignRequest,
    },
    /// 验签：verify <json>
    Verify {
        request: integration_tests::vsock_client::VerifyRequest,
    },
    /// 验签+签名：verify-sign <json>
    VerifySign {
        request: integration_tests::vsock_client::VerifySignRequest,
    },
    /// 原始请求：raw <type> <json_body>
    Raw {
        msg_type: u32,
        body: String,
    },

    // 性能测试
    /// 性能签名测试：perf sign --count <n> [--data <text>] [--interval <ms>]
    PerfSign {
        count: u32,
        data: Option<String>,
        interval: Option<u32>,
    },
    /// 性能验签测试：perf verify --count <n> --data <text> --signed-data <b64> --id <b64> [--interval <ms>]
    PerfVerify {
        count: u32,
        data: String,
        signed_data: String,
        id: String,
        interval: Option<u32>,
    },
    /// 性能验签+签名测试：perf verify-sign --count <n> --sign-data <text> [其他可选参数]
    PerfVerifySign {
        count: u32,
        sign_data: String,
        sign_id: Option<String>,
        verify_data: Option<String>,
        signed_data: Option<String>,
        verify_id: Option<String>,
        interval: Option<u32>,
    },
    /// 显示性能报告
    PerfReport,

    // 并发测试
    /// 并发签名测试：concurrent sign --threads <n> --count <n> [--data <text>] [--interval <ms>]
    ConcurrentSign {
        threads: u32,
        count: u32,
        data: Option<String>,
        interval: Option<u32>,
    },
    /// 并发验签测试：concurrent verify --threads <n> --count <n> --data <text> --signed-data <b64> --id <b64> [--interval <ms>]
    ConcurrentVerify {
        threads: u32,
        count: u32,
        data: String,
        signed_data: String,
        id: String,
        interval: Option<u32>,
    },
    /// 并发验签+签名测试：concurrent verify-sign --threads <n> --count <n> --sign-data <text> [其他可选参数]
    ConcurrentVerifySign {
        threads: u32,
        count: u32,
        sign_data: String,
        sign_id: Option<String>,
        verify_data: Option<String>,
        signed_data: Option<String>,
        verify_id: Option<String>,
        interval: Option<u32>,
    },
    /// 显示并发报告
    ConcurrentReport,

    // 安全测试
    /// 协议层安全测试：security protocol [test]
    #[allow(dead_code)]
    SecurityProtocol {
        test: Option<String>,
    },
    /// 证书层安全测试：security cert [test]
    #[allow(dead_code)]
    SecurityCert {
        test: Option<String>,
    },
    /// TLS 层安全测试：security tls [test]
    #[allow(dead_code)]
    SecurityTls {
        test: Option<String>,
    },
    /// 运行所有安全测试
    SecurityAll,
    /// 显示安全报告
    SecurityReport,

    // 场景测试
    /// 运行场景：scenario <name>
    Scenario {
        name: String,
    },

    // 元命令
    /// 显示帮助：help [command]
    Help {
        cmd: Option<String>,
    },
    /// 显示历史
    History,
    /// 清屏
    Clear,
    /// 退出
    Quit,
}

/// 解析用户输入为命令
///
/// # 参数
/// - `input`: 用户输入字符串
///
/// # 返回
/// - `Ok(Command)`: 解析成功
/// - `Err(ParseError)`: 解析失败
///
/// # 示例
/// ```
/// parse("connect 12345")  // => Command::Connect { port: Some(12345) }
/// parse("sign \"hello\"")  // => Command::Sign { data: "hello".to_string() }
/// ```
pub fn parse(input: &str) -> Result<Command, ParseError> {
    // 分割参数（支持引号包裹）
    let parts = split_args(input);
    if parts.is_empty() {
        return Err(ParseError::Other("empty input".to_string()));
    }

    // 命令名不区分大小写
    let cmd = parts[0].to_lowercase();
    let args = &parts[1..];

    // 根据命令名分发到对应解析器
    match cmd.as_str() {
        "connect" => parse_connect(args),
        "disconnect" => Ok(Command::Disconnect),
        "status" => Ok(Command::Status),

        "sign" => parse_sign(args),
        "verify" => parse_verify(args),
        "verify-sign" => parse_verify_sign(args),
        "raw" => parse_raw(args),

        "perf" => parse_perf(args),
        "concurrent" => parse_concurrent(args),

        "security" => parse_security(args),
        "scenario" => parse_scenario(args),

        "help" => Ok(Command::Help {
            cmd: args.first().map(|s| s.to_string()),
        }),
        "history" => Ok(Command::History),
        "clear" => Ok(Command::Clear),
        "quit" | "exit" => Ok(Command::Quit),

        _ => Err(ParseError::UnknownCommand(cmd)),
    }
}

/// 分割命令行参数
///
/// 支持引号包裹的参数，引号内的空格作为参数值的一部分。
///
/// # 示例
/// - `sign hello world` => ["sign", "hello", "world"]
/// - `sign "hello world"` => ["sign", "hello world"]
/// - `sign 'hello world'` => ["sign", "hello world"]
fn split_args(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut quote_char = ' ';

    for ch in input.chars() {
        if in_quotes {
            // 在引号内：遇到匹配引号则结束，否则追加字符
            if ch == quote_char {
                in_quotes = false;
                args.push(current.clone());
                current.clear();
            } else {
                current.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            // 遇到引号：开始引用
            in_quotes = true;
            quote_char = ch;
        } else if ch == ' ' {
            // 遇到空格：完成当前参数
            if !current.is_empty() {
                args.push(current.clone());
                current.clear();
            }
        } else {
            current.push(ch);
        }
    }

    // 处理最后一个参数
    if !current.is_empty() {
        args.push(current);
    }

    args
}

fn parse_connect(args: &[String]) -> Result<Command, ParseError> {
    let port = if args.is_empty() {
        None
    } else {
        Some(
            args[0]
                .parse::<u32>()
                .map_err(|_| ParseError::InvalidArgument("port".to_string()))?,
        )
    };
    Ok(Command::Connect { port })
}

/// 解析 JSON 请求参数
///
/// # 参数
/// - `args`: 命令参数列表
///
/// # 返回
/// 解析后的请求结构体
fn parse_json_request<T: serde::de::DeserializeOwned>(args: &[String]) -> Result<T, ParseError> {
    let json = args
        .first()
        .ok_or_else(|| ParseError::MissingArgument("json".to_string()))?
        .to_string();

    serde_json::from_str(&json)
        .map_err(|e| ParseError::InvalidArgument(format!("Invalid JSON: {}", e)))
}

/// 解析 sign 命令
///
/// 格式：sign <json>
fn parse_sign(args: &[String]) -> Result<Command, ParseError> {
    let request = parse_json_request(args)?;
    Ok(Command::Sign { request })
}

/// 解析 verify 命令
///
/// 格式：verify <json>
fn parse_verify(args: &[String]) -> Result<Command, ParseError> {
    let request = parse_json_request(args)?;
    Ok(Command::Verify { request })
}

/// 解析 verify-sign 命令
///
/// 格式：verify-sign <json>
fn parse_verify_sign(args: &[String]) -> Result<Command, ParseError> {
    let request = parse_json_request(args)?;
    Ok(Command::VerifySign { request })
}

/// 解析 raw 命令
///
/// 格式：raw <msg_type> <json_body>
fn parse_raw(args: &[String]) -> Result<Command, ParseError> {
    let msg_type = args
        .first()
        .ok_or_else(|| ParseError::MissingArgument("msg_type".to_string()))?
        .parse::<u32>()
        .map_err(|_| ParseError::InvalidArgument("msg_type".to_string()))?;
    let body = args
        .get(1)
        .ok_or_else(|| ParseError::MissingArgument("body".to_string()))?
        .to_string();

    Ok(Command::Raw { msg_type, body })
}

/// 解析 perf 命令
///
/// 子命令：sign、verify、report
fn parse_perf(args: &[String]) -> Result<Command, ParseError> {
    let subcmd = args
        .first()
        .ok_or_else(|| ParseError::MissingArgument("subcommand".to_string()))?
        .to_lowercase();

    match subcmd.as_str() {
        "sign" => parse_perf_sign(&args[1..]),
        "verify" => parse_perf_verify(&args[1..]),
        "verify-sign" => parse_perf_verify_sign(&args[1..]),
        "report" => Ok(Command::PerfReport),
        _ => Err(ParseError::UnknownCommand(format!("perf {}", subcmd))),
    }
}

/// 解析 perf sign 子命令
///
/// 格式：perf sign --count <n> [--data <text>] [--interval <ms>]
/// 默认值：count=10
fn parse_perf_sign(args: &[String]) -> Result<Command, ParseError> {
    let mut count = 10u32;
    let mut data = None;
    let mut interval = None;

    // 遍历解析长选项
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--count" {
            count = args
                .get(i + 1)
                .ok_or_else(|| ParseError::MissingArgument("count value".to_string()))?
                .parse::<u32>()
                .map_err(|_| ParseError::InvalidArgument("count".to_string()))?;
            i += 2;
        } else if args[i] == "--data" {
            data = Some(
                args.get(i + 1)
                    .ok_or_else(|| ParseError::MissingArgument("data value".to_string()))?
                    .to_string(),
            );
            i += 2;
        } else if args[i] == "--interval" {
            interval = Some(
                args.get(i + 1)
                    .ok_or_else(|| ParseError::MissingArgument("interval value".to_string()))?
                    .parse::<u32>()
                    .map_err(|_| ParseError::InvalidArgument("interval".to_string()))?,
            );
            i += 2;
        } else {
            i += 1;
        }
    }

    Ok(Command::PerfSign {
        count,
        data,
        interval,
    })
}

/// 解析 perf verify 子命令
///
/// 格式：perf verify --count <n> --data <text> --signed-data <b64> --id <b64> [--interval <ms>]
/// 默认值：count=10
fn parse_perf_verify(args: &[String]) -> Result<Command, ParseError> {
    let mut count = 10u32;
    let mut data = String::new();
    let mut signed_data = String::new();
    let mut id = String::new();
    let mut interval = None;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--count" {
            count = args
                .get(i + 1)
                .ok_or_else(|| ParseError::MissingArgument("count value".to_string()))?
                .parse::<u32>()
                .map_err(|_| ParseError::InvalidArgument("count".to_string()))?;
            i += 2;
        } else if args[i] == "--data" {
            data = args
                .get(i + 1)
                .ok_or_else(|| ParseError::MissingArgument("data value".to_string()))?
                .to_string();
            i += 2;
        } else if args[i] == "--signed-data" {
            signed_data = args
                .get(i + 1)
                .ok_or_else(|| ParseError::MissingArgument("signed-data value".to_string()))?
                .to_string();
            i += 2;
        } else if args[i] == "--id" {
            id = args
                .get(i + 1)
                .ok_or_else(|| ParseError::MissingArgument("id value".to_string()))?
                .to_string();
            i += 2;
        } else if args[i] == "--interval" {
            interval = Some(
                args.get(i + 1)
                    .ok_or_else(|| ParseError::MissingArgument("interval value".to_string()))?
                    .parse::<u32>()
                    .map_err(|_| ParseError::InvalidArgument("interval".to_string()))?,
            );
            i += 2;
        } else {
            i += 1;
        }
    }

    // 必需参数验证
    if data.is_empty() {
        return Err(ParseError::MissingArgument("data".to_string()));
    }
    if signed_data.is_empty() {
        return Err(ParseError::MissingArgument("signed-data".to_string()));
    }
    if id.is_empty() {
        return Err(ParseError::MissingArgument("id".to_string()));
    }

    Ok(Command::PerfVerify {
        count,
        data,
        signed_data,
        id,
        interval,
    })
}

/// 验签+签名命令的公共参数
struct VerifySignArgs {
    sign_data: String,
    sign_id: Option<String>,
    verify_data: Option<String>,
    signed_data: Option<String>,
    verify_id: Option<String>,
}

/// 解析 verify-sign 命令的公共参数
///
/// 公共参数：--sign-data, --sign-id, --verify-data, --signed-data, --verify-id
fn parse_verify_sign_common(args: &[String]) -> Result<VerifySignArgs, ParseError> {
    let mut sign_data = String::new();
    let mut sign_id = None;
    let mut verify_data = None;
    let mut signed_data = None;
    let mut verify_id = None;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--sign-data" {
            sign_data = args
                .get(i + 1)
                .ok_or_else(|| ParseError::MissingArgument("sign-data value".to_string()))?
                .to_string();
            i += 2;
        } else if args[i] == "--sign-id" {
            sign_id = Some(
                args.get(i + 1)
                    .ok_or_else(|| ParseError::MissingArgument("sign-id value".to_string()))?
                    .to_string(),
            );
            i += 2;
        } else if args[i] == "--verify-data" {
            verify_data = Some(
                args.get(i + 1)
                    .ok_or_else(|| ParseError::MissingArgument("verify-data value".to_string()))?
                    .to_string(),
            );
            i += 2;
        } else if args[i] == "--signed-data" {
            signed_data = Some(
                args.get(i + 1)
                    .ok_or_else(|| ParseError::MissingArgument("signed-data value".to_string()))?
                    .to_string(),
            );
            i += 2;
        } else if args[i] == "--verify-id" {
            verify_id = Some(
                args.get(i + 1)
                    .ok_or_else(|| ParseError::MissingArgument("verify-id value".to_string()))?
                    .to_string(),
            );
            i += 2;
        } else {
            i += 1;
        }
    }

    if sign_data.is_empty() {
        return Err(ParseError::MissingArgument("sign-data".to_string()));
    }

    Ok(VerifySignArgs {
        sign_data,
        sign_id,
        verify_data,
        signed_data,
        verify_id,
    })
}

/// 解析 perf verify-sign 子命令
///
/// 格式：
/// - 简化模式：perf verify-sign --count <n> --sign-data <text> [--sign-id <id>] [--interval <ms>]
/// - 完整模式：perf verify-sign --count <n> --sign-data <text> --verify-data <text> --signed-data <b64> --verify-id <b64> [--sign-id <id>] [--interval <ms>]
///   默认值：count=10
fn parse_perf_verify_sign(args: &[String]) -> Result<Command, ParseError> {
    let mut count = 10u32;
    let mut interval = None;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--count" {
            count = args
                .get(i + 1)
                .ok_or_else(|| ParseError::MissingArgument("count value".to_string()))?
                .parse::<u32>()
                .map_err(|_| ParseError::InvalidArgument("count".to_string()))?;
            i += 2;
        } else if args[i] == "--interval" {
            interval = Some(
                args.get(i + 1)
                    .ok_or_else(|| ParseError::MissingArgument("interval value".to_string()))?
                    .parse::<u32>()
                    .map_err(|_| ParseError::InvalidArgument("interval".to_string()))?,
            );
            i += 2;
        } else {
            i += 1;
        }
    }

    let common = parse_verify_sign_common(args)?;

    Ok(Command::PerfVerifySign {
        count,
        sign_data: common.sign_data,
        sign_id: common.sign_id,
        verify_data: common.verify_data,
        signed_data: common.signed_data,
        verify_id: common.verify_id,
        interval,
    })
}

/// 解析 concurrent 命令
///
/// 子命令：sign、verify、report
fn parse_concurrent(args: &[String]) -> Result<Command, ParseError> {
    let subcmd = args
        .first()
        .ok_or_else(|| ParseError::MissingArgument("subcommand".to_string()))?
        .to_lowercase();

    match subcmd.as_str() {
        "sign" => parse_concurrent_sign(&args[1..]),
        "verify" => parse_concurrent_verify(&args[1..]),
        "verify-sign" => parse_concurrent_verify_sign(&args[1..]),
        "report" => Ok(Command::ConcurrentReport),
        _ => Err(ParseError::UnknownCommand(format!("concurrent {}", subcmd))),
    }
}

/// 解析 concurrent sign 子命令
///
/// 格式：concurrent sign --threads <n> --count <n> [--data <text>] [--interval <ms>]
/// 默认值：threads=4, count=10
fn parse_concurrent_sign(args: &[String]) -> Result<Command, ParseError> {
    let mut threads = 4u32;
    let mut count = 10u32;
    let mut data = None;
    let mut interval = None;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--threads" {
            threads = args
                .get(i + 1)
                .ok_or_else(|| ParseError::MissingArgument("threads value".to_string()))?
                .parse::<u32>()
                .map_err(|_| ParseError::InvalidArgument("threads".to_string()))?;
            i += 2;
        } else if args[i] == "--count" {
            count = args
                .get(i + 1)
                .ok_or_else(|| ParseError::MissingArgument("count value".to_string()))?
                .parse::<u32>()
                .map_err(|_| ParseError::InvalidArgument("count".to_string()))?;
            i += 2;
        } else if args[i] == "--data" {
            data = Some(
                args.get(i + 1)
                    .ok_or_else(|| ParseError::MissingArgument("data value".to_string()))?
                    .to_string(),
            );
            i += 2;
        } else if args[i] == "--interval" {
            interval = Some(
                args.get(i + 1)
                    .ok_or_else(|| ParseError::MissingArgument("interval value".to_string()))?
                    .parse::<u32>()
                    .map_err(|_| ParseError::InvalidArgument("interval".to_string()))?,
            );
            i += 2;
        } else {
            i += 1;
        }
    }

    Ok(Command::ConcurrentSign {
        threads,
        count,
        data,
        interval,
    })
}

/// 解析 concurrent verify 子命令
///
/// 格式：concurrent verify --threads <n> --count <n> --data <text> --signed-data <b64> --id <b64> [--interval <ms>]
/// 默认值：threads=4, count=10
fn parse_concurrent_verify(args: &[String]) -> Result<Command, ParseError> {
    let mut threads = 4u32;
    let mut count = 10u32;
    let mut data = String::new();
    let mut signed_data = String::new();
    let mut id = String::new();
    let mut interval = None;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--threads" {
            threads = args
                .get(i + 1)
                .ok_or_else(|| ParseError::MissingArgument("threads value".to_string()))?
                .parse::<u32>()
                .map_err(|_| ParseError::InvalidArgument("threads".to_string()))?;
            i += 2;
        } else if args[i] == "--count" {
            count = args
                .get(i + 1)
                .ok_or_else(|| ParseError::MissingArgument("count value".to_string()))?
                .parse::<u32>()
                .map_err(|_| ParseError::InvalidArgument("count".to_string()))?;
            i += 2;
        } else if args[i] == "--data" {
            data = args
                .get(i + 1)
                .ok_or_else(|| ParseError::MissingArgument("data value".to_string()))?
                .to_string();
            i += 2;
        } else if args[i] == "--signed-data" {
            signed_data = args
                .get(i + 1)
                .ok_or_else(|| ParseError::MissingArgument("signed-data value".to_string()))?
                .to_string();
            i += 2;
        } else if args[i] == "--id" {
            id = args
                .get(i + 1)
                .ok_or_else(|| ParseError::MissingArgument("id value".to_string()))?
                .to_string();
            i += 2;
        } else if args[i] == "--interval" {
            interval = Some(
                args.get(i + 1)
                    .ok_or_else(|| ParseError::MissingArgument("interval value".to_string()))?
                    .parse::<u32>()
                    .map_err(|_| ParseError::InvalidArgument("interval".to_string()))?,
            );
            i += 2;
        } else {
            i += 1;
        }
    }

    // 必需参数验证
    if data.is_empty() {
        return Err(ParseError::MissingArgument("data".to_string()));
    }
    if signed_data.is_empty() {
        return Err(ParseError::MissingArgument("signed-data".to_string()));
    }
    if id.is_empty() {
        return Err(ParseError::MissingArgument("id".to_string()));
    }

    Ok(Command::ConcurrentVerify {
        threads,
        count,
        data,
        signed_data,
        id,
        interval,
    })
}

/// 解析 concurrent verify-sign 子命令
///
/// 格式：
/// - 简化模式：concurrent verify-sign --threads <n> --count <n> --sign-data <text> [--sign-id <id>] [--interval <ms>]
/// - 完整模式：concurrent verify-sign --threads <n> --count <n> --sign-data <text> --verify-data <text> --signed-data <b64> --verify-id <b64> [--sign-id <id>] [--interval <ms>]
///   默认值：threads=4, count=10
fn parse_concurrent_verify_sign(args: &[String]) -> Result<Command, ParseError> {
    let mut threads = 4u32;
    let mut count = 10u32;
    let mut interval = None;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--threads" {
            threads = args
                .get(i + 1)
                .ok_or_else(|| ParseError::MissingArgument("threads value".to_string()))?
                .parse::<u32>()
                .map_err(|_| ParseError::InvalidArgument("threads".to_string()))?;
            i += 2;
        } else if args[i] == "--count" {
            count = args
                .get(i + 1)
                .ok_or_else(|| ParseError::MissingArgument("count value".to_string()))?
                .parse::<u32>()
                .map_err(|_| ParseError::InvalidArgument("count".to_string()))?;
            i += 2;
        } else if args[i] == "--interval" {
            interval = Some(
                args.get(i + 1)
                    .ok_or_else(|| ParseError::MissingArgument("interval value".to_string()))?
                    .parse::<u32>()
                    .map_err(|_| ParseError::InvalidArgument("interval".to_string()))?,
            );
            i += 2;
        } else {
            i += 1;
        }
    }

    let common = parse_verify_sign_common(args)?;

    Ok(Command::ConcurrentVerifySign {
        threads,
        count,
        sign_data: common.sign_data,
        sign_id: common.sign_id,
        verify_data: common.verify_data,
        signed_data: common.signed_data,
        verify_id: common.verify_id,
        interval,
    })
}

/// 解析 security 命令
///
/// 子命令：protocol、cert、tls、all、report
fn parse_security(args: &[String]) -> Result<Command, ParseError> {
    let subcmd = args
        .first()
        .ok_or_else(|| ParseError::MissingArgument("subcommand".to_string()))?
        .to_lowercase();

    match subcmd.as_str() {
        "protocol" => Ok(Command::SecurityProtocol {
            test: args.get(1).map(|s| s.to_string()),
        }),
        "cert" => Ok(Command::SecurityCert {
            test: args.get(1).map(|s| s.to_string()),
        }),
        "tls" => Ok(Command::SecurityTls {
            test: args.get(1).map(|s| s.to_string()),
        }),
        "all" => Ok(Command::SecurityAll),
        "report" => Ok(Command::SecurityReport),
        _ => Err(ParseError::UnknownCommand(format!("security {}", subcmd))),
    }
}

/// 解析 scenario 命令
///
/// 格式：scenario <name>
fn parse_scenario(args: &[String]) -> Result<Command, ParseError> {
    let name = args
        .first()
        .ok_or_else(|| ParseError::MissingArgument("scenario name".to_string()))?
        .to_string();

    Ok(Command::Scenario { name })
}
