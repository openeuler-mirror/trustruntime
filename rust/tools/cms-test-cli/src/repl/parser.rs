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
    /// 签名：sign <data>
    Sign {
        data: String,
    },
    /// 验签：verify <data> <signed_data> <id>
    Verify {
        data: String,
        signed_data: String,
        id: String,
    },
    /// 验签+签名：verify-sign <verify_json> <sign_json>
    VerifySign {
        verify_json: String,
        sign_json: String,
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
    /// 显示性能报告
    PerfReport,

    // 并发测试
    /// 并发签名测试：concurrent sign --threads <n> --count <n> [--data <text>]
    ConcurrentSign {
        threads: u32,
        count: u32,
        data: Option<String>,
    },
    /// 并发验签测试：concurrent verify --threads <n> --count <n> --data <text> --signed-data <b64> --id <b64>
    ConcurrentVerify {
        threads: u32,
        count: u32,
        data: String,
        signed_data: String,
        id: String,
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

/// 解析 sign 命令
///
/// 格式：sign <data>
fn parse_sign(args: &[String]) -> Result<Command, ParseError> {
    let data = args
        .first()
        .ok_or_else(|| ParseError::MissingArgument("data".to_string()))?
        .to_string();

    Ok(Command::Sign { data })
}

/// 解析 verify 命令
///
/// 格式：verify <data> <signed_data> <id>
fn parse_verify(args: &[String]) -> Result<Command, ParseError> {
    let data = args
        .first()
        .ok_or_else(|| ParseError::MissingArgument("data".to_string()))?
        .to_string();
    let signed_data = args
        .get(1)
        .ok_or_else(|| ParseError::MissingArgument("signed_data".to_string()))?
        .to_string();
    let id = args
        .get(2)
        .ok_or_else(|| ParseError::MissingArgument("id".to_string()))?
        .to_string();

    Ok(Command::Verify {
        data,
        signed_data,
        id,
    })
}

/// 解析 verify-sign 命令
///
/// 格式：verify-sign <verify_json> <sign_json>
fn parse_verify_sign(args: &[String]) -> Result<Command, ParseError> {
    let verify_json = args
        .first()
        .ok_or_else(|| ParseError::MissingArgument("verify_json".to_string()))?
        .to_string();
    let sign_json = args
        .get(1)
        .ok_or_else(|| ParseError::MissingArgument("sign_json".to_string()))?
        .to_string();

    Ok(Command::VerifySign {
        verify_json,
        sign_json,
    })
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
        "report" => Ok(Command::ConcurrentReport),
        _ => Err(ParseError::UnknownCommand(format!("concurrent {}", subcmd))),
    }
}

/// 解析 concurrent sign 子命令
///
/// 格式：concurrent sign --threads <n> --count <n> [--data <text>]
/// 默认值：threads=4, count=10
fn parse_concurrent_sign(args: &[String]) -> Result<Command, ParseError> {
    let mut threads = 4u32;
    let mut count = 10u32;
    let mut data = None;

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
        } else {
            i += 1;
        }
    }

    Ok(Command::ConcurrentSign {
        threads,
        count,
        data,
    })
}

/// 解析 concurrent verify 子命令
///
/// 格式：concurrent verify --threads <n> --count <n> --data <text> --signed-data <b64> --id <b64>
/// 默认值：threads=4, count=10
fn parse_concurrent_verify(args: &[String]) -> Result<Command, ParseError> {
    let mut threads = 4u32;
    let mut count = 10u32;
    let mut data = String::new();
    let mut signed_data = String::new();
    let mut id = String::new();

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
