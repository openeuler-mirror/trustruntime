/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL v2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! 推理路由 UDS 远程裁决通道（AR-005 双模式分发，2026-09-09）。
//!
//! 分发依据：环境变量 [`ROUTE_ENV_VAR`]（`HISEC_ROUT_PORT`）——
//! - **存在且非空**（值为 UDS socket 文件路径）：经 Unix stream socket
//!   请求远程推理路由服务裁决（每请求一连接：connect → 写请求行 →
//!   读响应行 → 关闭）；
//! - **不存在/空**：本地直调注入的 router（生产默认 mock——真实库
//!   落地后同 trait 替换）。
//!
//! **UDS 协议**（2026-09-17 信封化——NDJSON，每帧单行 JSON + `\n`，
//! 详见 `inference/API.md`）：
//! - **请求/响应对称信封** `{"msg_type":N,"body":"<JSON 格式字符串>"}`；
//! - `msg_type=10`（推理路由）：请求 body = `{"headers":[...],"body":"..."}`
//!   （多值头逐项展开保序）；响应 body = `{"result":0|1|2,"modifications":
//!   [{"action":1|2,"type":1|2,"key":"...","value":"..."}]}`；
//! - `msg_type=1`（set/delete api key，2026-09-17）：请求 body =
//!   `{"action":"set|delete","items":[{"model_id":"...","api_key":"..."}]}`；
//!   响应 body = `{"status":0}`（0=成功，非零=失败）。
//!
//! **失败语义（fail-closed）**：连接拒绝/IO 错误/超时/响应畸形（非
//! JSON/字段缺失/枚举值域外/超长）→ 返回 [`InferenceResult::Block`]
//!（推理服务不可用时拒绝推理流量）+ warn 日志（不含请求内容）。
//!
//! 阻塞 I/O 隔离：本实现经 std 阻塞 socket；调用方（server 层）以
//! `spawn_blocking` 承载，不得占用 async worker 线程。

use std::io::{BufReader, Read as _, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use agentsandbox_inference::{
    InferenceRequest, InferenceResult, InferenceRouteResult, InferenceRouter, ModifyAction,
    ModifyTarget,
};

/// 分发环境变量（存在且非空 = UDS 远程裁决；值 = UDS socket 文件路径）。
pub const ROUTE_ENV_VAR: &str = "UDS_PATH";

/// UDS 单请求总超时（connect 即时；读写在流上以 read/write 超时约束）。
const UDS_TIMEOUT: Duration = Duration::from_secs(5);

/// 响应行读取上限（防异常服务端返回超长帧撑爆内存）。
const MAX_RESPONSE_LINE: usize = 16 * 1024 * 1024;

// ===== UDS 信封协议（2026-09-17：请求/响应对称信封）=====

/// 信封消息类型：set/delete api key。
pub const MSG_TYPE_API_KEY: u8 = 1;
/// 信封消息类型：推理路由（原裁决协议载荷整体内嵌于 body）。
pub const MSG_TYPE_ROUTE: u8 = 10;

/// UDS 通信信封（请求与响应对称形态；`body` 为 JSON 格式字符串——
/// 按 `msg_type` 解释载荷结构）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UdsEnvelope {
    /// 消息类型（1=set api key / 10=推理路由）。
    pub msg_type: u8,
    /// JSON 格式字符串（序列化后的载荷）。
    pub body: String,
}

/// api key 响应 body（`msg_type=1`）：`{"status":0}`（0=成功）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UdsApiKeyResponse {
    /// 0=成功，非零=失败。
    pub status: u8,
}

// ===== 线格式 DTO（serde；pub 供测试与参考实现对照）=====

/// 请求帧（单行 JSON + `\n`）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UdsRequest {
    /// 请求头二元组数组（多值头逐项展开，保序）。
    pub headers: Vec<(String, String)>,
    /// 请求体（lossy UTF-8 文本）。
    pub body: String,
}

/// 响应帧（单行 JSON + `\n`）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UdsResponse {
    /// 0=Forward / 1=Modified / 2=Block。
    pub result: u8,
    /// 修改列表（缺省 = 空——`#[serde(default)]` 前向兼容）。
    #[serde(default)]
    pub modifications: Vec<UdsModification>,
}

/// 修改项线格式（`type` 为协议字段名——Rust 侧映射 `ModifyTarget`）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UdsModification {
    /// 1=添加 / 2=修改。
    pub action: u8,
    /// 1=header / 2=body。
    #[serde(rename = "type")]
    pub target: u8,
    /// Header：头名；Body：忽略。
    pub key: String,
    /// Header：头值；Body：替换后完整请求体。
    pub value: String,
}

// ===== 线格式 ↔ 契约类型映射 =====

/// 契约请求 → 请求帧（多值头逐项展开保序；头值 lossy UTF-8）。
fn to_wire(req: &InferenceRequest) -> UdsRequest {
    let headers = req
        .headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();
    UdsRequest {
        headers,
        body: req.body.clone(),
    }
}

/// 响应帧 → 契约返回（枚举值域校验——非法值 Err → fail-closed Block）。
fn from_wire(resp: &UdsResponse) -> Option<InferenceRouteResult> {
    let result = match resp.result {
        0 => InferenceResult::Forward,
        1 => InferenceResult::Modified,
        2 => InferenceResult::Block,
        _ => return None,
    };
    let mut modifications = Vec::with_capacity(resp.modifications.len());
    for m in &resp.modifications {
        let action = match m.action {
            1 => ModifyAction::Add,
            2 => ModifyAction::Modify,
            _ => return None,
        };
        let target = match m.target {
            1 => ModifyTarget::Header,
            2 => ModifyTarget::Body,
            _ => return None,
        };
        modifications.push(agentsandbox_inference::InferenceModification {
            action,
            target,
            key: m.key.clone(),
            value: m.value.clone(),
        });
    }
    Some(InferenceRouteResult {
        result,
        modifications,
    })
}

// ===== UDS 客户端 =====

/// 单请求 UDS 信封往返：connect → 写信封行 → 读信封行 → 关闭。
///
/// 任一环节失败 → None（route 调用方 fail-closed Block；api key 调用方
/// 映射 Delivery）。各阶段独立 warn 日志辅助定位（不含路径与载荷内容
/// ——日志安全）。
fn uds_exchange(path: &str, envelope: &UdsEnvelope) -> Option<UdsEnvelope> {
    // 序列化先行（序列化失败 = 程序不变量破坏，等价协议失败）。
    let line = serde_json::to_string(envelope).unwrap_or_else(|e| {
        crate::log_warn!("inference", "uds request serialize failed: {e}");
        String::new()
    });
    if line.is_empty() {
        return None;
    }
    let mut stream = match UnixStream::connect(path) {
        Ok(s) => s,
        Err(e) => {
            crate::log_warn!("inference", "uds connect failed: {e}");
            return None;
        }
    };
    let _ = stream.set_read_timeout(Some(UDS_TIMEOUT));
    let _ = stream.set_write_timeout(Some(UDS_TIMEOUT));

    // 写请求行（超时约束下的 write_all + flush）。
    if let Err(e) = stream.write_all(line.as_bytes())
        .and_then(|_| stream.write_all(b"\n"))
        .and_then(|_| stream.flush())
    {
        crate::log_warn!("inference", "uds request write failed: {e}");
        return None;
    }
    let req_len = line.len();

    // 读响应行（BufReader 分块读取——超长/EOF → None；read_line 无上限，
    // 此处手动按 MAX_RESPONSE_LINE 截断防异常服务端撑爆内存）。
    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = match reader.read(&mut chunk) {
            Ok(n) => n,
            Err(e) => {
                crate::log_warn!("inference", "uds response read failed: {e}");
                return None;
            }
        };
        if n == 0 {
            crate::log_warn!("inference", "uds response EOF before newline");
            return None; // EOF：响应未完整抵达。
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.contains(&b'\n') {
            break;
        }
        if buf.len() > MAX_RESPONSE_LINE {
            crate::log_warn!("inference", "uds response line exceeds limit; dropped");
            return None; // 超长帧——协议畸形。
        }
    }
    let line_end = buf.iter().position(|&b| b == b'\n').unwrap_or(buf.len());
    let resp: UdsEnvelope = match serde_json::from_slice(&buf[..line_end]) {
        Ok(r) => r,
        Err(e) => {
            crate::log_warn!("inference", "uds response parse failed: {e}");
            return None;
        }
    };
    // 收发完成观测（info——release 可见；字节数不含内容，日志安全）。
    crate::log_info!(
        "inference",
        "uds roundtrip done: msg_type={} req_bytes={} resp_bytes={}",
        resp.msg_type,
        req_len,
        line_end
    );
    Some(resp)
}

/// 推理路由 UDS 往返（`msg_type=10`）：请求 body = 原裁决协议载荷；
/// 响应 body 解析为 [`UdsResponse`]。
fn uds_roundtrip(path: &str, req: &InferenceRequest) -> Option<InferenceRouteResult> {
    let body = serde_json::to_string(&to_wire(req)).ok()?;
    let resp = uds_exchange(
        path,
        &UdsEnvelope {
            msg_type: MSG_TYPE_ROUTE,
            body,
        },
    )?;
    let parsed: UdsResponse = serde_json::from_str(&resp.body).ok()?;
    from_wire(&parsed).or_else(|| {
        // 值域外枚举（result/action/target 非法）——协议畸形定位。
        crate::log_warn!("inference", "uds response enum value out of range; dropped");
        None
    })
}

/// set/delete api key UDS 往返（`msg_type=1`，2026-09-17）：请求 body =
/// [`ApiKeyRequest`](agentsandbox_inference::ApiKeyRequest) JSON 串；响应
/// body 解析为 [`UdsApiKeyResponse`]（status=0 成功）。
///
/// 失败（通道/解析/status 非零）→ None（调用方映射
/// [`ApiKeyError::Delivery`](agentsandbox_inference::ApiKeyError)——可重试）。
pub fn uds_api_key(path: &str, req: &agentsandbox_inference::ApiKeyRequest) -> Option<()> {
    let body = serde_json::to_string(req).ok()?;
    let resp = uds_exchange(
        path,
        &UdsEnvelope {
            msg_type: MSG_TYPE_API_KEY,
            body,
        },
    )?;
    let parsed: UdsApiKeyResponse = serde_json::from_str(&resp.body).ok()?;
    if parsed.status != 0 {
        crate::log_warn!("inference", "uds api key rejected: status={}", parsed.status);
        return None;
    }
    Some(())
}

/// 打桩存储查询转发（测试观测缝——facade `set_api_key` 本地模式消费的
/// 同一存储；真实外部库落地后随存储替换移除）。
#[doc(hidden)]
pub fn stub_api_key_for(model_id: &str) -> Option<String> {
    agentsandbox_inference::api_key_for(model_id)
}

// ===== 分发器 =====

/// 双模式分发 router（[`crate::server::ServeContext`] 默认装配）。
///
/// 每请求读 env（运行时可切换）：`HISEC_ROUT_PORT` 非空 → UDS 远程
/// 裁决（失败 fail-closed Block）；否则本地直调注入的 router。
pub struct UdsRouteDispatcher {
    /// 本地 router（env 未设路径；生产默认 mock）。
    local: Box<dyn InferenceRouter>,
}

impl UdsRouteDispatcher {
    /// 构造（local：本地直调 router）。
    pub fn new(local: Box<dyn InferenceRouter>) -> Self {
        Self { local }
    }
}

impl InferenceRouter for UdsRouteDispatcher {
    fn route(&self, req: InferenceRequest) -> InferenceRouteResult {
        let path = std::env::var_os(ROUTE_ENV_VAR).filter(|v| !v.is_empty());
        match path {
            Some(path) => {
                let path = path.to_string_lossy().into_owned();
                uds_roundtrip(&path, &req).unwrap_or_else(|| {
                    // fail-closed：推理服务不可用 → 拒绝推理流量
                    //（日志不含路径/请求内容——日志安全约束）。
                    crate::log_warn!("inference", "uds route failed; blocked (fail-closed)");
                    InferenceRouteResult {
                        result: InferenceResult::Block,
                        modifications: Vec::new(),
                    }
                })
            }
            None => {
                // 本地直调观测（debug 级——mock 常态路径低噪声）。
                crate::log_debug!("inference", "route dispatch: local (env unset)");
                self.local.route(req)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead as _;

    /// env 测试串行锁（进程全局变量——用例间互斥；guard Drop 时清理 env）。
    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(ROUTE_ENV_VAR);
        }
    }
    fn env_serial() -> EnvGuard {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var(ROUTE_ENV_VAR);
        EnvGuard { _lock: lock }
    }

    fn wire_request() -> UdsRequest {
        UdsRequest {
            headers: vec![
                ("host".to_string(), "a.com".to_string()),
                ("x-multi".to_string(), "v1".to_string()),
                ("x-multi".to_string(), "v2".to_string()),
            ],
            body: "{\"q\":\"hi\"}".to_string(),
        }
    }

    // 请求序列化：单行 JSON + 多值头保序 + body 转义后无裸换行。
    #[test]
    fn request_wire_serialization() {
        let json = serde_json::to_string(&wire_request()).unwrap();
        assert!(!json.contains('\n'), "帧必须单行：{json}");
        let back: UdsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.headers.len(), 3);
        assert_eq!(back.headers[1].1, "v1");
        assert_eq!(back.headers[2].1, "v2", "多值头保序");
        assert_eq!(back.body, "{\"q\":\"hi\"}");
        // body 含换行 → JSON 转义为 \\n（分帧安全）。
        let with_nl = UdsRequest {
            headers: vec![],
            body: "line1\nline2".to_string(),
        };
        let json = serde_json::to_string(&with_nl).unwrap();
        assert!(!json.contains('\n'));
    }

    // 响应解析：三态 + 修改映射（线格式 type → ModifyTarget）+ 缺省
    // modifications = 空列表。
    #[test]
    fn response_wire_parsing() {
        let resp: UdsResponse =
            serde_json::from_str(r#"{"result":0}"#).expect("缺省 modifications 兼容");
        let out = from_wire(&resp).unwrap();
        assert_eq!(out.result, InferenceResult::Forward);
        assert!(out.modifications.is_empty());

        let resp: UdsResponse = serde_json::from_str(
            r#"{"result":1,"modifications":[{"action":2,"type":1,"key":"authorization","value":"Bearer x"},{"action":1,"type":2,"key":"","value":"{}"}]}"#,
        )
        .unwrap();
        let out = from_wire(&resp).unwrap();
        assert_eq!(out.result, InferenceResult::Modified);
        assert_eq!(out.modifications.len(), 2);
        assert_eq!(out.modifications[0].action, ModifyAction::Modify);
        assert_eq!(out.modifications[0].target, ModifyTarget::Header);
        assert_eq!(out.modifications[1].target, ModifyTarget::Body);
    }

    // 枚举值域外 → None（协议错误 → fail-closed Block 路径）。
    #[test]
    fn response_wire_invalid_enums_rejected() {
        for bad in [
            r#"{"result":3}"#,
            r#"{"result":1,"modifications":[{"action":0,"type":1,"key":"k","value":"v"}]}"#,
            r#"{"result":1,"modifications":[{"action":1,"type":3,"key":"k","value":"v"}]}"#,
        ] {
            let resp: UdsResponse = serde_json::from_str(bad).unwrap();
            assert!(from_wire(&resp).is_none(), "应拒绝：{bad}");
        }
        // 响应畸形 JSON → 反序列化失败（roundtrip None 路径）。
        assert!(serde_json::from_str::<UdsResponse>("not-json").is_err());
    }

    // UDS 往返（真实 UnixStream 回环，信封协议）：server 线程按 msg_type
    // 回对称信封（route → UdsResponse body）。
    #[test]
    fn uds_roundtrip_against_local_server() {
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("route.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut reader = BufReader::new(&mut conn);
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    // 解包请求信封 → 响应对称信封（body = UdsResponse）。
                    let resp_body = match serde_json::from_str::<UdsEnvelope>(
                        line.trim_end(),
                    ) {
                        Ok(env) if env.msg_type == MSG_TYPE_ROUTE => {
                            let resp = UdsResponse {
                                result: 1,
                                modifications: vec![UdsModification {
                                    action: 2,
                                    target: 1,
                                    key: "x-test".to_string(),
                                    value: "rewritten".to_string(),
                                }],
                            };
                            serde_json::to_string(&resp).unwrap()
                        }
                        _ => r#"{"result":2}"#.to_string(), // 非法信封 → Block。
                    };
                    let out = serde_json::to_string(&UdsEnvelope {
                        msg_type: MSG_TYPE_ROUTE,
                        body: resp_body,
                    })
                    .unwrap()
                        + "\n";
                    let _ = conn.write_all(out.as_bytes());
                }
            }
        });

        let req = InferenceRequest {
            headers: {
                let mut h = http::HeaderMap::new();
                h.insert("x-test", http::HeaderValue::from_static("orig"));
                h
            },
            body: "body".to_string(),
        };
        let out = uds_roundtrip(sock_path.to_str().unwrap(), &req).expect("往返成功");
        assert_eq!(out.result, InferenceResult::Modified);
        assert_eq!(out.modifications[0].key, "x-test");
    }

    // 信封序列化：msg_type + body 双重编码（body 为 JSON 字符串）。
    #[test]
    fn envelope_double_encoding() {
        let env = UdsEnvelope {
            msg_type: MSG_TYPE_ROUTE,
            body: r#"{"headers":[],"body":"x"}"#.to_string(),
        };
        let json = serde_json::to_string(&env).unwrap();
        // body 作为字符串字段转义（内层引号转义——双重编码锚定）。
        assert!(json.contains(r#""body":"{\"headers\":[],\"body\":\"x\"}""#));
        let back: UdsEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, env);
        // msg_type 常量锚定（协议契约）。
        assert_eq!(MSG_TYPE_API_KEY, 1);
        assert_eq!(MSG_TYPE_ROUTE, 10);
    }

    // api key UDS 往返（真实 UnixStream 回环）：msg_type=1 送达 +
    // status=0 应答 → Some(())；status 非零 → None。
    #[test]
    fn uds_api_key_roundtrip() {
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("api-key.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let rec = received.clone();
        std::thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut reader = BufReader::new(&mut conn);
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    if let Ok(env) = serde_json::from_str::<UdsEnvelope>(line.trim_end()) {
                        rec.lock().unwrap().push(env.body.clone());
                        let out = serde_json::to_string(&UdsEnvelope {
                            msg_type: MSG_TYPE_API_KEY,
                            body: r#"{"status":0}"#.to_string(),
                        })
                        .unwrap()
                            + "\n";
                        let _ = conn.write_all(out.as_bytes());
                    }
                }
            }
        });

        let req = agentsandbox_inference::ApiKeyRequest {
            action: agentsandbox_inference::ApiKeyAction::Set,
            items: vec![agentsandbox_inference::ApiKeyItem {
                model_id: "GLM_53".to_string(),
                api_key: "sk-112".to_string(),
            }],
        };
        uds_api_key(sock_path.to_str().unwrap(), &req).expect("api key roundtrip");
        // 服务端收到 msg_type=1 的 body（ApiKeyRequest JSON 串）。
        let bodies = received.lock().unwrap();
        assert_eq!(bodies.len(), 1);
        let parsed: agentsandbox_inference::ApiKeyRequest =
            serde_json::from_str(&bodies[0]).unwrap();
        assert_eq!(parsed, req);
    }

    // UDS 不可达（路径无监听）→ None → dispatcher fail-closed Block。
    #[test]
    fn dispatcher_fail_closed_on_dead_uds() {
        let _env = env_serial();
        let dir = tempfile::tempdir().unwrap();
        let dead_path = dir.path().join("dead.sock");
        std::env::set_var(ROUTE_ENV_VAR, &dead_path);

        let dispatcher =
            UdsRouteDispatcher::new(Box::new(agentsandbox_inference::MockInferenceRouter));
        let out = dispatcher.route(InferenceRequest {
            headers: http::HeaderMap::new(),
            body: String::new(),
        });
        assert_eq!(out.result, InferenceResult::Block, "UDS 失败必须 Block");
        assert!(out.modifications.is_empty());
    }

    // env 未设 → 本地直调（mock Forward）。
    #[test]
    fn dispatcher_falls_back_to_local_when_env_absent() {
        let _env = env_serial();
        let dispatcher =
            UdsRouteDispatcher::new(Box::new(agentsandbox_inference::MockInferenceRouter));
        let out = dispatcher.route(InferenceRequest {
            headers: http::HeaderMap::new(),
            body: String::new(),
        });
        assert_eq!(out.result, InferenceResult::Forward);
    }
}
