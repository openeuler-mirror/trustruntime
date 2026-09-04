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
//! **UDS 协议**（NDJSON——每帧单行 JSON + `\n`，详见 `inference/API.md`）：
//! - 请求：`{"headers":[["name","value"],...],"body":"..."}`（多值头逐项
//!   展开保序；body 为 lossy UTF-8 文本）；
//! - 响应：`{"result":0|1|2,"modifications":[{"action":1|2,"type":1|2,
//!   "key":"...","value":"..."}]}`（线格式沿用协议字段名 `type`——
//!   Rust 侧映射 [`agentsandbox_inference::ModifyTarget`]）。
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
pub const ROUTE_ENV_VAR: &str = "HISEC_ROUT_PORT";

/// UDS 单请求总超时（connect 即时；读写在流上以 read/write 超时约束）。
const UDS_TIMEOUT: Duration = Duration::from_secs(5);

/// 响应行读取上限（防异常服务端返回超长帧撑爆内存）。
const MAX_RESPONSE_LINE: usize = 16 * 1024 * 1024;

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

/// 单请求 UDS 往返：connect → 写请求行 → 读响应行 → 关闭。
///
/// 任一环节失败 → Err（调用方 fail-closed Block）。
fn uds_roundtrip(path: &str, req: &InferenceRequest) -> Option<InferenceRouteResult> {
    // 序列化先行（序列化失败 = 程序不变量破坏，等价协议失败）。
    let line = serde_json::to_string(&to_wire(req)).ok()?;
    let mut stream = UnixStream::connect(path).ok()?;
    let _ = stream.set_read_timeout(Some(UDS_TIMEOUT));
    let _ = stream.set_write_timeout(Some(UDS_TIMEOUT));

    // 写请求行（超时约束下的 write_all + flush）。
    stream.write_all(line.as_bytes()).ok()?;
    stream.write_all(b"\n").ok()?;
    stream.flush().ok()?;

    // 读响应行（BufReader 分块读取——超长/EOF → Err；read_line 无上限，
    // 此处手动按 MAX_RESPONSE_LINE 截断防异常服务端撑爆内存）。
    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = reader.read(&mut chunk).ok()?;
        if n == 0 {
            return None; // EOF：响应未完整抵达。
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.contains(&b'\n') {
            break;
        }
        if buf.len() > MAX_RESPONSE_LINE {
            return None; // 超长帧——协议畸形。
        }
    }
    let line_end = buf.iter().position(|&b| b == b'\n').unwrap_or(buf.len());
    let resp: UdsResponse = serde_json::from_slice(&buf[..line_end]).ok()?;
    from_wire(&resp)
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
            None => self.local.route(req),
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

    // UDS 往返（真实 UnixStream 回环）：server 线程 echo 决策。
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
                    let resp = UdsResponse {
                        result: 1,
                        modifications: vec![UdsModification {
                            action: 2,
                            target: 1,
                            key: "x-test".to_string(),
                            value: "rewritten".to_string(),
                        }],
                    };
                    let out = serde_json::to_string(&resp).unwrap() + "\n";
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
