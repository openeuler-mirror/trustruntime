use agentsandbox_config::ContainerId;
use agentsandbox_proxy::facade::{remove_container_policy, set_container_ca, set_container_config};
use agentsandbox_proxy::model::{CaCert, FilterConfig};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::OnceLock;

/// HC -> proxy_proc management message (mirrors controller::messaging::ManagementMessage).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementMessage {
    pub msg_type: String,
    pub payload: serde_json::Value,
    pub request_id: String,
}

/// proxy_proc -> HC management response (mirrors controller::messaging::ManagementResponse).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementResponse {
    pub status: String,
    pub detail: Option<serde_json::Value>,
    pub request_id: String,
}

pub const MSG_REFRESH_POLICY: &str = "refresh_policy";
pub const MSG_REMOVE_CONTAINER: &str = "remove_container";
/// HC → proxy_proc 下发 API key（set/delete——2026-09-17）。
pub const MSG_SET_API_KEY: &str = "set_api_key";

/// refresh_policy payload from HC: { container_id, filter_config }.
#[derive(Debug, Deserialize)]
struct RefreshPolicyPayload {
    container_id: ContainerId,
    filter_config: FilterConfig,
}

/// remove_container payload from HC: { container_id }.
#[derive(Debug, Deserialize)]
struct RemoveContainerPayload {
    container_id: ContainerId,
}

/// Global CA material (loaded once at startup, applied to each new container).
static CA_MATERIAL: OnceLock<CaCert> = OnceLock::new();

/// Stores the global CA PEM material for per-container injection.
pub fn set_global_ca(ca: CaCert) {
    let _ = CA_MATERIAL.set(ca);
}

/// Reads the globally loaded CA material (set at startup by `set_global_ca`).
pub fn global_ca() -> Option<&'static CaCert> {
    CA_MATERIAL.get()
}

/// Receives container lifecycle and config updates from HiController via Unix socket.
///
/// HC sends:
/// - `refresh_policy`: { container_id, filter_config } — create/update container config + CA
/// - `remove_container`: { container_id } — remove container config (on destruction)
pub struct ConfigReceiver {
    socket_path: String,
}

impl ConfigReceiver {
    pub fn new(socket_path: &str) -> Self {
        Self { socket_path: socket_path.to_string() }
    }

    pub fn listen(&self) -> std::io::Result<()> {
        let _ = std::fs::remove_file(&self.socket_path);
        let listener = UnixListener::bind(&self.socket_path)?;
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    std::thread::spawn(move || { let _ = handle_connection(&mut stream); });
                }
                Err(e) => eprintln!("[WARN] proxy_proc: accept error: {}", e),
            }
        }
        Ok(())
    }
}

fn handle_connection(stream: &mut UnixStream) -> std::io::Result<()> {
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let msg: ManagementMessage = match serde_json::from_slice(&buf) {
        Ok(m) => m,
        Err(e) => {
            send_response(stream, "error", &serde_json::json!({ "error": format!("parse: {}", e) }), "")?;
            return Ok(());
        }
    };
    let resp = match msg.msg_type.as_str() {
        MSG_REFRESH_POLICY => handle_refresh_policy(&msg),
        MSG_REMOVE_CONTAINER => handle_remove_container(&msg),
        MSG_SET_API_KEY => handle_set_api_key(&msg),
        other => ManagementResponse {
            status: "error".to_string(),
            detail: Some(serde_json::json!({ "error": format!("unknown msg_type: {}", other) })),
            request_id: msg.request_id,
        },
    };
    let json = serde_json::to_string(&resp)?;
    stream.write_all(json.as_bytes())?;
    Ok(())
}

fn handle_refresh_policy(msg: &ManagementMessage) -> ManagementResponse {
    let payload: RefreshPolicyPayload = match serde_json::from_value(msg.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            return ManagementResponse {
                status: "error".to_string(),
                detail: Some(serde_json::json!({ "error": format!("payload: {}", e) })),
                request_id: msg.request_id.clone(),
            };
        }
    };
    let container_id = payload.container_id.as_key();
    if let Some(ca) = CA_MATERIAL.get() {
        if let Err(e) = set_container_ca(&container_id, ca.clone()) {
            eprintln!("[WARN] proxy_proc: set_container_ca failed for {}: {:?}", container_id, e);
        }
    }
    match set_container_config(&container_id, payload.filter_config) {
        Ok(()) => ManagementResponse {
            status: "ok".to_string(),
            detail: Some(serde_json::json!({ "container_id": payload.container_id })),
            request_id: msg.request_id.clone(),
        },
        Err(e) => ManagementResponse {
            status: "error".to_string(),
            detail: Some(serde_json::json!({ "error": format!("set_container_config: {:?}", e) })),
            request_id: msg.request_id.clone(),
        },
    }
}

fn handle_remove_container(msg: &ManagementMessage) -> ManagementResponse {
    let payload: RemoveContainerPayload = match serde_json::from_value(msg.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            return ManagementResponse {
                status: "error".to_string(),
                detail: Some(serde_json::json!({ "error": format!("payload: {}", e) })),
                request_id: msg.request_id.clone(),
            };
        }
    };
    let container_id = payload.container_id.as_key();
    match remove_container_policy(&container_id) {
        Ok(()) => {
            eprintln!("[INFO] proxy_proc: removed container {}", payload.container_id);
            ManagementResponse {
                status: "ok".to_string(),
                detail: Some(serde_json::json!({ "container_id": payload.container_id })),
                request_id: msg.request_id.clone(),
            }
        }
        Err(e) => {
            eprintln!("[WARN] proxy_proc: remove for {}: {:?}", payload.container_id, e);
            ManagementResponse {
                status: "ok".to_string(),
                detail: Some(serde_json::json!({ "container_id": payload.container_id, "note": "already removed" })),
                request_id: msg.request_id.clone(),
            }
        }
    }
}

/// set_api_key handler（2026-09-17）：payload → ApiKeyRequest → facade
/// set_api_key（env 双模式：UDS msg_type=1 / 本地打桩存储）。
fn handle_set_api_key(msg: &ManagementMessage) -> ManagementResponse {
    let payload: agentsandbox_proxy::ApiKeyRequest =
        match serde_json::from_value(msg.payload.clone()) {
            Ok(p) => p,
            Err(e) => {
                return ManagementResponse {
                    status: "error".to_string(),
                    detail: Some(serde_json::json!({ "error": format!("payload: {}", e) })),
                    request_id: msg.request_id.clone(),
                };
            }
        };
    // 日志不含 api key 内容（安全——仅动作与条数）。
    eprintln!(
        "[INFO] proxy_proc: set_api_key action={:?} items={}",
        payload.action,
        payload.items.len()
    );
    match agentsandbox_proxy::facade::set_api_key(payload) {
        Ok(()) => ManagementResponse {
            status: "ok".to_string(),
            detail: None,
            request_id: msg.request_id.clone(),
        },
        Err(e) => {
            eprintln!("[WARN] proxy_proc: set_api_key failed: {:?}", e);
            ManagementResponse {
                status: "error".to_string(),
                detail: Some(serde_json::json!({ "error": format!("set_api_key: {:?}", e) })),
                request_id: msg.request_id.clone(),
            }
        }
    }
}

fn send_response(stream: &mut UnixStream, status: &str, detail: &serde_json::Value, request_id: &str) -> std::io::Result<()> {
    let resp = ManagementResponse { status: status.to_string(), detail: Some(detail.clone()), request_id: request_id.to_string() };
    let json = serde_json::to_string(&resp)?;
    stream.write_all(json.as_bytes())
}
