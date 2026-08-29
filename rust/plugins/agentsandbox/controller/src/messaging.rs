use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementMessage {
    pub msg_type: String,
    pub payload: serde_json::Value,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementResponse {
    pub status: String,
    pub detail: Option<serde_json::Value>,
    pub request_id: String,
}

/// Trait for sending management messages over Unix socket + JSON transport.
pub trait MessageSender: Send + Sync {
    fn send(&self, msg: &ManagementMessage) -> Result<ManagementResponse, std::io::Error>;
}

pub struct UnixSocketSender {
    socket_path: String,
}

impl UnixSocketSender {
    /// Creates a new UnixSocketSender connected to the given socket path.
    pub fn new(socket_path: &str) -> Self {
        Self { socket_path: socket_path.to_string() }
    }
}

impl MessageSender for UnixSocketSender {
    fn send(&self, msg: &ManagementMessage) -> Result<ManagementResponse, std::io::Error> {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        let mut stream = UnixStream::connect(&self.socket_path)?;
        let json = serde_json::to_string(msg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        stream.write_all(json.as_bytes())?;
        stream.write_all(b"\n")?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf)?;
        serde_json::from_slice(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

pub const MSG_CMD_START: &str = "cmd_start";
pub const MSG_CMD_STOP: &str = "cmd_stop";
pub const MSG_CMD_RESTART: &str = "cmd_restart";
pub const MSG_HEALTH_CHECK: &str = "health_check";
pub const MSG_SET_LOG_LEVEL: &str = "set_log_level";
pub const MSG_REFRESH_POLICY: &str = "refresh_policy";
pub const MSG_CONFIG_FILE: &str = "config_file";
pub const MSG_REGISTER_RESPONSE_ACTION: &str = "register_response_action";
pub const MSG_STATUS_REPORT: &str = "status_report";
