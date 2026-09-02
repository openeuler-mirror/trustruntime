use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;

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
    /// Sends a management message and awaits a response.
    fn send(&self, msg: &ManagementMessage) -> Result<ManagementResponse, Error>;

    /// Creates a boxed clone of this sender for use in spawned threads.
    fn clone_box(&self) -> Box<dyn MessageSender + Send>;
}

/// Unix socket client for sending management messages to proxy.
pub struct UnixSocketSender {
    socket_path: String,
}

impl UnixSocketSender {
    /// Creates a UnixSocketSender connected to the given socket path.
    pub fn new(socket_path: &str) -> Self {
        Self { socket_path: socket_path.to_string() }
    }
}

impl MessageSender for UnixSocketSender {
    fn send(&self, msg: &ManagementMessage) -> Result<ManagementResponse, Error> {
        let mut stream = UnixStream::connect(&self.socket_path)?;
        let json = serde_json::to_string(msg).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        stream.write_all(json.as_bytes())?;
        stream.write_all(b"\n")?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf)?;
        serde_json::from_slice(&buf).map_err(|e| Error::new(ErrorKind::InvalidData, e))
    }

    fn clone_box(&self) -> Box<dyn MessageSender + Send> {
        Box::new(UnixSocketSender { socket_path: self.socket_path.clone() })
    }
}

pub const MSG_REFRESH_POLICY: &str = "refresh_policy";
