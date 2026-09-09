use std::fs;
use std::io::Read;
use std::os::unix::net::UnixListener as StdUnixListener;
use thiserror::Error;
use agentsandbox_config::ContainerId;

#[derive(Debug, Error)]
pub enum SockError {
    #[error("socket bind failed: {0}")]
    BindError(String),
    #[error("socket accept failed: {0}")]
    AcceptError(String),
    #[error("message parse failed: {0}")]
    ParseError(String),
}

/// Container lifecycle message type from hook/HC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerAction {
    /// Container created (hook → HC: register container_id + config_path).
    Register,
    /// Container destroyed (cgroup inotify or HC detection: unregister container_id).
    Unregister,
}

/// Container lifecycle message received from hook or HC cgroup monitor.
#[derive(Debug, Clone)]
pub struct ContainerMessage {
    pub action: ContainerAction,
    pub container_id: ContainerId,
    /// config_path is only present for Register action; None for Unregister.
    pub config_path: Option<String>,
}

/// Unix domain socket listener for container lifecycle messages.
pub struct SockListener {
    sock_path: String,
}

impl SockListener {
    pub fn new(sock_path: &str) -> Self {
        Self { sock_path: sock_path.to_string() }
    }

    pub fn listen<F>(&self, on_message: F) -> Result<(), SockError>
    where F: Fn(ContainerMessage) + Send + 'static {
        let _ = fs::remove_file(&self.sock_path);
        let listener = StdUnixListener::bind(&self.sock_path)
            .map_err(|e| SockError::BindError(e.to_string()))?;
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let mut buf = String::new();
                    if stream.read_to_string(&mut buf).is_err() { continue; }
                    if let Some(msg) = Self::parse_message(&buf) { on_message(msg); }
                }
                Err(e) => eprintln!("sock accept error: {}", e),
            }
        }
        Ok(())
    }

    /// Parses a JSON lifecycle message.
    ///
    /// Register format: `{"msg_type":"register","container_id":{"cgroup_id":12345},"config_path":"..."}`
    /// Unregister format: `{"msg_type":"unregister","container_id":{"cgroup_id":12345}}`
    pub fn parse_message(msg: &str) -> Option<ContainerMessage> {
        let parsed: serde_json::Value = serde_json::from_str(msg).ok()?;
        let container_id: ContainerId = serde_json::from_value(parsed.get("container_id")?.clone()).ok()?;
        let msg_type = parsed.get("msg_type")?.as_str()?;
        match msg_type {
            "register" => {
                let config_path = parsed.get("config_path")?.as_str()?.to_string();
                Some(ContainerMessage { action: ContainerAction::Register, container_id, config_path: Some(config_path) })
            }
            "unregister" => {
                Some(ContainerMessage { action: ContainerAction::Unregister, container_id, config_path: None })
            }
            _ => None,
        }
    }

    pub fn sock_path(&self) -> &str { &self.sock_path }
}
