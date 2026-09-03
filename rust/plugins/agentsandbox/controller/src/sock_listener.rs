use std::fs;
use std::io::Read;
use std::os::unix::net::UnixListener;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SockError {
    #[error("socket bind failed: {0}")]
    BindError(String),
    #[error("socket accept failed: {0}")]
    AcceptError(String),
    #[error("message parse failed: {0}")]
    ParseError(String),
}

/// Listens on a Unix socket for container lifecycle messages from kata-agent.
pub struct SockListener {
    sock_path: String,
}

/// Container lifecycle message received from kata-agent hook.
pub struct ContainerMessage {
    pub cgroup_id: u64,
    pub config_path: String,
}

impl SockListener {
    /// Creates a SockListener bound to the given socket path.
    pub fn new(sock_path: &str) -> Self {
        Self { sock_path: sock_path.to_string() }
    }

    /// Starts accepting connections. Calls on_connect(cgroup_id, toml_content) for each message. Blocks the calling thread.
    pub fn listen<F>(&self, on_connect: F) -> Result<(), SockError> where F: Fn(ContainerMessage) + Send + 'static {
        let _ = fs::remove_file(&self.sock_path);
        let listener = UnixListener::bind(&self.sock_path)
            .map_err(|e| SockError::BindError(e.to_string()))?;

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let mut buf = String::new();
                    if stream.read_to_string(&mut buf).is_err() {
                        continue;
                    }
                    if let Some(msg) = Self::parse_message(&buf) {
                        on_connect(msg);
                    }
                }
                Err(e) => eprintln!("sock accept error: {}", e),
            }
        }
        Ok(())
    }

    /// Parses a JSON message containing cgroup_id and config_path.
    pub fn parse_message(msg: &str) -> Option<ContainerMessage> {
        let parsed: serde_json::Value = serde_json::from_str(msg).ok()?;
        let cgroup_id = parsed.get("cgroup_id")?.as_u64()?;
        let config_path = parsed.get("config_path")?.as_str()?.to_string();
        Some(ContainerMessage { cgroup_id, config_path })
    }

    /// Returns the socket path this listener is bound to.
    pub fn sock_path(&self) -> &str {
        &self.sock_path
    }
}
