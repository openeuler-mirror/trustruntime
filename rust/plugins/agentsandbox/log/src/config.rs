use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub log_dir: String,
    pub debug_level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self { log_dir: "/var/log/agentsandbox".to_string(), debug_level: "INFO".to_string() }
    }
}

/// Thread-safe log configuration handle. Created via LogHandle::new(), shared across threads.
pub struct LogHandle {
    inner: Mutex<LogConfig>,
}

impl LogHandle {
    /// Creates a new LogHandle with the given config.
    pub fn new(config: LogConfig) -> Self {
        Self { inner: Mutex::new(config) }
    }

    /// Creates a LogHandle with default config (log_dir=/var/log/agentsandbox, debug_level=INFO).
    pub fn default() -> Self {
        Self::new(LogConfig::default())
    }

    /// Returns a clone of the current config.
    pub fn config(&self) -> LogConfig {
        self.inner.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// Updates the log config (e.g. log_dir or debug_level at runtime).
    pub fn set_config(&self, config: LogConfig) {
        if let Ok(mut g) = self.inner.lock() {
            *g = config;
        }
    }
}
