use std::sync::Mutex;
use agentsandbox_log::AuditLogEntry;

type SinkFn = Box<dyn Fn(&AuditLogEntry) -> Result<(), String> + Send + Sync>;

/// Registry for audit log sink callbacks (scenario 2 only).
pub struct LogSinkRegistry {
    sink: Mutex<Option<SinkFn>>,
}

impl LogSinkRegistry {
    pub fn new() -> Self {
        Self { sink: Mutex::new(None) }
    }

    /// Registers a log sink callback.
    pub fn register<F>(&self, h: F)
    where F: Fn(&AuditLogEntry) -> Result<(), String> + Send + Sync + 'static {
        if let Ok(mut s) = self.sink.lock() {
            *s = Some(Box::new(h));
        }
    }

    /// Invokes the registered sink. Returns Err if no sink or sink fails.
    pub fn write(&self, entry: &AuditLogEntry) -> Result<(), String> {
        let s = self.sink.lock().map_err(|e| e.to_string())?;
        s.as_ref().ok_or("no_sink_registered".to_string())?(entry)
    }
}
