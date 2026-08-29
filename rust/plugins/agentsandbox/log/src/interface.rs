use crate::config::LogConfig;
use crate::error::LogError;
use crate::file::write_line;
use serde::Serialize;

/// Audit log entry (12 fields). Written to audit.log as JSON lines via flock.
#[derive(Debug, Serialize)]
pub struct AuditLogEntry {
    pub timestamp: String,
    pub group_id: String,
    pub scenario: String,
    pub protocol: String,
    pub domain: String,
    pub url_path: String,
    pub method: String,
    pub status_code: i32,
    pub action: String,
    pub reason: String,
    pub source_ip: Option<String>,
    pub target_ip: Option<String>,
}

/// Security event (9 fields). Written to security.log as JSON lines via flock.
#[derive(Debug, Serialize)]
pub struct SecurityEvent {
    pub timestamp: String,
    pub cgroup_id: String,
    pub group_id: String,
    pub event_type: String,
    pub operation_detail: String,
    pub action: String,
    pub result: String,
    pub process_name: String,
    pub pid: u32,
}

/// Debug log entry. Written to debug.log as JSON lines via flock.
#[derive(Debug, Serialize)]
pub struct DebugEntry {
    pub timestamp: String,
    pub level: String,
    pub module: String,
    pub message: String,
    pub context: Option<serde_json::Value>,
}

const LEVELS: [&str; 5] = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];

fn level_idx(lvl: &str) -> usize {
    LEVELS.iter().position(|&l| l == lvl).unwrap_or(2)
}

fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs().to_string()).unwrap_or_default()
}

/// Writes an audit log entry to audit.log.
pub fn write_audit_log(e: &AuditLogEntry, cfg: &LogConfig) -> Result<(), LogError> {
    let json = serde_json::to_string(e).map_err(|_| LogError::WriteError)?;
    write_line("audit", &json, cfg)
}

/// Writes a security event to security.log.
pub fn write_security_log(e: &SecurityEvent, cfg: &LogConfig) -> Result<(), LogError> {
    let json = serde_json::to_string(e).map_err(|_| LogError::WriteError)?;
    write_line("security", &json, cfg)
}

/// Writes a debug log entry to debug.log if level >= configured minimum.
pub fn write_debug_log(lvl: &str, mod_name: &str, msg: &str,
                       ctx: Option<serde_json::Value>, cfg: &LogConfig) -> Result<(), LogError> {
    let upper = lvl.to_uppercase();
    if level_idx(&upper) < level_idx(&cfg.debug_level.to_uppercase()) {
        return Ok(());
    }
    let e = DebugEntry { timestamp: now_iso(), level: upper, module: mod_name.to_string(),
        message: msg.to_string(), context: ctx };
    let json = serde_json::to_string(&e).map_err(|_| LogError::WriteError)?;
    write_line("debug", &json, cfg)
}
