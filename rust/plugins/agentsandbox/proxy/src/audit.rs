use agentsandbox_config::FilterConfig;
use agentsandbox_log::{write_audit_log, AuditLogEntry, LogConfig, LogError};

/// Writes audit log entry if audit_enabled is true in filter_config.
/// Returns Ok(()) silently if audit disabled.
pub fn write_audit_if_enabled(fc: &FilterConfig, entry: &AuditLogEntry, config: &LogConfig) -> Result<(), LogError> {
    if !fc.audit_enabled {
        return Ok(());
    }
    write_audit_log(entry, config)
}
