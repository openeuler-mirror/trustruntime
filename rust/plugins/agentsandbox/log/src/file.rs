use fs2::FileExt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use crate::config::LogConfig;
use crate::error::LogError;

/// Appends a single JSON line to {log_dir}/{log_type}.log using flock LOCK_EX for concurrency control.
/// Creates parent directory if missing. Returns LogError on I/O or lock failure.
pub fn write_line(log_type: &str, json_line: &str, config: &LogConfig) -> Result<(), LogError> {
    let log_path = Path::new(&config.log_dir).join(format!("{}.log", log_type));
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| LogError::WriteError)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|_| LogError::WriteError)?;
    file.lock_exclusive().map_err(|_| LogError::LockError)?;
    let result = writeln!(file, "{}", json_line).map_err(|_| LogError::WriteError);
    let _ = file.unlock();
    result
}
