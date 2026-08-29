use agentsandbox_config::{parse_proxy_policy, parse_security_policy, FilterConfig, SecurityPolicy};
use notify::{Event, RecursiveMode, Watcher};
use std::path::PathBuf;

/// Watches virtio-fs config directory for TOML file changes.
pub struct ConfigMonitor {
    watch_dir: PathBuf,
}

impl ConfigMonitor {
    pub fn new(watch_dir: &str) -> Self {
        Self { watch_dir: PathBuf::from(watch_dir) }
    }

    /// Starts watching the config directory. Calls on_change when any .toml file is modified.
    /// Blocks the calling thread; spawn in a dedicated task.
    pub fn watch<F>(&self, on_change: F) -> Result<(), std::io::Error> where F: Fn(&str) + Send + 'static {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, _>| {
            if let Ok(ev) = res {
                for path in &ev.paths {
                    if let Some(ext) = path.extension() { if ext == "toml" {
                        if let Some(s) = path.to_str() { let _ = tx.send(s.to_string()); }
                    }}
                }
            }
        }).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        watcher.watch(&self.watch_dir, RecursiveMode::NonRecursive)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::mem::forget(watcher);
        while let Ok(path_str) = rx.recv() { on_change(&path_str); }
        Ok(())
    }

    /// Parses a TOML file and returns (filter_config, security_policy) if sections present.
    pub fn parse_file(&self, path: &str) -> Result<(Option<FilterConfig>, Option<SecurityPolicy>), String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        Ok((parse_proxy_policy(&content).ok(), parse_security_policy(&content).ok()))
    }
}
