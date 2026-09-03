use agentsandbox_config::{parse_proxy_policy, parse_security_policy, parse_container_port, FilterConfig, SecurityPolicy};
use notify::{Event, RecursiveMode, Watcher};
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::sync::mpsc;
use std::{fs, mem};

/// Watches virtio-fs config directory for TOML file changes.
#[derive(Clone)]
pub struct ConfigMonitor {
    watch_dir: PathBuf,
}

impl ConfigMonitor {
    /// Creates a ConfigMonitor watching the given directory.
    pub fn new(watch_dir: &str) -> Self {
        Self { watch_dir: PathBuf::from(watch_dir) }
    }

    /// Creates a clone for use in a separate watch thread.
    pub fn clone_for_watch(&self) -> Self {
        Self { watch_dir: self.watch_dir.clone() }
    }

    /// Starts watching the config directory, calling on_change for each .toml file modified. Blocks the calling thread.
    pub fn watch<F>(&self, on_change: F) -> Result<(), Error> where F: Fn(&str) + Send + 'static {
        let (tx, rx) = mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, _>| {
            if let Ok(ev) = res {
                for path in &ev.paths {
                    if let Some(ext) = path.extension() { if ext == "toml" {
                        if let Some(s) = path.to_str() { let _ = tx.send(s.to_string()); }
                    }}
                }
            }
        }).map_err(|e| Error::new(ErrorKind::Other, e))?;
        watcher.watch(&self.watch_dir, RecursiveMode::NonRecursive)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        mem::forget(watcher);
        while let Ok(path_str) = rx.recv() { on_change(&path_str); }
        Ok(())
    }

    /// Parses a TOML file and returns (filter_config, security_policy, container_port) if sections present.
    pub fn parse_file(&self, path: &str) -> Result<(Option<FilterConfig>, Option<SecurityPolicy>, u16), String> {
        let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
        let container_port = parse_container_port(&content).unwrap_or(0);
        Ok((parse_proxy_policy(&content).ok(), parse_security_policy(&content).ok(), container_port))
    }
}
