use agentsandbox_config::{parse_proxy_policy, parse_security_policy, parse_container_port, FilterConfig, SecurityPolicy};
use std::collections::HashMap;
use std::io::Error;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use std::{fs, thread};

const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Watches config files associated with registered containers for changes.
/// Uses mtime-based polling instead of inotify, because config files reside
/// on virtio-fs and are modified by the host side (inotify does not fire for
/// host-side FUSE writes).
#[derive(Clone)]
pub struct ConfigMonitor {
    inner: Arc<Mutex<WatchInner>>,
}

struct WatchInner {
    paths: HashMap<String, SystemTime>,
    event_tx: Option<mpsc::Sender<String>>,
    started: bool,
}

impl ConfigMonitor {
    pub fn new(_watch_dir: &str) -> Self {
        Self {
            inner: Arc::new(Mutex::new(WatchInner {
                paths: HashMap::new(),
                event_tx: None,
                started: false,
            })),
        }
    }

    pub fn clone_for_watch(&self) -> Self {
        self.clone()
    }

    /// Starts the background polling thread. Must be called once before `add_watch`.
    pub fn start(&self) -> Result<(), Error> {
        let started = self.inner.lock()
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?
            .started;
        if started {
            return Ok(());
        }

        self.set_started()?;
        let inner = self.inner.clone();
        thread::spawn(move || {
            Self::poll_loop(inner);
        });
        Ok(())
    }

    fn set_started(&self) -> Result<(), Error> {
        let mut inner = self.inner.lock()
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        inner.started = true;
        Ok(())
    }

    fn poll_loop(inner: Arc<Mutex<WatchInner>>) {
        loop {
            thread::sleep(POLL_INTERVAL);

            let changed_paths = Self::check_changes(&inner);
            let tx = inner.lock()
                .map(|i| i.event_tx.clone())
                .unwrap_or(None);

            if let Some(tx) = tx {
                for path in changed_paths {
                    let _ = tx.send(path);
                }
            }
        }
    }

    fn check_changes(inner: &Arc<Mutex<WatchInner>>) -> Vec<String> {
        let paths: Vec<String> = inner.lock()
            .map(|i| i.paths.keys().cloned().collect())
            .unwrap_or_default();

        let mut changed = Vec::new();
        for path in &paths {
            let mtime = match fs::metadata(path).and_then(|m| m.modified()) {
                Ok(t) => t,
                Err(_) => continue,
            };

            let prev = inner.lock()
                .map(|i| i.paths.get(path).copied())
                .unwrap_or(None);

            let is_changed = matches!(prev, Some(prev_mtime) if mtime != prev_mtime);

            if is_changed || prev.is_none() {
                changed.push(path.clone());
            }

            if let Ok(mut i) = inner.lock() {
                i.paths.insert(path.clone(), mtime);
            }
        }
        changed
    }

    /// Adds a file to watch. The file path should be the full path of the
    /// container's config file. Calling multiple times with the same path is safe.
    pub fn add_watch(&self, config_path: &str) -> Result<(), Error> {
        let mut inner = self.inner.lock()
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        if !inner.started {
            return Err(Error::new(std::io::ErrorKind::NotConnected, "monitor not started"));
        }

        if inner.paths.contains_key(config_path) {
            return Ok(());
        }

        let mtime = fs::metadata(config_path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        inner.paths.insert(config_path.to_string(), mtime);
        Ok(())
    }

    /// Removes a file from watch.
    pub fn remove_watch(&self, config_path: &str) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.paths.remove(config_path);
        }
    }

    /// Installs the event receiver and blocks the calling thread, invoking
    /// `on_change` for each config file change.
    pub fn watch<F>(&self, on_change: F) -> Result<(), Error>
    where F: Fn(&str) + Send + 'static {
        let (tx, rx) = mpsc::channel::<String>();
        let mut inner = self.inner.lock()
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        inner.event_tx = Some(tx);
        drop(inner);

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
