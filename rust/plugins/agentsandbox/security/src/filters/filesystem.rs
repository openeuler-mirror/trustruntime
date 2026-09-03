use agentsandbox_config::FilesystemRule;
use super::FilterDecision;

pub const PERM_READ: u8 = 1 << 0;
pub const PERM_WRITE: u8 = 1 << 1;
pub const PERM_EXEC: u8 = 1 << 2;

/// Evaluates whether a filesystem access should be blocked.
/// Returns Block/Alert if path matches a rule and requested permissions
/// are not fully covered by the rule's allowed attrs.
pub fn evaluate(path: &str, requested_perm: u8, rules: &[FilesystemRule], enforcement_mode: &str) -> FilterDecision {
    if !should_block(path, requested_perm, rules) {
        return FilterDecision::Allow;
    }
    match enforcement_mode {
        "block" => FilterDecision::Block,
        "alert" => FilterDecision::Alert,
        _ => FilterDecision::Block,
    }
}

/// Returns true if path matches a rule and requested permissions
/// exceed what the rule allows.
pub fn should_block(path: &str, requested_perm: u8, rules: &[FilesystemRule]) -> bool {
    rules.iter().any(|r| {
        let path_matched = if r.path_prefix.ends_with('*') {
            let prefix = &r.path_prefix[..r.path_prefix.len() - 1];
            path.starts_with(prefix)
        } else {
            path == r.path_prefix
        };
        if !path_matched {
            return false;
        }
        let allowed = attrs_to_perm_mask(&r.attrs);
        (allowed & requested_perm) != requested_perm
    })
}

/// Converts an attrs string like "rwx" to a permission bitmask.
pub fn attrs_to_perm_mask(attrs: &str) -> u8 {
    let mut mask = 0u8;
    for c in attrs.chars() {
        match c {
            'r' | 'R' => mask |= PERM_READ,
            'w' | 'W' => mask |= PERM_WRITE,
            'x' | 'X' => mask |= PERM_EXEC,
            _ => {}
        }
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsandbox_config::FilesystemRule;

    fn rule(path: &str, attrs: &str) -> FilesystemRule {
        FilesystemRule { path_prefix: path.to_string(), attrs: attrs.to_string() }
    }

    #[test]
    fn test_read_allowed() {
        let rules = vec![rule("/proc/*", "r")];
        assert!(!should_block("/proc/1/status", PERM_READ, &rules));
    }

    #[test]
    fn test_write_blocked() {
        let rules = vec![rule("/proc/*", "r")];
        assert!(should_block("/proc/1/status", PERM_WRITE, &rules));
    }

    #[test]
    fn test_rw_allowed() {
        let rules = vec![rule("/etc/shadow", "rw")];
        assert!(!should_block("/etc/shadow", PERM_READ, &rules));
        assert!(!should_block("/etc/shadow", PERM_WRITE, &rules));
        assert!(!should_block("/etc/shadow", PERM_READ | PERM_WRITE, &rules));
    }

    #[test]
    fn test_exec_blocked_when_not_allowed() {
        let rules = vec![rule("/usr/bin/*", "rw")];
        assert!(should_block("/usr/bin/curl", PERM_EXEC, &rules));
    }

    #[test]
    fn test_exec_allowed() {
        let rules = vec![rule("/usr/bin/*", "rx")];
        assert!(!should_block("/usr/bin/curl", PERM_EXEC, &rules));
        assert!(!should_block("/usr/bin/curl", PERM_READ, &rules));
        assert!(should_block("/usr/bin/curl", PERM_WRITE, &rules));
    }

    #[test]
    fn test_rwx_all_allowed() {
        let rules = vec![rule("/tmp/*", "rwx")];
        assert!(!should_block("/tmp/file", PERM_READ, &rules));
        assert!(!should_block("/tmp/file", PERM_WRITE, &rules));
        assert!(!should_block("/tmp/file", PERM_EXEC, &rules));
        assert!(!should_block("/tmp/file", PERM_READ | PERM_WRITE | PERM_EXEC, &rules));
    }

    #[test]
    fn test_path_not_matched_allow() {
        let rules = vec![rule("/proc/*", "r")];
        assert!(!should_block("/etc/shadow", PERM_WRITE, &rules));
    }

    #[test]
    fn test_exact_match() {
        let rules = vec![rule("/etc/shadow", "rw")];
        assert!(!should_block("/etc/shadow", PERM_READ, &rules));
        assert!(!should_block("/etc/passwd", PERM_READ, &rules));
    }

    #[test]
    fn test_empty_attrs_blocks_all() {
        let rules = vec![rule("/secret/*", "")];
        assert!(should_block("/secret/file", PERM_READ, &rules));
        assert!(should_block("/secret/file", PERM_WRITE, &rules));
        assert!(should_block("/secret/file", PERM_EXEC, &rules));
    }

    #[test]
    fn test_block_mode() {
        let rules = vec![rule("/proc/*", "r")];
        assert_eq!(evaluate("/proc/1/status", PERM_WRITE, &rules, "block"), FilterDecision::Block);
    }

    #[test]
    fn test_alert_mode() {
        let rules = vec![rule("/proc/*", "r")];
        assert_eq!(evaluate("/proc/1/status", PERM_WRITE, &rules, "alert"), FilterDecision::Alert);
    }

    #[test]
    fn test_allow_when_perm_covered() {
        let rules = vec![rule("/proc/*", "r")];
        assert_eq!(evaluate("/proc/1/status", PERM_READ, &rules, "block"), FilterDecision::Allow);
    }
}
