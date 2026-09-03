use agentsandbox_config::CapabilityRule;
use super::FilterDecision;

/// Evaluates whether a process capability should be blocked.
/// Returns Block/Alert if capability matches a rule AND (if the rule has a path_pattern)
/// the process_path matches the glob pattern. Otherwise returns Allow.
pub fn evaluate(capability: &str, process_path: Option<&str>, rules: &[CapabilityRule], enforcement_mode: &str) -> FilterDecision {
    for r in rules {
        if !r.capabilities.iter().any(|c| c == capability) {
            continue;
        }
        let path_match = match (&r.path_pattern, process_path) {
            (None, _) => true,
            (Some(pattern), None) => pattern.is_empty() || pattern == "*",
            (Some(pattern), Some(path)) => glob_match(pattern, path),
        };
        if !path_match {
            continue;
        }
        return match enforcement_mode {
            "block" => FilterDecision::Block,
            "alert" => FilterDecision::Alert,
            _ => FilterDecision::Block,
        };
    }
    FilterDecision::Allow
}

/// Returns true if the capability matches any rule (ignoring path conditions).
pub fn should_block(capability: &str, rules: &[CapabilityRule]) -> bool {
    rules.iter().any(|r| r.capabilities.iter().any(|c| c == capability))
}

/// Returns true if the capability and process_path match any rule.
pub fn should_block_path(capability: &str, process_path: &str, rules: &[CapabilityRule]) -> bool {
    rules.iter().any(|r| {
        r.capabilities.iter().any(|c| c == capability) && match &r.path_pattern {
            None => true,
            Some(p) => p.is_empty() || p == "*" || glob_match(p, process_path),
        }
    })
}

/// Simple glob matcher supporting `*` wildcard.
/// `*` matches any sequence of characters (including empty).
/// No `?` or character class support.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    glob_match_inner(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_inner(pattern: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = None;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if pi < pattern.len() && pattern[pi] == text[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(spi) = star_pi {
            pi = spi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsandbox_config::CapabilityRule;

    fn rule(cap: &str, path: Option<&str>) -> CapabilityRule {
        CapabilityRule { capabilities: vec![cap.to_string()], path_pattern: path.map(|s| s.to_string()) }
    }

    fn rule_multi(caps: &[&str], path: Option<&str>) -> CapabilityRule {
        CapabilityRule { capabilities: caps.iter().map(|c| c.to_string()).collect(), path_pattern: path.map(|s| s.to_string()) }
    }

    // --- glob_match tests ---

    #[test]
    fn test_glob_exact() {
        assert!(glob_match("/usr/bin/curl", "/usr/bin/curl"));
        assert!(!glob_match("/usr/bin/curl", "/usr/bin/wget"));
    }

    #[test]
    fn test_glob_prefix_wildcard() {
        assert!(glob_match("/usr/bin/*", "/usr/bin/curl"));
        assert!(glob_match("/usr/bin/*", "/usr/bin/"));
        assert!(!glob_match("/usr/bin/*", "/usr/sbin/curl"));
    }

    #[test]
    fn test_glob_mid_wildcard() {
        assert!(glob_match("/usr/*/curl", "/usr/bin/curl"));
        assert!(glob_match("/usr/*/curl", "/usr/local/bin/curl"));
        assert!(!glob_match("/usr/*/curl", "/usr/bin/wget"));
    }

    #[test]
    fn test_glob_multiple_wildcards() {
        assert!(glob_match("/*/bin/*", "/usr/bin/curl"));
        assert!(glob_match("/*/bin/*", "/usr/local/bin/curl"));
        assert!(!glob_match("/*/bin/*", "/usr/lib/curl"));
    }

    #[test]
    fn test_glob_star_only() {
        assert!(glob_match("*", "/usr/bin/curl"));
        assert!(glob_match("*", "/anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn test_glob_empty_pattern() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "/usr/bin/curl"));
    }

    #[test]
    fn test_glob_trailing_stars() {
        assert!(glob_match("/usr/bin/curl***", "/usr/bin/curl"));
        assert!(glob_match("/usr/bin/*", "/usr/bin/curl"));
    }

    // --- evaluate tests ---

    #[test]
    fn test_evaluate_block_no_path() {
        let rules = vec![rule("cap_sys_admin", None)];
        assert_eq!(evaluate("cap_sys_admin", None, &rules, "block"), FilterDecision::Block);
    }

    #[test]
    fn test_evaluate_no_match_allow() {
        let rules = vec![rule("cap_sys_admin", None)];
        assert_eq!(evaluate("cap_sys_ptrace", None, &rules, "block"), FilterDecision::Allow);
    }

    #[test]
    fn test_evaluate_alert_mode() {
        let rules = vec![rule("cap_sys_admin", None)];
        assert_eq!(evaluate("cap_sys_admin", None, &rules, "alert"), FilterDecision::Alert);
    }

    #[test]
    fn test_evaluate_empty_rules() {
        assert_eq!(evaluate("cap_sys_admin", None, &[], "block"), FilterDecision::Allow);
    }

    #[test]
    fn test_evaluate_path_match_block() {
        let rules = vec![rule("cap_net_raw", Some("/usr/bin/curl"))];
        assert_eq!(
            evaluate("cap_net_raw", Some("/usr/bin/curl"), &rules, "block"),
            FilterDecision::Block
        );
    }

    #[test]
    fn test_evaluate_path_no_match_allow() {
        let rules = vec![rule("cap_net_raw", Some("/usr/bin/curl"))];
        assert_eq!(
            evaluate("cap_net_raw", Some("/usr/bin/wget"), &rules, "block"),
            FilterDecision::Allow
        );
    }

    #[test]
    fn test_evaluate_path_glob_prefix() {
        let rules = vec![rule("cap_net_raw", Some("/usr/bin/*"))];
        assert_eq!(
            evaluate("cap_net_raw", Some("/usr/bin/curl"), &rules, "block"),
            FilterDecision::Block
        );
        assert_eq!(
            evaluate("cap_net_raw", Some("/usr/sbin/curl"), &rules, "block"),
            FilterDecision::Allow
        );
    }

    #[test]
    fn test_evaluate_path_star_matches_all() {
        let rules = vec![rule("cap_sys_admin", Some("*"))];
        assert_eq!(
            evaluate("cap_sys_admin", Some("/anything"), &rules, "block"),
            FilterDecision::Block
        );
        assert_eq!(
            evaluate("cap_sys_admin", None, &rules, "block"),
            FilterDecision::Block
        );
    }

    #[test]
    fn test_evaluate_mixed_rules_path_and_no_path() {
        let rules = vec![
            rule("cap_sys_admin", None),
            rule("cap_net_raw", Some("/usr/bin/curl")),
        ];
        assert_eq!(
            evaluate("cap_sys_admin", Some("/anything"), &rules, "block"),
            FilterDecision::Block
        );
        assert_eq!(
            evaluate("cap_net_raw", Some("/usr/bin/curl"), &rules, "block"),
            FilterDecision::Block
        );
        assert_eq!(
            evaluate("cap_net_raw", Some("/usr/bin/wget"), &rules, "block"),
            FilterDecision::Allow
        );
    }

    #[test]
    fn test_evaluate_path_none_with_path_rule() {
        let rules = vec![rule("cap_net_raw", Some("/usr/bin/curl"))];
        assert_eq!(
            evaluate("cap_net_raw", None, &rules, "block"),
            FilterDecision::Allow
        );
    }
}
