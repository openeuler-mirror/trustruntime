use agentsandbox_config::{parse_proxy_policy, parse_security_policy};
use agentsandbox_proxy::{FilterEngine, FilterResult};

const SAMPLE_TOML: &str = r#"
version = 1

[proxy]
default_policy = "deny"
audit_enabled = true
policy_change_strategy = "drain"
whitelist = [
  { domain = "api.example.com", method = "POST", uri = "/v1/chat" },
  { domain = "*.example.com", method = "*", uri = "*" },
]
blacklist = [
  { domain = "*.internal.com", method = "DELETE", uri = "*" },
  { domain = "*", method = "*", uri = "*" },
]

[model_route]
container_port = 8000

[security]
enforcement_mode = "block"
default_action = "allow"
privilege_escalation_rules = [
  { capabilities = ["cap_sys_admin"] },
  { capabilities = ["cap_net_raw", "cap_sys_ptrace"], path_pattern = "/usr/bin/curl" },
  { capabilities = ["cap_sys_ptrace"], path_pattern = "/usr/sbin/*" },
]
filesystem_access_rules = [
  { path_prefix = "/proc/1/*", attrs = "rw" },
  { path_prefix = "/etc/shadow", attrs = "r" },
  { path_prefix = "/usr/bin/*", attrs = "rx" },
]
network_rules = [
  { operation = "connect", target = "*", port = "443", protocol = "tcp", action = "redirect_to_proxy" },
  { operation = "connect", target = "8.8.8.8", port = "53", protocol = "udp", action = "allow" },
  { operation = "connect", target = "10.0.0.0/8", port = "*", protocol = "*", action = "block" },
]
"#;

#[test]
fn test_parse_proxy_policy() {
    let fc = parse_proxy_policy(SAMPLE_TOML).unwrap();
    assert_eq!(fc.default_policy, "deny");
    assert!(fc.audit_enabled);
    assert_eq!(fc.policy_change_strategy, "drain");
    assert_eq!(fc.whitelist.len(), 2);
    assert_eq!(fc.blacklist.len(), 2);
}

#[test]
fn test_parse_security_policy() {
    let sp = parse_security_policy(SAMPLE_TOML).unwrap();
    assert_eq!(sp.enforcement_mode, "block");
    assert_eq!(sp.privilege_escalation_rules.len(), 1);
    assert_eq!(sp.network_rules[0].action, "redirect_to_proxy");
}

#[test]
fn test_filter_engine_blacklist_priority() {
    let fc = parse_proxy_policy(SAMPLE_TOML).unwrap();
    let result = FilterEngine::evaluate(&fc, "malicious.internal.com", "DELETE", "/admin");
    assert!(matches!(result, FilterResult::Deny(ref r) if r == "blacklist_match"));
}

#[test]
fn test_filter_engine_whitelist_match() {
    let fc = parse_proxy_policy(SAMPLE_TOML).unwrap();
    let result = FilterEngine::evaluate(&fc, "api.example.com", "POST", "/v1/chat");
    assert!(matches!(result, FilterResult::Allow(ref r) if r == "whitelist_match"));
}

#[test]
fn test_filter_engine_blacklist_overrides_whitelist() {
    let fc = parse_proxy_policy(SAMPLE_TOML).unwrap();
    let result = FilterEngine::evaluate(&fc, "*", "DELETE", "/admin/*");
    assert!(matches!(result, FilterResult::Deny(_)));
}
