use agentsandbox_config::NetworkRule;

/// Evaluates network_rules for a connect operation.
/// Returns the action string: "allow", "block", or "redirect_to_proxy".
/// Matches from top to bottom; first matching rule wins.
pub fn evaluate_connect(target: &str, port: &str, protocol: &str, rules: &[NetworkRule]) -> String {
    for rule in rules {
        if rule.operation != "connect" {
            continue;
        }
        if !match_target(&rule.target, target) {
            continue;
        }
        if !match_field(&rule.port, port) {
            continue;
        }
        if !match_field(&rule.protocol, protocol) {
            continue;
        }
        return rule.action.clone();
    }
    "allow".to_string()
}

fn match_target(pattern: &str, target: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.contains('/') {
        return target.starts_with(pattern.split('/').next().unwrap_or(""));
    }
    pattern == target
}

fn match_field(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    pattern == value
}
