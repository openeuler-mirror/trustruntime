use agentsandbox_config::NetworkRule;
use super::FilterDecision;

/// Network action returned by evaluate.
const ACTION_ALLOW: &str = "allow";
const ACTION_BLOCK: &str = "block";
const ACTION_REDIRECT: &str = "redirect_to_proxy";

/// Evaluates network_rules for a connect operation.
/// Returns the FilterDecision based on first matching rule, or Allow if no match.
pub fn evaluate(target: &str, port: &str, protocol: &str, rules: &[NetworkRule]) -> FilterDecision {
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
        return action_to_decision(&rule.action);
    }
    FilterDecision::Allow
}

/// Returns the action string for a connect operation (compat with old API).
pub fn evaluate_connect(target: &str, port: &str, protocol: &str, rules: &[NetworkRule]) -> String {
    match evaluate(target, port, protocol, rules) {
        FilterDecision::Allow => ACTION_ALLOW.to_string(),
        FilterDecision::Block => ACTION_BLOCK.to_string(),
        FilterDecision::Redirect => ACTION_REDIRECT.to_string(),
        _ => ACTION_ALLOW.to_string(),
    }
}

fn action_to_decision(action: &str) -> FilterDecision {
    match action {
        ACTION_BLOCK => FilterDecision::Block,
        ACTION_REDIRECT => FilterDecision::Redirect,
        _ => FilterDecision::Allow,
    }
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
    pattern == "*" || pattern == value
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsandbox_config::NetworkRule;

    fn make_rule(target: &str, port: &str, protocol: &str, action: &str) -> NetworkRule {
        NetworkRule {
            operation: "connect".to_string(),
            target: target.to_string(),
            port: port.to_string(),
            protocol: protocol.to_string(),
            action: action.to_string(),
        }
    }

    #[test]
    fn test_block_rule() {
        let rules = vec![make_rule("8.8.8.8", "53", "udp", "block")];
        assert_eq!(evaluate("8.8.8.8", "53", "udp", &rules), FilterDecision::Block);
    }

    #[test]
    fn test_redirect_rule() {
        let rules = vec![make_rule("*", "443", "tcp", "redirect_to_proxy")];
        assert_eq!(evaluate("1.2.3.4", "443", "tcp", &rules), FilterDecision::Redirect);
    }

    #[test]
    fn test_no_match_allow() {
        let rules = vec![make_rule("8.8.8.8", "53", "udp", "block")];
        assert_eq!(evaluate("1.1.1.1", "443", "tcp", &rules), FilterDecision::Allow);
    }

    #[test]
    fn test_wildcard_match() {
        let rules = vec![make_rule("*", "*", "*", "block")];
        assert_eq!(evaluate("any", "any", "any", &rules), FilterDecision::Block);
    }

    #[test]
    fn test_protocol_mismatch() {
        let rules = vec![make_rule("*", "443", "tcp", "redirect_to_proxy")];
        assert_eq!(evaluate("1.2.3.4", "443", "udp", &rules), FilterDecision::Allow);
    }

    #[test]
    fn test_first_match_wins() {
        let rules = vec![
            make_rule("8.8.8.8", "53", "udp", "block"),
            make_rule("*", "*", "*", "allow"),
        ];
        assert_eq!(evaluate("8.8.8.8", "53", "udp", &rules), FilterDecision::Block);
    }
}
