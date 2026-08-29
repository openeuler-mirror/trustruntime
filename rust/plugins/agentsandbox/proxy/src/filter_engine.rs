use agentsandbox_config::{FilterConfig, MatchRule};

/// Result of rule evaluation: Allow or Deny with reason.
#[derive(Debug, Clone)]
pub enum FilterResult {
    Allow(String),
    Deny(String),
}

/// Evaluates HTTP request against filter_config rules.
/// Priority: blacklist > whitelist > default_policy.
pub struct FilterEngine;

impl FilterEngine {
    /// Evaluates a request against the filter_config. Blacklist takes highest priority.
    pub fn evaluate(fc: &FilterConfig, domain: &str, method: &str, uri: &str) -> FilterResult {
        if Self::match_rules(&fc.blacklist, domain, method, uri) {
            return FilterResult::Deny("blacklist_match".to_string());
        }
        if Self::match_rules(&fc.whitelist, domain, method, uri) {
            return FilterResult::Allow("whitelist_match".to_string());
        }
        match fc.default_policy.as_str() {
            "allow" => FilterResult::Allow("default_policy".to_string()),
            _ => FilterResult::Deny("default_policy".to_string()),
        }
    }

    fn match_rules(rules: &[MatchRule], domain: &str, method: &str, uri: &str) -> bool {
        rules.iter().any(|r| Self::match_one(r, domain, method, uri))
    }

    fn match_one(rule: &MatchRule, domain: &str, method: &str, uri: &str) -> bool {
        Self::match_domain(&rule.domain, domain)
            && Self::match_field(&rule.method, method)
            && Self::match_field(&rule.uri, uri)
    }

    fn match_domain(pattern: &str, domain: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if let Some(suffix) = pattern.strip_prefix("*.") {
            return domain.ends_with(suffix) || domain == &suffix[1..];
        }
        pattern == domain
    }

    fn match_field(pattern: &str, value: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if pattern.ends_with('*') {
            return value.starts_with(&pattern[..pattern.len() - 1]);
        }
        pattern == value
    }
}
