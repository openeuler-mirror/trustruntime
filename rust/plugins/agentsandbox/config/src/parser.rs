use crate::error::ParseError;
use crate::types::{FilterConfig, SecurityPolicy, TomlConfig};

/// Parses raw TOML content into TomlConfig struct.
/// Returns ParseError::SyntaxError on invalid TOML syntax.
pub fn parse_toml(toml_content: &str) -> Result<TomlConfig, ParseError> {
    toml::from_str::<TomlConfig>(toml_content).map_err(|_| ParseError::SyntaxError {
        section: "root".to_string(),
    })
}

/// Parses [proxy] section from TOML content and returns validated FilterConfig.
/// Validates default_policy (allow/deny), policy_change_strategy (drain/reset),
/// and whitelist/blacklist rule fields. Returns ParseError on validation failure.
pub fn parse_proxy_policy(toml_content: &str) -> Result<FilterConfig, ParseError> {
    let config = parse_toml(toml_content)?;
    let fc = config.proxy.ok_or(ParseError::MissingField {
        section: "proxy".to_string(),
    })?;
    if fc.default_policy != "allow" && fc.default_policy != "deny" {
        return Err(ParseError::TypeMismatch { section: "proxy".to_string() });
    }
    if fc.policy_change_strategy != "drain" && fc.policy_change_strategy != "reset" {
        return Err(ParseError::TypeMismatch { section: "proxy".to_string() });
    }
    for (_i, rule) in fc.whitelist.iter().enumerate() {
        if rule.domain.is_empty() {
            return Err(ParseError::MissingField { section: "proxy".to_string() });
        }
    }
    for (_i, rule) in fc.blacklist.iter().enumerate() {
        if rule.domain.is_empty() {
            return Err(ParseError::MissingField { section: "proxy".to_string() });
        }
    }
    Ok(fc)
}

/// Parses [security] section from TOML content and returns validated SecurityPolicy.
/// Validates enforcement_mode (block/alert) and network_rules action values
/// (allow/block/redirect_to_proxy, redirect_to_proxy requires tcp). Returns ParseError on failure.
pub fn parse_security_policy(toml_content: &str) -> Result<SecurityPolicy, ParseError> {
    let config = parse_toml(toml_content)?;
    let sp = config.security.ok_or(ParseError::MissingField {
        section: "security".to_string(),
    })?;
    if sp.enforcement_mode != "block" && sp.enforcement_mode != "alert" {
        return Err(ParseError::TypeMismatch { section: "security".to_string() });
    }
    for (_i, rule) in sp.network_rules.iter().enumerate() {
        match rule.action.as_str() {
            "allow" | "block" | "redirect_to_proxy" => {}
            _ => return Err(ParseError::TypeMismatch { section: "security".to_string() }),
        }
        if rule.action == "redirect_to_proxy" && rule.protocol != "tcp" {
            return Err(ParseError::TypeMismatch { section: "security".to_string() });
        }
    }
    Ok(sp)
}
