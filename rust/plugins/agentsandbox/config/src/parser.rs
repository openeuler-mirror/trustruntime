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
/// Validates default_policy (allow/deny/alert), policy_change_strategy
/// (drain/reset), and ruleset fields (2026-09-16 structure: name non-empty,
/// host type-specific field presence, target/binary rule field non-empty,
/// action values deny/block/alert/allow).
/// Returns ParseError on validation failure.
pub fn parse_proxy_policy(toml_content: &str) -> Result<FilterConfig, ParseError> {
    let config = parse_toml(toml_content)?;
    let fc = config.proxy.ok_or(ParseError::MissingField {
        section: "proxy".to_string(),
    })?;
    if !matches!(
        fc.default_policy.as_str(),
        "allow" | "deny" | "alert"
    ) {
        return Err(ParseError::TypeMismatch { section: "proxy".to_string() });
    }
    if fc.policy_change_strategy != "drain" && fc.policy_change_strategy != "reset" {
        return Err(ParseError::TypeMismatch { section: "proxy".to_string() });
    }
    for rs in fc.rule_list.iter() {
        if rs.name.is_empty() {
            return Err(ParseError::MissingField { section: "proxy".to_string() });
        }
        let host_ok = match rs.host.host_type.as_str() {
            "ip" => rs.host.addr_host().is_some_and(|a| !a.is_empty()),
            "host" => rs.host.context.as_deref().is_some_and(|c| !c.is_empty()),
            _ => false,
        };
        if !host_ok {
            return Err(ParseError::TypeMismatch { section: "proxy".to_string() });
        }
        for tr in rs.targetrules.iter() {
            if tr.method.is_empty() || tr.path.is_empty() {
                return Err(ParseError::MissingField { section: "proxy".to_string() });
            }
            if !is_valid_action(&tr.action) {
                return Err(ParseError::TypeMismatch { section: "proxy".to_string() });
            }
        }
        for br in rs.binaryrules.iter() {
            if br.path.is_empty() {
                return Err(ParseError::MissingField { section: "proxy".to_string() });
            }
            if !is_valid_action(&br.action) {
                return Err(ParseError::TypeMismatch { section: "proxy".to_string() });
            }
        }
    }
    Ok(fc)
}

/// 规则动作合法值（deny 与 block 同义——HC 侧术语兼容）。
fn is_valid_action(action: &str) -> bool {
    matches!(action, "deny" | "block" | "alert" | "allow")
}

/// Parses [model_route] section from TOML and returns container_port (0 if absent).
pub fn parse_container_port(toml_content: &str) -> Result<u16, ParseError> {
    let config = parse_toml(toml_content)?;
    Ok(config.model_route.map(|r| r.container_port).unwrap_or(0))
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
