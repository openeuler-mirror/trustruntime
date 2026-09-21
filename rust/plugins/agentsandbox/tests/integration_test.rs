/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! 集成测试（2026-09-16 ruleset 结构重写版）：config TOML（[[proxy.ruleset]]）
//! 解析 + 转换 + 新求值引擎（prio 降序链式）跨模块协作。
//!
//! 保持「TOML → 解析 → 转换 → 求值」全链断言。

use agentsandbox_config::{parse_proxy_policy, parse_security_policy};
use agentsandbox_proxy::filter::evaluate;
use agentsandbox_proxy::model::{
    Action, FilterConfig, HostRule, HostRuleConfig, HostType, Policy, Reason, RuleAction, RuleSet,
    TargetRule,
};

const SAMPLE_TOML: &str = r#"
version = 1
[proxy]
default_policy = "deny"
audit_enabled = true
policy_change_strategy = "drain"
[[proxy.ruleset]]
name = "allow-example"
host = { type = "host", context = "*.example.com", prio = 100 }
targetrules = [
  { method = "POST", path = "/v1/chat", action = "allow" },
  { method = "*", path = "*", action = "allow" },
]
[[proxy.ruleset]]
name = "block-internal"
host = { type = "host", context = "*.internal.com", prio = 300 }
targetrules = [
  { method = "DELETE", path = "*", action = "deny" },
]
[[proxy.ruleset]]
name = "block-example-delete"
host = { type = "host", context = "api.example.com", prio = 200 }
targetrules = [
  { method = "DELETE", path = "*", action = "deny" },
]
[security]
enforcement_mode = "block"
privilege_escalation_rules = [
  { capability = "cap_sys_admin" },
]
filesystem_access_rules = [
  { path_prefix = "/proc/1/*", attrs = "rw" },
]
network_rules = [
  { operation = "connect", target = "*", port = "443", protocol = "tcp", action = "redirect_to_proxy" },
  { operation = "connect", target = "8.8.8.8", port = "53", protocol = "udp", action = "allow" },
]
"#;

/// config 模块解析结果 → proxy FilterConfig 转换（集成方装配形态）。
///
/// 规则集内 targetrules 按 deny>alert>allow 排序（等价 registry
/// 归一化——测试直连 evaluate 需自带序）。
fn to_proxy_fc(parsed: &agentsandbox_config::FilterConfig) -> FilterConfig {
    fn rank(a: &str) -> u8 {
        match a {
            "deny" | "block" => 0,
            "alert" => 1,
            _ => 2,
        }
    }
    let rule_list = parsed
        .rule_list
        .iter()
        .map(|rs| RuleSet {
            name: rs.name.clone(),
            host: HostRule {
                host_type: match rs.host.host_type.as_str() {
                    "ip" => HostType::Ip,
                    _ => HostType::Host,
                },
                addr: rs.host.addr.clone(),
                context: rs.host.context.clone(),
                prio: rs.host.prio,
            },
            targetrules: {
                let mut ts: Vec<TargetRule> = rs
                    .targetrules
                    .iter()
                    .map(|t| TargetRule {
                        method: t.method.clone(),
                        path: t.path.clone(),
                        action: match t.action.as_str() {
                            "deny" | "block" => RuleAction::Deny,
                            "alert" => RuleAction::Alert,
                            _ => RuleAction::Allow,
                        },
                    })
                    .collect();
                ts.sort_by_key(|t| rank(match t.action {
                    RuleAction::Deny => "deny",
                    RuleAction::Alert => "alert",
                    RuleAction::Allow => "allow",
                }));
                ts
            },
            binaryrules: rs
                .binaryrules
                .iter()
                .map(|b| agentsandbox_proxy::model::BinaryRule {
                    path: b.path.clone(),
                    action: match b.action.as_str() {
                        "deny" | "block" => RuleAction::Deny,
                        "alert" => RuleAction::Alert,
                        _ => RuleAction::Allow,
                    },
                })
                .collect(),
            port: rs.port,
        })
        .collect();
    FilterConfig {
        default_policy: match parsed.default_policy.as_str() {
            "allow" => Policy::Allow,
            "alert" => Policy::Alert,
            _ => Policy::Deny,
        },
        rule_list,
    }
}

#[test]
fn test_parse_proxy_policy() {
    let fc = parse_proxy_policy(SAMPLE_TOML).unwrap();
    assert_eq!(fc.default_policy, "deny");
    assert!(fc.audit_enabled);
    assert_eq!(fc.policy_change_strategy, "drain");
    assert_eq!(fc.rule_list.len(), 3);
    assert_eq!(fc.rule_list[0].name, "allow-example");
    assert_eq!(fc.rule_list[0].host.prio, 100);
}

#[test]
fn test_parse_security_policy() {
    let sp = parse_security_policy(SAMPLE_TOML).unwrap();
    assert_eq!(sp.enforcement_mode, "block");
    assert_eq!(sp.privilege_escalation_rules.len(), 1);
    assert_eq!(sp.network_rules[0].action, "redirect_to_proxy");
}

#[test]
fn test_filter_engine_high_prio_ruleset_wins() {
    let fc = to_proxy_fc(&parse_proxy_policy(SAMPLE_TOML).unwrap());
    // *.internal.com 命中 block-internal(300) deny。
    let d = evaluate("c-001", "malicious.internal.com", "DELETE", "/admin", None, &[], 443, &fc);
    assert_eq!(d.action, Action::Deny);
    assert_eq!(d.reason, Reason::BlacklistMatch);
}

#[test]
fn test_filter_engine_whitelist_match() {
    let fc = to_proxy_fc(&parse_proxy_policy(SAMPLE_TOML).unwrap());
    let d = evaluate("c-001", "api.example.com", "POST", "/v1/chat", None, &[], 443, &fc);
    assert_eq!(d.action, Action::Allow);
    assert_eq!(d.reason, Reason::WhitelistMatch);
}

#[test]
fn test_filter_engine_prio_overrides_lower() {
    let fc = to_proxy_fc(&parse_proxy_policy(SAMPLE_TOML).unwrap());
    // api.example.com DELETE：高 prio block-example-delete(200) 先于
    // allow-example(100)——deny 决策（prio 序链式）。
    let d = evaluate("c-001", "api.example.com", "DELETE", "/admin/x", None, &[], 443, &fc);
    assert_eq!(d.action, Action::Deny);
    assert_eq!(d.reason, Reason::BlacklistMatch);
}

#[test]
fn test_filter_engine_default_policy_deny() {
    let fc = to_proxy_fc(&parse_proxy_policy(SAMPLE_TOML).unwrap());
    // 无规则集命中 → default_policy=deny。
    let d = evaluate("c-001", "neutral.example.org", "GET", "/", None, &[], 443, &fc);
    assert_eq!(d.action, Action::Deny);
    assert_eq!(d.reason, Reason::DefaultPolicy);
}

#[test]
fn test_parse_proxy_policy_alert_and_invalid() {
    // default_policy=alert 解析通过；block 动作别名兼容。
    let alert_toml = r#"
[proxy]
default_policy = "alert"
policy_change_strategy = "drain"
[[proxy.ruleset]]
name = "block-metadata"
host = { type = "ip", addr = "169.254.169.254", prio = 50 }
targetrules = [
  { method = "*", path = "*", action = "block" },
]
binaryrules = [
  { path = "*", action = "block" },
]
port = 8843
"#;
    let fc = parse_proxy_policy(alert_toml).unwrap();
    assert_eq!(fc.default_policy, "alert");
    assert_eq!(fc.rule_list.len(), 1);
    assert_eq!(fc.rule_list[0].host.host_type, "ip");
    assert_eq!(fc.rule_list[0].host.addr.as_deref(), Some("169.254.169.254"));
    assert_eq!(fc.rule_list[0].port, Some(8843));
    assert_eq!(fc.rule_list[0].targetrules[0].action, "block");
    assert_eq!(fc.rule_list[0].binaryrules[0].action, "block");

    // alert 求值语义：无命中 → 放行 + alert 标记（Decision 携带）。
    let proxy_fc = to_proxy_fc(&fc);
    let d = evaluate("c-001", "neutral.example.org", "GET", "/", None, &[], 443, &proxy_fc);
    assert_eq!(d.action, Action::Allow);
    assert_eq!(d.reason, Reason::DefaultPolicy);
    assert!(d.alert);

    // 非法值拒绝。
    let bad_toml = r#"
[proxy]
default_policy = "warn"
policy_change_strategy = "drain"
[[proxy.ruleset]]
name = "x"
host = { type = "host", context = "a.com", prio = 1 }
"#;
    assert!(parse_proxy_policy(bad_toml).is_err());
}

#[test]
fn test_host_rule_config_helper() {
    // config 侧 HostRuleConfig::addr_host 辅助（parser 校验消费面）。
    let h = HostRuleConfig {
        host_type: "ip".to_string(),
        addr: Some("10.0.0.1".to_string()),
        context: None,
        prio: 5,
    };
    assert_eq!(h.addr_host(), Some("10.0.0.1"));
}
