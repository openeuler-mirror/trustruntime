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

//! 集成测试（新 proxy API 重写版）：config TOML 解析 + 新 proxy 容器 API
//! 契约 + 求值引擎（黑>白>默认）跨模块协作。
//!
//! 旧 `FilterEngine::evaluate(&agentsandbox_config::FilterConfig, ..)` 形态已
//! 随旧 proxy 退役——本测试将 config 模块解析结果**转换**为新 proxy 的
//! `FilterConfig` 后经新引擎 `agentsandbox_proxy::filter::evaluate` 求值，
//! 保持「TOML → 解析 → 转换 → 求值」的全链断言。

use agentsandbox_config::{parse_proxy_policy, parse_security_policy};
use agentsandbox_proxy::filter::evaluate;
use agentsandbox_proxy::model::{Action, FilterConfig, Policy, Reason, RuleEntry};

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
  { domain = "api.example.com", method = "DELETE", uri = "*" },
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

/// config 模块解析结果 → 新 proxy FilterConfig 转换（集成方装配形态）。
///
/// 旧 `MatchRule` 字段全 String（"*" 缺省）；新 `RuleEntry` 的 uri/binary
/// 为 Option——"*" 转为 None（等同缺省全匹配语义）。
fn to_proxy_fc(parsed: &agentsandbox_config::FilterConfig) -> FilterConfig {
    let conv = |rules: &[agentsandbox_config::MatchRule]| -> Vec<RuleEntry> {
        rules
            .iter()
            .map(|r| RuleEntry {
                domain: r.domain.clone(),
                method: r.method.clone(),
                uri: if r.uri == "*" { None } else { Some(r.uri.clone()) },
                binary: if r.binary == "*" { None } else { Some(r.binary.clone()) },
            })
            .collect()
    };
    FilterConfig {
        default_policy: if parsed.default_policy == "allow" {
            Policy::Allow
        } else {
            Policy::Deny
        },
        whitelist: conv(&parsed.whitelist),
        blacklist: conv(&parsed.blacklist),
    }
}

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
    let fc = to_proxy_fc(&parse_proxy_policy(SAMPLE_TOML).unwrap());
    let (action, reason) = evaluate("c-001", "malicious.internal.com", "DELETE", "/admin", None, &fc);
    assert_eq!(action, Action::Deny);
    assert_eq!(reason, Reason::BlacklistMatch);
}

#[test]
fn test_filter_engine_whitelist_match() {
    let fc = to_proxy_fc(&parse_proxy_policy(SAMPLE_TOML).unwrap());
    let (action, reason) = evaluate("c-001", "api.example.com", "POST", "/v1/chat", None, &fc);
    assert_eq!(action, Action::Allow);
    assert_eq!(reason, Reason::WhitelistMatch);
}

#[test]
fn test_filter_engine_blacklist_overrides_whitelist() {
    let fc = to_proxy_fc(&parse_proxy_policy(SAMPLE_TOML).unwrap());
    // 同时命中白名单（*.example.com）与黑名单（api.example.com DELETE）：
    // 黑名单优先（黑>白>默认）。
    let (action, reason) = evaluate("c-001", "api.example.com", "DELETE", "/admin/x", None, &fc);
    assert_eq!(action, Action::Deny);
    assert_eq!(reason, Reason::BlacklistMatch);
}

#[test]
fn test_filter_engine_default_policy_deny() {
    let fc = to_proxy_fc(&parse_proxy_policy(SAMPLE_TOML).unwrap());
    // 既不在白名单也不在黑名单 → default_policy=deny。
    let (action, reason) = evaluate("c-001", "neutral.example.org", "GET", "/", None, &fc);
    assert_eq!(action, Action::Deny);
    assert_eq!(reason, Reason::DefaultPolicy);
}
