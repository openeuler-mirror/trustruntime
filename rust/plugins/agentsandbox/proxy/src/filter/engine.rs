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

//! 规则求值引擎（2026-09-16 结构重设计：ruleset 链式求值）。
//!
//! 纯函数决策，无状态、无 I/O、不缓存。**前置条件**：`rule_list` 已按
//! `host.prio` **降序**、各规则集内 targetrules/binaryrules 已按 action
//! rank（deny>alert>allow）排序——由 [`crate::registry::Registry::
//! set_container_config`] 存储时归一化（单一保证点）。
//!
//! 求值算法（链式——首个**规则**命中即决策）：
//! ```text
//! for rs in rule_list（prio 降序）:
//!     host 不匹配 → continue 下一规则集
//!     for br in rs.binaryrules:            // deny/alert 即决策；allow 透传
//!         deny  → (Deny,  blacklist_match)
//!         alert → (Allow, blacklist_match, alert=true)
//!     for tr in rs.targetrules:            // 首中即决策
//!         deny  → (Deny,  blacklist_match)
//!         alert → (Allow, blacklist_match, alert=true)
//!         allow → (Allow, whitelist_match)
//!     （规则集内无命中 → 继续下一规则集）
//! 全部未命中 → default_policy（Alert → 放行 + alert=true）
//! ```
//!
//! host 匹配：`type=ip` → addr（精确/CIDR）对 DNS 预解析 target_ips
//! **任一命中**（deny 保守）；`type=host` → context 单星 glob 对请求域名
//!（大小写不敏感）。`port` 为**预留字段**（不参与匹配）。
//!
//! binary 匹配：path 单星 glob 对 resolver 的 binary_path；`None`（未
//! 解析）不命中——含 binaryrules 的配置由服务层前置收敛
//! binary_not_found（`has_binary_condition`），不以 None 进入求值。

use crate::filter::matcher::{
    star_glob_match, DimensionMatcher, DomainMatcher, IpMatcher, MethodMatcher, RequestMeta,
    UriMatcher,
};
use crate::model::{
    Action, Decision, FilterConfig, HostType, Policy, Reason, RuleAction, RuleSet,
};

/// 静态匹配器组（无状态 unit struct，进程内共享）。
static DOMAIN: DomainMatcher = DomainMatcher;
static METHOD: MethodMatcher = MethodMatcher;
static URI: UriMatcher = UriMatcher;
static TARGET_IP: IpMatcher = IpMatcher;

/// 规则求值（K3，2026-09-16 起 [`Decision`] 返回）。
///
/// `group_id` 不参与匹配（契约锚点）；`url_path` 可含 query（uri 匹配器
/// 内部剥离）；`target_ips` 为 DNS 预解析结果（仅 host.type=ip 规则集
/// 消费）；`target_port` 当前不参与匹配（port 预留）。
#[allow(clippy::too_many_arguments)] // K3 契约平铺签名（维度演进追加）。
pub fn evaluate(
    group_id: &str,
    domain: &str,
    method: &str,
    url_path: &str,
    binary_path: Option<&str>,
    target_ips: &[std::net::IpAddr],
    target_port: u16,
    fc: &FilterConfig,
) -> Decision {
    // group_id 不参与匹配（契约锚点；防未使用告警的显式标记）。
    let _ = group_id;
    let _ = target_port; // port 预留——不参与匹配。
    let req = RequestMeta {
        domain,
        method,
        url_path,
        binary_path,
        target_ips,
        target_port,
    };

    for rs in &fc.rule_list {
        if !ruleset_matches(&req, rs) {
            continue;
        }
        // binaryrules：deny/alert 命中即决策；allow 透传（无决策——排序
        // 保证 allow 段最后，透传后落入 targetrules）。
        for br in &rs.binaryrules {
            if !binary_rule_matches(br, req.binary_path) {
                continue;
            }
            match br.action {
                RuleAction::Deny => {
                    return Decision {
                        action: Action::Deny,
                        reason: Reason::BlacklistMatch,
                        alert: false,
                    }
                }
                RuleAction::Alert => {
                    return Decision {
                        action: Action::Allow,
                        reason: Reason::BlacklistMatch,
                        alert: true,
                    }
                }
                RuleAction::Allow => {} // 透传。
            }
        }
        // targetrules：首个命中即决策。
        for tr in &rs.targetrules {
            if !METHOD.matches(&req, Some(&tr.method)) || !URI.matches(&req, Some(&tr.path)) {
                continue;
            }
            match tr.action {
                RuleAction::Deny => {
                    return Decision {
                        action: Action::Deny,
                        reason: Reason::BlacklistMatch,
                        alert: false,
                    }
                }
                RuleAction::Alert => {
                    return Decision {
                        action: Action::Allow,
                        reason: Reason::BlacklistMatch,
                        alert: true,
                    }
                }
                RuleAction::Allow => {
                    return Decision {
                        action: Action::Allow,
                        reason: Reason::WhitelistMatch,
                        alert: false,
                    }
                }
            }
        }
        // 本规则集无命中 → 链式继续下一规则集（首个规则命中才决策）。
    }

    // 默认策略（全部规则集未命中）。
    match fc.default_policy {
        Policy::Allow => Decision {
            action: Action::Allow,
            reason: Reason::DefaultPolicy,
            alert: false,
        },
        Policy::Deny => Decision {
            action: Action::Deny,
            reason: Reason::DefaultPolicy,
            alert: false,
        },
        Policy::Alert => Decision {
            action: Action::Allow,
            reason: Reason::DefaultPolicy,
            alert: true,
        },
    }
}

/// 规则集命中判定（host 条件——port 预留不参与）。
fn ruleset_matches(req: &RequestMeta<'_>, rs: &RuleSet) -> bool {
    match rs.host.host_type {
        HostType::Ip => rs
            .host
            .addr
            .as_deref()
            .map(|addr| TARGET_IP.matches(req, Some(addr)))
            .unwrap_or(false),
        HostType::Host => rs
            .host
            .context
            .as_deref()
            .map(|ctx| DOMAIN.matches(req, Some(ctx)))
            .unwrap_or(false),
    }
}

/// binary 规则命中判定（path 单星 glob；未解析 None 不命中——服务层
/// 前置 binary_not_found 收敛）。
fn binary_rule_matches(br: &crate::model::BinaryRule, binary_path: Option<&str>) -> bool {
    binary_path.is_some_and(|bp| star_glob_match(&br.path, bp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BinaryRule, HostRule, RuleSet, TargetRule};

    fn mk_host_ruleset(context: &str, prio: u32, targets: Vec<TargetRule>) -> RuleSet {
        RuleSet {
            name: format!("rs-{context}"),
            host: HostRule {
                host_type: HostType::Host,
                addr: None,
                context: Some(context.to_string()),
                prio,
            },
            targetrules: targets,
            binaryrules: vec![],
            port: None,
        }
    }

    fn mk_ip_ruleset(addr: &str, prio: u32, targets: Vec<TargetRule>) -> RuleSet {
        RuleSet {
            name: format!("rs-{addr}"),
            host: HostRule {
                host_type: HostType::Ip,
                addr: Some(addr.to_string()),
                context: None,
                prio,
            },
            targetrules: targets,
            binaryrules: vec![],
            port: None,
        }
    }

    fn t(method: &str, path: &str, action: RuleAction) -> TargetRule {
        TargetRule {
            method: method.to_string(),
            path: path.to_string(),
            action,
        }
    }

    fn fc(default: Policy, rule_list: Vec<RuleSet>) -> FilterConfig {
        FilterConfig {
            default_policy: default,
            rule_list,
        }
    }

    fn eval(domain: &str, method: &str, path: &str, fc: &FilterConfig) -> Decision {
        evaluate("g", domain, method, path, None, &[], 443, fc)
    }

    // TC1：prio 降序链式——高优先级规则集先决策；未命中回退低优先级。
    #[test]
    fn tc1_prio_order_chain() {
        let conf = fc(
            Policy::Deny,
            vec![
                mk_host_ruleset(
                    "dual.com",
                    300,
                    vec![t("*", "/admin/*", RuleAction::Deny)],
                ),
                mk_host_ruleset("dual.com", 100, vec![t("*", "*", RuleAction::Allow)]),
            ],
        );
        // 高 prio 规则集命中 deny。
        assert_eq!(
            eval("dual.com", "GET", "/admin/x", &conf),
            Decision {
                action: Action::Deny,
                reason: Reason::BlacklistMatch,
                alert: false
            }
        );
        // 高 prio 规则集无命中 → 链式回退低 prio allow。
        assert_eq!(
            eval("dual.com", "GET", "/v1/x", &conf),
            Decision {
                action: Action::Allow,
                reason: Reason::WhitelistMatch,
                alert: false
            }
        );
    }

    // TC2：host 匹配——type=host glob 命中/不命中。
    #[test]
    fn tc2_host_glob_matching() {
        let conf = fc(
            Policy::Deny,
            vec![mk_host_ruleset("*.example.com", 100, vec![t("*", "*", RuleAction::Allow)])],
        );
        assert_eq!(
            eval("a.example.com", "GET", "/", &conf).action,
            Action::Allow
        );
        // 裸域不命中（glob 字面 `.` 分隔）。
        assert_eq!(eval("example.com", "GET", "/", &conf).reason, Reason::DefaultPolicy);
        // 无关域名。
        assert_eq!(eval("other.org", "GET", "/", &conf).action, Action::Deny);
    }

    // TC3：host 匹配——type=ip（DNS 预解析 IP 任一命中；CIDR 网段）。
    #[test]
    fn tc3_host_ip_matching() {
        let conf = fc(
            Policy::Deny,
            vec![mk_ip_ruleset("10.0.0.0/8", 100, vec![t("*", "*", RuleAction::Deny)])],
        );
        let hit = ["10.1.2.3".parse().unwrap()];
        let miss = ["192.168.1.1".parse().unwrap()];
        assert_eq!(
            evaluate("g", "cdn.com", "GET", "/", None, &hit, 443, &conf).reason,
            Reason::BlacklistMatch
        );
        assert_eq!(
            evaluate("g", "cdn.com", "GET", "/", None, &miss, 443, &conf).reason,
            Reason::DefaultPolicy
        );
        // 空 IP 集（未解析）：ip 规则集不命中。
        assert_eq!(
            evaluate("g", "cdn.com", "GET", "/", None, &[], 443, &conf).reason,
            Reason::DefaultPolicy
        );
    }

    // TC4：targetrules 维度——method + path AND 匹配。
    #[test]
    fn tc4_targetrule_method_path() {
        let conf = fc(
            Policy::Deny,
            vec![mk_host_ruleset(
                "a.com",
                100,
                vec![t("GET", "/v1/*", RuleAction::Allow)],
            )],
        );
        assert_eq!(eval("a.com", "GET", "/v1/x", &conf).action, Action::Allow);
        assert_eq!(eval("a.com", "GET", "/", &conf).reason, Reason::DefaultPolicy);
        assert_eq!(
            eval("a.com", "POST", "/v1/x", &conf).reason,
            Reason::DefaultPolicy
        );
        // query 剥离。
        assert_eq!(
            eval("a.com", "GET", "/v1/x?q=1", &conf).action,
            Action::Allow
        );
    }

    // TC5：action 三态——deny/alert/allow 的 Decision 形态。
    #[test]
    fn tc5_action_three_states() {
        let mk = |action: RuleAction| {
            fc(
                Policy::Deny,
                vec![mk_host_ruleset("a.com", 100, vec![t("*", "*", action)])],
            )
        };
        assert_eq!(
            eval("a.com", "GET", "/", &mk(RuleAction::Deny)),
            Decision {
                action: Action::Deny,
                reason: Reason::BlacklistMatch,
                alert: false
            }
        );
        assert_eq!(
            eval("a.com", "GET", "/", &mk(RuleAction::Alert)),
            Decision {
                action: Action::Allow,
                reason: Reason::BlacklistMatch,
                alert: true
            }
        );
        assert_eq!(
            eval("a.com", "GET", "/", &mk(RuleAction::Allow)),
            Decision {
                action: Action::Allow,
                reason: Reason::WhitelistMatch,
                alert: false
            }
        );
    }

    // TC6：action 排序优先级——同规则集内 deny 条目先于 alert 先于 allow
    //（registry 归一化后形态；deny 命中优先）。
    #[test]
    fn tc6_action_precedence_within_ruleset() {
        // 手工构造已排序形态（deny → alert → allow——存储归一化结果）。
        let conf = fc(
            Policy::Deny,
            vec![mk_host_ruleset(
                "a.com",
                100,
                vec![
                    t("GET", "/x", RuleAction::Deny),
                    t("*", "/x", RuleAction::Alert),
                    t("*", "*", RuleAction::Allow),
                ],
            )],
        );
        // deny 段命中优先于 alert 段。
        assert_eq!(
            eval("a.com", "GET", "/x", &conf),
            Decision {
                action: Action::Deny,
                reason: Reason::BlacklistMatch,
                alert: false
            }
        );
        // deny 段 method 不符 → alert 段命中（放行 + 告警）。
        assert_eq!(
            eval("a.com", "POST", "/x", &conf),
            Decision {
                action: Action::Allow,
                reason: Reason::BlacklistMatch,
                alert: true
            }
        );
        // 前段均不命中 → allow 段。
        assert_eq!(
            eval("a.com", "GET", "/y", &conf),
            Decision {
                action: Action::Allow,
                reason: Reason::WhitelistMatch,
                alert: false
            }
        );
    }

    // TC7：binaryrules——deny/alert 即决策；allow 透传至 targetrules；
    // glob 匹配 binary_path。
    #[test]
    fn tc7_binaryrules() {
        let mut rs = mk_host_ruleset("a.com", 100, vec![t("*", "*", RuleAction::Allow)]);
        rs.binaryrules = vec![
            BinaryRule {
                path: "/usr/bin/wget".to_string(),
                action: RuleAction::Deny,
            },
            BinaryRule {
                path: "/usr/bin/curl".to_string(),
                action: RuleAction::Alert,
            },
            BinaryRule {
                path: "*".to_string(),
                action: RuleAction::Allow,
            },
        ];
        let conf = fc(Policy::Deny, vec![rs]);
        // binary deny 命中（优先于 target allow）。
        assert_eq!(
            evaluate("g", "a.com", "GET", "/", Some("/usr/bin/wget"), &[], 443, &conf),
            Decision {
                action: Action::Deny,
                reason: Reason::BlacklistMatch,
                alert: false
            }
        );
        // binary alert 命中（放行 + 告警）。
        assert_eq!(
            evaluate("g", "a.com", "GET", "/", Some("/usr/bin/curl"), &[], 443, &conf),
            Decision {
                action: Action::Allow,
                reason: Reason::BlacklistMatch,
                alert: true
            }
        );
        // binary allow（透传）→ target allow 决策。
        assert_eq!(
            evaluate("g", "a.com", "GET", "/", Some("/usr/bin/python3"), &[], 443, &conf),
            Decision {
                action: Action::Allow,
                reason: Reason::WhitelistMatch,
                alert: false
            }
        );
        // binary 未解析（None）：不命中任何 binaryrule → target allow。
        assert_eq!(
            eval("a.com", "GET", "/", &conf).action,
            Action::Allow
        );
    }

    // TC8：默认策略三态（无规则集命中）。
    #[test]
    fn tc8_default_policy_states() {
        let empty = |p: Policy| fc(p, vec![]);
        assert_eq!(
            eval("x.com", "GET", "/", &empty(Policy::Deny)),
            Decision {
                action: Action::Deny,
                reason: Reason::DefaultPolicy,
                alert: false
            }
        );
        assert_eq!(
            eval("x.com", "GET", "/", &empty(Policy::Allow)),
            Decision {
                action: Action::Allow,
                reason: Reason::DefaultPolicy,
                alert: false
            }
        );
        assert_eq!(
            eval("x.com", "GET", "/", &empty(Policy::Alert)),
            Decision {
                action: Action::Allow,
                reason: Reason::DefaultPolicy,
                alert: true
            }
        );
    }

    // TC9：port 预留——规则集带 port 字段不影响匹配（任意端口均命中）。
    #[test]
    fn tc9_port_reserved_ignored() {
        let mut rs = mk_host_ruleset("a.com", 100, vec![t("*", "*", RuleAction::Allow)]);
        rs.port = Some(8843);
        let conf = fc(Policy::Deny, vec![rs]);
        for port in [443u16, 80, 8843] {
            assert_eq!(
                evaluate("g", "a.com", "GET", "/", None, &[], port, &conf).action,
                Action::Allow,
                "port={port} 应命中（预留不参与匹配）"
            );
        }
    }
}
