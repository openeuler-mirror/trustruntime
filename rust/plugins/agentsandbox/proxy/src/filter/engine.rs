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

//! 规则求值引擎（过滤引擎 T2，说明书 4.1 / K3 / D3）。
//!
//! 纯函数决策：**黑名单条目序遍历**（条目内四维 AND 短路，固定维度序
//! domain→method→uri→binary）→ 命中即 `(deny, blacklist_match)`；
//! 未命中 → **白名单同法**（`allow, whitelist_match`）；仍未命中 →
//! `(default_policy 值, default_policy)`。无状态、无 I/O、不缓存——
//! 决策只由入参决定（同一配置多次求值结果确定，D3）。
//!
//! 求值顺序为**黑名单>白名单>默认**（2026-09-01 用户决策修订——同请求
//! 命中双名单时黑名单优先，deny-overrides-allow 安全模型）。
//!
//! 签名对齐 K3（`evaluate(group_id, domain, method, url_path,
//! binary_path, fc) -> (Action, Reason)`）；`group_id` 不参与匹配
//!（审计/回调入参），保留以锚定契约形态。
//!
//! 条目命中判定复用 [`crate::filter::matcher`] 四维匹配器（T1 已交付）；
//! 未声明维度（None）等同 "*" 全匹配（v1.0 兼容，TC-016）。

use crate::filter::matcher::{
    BinaryMatcher, DimensionMatcher, DomainMatcher, IpMatcher, MethodMatcher, PortMatcher,
    RequestMeta, UriMatcher,
};
use crate::model::{Action, FilterConfig, Policy, Reason, RuleEntry};

/// 静态匹配器组（无状态 unit struct，进程内共享）。
static DOMAIN: DomainMatcher = DomainMatcher;
static METHOD: MethodMatcher = MethodMatcher;
static URI: UriMatcher = UriMatcher;
static BINARY: BinaryMatcher = BinaryMatcher;
static TARGET_IP: IpMatcher = IpMatcher;
static TARGET_PORT: PortMatcher = PortMatcher;

/// 规则求值（K3）：按**黑>白>默认**顺序确定 (action, reason)——
/// 同请求命中双名单时黑名单优先（deny-overrides-allow，2026-09-01
/// 用户决策修订原「白>黑>默认」）。
///
/// `url_path` 可含 query string（uri 匹配器内部剥离）；
/// `binary_path` 为 [`None`] 时 binary 维度条件视为匹配通过
///（D2——统一激活语义下 pid 反查失败在管道层先行收敛为
/// binary_not_found，不会以 None 进入本函数的求值）；
/// `target_ips` 为 DNS 预解析结果（空切片时含 IP 条目的规则不命中
/// ——未解析拒绝在管道层先行收敛为 dns_resolve_error）；
/// `target_port`：明文 = Host 头端口（缺省 80）、TLS = 443。
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
) -> (Action, Reason) {
    // group_id 不参与匹配（契约锚点；防未使用告警的显式标记）。
    let _ = group_id;
    let req = RequestMeta {
        domain,
        method,
        url_path,
        binary_path,
        target_ips,
        target_port,
    };
    // 黑名单全条目序遍历：命中即 deny（黑>白>默认——同命中黑名单优先，
    // D3 顺序确定性保持）。
    for entry in &fc.blacklist {
        if entry_matches(&req, entry) {
            return (Action::Deny, Reason::BlacklistMatch);
        }
    }
    // 白名单全条目序遍历：命中即 allow。
    for entry in &fc.whitelist {
        if entry_matches(&req, entry) {
            return (Action::Allow, Reason::WhitelistMatch);
        }
    }
    // 默认策略（无规则匹配；Alert → 放行 + 告警标记由服务管道按
    // default_policy 组合判定——求值动作与 Allow 一致）。
    match fc.default_policy {
        Policy::Allow | Policy::Alert => (Action::Allow, Reason::DefaultPolicy),
        Policy::Deny => (Action::Deny, Reason::DefaultPolicy),
    }
}

/// 单条目命中判定：固定维度序（domain→method→uri→binary→target_ip→
/// target_port）AND 短路（D3）。
///
/// 条件传入形态：`Some(&str)` 已声明维度 / `None` 未声明（等同 "*"，
/// 匹配器内部全匹配——v1.0 兼容）。
fn entry_matches(req: &RequestMeta<'_>, entry: &RuleEntry) -> bool {
    DOMAIN.matches(req, Some(entry.domain.as_str()))
        && METHOD.matches(req, Some(entry.method.as_str()))
        && URI.matches(req, entry.uri.as_deref())
        && BINARY.matches(req, entry.binary.as_deref())
        && TARGET_IP.matches(req, entry.target_ip.as_deref())
        && TARGET_PORT.matches(req, entry.target_port.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(domain: &str, method: &str, uri: Option<&str>, binary: Option<&str>) -> RuleEntry {
        RuleEntry {
            domain: domain.to_string(),
            method: method.to_string(),
            uri: uri.map(str::to_string),
            binary: binary.map(str::to_string),
            target_ip: None,
            target_port: None,
        }
    }

    /// 含 IP/端口条件的条目（维度组合测试辅助）。
    fn entry_net(
        domain: &str,
        target_ip: Option<&str>,
        target_port: Option<&str>,
    ) -> RuleEntry {
        RuleEntry {
            target_ip: target_ip.map(str::to_string),
            target_port: target_port.map(str::to_string),
            ..entry(domain, "GET", None, None)
        }
    }

    fn fc(default: Policy, whitelist: Vec<RuleEntry>, blacklist: Vec<RuleEntry>) -> FilterConfig {
        FilterConfig {
            default_policy: default,
            whitelist,
            blacklist,
        }
    }

    // TC1（表驱动）：黑命中/白命中/无命中走默认（allow 与 deny 两种默认；
    // 本用例黑白名单无重叠，顺序无关）。
    #[test]
    fn tc1_three_way_decision_table() {
        let deny_default = fc(
            Policy::Deny,
            vec![entry("allow.com", "GET", None, None)],
            vec![entry("block.com", "*", None, None)],
        );
        // 白命中。
        assert_eq!(
            evaluate("g", "allow.com", "GET", "/x", None, &[], 443, &deny_default),
            (Action::Allow, Reason::WhitelistMatch)
        );
        // 黑命中。
        assert_eq!(
            evaluate("g", "block.com", "POST", "/y", None, &[], 443, &deny_default),
            (Action::Deny, Reason::BlacklistMatch)
        );
        // 均不命中 → 默认 deny。
        assert_eq!(
            evaluate("g", "other.com", "GET", "/", None, &[], 443, &deny_default),
            (Action::Deny, Reason::DefaultPolicy)
        );
        // 默认 allow 变体。
        let allow_default = fc(Policy::Allow, vec![], vec![]);
        assert_eq!(
            evaluate("g", "anything.com", "GET", "/", None, &[], 443, &allow_default),
            (Action::Allow, Reason::DefaultPolicy)
        );
    }

    // TC2：条目内四维 AND——仅全命中才放行，任一维不匹配落入后续求值。
    #[test]
    fn tc2_multi_dimension_and() {
        let conf = fc(
            Policy::Deny,
            vec![entry("a.com", "POST", Some("/v1/*"), Some("python3"))],
            vec![],
        );
        // 全命中 → allow。
        assert_eq!(
            evaluate("g", "a.com", "POST", "/v1/chat", Some("python3"), &[], 443, &conf),
            (Action::Allow, Reason::WhitelistMatch)
        );
        // domain+uri 命中但 binary 不匹配 → 不命中（走默认 deny）。
        assert_eq!(
            evaluate("g", "a.com", "POST", "/v1/chat", Some("curl"), &[], 443, &conf),
            (Action::Deny, Reason::DefaultPolicy)
        );
        // method 不匹配。
        assert_eq!(
            evaluate("g", "a.com", "GET", "/v1/chat", Some("python3"), &[], 443, &conf),
            (Action::Deny, Reason::DefaultPolicy)
        );
        // uri 不匹配。
        assert_eq!(
            evaluate("g", "a.com", "POST", "/v2/chat", Some("python3"), &[], 443, &conf),
            (Action::Deny, Reason::DefaultPolicy)
        );
    }

    // TC5：binary 维度——Some 命中/不命中；None（统一激活下管道层先行
    // 收敛，此路径为防御性断言：条件永真，D2）。
    #[test]
    fn tc5_binary_dimension() {
        let conf = fc(
            Policy::Deny,
            vec![entry("a.com", "*", None, Some("python3"))],
            vec![],
        );
        assert_eq!(
            evaluate("g", "a.com", "GET", "/", Some("python3"), &[], 443, &conf),
            (Action::Allow, Reason::WhitelistMatch)
        );
        assert_eq!(
            evaluate("g", "a.com", "GET", "/", Some("curl"), &[], 443, &conf),
            (Action::Deny, Reason::DefaultPolicy)
        );
        // None：binary 条件视为匹配通过（D2 条件永真）。
        assert_eq!(
            evaluate("g", "a.com", "GET", "/", None, &[], 443, &conf),
            (Action::Allow, Reason::WhitelistMatch)
        );
    }

    // TC6（TC-016）：v1.0 条目缺省维度（uri/binary 未声明）等同 "*"。
    #[test]
    fn tc6_v10_entry_compatibility() {
        let conf = fc(
            Policy::Deny,
            vec![entry("a.com", "GET", None, None)],
            vec![],
        );
        // 任意 url_path/进程均不限制。
        assert_eq!(
            evaluate("g", "a.com", "GET", "/any/path?x=1", Some("any-bin"), &[], 443, &conf),
            (Action::Allow, Reason::WhitelistMatch)
        );
    }

    // TC8：通配边界经求值引擎的组合（domain 通配/uri 前缀后缀）。
    #[test]
    fn tc8_wildcard_semantics_through_engine() {
        let conf = fc(
            Policy::Deny,
            vec![entry("*.example.com", "*", Some("/v1/*"), None)],
            vec![],
        );
        assert_eq!(
            evaluate("g", "a.example.com", "GET", "/v1/chat?q=1", None, &[], 443, &conf),
            (Action::Allow, Reason::WhitelistMatch)
        );
        // 裸域不命中（通配边界）。
        assert_eq!(
            evaluate("g", "example.com", "GET", "/v1/chat", None, &[], 443, &conf),
            (Action::Deny, Reason::DefaultPolicy)
        );
        // uri 后缀模式（黑名单）。
        let conf2 = fc(
            Policy::Allow,
            vec![],
            vec![entry("cdn.com", "*", Some("*.js"), None)],
        );
        assert_eq!(
            evaluate("g", "cdn.com", "GET", "/script.js", None, &[], 443, &conf2),
            (Action::Deny, Reason::BlacklistMatch)
        );
        assert_eq!(
            evaluate("g", "cdn.com", "GET", "/script.css", None, &[], 443, &conf2),
            (Action::Allow, Reason::DefaultPolicy)
        );
    }

    // 求值顺序确定性（D3，2026-09-01 修订）：黑名单先于白名单
    //（同请求命中双名单时黑胜——deny-overrides-allow）。
    #[test]
    fn blacklist_precedes_whitelist() {
        let conf = fc(
            Policy::Deny,
            vec![entry("dual.com", "GET", None, None)],
            vec![entry("dual.com", "*", None, None)],
        );
        assert_eq!(
            evaluate("g", "dual.com", "GET", "/", None, &[], 443, &conf),
            (Action::Deny, Reason::BlacklistMatch)
        );
    }

    // 默认策略 Alert（2026-09-09）：黑白未命中 → 放行（与 Allow 同动作；
    // 告警标记由服务侧组合判定承载）；黑白命中不受 default_policy 影响。
    #[test]
    fn default_policy_alert_allows_unmatched() {
        let conf = fc(Policy::Alert, vec![], vec![]);
        assert_eq!(
            evaluate("g", "anything.com", "GET", "/", None, &[], 443, &conf),
            (Action::Allow, Reason::DefaultPolicy)
        );

        // 白名单命中：不受 alert 影响（allow + whitelist_match）。
        let conf = fc(
            Policy::Alert,
            vec![entry("allow.com", "GET", None, None)],
            vec![entry("block.com", "*", None, None)],
        );
        assert_eq!(
            evaluate("g", "allow.com", "GET", "/", None, &[], 443, &conf),
            (Action::Allow, Reason::WhitelistMatch)
        );
        // 黑名单命中：alert 模式下仍拒绝（黑白命中优先于默认策略）。
        assert_eq!(
            evaluate("g", "block.com", "GET", "/", None, &[], 443, &conf),
            (Action::Deny, Reason::BlacklistMatch)
        );
    }

    // 单星任意位置经求值引擎（2026-09-05 三维统一 glob——中间星
    // domain + 中间星 uri + 单星 method 组合）。
    #[test]
    fn single_star_anywhere_through_engine() {
        let conf = fc(
            Policy::Deny,
            vec![entry("api.*.example.com", "G*T", Some("/one/box/*/v1"), None)],
            vec![],
        );
        // 全维命中 → allow。
        assert_eq!(
            evaluate(
                "g",
                "api.v2.example.com",
                "GET",
                "/one/box/a/b/v1",
                None,
                &[],
                443,
                &conf
            ),
            (Action::Allow, Reason::WhitelistMatch)
        );
        // domain 结构不符（缺中间段）。
        assert_eq!(
            evaluate("g", "api.example.com", "GET", "/one/box/a/v1", None, &[], 443, &conf),
            (Action::Deny, Reason::DefaultPolicy)
        );
        // uri 不符（尾段不匹配）。
        assert_eq!(
            evaluate("g", "api.v2.example.com", "GET", "/one/box/a/v2", None, &[], 443, &conf),
            (Action::Deny, Reason::DefaultPolicy)
        );
        // method 不符（大小写敏感）。
        assert_eq!(
            evaluate("g", "api.v2.example.com", "get", "/one/box/a/v1", None, &[], 443, &conf),
            (Action::Deny, Reason::DefaultPolicy)
        );
    }

    // 目标 IP/端口维度经求值引擎（2026-09-09）：任一解析 IP 命中、
    // 端口范围、六维 AND 组合。
    #[test]
    fn target_ip_port_through_engine() {
        let ip = |s: &str| -> std::net::IpAddr { s.parse().unwrap() };

        // IP 黑名单（CIDR）：任一解析 IP 命中即 deny。
        let conf = fc(
            Policy::Allow,
            vec![],
            vec![entry_net("*", Some("203.0.113.0/24"), None)],
        );
        let cdn_ips = [ip("1.1.1.1"), ip("203.0.113.7")];
        assert_eq!(
            evaluate("g", "cdn.example.com", "GET", "/", None, &cdn_ips, 443, &conf),
            (Action::Deny, Reason::BlacklistMatch)
        );
        // 全部解析 IP 不在网段 → 未命中。
        let clean = [ip("1.1.1.1")];
        assert_eq!(
            evaluate("g", "cdn.example.com", "GET", "/", None, &clean, 443, &conf),
            (Action::Allow, Reason::DefaultPolicy)
        );
        // 空解析集（未解析——管道层已 fail-closed，此处为引擎防御路径）：
        // 含 IP 条目不命中。
        assert_eq!(
            evaluate("g", "cdn.example.com", "GET", "/", None, &[], 443, &conf),
            (Action::Allow, Reason::DefaultPolicy)
        );

        // 端口白名单（范围）+ domain 组合。
        let conf = fc(
            Policy::Deny,
            vec![entry_net("*.internal.com", None, Some("8000-9000"))],
            vec![],
        );
        assert_eq!(
            evaluate("g", "api.internal.com", "GET", "/", None, &[], 8443, &conf),
            (Action::Allow, Reason::WhitelistMatch)
        );
        assert_eq!(
            evaluate("g", "api.internal.com", "GET", "/", None, &[], 443, &conf),
            (Action::Deny, Reason::DefaultPolicy)
        );

        // 六维 AND：IP 与端口同时声明，任一不符即不命中。
        let conf = fc(
            Policy::Deny,
            vec![entry_net("api.internal.com", Some("10.0.0.0/8"), Some("8443"))],
            vec![],
        );
        let ips = [ip("10.1.2.3")];
        assert_eq!(
            evaluate("g", "api.internal.com", "GET", "/", None, &ips, 8443, &conf),
            (Action::Allow, Reason::WhitelistMatch)
        );
        assert_eq!(
            evaluate("g", "api.internal.com", "GET", "/", None, &ips, 443, &conf),
            (Action::Deny, Reason::DefaultPolicy)
        );
        let wrong_ips = [ip("192.168.1.1")];
        assert_eq!(
            evaluate("g", "api.internal.com", "GET", "/", None, &wrong_ips, 8443, &conf),
            (Action::Deny, Reason::DefaultPolicy)
        );
    }
}
