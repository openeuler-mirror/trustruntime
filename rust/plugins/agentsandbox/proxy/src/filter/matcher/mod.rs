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

//! 四维匹配器与维度抽象（过滤引擎 T1，说明书 4.2.2 / D1/D2）。
//!
//! 维度语义权威（4.2.2 匹配规则表 + 2026-09-05 三维统一通配决策）：
//! - **单星 glob 通配（domain/method/uri 三维统一）**：至多一个 `*`、
//!   任意位置；`*` 匹配**任意字符序列**（含 `/`、含空串——`/one/box/*/v1`
//!   命中 `/one/box/a/b/v1`）；裸 `*` 全匹配；无星精确。`?`/`[`/`]`/
//!   `{`/`}`/`\` 一律字面（URL/DNS 合法字符——经 globset 转义保字面，
//!   见 [`glob`]）。多星形态由 K10 校验器在注入口判非法（fail-closed）；
//! - domain：通配与精确均 ASCII 大小写不敏感（DNS 名称等价类，
//!   RFC 4343：SNI 为 Agent 可构造输入，大小写变体解析到同一主机，
//!   字节比较将旁路黑名单）；`*.example.com` 不匹配裸域名
//!   `example.com`（glob 天然边界——模式含字面 `.` 分隔）；纯 glob
//!   语义（2026-09-05 决策：空标签防御不保留——`..example.com` 等
//!   畸形主机可命中通配）；
//! - method：精确与通配均大小写敏感（HTTP 方法按 RFC 9110）；
//! - uri：**匹配对象为路径部分，不含 query string**（自首个 `?` 截断）；
//! - binary：精确全等；`*`/未声明全匹配；**场景一（无 binary_path 入参）
//!   该维度条件视为匹配通过（D2：忽略=条件永真，非跳过条目）**。
//!
//! 条件 `None`（维度未声明，等同 "*"）全匹配；条目命中 = 全部已声明维度
//! 匹配通过（AND 短路由 T2 求值遍历按固定维度序 domain→method→uri→binary
//! 执行，D3）。新维度（header 等）经新增 [`DimensionMatcher`] 实现扩展，
//! 不改求值遍历（D1）。

mod glob;

/// 请求元数据（求值入参的匹配维度视图——K3 元组的匹配相关子集；
/// group_id 为审计/回调入参，不参与匹配）。
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct RequestMeta<'a> {
    /// 请求域名（SNI）。
    pub domain: &'a str,
    /// HTTP 方法。
    pub method: &'a str,
    /// 请求路径（可能含 query string——uri 匹配器内部剥离）。
    pub url_path: &'a str,
    /// binary 二进制路径（resolver 连接级解析 Some / 未解析 None）。
    pub binary_path: Option<&'a str>,
}

/// 维度匹配器抽象（D1：输入请求元组 + 条目维度条件 → bool）。
///
/// 实现为无状态纯函数（`Send + Sync` 供求值侧共享）。
pub trait DimensionMatcher: Send + Sync {
    /// 判定请求是否命中该维度条件（`None`=未声明，等同 "*" 全匹配）。
    fn matches(&self, req: &RequestMeta<'_>, cond: Option<&str>) -> bool;
}

/// ASCII 大小写不敏感后缀判定（DNS 名称等价类，RFC 4343；零分配）。
fn ends_with_ignore_ascii_case(hay: &str, needle: &str) -> bool {
    hay.len() >= needle.len()
        && hay.as_bytes()[hay.len() - needle.len()..].eq_ignore_ascii_case(needle.as_bytes())
}

/// ASCII 大小写不敏感前缀判定（零分配）。
fn starts_with_ignore_ascii_case(hay: &str, needle: &str) -> bool {
    hay.len() >= needle.len()
        && hay.as_bytes()[..needle.len()].eq_ignore_ascii_case(needle.as_bytes())
}

/// domain 维度匹配器（2026-09-05 统一 glob：单星任意位置——后缀
/// `*.suffix`/前缀 `api*`/中间 `api.*.com`；纯 glob 语义——空标签
/// 防御不保留；全维 ASCII 大小写不敏感，RFC 4343）。
pub struct DomainMatcher;

impl DimensionMatcher for DomainMatcher {
    fn matches(&self, req: &RequestMeta<'_>, cond: Option<&str>) -> bool {
        let Some(pattern) = cond else {
            return true; // 未声明维度等同 "*"。
        };
        if pattern == "*" {
            return true; // 裸 * = 全匹配（2026-09-05 决策：与 method 对齐）。
        }
        if let Some(suffix) = pattern.strip_prefix('*') {
            // 后缀通配（含 *.suffix 形态）：以 suffix 结尾——纯 glob 语义
            //（*.example.com 不匹配裸域 example.com：模式含字面 '.' 分隔）。
            ends_with_ignore_ascii_case(req.domain, suffix)
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            // 前缀通配 api*：以 prefix 开头。
            starts_with_ignore_ascii_case(req.domain, prefix)
        } else if pattern.contains('*') {
            // 中间星 api.*.example.com：glob（ci）。
            glob::glob_match(pattern, req.domain, true)
        } else {
            // 精确全等（DNS 名称等价类：ASCII 大小写不敏感，RFC 4343）。
            req.domain.eq_ignore_ascii_case(pattern)
        }
    }
}

/// method 维度匹配器（2026-09-05 统一 glob：单星任意位置；精确与通配
/// 均大小写敏感——HTTP 方法按 RFC 9110）。
pub struct MethodMatcher;

impl DimensionMatcher for MethodMatcher {
    fn matches(&self, req: &RequestMeta<'_>, cond: Option<&str>) -> bool {
        let Some(pattern) = cond else {
            return true;
        };
        if pattern == "*" {
            return true; // 全匹配（K3 契约原语义）。
        }
        if pattern.contains('*') {
            // 单星通配（GET* / *ET / G*T）。
            glob::glob_match(pattern, req.method, false)
        } else {
            pattern == req.method
        }
    }
}

/// uri 维度匹配器（2026-09-05 统一 glob：单星任意位置——前缀 `/v1/*` /
/// 后缀 `*.js` / 中间 `/one/box/*/v1`（`*` 任意序列含 `/` 与空串）；
/// 匹配路径部分不含 query；大小写敏感）。
pub struct UriMatcher;

impl DimensionMatcher for UriMatcher {
    fn matches(&self, req: &RequestMeta<'_>, cond: Option<&str>) -> bool {
        let Some(pattern) = cond else {
            return true;
        };
        // 匹配对象为路径部分：自首个 '?' 截断 query string（TC-013）。
        let path = req.url_path.split('?').next().unwrap_or("");
        if pattern == "*" {
            return true; // 裸 * = 全匹配（三维统一）。
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            // 前缀模式 /v1/*：path 以 /v1/ 开头（星号前含分隔符）。
            path.starts_with(prefix)
        } else if let Some(suffix) = pattern.strip_prefix('*') {
            // 后缀模式 *.js：path 以 .js 结尾。
            path.ends_with(suffix)
        } else if pattern.contains('*') {
            // 中间星 /one/box/*/v1：glob（cs）。
            glob::glob_match(pattern, path, false)
        } else {
            // 裸值：精确全等。
            path == pattern
        }
    }
}

/// binary 维度匹配器（进程二进制路径精确全等——与 resolver 输出的
/// `binary_path` 比较；未解析 None 时条件永真：忽略维度而非跳过条目）。
pub struct BinaryMatcher;

impl DimensionMatcher for BinaryMatcher {
    fn matches(&self, req: &RequestMeta<'_>, cond: Option<&str>) -> bool {
        let Some(pattern) = cond else {
            return true; // 未声明维度等同 "*"。
        };
        if pattern == "*" {
            return true; // 显式通配。
        }
        match req.binary_path {
            // 未解析：忽略该维度条件（视为匹配通过——条件永真而非跳过
            // 条目；含 binary 条件规则的未解析拒绝在服务管道前置收敛为
            // binary_not_found，不进入匹配）。
            None => true,
            // 已解析：二进制路径精确匹配。
            Some(path) => path == pattern,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(
        domain: &'a str,
        method: &'a str,
        url_path: &'a str,
        binary: Option<&'a str>,
    ) -> RequestMeta<'a> {
        RequestMeta {
            domain,
            method,
            url_path,
            binary_path: binary,
        }
    }

    // TC3：domain 通配边界（`*.example.com` 匹配子域、不匹配裸域）+
    // 单星任意位置扩展（中间/无点星/前缀——2026-09-05 统一 glob）。
    #[test]
    fn tc3_domain_wildcard_boundaries() {
        let m = DomainMatcher;
        // 子域名命中（含多级子域——任意深度）。
        assert!(m.matches(&req("a.example.com", "GET", "/", None), Some("*.example.com")));
        assert!(m.matches(
            &req("a.b.example.com", "GET", "/", None),
            Some("*.example.com")
        ));
        // 裸域名不命中。
        assert!(!m.matches(&req("example.com", "GET", "/", None), Some("*.example.com")));
        // 前缀串扰不命中（aexample.com 非 example.com 子域）。
        assert!(!m.matches(
            &req("aexample.com", "GET", "/", None),
            Some("*.example.com")
        ));
        // 精确全等。
        assert!(m.matches(&req("example.com", "GET", "/", None), Some("example.com")));
        assert!(!m.matches(&req("other.com", "GET", "/", None), Some("example.com")));
        // 未声明维度：全匹配。
        assert!(m.matches(&req("anything.com", "GET", "/", None), None));

        // 中间星 api.*.example.com：命中结构符合的子域深度形态。
        assert!(m.matches(
            &req("api.v2.example.com", "GET", "/", None),
            Some("api.*.example.com")
        ));
        assert!(!m.matches(&req("api.example.com", "GET", "/", None), Some("api.*.example.com")));
        assert!(!m.matches(&req("apiv2.example.com", "GET", "/", None), Some("api.*.example.com")));
        // 无点星 *example.com：命中裸域与任意前缀（标准 glob——空串含）。
        assert!(m.matches(&req("example.com", "GET", "/", None), Some("*example.com")));
        assert!(m.matches(&req("x.example.com", "GET", "/", None), Some("*example.com")));
        assert!(m.matches(&req("aexample.com", "GET", "/", None), Some("*example.com")));
        // 前缀星 api*。
        assert!(m.matches(&req("api.example.com", "GET", "/", None), Some("api*")));
        assert!(m.matches(&req("apiv2.com", "GET", "/", None), Some("api*")));
        assert!(!m.matches(&req("ap.example.com", "GET", "/", None), Some("api*")));
        // 大小写不敏感到达新星形态（ci 贯穿全分发）。
        assert!(m.matches(
            &req("API.V2.Example.COM", "GET", "/", None),
            Some("api.*.example.com")
        ));
    }

    // F1 锁定：大小写变体不旁路（DNS 名称等价类，RFC 4343——SNI 为 Agent
    // 可构造输入，字节比较将旁路黑名单）。
    #[test]
    fn domain_matching_is_case_insensitive() {
        let m = DomainMatcher;
        // 精确：大小写变体命中同一域名。
        assert!(m.matches(&req("EXAMPLE.com", "GET", "/", None), Some("example.com")));
        assert!(m.matches(&req("Example.COM", "GET", "/", None), Some("example.com")));
        // 通配：大小写变体子域命中。
        assert!(m.matches(
            &req("a.EXAMPLE.com", "GET", "/", None),
            Some("*.example.com")
        ));
        assert!(m.matches(
            &req("A.Example.Com", "GET", "/", None),
            Some("*.Example.com")
        ));
    }

    // F2 翻转（2026-09-05 决策：空标签防御不保留——纯 glob 语义）：
    // 空标签/双点主机命中通配；尾点 FQDN 仍不命中（glob 天然边界：
    // 不以 .example.com 结尾）。
    #[test]
    fn domain_wildcard_matches_empty_label_hosts() {
        let m = DomainMatcher;
        assert!(m.matches(&req(".example.com", "GET", "/", None), Some("*.example.com")));
        assert!(m.matches(&req("..example.com", "GET", "/", None), Some("*.example.com")));
        assert!(m.matches(&req("a..example.com", "GET", "/", None), Some("*.example.com")));
        // 尾点 FQDN 保守不命中。
        assert!(!m.matches(&req("a.example.com.", "GET", "/", None), Some("*.example.com")));
    }

    // F3 翻转（2026-09-05 决策：裸 * = 全匹配——与 method 对齐；原
    // 「字面精确永不匹配」防旁路语义退役，裸 * 已是合法显式全匹配配置）。
    #[test]
    fn domain_bare_star_matches_all() {
        let m = DomainMatcher;
        assert!(m.matches(&req("a.com", "GET", "/", None), Some("*")));
        assert!(m.matches(&req("anything.example.com", "GET", "/", None), Some("*")));
        // 退化形态 `*.`（空后缀）：命中以点结尾的畸形主机（纯 glob）。
        assert!(!m.matches(&req("a.com", "GET", "/", None), Some("*.")));
    }

    // TC4：uri 匹配语义（表驱动：前缀/后缀/中间星/裸值精确/query 不
    // 参与/特殊字符字面——2026-09-05 统一 glob）。
    #[test]
    fn tc4_uri_matching_semantics() {
        let m = UriMatcher;
        let cases: &[(&str, &str, bool)] = &[
            // 前缀 "/v1/*"。
            ("/v1/*", "/v1/chat", true),
            ("/v1/*", "/v1/chat?x=1", true), // query 剥离后命中
            ("/v1/*", "/v1/chat/sub", true),
            ("/v1/*", "/v2/chat", false),
            ("/v1/*", "/v1", false), // 不以 /v1/ 开头
            // 后缀 "*.js"。
            ("*.js", "/script.js", true),
            ("*.js", "/script.js?a=b", true),
            ("*.js", "/v1/chat", false),
            ("*.js", "/v1/chat?x=.js", false), // query 不能伪造后缀
            // 裸值精确 "/v1/chat"。
            ("/v1/chat", "/v1/chat", true),
            ("/v1/chat", "/v1/chat?x=1", true),
            ("/v1/chat", "/v1/chat/sub", false),
            ("/v1/chat", "/v2/chat", false),
            // 中间星 "/one/box/*/v1"（* 任意序列含 / 与空串）。
            ("/one/box/*/v1", "/one/box/a/v1", true),
            ("/one/box/*/v1", "/one/box/a/b/v1", true),  // 跨段
            ("/one/box/*/v1", "/one/box//v1", true),     // 空串
            ("/one/box/*/v1", "/one/box/a/v1?x=1", true), // query 剥离
            ("/one/box/*/v1", "/one/box/v1", false),     // 结构不符（空标签外的段缺失）
            ("/one/box/*/v1", "/one/box/a/v2", false),
            // 特殊字符字面（globset 转义——[ ] { } 不作 glob 语法；
            // ? 无法直测：URL 路径中即 query 分隔符——字面性归 glob.rs 单测）。
            ("/box/*/v[1]", "/box/x/v[1]", true),
            ("/box/*/v[1]", "/box/x/v1", false), // 非字符类
            ("/box/*/{v}", "/box/x/{v}", true),
            ("/box/*/{v}", "/box/x/v", false), // 非交替
            // 裸 * = 全匹配（三维统一）。
            ("*", "/anything/at/all", true),
        ];
        for (pattern, path, expected) in cases {
            assert_eq!(
                m.matches(&req("a.com", "GET", path, None), Some(pattern)),
                *expected,
                "pattern={pattern:?} path={path:?}"
            );
        }
        // 未声明维度：全匹配。
        assert!(m.matches(&req("a.com", "GET", "/anything", None), None));
    }

    // method 维度语义（精确 / `*` / 未声明 / 单星任意位置；大小写敏感全等）。
    #[test]
    fn method_matcher_semantics() {
        let m = MethodMatcher;
        assert!(m.matches(&req("a.com", "GET", "/", None), Some("GET")));
        assert!(!m.matches(&req("a.com", "get", "/", None), Some("GET"))); // 精确全等
        assert!(m.matches(&req("a.com", "POST", "/", None), Some("*")));
        assert!(m.matches(&req("a.com", "GET", "/", None), None));
        // 单星任意位置（2026-09-05 统一 glob——大小写敏感）。
        assert!(m.matches(&req("a.com", "GET", "/", None), Some("G*T")));
        assert!(m.matches(&req("a.com", "GET", "/", None), Some("GET*")));
        assert!(m.matches(&req("a.com", "POST", "/", None), Some("*T")));
        assert!(!m.matches(&req("a.com", "get", "/", None), Some("G*T"))); // cs
        assert!(!m.matches(&req("a.com", "PUT", "/", None), Some("GET*")));
    }

    // binary 维度语义（D2 场景差异的条件级行为；TC5/TC-015 的求值级断言归 T2）。
    #[test]
    fn binary_matcher_dimension_semantics() {
        let m = BinaryMatcher;
        // 场景一（无 binary_path）：含条件条目的该维度恒通过（忽略=条件永真）。
        assert!(m.matches(&req("a.com", "GET", "/", None), Some("python3")));
        // 场景二：精确匹配。
        assert!(m.matches(
            &req("a.com", "GET", "/", Some("python3")),
            Some("python3")
        ));
        assert!(!m.matches(&req("a.com", "GET", "/", Some("curl")), Some("python3")));
        // 显式通配与未声明：全匹配。
        assert!(m.matches(&req("a.com", "GET", "/", Some("curl")), Some("*")));
        assert!(m.matches(&req("a.com", "GET", "/", Some("curl")), None));
    }

}
