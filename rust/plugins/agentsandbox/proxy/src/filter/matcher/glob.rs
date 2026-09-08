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

//! 单星 glob 匹配基建（globset 封装：字面转义 + 编译缓存；2026-09-05
//! 三维统一通配决策）。
//!
//! 语义：`*` 匹配**任意字符序列**（含 `/`、含空串——globset 默认
//! `literal_separator=false`，与 uri 前缀模式 `/v1/*` 的跨段行为一致）。
//!
//! 字面性保证：`?`/`[`/`]`/`{`/`}`/`\` 在 URL 路径与 DNS 名称中是合法
//! **字面**字符（历史实现按字面处理），构造 glob 前统一经 backslash
//! 转义（`backslash_escape(true)`），防被 globset 解释为单字符/字符类/
//! 交替语法。我方 `*`（校验层保证至多一个）保留为唯一通配符。
//!
//! 编译缓存：模式串来自 filter_config（条目数天然约束容量），按
//! (转义模式, 大小写标志) 全局缓存——热路径（每请求匹配）零重编译。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use globset::{GlobBuilder, GlobMatcher};

/// 转义 glob 特殊字符（`?`/`[`/`]`/`{`/`}`/`\` → backslash 转义字面；
/// `*` 保留为我方通配符）。
fn escape(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    for ch in pattern.chars() {
        match ch {
            '*' => out.push('*'),
            '?' | '[' | ']' | '{' | '}' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

/// 编译缓存键（转义模式 + 大小写标志）。
type CacheKey = (String, bool);

/// 全局编译缓存（pattern → matcher；容量受配置条目数约束）。
fn cache() -> &'static Mutex<HashMap<CacheKey, GlobMatcher>> {
    static CACHE: OnceLock<Mutex<HashMap<CacheKey, GlobMatcher>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 单星 glob 匹配（缓存编译；build 失败 → false 永不匹配——fail-closed，
/// 仅程序不变量破坏时可到达：全字面转义后理论不可失败）。
pub(crate) fn glob_match(pattern: &str, text: &str, case_insensitive: bool) -> bool {
    let key = (escape(pattern), case_insensitive);
    let mut guard = crate::lock_util::recovered(cache().lock(), "glob cache");
    if let Some(m) = guard.get(&key) {
        return m.is_match(text);
    }
    let Some(matcher) = GlobBuilder::new(&key.0)
        .case_insensitive(case_insensitive)
        .backslash_escape(true)
        .build()
        .ok()
        .map(|g| g.compile_matcher())
    else {
        crate::log_warn!("matcher", "glob build failed; pattern rejected");
        return false;
    };
    let hit = matcher.is_match(text);
    guard.insert(key, matcher);
    hit
}

#[cfg(test)]
mod tests {
    use super::*;

    // 通配范围：任意序列（跨 /、含空串、跨多段）。
    #[test]
    fn star_matches_any_sequence() {
        assert!(glob_match("a*b", "a-x-b", false));
        assert!(glob_match("a*b", "ab", false)); // 空串
        assert!(glob_match("a*b", "a/b", false)); // 跨 /
        assert!(glob_match("/one/box/*/v1", "/one/box/a/v1", false));
        assert!(glob_match("/one/box/*/v1", "/one/box/a/b/v1", false)); // 跨段
        assert!(glob_match("/one/box/*/v1", "/one/box//v1", false)); // 空串
        assert!(!glob_match("/one/box/*/v1", "/one/box/v1", false));
        assert!(!glob_match("/one/box/*/v1", "/one/box/a/v2", false));
    }

    // 字面性：? / [ ] / { } / \ 不作 glob 语法（转义后字面匹配）。
    #[test]
    fn special_chars_are_literal() {
        // ? 字面（非单字符通配）。
        assert!(glob_match("cat?", "cat?", false));
        assert!(!glob_match("cat?", "cats", false));
        assert!(glob_match("/box/*/v[1]", "/box/x/v[1]", false));
        assert!(!glob_match("/box/*/v[1]", "/box/x/v1", false)); // 非字符类
        // { } 字面（非交替）。
        assert!(glob_match("{a,b}", "{a,b}", false));
        assert!(!glob_match("{a,b}", "a", false));
        // \ 字面（转义后）。
        assert!(glob_match("a\\b", "a\\b", false));
        assert!(!glob_match("a\\b", "ab", false));
    }

    // 大小写标志：domain 语境 ci / uri·method 语境 cs。
    #[test]
    fn case_sensitivity_flag() {
        assert!(glob_match("*.example.com", "A.Example.COM", true));
        assert!(!glob_match("*.example.com", "A.Example.COM", false));
        // cs：首字符小写不命中；星区字符不影响大小写边界。
        assert!(!glob_match("G*T", "geT", false));
        assert!(glob_match("G*T", "GET", false));
        assert!(glob_match("G*T", "GeT", false));
        assert!(glob_match("g*t", "GeT", true));
    }

    // 纯 glob 边界（空标签防御不保留——2026-09-05 决策）：空标签/双点
    // 主机命中通配；裸域/串扰/尾点仍不命中（glob 天然边界）。
    #[test]
    fn pure_glob_domain_boundaries() {
        assert!(glob_match("*.example.com", "..example.com", true));
        assert!(glob_match("*.example.com", "a..example.com", true));
        assert!(!glob_match("*.example.com", "example.com", true));
        assert!(!glob_match("*.example.com", "aexample.com", true));
        assert!(!glob_match("*.example.com", "a.example.com.", true));
        // 无点星：命中裸域与任意前缀（标准 glob）。
        assert!(glob_match("*example.com", "example.com", true));
        assert!(glob_match("*example.com", "aexample.com", true));
    }

    // 编译缓存：同模式二次调用命中缓存（行为等价——间接经重复断言覆盖）。
    #[test]
    fn cache_reuses_compiled_matcher() {
        assert!(glob_match("/a/*/c", "/a/b/c", false));
        assert!(glob_match("/a/*/c", "/a/b/c", false));
        assert!(!glob_match("/a/*/c", "/a/b", false));
        assert!(!cache().lock().unwrap().is_empty());
    }
}
