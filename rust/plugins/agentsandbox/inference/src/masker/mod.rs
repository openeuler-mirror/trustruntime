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

//! 敏感数据识别与脱敏（BeDemo `TextIdentify.cpp` + `text_identify_masker.cpp`
//! 移植）。
//!
//! 算法：关键词命中（大小写不敏感）→ 以命中点为中心取 `key_dist` 字符
//! 窗口 → 窗口内同 pattern 正则扫描 → 实体校验（边界/长度）→ 全局去重
//! （start 升序、长度降序贪心不重叠）→ 替换为 `[PII_{pattern_id}]`。

mod engine;
mod utf8;
mod validator;

use std::collections::HashSet;

pub(crate) use engine::{Match, Mode, MultiEngine};
pub(crate) use validator::validate as validate_entity;

use crate::config::model::Pattern;

/// 脱敏器（一次构建，多次调用；`Send + Sync`）。
pub(crate) struct TextIdentify {
    patterns: Vec<Pattern>,
    keyword_engine: MultiEngine,
    keyword_to_pattern: Vec<usize>,
    regex_engine: MultiEngine,
    regex_to_pattern: Vec<usize>,
}

impl TextIdentify {
    /// 从敏感模式配置构建（仅启用项；无启用项或正则编译失败 → None，
    /// 调用方降级为 no-op 脱敏——对齐 C++ TextIdentifyMasker 语义）。
    pub(crate) fn from_patterns(config_patterns: &[Pattern]) -> Option<Self> {
        let patterns: Vec<Pattern> = config_patterns
            .iter()
            .filter(|p| p.enabled)
            .cloned()
            .collect();
        if patterns.is_empty() {
            log::warn!("masker: no enabled sensitive patterns, mask will be no-op");
            return None;
        }

        let mut keyword_patterns = Vec::new();
        let mut keyword_to_pattern = Vec::new();
        let mut regex_patterns = Vec::new();
        let mut regex_to_pattern = Vec::new();
        for (i, pattern) in patterns.iter().enumerate() {
            if let Some(keywords) = &pattern.keywords {
                for keyword in keywords {
                    keyword_patterns.push(keyword.clone());
                    keyword_to_pattern.push(i);
                }
            }
            if let Some(regex) = &pattern.regex {
                if !regex.is_empty() {
                    regex_patterns.push(regex.clone());
                    regex_to_pattern.push(i);
                }
            }
        }

        let keyword_engine = MultiEngine::compile(&keyword_patterns, Mode::Literal, true)?;
        let regex_engine = MultiEngine::compile(&regex_patterns, Mode::Regex, false)?;

        log::info!("masker initialized with {} patterns", patterns.len());
        Some(Self {
            patterns,
            keyword_engine,
            keyword_to_pattern,
            regex_engine,
            regex_to_pattern,
        })
    }

    /// 脱敏：识别并替换敏感实体（无命中时原样返回）。
    pub(crate) fn desensitize(&self, text: &str) -> String {
        if text.is_empty() {
            return text.to_string();
        }

        let total_chars = utf8::count_chars(text);
        let mut seen: HashSet<(usize, usize)> = HashSet::new();
        let mut all_matches: Vec<Match> = Vec::new();

        for kw_match in self.keyword_engine.scan(text) {
            let Some(&pattern_idx) = self.keyword_to_pattern.get(kw_match.id) else {
                continue;
            };
            let key_dist = self.patterns[pattern_idx].key_dist;

            let kw_start_char = utf8::byte_pos_to_char_index(text, kw_match.start);
            let kw_end_char = utf8::byte_pos_to_char_index(text, kw_match.end);
            let extract_start_char = kw_start_char.saturating_sub(key_dist);
            let extract_end_char = std::cmp::min(total_chars, kw_end_char + key_dist);
            let extract_start_byte = utf8::char_index_to_byte_pos(text, extract_start_char);
            let extract_end_byte = utf8::char_index_to_byte_pos(text, extract_end_char);
            let short_text = &text[extract_start_byte..extract_end_byte];

            for rm in self.regex_engine.scan(short_text) {
                let Some(&regex_pattern_idx) = self.regex_to_pattern.get(rm.id) else {
                    continue;
                };
                if regex_pattern_idx != pattern_idx {
                    continue;
                }

                let orig_start = extract_start_byte + rm.start;
                let orig_end = extract_start_byte + rm.end;
                if !seen.insert((orig_start, orig_end)) {
                    continue;
                }

                let matched_text = &text[orig_start..orig_end];
                let pattern_id = &self.patterns[pattern_idx].pattern_id;
                if !validate_entity(pattern_id, matched_text, text, orig_start, orig_end) {
                    continue;
                }
                all_matches.push(Match {
                    id: rm.id,
                    start: orig_start,
                    end: orig_end,
                });
            }
        }

        let final_matches = deduplicate_matches(all_matches);

        let mut result = String::with_capacity(text.len());
        let mut last_pos = 0usize;
        for m in &final_matches {
            result.push_str(&text[last_pos..m.start]);
            if let Some(&pattern_idx) = self.regex_to_pattern.get(m.id) {
                result.push_str("[PII_");
                result.push_str(&self.patterns[pattern_idx].pattern_id);
                result.push(']');
            } else {
                result.push_str(&text[m.start..m.end]);
            }
            last_pos = m.end;
        }
        result.push_str(&text[last_pos..]);
        result
    }
}

/// 去重：start 升序、长度降序排序后贪心选取互不重叠项。
fn deduplicate_matches(mut matches: Vec<Match>) -> Vec<Match> {
    matches.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then((b.end - b.start).cmp(&(a.end - a.start)))
    });
    let mut result: Vec<Match> = Vec::new();
    for m in matches {
        if result.is_empty() || m.start >= result.last().expect("non-empty").end {
            result.push(m);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(pattern_id: &str, regex: &str, keywords: &[&str], key_dist: usize) -> Pattern {
        Pattern {
            pattern_id: pattern_id.to_string(),
            name: pattern_id.to_string(),
            type_: pattern_id.to_string(),
            regex: Some(regex.to_string()),
            keywords: Some(keywords.iter().map(|s| s.to_string()).collect()),
            description: None,
            severity: "medium".to_string(),
            enabled: true,
            key_dist,
        }
    }

    fn masker(patterns: &[Pattern]) -> Option<TextIdentify> {
        TextIdentify::from_patterns(patterns)
    }

    // C++ test_inference_router 使用的两条模式（keyDist=20）。
    fn std_masker() -> Option<TextIdentify> {
        masker(&[
            pattern(
                "id_card",
                "[1-9][0-9]{5}(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx]",
                &["身份证"],
                20,
            ),
            pattern("mobile_phone", "1[3-9][0-9]{9}", &["手机"], 20),
        ])
    }

    #[test]
    fn masks_id_card_and_phone() {
        let masker = std_masker().unwrap();
        let out = masker.desensitize("我的身份证号是110101199003071234，手机号13800138000");
        assert_eq!(out, "我的身份证号是[PII_id_card]，手机号[PII_mobile_phone]");
    }

    #[test]
    fn no_keyword_no_match() {
        let masker = std_masker().unwrap();
        // 无关键词锚定 → 不脱敏（关键词窗口是必要条件）。
        let out = masker.desensitize("110101199003071234 裸数字无关键词");
        assert_eq!(out, "110101199003071234 裸数字无关键词");
    }

    #[test]
    fn multiple_matches_non_overlapping() {
        let masker = std_masker().unwrap();
        let out =
            masker.desensitize("身份证110101199003071234然后手机13800138000再手机13900139000");
        assert_eq!(
            out,
            "身份证[PII_id_card]然后手机[PII_mobile_phone]再手机[PII_mobile_phone]"
        );
    }

    #[test]
    fn keyword_case_insensitive() {
        let masker = masker(&[pattern(
            "email",
            "[a-z]+@[a-z]+\\.[a-z]{2,3}",
            &["Email"],
            30,
        )])
        .unwrap();
        let out = masker.desensitize("EMAIL: someone@example.com here");
        assert!(out.contains("[PII_email]"), "got: {out}");
        // 大小写折叠只作用于关键词锚定："E-MAIL" 不含字面量 "email" → 不脱敏。
        let out = masker.desensitize("E-MAIL: someone@example.com here");
        assert_eq!(out, "E-MAIL: someone@example.com here");
    }

    #[test]
    fn key_dist_window_limits_detection() {
        // keyDist=20：关键词紧邻号码 → 窗口完整覆盖 → 脱敏。
        let masker = masker(&[pattern("id_card", "[0-9]{18}", &["身份证"], 20)]).unwrap();
        assert_eq!(
            masker.desensitize("身份证110101199003071234"),
            "身份证[PII_id_card]"
        );
        // 关键词与号码相隔 5 个汉字 → 窗口（20 字符）只覆盖到号码第 15 位
        // → 18 位正则无法完整命中 → 不脱敏。
        let far = "身份证号太远了：110101199003071234";
        assert_eq!(masker.desensitize(far), far);
    }

    #[test]
    fn disabled_patterns_skipped() {
        let mut p = pattern("id_card", "[0-9]{18}", &["身份证"], 20);
        p.enabled = false;
        assert!(masker(&[p]).is_none(), "全部禁用 → no-op 脱敏器");
    }

    #[test]
    fn empty_and_clean_text_passthrough() {
        let masker = std_masker().unwrap();
        assert_eq!(masker.desensitize(""), "");
        let clean = "你好今天天气怎么样";
        assert_eq!(masker.desensitize(clean), clean);
    }

    #[test]
    fn shipped_default_patterns_compile() {
        // 交付默认 sensitive_patterns.json 的全部启用模式可编译且基本可用。
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("resources/config/sensitive_patterns.json");
        let content = std::fs::read_to_string(root).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&content).unwrap();
        let mut patterns = Vec::new();
        for item in doc["patterns"].as_array().unwrap() {
            let kw = item["keywords"].as_array().map(|a| {
                a.iter()
                    .filter_map(|k| k.as_str().map(String::from))
                    .collect()
            });
            patterns.push(Pattern {
                pattern_id: item["pattern_id"].as_str().unwrap().to_string(),
                name: String::new(),
                type_: String::new(),
                regex: item["regex"].as_str().map(String::from),
                keywords: kw,
                description: None,
                severity: "medium".to_string(),
                enabled: item["enabled"].as_bool().unwrap_or(true),
                key_dist: item["keyDist"].as_u64().unwrap_or(50) as usize,
            });
        }
        let masker = TextIdentify::from_patterns(&patterns).expect("默认模式集应可编译");
        let out = masker.desensitize("我的身份证号是110101199003071234");
        assert_eq!(out, "我的身份证号是[PII_id_card]");
        let out = masker.desensitize("邮箱 someone@example.com 联系");
        assert!(out.contains("[PII_email]"), "got: {out}");
    }
}
