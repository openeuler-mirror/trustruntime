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

//! 多模式匹配引擎（BeDemo `HyperscanEngine.cpp` 的 `#else` std::regex
//! 回退路径移植——`regex` crate 实现，无 C 依赖）。
//!
//! - `Literal` 模式：大小写可配置的子串搜索（重叠推进：`found + 1`）；
//! - `Regex` 模式：每模式独立 `find_iter`（后继不重叠）。
//!
//! 语义对齐说明：ASCII 大小写折叠（`to_ascii_lowercase`）与 C++ C locale
//! `tolower` 逐字节等价且长度不变，匹配位置可直接映射回原文。

/// 单条命中（字节区间 [start, end)，id 为引擎内模式序号）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Match {
    pub id: usize,
    pub start: usize,
    pub end: usize,
}

/// 引擎模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// 字面量子串匹配。
    Literal,
    /// 正则匹配。
    Regex,
}

/// 多模式匹配引擎（一次编译，多次扫描；`Send + Sync`）。
pub(crate) struct MultiEngine {
    mode: Mode,
    case_insensitive: bool,
    literals: Vec<String>,
    regexes: Vec<regex::Regex>,
    ready: bool,
}

impl MultiEngine {
    /// 编译（空模式列表 → ready=false 的空引擎；正则编译失败 → None）。
    pub(crate) fn compile(patterns: &[String], mode: Mode, case_insensitive: bool) -> Option<Self> {
        if patterns.is_empty() {
            return Some(Self {
                mode,
                case_insensitive,
                literals: Vec::new(),
                regexes: Vec::new(),
                ready: false,
            });
        }
        let mut engine = Self {
            mode,
            case_insensitive,
            literals: Vec::new(),
            regexes: Vec::new(),
            ready: false,
        };
        match mode {
            Mode::Literal => {
                engine.literals = patterns.to_vec();
            }
            Mode::Regex => {
                for (i, pattern) in patterns.iter().enumerate() {
                    match regex::RegexBuilder::new(pattern)
                        .case_insensitive(case_insensitive)
                        .build()
                    {
                        Ok(re) => engine.regexes.push(re),
                        Err(e) => {
                            log::error!("masker regex compile failed at index {}: {}", i, e);
                            return None;
                        }
                    }
                }
            }
        }
        engine.ready = true;
        Some(engine)
    }

    /// 扫描（结果按 start 升序；空文本/未就绪 → 空）。
    pub(crate) fn scan(&self, text: &str) -> Vec<Match> {
        let mut matches = Vec::new();
        if !self.ready || text.is_empty() {
            return matches;
        }
        match self.mode {
            Mode::Literal => {
                let haystack = if self.case_insensitive {
                    text.to_ascii_lowercase()
                } else {
                    text.to_string()
                };
                for (id, pattern) in self.literals.iter().enumerate() {
                    if pattern.is_empty() {
                        continue;
                    }
                    let needle = if self.case_insensitive {
                        pattern.to_ascii_lowercase()
                    } else {
                        pattern.clone()
                    };
                    let mut pos = 0usize;
                    while pos <= haystack.len() {
                        match haystack[pos..].find(&needle) {
                            Some(offset) => {
                                let found = pos + offset;
                                matches.push(Match {
                                    id,
                                    start: found,
                                    end: found + needle.len(),
                                });
                                // 重叠推进至下一字符边界（C++ 逐字节 +1；
                                // UTF-8 下非边界起点不可能命中——合法串的
                                // 子串命中必起于边界，跳过中间字节等价）。
                                let mut next = found + 1;
                                while next < haystack.len() && !haystack.is_char_boundary(next) {
                                    next += 1;
                                }
                                pos = next;
                            }
                            None => break,
                        }
                    }
                }
            }
            Mode::Regex => {
                for (id, re) in self.regexes.iter().enumerate() {
                    for m in re.find_iter(text) {
                        matches.push(Match {
                            id,
                            start: m.start(),
                            end: m.end(),
                        });
                    }
                }
            }
        }
        matches.sort_by_key(|m| m.start);
        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_case_insensitive_overlapping() {
        let engine = MultiEngine::compile(
            &["ID number".to_string(), "手机".to_string()],
            Mode::Literal,
            true,
        )
        .unwrap();
        let matches = engine.scan("id NUMBER and ID number, 手机 ok");
        // "id NUMBER"（大小写折叠命中）+ "ID number" + "手机"。
        assert_eq!(matches.len(), 3);
        assert_eq!(matches[0].start, 0);
        assert_eq!(matches[1].start, 14);
        assert_eq!(matches[2].id, 1);

        // 重叠推进：needle 自重叠（"aa" 在 "aaa" 中命中 2 次）。
        let engine = MultiEngine::compile(&["aa".to_string()], Mode::Literal, false).unwrap();
        let matches = engine.scan("aaa");
        assert_eq!(matches.len(), 2);
        assert_eq!((matches[0].start, matches[0].end), (0, 2));
        assert_eq!((matches[1].start, matches[1].end), (1, 3));
    }

    #[test]
    fn literal_empty_engine_no_matches() {
        let engine = MultiEngine::compile(&[], Mode::Literal, true).unwrap();
        assert!(engine.scan("anything").is_empty());
        let engine = MultiEngine::compile(&["".to_string()], Mode::Literal, true).unwrap();
        assert!(engine.scan("anything").is_empty());
    }

    #[test]
    fn regex_scan_sorted_by_start() {
        let engine = MultiEngine::compile(
            &[r"[0-9]{4}".to_string(), r"[0-9]{2}".to_string()],
            Mode::Regex,
            false,
        )
        .unwrap();
        let matches = engine.scan("ab 12 cd 3456");
        // id1 "12" (3,5)；id1 "34" (9,11) 与 "56" (11,13)（find_iter 后继
        // 不重叠）；id0 "3456" (9,13)。按 start 升序（稳定排序，同 start
        // 保持收集序：id0 在前）。
        assert_eq!(matches.len(), 4);
        assert_eq!((matches[0].id, matches[0].start, matches[0].end), (1, 3, 5));
        assert_eq!(
            (matches[1].id, matches[1].start, matches[1].end),
            (0, 9, 13)
        );
        assert_eq!(
            (matches[2].id, matches[2].start, matches[2].end),
            (1, 9, 11)
        );
        assert_eq!(
            (matches[3].id, matches[3].start, matches[3].end),
            (1, 11, 13)
        );
    }

    #[test]
    fn regex_compile_failure_returns_none() {
        assert!(MultiEngine::compile(&["[invalid".to_string()], Mode::Regex, false).is_none());
    }
}
