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

//! 实体校验（BeDemo `EntityValidator.cpp` 移植）。
//!
//! 行为保真说明：C++ 硬编码 patternId（`ID_Card`/`Phone`/`Email`/
//! `Bank_Card`）与实际配置 `pattern_id`（`id_card` 等小写下划线风格）
//! 大小写不匹配，实际恒走默认边界校验——本实现照抄，保持行为一致。

/// 校验是否接受该匹配（true = 有效）。
pub(crate) fn validate(
    pattern_id: &str,
    matched_text: &str,
    full_text: &str,
    match_start: usize,
    match_end: usize,
) -> bool {
    match pattern_id {
        "ID_Card" => validate_id_card(matched_text, full_text, match_start, match_end),
        "Phone" => validate_phone(matched_text, full_text, match_start, match_end),
        "Email" => validate_email(matched_text, full_text, match_start, match_end),
        "Bank_Card" => validate_bank_card(matched_text, full_text, match_start, match_end),
        _ => validate_default(matched_text, full_text, match_start, match_end),
    }
}

fn is_digit_at(text: &str, byte_pos: usize) -> bool {
    text.as_bytes()
        .get(byte_pos)
        .is_some_and(|b| b.is_ascii_digit())
}

fn is_alnum_at(text: &str, byte_pos: usize) -> bool {
    text.as_bytes()
        .get(byte_pos)
        .is_some_and(|b| b.is_ascii_alphanumeric())
}

fn validate_id_card(matched_text: &str, full_text: &str, start: usize, end: usize) -> bool {
    if matched_text.len() != 18 {
        return false;
    }
    if start
        .checked_sub(1)
        .is_some_and(|i| is_digit_at(full_text, i))
        || is_digit_at(full_text, end)
    {
        return false;
    }
    true
}

fn validate_phone(matched_text: &str, full_text: &str, start: usize, end: usize) -> bool {
    if matched_text.len() != 11 {
        return false;
    }
    if start
        .checked_sub(1)
        .is_some_and(|i| is_digit_at(full_text, i))
        || is_digit_at(full_text, end)
    {
        return false;
    }
    true
}

fn validate_email(matched_text: &str, full_text: &str, start: usize, end: usize) -> bool {
    if !matched_text.contains('@') {
        return false;
    }
    if start
        .checked_sub(1)
        .is_some_and(|i| is_alnum_at(full_text, i))
        || is_alnum_at(full_text, end)
    {
        return false;
    }
    true
}

fn validate_bank_card(matched_text: &str, full_text: &str, start: usize, end: usize) -> bool {
    let len = matched_text.len();
    if !(16..=19).contains(&len) {
        return false;
    }
    if start
        .checked_sub(1)
        .is_some_and(|i| is_digit_at(full_text, i))
        || is_digit_at(full_text, end)
    {
        return false;
    }
    true
}

fn validate_default(matched_text: &str, full_text: &str, start: usize, end: usize) -> bool {
    if matched_text.is_empty() {
        return false;
    }
    let left_boundary = start == 0 || !is_alnum_at(full_text, start - 1);
    let right_boundary = end >= full_text.len() || !is_alnum_at(full_text, end);
    left_boundary && right_boundary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_boundary_validation() {
        // "x110101..." 左邻 ASCII 字母数字 → 拒绝（截断嫌疑）。
        assert!(!validate(
            "id_card",
            "110101199003071234",
            "x110101199003071234",
            1,
            19
        ));
        // 两侧汉字（非 ASCII 字母数字）→ 接受（"号是" 6 字节 + 18 位数字）。
        assert!(validate(
            "id_card",
            "110101199003071234",
            "号是110101199003071234，完",
            6,
            24
        ));
        // 边界即串首/串尾 → 接受。
        assert!(validate(
            "id_card",
            "110101199003071234",
            "110101199003071234",
            0,
            18
        ));
    }

    #[test]
    fn known_ids_use_special_rules() {
        // 长度不符 → 拒绝（即便边界干净）。
        assert!(!validate("ID_Card", "123", "x123y", 1, 4));
        assert!(validate(
            "ID_Card",
            "110101199003071234",
            "a110101199003071234b",
            1,
            19
        ));
        // Email 必须含 @。
        assert!(!validate("Email", "no-at-sign", "x no-at-sign y", 2, 12));
        assert!(validate("Email", "a@b.com", "联系 a@b.com 谢谢", 7, 14));
        // Bank_Card 长度 16-19。
        assert!(!validate("Bank_Card", "1234", "x1234y", 1, 5));
        assert!(validate(
            "Bank_Card",
            "6222020000000000",
            "卡6222020000000000。",
            3,
            19
        ));
    }
}
