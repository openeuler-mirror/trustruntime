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

//! UTF-8 字符索引/字节位置换算（BeDemo `UTF8Util.cpp` 移植）。
//!
//! Rust `&str` 保证合法 UTF-8，换算基于 `char_indices`；非边界字节位置
//! 向下取整（C++ 按前导字节步进，本实现输入恒为边界，仅为防御）。

pub(crate) fn count_chars(s: &str) -> usize {
    s.chars().count()
}

/// 字符索引 → 字节位置（越界收敛到串尾）。
pub(crate) fn char_index_to_byte_pos(s: &str, char_index: usize) -> usize {
    s.char_indices().nth(char_index).map_or(s.len(), |(i, _)| i)
}

/// 字节位置 → 字符索引（非边界向下取整）。
pub(crate) fn byte_pos_to_char_index(s: &str, byte_pos: usize) -> usize {
    let pos = floor_boundary(s, byte_pos.min(s.len()));
    s[..pos].chars().count()
}

fn floor_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions_ascii() {
        assert_eq!(count_chars("hello"), 5);
        assert_eq!(char_index_to_byte_pos("hello", 3), 3);
        assert_eq!(byte_pos_to_char_index("hello", 3), 3);
    }

    #[test]
    fn conversions_multibyte() {
        // 3 个汉字（9 字节）+ "ab"。
        let s = "身份证ab";
        assert_eq!(count_chars(s), 5);
        assert_eq!(s.len(), 11);
        assert_eq!(char_index_to_byte_pos(s, 3), 9);
        assert_eq!(byte_pos_to_char_index(s, 9), 3);
        // 越界与中文字节位置。
        assert_eq!(char_index_to_byte_pos(s, 99), s.len());
        assert_eq!(byte_pos_to_char_index(s, 1), 0);
        assert_eq!(byte_pos_to_char_index(s, 4), 1);
    }
}
