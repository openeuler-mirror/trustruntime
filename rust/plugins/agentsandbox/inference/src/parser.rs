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

//! 请求解析（BeDemo `model_request_parser.cpp` 移植）。
//!
//! 格式判定（有序规则，命中即停）+ user 消息 text 块提取。段序不变量：
//! 段顺序 = 消息顺序 × 消息内 text 块顺序；非 text 块（image/audio/
//! document）不贡献段。解析失败由路由层收敛为 Block（fail-closed）。

use http::HeaderMap;
use serde_json::Value;

/// 请求格式（openai / anthropic）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum RequestFormat {
    #[default]
    OpenAI,
    Anthropic,
}

/// 解析产物：格式 + 用户输入文本段列表。
#[derive(Debug, Clone, Default)]
pub(crate) struct ParsedModelRequest {
    pub format: RequestFormat,
    pub payloads: Vec<String>,
}

/// 解析失败原因（固定文案，不含请求内容——日志安全）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ParseError {
    #[error("request body is not a valid JSON object")]
    NotJsonObject,
    #[error("messages is required and must be an array")]
    MessagesRequired,
    #[error("no user message found in messages")]
    NoUserMessage,
}

/// 解析入口：body（LLM 请求 JSON）+ 请求头（格式判定辅助）。
pub(crate) fn parse(body: &str, headers: &HeaderMap) -> Result<ParsedModelRequest, ParseError> {
    let doc: Value = serde_json::from_str(body).map_err(|_| ParseError::NotJsonObject)?;
    if !doc.is_object() {
        return Err(ParseError::NotJsonObject);
    }

    let messages = doc
        .get("messages")
        .and_then(Value::as_array)
        .ok_or(ParseError::MessagesRequired)?;

    let mut result = ParsedModelRequest {
        format: detect_format(&doc, headers),
        payloads: Vec::new(),
    };

    let mut has_user_message = false;
    for message in messages {
        let Some(message_obj) = message.as_object() else {
            continue;
        };
        if message_obj.get("role").and_then(Value::as_str) != Some("user") {
            continue;
        }
        has_user_message = true;
        if let Some(content) = message_obj.get("content") {
            extract_content_segments(content, &mut result.payloads);
        }
    }
    if !has_user_message {
        return Err(ParseError::NoUserMessage);
    }

    Ok(result)
}

/// 格式判定（规则 1-3 body 启发式 → 规则 4-6 header 辅助，命中即停）。
fn detect_format(body: &Value, headers: &HeaderMap) -> RequestFormat {
    // 规则 1：messages 内存在 message 级 system 角色 → OpenAI
    //（anthropic 的 system 只在顶层）。
    if let Some(messages) = body.get("messages").and_then(Value::as_array) {
        let has_system_role = messages.iter().any(|m| {
            m.as_object()
                .and_then(|o| o.get("role"))
                .and_then(Value::as_str)
                == Some("system")
        });
        if has_system_role {
            return RequestFormat::OpenAI;
        }
    }
    // 规则 2：顶层 system 为 string 或 array → Anthropic。
    if let Some(system) = body.get("system") {
        if system.is_string() || system.is_array() {
            return RequestFormat::Anthropic;
        }
    }
    // 规则 3：max_tokens 为数字 → Anthropic。
    if body.get("max_tokens").is_some_and(Value::is_number) {
        return RequestFormat::Anthropic;
    }
    // 规则 4：host 含 "anthropic" 或存在 x-api-key 头 → Anthropic。
    let host = headers.get("host").and_then(|v| v.to_str().ok());
    if host.is_some_and(|h| h.to_ascii_lowercase().contains("anthropic"))
        || headers.contains_key("x-api-key")
    {
        return RequestFormat::Anthropic;
    }
    // 规则 5：存在 authorization 头 → OpenAI。
    if headers.contains_key("authorization") {
        return RequestFormat::OpenAI;
    }
    // 规则 6：默认 OpenAI。
    RequestFormat::OpenAI
}

/// 从单条消息 content 提取文本段：
/// string → 单段；array → 每个含字符串 text 字段的 text 块独立一段；
/// 其他类型 → 空（该消息不贡献段，维持段位置不变量）。
fn extract_content_segments(content: &Value, segments: &mut Vec<String>) {
    match content {
        Value::String(s) => segments.push(s.clone()),
        Value::Array(blocks) => {
            for block in blocks {
                let block_obj = block.as_object();
                let is_text = block_obj
                    .and_then(|o| o.get("type"))
                    .and_then(Value::as_str)
                    == Some("text");
                if is_text {
                    if let Some(text) = block_obj
                        .and_then(|o| o.get("text"))
                        .and_then(Value::as_str)
                    {
                        segments.push(text.to_string());
                    }
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    fn parse_ok(body: &str, headers: &HeaderMap) -> ParsedModelRequest {
        parse(body, headers).unwrap()
    }

    #[test]
    fn openai_basic() {
        let parsed = parse_ok(
            r#"{"model":"gpt-4o","messages":[
                {"role":"system","content":"be strict"},
                {"role":"user","content":"hello"},
                {"role":"assistant","content":"hi"}]}"#,
            &headers(&[("host", "api.openai.com")]),
        );
        assert_eq!(parsed.format, RequestFormat::OpenAI);
        assert_eq!(parsed.payloads, vec!["hello".to_string()]);
    }

    #[test]
    fn anthropic_basic_top_level_system() {
        let parsed = parse_ok(
            r#"{"system":"be strict","max_tokens":1024,"messages":[
                {"role":"user","content":"hello"}]}"#,
            &headers(&[("host", "api.anthropic.com")]),
        );
        assert_eq!(parsed.format, RequestFormat::Anthropic);
        assert_eq!(parsed.payloads, vec!["hello".to_string()]);
    }

    #[test]
    fn anthropic_block_content() {
        let parsed = parse_ok(
            r#"{"system":"s","messages":[{"role":"user","content":[
                {"type":"text","text":"first"},
                {"type":"image","source":{"type":"base64"}},
                {"type":"text","text":"second"}]}]}"#,
            &HeaderMap::new(),
        );
        assert_eq!(parsed.format, RequestFormat::Anthropic);
        assert_eq!(
            parsed.payloads,
            vec!["first".to_string(), "second".to_string()]
        );
    }

    #[test]
    fn format_detection_ordered_rules() {
        let empty = HeaderMap::new();
        // 规则 1 优先于规则 2：message 级 system + 顶层 system → OpenAI。
        let parsed = parse_ok(
            r#"{"system":"x","messages":[{"role":"system","content":"s"},
                {"role":"user","content":"u"}]}"#,
            &empty,
        );
        assert_eq!(parsed.format, RequestFormat::OpenAI);
        // 规则 2：顶层 system 为数字 → 不命中，继续判定。
        let parsed = parse_ok(
            r#"{"system":1,"messages":[{"role":"user","content":"u"}]}"#,
            &empty,
        );
        assert_eq!(parsed.format, RequestFormat::OpenAI);
        // 规则 3：max_tokens 数字 → Anthropic（无 header 佐证时）。
        let parsed = parse_ok(
            r#"{"max_tokens":100,"messages":[{"role":"user","content":"u"}]}"#,
            &empty,
        );
        assert_eq!(parsed.format, RequestFormat::Anthropic);
        // 规则 3 不命中：max_tokens 非数字。
        let parsed = parse_ok(
            r#"{"max_tokens":"100","messages":[{"role":"user","content":"u"}]}"#,
            &empty,
        );
        assert_eq!(parsed.format, RequestFormat::OpenAI);
    }

    #[test]
    fn header_format_detection() {
        let body = r#"{"messages":[{"role":"user","content":"u"}]}"#;
        // 规则 4a：host 含 anthropic → Anthropic。
        assert_eq!(
            parse_ok(body, &headers(&[("host", "API.Anthropic.com")])).format,
            RequestFormat::Anthropic
        );
        // 规则 4b：x-api-key 头 → Anthropic。
        assert_eq!(
            parse_ok(body, &headers(&[("host", "any.host"), ("x-api-key", "k")])).format,
            RequestFormat::Anthropic
        );
        // 规则 5：authorization 头 → OpenAI。
        assert_eq!(
            parse_ok(
                body,
                &headers(&[("host", "any.host"), ("authorization", "Bearer t")])
            )
            .format,
            RequestFormat::OpenAI
        );
        // 规则 6：默认 OpenAI。
        assert_eq!(
            parse_ok(body, &headers(&[("host", "any.host")])).format,
            RequestFormat::OpenAI
        );
    }

    #[test]
    fn multi_user_messages_in_order() {
        let parsed = parse_ok(
            r#"{"messages":[
                {"role":"user","content":"one"},
                {"role":"assistant","content":"mid"},
                {"role":"user","content":[{"type":"text","text":"two"},{"type":"text","text":"three"}]}]}"#,
            &HeaderMap::new(),
        );
        assert_eq!(
            parsed.payloads,
            vec!["one".to_string(), "two".to_string(), "three".to_string()]
        );
    }

    #[test]
    fn parse_errors() {
        let empty = HeaderMap::new();
        assert_eq!(
            parse("not a json", &empty).unwrap_err(),
            ParseError::NotJsonObject
        );
        assert_eq!(
            parse("[1,2]", &empty).unwrap_err(),
            ParseError::NotJsonObject
        );
        assert_eq!(
            parse(r#"{"no_messages":1}"#, &empty).unwrap_err(),
            ParseError::MessagesRequired
        );
        assert_eq!(
            parse(r#"{"messages":"not-array"}"#, &empty).unwrap_err(),
            ParseError::MessagesRequired
        );
        assert_eq!(
            parse(
                r#"{"messages":[{"role":"assistant","content":"x"}]}"#,
                &empty
            )
            .unwrap_err(),
            ParseError::NoUserMessage
        );
        // user 消息无 content：合法（不贡献段，但存在 user 消息）。
        let parsed = parse_ok(r#"{"messages":[{"role":"user"}]}"#, &empty);
        assert!(parsed.payloads.is_empty());
    }
}
