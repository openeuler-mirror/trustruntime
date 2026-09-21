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

//! 配置校验（BeDemo `config_validator.cpp` 移植——全量规则，错误聚合后一次性抛出）。

use std::sync::OnceLock;

use super::error::ConfigError;
use super::model::{Config, Pattern};

/// 收集全部校验错误（C++ errors_ 向量语义）。
pub(crate) fn validate(config: &Config) -> Result<(), ConfigError> {
    let mut errors = Vec::new();

    validate_routing_policy(&config.routing_policy, &mut errors);
    validate_models(&config.models, &mut errors);
    validate_sensitive_patterns(&config.sensitive_patterns.patterns, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::Validation(errors.join("; ")))
    }
}

fn validate_routing_policy(rp: &super::model::RoutingPolicyConfig, errors: &mut Vec<String>) {
    check_semver("routing_policy.version", &rp.version, errors);

    if rp.strategies.is_empty() {
        errors.push("routing_policy.strategies: must have at least one strategy".to_string());
    }

    let mut seen_ids = Vec::new();
    for s in &rp.strategies {
        let prefix = format!("strategy[{}]", s.strategy_id);

        if s.strategy_id.is_empty() {
            errors.push("strategy.strategy_id: is required".to_string());
        } else if !is_alnum_underscore(&s.strategy_id) {
            errors.push(format!(
                "strategy.strategy_id: {} must be alphanumeric/underscore only",
                s.strategy_id
            ));
        } else {
            check_string_length(&format!("{prefix}.strategy_id"), &s.strategy_id, 32, errors);
        }

        if seen_ids.contains(&s.strategy_id) {
            errors.push(format!(
                "strategy.strategy_id: {} is duplicated",
                s.strategy_id
            ));
        } else {
            seen_ids.push(s.strategy_id.clone());
        }

        check_string_length(&format!("{prefix}.name"), &s.name, 64, errors);

        if !(1..=100).contains(&s.priority) {
            errors.push(format!("{prefix}.priority: {} must be 1-100", s.priority));
        }

        check_enum(
            &format!("{prefix}.condition.request_format"),
            s.condition.request_format.as_deref().unwrap_or("any"),
            &["openai", "anthropic", "any"],
            errors,
        );

        if let Some(cond_model) = &s.condition.model_id {
            if cond_model.is_empty() {
                errors.push(format!(
                    "{prefix}.condition.model_id: must not be empty when present"
                ));
            } else {
                check_string_length(
                    &format!("{prefix}.condition.model_id"),
                    cond_model,
                    32,
                    errors,
                );
            }
        }

        check_enum(
            &format!("{prefix}.action.target"),
            &s.action.target,
            &["local", "cloud", "cloud_with_sanitization"],
            errors,
        );

        if s.action.model_id.is_empty() {
            errors.push(format!("{prefix}.action.model_id: is required"));
        }
    }

    for dp in &rp.default_priority {
        if !seen_ids.contains(dp) {
            errors.push(format!("default_priority: {dp} is not a valid strategy_id"));
        }
    }
}

fn validate_models(
    models: &std::collections::HashMap<String, super::model::ModelConfig>,
    errors: &mut Vec<String>,
) {
    if models.is_empty() {
        errors.push("models: must have at least one model".to_string());
        return;
    }

    for (id, m) in models {
        let prefix = format!("model[{id}]");

        if m.model_id.is_empty() {
            errors.push("model.model_id: is required".to_string());
        } else {
            check_string_length(&format!("{prefix}.model_id"), &m.model_id, 32, errors);
        }

        check_string_length(&format!("{prefix}.name"), &m.name, 64, errors);
        check_enum(
            &format!("{prefix}.type"),
            &m.type_,
            &["local", "cloud"],
            errors,
        );
        check_enum(
            &format!("{prefix}.provider"),
            &m.provider,
            &["openai", "anthropic", "custom"],
            errors,
        );
        check_string_length(&format!("{prefix}.endpoint"), &m.endpoint, 512, errors);

        if m.timeout_ms <= 0 {
            errors.push(format!("{prefix}.timeout_ms: must be positive"));
        }
        if m.max_retries < 0 {
            errors.push(format!("{prefix}.max_retries: must be non-negative"));
        }
    }
}

fn validate_sensitive_patterns(patterns: &[Pattern], errors: &mut Vec<String>) {
    if patterns.is_empty() {
        errors.push("sensitive_patterns.patterns: must have at least one pattern".to_string());
    }

    let mut seen_ids = Vec::new();
    for p in patterns {
        let prefix = format!("pattern[{}]", p.pattern_id);

        if p.pattern_id.is_empty() {
            errors.push("pattern.pattern_id: is required".to_string());
        } else {
            check_string_length(&format!("{prefix}.pattern_id"), &p.pattern_id, 32, errors);
        }

        if seen_ids.contains(&p.pattern_id) {
            errors.push(format!(
                "pattern.pattern_id: {} is duplicated",
                p.pattern_id
            ));
        } else {
            seen_ids.push(p.pattern_id.clone());
        }

        check_string_length(&format!("{prefix}.name"), &p.name, 64, errors);
        check_enum(
            &format!("{prefix}.severity"),
            &p.severity,
            &["low", "medium", "high"],
            errors,
        );

        if p.type_ == "custom" && p.regex.as_deref().unwrap_or("").is_empty() {
            errors.push(format!("{prefix}.regex: is required when type=custom"));
        }

        if let Some(desc) = &p.description {
            check_string_length(&format!("{prefix}.description"), desc, 256, errors);
        }
    }
}

fn check_string_length(field: &str, value: &str, max_len: usize, errors: &mut Vec<String>) {
    if value.len() > max_len {
        errors.push(format!(
            "{field}: length {} exceeds max {max_len}",
            value.len()
        ));
    }
}

fn check_enum(field: &str, value: &str, allowed: &[&str], errors: &mut Vec<String>) {
    if !allowed.contains(&value) {
        errors.push(format!(
            "{field}: '{value}' is not one of [{}]",
            allowed.join("/")
        ));
    }
}

fn check_semver(field: &str, value: &str, errors: &mut Vec<String>) {
    static SEMVER: OnceLock<regex::Regex> = OnceLock::new();
    let re = SEMVER.get_or_init(|| {
        // ASCII 数字类（对齐 C++ ECMAScript \d 语义，避免 Unicode 数字误匹配）。
        regex::Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+$").expect("semver regex")
    });
    if !re.is_match(value) {
        errors.push(format!(
            "{field}: '{value}' is not a valid semver (MAJOR.MINOR.PATCH)"
        ));
    }
}

fn is_alnum_underscore(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}
