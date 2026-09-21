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

//! 配置文件加载与宽松提取（BeDemo `config_loader.cpp` 移植）。
//!
//! 提取语义对齐 C++：字段缺失或类型不符时取默认值（不报错），结构性
//! 错误（根非对象等）收敛为 [`ConfigError::Parse`]，业务约束由
//! [`crate::config::validator`] 兜底。

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;

use super::error::ConfigError;
use super::model::{Action, Condition, Config, ModelConfig, Pattern, Strategy};
use super::validator;

/// 单文件路径长度上限（对齐 C++ `MAX_PATH_LEN`）。
const MAX_PATH_LEN: usize = 256;

/// 读取必需文件（缺失/路径过长/IO 错误 → [`ConfigError::Load`]）。
pub(crate) fn load_file(path: &Path, file: &'static str) -> Result<String, ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::Load { file });
    }
    if path.as_os_str().len() > MAX_PATH_LEN {
        return Err(ConfigError::Load { file });
    }
    std::fs::read_to_string(path).map_err(|_| ConfigError::Load { file })
}

/// 读取可选文件（缺失 → 空串；api_keys.json 初次部署允许不存在）。
pub(crate) fn load_file_optional(path: &Path, file: &'static str) -> Result<String, ConfigError> {
    if path.as_os_str().is_empty() {
        return Ok(String::new());
    }
    if path.as_os_str().len() > MAX_PATH_LEN {
        return Err(ConfigError::Load { file });
    }
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(_) => Ok(String::new()),
    }
}

/// JSON 解析（失败 → [`ConfigError::Parse`]）。
pub(crate) fn parse_json(content: &str, file: &'static str) -> Result<Value, ConfigError> {
    serde_json::from_str(content).map_err(|_| ConfigError::Parse { file })
}

/// 四文件聚合加载入口：读文件 → 解析 → 建模 → 校验。
pub(crate) fn load_config(
    routing_policy_path: &Path,
    model_config_path: &Path,
    sensitive_patterns_path: &Path,
    api_keys_path: &Path,
) -> Result<Config, ConfigError> {
    let rp_content = load_file(routing_policy_path, "routing_policy.json")?;
    let mc_content = load_file(model_config_path, "model_config.json")?;
    let sp_content = load_file(sensitive_patterns_path, "sensitive_patterns.json")?;
    let ak_content = load_file_optional(api_keys_path, "api_keys.json")?;
    load_config_from_contents(
        &rp_content,
        &mc_content,
        &sp_content,
        &ak_content,
        api_keys_path,
    )
}

/// 内容式加载入口（默认配置内嵌路径——三份只读配置以 `include_str!`
/// 提供，api_keys 以内容 + 可写路径分离）。
pub(crate) fn load_config_from_contents(
    rp_content: &str,
    mc_content: &str,
    sp_content: &str,
    ak_content: &str,
    api_keys_path: &Path,
) -> Result<Config, ConfigError> {
    let rp = parse_json(rp_content, "routing_policy.json")?;
    let mc = parse_json(mc_content, "model_config.json")?;
    let sp = parse_json(sp_content, "sensitive_patterns.json")?;
    let ak = if ak_content.is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        parse_json(ak_content, "api_keys.json")?
    };

    let config = build_config(&rp, &mc, &sp, &ak, api_keys_path)?;
    validator::validate(&config)?;
    Ok(config)
}

/// 聚合建模（根非对象 → Parse 错误）。
fn build_config(
    rp: &Value,
    mc: &Value,
    sp: &Value,
    ak: &Value,
    api_keys_path: &Path,
) -> Result<Config, ConfigError> {
    let mut config = Config {
        api_keys_path: api_keys_path.to_path_buf(),
        ..Config::default()
    };

    if !rp.is_object() {
        return Err(ConfigError::Parse {
            file: "routing_policy.json",
        });
    }
    config.routing_policy.version = get_string(rp, "version");
    config.routing_policy.default_priority =
        get_optional_string_array(rp, "default_priority").unwrap_or_default();
    if let Some(items) = rp.get("strategies").and_then(Value::as_array) {
        for item in items {
            config.routing_policy.strategies.push(build_strategy(item));
        }
    }

    if !mc.is_object() {
        return Err(ConfigError::Parse {
            file: "model_config.json",
        });
    }
    if let Some(items) = mc.get("models").and_then(Value::as_array) {
        for item in items {
            let model = build_model_config(item);
            config.models.insert(model.model_id.clone(), model);
        }
    }

    if !sp.is_object() {
        return Err(ConfigError::Parse {
            file: "sensitive_patterns.json",
        });
    }
    config.sensitive_patterns.version = get_string(sp, "version");
    if let Some(items) = sp.get("patterns").and_then(Value::as_array) {
        for item in items {
            config.sensitive_patterns.patterns.push(build_pattern(item));
        }
    }

    config.api_keys = build_api_keys(ak);

    Ok(config)
}

fn build_strategy(val: &Value) -> Strategy {
    Strategy {
        strategy_id: get_string(val, "strategy_id"),
        name: get_string(val, "name"),
        enabled: get_bool(val, "enabled", true),
        priority: get_int(val, "priority", 50),
        condition: val
            .get("condition")
            .filter(|v| v.is_object())
            .map(build_condition)
            .unwrap_or_default(),
        action: val
            .get("action")
            .filter(|v| v.is_object())
            .map(build_action)
            .unwrap_or_default(),
    }
}

fn build_condition(val: &Value) -> Condition {
    Condition {
        sensitive_data_detected: get_bool(val, "sensitive_data_detected", false),
        local_model_available: get_optional_bool(val, "local_model_available"),
        request_format: get_optional_string(val, "request_format"),
        model_id: get_optional_string(val, "model_id"),
    }
}

fn build_action(val: &Value) -> Action {
    Action {
        target: get_string(val, "target"),
        model_id: get_string(val, "model_id"),
        sanitize: get_optional_bool(val, "sanitize"),
    }
}

fn build_model_config(val: &Value) -> ModelConfig {
    ModelConfig {
        model_id: get_string(val, "model_id"),
        name: get_string(val, "name"),
        type_: get_string(val, "type"),
        provider: get_string(val, "provider"),
        endpoint: get_string(val, "endpoint"),
        timeout_ms: get_int(val, "timeout_ms", 30000),
        max_retries: get_int(val, "max_retries", 3),
        headers: get_optional_map(val, "headers"),
        enabled: get_bool(val, "enabled", true),
    }
}

fn build_pattern(val: &Value) -> Pattern {
    let mut pattern = Pattern {
        pattern_id: get_string(val, "pattern_id"),
        name: get_string(val, "name"),
        type_: get_string(val, "type"),
        regex: get_optional_string(val, "regex"),
        keywords: get_optional_string_array(val, "keywords"),
        description: get_optional_string(val, "description"),
        severity: get_string(val, "severity"),
        enabled: get_bool(val, "enabled", true),
        key_dist: get_int(val, "keyDist", 50).max(0) as usize,
    };
    if pattern.severity.is_empty() {
        pattern.severity = "medium".to_string();
    }
    pattern
}

fn build_api_keys(ak: &Value) -> HashMap<String, String> {
    let mut result = HashMap::new();
    let Some(obj) = ak.get("api_keys").and_then(Value::as_object) else {
        return result;
    };
    for (key, val) in obj {
        if let Some(v) = val.as_str() {
            if !v.is_empty() {
                result.insert(key.clone(), v.to_string());
            }
        }
    }
    result
}

// ---- 宽松提取辅助（缺失或类型不符 → 默认值，对齐 C++ get_* 系列）----

fn get_bool(obj: &Value, key: &str, default: bool) -> bool {
    obj.get(key).and_then(Value::as_bool).unwrap_or(default)
}

fn get_int(obj: &Value, key: &str, default: i32) -> i32 {
    obj.get(key)
        .and_then(Value::as_i64)
        .and_then(|v| i32::try_from(v).ok())
        .unwrap_or(default)
}

fn get_string(obj: &Value, key: &str) -> String {
    obj.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn get_optional_string(obj: &Value, key: &str) -> Option<String> {
    obj.get(key).and_then(Value::as_str).map(String::from)
}

fn get_optional_bool(obj: &Value, key: &str) -> Option<bool> {
    obj.get(key).and_then(Value::as_bool)
}

fn get_optional_string_array(obj: &Value, key: &str) -> Option<Vec<String>> {
    obj.get(key).and_then(Value::as_array).map(|items| {
        items
            .iter()
            .filter_map(Value::as_str)
            .map(String::from)
            .collect()
    })
}

fn get_optional_map(obj: &Value, key: &str) -> Option<std::collections::BTreeMap<String, String>> {
    obj.get(key).and_then(Value::as_object).map(|o| {
        o.iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect()
    })
}
