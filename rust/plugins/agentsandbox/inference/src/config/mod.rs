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

//! 配置管理（BeDemo `config_manager.cpp` 移植）。
//!
//! C++ 侧为进程单例；Rust 侧配置快照挂在 [`crate::router`] 的全局
//! `RouterState` 上，本模块只提供无状态的加载/查询/持久化函数。

pub(crate) mod error;
pub(crate) mod loader;
pub(crate) mod model;
pub(crate) mod validator;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde_json::json;

use error::ConfigError;
pub(crate) use error::CredentialError;
use model::Config;

pub(crate) use loader::{load_config, load_config_from_contents};

/// 凭据查询（C++ `ConfigManager::get_api_key`）。
///
/// 语义：模型不存在 → `NotFound`；密钥未配置/为空 → `Missing`（route 侧
/// 收敛为空凭据）；解密失败 → `Crypto`（route 侧收敛为 Block）。
pub(crate) fn get_api_key(config: &Config, model_id: &str) -> Result<String, CredentialError> {
    if !config.models.contains_key(model_id) {
        return Err(CredentialError::NotFound);
    }
    match config.api_keys.get(model_id) {
        Some(enc) if !enc.is_empty() => {
            crate::crypto::decrypt(enc).map_err(CredentialError::Crypto)
        }
        _ => Err(CredentialError::Missing),
    }
}

/// API-Key 持久化 + 内存缓存更新（C++ `persist_api_keys_impl` 语义）。
///
/// 非事务：合并（删除优先于覆盖，覆盖优先于保留）→ 原子写（tmp + 校验 +
/// rename 重试）→ 成功后才更新内存快照。文件 I/O 在锁外执行。
pub(crate) fn persist_and_update(
    config_lock: &RwLock<Arc<Config>>,
    overrides: &HashMap<String, String>,
    deletes: &[String],
) -> Result<(), ConfigError> {
    let (path, current) = {
        let config = crate::lock_util_recovered::recovered(config_lock.read());
        (config.api_keys_path.clone(), config.api_keys.clone())
    };

    let mut merged: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (id, enc) in &current {
        if deletes.contains(id) {
            continue;
        }
        let value = overrides.get(id).unwrap_or(enc).clone();
        merged.insert(id.clone(), value);
    }
    for (id, enc) in overrides {
        merged.entry(id.clone()).or_insert_with(|| enc.clone());
    }

    let doc = json!({ "api_keys": merged });
    let content = serde_json::to_string_pretty(&doc).map_err(|_| ConfigError::Persist)?;

    // 原子写：tmp → 回读校验 → rename（Windows 占用重试，对齐 C++）。
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp: std::path::PathBuf = tmp.into();
    std::fs::write(&tmp, &content).map_err(|_| ConfigError::Persist)?;
    let verify = std::fs::read_to_string(&tmp).map_err(|_| ConfigError::Persist)?;
    if serde_json::from_str::<serde_json::Value>(&verify).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::Persist);
    }
    for i in 0..5u32 {
        if std::fs::rename(&tmp, &path).is_ok() {
            return update_cache(config_lock, overrides, deletes);
        }
        if i == 4 {
            let _ = std::fs::remove_file(&path);
            if std::fs::rename(&tmp, &path).is_ok() {
                return update_cache(config_lock, overrides, deletes);
            }
            let _ = std::fs::remove_file(&tmp);
            return Err(ConfigError::Persist);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Err(ConfigError::Persist)
}

/// 持久化成功后的内存缓存更新（写锁内重建快照）。
fn update_cache(
    config_lock: &RwLock<Arc<Config>>,
    overrides: &HashMap<String, String>,
    deletes: &[String],
) -> Result<(), ConfigError> {
    let mut config = crate::lock_util_recovered::recovered(config_lock.write());
    let mut next = (**config).clone();
    for (id, enc) in overrides {
        next.api_keys.insert(id.clone(), enc.clone());
    }
    for id in deletes {
        next.api_keys.remove(id);
    }
    *config = Arc::new(next);
    Ok(())
}

/// 校验 model_id 在 model_config 中存在且启用（C++ `get_model_config` 查询语义）。
pub(crate) fn model_enabled(config: &Config, model_id: &str) -> bool {
    config.models.get(model_id).is_some_and(|m| m.enabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(dir: &std::path::Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("routing_policy.json"),
            r#"{"version":"1.0.0","strategies":[
                {"strategy_id":"s1","name":"a","enabled":true,"priority":10,
                 "action":{"target":"cloud_with_sanitization","model_id":"m1","sanitize":true}}]}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("model_config.json"),
            r#"{"models":[{"model_id":"m1","name":"M","type":"cloud","provider":"openai",
                "endpoint":"http://h.example.com/p","timeout_ms":1000,"max_retries":1}]}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("sensitive_patterns.json"),
            r#"{"version":"1.0.0","patterns":[
                {"pattern_id":"id_card","name":"ID","type":"id_card","regex":"[0-9]{18}",
                 "keywords":["身份证"],"keyDist":20}]}"#,
        )
        .unwrap();
        std::fs::write(dir.join("api_keys.json"), r#"{"api_keys":{}}"#).unwrap();
    }

    fn temp_dir() -> std::path::PathBuf {
        tempfile::tempdir().unwrap().keep()
    }

    fn load(dir: &std::path::Path) -> Result<Config, ConfigError> {
        load_config(
            &dir.join("routing_policy.json"),
            &dir.join("model_config.json"),
            &dir.join("sensitive_patterns.json"),
            &dir.join("api_keys.json"),
        )
    }

    #[test]
    fn loads_with_defaults() {
        let dir = temp_dir();
        write_config(&dir);
        let config = load(&dir).unwrap();
        assert_eq!(config.routing_policy.version, "1.0.0");
        assert_eq!(config.routing_policy.strategies.len(), 1);
        let strategy = &config.routing_policy.strategies[0];
        assert!(strategy.enabled);
        assert_eq!(strategy.priority, 10);
        assert_eq!(strategy.action.model_id, "m1");
        let model = &config.models["m1"];
        assert!(model.enabled); // 缺省 true。
        assert_eq!(model.timeout_ms, 1000);
        assert_eq!(model.type_, "cloud");
        let pattern = &config.sensitive_patterns.patterns[0];
        assert_eq!(pattern.severity, "medium"); // 缺省 medium。
        assert_eq!(pattern.key_dist, 20);
        assert!(config.api_keys.is_empty());
    }

    #[test]
    fn api_keys_file_optional_and_empty_values_skipped() {
        let dir = temp_dir();
        write_config(&dir);
        std::fs::remove_file(dir.join("api_keys.json")).unwrap();
        let config = load(&dir).unwrap();
        assert!(config.api_keys.is_empty());

        std::fs::write(
            dir.join("api_keys.json"),
            r#"{"api_keys":{"m1":"","m2":"cipher"}}"#,
        )
        .unwrap();
        let config = load(&dir).unwrap();
        assert!(!config.api_keys.contains_key("m1")); // 空值跳过。
        assert_eq!(config.api_keys["m2"], "cipher");
    }

    #[test]
    fn missing_required_file_fails() {
        let dir = temp_dir();
        write_config(&dir);
        let err = load_config(
            &dir.join("nonexistent.json"),
            &dir.join("model_config.json"),
            &dir.join("sensitive_patterns.json"),
            &dir.join("api_keys.json"),
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Load { .. }));
    }

    #[test]
    fn parse_error_reports_file() {
        let dir = temp_dir();
        write_config(&dir);
        std::fs::write(dir.join("model_config.json"), "not json").unwrap();
        let err = load(&dir).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Parse {
                file: "model_config.json"
            }
        ));
    }

    #[test]
    fn validation_rejects_bad_config() {
        let dir = temp_dir();
        write_config(&dir);
        // 非法 target + 空 strategies 双错误聚合。
        std::fs::write(
            dir.join("routing_policy.json"),
            r#"{"version":"9.9","strategies":[
                {"strategy_id":"s1","name":"a","priority":200,
                 "action":{"target":"wrong","model_id":""}}]}"#,
        )
        .unwrap();
        let err = load(&dir).unwrap_err();
        let ConfigError::Validation(msg) = err else {
            panic!("expected validation error");
        };
        assert!(msg.contains("target"));
        assert!(msg.contains("1-100"));
        assert!(msg.contains("action.model_id: is required"));
        assert!(msg.contains("semver"));
    }

    #[test]
    fn validation_rejects_duplicate_strategy_and_unknown_default_priority() {
        let dir = temp_dir();
        write_config(&dir);
        std::fs::write(
            dir.join("routing_policy.json"),
            r#"{"version":"1.0.0","default_priority":["ghost"],
                "strategies":[
                {"strategy_id":"s1","name":"a","priority":10,"action":{"target":"cloud","model_id":"m1"}},
                {"strategy_id":"s1","name":"b","priority":20,"action":{"target":"cloud","model_id":"m1"}}]}"#,
        )
        .unwrap();
        let err = load(&dir).unwrap_err();
        let ConfigError::Validation(msg) = err else {
            panic!("expected validation error");
        };
        assert!(msg.contains("duplicated"));
        assert!(msg.contains("ghost is not a valid strategy_id"));
    }

    #[test]
    fn validation_rejects_bad_model_and_pattern_rules() {
        let dir = temp_dir();
        write_config(&dir);
        std::fs::write(
            dir.join("model_config.json"),
            r#"{"models":[{"model_id":"m1","name":"M","type":"hybrid","provider":"openai",
                "endpoint":"http://x","timeout_ms":0,"max_retries":-1}]}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("sensitive_patterns.json"),
            r#"{"version":"1.0.0","patterns":[
                {"pattern_id":"p1","name":"P","type":"custom","severity":"urgent"}]}"#,
        )
        .unwrap();
        let err = load(&dir).unwrap_err();
        let ConfigError::Validation(msg) = err else {
            panic!("expected validation error");
        };
        assert!(msg.contains("type"));
        assert!(msg.contains("timeout_ms"));
        assert!(msg.contains("max_retries"));
        assert!(msg.contains("severity"));
        assert!(msg.contains("regex: is required when type=custom"));
    }

    #[test]
    fn shipped_default_configs_pass_validation() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/config");
        let config = load_config(
            &root.join("routing_policy.json"),
            &root.join("model_config.json"),
            &root.join("sensitive_patterns.json"),
            &root.join("api_keys.json"),
        )
        .unwrap();
        assert_eq!(config.routing_policy.strategies.len(), 3);
        assert_eq!(config.models.len(), 3);
        assert!(config.sensitive_patterns.patterns.len() >= 14);
        assert!(config.api_keys.is_empty());
    }

    #[test]
    fn persist_and_update_roundtrip() {
        let dir = temp_dir();
        write_config(&dir);
        let config = load(&dir).unwrap();
        let shared: RwLock<Arc<Config>> = RwLock::new(Arc::new(config));

        let mut overrides = HashMap::new();
        overrides.insert("m1".to_string(), "cipher-1".to_string());
        persist_and_update(&shared, &overrides, &[]).unwrap();

        let snapshot = crate::lock_util_recovered::recovered(shared.read()).clone();
        assert_eq!(snapshot.api_keys["m1"], "cipher-1");

        // 文件侧同样落盘且可重新加载。
        let reloaded = load(&dir).unwrap();
        assert_eq!(reloaded.api_keys["m1"], "cipher-1");

        // 覆盖 + 删除合并语义。
        let mut overrides2 = HashMap::new();
        overrides2.insert("m2".to_string(), "cipher-2".to_string());
        persist_and_update(&shared, &overrides2, &["m1".to_string()]).unwrap();
        let snapshot = crate::lock_util_recovered::recovered(shared.read()).clone();
        assert!(!snapshot.api_keys.contains_key("m1"));
        assert_eq!(snapshot.api_keys["m2"], "cipher-2");
        let reloaded = load(&dir).unwrap();
        assert!(!reloaded.api_keys.contains_key("m1"));
        assert_eq!(reloaded.api_keys["m2"], "cipher-2");
    }
}
