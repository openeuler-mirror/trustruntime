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

//! InferenceRouter 端到端测试（BeDemo `tests/test_inference_router.cpp`
//! 移植；全局状态 + 环境变量进程级——单测试函数内顺序执行）。

use agentsandbox_inference::{
    api_key_for, apply_api_key, init, is_initialized, AgentRouter, ApiKeyAction, ApiKeyError,
    ApiKeyItem, ApiKeyRequest, InferenceRequest, InferenceResult, InferenceRouteResult,
    InferenceRouter, ModifyTarget,
};
use http::{HeaderMap, HeaderName, HeaderValue};

const ENCRYPTION_KEY: &str = "X43uDpE8Q/tC0NGIUY81vCS7CalCk405XxxQ/3hR/NQ=";

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        map.insert(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    map
}

fn request(pairs: &[(&str, &str)], body: &str) -> InferenceRequest {
    InferenceRequest {
        headers: headers(pairs),
        body: body.to_string(),
    }
}

fn set_key(model_id: &str, api_key: &str) {
    apply_api_key(&ApiKeyRequest {
        action: ApiKeyAction::Set,
        items: vec![ApiKeyItem {
            model_id: model_id.to_string(),
            api_key: api_key.to_string(),
        }],
    })
    .unwrap();
}

fn delete_key(model_id: &str) {
    apply_api_key(&ApiKeyRequest {
        action: ApiKeyAction::Delete,
        items: vec![ApiKeyItem {
            model_id: model_id.to_string(),
            api_key: String::new(),
        }],
    })
    .unwrap();
}

fn route(req: InferenceRequest) -> InferenceRouteResult {
    AgentRouter.route(req)
}

/// 查找指定目标的修改项。
fn find_mod<'a>(
    result: &'a InferenceRouteResult,
    target: ModifyTarget,
    key: &str,
) -> Option<&'a agentsandbox_inference::InferenceModification> {
    result
        .modifications
        .iter()
        .find(|m| m.target == target && m.key == key)
}

fn write_file(dir: &std::path::Path, name: &str, content: &str) {
    std::fs::write(dir.join(name), content).unwrap();
}

/// C++ test_inference_router 的自包含临时配置（keyDist=20 的两条模式）。
fn setup_config(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::env::set_var("CONFIG_ENCRYPTION_KEY", ENCRYPTION_KEY);

    write_file(
        dir,
        "routing_policy.json",
        r#"{
        "version": "1.0.0",
        "strategies": [
            {"strategy_id": "s_cloud_sanitize", "name": "cloud sanitize", "enabled": true, "priority": 10,
             "action": {"target": "cloud_with_sanitization", "model_id": "qwen36-35b-vl", "sanitize": true}},
            {"strategy_id": "s_cloud_direct", "name": "cloud direct", "enabled": true, "priority": 20,
             "action": {"target": "cloud", "model_id": "claude-3", "sanitize": false}},
            {"strategy_id": "s_local", "name": "local", "enabled": true, "priority": 30,
             "action": {"target": "local", "model_id": "llama-8b", "sanitize": false}}
        ]
    }"#,
    );

    write_file(
        dir,
        "model_config.json",
        r#"{
        "models": [
            {"model_id": "qwen36-35b-vl", "name": "Qwen", "type": "cloud",
             "provider": "openai", "endpoint": "http://mlops.huawei.com/mlops-service/api/v2/agentService/v1",
             "timeout_ms": 30000, "max_retries": 3, "headers": {"X-Custom": "yes"}, "enabled": true},
            {"model_id": "claude-3", "name": "Claude", "type": "cloud",
             "provider": "anthropic", "endpoint": "https://api.anthropic.com/v1/messages",
             "timeout_ms": 60000, "max_retries": 3, "enabled": true},
            {"model_id": "llama-8b", "name": "Llama", "type": "local",
             "provider": "custom", "endpoint": "http://localhost:8080",
             "timeout_ms": 120000, "max_retries": 1, "enabled": true}
        ]
    }"#,
    );

    write_file(
        dir,
        "sensitive_patterns.json",
        r#"{
        "version": "1.0.0",
        "patterns": [
            {"pattern_id": "id_card", "name": "ID Card", "type": "id_card",
             "regex": "[1-9]\\d{5}(?:19|20)\\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\\d|3[01])\\d{3}[0-9Xx]",
             "keywords": ["身份证"], "severity": "high", "keyDist": 20, "enabled": true},
            {"pattern_id": "mobile_phone", "name": "Phone", "type": "mobile_phone",
             "regex": "1[3-9]\\d{9}",
             "keywords": ["手机"], "severity": "medium", "keyDist": 20, "enabled": true}
        ]
    }"#,
    );

    write_file(dir, "api_keys.json", r#"{"api_keys": {}}"#);
}

#[test]
fn inference_router_e2e() {
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("config");
    setup_config(&config_dir);
    let host = &[("host", "api.openai.com")];

    // ---- G14（顺序前置）：未初始化 → route Block + apply NotInitialized ----
    assert!(!is_initialized());
    let out = route(request(
        host,
        r#"{"messages":[{"role":"user","content":"hello"}]}"#,
    ));
    assert_eq!(out.result, InferenceResult::Block);
    assert!(out.modifications.is_empty());
    let err = apply_api_key(&ApiKeyRequest {
        action: ApiKeyAction::Set,
        items: vec![ApiKeyItem {
            model_id: "qwen36-35b-vl".to_string(),
            api_key: "sk-x".to_string(),
        }],
    })
    .unwrap_err();
    assert_eq!(err, ApiKeyError::NotInitialized);

    // ---- G1: init ----
    init(config_dir.to_str().unwrap()).unwrap();
    assert!(is_initialized());

    // init 幂等重入（配置重载）。
    init(config_dir.to_str().unwrap()).unwrap();

    // ---- G2: set single ----
    set_key("qwen36-35b-vl", "sk-test-123");
    assert_eq!(api_key_for("qwen36-35b-vl").as_deref(), Some("sk-test-123"));

    // ---- G3: set batch ----
    apply_api_key(&ApiKeyRequest {
        action: ApiKeyAction::Set,
        items: vec![
            ApiKeyItem {
                model_id: "qwen36-35b-vl".to_string(),
                api_key: "sk-key1".to_string(),
            },
            ApiKeyItem {
                model_id: "claude-3".to_string(),
                api_key: "sk-key2".to_string(),
            },
        ],
    })
    .unwrap();
    assert_eq!(api_key_for("qwen36-35b-vl").as_deref(), Some("sk-key1"));
    assert_eq!(api_key_for("claude-3").as_deref(), Some("sk-key2"));

    // ---- G4/G5: delete single + batch（不存在的 model_id 幂等成功）----
    delete_key("claude-3");
    assert_eq!(api_key_for("claude-3"), None);
    delete_key("qwen36-35b-vl");
    delete_key("claude-3");
    delete_key("ghost-model");
    assert_eq!(api_key_for("qwen36-35b-vl"), None);

    // ---- G6: 混合操作（Rust 契约为单 action——分两次调用模拟）----
    set_key("qwen36-35b-vl", "sk-new");
    set_key("claude-3", "sk-222");
    delete_key("claude-3");
    assert_eq!(api_key_for("qwen36-35b-vl").as_deref(), Some("sk-new"));

    // ---- 额外：错误路径 ----
    // 空列表 no-op。
    apply_api_key(&ApiKeyRequest {
        action: ApiKeyAction::Set,
        items: vec![],
    })
    .unwrap();
    // 未知模型 set → ModelNotFound（且不影响既有条目）。
    let err = apply_api_key(&ApiKeyRequest {
        action: ApiKeyAction::Set,
        items: vec![ApiKeyItem {
            model_id: "ghost".to_string(),
            api_key: "k".to_string(),
        }],
    })
    .unwrap_err();
    assert_eq!(err, ApiKeyError::ModelNotFound);
    assert_eq!(api_key_for("qwen36-35b-vl").as_deref(), Some("sk-new"));
    // 部分成功：未知模型条目失败，有效条目仍生效。
    apply_api_key(&ApiKeyRequest {
        action: ApiKeyAction::Set,
        items: vec![
            ApiKeyItem {
                model_id: "claude-3".to_string(),
                api_key: "sk-cc".to_string(),
            },
            ApiKeyItem {
                model_id: "ghost".to_string(),
                api_key: "k".to_string(),
            },
        ],
    })
    .unwrap_err();
    assert_eq!(api_key_for("claude-3").as_deref(), Some("sk-cc"));
    // 空 api_key set → Invalid。
    let err = apply_api_key(&ApiKeyRequest {
        action: ApiKeyAction::Set,
        items: vec![ApiKeyItem {
            model_id: "claude-3".to_string(),
            api_key: String::new(),
        }],
    })
    .unwrap_err();
    assert_eq!(err, ApiKeyError::Invalid);
    // 禁用模型 set → ModelNotFound。
    //（model_config 未含禁用模型——经 ghost 用例已覆盖不存在分支，此处跳过。）

    // ---- 恢复 key 供路由测试（对齐 C++ main 顺序）----
    set_key("qwen36-35b-vl", "sk-test-123");
    delete_key("claude-3");

    // ---- G7: 含敏感信息 → Modified + 脱敏 ----
    let out = route(request(
        host,
        r#"{"messages":[{"role":"user","content":"我的身份证号是110101199003071234，手机号13800138000"}]}"#,
    ));
    assert_eq!(out.result, InferenceResult::Modified);
    assert!(out.modifications.len() >= 2);
    let auth = find_mod(&out, ModifyTarget::Header, "authorization").unwrap();
    assert_eq!(auth.value, "Bearer sk-test-123");
    assert_eq!(auth.action, agentsandbox_inference::ModifyAction::Add);
    let body_mod = out
        .modifications
        .iter()
        .find(|m| m.target == ModifyTarget::Body)
        .unwrap();
    let rewritten: serde_json::Value = serde_json::from_str(&body_mod.value).unwrap();
    // model 注入 + 双模式脱敏 + 非 user 内容不动。
    assert_eq!(rewritten["model"], "qwen36-35b-vl");
    assert_eq!(
        rewritten["messages"][0]["content"],
        "我的身份证号是[PII_id_card]，手机号[PII_mobile_phone]"
    );

    // ---- G8: 无敏感信息 → Modified（鉴权 + host + model 注入）----
    let out = route(request(
        host,
        r#"{"messages":[{"role":"user","content":"你好今天天气怎么样"}]}"#,
    ));
    assert_eq!(out.result, InferenceResult::Modified);
    assert!(find_mod(&out, ModifyTarget::Header, "authorization").is_some());
    // 无 model 字段 → model 注入生成 body 修改。
    let body_mod = out
        .modifications
        .iter()
        .find(|m| m.target == ModifyTarget::Body)
        .expect("model 注入应生成 body 修改");
    let rewritten: serde_json::Value = serde_json::from_str(&body_mod.value).unwrap();
    assert_eq!(rewritten["model"], "qwen36-35b-vl");
    assert_eq!(rewritten["messages"][0]["content"], "你好今天天气怎么样");

    // ---- G9: 非法 body → Block ----
    let out = route(request(host, "not a json"));
    assert_eq!(out.result, InferenceResult::Block);

    // ---- G10: 未配置 API-Key → Bearer EMPTY ----
    delete_key("qwen36-35b-vl");
    let out = route(request(
        host,
        r#"{"messages":[{"role":"user","content":"hello"}]}"#,
    ));
    assert_eq!(out.result, InferenceResult::Modified);
    let auth = find_mod(&out, ModifyTarget::Header, "authorization").unwrap();
    assert_eq!(auth.value, "Bearer EMPTY");
    set_key("qwen36-35b-vl", "sk-test-123");

    // ---- G11: 多模态（text + image_url）----
    let out = route(request(
        host,
        r#"{"messages":[{"role":"user","content":[
            {"type":"text","text":"我的身份证号是110101199003071234"},
            {"type":"image_url","image_url":{"url":"https://example.com/img.jpg"}},
            {"type":"text","text":"请处理"}]}]}"#,
    ));
    assert_eq!(out.result, InferenceResult::Modified);
    let body_mod = out
        .modifications
        .iter()
        .find(|m| m.target == ModifyTarget::Body)
        .unwrap();
    let rewritten: serde_json::Value = serde_json::from_str(&body_mod.value).unwrap();
    assert_eq!(
        rewritten["messages"][0]["content"][0]["text"],
        "我的身份证号是[PII_id_card]"
    );
    assert_eq!(
        rewritten["messages"][0]["content"][1]["image_url"]["url"],
        "https://example.com/img.jpg"
    );
    assert_eq!(rewritten["messages"][0]["content"][2]["text"], "请处理");

    // ---- G12: 原帧已有 authorization → Modify ----
    let out = route(request(
        &[
            ("host", "api.openai.com"),
            ("authorization", "Bearer old-key"),
        ],
        r#"{"messages":[{"role":"user","content":"hello"}]}"#,
    ));
    assert_eq!(out.result, InferenceResult::Modified);
    let auth = find_mod(&out, ModifyTarget::Header, "authorization").unwrap();
    assert_eq!(auth.action, agentsandbox_inference::ModifyAction::Modify);
    assert_eq!(auth.value, "Bearer sk-test-123");

    // ---- G13: host 重定向 ----
    let out = route(request(
        host,
        r#"{"messages":[{"role":"user","content":"hello"}]}"#,
    ));
    let host_mod = find_mod(&out, ModifyTarget::Header, "host").unwrap();
    assert_eq!(host_mod.value, "mlops.huawei.com");
    assert_eq!(
        host_mod.action,
        agentsandbox_inference::ModifyAction::Modify
    );

    // ---- 额外：header-only 模式（空 body / "{}"）----
    for body in ["", "{}"] {
        let out = route(request(host, body));
        assert_eq!(out.result, InferenceResult::Modified);
        assert!(find_mod(&out, ModifyTarget::Header, "authorization").is_some());
        assert!(find_mod(&out, ModifyTarget::Header, "host").is_some());
        assert!(
            !out.modifications
                .iter()
                .any(|m| m.target == ModifyTarget::Body),
            "header-only 不应有 body 修改"
        );
    }

    // ---- 额外：Anthropic 格式 → x-api-key 裸值 ----
    let out = route(request(
        &[("host", "api.anthropic.com")],
        r#"{"system":"s","messages":[{"role":"user","content":"hello"}]}"#,
    ));
    assert_eq!(out.result, InferenceResult::Modified);
    let key_mod = find_mod(&out, ModifyTarget::Header, "x-api-key").unwrap();
    // 无敏感 → cloud 优先 → s_cloud_sanitize（qwen，priority 10）。
    assert_eq!(key_mod.value, "sk-test-123");
    assert!(
        find_mod(&out, ModifyTarget::Header, "authorization").is_none(),
        "anthropic 族不应使用 authorization"
    );

    // ---- 额外：engine 级场景（配置重载验证）----
    // 无可用策略（全部禁用）→ Block。
    let dir2 = tmp.path().join("config_no_strategy");
    setup_config(&dir2);
    let disabled = std::fs::read_to_string(dir2.join("routing_policy.json"))
        .unwrap()
        .replace("\"enabled\": true", "\"enabled\": false");
    write_file(&dir2, "routing_policy.json", &disabled);
    init(dir2.to_str().unwrap()).unwrap();
    let out = route(request(
        host,
        r#"{"messages":[{"role":"user","content":"hello"}]}"#,
    ));
    assert_eq!(out.result, InferenceResult::Block, "无可用策略应阻断");

    // 敏感 + sanitize=false 策略集：脱敏检测仍执行但不采用脱敏结果。
    let dir3 = tmp.path().join("config_no_sanitize");
    setup_config(&dir3);
    let no_sanitize = std::fs::read_to_string(dir3.join("routing_policy.json"))
        .unwrap()
        .replace("\"priority\": 10", "\"priority\": 90");
    write_file(&dir3, "routing_policy.json", &no_sanitize);
    init(dir3.to_str().unwrap()).unwrap();
    set_key("qwen36-35b-vl", "sk-test-123");
    let out = route(request(
        host,
        r#"{"messages":[{"role":"user","content":"我的身份证号是110101199003071234"}]}"#,
    ));
    assert_eq!(out.result, InferenceResult::Modified);
    let body_mod = out
        .modifications
        .iter()
        .find(|m| m.target == ModifyTarget::Body)
        .unwrap();
    let rewritten: serde_json::Value = serde_json::from_str(&body_mod.value).unwrap();
    // 有敏感信息 → 最小 priority 策略 = s_cloud_direct（20，sanitize=false）
    // → model=claude-3，原文保留。
    assert_eq!(rewritten["model"], "claude-3");
    assert_eq!(
        rewritten["messages"][0]["content"],
        "我的身份证号是110101199003071234"
    );

    // 无敏感 → cloud 优先 → s_cloud_direct（20 < 90，claude-3）。
    let out = route(request(
        host,
        r#"{"messages":[{"role":"user","content":"你好"}]}"#,
    ));
    let body_mod = out
        .modifications
        .iter()
        .find(|m| m.target == ModifyTarget::Body)
        .unwrap();
    let rewritten: serde_json::Value = serde_json::from_str(&body_mod.value).unwrap();
    assert_eq!(rewritten["model"], "claude-3");

    // 目标模型缺失（策略指向不存在的 model）→ Block。
    // 有敏感信息路径：无类型过滤直接命中 s_cloud_sanitize（priority 10，
    // model_id=ghost）→ 凭据 NotFound 收敛空 → 目标模型缺失 → Block。
    let dir4 = tmp.path().join("config_missing_model");
    setup_config(&dir4);
    let broken = std::fs::read_to_string(dir4.join("routing_policy.json"))
        .unwrap()
        .replace("\"model_id\": \"qwen36-35b-vl\"", "\"model_id\": \"ghost\"");
    write_file(&dir4, "routing_policy.json", &broken);
    init(dir4.to_str().unwrap()).unwrap();
    let out = route(request(
        host,
        r#"{"messages":[{"role":"user","content":"我的身份证号是110101199003071234"}]}"#,
    ));
    assert_eq!(out.result, InferenceResult::Block, "目标模型缺失应阻断");

    // ---- 额外：持久化跨 init 保留（api_keys.json 重载）----
    let dir5 = tmp.path().join("config_persist");
    setup_config(&dir5);
    init(dir5.to_str().unwrap()).unwrap();
    set_key("qwen36-35b-vl", "sk-persisted");
    init(dir5.to_str().unwrap()).unwrap(); // 重新加载。
    assert_eq!(
        api_key_for("qwen36-35b-vl").as_deref(),
        Some("sk-persisted")
    );
}
