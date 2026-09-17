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

//! 真实裁决入口（BeDemo `inference_router.cpp` API 库模式移植）。
//!
//! 全局状态：`init(config_dir)` 构建 [`RouterState`]（配置 + 脱敏器）并
//! 挂到进程级槽位（可重复 init = 配置重载）；[`crate::AgentRouter`] 经
//! 状态快照同步裁决。fail-closed：未初始化 / 解析失败 / 无策略 / 构建
//! 失败一律 Block。

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

use serde_json::Value;

use crate::config::model::Config;
use crate::parser::{self, ParseError, RequestFormat};
use crate::{
    InferenceModification, InferenceRequest, InferenceResult, InferenceRouteResult, ModifyAction,
    ModifyTarget,
};

/// 运行时状态（init 构建；config 快照可经 API-Key 管理原地演进）。
pub(crate) struct RouterState {
    config: RwLock<Arc<Config>>,
    masker: Option<crate::masker::TextIdentify>,
}

impl RouterState {
    /// 配置快照（读锁内 Arc 克隆）。
    pub(crate) fn config_snapshot(&self) -> Arc<Config> {
        crate::lock_util_recovered::recovered(self.config.read()).clone()
    }

    /// 脱敏（no-op 脱敏器原样返回——对齐 C++ 未初始化 masker 语义）。
    pub(crate) fn mask(&self, payload: &str) -> String {
        match &self.masker {
            Some(masker) => masker.desensitize(payload),
            None => payload.to_string(),
        }
    }
}

/// 进程级状态槽位（init 替换式重载）。
static STATE: RwLock<Option<Arc<RouterState>>> = RwLock::new(None);

/// 默认配置（resources/config 内嵌——rlib 交付不依赖部署侧文件路径；
/// 三份只读配置经 `include_str!` 编入，api_keys 落状态目录）。
const DEFAULT_ROUTING_POLICY: &str = include_str!("../resources/config/routing_policy.json");
const DEFAULT_MODEL_CONFIG: &str = include_str!("../resources/config/model_config.json");
const DEFAULT_SENSITIVE_PATTERNS: &str =
    include_str!("../resources/config/sensitive_patterns.json");

/// 状态快照。
pub(crate) fn state_snapshot() -> Option<Arc<RouterState>> {
    crate::lock_util_recovered::recovered(STATE.read()).clone()
}

/// 全局初始化：加载四配置 + 构建脱敏器（可重复调用 = 配置重载）。
pub(crate) fn init(config_dir: &str) -> Result<(), crate::InitError> {
    let dir = Path::new(config_dir);
    let config = crate::config::load_config(
        &dir.join("routing_policy.json"),
        &dir.join("model_config.json"),
        &dir.join("sensitive_patterns.json"),
        &dir.join("api_keys.json"),
    )?;
    install(config);
    Ok(())
}

/// 默认配置初始化（未提供 config_dir 时使用）：三份只读配置取内嵌默认，
/// `api_keys.json` 落状态目录（env `AGENT_ROUTER_STATE_DIR` 覆盖，默认
/// `{temp}/agentsandbox-inference/`——首用创建空态，并发首建竞态容忍）。
pub(crate) fn init_default() -> Result<(), crate::InitError> {
    let state_dir = match std::env::var("AGENT_ROUTER_STATE_DIR") {
        Ok(v) if !v.is_empty() => std::path::PathBuf::from(v),
        _ => std::env::temp_dir().join("agentsandbox-inference"),
    };
    let api_keys_path = ensure_state_api_keys(&state_dir)?;
    let ak_content =
        std::fs::read_to_string(&api_keys_path).map_err(|_| crate::InitError::Load {
            file: "api_keys.json",
        })?;
    let config = crate::config::load_config_from_contents(
        DEFAULT_ROUTING_POLICY,
        DEFAULT_MODEL_CONFIG,
        DEFAULT_SENSITIVE_PATTERNS,
        &ak_content,
        &api_keys_path,
    )?;
    install(config);
    Ok(())
}

/// 确保状态目录存在且含 api_keys.json（已存在则不动——保留既有密文）。
fn ensure_state_api_keys(state_dir: &Path) -> Result<std::path::PathBuf, crate::InitError> {
    std::fs::create_dir_all(state_dir).map_err(|_| crate::InitError::Load {
        file: "api_keys.json",
    })?;
    let path = state_dir.join("api_keys.json");
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut file) => {
            use std::io::Write as _;
            if file.write_all(b"{\"api_keys\":{}}").is_err() {
                let _ = std::fs::remove_file(&path);
                return Err(crate::InitError::Load {
                    file: "api_keys.json",
                });
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => {
            return Err(crate::InitError::Load {
                file: "api_keys.json",
            })
        }
    }
    Ok(path)
}

/// 配置装载后的状态装配（构建成功才替换全局槽位——失败不改既有状态）。
fn install(config: Config) {
    let masker = crate::masker::TextIdentify::from_patterns(&config.sensitive_patterns.patterns);
    let state = Arc::new(RouterState {
        config: RwLock::new(Arc::new(config)),
        masker,
    });
    *crate::lock_util_recovered::recovered(STATE.write()) = Some(state);
    log::info!("inference router initialized");
}

/// 是否已初始化。
pub(crate) fn is_initialized() -> bool {
    state_snapshot().is_some()
}

/// 裁决入口（fail-closed 收敛点：任一内部失败 → Block）。
pub(crate) fn route(req: InferenceRequest) -> InferenceRouteResult {
    match route_inner(&req) {
        Ok(result) => result,
        Err(failure) => {
            failure.log();
            InferenceRouteResult {
                result: InferenceResult::Block,
                modifications: Vec::new(),
            }
        }
    }
}

/// 内部失败分类（日志级别区分：NoMatchPolicy 为 warn，其余 error）。
enum RouteFailure {
    NotInitialized,
    UnparseableBody(ParseError),
    Engine(crate::engine::RouteError),
    BuildModifications,
}

impl RouteFailure {
    fn log(&self) {
        match self {
            Self::NotInitialized => {
                log::error!("inference router: not initialized, blocking request");
            }
            Self::UnparseableBody(e) => {
                log::warn!("inference router: block, unparseable body: {}", e);
            }
            Self::Engine(e @ crate::engine::RouteError::NoMatchPolicy) => {
                log::warn!("inference router: block, {:?}", e);
            }
            Self::Engine(e) => {
                log::error!("inference router: block, {:?}", e);
            }
            Self::BuildModifications => {
                log::error!("inference router: block, build modifications failed");
            }
        }
    }
}

fn route_inner(req: &InferenceRequest) -> Result<InferenceRouteResult, RouteFailure> {
    let state = state_snapshot().ok_or(RouteFailure::NotInitialized)?;

    // ---- 1. 帧解析（body 空/空对象 → header-only 模式）----
    let header_only = req.body.is_empty() || req.body == "{}";
    let mut format = RequestFormat::OpenAI;
    let payloads = if header_only {
        Vec::new()
    } else {
        let parsed =
            parser::parse(&req.body, &req.headers).map_err(RouteFailure::UnparseableBody)?;
        format = parsed.format;
        parsed.payloads
    };

    // ---- 2. 引擎路由 ----
    let result = crate::engine::route(&state, &crate::engine::RouteRequest { payloads })
        .map_err(RouteFailure::Engine)?;

    // ---- 3. 构建修改项（空 → Forward）----
    let modifications =
        build_modifications(req, format, &result).ok_or(RouteFailure::BuildModifications)?;
    log::info!(
        "route: target {} model {} (strategy {}, masked={}, {} mod(s))",
        result.target,
        result.model_id,
        result.strategy_id,
        result.masked,
        modifications.len()
    );
    if modifications.is_empty() {
        return Ok(InferenceRouteResult {
            result: InferenceResult::Forward,
            modifications: Vec::new(),
        });
    }
    Ok(InferenceRouteResult {
        result: InferenceResult::Modified,
        modifications,
    })
}

/// 构建修改项（鉴权头 → host 重定向 → body 替换）。
fn build_modifications(
    req: &InferenceRequest,
    format: RequestFormat,
    result: &crate::engine::RouteResult,
) -> Option<Vec<InferenceModification>> {
    let mut mods = Vec::with_capacity(3);

    // ---- ① 鉴权头（凭据未配置 EMPTY 兜底）----
    let effective_cred = if result.credential.is_empty() {
        "EMPTY".to_string()
    } else {
        result.credential.clone()
    };
    if format == RequestFormat::Anthropic {
        let action = if req.headers.contains_key("x-api-key") {
            ModifyAction::Modify
        } else {
            ModifyAction::Add
        };
        mods.push(InferenceModification {
            action,
            target: ModifyTarget::Header,
            key: "x-api-key".to_string(),
            value: effective_cred,
        });
    } else {
        let action = if req.headers.contains_key("authorization") {
            ModifyAction::Modify
        } else {
            ModifyAction::Add
        };
        mods.push(InferenceModification {
            action,
            target: ModifyTarget::Header,
            key: "authorization".to_string(),
            value: format!("Bearer {effective_cred}"),
        });
    }

    // ---- ② host 重定向（endpoint host 与帧 host 不同时生成）----
    let endpoint_host = host_of_endpoint(&result.target_model.endpoint);
    let frame_host = req.headers.get("host").and_then(|v| v.to_str().ok());
    if !endpoint_host.is_empty()
        && (frame_host.is_none() || frame_host != Some(endpoint_host.as_str()))
    {
        let action = if req.headers.contains_key("host") {
            ModifyAction::Modify
        } else {
            ModifyAction::Add
        };
        mods.push(InferenceModification {
            action,
            target: ModifyTarget::Header,
            key: "host".to_string(),
            value: endpoint_host,
        });
    }

    // ---- ③ body 替换（header-only 跳过；脱敏生效或 model 需改写时生成）----
    let header_only = req.body.is_empty() || req.body == "{}";
    if !header_only && (result.masked || model_field_differs(&req.body, &result.model_id)) {
        let modified_body = build_modified_body(&req.body, result)?;
        mods.push(InferenceModification {
            action: ModifyAction::Add,
            target: ModifyTarget::Body,
            key: String::new(),
            value: modified_body,
        });
    }

    Some(mods)
}

/// endpoint URL → host[:port]（剥离 scheme://、userinfo 与 path）。
fn host_of_endpoint(endpoint: &str) -> String {
    let rest = match endpoint.find("://") {
        Some(pos) => &endpoint[pos + 3..],
        None => endpoint,
    };
    let rest = match rest.find('/') {
        Some(pos) => &rest[..pos],
        None => rest,
    };
    match rest.rfind('@') {
        Some(pos) => &rest[pos + 1..],
        None => rest,
    }
    .to_string()
}

/// body 替换条件：原 body 的 model 字段值 ≠ 目标模型（含缺失/非字符串）。
fn model_field_differs(body: &str, target_model_id: &str) -> bool {
    match serde_json::from_str::<Value>(body) {
        Ok(doc) if doc.is_object() => match doc.get("model") {
            Some(Value::String(s)) => s != target_model_id,
            _ => true,
        },
        _ => true,
    }
}

/// body 替换内容构建：model 注入 + user 消息 text 块逐段回写（非 text
/// 块原样保留）。段消费对齐 C++（text 块无论是否有 text 字段都推进
/// 段游标——行为保真）。
fn build_modified_body(original_body: &str, result: &crate::engine::RouteResult) -> Option<String> {
    let mut doc: Value = serde_json::from_str(original_body).ok()?;
    {
        let obj = doc.as_object_mut()?;

        // model 注入：已有且为字符串 → 替换；缺失 → 添加；非字符串 → 保留。
        match obj.get("model") {
            Some(Value::String(_)) | None => {
                obj.insert("model".to_string(), Value::String(result.model_id.clone()));
            }
            _ => {}
        }

        if let Some(Value::Array(messages)) = obj.get_mut("messages") {
            let mut payload_idx = 0usize;
            for message in messages.iter_mut() {
                let Some(message_obj) = message.as_object_mut() else {
                    continue;
                };
                if message_obj.get("role").and_then(Value::as_str) != Some("user") {
                    continue;
                }
                let Some(content) = message_obj.get_mut("content") else {
                    continue;
                };
                match content {
                    Value::String(_) => {
                        if payload_idx < result.payloads.len() {
                            *content = Value::String(result.payloads[payload_idx].clone());
                            payload_idx += 1;
                        }
                    }
                    Value::Array(blocks) => {
                        for block in blocks.iter_mut() {
                            let is_text = block
                                .as_object()
                                .and_then(|o| o.get("type"))
                                .and_then(Value::as_str)
                                == Some("text");
                            if is_text && payload_idx < result.payloads.len() {
                                if let Some(block_obj) = block.as_object_mut() {
                                    if block_obj.contains_key("text") {
                                        block_obj.insert(
                                            "text".to_string(),
                                            Value::String(result.payloads[payload_idx].clone()),
                                        );
                                    }
                                }
                                payload_idx += 1;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    serde_json::to_string(&doc).ok()
}

/// 应用 API key 管理请求（真实实现；对齐 C++ `manage_api_keys` 非事务
/// 语义：逐条处理，部分成功仍生效，任一失败返回首个错误）。
pub(crate) fn apply_api_key(req: &crate::ApiKeyRequest) -> Result<(), crate::ApiKeyError> {
    use crate::{ApiKeyAction, ApiKeyError};

    let state = state_snapshot().ok_or(ApiKeyError::NotInitialized)?;
    if req.items.is_empty() {
        return Ok(());
    }

    let mut first_err: Option<ApiKeyError> = None;
    match req.action {
        ApiKeyAction::Set => {
            let mut encrypted: HashMap<String, String> = HashMap::new();
            for item in &req.items {
                match encrypt_item(&state, item) {
                    Ok(cipher) => {
                        encrypted.insert(item.model_id.clone(), cipher);
                    }
                    Err(e) => {
                        log::error!("set api_key failed for one item: {}", e);
                        if first_err.is_none() {
                            first_err = Some(e);
                        }
                    }
                }
            }
            if !encrypted.is_empty() {
                if let Err(e) = crate::config::persist_and_update(&state.config, &encrypted, &[]) {
                    log::error!("persist api_keys failed: {}", e);
                    if first_err.is_none() {
                        first_err = Some(ApiKeyError::Storage);
                    }
                }
            }
        }
        ApiKeyAction::Delete => {
            let deletes: Vec<String> = req.items.iter().map(|i| i.model_id.clone()).collect();
            if let Err(e) =
                crate::config::persist_and_update(&state.config, &HashMap::new(), &deletes)
            {
                log::error!("delete api_keys failed: {}", e);
                if first_err.is_none() {
                    first_err = Some(ApiKeyError::Storage);
                }
            }
        }
    }

    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// 单条 set：模型存在且启用 → 加密。
fn encrypt_item(
    state: &RouterState,
    item: &crate::ApiKeyItem,
) -> Result<String, crate::ApiKeyError> {
    use crate::ApiKeyError;

    let config = state.config_snapshot();
    if !crate::config::model_enabled(&config, &item.model_id) {
        return Err(ApiKeyError::ModelNotFound);
    }
    crate::crypto::encrypt(&item.api_key).map_err(|e| match e {
        crate::crypto::CryptoError::EmptyPlaintext => ApiKeyError::Invalid,
        _ => ApiKeyError::Crypto,
    })
}

/// 查询指定模型的 API key（测试/观测缝：解密返回；未配置/解密失败 → None）。
pub(crate) fn api_key_for(model_id: &str) -> Option<String> {
    let state = state_snapshot()?;
    let config = state.config_snapshot();
    let encrypted = config.api_keys.get(model_id)?;
    if encrypted.is_empty() {
        return None;
    }
    crate::crypto::decrypt(encrypted).ok()
}
