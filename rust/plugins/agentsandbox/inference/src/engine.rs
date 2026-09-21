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

//! 路由决策引擎（BeDemo `route_engine.cpp` 移植）。
//!
//! 决策序：逐段脱敏（总是执行）→ 敏感对比 → 策略选择（敏感 → 全
//! enabled 最小 priority；干净 → cloud 优先降级 local）→ 脱敏结果选择
//! （`sanitize` 只控制用哪个结果）→ 凭据获取（缺配置不算失败）→ 目标
//! 模型连接信息。

use std::collections::HashMap;
use std::sync::Arc;

use crate::config::model::{Config, ModelConfig, Strategy};
use crate::config::{get_api_key, CredentialError};
use crate::router::RouterState;

/// 路由请求（用户输入文本段）。
pub(crate) struct RouteRequest {
    pub payloads: Vec<String>,
}

/// 路由结果。
pub(crate) struct RouteResult {
    pub strategy_id: String,
    pub target: String,
    pub model_id: String,
    pub payloads: Vec<String>,
    pub masked: bool,
    pub credential: String,
    pub target_model: ModelConfig,
}

/// 路由错误（对应 C++ RouteErrorCode；MaskerFailure 在纯 Rust 回退实现
/// 中不可达，未保留）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteError {
    /// 无策略命中（无兜底）。
    NoMatchPolicy,
    /// 凭据接口执行失败（解密异常；未配置不算失败——返回空）。
    CredentialProviderFailure,
    /// 目标模型不存在或已禁用。
    TargetModelNotFound,
}

/// 路由决策入口（同步、无 I/O）。
pub(crate) fn route(
    state: &RouterState,
    request: &RouteRequest,
) -> Result<RouteResult, RouteError> {
    let config: Arc<Config> = state.config_snapshot();

    // ---- 1. 逐段脱敏（mask 总是执行，结果供 sanitize 选择）----
    let masked_payloads: Vec<String> = request.payloads.iter().map(|p| state.mask(p)).collect();

    // ---- 2. 对比脱敏前后，判断是否包含敏感信息 ----
    let has_sensitive = request
        .payloads
        .iter()
        .zip(&masked_payloads)
        .any(|(original, masked)| original != masked);

    // ---- 3. 策略选择 ----
    let models = &config.models;
    let matched = if has_sensitive {
        find_first_enabled(&config.routing_policy.strategies, models, "")
    } else {
        find_first_enabled(&config.routing_policy.strategies, models, "cloud")
            .or_else(|| find_first_enabled(&config.routing_policy.strategies, models, "local"))
    };
    let Some(matched) = matched else {
        return Err(RouteError::NoMatchPolicy);
    };

    // ---- 4. 脱敏结果选择 ----
    let (payloads, masked) = if has_sensitive && matched.action.sanitize.unwrap_or(false) {
        (masked_payloads, true)
    } else {
        (request.payloads.clone(), false)
    };

    // ---- 5. 凭据获取（未配置 → 空；解密失败 → 失败）----
    let credential = match get_api_key(&config, &matched.action.model_id) {
        Ok(key) => key,
        Err(CredentialError::NotFound) | Err(CredentialError::Missing) => String::new(),
        Err(CredentialError::Crypto(e)) => {
            log::error!("credential provider failed: {}", e);
            return Err(RouteError::CredentialProviderFailure);
        }
    };

    // ---- 6. 目标模型连接信息 ----
    let target_model = models
        .get(&matched.action.model_id)
        .filter(|m| m.enabled)
        .cloned()
        .ok_or(RouteError::TargetModelNotFound)?;

    Ok(RouteResult {
        strategy_id: matched.strategy_id.clone(),
        target: matched.action.target.clone(),
        model_id: matched.action.model_id.clone(),
        payloads,
        masked,
        credential,
        target_model,
    })
}

/// 按 priority 升序从 enabled 策略中选最小的一条（同优先级取先出现者）。
///
/// `target_model_type` 非空时按 model_config 的 type 过滤（cloud/local）。
fn find_first_enabled<'a>(
    strategies: &'a [Strategy],
    models: &HashMap<String, ModelConfig>,
    target_model_type: &str,
) -> Option<&'a Strategy> {
    let mut best: Option<&Strategy> = None;
    for s in strategies {
        if !s.enabled {
            continue;
        }
        if !target_model_type.is_empty() {
            match models.get(&s.action.model_id) {
                Some(model) if model.type_ == target_model_type => {}
                _ => continue,
            }
        }
        if best.map_or(true, |b| s.priority < b.priority) {
            best = Some(s);
        }
    }
    best
}
