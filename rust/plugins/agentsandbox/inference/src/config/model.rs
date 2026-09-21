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

//! 配置数据模型（BeDemo `src/access_control_config/include/model/` 移植）。
//!
//! 字段与默认值逐一对齐 C++ loader 语义：缺失或类型不符的字段取默认值
//! （宽松提取），结构性错误由 [`crate::config::validator`] 统一校验。

use std::collections::HashMap;
use std::path::PathBuf;

/// 路由策略触发条件（三维保留字段 + model_id 精确匹配）。
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Condition {
    /// 敏感数据已检出（保留字段，决策实际以脱敏对比结果为准）。
    pub sensitive_data_detected: bool,
    /// 本地模型可用（保留字段）。
    pub local_model_available: Option<bool>,
    /// 请求格式（openai/anthropic/any；保留字段）。
    pub request_format: Option<String>,
    /// 精确匹配的请求模型标识；None = 通配。
    pub model_id: Option<String>,
}

/// 路由策略动作。
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Action {
    /// 目标（local / cloud / cloud_with_sanitization）。
    pub target: String,
    /// 目标模型标识（model_config 中定义）。
    pub model_id: String,
    /// 检出敏感信息时是否采用脱敏结果（默认 false）。
    pub sanitize: Option<bool>,
}

/// 单条路由策略。
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Strategy {
    pub strategy_id: String,
    pub name: String,
    /// 默认 true。
    pub enabled: bool,
    /// 默认 50（值域 1-100，越小越优先）。
    pub priority: i32,
    pub condition: Condition,
    pub action: Action,
}

/// 路由策略配置（routing_policy.json）。
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct RoutingPolicyConfig {
    pub version: String,
    pub default_priority: Vec<String>,
    pub strategies: Vec<Strategy>,
}

/// 目标模型配置（model_config.json 单项）。
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct ModelConfig {
    pub model_id: String,
    pub name: String,
    /// cloud / local（参与策略选择）。
    pub type_: String,
    /// openai / anthropic / custom。
    pub provider: String,
    /// 目标端点 URL（host 重定向来源）。
    pub endpoint: String,
    /// 默认 30000。
    pub timeout_ms: i32,
    /// 默认 3。
    pub max_retries: i32,
    /// 附加请求头。
    pub headers: Option<std::collections::BTreeMap<String, String>>,
    /// 默认 true。
    pub enabled: bool,
}

/// 敏感数据识别模式（sensitive_patterns.json 单项；脱敏模块共用）。
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Pattern {
    pub pattern_id: String,
    pub name: String,
    /// 实体类型（对应 C++ 字段 `type`——Rust 关键字避让）。
    pub type_: String,
    pub regex: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub description: Option<String>,
    /// 默认 medium。
    pub severity: String,
    /// 默认 true。
    pub enabled: bool,
    /// 关键词到实体的字符距离窗口（对应 C++ 字段 keyDist；默认 50）。
    pub key_dist: usize,
}

/// 敏感模式配置（sensitive_patterns.json）。
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct SensitivePatternsConfig {
    pub version: String,
    pub patterns: Vec<Pattern>,
}

/// 全量运行时配置（四文件聚合；api_keys 经管理操作原地演进）。
#[derive(Debug, Clone, Default)]
pub(crate) struct Config {
    pub routing_policy: RoutingPolicyConfig,
    /// model_id → 模型配置。
    pub models: HashMap<String, ModelConfig>,
    pub sensitive_patterns: SensitivePatternsConfig,
    /// model_id → 加密后的 API-Key（密文，base64）。
    pub api_keys: HashMap<String, String>,
    /// api_keys.json 路径（持久化目标）。
    pub api_keys_path: PathBuf,
}
