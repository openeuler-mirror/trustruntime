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

//! 推理路由外部库（AR-005 推理路由；BeDemo C++ 移植真实实现）。
//!
//! 职责边界（2026-09-05 接口修订）：proxy 在请求命中推理路由列表
//! （host+url 精确匹配，经 `proxy_init` 配置）后，将**全量缓冲**的请求
//! 以 [`InferenceRequest`] 交本库裁决；本库**不直接改写请求**，而是返回
//! [`InferenceRouteResult`]——裁决结果码（[`InferenceResult`]：
//! 0 原样转发 / 1 修改后转发 / 2 阻断）+ 修改列表（仅 result=Modified
//! 时生效，[`InferenceModification`] 逐条声明动作/目标/key/value）。
//! proxy 按返回值应用修改后转发（或 403 阻断）。
//!
//! 真实实现（2026-09-17 落地，契约面不变）：`init(config_dir)` 加载
//! 四配置（路由策略 / 模型 / 敏感模式 / API-Key 密文存储）后，
//! [`AgentRouter`] 按「脱敏检测 → 策略选择 → 鉴权注入 + host 重定向 +
//! body 回写」产出修改指令；API-Key 经 AES-256-GCM 加密持久化。未
//! 初始化调用一律 Block（fail-closed）。[`MockInferenceRouter`] 保留为
//! 测试替身。
//!
//! 接口形态：同步 trait（body 已缓冲，无 I/O 等待语义）；实现方若需
//! 阻塞式重计算应自行控制耗时（调用发生在 proxy 异步线程上）。
//!
//! 数值映射（外部协议对接形态）：判别值即协议值——result 0/1/2、
//! action 1/2、target 1/2（FFI/serde 边界按 `as u8` 映射）。

mod config;
mod crypto;
mod engine;
mod masker;
mod parser;
mod router;

use http::HeaderMap;
use serde::{Deserialize, Serialize};

/// 推理路由请求（proxy 侧全量缓冲后的可裁决形态——仅含外部库关注的
/// 请求头与请求体；method/uri 不在裁决面）。
///
/// `body` 为 UTF-8 文本（proxy 侧 lossy 转换——非法字节序列替换为
/// U+FFFD，**仅影响本库可见性**：`Forward`（无 body 修改）时 proxy 仍
/// 转发原始字节，转发保真不受损）。
#[derive(Debug, Clone)]
pub struct InferenceRequest {
    /// 请求头集合。
    pub headers: HeaderMap,
    /// 请求体（已全量缓冲的 UTF-8 文本——推理流量 JSON）。
    pub body: String,
}

/// 裁决结果码（协议值：0/1/2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InferenceResult {
    /// 0：原样转发（修改列表忽略）。
    Forward = 0,
    /// 1：修改后转发（应用修改列表）。
    Modified = 1,
    /// 2：阻断（proxy 返回 403 并审计 deny）。
    Block = 2,
}

/// 修改动作（协议值：1/2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ModifyAction {
    /// 1：添加（header 场景：key 已存在则跳过——只加新头）。
    Add = 1,
    /// 2：修改（header 场景：key 不存在则补写——upsert 语义）。
    Modify = 2,
}

/// 修改目标类型（协议值：1/2；Rust 侧命名 target——`type` 为关键字）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ModifyTarget {
    /// 1：请求头（key=头名、value=头值）。
    Header = 1,
    /// 2：请求体（key 忽略、value=替换后的完整请求体；整体替换——
    /// 多条按列表序覆盖，最后一条生效）。
    Body = 2,
}

/// 单条修改项（外部库按列表逐条声明；仅 result=Modified 时由 proxy 应用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceModification {
    /// 修改动作（1=添加 / 2=修改）。
    pub action: ModifyAction,
    /// 修改目标（1=header / 2=body）。
    pub target: ModifyTarget,
    /// Header：请求头 key（头名）；Body：忽略（空串约定）。
    pub key: String,
    /// Header：key 对应的 value（头值）；Body：替换后的完整请求体。
    pub value: String,
}

/// 裁决返回（决策码 + 修改列表）。
///
/// `modifications` 仅在 `result == Modified` 时由 proxy 应用——其余
/// 结果码下忽略（外部库应返回空列表，proxy 不做强制约束）。
#[derive(Debug, Clone)]
pub struct InferenceRouteResult {
    /// 裁决结果（0=Forward / 1=Modified / 2=Block）。
    pub result: InferenceResult,
    /// 修改列表（仅 Modified 生效）。
    pub modifications: Vec<InferenceModification>,
}

/// 推理路由外部库接口（proxy 经 crate 依赖引入并逐请求调用）。
///
/// 外部库**不构造/改写请求对象**——裁决语义经 [`InferenceRouteResult`]
/// 声明，修改由 proxy 统一应用（契约收敛点）。
pub trait InferenceRouter: Send + Sync {
    /// 对命中推理路由列表的请求做裁决。
    fn route(&self, req: InferenceRequest) -> InferenceRouteResult;
}

/// mock 空实现（测试替身）：恒返回 `Forward` + 空修改列表（原样转发）。
pub struct MockInferenceRouter;

impl InferenceRouter for MockInferenceRouter {
    fn route(&self, _req: InferenceRequest) -> InferenceRouteResult {
        InferenceRouteResult {
            result: InferenceResult::Forward,
            modifications: Vec::new(),
        }
    }
}

// ===== 真实实现（BeDemo C++ 移植；契约面与上方打桩期一致）=====

/// 初始化错误（Display 仅含固定文件名/字段级信息，不含路径——日志安全）。
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// 配置文件不可读（routing_policy / model_config / sensitive_patterns 必需）。
    #[error("config load failed: {file}")]
    Load {
        /// 固定文件名（非路径）。
        file: &'static str,
    },
    /// JSON 解析失败或根结构非法。
    #[error("config parse failed: {file}")]
    Parse {
        /// 固定文件名（非路径）。
        file: &'static str,
    },
    /// 配置校验失败（全部规则错误以 "; " 连接）。
    #[error("config validation failed: {0}")]
    Validation(String),
}

impl From<config::error::ConfigError> for InitError {
    fn from(e: config::error::ConfigError) -> Self {
        match e {
            config::error::ConfigError::Load { file } => InitError::Load { file },
            config::error::ConfigError::Parse { file } => InitError::Parse { file },
            config::error::ConfigError::Validation(msg) => InitError::Validation(msg),
            config::error::ConfigError::Persist => InitError::Load {
                file: "api_keys.json",
            },
        }
    }
}

/// 全局初始化：加载 config_dir 下四配置并构建脱敏引擎。
///
/// - 可重复调用（配置重载语义，对齐 C++ init 后 `load_and_parse_config`
///   重复加载）；
/// - `api_keys.json` 允许缺失（空态起步，经 [`apply_api_key`] 落盘）；
/// - 失败不改变既有状态（构建成功才替换全局槽位）。
pub fn init(config_dir: &str) -> Result<(), InitError> {
    router::init(config_dir)
}

/// 默认配置初始化（未提供 config_dir 时使用）。
///
/// 三份只读配置（路由策略 / 模型 / 敏感模式）取内嵌默认
/// （`resources/config`，`include_str!` 编入——不依赖部署侧文件路径）；
/// `api_keys.json` 落状态目录：env `AGENT_ROUTER_STATE_DIR` 覆盖，默认
/// `{temp}/agentsandbox-inference/`（首用创建空态，密文跨 init 保留；
/// temp 目录重启后可能被清理——持久化部署请用 [`init`] 指定目录）。
pub fn init_default() -> Result<(), InitError> {
    router::init_default()
}

/// 是否已初始化（[`init`] 成功后为 true）。
pub fn is_initialized() -> bool {
    router::is_initialized()
}

/// 真实裁决器（无内部可变状态——经 [`init`] 建立的进程级快照裁决）。
///
/// 未初始化时 [`InferenceRouter::route`] 恒 Block（fail-closed）。
pub struct AgentRouter;

impl InferenceRouter for AgentRouter {
    fn route(&self, req: InferenceRequest) -> InferenceRouteResult {
        router::route(req)
    }
}

/// 默认裁决器：已初始化 → [`AgentRouter`]；未初始化 → [`MockInferenceRouter`]
/// （proxy 默认装配点——无配置时保持既有 mock 语义，测试零回归）。
pub fn default_router() -> Box<dyn InferenceRouter> {
    if is_initialized() {
        Box::new(AgentRouter)
    } else {
        Box::new(MockInferenceRouter)
    }
}

// ===== API key 管理（真实实现——AES-256-GCM 加密 + api_keys.json 持久化）=====

/// API key 管理动作（facade `set_api_key` 入参 / UDS msg_type=1 body）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyAction {
    /// 设置：有则更新、无则添加（upsert）。
    Set,
    /// 删除：按 `model_id` 移除（`api_key` 字段忽略；不存在幂等成功）。
    Delete,
}

/// API key 条目（`{model_id, api_key}`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyItem {
    /// 模型标识（非空）。
    pub model_id: String,
    /// API key（set 时非空；delete 时忽略）。
    pub api_key: String,
}

/// API key 管理请求（facade [`set_api_key`](crate::facade 侧同名) 入参；
/// serde 形态 `{"action":"set","items":[{"model_id":"GLM_53","api_key":"sk-112"}]}`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyRequest {
    /// 管理动作。
    pub action: ApiKeyAction,
    /// 条目列表（空列表 = no-op 成功）。
    #[serde(default)]
    pub items: Vec<ApiKeyItem>,
}

/// API key 管理错误。
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApiKeyError {
    /// 参数非法（set 的 model_id/api_key 空或 delete 的 model_id 空）。
    #[error("api_key_invalid")]
    Invalid,
    /// UDS 交付失败（远程推理服务不可用——可重试）。
    #[error("api_key_delivery")]
    Delivery,
    /// 真实库：全局未初始化（[`init`] 未调用）。
    #[error("api_key_not_initialized")]
    NotInitialized,
    /// 真实库：model_id 不在 model_config 或已禁用（对齐 C++ set 路径
    /// `get_model_config` 校验；delete 路径不校验——幂等）。
    #[error("api_key_model_not_found")]
    ModelNotFound,
    /// 真实库：加密失败（`CONFIG_ENCRYPTION_KEY` 缺失/非法等）。
    #[error("api_key_crypto")]
    Crypto,
    /// 真实库：api_keys.json 持久化失败。
    #[error("api_key_storage")]
    Storage,
}

/// 应用 API key 管理请求（真实实现，对齐 C++ `manage_api_keys` 语义）。
///
/// - `Set`：逐条校验模型存在且启用 → AES-256-GCM 加密 → 批量落盘 +
///   内存快照更新（部分成功仍生效，任一条失败返回首个错误）；
/// - `Delete`：逐条按 `model_id` 移除（`api_key` 忽略；不存在幂等成功）；
/// - 空列表：no-op 成功；
/// - 未初始化：[`ApiKeyError::NotInitialized`]。
pub fn apply_api_key(req: &ApiKeyRequest) -> Result<(), ApiKeyError> {
    router::apply_api_key(req)
}

/// 查询指定模型的 API key（测试/观测缝——解密后的明文；未配置或
/// 解密失败返回 None）。
pub fn api_key_for(model_id: &str) -> Option<String> {
    router::api_key_for(model_id)
}

/// 全局锁的锁恢复（PoisonError 自愈——与 proxy lock_util 同语义；
/// crate 内最小实现避免依赖）。
pub(crate) mod lock_util_recovered {
    /// 锁获取结果 → 值/守卫（毒化自愈；泛型透传）。
    pub(crate) fn recovered<T>(result: std::sync::LockResult<T>) -> T {
        match result {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> InferenceRequest {
        InferenceRequest {
            headers: HeaderMap::new(),
            body: "{\"q\":\"hi\"}".to_string(),
        }
    }

    // mock 空实现：恒 Forward + 空修改列表。
    #[test]
    fn mock_router_always_forwards() {
        let router = MockInferenceRouter;
        let out = router.route(sample_request());
        assert_eq!(out.result, InferenceResult::Forward);
        assert!(out.modifications.is_empty());
    }

    // 协议数值映射锚定（外部 FFI/serde 对接契约）：判别值不可漂移。
    #[test]
    fn protocol_numeric_values() {
        assert_eq!(InferenceResult::Forward as u8, 0);
        assert_eq!(InferenceResult::Modified as u8, 1);
        assert_eq!(InferenceResult::Block as u8, 2);
        assert_eq!(ModifyAction::Add as u8, 1);
        assert_eq!(ModifyAction::Modify as u8, 2);
        assert_eq!(ModifyTarget::Header as u8, 1);
        assert_eq!(ModifyTarget::Body as u8, 2);
    }

    // 修改项构造形态：header add / header modify / body 整体替换。
    #[test]
    fn modification_shapes() {
        let header_add = InferenceModification {
            action: ModifyAction::Add,
            target: ModifyTarget::Header,
            key: "x-trace-id".to_string(),
            value: "abc".to_string(),
        };
        let header_modify = InferenceModification {
            action: ModifyAction::Modify,
            target: ModifyTarget::Header,
            key: "authorization".to_string(),
            value: "Bearer new-token".to_string(),
        };
        let body_replace = InferenceModification {
            action: ModifyAction::Modify,
            target: ModifyTarget::Body,
            key: String::new(), // body 场景 key 忽略。
            value: "{\"q\":\"rewritten\"}".to_string(),
        };
        let result = InferenceRouteResult {
            result: InferenceResult::Modified,
            modifications: vec![header_add, header_modify, body_replace],
        };
        assert_eq!(result.modifications.len(), 3);
        assert_eq!(result.modifications[0].key, "x-trace-id");
        assert_eq!(result.modifications[2].value, "{\"q\":\"rewritten\"}");
    }

    // 请求体 String 形态：文本直读 + 与修改 value 同型（对称契约）。
    #[test]
    fn request_body_is_text() {
        let req = sample_request();
        assert_eq!(req.body, "{\"q\":\"hi\"}");
        assert_eq!(
            req.body.chars().count(),
            10,
            "body 为 UTF-8 文本（可直接字符串操作）"
        );
    }

    // ===== API key 契约测试（2026-09-17；存储语义见 tests/router_e2e.rs）=====

    fn item(model_id: &str, api_key: &str) -> ApiKeyItem {
        ApiKeyItem {
            model_id: model_id.to_string(),
            api_key: api_key.to_string(),
        }
    }

    // serde 形态锚定（UDS msg_type=1 body / facade 入参 JSON 同构）：
    // {"action":"set","items":[{"model_id":"GLM_53","api_key":"sk-112"}]}
    #[test]
    fn api_key_request_serde_shape() {
        let req = ApiKeyRequest {
            action: ApiKeyAction::Set,
            items: vec![item("GLM_53", "sk-112")],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"action":"set","items":[{"model_id":"GLM_53","api_key":"sk-112"}]}"#
        );
        let back: ApiKeyRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);

        // delete 形态 + items 缺省（空列表）。
        let del: ApiKeyRequest =
            serde_json::from_str(r#"{"action":"delete","items":[{"model_id":"M1","api_key":""}]}"#)
                .unwrap();
        assert_eq!(del.action, ApiKeyAction::Delete);
        let no_items: ApiKeyRequest = serde_json::from_str(r#"{"action":"set"}"#).unwrap();
        assert!(no_items.items.is_empty());
    }
}
