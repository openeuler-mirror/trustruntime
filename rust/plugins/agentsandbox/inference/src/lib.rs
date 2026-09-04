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

//! 推理路由外部库契约（AR-005 推理路由；当前为 mock 空实现——真实
//! 外部库落地后在本 crate 内替换实现，契约面不变）。
//!
//! 职责边界（2026-09-05 接口修订）：proxy 在请求命中推理路由列表
//! （host+url 精确匹配，经 `proxy_init` 配置）后，将**全量缓冲**的请求
//! 以 [`InferenceRequest`] 交本库裁决；本库**不直接改写请求**，而是返回
//! [`InferenceRouteResult`]——裁决结果码（[`InferenceResult`]：
//! 0 原样转发 / 1 修改后转发 / 2 阻断）+ 修改列表（仅 result=Modified
//! 时生效，[`InferenceModification`] 逐条声明动作/目标/key/value）。
//! proxy 按返回值应用修改后转发（或 403 阻断）。
//!
//! 接口形态：同步 trait（body 已缓冲，无 I/O 等待语义）；实现方若需
//! 阻塞式重计算应自行控制耗时（调用发生在 proxy 异步线程上）。
//!
//! 数值映射（外部协议对接形态）：判别值即协议值——result 0/1/2、
//! action 1/2、target 1/2（FFI/serde 边界按 `as u8` 映射）。

use http::HeaderMap;

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

/// mock 空实现（真实外部库未落地前的占位）：恒返回
/// `Forward` + 空修改列表（原样转发）。
pub struct MockInferenceRouter;

impl InferenceRouter for MockInferenceRouter {
    fn route(&self, _req: InferenceRequest) -> InferenceRouteResult {
        InferenceRouteResult {
            result: InferenceResult::Forward,
            modifications: Vec::new(),
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
}
