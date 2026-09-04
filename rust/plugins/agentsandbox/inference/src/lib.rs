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
//! 职责边界：proxy 在请求命中推理路由列表（host+url 精确匹配，经
//! `proxy_init` 配置）后，将**全量缓冲**的请求以 [`InferenceRequest`]
//! 交本库裁决；本库可检查并**更改 header/body**，反馈三态决策
//! （[`InferenceDecision`]）：原样转发 / 更改后转发 / 阻断。proxy 按
//! 决策执行对应处理（转发或 403 阻断）。
//!
//! 接口形态：同步 trait（body 已缓冲，无 I/O 等待语义）；实现方若需
//! 阻塞式重计算应自行控制耗时（调用发生在 proxy 异步线程上）。

use bytes::Bytes;
use http::{HeaderMap, Method, Uri};

/// 推理路由请求（proxy 侧全量缓冲后的完整请求形态）。
#[derive(Debug, Clone)]
pub struct InferenceRequest {
    /// HTTP 方法。
    pub method: Method,
    /// 请求 URI（路径 + query）。
    pub uri: Uri,
    /// 请求头集合。
    pub headers: HeaderMap,
    /// 请求体（已全量缓冲）。
    pub body: Bytes,
}

/// 推理路由决策（外部库反馈三态）。
///
/// `ForwardModified` 装箱收敛变体大小差异（`InferenceRequest` 240 字节级）。
#[derive(Debug, Clone)]
pub enum InferenceDecision {
    /// 原样转发（不改写请求任何部分）。
    Forward,
    /// 更改后转发（header/body 均可改——以返回的请求为准）。
    ForwardModified(Box<InferenceRequest>),
    /// 阻断（proxy 返回 403 并审计 deny）。
    Block,
}

/// 推理路由外部库接口（proxy 经 crate 依赖引入并逐请求调用）。
pub trait InferenceRouter: Send + Sync {
    /// 对命中推理路由列表的请求做裁决。
    fn route(&self, req: InferenceRequest) -> InferenceDecision;
}

/// mock 空实现（真实外部库未落地前的占位）：恒返回 [`InferenceDecision::Forward`]
/// （原样转发——不检查不改写请求）。
pub struct MockInferenceRouter;

impl InferenceRouter for MockInferenceRouter {
    fn route(&self, _req: InferenceRequest) -> InferenceDecision {
        InferenceDecision::Forward
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> InferenceRequest {
        InferenceRequest {
            method: Method::POST,
            uri: "/v1/chat/completions".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"{\"q\":\"hi\"}"),
        }
    }

    // mock 空实现：恒 Forward（不检查不改写）。
    #[test]
    fn mock_router_always_forwards() {
        let router = MockInferenceRouter;
        assert!(matches!(
            router.route(sample_request()),
            InferenceDecision::Forward
        ));
    }

    // 决策枚举形状：三态可构造可匹配。
    #[test]
    fn decision_variants_shape() {
        let req = sample_request();
        assert!(matches!(
            InferenceDecision::Forward,
            InferenceDecision::Forward
        ));
        assert!(matches!(InferenceDecision::Block, InferenceDecision::Block));
        match InferenceDecision::ForwardModified(Box::new(req)) {
            InferenceDecision::ForwardModified(r) => {
                assert_eq!(r.method, Method::POST);
                assert_eq!(r.body, Bytes::from_static(b"{\"q\":\"hi\"}"));
            }
            _ => panic!("expected ForwardModified"),
        }
    }
}
