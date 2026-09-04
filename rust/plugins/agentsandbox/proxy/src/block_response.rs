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

//! 阻断响应构造（reason → HTTP 状态码映射，用户 2026-08-31 决策）。
//!
//! 阻断不再静默关闭连接，而是向发起方返回 HTTP 错误响应（可观测、可区分
//! 失败类别），随后 `Connection: close` 关闭（fail-closed 不维持会话）：
//!
//! | 类别 | reason | 状态码 |
//! |---|---|---|
//! | 策略拒绝 | whitelist/blacklist/default_policy/binary_not_found/inference_route | **403 Forbidden** |
//! | 目标出站失败 | target_tls_error/connection_refused/connection_timeout | **502 Bad Gateway** |
//! | 配置/服务缺失 | config_not_found/group_id_not_found/log_write_error | **503 Service Unavailable** |
//!
//! TLS 层失败（无 SNI、CA 缺失、证书签发失败、MITM 握手失败）发生在 HTTP
//! 之前——无法返回 HTTP 响应，维持连接关闭（经日志观测）。
//! ca_error/cert_error 属证书链路：若握手已成功（不可能出现这两类阻断）
//! 防御性归 503。

use http::{HeaderName, HeaderValue, Response, StatusCode};

use crate::model::Reason;

/// 策略拒绝类 reason → 403。
fn is_policy_rejection(reason: Reason) -> bool {
    matches!(
        reason,
        Reason::WhitelistMatch
            | Reason::BlacklistMatch
            | Reason::DefaultPolicy
            | Reason::BinaryNotFound
            | Reason::InferenceRoute
    )
}

/// 目标出站失败类 reason → 502。
fn is_target_failure(reason: Reason) -> bool {
    matches!(
        reason,
        Reason::TargetTlsError | Reason::ConnectionRefused | Reason::ConnectionTimeout
    )
}

/// reason → 阻断响应状态码（403/502/503 三类映射）。
pub fn block_status(reason: Reason) -> StatusCode {
    if is_policy_rejection(reason) {
        StatusCode::FORBIDDEN
    } else if is_target_failure(reason) {
        StatusCode::BAD_GATEWAY
    } else {
        // 配置缺失/审计失败/证书类防御性归 503。
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// 构造最小错误响应体（不含敏感信息；状态行语义文本）。
fn block_body(status: StatusCode) -> &'static str {
    match status {
        StatusCode::FORBIDDEN => "forbidden by policy",
        StatusCode::BAD_GATEWAY => "upstream target unavailable",
        _ => "service unavailable",
    }
}

/// 构造阻断响应（`Connection: close` + 最短文本体）。
///
/// 供 hyper 服务层直接返回（body 为完整 body 类型）。
pub fn block_response(reason: Reason) -> Response<http_body_util::Full<bytes::Bytes>> {
    let status = block_status(reason);
    let mut response = Response::new(http_body_util::Full::new(bytes::Bytes::from_static(
        block_body(status).as_bytes(),
    )));
    *response.status_mut() = status;
    // fail-closed：阻断后不维持会话（h1 显式关连接；h2 流结束 + GOAWAY 语义
    // 由 hyper 承接）。
    response.headers_mut().insert(
        HeaderName::from_static("connection"),
        HeaderValue::from_static("close"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    // reason→状态码映射表（403/502/503 全覆盖）。
    #[test]
    fn reason_to_status_mapping() {
        // 403：策略拒绝类。
        for reason in [
            Reason::WhitelistMatch,
            Reason::BlacklistMatch,
            Reason::DefaultPolicy,
            Reason::BinaryNotFound,
            Reason::InferenceRoute,
        ] {
            assert_eq!(block_status(reason), StatusCode::FORBIDDEN, "{reason:?}");
        }
        // 502：目标出站失败类。
        for reason in [
            Reason::TargetTlsError,
            Reason::ConnectionRefused,
            Reason::ConnectionTimeout,
        ] {
            assert_eq!(block_status(reason), StatusCode::BAD_GATEWAY, "{reason:?}");
        }
        // 503：配置/服务缺失类。
        for reason in [Reason::ConfigNotFound, Reason::GroupIdNotFound] {
            assert_eq!(
                block_status(reason),
                StatusCode::SERVICE_UNAVAILABLE,
                "{reason:?}"
            );
        }
    }

    // 阻断响应构造：状态码 + Connection: close + 非空最小体。
    #[test]
    fn block_response_shape() {
        let resp = block_response(Reason::BlacklistMatch);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers().get("connection").and_then(|v| v.to_str().ok()),
            Some("close")
        );
        let (parts, body) = resp.into_parts();
        let _ = parts;
        // Full<Bytes> body 为立即就绪的同步 body——轮询一次即可收集。
        let bytes = futures_ready_collect(body);
        assert!(!bytes.is_empty());
    }

    /// 无 futures 依赖下收集 Full body（poll_frame 一次即完）。
    fn futures_ready_collect(mut body: http_body_util::Full<bytes::Bytes>) -> bytes::Bytes {
        use http_body::Body as _;
        let mut collected = bytes::BytesMut::new();
        loop {
            match std::pin::Pin::new(&mut body)
                .poll_frame(&mut std::task::Context::from_waker(std::task::Waker::noop()))
            {
                std::task::Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        collected.extend_from_slice(&data);
                    }
                }
                std::task::Poll::Ready(None) => break,
                _ => break,
            }
        }
        collected.freeze()
    }
}
