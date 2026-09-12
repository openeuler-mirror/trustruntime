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

//! AgentSandbox HTTPS 透明代理库（**仅以 crate 库形态交付**——集成方经
//! Cargo 引入，不作为独立进程）。
//!
//! 职责：对 Agent 出站 HTTPS 流量做 MITM 解密、四维过滤（domain/method/uri/binary）、
//! 审计与动态证书签发（统一服务路径：端口监听 + 当前全局配置）。
//! 日志（审计 + 运行日志[四级 debug/info/warn/error]）统一经 [`logging`]
//! 模块以 [`facade::register_log_sink`] 回调交付（**必需 API**——未注册
//! 时审计 fail-closed）。
//! 架构决策见 `.sdd/SR.IR20260711000103.001`（SR-design v2.4）。

pub mod block_response;
pub mod cert;
pub mod error;
pub mod facade;
pub mod filter;
pub mod forward;
pub mod inference_uds;
pub mod logging;
pub mod mitm;
pub mod model;
pub mod server;
pub(crate) mod lock_util;
pub mod registry;

pub use error::{BindError, CaError, ConfigError};
pub use model::{
    Action, AuditLogEntry, CaCert, ContainerEndpoint, FilterConfig, InferenceRoute, Policy,
    Protocol, ProxyConfig, Reason, ResolverOutput, RuleEntry, SCENARIO_LIB,
};
pub use cert::{parse_ca, CertCache, CertIssuer, CertService, ParsedCa};
pub use registry::{Registry, Resolver};
pub use facade::{
    proxy_init, register_binary_resolver, register_log_sink, remove_container_policy,
    set_container_ca, set_container_config,
};
pub use facade::ProxyInitError;
pub use logging::{LogEvent, LogKind, LogLevel, LogSink, LogSinkError};
