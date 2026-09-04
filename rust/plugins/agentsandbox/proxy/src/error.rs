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

//! 公共错误类型（K14：每接口独立枚举，`#[non_exhaustive]` 演进兼容）。
//!
//! 契约来源：模块详细设计说明书 4.1.3/4.2.3（K5/K6/K1）与 lib 门面说明书 4.3.2。

use thiserror::Error;

/// 过滤策略注入错误（K5）。
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// filter_config 结构非法（含三维通配模式不合法——空值/多星），保持
    /// 旧策略（fail-closed）。
    #[error("config_format_error")]
    Format,
    /// 无生效配置（remove 幂等语义，调用方可忽略）。
    #[error("config_not_found")]
    NotFound,
}

/// 端口绑定错误（K6）。
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindError {
    /// 监听端口已被占用。
    #[error("port_in_use")]
    PortInUse,
    /// 端口号不合法。
    #[error("invalid_port")]
    InvalidPort,
}

/// CA 注入错误（K1）。
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaError {
    /// CA 格式非法（非合法 PEM/X.509/PKCS#8），fail-closed。
    #[error("ca_invalid")]
    Invalid,
}
