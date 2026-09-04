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

//! 过滤引擎（AR-002 承接：规则求值引擎、四维匹配器、filter_config 校验器）。
//!
//! 契约来源：模块详细设计说明书 4.1（求值引擎——T2）、4.2（四维匹配语义——
//! T1）、4.3（结构校验——T3）；求值签名与 Action/Reason 常量的权威定义在
//! AR-001 4.1.3（K3，`crate::model`），本模块为实现方。

pub mod engine;
pub mod matcher;

pub use engine::evaluate;
