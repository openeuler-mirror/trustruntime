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

//! 证书生成库
//!
//! 提供测试证书生成功能，供CLI工具和集成测试复用。
//!
//! ## 功能
//! - CA证书生成
//! - 签名者证书生成
//! - 过期/未生效证书生成
//! - 自签名证书生成
//! - TLS客户端/服务器证书生成
//! - CRL吊销列表生成

pub mod certificate;
pub mod utils;

pub use certificate::*;
pub use utils::*;
