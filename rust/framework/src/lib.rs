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

//! TrustRuntime 框架库 - 提供安全运行时的核心基础设施
//!
//! 该库为 TrustRuntime 提供模块化的基础组件，支持插件扩展和 Enclave 安全通信。
//!
//! ## 模块结构
//! - `cert`：证书管理，支持 PEM/DER 双格式加载和 ECC-256 证书处理
//! - `communication`：通信层，提供基于 vsock 的 TLS 安全传输
//! - `config`：配置管理，解析运行时配置文件
//! - `core`：核心功能，包括守护进程、证书检查和信号处理
//! - `logger`：日志系统，提供结构化日志输出
//! - `message`：消息定义，纯数据层，包含协议消息类型
//! - `plugin_manager`：插件管理器，负责插件加载和生命周期管理
//! - `transport`：传输层抽象，定义 TransportLayer 和 DataHandler trait

pub mod cert;
pub mod communication;
pub mod config;
pub mod core;
pub mod logger;
pub mod message;
pub mod plugin_manager;
pub mod transport;
