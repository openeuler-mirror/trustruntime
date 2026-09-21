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

//! 配置错误（Display 仅含固定文件名与字段级信息，不含路径——日志安全）。

/// 配置加载/解析/校验/持久化错误。
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    /// 文件不可读（不存在/路径过长/IO 错误）。
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
    /// 校验失败（全部规则错误以 "; " 连接）。
    #[error("config validation failed: {0}")]
    Validation(String),
    /// api_keys.json 持久化失败。
    #[error("api_keys persist failed")]
    Persist,
}

/// 凭据获取错误（对应 C++ ApiKeyMissing / ConfigNotFound / 解密异常三分支）。
#[derive(Debug)]
pub(crate) enum CredentialError {
    /// 模型不存在于 model_config。
    NotFound,
    /// 模型未配置 API-Key（不算失败——route 侧收敛为空凭据）。
    Missing,
    /// 解密失败（如密钥与密文不匹配）。
    Crypto(crate::crypto::CryptoError),
}
