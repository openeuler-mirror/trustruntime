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

//! API-Key 加解密（BeDemo `kunpeng_crypto.cpp` 移植——AES-256-GCM 纯 Rust 实现）。
//!
//! 线格式与 C++ OpenSSL 版互通：`base64(nonce[12] ‖ ciphertext ‖ tag[16])`。
//! 密钥来自环境变量 `CONFIG_ENCRYPTION_KEY`（Base64 编码的 32 字节），
//! 与 C++ 仓库约定的部署密钥一致，可互读 `api_keys.json`。
//!
//! C++ 侧 `CRYPTO_IMPL=sdf`（鲲鹏 SM4）在库模式路径实际未启用（恒走
//! AES-256-GCM 回退），故不移植。

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use zeroize::Zeroizing;

/// 密钥长度（字节）。
pub(crate) const KEY_SIZE: usize = 32;
/// GCM nonce 长度（字节）。
const NONCE_SIZE: usize = 12;
/// GCM 认证标签长度（字节）。
const TAG_SIZE: usize = 16;

/// 加解密错误（Display 不含密钥/密文内容——日志安全）。
#[derive(Debug, thiserror::Error)]
pub(crate) enum CryptoError {
    /// `CONFIG_ENCRYPTION_KEY` 未设置。
    #[error("encryption key not configured")]
    KeyMissing,
    /// 密钥 Base64 解码失败或长度非 32 字节。
    #[error("encryption key invalid")]
    KeyInvalid,
    /// 明文为空（C++ encrypt 对空明文直接拒绝）。
    #[error("plaintext is empty")]
    EmptyPlaintext,
    /// 加密失败。
    #[error("encrypt failed")]
    Encrypt,
    /// 密文 Base64 解码失败。
    #[error("malformed ciphertext")]
    Malformed,
    /// 密文长度不足（< nonce + tag）。
    #[error("ciphertext too short")]
    TooShort,
    /// 解密失败（认证标签不符——密钥不匹配或密文损坏）。
    #[error("decrypt failed")]
    Decrypt,
}

/// 从环境变量读取并解码密钥（C++ `get_key`）。
fn load_key() -> Result<Zeroizing<[u8; KEY_SIZE]>, CryptoError> {
    let raw = std::env::var("CONFIG_ENCRYPTION_KEY")
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or(CryptoError::KeyMissing)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw.as_bytes())
        .map_err(|_| CryptoError::KeyInvalid)?;
    let key: [u8; KEY_SIZE] = decoded.try_into().map_err(|_| CryptoError::KeyInvalid)?;
    Ok(Zeroizing::new(key))
}

/// 加密（密钥取自环境变量）。
pub(crate) fn encrypt(plaintext: &str) -> Result<String, CryptoError> {
    let key = load_key()?;
    encrypt_with(&key, plaintext)
}

/// 解密（密钥取自环境变量）。
pub(crate) fn decrypt(ciphertext_b64: &str) -> Result<String, CryptoError> {
    let key = load_key()?;
    decrypt_with(&key, ciphertext_b64)
}

/// 显式密钥加密（测试与内部复用）。
pub(crate) fn encrypt_with(key: &[u8; KEY_SIZE], plaintext: &str) -> Result<String, CryptoError> {
    if plaintext.is_empty() {
        return Err(CryptoError::EmptyPlaintext);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Encrypt)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    // aes-gcm 输出 = ciphertext ‖ tag。
    let sealed = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| CryptoError::Encrypt)?;
    let mut combined = Vec::with_capacity(NONCE_SIZE + sealed.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&sealed);
    Ok(base64::engine::general_purpose::STANDARD.encode(&combined))
}

/// 显式密钥解密（测试与内部复用）。
pub(crate) fn decrypt_with(
    key: &[u8; KEY_SIZE],
    ciphertext_b64: &str,
) -> Result<String, CryptoError> {
    let combined = base64::engine::general_purpose::STANDARD
        .decode(ciphertext_b64.as_bytes())
        .map_err(|_| CryptoError::Malformed)?;
    if combined.len() < NONCE_SIZE + TAG_SIZE {
        return Err(CryptoError::TooShort);
    }
    let (nonce, sealed) = combined.split_at(NONCE_SIZE);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Decrypt)?;
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, sealed)
        .map_err(|_| CryptoError::Decrypt)?;
    String::from_utf8(plaintext).map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8; KEY_SIZE] = &[7u8; KEY_SIZE];

    // roundtrip：nonce 随机 → 两次密文不同，均可解回。
    #[test]
    fn encrypt_decrypt_roundtrip() {
        let a = encrypt_with(KEY, "sk-test-123").unwrap();
        let b = encrypt_with(KEY, "sk-test-123").unwrap();
        assert_ne!(a, b, "随机 nonce 应使密文不同");
        assert_eq!(decrypt_with(KEY, &a).unwrap(), "sk-test-123");
        assert_eq!(decrypt_with(KEY, &b).unwrap(), "sk-test-123");
    }

    // 线格式：base64 解码后长度 = 12 (nonce) + 明文长 + 16 (tag)。
    #[test]
    fn wire_format_is_nonce_ct_tag() {
        let plaintext = "0123456789abcdef";
        let sealed = encrypt_with(KEY, plaintext).unwrap();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(sealed.as_bytes())
            .unwrap();
        assert_eq!(raw.len(), NONCE_SIZE + plaintext.len() + TAG_SIZE);
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let sealed = encrypt_with(KEY, "secret").unwrap();
        let other = [9u8; KEY_SIZE];
        assert!(matches!(
            decrypt_with(&other, &sealed),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn malformed_inputs_rejected() {
        assert!(matches!(
            encrypt_with(KEY, ""),
            Err(CryptoError::EmptyPlaintext)
        ));
        assert!(matches!(
            decrypt_with(KEY, "not-base64!!!"),
            Err(CryptoError::Malformed)
        ));
        assert!(matches!(
            decrypt_with(KEY, "AAAA"),
            Err(CryptoError::TooShort)
        ));
        // 长度恰为 nonce+tag 的空密文：可解码、可拆分，但认证失败。
        let empty_ct =
            base64::engine::general_purpose::STANDARD.encode([0u8; NONCE_SIZE + TAG_SIZE]);
        assert!(matches!(
            decrypt_with(KEY, &empty_ct),
            Err(CryptoError::Decrypt)
        ));
    }

    // 环境变量路径（进程级 env——串行执行）。
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn env_key_paths() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(
            "CONFIG_ENCRYPTION_KEY",
            "X43uDpE8Q/tC0NGIUY81vCS7CalCk405XxxQ/3hR/NQ=",
        );
        let sealed = encrypt("sk-env").unwrap();
        assert_eq!(decrypt(&sealed).unwrap(), "sk-env");

        std::env::remove_var("CONFIG_ENCRYPTION_KEY");
        assert!(matches!(encrypt("x"), Err(CryptoError::KeyMissing)));
        assert!(matches!(decrypt("AAAA"), Err(CryptoError::KeyMissing)));

        std::env::set_var("CONFIG_ENCRYPTION_KEY", "c2hvcnQ="); // "short"
        assert!(matches!(encrypt("x"), Err(CryptoError::KeyInvalid)));

        std::env::remove_var("CONFIG_ENCRYPTION_KEY");
    }
}
