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

//! TLS MITM 终止层（说明书 4.2 / D4 / D5）。
//!
//! 职责：以注入 CA 为每个 SNI 域名动态签发证书完成与发起方的 TLS 握手
//!（解密），并**捕获 SNI**——连接目标域名在整个生命周期里唯一以明文
//! 存在的位置（ClientHello 内），是求值 domain 维度、审计 domain 字段与
//! 目标出站 SNI 的共同输入。
//!
//! 机制：rustls 在握手过程中解析完 ClientHello 后回调
//! [`ResolvesServerCert::resolve`]（唯一的 SNI 钩子，时机在证书选择点）——
//! 实现里同时完成「供证」与「捕获」：按 SNI 从 [`CertService`] 取/签域名
//! 证书（缓存命中不重复签发，D4），并把 SNI 写入每连接槽位，握手完成后
//! 由 serve 层读出。
//!
//! 失败语义（4.2.4）：
//! - **CA 未注入**：全量 fail-closed（ca_error）——serve 层握手前前置检查；
//! - **无 SNI**：握手拒绝（config_not_found 语义）——域名输入缺失；
//! - **签发失败**（cert_error）：该连接握手失败关闭，不影响其他连接；
//! - **ALPN**（D5）：`[h2, http/1.1]` 按发起方偏好协商，协商结果经
//!   `TlsStream::get_ref().1.alpn_protocol()` 读取，作为目标出站 ALPN 与
//!   hyper 协议分发的依据。
//!
//! 不变量：握手完成前不得有任何明文 HTTP 数据被处理（4.2.2——rustls
//! accept 之前不解码任何字节，天然满足）。

use std::sync::{Arc, Mutex};

use rustls::server::ClientHello;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;

use crate::cert::{CertService, IssuedCert};

/// 每连接 TLS 终止结果（握手成功后的上下文）。
pub struct MitmHandshake {
    /// 捕获的 SNI 域名。
    pub sni: String,
    /// MITM 侧协商的 ALPN（原始字节，如 b"h2"/b"http/1.1"；None=未协商）。
    pub alpn: Option<Vec<u8>>,
}

/// SNI 捕获 + 动态供证 resolver。
///
/// 每连接实例化（sni 槽随连接生命周期）：
/// `resolve(ClientHello)` 被 rustls 在 ClientHello 解析后调用——提取 SNI
/// 存入 `captured_sni`，并返回该域名的动态证书链。无 SNI → 返回 None
///（rustls 拒绝握手——config_not_found 语义）。
pub struct SniResolvingCert {
    service: Arc<CertService>,
    captured_sni: Mutex<Option<String>>,
}

impl std::fmt::Debug for SniResolvingCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniResolvingCert")
            .field("captured_sni", &self.captured_sni)
            .finish_non_exhaustive()
    }
}

impl SniResolvingCert {
    /// 构造（service：证书服务——CA 持有 + LRU 缓存 + 签发）。
    pub fn new(service: Arc<CertService>) -> Self {
        Self {
            service,
            captured_sni: Mutex::new(None),
        }
    }

    /// 握手后取捕获的 SNI（未捕获 = 握手未发生或无 SNI 被拒）。
    pub fn captured_sni(&self) -> Option<String> {
        crate::lock_util::recovered(self.captured_sni.lock(), "sni slot lock").clone()
    }
}

impl ResolvesServerCert for SniResolvingCert {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // SNI 捕获：无 SNI → None（握手拒绝，config_not_found 语义——
        // 求值缺 domain 输入，4.2.2 关键映射表）。
        let sni = client_hello.server_name()?.to_string();
        // 动态供证：缓存命中复用 / 未命中签发（D4）；签发失败 → None
        //（握手失败，cert_error——该连接隔离，不影响其他连接）。
        let issued = self.service.certificate_for(sni.as_str()).ok()?;
        *crate::lock_util::recovered(self.captured_sni.lock(), "sni slot lock") = Some(sni);
        build_certified_key(issued)
    }
}

/// IssuedCert → rustls CertifiedKey（链 + 叶子私钥签名器）。
///
/// 每次握手重建（CertifiedKey 未缓存共享：叶子 key 的 SigningKey 构建为
/// 纯内存操作，且 cert_cache 已在 service 层避免重复签发——本层重建的
/// 仅是签名器包装）。
fn build_certified_key(issued: Arc<IssuedCert>) -> Option<Arc<CertifiedKey>> {
    let key = rustls::crypto::ring::sign::any_ecdsa_type(&issued.key.clone_key())
        .map_err(|e| {
            // 叶子私钥由 rcgen P-256 生成——构建失败即程序不变量破坏；
            // 记日志（不含密钥内容）并以 None 拒绝握手（cert_error）。
            crate::log_error!("mitm", "leaf key signing build failed: {e}");
            e
        })
        .ok()?;
    Some(Arc::new(CertifiedKey::new(issued.chain.clone(), key)))
}

/// MITM 握手错误（握手阶段失败——发生在 HTTP 之前，无法返回 HTTP 响应，
/// 连接关闭经日志观测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MitmError {
    /// CA 未注入（ca_error——全量 fail-closed 前置）。
    #[error("ca_error")]
    CaMissing,
    /// ClientHello 无 SNI（config_not_found 语义——域名输入缺失）。
    #[error("config_not_found")]
    NoSni,
    /// 证书签发失败（cert_error——该连接隔离）。
    #[error("cert_error")]
    CertIssue,
    /// TLS 握手失败（客户端中止/协议不匹配等）。
    #[error("tls_handshake_failed")]
    Handshake,
}

/// 构造 MITM 侧 ServerConfig（每连接一份——resolver 携带 SNI 捕获槽）。
///
/// ALPN `[h2, http/1.1]`（D5：按发起方偏好协商）。
pub fn server_config(resolver: Arc<SniResolvingCert>) -> ServerConfig {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

/// 握手前置检查（CA 可用性——全量 fail-closed 判定，4.2.2）。
pub fn precheck_ca(service: &CertService) -> Result<(), MitmError> {
    if service.has_ca() {
        Ok(())
    } else {
        Err(MitmError::CaMissing)
    }
}

/// 从握手完成的 TLS 流提取 MITM 上下文（SNI + ALPN）。
///
/// SNI 取 resolver 捕获槽（握手成功则必已写入）；ALPN 取 rustls 协商结果。
pub fn handshake_context(
    resolver: &SniResolvingCert,
    alpn: Option<&[u8]>,
) -> Result<MitmHandshake, MitmError> {
    let sni = resolver
        .captured_sni()
        .ok_or(MitmError::NoSni)?;
    Ok(MitmHandshake {
        sni,
        alpn: alpn.map(<[u8]>::to_vec),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // 无 SNI 的 ClientHello → resolve 返回 None（握手拒绝语义）。
    //（ClientHello 构造不可行——经集成测试以真实无 SNI 客户端覆盖；
    // 此处锁定 resolver 空槽语义。）
    #[test]
    fn captured_sni_initially_none() {
        let service = Arc::new(CertService::new(8));
        let resolver = SniResolvingCert::new(service);
        assert_eq!(resolver.captured_sni(), None);
    }

    // CA 前置检查：未注入 → CaMissing；注入后 → Ok（4.2.2 全量 fail-closed）。
    #[test]
    fn precheck_ca_semantics() {
        let service = CertService::new(8);
        assert_eq!(precheck_ca(&service), Err(MitmError::CaMissing));
        let (cert_pem, key_pem) = test_ca_pem();
        let ca = crate::cert::parse_ca(&cert_pem, &key_pem).unwrap();
        service.set_ca(ca);
        assert_eq!(precheck_ca(&service), Ok(()));
    }

    fn test_ca_pem() -> (Vec<u8>, Vec<u8>) {
        use rcgen::{CertificateParams, KeyPair};
        let key = KeyPair::generate().unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "MITM Test CA");
        let mut params = CertificateParams::new(vec!["mitm-ca.local".to_string()]).unwrap();
        params.distinguished_name = dn;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }
}
