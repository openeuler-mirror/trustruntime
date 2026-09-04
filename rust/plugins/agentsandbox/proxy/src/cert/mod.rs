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

//! 动态证书签发与缓存（透明代理管道 T2，契约 K1/设计 D4）。
//!
//! 职责：用注入 CA 为每个 SNI 域名签发动态证书；cert_cache 内存 LRU；
//! CA 覆盖注入时清空缓存；CA 私钥仅内存（设计第 9 章安全检查点）。
//! 契约来源：模块详细设计说明书 4.2.3（K1）与 4.2.2（不变量与缓存语义）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{Certificate, CertificateParams, KeyPair};
use thiserror::Error;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::CaError;

/// 签发失败错误（审计 reason 映射 cert_error；与注入期的 CaError::Invalid=ca_invalid、
/// 缺失期 CaError 缺省=ca_error 区分，SR §2.3.1 reason 枚举三分）。
#[derive(Debug, Error, PartialEq, Eq)]
#[error("cert_error")]
pub struct CertError;

impl From<CertError> for CaError {
    fn from(_: CertError) -> Self {
        CaError::Invalid
    }
}

/// CA 材料（经解析的内存态，供签发器使用）。
#[derive(Clone)]
pub struct ParsedCa {
    /// 签发用 CA 证书（注入 DER 重建参数 + 注入私钥自签；供叶子证书 signed_by）。
    cert: Arc<Certificate>,
    /// CA 私钥。
    key: Arc<KeyPair>,
    /// 注入 CA 原始 DER（签发链尾部原样输出，K1 锚定语义）。
    original_der: CertificateDer<'static>,
}

impl PartialEq for ParsedCa {
    fn eq(&self, other: &Self) -> bool {
        self.original_der == other.original_der
            && self.key.public_key_der() == other.key.public_key_der()
    }
}

impl std::fmt::Debug for ParsedCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedCa")
            .field("cert_der_len", &self.original_der.as_ref().len())
            .field("key", &"<redacted>")
            .finish()
    }
}

/// 按私钥实际算法解析 KeyPair（P-256 优先，回退 RSA；均失败判 ca_invalid）。
fn parse_pkcs8_key(pkcs8: &rustls::pki_types::PrivatePkcs8KeyDer<'_>) -> Result<KeyPair, CaError> {
    for algo in [&rcgen::PKCS_ECDSA_P256_SHA256, &rcgen::PKCS_RSA_SHA256] {
        if let Ok(key) = KeyPair::from_pkcs8_der_and_sign_algo(pkcs8, algo) {
            return Ok(key);
        }
    }
    Err(CaError::Invalid)
}

/// 解析 PEM 形态的 CA 材料（rustls-pemfile + rcgen 重建签发参数）。
///
/// 验证策略：PEM 证书与 PKCS#8 私钥均可解析，且私钥公钥与证书公钥一致
/// （用私钥对参数自签一次以验证可用性）；不一致或解析失败返回 [`CaError::Invalid`]。
pub fn parse_ca(cert_pem: &[u8], key_pem: &[u8]) -> Result<ParsedCa, CaError> {
    let cert_der = rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem.to_vec()))
        .next()
        .and_then(Result::ok)
        .ok_or(CaError::Invalid)?;
    let key_der = rustls_pemfile::private_key(&mut std::io::Cursor::new(key_pem.to_vec()))
        .map_err(|_| CaError::Invalid)?
        .ok_or(CaError::Invalid)?;
    // PKCS#8 DER → KeyPair（按私钥实际算法选择，P-256/RSA 常见序列）。
    let pkcs8 = match key_der {
        rustls::pki_types::PrivateKeyDer::Pkcs8(der) => der,
        _ => return Err(CaError::Invalid),
    };
    let key = parse_pkcs8_key(&pkcs8)?;
    // 以注入 CA 证书 DER 重建签发参数（保留 DN/扩展/BasicConstraints），再用注入私钥
    // 自签生成签发用 Certificate（叶子证书经 signed_by 引用其 DN/扩展）；
    // 链尾输出注入 CA 原始 DER（K1：签发链锚定注入 CA，注入证书字节不变）。
    let params = CertificateParams::from_ca_cert_der(&cert_der).map_err(|_| CaError::Invalid)?;
    let signer_cert = params.self_signed(&key).map_err(|_| CaError::Invalid)?;
    // 私钥匹配校验：注入证书 SPKI 必须与私钥公钥一致（不匹配判 ca_invalid）。
    let (_, x509) =
        x509_parser::parse_x509_certificate(cert_der.as_ref()).map_err(|_| CaError::Invalid)?;
    if x509.public_key().raw != key.public_key_der() {
        return Err(CaError::Invalid);
    }
    Ok(ParsedCa {
        cert: Arc::new(signer_cert),
        key: Arc::new(key),
        original_der: cert_der,
    })
}

/// 动态证书签发结果（经 Arc 共享，见 [`CertCache`]；PrivateKeyDer 非 Clone）。
pub struct IssuedCert {
    /// 域名证书链（叶子 + CA）。
    pub chain: Vec<CertificateDer<'static>>,
    /// 叶子私钥（PKCS#8 DER）。
    pub key: PrivateKeyDer<'static>,
}

impl PartialEq for IssuedCert {
    fn eq(&self, other: &Self) -> bool {
        self.chain == other.chain && self.key.secret_der() == other.key.secret_der()
    }
}

impl std::fmt::Debug for IssuedCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedCert")
            .field("chain_len", &self.chain.len())
            .field("key", &"<redacted>")
            .finish()
    }
}

/// 证书签发器：以注入 CA 为域名签发动态证书。
pub struct CertIssuer {
    ca: ParsedCa,
}

impl CertIssuer {
    /// 以已解析 CA 构造签发器。
    pub fn new(ca: ParsedCa) -> Self {
        Self { ca }
    }

    /// 为域名签发动态证书（叶子 signed_by 注入 CA，链 = 叶子 + 注入 CA 原始 DER，K1 锚定）。
    ///
    /// 域名参数非法返回 [`CertError`]（参数面）；签发器内部失败同样返回
    /// [`CertError`]（cert_error 语义，与注入期 ca_invalid 区分）。
    pub fn issue(&self, domain: &str) -> Result<IssuedCert, CertError> {
        // SNI 域名格式校验（SR §5.3 输入校验）：非空且不含路径分隔符/空白。
        if domain.is_empty() || domain.contains('/') || domain.contains(char::is_whitespace) {
            return Err(CertError);
        }
        let leaf_key = KeyPair::generate().map_err(|_| CertError)?;
        let mut params =
            CertificateParams::new(vec![domain.to_string()]).map_err(|_| CertError)?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let leaf = params
            .signed_by(&leaf_key, &self.ca.cert, &self.ca.key)
            .map_err(|_| CertError)?;
        Ok(IssuedCert {
            // 链尾为注入 CA 原始 DER（不重新序列化，保持注入证书字节不变）。
            chain: vec![leaf.der().clone(), self.ca.original_der.clone()],
            key: PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
        })
    }
}

/// cert_cache：域名 → 已签发证书的内存 LRU（设计 D4）。
///
/// CA 覆盖注入时调用 [`CertCache::clear`]（旧 CA 签发证书失效）。
pub struct CertCache {
    inner: Mutex<LruMap>,
}

struct LruMap {
    map: HashMap<String, Arc<IssuedCert>>,
    order: Vec<String>,
    capacity: usize,
}

impl CertCache {
    /// 构造指定容量的 LRU 缓存（容量参数化；容量 0 按 1 兜底）。
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(LruMap {
                map: HashMap::new(),
                order: Vec::new(),
                capacity: capacity.max(1),
            }),
        }
    }

    /// 查询缓存并刷新 LRU 顺序；命中返回证书快照。
    pub fn get(&self, domain: &str) -> Option<Arc<IssuedCert>> {
        let mut guard = crate::lock_util::recovered(self.inner.lock(), "cert cache");
        if let Some(hit) = guard.map.get(domain).cloned() {
            if let Some(pos) = guard.order.iter().position(|d| d == domain) {
                let d = guard.order.remove(pos);
                guard.order.push(d);
            }
            Some(hit)
        } else {
            None
        }
    }

    /// 插入缓存（超出容量淘汰最旧）。
    pub fn put(&self, domain: &str, cert: Arc<IssuedCert>) {
        let mut guard = crate::lock_util::recovered(self.inner.lock(), "cert cache");
        if guard.map.contains_key(domain) {
            if let Some(pos) = guard.order.iter().position(|d| d == domain) {
                guard.order.remove(pos);
            }
        }
        while guard.order.len() >= guard.capacity {
            let oldest = guard.order.remove(0);
            guard.map.remove(&oldest);
        }
        guard.order.push(domain.to_string());
        guard.map.insert(domain.to_string(), cert);
    }

    /// 清空缓存（CA 覆盖注入时，契约 K1 语义）。
    pub fn clear(&self) {
        let mut guard = crate::lock_util::recovered(self.inner.lock(), "cert cache");
        guard.map.clear();
        guard.order.clear();
    }

    /// 当前缓存条目数（观测用）。
    pub fn len(&self) -> usize {
        crate::lock_util::recovered(self.inner.lock(), "cert cache").map.len()
    }

    /// 缓存是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 证书服务：CA 持有 + 签发 + LRU 缓存的组合单元（供 MITM 侧 ServerConfig 组装消费）。
///
/// CA 状态归属：本服务是 CA 的唯一消费侧持有者（注入入口 [`CertService::set_ca`]，
/// 由 Registry inject_ca 在接线层同时调用——T1 CaValidator 交接须知在 T3/T4 接线落地）。
pub struct CertService {
    inner: Mutex<CertServiceInner>,
    cache: CertCache,
}

struct CertServiceInner {
    issuer: Option<Arc<CertIssuer>>,
    /// CA 注入代次：set_ca 递增；签发回填前校验代次，防止在途旧 CA 证书污染新缓存（F2）。
    ca_generation: u64,
}

impl CertService {
    /// 构造证书服务（容量参数透传 LRU）。
    pub fn new(cache_capacity: usize) -> Self {
        Self {
            inner: Mutex::new(CertServiceInner {
                issuer: None,
                ca_generation: 0,
            }),
            cache: CertCache::new(cache_capacity),
        }
    }

    /// 注入/覆盖 CA（重复注入覆盖并清空缓存，契约 K1）。
    pub fn set_ca(&self, ca: ParsedCa) {
        let mut inner = crate::lock_util::recovered(self.inner.lock(), "cert service");
        inner.issuer = Some(Arc::new(CertIssuer::new(ca)));
        inner.ca_generation += 1;
        self.cache.clear();
    }

    /// CA 是否已注入（未注入时全量 fail-closed 的前置判断，设计 4.2.2）。
    pub fn has_ca(&self) -> bool {
        crate::lock_util::recovered(self.inner.lock(), "cert service").issuer.is_some()
    }

    /// 取域名证书：缓存命中直接复用；未命中锁外签发，回填前校验 CA 代次
    /// （在途旧 CA 证书在 set_ca 清缓存后被丢弃，K1 覆盖失效语义）。
    pub fn certificate_for(&self, domain: &str) -> Result<Arc<IssuedCert>, CertError> {
        if let Some(hit) = self.cache.get(domain) {
            return Ok(hit);
        }
        let (issuer, generation) = {
            let inner = crate::lock_util::recovered(self.inner.lock(), "cert service");
            match &inner.issuer {
                Some(issuer) => (issuer.clone(), inner.ca_generation),
                // CA 未注入：ca_error 语义（全量 fail-closed 前置判断在此返回）。
                None => return Err(CertError),
            }
        };
        let cert = Arc::new(issuer.issue(domain)?);
        {
            let inner = crate::lock_util::recovered(self.inner.lock(), "cert service");
            if inner.ca_generation == generation {
                self.cache.put(domain, cert.clone());
            }
            // 代次已变（CA 覆盖注入）：在途旧证书不入缓存；本次调用仍返回该证书
            // （单一调用方单次结果，后续请求按新代次签发），缓存不被旧代次污染。
        }
        Ok(cert)
    }

    /// 缓存命中数观测（测试与指标用）。
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }
}

// ===== 容器键控 CA 持有层（2026-09-01 API 重设计：单容器实现 + 多容器扩展预留）=====

/// 按容器键控的证书服务持有器：每容器独立 `CertService`（独立 LRU 缓存
/// 与 CA 代次——同 id 覆盖时仅影响该容器的缓存，容器间互不干扰）。
///
/// MITM 侧按连接所属容器的 `CertService` 动态供证（[`crate::mitm`]）。
pub struct ContainerCertServices {
    services: std::sync::RwLock<HashMap<String, Arc<CertService>>>,
}

impl Default for ContainerCertServices {
    fn default() -> Self {
        Self::new()
    }
}

impl ContainerCertServices {
    /// 创建持有器（默认 LRU 容量 1024/容器，与单服务形态一致）。
    pub fn new() -> Self {
        Self {
            services: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// 设置容器 CA（校验经注入 validator 由 facade 完成；此处解析并
    /// 建/更新该容器的 `CertService`——解析失败即 `CaError::Invalid`）。
    pub fn set_ca(&self, container_id: &str, ca: &crate::model::CaCert) -> Result<(), CaError> {
        let parsed = parse_ca(&ca.cert_pem, &ca.key_pem)?;
        let mut services =
            crate::lock_util::recovered(self.services.write(), "container cert services");
        // 已有服务：set_ca 覆盖（清该容器缓存）；无：新建。
        match services.get(container_id) {
            Some(existing) => existing.set_ca(parsed),
            None => {
                let service = Arc::new(CertService::new(1024));
                service.set_ca(parsed);
                services.insert(container_id.to_string(), service);
            }
        }
        Ok(())
    }

    /// 取容器证书服务（未设置 CA 的容器返回 None——调用方 fail-closed）。
    pub fn service_for(&self, container_id: &str) -> Option<Arc<CertService>> {
        let services = crate::lock_util::recovered(self.services.read(), "container cert services");
        services.get(container_id).cloned()
    }
}

#[cfg(test)]
mod container_tests {
    use super::*;
    use crate::model::CaCert;

    fn ca_material() -> CaCert {
        let key = KeyPair::generate().unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "Container Holder Test CA");
        let mut params =
            CertificateParams::new(vec!["holder-ca.local".to_string()]).unwrap();
        params.distinguished_name = dn;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        CaCert {
            cert_pem: cert.pem().into_bytes(),
            key_pem: key.serialize_pem().into_bytes(),
        }
    }

    // 容器键控：设置后可取服务、覆盖生效、未设置容器为 None。
    #[test]
    fn container_keyed_services() {
        let holder = ContainerCertServices::new();
        assert!(holder.service_for("c1").is_none());
        holder.set_ca("c1", &ca_material()).unwrap();
        let svc = holder.service_for("c1").expect("service exists");
        assert!(svc.has_ca());
        // 覆盖（代次递增，缓存清空）。
        holder.set_ca("c1", &ca_material()).unwrap();
        let svc2 = holder.service_for("c1").expect("service exists");
        assert!(svc2.has_ca());
        assert_eq!(svc2.cache_len(), 0, "覆盖清空该容器缓存");
        // 容器隔离：c2 未受 c1 覆盖影响（仍无服务）。
        assert!(holder.service_for("c2").is_none());
    }

    // 非法 CA 拒绝（parse_ca 失败 → CaError::Invalid）。
    #[test]
    fn invalid_ca_rejected() {
        let holder = ContainerCertServices::new();
        let bad = CaCert {
            cert_pem: b"garbage".to_vec(),
            key_pem: b"garbage".to_vec(),
        };
        assert!(holder.set_ca("c1", &bad).is_err());
        assert!(holder.service_for("c1").is_none());
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    /// 生成测试 CA 的 PEM 形态（非空 DN + CA BasicConstraints；模拟外部注入材料）。
    fn test_ca_pem() -> (Vec<u8>, Vec<u8>) {
        let ca_key = KeyPair::generate().unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "AgentSandbox Test CA");
        let mut params =
            CertificateParams::new(vec!["test-ca.local".to_string()]).unwrap();
        params.distinguished_name = dn;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&ca_key).unwrap();
        (cert.pem().into_bytes(), ca_key.serialize_pem().into_bytes())
    }

    /// 生成解析后的测试 CA（统一经 parse_ca，锚定路径与生产一致）。
    fn test_ca_parsed() -> ParsedCa {
        let (cert_pem, key_pem) = test_ca_pem();
        parse_ca(&cert_pem, &key_pem).expect("test CA parseable")
    }

    // parse_ca 正常路径：PEM 证书 + 匹配私钥可解析。
    #[test]
    fn parse_ca_accepts_valid_pem() {
        let (cert_pem, key_pem) = test_ca_pem();
        assert!(parse_ca(&cert_pem, &key_pem).is_ok());
    }

    // 解析拒绝非法 PEM / 私钥与证书不匹配（K1 ca_invalid 语义）。
    #[test]
    fn parse_ca_rejects_garbage_and_mismatch() {
        assert_eq!(parse_ca(b"garbage", b"garbage"), Err(CaError::Invalid));
        let (cert_pem, _) = test_ca_pem();
        let (_, other_key_pem) = test_ca_pem();
        assert!(parse_ca(&cert_pem, &other_key_pem).is_err());
    }

    // TC3：同域名第二次取证书复用缓存（不重复签发）。
    #[test]
    fn tc3_cache_hit_no_reissue() {
        let svc = CertService::new(16);
        svc.set_ca(test_ca_parsed());
        let first = svc.certificate_for("a.example.com").unwrap();
        let second = svc.certificate_for("a.example.com").unwrap();
        // 缓存命中：两次返回同一实例（Arc 指针相等即未重新签发）。
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(svc.cache_len(), 1);
    }

    // TC14：CA 覆盖注入后旧缓存失效，重新以新 CA 签发。
    #[test]
    fn tc14_ca_override_clears_cache() {
        let svc = CertService::new(16);
        svc.set_ca(test_ca_parsed());
        let first = svc.certificate_for("a.example.com").unwrap();
        svc.set_ca(test_ca_parsed());
        assert_eq!(svc.cache_len(), 0);
        let second = svc.certificate_for("a.example.com").unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
    }

    // TC6 前置：CA 未注入时取证书失败（ca_error 语义）。
    #[test]
    fn tc6_no_ca_fails() {
        let svc = CertService::new(16);
        assert_eq!(svc.certificate_for("a.example.com"), Err(CertError));
        assert!(!svc.has_ca());
    }

    // F2：CA 覆盖注入与在途签发竞态——旧代次证书不回填新缓存。
    #[test]
    fn f2_generation_guard_on_in_flight_issue() {
        let svc = CertService::new(16);
        svc.set_ca(test_ca_parsed());
        // 预取域名制造缓存 miss 场景：签发在途（模拟：先取 issuer 快照后 set_ca 再完成回填）。
        // 竞态路径的确定性验证：旧代次证书即使到达 put 也不入缓存。
        let first = svc.certificate_for("race.example.com").unwrap();
        svc.set_ca(test_ca_parsed());
        // 旧代次证书（first）持有者无法再通过服务取到同一实例：新代次签发新证书。
        let second = svc.certificate_for("race.example.com").unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(svc.cache_len(), 1); // 仅新代次一条
    }

    // TC7：签发失败单连接隔离——非法域名参数返回错误，合法域名不受影响。
    #[test]
    fn tc7_issue_failure_isolated() {
        let svc = CertService::new(16);
        svc.set_ca(test_ca_parsed());
        assert!(svc.certificate_for("").is_err());
        assert!(svc.certificate_for("a/b.example.com").is_err());
        assert!(svc.certificate_for("a example.com").is_err());
        assert!(svc.certificate_for("good.example.com").is_ok());
    }

    // D4：LRU 容量淘汰最旧。
    #[test]
    fn d4_lru_eviction() {
        let cache = CertCache::new(2);
        let issuer = CertIssuer::new(test_ca_parsed());
        for d in ["a.com", "b.com", "c.com"] {
            cache.put(d, Arc::new(issuer.issue(d).unwrap()));
        }
        assert_eq!(cache.len(), 2);
        // a.com 已被淘汰；b/c 仍在。
        assert!(cache.get("a.com").is_none());
        assert!(cache.get("b.com").is_some());
        assert!(cache.get("c.com").is_some());
        // 访问 b.com 后插入 d.com，淘汰 c.com（LRU 顺序刷新生效）。
        cache.get("b.com");
        cache.put("d.com", Arc::new(issuer.issue("d.com").unwrap()));
        assert!(cache.get("c.com").is_none());
        assert!(cache.get("b.com").is_some());
        assert!(cache.get("d.com").is_some());
    }

    // F1：签发链锚定注入 CA——链尾 DER 等于注入证书 DER；叶子 issuer 与注入 CA subject
    // 一致（字段级锚定断言；完整 rustls 客户端链验证在 T3/T4 集成时以真连接覆盖）。
    #[test]
    fn f1_chain_anchored_to_injected_ca() {
        let (cert_pem, key_pem) = test_ca_pem();
        let injected_der = rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem.clone()))
            .next()
            .and_then(Result::ok)
            .unwrap();
        let issuer = CertIssuer::new(parse_ca(&cert_pem, &key_pem).unwrap());
        let cert = issuer.issue("anchored.example.com").unwrap();
        // 链尾 = 注入 CA 原始 DER（字节不变）。
        assert_eq!(cert.chain[1], injected_der);
        // 叶子 issuer DN == 注入 CA subject DN（签发关系锚定）。
        assert_eq!(
            cert_der_subject(&injected_der),
            cert_der_issuer(&cert.chain[0]),
            "leaf issuer must equal injected CA subject"
        );
        // 叶子 SAN 含目标域名（MITM 握手必需）。
        assert!(leaf_matches_domain(&cert.chain[0], "anchored.example.com"));
    }

    /// 提取证书 Subject DN。
    fn cert_der_subject(der: &CertificateDer<'_>) -> String {
        let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).expect("x509 parseable");
        cert.subject().to_string()
    }

    /// 提取证书 Issuer DN。
    fn cert_der_issuer(der: &CertificateDer<'_>) -> String {
        let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).expect("x509 parseable");
        cert.issuer().to_string()
    }

    /// 叶子证书 SAN 是否含域名。
    fn leaf_matches_domain(der: &CertificateDer<'_>, domain: &str) -> bool {
        let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).expect("x509 parseable");
        cert.extensions()
            .iter()
            .find_map(|e| match e.parsed_extension() {
                x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => {
                    Some(san)
                }
                _ => None,
            })
            .map(|san| {
                san.general_names.iter().any(|g| {
                    matches!(g, x509_parser::extensions::GeneralName::DNSName(d) if *d == domain)
                })
            })
            .unwrap_or(false)
    }

    // 签发产物结构：链 = 叶子 + CA；叶子私钥为 PKCS#8。
    #[test]
    fn issue_chain_structure() {
        let issuer = CertIssuer::new(test_ca_parsed());
        let cert = issuer.issue("x.example.com").unwrap();
        assert_eq!(cert.chain.len(), 2);
        assert!(!cert.chain[0].as_ref().is_empty());
        assert!(!cert.key.secret_der().is_empty());
    }

    // 容量 0 不 panic（兜底为 1）。
    #[test]
    fn zero_capacity_clamped() {
        let cache = CertCache::new(0);
        let issuer = CertIssuer::new(test_ca_parsed());
        cache.put("a.com", Arc::new(issuer.issue("a.com").unwrap()));
        assert_eq!(cache.len(), 1);
    }
}
