//! CMS验签模块
//!
//! 职责：
//! - 验证CMS签名数据的完整性和证书链有效性
//! - 检查证书是否被CRL吊销
//! - 判断签名方证书身份（本节点/其他节点/身份冲突）
//!
//! 架构决策：
//! - 统一使用OpenSSL处理CMS验签（ADR-0004）
//! - 统一结果码编码（ADR-0001）
//!
//! 依赖：cert_loader模块（证书加载）、openssl crate（CMS验签）

use crate::cert_loader::{CaCertificate, CertificateRevocationList, CmsCertificate};
use foreign_types_shared::ForeignType;
use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509;
use openssl_sys::{
    stack_st_X509, CMS_ContentInfo, OPENSSL_STACK, X509 as X509_sys, X509_STORE, X509_STORE_CTX,
};
use std::cell::Cell;
use std::os::raw::c_int;
use thiserror::Error;

thread_local! {
    static VERIFY_ERROR_CODE: Cell<c_int> = const { Cell::new(0) };
}

const X509_V_ERR_CERT_HAS_EXPIRED: c_int = 10;

const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: c_int = 2;
const X509_V_ERR_CERT_SIGNATURE_FAILURE: c_int = 7;
const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: c_int = 18;
const X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: c_int = 19;
const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: c_int = 20;
const X509_V_ERR_CERT_REVOKED: c_int = 23;
const X509_V_ERR_CERT_UNTRUSTED: c_int = 27;
const X509_V_ERR_CERT_REJECTED: c_int = 28;

extern "C" {
    /// 获取CMS签名中的签名者证书列表
    fn CMS_get0_signers(cms: *mut CMS_ContentInfo) -> *mut stack_st_X509;
    /// 获取CMS签名中的所有证书
    fn CMS_get1_certs(cms: *mut CMS_ContentInfo) -> *mut stack_st_X509;
    /// 获取OpenSSL栈的元素数量
    fn OPENSSL_sk_num(st: *const OPENSSL_STACK) -> ::std::os::raw::c_int;
    /// 获取OpenSSL栈中指定索引的元素
    fn OPENSSL_sk_value(
        st: *const OPENSSL_STACK,
        i: ::std::os::raw::c_int,
    ) -> *mut ::std::os::raw::c_void;
    /// 释放OpenSSL栈（不释放栈中元素）
    fn OPENSSL_sk_free(st: *mut OPENSSL_STACK);
    /// 增加X509证书的引用计数
    fn X509_up_ref(x: *mut X509_sys);
    /// 设置X509存储的验证回调函数
    fn X509_STORE_set_verify_cb(
        store: *mut X509_STORE,
        callback: Option<unsafe extern "C" fn(c_int, *mut X509_STORE_CTX) -> c_int>,
    );
    /// 获取X509验证上下文的错误码
    fn X509_STORE_CTX_get_error(ctx: *const X509_STORE_CTX) -> c_int;
    /// 获取错误证书在证书链中的深度（0=leaf证书）
    fn X509_STORE_CTX_get_error_depth(ctx: *const X509_STORE_CTX) -> c_int;
}

fn map_x509_error_to_verify_error(error_code: c_int) -> VerifyError {
    match error_code {
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
        | X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
        | X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
        | X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        | X509_V_ERR_CERT_UNTRUSTED
        | X509_V_ERR_CERT_REJECTED => VerifyError::CertificateChainInvalid,

        X509_V_ERR_CERT_REVOKED => VerifyError::CertificateRevoked,

        X509_V_ERR_CERT_SIGNATURE_FAILURE => VerifyError::SignatureMismatch,

        _ => VerifyError::SignatureMismatch,
    }
}

/// OpenSSL证书验证回调函数
///
/// 业务规则：仅忽略签名方证书（leaf）的过期错误
///
/// 安全策略：
/// - X509_V_ERR_CERT_HAS_EXPIRED：仅对depth==0（leaf证书）忽略，CA/中间证书过期严格拒绝
/// - X509_V_ERR_CERT_NOT_YET_VALID：严格拒绝（证书尚未生效）
/// - X509_V_ERR_INVALID_PURPOSE：严格拒绝（证书用途无效），由verify_signer_key_usage做精确匹配检查
///
/// 详见 CONTEXT.md §证书类型 - 验签时签名方证书过期处理
unsafe extern "C" fn verify_callback(ok: c_int, ctx: *mut X509_STORE_CTX) -> c_int {
    if ok == 0 {
        let error = X509_STORE_CTX_get_error(ctx);

        // 存储错误码到线程局部变量
        VERIFY_ERROR_CODE.with(|cell| cell.set(error));

        // 仅对leaf证书（depth==0）忽略过期错误
        if error == X509_V_ERR_CERT_HAS_EXPIRED {
            let depth = X509_STORE_CTX_get_error_depth(ctx);
            if depth == 0 {
                return 1; // leaf证书：签名时有效即可
            }
            return 0; // CA/中间证书过期：严格拒绝
        }
    }
    ok
}

/// 验签错误类型
///
/// 架构决策：错误类型映射为统一结果码（ADR-0001）
///
/// 映射规则：
/// - CertificateChainInvalid → result=3（证书链无效）
/// - CertificateRevoked → result=4（CRL吊销）
/// - SignatureMismatch → result=5（签名不匹配）
/// - InvalidKeyUsage → result=6（证书KeyUsage无效）
/// - FormatError → result=7（格式错误）
#[derive(Error, Debug, PartialEq)]
pub(crate) enum VerifyError {
    /// OpenSSL内部错误
    #[error("openssl error: {0}")]
    OpenSslError(String),
    /// 证书链验证失败（非CA签发、自签名等）
    #[error("certificate chain invalid")]
    CertificateChainInvalid,
    /// 证书被CRL吊销
    #[error("certificate revoked")]
    CertificateRevoked,
    /// 签名不匹配（数据被篡改或签名无效）
    #[error("signature mismatch")]
    SignatureMismatch,
    /// CMS数据格式错误
    #[error("format error")]
    FormatError,
    /// 证书KeyUsage无效
    #[error("invalid key usage")]
    InvalidKeyUsage,
}

impl From<openssl::error::ErrorStack> for VerifyError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        VerifyError::OpenSslError(e.to_string())
    }
}

/// 验签结果
///
/// 架构决策：统一结果码编码（ADR-0001）
///
/// 编码规则：
/// - result=0: SameNode（公钥不同且ID相同，本节点签名）
/// - result=1: OtherNode（公钥不同且ID不同，其他节点签名）
/// - result=2: IdentityConflict（公钥相同，安全告警）
///
/// 注意：result=1/2为验签通过的合法结果，不表示失败
/// result=2优先级高于result=1（公钥比较优先）
#[derive(Debug, PartialEq)]
pub(crate) enum VerifyOutcome {
    /// 验签通过，公钥不同且ID相同（确认是本节点签名）
    SameNode,
    /// 验签通过，公钥不同且ID不同（其他节点签名）
    OtherNode,
    /// 证书身份冲突：签名方证书公钥 == 本地证书公钥
    /// 这是安全告警，表示可能存在证书复制或私钥泄露风险
    /// 注意：公钥相同时无需判断ID，直接返回此结果（优先级最高）
    IdentityConflict,
}

/// CMS验签器
///
/// 职责：
/// - 验证CMS签名的完整性和证书链有效性
/// - 检查签名方证书是否被CRL吊销
/// - 判断签名方证书身份（本节点/其他节点/身份冲突）
pub(crate) struct Verifier {
    /// CA根证书（用于验证签名方证书链）
    ca_cert: X509,
    /// CRL吊销列表（可选）
    crl: Option<openssl::x509::X509Crl>,
    /// 本地证书ID（Subject Key Identifier，用于身份判断）
    local_cert_id: Vec<u8>,
    /// 本地证书（用于公钥比较，检测身份冲突）
    local_cert: X509,
}

impl Verifier {
    /// 创建验签器实例
    ///
    /// # Arguments
    /// * `ca_cert` - CA根证书（用于验证证书链）
    /// * `crl` - CRL吊销列表（可选，用于检查证书是否被吊销）
    /// * `local_cert` - 本地签名证书（用于身份判断和公钥比较）
    ///
    /// # Returns
    /// 验签器实例
    pub(crate) fn new(
        ca_cert: CaCertificate,
        crl: Option<CertificateRevocationList>,
        local_cert: CmsCertificate,
    ) -> Self {
        let local_cert_id = local_cert.cert_id().to_vec();
        let local_cert_x509 = local_cert.into_inner();

        Self {
            ca_cert: ca_cert.cert().clone(),
            crl: crl.map(|c| c.into_inner()),
            local_cert_id,
            local_cert: local_cert_x509,
        }
    }

    /// 解析CMS签名数据
    ///
    /// # Arguments
    /// * `signed_data` - DER编码的CMS签名数据
    ///
    /// # Returns
    /// * `Ok(CmsContentInfo)` - 解析成功
    /// * `Err(VerifyError::FormatError)` - CMS数据格式错误
    fn parse_cms(signed_data: &[u8]) -> Result<CmsContentInfo, VerifyError> {
        CmsContentInfo::from_der(signed_data).map_err(|_| VerifyError::FormatError)
    }

    /// 构建证书存储并设置验证回调
    ///
    /// # Returns
    /// * `Ok(X509Store)` - 构建成功
    /// * `Err(VerifyError)` - OpenSSL错误
    fn build_cert_store(&self) -> Result<openssl::x509::store::X509Store, VerifyError> {
        let mut store_builder = X509StoreBuilder::new()?;
        store_builder.add_cert(self.ca_cert.clone())?;

        let store = store_builder.build();

        unsafe {
            X509_STORE_set_verify_cb(store.as_ptr(), Some(verify_callback));
        }

        Ok(store)
    }

    /// 验证CMS签名
    ///
    /// # Arguments
    /// * `cms` - CMS签名数据
    /// * `store` - X509证书存储
    /// * `data` - 原始数据
    /// * `signer_cert_id` - 签名方证书ID
    ///
    /// # Returns
    /// * `Ok(())` - 验证通过
    /// * `Err(VerifyError)` - 验证失败
    fn verify_cms_signature(
        &self,
        cms: &mut CmsContentInfo,
        store: &openssl::x509::store::X509Store,
        data: &[u8],
        signer_cert_id: &[u8],
    ) -> Result<(), VerifyError> {
        let mut input = data.to_vec();
        input.extend_from_slice(signer_cert_id);

        VERIFY_ERROR_CODE.with(|cell| cell.set(0));

        cms.verify(None, Some(store), Some(&input), None, CMSOptions::BINARY)
            .map_err(|_| {
                let error_code = VERIFY_ERROR_CODE.with(|cell| cell.get());
                map_x509_error_to_verify_error(error_code)
            })?;

        Ok(())
    }

    /// 从CMS签名中提取签名者证书
    ///
    /// # Arguments
    /// * `cms` - CMS签名数据
    ///
    /// # Returns
    /// * `Some(X509)` - 签名者证书
    /// * `None` - 提取失败（无签名者或栈为空）
    fn extract_signer_cert(cms: &CmsContentInfo) -> Option<X509> {
        unsafe {
            let cms_ptr = cms.as_ptr();
            let signers_stack = CMS_get0_signers(cms_ptr);

            if signers_stack.is_null() {
                return None;
            }

            let stack = signers_stack as *const OPENSSL_STACK;
            let num = OPENSSL_sk_num(stack);

            if num == 0 {
                OPENSSL_sk_free(stack as *mut OPENSSL_STACK);
                return None;
            }

            let x509_ptr = OPENSSL_sk_value(stack, 0) as *mut X509_sys;
            X509_up_ref(x509_ptr);

            OPENSSL_sk_free(stack as *mut OPENSSL_STACK);
            Some(X509::from_ptr(x509_ptr))
        }
    }

    fn verify_signer_key_usage(cert: &X509) -> Result<(), VerifyError> {
        let actual_flags = match trustruntime_framework::cert::extract_key_usage_flags(cert) {
            Ok(flags) => flags,
            Err(_) => return Err(VerifyError::InvalidKeyUsage),
        };

        if actual_flags != trustruntime_framework::cert::KeyUsageFlags::DIGITAL_SIGNATURE {
            return Err(VerifyError::InvalidKeyUsage);
        }

        Ok(())
    }

    fn check_crl_revocation(&self, cms: &CmsContentInfo) -> Result<(), VerifyError> {
        let crl = match &self.crl {
            Some(crl) => crl,
            None => return Ok(()),
        };

        let certs = unsafe {
            let cms_ptr = cms.as_ptr();
            let certs_stack = CMS_get1_certs(cms_ptr);

            if certs_stack.is_null() {
                return Ok(());
            }

            let stack = certs_stack as *const OPENSSL_STACK;
            let num = OPENSSL_sk_num(stack);

            let mut certs_vec = Vec::with_capacity(num as usize);
            for i in 0..num {
                let x509_ptr = OPENSSL_sk_value(stack, i) as *mut X509_sys;
                certs_vec.push(X509::from_ptr(x509_ptr));
            }

            OPENSSL_sk_free(stack as *mut OPENSSL_STACK);

            certs_vec
        };

        if let Some(revoked_stack) = crl.get_revoked() {
            for cert in &certs {
                for revoked in revoked_stack.iter() {
                    if revoked.serial_number() == cert.serial_number() {
                        return Err(VerifyError::CertificateRevoked);
                    }
                }
            }
        }

        Ok(())
    }

    /// 判断签名者证书身份
    ///
    /// 身份判断优先级：
    /// 1. 公钥比较：如果相同，返回IdentityConflict（安全告警，优先级最高）
    /// 2. ID比较：如果相同返回SameNode，否则返回OtherNode
    ///
    /// # Arguments
    /// * `cms` - CMS签名数据
    /// * `signer_cert_id` - 签名方证书ID
    ///
    /// # Returns
    /// * `Ok(VerifyOutcome)` - 身份判断结果
    /// * `Err(VerifyError::FormatError)` - 提取公钥失败
    fn determine_identity(
        &self,
        cms: &CmsContentInfo,
        signer_cert_id: &[u8],
    ) -> Result<VerifyOutcome, VerifyError> {
        let signer_cert = match Self::extract_signer_cert(cms) {
            Some(cert) => cert,
            None => return Ok(VerifyOutcome::OtherNode),
        };

        let signer_pubkey_pem = signer_cert
            .public_key()
            .map_err(|_| VerifyError::FormatError)?
            .public_key_to_pem()
            .map_err(|_| VerifyError::FormatError)?;

        let local_pubkey_pem = self
            .local_cert
            .public_key()
            .map_err(|_| VerifyError::FormatError)?
            .public_key_to_pem()
            .map_err(|_| VerifyError::FormatError)?;

        if signer_pubkey_pem == local_pubkey_pem {
            return Ok(VerifyOutcome::IdentityConflict);
        }

        if signer_cert_id == self.local_cert_id.as_slice() {
            Ok(VerifyOutcome::SameNode)
        } else {
            Ok(VerifyOutcome::OtherNode)
        }
    }

    /// 验签并判断证书身份
    ///
    /// 验签流程：
    /// 1. 解析CMS签名数据（DER格式）
    /// 2. 构建证书存储，添加CA根证书
    /// 3. 设置验证回调（忽略签名方证书过期等错误）
    /// 4. 验证签名：sign(data + signer_cert_id)
    /// 5. 检查CRL（如果配置了CRL）
    /// 6. 判断证书身份：
    ///    - 先比较公钥：如果相同，返回IdentityConflict（优先级最高）
    ///    - 再比较ID：如果相同返回SameNode，否则返回OtherNode
    ///
    /// # Arguments
    /// * `signed_data` - DER编码的CMS签名数据
    /// * `data` - 原始数据
    /// * `signer_cert_id` - 签名方证书ID（Subject Key Identifier）
    ///
    /// # Returns
    /// * `Ok(VerifyOutcome::SameNode)` - 验签通过，公钥不同且ID相同
    /// * `Ok(VerifyOutcome::OtherNode)` - 验签通过，公钥不同且ID不同
    /// * `Ok(VerifyOutcome::IdentityConflict)` - 公钥相同（安全告警，优先级最高）
    /// * `Err(VerifyError)` - 验签失败
    ///
    /// # Errors
    /// - `VerifyError::FormatError` - CMS数据格式错误
    /// - `VerifyError::CertificateChainInvalid` - 证书链验证失败
    /// - `VerifyError::CertificateRevoked` - 证书被CRL吊销
    /// - `VerifyError::SignatureMismatch` - 签名不匹配
    pub(crate) fn verify(
        &self,
        signed_data: &[u8],
        data: &[u8],
        signer_cert_id: &[u8],
    ) -> Result<VerifyOutcome, VerifyError> {
        let mut cms = Self::parse_cms(signed_data)?;
        let store = self.build_cert_store()?;
        self.verify_cms_signature(&mut cms, &store, data, signer_cert_id)?;

        // 验证签名方证书的KeyUsage（必须存在，否则返回格式错误）
        let signer_cert = Self::extract_signer_cert(&cms).ok_or(VerifyError::FormatError)?;
        Self::verify_signer_key_usage(&signer_cert)?;

        self.check_crl_revocation(&cms)?;
        self.determine_identity(&cms, signer_cert_id)
    }

    /// 仅验签（不判断证书身份）
    ///
    /// 用于验签+签名场景（0x12→0x13）：
    /// - 先验签sign(data + 输入证书id)
    /// - 验签通过后，再签名sign(新data + 输入证书id)
    ///
    /// 与verify方法的区别：
    /// - 不进行证书身份判断（不返回VerifyOutcome）
    /// - 不比较公钥和ID
    ///
    /// # Arguments
    /// * `signed_data` - DER编码的CMS签名数据
    /// * `data` - 原始数据
    /// * `signer_cert_id` - 签名方证书ID（Subject Key Identifier）
    ///
    /// # Returns
    /// * `Ok(())` - 验签通过
    /// * `Err(VerifyError)` - 验签失败
    ///
    /// # Errors
    /// - `VerifyError::FormatError` - CMS数据格式错误
    /// - `VerifyError::CertificateChainInvalid` - 证书链验证失败
    /// - `VerifyError::CertificateRevoked` - 证书被CRL吊销
    /// - `VerifyError::SignatureMismatch` - 签名不匹配
    pub(crate) fn verify_signature_only(
        &self,
        signed_data: &[u8],
        data: &[u8],
        signer_cert_id: &[u8],
    ) -> Result<(), VerifyError> {
        let mut cms = Self::parse_cms(signed_data)?;
        let store = self.build_cert_store()?;
        self.verify_cms_signature(&mut cms, &store, data, signer_cert_id)?;

        // 验证签名方证书的KeyUsage（必须存在，否则返回格式错误）
        let signer_cert = Self::extract_signer_cert(&cms).ok_or(VerifyError::FormatError)?;
        Self::verify_signer_key_usage(&signer_cert)?;

        self.check_crl_revocation(&cms)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_loader::{CaCertificate, CmsCertificate};
    use crate::sign::Signer;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::extension::{BasicConstraints, SubjectKeyIdentifier};
    use openssl::x509::{X509Builder, X509NameBuilder};
    use std::fs;

    /// 测试环境（封装测试所需的所有对象）
    ///
    /// 避免在每个测试中重复创建临时目录、证书文件、加载对象等步骤。
    struct TestEnv {
        _temp_dir: tempfile::TempDir,
        _ca_cert: CaCertificate,
        _local_cert: CmsCertificate,
        signer: Signer,
        verifier: Verifier,
        cert_id: Vec<u8>,
    }

    /// 创建测试环境（默认无 CRL）
    ///
    /// # Returns
    /// 包含临时目录、证书对象、签名器、验签器、证书ID的测试环境
    fn create_test_env() -> TestEnv {
        let temp_dir = tempfile::tempdir().unwrap();

        let (ca_pem, signer_pem, signer_key_pem) = create_ca_and_signer();

        let ca_path = temp_dir.path().join("ca.crt");
        let signer_path = temp_dir.path().join("signer.crt");
        let signer_key_path = temp_dir.path().join("signer.key");

        fs::write(&ca_path, &ca_pem).unwrap();
        fs::write(&signer_path, &signer_pem).unwrap();
        fs::write(&signer_key_path, &signer_key_pem).unwrap();

        let ca_cert = CaCertificate::load(ca_path.to_str().unwrap()).unwrap();
        let local_cert = CmsCertificate::load(
            signer_path.to_str().unwrap(),
            signer_key_path.to_str().unwrap(),
        )
        .unwrap();

        let signer = Signer::new(local_cert.clone());
        let cert_id = signer.cert_id().to_vec();
        let verifier = Verifier::new(ca_cert.clone(), None, local_cert.clone());

        TestEnv {
            _temp_dir: temp_dir,
            _ca_cert: ca_cert,
            _local_cert: local_cert,
            signer,
            verifier,
            cert_id,
        }
    }

    /// 创建 CA 证书
    ///
    /// # Arguments
    /// * `cn` - Common Name
    /// * `serial` - 序列号
    /// * `pkey` - 公钥
    ///
    /// # Returns
    /// X509 证书
    fn build_ca_cert(cn: &str, serial: u32, pkey: &PKey<openssl::pkey::Private>) -> X509 {
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();

        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(pkey).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(3650).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        let serial_bn = BigNum::from_u32(serial).unwrap();
        builder
            .set_serial_number(&serial_bn.to_asn1_integer().unwrap())
            .unwrap();

        let bc = BasicConstraints::new().critical().ca().build().unwrap();
        builder.append_extension(bc).unwrap();

        let context = builder.x509v3_context(None, None);
        let ski = SubjectKeyIdentifier::new().build(&context).unwrap();
        builder.append_extension(ski).unwrap();

        builder.sign(pkey, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    /// 创建签名者证书
    ///
    /// # Arguments
    /// * `cn` - Common Name
    /// * `serial` - 序列号
    /// * `pkey` - 公钥
    /// * `issuer_name` - 颁发者名称
    /// * `ca_cert` - CA 证书（用于 SKI 扩展）
    /// * `ca_pkey` - CA 私钥（用于签名）
    ///
    /// # Returns
    /// X509 证书
    fn build_signer_cert(
        cn: &str,
        serial: u32,
        pkey: &PKey<openssl::pkey::Private>,
        issuer_name: &openssl::x509::X509NameRef,
        ca_cert: &X509,
        ca_pkey: &PKey<openssl::pkey::Private>,
    ) -> X509 {
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        builder.set_subject_name(&name.build()).unwrap();

        builder.set_issuer_name(issuer_name).unwrap();
        builder.set_pubkey(pkey).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(3650).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        let serial_bn = BigNum::from_u32(serial).unwrap();
        builder
            .set_serial_number(&serial_bn.to_asn1_integer().unwrap())
            .unwrap();

        use openssl::x509::extension::KeyUsage;
        let mut ku_builder = KeyUsage::new();
        ku_builder.digital_signature();
        let ku = ku_builder.build().unwrap();
        builder.append_extension(ku).unwrap();

        let context = builder.x509v3_context(Some(ca_cert), None);
        let ski = SubjectKeyIdentifier::new().build(&context).unwrap();
        builder.append_extension(ski).unwrap();

        builder.sign(ca_pkey, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    /// 创建 CA 和多个签名者证书
    ///
    /// # Arguments
    /// * `num_signers` - 签名者数量
    ///
    /// # Returns
    /// (CA PEM, 签名者 PEM 列表, 私钥 PEM 列表)
    fn create_ca_and_multiple_signers(num_signers: usize) -> (Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();

        let ca_key = EcKey::generate(&group).unwrap();
        let ca_pkey = PKey::from_ec_key(ca_key).unwrap();
        let ca_cert = build_ca_cert("Test CA", 1, &ca_pkey);

        let mut signer_pems = Vec::new();
        let mut key_pems = Vec::new();
        for i in 2..(2 + num_signers) {
            let signer_key = EcKey::generate(&group).unwrap();
            let signer_pkey = PKey::from_ec_key(signer_key).unwrap();
            let signer_cert = build_signer_cert(
                &format!("Signer {}", i - 1),
                i as u32,
                &signer_pkey,
                ca_cert.subject_name(),
                &ca_cert,
                &ca_pkey,
            );

            signer_pems.push(signer_cert.to_pem().unwrap());
            key_pems.push(signer_pkey.private_key_to_pem_pkcs8().unwrap());
        }

        (ca_cert.to_pem().unwrap(), signer_pems, key_pems)
    }

    /// 创建测试用的CA证书和签名者证书
    ///
    /// 返回：(CA证书PEM, 签名者证书PEM, 签名者私钥PEM)
    fn create_ca_and_signer() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();

        let ca_key = EcKey::generate(&group).unwrap();
        let ca_pkey = PKey::from_ec_key(ca_key).unwrap();
        let ca_cert = build_ca_cert("Test CA", 1, &ca_pkey);

        let signer_key = EcKey::generate(&group).unwrap();
        let signer_pkey = PKey::from_ec_key(signer_key).unwrap();
        let signer_cert = build_signer_cert(
            "Test Signer",
            2,
            &signer_pkey,
            ca_cert.subject_name(),
            &ca_cert,
            &ca_pkey,
        );

        (
            ca_cert.to_pem().unwrap(),
            signer_cert.to_pem().unwrap(),
            signer_pkey.private_key_to_pem_pkcs8().unwrap(),
        )
    }

    /// 测试Verifier构造函数
    ///
    /// 场景：从证书文件构造Verifier实例
    /// 预期：成功创建实例，local_cert_id非空
    #[test]
    fn verifier_new_from_certificate_structs() {
        let env = create_test_env();
        assert!(!env.verifier.local_cert_id.is_empty());
    }

    /// 测试验签结果：公钥相同时返回IdentityConflict
    ///
    /// 场景：使用相同证书签名并验签
    /// 预期：验签通过，返回IdentityConflict（公钥相同，安全告警）
    #[test]
    fn verify_identity_conflict_when_pubkey_matches() {
        let env = create_test_env();

        let data = b"test data";
        let signed = env.signer.sign(data).unwrap();

        let result = env.verifier.verify(&signed, data, &env.cert_id);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), VerifyOutcome::IdentityConflict);
    }

    /// 测试验签结果：OtherNode判定
    ///
    /// 场景：使用不同证书签名（signer1本地证书，signer2签名）
    /// 预期：验签通过，返回OtherNode（签名方证书ID != 本地证书ID，公钥不同）
    #[test]
    fn verify_other_node_when_different_signer() {
        let temp_dir = tempfile::tempdir().unwrap();

        let (ca_pem, signer_pems, key_pems) = create_ca_and_multiple_signers(2);

        let ca_path = temp_dir.path().join("ca.crt");
        let signer1_path = temp_dir.path().join("signer1.crt");
        let signer1_key_path = temp_dir.path().join("signer1.key");
        let signer2_path = temp_dir.path().join("signer2.crt");
        let signer2_key_path = temp_dir.path().join("signer2.key");

        fs::write(&ca_path, &ca_pem).unwrap();
        fs::write(&signer1_path, &signer_pems[0]).unwrap();
        fs::write(&signer1_key_path, &key_pems[0]).unwrap();
        fs::write(&signer2_path, &signer_pems[1]).unwrap();
        fs::write(&signer2_key_path, &key_pems[1]).unwrap();

        let ca_cert = CaCertificate::load(ca_path.to_str().unwrap()).unwrap();
        let local_cert = CmsCertificate::load(
            signer1_path.to_str().unwrap(),
            signer1_key_path.to_str().unwrap(),
        )
        .unwrap();

        let other_signer = Signer::new(
            CmsCertificate::load(
                signer2_path.to_str().unwrap(),
                signer2_key_path.to_str().unwrap(),
            )
            .unwrap(),
        );
        let other_cert_id = other_signer.cert_id().to_vec();

        let verifier = Verifier::new(ca_cert, None, local_cert);

        let data = b"test data";
        let signed = other_signer.sign(data).unwrap();

        let result = verifier.verify(&signed, data, &other_cert_id);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), VerifyOutcome::OtherNode);
    }

    /// 测试验签错误：FormatError
    ///
    /// 场景：传入无效的CMS DER数据
    /// 预期：验签失败，返回FormatError（result=7）
    #[test]
    fn verify_format_error_for_invalid_der() {
        let env = create_test_env();

        let invalid_der = b"invalid cms data";
        let result = env.verifier.verify(invalid_der, b"test", b"id");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), VerifyError::FormatError);
    }

    /// 测试验签错误：SignatureMismatch
    ///
    /// 场景：签名数据与原始数据不匹配（数据被篡改）
    /// 预期：验签失败，返回SignatureMismatch（result=5）
    #[test]
    fn verify_signature_mismatch_for_wrong_data() {
        let env = create_test_env();

        let data = b"test data";
        let signed = env.signer.sign(data).unwrap();

        let wrong_data = b"wrong data";
        let result = env.verifier.verify(&signed, wrong_data, &env.cert_id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), VerifyError::SignatureMismatch);
    }

    /// 创建带 CRL 的测试环境
    ///
    /// # Arguments
    /// * `revoked_serial` - 待吊销的证书序列号（None 表示不吊销任何证书）
    ///
    /// # Returns
    /// (临时目录, CA 证书对象, 本地证书对象, 签名器, 验签器, 证书ID)
    fn create_test_env_with_crl(
        revoked_serial: Option<u32>,
    ) -> (
        tempfile::TempDir,
        CaCertificate,
        CmsCertificate,
        Signer,
        Verifier,
        Vec<u8>,
    ) {
        use openssl::x509::extension::{AuthorityKeyIdentifier, CrlNumber};
        use openssl::x509::X509CrlBuilder;

        let temp_dir = tempfile::tempdir().unwrap();

        // 创建 CA 和签名者（含私钥）
        let (ca_pem, ca_key_pem, signer_pem, signer_key_pem) = create_ca_signer_and_keys();

        let ca_path = temp_dir.path().join("ca.crt");
        let signer_path = temp_dir.path().join("signer.crt");
        let signer_key_path = temp_dir.path().join("signer.key");
        let crl_path = temp_dir.path().join("crl.crl");

        fs::write(&ca_path, &ca_pem).unwrap();
        fs::write(&signer_path, &signer_pem).unwrap();
        fs::write(&signer_key_path, &signer_key_pem).unwrap();

        // 创建 CRL（如果需要）
        let crl_obj = if let Some(serial_to_revoke) = revoked_serial {
            let ca_cert = X509::from_pem(&ca_pem).unwrap();
            let ca_key = PKey::private_key_from_pem(&ca_key_pem).unwrap();

            let mut crl_builder = X509CrlBuilder::new().unwrap();
            crl_builder.set_issuer_name(ca_cert.subject_name()).unwrap();

            let last_update = Asn1Time::days_from_now(0).unwrap();
            let next_update = Asn1Time::days_from_now(365).unwrap();
            crl_builder.set_last_update(&last_update).unwrap();
            crl_builder.set_next_update(&next_update).unwrap();

            let crl_number = CrlNumber::new(BigNum::from_u32(1).unwrap()).unwrap();
            crl_builder
                .append_extension(crl_number.build().unwrap())
                .unwrap();

            let temp_builder = X509Builder::new().unwrap();
            let context = temp_builder.x509v3_context(Some(&ca_cert), None);
            let aki = AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&context)
                .unwrap();
            crl_builder.append_extension(aki).unwrap();

            let mut revoked_builder = openssl::x509::X509RevokedBuilder::new().unwrap();
            let serial_bn = BigNum::from_u32(serial_to_revoke).unwrap();
            revoked_builder
                .set_serial_number(&serial_bn.to_asn1_integer().unwrap())
                .unwrap();
            revoked_builder.set_revocation_date(&last_update).unwrap();
            crl_builder.add_revoked(revoked_builder.build()).unwrap();

            crl_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
            let crl = crl_builder.build().unwrap();
            fs::write(&crl_path, crl.to_pem().unwrap()).unwrap();

            Some(CertificateRevocationList::load(crl_path.to_str().unwrap()).unwrap())
        } else {
            None
        };

        // 加载证书对象
        let ca_cert_obj = CaCertificate::load(ca_path.to_str().unwrap()).unwrap();
        let local_cert = CmsCertificate::load(
            signer_path.to_str().unwrap(),
            signer_key_path.to_str().unwrap(),
        )
        .unwrap();

        let signer = Signer::new(local_cert.clone());
        let cert_id = signer.cert_id().to_vec();
        let verifier = Verifier::new(ca_cert_obj.clone(), crl_obj, local_cert.clone());

        (temp_dir, ca_cert_obj, local_cert, signer, verifier, cert_id)
    }

    /// 创建 CA 和签名者证书（含私钥）
    ///
    /// # Returns
    /// (CA PEM, CA 私钥 PEM, 签名者 PEM, 签名者私钥 PEM)
    fn create_ca_signer_and_keys() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();

        let ca_key = EcKey::generate(&group).unwrap();
        let ca_pkey = PKey::from_ec_key(ca_key).unwrap();
        let ca_cert = build_ca_cert("Test CA", 1, &ca_pkey);

        let signer_key = EcKey::generate(&group).unwrap();
        let signer_pkey = PKey::from_ec_key(signer_key).unwrap();
        let signer_cert = build_signer_cert(
            "Test Signer",
            2,
            &signer_pkey,
            ca_cert.subject_name(),
            &ca_cert,
            &ca_pkey,
        );

        (
            ca_cert.to_pem().unwrap(),
            ca_pkey.private_key_to_pem_pkcs8().unwrap(),
            signer_cert.to_pem().unwrap(),
            signer_pkey.private_key_to_pem_pkcs8().unwrap(),
        )
    }

    /// 测试：CRL 吊销检查 - 证书被吊销
    ///
    /// 场景：签名方证书在 CRL 吊销列表中
    /// 预期：验签失败，返回 CertificateRevoked（result=4）
    #[test]
    fn verify_returns_certificate_revoked_when_signer_in_crl() {
        let (_temp_dir, _ca_cert, _local_cert, signer, verifier, cert_id) =
            create_test_env_with_crl(Some(2)); // 吊销序列号 2（签名者证书）

        let data = b"test data";
        let signed = signer.sign(data).unwrap();

        let result = verifier.verify(&signed, data, &cert_id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), VerifyError::CertificateRevoked);
    }

    /// 测试：CRL 吊销检查 - 证书未被吊销
    ///
    /// 场景：CRL 中不包含签名方证书序列号
    /// 预期：验签通过
    #[test]
    fn verify_passes_when_crl_does_not_contain_signer() {
        let (_temp_dir, _ca_cert, _local_cert, signer, verifier, cert_id) =
            create_test_env_with_crl(Some(999)); // 吊销序列号 999（不包含签名者）

        let data = b"test data";
        let signed = signer.sign(data).unwrap();

        let result = verifier.verify(&signed, data, &cert_id);
        assert!(result.is_ok());
    }

    /// 测试：verify_signature_only 正常通过
    ///
    /// 场景：验签有效的 CMS 签名（不判断证书身份）
    /// 预期：返回 Ok(())
    #[test]
    fn verify_signature_only_returns_ok_for_valid_signature() {
        let env = create_test_env();

        let data = b"test data";
        let signed = env.signer.sign(data).unwrap();

        let result = env
            .verifier
            .verify_signature_only(&signed, data, &env.cert_id);
        assert!(result.is_ok());
    }

    /// 测试：verify_signature_only CRL 吊销
    ///
    /// 场景：签名方证书在 CRL 吊销列表中
    /// 预期：返回 Err(CertificateRevoked)
    #[test]
    fn verify_signature_only_returns_certificate_revoked_when_crl_contains_signer() {
        let (_temp_dir, _ca_cert, _local_cert, signer, verifier, cert_id) =
            create_test_env_with_crl(Some(2)); // 吊销序列号 2（签名者证书）

        let data = b"test data";
        let signed = signer.sign(data).unwrap();

        let result = verifier.verify_signature_only(&signed, data, &cert_id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), VerifyError::CertificateRevoked);
    }
}
