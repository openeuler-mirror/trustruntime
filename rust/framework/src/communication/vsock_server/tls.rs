//! TLS 配置相关

use super::error::VsockError;
use openssl::ssl::{SslAcceptor, SslMethod, SslVerifyMode};
use std::time::Duration;

/// TLS配置参数
///
/// 封装TLS服务端所需的证书和密钥路径
pub struct TlsConfig {
    /// 服务端证书路径（PEM格式）
    pub cert_path: String,
    /// 服务端私钥路径（PEM格式）
    pub key_path: String,
    /// 私钥密码（可选）
    pub key_password: Option<String>,
    /// CA根证书路径（用于客户端证书验证）
    pub ca_cert_path: String,
    /// CRL吊销列表路径（可选）
    pub crl_path: Option<String>,
}

/// 配置TLS安全参数
///
/// 架构决策（ADR-0004）：
/// - 仅允许TLS 1.2和TLS 1.3
/// - 强密码套件（AES-256/128-GCM, CHACHA20-POLY1305）
/// - 前向保密（ECDHE密钥交换）
/// - 禁用重协商和Session Ticket
///
/// # Returns
/// * `Ok(SslAcceptorBuilder)` - TLS配置构建器
pub fn configure_tls_builder() -> Result<openssl::ssl::SslAcceptorBuilder, VsockError> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;

    builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;
    builder.set_max_proto_version(None)?;

    builder.set_ciphersuites(
        "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",
    )?;
    builder.set_cipher_list("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256")?;

    builder.set_options(
        openssl::ssl::SslOptions::NO_RENEGOTIATION | openssl::ssl::SslOptions::NO_TICKET,
    );

    Ok(builder)
}

pub fn load_tls_certificates(
    builder: &mut openssl::ssl::SslAcceptorBuilder,
    tls_config: &TlsConfig,
) -> Result<openssl::x509::X509, VsockError> {
    let cert = crate::cert::load_x509(&tls_config.cert_path)
        .map_err(|e| VsockError::TlsConfigError(e.to_string()))?;

    crate::cert::check_key_usage_contains(
        &cert,
        crate::cert::KeyUsageFlags::DIGITAL_SIGNATURE
            | crate::cert::KeyUsageFlags::KEY_ENCIPHERMENT,
    )
    .map_err(|e| VsockError::TlsConfigError(e.to_string()))?;

    crate::cert::check_extended_key_usage(&cert, "serverAuth")
        .map_err(|e| VsockError::TlsConfigError(e.to_string()))?;

    builder.set_certificate(&cert)?;

    let key =
        crate::cert::load_private_key(&tls_config.key_path, tls_config.key_password.as_deref())
            .map_err(|e| VsockError::TlsConfigError(e.to_string()))?;
    builder.set_private_key(&key)?;

    let ca_cert = crate::cert::load_x509(&tls_config.ca_cert_path)
        .map_err(|e| VsockError::TlsConfigError(e.to_string()))?;
    builder.cert_store_mut().add_cert(ca_cert.clone())?;

    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);

    Ok(ca_cert)
}

pub fn configure_crl_verification(
    builder: &mut openssl::ssl::SslAcceptorBuilder,
    crl_path: &str,
    _ca_cert: &openssl::x509::X509,
) -> Result<(), VsockError> {
    let crl =
        crate::cert::load_crl(crl_path).map_err(|e| VsockError::TlsConfigError(e.to_string()))?;

    builder.set_verify_callback(
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        move |ok, ctx| verify_cert_with_crl(ok, ctx, &crl),
    );

    Ok(())
}

fn verify_cert_with_crl(
    ok: bool,
    ctx: &mut openssl::x509::X509StoreContextRef,
    crl: &openssl::x509::X509Crl,
) -> bool {
    if !ok {
        return false;
    }

    if let Some(chain) = ctx.chain() {
        for cert in chain.iter() {
            if is_cert_revoked(cert, crl) {
                return false;
            }
        }
    }

    true
}

fn is_cert_revoked(cert: &openssl::x509::X509Ref, crl: &openssl::x509::X509Crl) -> bool {
    let serial = cert.serial_number();
    crl.get_revoked()
        .map(|revoked_stack| {
            revoked_stack
                .iter()
                .any(|revoked| revoked.serial_number() == serial)
        })
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
pub fn set_socket_timeout(fd: i32, timeout: Duration) -> Result<(), VsockError> {
    use libc::{setsockopt, timeval, SOL_SOCKET, SO_RCVTIMEO};
    use std::mem::size_of;

    let tv = timeval {
        tv_sec: timeout.as_secs() as i64,
        tv_usec: (timeout.subsec_micros() as i32).into(),
    };

    let result = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &tv as *const _ as *const _,
            size_of::<timeval>() as u32,
        )
    };

    if result != 0 {
        return Err(VsockError::IoError(std::io::Error::last_os_error()));
    }

    Ok(())
}
