//! TLS 配置相关

use super::error::VsockError;
use openssl::ssl::{SslAcceptor, SslMethod, SslVerifyMode};
use std::time::Duration;

pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub key_password: Option<String>,
    pub ca_cert_path: String,
    pub crl_path: Option<String>,
}

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
) -> Result<(), VsockError> {
    let cert = crate::cert::load_x509(&tls_config.cert_path)
        .map_err(|e| VsockError::TlsConfigError(e.to_string()))?;
    builder.set_certificate(&cert)?;

    let key =
        crate::cert::load_private_key(&tls_config.key_path, tls_config.key_password.as_deref())
            .map_err(|e| VsockError::TlsConfigError(e.to_string()))?;
    builder.set_private_key(&key)?;

    let ca_cert = crate::cert::load_x509(&tls_config.ca_cert_path)
        .map_err(|e| VsockError::TlsConfigError(e.to_string()))?;
    builder.cert_store_mut().add_cert(ca_cert)?;

    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);

    Ok(())
}

pub fn configure_crl_verification(
    builder: &mut openssl::ssl::SslAcceptorBuilder,
    crl_path: &str,
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

    ctx.current_cert()
        .map(|cert| !is_cert_revoked(cert, crl))
        .unwrap_or(true)
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
