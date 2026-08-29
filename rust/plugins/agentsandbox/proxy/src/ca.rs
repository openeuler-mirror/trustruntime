use rcgen::Certificate;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaError {
    #[error("ca_read_error")]
    ReadError,
    #[error("ca_invalid")]
    Invalid,
}

/// Provides CA certificate and key for MITM dynamic certificate signing.
/// Scenario 1: reads from local pre-made PEM files. Scenario 2: injected via inject_ca().
pub struct CaProvider {
    signer: rcgen::KeyPair,
}

impl CaProvider {
    /// Loads CA from local pre-made PEM files (scenario 1).
    pub fn from_local(cert_path: &str, key_path: &str) -> Result<Self, CaError> {
        let key_pem = std::fs::read(key_path).map_err(|_| CaError::ReadError)?;
        Self::from_pem(&key_pem)
    }

    /// Creates CaProvider from in-memory PEM key bytes (scenario 2 inject_ca).
    pub fn from_pem(key_pem: &[u8]) -> Result<Self, CaError> {
        let key_str = std::str::from_utf8(key_pem).map_err(|_| CaError::Invalid)?;
        let signer = rcgen::KeyPair::from_pem(key_str).map_err(|_| CaError::Invalid)?;
        Ok(Self { signer })
    }

    /// Signs a dynamic certificate for the given domain using the CA key.
    /// Returns (cert_der, key_der) bytes for TLS server config.
    pub fn sign_domain_cert(&self, domain: &str) -> Result<(Vec<u8>, Vec<u8>), CaError> {
        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()]);
        params.distinguished_name = rcgen::DistinguishedName::new();
        let cert = Certificate::with_signer(&params, &self.signer).map_err(|_| CaError::Invalid)?;
        let cert_der = cert.der().to_vec();
        let key_der = cert.serialize_private_key_der();
        Ok((cert_der, key_der))
    }
}
