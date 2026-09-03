use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaError {
    #[error("ca_read_error")]
    ReadError,
    #[error("ca_invalid: {0}")]
    Invalid(String),
}

pub struct CaProvider {
    signer: rcgen::KeyPair,
}

impl CaProvider {
    pub fn from_local(_cert_path: &str, key_path: &str) -> Result<Self, CaError> {
        let key_pem = std::fs::read(key_path).map_err(|_| CaError::ReadError)?;
        Self::from_pem(&key_pem)
    }

    pub fn from_pem(key_pem: &[u8]) -> Result<Self, CaError> {
        let key_str = std::str::from_utf8(key_pem).map_err(|_| CaError::Invalid("invalid utf8".to_string()))?;
        let signer = rcgen::KeyPair::from_pem(key_str).map_err(|e| CaError::Invalid(e.to_string()))?;
        Ok(Self { signer })
    }

    pub fn sign_domain_cert(&self, domain: &str) -> Result<(Vec<u8>, Vec<u8>), CaError> {
        let params = rcgen::CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| CaError::Invalid(e.to_string()))?;
        let cert = params.self_signed(&self.signer).map_err(|e| CaError::Invalid(e.to_string()))?;
        let cert_der = cert.der().to_vec();
        let key_der = self.signer.serialize_der();
        Ok((cert_der, key_der))
    }
}
