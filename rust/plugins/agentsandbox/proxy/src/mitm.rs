use crate::ca::CaProvider;
use crate::error::ProxyError;
use std::collections::HashMap;
use std::sync::Mutex;

/// TLS MITM handler. Performs TLS handshake with dynamic certificate signing.
/// Protocol detection: first byte 0x16 = TLS ClientHello (HTTPS), otherwise HTTP.
pub struct MitmHandler {
    ca: CaProvider,
    cert_cache: Mutex<HashMap<String, (Vec<u8>, Vec<u8>)>>,
}

impl MitmHandler {
    pub fn new(ca: CaProvider) -> Self {
        Self { ca, cert_cache: Mutex::new(HashMap::new()) }
    }

    /// Detects protocol from first byte. Returns true if HTTPS (0x16 TLS ClientHello).
    pub fn is_tls(first_byte: u8) -> bool {
        first_byte == 0x16
    }

    /// Signs a dynamic certificate for the given domain. Uses in-memory cache.
    pub fn get_cert_for_domain(&self, domain: &str) -> Result<(Vec<u8>, Vec<u8>), ProxyError> {
        if let Ok(cache) = self.cert_cache.lock() {
            if let Some(c) = cache.get(domain) {
                return Ok(c.clone());
            }
        }
        let (cert, key) = self.ca.sign_domain_cert(domain).map_err(|_| ProxyError::CertGenerationError)?;
        if let Ok(mut cache) = self.cert_cache.lock() {
            cache.insert(domain.to_string(), (cert, key));
        }
        let pair = cache_entry(domain, &self.cert_cache);
        pair.ok_or(ProxyError::CertGenerationError)
    }
}

fn cache_entry(domain: &str, cache: &Mutex<HashMap<String, (Vec<u8>, Vec<u8>)>>) -> Option<(Vec<u8>, Vec<u8>)> {
    let c = cache.lock().ok()?;
    c.get(domain).cloned()
}
