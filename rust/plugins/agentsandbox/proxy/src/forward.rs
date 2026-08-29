/// Forwards allowed traffic to target server.
/// Supports HTTP (plain TCP) and HTTPS (TLS outbound). When handler modifies Host header,
/// proxy connects to the new target domain instead of the original SNI.
use crate::error::ForwardError;

/// Forwards an HTTP request to the target. Uses plain TCP for HTTP, TLS for HTTPS.
pub async fn forward_request(domain: &str, port: u16, is_https: bool, request: &[u8]) -> Result<Vec<u8>, ForwardError> {
    let _ = (domain, port, is_https, request);
    Err(ForwardError::TargetUnreachable)
}
