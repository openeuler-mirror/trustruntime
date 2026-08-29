use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("group_id_not_found")]
    GroupIdNotFound,
    #[error("config_not_found")]
    ConfigNotFound,
    #[error("ca_error")]
    CaError,
    #[error("cert_generation_error")]
    CertGenerationError,
    #[error("log_write_error")]
    LogWriteError,
}

#[derive(Debug, Error)]
pub enum ForwardError {
    #[error("group_not_found")]
    GroupNotFound,
    #[error("rule_deny")]
    RuleDeny,
    #[error("target_unreachable")]
    TargetUnreachable,
    #[error("tls_error")]
    TlsError,
    #[error("timeout")]
    Timeout,
}

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("flow_not_found")]
    FlowNotFound,
    #[error("already_released")]
    AlreadyReleased,
    #[error("not_cached")]
    NotCached,
}
