use thiserror::Error;

#[derive(Debug, Error)]
pub enum LogError {
    #[error("write_error")]
    WriteError,
    #[error("lock_error")]
    LockError,
}
