use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum ParseError {
    #[error("syntax_error: section={section}")]
    SyntaxError { section: String },

    #[error("missing_field: section={section}")]
    MissingField { section: String },

    #[error("type_mismatch: section={section}")]
    TypeMismatch { section: String },

    #[error("conflict: section={section}, rule_index={rule_index}, conflict_with={conflict_with}")]
    Conflict { section: String, rule_index: usize, conflict_with: usize },

    #[error("invalid_config: section={section}")]
    InvalidConfig { section: String },
}

impl ParseError {
    /// Returns the error type string for this error variant.
    pub fn error_type(&self) -> &'static str {
        match self {
            Self::SyntaxError { .. } => "syntax_error",
            Self::MissingField { .. } => "missing_field",
            Self::TypeMismatch { .. } => "type_mismatch",
            Self::Conflict { .. } => "conflict",
            Self::InvalidConfig { .. } => "invalid_config",
        }
    }
}
