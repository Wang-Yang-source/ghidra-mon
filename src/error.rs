// Typed error handling for Ghidrai.
// Replaces all Box<dyn Error> usage with specific, actionable error variants.

use thiserror::Error;

/// All errors that can occur in Ghidrai operations.
#[derive(Error, Debug)]
pub enum RevisorError {
    /// IO errors with context about what operation failed
    #[error("IO error: {operation} - {source}")]
    Io {
        operation: String,
        #[source]
        source: std::io::Error,
    },

    /// Errors communicating with the Ghidra Java bridge
    #[error("Bridge error: {message}")]
    Bridge { message: String },

    /// JSON serialization/deserialization errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Errors during Ghidra setup/download
    #[error("Setup error: {0}")]
    Setup(String),

    /// Ghidra installation not found
    #[error("Ghidra not found. Run 'ghidrai setup' first.")]
    GhidraNotFound,

    /// Network errors (downloads, bridge connections)
    #[error("Network error: {0}")]
    Network(String),

    /// Catch-all for other errors
    #[error("{0}")]
    Other(String),
}

impl RevisorError {
    /// Create an IO error with context about what operation was being performed
    pub fn io(operation: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            operation: operation.into(),
            source,
        }
    }
}

impl From<std::io::Error> for RevisorError {
    fn from(e: std::io::Error) -> Self {
        Self::Io {
            operation: "unknown".to_string(),
            source: e,
        }
    }
}

impl From<reqwest::Error> for RevisorError {
    fn from(e: reqwest::Error) -> Self {
        Self::Network(e.to_string())
    }
}

impl From<zip::result::ZipError> for RevisorError {
    fn from(e: zip::result::ZipError) -> Self {
        Self::Setup(format!("ZIP extraction failed: {e}"))
    }
}

impl From<std::env::VarError> for RevisorError {
    fn from(e: std::env::VarError) -> Self {
        Self::Setup(format!("Environment variable error: {e}"))
    }
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, RevisorError>;
