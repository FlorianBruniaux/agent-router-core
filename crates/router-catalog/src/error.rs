use thiserror::Error;

#[derive(Debug, Error)]
#[error("{code} at {path}: {message}")]
pub struct CatalogError {
    pub code: String,
    pub path: String,
    pub message: String,
}

impl CatalogError {
    pub fn new(
        code: impl Into<String>,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            path: path.into(),
            message: message.into(),
        }
    }

    pub fn code(&self) -> &str {
        &self.code
    }
}
