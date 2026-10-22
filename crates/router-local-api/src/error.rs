/// Setup failures. Each carries a stable code and never a path, token or
/// request content.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("local_api.limits.invalid")]
    Limits,
    #[error("{0}")]
    StateDir(&'static str),
    #[error("{0}")]
    Token(&'static str),
    #[error("{0}")]
    Socket(&'static str),
    #[error("local_api.io")]
    Io,
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Limits => "local_api.limits.invalid",
            Self::StateDir(code) | Self::Token(code) | Self::Socket(code) => code,
            Self::Io => "local_api.io",
        }
    }
}
