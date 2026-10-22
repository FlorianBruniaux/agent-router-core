#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Bounded metadata-only BM25. Retrieval never executes an asset or grants authority.
mod body;
mod context;
mod fusion;
mod index;
mod tokenize;
mod types;
#[cfg(feature = "semantic-ranking")]
mod vectors;

pub use context::*;
pub use fusion::*;
pub use index::Bm25Index;
pub use types::*;
#[cfg(feature = "semantic-ranking")]
pub use vectors::*;

pub const MAX_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_ASSETS: usize = 20_000;
pub const MAX_FIELD_BYTES: usize = 8 * 1024;
pub const MAX_ASSET_BYTES: usize = 32 * 1024;
pub const MAX_LIST_ITEMS: usize = 32;
pub const MAX_INDEX_TERMS: usize = 2_000_000;
pub const MAX_QUERY_BYTES: usize = 4096;
pub const MAX_QUERY_TERMS: usize = 64;
pub const MAX_QUERY_PHRASES: usize = 8;
pub const MAX_RESULTS: usize = 50;
pub const MAX_QUERY_POSTINGS: usize = 2_000_000;
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
pub const INDEX_VERSION: &str = "bm25-fields-v1";
pub const CONTEXT_INDEX_VERSION: &str = "bm25-context-v3:signals-v1:rrf-nanos-v1";

#[derive(Debug, thiserror::Error)]
pub enum RetrievalError {
    #[error("retrieval.invalid: {0}")]
    Invalid(&'static str),
    #[error("retrieval.limit: {0}")]
    Limit(&'static str),
    #[error("retrieval.stale: metadata source changed; rebuild the index")]
    Stale,
    #[error("retrieval.context.required: version 3 requires explicit contextual search")]
    ContextRequired,
    #[error("retrieval.semantic.unavailable")]
    SemanticUnavailable,
    #[error("retrieval.semantic.invalid")]
    SemanticInvalid,
    #[error("retrieval.catalog.unbound: legacy metadata has no catalog content binding")]
    UnboundCatalog,
    #[error("retrieval.catalog.required: supply the current catalog digest before selection")]
    CatalogBindingRequired,
    #[error("retrieval.catalog.mismatch: catalog content changed; rebuild the bound metadata")]
    CatalogMismatch,
    #[error("retrieval.selection: asset is absent, untrusted, blocked or has no body")]
    Selection,
    #[error("retrieval.path: body path must remain a regular file beneath the supplied root")]
    UnsafePath,
    #[error("retrieval.integrity: selected body does not match its recorded SHA-256")]
    BodyHashMismatch,
    #[error("retrieval.io: unable to {operation}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
}

pub type Result<T> = std::result::Result<T, RetrievalError>;

fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

fn trusted(trust: router_types::SkillTrust) -> bool {
    matches!(
        trust,
        router_types::SkillTrust::Builtin
            | router_types::SkillTrust::TrustedLocal
            | router_types::SkillTrust::VerifiedThirdParty
    )
}
