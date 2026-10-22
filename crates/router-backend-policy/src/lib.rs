//! Explicit, externally authorized backend promotion. No network, process,
//! model execution, file I/O, automatic activation or permission grants.
#![forbid(unsafe_code)]

mod activation;
mod crypto;
mod decision;
mod promotion;
mod types;

pub use activation::{ActivationEvent, BackendActivationState};
pub use crypto::{AuthorityRole, TrustedAuthorities, signing_message};
pub use decision::{
    ActivatedBackendDecision, ActiveDecisionEvidence, ActiveDecisionMode, ActiveDecisionReason,
    decide_active,
};
pub use promotion::{
    FamilyEvaluationReport, ValidatedBackendEvaluation, ValidatedBackendPromotion,
    evaluate_backend, evaluate_backend_with_verifier, evaluate_promotion,
    evaluate_promotion_with_verifier, evaluation_dataset_hash,
};
pub use types::*;

use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CASES: usize = 1000;
pub const MAX_ACTIVATION_EVENTS: usize = 128;

#[derive(Debug, thiserror::Error)]
pub enum PromotionError {
    #[error("backend_policy.invalid")]
    Invalid,
    #[error("backend_policy.limit")]
    Limit,
    #[error("backend_policy.signature")]
    Signature,
    #[error("backend_policy.authority")]
    Authority,
    #[error("backend_policy.integrity")]
    Integrity,
    #[error("backend_policy.freshness")]
    Freshness,
    #[error("backend_policy.gate")]
    Gate,
    #[error("backend_policy.context")]
    Context,
    #[error("backend_policy.state")]
    State,
}
pub type Result<T> = std::result::Result<T, PromotionError>;

pub fn parse_document<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(PromotionError::Limit);
    }
    let value = router_adapter_api::strict_json_limited(bytes, MAX_DOCUMENT_BYTES)
        .map_err(|_| PromotionError::Invalid)?;
    serde_json::from_value(value).map_err(|_| PromotionError::Invalid)
}
pub(crate) fn digest<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| PromotionError::Invalid)?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(PromotionError::Limit);
    }
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}
pub(crate) fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
}
pub(crate) fn valid_hash(value: &str) -> bool {
    router_adapter_api::is_digest(value)
}
