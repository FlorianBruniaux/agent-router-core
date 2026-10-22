#![forbid(unsafe_code)]

mod evaluator_qualification;
pub use evaluator_qualification::*;

mod qualified_pricing;
pub use qualified_pricing::*;

mod candidate_replay;
mod corpus;
mod metrics;
mod promotion;
mod replay;
mod tradeoffs;

pub use candidate_replay::{CandidateReplay, ProposedDecision};
pub use corpus::{CandidateCase, CandidateCorpus};
pub use metrics::*;
pub use promotion::{
    EvaluationMetrics, MetricRule, OutcomeCounts, PairedTrace, PromotionCriteria, PromotionMetric,
    ShadowReport, compare_shadow, dataset_hash,
};
pub use replay::*;
pub use tradeoffs::*;

use serde::Serialize;
use sha2::{Digest, Sha256};

pub const MAX_REPLAY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EVALUATION_CASES: usize = 1000;

#[derive(Debug, thiserror::Error)]
pub enum EvalError {
    #[error("eval.invalid: {0}")]
    Invalid(&'static str),
    #[error("eval.limit: {0}")]
    Limit(&'static str),
    #[error("eval.integrity")]
    Integrity,
    #[error("eval.model.unknown")]
    UnknownModel,
    #[error("eval.pricing.unknown")]
    UnknownPricing,
    #[error("eval.pricing.overflow")]
    CostOverflow,
    #[error("eval.policy.unknown")]
    UnknownPolicy,
    #[error("eval.snapshot: {0}")]
    Snapshot(#[from] router_adapter_api::SnapshotError),
    #[error("eval.catalog.invalid")]
    Catalog,
    #[error("eval.backend.failed")]
    Backend,
}
pub type Result<T> = std::result::Result<T, EvalError>;

pub(crate) fn hash<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| EvalError::Invalid("serialization"))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}
pub(crate) fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub(crate) fn text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}
