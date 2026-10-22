#![forbid(unsafe_code)]
mod execution;
mod normalize;
mod plan;
mod policy;
mod prompt;
mod proposal;
pub use execution::{seal_execution_contract, validate_execution_contract};
pub use normalize::{normalize, normalize_with_risk, validate_task};
pub use plan::{PlanLimits, build_plan, validate_plan};
pub use policy::{merge_restrictions, resolve_configuration, validate_restrictions};
pub use prompt::{render_prompt, seal_prompt};
pub use proposal::{
    MAX_PROPOSAL_BYTES, NodeDivergence, PLAN_PROPOSAL_SCHEMA, PlanDivergence, PlanProposalReview,
    review_plan_proposal,
};

use sha2::{Digest, Sha256};
#[derive(Debug, thiserror::Error)]
pub enum WorkflowError {
    #[error("workflow.invalid: {0}")]
    Invalid(&'static str),
    #[error("workflow.limit: {0}")]
    Limit(&'static str),
    #[error("workflow.authority: {0}")]
    Authority(&'static str),
    #[error("workflow.integrity")]
    Integrity,
    #[error("workflow.cost.exceeded: simplify with preset {suggested}")]
    Cost { suggested: &'static str },
}
pub type Result<T> = std::result::Result<T, WorkflowError>;
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && !path.contains('\\')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && !std::path::Path::new(path).is_absolute()
        && !path
            .chars()
            .any(|c| c.is_control() || matches!(c, '*' | '?' | '[' | ']'))
}
fn text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 16_384 && !value.contains('\0')
}
