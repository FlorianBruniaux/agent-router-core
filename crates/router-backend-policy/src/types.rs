use crate::{PromotionError, Result, digest, label, valid_hash};
use router_eval::{PromotionCriteria, ReplayRecord};
use router_types::{BackendDataPolicy, BackendFailurePolicy, BackendProposal};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const SIGNED_PROTOCOL: &str = "agent-router:signed-backend-proposal:v1;identity=artifact+code+protocol;scope=context+closed-pool+evaluation-or-activation;permissions=none";
pub fn protocol_hash() -> String {
    router_adapter_api::content_digest(SIGNED_PROTOCOL.as_bytes())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendArtifact {
    pub schema_version: u32,
    pub backend_id: String,
    pub version: String,
    pub artifact_sha256: String,
    pub implementation_sha256: String,
    pub protocol_sha256: String,
    pub backend_key_id: String,
    pub authors: BTreeSet<String>,
    pub routing_policy_hash: String,
    pub created_at_unix_seconds: u64,
    pub minimum_confidence_micros: u32,
    pub failure_policy: BackendFailurePolicy,
    pub data_policy: BackendDataPolicy,
    pub maximum_proposal_age_seconds: u64,
    pub maximum_evidence_age_seconds: u64,
    pub minimum_shadow_cases: usize,
    pub maximum_canary_cases: usize,
}
impl BackendArtifact {
    pub fn content_hash(&self) -> Result<String> {
        self.validate()?;
        digest("agent-router:backend-artifact:v1\0", self)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || !label(&self.backend_id)
            || !label(&self.version)
            || !label(&self.backend_key_id)
            || !valid_hash(&self.artifact_sha256)
            || !valid_hash(&self.implementation_sha256)
            || !valid_hash(&self.routing_policy_hash)
            || self.protocol_sha256 != protocol_hash()
            || self.authors.is_empty()
            || self.authors.len() > 64
            || self.authors.iter().any(|id| !label(id))
            || self.minimum_confidence_micros > 1_000_000
            || !(1..=600).contains(&self.maximum_proposal_age_seconds)
            || !(1..=30 * 86_400).contains(&self.maximum_evidence_age_seconds)
            || !(1..=crate::MAX_CASES).contains(&self.minimum_shadow_cases)
            || !(1..=crate::MAX_CASES).contains(&self.maximum_canary_cases)
        {
            return Err(PromotionError::Invalid);
        }
        Ok(())
    }
}

/// A statement is authenticated only against a separately supplied role/key.
/// The document carries no public key and cannot nominate a trusted authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub statement: T,
    pub key_id: String,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "mode",
    content = "binding",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProposalPurpose {
    Evaluation(String),
    Active(String),
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendResponse {
    pub schema_version: u32,
    pub backend_artifact_hash: String,
    pub request_sha256: String,
    pub purpose: ProposalPurpose,
    pub proposal: BackendProposal,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}
pub type SignedBackendProposal = Signed<BackendResponse>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanLabelStatement {
    pub schema_version: u32,
    pub replay_input_hash: String,
    pub label_sha256: String,
    pub reviewed_at_unix_seconds: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CriteriaStatement {
    pub schema_version: u32,
    pub backend_artifact_hash: String,
    pub criteria_sha256: String,
    pub registered_at_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialStage {
    Shadow,
    Canary,
}
/// Independent operator attestation. A signature authenticates the attestation,
/// not the physical truth of an external trial; exact evidence is approval-bound.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrialStatement {
    pub schema_version: u32,
    pub stage: TrialStage,
    pub backend_artifact_hash: String,
    pub evaluation_sha256: String,
    pub evidence_sha256: String,
    pub cases: usize,
    pub hard_constraint_violations: usize,
    pub subgroup_regressions: usize,
    pub accepted: bool,
    pub started_at_unix_seconds: u64,
    pub completed_at_unix_seconds: u64,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendEvaluationCase {
    pub record: ReplayRecord,
    pub baseline_policy_id: String,
    pub semantic_policy_id: String,
    pub evaluated_at_unix_seconds: u64,
    pub snapshot_max_age_seconds: u64,
    pub proposal: SignedBackendProposal,
    pub label: Signed<HumanLabelStatement>,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionEvidence {
    pub schema_version: u32,
    pub criteria: PromotionCriteria,
    pub criteria_registration: Signed<CriteriaStatement>,
    pub cases: Vec<BackendEvaluationCase>,
    pub shadow: Signed<TrialStatement>,
    pub canary: Signed<TrialStatement>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationAction {
    Activate,
    Rollback,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationApproval {
    pub schema_version: u32,
    pub action: ActivationAction,
    pub expected_state_hash: String,
    /// Promotion hash for Activate, retained deterministic policy hash for Rollback.
    pub target_hash: String,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub nonce_sha256: String,
}

pub fn label_hash(label: &router_eval::CaseLabel) -> Result<String> {
    digest("agent-router:human-label:v1\0", label)
}
pub fn criteria_hash(criteria: &PromotionCriteria) -> Result<String> {
    digest("agent-router:promotion-criteria:v1\0", criteria)
}
pub fn backend_request_hash(request: &router_types::BackendRequest) -> Result<String> {
    digest("agent-router:backend-request:v1\0", request)
}
