use serde::{Deserialize, Serialize};

/// Audit data only. Deserializing this binding never authorizes execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionDecisionBinding {
    pub schema_version: u32,
    pub decision_id: String,
    pub baseline_receipt_id: String,
    pub context_hash: String,
    pub selected_candidate_id: String,
    pub selection_sha256: String,
    pub backend: BackendDecisionBinding,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendDecisionBinding {
    pub activation_state_hash: String,
    pub authority_roots_sha256: String,
    pub backend_artifact_hash: Option<String>,
    pub promotion_hash: Option<String>,
    pub proposal_sha256: Option<String>,
    pub proposal_expires_at_unix_seconds: Option<u64>,
    pub backend_decision_hash: String,
}
