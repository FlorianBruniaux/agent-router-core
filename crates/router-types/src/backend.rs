use crate::{RiskLevel, StageKind, TaskKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendFailurePolicy {
    DeterministicFallback,
    Abstain,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendDataPolicy {
    Deny,
    RedactedMetadataToLoopback,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendCandidate {
    pub id: String,
    pub utility_micros: i64,
    pub cost_microusd: u64,
    pub tokens: u64,
    pub elapsed_ms: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendRequest {
    pub schema_version: u32,
    pub artifact_digest: String,
    pub kind: TaskKind,
    pub risk: RiskLevel,
    pub phase: StageKind,
    pub candidates: Vec<BackendCandidate>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendProposal {
    pub schema_version: u32,
    pub artifact_digest: String,
    pub candidate_id: Option<String>,
    pub confidence_micros: u32,
    pub probabilities_micros: BTreeMap<String, u32>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackendDecision {
    pub schema_version: u32,
    pub baseline_receipt_id: String,
    pub backend: String,
    pub active_candidate_id: Option<String>,
    pub shadow_candidate_id: Option<String>,
    pub confidence_micros: Option<u32>,
    pub fallback_reason: Option<String>,
    pub semantic_execution_enabled: bool,
}
