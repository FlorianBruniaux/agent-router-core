//! Standard sidecar v1. These messages convey claims, never execution authority.
use crate::{
    BackendProposal, BackendRequest, EffortLevel, FeedbackFailure, FeedbackMeasurements,
    PerceivedCost, RiskLevel, TaskKind, VerificationOutcome,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SidecarOperation {
    Rank,
    Outcome,
    Feedback,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarCapabilities {
    pub schema_version: u32,
    pub protocol_version: u32,
    pub backend_artifact_sha256: String,
    pub operations: Vec<SidecarOperation>,
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
    pub max_candidates: u32,
    pub idempotent_telemetry: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarRankRequest {
    pub schema_version: u32,
    pub protocol_version: u32,
    pub backend_artifact_sha256: String,
    pub request: BackendRequest,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarRankResponse {
    pub schema_version: u32,
    pub protocol_version: u32,
    pub backend_artifact_sha256: String,
    pub proposal: BackendProposal,
}

/// Fixed allowlist projection. No free-text identifiers, paths or comments.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarObservation {
    pub event_sha256: String,
    pub consent_revision: u64,
    pub observed_at_unix_seconds: u64,
    pub task_sha256: String,
    pub run_sha256: String,
    pub receipt_sha256: String,
    pub policy_sha256: String,
    pub catalog_sha256: String,
    pub snapshot_sha256: String,
    pub provenance_sha256: String,
    pub context_sha256: String,
    pub model_sha256: String,
    pub harness_sha256: String,
    pub task_kind: TaskKind,
    pub risk: RiskLevel,
    pub effort: EffortLevel,
    pub transport: VerificationOutcome,
    pub validation: VerificationOutcome,
    pub objective: VerificationOutcome,
    pub verification_evidence_sha256: Option<String>,
    pub failure: Option<FeedbackFailure>,
    pub measurements: FeedbackMeasurements,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarHumanVerdict {
    pub success: VerificationOutcome,
    pub quality: Option<u8>,
    pub perceived_cost: PerceivedCost,
    pub correction_required: Option<bool>,
    pub reviewer_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarOutcome {
    pub observation: SidecarObservation,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarHumanFeedback {
    pub observation: SidecarObservation,
    pub human: SidecarHumanVerdict,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarTelemetryRequest<T> {
    pub schema_version: u32,
    pub protocol_version: u32,
    pub backend_artifact_sha256: String,
    pub message_sha256: String,
    pub payload: T,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SidecarAcknowledgementStatus {
    Accepted,
    Duplicate,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarAcknowledgement {
    pub schema_version: u32,
    pub protocol_version: u32,
    pub backend_artifact_sha256: String,
    pub operation: SidecarOperation,
    pub message_sha256: String,
    pub status: SidecarAcknowledgementStatus,
}
