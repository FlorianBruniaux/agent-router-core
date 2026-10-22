use crate::{RuntimeEvidence, TransportOutcome, VerificationOutcome};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Planned,
    AwaitingApproval,
    Queued,
    Preparing,
    Running,
    SucceededTransport,
    Verifying,
    Verified,
    Failed,
    VerificationFailed,
    TimedOut,
    Cancelled,
    Blocked,
}
impl RunState {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Verified
                | Self::Failed
                | Self::VerificationFailed
                | Self::TimedOut
                | Self::Cancelled
                | Self::Blocked
        )
    }
    pub fn permits(self, next: Self) -> bool {
        use RunState::*;
        matches!(
            (self, next),
            (Planned, AwaitingApproval | Cancelled)
                | (AwaitingApproval, Queued | Cancelled)
                | (Queued, Preparing | Blocked | Cancelled)
                | (Preparing, Running | Failed | Blocked | Cancelled)
                | (Running, SucceededTransport | Failed | TimedOut | Cancelled)
                | (SucceededTransport, Verifying)
                | (Verifying, Verified | VerificationFailed)
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueReason {
    Dependencies,
    GlobalCapacity,
    ProviderCapacity,
    AgentCapacity,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunFailure {
    Authentication,
    RateLimit,
    Timeout,
    Crash,
    Network,
    Policy,
    Verification,
    Interrupted,
    OutputLimit,
    Spawn,
    /// The outcome could not be classified (adapter classification error, or
    /// output known to be incomplete). Never retryable and never attributed to
    /// the candidate model. Additive serialized value: `unclassified`.
    Unclassified,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunSummary {
    pub run_id: String,
    pub definition_hash: String,
    pub approval_digest: String,
    pub receipt_id: String,
    pub plan_id: String,
    pub node_id: String,
    pub state: RunState,
    pub attempts: u32,
    pub failure: Option<RunFailure>,
    pub worktree: Option<String>,
    pub artifact_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "OutputRetentionPolicy::is_disabled")]
    pub output_retention: OutputRetentionPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<WorkflowRunBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_contract_sha256: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRunBinding {
    pub instance_id: String,
    pub contract_sha256: String,
    pub generation: u32,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEvent {
    pub sequence: u64,
    pub run_id: String,
    pub kind: String,
    pub state: RunState,
    pub detail: String,
    pub previous_hash: String,
    pub event_hash: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunCompletion {
    pub run: RunSummary,
    pub transport: TransportOutcome,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub validation: VerificationOutcome,
    pub objective: VerificationOutcome,
    pub memory_enforcement: MemoryEnforcement,
    pub runtime_evidence: Option<RuntimeEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_artifacts: Option<OutputArtifacts>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum OutputRetentionPolicy {
    #[default]
    Disabled,
    PrivateArtifacts {
        retention_seconds: u64,
    },
}
impl OutputRetentionPolicy {
    pub fn is_disabled(&self) -> bool {
        *self == Self::Disabled
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputArtifactsState {
    Pending,
    Retained,
    Purging,
    Purged,
}

/// Metadata only. Captured process bytes are never serialized into a receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputArtifact {
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputArtifacts {
    pub schema_version: u32,
    pub run_id: String,
    pub attempt: u32,
    pub state: OutputArtifactsState,
    pub created_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub truncated: bool,
    pub stdout: OutputArtifact,
    pub stderr: OutputArtifact,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryEnforcement {
    Enforced,
    NotRequested,
    Unsupported,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationRecord {
    pub verifier: String,
    pub evidence_sha256: String,
    pub artifact_sha256: Option<String>,
    pub validation: VerificationOutcome,
    pub objective: VerificationOutcome,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationPreview {
    pub run_id: String,
    pub source_state: String,
    pub artifact_sha256: String,
    pub approval_digest: String,
    pub changed_paths: Vec<String>,
}
/// Evidence scope matters: a process group excludes descendants that detached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessCleanupEvidence {
    Unknown,
    NotStarted,
    GroupTerminated,
    NamespaceTerminated,
}

/// A regular Git blob and its executable-bit mode. No symlink/submodule entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationBlob {
    pub oid: String,
    pub mode: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationFile {
    pub path: String,
    pub before: Option<IntegrationBlob>,
    pub after: Option<IntegrationBlob>,
}
/// Publication is to a dedicated Git ref, never to the user's working files.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PatchPublicationReview {
    pub schema_version: u32,
    pub run_id: String,
    pub definition_sha256: String,
    pub repository_sha256: String,
    pub source_revision: String,
    pub artifact_sha256: String,
    pub files: Vec<IntegrationFile>,
    pub result_tree: String,
    pub result_revision: String,
    pub verification: VerificationRecord,
    pub diff: String,
    pub approval_digest: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PatchPublicationReceipt {
    pub schema_version: u32,
    pub run_id: String,
    pub approval_digest: String,
    pub source_revision: String,
    pub result_revision: String,
    pub result_tree: String,
    pub target_ref: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchPublicationState {
    NotAttempted,
    Published,
    Unknown,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PatchPublicationStatus {
    pub schema_version: u32,
    pub state: PatchPublicationState,
    pub receipt: Option<PatchPublicationReceipt>,
    /// A read-time ref observation does not repair missing terminal evidence.
    pub observed_revision: Option<String>,
}
