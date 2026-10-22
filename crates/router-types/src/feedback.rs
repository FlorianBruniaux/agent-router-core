//! Redacted local feedback. No prompt, output, path or free-text comment field.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    EffortLevel, HarnessId, HostUsage, ModelId, PhaseAbstention, RiskLevel, TaskKind,
    VerificationOutcome,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackPreferences {
    pub schema_version: u32,
    pub collection_enabled: bool,
    pub learning_enabled: bool,
    pub retention_seconds: u64,
}

impl Default for FeedbackPreferences {
    fn default() -> Self {
        Self {
            schema_version: 1,
            collection_enabled: false,
            learning_enabled: false,
            retention_seconds: 30 * 86400,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackConsent {
    pub preferences: FeedbackPreferences,
    pub revision: u64,
    pub updated_at_unix_seconds: u64,
}

/// Only immutable identities, never historical receipt bodies.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackBinding {
    pub task_hash: String,
    pub run_hash: String,
    pub receipt_hash: String,
    pub policy_hash: String,
    pub catalog_hash: String,
    pub snapshot_hash: String,
    pub producer_version: String,
    pub provenance_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackOrigin {
    Human,
    Automated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackFailure {
    Authentication,
    RateLimit,
    Timeout,
    Crash,
    Network,
    Policy,
    Validation,
    Objective,
    Budget,
    Cancelled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PerceivedCost {
    Low,
    Acceptable,
    High,
    Unknown,
}

/// Discrete context and registered asset identities. No task text or embedding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackContext {
    pub task_kind: TaskKind,
    pub risk: RiskLevel,
    pub model: ModelId,
    pub effort: EffortLevel,
    pub harness: HarnessId,
    pub transport: String,
    pub agent: Option<String>,
    pub skills: BTreeSet<String>,
    pub plan: String,
    /// Actual selection probability in millionths; None means UNKNOWN.
    pub propensity_micros: Option<u32>,
    /// Route facts from the receipt. Absent in v1 events; None means UNKNOWN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<FeedbackRoute>,
}

/// Discrete facts about how the executed candidate was ranked. No text: the
/// only string is a registered candidate identifier, validated on record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackRoute {
    pub candidate_id: String,
    /// One-based rank among the receipt's ranked candidates; None is UNKNOWN
    /// (the executed candidate is not in the receipt).
    pub rank: Option<u32>,
    /// Utility of this candidate minus the next ranked one, in micros. Signed:
    /// the receipt ranks the preferred model first, so it can be negative.
    /// None when no candidate follows or the candidate is not ranked.
    pub margin_micros: Option<i64>,
    /// Ranked candidates other than the executed one, as kept by the receipt.
    pub alternatives: u32,
    /// The baseline receipt's abstention, when the execution overrode it.
    pub abstention: Option<PhaseAbstention>,
}

/// Explicit scope of the host usage attached to a feedback snapshot.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackUsageScope {
    /// Usage for the one-based attempt ordinal in `measurements.attempts`.
    PerAttempt,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackMeasurements {
    pub cost_microusd: Option<u64>,
    pub latency_ms: Option<u64>,
    /// Total tokens declared by the caller. The automatic CLI feedback sets it
    /// only to input plus output tokens the host declared in its own stream
    /// (`host_reported`, decoded into `RuntimeEvidence.host_usage`); manual and
    /// sidecar feedback set it themselves. `None` is UNKNOWN, never zero.
    pub tokens: Option<u64>,
    pub attempts: u32,
    pub escalations: u32,
    /// Token split the host declared, with its provenance. Report input only:
    /// it prices runs at report time and never feeds admission budgets. Absent
    /// in earlier events, so they keep their bytes and hash; None is UNKNOWN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<HostUsage>,
    /// Absent legacy usage has no retry scope guarantee. Omission preserves
    /// existing event bytes and hashes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_scope: Option<FeedbackUsageScope>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanVerdict {
    pub success: VerificationOutcome,
    /// Quality on an explicit 0..=100 scale.
    pub quality: Option<u8>,
    pub perceived_cost: PerceivedCost,
    pub correction_required: Option<bool>,
    pub reviewer_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackInput {
    pub schema_version: u32,
    pub observed_at_unix_seconds: u64,
    /// Start of the native process, at most `observed_at_unix_seconds`. Absent in
    /// earlier events and in human feedback; None means UNKNOWN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at_unix_seconds: Option<u64>,
    /// Digest of the stable run identity (run id, definition hash, approval
    /// digest), the key late facts use to refer to the run. It is not part of
    /// `FeedbackBinding`, which human and automated verdicts must share. None
    /// means UNKNOWN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_key_sha256: Option<String>,
    pub binding: FeedbackBinding,
    pub context: FeedbackContext,
    pub origin: FeedbackOrigin,
    pub transport: VerificationOutcome,
    pub validation: VerificationOutcome,
    pub objective: VerificationOutcome,
    /// Required for a claimed validation or objective result, not authenticity proof.
    pub verification_evidence_sha256: Option<String>,
    pub human: Option<HumanVerdict>,
    pub failure: Option<FeedbackFailure>,
    pub measurements: FeedbackMeasurements,
    /// Explicitly redacted comment digest. The comment itself is never persisted.
    pub comment_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackEvent {
    pub sequence: u64,
    pub consent_revision: u64,
    pub recorded_at_unix_seconds: u64,
    pub input: FeedbackInput,
    pub event_hash: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationOutcome {
    Applied,
    Discarded,
}

/// What a late fact states. Enumerations and digests only, never free text.
/// The human outcome is not a kind: it stays the human-origin `FeedbackEvent`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FeedbackFactKind {
    Verification {
        validation: VerificationOutcome,
        objective: VerificationOutcome,
        evidence_sha256: String,
    },
    Integration {
        outcome: IntegrationOutcome,
    },
}

impl FeedbackFactKind {
    /// Stable storage key: at most one fact per `(run key, name)`.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Verification { .. } => "verification",
            Self::Integration { .. } => "integration",
        }
    }
}

/// A fact learned after the automated verdict, keyed by the stable run key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackFact {
    pub schema_version: u32,
    pub run_key_sha256: String,
    pub observed_at_unix_seconds: u64,
    pub kind: FeedbackFactKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackFactEvent {
    pub sequence: u64,
    pub consent_revision: u64,
    pub recorded_at_unix_seconds: u64,
    pub fact: FeedbackFact,
    pub fact_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackExport {
    pub schema_version: u32,
    pub exported_at_unix_seconds: u64,
    pub consent: FeedbackConsent,
    pub events: Vec<FeedbackEvent>,
    /// Late facts. Absent when there are none, so an export without facts keeps
    /// its earlier bytes and hash.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facts: Vec<FeedbackFactEvent>,
    pub content_hash: String,
}

/// Read-only measurement projection from a coherent runtime journal snapshot.
/// This is correlation evidence, never execution authority or host usage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FeedbackRuntimeInventory {
    pub schema_version: u32,
    pub journal_sha256: String,
    pub runs: Vec<FeedbackRuntimeRun>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FeedbackRuntimeRun {
    pub run_key_sha256: String,
    /// Original feedback keys across fresh retry approvals, never inferred from task text.
    pub feedback_run_keys_sha256: Vec<String>,
    pub occurrence_sha256: String,
    pub predecessor_run_key_sha256: Option<String>,
    pub attempts: u32,
    pub state: crate::RunState,
}
