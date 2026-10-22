//! Host preparation and observed transport, separate from objective verification.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Capability, EffortLevel, HarnessId, ModelId, SkillId, SkillTrust, StageKind};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    DryRun,
    Shadow,
    Execute,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionSandbox {
    ReadOnly,
    WorkspaceWrite,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionTarget {
    ExternalWorker,
    NativeSubagent,
    ParentConversation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolSelection {
    HostPolicy,
    Disabled,
    AllowList(Vec<String>),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionSkillKind {
    Instruction,
    Executable,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionSkill {
    pub id: SkillId,
    pub content_sha256: String,
    pub kind: ExecutionSkillKind,
    pub trust: SkillTrust,
    pub body: String,
}

impl fmt::Debug for ExecutionSkill {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionSkill")
            .field("id", &self.id)
            .field("body", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequest {
    pub schema_version: u32,
    pub receipt_id: String,
    pub candidate_id: String,
    pub phase: StageKind,
    pub host: HarnessId,
    pub model: ModelId,
    pub effort: EffortLevel,
    pub workspace: String,
    pub source_state: String,
    pub scope: Vec<String>,
    pub sandbox: ExecutionSandbox,
    pub required_capabilities: BTreeSet<Capability>,
    pub tools: ToolSelection,
    pub agent: Option<String>,
    pub skills: Vec<ExecutionSkill>,
    pub prompt: String,
    pub mode: ExecutionMode,
    pub target: ExecutionTarget,
    pub allow_degradation: bool,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
}

impl fmt::Debug for ExecutionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionRequest")
            .field("receipt_id", &self.receipt_id)
            .field("host", &self.host)
            .field("model", &self.model)
            .field("prompt", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdapterDegradation {
    pub code: String,
    pub requested: String,
    pub applied: String,
}

/// Omitted from serialised previews and debug logs. The supervisor alone feeds
/// these bytes to the child. A preview cannot be deserialised into an execution.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedInput(Vec<u8>);

impl PreparedInput {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PreparedInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PreparedRun {
    pub schema_version: u32,
    pub receipt_id: String,
    pub source_state: String,
    pub scope: Vec<String>,
    pub authorization_digest: String,
    pub snapshot_hash: String,
    pub host: HarnessId,
    pub requested_model: ModelId,
    pub requested_effort: EffortLevel,
    pub program: String,
    pub argv: Vec<String>,
    pub cwd: String,
    #[serde(skip_serializing)]
    pub stdin: PreparedInput,
    pub mode: ExecutionMode,
    pub target: ExecutionTarget,
    pub sandbox: ExecutionSandbox,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
    pub degradations: Vec<AdapterDegradation>,
    pub missing_runtime_evidence: Vec<String>,
    /// The parent conversation is never reconfigured by an external worker.
    pub parent_model_changed: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportTermination {
    Exited,
    TimedOut,
    Cancelled,
    Killed,
    SpawnFailed,
}

/// Supplied by the supervising process, never inferred from assistant text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransportOutcome {
    pub termination: TransportTermination,
    pub exit_code: Option<i32>,
    pub elapsed_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcome {
    Unknown,
    Passed,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportEventKind {
    SessionStarted,
    TurnStarted,
    AssistantMessage,
    ToolActivity,
    TurnCompleted,
    HostError,
    Ignored,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransportEvent {
    pub sequence: usize,
    pub kind: TransportEventKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservedModel {
    pub model: ModelId,
    pub source: String,
    pub source_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvidence {
    pub schema_version: u32,
    pub transport: TransportOutcome,
    pub transport_success: bool,
    pub stream_complete: bool,
    pub validation: VerificationOutcome,
    pub objective: VerificationOutcome,
    pub executed_models: Vec<ObservedModel>,
    pub executed_effort: Option<EffortLevel>,
    pub events: Vec<TransportEvent>,
    pub missing_evidence: Vec<String>,
    /// Token counts the host declared in its own stream. Absent means UNKNOWN,
    /// never zero. Report-only: admission budgets never read it (ADR 0009).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_usage: Option<HostUsage>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageProvenance {
    /// Declared by the host process. Not metered, signed or billed by the router.
    HostReported,
    Unknown,
}

/// One token count. `tokens` is `Some` exactly when `provenance` is
/// `HostReported`: a missing, negative, fractional or oversized declaration is
/// `Unknown`, never zero. Deserialization refuses any other pairing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UsageFieldWire")]
pub struct UsageField {
    pub tokens: Option<u64>,
    pub provenance: UsageProvenance,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UsageFieldWire {
    tokens: Option<u64>,
    provenance: UsageProvenance,
}

impl TryFrom<UsageFieldWire> for UsageField {
    type Error = &'static str;

    fn try_from(wire: UsageFieldWire) -> Result<Self, Self::Error> {
        match (wire.tokens, wire.provenance) {
            (Some(tokens), UsageProvenance::HostReported) if tokens <= HostUsage::MAX_TOKENS => {
                Ok(Self::host_reported(tokens))
            }
            (None, UsageProvenance::Unknown) => Ok(Self::UNKNOWN),
            _ => Err("usage field: tokens and provenance disagree or exceed the bound"),
        }
    }
}

impl UsageField {
    pub const UNKNOWN: Self = Self {
        tokens: None,
        provenance: UsageProvenance::Unknown,
    };

    /// The count, only when the host reported it.
    pub fn reported(&self) -> Option<u64> {
        match (self.tokens, self.provenance) {
            (Some(tokens), UsageProvenance::HostReported) => Some(tokens),
            _ => None,
        }
    }

    pub fn host_reported(tokens: u64) -> Self {
        Self {
            tokens: Some(tokens),
            provenance: UsageProvenance::HostReported,
        }
    }
}

/// Token counts declared by the host, normalized to one meaning for every host.
/// A field the host did not declare validly is `UsageField::UNKNOWN`.
///
/// - `input_tokens`: total input, cache reads and cache writes included.
/// - `cached_input_tokens`: cache reads, a subset of `input_tokens`.
/// - `cache_write_input_tokens`: cache creation, a subset of `input_tokens`.
///   UNKNOWN when the host omits it or declares it as null.
/// - `output_tokens`: total output, reasoning included.
/// - `reasoning_output_tokens`: a subset of `output_tokens`. Codex only;
///   UNKNOWN for Claude, which documents no such field.
///
/// Codex reports cache reads and writes within `input_tokens`, and reasoning
/// within `output_tokens`. Its upstream usage parser test declares 100 input,
/// 40 cached, 60 cache-write, 10 output, and 110 total tokens.
/// Claude reports `input_tokens` without cache reads or writes, so the decoder
/// adds them. Totals therefore never add a subset field a second time.
///
/// A Codex stream with more than one `turn.completed`, or a Claude stream with
/// more than one root `result`, yields no usage at all: nothing establishes
/// whether each `usage` is per turn or cumulative, and a sum would double count
/// in the cumulative case.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostUsage {
    pub input_tokens: UsageField,
    pub cached_input_tokens: UsageField,
    pub cache_write_input_tokens: UsageField,
    pub output_tokens: UsageField,
    pub reasoning_output_tokens: UsageField,
}

impl HostUsage {
    /// Ceiling for one field or a total. Larger declarations are refused.
    pub const MAX_TOKENS: u64 = 1_000_000_000_000;

    /// `input_tokens + output_tokens`, only when both are known and the total is in bounds.
    pub fn total_tokens(&self) -> Option<u64> {
        self.input_tokens
            .reported()?
            .checked_add(self.output_tokens.reported()?)
            .filter(|total| *total <= Self::MAX_TOKENS)
    }
}
