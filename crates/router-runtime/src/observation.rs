//! Redacted projection of one coherent, bounded runtime-store read.
//! These are observation contracts, never executable authority.
use router_types::{ProcessCleanupEvidence, RunFailure, RunState};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunObservation {
    pub schema_version: u32,
    pub snapshot_sha256: String,
    pub identity: RunObservationIdentity,
    pub horizon: RunObservationHorizon,
    pub known: RunObservationKnown,
    pub unknown: RunObservationUnknowns,
    pub completeness: RunObservationCompleteness,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunObservationIdentity {
    pub run_key_sha256: String,
    pub definition_sha256: String,
    pub receipt_id_sha256: String,
    pub plan_id_sha256: String,
    pub node_id_sha256: String,
}
/// Horizon of the entire verified journal, including events for other runs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunObservationHorizon {
    pub sequence: u64,
    pub event_sha256: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunObservationKnown {
    /// Persisted runtime state, not independent process or objective evidence.
    pub state: RunState,
    pub attempts: u32,
    pub failure: Option<RunFailure>,
    /// Persisted cleanup scope only. No process or lease is probed on read.
    pub cleanup: ProcessCleanupEvidence,
    pub events: Vec<RunEventReference>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunEventReference {
    pub sequence: u64,
    pub state: RunState,
    pub event_sha256: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationUnknown {
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunObservationUnknowns {
    pub requested_model: ObservationUnknown,
    pub requested_effort: ObservationUnknown,
    pub observed_model: ObservationUnknown,
    pub observed_effort: ObservationUnknown,
    pub transport: ObservationUnknown,
    pub validation: ObservationUnknown,
    pub objective: ObservationUnknown,
    pub duration: ObservationUnknown,
    pub journal_authenticity: ObservationUnknown,
    pub process_liveness: ObservationUnknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationJournalCoverage {
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationDetailCoverage {
    Redacted,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunObservationCompleteness {
    /// Complete chain coverage through horizon. Hashes do not prove authenticity.
    pub journal: ObservationJournalCoverage,
    pub external_observations: ObservationUnknown,
    pub detail: ObservationDetailCoverage,
}

/// Opt-in attempt facts, projected in the same passive snapshot as the summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RunObservationV2 {
    #[serde(flatten)]
    pub summary: RunObservation,
    pub attempts: Vec<RunAttemptObservation>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunAttemptObservation {
    pub ordinal: u32,
    pub attempt_key_sha256: String,
    pub evidence: AttemptObservationEvidence,
    pub requested: Option<AttemptObservationRequested>,
    pub transport: Option<AttemptObservationTransport>,
    pub sources: AttemptObservationSources,
    pub capture: AttemptObservationCapture,
    pub protocol: ObservationUnknown,
    pub native: AttemptObservationNative,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptObservationEvidence {
    Unknown,
    DurableAttempt,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptObservationRequested {
    pub model: router_types::ModelId,
    pub effort: router_types::EffortLevel,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptObservationTransport {
    pub termination: router_types::TransportTermination,
    pub exit_code: Option<i32>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptObservationSources {
    pub started_event_sha256: String,
    pub attempt_evidence_sha256: Option<String>,
    pub finished_event_sha256: Option<String>,
    pub transition_event_sha256: Option<String>,
    pub output_incomplete_event_sha256: Option<String>,
    /// Legacy protocol events have no ordinal binding and cannot qualify here.
    pub protocol_event_sha256: Option<String>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptObservationCapture {
    Unknown,
    Incomplete,
    OutputLimit,
    OutputLimitIncomplete,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptObservationNative {
    pub observed_model: ObservationUnknown,
    pub observed_effort: ObservationUnknown,
    pub thread_id: ObservationUnknown,
    pub turn_id: ObservationUnknown,
    pub usage: ObservationUnknown,
    pub notification_delivery: ObservationUnknown,
    pub lost_notifications: ObservationUnknown,
    pub duration: ObservationUnknown,
    pub validation: ObservationUnknown,
    pub objective: ObservationUnknown,
}

/// Explicit opt-in local capture intervals, read with the v2 facts in one snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RunObservationV3 {
    #[serde(flatten)]
    pub observation: RunObservationV2,
    pub timings: Vec<crate::AttemptTimingObservation>,
}
