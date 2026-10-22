//! Audit data for escalation. Deserializing these records grants no authority.
use crate::{
    EffortLevel, ExecutionSandbox, ModelId, PhaseSelection, ProcessCleanupEvidence, RunFailure,
    RunState, TaskBudget, TransportOutcome, WorkflowRunBinding,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptIdentity {
    pub run_id: String,
    pub attempt: u32,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionDecisionOrigin {
    Deterministic,
    Activated,
    Escalated,
    Generated,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptEvidence {
    pub schema_version: u32,
    pub identity: AttemptIdentity,
    pub definition_hash: String,
    pub authorization_id: String,
    pub decision_origin: ExecutionDecisionOrigin,
    pub sandbox: ExecutionSandbox,
    pub context_hash: String,
    pub pool_hash: String,
    pub source_state: String,
    pub task_execution_sha256: String,
    pub candidate_id: String,
    pub model: ModelId,
    pub effort: EffortLevel,
    pub workflow: Option<WorkflowRunBinding>,
    pub state: RunState,
    pub failure: Option<RunFailure>,
    pub transport: TransportOutcome,
    pub cleanup: ProcessCleanupEvidence,
    /// None is UNKNOWN, never zero. Native usage accounting is not yet attested.
    pub observed_cost_microusd: Option<u64>,
    pub observed_tokens: Option<u64>,
    pub started_event_hash: String,
    pub finished_event_hash: String,
    pub transition_event_hash: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountingUpperBound {
    pub cost_microusd: u64,
    pub tokens: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptBoundPreview {
    pub schema_version: u32,
    pub identity: AttemptIdentity,
    pub attempt_evidence_hash: String,
    pub ledger_hash: String,
    pub upper_bound: AccountingUpperBound,
    pub approval_digest: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationTransition {
    pub from_candidate_id: String,
    pub to_candidate_id: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationPolicy {
    pub schema_version: u32,
    pub minimum_failed_attempts: u32,
    pub retryable_failures: Vec<RunFailure>,
    /// Ordered, explicitly authorized edges. No model-quality order is inferred.
    pub transitions: Vec<EscalationTransition>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationDecisionBinding {
    pub schema_version: u32,
    pub decision_id: String,
    pub baseline_receipt_id: String,
    pub context_hash: String,
    pub pool_hash: String,
    pub source_run_id: String,
    pub source_definition_hash: String,
    pub source_authorization_id: String,
    pub source_candidate_id: String,
    pub source_model: ModelId,
    pub source_effort: EffortLevel,
    pub source_state: String,
    pub task_execution_sha256: String,
    pub ledger_hash: String,
    pub policy: EscalationPolicy,
    pub attempts: Vec<AttemptIdentity>,
    pub remaining_budget: TaskBudget,
    /// True means part of the spending bound was explicitly attested by the
    /// parent, not measured by a host or inferred from candidate estimates.
    pub uses_parent_accounting_bounds: bool,
    pub selection: PhaseSelection,
}
