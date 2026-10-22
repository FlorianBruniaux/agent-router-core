//! Durable attempt-based escalation. Audit JSON never grants execution rights.
use crate::{PendingRun, Runtime, RuntimeError, digest, store::EscalationHistory};
use router_policy::{PhaseRouter, ValidatedPhaseContext};
use router_types::*;

#[derive(Debug, thiserror::Error)]
pub enum EscalationError {
    #[error("escalation.runtime: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("escalation.policy.invalid")]
    Policy,
    #[error("escalation.attempt_evidence.missing_or_changed")]
    Evidence,
    #[error("escalation.accounting.unknown")]
    AccountingUnknown,
    #[error("escalation.budget.exhausted")]
    Budget,
    #[error("escalation.attempts.insufficient_or_not_retryable")]
    Attempts,
    #[error("escalation.target.not_admissible")]
    Target,
    #[error("escalation.approval.required_or_changed")]
    Approval,
}
type Result<T> = std::result::Result<T, EscalationError>;

#[derive(Clone, Debug)]
pub struct ReviewedAttemptBound {
    source_run_id: String,
    preview: AttemptBoundPreview,
}
impl ReviewedAttemptBound {
    pub fn preview(&self) -> &AttemptBoundPreview {
        &self.preview
    }
    pub fn approval_digest(&self) -> &str {
        &self.preview.approval_digest
    }
}
#[derive(Clone, Debug)]
pub struct EscalationProof {
    binding: EscalationDecisionBinding,
}
impl EscalationProof {
    pub fn binding(&self) -> &EscalationDecisionBinding {
        &self.binding
    }
    pub fn decision(
        &self,
        router: &PhaseRouter,
        context: &ValidatedPhaseContext,
    ) -> Result<router_execution_decision::ExecutionDecision> {
        let baseline = router.route(context).map_err(|_| EscalationError::Target)?;
        router_execution_decision::ExecutionDecision::escalated(router, context, &baseline, self)
            .map_err(|_| EscalationError::Target)
    }
}
impl router_execution_decision::EscalationAuthority for EscalationProof {
    fn escalation_binding(&self) -> &EscalationDecisionBinding {
        &self.binding
    }
}
#[derive(serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Claim {
    decision_id: String,
    target_run_id: String,
    target_definition_hash: String,
}
impl Runtime {
    /// Check the fully prepared request against durable source evidence before
    /// writing an execution bundle. This neither registers nor reserves a run;
    /// review and dispatch must still perform their existing independent checks.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_escalation_preparation(
        &self,
        router: &PhaseRouter,
        context: &ValidatedPhaseContext,
        decision: &router_execution_decision::ExecutionDecision,
        request: &ExecutionRequest,
        plan: &WorkflowPlan,
        node_id: &str,
        target_run_id: &str,
        workflow: Option<(&WorkflowExecutionContract, u32)>,
    ) -> crate::Result<()> {
        let binding = decision
            .escalation_binding()
            .ok_or(RuntimeError::Invalid("escalation decision required"))?;
        router_workflow::validate_plan(plan).map_err(|_| RuntimeError::Invalid("workflow plan"))?;
        if context.request().task != plan.task {
            return Err(RuntimeError::Route);
        }
        decision.validate_identity(router, context)?;
        let node = plan
            .nodes
            .iter()
            .find(|node| node.id == node_id)
            .ok_or(RuntimeError::Invalid("node id"))?;
        let selected = decision.selection();
        let capabilities = router
            .execution_capabilities(context, selected)
            .map_err(|_| RuntimeError::Route)?;
        crate::validate_binding(
            request,
            &selected.candidate,
            decision.baseline(),
            decision.authorization_id(),
            node,
            context,
            &capabilities,
        )?;
        let target_workflow =
            crate::workflow::validate(workflow, plan, node, request, context, selected)?;
        self.validate_escalation(router, context, decision, node, request, None, false)?;
        let source = self.summary(&binding.source_run_id)?;
        if target_run_id.is_empty()
            || target_run_id == source.run_id
            || source.plan_id != plan.plan_id
            || source.node_id != node_id
            || match (&source.workflow, target_workflow.as_ref()) {
                (None, None) => false,
                (Some(a), Some(b)) => {
                    a.instance_id != b.instance_id
                        || a.contract_sha256 != b.contract_sha256
                        || a.generation.checked_add(1) != Some(b.generation)
                }
                _ => true,
            }
        {
            return Err(RuntimeError::Invalid("escalation target identity"));
        }
        Ok(())
    }
    /// Returns only facts emitted by this runtime, with event-chain validation.
    pub fn attempt_evidence(&self, source_run_id: &str) -> Result<Vec<AttemptEvidence>> {
        let history = self.store.escalation_history(source_run_id)?;
        evidence(&history).map(|values| values.into_iter().map(|(_, value)| value).collect())
    }
    pub fn review_attempt_bound(
        &self,
        pending: &PendingRun,
        identity: &AttemptIdentity,
        upper_bound: AccountingUpperBound,
    ) -> Result<ReviewedAttemptBound> {
        self.validate_pending_retention(pending)?;
        let history = self.store.escalation_history(&pending.run.run_id)?;
        let values = evidence(&history)?;
        let (event_hash, _) = values
            .iter()
            .find(|(_, value)| value.identity == *identity)
            .ok_or(EscalationError::Evidence)?;
        if bounds(&history)?.iter().any(|b| b.identity == *identity) {
            return Err(EscalationError::Approval);
        }
        let mut preview = AttemptBoundPreview {
            schema_version: 1,
            identity: identity.clone(),
            attempt_evidence_hash: event_hash.clone(),
            ledger_hash: history.ledger_hash,
            upper_bound,
            approval_digest: String::new(),
        };
        preview.approval_digest = digest("runtime-attempt-accounting-approval-v1", &preview)?;
        Ok(ReviewedAttemptBound {
            source_run_id: pending.run.run_id.clone(),
            preview,
        })
    }
    /// A parent attestation, never relabeled as measured cost or native usage.
    pub fn approve_attempt_bound(
        &self,
        reviewed: &ReviewedAttemptBound,
        approval: &str,
    ) -> Result<()> {
        if approval != reviewed.approval_digest() {
            return Err(EscalationError::Approval);
        }
        self.store.escalation_event(
            &reviewed.source_run_id,
            &reviewed.preview.ledger_hash,
            "attempt.bound.v1",
            &serde_json::to_string(&reviewed.preview).map_err(RuntimeError::from)?,
        )?;
        Ok(())
    }
    pub fn review_escalation(
        &self,
        pending: &PendingRun,
        policy: &EscalationPolicy,
    ) -> Result<EscalationProof> {
        self.validate_pending_retention(pending)?;
        let history = self.store.escalation_history(&pending.run.run_id)?;
        let binding = build(
            &history,
            &pending.router,
            &pending.context,
            &pending.node.budget,
            policy,
            self.limits.max_attempts,
        )?;
        if binding.source_definition_hash != pending.run.definition_hash
            || binding.source_state != pending.request.source_state
            || binding.source_candidate_id != pending.request.candidate_id
        {
            return Err(EscalationError::Evidence);
        }
        Ok(EscalationProof { binding })
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_escalation(
        &self,
        router: &PhaseRouter,
        context: &ValidatedPhaseContext,
        decision: &router_execution_decision::ExecutionDecision,
        node: &WorkflowNode,
        request: &ExecutionRequest,
        target: Option<&RunSummary>,
        dispatch: bool,
    ) -> crate::Result<()> {
        let Some(binding) = decision.escalation_binding() else {
            return Ok(());
        };
        let history = self.store.escalation_history(&binding.source_run_id)?;
        let rebuilt = build(
            &history,
            router,
            context,
            &node.budget,
            &binding.policy,
            if target.is_none() {
                self.limits.max_attempts
            } else {
                u32::MAX
            },
        )
        .map_err(|_| RuntimeError::Invalid("escalation evidence changed"))?;
        let source = history.runs.last().ok_or(RuntimeError::NotFound)?;
        if rebuilt != *binding
            || request.source_state != binding.source_state
            || task_execution_hash(request)? != binding.task_execution_sha256
            || source.node_id != node.id
            || request.timeout_ms > binding.remaining_budget.max_elapsed_ms
        {
            return Err(RuntimeError::Invalid("escalation binding"));
        }
        if let Some(target) = target {
            validate_target_identity(source, target)?;
            let expected = Claim {
                decision_id: binding.decision_id.clone(),
                target_run_id: target.run_id.clone(),
                target_definition_hash: target.definition_hash.clone(),
            };
            let claims = history
                .events
                .iter()
                .filter(|e| e.kind == "escalation.claim.v1")
                .map(|e| serde_json::from_str::<Claim>(&e.detail))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if claims.len() != 1 || claims[0] != expected {
                return Err(RuntimeError::Approval);
            }
            if dispatch
                && (target.attempts != 0
                    || history.attempts.len() >= self.limits.max_attempts as usize)
            {
                return Err(RuntimeError::Limit);
            }
        }
        Ok(())
    }
    pub(crate) fn claim_escalation(&self, pending: &PendingRun) -> crate::Result<()> {
        let Some(binding) = pending.decision.escalation_binding() else {
            return Ok(());
        };
        let source = self.store.get(&binding.source_run_id)?;
        validate_target_identity(&source, &pending.run)?;
        let claim = Claim {
            decision_id: binding.decision_id.clone(),
            target_run_id: pending.run.run_id.clone(),
            target_definition_hash: pending.run.definition_hash.clone(),
        };
        self.store.escalation_event(
            &binding.source_run_id,
            &binding.ledger_hash,
            "escalation.claim.v1",
            &serde_json::to_string(&claim)?,
        )?;
        self.validate_escalation(
            &pending.router,
            &pending.context,
            &pending.decision,
            &pending.node,
            &pending.request,
            Some(&pending.run),
            false,
        )
    }
    pub(crate) fn validate_pending_escalation(
        &self,
        pending: &PendingRun,
        dispatch: bool,
    ) -> crate::Result<()> {
        self.validate_escalation(
            &pending.router,
            &pending.context,
            &pending.decision,
            &pending.node,
            &pending.request,
            Some(&self.store.get(&pending.run.run_id)?),
            dispatch,
        )
    }
}

fn policy_valid(policy: &EscalationPolicy) -> bool {
    policy.schema_version == 1
        && (2..=5).contains(&policy.minimum_failed_attempts)
        && !policy.retryable_failures.is_empty()
        && policy.retryable_failures.len() <= 4
        && policy
            .retryable_failures
            .iter()
            .all(|failure| retryable(Some(*failure)))
        && !policy.transitions.is_empty()
        && policy.transitions.len() <= 32
        && policy.transitions.iter().all(|t| {
            !t.from_candidate_id.is_empty()
                && t.from_candidate_id.len() <= 128
                && !t.to_candidate_id.is_empty()
                && t.to_candidate_id.len() <= 128
                && t.from_candidate_id != t.to_candidate_id
        })
}
fn retryable(failure: Option<RunFailure>) -> bool {
    matches!(
        failure,
        Some(RunFailure::RateLimit | RunFailure::Network | RunFailure::Timeout | RunFailure::Crash)
    )
}
pub(crate) fn evidence(history: &EscalationHistory) -> Result<Vec<(String, AttemptEvidence)>> {
    let mut values = Vec::new();
    for event in history
        .events
        .iter()
        .filter(|e| e.kind == "attempt.evidence.v1")
    {
        let value: AttemptEvidence =
            serde_json::from_str(&event.detail).map_err(|_| EscalationError::Evidence)?;
        let run = history
            .runs
            .iter()
            .find(|r| r.run_id == value.identity.run_id)
            .ok_or(EscalationError::Evidence)?;
        let find = |hash: &str, kind: &str| {
            history
                .events
                .iter()
                .find(|e| e.event_hash == hash && e.kind == kind && e.run_id == run.run_id)
        };
        let started =
            find(&value.started_event_hash, "attempt.started").ok_or(EscalationError::Evidence)?;
        let finished = find(&value.finished_event_hash, "attempt.finished")
            .ok_or(EscalationError::Evidence)?;
        let transition =
            find(&value.transition_event_hash, "transition").ok_or(EscalationError::Evidence)?;
        let attempt_index = history
            .events
            .iter()
            .filter(|e| {
                e.run_id == run.run_id
                    && e.kind == "attempt.started"
                    && e.sequence <= started.sequence
            })
            .count();
        if value.schema_version != 1
            || value.identity.attempt == 0
            || value.identity.attempt as usize != attempt_index
            || value.identity.attempt > run.attempts
            || value.definition_hash != run.definition_hash
            || value.authorization_id != run.receipt_id
            || value.workflow != run.workflow
            || event.run_id != run.run_id
            || event.state != value.state
            || transition.state != value.state
            // These events are written by attempt() and observed_attempt().
            // Hash integrity alone does not establish their producer semantics.
            || started.state != RunState::Preparing
            || !started.detail.is_empty()
            || finished.state != RunState::Running
            || finished.detail != "observed"
            || transition.detail != "transport_observed"
            || !RunState::Running.permits(transition.state)
            || history.events.iter().any(|next| {
                next.run_id == run.run_id
                    && next.kind == "attempt.started"
                    && next.sequence > started.sequence
                    && next.sequence < event.sequence
            })
            || !(started.sequence < finished.sequence
                && finished.sequence < transition.sequence
                && transition.sequence < event.sequence)
            || values
                .iter()
                .any(|(_, previous): &(String, AttemptEvidence)| {
                    previous.identity == value.identity
                })
            || !history.attempts.iter().any(|(id, attempt, status)| {
                *id == run.run_id && *attempt == value.identity.attempt && status == "observed"
            })
        {
            return Err(EscalationError::Evidence);
        }
        values.push((event.event_hash.clone(), value));
    }
    Ok(values)
}
fn bounds(history: &EscalationHistory) -> Result<Vec<AttemptBoundPreview>> {
    let mut values = Vec::new();
    for event in history
        .events
        .iter()
        .filter(|e| e.kind == "attempt.bound.v1")
    {
        let value: AttemptBoundPreview =
            serde_json::from_str(&event.detail).map_err(|_| EscalationError::Evidence)?;
        let mut unsigned = value.clone();
        unsigned.approval_digest.clear();
        if value.schema_version != 1
            || digest("runtime-attempt-accounting-approval-v1", &unsigned)? != value.approval_digest
            || values
                .iter()
                .any(|v: &AttemptBoundPreview| v.identity == value.identity)
        {
            return Err(EscalationError::Evidence);
        }
        values.push(value);
    }
    Ok(values)
}
fn build(
    history: &EscalationHistory,
    router: &PhaseRouter,
    context: &ValidatedPhaseContext,
    budget: &TaskBudget,
    policy: &EscalationPolicy,
    max_attempts: u32,
) -> Result<EscalationDecisionBinding> {
    if !policy_valid(policy) {
        return Err(EscalationError::Policy);
    }
    let values = evidence(history)?;
    if values.len() != history.attempts.len() {
        return Err(EscalationError::Evidence);
    }
    if values.len() >= max_attempts as usize {
        return Err(EscalationError::Attempts);
    }
    let source = history.runs.last().ok_or(EscalationError::Evidence)?;
    let last = values
        .last()
        .map(|(_, v)| v)
        .ok_or(EscalationError::Attempts)?;
    if !matches!(source.state, RunState::Failed | RunState::TimedOut)
        || source.worktree.is_some()
        || !retryable(source.failure)
        || source.failure != last.failure
        || source.attempts != last.identity.attempt
        || source.run_id != last.identity.run_id
    {
        return Err(EscalationError::Attempts);
    }
    if values.len() < policy.minimum_failed_attempts as usize {
        return Err(EscalationError::Attempts);
    }
    let approved_bounds = bounds(history)?;
    let mut remaining = budget.clone();
    let mut uses_parent = false;
    for (event_hash, value) in &values {
        if value.sandbox != ExecutionSandbox::ReadOnly
            || !matches!(
                value.decision_origin,
                ExecutionDecisionOrigin::Deterministic | ExecutionDecisionOrigin::Activated
            )
            || value.context_hash != context.context_hash()
            || value.pool_hash != context.pool_hash()
            || value.source_state != last.source_state
            || value.task_execution_sha256 != last.task_execution_sha256
            || !matches!(
                value.cleanup,
                ProcessCleanupEvidence::GroupTerminated
                    | ProcessCleanupEvidence::NamespaceTerminated
            )
        {
            return Err(EscalationError::Evidence);
        }
        let parent = approved_bounds
            .iter()
            .find(|b| b.identity == value.identity && b.attempt_evidence_hash == *event_hash);
        let cost = value
            .observed_cost_microusd
            .or_else(|| parent.map(|p| p.upper_bound.cost_microusd))
            .ok_or(EscalationError::AccountingUnknown)?;
        let tokens = value
            .observed_tokens
            .or_else(|| parent.map(|p| p.upper_bound.tokens))
            .ok_or(EscalationError::AccountingUnknown)?;
        uses_parent |= value.observed_cost_microusd.is_none() || value.observed_tokens.is_none();
        remaining.max_cost_microusd = remaining
            .max_cost_microusd
            .checked_sub(cost)
            .ok_or(EscalationError::Budget)?;
        remaining.max_tokens = remaining
            .max_tokens
            .checked_sub(tokens)
            .ok_or(EscalationError::Budget)?;
        remaining.max_elapsed_ms = remaining
            .max_elapsed_ms
            .checked_sub(value.transport.elapsed_ms)
            .ok_or(EscalationError::Budget)?;
    }
    // Require consecutive real failures of the same prior configuration. Earlier
    // generations still consume budget even when they do not count as failures.
    let recent = values
        .iter()
        .rev()
        .take(policy.minimum_failed_attempts as usize);
    for (_, value) in recent {
        if value.model != last.model
            || value.effort != last.effort
            || value.candidate_id != last.candidate_id
            || !matches!(value.state, RunState::Failed | RunState::TimedOut)
            || !value
                .failure
                .is_some_and(|f| policy.retryable_failures.contains(&f))
        {
            return Err(EscalationError::Attempts);
        }
    }
    let baseline = router.route(context).map_err(|_| EscalationError::Target)?;
    let selection = policy
        .transitions
        .iter()
        .filter(|t| t.from_candidate_id == last.candidate_id)
        .find_map(|t| {
            baseline
                .selected
                .iter()
                .chain(&baseline.alternatives)
                .find(|s| s.candidate.id == t.to_candidate_id)
                .filter(|s| {
                    let c = &s.candidate;
                    (c.model != last.model || c.effort != last.effort)
                        && c.estimated_cost_microusd <= remaining.max_cost_microusd
                        && c.estimated_tokens <= remaining.max_tokens
                        && c.estimated_elapsed_ms <= remaining.max_elapsed_ms
                        && router.validate_selection(context, s).is_ok()
                })
        })
        .cloned()
        .ok_or(EscalationError::Target)?;
    let mut result = EscalationDecisionBinding {
        schema_version: 1,
        decision_id: String::new(),
        baseline_receipt_id: baseline.receipt_id,
        context_hash: context.context_hash().into(),
        pool_hash: context.pool_hash().into(),
        source_run_id: source.run_id.clone(),
        source_definition_hash: source.definition_hash.clone(),
        source_authorization_id: last.authorization_id.clone(),
        source_candidate_id: last.candidate_id.clone(),
        source_model: last.model.clone(),
        source_effort: last.effort,
        source_state: last.source_state.clone(),
        task_execution_sha256: last.task_execution_sha256.clone(),
        ledger_hash: history.ledger_hash.clone(),
        policy: policy.clone(),
        attempts: values.iter().map(|(_, v)| v.identity.clone()).collect(),
        remaining_budget: remaining,
        uses_parent_accounting_bounds: uses_parent,
        selection,
    };
    result.decision_id = digest("runtime-escalation-decision-v1", &result)?;
    Ok(result)
}

pub(crate) fn task_execution_hash(request: &ExecutionRequest) -> crate::Result<String> {
    digest(
        "runtime-escalation-task-execution-v1",
        &(
            &request.workspace,
            &request.source_state,
            &request.scope,
            &request.prompt,
            request.mode,
            request.target,
            request.allow_degradation,
        ),
    )
}

fn validate_target_identity(source: &RunSummary, target: &RunSummary) -> crate::Result<()> {
    if target.plan_id != source.plan_id
        || target.artifact_contract_sha256 != source.artifact_contract_sha256
        || target.node_id != source.node_id
        || target.run_id == source.run_id
        || match (&source.workflow, &target.workflow) {
            (None, None) => false,
            (Some(a), Some(b)) => {
                a.instance_id != b.instance_id
                    || a.contract_sha256 != b.contract_sha256
                    || a.generation.checked_add(1) != Some(b.generation)
            }
            _ => true,
        }
    {
        return Err(RuntimeError::Invalid("escalation target identity"));
    }
    Ok(())
}

#[cfg(test)]
mod target_identity_tests {
    use super::*;
    #[test]
    fn escalation_never_drops_or_substitutes_the_source_artifact_contract() {
        let source = RunSummary {
            run_id: "source".into(),
            definition_hash: "source-definition".into(),
            approval_digest: "source-approval".into(),
            receipt_id: "baseline".into(),
            plan_id: "plan".into(),
            node_id: "execute".into(),
            state: RunState::Failed,
            attempts: 2,
            failure: Some(RunFailure::Crash),
            worktree: None,
            artifact_sha256: None,
            output_retention: OutputRetentionPolicy::Disabled,
            workflow: Some(WorkflowRunBinding {
                instance_id: "instance".into(),
                contract_sha256: "contract".into(),
                generation: 1,
            }),
            artifact_contract_sha256: Some("exact-source-grants".into()),
        };
        let mut target = source.clone();
        target.run_id = "target".into();
        target.workflow.as_mut().unwrap().generation = 2;
        assert!(validate_target_identity(&source, &target).is_ok());
        target.artifact_contract_sha256 = None;
        assert!(validate_target_identity(&source, &target).is_err());
        target.artifact_contract_sha256 = Some("different-grant-same-prompt".into());
        assert!(validate_target_identity(&source, &target).is_err());
        target.artifact_contract_sha256 = source.artifact_contract_sha256.clone();
        assert!(validate_target_identity(&source, &target).is_ok());
    }
}

#[cfg(test)]
mod retryable_tests {
    use super::*;

    #[test]
    fn unclassified_and_verification_failures_are_never_retryable() {
        assert!(!retryable(Some(RunFailure::Unclassified)));
        assert!(!retryable(Some(RunFailure::Verification)));
        assert!(retryable(Some(RunFailure::Crash)));
    }
}
