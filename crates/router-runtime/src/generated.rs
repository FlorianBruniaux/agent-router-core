//! Global-plan authority remains immutable for the entire workflow instance.
use crate::{PendingRun, Result, Runtime, RuntimeError, now};
use router_execution_decision::ExecutionDecision;
use router_types::{ExecutionRequest, WorkflowExecutionContract, WorkflowPlan};

pub(crate) fn validate(
    decision: &ExecutionDecision,
    plan: &WorkflowPlan,
    node_id: &str,
    request: &ExecutionRequest,
    contract: Option<&WorkflowExecutionContract>,
    current: bool,
) -> Result<()> {
    let Some(proof) = decision.generated_plan() else {
        return Ok(());
    };
    let binding = decision.generated_binding().ok_or(RuntimeError::Route)?;
    if binding.node_id != node_id {
        return Err(RuntimeError::Route);
    }
    proof
        .validate_workflow(
            plan,
            contract.ok_or(RuntimeError::Invalid(
                "generated plan requires workflow instance",
            ))?,
        )
        .map_err(|_| RuntimeError::Route)?;
    // Historical reopening retains original identity without granting dispatch.
    proof
        .validate_execution(
            node_id,
            request,
            if current {
                now()?
            } else {
                proof.planned_at_unix_seconds()
            },
        )
        .map_err(|_| RuntimeError::Route)
}
impl Runtime {
    pub(crate) fn validate_pending_generated(
        &self,
        pending: &PendingRun,
        current: bool,
    ) -> Result<()> {
        validate(
            &pending.decision,
            &pending.plan,
            &pending.node.id,
            &pending.request,
            pending.workflow.as_ref(),
            current,
        )?;
        self.store.verify_plan_pin(
            pending.run.workflow.as_ref(),
            pending.decision.generated_binding(),
        )
    }
}
