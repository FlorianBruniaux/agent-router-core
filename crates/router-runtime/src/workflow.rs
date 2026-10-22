use crate::{Cancellation, PendingRun, Result, Runtime, RuntimeError};
use router_policy::ValidatedPhaseContext;
use router_types::*;

pub(crate) fn validate(
    workflow: Option<(&WorkflowExecutionContract, u32)>,
    plan: &WorkflowPlan,
    node: &WorkflowNode,
    request: &ExecutionRequest,
    context: &ValidatedPhaseContext,
    selected: &PhaseSelection,
) -> Result<Option<WorkflowRunBinding>> {
    if node.independent_verifier
        && (request.phase != StageKind::Verify
            || selected.candidate.verification != PhaseVerification::Independent)
    {
        return Err(RuntimeError::Verification);
    }
    let Some((contract, generation)) = workflow else {
        if !node.dependencies.is_empty() {
            return Err(RuntimeError::Invalid(
                "dependencies require an execution instance",
            ));
        }
        return Ok(None);
    };
    router_workflow::validate_execution_contract(contract, plan)
        .map_err(|_| RuntimeError::Invalid("execution contract"))?;
    if generation >= 5
        || contract.workspace != request.workspace
        || contract.source_state != request.source_state
        || contract.nodes[&node.id].phase != request.phase
        || context.request().phase != request.phase
    {
        return Err(RuntimeError::Invalid("execution instance binding"));
    }
    Ok(Some(WorkflowRunBinding {
        instance_id: contract.instance_id.clone(),
        contract_sha256: contract.contract_sha256.clone(),
        generation,
    }))
}

impl Runtime {
    /// Checks only this instance's persisted dependency generations. No execution authority is added.
    pub fn dependencies_ready(&self, pending: &PendingRun) -> Result<bool> {
        self.validate_pending_retention(pending)?;
        let Some(contract) = &pending.workflow else {
            return Ok(true);
        };
        let dependencies = &contract.nodes[&pending.node.id].dependencies;
        let mut ready = true;
        for (dependency, requirement) in dependencies {
            let Some((run, model, agent)) = self
                .store
                .workflow_node(&contract.instance_id, dependency)?
            else {
                ready = false;
                continue;
            };
            if run
                .workflow
                .as_ref()
                .is_none_or(|w| w.contract_sha256 != contract.contract_sha256)
            {
                return Err(RuntimeError::Integrity("dependency contract changed"));
            }
            if pending.node.independent_verifier
                && (pending.context.request().previous_model.as_ref() != Some(&model)
                    || pending.request.model == model
                    || (agent.is_some() && agent == pending.request.agent))
            {
                return Err(RuntimeError::Verification);
            }
            ready &= match requirement {
                DependencyRequirement::Verified => run.state == RunState::Verified,
                DependencyRequirement::ArtifactReadyForVerification => {
                    matches!(run.state, RunState::Verifying | RunState::Verified)
                        && match &run.artifact_sha256 {
                            Some(hash) => {
                                crate::workspace::read_artifact(
                                    &self.store.root,
                                    &run.run_id,
                                    hash,
                                )?;
                                true
                            }
                            None => false,
                        }
                }
            };
        }
        Ok(ready)
    }
    /// A queued dependency wait holds no capacity permits and stays resumable.
    pub(crate) async fn wait_dependencies(
        &self,
        pending: &PendingRun,
        cancel: &Cancellation,
    ) -> Result<()> {
        if pending.workflow.is_none() {
            return Ok(());
        }
        let mut announced = false;
        loop {
            if cancel.is_cancelled() || self.store.cancel_requested(&pending.run.run_id)? {
                self.store.transition_queued(
                    &pending.run.run_id,
                    RunState::Cancelled,
                    "cancelled_while_waiting_dependencies",
                    None,
                )?;
                return Err(RuntimeError::Cancelled);
            }
            if self.dependencies_ready(pending)? {
                return Ok(());
            }
            if !announced {
                self.store
                    .event(&pending.run.run_id, "queued", "dependencies")?;
                announced = true;
            }
            tokio::select! { _ = cancel.cancelled() => {}, _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {} }
        }
    }
}
