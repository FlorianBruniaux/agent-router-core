#![forbid(unsafe_code)]
//! Durable per-step orchestration. Model results are untrusted proposals, and
//! every step needs an approval bound to its final prompt and artifact inputs.
mod definition;
mod store;
pub use definition::{
    ValidatedDefinition, seal_definition, validate_definition, validations_on_this_thread,
};
use router_adapter_api::HarnessAdapter;
use router_execution_decision::{ActivationAuthority, ExecutionDecision};
use router_policy::{PhaseRouter, ValidatedPhaseContext, ValidatedPhaseReceipt};
use router_runtime::{ApprovedRun, Cancellation, PendingRun, Runtime, SandboxSupervisor};
use router_types::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    future::{Future, poll_fn},
    path::Path,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
};
pub use store::{observe, request_approval, request_cancel, request_verification};

#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    #[error("coordinator.invalid: {0}")]
    Invalid(&'static str),
    #[error("coordinator.integrity")]
    Integrity,
    #[error("coordinator.limit")]
    Limit,
    #[error("coordinator.locked")]
    Locked,
    #[error("coordinator.dependencies.pending")]
    DependenciesPending,
    #[error("coordinator.cancelled")]
    Cancelled,
    #[error("coordinator.runtime: {0}")]
    Runtime(#[from] router_runtime::RuntimeError),
    #[error("coordinator.workflow: {0}")]
    Workflow(#[from] router_workflow::WorkflowError),
    #[error("coordinator.storage")]
    Storage(#[from] rusqlite::Error),
    #[error("coordinator.io")]
    Io(#[from] std::io::Error),
    #[error("coordinator.json")]
    Json(#[from] serde_json::Error),
}
pub type Result<T> = std::result::Result<T, CoordinatorError>;
fn hash<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(serde_json::to_vec(value)?);
    Ok(hex::encode(hash.finalize()))
}
const MAX_MATERIALS: usize = 320;
pub struct Coordinator {
    store: store::Store,
    runtime: Arc<Runtime>,
    materials: Mutex<std::collections::BTreeMap<String, PendingStep>>,
    material_limit: usize,
    review_admission: tokio::sync::Mutex<()>,
}
/// Contains confidential request text, intentionally not serializable or Debug.
#[derive(Clone)]
pub struct PendingStep {
    pending: PendingRun,
    definition_sha256: String,
    node: String,
    generation: u32,
    request: ExecutionRequest,
    artifacts: RunArtifactContract,
}
impl PendingStep {
    pub fn decision(&self) -> &ExecutionDecision {
        self.pending.decision()
    }
    pub fn summary(&self) -> &RunSummary {
        self.pending.summary()
    }
    pub fn approval_digest(&self) -> &str {
        self.pending.approval_digest()
    }
    pub fn final_request(&self) -> &ExecutionRequest {
        &self.request
    }
    pub fn artifact_contract(&self) -> &RunArtifactContract {
        &self.artifacts
    }
}
pub struct ApprovedStep {
    pending: PendingStep,
    approved: ApprovedRun,
}
pub struct StepExecution<'a> {
    pub step: ApprovedStep,
    pub adapter: &'a dyn HarnessAdapter,
    pub supervisor: &'a dyn SandboxSupervisor,
}
/// Each activated decision supplies the current store authority at dispatch.
pub struct DecisionStepExecution<'a> {
    pub execution: StepExecution<'a>,
    pub authority: Option<&'a dyn ActivationAuthority>,
}
impl Coordinator {
    pub fn open(root: &Path, runtime: Arc<Runtime>) -> Result<Self> {
        Ok(Self {
            store: store::Store::open(root)?,
            runtime,
            materials: Mutex::new(std::collections::BTreeMap::new()),
            material_limit: MAX_MATERIALS,
            review_admission: tokio::sync::Mutex::new(()),
        })
    }
    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }
    /// Lowers the number of confidential step materials held in memory. The
    /// built-in bound of 320 cannot be raised.
    pub fn with_material_limit(mut self, limit: usize) -> Self {
        self.material_limit = limit.min(MAX_MATERIALS);
        self
    }
    /// Refuses a new step before any runtime or store side effect when its
    /// material could not be retained. Terminal steps release their material.
    fn reserve_material(&self, run_id: &str) -> Result<()> {
        let mut materials = self
            .materials
            .lock()
            .map_err(|_| CoordinatorError::Integrity)?;
        if materials.len() >= self.material_limit && !materials.contains_key(run_id) {
            materials.retain(|id, _| self.runtime.summary(id).is_ok_and(|s| !s.state.terminal()));
            if materials.len() >= self.material_limit {
                return Err(CoordinatorError::Limit);
            }
        }
        Ok(())
    }
    /// Number of confidential step materials currently retained in memory.
    pub fn retained_materials(&self) -> usize {
        self.materials.lock().map_or(0, |m| m.len())
    }
    fn release_if_terminal(&self, run: &RunSummary) {
        if run.state.terminal() {
            if let Ok(mut materials) = self.materials.lock() {
                materials.remove(&run.run_id);
            }
        }
    }
    pub fn register(&self, definition: &WorkflowDefinition) -> Result<()> {
        validate_definition(definition)?;
        self.store.register(definition, self.runtime.storage_root())
    }
    pub fn status(&self, definition: &WorkflowDefinition) -> Result<WorkflowStatus> {
        observe(&self.store.root, definition)
    }
    fn check(&self, definition: &WorkflowDefinition) -> Result<()> {
        self.check_validated(validate_definition(definition)?)
    }
    fn check_validated(&self, definition: ValidatedDefinition<'_>) -> Result<()> {
        if self.store.check(&definition)? {
            return Err(CoordinatorError::Cancelled);
        }
        if definition.failure_policy == WorkflowFailurePolicy::FailFast
            && self.status(&definition)?.nodes.iter().any(|n| {
                n.state
                    .is_some_and(|s| s.terminal() && s != RunState::Verified)
            })
        {
            return Err(CoordinatorError::Cancelled);
        }
        Ok(())
    }
    pub fn inputs(
        &self,
        definition: &WorkflowDefinition,
        node: &str,
    ) -> Result<RunArtifactContract> {
        self.check(definition)?;
        let execution = definition
            .execution
            .nodes
            .get(node)
            .ok_or(CoordinatorError::Invalid("node"))?;
        let declaration = &definition.artifacts[node];
        let steps = self.store.steps(&definition.execution.instance_id)?;
        let mut inputs = Vec::new();
        for (producer, requirement) in &execution.dependencies {
            let (_, _, run_id) = steps
                .iter()
                .filter(|(n, _, _)| n == producer)
                .max_by_key(|(_, g, _)| g)
                .ok_or(CoordinatorError::DependenciesPending)?;
            let run = self.runtime.summary(run_id)?;
            let ready = match requirement {
                DependencyRequirement::Verified => run.state == RunState::Verified,
                DependencyRequirement::ArtifactReadyForVerification => {
                    matches!(run.state, RunState::Verifying | RunState::Verified)
                        && run.artifact_sha256.is_some()
                }
            };
            if !ready {
                return Err(CoordinatorError::DependenciesPending);
            }
        }
        let mut bytes = 0_usize;
        for edge in &declaration.inputs {
            let (_, generation, run_id) = steps
                .iter()
                .filter(|(n, _, _)| n == &edge.producer)
                .max_by_key(|(_, g, _)| g)
                .ok_or(CoordinatorError::DependenciesPending)?;
            let run = self.runtime.summary(run_id)?;
            let artifact = self
                .runtime
                .declared_artifacts(run_id)?
                .into_iter()
                .find(|a| a.attempt == run.attempts && a.label == edge.label)
                .ok_or(CoordinatorError::DependenciesPending)?;
            if artifact.state != DeclaredArtifactState::Retained
                || artifact.workflow.generation != *generation
                || artifact.workflow_definition_sha256 != definition.definition_sha256
            {
                return Err(CoordinatorError::Integrity);
            }
            bytes = bytes
                .checked_add(artifact.bytes)
                .ok_or(CoordinatorError::Limit)?;
            if bytes > definition.max_input_bytes {
                return Err(CoordinatorError::Limit);
            }
            self.runtime.read_declared_artifact(&artifact.artifact_id)?;
            inputs.push(ArtifactGrant {
                artifact_id: artifact.artifact_id,
                workflow: artifact.workflow,
                node_id: artifact.node_id,
                run_id: artifact.run_id,
                label: artifact.label,
                sha256: artifact.sha256,
                bytes: artifact.bytes,
                exposure: edge.exposure,
            });
        }
        Ok(RunArtifactContract {
            schema_version: 1,
            workflow_definition_sha256: definition.definition_sha256.clone(),
            outputs: declaration.outputs.clone(),
            inputs,
            max_input_bytes: definition.max_input_bytes,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn review_step(
        &self,
        definition: &WorkflowDefinition,
        node: &str,
        generation: u32,
        router: &PhaseRouter,
        context: &ValidatedPhaseContext,
        selection: &ValidatedPhaseReceipt,
        request: ExecutionRequest,
    ) -> Result<PendingStep> {
        let decision = ExecutionDecision::deterministic(router, context, selection)
            .map_err(router_runtime::RuntimeError::from)?;
        self.review_step_decision(
            definition, node, generation, router, context, &decision, request,
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn review_step_decision(
        &self,
        definition: &WorkflowDefinition,
        node: &str,
        generation: u32,
        router: &PhaseRouter,
        context: &ValidatedPhaseContext,
        decision: &ExecutionDecision,
        mut request: ExecutionRequest,
    ) -> Result<PendingStep> {
        let _admission = self.review_admission.lock().await;
        let artifacts = self.inputs(definition, node)?;
        request
            .prompt
            .push_str(&self.runtime.render_dependency_context(&artifacts)?);
        router_prepare::validate_prepared_input(
            router,
            context,
            &request,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| CoordinatorError::Invalid("clock"))?
                .as_secs(),
        )
        .map_err(|_| CoordinatorError::Invalid("final input assets"))?;
        let run_id = run_id(definition, node, generation)?;
        self.reserve_material(&run_id)?;
        if let Some(binding) = decision.escalation_binding() {
            let source = self.runtime.summary(&binding.source_run_id)?;
            if source.artifact_contract_sha256.as_deref()
                != Some(hash("runtime-artifact-contract-v1", &artifacts)?.as_str())
            {
                return Err(CoordinatorError::Integrity);
            }
            self.runtime.validate_escalation_preparation(
                router,
                context,
                decision,
                &request,
                &definition.plan,
                node,
                &run_id,
                Some((&definition.execution, generation)),
            )?;
        }
        let candidate = &decision.selection().candidate;
        // The exclusive coordinator owner serializes step registrations. Refuse
        // cumulative limits before the runtime reserves an escalation claim.
        self.store.check_budget(
            definition,
            node,
            generation,
            candidate.estimated_cost_microusd,
            candidate.estimated_tokens,
        )?;
        let pending = self
            .runtime
            .review_decision(
                &run_id,
                router,
                context,
                decision,
                request.clone(),
                definition.plan.clone(),
                node,
                Some((&definition.execution, generation)),
                Some(&artifacts),
            )
            .await?;
        let candidate = &decision.selection().candidate;
        self.store.bind_step(
            definition,
            node,
            generation,
            pending.summary(),
            candidate.estimated_cost_microusd,
            candidate.estimated_tokens,
        )?;
        let step = PendingStep {
            pending,
            definition_sha256: definition.definition_sha256.clone(),
            node: node.into(),
            generation,
            request,
            artifacts,
        };
        let mut materials = self
            .materials
            .lock()
            .map_err(|_| CoordinatorError::Integrity)?;
        if materials.len() >= self.material_limit && !materials.contains_key(&step.summary().run_id)
        {
            return Err(CoordinatorError::Limit);
        }
        materials.insert(step.summary().run_id.clone(), step.clone());
        Ok(step)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn reopen_step(
        &self,
        definition: &WorkflowDefinition,
        node: &str,
        generation: u32,
        router: &PhaseRouter,
        context: &ValidatedPhaseContext,
        selection: &ValidatedPhaseReceipt,
        request: ExecutionRequest,
        artifacts: RunArtifactContract,
    ) -> Result<PendingStep> {
        let decision = ExecutionDecision::deterministic(router, context, selection)
            .map_err(router_runtime::RuntimeError::from)?;
        self.reopen_step_decision(
            definition, node, generation, router, context, &decision, request, artifacts,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn reopen_step_decision(
        &self,
        definition: &WorkflowDefinition,
        node: &str,
        generation: u32,
        router: &PhaseRouter,
        context: &ValidatedPhaseContext,
        decision: &ExecutionDecision,
        request: ExecutionRequest,
        artifacts: RunArtifactContract,
    ) -> Result<PendingStep> {
        self.reserve_material(&run_id(definition, node, generation)?)?;
        let pending = reopen_recorded_step(
            &self.store.root,
            &self.runtime,
            definition,
            node,
            generation,
            router,
            context,
            decision,
            request.clone(),
            artifacts.clone(),
        )?;
        let step = PendingStep {
            pending,
            definition_sha256: definition.definition_sha256.clone(),
            node: node.into(),
            generation,
            request,
            artifacts,
        };
        let mut materials = self
            .materials
            .lock()
            .map_err(|_| CoordinatorError::Integrity)?;
        if materials.len() >= self.material_limit && !materials.contains_key(&step.summary().run_id)
        {
            return Err(CoordinatorError::Limit);
        }
        materials.insert(step.summary().run_id.clone(), step.clone());
        Ok(step)
    }
    pub fn approve_step(
        &self,
        definition: &WorkflowDefinition,
        pending: PendingStep,
        digest: &str,
    ) -> Result<ApprovedStep> {
        self.check_step(definition, &pending)?;
        let state = self.runtime.summary(&pending.summary().run_id)?.state;
        let approved = if state == RunState::Queued {
            self.runtime
                .resume_approved(pending.pending.clone(), digest)?
        } else {
            self.runtime.approve(pending.pending.clone(), digest)?
        };
        self.store
            .event(&definition.execution.instance_id, "step.approved", digest)?;
        Ok(ApprovedStep { pending, approved })
    }
    fn check_step(&self, definition: &WorkflowDefinition, pending: &PendingStep) -> Result<()> {
        self.check_step_validated(validate_definition(definition)?, pending)
    }
    fn check_step_validated(
        &self,
        definition: ValidatedDefinition<'_>,
        pending: &PendingStep,
    ) -> Result<()> {
        self.check_validated(definition)?;
        if definition.definition_sha256 != pending.definition_sha256
            || run_id(&definition, &pending.node, pending.generation)? != pending.summary().run_id
        {
            return Err(CoordinatorError::Integrity);
        }
        Ok(())
    }
    pub fn verify_step(
        &self,
        definition: &WorkflowDefinition,
        pending: &PendingStep,
        record: VerificationRecord,
    ) -> Result<RunSummary> {
        validate_definition(definition)?;
        self.store.check(definition)?;
        if pending.definition_sha256 != definition.definition_sha256 {
            return Err(CoordinatorError::Integrity);
        }
        let run = self.runtime.summary(&pending.summary().run_id)?;
        let outputs = self.runtime.declared_artifacts(&run.run_id)?;
        for declaration in &pending.artifacts.outputs {
            let artifact = outputs
                .iter()
                .find(|a| {
                    a.attempt == run.attempts
                        && a.label == declaration.label
                        && a.state == DeclaredArtifactState::Retained
                })
                .ok_or(CoordinatorError::DependenciesPending)?;
            self.runtime.read_declared_artifact(&artifact.artifact_id)?;
        }
        let run = self.runtime.record_verification(&pending.pending, record)?;
        self.release_if_terminal(&run);
        self.store.event(
            &definition.execution.instance_id,
            "step.verification",
            &hash("coordinator-verification-v1", &(&run.run_id, run.state))?,
        )?;
        Ok(run)
    }
    /// Processes approval/verification requests from another CLI while this
    /// owner is supervising workers. Missing confidential material stays queued
    /// until the caller reconstructs that exact step after a restart.
    pub fn service_controls(&self, definition: &WorkflowDefinition) -> Result<usize> {
        self.service_controls_validated(validate_definition(definition)?)
    }
    fn service_controls_validated(&self, definition: ValidatedDefinition<'_>) -> Result<usize> {
        self.store.check(&definition)?;
        let mut applied = 0;
        for (id, run, control) in self.store.controls(&definition.execution.instance_id)? {
            let pending = self
                .materials
                .lock()
                .map_err(|_| CoordinatorError::Integrity)?
                .get(&run)
                .cloned();
            let Some(pending) = pending else {
                // Material is released once a step is terminal; nothing can
                // apply this control any more, so settle it instead of leaving
                // it pending forever. A run that cannot be read is skipped, as
                // before, and never blocks the other controls.
                if self
                    .runtime
                    .summary(&run)
                    .is_ok_and(|current| current.state.terminal())
                {
                    let settled = match &control {
                        store::Control::Approve { .. } => self.approval_applied(&run).ok(),
                        store::Control::Verify { record, .. } => self
                            .runtime
                            .verification_record(&run)
                            .ok()
                            .map(|recorded| recorded.as_ref() == Some(record)),
                    };
                    if let Some(settled) = settled {
                        self.store.finish_control(
                            &definition.execution.instance_id,
                            &id,
                            settled,
                        )?;
                        applied += usize::from(settled);
                    }
                }
                continue;
            };
            let current = self.runtime.summary(&run)?;
            let digest = match &control {
                store::Control::Approve { digest } | store::Control::Verify { digest, .. } => {
                    digest
                }
            };
            let outcome = if current.approval_digest != *digest {
                Err(CoordinatorError::Integrity)
            } else {
                match control {
                    store::Control::Approve { digest } => {
                        // A crash between approve_step and finish_control leaves
                        // the control pending while the run moved past approval.
                        // That approval was applied; it must not be recorded as
                        // rejected.
                        if !matches!(current.state, RunState::AwaitingApproval | RunState::Queued)
                            && self.approval_applied(&run)?
                        {
                            Ok(())
                        } else {
                            self.approve_step(&definition, pending, &digest).map(|_| ())
                        }
                    }
                    store::Control::Verify { record, .. } => {
                        if self.runtime.verification_record(&run)?.as_ref() == Some(&record) {
                            Ok(())
                        } else {
                            self.verify_step(&definition, &pending, record).map(|_| ())
                        }
                    }
                }
            };
            self.store
                .finish_control(&definition.execution.instance_id, &id, outcome.is_ok())?;
            if outcome.is_ok() {
                applied += 1;
            }
        }
        Ok(applied)
    }
    fn approval_applied(&self, run_id: &str) -> Result<bool> {
        Ok(self
            .runtime
            .has_event(run_id, "transition", "explicit_approval")?)
    }
    pub async fn review_publication(
        &self,
        pending: &PendingStep,
    ) -> Result<PatchPublicationReview> {
        Ok(self.runtime.review_publication(&pending.pending).await?)
    }
    pub async fn validate_publication_review(
        &self,
        pending: &PendingStep,
        review: &PatchPublicationReview,
    ) -> Result<()> {
        Ok(self
            .runtime
            .validate_publication_review(&pending.pending, review)
            .await?)
    }
    pub async fn publish_patch(
        &self,
        pending: &PendingStep,
        approval: &str,
    ) -> Result<PatchPublicationReceipt> {
        Ok(self
            .runtime
            .publish_patch(&pending.pending, approval)
            .await?)
    }
    pub async fn publication_status(
        &self,
        pending: &PendingStep,
    ) -> Result<PatchPublicationStatus> {
        Ok(self.runtime.publication_status(&pending.pending).await?)
    }
    pub async fn integration_preview(&self, pending: &PendingStep) -> Result<IntegrationPreview> {
        Ok(self.runtime.integration_preview(&pending.pending).await?)
    }
    pub async fn apply(&self, pending: &PendingStep, approval: &str) -> Result<IntegrationPreview> {
        Ok(self.runtime.apply(&pending.pending, approval).await?)
    }
    pub async fn discard(&self, pending: &PendingStep, approval: &str) -> Result<()> {
        Ok(self.runtime.discard(&pending.pending, approval).await?)
    }
    /// Runs an explicitly approved wave. Later waves require fresh final inputs
    /// and their own approvals; no model-produced plan grants execution rights.
    pub async fn run_ready<'a>(
        &'a self,
        definition: &WorkflowDefinition,
        jobs: Vec<StepExecution<'a>>,
    ) -> Result<WaveCompletion> {
        self.run_ready_decisions(
            definition,
            jobs.into_iter()
                .map(|execution| DecisionStepExecution {
                    execution,
                    authority: None,
                })
                .collect(),
        )
        .await
    }
    pub async fn run_ready_decisions<'a>(
        &'a self,
        definition: &WorkflowDefinition,
        jobs: Vec<DecisionStepExecution<'a>>,
    ) -> Result<WaveCompletion> {
        // Validated once per wave: the borrow keeps the definition unchanged
        // and every tick still compares the stored hash through the store.
        let validated = validate_definition(definition)?;
        self.check_validated(validated)?;
        if jobs.len() > 64 {
            return Err(CoordinatorError::Limit);
        }
        let mut unique = BTreeSet::new();
        for job in &jobs {
            self.check_step_validated(validated, &job.execution.step.pending)?;
            if !unique.insert(job.execution.step.pending.summary().run_id.clone()) {
                return Err(CoordinatorError::Invalid("duplicate step"));
            }
            if !self
                .runtime
                .dependencies_ready(&job.execution.step.pending.pending)?
            {
                return Err(CoordinatorError::DependenciesPending);
            }
        }
        let mut queued = jobs.into_iter();
        type Active<'a> = Pin<
            Box<
                dyn Future<
                        Output = (
                            String,
                            std::result::Result<RunCompletion, router_runtime::RuntimeError>,
                        ),
                    > + 'a,
            >,
        >;
        let mut active: Vec<Active<'a>> = Vec::new();
        let mut results = Vec::new();
        let cancel = Cancellation::default();
        let mut errors = Vec::new();
        let mut stopped = false;
        loop {
            if stopped {
                for job in queued.by_ref() {
                    errors.push(StepExecutionError {
                        run_id: job.execution.step.pending.summary().run_id.clone(),
                        code: StepExecutionErrorCode::Cancelled,
                    });
                }
            }
            if !stopped {
                while active.len() < definition.plan.max_width {
                    let Some(job) = queued.next() else {
                        break;
                    };
                    let token = cancel.clone();
                    let runtime = &self.runtime;
                    let id = job.execution.step.pending.summary().run_id.clone();
                    active.push(Box::pin(async move {
                        (
                            id,
                            runtime
                                .execute_decision(
                                    job.execution.step.approved,
                                    job.execution.adapter,
                                    job.execution.supervisor,
                                    token,
                                    job.authority,
                                )
                                .await,
                        )
                    }));
                }
            }
            if active.is_empty() {
                break;
            }
            let completed = tokio::select! {result=poll_fn(|cx|{for (index,future) in active.iter_mut().enumerate(){if let Poll::Ready(result)=future.as_mut().poll(cx){return Poll::Ready((index,result));}}Poll::Pending})=>Some(result),_=tokio::time::sleep(std::time::Duration::from_millis(20))=>None};
            self.service_controls_validated(validated)?;
            if self.store.check(definition)? && !stopped {
                stopped = true;
                cancel.cancel();
                self.cancel_registered(definition)?;
            }
            if let Some((index, (run_id, result))) = completed {
                drop(active.swap_remove(index));
                match result {
                    Ok(completion) => {
                        self.release_if_terminal(&completion.run);
                        let failed = completion.run.state.terminal()
                            && completion.run.state != RunState::Verified;
                        results.push(completion);
                        if failed
                            && definition.failure_policy == WorkflowFailurePolicy::FailFast
                            && !stopped
                        {
                            stopped = true;
                            cancel.cancel();
                            self.cancel_registered(definition)?;
                        }
                    }
                    Err(error) => {
                        errors.push(StepExecutionError {
                            run_id,
                            code: error_code(&error),
                        });
                        if definition.failure_policy == WorkflowFailurePolicy::FailFast && !stopped
                        {
                            stopped = true;
                            cancel.cancel();
                            self.cancel_registered(definition)?;
                        }
                    }
                }
            }
        }
        results.sort_by(|left, right| left.run.run_id.cmp(&right.run.run_id));
        errors.sort_by(|left, right| left.run_id.cmp(&right.run_id));
        Ok(WaveCompletion {
            completions: results,
            errors,
            cancelled: stopped,
        })
    }
    fn cancel_registered(&self, definition: &WorkflowDefinition) -> Result<()> {
        for (_, _, id) in self.store.steps(&definition.execution.instance_id)? {
            let state = self.runtime.summary(&id)?.state;
            if matches!(
                state,
                RunState::Planned
                    | RunState::AwaitingApproval
                    | RunState::Queued
                    | RunState::Preparing
                    | RunState::Running
            ) {
                match router_runtime::request_cancel(self.runtime.storage_root(), &id) {
                    Ok(()) | Err(router_runtime::RuntimeError::Transition) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(())
    }
}
/// Reconstruct confidential material for a registered historical step without
/// acquiring another coordinator or runtime ownership lock. This grants no
/// approval and never substitutes a JSON receipt for the execution decision.
#[allow(clippy::too_many_arguments)]
pub fn reopen_recorded_step(
    root: &Path,
    runtime: &Runtime,
    definition: &WorkflowDefinition,
    node: &str,
    generation: u32,
    router: &PhaseRouter,
    context: &ValidatedPhaseContext,
    decision: &ExecutionDecision,
    request: ExecutionRequest,
    artifacts: RunArtifactContract,
) -> Result<PendingRun> {
    validate_definition(definition)?;
    if artifacts.workflow_definition_sha256 != definition.definition_sha256
        || artifacts.outputs
            != definition
                .artifacts
                .get(node)
                .ok_or(CoordinatorError::Invalid("node"))?
                .outputs
    {
        return Err(CoordinatorError::Integrity);
    }
    let id = run_id(definition, node, generation)?;
    let pending = runtime.reopen_decision(
        &id,
        router,
        context,
        decision,
        request,
        definition.plan.clone(),
        node,
        Some((&definition.execution, generation)),
        Some(&artifacts),
    )?;
    store::check_recorded(
        root,
        definition,
        runtime.storage_root(),
        node,
        generation,
        pending.summary(),
    )?;
    Ok(pending)
}

fn run_id(definition: &WorkflowDefinition, node: &str, generation: u32) -> Result<String> {
    if !definition.execution.nodes.contains_key(node) || generation >= 5 {
        return Err(CoordinatorError::Invalid("step identity"));
    }
    Ok(format!(
        "wf-{}",
        hash(
            "coordinator-run-id-v1",
            &(&definition.definition_sha256, node, generation)
        )?
    ))
}

fn error_code(error: &router_runtime::RuntimeError) -> StepExecutionErrorCode {
    use router_runtime::RuntimeError::*;
    match error {
        Cancelled => StepExecutionErrorCode::Cancelled,
        DependenciesPending => StepExecutionErrorCode::DependenciesPending,
        Limit => StepExecutionErrorCode::Limit,
        Integrity(_) | Json(_) | Storage(_) => StepExecutionErrorCode::Integrity,
        Approval
        | SourceChanged
        | Scope
        | Sandbox
        | ResourceUnsupported(_)
        | Route
        | Adapter(_)
        | Verification
        | Invalid(_) => StepExecutionErrorCode::PreparationDenied,
        _ => StepExecutionErrorCode::ExecutionFailed,
    }
}
