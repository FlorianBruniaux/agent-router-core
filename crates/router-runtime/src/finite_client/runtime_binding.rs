//! Durable review binding only. No backend, process or provider authority.
use super::*;
use crate::{ApprovedRun, PendingRun, Runtime};
use router_adapter_api::{
    authorize_execution_with_capability_acceptance,
    execution_authorization_digest_with_capability_acceptance,
};
use router_execution_decision::ExecutionDecision;
use router_policy::{PhaseRouter, ValidatedPhaseContext};
use router_types::{ExecutionRequest, RunState, RunSummary, WorkflowPlan};

/// Owns both reviews without exposing a clonable generic runtime entrance.
/// ```compile_fail
/// use router_runtime::{Runtime, PendingFiniteClientRun};
/// fn bypass(runtime: &Runtime, pending: PendingFiniteClientRun) {
///     runtime.approve(pending, "digest");
/// }
/// ```
pub struct PendingFiniteClientRun {
    pending: PendingRun,
    client: FiniteClientReview,
}
/// The runtime persisted the combined approval. Fresh OS evidence and a
/// dedicated backend are still required; this handle cannot produce a Command.
/// ```compile_fail
/// use router_runtime::{Runtime, ApprovedFiniteClientRun, SandboxSupervisor, Cancellation};
/// use router_adapter_api::HarnessAdapter;
/// async fn bypass(runtime: &Runtime, approved: ApprovedFiniteClientRun,
///                 adapter: &dyn HarnessAdapter, sandbox: &dyn SandboxSupervisor) {
///     runtime.execute(approved, adapter, sandbox, Cancellation::default()).await;
/// }
/// ```
pub struct ApprovedFiniteClientRun {
    pub(super) approved: ApprovedRun,
    pub(super) client: ApprovedFiniteClient,
}
impl PendingFiniteClientRun {
    pub fn summary(&self) -> &RunSummary {
        self.pending.summary()
    }
    pub fn approval_digest(&self) -> &str {
        self.pending.approval_digest()
    }
}
impl ApprovedFiniteClientRun {
    pub fn summary(&self) -> &RunSummary {
        self.approved.summary()
    }
    pub fn proof_binding(&self) -> Result<CapabilityProofBinding> {
        self.client
            .proof_binding(&self.client.reviewed.manifest.host_snapshot_id)
    }
}
pub(crate) fn bind_runtime_definition(base: &str, client: Option<&str>) -> Result<String> {
    match client {
        Some(client) => crate::digest("runtime-finite-client-definition-v1", &(base, client)),
        None => Ok(base.into()), // Existing approvals keep their exact definition.
    }
}
impl Runtime {
    pub(super) fn check_finite_review(
        &self,
        id: &str,
        context: &ValidatedPhaseContext,
        request: &ExecutionRequest,
        client: &FiniteClientReview,
    ) -> Result<()> {
        let tools = client.owned_tools.is_some();
        // A prepared remote profile alone cannot borrow fixture quota/accounting.
        client.provider_identity()?;
        let startup_tools = client
            .owned_state
            .as_ref()
            .is_some_and(|state| state.startup.tools);
        let selected_tools = match &request.tools {
            router_types::ToolSelection::AllowList(names) if tools => {
                names.len() == 3
                    && names.iter().map(String::as_str).collect::<BTreeSet<_>>()
                        == BTreeSet::from([
                            "mcp__finite__read_file",
                            "mcp__finite__write_file",
                            "mcp__finite__exec",
                        ])
            }
            router_types::ToolSelection::Disabled => !tools,
            _ => false,
        };
        if startup_tools != tools
            || !selected_tools
            || request.agent.is_some()
            || !request.skills.is_empty()
            || (tools
                && (!request.required_capabilities.contains(&Capability::Tools)
                    || !request
                        .required_capabilities
                        .contains(&Capability::WorkspaceWrite)))
            || request.required_capabilities.iter().any(|capability| {
                !(matches!(capability, Capability::Network | Capability::WorkspaceWrite)
                    || tools && *capability == Capability::Tools)
            })
        {
            return Err(RuntimeError::Sandbox);
        }
        if client.owned_namespace.is_some() && client.broker.isolation.is_none() {
            return Err(RuntimeError::Sandbox);
        }
        let run = &client.run;
        let snapshot = self.snapshot(context)?;
        let auth = execution_authorization_digest_with_capability_acceptance(
            request,
            &snapshot,
            &context.request().restrictions,
            context.capability_acceptance(),
        )?;
        let validated = authorize_execution_with_capability_acceptance(
            request.clone(),
            &snapshot,
            &context.request().restrictions,
            context.capability_acceptance(),
            Some(&auth),
        )?;
        let expected = router_adapter_api::prepared_run(
            &validated,
            "finite-client",
            run.argv.clone(),
            vec![],
        )?;
        // Do not authorize relocation: generated startup state binds this cwd.
        if run.authorization_digest != auth
            || run.snapshot_hash != snapshot.hash()
            || run.receipt_id != expected.receipt_id
            || run.host != expected.host
            || run.source_state != expected.source_state
            || run.scope != expected.scope
            || run.cwd != expected.cwd
            || run.sandbox != expected.sandbox
            || run.mode != expected.mode
            || run.requested_model != expected.requested_model
            || run.requested_effort != expected.requested_effort
            || run.timeout_ms != expected.timeout_ms
            || run.max_output_bytes != expected.max_output_bytes
            || run.stdin.as_bytes() != expected.stdin.as_bytes()
            || client.manifest.task_id != id
            || client.manifest.host_snapshot_id != snapshot.host().id
            || !request.required_capabilities.contains(&Capability::Network)
        {
            return Err(RuntimeError::Integrity("finite client runtime request"));
        }
        if run.sandbox == router_types::ExecutionSandbox::WorkspaceWrite {
            let view = client
                .owned_workspace
                .as_ref()
                .ok_or(RuntimeError::Sandbox)?;
            if !tools {
                view.existing_preimage()?;
            }
            view.check_for_review(&self.store.root, id, run)?;
            // This entrance produces a private patch artifact. It cannot mint
            // source publication authority by treating its mutable view as the
            // original repository or by converting to a generic PendingRun.
            require_private_artifact_scope(&context.request().task.allowed_mutations)?;
        } else if client.owned_workspace.is_some() {
            return Err(RuntimeError::Sandbox);
        }
        prepared_digest(run)?;
        let state = client.owned_state.as_ref().ok_or(RuntimeError::Sandbox)?;
        client.owned_assets.as_ref().ok_or(RuntimeError::Sandbox)?;
        if state.path().parent() != Some(self.store.root.as_path()) {
            return Err(RuntimeError::Integrity("finite client runtime owner"));
        }
        if !client
            .resource_arguments
            .windows(2)
            .any(|args| args == ["--address-space-bytes", "8589934592"])
        {
            return Err(RuntimeError::Integrity("finite client 8 GiB bound"));
        }
        client.check_files()
    }
    /// Registers one immutable definition in the existing store. No worktree,
    /// lease, attempt, admission ticket, native probe or provider turn is made.
    #[allow(clippy::too_many_arguments)]
    pub async fn review_finite_client(
        &self,
        run_id: &str,
        router: &PhaseRouter,
        context: &ValidatedPhaseContext,
        request: ExecutionRequest,
        plan: WorkflowPlan,
        node_id: &str,
        client: FiniteClientReview,
    ) -> Result<PendingFiniteClientRun> {
        self.check_finite_review(run_id, context, &request, &client)?;
        let receipt = router.route(context).map_err(|_| RuntimeError::Route)?;
        let selection = router
            .validate_receipt(context, &receipt)
            .map_err(|_| RuntimeError::Route)?;
        let decision = ExecutionDecision::deterministic(router, context, &selection)
            .map_err(|_| RuntimeError::Route)?;
        let pending = self
            .review_decision_bound(
                run_id,
                router,
                context,
                &decision,
                request,
                plan,
                node_id,
                None,
                None,
                Some(client.approval_digest()),
                Some(client.provider_identity()?),
            )
            .await?;
        self.store
            .event(run_id, "finite_client.review.v1", client.approval_digest())?;
        Ok(PendingFiniteClientRun { pending, client })
    }
    /// Requires the combined runtime digest, never just the preparation digest.
    pub fn approve_finite_client(
        &self,
        pending: PendingFiniteClientRun,
        digest: &str,
    ) -> Result<ApprovedFiniteClientRun> {
        self.check_finite_review(
            &pending.pending.run.run_id,
            &pending.pending.context,
            &pending.pending.request,
            &pending.client,
        )?;
        let client_digest = pending.client.approval_digest().to_owned();
        let approved = self.approve_pending(pending.pending, digest)?;
        let client = pending.client.approve(&client_digest)?;
        Ok(ApprovedFiniteClientRun { approved, client })
    }
    /// Reopens authenticated evidence under this exact queued runtime owner.
    /// This borrow supplies no process or admission authority. A copied JSON
    /// receipt, historical verifier, revoked proof or cancelled run cannot pass.
    pub fn validate_finite_client<'a>(
        &self,
        approved: &'a ApprovedFiniteClientRun,
        source: &EvidenceSource,
        verifier: &StoredCapabilityProofVerifier,
    ) -> Result<FiniteClientValidation<'a>> {
        let pending = &approved.approved.pending;
        self.validate_pending_retention(pending)?;
        let current = self.store.get(&pending.run.run_id)?;
        if current.state != RunState::Queued
            || current.definition_hash != pending.run.definition_hash
            || current.approval_digest != pending.run.approval_digest
            || pending.finite_client_binding.as_deref()
                != Some(approved.client.reviewed.approval_digest())
        {
            return Err(RuntimeError::Approval);
        }
        self.check_finite_review(
            &pending.run.run_id,
            &pending.context,
            &pending.request,
            &approved.client.reviewed,
        )?;
        let snapshot = self.snapshot(&pending.context)?;
        approved.client.validate(
            &approved.client.reviewed.run,
            snapshot.host(),
            source,
            verifier,
            crate::now()?,
        )
    }
}

fn require_private_artifact_scope(mutations: &BTreeSet<router_types::Mutation>) -> Result<()> {
    if mutations.contains(&router_types::Mutation::Integrate) {
        return Err(RuntimeError::Invalid(
            "finite writes are private artifacts only",
        ));
    }
    Ok(())
}
#[cfg(test)]
mod private_artifact_tests {
    use super::*;
    #[test]
    fn finite_write_approval_cannot_include_source_integration_authority() {
        let mut mutations = [
            router_types::Mutation::Network,
            router_types::Mutation::WorkspaceWrite,
        ]
        .into();
        require_private_artifact_scope(&mutations).unwrap();
        mutations.insert(router_types::Mutation::Integrate);
        assert!(matches!(
            require_private_artifact_scope(&mutations),
            Err(RuntimeError::Invalid(
                "finite writes are private artifacts only"
            ))
        ));
    }
}
