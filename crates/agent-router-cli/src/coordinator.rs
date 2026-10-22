//! Private workflow bundles and explicit wave execution. A queued control never
//! supplies confidential step material or selects a sandbox on the owner's behalf.
use crate::{
    CliError, Outcome, command::CoordinateCommand, execution, phases, product::json_output,
};
use router_coordinator::{
    Coordinator, CoordinatorError, DecisionStepExecution, PendingStep, StepExecution,
};
use router_runtime::{Runtime, RuntimeLimits};
use router_types::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

const LIMIT: usize = 4 * 1024 * 1024;
fn error(error: CoordinatorError) -> CliError {
    match error {
        CoordinatorError::Runtime(error) => execution::error(error),
        CoordinatorError::Invalid(_) => CliError::Product("coordinator.invalid"),
        CoordinatorError::Integrity => CliError::Product("coordinator.integrity"),
        CoordinatorError::Limit => CliError::Product("coordinator.limit"),
        CoordinatorError::Locked => CliError::Product("coordinator.locked"),
        CoordinatorError::DependenciesPending => {
            CliError::Product("coordinator.dependencies.pending")
        }
        CoordinatorError::Cancelled => CliError::Product("coordinator.cancelled"),
        CoordinatorError::Workflow(_) => CliError::Product("coordinator.workflow.invalid"),
        CoordinatorError::Storage(e)
            if execution::contention(e.sqlite_error().map(|f| f.extended_code)) =>
        {
            CliError::Product("coordinator.busy")
        }
        CoordinatorError::Storage(e)
            if execution::corruption(e.sqlite_error().map(|f| f.extended_code)) =>
        {
            CliError::Product("coordinator.storage_corrupt")
        }
        CoordinatorError::Storage(_) => CliError::Product("coordinator.storage"),
        CoordinatorError::Io(_) => CliError::Product("coordinator.io"),
        CoordinatorError::Json(_) => CliError::Product("coordinator.json"),
    }
}
fn resolve(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}
fn definition(path: &Path) -> Result<WorkflowDefinition, CliError> {
    let value = phases::read_json(path, LIMIT)?;
    router_coordinator::validate_definition(&value).map_err(error)?;
    Ok(value)
}
fn absolute(path: &Path) -> Result<PathBuf, CliError> {
    fs::canonicalize(path).map_err(|_| CliError::RequestRead)
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| CliError::Product("coordinator.bundle.create"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| CliError::Product("coordinator.bundle.write"))
}
fn bytes(value: &impl Serialize) -> Result<Vec<u8>, CliError> {
    serde_json::to_vec_pretty(value).map_err(|_| CliError::Internal)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    schema_version: u32,
    workflow: PathBuf,
    source_definition: PathBuf,
    sandbox: PathBuf,
    final_request: PathBuf,
    artifact_contract: PathBuf,
    node_id: String,
    generation: u32,
    run_id: String,
    #[serde(skip)]
    proposal: Option<crate::escalation::LoadedProposal>,
}
fn bundle_base(path: &Path) -> Result<Bundle, CliError> {
    let mut value: Bundle = phases::read_json(path, 64 * 1024)?;
    if value.schema_version != 1 || value.generation >= 5 {
        return Err(CliError::Product("coordinator.bundle.invalid"));
    }
    let path = absolute(path)?;
    let base = path.parent().ok_or(CliError::RequestRead)?;
    value.workflow = resolve(base, value.workflow);
    value.source_definition = resolve(base, value.source_definition);
    value.sandbox = resolve(base, value.sandbox);
    value.final_request = resolve(base, value.final_request);
    value.artifact_contract = resolve(base, value.artifact_contract);
    Ok(value)
}
fn bundle(path: &Path) -> Result<Bundle, CliError> {
    let mut value = bundle_base(path)?;
    let source = execution::load_definition(&value.source_definition)?;
    value.proposal = proposal(&source)?;
    Ok(value)
}
fn proposal(
    source: &execution::Definition,
) -> Result<Option<crate::escalation::LoadedProposal>, CliError> {
    let result = source
        .escalation_decision
        .as_deref()
        .map(crate::escalation::LoadedProposal::read)
        .transpose()?;
    if result.as_ref().is_some_and(|p| !p.is_coordinator()) {
        return Err(CliError::Product("escalation.source.coordinator_required"));
    }
    Ok(result)
}
pub(crate) struct EscalationSource {
    pub pending: router_runtime::PendingRun,
    pub material: String,
    pub workflow: WorkflowDefinition,
    pub generation: u32,
    pub artifacts: RunArtifactContract,
}
fn escalation_bundle(path: &Path) -> Result<(Bundle, execution::Definition), CliError> {
    let bundle = bundle_base(path)?;
    let source = execution::load_definition(&bundle.source_definition)?;
    // Never follow a decision file from a disallowed source origin.
    if source.generated_plan.is_some() || source.escalation_decision.is_some() {
        return Err(CliError::Product("escalation.source.origin_denied"));
    }
    execution::require_asset_authority(&source)?;
    Ok((bundle, source))
}
pub(crate) fn escalation_source_id(path: &Path) -> Result<String, CliError> {
    escalation_bundle(path).map(|(bundle, _)| bundle.run_id)
}
pub(crate) fn escalation_source(
    runtime: &Runtime,
    path: &Path,
) -> Result<EscalationSource, CliError> {
    let path = absolute(path)?;
    let (bundle, mut source) = escalation_bundle(&path)?;
    if source.node_id != bundle.node_id {
        return Err(CliError::Product("coordinator.node.mismatch"));
    }
    let workflow = definition(&bundle.workflow)?;
    source.run_id = bundle.run_id.clone();
    source.request = bundle.final_request.clone();
    let (router, context) = execution::historical_context(runtime, &source)?;
    let baseline = execution::selection(&source, &router, &context)?;
    let request: ExecutionRequest = phases::read_json(
        &bundle.final_request,
        router_adapter_api::MAX_EXECUTION_INPUT_BYTES,
    )?;
    let artifacts: RunArtifactContract = phases::read_json(&bundle.artifact_contract, LIMIT)?;
    let loaded = crate::generation::load_decision(
        source.backend_decision.as_deref(),
        None,
        None,
        None,
        &source.node_id,
        &router,
        &context,
        &baseline,
        &crate::execution_backend::scope_hash(
            &request.workspace,
            &request.source_state,
            &request.scope,
        )?,
        true,
    )?;
    let coordinator_root = runtime
        .storage_root()
        .parent()
        .ok_or(CliError::RequestRead)?
        .join("coordinator");
    let pending = router_coordinator::reopen_recorded_step(
        &coordinator_root,
        runtime,
        &workflow,
        &bundle.node_id,
        bundle.generation,
        &router,
        &context,
        &loaded.decision,
        request,
        artifacts.clone(),
    )
    .map_err(error)?;
    if pending.summary().run_id != bundle.run_id {
        return Err(CliError::Product("coordinator.run.mismatch"));
    }
    let material = router_adapter_api::content_digest(&bytes(&(
        "agent-router:escalation-coordinator-source:v1",
        &path,
        &bundle,
        &source,
        &workflow,
        &pending.summary().definition_hash,
        &loaded.binding,
        &artifacts,
    ))?);
    Ok(EscalationSource {
        pending,
        material,
        workflow,
        generation: bundle.generation,
        artifacts,
    })
}
pub(crate) fn bundle_admission(
    path: &Path,
) -> Result<Option<router_types::AdmissionConfig>, CliError> {
    Ok(execution::load_definition(&bundle_base(path)?.source_definition)?.admission)
}
type ProofVerifier = Arc<dyn router_adapter_api::CapabilityProofVerifier>;
fn fresh_verifier(
    store: &Path,
    source: &execution::Definition,
    config: &execution::SandboxConfig,
) -> Result<Option<ProofVerifier>, CliError> {
    let observation: router_adapter_api::HostObservation = phases::read_json(
        &source.host_snapshot,
        router_adapter_api::MAX_SNAPSHOT_BYTES,
    )?;
    if !crate::capability_proofs::has_claims(&observation) {
        return Ok(None);
    }
    let request: ExecutionRequest = phases::read_json(
        &source.request,
        router_adapter_api::MAX_EXECUTION_INPUT_BYTES,
    )?;
    Ok(Some(crate::capability_proofs::fresh(
        &store.join("runtime"),
        config,
        &observation,
        Some((
            &request.scope,
            request.required_capabilities.contains(&Capability::Network),
        )),
    )?))
}
/// A wave uses only the verifiers derived from each explicitly configured step.
/// An empty set grants no capability; the wave manifest bounds this collection.
struct WaveProofVerifier(Vec<ProofVerifier>);
impl router_adapter_api::CapabilityProofVerifier for WaveProofVerifier {
    fn verify_attestation(
        &self,
        reference: &router_adapter_api::CapabilityAttestationReference,
        host: &HostSnapshot,
        now: u64,
    ) -> Result<router_adapter_api::VerifiedCapabilityProof, router_adapter_api::CapabilityProofError>
    {
        self.0
            .iter()
            .find_map(|verifier| verifier.verify_attestation(reference, host, now).ok())
            .ok_or(router_adapter_api::CapabilityProofError::Unauthenticated)
    }

    fn verify(
        &self,
        source: &router_adapter_api::EvidenceSource,
        capability: Capability,
        host: &HostSnapshot,
        now: u64,
    ) -> Result<router_adapter_api::VerifiedCapabilityProof, router_adapter_api::CapabilityProofError>
    {
        self.0
            .iter()
            .find_map(|verifier| verifier.verify(source, capability, host, now).ok())
            .ok_or(router_adapter_api::CapabilityProofError::Unauthenticated)
    }
}
fn runtime(
    store: &Path,
    retention: OutputRetentionPolicy,
    max_attempts: u32,
    admission: Option<&router_types::AdmissionConfig>,
) -> Result<Arc<Runtime>, CliError> {
    runtime_with_verifier(store, retention, max_attempts, admission, None)
}
fn runtime_with_verifier(
    store: &Path,
    retention: OutputRetentionPolicy,
    max_attempts: u32,
    admission: Option<&router_types::AdmissionConfig>,
    verifier: Option<ProofVerifier>,
) -> Result<Arc<Runtime>, CliError> {
    let runtime = crate::admission::open(
        &store.join("runtime"),
        RuntimeLimits {
            output_retention: retention,
            max_attempts,
            ..RuntimeLimits::default()
        },
        admission,
    )
    .map_err(execution::error)?;
    Ok(Arc::new(match verifier {
        Some(verifier) => runtime.with_capability_proof_verifier(verifier),
        None => runtime,
    }))
}
fn owner(store: &Path, runtime: Arc<Runtime>) -> Result<Coordinator, CliError> {
    Coordinator::open(&store.join("coordinator"), runtime).map_err(error)
}
fn ensure_store(store: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    match fs::symlink_metadata(store) {
        Ok(meta)
            if meta.is_dir()
                && !meta.file_type().is_symlink()
                && meta.permissions().mode() & 0o077 == 0 =>
        {
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::DirBuilder::new()
            .mode(0o700)
            .create(store)
            .map_err(|_| CliError::Product("coordinator.store.create")),
        _ => Err(CliError::Product(
            "coordinator.store.private_directory_required",
        )),
    }
}
fn reopen(
    coordinator: &Coordinator,
    workflow: &WorkflowDefinition,
    bundle: &Bundle,
    historical: bool,
) -> Result<
    (
        PendingStep,
        execution::Definition,
        router_policy::PhaseRouter,
        router_policy::ValidatedPhaseContext,
        crate::generation::LoadedDecision,
    ),
    CliError,
> {
    let mut source = execution::load_definition(&bundle.source_definition)?;
    if source.node_id != bundle.node_id {
        return Err(CliError::Product("coordinator.node.mismatch"));
    }
    source.run_id = bundle.run_id.clone();
    source.request = bundle.final_request.clone();
    let (router, context) = if historical {
        execution::historical_context(coordinator.runtime(), &source)?
    } else {
        let config = execution::sandbox(&bundle.sandbox)?;
        let store = coordinator
            .runtime()
            .storage_root()
            .parent()
            .ok_or(CliError::RequestRead)?;
        let verifier = fresh_verifier(store, &source, &config)?;
        execution::context_with_proofs(&source, false, verifier.as_deref(), None)?
    };
    let selection = execution::selection(&source, &router, &context)?;
    let request: ExecutionRequest = phases::read_json(
        &bundle.final_request,
        router_adapter_api::MAX_EXECUTION_INPUT_BYTES,
    )?;
    let loaded = crate::generation::load_decision(
        source.backend_decision.as_deref(),
        source.generated_plan.as_deref(),
        bundle.proposal.as_ref(),
        Some(coordinator.runtime()),
        &source.node_id,
        &router,
        &context,
        &selection,
        &crate::execution_backend::scope_hash(
            &request.workspace,
            &request.source_state,
            &request.scope,
        )?,
        historical,
    )?;
    let artifacts = phases::read_json(&bundle.artifact_contract, LIMIT)?;
    let pending = coordinator
        .reopen_step_decision(
            workflow,
            &bundle.node_id,
            bundle.generation,
            &router,
            &context,
            &loaded.decision,
            request,
            artifacts,
        )
        .map_err(error)?;
    if pending.summary().run_id != bundle.run_id {
        return Err(CliError::Product("coordinator.run.mismatch"));
    }
    Ok((pending, source, router, context, loaded))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wave {
    schema_version: u32,
    steps: Vec<WaveStep>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WaveStep {
    bundle: PathBuf,
    approval: String,
}

pub(crate) fn run(command: CoordinateCommand, json: bool) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    match command {
        CoordinateCommand::Seal { definition: path } => {
            let value = phases::read_json(&path, LIMIT)?;
            json_output(
                &serde_json::json!({"schema_version":1,"definition":router_coordinator::seal_definition(value).map_err(error)?,"approved":false}),
                ExitCode::SUCCESS,
            )
        }
        CoordinateCommand::Status {
            definition: path,
            store,
        } => {
            let workflow = definition(&path)?;
            json_output(
                &router_coordinator::observe(&store.join("coordinator"), &workflow)
                    .map_err(error)?,
                ExitCode::SUCCESS,
            )
        }
        CoordinateCommand::Cancel {
            definition: path,
            store,
        } => {
            let workflow = definition(&path)?;
            // Verify the supplied definition belongs to this existing store.
            router_coordinator::observe(&store.join("coordinator"), &workflow).map_err(error)?;
            router_coordinator::request_cancel(
                &store.join("coordinator"),
                &workflow.execution.instance_id,
            )
            .map_err(error)?;
            json_output(
                &serde_json::json!({"schema_version":1,"instance_id":workflow.execution.instance_id,"cancellation_requested":true}),
                ExitCode::SUCCESS,
            )
        }
        CoordinateCommand::Review {
            definition: path,
            source_definition,
            sandbox,
            node_id,
            generation,
            store,
            output_directory,
        } => execution::block(async {
            let workflow = definition(&path)?;
            let mut source = execution::load_definition(&source_definition)?;
            if source.node_id != node_id {
                return Err(CliError::Product("coordinator.node.mismatch"));
            }
            let config = execution::sandbox(&sandbox)?;
            let proof_verifier = fresh_verifier(&store, &source, &config)?;
            let (router, context) =
                execution::context_with_proofs(&source, false, proof_verifier.as_deref(), None)?;
            let selection = execution::selection(&source, &router, &context)?;
            let request: router_types::ExecutionRequest = phases::read_json(
                &source.request,
                router_adapter_api::MAX_EXECUTION_INPUT_BYTES,
            )?;
            execution::validate_adapter_config(request.host.as_str(), &config)?;
            // Refuse an existing bundle before registering anything in the store.
            if output_directory.exists() {
                return Err(CliError::Product("coordinator.bundle.exists"));
            }
            ensure_store(&store)?;
            let proposal = proposal(&source)?;
            if let Some(proposal) = &proposal {
                proposal.validate_store(&store.join("runtime"))?;
            }
            let runtime = runtime_with_verifier(
                &store,
                config.output_retention,
                proposal.as_ref().map_or(2, |p| p.max_attempts()),
                source.admission.as_ref(),
                proof_verifier,
            )?;
            let coordinator = owner(&store, runtime)?;
            coordinator.register(&workflow).map_err(error)?;
            let loaded = crate::generation::load_decision(
                source.backend_decision.as_deref(),
                source.generated_plan.as_deref(),
                proposal.as_ref(),
                Some(coordinator.runtime()),
                &source.node_id,
                &router,
                &context,
                &selection,
                &crate::execution_backend::scope_hash(
                    &request.workspace,
                    &request.source_state,
                    &request.scope,
                )?,
                false,
            )?;

            let pending = coordinator
                .review_step_decision(
                    &workflow,
                    &node_id,
                    generation,
                    &router,
                    &context,
                    &loaded.decision,
                    request,
                )
                .await
                .map_err(error)?;
            let parent = absolute(
                output_directory
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new(".")),
            )?;
            let name = output_directory
                .file_name()
                .ok_or(CliError::Product("coordinator.bundle.path"))?;
            let directory = parent.join(name);
            source.run_id = pending.summary().run_id.clone();
            source.request = directory.join("request.json");
            let (approval, binaries) = execution::approval_for_digest(
                pending.approval_digest(),
                &config,
                &source,
                loaded.binding.as_ref(),
                &store.join("runtime"),
            )?;
            execution::validate_proof_binary_pins(&context, &config, &binaries)?;
            let bundle = Bundle {
                schema_version: 1,
                workflow: absolute(&path)?,
                source_definition: absolute(&source_definition)?,
                sandbox: absolute(&sandbox)?,
                final_request: PathBuf::from("request.json"),
                artifact_contract: PathBuf::from("artifacts.json"),
                node_id,
                generation,
                run_id: pending.summary().run_id.clone(),
                proposal: None,
            };
            let files = [
                ("request.json", bytes(pending.final_request())?),
                ("artifacts.json", bytes(pending.artifact_contract())?),
                ("bundle.json", bytes(&bundle)?),
            ];
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .map_err(|_| CliError::Product("coordinator.bundle.create"))?;
            for (name, content) in files {
                write_private(&directory.join(name), &content)?;
            }
            json_output(
                &serde_json::json!({"schema_version":1,"run":pending.summary(),"approval_digest":approval,"binary_hashes":binaries,"artifact_contract":pending.artifact_contract(),"execution_decision":loaded.decision.binding(),"generated_decision":loaded.decision.generated_binding(),"escalation_decision":loaded.decision.escalation_binding(),"decision_origin":loaded.decision.origin(),"baseline_receipt_id":loaded.decision.baseline().receipt_id,"final_request_sha256":router_adapter_api::content_digest(&bytes(pending.final_request())?),"bundle":directory.join("bundle.json"),"executed":false}),
                ExitCode::SUCCESS,
            )
        }),
        CoordinateCommand::RunWave {
            definition: path,
            wave,
            store,
        } => execution::block(async {
            let workflow = definition(&path)?;
            let manifest: Wave = phases::read_json(&wave, 256 * 1024)?;
            if manifest.schema_version != 1
                || manifest.steps.is_empty()
                || manifest.steps.len() > 64
            {
                return Err(CliError::Product("coordinator.wave.invalid"));
            }
            let wave = absolute(&wave)?;
            let base = wave.parent().ok_or(CliError::RequestRead)?;
            let mut entries = Vec::new();
            let mut unique = BTreeSet::new();
            let mut retention = None;
            for step in manifest.steps {
                let bundle = bundle(&resolve(base, step.bundle))?;
                if definition(&bundle.workflow)? != workflow
                    || !unique.insert(bundle.run_id.clone())
                {
                    return Err(CliError::Product("coordinator.wave.binding"));
                }
                let config = execution::sandbox(&bundle.sandbox)?;
                if retention.is_some_and(|value| value != config.output_retention) {
                    return Err(CliError::Product("coordinator.wave.retention_mismatch"));
                }
                retention = Some(config.output_retention);
                entries.push((bundle, config, step.approval));
            }
            // A wave only reconstructs registered steps; a missing store is not created.
            router_coordinator::observe(&store.join("coordinator"), &workflow).map_err(error)?;
            let limits: BTreeSet<_> = entries
                .iter()
                .map(|(bundle, _, _)| bundle.proposal.as_ref().map_or(2, |p| p.max_attempts()))
                .collect();
            if limits.len() != 1 {
                return Err(CliError::Product("coordinator.wave.attempt_limit_mismatch"));
            }
            let max_attempts = *limits.first().ok_or(CliError::InvalidCommand)?;
            let configs = entries
                .iter()
                .map(|(b, _, _)| {
                    execution::load_definition(&b.source_definition).map(|d| d.admission)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let admission = crate::admission::same(&configs)?;
            let mut verifiers = Vec::new();
            for (bundle, config, _) in &entries {
                let mut source = execution::load_definition(&bundle.source_definition)?;
                source.request = bundle.final_request.clone();
                if let Some(verifier) = fresh_verifier(&store, &source, config)? {
                    verifiers.push(verifier);
                }
            }
            let proof_verifier: Option<ProofVerifier> = if verifiers.is_empty() {
                None
            } else {
                Some(Arc::new(WaveProofVerifier(verifiers)))
            };
            let runtime = runtime_with_verifier(
                &store,
                retention.ok_or(CliError::InvalidCommand)?,
                max_attempts,
                admission.as_ref(),
                proof_verifier,
            )?;
            let coordinator = owner(&store, runtime)?;
            let mut pending_steps = Vec::new();
            let mut adapters = Vec::new();
            let mut supervisors = Vec::new();
            let mut feedback = Vec::new();
            let mut authorities = Vec::new();
            for (bundle, config, approval) in entries {
                let (pending, source, _router, context, loaded) =
                    reopen(&coordinator, &workflow, &bundle, false)?;
                execution::require_asset_authority(&source)?;
                let (digest, binaries) = execution::approval_for_digest(
                    pending.approval_digest(),
                    &config,
                    &source,
                    loaded.binding.as_ref(),
                    &store.join("runtime"),
                )?;
                execution::validate_proof_binary_pins(&context, &config, &binaries)?;
                if approval != digest {
                    return Err(CliError::Product(
                        "coordinator.approval.required_or_changed",
                    ));
                }
                let feedback_path = config.feedback_store.clone();
                let consent = crate::execution_feedback::consent(feedback_path.as_deref())?;
                adapters.push(execution::adapter(
                    pending.final_request().host.as_str(),
                    &config,
                )?);
                supervisors
                    .push(execution::supervisor(&store.join("runtime"), config, &binaries).await?);
                feedback.push((
                    pending.summary().run_id.clone(),
                    feedback_path,
                    consent,
                    context,
                    loaded.decision,
                ));
                authorities.push(loaded.authority);
                pending_steps.push(pending);
            }
            let mut jobs = Vec::new();
            for (((pending, adapter), supervisor), authority) in pending_steps
                .into_iter()
                .zip(&adapters)
                .zip(&supervisors)
                .zip(&authorities)
            {
                let digest = pending.approval_digest().to_owned();
                let approved = coordinator
                    .approve_step(&workflow, pending, &digest)
                    .map_err(error)?;
                jobs.push(DecisionStepExecution {
                    execution: StepExecution {
                        step: approved,
                        adapter: adapter.as_ref(),
                        supervisor: supervisor.as_ref(),
                    },
                    authority: authority
                        .as_ref()
                        .map(|store| store as &dyn router_execution_decision::ActivationAuthority),
                });
            }
            let control = store.join("coordinator");
            let instance = workflow.execution.instance_id.clone();
            let listener = tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    let _ = router_coordinator::request_cancel(&control, &instance);
                }
            });
            // One start for the wave: its steps are launched together.
            let started_at = crate::inspect::current_time(None).ok();
            let result = coordinator.run_ready_decisions(&workflow, jobs).await;
            listener.abort();
            let result = result.map_err(error)?;
            let recorded:Vec<_>=result.completions.iter().filter_map(|completion|feedback.iter().find(|f|f.0==completion.run.run_id).map(|(_,path,consent,context,selection)|serde_json::json!({"run_id":completion.run.run_id,"feedback":crate::execution_feedback::record(path.as_deref(),consent.as_ref(),selection,context,completion,started_at)}))).collect();
            let success = !result.cancelled
                && result.errors.is_empty()
                && result.completions.iter().all(|c| {
                    c.transport.exit_code == Some(0)
                        && c.transport.termination == TransportTermination::Exited
                        && c.run.failure.is_none()
                });
            json_output(
                &serde_json::json!({"schema_version":1,"wave":result,"feedback":recorded,"workflow":coordinator.status(&workflow).map_err(error)?}),
                if success {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(3)
                },
            )
        }),
        CoordinateCommand::Verify {
            bundle: path,
            store,
            evidence,
            approval,
        } => {
            let bundle = bundle(&path)?;
            let workflow = definition(&bundle.workflow)?;
            router_coordinator::observe(&store.join("coordinator"), &workflow).map_err(error)?;
            let source = execution::load_definition(&bundle.source_definition)?;
            let mut source = source;
            source.run_id = bundle.run_id.clone();
            source.request = bundle.final_request.clone();
            let config = execution::sandbox(&bundle.sandbox)?;
            let summary = router_runtime::observe(&store.join("runtime"), &bundle.run_id)
                .map_err(execution::error)?;
            let binding = if let Some(proposal) = &bundle.proposal {
                proposal.validate_store(&store.join("runtime"))?;
                Some(crate::generation::SourceBinding::Escalated(
                    proposal.control_binding(),
                ))
            } else {
                let evidence_runtime = runtime(
                    &store,
                    summary.output_retention,
                    2,
                    source.admission.as_ref(),
                )?;
                let (router, context) = execution::historical_context(&evidence_runtime, &source)?;
                let baseline = execution::selection(&source, &router, &context)?;
                let request: ExecutionRequest = phases::read_json(
                    &source.request,
                    router_adapter_api::MAX_EXECUTION_INPUT_BYTES,
                )?;
                let loaded = crate::generation::load_decision(
                    source.backend_decision.as_deref(),
                    source.generated_plan.as_deref(),
                    None,
                    None,
                    &source.node_id,
                    &router,
                    &context,
                    &baseline,
                    &crate::execution_backend::scope_hash(
                        &request.workspace,
                        &request.source_state,
                        &request.scope,
                    )?,
                    true,
                )?;
                loaded.binding
            };
            let (digest, _) = execution::approval_for_digest(
                &summary.approval_digest,
                &config,
                &source,
                binding.as_ref(),
                &store.join("runtime"),
            )?;
            if approval != digest {
                return Err(CliError::Product(
                    "coordinator.approval.required_or_changed",
                ));
            }
            let record = phases::read_json(&evidence, 64 * 1024)?;
            let id = router_coordinator::request_verification(
                &store.join("coordinator"),
                &workflow.execution.instance_id,
                &bundle.node_id,
                bundle.generation,
                &summary.approval_digest,
                record,
            )
            .map_err(error)?;
            json_output(
                &serde_json::json!({"schema_version":1,"request_id":id,"queued":true,"verified":false}),
                ExitCode::SUCCESS,
            )
        }
        CoordinateCommand::Service {
            definition: path,
            bundles,
            store,
        } => {
            let workflow = definition(&path)?;
            if bundles.is_empty() || bundles.len() > 320 {
                return Err(CliError::Product("coordinator.materials.limit"));
            }
            router_coordinator::observe(&store.join("coordinator"), &workflow).map_err(error)?;
            let loaded = bundles
                .iter()
                .map(|path| bundle(path))
                .collect::<Result<Vec<_>, _>>()?;
            let first = loaded.first().ok_or(CliError::InvalidCommand)?;
            let retained = router_runtime::observe(&store.join("runtime"), &first.run_id)
                .map_err(execution::error)?
                .output_retention;
            let max_attempts = loaded
                .iter()
                .filter_map(|bundle| bundle.proposal.as_ref())
                .map(|p| p.max_attempts())
                .max()
                .unwrap_or(2);
            let configs = loaded
                .iter()
                .map(|b| execution::load_definition(&b.source_definition).map(|d| d.admission))
                .collect::<Result<Vec<_>, _>>()?;
            let admission = crate::admission::same(&configs)?;
            let runtime = runtime(&store, retained, max_attempts, admission.as_ref())?;
            let coordinator = owner(&store, Arc::clone(&runtime))?;
            // Same opt-in as the automated event of each run: the feedback store
            // of the bundle's own sandbox configuration.
            let concluded = |id: &str| {
                runtime.summary(id).is_ok_and(|run| {
                    matches!(run.state, RunState::Verified | RunState::VerificationFailed)
                })
            };
            let runs: Vec<_> = loaded
                .iter()
                .map(|b| (b.run_id.clone(), b.sandbox.clone(), concluded(&b.run_id)))
                .collect();
            for bundle in loaded {
                if definition(&bundle.workflow)? != workflow {
                    return Err(CliError::Product("coordinator.wave.binding"));
                }
                reopen(&coordinator, &workflow, &bundle, true)?;
            }
            let count = coordinator.service_controls(&workflow).map_err(error)?;
            // A feedback failure is only reported, never a service failure.
            let feedback: Vec<_> = runs
                .iter()
                .filter_map(|(id, sandbox, was_concluded)| {
                    let now = runtime.summary(id).ok()?;
                    let value = crate::execution_feedback::service_verification_fact(
                        *was_concluded,
                        &now,
                        || runtime.verification_record(id).map_err(|_| ()),
                        || {
                            execution::sandbox(sandbox)
                                .map(|c| c.feedback_store)
                                .map_err(|_| ())
                        },
                    )?;
                    Some(serde_json::json!({"run_id":id,"feedback":value}))
                })
                .collect();
            json_output(
                &serde_json::json!({"schema_version":1,"applied_controls":count,"feedback":feedback,"workflow":coordinator.status(&workflow).map_err(error)?}),
                ExitCode::SUCCESS,
            )
        }
        CoordinateCommand::Artifacts {
            bundle: path,
            store,
            config,
            command,
        } => execution::block(async {
            let feedback_path = execution::late_feedback_store(config.as_deref())?;
            let bundle = bundle(&path)?;
            let workflow = definition(&bundle.workflow)?;
            router_coordinator::observe(&store.join("coordinator"), &workflow).map_err(error)?;
            let retained = router_runtime::observe(&store.join("runtime"), &bundle.run_id)
                .map_err(execution::error)?
                .output_retention;
            let mut source = execution::load_definition(&bundle.source_definition)?;
            let verifier = match &command {
                crate::command::ArtifactCommand::Publish { .. } => {
                    // Match the reviewed coordinator step, not its original
                    // request before prompt/scope preparation.
                    source.request = bundle.final_request.clone();
                    execution::publication_verifier(
                        &store.join("runtime"),
                        &source,
                        config.as_deref(),
                    )?
                }
                crate::command::ArtifactCommand::Apply { .. } => execution::integration_verifier(
                    &store.join("runtime"),
                    &source,
                    config.as_deref(),
                )?,
                _ => None,
            };
            let runtime = runtime_with_verifier(
                &store,
                retained,
                bundle.proposal.as_ref().map_or(2, |p| p.max_attempts()),
                source.admission.as_ref(),
                verifier,
            )?;
            let coordinator = owner(&store, Arc::clone(&runtime))?;
            let (pending, ..) = reopen(&coordinator, &workflow, &bundle, true)?;
            use crate::command::ArtifactCommand;
            let integration = |outcome| {
                crate::execution_feedback::record_fact(
                    feedback_path.as_deref(),
                    pending.summary(),
                    router_types::FeedbackFactKind::Integration { outcome },
                )
            };
            let value = match command {
                ArtifactCommand::ReviewPublication => {
                    serde_json::json!({"schema_version":1,"review":coordinator.review_publication(&pending).await.map_err(error)?})
                }
                ArtifactCommand::CheckPublicationReview { review } => {
                    let review = phases::read_json(&review, 128 * 1024 * 1024)?;
                    coordinator
                        .validate_publication_review(&pending, &review)
                        .await
                        .map_err(error)?;
                    serde_json::json!({"schema_version":1,"review":review})
                }
                ArtifactCommand::Publish { approve } => {
                    serde_json::json!({"schema_version":1,"publication":coordinator.publish_patch(&pending, &approve).await.map_err(error)?})
                }
                ArtifactCommand::PublicationStatus => {
                    let status = coordinator
                        .publication_status(&pending)
                        .await
                        .map_err(error)?;
                    let exit = if status.state == router_types::PatchPublicationState::Unknown {
                        ExitCode::from(3)
                    } else {
                        ExitCode::SUCCESS
                    };
                    return json_output(
                        &serde_json::json!({"schema_version":1,"publication":status}),
                        exit,
                    );
                }
                ArtifactCommand::Preview => {
                    serde_json::json!({"schema_version":1,"preview":coordinator.integration_preview(&pending).await.map_err(error)?})
                }
                ArtifactCommand::Apply { approve } => {
                    let applied = coordinator.apply(&pending, &approve).await.map_err(error)?;
                    serde_json::json!({"schema_version":1,"applied":applied,"feedback":integration(router_types::IntegrationOutcome::Applied)})
                }
                ArtifactCommand::Discard { approve } => {
                    coordinator
                        .discard(&pending, &approve)
                        .await
                        .map_err(error)?;
                    serde_json::json!({"schema_version":1,"discarded":true,"feedback":integration(router_types::IntegrationOutcome::Discarded)})
                }
                ArtifactCommand::Keep => {
                    serde_json::json!({"schema_version":1,"kept":true,"run":pending.summary()})
                }
                ArtifactCommand::Outputs => {
                    serde_json::json!({"schema_version":1,"outputs":runtime.output_artifacts(&bundle.run_id).map_err(execution::error)?})
                }
                ArtifactCommand::PurgeOutputs { attempt } => {
                    serde_json::json!({"schema_version":1,"purged":runtime.purge_output_artifacts(&bundle.run_id,attempt).map_err(execution::error)?})
                }
                ArtifactCommand::Declared => {
                    serde_json::json!({"schema_version":1,"artifacts":runtime.declared_artifacts(&bundle.run_id).map_err(execution::error)?})
                }
                ArtifactCommand::PurgeDeclared { id } => {
                    if !runtime
                        .declared_artifacts(&bundle.run_id)
                        .map_err(execution::error)?
                        .iter()
                        .any(|a| a.artifact_id == id)
                    {
                        return Err(CliError::Product("coordinator.artifact.outside_run"));
                    }
                    serde_json::json!({"schema_version":1,"purged":runtime.purge_declared_artifact(&id).map_err(execution::error)?})
                }
            };
            json_output(&value, ExitCode::SUCCESS)
        }),
    }
}

#[cfg(test)]
mod code_alignment_tests {
    use super::*;

    #[test]
    fn coordinator_display_codes_match_the_cli_codes() {
        use CoordinatorError::*;
        let json = serde_json::from_str::<u8>("x").unwrap_err();
        for variant in [
            Integrity,
            Limit,
            Locked,
            DependenciesPending,
            Cancelled,
            Io(std::io::Error::other("fixture")),
            Json(json),
        ] {
            let display = variant.to_string();
            assert_eq!(error(variant).code(), display);
        }
    }
}
#[cfg(test)]
mod attested_wave_tests {
    use super::*;
    use router_adapter_api::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn wave_forwards_attestations_and_observes_revocation_live() {
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let mut store = router_runtime::CapabilityProofStore::create(root.path()).unwrap();
        store.enable_attestations(&[42; 32]).unwrap();
        let binding = CapabilityAttestationBinding {
            harness_id: "fixture-host".into(),
            host_snapshot_id: "fixture-snapshot".into(),
            binary_sha256: "1".repeat(64),
            declared_version: "fixture-v1".into(),
            adapter_id: "fixture-adapter".into(),
            argument_template_sha256: "2".repeat(64),
            sandbox_helper_sha256: "3".repeat(64),
            sandbox_wrapper_sha256: "4".repeat(64),
            sandbox_profile_sha256: "5".repeat(64),
            write_roots: BTreeSet::from(["src".into()]),
            network: false,
            os: "fixture-os".into(),
        };
        let key = CapabilityAttestationKey::derive(&[42; 32], store.store_id()).unwrap();
        let grant = key
            .authenticate(CapabilityAttestationRecord {
                schema_version: 2,
                record_id: "grant".into(),
                sequence: 1,
                store_id: store.store_id().into(),
                capability: Capability::WorkspaceWrite,
                binding: binding.clone(),
                operator_label: "fixture-operator".into(),
                reason: "Offline wave fixture".into(),
                created_at_unix_seconds: 100,
                action: CapabilityAttestationAction::Grant {
                    max_age_seconds: 1000,
                },
            })
            .unwrap();
        store.append_attestation(&grant, &[42; 32]).unwrap();
        let host = HostSnapshot {
            id: binding.host_snapshot_id.clone(),
            harness: router_types::HarnessId::parse(&binding.harness_id).unwrap(),
            supported_models: Default::default(),
            supported_efforts: Default::default(),
            capabilities: Default::default(),
        };
        let verifier = Arc::new(
            router_runtime::StoredCapabilityProofVerifier::open_existing(
                root.path(),
                [42; 32],
                vec![binding.execution_pins()],
            )
            .unwrap(),
        );
        let wave = WaveProofVerifier(vec![verifier]);
        assert_eq!(
            wave.verify_attestation(&grant.reference().unwrap(), &host, 110)
                .unwrap()
                .tier,
            CapabilityProofTier::Attested
        );
        let mut revoke = grant.record.clone();
        revoke.record_id = "revoke".into();
        revoke.sequence = 2;
        revoke.action = CapabilityAttestationAction::Revoke {
            record_id: grant.record.record_id.clone(),
            content_sha256: grant.digest().unwrap(),
        };
        store
            .append_attestation(&key.authenticate(revoke).unwrap(), &[42; 32])
            .unwrap();
        assert!(
            wave.verify_attestation(&grant.reference().unwrap(), &host, 110)
                .is_err()
        );
        assert!(
            WaveProofVerifier(vec![])
                .verify_attestation(&grant.reference().unwrap(), &host, 110)
                .is_err()
        );
    }
}
