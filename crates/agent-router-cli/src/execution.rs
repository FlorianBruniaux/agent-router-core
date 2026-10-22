use crate::{
    CliError, Outcome,
    command::{ArtifactCommand, PhaseArgs},
    phases,
    product::json_output,
};
use router_adapter_api::{HarnessAdapter, HostObservation, content_digest};
use router_policy::{PhaseRouter, ValidatedPhaseContext};
use router_runtime::{
    Cancellation, PendingRun, ResourceLimits, ResourceSupervisor, Runtime, RuntimeError,
    RuntimeLimits, SandboxSupervisor,
};
use router_types::{ExecutionRequest, WorkflowPlan};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    future::Future,
    path::{Path, PathBuf},
    process::ExitCode,
};

const DOCUMENT_LIMIT: usize = 4 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Definition {
    schema_version: u32,
    pub(crate) run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) admission: Option<router_types::AdmissionConfig>,
    context: PathBuf,
    pub(crate) host_snapshot: PathBuf,
    catalog: PathBuf,
    policy: Option<PathBuf>,
    policy_store: Option<PathBuf>,
    policy_artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    asset_authority: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) backend_decision: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) generated_plan: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) escalation_decision: Option<PathBuf>,
    plan: PathBuf,
    pub(crate) node_id: String,
    pub(crate) request: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workflow_contract: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    generation: Option<u32>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    cpu_seconds: u64,
    #[serde(deserialize_with = "explicit_memory_limit")]
    address_space_bytes: Option<u64>,
    max_open_files: u64,
    max_processes: u64,
    max_file_bytes: u64,
}
fn explicit_memory_limit<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    Option::<u64>::deserialize(deserializer)
}
impl From<Limits> for ResourceLimits {
    fn from(value: Limits) -> Self {
        Self {
            cpu_seconds: value.cpu_seconds,
            address_space_bytes: value.address_space_bytes,
            max_open_files: value.max_open_files,
            max_processes: value.max_processes,
            max_file_bytes: value.max_file_bytes,
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SandboxConfig {
    schema_version: u32,
    programs: BTreeMap<String, PathBuf>,
    read_roots: Vec<PathBuf>,
    environment_names: Vec<String>,
    helper: PathBuf,
    bubblewrap: Option<PathBuf>,
    limits: Limits,
    pub(crate) feedback_store: Option<PathBuf>,
    #[serde(default)]
    pub(crate) output_retention: router_types::OutputRetentionPolicy,
    #[cfg(feature = "opencode")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    opencode: Option<adapter_opencode::OpenCodeConfig>,
    #[cfg(feature = "copilot")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    copilot: Option<adapter_copilot::CopilotConfig>,
}

pub(crate) fn error(error: RuntimeError) -> CliError {
    CliError::Product(match error {
        RuntimeError::Budget(e) => match e {
            router_runtime::BudgetError::Policy => "session_budget.policy.invalid",
            router_runtime::BudgetError::Authority => {
                "session_budget.authority.required_or_changed"
            }
            router_runtime::BudgetError::Cost => "session_budget.cost.exhausted",
            router_runtime::BudgetError::Tokens => "session_budget.tokens.exhausted",
            router_runtime::BudgetError::Stale => "session_budget.review.stale",
            router_runtime::BudgetError::Unknown => "session_budget.accounting.unknown",
        },
        RuntimeError::Invalid(_) => "runtime.invalid",
        RuntimeError::Io(_) => "runtime.io",
        RuntimeError::Storage(e) if contention(e.sqlite_error().map(|f| f.extended_code)) => {
            "runtime.busy"
        }
        RuntimeError::Storage(e) if corruption(e.sqlite_error().map(|f| f.extended_code)) => {
            "runtime.storage_corrupt"
        }
        RuntimeError::Storage(_) => "runtime.storage",
        RuntimeError::Json(_) => "runtime.json",
        RuntimeError::Integrity(_) => "runtime.integrity",
        RuntimeError::Locked => "runtime.locked",
        RuntimeError::Transition => "runtime.transition.invalid",
        RuntimeError::NotFound => "runtime.not_found",
        RuntimeError::Approval => "runtime.approval.required_or_changed",
        RuntimeError::SourceChanged => "runtime.source.changed_or_dirty",
        RuntimeError::Scope => "runtime.scope.denied",
        RuntimeError::NestedGit => "runtime.workspace.nested_git",
        RuntimeError::Sandbox => "runtime.sandbox.unknown_or_unsafe",
        RuntimeError::ScriptProgram => "runtime.program.script_unsupported",
        RuntimeError::ResourceUnsupported(_) => "runtime.resource.unsupported",
        RuntimeError::Route => "runtime.route.invalid",
        RuntimeError::Adapter(_) => "runtime.adapter",
        RuntimeError::Process => "runtime.process.failed",
        RuntimeError::Limit => "runtime.limit",
        RuntimeError::Cancelled => "runtime.cancelled",
        RuntimeError::Verification => "runtime.verification.required",
        RuntimeError::DependenciesPending => "runtime.dependencies.pending",
        RuntimeError::CleanupUnknown => "runtime.cleanup.unknown",
        RuntimeError::Decision(_) => "runtime.decision.invalid_or_changed",
    })
}
/// SQLite reports contention as SQLITE_BUSY (5) or SQLITE_LOCKED (6) in the
/// primary byte of its extended result code. Relaunching may then succeed.
pub(crate) fn contention(extended_code: Option<i32>) -> bool {
    extended_code.is_some_and(|code| matches!(code & 0xff, 5 | 6))
}
/// SQLITE_CORRUPT (11) or SQLITE_NOTADB (26): the stored database is damaged
/// or replaced, an integrity failure rather than an internal one.
pub(crate) fn corruption(extended_code: Option<i32>) -> bool {
    extended_code.is_some_and(|code| matches!(code & 0xff, 11 | 26))
}
pub(crate) fn block<T>(future: impl Future<Output = Result<T, CliError>>) -> Result<T, CliError> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| CliError::Internal)?
        .block_on(future)
}
fn require_json(json: bool) -> Result<(), CliError> {
    if json {
        Ok(())
    } else {
        Err(CliError::JsonOutputRequired)
    }
}
fn resolve(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}
pub(crate) fn load_definition(path: &Path) -> Result<Definition, CliError> {
    let mut value: Definition = phases::read_json(path, 64 * 1024)?;
    if value.schema_version != 1 {
        return Err(CliError::Product("runtime.definition.schema"));
    }
    let absolute = std::fs::canonicalize(path).map_err(|_| CliError::RequestRead)?;
    let base = absolute.parent().ok_or(CliError::RequestRead)?;
    if let Some(config) = &mut value.admission {
        crate::admission::resolve(config, base)?;
    }
    value.context = resolve(base, value.context);
    value.host_snapshot = resolve(base, value.host_snapshot);
    value.catalog = resolve(base, value.catalog);
    value.policy = value.policy.map(|path| resolve(base, path));
    value.policy_store = value.policy_store.map(|path| resolve(base, path));
    value.asset_authority = value.asset_authority.map(|path| resolve(base, path));
    value.backend_decision = value.backend_decision.map(|path| resolve(base, path));
    value.generated_plan = value.generated_plan.map(|path| resolve(base, path));
    value.escalation_decision = value.escalation_decision.map(|path| resolve(base, path));
    if value.escalation_decision.is_some()
        && (value.backend_decision.is_some() || value.generated_plan.is_some())
    {
        return Err(CliError::Product("escalation.composition.denied"));
    }
    if value.backend_decision.is_some() && value.generated_plan.is_some() {
        return Err(CliError::Product("generation.composition.denied"));
    }
    if value.policy_store.is_some() != value.policy_artifact_id.is_some() {
        return Err(CliError::Product("policy.artifact.required"));
    }
    // One policy authority per definition: a file would silently shadow the
    // pinned store artifact.
    if value.policy.is_some() && value.policy_store.is_some() {
        return Err(CliError::Product("policy.composition.denied"));
    }
    value.plan = resolve(base, value.plan);
    value.request = resolve(base, value.request);
    value.receipt = value.receipt.map(|path| resolve(base, path));
    value.workflow_contract = value.workflow_contract.map(|path| resolve(base, path));
    if value.workflow_contract.is_some() != value.generation.is_some() {
        return Err(CliError::Product("runtime.workflow.generation_required"));
    }
    Ok(value)
}
fn workflow_contract(
    definition: &Definition,
) -> Result<Option<(router_types::WorkflowExecutionContract, u32)>, CliError> {
    definition
        .workflow_contract
        .as_ref()
        .map(|path| {
            Ok((
                phases::read_json(path, DOCUMENT_LIMIT)?,
                definition
                    .generation
                    .ok_or(CliError::Product("runtime.workflow.generation_required"))?,
            ))
        })
        .transpose()
}
pub(crate) fn selection(
    definition: &Definition,
    router: &PhaseRouter,
    context: &ValidatedPhaseContext,
) -> Result<router_types::PhaseReceipt, CliError> {
    let receipt = match &definition.receipt {
        Some(path) => phases::read_json(path, DOCUMENT_LIMIT)?,
        None => router
            .route(context)
            .map_err(|_| CliError::Product("runtime.route.invalid"))?,
    };
    if definition.backend_decision.is_none()
        && definition.generated_plan.is_none()
        && definition.escalation_decision.is_none()
    {
        router
            .validate_receipt(context, &receipt)
            .map_err(|_| CliError::Product("runtime.receipt.invalid"))?;
    }
    Ok(receipt)
}
pub(crate) fn plan(path: &Path) -> Result<WorkflowPlan, CliError> {
    let value: serde_json::Value = phases::read_json(path, DOCUMENT_LIMIT)?;
    let result = if value.get("plan").is_some() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Envelope {
            schema_version: u32,
            plan: WorkflowPlan,
            assumptions: Vec<String>,
            #[serde(default)]
            risk_assessment: Option<router_types::RiskAssessment>,
        }
        let wrapper: Envelope =
            serde_json::from_value(value).map_err(|_| CliError::RequestJsonInvalid)?;
        let risk_valid = match (wrapper.schema_version, &wrapper.risk_assessment) {
            (1, None) => true,
            (2, Some(assessment)) => {
                assessment.schema_version == 1
                    && assessment.rules_version == "risk-floor-v1"
                    && assessment.effective == Some(wrapper.plan.task.risk)
                    && assessment.floor <= wrapper.plan.task.risk
            }
            _ => false,
        };
        if !risk_valid || wrapper.assumptions.len() > 128 {
            return Err(CliError::Product("workflow.invalid"));
        }
        wrapper.plan
    } else {
        serde_json::from_value(value).map_err(|_| CliError::RequestJsonInvalid)?
    };
    router_workflow::validate_plan(&result).map_err(|_| CliError::Product("workflow.invalid"))?;
    Ok(result)
}
pub(crate) fn context_with_proofs(
    definition: &Definition,
    historical: bool,
    verifier: Option<&dyn router_adapter_api::CapabilityProofVerifier>,
    run_clock: Option<u64>,
) -> Result<(PhaseRouter, ValidatedPhaseContext), CliError> {
    // Historical reconstruction can only feed Runtime::reopen, whose stored
    // immutable definition must match. It is never fresh execution authority.
    let now = if historical {
        let snapshot: HostObservation =
            phases::read_json(&definition.host_snapshot, DOCUMENT_LIMIT)?;
        Some(match run_clock {
            Some(clock) => clock,
            None => match &definition.asset_authority {
                Some(path) => crate::assets::historical_time(path)?,
                None => snapshot.observed_at_unix_seconds,
            },
        })
    } else {
        None
    };
    let pinned = if definition.policy.is_none() {
        if let (Some(path), Some(id)) = (&definition.policy_store, &definition.policy_artifact_id) {
            if !path.join("feedback.sqlite3").is_file() {
                return Err(CliError::Product("policy.store.unavailable"));
            }
            let store = router_feedback::FeedbackStore::open(path)
                .map_err(|_| CliError::Product("policy.store.invalid"))?;
            if !historical
                && store
                    .active_policy()
                    .map_err(|_| CliError::Product("policy.active.invalid"))?
                    .as_ref()
                    .map(|active| &active.artifact_id)
                    != Some(id)
            {
                return Err(CliError::Product("policy.active.changed"));
            }
            Some(
                store
                    .policy(id)
                    .map_err(|_| CliError::Product("policy.artifact.invalid"))?
                    .artifact
                    .policy,
            )
        } else {
            None
        }
    } else {
        None
    };
    phases::load_with_policy_and_verifier(
        &PhaseArgs {
            store: None,
            execution_config: None,
            context: definition.context.clone(),
            host_snapshot: definition.host_snapshot.clone(),
            catalog: definition.catalog.clone(),
            policy: definition.policy.clone(),
            policy_store: None,
            asset_authority: definition.asset_authority.clone(),
            now,
            snapshot_max_age_seconds: if historical { 86400 } else { 300 },
        },
        pinned,
        verifier,
    )
}
fn open_existing(store: &Path, definition: &Definition) -> Result<(Runtime, PendingRun), CliError> {
    open_existing_decision(store, definition).map(|(runtime, pending, _)| (runtime, pending))
}
fn open_existing_decision(
    store: &Path,
    definition: &Definition,
) -> Result<(Runtime, PendingRun, crate::generation::LoadedDecision), CliError> {
    let existing = router_runtime::observe(store, &definition.run_id).map_err(error)?;
    let proposal = definition
        .escalation_decision
        .as_deref()
        .map(crate::escalation::LoadedProposal::read)
        .transpose()?;
    if proposal.as_ref().is_some_and(|p| p.is_coordinator()) {
        return Err(CliError::Product("escalation.source.coordinator_required"));
    }
    if let Some(proposal) = &proposal {
        proposal.validate_store(store)?;
    }
    let runtime = crate::admission::open(
        store,
        RuntimeLimits {
            max_attempts: proposal
                .as_ref()
                .map_or(2, crate::escalation::LoadedProposal::max_attempts),
            output_retention: existing.output_retention,
            ..RuntimeLimits::default()
        },
        definition.admission.as_ref(),
    )
    .map_err(error)?;
    let (pending, loaded) = reopen_in(&runtime, definition, proposal.as_ref())?;
    Ok((runtime, pending, loaded))
}
/// What a replay export reads from a run definition. Nothing is re-routed: the
/// executed candidate is the one the runtime reopened from its stored record.
pub(crate) struct ReplaySource {
    pub(crate) request: router_types::PhaseRouteRequest,
    pub(crate) snapshot: HostObservation,
    pub(crate) catalog: serde_json::Value,
    pub(crate) policy: router_types::PhasePolicy,
    pub(crate) run: router_types::RunSummary,
    pub(crate) executed_candidate: String,
    pub(crate) uses_assets: bool,
}
pub(crate) fn replay_source(path: &Path, store: &Path) -> Result<ReplaySource, CliError> {
    let definition = load_definition(path)?;
    let (runtime, pending, loaded) = open_existing_decision(store, &definition)?;
    let request: router_types::PhaseRouteRequest =
        phases::read_json(&definition.context, router_policy::MAX_PHASE_REQUEST_BYTES)?;
    let snapshot: HostObservation = phases::read_json(&definition.host_snapshot, DOCUMENT_LIMIT)?;
    let checkpoint = runtime
        .capability_evidence_checkpoint(&definition.run_id)
        .map_err(error)?;
    let now = match checkpoint {
        Some((clock, _)) => clock,
        None => match &definition.asset_authority {
            Some(path) => crate::assets::historical_time(path)?,
            None => snapshot.observed_at_unix_seconds,
        },
    };
    let verifier = if crate::capability_proofs::has_claims(&snapshot) {
        let (_, sequence) = checkpoint.ok_or(CliError::Product(
            "capability.evidence.historical_clock_missing",
        ))?;
        Some(crate::capability_proofs::historical_through(
            store,
            Some(sequence),
        )?)
    } else {
        None
    };
    let (catalog, embedded) = crate::catalogs::load_with_verifier(
        &definition.catalog,
        Some(now),
        86400,
        verifier.as_deref(),
    )?;
    if embedded.is_some_and(|value| value.hash() != snapshot.snapshot_hash) {
        return Err(CliError::Product("catalog.snapshot.mismatch"));
    }
    let catalog = catalog
        .canonical_json()
        .map_err(|_| CliError::CatalogInvalid)
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|_| CliError::CatalogInvalid))?;
    // The same policy authority `context` resolves, without its active-artifact check.
    let policy = match (
        &definition.policy,
        &definition.policy_store,
        &definition.policy_artifact_id,
    ) {
        (Some(path), _, _) => phases::read_json(path, 64 * 1024)?,
        (None, Some(dir), Some(id)) => {
            if !dir.join("feedback.sqlite3").is_file() {
                return Err(CliError::Product("policy.store.unavailable"));
            }
            router_feedback::FeedbackStore::open(dir)
                .map_err(|_| CliError::Product("policy.store.invalid"))?
                .policy(id)
                .map_err(|_| CliError::Product("policy.artifact.invalid"))?
                .artifact
                .policy
        }
        _ => router_types::PhasePolicy::default(),
    };
    Ok(ReplaySource {
        request,
        snapshot,
        catalog,
        policy,
        run: pending.summary().clone(),
        executed_candidate: loaded.decision.selection().candidate.id.clone(),
        uses_assets: definition.asset_authority.is_some(),
    })
}
pub(crate) fn historical_context(
    runtime: &Runtime,
    definition: &Definition,
) -> Result<(PhaseRouter, ValidatedPhaseContext), CliError> {
    let observation: HostObservation =
        phases::read_json(&definition.host_snapshot, DOCUMENT_LIMIT)?;
    let checkpoint = runtime
        .capability_evidence_checkpoint(&definition.run_id)
        .map_err(error)?;
    let verifier = if crate::capability_proofs::has_claims(&observation) {
        let (_, sequence) = checkpoint.ok_or(CliError::Product(
            "capability.evidence.historical_clock_missing",
        ))?;
        Some(crate::capability_proofs::historical_through(
            runtime.storage_root(),
            Some(sequence),
        )?)
    } else {
        None
    };
    context_with_proofs(
        definition,
        true,
        verifier.as_deref(),
        checkpoint.map(|(clock, _)| clock),
    )
}

pub(crate) fn validate_proof_binary_pins(
    context: &ValidatedPhaseContext,
    config: &SandboxConfig,
    binaries: &BTreeMap<PathBuf, String>,
) -> Result<(), CliError> {
    let authenticated = context
        .revalidate_snapshot(router_adapter_api::SnapshotValidation {
            now_unix_seconds: crate::inspect::current_time(None)?,
            max_age_seconds: 300,
        })
        .map_err(|e| CliError::Snapshot(e.code()))?;
    for proof in authenticated.capability_proofs() {
        let program = if proof.binding.harness_id == "claude-code" {
            "claude"
        } else {
            proof.binding.harness_id.as_str()
        };
        let path = config
            .programs
            .get(program)
            .ok_or(CliError::Product("capability.evidence.program_missing"))?;
        if binaries.get(path) != Some(&proof.binding.binary_sha256)
            || binaries.get(&config.helper) != Some(&proof.binding.sandbox_helper_sha256)
        {
            return Err(CliError::Product("capability.evidence.binding_mismatch"));
        }
        #[cfg(target_os = "macos")]
        let wrapper = PathBuf::from("/usr/bin/sandbox-exec");
        #[cfg(not(target_os = "macos"))]
        let wrapper = config
            .bubblewrap
            .clone()
            .ok_or(CliError::Product("runtime.sandbox.configuration"))?;
        if binaries.get(&wrapper) != Some(&proof.binding.sandbox_wrapper_sha256) {
            return Err(CliError::Product("capability.evidence.binding_mismatch"));
        }
    }
    Ok(())
}

/// Reconstruct against an already-owned store; never acquire it recursively.
pub(crate) fn reopen_in(
    runtime: &Runtime,
    definition: &Definition,
    proposal: Option<&crate::escalation::LoadedProposal>,
) -> Result<(PendingRun, crate::generation::LoadedDecision), CliError> {
    if definition.escalation_decision.is_some() != proposal.is_some() {
        return Err(CliError::Product("escalation.runtime.required"));
    }
    let (router, context) = historical_context(runtime, definition)?;
    let proof = selection(definition, &router, &context)?;
    let request: ExecutionRequest = phases::read_json(
        &definition.request,
        router_adapter_api::MAX_EXECUTION_INPUT_BYTES,
    )?;
    let loaded = crate::generation::load_decision(
        definition.backend_decision.as_deref(),
        definition.generated_plan.as_deref(),
        proposal,
        Some(runtime),
        &definition.node_id,
        &router,
        &context,
        &proof,
        &crate::execution_backend::scope_hash(
            &request.workspace,
            &request.source_state,
            &request.scope,
        )?,
        true,
    )?;
    let plan = plan(&definition.plan)?;
    let workflow = workflow_contract(definition)?;
    let pending = runtime
        .reopen_decision(
            &definition.run_id,
            &router,
            &context,
            &loaded.decision,
            request,
            plan,
            &definition.node_id,
            workflow
                .as_ref()
                .map(|(contract, generation)| (contract, *generation)),
            None,
        )
        .map_err(error)?;
    Ok((pending, loaded))
}
pub(crate) fn adapter(
    host: &str,
    _config: &SandboxConfig,
) -> Result<Box<dyn HarnessAdapter>, CliError> {
    match host {
        #[cfg(feature = "codex")]
        "codex" => Ok(Box::new(adapter_codex::CodexAdapter)),
        #[cfg(feature = "claude")]
        "claude-code" => Ok(Box::new(adapter_claude::ClaudeAdapter)),
        #[cfg(feature = "opencode")]
        "opencode" => Ok(Box::new(
            adapter_opencode::OpenCodeAdapter::new(
                _config
                    .opencode
                    .clone()
                    .ok_or(CliError::Product("runtime.opencode.configuration_required"))?,
            )
            .map_err(|_| CliError::Product("runtime.opencode.configuration"))?,
        )),
        #[cfg(feature = "copilot")]
        "copilot" => Ok(Box::new(
            adapter_copilot::CopilotAdapter::new(
                _config
                    .copilot
                    .clone()
                    .ok_or(CliError::Product("runtime.copilot.configuration_required"))?,
            )
            .map_err(|_| CliError::Product("runtime.copilot.configuration"))?,
        )),
        _ => Err(CliError::Product("runtime.host.unavailable")),
    }
}
pub(crate) fn validate_adapter_config(host: &str, config: &SandboxConfig) -> Result<(), CliError> {
    // Preserve legacy/core-only review without optional host features. New
    // transports require their version/protocol pin even for a review.
    if matches!(host, "opencode" | "copilot") {
        adapter(host, config)?;
    }
    Ok(())
}
pub(crate) fn sandbox(path: &Path) -> Result<SandboxConfig, CliError> {
    let config: SandboxConfig = phases::read_json(path, 64 * 1024)?;
    if config.schema_version != 1
        || config.programs.is_empty()
        || config.programs.len() > 16
        || config.read_roots.len() > 32
        || config.environment_names.len() > 64
        || !config.helper.is_absolute()
        || config.bubblewrap.as_ref().is_some_and(|p| !p.is_absolute())
        || config.programs.values().any(|p| !p.is_absolute())
        || config.read_roots.iter().any(|p| !p.is_absolute())
        || config.environment_names.iter().any(|v| {
            v.is_empty()
                || v.len() > 128
                || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
    {
        return Err(CliError::Product("runtime.sandbox.configuration"));
    }
    Ok(config)
}
fn approval(
    pending: &PendingRun,
    config: &SandboxConfig,
    definition: &Definition,
    backend: Option<&crate::generation::SourceBinding>,
    store: &Path,
) -> Result<(String, BTreeMap<PathBuf, String>), CliError> {
    approval_for_digest(
        pending.approval_digest(),
        config,
        definition,
        backend,
        store,
    )
}

const BINARY_LIMIT: u64 = 256 * 1024 * 1024;

/// Streams a binary through SHA-256 in fixed blocks: memory stays constant.
/// Same open rules, bound and errors as `read_bounded`, and the same hex
/// digest as `content_digest` of the whole content.
fn binary_digest(path: &Path, limit: u64) -> Result<String, CliError> {
    use sha2::{Digest, Sha256};
    use std::io::Read as _;
    let mut file = crate::open_regular(path, CliError::RequestRead)?.take(limit + 1);
    let mut hasher = Sha256::new();
    let mut block = vec![0; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = match file.read(&mut block) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(CliError::RequestRead),
        };
        total += read as u64;
        if total > limit {
            return Err(CliError::RequestTooLarge);
        }
        hasher.update(&block[..read]);
    }
    Ok(hex(&hasher.finalize()))
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Configuration variables bound by value. Every other named variable, API
/// keys included, is bound only through a keyed MAC of its value.
const PLAIN_ENVIRONMENT: [&str; 4] = ["HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR", "SSL_CERT_FILE"];
const ENVIRONMENT_VALUE_DOMAIN: &[u8] = b"agent-router.approval.environment-hmac.v1";

/// What the approval binds for one named variable. A secret value never
/// appears here, only its HMAC-SHA256 under the runtime store's approval key:
/// the displayed digest cannot confirm a guessed key without that file.
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum EnvironmentBinding {
    Absent,
    Value { value: String },
    HmacSha256 { hmac_sha256: String },
}

fn environment_value_mac(
    key: &crate::approval_key::ApprovalKey,
    name: &str,
    value: &[u8],
) -> Result<String, CliError> {
    use hmac::{Hmac, Mac};
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(key.bytes()).map_err(|_| CliError::Internal)?;
    mac.update(ENVIRONMENT_VALUE_DOMAIN);
    mac.update(&[0]);
    mac.update(name.as_bytes());
    mac.update(&[0]);
    mac.update(value);
    Ok(hex(&mac.finalize().into_bytes()))
}

/// The approval key is loaded (or created) only when a secret value is bound.
fn environment_binding(
    names: &[String],
    lookup: impl Fn(&str) -> Option<OsString>,
    key: impl FnOnce() -> Result<crate::approval_key::ApprovalKey, CliError>,
) -> Result<BTreeMap<&str, EnvironmentBinding>, CliError> {
    let mut source = Some(key);
    let mut loaded = None;
    let mut bound = BTreeMap::new();
    for name in names {
        let value = match lookup(name).map(OsString::into_string) {
            None => {
                bound.insert(name.as_str(), EnvironmentBinding::Absent);
                continue;
            }
            Some(Ok(value)) if PLAIN_ENVIRONMENT.contains(&name.as_str()) => {
                bound.insert(name.as_str(), EnvironmentBinding::Value { value });
                continue;
            }
            Some(Ok(value)) => value.into_bytes(),
            // Not launchable either; bound so that any later change differs.
            Some(Err(value)) => value.into_encoded_bytes(),
        };
        if loaded.is_none() {
            let load = source.take().ok_or(CliError::Internal)?;
            loaded = Some(load()?);
        }
        let key = loaded.as_ref().ok_or(CliError::Internal)?;
        let hmac_sha256 = environment_value_mac(key, name, &value)?;
        bound.insert(
            name.as_str(),
            EnvironmentBinding::HmacSha256 { hmac_sha256 },
        );
    }
    Ok(bound)
}

/// The launch reads the named variables from this same process environment,
/// so a value changed between review and `--approve` changes the digest.
/// `store` is the runtime store directory holding the approval key.
pub(crate) fn approval_for_digest(
    inner_digest: &str,
    config: &SandboxConfig,
    definition: &Definition,
    backend: Option<&crate::generation::SourceBinding>,
    store: &Path,
) -> Result<(String, BTreeMap<PathBuf, String>), CliError> {
    approval_with_environment(
        inner_digest,
        config,
        definition,
        backend,
        |name| std::env::var_os(name),
        || crate::approval_key::load_or_create(store),
    )
}
fn approval_with_environment(
    inner_digest: &str,
    config: &SandboxConfig,
    definition: &Definition,
    backend: Option<&crate::generation::SourceBinding>,
    lookup: impl Fn(&str) -> Option<OsString>,
    key: impl FnOnce() -> Result<crate::approval_key::ApprovalKey, CliError>,
) -> Result<(String, BTreeMap<PathBuf, String>), CliError> {
    let environment = environment_binding(&config.environment_names, lookup, key)?;
    let mut hashes = BTreeMap::new();
    for path in config
        .programs
        .values()
        .chain(std::iter::once(&config.helper))
        .chain(config.bubblewrap.iter())
    {
        hashes.insert(path.clone(), binary_digest(path, BINARY_LIMIT)?);
    }
    #[cfg(target_os = "macos")]
    {
        let wrapper = PathBuf::from("/usr/bin/sandbox-exec");
        let digest = binary_digest(&wrapper, BINARY_LIMIT)?;
        hashes.insert(wrapper, digest);
    }
    // v7 binds execution from a private verified Codex/Claude entry copy.
    let bytes = if let Some(backend) = backend {
        serde_json::to_vec(&(
            if matches!(backend, crate::generation::SourceBinding::Escalated(_)) {
                "runtime-cli-approval-v7-escalation"
            } else {
                "runtime-cli-approval-v7-backend"
            },
            inner_digest,
            definition,
            config,
            &hashes,
            &environment,
            backend,
        ))
    } else {
        serde_json::to_vec(&(
            "runtime-cli-approval-v7",
            inner_digest,
            definition,
            config,
            &hashes,
            &environment,
        ))
    }
    .map_err(|_| CliError::Internal)?;
    Ok((content_digest(&bytes), hashes))
}
/// Recompute the binding from the exact local execution configuration. Hashing
/// compiled source is conservative: even a non-behavioral edit voids old proofs.
pub(crate) fn capability_binding(
    config: &SandboxConfig,
    host: &router_types::HostSnapshot,
    version: &str,
    write_roots: std::collections::BTreeSet<String>,
    network: bool,
) -> Result<router_adapter_api::CapabilityProofBinding, CliError> {
    let (program, template) = match host.harness.as_str() {
        "codex" => (
            "codex",
            include_str!("../../adapter-codex/src/execution.rs"),
        ),
        "claude-code" => (
            "claude",
            include_str!("../../adapter-claude/src/execution.rs"),
        ),
        "opencode" => (
            "opencode",
            include_str!("../../adapter-opencode/src/lib.rs"),
        ),
        "copilot" => ("copilot", include_str!("../../adapter-copilot/src/lib.rs")),
        _ => return Err(CliError::Product("capability.evidence.host_unavailable")),
    };
    let binary = config
        .programs
        .get(program)
        .ok_or(CliError::Product("capability.evidence.program_missing"))?;
    #[cfg(target_os = "macos")]
    let wrapper = PathBuf::from("/usr/bin/sandbox-exec");
    #[cfg(not(target_os = "macos"))]
    let wrapper = config
        .bubblewrap
        .clone()
        .ok_or(CliError::Product("runtime.sandbox.configuration"))?;
    let profile = serde_json::to_vec(&(
        "capability-profile-v1",
        include_str!("../../router-runtime/src/sandbox.rs"),
        include_str!("../../router-runtime/src/bubblewrap.rs"),
        include_str!("../../router-runtime/src/host_state.rs"),
        include_str!("../../router-runtime/src/private_program.rs"),
        serde_json::to_value(config).map_err(|_| CliError::Internal)?,
        &write_roots,
        network,
    ))
    .map_err(|_| CliError::Internal)?;
    Ok(router_adapter_api::CapabilityProofBinding {
        harness_id: host.harness.to_string(),
        host_snapshot_id: host.id.clone(),
        binary_sha256: binary_digest(binary, BINARY_LIMIT)?,
        observed_version: version.into(),
        adapter_id: host.harness.to_string(),
        argument_template_sha256: content_digest(template.as_bytes()),
        sandbox_helper_sha256: binary_digest(&config.helper, BINARY_LIMIT)?,
        sandbox_wrapper_sha256: binary_digest(&wrapper, BINARY_LIMIT)?,
        sandbox_profile_sha256: content_digest(&profile),
        write_roots,
        network,
        os: std::env::consts::OS.into(),
    })
}

pub(crate) async fn supervisor(
    store: &Path,
    config: SandboxConfig,
    expected: &BTreeMap<PathBuf, String>,
) -> Result<Box<dyn SandboxSupervisor>, CliError> {
    let environment = config
        .environment_names
        .iter()
        .map(|name| {
            std::env::var(name)
                .map(|value| (name.clone(), value))
                .map_err(|_| CliError::Product("runtime.environment.unavailable"))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let private_dir = std::fs::canonicalize(store).map_err(|_| CliError::Product("runtime.io"))?;
    #[cfg(target_os = "macos")]
    {
        if config.bubblewrap.is_some() {
            return Err(CliError::Product("runtime.sandbox.configuration"));
        }
        let native = router_runtime::SeatbeltSandbox::probe_expected(
            &private_dir,
            config.programs,
            config.read_roots,
            environment,
            expected,
        )
        .await
        .map_err(error)?;
        Ok(Box::new(
            ResourceSupervisor::probe_expected(
                &config.helper,
                config.limits.into(),
                native,
                expected,
            )
            .await
            .map_err(error)?,
        ))
    }
    #[cfg(target_os = "linux")]
    {
        let wrapper = config
            .bubblewrap
            .ok_or(CliError::Product("runtime.sandbox.bubblewrap.required"))?;
        let native = router_runtime::BubblewrapSandbox::probe_expected(
            &private_dir,
            &wrapper,
            config.programs,
            config.read_roots,
            environment,
            expected,
        )
        .await
        .map_err(error)?;
        Ok(Box::new(
            ResourceSupervisor::probe_expected(
                &config.helper,
                config.limits.into(),
                native,
                expected,
            )
            .await
            .map_err(error)?,
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (private_dir, config, environment);
        Err(CliError::Product("runtime.sandbox.unsupported"))
    }
}

pub(crate) fn run(
    definition: &Path,
    store: &Path,
    config: &Path,
    approve: Option<&str>,
    retry: bool,
    json: bool,
) -> Result<Outcome, CliError> {
    require_json(json)?;
    let definition = load_definition(definition)?;
    if approve.is_some() {
        require_asset_authority(&definition)?;
    }
    let config = sandbox(config)?;
    let feedback_path = config.feedback_store.clone();
    let feedback_consent = crate::execution_feedback::consent(feedback_path.as_deref())?;
    block(async {
        let observation: HostObservation =
            phases::read_json(&definition.host_snapshot, DOCUMENT_LIMIT)?;
        let proof_request: ExecutionRequest = phases::read_json(
            &definition.request,
            router_adapter_api::MAX_EXECUTION_INPUT_BYTES,
        )?;
        let proof_verifier = if crate::capability_proofs::has_claims(&observation) {
            Some(crate::capability_proofs::fresh(
                store,
                &config,
                &observation,
                Some((
                    &proof_request.scope,
                    proof_request
                        .required_capabilities
                        .contains(&router_types::Capability::Network),
                )),
            )?)
        } else {
            None
        };
        let (router, context) = context_with_proofs(
            &definition,
            false,
            proof_verifier
                .as_deref()
                .map(|v| v as &dyn router_adapter_api::CapabilityProofVerifier),
            None,
        )?;
        let proof = selection(&definition, &router, &context)?;
        let workflow = workflow_contract(&definition)?;
        let request: ExecutionRequest = phases::read_json(
            &definition.request,
            router_adapter_api::MAX_EXECUTION_INPUT_BYTES,
        )?;
        let proposal = definition
            .escalation_decision
            .as_deref()
            .map(crate::escalation::LoadedProposal::read)
            .transpose()?;
        if proposal.as_ref().is_some_and(|p| p.is_coordinator()) {
            return Err(CliError::Product("escalation.source.coordinator_required"));
        }
        if let Some(proposal) = &proposal {
            proposal.validate_store(store)?;
        }
        let open_runtime = || {
            crate::admission::open(
                store,
                RuntimeLimits {
                    max_attempts: proposal
                        .as_ref()
                        .map_or(2, crate::escalation::LoadedProposal::max_attempts),
                    output_retention: config.output_retention,
                    ..RuntimeLimits::default()
                },
                definition.admission.as_ref(),
            )
            .map_err(error)
            .map(|runtime| match &proof_verifier {
                Some(verifier) => runtime.with_capability_proof_verifier(verifier.clone()),
                None => runtime,
            })
        };
        // Only escalation needs an existing owned journal while reconstructing.
        // Invalid ordinary/backend/generated inputs still cannot create a store.
        let runtime = if proposal.is_some() {
            Some(open_runtime()?)
        } else {
            None
        };
        let loaded = crate::generation::load_decision(
            definition.backend_decision.as_deref(),
            definition.generated_plan.as_deref(),
            proposal.as_ref(),
            runtime.as_ref(),
            &definition.node_id,
            &router,
            &context,
            &proof,
            &crate::execution_backend::scope_hash(
                &request.workspace,
                &request.source_state,
                &request.scope,
            )?,
            false,
        )?;
        let host = request.host.as_str().to_owned();
        validate_adapter_config(&host, &config)?;
        let runtime = runtime.map_or_else(open_runtime, Ok)?;
        let display = serde_json::json!({"host": request.host, "model": request.model, "effort": request.effort,
            "scope": request.scope, "sandbox": request.sandbox, "tools": request.tools,
            "prompt_sha256": content_digest(request.prompt.as_bytes()), "resource_limits": config.limits});
        let pending = runtime
            .review_decision(
                &definition.run_id,
                &router,
                &context,
                &loaded.decision,
                request,
                plan(&definition.plan)?,
                &definition.node_id,
                workflow
                    .as_ref()
                    .map(|(contract, generation)| (contract, *generation)),
                None,
            )
            .await
            .map_err(error)?;
        // The approval (binary hashes included) is computed once per invocation.
        let (pending, (digest, binaries)) = if retry {
            // Read-only preview first: nothing is persisted until the caller
            // presents the digest of this exact preview with `--approve`.
            let preview = runtime.preview_retry(&pending).map_err(error)?;
            let computed = approval(
                &preview,
                &config,
                &definition,
                loaded.binding.as_ref(),
                store,
            )?;
            match approve {
                None => (preview, computed),
                Some(approved) => {
                    if approved != computed.0 {
                        return Err(CliError::Product("runtime.approval.required_or_changed"));
                    }
                    // The store re-checks the inner digest inside its transaction.
                    let inner = preview.approval_digest().to_owned();
                    let retried = runtime.retry_approved(pending, &inner).map_err(error)?;
                    // The approved digest covers the previewed inner digest only.
                    if retried.approval_digest() != inner {
                        return Err(CliError::Product("runtime.approval.required_or_changed"));
                    }
                    (retried, computed)
                }
            }
        } else if approve.is_some()
            && matches!(
                pending.summary().state,
                router_types::RunState::Failed | router_types::RunState::TimedOut
            )
        {
            // A failed run needs a fresh approval: `--retry --approve <digest>`.
            return Err(CliError::Product("runtime.retry.use_retry_approve"));
        } else {
            let computed = approval(
                &pending,
                &config,
                &definition,
                loaded.binding.as_ref(),
                store,
            )?;
            (pending, computed)
        };
        if let Some(verifier) = &proof_verifier {
            let authenticated =
                router_adapter_api::ValidatedHostObservation::from_observation_with_verifier(
                    observation.clone(),
                    router_adapter_api::SnapshotValidation {
                        now_unix_seconds: crate::inspect::current_time(None)?,
                        max_age_seconds: 300,
                    },
                    Some(verifier.as_ref()),
                )
                .map_err(|e| CliError::Snapshot(e.code()))?;
            for proof in authenticated.capability_proofs() {
                let program = if proof.binding.harness_id == "claude-code" {
                    "claude"
                } else {
                    proof.binding.harness_id.as_str()
                };
                let path = config
                    .programs
                    .get(program)
                    .ok_or(CliError::Product("capability.evidence.program_missing"))?;
                if binaries.get(path) != Some(&proof.binding.binary_sha256)
                    || binaries.get(&config.helper) != Some(&proof.binding.sandbox_helper_sha256)
                {
                    return Err(CliError::Product("capability.evidence.binding_mismatch"));
                }
                #[cfg(target_os = "macos")]
                let wrapper = PathBuf::from("/usr/bin/sandbox-exec");
                #[cfg(not(target_os = "macos"))]
                let wrapper = config
                    .bubblewrap
                    .clone()
                    .ok_or(CliError::Product("runtime.sandbox.configuration"))?;
                if binaries.get(&wrapper) != Some(&proof.binding.sandbox_wrapper_sha256) {
                    return Err(CliError::Product("capability.evidence.binding_mismatch"));
                }
            }
        }
        let Some(approved) = approve else {
            return json_output(
                &serde_json::json!({"schema_version":1,"run":pending.summary(),"approval_digest":digest,
                "request":display,"sandbox_configuration":config,"binary_hashes":binaries,"execution_decision":loaded.decision.binding(),"generated_decision":loaded.decision.generated_binding(),"escalation_decision":loaded.decision.escalation_binding(),"decision_origin":loaded.decision.origin(),"baseline_receipt_id":loaded.decision.baseline().receipt_id,"executed":false}),
                ExitCode::SUCCESS,
            );
        };
        if approved != digest {
            return Err(CliError::Product("runtime.approval.required_or_changed"));
        }
        if !runtime.dependencies_ready(&pending).map_err(error)? {
            // This command owns one step. Release the store owner so a separate
            // invocation can run its prerequisites; do not wait holding the lock.
            let inner_digest = pending.approval_digest().to_owned();
            if pending.summary().state == router_types::RunState::Queued {
                runtime
                    .resume_approved(pending, &inner_digest)
                    .map_err(error)?;
            } else {
                runtime.approve(pending, &inner_digest).map_err(error)?;
            }
            return json_output(
                &serde_json::json!({"schema_version":1,"run":router_runtime::observe(store,&definition.run_id).map_err(error)?,"executed":false,"dependencies_pending":true,"approval_digest":digest}),
                ExitCode::from(3),
            );
        }
        let adapter = adapter(&host, &config)?;
        let supervisor = supervisor(store, config, &binaries).await?;
        let inner_digest = pending.approval_digest().to_owned();
        let approved = if pending.summary().state == router_types::RunState::Queued {
            runtime
                .resume_approved(pending, &inner_digest)
                .map_err(error)?
        } else {
            runtime.approve(pending, &inner_digest).map_err(error)?
        };
        let cancel = Cancellation::default();
        let interrupt = cancel.clone();
        let listener = tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                interrupt.cancel();
            }
        });
        let started_at = crate::inspect::current_time(None).ok();
        let completed = runtime
            .execute_decision(
                approved,
                adapter.as_ref(),
                supervisor.as_ref(),
                cancel,
                loaded.authority(),
            )
            .await;
        listener.abort();
        let completed = completed.map_err(error)?;
        let feedback = crate::execution_feedback::record(
            feedback_path.as_deref(),
            feedback_consent.as_ref(),
            &loaded.decision,
            &context,
            &completed,
            started_at,
        );
        let code = if completed.transport.exit_code == Some(0)
            && completed.transport.termination == router_types::TransportTermination::Exited
            && matches!(
                completed.run.state,
                router_types::RunState::SucceededTransport
                    | router_types::RunState::Verifying
                    | router_types::RunState::Verified
            ) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(3)
        };
        json_output(
            &serde_json::json!({"schema_version":1,"completion":completed,"feedback":feedback}),
            code,
        )
    })
}

pub(crate) fn require_asset_authority(definition: &Definition) -> Result<(), CliError> {
    if definition.asset_authority.is_none() {
        return Err(CliError::Product("runtime.asset_authority.required"));
    }
    Ok(())
}
pub(crate) fn status(store: &Path, id: &str, json: bool) -> Result<Outcome, CliError> {
    require_json(json)?;
    json_output(
        &serde_json::json!({"schema_version":1,"run":router_runtime::observe(store,id).map_err(error)?,"cleanup_evidence":router_runtime::observe_cleanup(store,id).map_err(error)?}),
        ExitCode::SUCCESS,
    )
}
pub(crate) fn cancel(store: &Path, id: &str, json: bool) -> Result<Outcome, CliError> {
    require_json(json)?;
    router_runtime::request_cancel(store, id).map_err(error)?;
    json_output(
        &serde_json::json!({"schema_version":1,"run_id":id,"cancellation_requested":true}),
        ExitCode::SUCCESS,
    )
}
pub(crate) fn events(store: &Path, id: &str, json: bool) -> Result<Outcome, CliError> {
    require_json(json)?;
    json_output(
        &serde_json::json!({"schema_version":1,"events":router_runtime::observe_events(store,id).map_err(error)?}),
        ExitCode::SUCCESS,
    )
}
pub(crate) fn source_state(workspace: &Path, json: bool) -> Result<Outcome, CliError> {
    require_json(json)?;
    block(async {
        json_output(
            &serde_json::json!({"schema_version":1,"source_state":router_runtime::source_state(workspace).await.map_err(error)?}),
            ExitCode::SUCCESS,
        )
    })
}
pub(crate) fn workflow(
    path: &Path,
    contract: Option<&Path>,
    seal: bool,
    json: bool,
) -> Result<Outcome, CliError> {
    require_json(json)?;
    let plan = plan(path)?;
    let contract = contract
        .map(|path| {
            let contract = phases::read_json(path, DOCUMENT_LIMIT)?;
            if seal {
                router_workflow::seal_execution_contract(contract, &plan)
                    .map_err(|_| CliError::Product("workflow.contract.invalid"))
            } else {
                router_workflow::validate_execution_contract(&contract, &plan)
                    .map_err(|_| CliError::Product("workflow.contract.invalid"))?;
                Ok(contract)
            }
        })
        .transpose()?;
    json_output(
        &serde_json::json!({"schema_version":1,"plan":plan,"execution_contract":contract,"valid":true,"approved":false}),
        ExitCode::SUCCESS,
    )
}
/// Only `feedback_store` is read from the configuration. It is validated before
/// the operation, while nothing has changed; a feedback failure after it never
/// fails the command.
pub(crate) fn late_feedback_store(config: Option<&Path>) -> Result<Option<PathBuf>, CliError> {
    Ok(config
        .map(sandbox)
        .transpose()?
        .and_then(|c| c.feedback_store))
}
pub(crate) fn verify(
    definition: &Path,
    store: &Path,
    evidence: &Path,
    config: Option<&Path>,
    json: bool,
) -> Result<Outcome, CliError> {
    require_json(json)?;
    let definition = load_definition(definition)?;
    let record: router_types::VerificationRecord = phases::read_json(evidence, 64 * 1024)?;
    let feedback_path = late_feedback_store(config)?;
    let (runtime, pending) = open_existing(store, &definition)?;
    let run = runtime
        .record_verification(&pending, record.clone())
        .map_err(error)?;
    let feedback = crate::execution_feedback::record_verification_fact(
        feedback_path.as_deref(),
        pending.summary(),
        &record,
        &run,
    );
    json_output(
        &serde_json::json!({"schema_version":1,"run":run,"feedback":feedback}),
        ExitCode::SUCCESS,
    )
}
/// Reopen is historical; mutation needs current executable/configuration pins.
/// This does not invoke a host or grant a native permission.
pub(crate) fn integration_verifier(
    store: &Path,
    definition: &Definition,
    config: Option<&Path>,
) -> Result<Option<std::sync::Arc<dyn router_adapter_api::CapabilityProofVerifier>>, CliError> {
    let observation: HostObservation =
        phases::read_json(&definition.host_snapshot, DOCUMENT_LIMIT)?;
    if !crate::capability_proofs::has_claims(&observation) {
        return Ok(None);
    }
    let config = sandbox(config.ok_or(CliError::Product("capability.config.required"))?)?;
    let request: ExecutionRequest = phases::read_json(
        &definition.request,
        router_adapter_api::MAX_EXECUTION_INPUT_BYTES,
    )?;
    Ok(Some(crate::capability_proofs::fresh(
        store,
        &config,
        &observation,
        Some((
            &request.scope,
            request
                .required_capabilities
                .contains(&router_types::Capability::Network),
        )),
    )?))
}
/// Publication pins the semantic configuration and original requested scope.
/// Every proof check reloads configuration and executable identities; formatting
/// changes alone are harmless. No host is invoked and no authority is issued.
struct PublicationVerifier {
    store: PathBuf,
    config: PathBuf,
    config_sha256: String,
    observation: HostObservation,
    scope: Vec<String>,
    network: bool,
}
impl PublicationVerifier {
    fn new(
        store: &Path,
        config: &Path,
        observation: HostObservation,
        scope: Vec<String>,
        network: bool,
    ) -> Result<Self, CliError> {
        let parsed = sandbox(config)?;
        let verifier = Self {
            store: store.to_owned(),
            config: config.to_owned(),
            config_sha256: router_adapter_api::content_digest(
                &serde_json::to_vec(&parsed).map_err(|_| CliError::Internal)?,
            ),
            observation,
            scope,
            network,
        };
        verifier.current()?;
        Ok(verifier)
    }
    fn current(
        &self,
    ) -> Result<std::sync::Arc<router_runtime::StoredCapabilityProofVerifier>, CliError> {
        let parsed = sandbox(&self.config)?;
        let hash = router_adapter_api::content_digest(
            &serde_json::to_vec(&parsed).map_err(|_| CliError::Internal)?,
        );
        if hash != self.config_sha256 {
            return Err(CliError::Product("capability.config.changed"));
        }
        crate::capability_proofs::fresh(
            &self.store,
            &parsed,
            &self.observation,
            Some((&self.scope, self.network)),
        )
    }
}
impl router_adapter_api::CapabilityProofVerifier for PublicationVerifier {
    fn verify(
        &self,
        source: &router_adapter_api::EvidenceSource,
        capability: router_types::Capability,
        host: &router_types::HostSnapshot,
        now: u64,
    ) -> Result<router_adapter_api::VerifiedCapabilityProof, router_adapter_api::CapabilityProofError>
    {
        let verifier = self
            .current()
            .map_err(|_| router_adapter_api::CapabilityProofError::Unauthenticated)?;
        let now = publication_clock(now)?;
        current_publication_proof(verifier.verify(source, capability, host, now)?, now)
    }
    fn verify_attestation(
        &self,
        reference: &router_adapter_api::CapabilityAttestationReference,
        host: &router_types::HostSnapshot,
        now: u64,
    ) -> Result<router_adapter_api::VerifiedCapabilityProof, router_adapter_api::CapabilityProofError>
    {
        let verifier = self
            .current()
            .map_err(|_| router_adapter_api::CapabilityProofError::Unauthenticated)?;
        let now = publication_clock(now)?;
        current_publication_proof(verifier.verify_attestation(reference, host, now)?, now)
    }
}
fn publication_clock(now: u64) -> Result<u64, router_adapter_api::CapabilityProofError> {
    crate::inspect::current_time(None)
        .map(|clock| clock.max(now))
        .map_err(|_| router_adapter_api::CapabilityProofError::Unauthenticated)
}
fn current_publication_proof(
    proof: router_adapter_api::VerifiedCapabilityProof,
    now: u64,
) -> Result<router_adapter_api::VerifiedCapabilityProof, router_adapter_api::CapabilityProofError> {
    // Hashing executables and authenticating the log can cross an expiry.
    if publication_clock(now)? > proof.expires_at_unix_seconds {
        return Err(router_adapter_api::CapabilityProofError::Expired);
    }
    Ok(proof)
}
pub(crate) fn publication_verifier(
    store: &Path,
    definition: &Definition,
    config: Option<&Path>,
) -> Result<Option<std::sync::Arc<dyn router_adapter_api::CapabilityProofVerifier>>, CliError> {
    let observation: HostObservation =
        phases::read_json(&definition.host_snapshot, DOCUMENT_LIMIT)?;
    if !crate::capability_proofs::has_claims(&observation) {
        return Ok(None);
    }
    let config = config.ok_or(CliError::Product("capability.config.required"))?;
    let request: ExecutionRequest = phases::read_json(
        &definition.request,
        router_adapter_api::MAX_EXECUTION_INPUT_BYTES,
    )?;
    Ok(Some(std::sync::Arc::new(PublicationVerifier::new(
        store,
        config,
        observation,
        request.scope,
        request
            .required_capabilities
            .contains(&router_types::Capability::Network),
    )?)))
}
pub(crate) fn artifacts(
    definition: &Path,
    store: &Path,
    command: ArtifactCommand,
    config: Option<&Path>,
    json: bool,
) -> Result<Outcome, CliError> {
    require_json(json)?;
    let definition = load_definition(definition)?;
    let feedback_path = late_feedback_store(config)?;
    let (runtime, pending) = open_existing(store, &definition)?;
    let verifier = match &command {
        ArtifactCommand::Publish { .. } => publication_verifier(store, &definition, config)?,
        ArtifactCommand::Apply { .. } => integration_verifier(store, &definition, config)?,
        _ => None,
    };
    let runtime = match verifier {
        Some(verifier) => runtime.with_capability_proof_verifier(verifier),
        None => runtime,
    };
    let integration = |outcome| {
        crate::execution_feedback::record_fact(
            feedback_path.as_deref(),
            pending.summary(),
            router_types::FeedbackFactKind::Integration { outcome },
        )
    };
    block(async {
        let value = match command {
            ArtifactCommand::Declared => {
                serde_json::json!({"schema_version":1,"artifacts":runtime.declared_artifacts(&definition.run_id).map_err(error)?})
            }
            ArtifactCommand::PurgeDeclared { id } => {
                if !runtime
                    .declared_artifacts(&definition.run_id)
                    .map_err(error)?
                    .iter()
                    .any(|a| a.artifact_id == id)
                {
                    return Err(CliError::Product("runtime.artifact.outside_run"));
                }
                serde_json::json!({"schema_version":1,"purged":runtime.purge_declared_artifact(&id).map_err(error)?})
            }
            ArtifactCommand::Outputs => {
                serde_json::json!({"schema_version":1,"outputs":runtime.output_artifacts(&definition.run_id).map_err(error)?})
            }
            ArtifactCommand::PurgeOutputs { attempt } => {
                serde_json::json!({"schema_version":1,"purged":runtime.purge_output_artifacts(&definition.run_id,attempt).map_err(error)?})
            }
            ArtifactCommand::ReviewPublication => {
                serde_json::json!({"schema_version":1,"review":runtime.review_publication(&pending).await.map_err(error)?})
            }
            ArtifactCommand::CheckPublicationReview { review } => {
                let review = phases::read_json(&review, 128 * 1024 * 1024)?;
                runtime
                    .validate_publication_review(&pending, &review)
                    .await
                    .map_err(error)?;
                serde_json::json!({"schema_version":1,"review":review})
            }
            ArtifactCommand::Publish { approve } => {
                serde_json::json!({"schema_version":1,"publication":runtime.publish_patch(&pending, &approve).await.map_err(error)?})
            }
            ArtifactCommand::PublicationStatus => {
                let status = runtime.publication_status(&pending).await.map_err(error)?;
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
                serde_json::json!({"schema_version":1,"preview":runtime.integration_preview(&pending).await.map_err(error)?})
            }
            ArtifactCommand::Apply { approve } => {
                let applied = runtime.apply(&pending, &approve).await.map_err(error)?;
                serde_json::json!({"schema_version":1,"applied":applied,"feedback":integration(router_types::IntegrationOutcome::Applied)})
            }
            ArtifactCommand::Discard { approve } => {
                runtime.discard(&pending, &approve).await.map_err(error)?;
                serde_json::json!({"schema_version":1,"discarded":true,"feedback":integration(router_types::IntegrationOutcome::Discarded)})
            }
            ArtifactCommand::Keep => {
                serde_json::json!({"schema_version":1,"kept":true,"run":pending.summary()})
            }
        };
        json_output(&value, ExitCode::SUCCESS)
    })
}

#[cfg(test)]
mod adapter_configuration_tests {
    use super::*;
    use crate::approval_key::ApprovalKey;
    use serde_json::json;

    fn config_value() -> serde_json::Value {
        // Hash-only fixture: the test executable is a regular file on every
        // runner. /bin/sh is a symlink on Linux and must fail no-follow reads.
        let executable = std::env::current_exe().unwrap();
        json!({"schema_version":1,"programs":{"codex":executable},"read_roots":[],
            "environment_names":[],"helper":executable,"bubblewrap":null,
            "limits":{"cpu_seconds":5,"address_space_bytes":null,"max_open_files":64,
                "max_processes":64,"max_file_bytes":1048576},"feedback_store":null,
            "output_retention":{"mode":"none"}})
    }
    fn definition() -> Definition {
        serde_json::from_value(
            json!({"schema_version":1,"run_id":"run-1","context":"context.json",
            "host_snapshot":"host.json","catalog":"catalog.json","plan":"plan.json",
            "node_id":"execute","request":"request.json"}),
        )
        .unwrap()
    }
    #[cfg(feature = "codex")]
    #[test]
    fn publication_verifier_refreshes_config_and_executable_between_checks() {
        use router_adapter_api::{
            CapabilityAttemptOutcome, CapabilityProofKey, CapabilityProofRecord,
            CapabilityProofTier, CapabilityProofVerifier, EvidenceKind, EvidenceSource,
        };
        use std::os::unix::fs::PermissionsExt;
        for expired in [false, true] {
            let clock =
                crate::inspect::current_time(None).unwrap_or_else(|e| panic!("{}", e.code()));
            let temp = tempfile::tempdir().unwrap();
            let store = temp.path().join("store");
            std::fs::create_dir(&store).unwrap();
            std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
            let secret = [42u8; 32];
            std::fs::write(store.join("approval.key"), secret).unwrap();
            std::fs::set_permissions(
                store.join("approval.key"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let binary = temp.path().join("fixture-binary");
            std::fs::write(&binary, b"original fake executable").unwrap();
            let config_path = temp.path().join("config.json");
            let mut config = config_value();
            config["output_retention"] =
                serde_json::to_value(router_types::OutputRetentionPolicy::default()).unwrap();
            config["programs"]["codex"] = json!(binary);
            config["helper"] = json!(binary);
            config["bubblewrap"] = json!(binary);
            std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
            let mut observation: HostObservation = serde_json::from_str(include_str!(
                "../../../fixtures/examples/phase-snapshot.json"
            ))
            .unwrap();
            observation.evidence.clear();
            let binding = capability_binding(
                &sandbox(&config_path).unwrap_or_else(|e| panic!("{}", e.code())),
                &observation.host,
                "fixture-v1",
                std::collections::BTreeSet::from(["src".into()]),
                false,
            )
            .unwrap_or_else(|e| panic!("{}", e.code()));
            let mut proofs = router_runtime::CapabilityProofStore::create(&store).unwrap();
            let proof = CapabilityProofKey::derive(&secret, proofs.store_id())
                .unwrap()
                .authenticate(CapabilityProofRecord {
                    schema_version: 1,
                    proof_id: "refresh-fixture".into(),
                    sequence: 1,
                    store_id: proofs.store_id().into(),
                    capability: router_types::Capability::WorkspaceWrite,
                    tier: CapabilityProofTier::Proven,
                    network_scope: None,
                    binding,
                    model_id: "fixture-model".into(),
                    nonce_sha256: "7".repeat(64),
                    expected_effect_sha256: "8".repeat(64),
                    started_at_unix_seconds: clock - 20,
                    ended_at_unix_seconds: clock - 10,
                    max_age_seconds: if expired { 5 } else { 1000 },
                    outcome: CapabilityAttemptOutcome::Succeeded,
                })
                .unwrap();
            proofs.append(&proof, &secret).unwrap();
            let source = EvidenceSource {
                id: proof.record.proof_id.clone(),
                kind: EvidenceKind::HostRuntime,
                observed_version: Some("fixture-v1".into()),
                observed_at_unix_seconds: clock - 10,
                content_sha256: proof.digest().unwrap(),
            };
            let verifier = PublicationVerifier::new(
                &store,
                &config_path,
                observation.clone(),
                vec!["src".into()],
                false,
            )
            .unwrap_or_else(|e| panic!("{}", e.code()));
            if expired {
                assert!(
                    verifier
                        .verify(
                            &source,
                            router_types::Capability::WorkspaceWrite,
                            &observation.host,
                            clock - 9
                        )
                        .is_err(),
                    "publication reused caller clock after refreshing pins"
                );
                continue;
            }
            assert!(
                verifier
                    .verify(
                        &source,
                        router_types::Capability::WorkspaceWrite,
                        &observation.host,
                        clock - 9
                    )
                    .is_ok()
            );
            std::fs::write(&binary, b"replacement executable").unwrap();
            assert!(
                verifier
                    .verify(
                        &source,
                        router_types::Capability::WorkspaceWrite,
                        &observation.host,
                        clock - 9
                    )
                    .is_err(),
                "publication reused old executable pins"
            );
            std::fs::write(&binary, b"original fake executable").unwrap();
            assert!(
                verifier
                    .verify(
                        &source,
                        router_types::Capability::WorkspaceWrite,
                        &observation.host,
                        clock - 9
                    )
                    .is_ok()
            );
            config["limits"]["max_file_bytes"] = json!(2048);
            std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
            assert!(
                verifier
                    .verify(
                        &source,
                        router_types::Capability::WorkspaceWrite,
                        &observation.host,
                        clock - 9
                    )
                    .is_err(),
                "publication reused old configuration pins"
            );
        }
    }
    #[test]
    fn absent_optional_host_config_keeps_legacy_approval_serialization() {
        // Start from the actual serde default for retention, whose wire shape
        // is owned by router-types rather than duplicated by this test.
        let mut value = config_value();
        value["output_retention"] =
            serde_json::to_value(router_types::OutputRetentionPolicy::default()).unwrap();
        let config: SandboxConfig = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(config).unwrap(), value);
    }
    #[cfg(any(feature = "opencode", feature = "copilot"))]
    #[test]
    fn protocol_and_version_configuration_are_bound_to_execution_approval() {
        let mut value = config_value();
        value["output_retention"] =
            serde_json::to_value(router_types::OutputRetentionPolicy::default()).unwrap();
        #[cfg(feature = "opencode")]
        let (host, extension) = (
            "opencode",
            json!({"schema_version":1,"expected_cli_version":"1.0.0-fixture",
            "protocol":"run_v1","model_variants":{"synthetic/model-v1":{"high":"provider-high"}}}),
        );
        #[cfg(all(not(feature = "opencode"), feature = "copilot"))]
        let (host, extension) = (
            "copilot",
            json!({"schema_version":1,"expected_cli_version":"1.0.0-fixture",
            "protocol":"cli_jsonl_v1"}),
        );
        let absent: SandboxConfig = serde_json::from_value(value.clone()).unwrap();
        assert!(adapter(host, &absent).is_err());
        value[host] = extension;
        let original: SandboxConfig = serde_json::from_value(value.clone()).unwrap();
        assert!(
            adapter(host, &original)
                .unwrap_or_else(|_| panic!("valid adapter config"))
                .requires_native_version()
        );
        // No secret variable is named, so the store key is never read.
        let store = Path::new("/nonexistent/runtime");
        let before = approval_for_digest(&"a".repeat(64), &original, &definition(), None, store)
            .unwrap_or_else(|_| panic!("valid approval fixture"));
        value[host]["expected_cli_version"] = json!("1.0.1-fixture");
        let changed: SandboxConfig = serde_json::from_value(value).unwrap();
        let after = approval_for_digest(&"a".repeat(64), &changed, &definition(), None, store)
            .unwrap_or_else(|_| panic!("valid changed fixture"));
        assert_eq!(
            before.1, after.1,
            "binary identity unchanged by version requirement"
        );
        assert_ne!(
            before.0, after.0,
            "configuration change requires fresh approval"
        );
    }
    fn environment(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
        let values: BTreeMap<&'static str, &'static str> = pairs.iter().copied().collect();
        move |name| values.get(name).map(OsString::from)
    }
    #[test]
    fn approval_binds_plain_values_and_keyed_macs_of_secret_values() {
        let mut value = config_value();
        value["environment_names"] = json!(["HOME", "SSL_CERT_FILE", "OPENAI_API_KEY"]);
        value["output_retention"] =
            serde_json::to_value(router_types::OutputRetentionPolicy::default()).unwrap();
        let config: SandboxConfig = serde_json::from_value(value).unwrap();
        let secret = "sk-unit-secret-value";
        let base = [
            ("HOME", "/home/a"),
            ("SSL_CERT_FILE", "/etc/a.pem"),
            ("OPENAI_API_KEY", secret),
        ];
        let keyed = |pairs: &[(&'static str, &'static str)], key: u8| {
            approval_with_environment(
                &"a".repeat(64),
                &config,
                &definition(),
                None,
                environment(pairs),
                || Ok(ApprovalKey::fixed(key)),
            )
            .unwrap_or_else(|_| panic!("valid approval fixture"))
        };
        let digest = |pairs: &[(&'static str, &'static str)]| keyed(pairs, 1);
        let reference = digest(&base);
        assert_eq!(reference, digest(&base), "same environment and key");
        assert_ne!(reference.0, keyed(&base, 2).0, "another store key");
        let mut changed = Vec::new();
        for (index, replacement) in [
            (0, Some("/home/b")),
            (1, Some("/etc/b.pem")),
            (1, None),
            (2, Some("sk-unit-secret-other")),
            (2, None),
            (2, Some("")),
        ] {
            let pairs: Vec<_> = base
                .iter()
                .enumerate()
                .filter_map(|(i, pair)| match (i == index, replacement) {
                    (false, _) => Some(*pair),
                    (true, Some(value)) => Some((pair.0, value)),
                    (true, None) => None,
                })
                .collect();
            let after = digest(&pairs);
            assert_eq!(after.1, reference.1, "binary identity unchanged");
            assert_ne!(after.0, reference.0, "{index} {replacement:?}");
            changed.push(after.0);
        }
        changed.sort();
        changed.dedup();
        assert_eq!(changed.len(), 6, "absent and empty values are distinct");

        let binding = serde_json::to_string(
            &environment_binding(&config.environment_names, environment(&base), || {
                Ok(ApprovalKey::fixed(1))
            })
            .unwrap_or_else(|_| panic!("binding")),
        )
        .unwrap();
        assert!(binding.contains("/home/a") && binding.contains("/etc/a.pem"));
        assert!(!binding.contains(secret), "{binding}");
        let mac = |key: u8, name: &str| {
            environment_value_mac(&ApprovalKey::fixed(key), name, secret.as_bytes())
                .unwrap_or_else(|_| panic!("mac"))
        };
        assert!(binding.contains(&mac(1, "OPENAI_API_KEY")));
        assert!(
            !binding.contains(&content_digest(secret.as_bytes())),
            "keyed"
        );
        assert_ne!(
            mac(1, "OPENAI_API_KEY"),
            mac(1, "ANTHROPIC_API_KEY"),
            "name bound"
        );
        assert_ne!(
            mac(1, "OPENAI_API_KEY"),
            mac(2, "OPENAI_API_KEY"),
            "key bound"
        );
    }
    #[test]
    fn the_store_key_is_read_only_when_a_secret_value_is_bound() {
        let names = vec!["HOME".to_owned(), "OPENAI_API_KEY".to_owned()];
        let unavailable = || Err(CliError::Product("runtime.approval_key.unavailable"));
        assert!(environment_binding(&names, environment(&[("HOME", "/h")]), unavailable).is_ok());
        assert_eq!(
            environment_binding(&names, environment(&[("OPENAI_API_KEY", "k")]), unavailable)
                .map(|_| ())
                .map_err(CliError::code),
            Err("runtime.approval_key.unavailable")
        );
    }
    #[test]
    fn unknown_names_are_bound_by_mac_and_absence_is_explicit() {
        let names = vec!["HOME".to_owned(), "CUSTOM_TOKEN".to_owned()];
        let bound = environment_binding(&names, environment(&[("CUSTOM_TOKEN", "t0ken")]), || {
            Ok(ApprovalKey::fixed(1))
        })
        .unwrap_or_else(|_| panic!("binding"));
        assert_eq!(bound["HOME"], EnvironmentBinding::Absent);
        assert_eq!(
            bound["CUSTOM_TOKEN"],
            EnvironmentBinding::HmacSha256 {
                hmac_sha256: environment_value_mac(
                    &ApprovalKey::fixed(1),
                    "CUSTOM_TOKEN",
                    b"t0ken"
                )
                .unwrap_or_else(|_| panic!("mac"))
            }
        );
    }
    #[test]
    fn streamed_binary_digest_equals_the_whole_content_digest() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("binary");
        // Empty, one partial block, exact blocks and a multi-block tail.
        for length in [0usize, 1, 64 * 1024, 128 * 1024, 200 * 1024 + 7] {
            let content: Vec<u8> = (0..length).map(|i| (i * 31 % 251) as u8).collect();
            std::fs::write(&path, &content).unwrap();
            let streamed = binary_digest(&path, BINARY_LIMIT)
                .unwrap_or_else(|_| panic!("streamed digest of {length} bytes"));
            assert_eq!(streamed, content_digest(&content), "{length} bytes");
            let whole = crate::read_bounded(
                &path,
                BINARY_LIMIT as usize,
                CliError::RequestRead,
                CliError::RequestTooLarge,
            )
            .unwrap_or_else(|_| panic!("bounded read of {length} bytes"));
            assert_eq!(streamed, content_digest(&whole));
        }
    }
    #[test]
    fn streamed_binary_digest_keeps_the_bound_and_errors() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("binary");
        std::fs::write(&path, vec![7u8; 100_000]).unwrap();
        assert!(
            binary_digest(&path, 100_000).is_ok(),
            "exactly at the bound"
        );
        for limit in [99_999u64, 65_536, 0] {
            let streamed = binary_digest(&path, limit)
                .map(|_| ())
                .map_err(CliError::code);
            let whole = crate::read_bounded(
                &path,
                limit as usize,
                CliError::RequestRead,
                CliError::RequestTooLarge,
            )
            .map(|_| ())
            .map_err(CliError::code);
            assert_eq!(streamed, Err("request.too_large"), "{limit}");
            assert_eq!(streamed, whole, "{limit}");
        }
        let missing = directory.path().join("missing");
        assert_eq!(
            binary_digest(&missing, BINARY_LIMIT).map_err(CliError::code),
            Err("request.read")
        );
        #[cfg(unix)]
        {
            let link = directory.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert_eq!(
                binary_digest(&link, BINARY_LIMIT).map_err(CliError::code),
                Err("request.read"),
                "no-follow like read_bounded"
            );
            assert_eq!(
                binary_digest(directory.path(), BINARY_LIMIT).map_err(CliError::code),
                Err("request.read"),
                "regular files only"
            );
        }
    }
    #[test]
    fn storage_contention_maps_to_the_retryable_busy_code() {
        assert!(contention(Some(5)) && contention(Some(6)));
        assert!(contention(Some(5 | (1 << 8))), "SQLITE_BUSY_RECOVERY");
        assert!(!contention(Some(11)) && !contention(None));
        assert!(corruption(Some(11)) && corruption(Some(26)));
        assert!(corruption(Some(11 | (1 << 8))), "SQLITE_CORRUPT_VTAB");
        assert!(!corruption(Some(5)) && !corruption(None));
    }
    #[test]
    fn runtime_display_codes_match_the_cli_codes() {
        use RuntimeError::*;
        for variant in [
            Locked,
            Transition,
            NotFound,
            Approval,
            SourceChanged,
            Scope,
            NestedGit,
            Sandbox,
            ScriptProgram,
            Route,
            Process,
            CleanupUnknown,
            Limit,
            Cancelled,
            DependenciesPending,
            Verification,
        ] {
            let display = variant.to_string();
            assert_eq!(error(variant).code(), display);
        }
        let io = Io(std::io::Error::other("fixture"));
        let display = io.to_string();
        assert_eq!(Some(error(io).code()), display.split(':').next());
    }
}
