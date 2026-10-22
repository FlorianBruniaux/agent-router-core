//! Explicit parent accounting and durable, reconstructed escalation proposals.
use crate::{CliError, Outcome, execution, phases, product::json_output};
use clap::{Args, Subcommand};
use router_adapter_api::content_digest;
use router_execution_decision::ExecutionDecision;
use router_policy::{PhaseRouter, ValidatedPhaseContext};
use router_runtime::{EscalationError, PendingRun, Runtime, RuntimeLimits};
use router_types::{
    AccountingUpperBound, AttemptIdentity, EscalationPolicy, ExecutionDecisionOrigin, PhaseReceipt,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

const LIMIT: usize = 64 * 1024;
#[derive(Args)]
pub(crate) struct SourceArgs {
    #[arg(long)]
    store: PathBuf,
    #[arg(
        long,
        required_unless_present = "source_bundle",
        conflicts_with = "source_bundle"
    )]
    source_definition: Option<PathBuf>,
    #[arg(
        long,
        required_unless_present = "source_definition",
        conflicts_with = "source_definition"
    )]
    source_bundle: Option<PathBuf>,
}
#[derive(Subcommand)]
pub(crate) enum Command {
    /// Review a parent accounting ceiling; only --approve persists it.
    Bound {
        #[command(flatten)]
        source: SourceArgs,
        #[arg(long)]
        attempt_run_id: String,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=5))]
        attempt: u32,
        #[arg(long)]
        max_cost_microusd: u64,
        #[arg(long)]
        max_tokens: u64,
        #[arg(long)]
        approve: Option<String>,
    },
    /// Propose a different eligible model/effort from accounted real attempts.
    Propose {
        #[command(flatten)]
        source: SourceArgs,
        #[arg(long)]
        policy: PathBuf,
        /// Explicit total attempt ceiling; unchanged runs still default to two.
        #[arg(long, value_parser = clap::value_parser!(u32).range(3..=5))]
        max_attempts: u32,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    runtime_store: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_definition: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_bundle: Option<PathBuf>,
    source_material_sha256: String,
    policy: EscalationPolicy,
    max_attempts: u32,
    expected_ledger_hash: String,
    expected_decision_id: String,
}
/// Parsed once per command. This is an input pin, never an execution proof.
pub(crate) struct LoadedProposal {
    document: Document,
    path: PathBuf,
    sha256: String,
}
#[derive(Serialize)]
pub(crate) struct SourceBinding {
    document: PathBuf,
    document_sha256: String,
    runtime_store: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_definition: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_bundle: Option<PathBuf>,
    source_material_sha256: String,
    ledger_hash: String,
    decision_id: String,
    max_attempts: u32,
}
fn canonical(path: &Path) -> Result<PathBuf, CliError> {
    fs::canonicalize(path).map_err(|_| CliError::RequestRead)
}
fn sha(value: &impl Serialize) -> Result<String, CliError> {
    serde_json::to_vec(value)
        .map(|bytes| content_digest(&bytes))
        .map_err(|_| CliError::Internal)
}
fn hash_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
pub(crate) fn error(error: EscalationError) -> CliError {
    match error {
        EscalationError::Runtime(error) => execution::error(error),
        EscalationError::Policy => CliError::Product("escalation.policy.invalid"),
        EscalationError::Evidence => {
            CliError::Product("escalation.attempt_evidence.missing_or_changed")
        }
        EscalationError::AccountingUnknown => CliError::Product("escalation.accounting.unknown"),
        EscalationError::Budget => CliError::Product("escalation.budget.exhausted"),
        EscalationError::Attempts => {
            CliError::Product("escalation.attempts.insufficient_or_not_retryable")
        }
        EscalationError::Target => CliError::Product("escalation.target.not_admissible"),
        EscalationError::Approval => CliError::Product("escalation.approval.required_or_changed"),
    }
}
fn definition(path: &Path) -> Result<execution::Definition, CliError> {
    let source = execution::load_definition(path)?;
    // Stop before following another decision document: no recursive manifests.
    if source.generated_plan.is_some() || source.escalation_decision.is_some() {
        return Err(CliError::Product("escalation.source.origin_denied"));
    }
    Ok(source)
}
fn source_in(
    runtime: &Runtime,
    path: Option<&Path>,
    bundle: Option<&Path>,
) -> Result<(PendingRun, String), CliError> {
    if let Some(path) = bundle {
        if path.as_os_str().is_empty() {
            return Err(CliError::RequestRead);
        }
        return crate::coordinator::escalation_source(runtime, path)
            .map(|s| (s.pending, s.material));
    }
    let path = path.ok_or(CliError::InvalidCommand)?;
    let path = canonical(path)?;
    let source = definition(&path)?;
    let (pending, loaded) = execution::reopen_in(runtime, &source, None)?;
    if !matches!(
        pending.decision().origin(),
        ExecutionDecisionOrigin::Deterministic | ExecutionDecisionOrigin::Activated
    ) {
        return Err(CliError::Product("escalation.source.origin_denied"));
    }
    let material = sha(&(
        "agent-router:escalation-source:v1",
        &path,
        &source,
        &pending.summary().definition_hash,
        &loaded.binding,
    ))?;
    Ok((pending, material))
}
fn open_source(
    store: &Path,
    path: Option<&Path>,
    bundle: Option<&Path>,
    max_attempts: u32,
) -> Result<Runtime, CliError> {
    let run_id = if let Some(path) = bundle {
        crate::coordinator::escalation_source_id(path)?
    } else {
        definition(path.ok_or(CliError::InvalidCommand)?)?.run_id
    };
    // Observe first so review/proposal never creates a missing source store.
    let summary = router_runtime::observe(store, &run_id).map_err(execution::error)?;
    let admission = if let Some(bundle) = bundle {
        crate::coordinator::bundle_admission(bundle)?
    } else {
        definition(path.ok_or(CliError::InvalidCommand)?)?.admission
    };
    crate::admission::open(
        store,
        RuntimeLimits {
            max_attempts,
            output_retention: summary.output_retention,
            ..RuntimeLimits::default()
        },
        admission.as_ref(),
    )
    .map_err(execution::error)
}
impl LoadedProposal {
    pub(crate) fn read(path: &Path) -> Result<Self, CliError> {
        let path = canonical(path)?;
        let raw = crate::read_bounded(
            &path,
            LIMIT,
            CliError::RequestRead,
            CliError::RequestTooLarge,
        )?;
        let mut document: Document = serde_json::from_value(
            router_adapter_api::strict_json(&raw).map_err(|_| CliError::RequestJsonInvalid)?,
        )
        .map_err(|_| CliError::RequestJsonInvalid)?;
        if !matches!(
            (
                document.schema_version,
                document.source_definition.is_some(),
                document.source_bundle.is_some()
            ),
            (1, true, false) | (2, false, true)
        ) || !(3..=5).contains(&document.max_attempts)
            || !hash_valid(&document.source_material_sha256)
            || !hash_valid(&document.expected_ledger_hash)
            || !hash_valid(&document.expected_decision_id)
        {
            return Err(CliError::Product("escalation.document.invalid"));
        }
        let base = path.parent().ok_or(CliError::RequestRead)?;
        document.runtime_store = canonical(&base.join(&document.runtime_store))?;
        document.source_definition = document
            .source_definition
            .map(|p| canonical(&base.join(p)))
            .transpose()?;
        document.source_bundle = document
            .source_bundle
            .map(|p| canonical(&base.join(p)))
            .transpose()?;
        Ok(Self {
            document,
            path,
            sha256: content_digest(&raw),
        })
    }
    pub(crate) fn max_attempts(&self) -> u32 {
        self.document.max_attempts
    }
    pub(crate) fn validate_store(&self, store: &Path) -> Result<(), CliError> {
        if canonical(store)? != self.document.runtime_store {
            return Err(CliError::Product("escalation.store.changed"));
        }
        Ok(())
    }
    pub(crate) fn open_runtime(&self) -> Result<Runtime, CliError> {
        open_source(
            &self.document.runtime_store,
            self.document.source_definition.as_deref(),
            self.document.source_bundle.as_deref(),
            self.max_attempts(),
        )
    }
    pub(crate) fn is_coordinator(&self) -> bool {
        self.document.source_bundle.is_some()
    }
    /// This is only a CLI digest projection for a queued control. The owner
    /// reconstructs the proof and confidential material before applying it.
    pub(crate) fn control_binding(&self) -> SourceBinding {
        SourceBinding {
            document: self.path.clone(),
            document_sha256: self.sha256.clone(),
            runtime_store: self.document.runtime_store.clone(),
            source_definition: self.document.source_definition.clone(),
            source_bundle: self.document.source_bundle.clone(),
            source_material_sha256: self.document.source_material_sha256.clone(),
            ledger_hash: self.document.expected_ledger_hash.clone(),
            decision_id: self.document.expected_decision_id.clone(),
            max_attempts: self.max_attempts(),
        }
    }
    pub(crate) fn prepared_request(
        &self,
        runtime: &Runtime,
        request: &router_types::ExecutionRequest,
        workflow: Option<(&router_types::WorkflowExecutionContract, u32)>,
    ) -> Result<router_types::ExecutionRequest, CliError> {
        let mut final_request = request.clone();
        if let Some(path) = &self.document.source_bundle {
            let source = crate::coordinator::escalation_source(runtime, path)?;
            let Some((contract, generation)) = workflow else {
                return Err(CliError::Product("escalation.workflow.required"));
            };
            if contract != &source.workflow.execution
                || source.generation.checked_add(1) != Some(generation)
            {
                return Err(CliError::Product("escalation.workflow.changed"));
            }
            final_request.prompt.push_str(
                &runtime
                    .render_dependency_context(&source.artifacts)
                    .map_err(execution::error)?,
            );
        }
        Ok(final_request)
    }
    pub(crate) fn reconstruct(
        &self,
        runtime: &Runtime,
        router: &PhaseRouter,
        context: &ValidatedPhaseContext,
        baseline: &PhaseReceipt,
    ) -> Result<(ExecutionDecision, SourceBinding), CliError> {
        self.validate_store(runtime.storage_root())?;
        let (source, material) = source_in(
            runtime,
            self.document.source_definition.as_deref(),
            self.document.source_bundle.as_deref(),
        )?;
        if material != self.document.source_material_sha256 {
            return Err(CliError::Product("escalation.source.changed"));
        }
        let proof = runtime
            .review_escalation(&source, &self.document.policy)
            .map_err(error)?;
        if proof.binding().ledger_hash != self.document.expected_ledger_hash
            || proof.binding().decision_id != self.document.expected_decision_id
        {
            return Err(CliError::Product("escalation.evidence.changed"));
        }
        let decision = proof.decision(router, context).map_err(error)?;
        if decision.baseline() != baseline {
            return Err(CliError::Product("escalation.baseline.changed"));
        }
        Ok((decision, self.control_binding()))
    }
}
pub(crate) fn run(command: Command, json: bool) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    match command {
        Command::Bound {
            source,
            attempt_run_id,
            attempt,
            max_cost_microusd,
            max_tokens,
            approve,
        } => {
            let runtime_root = if source.source_bundle.is_some() {
                source.store.join("runtime")
            } else {
                source.store.clone()
            };
            let runtime = open_source(
                &runtime_root,
                source.source_definition.as_deref(),
                source.source_bundle.as_deref(),
                2,
            )?;
            let (pending, _) = source_in(
                &runtime,
                source.source_definition.as_deref(),
                source.source_bundle.as_deref(),
            )?;
            let reviewed = runtime
                .review_attempt_bound(
                    &pending,
                    &AttemptIdentity {
                        run_id: attempt_run_id,
                        attempt,
                    },
                    AccountingUpperBound {
                        cost_microusd: max_cost_microusd,
                        tokens: max_tokens,
                    },
                )
                .map_err(error)?;
            if let Some(digest) = &approve {
                runtime
                    .approve_attempt_bound(&reviewed, digest)
                    .map_err(error)?;
            }
            json_output(
                &serde_json::json!({"schema_version":1,"preview":reviewed.preview(),"approved":approve.is_some(),"accounting_basis":"parent_attested_upper_bound","observed_cost_microusd":null,"observed_tokens":null,"executed":false}),
                ExitCode::SUCCESS,
            )
        }
        Command::Propose {
            source,
            policy,
            max_attempts,
            output,
        } => {
            let source_path = source
                .source_definition
                .as_deref()
                .map(canonical)
                .transpose()?;
            let bundle_path = source.source_bundle.as_deref().map(canonical).transpose()?;
            if let Some(path) = &source_path {
                execution::require_asset_authority(&definition(path)?)?;
            }
            let runtime_root = if bundle_path.is_some() {
                source.store.join("runtime")
            } else {
                source.store.clone()
            };
            let runtime = open_source(
                &runtime_root,
                source_path.as_deref(),
                bundle_path.as_deref(),
                max_attempts,
            )?;
            let (pending, source_material_sha256) =
                source_in(&runtime, source_path.as_deref(), bundle_path.as_deref())?;
            let policy: EscalationPolicy = phases::read_json(&policy, LIMIT)?;
            let proof = runtime
                .review_escalation(&pending, &policy)
                .map_err(error)?;
            let document = Document {
                schema_version: if bundle_path.is_some() { 2 } else { 1 },
                runtime_store: runtime.storage_root().to_owned(),
                source_definition: source_path,
                source_bundle: bundle_path,
                source_material_sha256,
                policy,
                max_attempts,
                expected_ledger_hash: proof.binding().ledger_hash.clone(),
                expected_decision_id: proof.binding().decision_id.clone(),
            };
            if let Some(path) = &output {
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(path)
                    .map_err(|_| CliError::Product("escalation.output.exists_or_unavailable"))?;
                let bytes = serde_json::to_vec(&document).map_err(|_| CliError::Internal)?;
                file.write_all(&bytes)
                    .and_then(|()| file.sync_all())
                    .map_err(|_| CliError::Product("escalation.output.write"))?;
            }
            json_output(
                &serde_json::json!({"schema_version":1,"document":document,"preview":proof.binding(),"written":output.is_some(),"approved":false,"executed":false}),
                ExitCode::SUCCESS,
            )
        }
    }
}
