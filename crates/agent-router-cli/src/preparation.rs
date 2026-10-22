use crate::{CliError, Outcome, catalogs, command::PhaseArgs, execution, inspect, phases, product};
use router_prepare::{PreparationInput, PreparationOptions};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    capability_store: Option<PathBuf>,
    execution_config: Option<PathBuf>,
    run_id: String,
    admission: Option<router_types::AdmissionConfig>,
    context: PathBuf,
    host_snapshot: PathBuf,
    catalog: PathBuf,
    policy: Option<PathBuf>,
    policy_store: Option<PathBuf>,
    asset_authority: Option<PathBuf>,
    backend_decision: Option<PathBuf>,
    generated_plan: Option<PathBuf>,
    escalation_decision: Option<PathBuf>,
    plan: PathBuf,
    node_id: String,
    metadata: PathBuf,
    body_root: PathBuf,
    template: PathBuf,
    variables: PathBuf,
    options: PathBuf,
    receipt: Option<PathBuf>,
    workflow_contract: Option<PathBuf>,
    generation: Option<u32>,
}
fn resolve(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| CliError::Product("prepare.output.create"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| CliError::Product("prepare.output.write"))
}
fn serialized(value: &impl serde::Serialize) -> Result<Vec<u8>, CliError> {
    serde_json::to_vec_pretty(value).map_err(|_| CliError::Internal)
}
pub(crate) fn run(path: &Path, output: Option<&Path>, json: bool) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    let mut manifest: Manifest = phases::read_json(path, 64 * 1024)?;
    if manifest.schema_version != 1
        || manifest.run_id.is_empty()
        || manifest.run_id.len() > 96
        || manifest.run_id.starts_with('.')
        || !manifest
            .run_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(CliError::Product("prepare.manifest.invalid"));
    }
    let absolute = fs::canonicalize(path).map_err(|_| CliError::RequestRead)?;
    let base = absolute.parent().ok_or(CliError::RequestRead)?;
    if let Some(config) = &mut manifest.admission {
        crate::admission::resolve(config, base)?;
    }
    let mut options: PreparationOptions =
        phases::read_json(&resolve(base, manifest.options), 64 * 1024)?;
    // Executable preparation never accepts a caller-supplied historic clock.
    options.now_unix_seconds = inspect::current_time(None)?;
    if options.max_snapshot_age_seconds > 300 {
        return Err(CliError::Product("prepare.snapshot.maximum_age"));
    }
    let inputs = PhaseArgs {
        store: manifest.capability_store.map(|p| resolve(base, p)),
        execution_config: manifest.execution_config.map(|p| resolve(base, p)),
        context: resolve(base, manifest.context),
        host_snapshot: resolve(base, manifest.host_snapshot),
        catalog: resolve(base, manifest.catalog),
        policy: manifest.policy.map(|p| resolve(base, p)),
        policy_store: manifest.policy_store.map(|p| resolve(base, p)),
        asset_authority: manifest.asset_authority.map(|p| resolve(base, p)),
        now: Some(options.now_unix_seconds),
        snapshot_max_age_seconds: options.max_snapshot_age_seconds,
    };
    let (policy, active_binding) = if inputs.policy.is_none() {
        if let Some(path) = &inputs.policy_store {
            if !path.join("feedback.sqlite3").is_file() {
                return Err(CliError::Product("policy.store.unavailable"));
            }
            let store = router_feedback::FeedbackStore::open(path)
                .map_err(|_| CliError::Product("policy.store.invalid"))?;
            let active = store
                .active_policy()
                .map_err(|_| CliError::Product("policy.active.invalid"))?
                .ok_or(CliError::Product("policy.active.missing"))?;
            (active.policy, Some((path.clone(), active.artifact_id)))
        } else {
            (phases::selected_policy(&inputs)?, None)
        }
    } else {
        (phases::selected_policy(&inputs)?, None)
    };
    let (router, context) = phases::load_with_policy(&inputs, Some(policy.clone()))?;
    let plan = execution::plan(&resolve(base, manifest.plan))?;
    if manifest.workflow_contract.is_some() != manifest.generation.is_some() {
        return Err(CliError::Product("prepare.workflow.generation_required"));
    }
    let workflow: Option<router_types::WorkflowExecutionContract> = manifest
        .workflow_contract
        .map(|path| {
            let contract = phases::read_json(&resolve(base, path), 1024 * 1024)?;
            router_workflow::validate_execution_contract(&contract, &plan)
                .map_err(|_| CliError::Product("prepare.workflow.invalid"))?;
            Ok::<_, CliError>(contract)
        })
        .transpose()?;
    let index = product::read_index(&resolve(base, manifest.metadata))?;
    let template = phases::read_json(&resolve(base, manifest.template), 256 * 1024)?;
    let variables: BTreeMap<String, router_types::PromptValue> =
        phases::read_json(&resolve(base, manifest.variables), 256 * 1024)?;
    let body_root = resolve(base, manifest.body_root);
    let receipt = if let Some(path) = manifest.receipt {
        phases::read_json(&resolve(base, path), 1024 * 1024)?
    } else {
        router
            .route(&context)
            .map_err(|_| CliError::Product("prepare.route.invalid"))?
    };
    if manifest.backend_decision.is_none()
        && manifest.generated_plan.is_none()
        && manifest.escalation_decision.is_none()
    {
        router
            .validate_receipt(&context, &receipt)
            .map_err(|_| CliError::Product("prepare.receipt.invalid_or_abstained"))?;
    }
    let backend_path = manifest
        .backend_decision
        .as_ref()
        .map(|p| resolve(base, p.clone()));
    let node = plan
        .nodes
        .iter()
        .find(|node| node.id == manifest.node_id)
        .ok_or(CliError::Product("prepare.node.invalid"))?;
    let generated_path = manifest
        .generated_plan
        .as_ref()
        .map(|path| resolve(base, path.clone()));
    let escalation_path = manifest
        .escalation_decision
        .as_ref()
        .map(|path| resolve(base, path.clone()));
    if escalation_path.is_some() && (backend_path.is_some() || generated_path.is_some()) {
        return Err(CliError::Product("escalation.composition.denied"));
    }
    let proposal = escalation_path
        .as_deref()
        .map(crate::escalation::LoadedProposal::read)
        .transpose()?;
    let runtime = proposal
        .as_ref()
        .map(crate::escalation::LoadedProposal::open_runtime)
        .transpose()?;
    let loaded = crate::generation::load_decision(
        backend_path.as_deref(),
        generated_path.as_deref(),
        proposal.as_ref(),
        runtime.as_ref(),
        &manifest.node_id,
        &router,
        &context,
        &receipt,
        &crate::execution_backend::scope_hash(
            &options.workspace,
            &options.source_state,
            &node.scope,
        )?,
        false,
    )?;
    if let Some(proof) = loaded.decision.generated_plan() {
        proof
            .validate_workflow(
                &plan,
                workflow
                    .as_ref()
                    .ok_or(CliError::Product("generation.workflow.required"))?,
            )
            .map_err(crate::generation::error)?;
    }
    let prepared = router_prepare::prepare_with_decision(
        PreparationInput {
            router: &router,
            context: &context,
            plan: &plan,
            node_id: &manifest.node_id,
            index: &index,
            body_root: &body_root,
            template: &template,
            variables: &variables,
            options: &options,
        },
        &loaded.decision,
    )
    .map_err(|error| CliError::Product(error.code()))?;
    if let Some(runtime) = &runtime {
        let final_request = proposal
            .as_ref()
            .ok_or(CliError::Internal)?
            .prepared_request(
                runtime,
                prepared.request(),
                workflow.as_ref().zip(manifest.generation),
            )?;
        router_prepare::validate_prepared_input(
            &router,
            &context,
            &final_request,
            options.now_unix_seconds,
        )
        .map_err(|error| CliError::Product(error.code()))?;
        runtime
            .validate_escalation_preparation(
                &router,
                &context,
                &loaded.decision,
                &final_request,
                &plan,
                &manifest.node_id,
                &manifest.run_id,
                workflow.as_ref().zip(manifest.generation),
            )
            .map_err(execution::error)?;
    }
    if let Some(directory) = output {
        use std::os::unix::fs::DirBuilderExt;
        // A generated catalog embeds its authenticated snapshot. Reopening it
        // must retain the same store/config authority as the phase load above.
        // Recompute current pins rather than trusting hashes from that document.
        let verifier = match (&inputs.store, &inputs.execution_config) {
            (Some(store), Some(config)) => Some(crate::capability_proofs::fresh(
                store,
                &execution::sandbox(config)?,
                context.snapshot(),
                Some((
                    &context.request().task.scope,
                    context
                        .request()
                        .task
                        .required_capabilities
                        .contains(&router_types::Capability::Network),
                )),
            )?),
            _ => None, // Incomplete pairs were already refused by phase loading.
        };
        let (catalog, embedded) = catalogs::load_with_verifier(
            &inputs.catalog,
            inputs.now,
            inputs.snapshot_max_age_seconds,
            verifier
                .as_deref()
                .map(|value| value as &dyn router_adapter_api::CapabilityProofVerifier),
        )?;
        if embedded.is_some_and(|snapshot| snapshot.hash() != context.snapshot().snapshot_hash) {
            return Err(CliError::Product("prepare.catalog.changed"));
        }
        if catalog
            .content_hash()
            .map_err(|_| CliError::CatalogInvalid)?
            != context.catalog_hash()
        {
            return Err(CliError::Product("prepare.catalog.changed"));
        }
        // Assemble every byte before creating an output directory. All names are
        // constant; create_new refuses user files and symlinks without overwrites.
        let (policy_file, policy_store, policy_artifact_id) =
            if let Some((store, id)) = &active_binding {
                (None, Some(store), Some(id))
            } else {
                (Some("policy.json"), None, None)
            };
        let mut definition = serde_json::json!({"schema_version":1,"run_id":manifest.run_id,"context":"context.json","host_snapshot":"snapshot.json","catalog":"catalog.json","policy":policy_file,"policy_store":policy_store,"policy_artifact_id":policy_artifact_id,"plan":"plan.json","node_id":manifest.node_id,"request":"request.json","receipt":"receipt.json"});
        if let Some(config) = &manifest.admission {
            definition["admission"] =
                serde_json::to_value(config).map_err(|_| CliError::Internal)?;
        }
        if let Some(path) = &inputs.asset_authority {
            definition["asset_authority"] =
                serde_json::json!(fs::canonicalize(path).map_err(|_| CliError::RequestRead)?);
        }
        if workflow.is_some() {
            // Workflow contract and backend decision are separate authorities.
            definition["workflow_contract"] = serde_json::json!("workflow-contract.json");
            definition["generation"] = serde_json::json!(manifest.generation);
        }
        if let Some(path) = &backend_path {
            definition["backend_decision"] =
                serde_json::json!(fs::canonicalize(path).map_err(|_| CliError::RequestRead)?);
        }
        if let Some(path) = &generated_path {
            definition["generated_plan"] =
                serde_json::json!(fs::canonicalize(path).map_err(|_| CliError::RequestRead)?);
        }
        if let Some(path) = &escalation_path {
            definition["escalation_decision"] =
                serde_json::json!(fs::canonicalize(path).map_err(|_| CliError::RequestRead)?);
        }
        let mut files = vec![
            ("context.json", serialized(context.request())?),
            ("snapshot.json", serialized(context.snapshot())?),
            (
                "catalog.json",
                catalog
                    .canonical_json()
                    .map_err(|_| CliError::CatalogInvalid)?,
            ),
            ("policy.json", serialized(&policy)?),
            ("plan.json", serialized(&plan)?),
            (
                "request.json",
                prepared
                    .canonical_request_json()
                    .map_err(|_| CliError::Internal)?,
            ),
            ("preview.json", serialized(prepared.preview())?),
            ("receipt.json", serialized(prepared.receipt())?),
        ];
        if let Some(contract) = &workflow {
            files.push(("workflow-contract.json", serialized(contract)?));
        }
        files.push(("definition.json", serialized(&definition)?));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(directory)
            .map_err(|_| CliError::Product("prepare.output.exists_or_unavailable"))?;
        for (name, bytes) in files {
            write_private(&directory.join(name), &bytes)?;
        }
    }
    product::json_output(
        &serde_json::json!({"schema_version":1,"preview":prepared.preview(),"preparation_hash":prepared.preparation_hash(),"written":output.is_some(),"executed":false,"approved":false}),
        ExitCode::SUCCESS,
    )
}
