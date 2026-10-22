use crate::{CliError, Outcome, read_bounded};
use router_retrieval::{
    Bm25Index, ContextSearchQuery, RetrievalError, SearchQuery, SemanticRanking,
};
use router_types::{TaskInput, WorkflowPreset};
use router_workflow::{PlanLimits, WorkflowError};
use std::{path::Path, process::ExitCode};

#[path = "config_input.rs"]
mod config_input;

pub(crate) fn json_output(
    value: &impl serde::Serialize,
    exit_code: ExitCode,
) -> Result<Outcome, CliError> {
    Ok(Outcome {
        output: format!(
            "{}\n",
            serde_json::to_string_pretty(value).map_err(|_| CliError::Internal)?
        ),
        exit_code,
    })
}
pub(crate) fn retrieval_error(error: RetrievalError) -> CliError {
    CliError::Product(match error {
        RetrievalError::Invalid(_) => "retrieval.invalid",
        RetrievalError::Limit(_) => "retrieval.limit",
        RetrievalError::Stale => "retrieval.stale",
        RetrievalError::UnboundCatalog => "retrieval.catalog.unbound",
        RetrievalError::CatalogBindingRequired => "retrieval.catalog.required",
        RetrievalError::CatalogMismatch => "retrieval.catalog.mismatch",
        RetrievalError::ContextRequired => "retrieval.context.required",
        RetrievalError::SemanticUnavailable => "retrieval.semantic.unavailable",
        RetrievalError::SemanticInvalid => "retrieval.semantic.invalid",
        RetrievalError::Selection => "retrieval.selection",
        RetrievalError::UnsafePath => "retrieval.path",
        RetrievalError::BodyHashMismatch => "retrieval.integrity",
        RetrievalError::Io { .. } => "retrieval.io",
    })
}
pub(crate) fn workflow_error(error: WorkflowError) -> CliError {
    CliError::Product(match error {
        WorkflowError::Invalid(_) => "workflow.invalid",
        WorkflowError::Limit(_) => "workflow.limit",
        WorkflowError::Authority(_) => "workflow.authority",
        WorkflowError::Integrity => "workflow.integrity",
        WorkflowError::Cost { .. } => "workflow.cost.exceeded",
    })
}
pub(crate) fn configuration(path: &Path, json: bool) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    let layers = config_input::read(path)?;
    let result = router_workflow::resolve_configuration(&layers).map_err(workflow_error)?;
    json_output(&result, ExitCode::SUCCESS)
}
pub(crate) fn read_index(path: &Path) -> Result<Bm25Index, CliError> {
    let bytes = read_bounded(
        path,
        router_retrieval::MAX_DOCUMENT_BYTES,
        CliError::Product("retrieval.read"),
        CliError::Product("retrieval.limit"),
    )?;
    Bm25Index::from_json(&bytes).map_err(retrieval_error)
}
pub(crate) struct SearchArgs<'a> {
    pub proof: &'a crate::command::ProofArgs,
    pub metadata: &'a Path,
    pub catalog: Option<&'a Path>,
    pub now: Option<u64>,
    pub text: Option<&'a str>,
    pub context_query: Option<&'a Path>,
    pub semantic_ranking: Option<&'a Path>,
    pub kind: Option<&'a str>,
    pub top_k: usize,
    pub json: bool,
}
pub(crate) fn search(args: SearchArgs<'_>) -> Result<Outcome, CliError> {
    if !args.json {
        return Err(CliError::JsonOutputRequired);
    }
    let index = read_index(args.metadata)?;
    let hash = args
        .catalog
        .map(|path| catalog_hash(path, args.now, args.proof))
        .transpose()?;
    if let Some(path) = args.context_query {
        if args.text.is_some() || args.kind.is_some() {
            return Err(CliError::InvalidCommand);
        }
        let mut query: ContextSearchQuery = crate::phases::read_json(path, 128 * 1024)?;
        // A serialized query does not select the validation clock. Only the
        // explicit --now replay flag overrides the actual invocation time.
        query.now_unix_seconds = crate::inspect::current_time(args.now)?;
        let ranking: Option<SemanticRanking> = args
            .semantic_ranking
            .map(|path| crate::phases::read_json(path, 128 * 1024))
            .transpose()?;
        let result = index
            .search_contextual_with_semantic(
                &query,
                hash.as_deref()
                    .ok_or(CliError::Product("retrieval.catalog.required"))?,
                ranking.as_ref(),
            )
            .map_err(retrieval_error)?;
        let exit = if result.abstention.is_some() {
            ExitCode::from(3)
        } else {
            ExitCode::SUCCESS
        };
        return json_output(&result, exit);
    }
    if args.semantic_ranking.is_some() {
        return Err(CliError::InvalidCommand);
    }
    let mut query = SearchQuery::new(args.text.ok_or(CliError::InvalidCommand)?);
    query.top_k = args.top_k;
    query.kind = args
        .kind
        .map(|kind| serde_json::from_value(serde_json::json!(kind)))
        .transpose()
        .map_err(|_| CliError::InvalidCommand)?;
    let result = if let Some(hash) = hash {
        index.search_with_catalog(&query, &hash)
    } else {
        index.search(&query)
    }
    .map_err(retrieval_error)?;
    json_output(
        &result,
        if result.abstention.is_some() {
            ExitCode::from(3)
        } else {
            ExitCode::SUCCESS
        },
    )
}
fn catalog_hash(
    path: &Path,
    now: Option<u64>,
    proof: &crate::command::ProofArgs,
) -> Result<String, CliError> {
    let (catalog, _) = crate::catalogs::load_with_proofs(path, now, 86400, proof)?;
    catalog.content_hash().map_err(|_| CliError::CatalogInvalid)
}
pub(crate) fn index(
    proof: &crate::command::ProofArgs,
    metadata: &Path,
    signals: Option<&Path>,
    catalog: &Path,
    now: Option<u64>,
    json: bool,
) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    let document = crate::phases::read_json(metadata, router_retrieval::MAX_DOCUMENT_BYTES)?;
    let hash = catalog_hash(catalog, now, proof)?;
    if let Some(path) = signals {
        let signals = crate::phases::read_json(path, router_retrieval::MAX_DOCUMENT_BYTES)?;
        let envelope = router_retrieval::MetadataEnvelopeV3::new(document, signals, &hash)
            .map_err(retrieval_error)?;
        Bm25Index::build_v3(envelope.clone()).map_err(retrieval_error)?;
        json_output(&envelope, ExitCode::SUCCESS)
    } else {
        let envelope =
            router_retrieval::MetadataEnvelope::new(document, &hash).map_err(retrieval_error)?;
        Bm25Index::build_envelope(envelope.clone()).map_err(retrieval_error)?;
        json_output(&envelope, ExitCode::SUCCESS)
    }
}
pub(crate) struct RefreshArgs<'a> {
    pub proof: &'a crate::command::ProofArgs,
    pub metadata: &'a Path,
    pub successor: &'a Path,
    pub expected_source_hash: &'a str,
    pub catalog: &'a Path,
    pub now: Option<u64>,
    pub output: Option<&'a Path>,
    pub json: bool,
}

pub(crate) fn refresh(args: RefreshArgs<'_>) -> Result<Outcome, CliError> {
    let RefreshArgs {
        proof,
        metadata,
        successor,
        expected_source_hash,
        catalog,
        now,
        output,
        json,
    } = args;
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    let mut index = read_index(metadata)?;
    let bytes = read_bounded(
        successor,
        router_retrieval::MAX_DOCUMENT_BYTES,
        CliError::Product("retrieval.read"),
        CliError::Product("retrieval.limit"),
    )?;
    let report = index
        .refresh_from_json(&bytes, expected_source_hash)
        .map_err(retrieval_error)?;
    index
        .validate_catalog_hash(&catalog_hash(catalog, now, proof)?)
        .map_err(retrieval_error)?;
    let canonical = index.canonical_source_json().map_err(retrieval_error)?;
    let document: serde_json::Value =
        serde_json::from_slice(&canonical).map_err(|_| CliError::Internal)?;
    let result = json_output(
        &serde_json::json!({"schema_version":1,"update":report,"document":document}),
        ExitCode::SUCCESS,
    )?;
    if let Some(path) = output {
        publish_index(path, &canonical)?;
    }
    Ok(result)
}
/// Publish a complete, synced source as a new file. An existing destination
/// (including a symlink) is never overwritten. Temporary files are adjacent,
/// private on Unix, and removed after publication or failure.
fn publish_index(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::{
        fs::{self, OpenOptions},
        io::Write,
    };
    let error = || CliError::Product("retrieval.output");
    let filename = path.file_name().ok_or_else(error)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|_| error())?;
    let destination = parent.join(filename);
    let mut pending = None;
    for attempt in 0..32 {
        let temporary = parent.join(format!(
            ".agent-router-index-{}-{attempt}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temporary) {
            Ok(file) => {
                pending = Some((temporary, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(error()),
        }
    }
    let (temporary, mut file) = pending.ok_or_else(error)?;
    let outcome = (|| {
        file.write_all(bytes).map_err(|_| error())?;
        file.sync_all().map_err(|_| error())?;
        // hard_link is an atomic no-clobber publication on the same filesystem.
        fs::hard_link(&temporary, &destination).map_err(|_| error())?;
        Ok(())
    })();
    drop(file);
    let cleanup = fs::remove_file(&temporary).map_err(|_| error());
    outcome?;
    cleanup?;
    #[cfg(unix)]
    fs::File::open(&parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| error())?;
    Ok(())
}

fn read_task(path: &Path) -> Result<TaskInput, CliError> {
    let bytes = read_bounded(
        path,
        1024 * 1024,
        CliError::RequestRead,
        CliError::RequestTooLarge,
    )?;
    let value =
        router_adapter_api::strict_json(&bytes).map_err(|_| CliError::RequestJsonInvalid)?;
    serde_json::from_value(value).map_err(|_| CliError::RequestJsonInvalid)
}
fn risk_normalization(
    path: &Path,
    risk_context: Option<&Path>,
) -> Result<router_types::TaskRiskNormalization, CliError> {
    let context: Option<router_types::TaskRiskContext> = risk_context
        .map(|path| crate::phases::read_json(path, 64 * 1024))
        .transpose()?;
    router_workflow::normalize_with_risk(read_task(path)?, context.as_ref()).map_err(workflow_error)
}
pub(crate) fn normalize(
    path: &Path,
    risk_context: Option<&Path>,
    json: bool,
) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    let result = risk_normalization(path, risk_context)?;
    json_output(
        &result,
        if result.normalization.task.is_some() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(3)
        },
    )
}
pub(crate) fn plan(
    path: &Path,
    risk_context: Option<&Path>,
    preset: &str,
    max_width: usize,
    max_depth: usize,
    reserve_cost_microusd: u64,
    json: bool,
) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    let result = risk_normalization(path, risk_context)?;
    let Some(task) = &result.normalization.task else {
        return json_output(&result, ExitCode::from(3));
    };
    let preset: WorkflowPreset =
        serde_json::from_value(serde_json::json!(preset)).map_err(|_| CliError::InvalidCommand)?;
    let limits = PlanLimits {
        max_width,
        max_depth,
        reserve_cost_microusd,
        ..PlanLimits::default()
    };
    match router_workflow::build_plan(task, preset, limits) {
        Ok(plan) => json_output(
            &serde_json::json!({"schema_version":2,"plan":plan,"assumptions":result.normalization.assumptions,"risk_assessment":result.assessment}),
            ExitCode::SUCCESS,
        ),
        Err(WorkflowError::Cost { suggested }) => json_output(
            &serde_json::json!({"schema_version":1,"error":"workflow.cost.exceeded","suggested_preset":suggested}),
            ExitCode::from(3),
        ),
        Err(error) => Err(workflow_error(error)),
    }
}
