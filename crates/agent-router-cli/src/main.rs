#![forbid(unsafe_code)]

mod admission;
mod approval_key;
mod assets;
mod attestations;
mod backend_activation;
mod capability_proofs;
mod catalogs;
mod cli;
mod command;
mod completions;
mod contracts;
mod coordinator;
mod diagnostics;
mod escalation;
mod evaluation;
mod execution;
mod execution_backend;
mod execution_feedback;
mod feedback;
mod generation;
mod human;
mod inspect;
mod phases;
mod preparation;
mod product;
mod render;
mod replay_export;
mod run_observation;
mod schema;
#[cfg(all(feature = "local-api", unix))]
mod serve;
mod session_budget;
mod sidecar;
mod task_guide;
mod version_info;

use std::{
    ffi::OsString,
    fs::OpenOptions,
    io::{self, Read, Write},
    path::Path,
    process::ExitCode,
};

use clap::{CommandFactory, Parser, error::ErrorKind};
use cli::Cli;
use command::Commands;
use router_adapter_api::ValidatedHostObservation;
use router_catalog::Catalog;
use router_policy::Router;
use router_types::{DecisionEnvelope, RouteDecision, RouteRequest};

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_CATALOG_BYTES: usize = 4 * 1024 * 1024;
const MAX_DECISION_BYTES: usize = 8 * 1024 * 1024;

fn main() -> ExitCode {
    // Read before parsing so that a usage error is reported in the requested format.
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let json = json_requested(&arguments);
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => match error.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                return match error.print() {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(_) => report_error(CliError::Internal, json),
                };
            }
            _ if json => return report_error(CliError::InvalidCommand, json),
            kind => {
                let text = usage_error(kind, &error.render().to_string(), &arguments);
                // A closed stderr must not turn a reported error into a panic.
                let _ = io::stderr().write_all(text.as_bytes());
                return CliError::InvalidCommand.exit_code();
            }
        },
    };

    match run(cli.command) {
        Ok(outcome) => {
            match write_stdout(&outcome.output) {
                Ok(()) => outcome.exit_code,
                // A failed write must never report success, nor panic.
                Err(_) => report_error(CliError::Internal, json),
            }
        }
        Err(error) => report_error(error, json),
    }
}

/// `--json` among the raw arguments, before any `--` separator. Detected
/// without clap so that a parse failure honors the requested format too.
fn json_requested(arguments: &[OsString]) -> bool {
    arguments
        .iter()
        .take_while(|argument| *argument != "--")
        .any(|argument| argument == "--json")
}

/// The deepest known subcommand path named by the raw arguments.
fn subcommand_path(arguments: &[OsString]) -> String {
    let mut command = Cli::command();
    let mut path = vec![command.get_name().to_owned()];
    for argument in arguments.iter().take_while(|argument| *argument != "--") {
        let Some(name) = argument.to_str().filter(|name| !name.starts_with('-')) else {
            continue;
        };
        let Some(subcommand) = command.find_subcommand(name).cloned() else {
            continue;
        };
        path.push(subcommand.get_name().to_owned());
        command = subcommand;
    }
    path.join(" ")
}

/// Text report of a clap usage failure. The first line stays the stable
/// `error: cli.invalid` scripts match; clap's account follows, indented so no
/// quoted argument can forge another `error:` line (clap quotes the arguments
/// the caller passed), then where to read the full usage. The command path
/// comes from the raw arguments, never from clap's text.
fn usage_error(kind: ErrorKind, rendered: &str, arguments: &[OsString]) -> String {
    let mut text = format!("error: {}\n", CliError::InvalidCommand.code());
    if kind == ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand {
        // clap rendered the whole help here; keep the short form.
        text.push_str("  a subcommand or required arguments are missing\n");
    } else {
        for line in rendered.lines() {
            if line.trim().is_empty() || line.starts_with("For more information") {
                continue;
            }
            let line = line.strip_prefix("error: ").unwrap_or(line);
            text.push_str(&format!("  {}\n", human::escaped(line)));
        }
    }
    text.push_str(&format!(
        "Run '{} --help' for usage.\n",
        human::escaped(&subcommand_path(arguments))
    ));
    text
}

struct Outcome {
    output: String,
    exit_code: ExitCode,
}

#[derive(Clone, Copy)]
enum CliError {
    InvalidCommand,
    JsonOutputRequired,
    RequestRead,
    RequestTooLarge,
    RequestJsonInvalid,
    RequestInvalid,
    CatalogRead,
    CatalogTooLarge,
    CatalogInvalid,
    DecisionRead,
    DecisionTooLarge,
    DecisionJsonInvalid,
    DecisionSchema,
    DecisionRender,
    SnapshotRead,
    SnapshotTooLarge,
    Snapshot(&'static str),
    HostUnknown,
    Probe(&'static str),
    Product(&'static str),
    Internal,
}

impl CliError {
    fn code(self) -> &'static str {
        match self {
            Self::InvalidCommand => "cli.invalid",
            Self::JsonOutputRequired => "cli.json.required",
            Self::RequestRead => "request.read",
            Self::RequestTooLarge => "request.too_large",
            Self::RequestJsonInvalid => "request.json.invalid",
            Self::RequestInvalid => "request.invalid",
            Self::CatalogRead => "catalog.read",
            Self::CatalogTooLarge => "catalog.too_large",
            Self::CatalogInvalid => "catalog.invalid",
            Self::DecisionRead => "decision.read",
            Self::DecisionTooLarge => "decision.too_large",
            Self::DecisionJsonInvalid => "decision.json.invalid",
            Self::DecisionSchema => "decision.schema.unsupported",
            Self::DecisionRender => "decision.render",
            Self::SnapshotRead => "snapshot.read",
            Self::SnapshotTooLarge => "snapshot.too_large",
            Self::Snapshot(code) => code,
            Self::HostUnknown => "host.unknown",
            Self::Probe(code) | Self::Product(code) => code,
            Self::Internal => "route.internal",
        }
    }

    fn exit_code(self) -> ExitCode {
        ExitCode::from(exit_class(self.code()) as u8)
    }
}

/// Exit status of a failed command. Status 0 (success), 3 (valid but not final
/// outcome) and 130 (interruption) are chosen by the command itself, never here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ExitClass {
    /// Invalid input or a policy refusal: change the input before retrying.
    Invalid = 2,
    /// Internal serialization, storage or invariant failure.
    Internal = 4,
    /// Transient contention: the same command may be relaunched unchanged.
    Retryable = 5,
    /// The outcome is unknown: inspect the state before any retry.
    OutcomeUnknown = 6,
    /// A stored record, hash chain, digest or signature no longer matches.
    Integrity = 7,
}

/// Codes whose effect may already have happened; retrying blindly could repeat it.
const OUTCOME_UNKNOWN_CODES: [&str; 3] = [
    "backend_store.published_durability_unknown",
    "runtime.approval_key.published_durability_unknown",
    "runtime.cleanup.unknown",
];

/// Integrity codes without the `integrity` suffix: a stored record, a hash
/// chain or a signature no longer matches (alteration or corruption).
const INTEGRITY_CODES: [&str; 8] = [
    "assets.review.trust_mismatch",
    "backend_store.anchor",
    "coordinator.storage_corrupt",
    "feedback.policy.signature",
    "feedback.storage_corrupt",
    "feedback.store.invalid",
    "policy.store.invalid",
    "runtime.storage_corrupt",
];

/// The single classification of every stable error code into an exit status.
/// It reads only the code: explicit tables first, then the last dotted segment.
/// `7` is an altered stored record, chain or signature, and `*.integrity` also
/// covers a sealed input edited after approval; `2` covers every refusal,
/// including user input that drifted after approval (`*.changed`).
/// `*.io` and `*.storage_io` stay invalid input: a missing or unreadable
/// caller path reaches them.
fn exit_class(code: &str) -> ExitClass {
    if OUTCOME_UNKNOWN_CODES.contains(&code) {
        return ExitClass::OutcomeUnknown;
    }
    if INTEGRITY_CODES.contains(&code) {
        return ExitClass::Integrity;
    }
    match code.rsplit('.').next().unwrap_or(code) {
        "busy" | "locked" | "storage_locked" => ExitClass::Retryable,
        "integrity" => ExitClass::Integrity,
        "internal" | "render" | "serialization" | "json" | "storage" | "storage_database" => {
            ExitClass::Internal
        }
        _ => ExitClass::Invalid,
    }
}

/// The `--json` error line, with the same body as the local API.
#[derive(serde::Serialize)]
struct ErrorLine {
    schema_version: u32,
    error: &'static str,
}

/// Writes one line to stderr: `error: <code>`, or with `--json`
/// `{"schema_version":1,"error":"<code>"}`. Only the stable code is written.
fn report_error(error: CliError, json: bool) -> ExitCode {
    let text = format!("error: {}", error.code());
    let line = if json {
        serde_json::to_string(&ErrorLine {
            schema_version: 1,
            error: error.code(),
        })
        .unwrap_or(text)
    } else {
        text
    };
    // A closed stderr must not turn a reported error into a panic.
    let _ = writeln!(io::stderr(), "{line}");
    error.exit_code()
}

/// Writes the whole output to stdout, surfacing every failure (EPIPE included)
/// instead of panicking like `print!`.
fn write_stdout(output: &str) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(output.as_bytes())?;
    stdout.flush()
}

fn run(mut command: Commands) -> Result<Outcome, CliError> {
    let human_title = command.structured_output();
    let mut result = run_structured(command)?;
    if let Some(title) = human_title {
        result.output = human::render(title, &result.output);
    }
    Ok(result)
}

fn run_structured(command: Commands) -> Result<Outcome, CliError> {
    match command {
        Commands::Capability { command } => attestations::run(command),
        Commands::Schema { name, list, .. } => schema::run(name.as_deref(), list),
        Commands::Version { .. } => version_info::run(),
        Commands::Completions { shell } => completions::run(shell),
        Commands::GeneratePlan {
            manifest,
            now,
            json,
        } => generation::run(&manifest, now, json),
        Commands::Sidecar { command, json } => sidecar::run(command, json),
        Commands::BackendActivation { command, json } => backend_activation::run(command, json),
        Commands::Escalation { command, json } => escalation::run(command, json),
        Commands::Admission { command, json } => admission::run(command, json),
        Commands::Coordinate { command, json } => coordinator::run(command, json),
        Commands::Assets { command } => match command {
            command::AssetCommand::Review {
                manifest,
                inputs,
                skills,
                json,
            } => assets::review(&manifest, &inputs, &skills, json),
            command::AssetCommand::Seal {
                proof,
                kind,
                document,
                catalog,
                host_snapshot,
                now,
                snapshot_max_age_seconds,
                json,
            } => assets::seal(assets::SealArgs {
                proof: &proof,
                kind,
                document: &document,
                catalog: catalog.as_deref(),
                host_snapshot: host_snapshot.as_deref(),
                now,
                snapshot_max_age_seconds,
                json,
            }),
        },
        Commands::Prepare {
            manifest,
            output_directory,
            json,
        } => preparation::run(&manifest, output_directory.as_deref(), json),
        Commands::Run {
            definition,
            store,
            sandbox,
            approve,
            retry,
            json,
        } => execution::run(
            &definition,
            &store,
            &sandbox,
            approve.as_deref(),
            retry,
            json,
        ),
        Commands::Status {
            store,
            run_id,
            json,
        } => execution::status(&store, &run_id, json),
        Commands::Observe {
            store,
            run_id,
            schema_version,
            json,
        } => run_observation::run(&store, &run_id, schema_version, json),
        Commands::Cancel {
            store,
            run_id,
            json,
        } => execution::cancel(&store, &run_id, json),
        Commands::Events {
            store,
            run_id,
            json,
        } => execution::events(&store, &run_id, json),
        Commands::SourceState { workspace, json } => execution::source_state(&workspace, json),
        Commands::Workflow {
            plan,
            execution_contract,
            seal_contract,
            json,
        } => execution::workflow(&plan, execution_contract.as_deref(), seal_contract, json),
        Commands::Verify {
            definition,
            store,
            evidence,
            config,
            json,
        } => execution::verify(&definition, &store, &evidence, config.as_deref(), json),
        Commands::Artifacts {
            definition,
            store,
            command,
            config,
            json,
        } => execution::artifacts(&definition, &store, command, config.as_deref(), json),
        Commands::Catalog { command } => catalogs::run(command),
        Commands::Feedback {
            store,
            now,
            json,
            command,
        } => feedback::feedback(&store, now, json, command),
        Commands::Policy {
            store,
            now,
            json,
            command,
        } => feedback::policy(&store, now, json, command),
        Commands::Doctor {
            request,
            runtime_root,
            now,
            deep,
            json,
        } => diagnostics::doctor(request.as_deref(), runtime_root.as_deref(), now, deep, json),
        Commands::Audit { command } => diagnostics::audit(command),
        Commands::Config { layers, json } => product::configuration(&layers, json),
        Commands::RoutePhase { inputs, json } => phases::route(inputs, json),
        Commands::Backend {
            inputs,
            backend,
            expected_backend_artifact,
            endpoint,
            bearer_env,
            allow_redacted_metadata,
            on_error,
            timeout_ms,
            minimum_confidence_micros,
            json,
        } => phases::backend(
            inputs,
            phases::BackendArgs {
                backend,
                expected_backend_artifact,
                endpoint,
                bearer_env,
                allow_redacted_metadata,
                on_error,
                timeout_ms,
                minimum_confidence_micros,
            },
            json,
        ),
        Commands::Replay {
            store,
            record,
            policy,
            now,
            snapshot_max_age_seconds,
            json,
        } => evaluation::replay(
            &record,
            &policy,
            store.as_deref(),
            now,
            snapshot_max_age_seconds,
            json,
        ),
        Commands::Eval { command } => evaluation::run(command),
        Commands::Route {
            request,
            catalog,
            json,
            host_snapshot,
            retrieval,
            snapshot_max_age_seconds,
            now,
        } => route(
            &request,
            &catalog,
            json,
            host_snapshot.as_deref(),
            snapshot_max_age_seconds,
            now,
            retrieval.as_deref(),
        ),
        Commands::Inspect {
            store,
            execution_config,
            host,
            model_cache,
            native_stream,
            observed_at,
            observed_version,
            now,
            json,
        } => inspect::inspect(
            inspect::InspectArgs {
                store,
                execution_config,
                host,
                model_cache,
                native_stream,
                observed_at,
                observed_version,
                now,
            },
            json,
        ),
        Commands::Search {
            proof,
            metadata,
            catalog,
            now,
            query,
            context_query,
            semantic_ranking,
            kind,
            top_k,
            json,
        } => product::search(product::SearchArgs {
            proof: &proof,
            metadata: &metadata,
            catalog: catalog.as_deref(),
            now,
            text: query.as_deref(),
            context_query: context_query.as_deref(),
            semantic_ranking: semantic_ranking.as_deref(),
            kind: kind.as_deref(),
            top_k,
            json,
        }),
        Commands::Index {
            proof,
            metadata,
            signals,
            catalog,
            now,
            json,
        } => product::index(&proof, &metadata, signals.as_deref(), &catalog, now, json),
        Commands::Refresh {
            proof,
            metadata,
            successor,
            expected_source_hash,
            catalog,
            now,
            output,
            json,
        } => product::refresh(product::RefreshArgs {
            proof: &proof,
            metadata: &metadata,
            successor: &successor,
            expected_source_hash: &expected_source_hash,
            catalog: &catalog,
            now,
            output: output.as_deref(),
            json,
        }),
        Commands::TaskGuide { args, json } => task_guide::run(args, json),
        Commands::Normalize {
            task,
            risk_context,
            json,
        } => product::normalize(&task, risk_context.as_deref(), json),
        Commands::Plan {
            task,
            risk_context,
            preset,
            max_width,
            max_depth,
            reserve_cost_microusd,
            json,
        } => product::plan(
            &task,
            risk_context.as_deref(),
            &preset,
            max_width,
            max_depth,
            reserve_cost_microusd,
            json,
        ),
        Commands::Explain { decision } => explain(&decision),
        #[cfg(all(feature = "local-api", unix))]
        Commands::Serve {
            state_dir,
            max_connections,
            request_deadline_ms,
        } => serve::run(&state_dir, max_connections, request_deadline_ms),
    }
}

fn route(
    request_path: &Path,
    catalog_path: &Path,
    json: bool,
    snapshot_path: Option<&Path>,
    snapshot_max_age: u64,
    now: Option<u64>,
    retrieval: Option<&Path>,
) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }

    let mut request = read_request(request_path)?;
    let snapshot = snapshot_path
        .map(|path| inspect::read_snapshot(path, now, snapshot_max_age))
        .transpose()?;
    let (catalog, embedded_snapshot) = catalogs::load(catalog_path, now, snapshot_max_age)?;
    if let Some(path) = retrieval {
        let index = product::read_index(path)?;
        let query = router_retrieval::SearchQuery::new(&request.task.objective);
        request.skill_candidates = if index.catalog_hash().is_some() {
            let hash = catalog
                .content_hash()
                .map_err(|_| CliError::CatalogInvalid)?;
            index.skill_candidates_with_catalog(&query, &hash)
        } else {
            index.skill_candidates(&query)
        }
        .map_err(product::retrieval_error)?;
    }
    decide(request, &catalog, snapshot, embedded_snapshot)
}

/// Shared by `route` and the local API: merges the explicit and embedded host
/// snapshots, routes, and renders the canonical decision JSON.
pub(crate) fn decide(
    mut request: RouteRequest,
    catalog: &Catalog,
    snapshot: Option<ValidatedHostObservation>,
    embedded_snapshot: Option<ValidatedHostObservation>,
) -> Result<Outcome, CliError> {
    let snapshot = match (snapshot, embedded_snapshot) {
        (Some(explicit), Some(embedded)) if explicit.hash() != embedded.hash() => {
            return Err(CliError::Product("catalog.snapshot.mismatch"));
        }
        (Some(explicit), _) => Some(explicit),
        (None, embedded) => embedded,
    };
    if let Some(snapshot) = &snapshot {
        request.host = snapshot.host().clone();
        request.capability_knowledge = snapshot.capabilities();
    }
    let router = Router::stable_v1();
    let decision = match &snapshot {
        Some(snapshot) => router.route_with_snapshot_hash(&request, catalog, snapshot.hash()),
        None => router.route(&request, catalog),
    }
    .map_err(|error| {
        if error.is_invalid_request() {
            CliError::RequestInvalid
        } else {
            CliError::Internal
        }
    })?;
    let exit_code = match decision.decision {
        RouteDecision::Selected { .. } => ExitCode::SUCCESS,
        RouteDecision::NoRoute { .. } => ExitCode::from(3),
    };

    Ok(Outcome {
        output: render::decision_json(&decision).map_err(|_| CliError::DecisionRender)?,
        exit_code,
    })
}

fn explain(decision_path: &Path) -> Result<Outcome, CliError> {
    let bytes = read_bounded(
        decision_path,
        MAX_DECISION_BYTES,
        CliError::DecisionRead,
        CliError::DecisionTooLarge,
    )?;
    let decision = serde_json::from_slice::<DecisionEnvelope>(&bytes)
        .map_err(|_| CliError::DecisionJsonInvalid)?;
    if !decision.has_supported_schema() {
        return Err(CliError::DecisionSchema);
    }
    Ok(Outcome {
        output: render::explain(&decision),
        exit_code: ExitCode::SUCCESS,
    })
}

fn read_request(path: &Path) -> Result<RouteRequest, CliError> {
    let bytes = read_bounded(
        path,
        MAX_REQUEST_BYTES,
        CliError::RequestRead,
        CliError::RequestTooLarge,
    )?;
    serde_json::from_slice(&bytes).map_err(|_| CliError::RequestJsonInvalid)
}

fn read_catalog(path: &Path) -> Result<Catalog, CliError> {
    let bytes = read_bounded(
        path,
        MAX_CATALOG_BYTES,
        CliError::CatalogRead,
        CliError::CatalogTooLarge,
    )?;
    Catalog::from_json(&bytes).map_err(|_| CliError::CatalogInvalid)
}

fn read_bounded(
    path: &Path,
    max_bytes: usize,
    read_error: CliError,
    too_large: CliError,
) -> Result<Vec<u8>, CliError> {
    let file = open_regular(path, read_error)?;
    let mut bytes = Vec::new();
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| read_error)?;
    if bytes.len() > max_bytes {
        return Err(too_large);
    }
    Ok(bytes)
}

/// Opens a regular file without following a final symlink or blocking on a FIFO.
fn open_regular(path: &Path, read_error: CliError) -> Result<std::fs::File, CliError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| read_error)?;
    if !file.metadata().map_err(|_| read_error)?.is_file() {
        return Err(read_error);
    }
    Ok(file)
}

#[cfg(test)]
mod exit_class_tests {
    use super::*;

    #[test]
    fn every_exit_class_is_reached_by_real_error_codes() {
        use ExitClass::*;
        for (code, class) in [
            ("cli.invalid", Invalid),
            ("request.json.invalid", Invalid),
            ("decision.schema.unsupported", Invalid),
            ("policy.composition.denied", Invalid),
            ("runtime.approval.required_or_changed", Invalid),
            ("runtime.sandbox.unknown_or_unsafe", Invalid),
            ("runtime.io", Invalid),
            ("runtime.not_found", Invalid),
            ("session_budget.accounting.unknown", Invalid),
            ("snapshot.json.invalid", Invalid),
            ("route.internal", Internal),
            ("decision.render", Internal),
            ("phase.serialization", Internal),
            ("feedback.serialization", Internal),
            ("runtime.json", Internal),
            ("coordinator.json", Internal),
            ("runtime.storage", Internal),
            ("coordinator.storage", Internal),
            ("feedback.storage_database", Internal),
            ("runtime.busy", Retryable),
            ("coordinator.busy", Retryable),
            ("backend_store.busy", Retryable),
            ("runtime.locked", Retryable),
            ("coordinator.locked", Retryable),
            ("feedback.storage_locked", Retryable),
            ("backend_store.published_durability_unknown", OutcomeUnknown),
            ("runtime.cleanup.unknown", OutcomeUnknown),
            (
                "runtime.approval_key.published_durability_unknown",
                OutcomeUnknown,
            ),
            ("runtime.integrity", Integrity),
            ("coordinator.integrity", Integrity),
            ("backend_store.integrity", Integrity),
            ("feedback.integrity", Integrity),
            ("retrieval.integrity", Integrity),
            ("workflow.integrity", Integrity),
            ("eval.integrity", Integrity),
            ("phase.catalog.integrity", Integrity),
            ("doctor.audit.integrity", Integrity),
            ("runtime.approval_key.integrity", Integrity),
            ("runtime.storage_corrupt", Integrity),
            ("coordinator.storage_corrupt", Integrity),
            ("feedback.storage_corrupt", Integrity),
            ("policy.store.invalid", Integrity),
            ("feedback.store.invalid", Integrity),
            ("feedback.policy.signature", Integrity),
            ("assets.review.trust_mismatch", Integrity),
            ("backend_store.anchor", Integrity),
            ("backend_store.conflict", Invalid),
            ("feedback.storage_io", Invalid),
            ("policy.active.changed", Invalid),
            ("escalation.source.changed", Invalid),
            ("generation.context.changed", Invalid),
            ("runtime.approval_key.unsafe", Invalid),
            ("runtime.approval_key.unavailable", Invalid),
        ] {
            assert_eq!(exit_class(code), class, "{code}");
        }
    }

    #[test]
    fn fixed_cli_errors_keep_their_documented_status() {
        for (error, status) in [
            (CliError::InvalidCommand, 2),
            (CliError::RequestTooLarge, 2),
            (CliError::DecisionSchema, 2),
            (CliError::Internal, 4),
            (CliError::DecisionRender, 4),
            (CliError::Product("runtime.busy"), 5),
            (CliError::Product("runtime.cleanup.unknown"), 6),
            (CliError::Product("runtime.integrity"), 7),
        ] {
            assert_eq!(exit_class(error.code()) as u8, status, "{}", error.code());
        }
    }

    #[test]
    fn every_preparation_error_has_a_unique_prepare_code_and_its_exit_class() {
        use router_execution_decision::DecisionError as D;
        use router_prepare::PreparationError as P;
        let table = [
            (P::Decision(D::AuthorityUnavailable), 2),
            (P::Decision(D::AuthorityRequired), 2),
            (P::Decision(D::Context), 2),
            (P::Decision(D::Abstained), 2),
            (P::Decision(D::Stale), 2),
            (P::Decision(D::Serialization), 4),
            (P::Workflow(router_workflow::WorkflowError::Invalid("x")), 2),
            (P::Route(router_policy::PhaseRouteError::Invalid("x")), 2),
            (P::Retrieval(router_retrieval::RetrievalError::Selection), 2),
            (
                P::Adapter(router_adapter_api::AdapterError::HostMismatch),
                2,
            ),
            (P::Snapshot, 2),
            (P::Abstained, 2),
            (P::Binding("secret"), 2),
            (P::Limit, 2),
            (P::Json, 4),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (error, status) in table {
            let code = error.code();
            assert!(code.starts_with("prepare."), "{code}");
            assert!(seen.insert(code), "duplicate {code}");
            assert!(!code.contains("secret"), "{code}");
            assert_eq!(exit_class(code) as u8, status, "{code}");
        }
        assert_eq!(seen.len(), 15);
    }

    #[test]
    fn the_outcome_unknown_list_is_not_matched_by_suffix() {
        // Only listed codes are unknown outcomes; other `unknown` suffixes are refusals.
        for code in ["task.budget.unknown", "risk.environment.unknown"] {
            assert_eq!(exit_class(code), ExitClass::Invalid, "{code}");
        }
    }

    /// `main.rs` without the classification tables and the test module.
    fn emitted_part_of_main(text: &str) -> String {
        let tables = text
            .find("/// Codes whose effect may already have happened")
            .expect("classification tables start");
        let classifier = text.find("fn exit_class(").expect("classifier");
        let tests = text
            .find("#[cfg(test)]\nmod exit_class_tests")
            .expect("test module");
        assert!(tables < classifier && classifier < tests);
        format!("{}{}", &text[..tables], &text[classifier..tests])
    }

    /// String literals shaped like a dotted error code, e.g. `"runtime.busy"`.
    fn quoted_codes(text: &str) -> std::vec::IntoIter<&str> {
        let bytes = text.as_bytes();
        let mut codes = Vec::new();
        for (start, _) in text.match_indices('"') {
            let body = &text[start + 1..];
            let length = body
                .bytes()
                .take_while(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.".contains(b))
                .count();
            let code = &body[..length];
            if bytes.get(start + 1 + length) == Some(&b'"')
                && code.contains('.')
                && code.starts_with(|c: char| c.is_ascii_lowercase())
            {
                codes.push(code);
            }
        }
        codes.into_iter()
    }

    #[test]
    fn every_emitted_integrity_contention_or_durability_code_has_its_class() {
        let mut texts = Vec::new();
        let mut pending = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    texts.push((path.clone(), std::fs::read_to_string(&path).unwrap()));
                }
            }
        }
        let mut emitted = std::collections::BTreeSet::new();
        for (path, text) in &texts {
            if path.file_name().is_some_and(|name| name == "main.rs") {
                // The classification tables and these tests would otherwise
                // count their own literals as emitted codes.
                emitted.extend(quoted_codes(&emitted_part_of_main(text)).map(str::to_owned));
            } else {
                emitted.extend(quoted_codes(text).map(str::to_owned));
            }
        }
        let mut checked = 0;
        for code in &emitted {
            let expected = if code.contains("durability") {
                ExitClass::OutcomeUnknown
            } else if code.contains("integrity") || code.contains("corrupt") {
                ExitClass::Integrity
            } else if code.contains("busy") || code.contains("locked") {
                ExitClass::Retryable
            } else {
                continue;
            };
            checked += 1;
            assert_eq!(exit_class(code), expected, "{code}");
        }
        assert!(checked >= 15, "scanner found only {checked} codes");
        // A typo in a table would silently leave the real code in class 2.
        for code in INTEGRITY_CODES.iter().chain(&OUTCOME_UNKNOWN_CODES) {
            assert!(emitted.contains(*code), "{code} is not emitted by the CLI");
        }
    }
}
