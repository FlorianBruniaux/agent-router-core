//! Explicit standard-sidecar commands. No caller on the runtime completion path.
use crate::{CliError, Outcome};
use clap::{Args, Subcommand};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Args)]
pub(crate) struct ConnectionArgs {
    #[arg(long)]
    endpoint: SocketAddr,
    #[arg(long)]
    expected_backend_artifact: String,
    #[arg(long)]
    bearer_env: Option<String>,
    #[arg(long, default_value_t = 500)]
    timeout_ms: u64,
}
#[derive(Args)]
pub(crate) struct ExportArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    event_sequence: u64,
    #[arg(long)]
    expected_event_hash: String,
    #[arg(long)]
    expected_consent_revision: u64,
    /// Send exactly this retained event to the explicitly selected sidecar.
    #[arg(long)]
    allow_sidecar_export: bool,
}
#[derive(Subcommand)]
pub(crate) enum Command {
    /// Explicitly query protocol v1 and capabilities; sends no task metadata.
    Capabilities(ConnectionArgs),
    /// Explicitly send one automated observation. Never runs a host.
    Outcome(ExportArgs),
    /// Explicitly send one separately recorded human verdict.
    Feedback(ExportArgs),
}
#[cfg(not(feature = "local-sidecar"))]
pub(crate) fn run(_: Command, _: bool) -> Result<Outcome, CliError> {
    Err(CliError::Product("backend.feature.disabled"))
}
#[cfg(feature = "local-sidecar")]
fn client(args: &ConnectionArgs) -> Result<router_decision::StandardSidecarBackend, CliError> {
    let bearer = args
        .bearer_env
        .as_ref()
        .map(|name| {
            if name.is_empty()
                || name.len() > 64
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(CliError::InvalidCommand);
            }
            std::env::var(name).map_err(|_| CliError::Product("backend.authentication.unavailable"))
        })
        .transpose()?;
    router_decision::StandardSidecarBackend::new(
        args.endpoint,
        bearer,
        args.expected_backend_artifact.clone(),
        router_types::BackendDataPolicy::Deny,
    )
    .map_err(|e| CliError::Product(e.code()))
}
#[cfg(feature = "local-sidecar")]
fn deadline(timeout_ms: u64) -> Result<std::time::Instant, CliError> {
    if timeout_ms == 0 || timeout_ms > 10_000 {
        return Err(CliError::Product("backend.invalid"));
    }
    Ok(std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms))
}
#[cfg(feature = "local-sidecar")]
pub(crate) fn run(command: Command, json: bool) -> Result<Outcome, CliError> {
    use router_decision::SidecarExportAuthorization;
    use router_feedback::{FeedbackStore, SidecarExportProjection};
    use std::process::ExitCode;
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    let (args, human) = match command {
        Command::Capabilities(args) => {
            let client = client(&args)?;
            let result = client
                .capabilities(deadline(args.timeout_ms)?)
                .map_err(|e| CliError::Product(e.code()))?;
            return crate::product::json_output(&result, ExitCode::SUCCESS);
        }
        Command::Outcome(args) => (args, false),
        Command::Feedback(args) => (args, true),
    };
    // Before env access, opening a store or any connection attempt.
    if !args.allow_sidecar_export {
        return Err(CliError::Product("backend.data_policy.denied"));
    }
    let client = client(&args.connection)?;
    if !args.store.is_dir() || !args.store.join("feedback.sqlite3").is_file() {
        return Err(CliError::Product("feedback.store.unavailable"));
    }
    let store = FeedbackStore::open(&args.store).map_err(feedback_error)?;
    let guard = store
        .authorize_sidecar_export(
            args.event_sequence,
            &args.expected_event_hash,
            args.expected_consent_revision,
            crate::inspect::current_time(None)?,
        )
        .map_err(feedback_error)?;
    let grant = SidecarExportAuthorization::for_event(
        args.expected_event_hash,
        args.expected_consent_revision,
    )
    .map_err(|e| CliError::Product(e.code()))?;
    let deadline = export_deadline(args.connection.timeout_ms, guard.valid_until_unix_seconds())?;
    let acknowledgement = match (guard.projection(), human) {
        (SidecarExportProjection::Outcome(payload), false) => {
            client.send_outcome(payload, &grant, deadline)
        }
        (SidecarExportProjection::Feedback(payload), true) => {
            client.send_feedback(payload, &grant, deadline)
        }
        _ => return Err(CliError::Product("feedback.origin.mismatch")),
    }
    .map_err(|e| CliError::Product(e.code()))?;
    // Guard remains held until the complete exchange; no local learning state,
    // native run or success label is changed by this transport acknowledgement.
    drop(guard);
    crate::product::json_output(
        &serde_json::json!({"schema_version":1,"acknowledgement":acknowledgement,"learning_effect":"unknown"}),
        ExitCode::SUCCESS,
    )
}
#[cfg(feature = "local-sidecar")]
fn feedback_error(error: router_feedback::FeedbackError) -> CliError {
    use router_feedback::FeedbackError;
    CliError::Product(match error {
        FeedbackError::Consent => "feedback.consent_required",
        FeedbackError::LearningDisabled => "feedback.learning_disabled",
        FeedbackError::NotFound => "feedback.not_found",
        FeedbackError::Locked => "feedback.storage_locked",
        FeedbackError::Limit => "feedback.limit",
        _ => "feedback.export.invalid",
    })
}

#[cfg(feature = "local-sidecar")]
fn export_deadline(timeout_ms: u64, valid_until: u64) -> Result<std::time::Instant, CliError> {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    let configured = deadline(timeout_ms)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliError::Product("feedback.export.invalid"))?;
    let remaining = Duration::from_secs(valid_until)
        .checked_sub(now)
        .filter(|d| !d.is_zero())
        .ok_or(CliError::Product("feedback.consent_required"))?;
    Ok(configured.min(Instant::now() + remaining))
}
