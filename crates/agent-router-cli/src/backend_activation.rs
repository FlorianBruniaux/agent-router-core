//! Explicit signed backend lifecycle. Inputs are parent-owned documents; this
//! module never generates a private signing key or activates from a status JSON.
use crate::{CliError, Outcome, inspect, product::json_output, read_bounded};
use router_backend_policy::{ActivationApproval, BackendArtifact, PromotionEvidence, Signed};
use router_backend_store::{BackendStore, StoreConfig, StoreError};
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(clap::Args, Debug)]
pub(crate) struct AuthorityArgs {
    /// Existing private backend store directory.
    #[arg(long)]
    store: PathBuf,
    /// Configuration digest retained outside the store, never auto-discovered.
    #[arg(long)]
    expected_config_hash: String,
    /// Independently retained checkpoint; signed successors remain permitted.
    #[arg(long)]
    expected_head: Option<String>,
}
impl AuthorityArgs {
    fn open(&self) -> Result<BackendStore, CliError> {
        BackendStore::open(
            &self.store,
            &self.expected_config_hash,
            self.expected_head.as_deref(),
        )
        .map_err(error)
    }
}

#[derive(clap::Subcommand, Debug)]
pub(crate) enum Command {
    /// Inspect a supplied configuration digest without trusting or installing it.
    ConfigHash {
        #[arg(long)]
        config: PathBuf,
    },
    /// Compute the exact workspace/source/scope binding of a prepared request.
    ScopeHash {
        #[arg(long)]
        request: PathBuf,
    },
    /// Create a new inactive store using explicit public authority configuration.
    Init {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        expected_config_hash: String,
    },
    /// Verify history and print a redacted state projection.
    Status {
        #[command(flatten)]
        authority: AuthorityArgs,
    },
    /// Verify signed evidence without changing activation state.
    Review {
        #[command(flatten)]
        authority: AuthorityArgs,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        evidence: PathBuf,
    },
    /// Apply an externally signed activation approval after repeating all gates.
    Activate {
        #[command(flatten)]
        authority: AuthorityArgs,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        approval: PathBuf,
    },
    /// Return to the pinned baseline using an externally signed rollback approval.
    Rollback {
        #[command(flatten)]
        authority: AuthorityArgs,
        #[arg(long)]
        approval: PathBuf,
    },
}
fn error(error: StoreError) -> CliError {
    CliError::Product(match error {
        StoreError::Invalid => "backend_store.invalid",
        StoreError::Limit => "backend_store.limit",
        StoreError::Integrity => "backend_store.integrity",
        StoreError::Configuration => "backend_store.configuration",
        StoreError::Anchor => "backend_store.anchor",
        StoreError::Conflict => "backend_store.conflict",
        StoreError::Busy => "backend_store.busy",
        StoreError::Exists => "backend_store.exists",
        StoreError::Missing => "backend_store.missing",
        StoreError::Permissions => "backend_store.permissions",
        StoreError::Path => "backend_store.path",
        StoreError::Io => "backend_store.io",
        StoreError::Clock => "backend_store.clock",
        StoreError::PublishedDurabilityUnknown => "backend_store.published_durability_unknown",
        StoreError::Unsupported => "backend_store.platform.unsupported",
        StoreError::Promotion(_) => "backend_store.promotion",
    })
}
fn read_document<T: serde::de::DeserializeOwned>(path: &Path, limit: usize) -> Result<T, CliError> {
    let bytes = read_bounded(
        path,
        limit,
        CliError::RequestRead,
        CliError::RequestTooLarge,
    )?;
    router_backend_policy::parse_document(&bytes)
        .map_err(|_| CliError::Product("backend_store.document.invalid"))
}
pub(crate) fn run(command: Command, json: bool) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    // No command-line clock override can revive an expired signed approval.
    let now = inspect::current_time(None)?;
    match command {
        Command::ConfigHash { config } => {
            let bytes = read_bounded(
                &config,
                64 * 1024,
                CliError::RequestRead,
                CliError::RequestTooLarge,
            )?;
            let config = StoreConfig::from_json(&bytes).map_err(error)?;
            json_output(
                &serde_json::json!({"schema_version":1,"config_hash":config.content_hash().map_err(error)?,"approved":false,"created":false}),
                ExitCode::SUCCESS,
            )
        }
        Command::ScopeHash { request } => {
            let request: router_types::ExecutionRequest =
                crate::phases::read_json(&request, router_adapter_api::MAX_EXECUTION_INPUT_BYTES)?;
            let hash = crate::execution_backend::scope_hash(
                &request.workspace,
                &request.source_state,
                &request.scope,
            )?;
            json_output(
                &serde_json::json!({"schema_version":1,"scope_sha256":hash,"approved":false,"created":false}),
                ExitCode::SUCCESS,
            )
        }
        Command::Init {
            store,
            config,
            expected_config_hash,
        } => {
            let bytes = read_bounded(
                &config,
                64 * 1024,
                CliError::RequestRead,
                CliError::RequestTooLarge,
            )?;
            let config = StoreConfig::from_json(&bytes).map_err(error)?;
            if config.content_hash().map_err(error)? != expected_config_hash {
                return Err(CliError::Product("backend_store.configuration"));
            }
            let store = BackendStore::create(&store, config).map_err(error)?;
            json_output(&store.status(now).map_err(error)?, ExitCode::SUCCESS)
        }
        Command::Status { authority } => json_output(
            &authority.open()?.status(now).map_err(error)?,
            ExitCode::SUCCESS,
        ),
        Command::Review {
            authority,
            artifact,
            evidence,
        } => {
            let store = authority.open()?;
            let artifact: BackendArtifact = read_document(&artifact, 64 * 1024)?;
            let evidence: PromotionEvidence =
                read_document(&evidence, router_backend_policy::MAX_DOCUMENT_BYTES)?;
            let review = store.review(&artifact, &evidence, now).map_err(error)?;
            json_output(review.projection(), ExitCode::SUCCESS)
        }
        Command::Activate {
            authority,
            artifact,
            evidence,
            approval,
        } => {
            let store = authority.open()?;
            let artifact: BackendArtifact = read_document(&artifact, 64 * 1024)?;
            let evidence: PromotionEvidence =
                read_document(&evidence, router_backend_policy::MAX_DOCUMENT_BYTES)?;
            let approval: Signed<ActivationApproval> = read_document(&approval, 16 * 1024)?;
            let review = store.review(&artifact, &evidence, now).map_err(error)?;
            // Re-read wall time after potentially expensive evidence review.
            json_output(
                &store
                    .activate(&approval, &review, inspect::current_time(None)?)
                    .map_err(error)?,
                ExitCode::SUCCESS,
            )
        }
        Command::Rollback {
            authority,
            approval,
        } => {
            let store = authority.open()?;
            let approval: Signed<ActivationApproval> = read_document(&approval, 16 * 1024)?;
            json_output(
                &store
                    .rollback(&approval, inspect::current_time(None)?)
                    .map_err(error)?,
                ExitCode::SUCCESS,
            )
        }
    }
}
