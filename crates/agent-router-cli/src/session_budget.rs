//! Explicit local budget operations. No provider invocation or private key.
use crate::{CliError, Outcome, execution, phases, product};
use clap::Subcommand;
use router_runtime::{AdmissionStore, session_budget_policy_hash};
use router_types::{BudgetAmount, SessionBudgetPolicy};
use std::{path::PathBuf, process::ExitCode};
#[derive(Subcommand)]
pub(crate) enum Command {
    /// Validate and hash a session budget policy without opening a registry.
    PolicyHash {
        #[arg(long)]
        policy: PathBuf,
    },
    /// Add session budgets to an empty shared registry.
    Init {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        expected_policy_sha256: String,
        #[arg(long)]
        policy: PathBuf,
    },
    /// Report reserved and committed allocations of one session.
    Status {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        expected_policy_sha256: String,
        #[arg(long)]
        expected_budget_policy_sha256: String,
        #[arg(long)]
        session: String,
    },
    /// Review a change. Applying requires its exact digest and ledger head.
    Limit {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        expected_policy_sha256: String,
        #[arg(long)]
        expected_budget_policy_sha256: String,
        #[arg(long)]
        session: String,
        #[arg(long)]
        new_limit: PathBuf,
        #[arg(long, requires = "expected_head")]
        approve: Option<String>,
        #[arg(long, requires = "approve")]
        expected_head: Option<String>,
    },
}
pub(crate) fn run(command: Command, json: bool) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    let value = match command {
        Command::PolicyHash { policy } => {
            let policy: SessionBudgetPolicy = phases::read_json(&policy, 128 * 1024)?;
            serde_json::json!({"schema_version":1,"policy_sha256":session_budget_policy_hash(&policy).map_err(execution::error)?,"executed":false})
        }
        Command::Init {
            registry,
            expected_policy_sha256,
            policy,
        } => {
            let policy: SessionBudgetPolicy = phases::read_json(&policy, 128 * 1024)?;
            let mut store = AdmissionStore::open(&registry, &expected_policy_sha256)
                .map_err(execution::error)?;
            let hash = store
                .initialize_session_budgets(&policy)
                .map_err(execution::error)?;
            serde_json::json!({"schema_version":1,"policy_sha256":hash,"initialized":true,"executed":false})
        }
        Command::Status {
            registry,
            expected_policy_sha256,
            expected_budget_policy_sha256,
            session,
        } => {
            let store = AdmissionStore::open(&registry, &expected_policy_sha256)
                .map_err(execution::error)?;
            serde_json::to_value(
                store
                    .session_budget_status(&session, &expected_budget_policy_sha256)
                    .map_err(execution::error)?,
            )
            .map_err(|_| CliError::Internal)?
        }
        Command::Limit {
            registry,
            expected_policy_sha256,
            expected_budget_policy_sha256,
            session,
            new_limit,
            approve,
            expected_head,
        } => {
            let new_limit: BudgetAmount = phases::read_json(&new_limit, 2048)?;
            let store = AdmissionStore::open(&registry, &expected_policy_sha256)
                .map_err(execution::error)?;
            let review = store
                .review_session_limit(&session, &expected_budget_policy_sha256, new_limit)
                .map_err(execution::error)?;
            let applied = match approve {
                Some(a) => {
                    if expected_head.as_deref()
                        != Some(review.preview().current.ledger_head.as_str())
                    {
                        return Err(CliError::Product("session_budget.review.stale"));
                    }
                    Some(
                        store
                            .approve_session_limit(&review, &a)
                            .map_err(execution::error)?,
                    )
                }
                None => None,
            };
            serde_json::json!({"schema_version":1,"preview":review.preview(),"applied":applied,"executed":false})
        }
    };
    product::json_output(&value, ExitCode::SUCCESS)
}
