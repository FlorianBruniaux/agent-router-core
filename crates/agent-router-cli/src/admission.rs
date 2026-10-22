//! Explicit parent configuration for shared concurrency. No implicit registry.
use crate::{CliError, Outcome, execution, phases, product};
use clap::Subcommand;
use router_runtime::{AdmissionStore, Runtime, RuntimeLimits};
use router_types::AdmissionConfig;
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};
#[derive(Subcommand)]
pub(crate) enum Command {
    /// Explicit local session allocations and limit approvals.
    Budget {
        #[command(subcommand)]
        command: crate::session_budget::Command,
    },
    /// Initialize a new private shared registry from an explicit parent policy.
    Init {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        policy: PathBuf,
    },
    /// Report aggregate ticket states, without granting or releasing capacity.
    Status {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        expected_policy_sha256: String,
    },
    /// Hash an existing canonical runtime root for a parent policy mapping.
    RootHash {
        #[arg(long)]
        root: PathBuf,
    },
    /// Validate and hash a parent policy without creating a registry.
    PolicyHash {
        #[arg(long)]
        policy: PathBuf,
    },
}
pub(crate) fn run(command: Command, json: bool) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    let value = match command {
        Command::Budget { command } => return crate::session_budget::run(command, json),
        Command::Init { registry, policy } => {
            let policy = phases::read_json(&policy, 128 * 1024)?;
            let store = AdmissionStore::create(&registry, &policy).map_err(execution::error)?;
            serde_json::to_value(store.status().map_err(execution::error)?)
                .map_err(|_| CliError::Internal)?
        }
        Command::Status {
            registry,
            expected_policy_sha256,
        } => {
            let store = AdmissionStore::open(&registry, &expected_policy_sha256)
                .map_err(execution::error)?;
            serde_json::to_value(store.status().map_err(execution::error)?)
                .map_err(|_| CliError::Internal)?
        }
        Command::RootHash { root } => {
            serde_json::json!({"schema_version":1,"root_sha256":router_runtime::admission_runtime_root_hash(&root).map_err(execution::error)?})
        }
        Command::PolicyHash { policy } => {
            let policy = phases::read_json(&policy, 128 * 1024)?;
            serde_json::json!({"schema_version":1,"policy_sha256":router_runtime::admission_policy_hash(&policy).map_err(execution::error)?})
        }
    };
    product::json_output(&value, ExitCode::SUCCESS)
}
pub(crate) fn resolve(config: &mut AdmissionConfig, base: &Path) -> Result<(), CliError> {
    if config.schema_version != 1 || !router_adapter_api::is_digest(&config.expected_policy_sha256)
    {
        return Err(CliError::Product("admission.config.invalid"));
    }
    if !config.registry.is_absolute() {
        config.registry = base.join(&config.registry);
    }
    // Do not canonicalize a final-component symlink into an accepted registry.
    if std::fs::symlink_metadata(&config.registry)
        .map_err(|_| CliError::RequestRead)?
        .file_type()
        .is_symlink()
    {
        return Err(CliError::Product("admission.registry.symlink"));
    }
    config.registry = std::fs::canonicalize(&config.registry).map_err(|_| CliError::RequestRead)?;
    Ok(())
}
pub(crate) fn open(
    root: &Path,
    limits: RuntimeLimits,
    config: Option<&AdmissionConfig>,
) -> Result<Runtime, router_runtime::RuntimeError> {
    match config {
        Some(c) => Runtime::open_with_admission(root, limits, c),
        None => Runtime::open(root, limits),
    }
}
pub(crate) fn same<'a>(
    configs: impl IntoIterator<Item = &'a Option<AdmissionConfig>>,
) -> Result<Option<AdmissionConfig>, CliError> {
    let mut iter = configs.into_iter();
    let first = iter.next().cloned().ok_or(CliError::InvalidCommand)?;
    if iter.any(|c| c != &first) {
        return Err(CliError::Product("coordinator.admission.mismatch"));
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_types::{BudgetAmount, SessionBudgetConfig};

    #[test]
    fn a_wave_cannot_widen_another_steps_approved_session_limit() {
        let original = Some(AdmissionConfig {
            schema_version: 1,
            registry: "/synthetic/registry".into(),
            expected_policy_sha256: "a".repeat(64),
            runtime_id: "worker".into(),
            session_budget: Some(SessionBudgetConfig {
                schema_version: 1,
                expected_policy_sha256: "b".repeat(64),
                session_id: "session".into(),
                approved_limit: BudgetAmount {
                    cost_microusd: 100,
                    tokens: 200,
                },
                attempt_allocation: BudgetAmount {
                    cost_microusd: 10,
                    tokens: 20,
                },
            }),
        });
        assert_eq!(same([&original, &original]).ok(), Some(original.clone()));
        let mut wider = original.clone();
        wider
            .as_mut()
            .unwrap()
            .session_budget
            .as_mut()
            .unwrap()
            .approved_limit
            .cost_microusd = 200;
        assert!(matches!(
            same([&original, &wider]),
            Err(CliError::Product("coordinator.admission.mismatch"))
        ));
        assert!(same([&original, &None]).is_err());
    }
}
