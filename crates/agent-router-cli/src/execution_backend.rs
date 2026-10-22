//! Reconstruct signed historical decisions, then use current authority at spawn.
use crate::{CliError, inspect, phases};
use router_backend_policy::{SignedBackendProposal, decide_active};
use router_backend_store::BackendStore;
use router_execution_decision::{ActivationGuard, ExecutionDecision};
use router_policy::{PhaseRouter, ValidatedPhaseContext};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    store: PathBuf,
    expected_config_hash: String,
    expected_head: Option<String>,
    activation_state_hash: String,
    decided_at_unix_seconds: u64,
    proposal: Option<SignedBackendProposal>,
}
pub(crate) struct LoadedDecision {
    pub decision: ExecutionDecision,
    pub authority: Option<BackendStore>,
    pub binding: Option<AuthorityBinding>,
}
#[derive(Serialize)]
pub(crate) struct AuthorityBinding {
    store: PathBuf,
    expected_config_hash: String,
    expected_head: Option<String>,
    manifest_sha256: String,
}
pub(crate) fn scope_hash(
    workspace: &str,
    source_state: &str,
    scope: &[String],
) -> Result<String, CliError> {
    serde_json::to_vec(&(
        "agent-router:backend-execution-scope:v1",
        workspace,
        source_state,
        scope,
    ))
    .map(|bytes| router_adapter_api::content_digest(&bytes))
    .map_err(|_| CliError::Internal)
}
pub(crate) fn load(
    path: Option<&Path>,
    router: &PhaseRouter,
    context: &ValidatedPhaseContext,
    baseline: &router_types::PhaseReceipt,
    scope_sha256: &str,
    historical: bool,
) -> Result<LoadedDecision, CliError> {
    let Some(path) = path else {
        let proof = router
            .validate_receipt(context, baseline)
            .map_err(|_| CliError::Product("runtime.receipt.invalid"))?;
        return Ok(LoadedDecision {
            decision: ExecutionDecision::deterministic(router, context, &proof)
                .map_err(|_| CliError::Product("runtime.decision.invalid"))?,
            authority: None,
            binding: None,
        });
    };
    let mut manifest: Manifest = phases::read_json(path, 1024 * 1024)?;
    let now = inspect::current_time(None)?;
    if manifest.schema_version != 1 || manifest.decided_at_unix_seconds > now {
        return Err(CliError::Product("runtime.backend.manifest"));
    }
    let absolute = std::fs::canonicalize(path).map_err(|_| CliError::RequestRead)?;
    let store_path = if manifest.store.is_absolute() {
        manifest.store.clone()
    } else {
        absolute
            .parent()
            .ok_or(CliError::RequestRead)?
            .join(&manifest.store)
    };
    let store_path = std::fs::canonicalize(store_path).map_err(|_| CliError::RequestRead)?;
    manifest.store = store_path.clone();
    let binding = AuthorityBinding {
        store: store_path.clone(),
        expected_config_hash: manifest.expected_config_hash.clone(),
        expected_head: manifest.expected_head.clone(),
        manifest_sha256: router_adapter_api::content_digest(
            &serde_json::to_vec(&manifest).map_err(|_| CliError::Internal)?,
        ),
    };
    let store = BackendStore::open(
        &store_path,
        &manifest.expected_config_hash,
        manifest.expected_head.as_deref(),
    )
    .map_err(|_| CliError::Product("runtime.backend.authority"))?;
    if store
        .status(now)
        .map_err(|_| CliError::Product("runtime.backend.authority"))?
        .scope_sha256
        != scope_sha256
    {
        return Err(CliError::Product("runtime.backend.scope"));
    }
    let guard = store
        .historical_guard(
            &manifest.activation_state_hash,
            manifest.decided_at_unix_seconds,
        )
        .map_err(|_| CliError::Product("runtime.backend.history"))?;
    let proof = decide_active(
        guard.state(),
        router,
        context,
        manifest.proposal.as_ref(),
        guard.authorities(),
        manifest.decided_at_unix_seconds,
    )
    .map_err(|_| CliError::Product("runtime.backend.decision"))?;
    if proof.baseline() != baseline {
        return Err(CliError::Product("runtime.backend.baseline_mismatch"));
    }
    let decision = ExecutionDecision::activated(
        router,
        context,
        &proof,
        &guard,
        manifest.decided_at_unix_seconds,
    )
    .map_err(|_| CliError::Product("runtime.backend.decision"))?;
    drop(guard);
    if !historical {
        drop(
            decision
                .acquire_dispatch(router, context, Some(&store), now)
                .map_err(|_| CliError::Product("runtime.backend.changed_or_expired"))?,
        );
    }
    Ok(LoadedDecision {
        decision,
        authority: Some(store),
        binding: Some(binding),
    })
}
