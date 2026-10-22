//! Signed preparation is a point-in-time preview, never current dispatch authority.
use crate::{
    PreparationError, PreparationInput, PreparationOptions, PreparationPreview, PreparedExecution,
    Result, json, loaded, prepare_with_decision_inner, validate_prepared_input_inner,
};
use router_adapter_api::{SnapshotValidation, content_digest};
use router_catalog::{CatalogAssetKind, SignedAssetKey, TrustedCatalogPublishers};
use router_catalog_store::{CatalogHead, CurrentCatalogGuard};
use router_execution_decision::ExecutionDecision;
use router_policy::{PhaseRouter, ValidatedPhaseContext, ValidatedPhaseReceipt};
use router_retrieval::{AssetKind, Bm25Index};
use router_types::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

/// The signed entry observes its own current time. A historical caller timestamp
/// is deliberately not an input; all other existing preparation bounds remain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSignedPreparationOptions {
    pub schema_version: u32,
    pub workspace: String,
    pub source_state: String,
    pub target: ExecutionTarget,
    pub allow_degradation: bool,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
    pub max_input_bytes: usize,
    pub max_snapshot_age_seconds: u64,
}
impl PublicSignedPreparationOptions {
    fn at(&self, now: u64) -> PreparationOptions {
        PreparationOptions {
            schema_version: self.schema_version,
            workspace: self.workspace.clone(),
            source_state: self.source_state.clone(),
            target: self.target,
            allow_degradation: self.allow_degradation,
            timeout_ms: self.timeout_ms,
            max_output_bytes: self.max_output_bytes,
            max_input_bytes: self.max_input_bytes,
            max_snapshot_age_seconds: self.max_snapshot_age_seconds,
            now_unix_seconds: now,
        }
    }
}

/// No autonomous plan/template or alternate decision source is accepted.
pub struct SignedPreparationInput<'a> {
    pub router: &'a PhaseRouter,
    pub context: &'a ValidatedPhaseContext,
    pub execution: &'a WorkflowExecutionContract,
    pub node_id: &'a str,
    pub index: &'a Bm25Index,
    pub body_root: &'a Path,
    pub variables: &'a BTreeMap<String, PromptValue>,
    pub options: &'a PublicSignedPreparationOptions,
}

/// Public review metadata only. Prompt text, variables and body contents are absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SignedPreparationPreview {
    pub schema_version: u32,
    pub preparation: PreparationPreview,
    pub catalog_head: CatalogHead,
    pub catalog_authority_sha256: String,
    pub execution_contract_sha256: String,
    pub context_sha256: String,
    pub started_at_unix_seconds: u64,
    pub verified_at_unix_seconds: u64,
    pub preparation_hash: String,
}

/// No serde implementation and no constructor from exported request/preview JSON.
/// This retains the exact assembled bytes, not a lock or permission to dispatch.
#[derive(Clone)]
pub struct SignedPreparedExecution {
    prepared: PreparedExecution,
    preview: SignedPreparationPreview,
}
impl fmt::Debug for SignedPreparedExecution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedPreparedExecution")
            .field("preparation_hash", &self.preview.preparation_hash)
            .field("catalog_head_hash", &self.preview.catalog_head.head_hash)
            .finish_non_exhaustive()
    }
}
impl SignedPreparedExecution {
    pub fn request(&self) -> &ExecutionRequest {
        self.prepared.request()
    }
    pub fn receipt(&self) -> &PhaseReceipt {
        self.prepared.receipt()
    }
    pub fn decision(&self) -> &ExecutionDecision {
        self.prepared.decision()
    }
    pub fn preview(&self) -> &SignedPreparationPreview {
        &self.preview
    }
    pub fn preparation_hash(&self) -> &str {
        &self.preview.preparation_hash
    }
    /// Explicit export of private material including prompt and selected bodies.
    pub fn canonical_request_json(&self) -> Result<Vec<u8>> {
        self.prepared.canonical_request_json()
    }
}

/// Prepare only a deterministic receipt (including an explicit valid fallback).
/// The caller keeps the current read guard alive throughout this operation.
pub fn prepare_signed_with_receipt(
    input: SignedPreparationInput<'_>,
    receipt: &ValidatedPhaseReceipt,
    guard: &CurrentCatalogGuard,
    publishers: &TrustedCatalogPublishers,
) -> Result<SignedPreparedExecution> {
    prepare_using_clock(input, receipt, guard, publishers, system_now)
}
fn system_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| PreparationError::Binding("signed preparation clock unavailable"))
}
fn validate_snapshot(
    context: &ValidatedPhaseContext,
    options: &PublicSignedPreparationOptions,
    now: u64,
) -> Result<()> {
    context
        .revalidate_snapshot(SnapshotValidation {
            now_unix_seconds: now,
            max_age_seconds: options.max_snapshot_age_seconds,
        })
        .map_err(|_| PreparationError::Snapshot)?;
    Ok(())
}
fn key(kind: AssetKind, id: &str) -> Result<SignedAssetKey> {
    Ok(SignedAssetKey {
        kind: match kind {
            AssetKind::Agent => CatalogAssetKind::Agent,
            AssetKind::Skill => CatalogAssetKind::Skill,
            AssetKind::Prompt => CatalogAssetKind::Prompt,
            _ => return Err(PreparationError::Binding("signed body family")),
        },
        id: id.into(),
    })
}
fn prepare_using_clock(
    input: SignedPreparationInput<'_>,
    receipt: &ValidatedPhaseReceipt,
    guard: &CurrentCatalogGuard,
    publishers: &TrustedCatalogPublishers,
    mut clock: impl FnMut() -> Result<u64>,
) -> Result<SignedPreparedExecution> {
    if !input.context.has_signed_catalog() || !input.context.has_asset_contracts() {
        return Err(PreparationError::Binding(
            "signed preparation requires signed v3 authority",
        ));
    }
    let started = clock()?;
    input.router.validate_signed_catalog_authority(
        input.context,
        guard,
        publishers,
        input.index,
        started,
    )?;
    validate_snapshot(input.context, input.options, started)?;
    let access = guard
        .access(publishers, started)
        .map_err(|_| PreparationError::Binding("signed catalog current authority"))?;
    let signed_catalog = guard
        .catalog()
        .catalog(&access)
        .map_err(|_| PreparationError::Binding("signed catalog metadata"))?;
    let proof = input
        .router
        .validate_receipt(input.context, receipt.receipt())?;
    if proof.receipt().schema_version != 4 {
        return Err(PreparationError::Binding("signed receipt version"));
    }
    let decision = ExecutionDecision::deterministic(input.router, input.context, &proof)?;
    input.router.validate_signed_assets_current(
        input.context,
        &signed_catalog,
        &decision.selection().candidate.id,
        started,
    )?;
    let plan = input
        .context
        .signed_plan()
        .ok_or(PreparationError::Binding("signed plan absent"))?;
    router_workflow::validate_execution_contract(input.execution, plan)?;
    let node = plan
        .nodes
        .iter()
        .find(|node| node.id == input.node_id)
        .ok_or(PreparationError::Binding("signed node absent"))?;
    let scope = input
        .context
        .signed_execution_scope()
        .ok_or(PreparationError::Binding("signed scope absent"))?;
    if input
        .execution
        .nodes
        .get(input.node_id)
        .map(|node| node.phase)
        != Some(input.context.request().phase)
        || input.execution.workspace != scope.workspace
        || input.execution.source_state != scope.source_state
        || input.options.workspace != scope.workspace
        || input.options.source_state != scope.source_state
        || node.scope != scope.scope
    {
        return Err(PreparationError::Binding("signed execution scope or phase"));
    }
    let prompt_id = input
        .context
        .signed_prompt_id(&decision.selection().candidate.id)
        .ok_or(PreparationError::Binding("signed prompt absent"))?;
    // Validate basic bounds before loading even the selected prompt.
    let options = input.options.at(started);
    if options.schema_version != 1
        || options.max_input_bytes == 0
        || options.max_input_bytes > router_adapter_api::MAX_EXECUTION_INPUT_BYTES
        || options.max_output_bytes == 0
        || options.max_output_bytes > router_adapter_api::MAX_TRANSPORT_BYTES
        || options.timeout_ms == 0
        || options.timeout_ms > node.budget.max_elapsed_ms
    {
        return Err(PreparationError::Limit);
    }
    let prompt_body = input.index.load_body_with_catalog(
        input.body_root,
        AssetKind::Prompt,
        prompt_id,
        input.context.catalog_hash(),
    )?;
    let access = guard
        .access(publishers, started)
        .map_err(|_| PreparationError::Binding("signed catalog current authority"))?;
    let template = guard
        .catalog()
        .validate_prompt(prompt_id, prompt_body.text.as_bytes(), &access)
        .map_err(|_| PreparationError::Binding("signed prompt body"))?;
    let metadata = input
        .index
        .asset(AssetKind::Prompt, prompt_id)
        .ok_or(PreparationError::Binding("signed prompt metadata"))?;
    if prompt_body.text.contains('\0') || prompt_body.text.len() > options.max_input_bytes {
        return Err(PreparationError::Limit);
    }
    let prompt_evidence = crate::PreparedAsset {
        kind: AssetKind::Prompt,
        id: prompt_id.into(),
        body_sha256: prompt_body.sha256.clone(),
        body_bytes: prompt_body.text.len(),
        trust: metadata.trust,
    };
    let mut first_prompt = Some((prompt_body, prompt_evidence));
    let common = PreparationInput {
        router: input.router,
        context: input.context,
        plan,
        node_id: input.node_id,
        index: input.index,
        body_root: input.body_root,
        template: &template,
        variables: input.variables,
        options: &options,
    };
    let prepared = prepare_with_decision_inner(common, &decision, |common, kind, id| {
        let value = if kind == AssetKind::Prompt && id == prompt_id {
            first_prompt
                .take()
                .ok_or(PreparationError::Binding("signed prompt reused"))?
        } else {
            loaded(common, kind, id)?
        };
        guard
            .catalog()
            .validate_selected_body(&key(kind, id)?, value.0.text.as_bytes(), &access)
            .map_err(|_| PreparationError::Binding("signed selected body"))?;
        Ok(value)
    })?;
    let finished = clock()?;
    if finished < started {
        return Err(PreparationError::Binding(
            "signed preparation clock moved backward",
        ));
    }
    input.router.validate_signed_catalog_authority(
        input.context,
        guard,
        publishers,
        input.index,
        finished,
    )?;
    validate_snapshot(input.context, input.options, finished)?;
    let access = guard
        .access(publishers, finished)
        .map_err(|_| PreparationError::Binding("signed catalog current authority"))?;
    let signed_catalog = guard
        .catalog()
        .catalog(&access)
        .map_err(|_| PreparationError::Binding("signed catalog metadata"))?;
    input.router.validate_signed_assets_current(
        input.context,
        &signed_catalog,
        &decision.selection().candidate.id,
        finished,
    )?;
    validate_prepared_input_inner(input.router, input.context, prepared.request(), finished)?;
    let authority = input
        .context
        .signed_catalog_authority_hash()
        .ok_or(PreparationError::Binding("signed authority absent"))?;
    let hash = content_digest(&json(&(
        "agent-router:signed-preparation:v1",
        guard.head(),
        authority,
        input.context.context_hash(),
        plan,
        input.node_id,
        input.execution,
        input.index.source_hash(),
        input.index.index_hash(),
        prepared.preview(),
        prepared.request(),
        input.options,
        started,
        finished,
    ))?);
    let preview = SignedPreparationPreview {
        schema_version: 1,
        preparation: prepared.preview().clone(),
        catalog_head: guard.head().clone(),
        catalog_authority_sha256: authority.into(),
        execution_contract_sha256: input.execution.contract_sha256.clone(),
        context_sha256: input.context.context_hash().into(),
        started_at_unix_seconds: started,
        verified_at_unix_seconds: finished,
        preparation_hash: hash,
    };
    Ok(SignedPreparedExecution { prepared, preview })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "../tests/support/signed_clock.rs"]
mod clock_tests;
