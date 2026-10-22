//! Parent-owned asset authority and explicit selected-skill review. No activation.
use crate::{
    CliError, Outcome, catalogs,
    command::{AssetSealKind, PhaseArgs, ProofArgs},
    inspect, phases, product, read_bounded,
};
use router_adapter_api::ValidatedHostObservation;
use router_asset_contracts::{
    ValidatedAvailability, ValidatedContracts, parse_gate_policy, parse_gate_request, review_skill,
};
use router_catalog::Catalog;
use router_policy::{
    PhaseAssetInputs, PhaseExecutionScope, PhaseRouter, asset_authority_scope_digest,
};
use router_retrieval::AssetKind;
use router_types::{AssetGateRequest, PhaseRouteRequest, SkillId};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::ExitCode,
};

const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PinnedDocument {
    path: PathBuf,
    expected_hash: String,
}

/// This file is supplied by the parent/operator. It must never be synthesized
/// from an asset's self-reported content_hash or from a child's response.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    contracts: PinnedDocument,
    availability: PinnedDocument,
    policy: PathBuf,
    requests: PathBuf,
    execution_scope: PhaseExecutionScope,
    approved_review_digests: BTreeMap<SkillId, String>,
    metadata: Option<PathBuf>,
    body_root: Option<PathBuf>,
}

fn bytes(path: &Path, limit: usize) -> Result<Vec<u8>, CliError> {
    read_bounded(
        path,
        limit,
        CliError::Product("assets.input.unavailable"),
        CliError::Product("assets.input.limit"),
    )
}
fn resolve(base: &Path, path: &Path) -> Result<PathBuf, CliError> {
    let text = path
        .to_str()
        .ok_or(CliError::Product("assets.path.invalid"))?;
    if text.is_empty() || text.len() > 4096 || text.contains(['\0', '\n', '\r']) {
        return Err(CliError::Product("assets.path.invalid"));
    }
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    })
}
fn manifest(path: &Path) -> Result<(Manifest, PathBuf), CliError> {
    let value = router_adapter_api::strict_json(&bytes(path, MAX_MANIFEST_BYTES)?)
        .map_err(|_| CliError::Product("assets.manifest.invalid"))?;
    let manifest: Manifest =
        serde_json::from_value(value).map_err(|_| CliError::Product("assets.manifest.invalid"))?;
    if manifest.schema_version != 1 || manifest.approved_review_digests.len() > 256 {
        return Err(CliError::Product("assets.manifest.invalid"));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| CliError::Product("assets.path.invalid"))?
            .join(path)
    };
    let base = absolute
        .parent()
        .ok_or(CliError::Product("assets.path.invalid"))?
        .to_path_buf();
    Ok((manifest, base))
}

fn load_manifest(
    manifest: &Manifest,
    base: &Path,
    request: &PhaseRouteRequest,
    snapshot: &ValidatedHostObservation,
    catalog: &Catalog,
    now: u64,
) -> Result<PhaseAssetInputs, CliError> {
    let contracts = ValidatedContracts::from_json(
        &bytes(
            &resolve(base, &manifest.contracts.path)?,
            MAX_DOCUMENT_BYTES,
        )?,
        catalog,
        &manifest.contracts.expected_hash,
    )
    .map_err(|e| CliError::Product(e.code()))?;
    let availability = ValidatedAvailability::from_json(
        &bytes(
            &resolve(base, &manifest.availability.path)?,
            MAX_DOCUMENT_BYTES,
        )?,
        snapshot,
        &manifest.availability.expected_hash,
        now,
    )
    .map_err(|e| CliError::Product(e.code()))?;
    let policy = parse_gate_policy(&bytes(
        &resolve(base, &manifest.policy)?,
        MAX_MANIFEST_BYTES,
    )?)
    .map_err(|e| CliError::Product(e.code()))?;
    let raw = router_adapter_api::strict_json(&bytes(
        &resolve(base, &manifest.requests)?,
        MAX_DOCUMENT_BYTES,
    )?)
    .map_err(|_| CliError::Product("assets.requests.invalid"))?;
    let object = raw
        .as_object()
        .filter(|o| !o.is_empty() && o.len() <= router_policy::MAX_PHASE_CANDIDATES)
        .ok_or(CliError::Product("assets.requests.invalid"))?;
    let mut requests = BTreeMap::<String, AssetGateRequest>::new();
    for (id, value) in object {
        let item = parse_gate_request(&serde_json::to_vec(value).map_err(|_| CliError::Internal)?)
            .map_err(|e| CliError::Product(e.code()))?;
        if id != &item.candidate_id {
            return Err(CliError::Product("assets.requests.binding"));
        }
        requests.insert(id.clone(), item);
    }
    let scope =
        asset_authority_scope_digest(request, &manifest.execution_scope).map_err(phases::error)?;
    if requests.values().any(|r| r.authority_scope_digest != scope) {
        return Err(CliError::Product("assets.scope.mismatch"));
    }
    for (id, digest) in &manifest.approved_review_digests {
        if contracts.skill(id).is_none()
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(CliError::Product("assets.approval.invalid"));
        }
    }
    Ok(PhaseAssetInputs {
        execution_scope: manifest.execution_scope.clone(),
        contracts,
        availability,
        policy,
        requests,
        approved_review_digests: manifest.approved_review_digests.clone(),
    })
}

/// Metadata only. In particular metadata/body_root are not opened here. The
/// phase router validates candidate bindings before any metadata ranking.
pub(crate) fn load(
    path: &Path,
    request: &PhaseRouteRequest,
    snapshot: &ValidatedHostObservation,
    catalog: &Catalog,
    now: u64,
) -> Result<PhaseAssetInputs, CliError> {
    let (manifest, base) = manifest(path)?;
    load_manifest(&manifest, &base, request, snapshot, catalog, now)
}

/// Historical reconstruction still validates the full pinned documents in
/// `load`. This clock is never passed to a new execution or approval.
pub(crate) fn historical_time(path: &Path) -> Result<u64, CliError> {
    let (manifest, base) = manifest(path)?;
    let document: router_types::AssetAvailabilityDocument = phases::read_json(
        &resolve(&base, &manifest.availability.path)?,
        MAX_DOCUMENT_BYTES,
    )?;
    Ok(document.observed_at_unix_seconds)
}

/// Print review projections for explicitly requested skills only. This does not
/// update an approval file, create a proof or launch any provider/skill process.
pub(crate) fn review(
    path: &Path,
    phase: &PhaseArgs,
    skill_ids: &[String],
    json: bool,
) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    if skill_ids.is_empty() || skill_ids.len() > 16 {
        return Err(CliError::Product("assets.review.selection"));
    }
    let skills: BTreeSet<_> = skill_ids
        .iter()
        .map(|id| {
            SkillId::parse(id.clone()).map_err(|_| CliError::Product("assets.review.selection"))
        })
        .collect::<Result<_, _>>()?;
    if skills.len() != skill_ids.len() {
        return Err(CliError::Product("assets.review.selection"));
    }
    let request: PhaseRouteRequest =
        phases::read_json(&phase.context, router_policy::MAX_PHASE_REQUEST_BYTES)?;
    let (snapshot, catalog) = phases::load_observation_catalog(phase, &request, None)?;
    let now = inspect::current_time(phase.now)?;
    let (manifest, base) = manifest(path)?;
    let loaded = load_manifest(&manifest, &base, &request, &snapshot, &catalog, now)?;
    let allowed: BTreeSet<_> = request
        .candidates
        .iter()
        .flat_map(|c| c.skills.iter())
        .collect();
    if skills.iter().any(|s| !allowed.contains(s)) {
        return Err(CliError::Product("assets.review.outside_pool"));
    }
    let scope =
        asset_authority_scope_digest(&request, &loaded.execution_scope).map_err(phases::error)?;
    // Ensure strict candidate/scope bindings without reading any body. Missing
    // approvals are allowed here because this command exists to review them.
    PhaseRouter::new(phases::selected_policy(phase)?)
        .map_err(phases::error)?
        .context_with_assets(request, &snapshot, &catalog, loaded.clone(), now)
        .map_err(phases::error)?;
    let metadata = manifest
        .metadata
        .as_ref()
        .ok_or(CliError::Product("assets.review.metadata_required"))?;
    let root = manifest
        .body_root
        .as_ref()
        .ok_or(CliError::Product("assets.review.body_root_required"))?;
    let index = product::read_index(&resolve(&base, metadata)?)?;
    index
        .validate_catalog_hash(loaded.contracts.catalog_hash())
        .map_err(|_| CliError::Product("assets.review.catalog_binding"))?;
    let root = resolve(&base, root)?;
    let mut projections = Vec::new();
    for skill in skills {
        let body = index
            .load_body_with_catalog(
                &root,
                AssetKind::Skill,
                skill.as_str(),
                loaded.contracts.catalog_hash(),
            )
            .map_err(|_| CliError::Product("assets.review.body_unavailable_or_mismatch"))?;
        let declared = loaded
            .contracts
            .skill(&skill)
            .ok_or(CliError::Product("assets.review.manifest_missing"))?;
        let metadata = index
            .asset(AssetKind::Skill, skill.as_str())
            .ok_or(CliError::Product("assets.review.metadata_missing"))?;
        if declared.trust != metadata.trust {
            return Err(CliError::Product("assets.review.trust_mismatch"));
        }
        let review = review_skill(
            &loaded.contracts,
            &skill,
            body.text.as_bytes(),
            &loaded.policy,
            &scope,
        )
        .map_err(|e| CliError::Product(e.code()))?;
        projections.push(review.projection().clone());
    }
    product::json_output(
        &serde_json::json!({"schema_version":1,"contracts_hash":loaded.contracts.hash(),"availability_hash":loaded.availability.hash(),
        "authority_scope_digest":scope,"reviews":projections,"approved":false,"executed":false,"source_authentication":"unknown"}),
        ExitCode::SUCCESS,
    )
}

fn seal_document<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    let value = router_adapter_api::strict_json(&bytes(path, MAX_DOCUMENT_BYTES)?)
        .map_err(|_| CliError::Product("assets.seal.document_invalid"))?;
    serde_json::from_value(value).map_err(|_| CliError::Product("assets.seal.document_invalid"))
}

/// Compute the integrity hash of an unsealed contracts or availability document
/// and print the sealed document. Nothing is written and no manifest, pin or
/// approval is created: the operator still pins the printed hash independently.
pub(crate) struct SealArgs<'a> {
    pub proof: &'a ProofArgs,
    pub kind: AssetSealKind,
    pub document: &'a Path,
    pub catalog: Option<&'a Path>,
    pub host_snapshot: Option<&'a Path>,
    pub now: Option<u64>,
    pub snapshot_max_age_seconds: u64,
    pub json: bool,
}

pub(crate) fn seal(args: SealArgs<'_>) -> Result<Outcome, CliError> {
    let SealArgs {
        proof,
        kind,
        document,
        catalog,
        host_snapshot,
        now,
        snapshot_max_age_seconds,
        json,
    } = args;
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    let (label, sealed, hash) = match kind {
        AssetSealKind::Contracts => {
            let catalog = catalog.ok_or(CliError::Product("assets.seal.input_required"))?;
            let (catalog, _) =
                catalogs::load_with_proofs(catalog, now, snapshot_max_age_seconds, proof)?;
            let unsealed: router_types::AssetContractsDocument = seal_document(document)?;
            let sealed = router_asset_contracts::seal_contracts(unsealed, &catalog)
                .map_err(|e| CliError::Product(e.code()))?;
            let hash = sealed.content_hash.clone();
            (
                "contracts",
                serde_json::to_value(&sealed).map_err(|_| CliError::Internal)?,
                hash,
            )
        }
        AssetSealKind::Availability => {
            let path = host_snapshot.ok_or(CliError::Product("assets.seal.input_required"))?;
            let snapshot =
                catalogs::read_snapshot_with_proofs(path, now, snapshot_max_age_seconds, proof)?;
            let unsealed: router_types::AssetAvailabilityDocument = seal_document(document)?;
            let sealed = router_asset_contracts::seal_availability(unsealed, &snapshot)
                .map_err(|e| CliError::Product(e.code()))?;
            let hash = sealed.content_hash.clone();
            (
                "availability",
                serde_json::to_value(&sealed).map_err(|_| CliError::Internal)?,
                hash,
            )
        }
    };
    product::json_output(
        &serde_json::json!({"schema_version":1,"kind":label,"content_hash":hash,"document":sealed,
        "approved":false,"authority_established":false,"source_authentication":"unknown"}),
        ExitCode::SUCCESS,
    )
}
