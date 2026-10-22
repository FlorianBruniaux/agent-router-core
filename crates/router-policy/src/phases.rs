//! Opt-in v2 phase routing. v1 Router behavior and receipts are unchanged.
use std::collections::{BTreeMap, BTreeSet};

use crate::asset_phases::ValidatedPhaseAssets;
use crate::signed_phases::ValidatedPhaseCatalog;
use router_adapter_api::{HostObservation, ValidatedHostObservation};
use router_catalog::Catalog;
use router_types::*;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const MAX_PHASE_CANDIDATES: usize = 64;
pub const MAX_PHASE_ASSETS: usize = 256;
pub const MAX_PHASE_REQUEST_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PhaseRouteError {
    #[error("phase.asset_contract: {0}")]
    AssetContract(#[from] router_asset_contracts::ContractError),
    #[error("phase.invalid: {0}")]
    Invalid(&'static str),
    #[error("phase.limit: {0}")]
    Limit(&'static str),
    #[error("phase.serialization")]
    Serialization,
    #[error("phase.catalog.integrity")]
    Catalog,
    #[error("phase.selection.outside_pool")]
    OutsidePool,
    #[error("phase.selection.ineligible")]
    Ineligible,
    #[error("phase.policy.mismatch")]
    PolicyMismatch,
    #[error("phase.receipt.mismatch")]
    ReceiptMismatch,
}

type Result<T> = std::result::Result<T, PhaseRouteError>;

/// A deterministic receipt reproduced against an immutable context. This does
/// not attest a provider failure or authorize execution; downstream approval
/// still covers the complete receipt, including caller-declared unavailable IDs.
#[derive(Clone, Debug)]
pub struct ValidatedPhaseReceipt {
    receipt: PhaseReceipt,
    selection: PhaseSelection,
}

impl ValidatedPhaseReceipt {
    pub fn receipt(&self) -> &PhaseReceipt {
        &self.receipt
    }
    pub fn selection(&self) -> &PhaseSelection {
        &self.selection
    }
    pub fn context_hash(&self) -> &str {
        &self.receipt.context_hash
    }
}

/// Immutable after construction: all eligibility evidence and full input hashes
/// are owned snapshots, not references to mutable candidate or catalog data.
#[derive(Clone, Debug)]
pub struct ValidatedPhaseContext {
    pub(crate) assets: Option<ValidatedPhaseAssets>,
    pub(crate) signed_catalog: Option<ValidatedPhaseCatalog>,
    request: PhaseRouteRequest,
    policy: PhasePolicy,
    snapshot: HostObservation,
    snapshot_authority: ValidatedHostObservation,
    capability_acceptance: router_adapter_api::CapabilityAcceptance,
    capability_evidence: BTreeMap<Capability, CapabilityReceiptEvidence>,
    context_hash: String,
    catalog_hash: String,
    policy_hash: String,
    pool_hash: String,
    registry_hash: String,
    eligible: Vec<PhaseSelection>,
    execution_capabilities: BTreeMap<String, BTreeSet<Capability>>,
    exclusions: Vec<PhaseExclusion>,
}

impl ValidatedPhaseContext {
    pub fn capability_acceptance(&self) -> &router_adapter_api::CapabilityAcceptance {
        &self.capability_acceptance
    }

    pub fn request(&self) -> &PhaseRouteRequest {
        &self.request
    }
    /// Retains non-serialized validation for pure preparation, never dispatch.
    pub fn revalidate_snapshot(
        &self,
        validation: router_adapter_api::SnapshotValidation,
    ) -> std::result::Result<ValidatedHostObservation, router_adapter_api::SnapshotError> {
        self.snapshot_authority.revalidate_at(validation)
    }
    pub fn snapshot(&self) -> &HostObservation {
        &self.snapshot
    }
    pub fn context_hash(&self) -> &str {
        &self.context_hash
    }
    pub fn pool_hash(&self) -> &str {
        &self.pool_hash
    }
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }
    pub fn catalog_hash(&self) -> &str {
        &self.catalog_hash
    }
    pub fn has_asset_contracts(&self) -> bool {
        self.assets.is_some()
    }
    pub(crate) fn eligible_selection(&self, id: &str) -> Option<&PhaseSelection> {
        self.eligible
            .iter()
            .find(|selection| selection.candidate.id == id)
    }
}

#[derive(Clone, Debug)]
pub struct PhaseRouter {
    policy: PhasePolicy,
}

impl PhaseRouter {
    pub fn new(policy: PhasePolicy) -> Result<Self> {
        validate_policy(&policy)?;
        Ok(Self { policy })
    }

    pub fn stable_v2() -> Self {
        Self {
            policy: PhasePolicy::default(),
        }
    }

    pub fn context(
        &self,
        request: PhaseRouteRequest,
        snapshot: &ValidatedHostObservation,
        catalog: &Catalog,
    ) -> Result<ValidatedPhaseContext> {
        self.context_inner(request, snapshot, catalog, None, None)
    }

    pub(crate) fn context_inner(
        &self,
        mut request: PhaseRouteRequest,
        snapshot: &ValidatedHostObservation,
        catalog: &Catalog,
        assets: Option<ValidatedPhaseAssets>,
        signed_catalog: Option<ValidatedPhaseCatalog>,
    ) -> Result<ValidatedPhaseContext> {
        validate_request(&request)?;
        router_workflow::validate_task(&request.task)
            .map_err(|_| PhaseRouteError::Invalid("normalized task"))?;
        router_workflow::validate_restrictions(&request.restrictions)
            .map_err(|_| PhaseRouteError::Invalid("effective restrictions"))?;
        request.candidates.sort_by(|a, b| a.id.cmp(&b.id));
        request
            .registry
            .assets
            .sort_by(|a, b| (a.kind, &a.id).cmp(&(b.kind, &b.id)));
        let catalog_hash = catalog
            .content_hash()
            .map_err(|_| PhaseRouteError::Catalog)?;
        let policy_hash = hash(
            if self.policy.schema_version == 3 {
                "phase-policy-v3"
            } else {
                "phase-policy-v2"
            },
            &self.policy,
        )?;
        let capability_acceptance =
            router_adapter_api::CapabilityAcceptance::from_policy(&self.policy, &policy_hash)
                .map_err(|_| PhaseRouteError::Invalid("capability acceptance"))?;
        let legacy_pool_hash = hash("phase-pool-v2", &request.candidates)?;
        let pool_hash = match &signed_catalog {
            Some(signed) => hash(
                "phase-pool-v4",
                &(&legacy_pool_hash, signed.binding_digest()),
            )?,
            None => legacy_pool_hash,
        };
        let registry_hash = hash("phase-registry-v2", &request.registry)?;
        // The snapshot payload is bound in addition to its digest, and the entire
        // canonical catalog hash is bound rather than its declared version.
        let legacy_context_hash = hash(
            "phase-context-v2",
            &(
                &request,
                snapshot.observation(),
                &catalog_hash,
                &self.policy,
            ),
        )?;
        let context_hash = match &assets {
            Some(assets) => hash(
                "phase-context-v3",
                &(&legacy_context_hash, assets.binding_digest()),
            )?,
            None => legacy_context_hash,
        };
        let context_hash = match &signed_catalog {
            Some(signed) => hash(
                "phase-context-v4",
                &(&context_hash, signed.binding_digest()),
            )?,
            None => context_hash,
        };
        let mut eligible = Vec::new();
        let mut execution_capabilities = BTreeMap::new();
        let mut exclusions = Vec::new();
        let registry: BTreeMap<_, _> = request
            .registry
            .assets
            .iter()
            .map(|asset| ((asset.kind, asset.id.as_str()), asset))
            .collect();
        for candidate in &request.candidates {
            match evaluate(
                &request,
                candidate,
                snapshot,
                catalog,
                &registry,
                &self.policy,
                &capability_acceptance,
                assets.as_ref(),
                signed_catalog.as_ref(),
            )? {
                Ok(evaluation) => {
                    execution_capabilities.insert(
                        evaluation.selection.candidate.id.clone(),
                        evaluation.capabilities,
                    );
                    eligible.push(evaluation.selection);
                }
                Err(mut failures) => exclusions.append(&mut failures),
            }
        }
        let preferred = request.restrictions.preferred_model.as_ref();
        for selection in &mut eligible {
            if preferred == Some(&selection.candidate.model) {
                selection.reasons.push(
                    "configuration prefers this model among candidates passing all hard constraints"
                        .into(),
                );
            }
        }
        eligible.sort_by(|a, b| {
            (preferred == Some(&b.candidate.model))
                .cmp(&(preferred == Some(&a.candidate.model)))
                .then_with(|| b.score.utility_micros.cmp(&a.score.utility_micros))
                .then_with(|| a.candidate.id.cmp(&b.candidate.id))
        });
        exclusions.sort_by(|a, b| {
            (&a.candidate_id, &a.code, &a.evidence).cmp(&(&b.candidate_id, &b.code, &b.evidence))
        });
        exclusions.dedup();
        Ok(ValidatedPhaseContext {
            assets,
            signed_catalog,
            request,
            policy: self.policy.clone(),
            snapshot: snapshot.observation().clone(),
            snapshot_authority: snapshot.clone(),
            capability_acceptance,
            capability_evidence: snapshot
                .capability_proofs()
                .iter()
                .map(|proof| {
                    (
                        proof.capability,
                        CapabilityReceiptEvidence {
                            proof_sha256: proof.proof_sha256.clone(),
                            tier: match proof.tier {
                                router_adapter_api::CapabilityProofTier::Proven => "proven",
                                router_adapter_api::CapabilityProofTier::Attested => "attested",
                            }
                            .into(),
                            observed_at_unix_seconds: proof.observed_at_unix_seconds,
                            expires_at_unix_seconds: proof.expires_at_unix_seconds,
                        },
                    )
                })
                .collect(),
            context_hash,
            catalog_hash,
            policy_hash,
            pool_hash,
            registry_hash,
            eligible,
            execution_capabilities,
            exclusions,
        })
    }

    pub fn route(&self, context: &ValidatedPhaseContext) -> Result<PhaseReceipt> {
        self.fallback(context, &BTreeSet::new())
    }

    /// Reproduce the entire normal or fallback decision, including score,
    /// exclusions, hashes and order. A valid candidate ID alone is insufficient.
    pub fn validate_receipt(
        &self,
        context: &ValidatedPhaseContext,
        receipt: &PhaseReceipt,
    ) -> Result<ValidatedPhaseReceipt> {
        let expected = self.fallback(context, &receipt.unavailable)?;
        if expected != *receipt {
            return Err(PhaseRouteError::ReceiptMismatch);
        }
        let selection = expected
            .selected
            .clone()
            .ok_or(PhaseRouteError::Ineligible)?;
        self.validate_selection(context, &selection)?;
        Ok(ValidatedPhaseReceipt {
            receipt: expected,
            selection,
        })
    }

    /// Explicitly unavailable candidate IDs are removed from the immutable pool.
    /// No retry adds assets, broadens permissions or probes a provider.
    pub fn fallback(
        &self,
        context: &ValidatedPhaseContext,
        unavailable: &BTreeSet<String>,
    ) -> Result<PhaseReceipt> {
        self.check_policy(context)?;
        if unavailable.len() > MAX_PHASE_CANDIDATES {
            return Err(PhaseRouteError::Limit("unavailable candidates"));
        }
        if unavailable
            .iter()
            .any(|id| !context.request.candidates.iter().any(|c| &c.id == id))
        {
            return Err(PhaseRouteError::OutsidePool);
        }
        let remaining: Vec<_> = context
            .eligible
            .iter()
            .filter(|s| !unavailable.contains(&s.candidate.id))
            .collect();
        let mut exclusions = context.exclusions.clone();
        for id in unavailable {
            exclusions.push(PhaseExclusion {
                candidate_id: id.clone(),
                code: "candidate.unavailable".into(),
                evidence: "explicit fallback input; no provider call".into(),
            });
        }
        exclusions.sort_by(|a, b| {
            (&a.candidate_id, &a.code, &a.evidence).cmp(&(&b.candidate_id, &b.code, &b.evidence))
        });
        let abstention = if context.request.candidates.is_empty() {
            Some(PhaseAbstention::EmptyPool)
        } else if context.eligible.is_empty() {
            Some(PhaseAbstention::NoEligibleCandidate)
        } else if remaining.is_empty() {
            Some(PhaseAbstention::AllUnavailable)
        } else if remaining[0].score.utility_micros < self.policy.minimum_utility_micros {
            Some(PhaseAbstention::BelowThreshold)
        } else if remaining.get(1).is_some_and(|next| {
            let preferred = context.request.restrictions.preferred_model.as_ref();
            (preferred == Some(&remaining[0].candidate.model))
                == (preferred == Some(&next.candidate.model))
                && i128::from(remaining[0].score.utility_micros)
                    - i128::from(next.score.utility_micros)
                    <= i128::from(self.policy.ambiguity_margin_micros)
        }) {
            Some(PhaseAbstention::Ambiguous)
        } else {
            None
        };
        let selected = if abstention.is_none() {
            remaining.first().map(|s| (*s).clone())
        } else {
            None
        };
        let alternatives = remaining
            .iter()
            .skip(usize::from(selected.is_some()))
            .take(self.policy.max_alternatives)
            .map(|s| (*s).clone())
            .collect();
        let required = selected
            .as_ref()
            .map(|selection| self.execution_capabilities(context, selection))
            .transpose()?
            .unwrap_or_default();
        let capability_evidence: BTreeMap<_, _> = context
            .capability_evidence
            .iter()
            .filter(|(capability, _)| required.contains(capability))
            .map(|(capability, proof)| (*capability, proof.clone()))
            .collect();
        let proven = !capability_evidence.is_empty();
        let attested = capability_evidence
            .values()
            .any(|evidence| evidence.tier == "attested");
        let mut receipt = PhaseReceipt {
            capability_evidence,
            schema_version: if attested {
                6
            } else if proven {
                5
            } else if context.signed_catalog.is_some() {
                4
            } else if context.assets.is_some() {
                3
            } else {
                2
            },
            receipt_id: String::new(),
            phase: context.request.phase,
            context_hash: context.context_hash.clone(),
            snapshot_hash: context.snapshot.snapshot_hash.clone(),
            catalog_hash: context.catalog_hash.clone(),
            policy_hash: context.policy_hash.clone(),
            pool_hash: context.pool_hash.clone(),
            registry_hash: context.registry_hash.clone(),
            selected,
            alternatives,
            exclusions,
            abstention,
            unavailable: unavailable.clone(),
        };
        receipt.receipt_id = hash(
            if attested {
                "phase-receipt-v6"
            } else if proven {
                "phase-receipt-v5"
            } else if context.signed_catalog.is_some() {
                "phase-receipt-v4"
            } else if context.assets.is_some() {
                "phase-receipt-v3"
            } else {
                "phase-receipt-v2"
            },
            &receipt,
        )?;
        Ok(receipt)
    }

    /// Validate the whole selection, not only its ID. A known ID cannot hide
    /// substituted models, efforts, skills, tools, sandbox or score evidence.
    pub fn validate_selection(
        &self,
        context: &ValidatedPhaseContext,
        selection: &PhaseSelection,
    ) -> Result<()> {
        self.check_policy(context)?;
        if !context
            .request
            .candidates
            .iter()
            .any(|c| c == &selection.candidate)
        {
            return Err(PhaseRouteError::OutsidePool);
        }
        if !context
            .eligible
            .iter()
            .any(|expected| expected == selection)
        {
            return Err(PhaseRouteError::Ineligible);
        }
        Ok(())
    }

    /// Exact capability union checked during eligibility, including selected
    /// registry/skill requirements, tools, sandbox and mutation effects. This
    /// immutable evidence is not inferred from caller-provided asset text.
    pub fn execution_capabilities(
        &self,
        context: &ValidatedPhaseContext,
        selection: &PhaseSelection,
    ) -> Result<BTreeSet<Capability>> {
        self.validate_selection(context, selection)?;
        context
            .execution_capabilities
            .get(&selection.candidate.id)
            .cloned()
            .ok_or(PhaseRouteError::Ineligible)
    }

    fn check_policy(&self, context: &ValidatedPhaseContext) -> Result<()> {
        if self.policy != context.policy {
            return Err(PhaseRouteError::PolicyMismatch);
        }
        Ok(())
    }
}

struct EligibleEvaluation {
    selection: PhaseSelection,
    capabilities: BTreeSet<Capability>,
}

#[allow(clippy::too_many_arguments)]
fn evaluate(
    request: &PhaseRouteRequest,
    candidate: &PhaseCandidate,
    snapshot: &ValidatedHostObservation,
    catalog: &Catalog,
    registry: &BTreeMap<(PhaseAssetKind, &str), &PhaseRegisteredAsset>,
    policy: &PhasePolicy,
    acceptance: &router_adapter_api::CapabilityAcceptance,
    extended_assets: Option<&ValidatedPhaseAssets>,
    signed_catalog: Option<&ValidatedPhaseCatalog>,
) -> Result<std::result::Result<EligibleEvaluation, Vec<PhaseExclusion>>> {
    let mut failures = Vec::new();
    let mut reject = |code: &str, evidence: String| {
        failures.push(PhaseExclusion {
            candidate_id: candidate.id.clone(),
            code: code.into(),
            evidence,
        })
    };
    let mut capabilities = request.task.required_capabilities.clone();
    capabilities.extend(&candidate.required_capabilities);
    let mut mutations = candidate.required_mutations.clone();
    let mut permissions = BTreeSet::from([
        PhasePermission::ModelInference,
        PhasePermission::WorkspaceRead,
    ]);
    let mut assets = Vec::new();
    let model = catalog.model(&candidate.model);
    if model.is_none() {
        reject("model.catalog.missing", candidate.model.to_string());
    }
    if !snapshot.host().supported_models.contains(&candidate.model) {
        reject("model.host.unsupported", candidate.model.to_string());
    }
    if !snapshot
        .host()
        .supported_efforts
        .get(&candidate.model)
        .is_some_and(|efforts| efforts.contains(&candidate.effort))
    {
        reject(
            "effort.host.unsupported",
            format!("{} {:?}", candidate.model, candidate.effort),
        );
    }
    if request
        .restrictions
        .allowed_models
        .as_ref()
        .is_some_and(|models| !models.contains(&candidate.model))
    {
        reject("model.policy.forbidden", candidate.model.to_string());
    }
    if let Some(model) = model {
        if !model.stages.contains(&request.phase) {
            reject("model.phase.unsupported", format!("{:?}", request.phase));
        }
        if !model.efforts.contains(&candidate.effort) {
            reject(
                "effort.catalog.unsupported",
                format!("{:?}", candidate.effort),
            );
        }
        assets.push(PhaseAssetEvidence {
            kind: "model".into(),
            id: model.id.to_string(),
            content_sha256: hash("phase-model-v2", model)?,
            authority: "policy_catalog".into(),
        });
    }
    if candidate.sandbox == PhaseSandbox::WorkspaceWrite {
        capabilities.insert(Capability::WorkspaceWrite);
        mutations.insert(Mutation::WorkspaceWrite);
    }
    if !candidate.tools.is_empty() {
        capabilities.insert(Capability::Tools);
    }
    if candidate.tool_policy == PhaseToolPolicy::NativeHost {
        capabilities.insert(Capability::Tools);
        permissions.insert(PhasePermission::NativeHostTools);
        if !candidate.tools.is_empty() {
            reject(
                "tools.policy.conflict",
                "native host tools cannot represent a tool allowlist".into(),
            );
        }
    }
    for (kind, id) in candidate
        .agent
        .iter()
        .map(|id| (PhaseAssetKind::Agent, id))
        .chain(candidate.tools.iter().map(|id| (PhaseAssetKind::Tool, id)))
    {
        let Some(asset) = registry.get(&(kind, id.as_str())) else {
            reject("asset.registry.missing", id.clone());
            continue;
        };
        if !is_trusted(asset.trust) {
            reject("asset.trust.forbidden", id.clone());
        }
        if asset.permission != CapabilitySupport::Supported {
            reject("asset.permission.unknown_or_denied", id.clone());
        }
        if !asset.allowed_sandboxes.contains(&candidate.sandbox) {
            reject("asset.sandbox.forbidden", id.clone());
        }
        if request.task.sensitivity > asset.maximum_sensitivity {
            reject("asset.data.forbidden", id.clone());
        }
        capabilities.extend(&asset.required_capabilities);
        mutations.extend(&asset.required_mutations);
        assets.push(PhaseAssetEvidence {
            kind: match kind {
                PhaseAssetKind::Agent => "agent",
                PhaseAssetKind::Tool => "tool",
            }
            .into(),
            id: id.clone(),
            content_sha256: asset.content_sha256.clone(),
            authority: "declared_phase_registry".into(),
        });
    }
    for id in &candidate.skills {
        let Some(skill) = catalog.skill(id) else {
            reject("skill.catalog.missing", id.to_string());
            continue;
        };
        if !is_trusted(skill.trust) {
            reject("skill.trust.forbidden", id.to_string());
        }
        if !skill.task_kinds.contains(&request.task.kind) {
            reject("skill.task.incompatible", id.to_string());
        }
        capabilities.extend(&skill.required_capabilities);
        assets.push(PhaseAssetEvidence {
            kind: "skill".into(),
            id: id.to_string(),
            content_sha256: hash("phase-skill-v2", skill)?,
            authority: "policy_catalog".into(),
        });
    }
    if let Some(signed) = signed_catalog {
        match signed.requirements(candidate) {
            Ok((extra_capabilities, extra_mutations)) => {
                capabilities.extend(extra_capabilities);
                mutations.extend(extra_mutations);
            }
            Err(code) => reject(code, "signed asset requirements unavailable".into()),
        }
    }
    if capabilities.contains(&Capability::WorkspaceWrite) {
        mutations.insert(Mutation::WorkspaceWrite);
    }
    if capabilities.contains(&Capability::Network) {
        mutations.insert(Mutation::Network);
    }
    for mutation in &mutations {
        permissions.insert(match mutation {
            Mutation::WorkspaceWrite => PhasePermission::WorkspaceWrite,
            Mutation::Network => PhasePermission::Network,
            Mutation::ExecuteSkills => PhasePermission::ExecuteSkills,
            Mutation::Integrate => PhasePermission::Integrate,
        });
        match mutation {
            Mutation::WorkspaceWrite => {
                capabilities.insert(Capability::WorkspaceWrite);
            }
            Mutation::Network => {
                capabilities.insert(Capability::Network);
            }
            _ => {}
        }
        if !request.task.allowed_mutations.contains(mutation)
            || request
                .restrictions
                .allowed_mutations
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(mutation))
        {
            reject("mutation.forbidden", format!("{mutation:?}"));
        }
        if *mutation == Mutation::WorkspaceWrite && candidate.sandbox == PhaseSandbox::ReadOnly {
            reject(
                "sandbox.write.forbidden",
                "read-only sandbox cannot perform writes".into(),
            );
        }
    }
    for capability in &capabilities {
        match capability {
            Capability::Network => {
                permissions.insert(PhasePermission::Network);
            }
            Capability::WorkspaceWrite => {
                permissions.insert(PhasePermission::WorkspaceWrite);
            }
            Capability::Subagents => {
                permissions.insert(PhasePermission::Delegate);
            }
            _ => {}
        }
        if !snapshot.permits_capability(*capability, acceptance) {
            reject(
                "capability.unknown_or_unsupported",
                format!("{capability:?}"),
            );
        }
        if model.is_some_and(|model| !model.capabilities.contains(capability)) {
            reject("capability.model.unsupported", format!("{capability:?}"));
        }
        if request
            .restrictions
            .allowed_capabilities
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(capability))
        {
            reject("capability.policy.forbidden", format!("{capability:?}"));
        }
    }
    for permission in &permissions {
        if request.permissions.get(permission) != Some(&CapabilitySupport::Supported) {
            reject("permission.unknown_or_denied", format!("{permission:?}"));
        }
    }
    if candidate.estimated_cost_microusd > request.task.budget.max_cost_microusd
        || request
            .restrictions
            .max_cost_microusd
            .is_some_and(|max| candidate.estimated_cost_microusd > max)
    {
        reject(
            "budget.cost.exceeded",
            "declared candidate estimate exceeds allowed cost".into(),
        );
    }
    if candidate.estimated_tokens > request.task.budget.max_tokens
        || request
            .restrictions
            .max_tokens
            .is_some_and(|max| candidate.estimated_tokens > max)
    {
        reject(
            "budget.tokens.exceeded",
            "declared candidate estimate exceeds allowed tokens".into(),
        );
    }
    if candidate.estimated_elapsed_ms > request.task.budget.max_elapsed_ms {
        reject(
            "budget.elapsed.exceeded",
            "declared candidate estimate exceeds allowed elapsed time".into(),
        );
    }
    if candidate.verification == PhaseVerification::None {
        reject(
            "verification.required",
            "normalized task acceptance requires verification".into(),
        );
    }
    if matches!(request.task.risk, RiskLevel::High | RiskLevel::Critical)
        && candidate.verification != PhaseVerification::Independent
    {
        reject(
            "verification.independence.required",
            "high-risk work requires an independent verifier".into(),
        );
    }
    if request.phase == StageKind::Verify
        && candidate.verification == PhaseVerification::Independent
    {
        match &request.previous_model {
            None => reject(
                "verification.previous_model.unknown",
                "cannot establish independence without the previous model".into(),
            ),
            Some(previous) if previous == &candidate.model => {
                reject("verification.model.not_independent", previous.to_string())
            }
            _ => {}
        }
    }
    if !failures.is_empty() {
        return Ok(Err(failures));
    }
    let model = model.ok_or(PhaseRouteError::Invalid("eligible model absent"))?;
    // Scoring is reached only after every hard constraint passes.
    if let Some(extended) = extended_assets {
        match extended.gate_candidate(request, candidate, &capabilities, &mutations, acceptance) {
            Ok((extra_capabilities, extra_mutations)) => {
                capabilities = extra_capabilities;
                mutations = extra_mutations;
                for asset in &mut assets {
                    if asset.kind == "skill" {
                        let id = SkillId::parse(asset.id.clone())
                            .map_err(|_| PhaseRouteError::Invalid("skill id"))?;
                        if let Some(manifest) = extended.skill(&id) {
                            asset.content_sha256 = manifest.body_sha256.clone();
                            asset.authority = "bound_asset_contracts_v1".into();
                        }
                    }
                }
            }
            Err(error) => {
                return Ok(Err(vec![PhaseExclusion {
                    candidate_id: candidate.id.clone(),
                    code: error.code().into(),
                    evidence: "extended asset gate rejected candidate".into(),
                }]));
            }
        }
    }
    if let Some(signed) = signed_catalog {
        match signed.gate_candidate(
            request,
            candidate,
            &capabilities,
            &mutations,
            snapshot,
            acceptance,
            extended_assets,
        ) {
            Ok(signed_assets) => assets.extend(signed_assets),
            Err(code) => {
                return Ok(Err(vec![PhaseExclusion {
                    candidate_id: candidate.id.clone(),
                    code: code.into(),
                    evidence: "current signed catalog rejected candidate before scoring".into(),
                }]));
            }
        }
    }
    let score = score(candidate, model, policy)?;
    assets.sort_by(|a, b| (&a.kind, &a.id).cmp(&(&b.kind, &b.id)));
    let attested_capability_used = capabilities.iter().any(|capability| {
        snapshot.capabilities().get(capability) != Some(&CapabilitySupport::Supported)
            && acceptance.accepts(*capability)
            && snapshot.capability_proofs().iter().any(|proof| {
                proof.capability == *capability
                    && proof.tier == router_adapter_api::CapabilityProofTier::Attested
            })
    });
    Ok(Ok(EligibleEvaluation { selection: PhaseSelection { candidate: candidate.clone(), score, assets, reasons: vec![
        "advertised candidate and exact model/effort are available in the validated snapshot and catalog".into(),
        if attested_capability_used {
            "all required capabilities have accepted evidence and permissions are explicitly supported"
        } else {
            "all required capabilities and permissions are explicitly supported"
        }.into(),
        "every asset passed authoritative trust, compatibility and sandbox checks".into(),
        "declared resource estimates fit task and effective policy limits; no runtime cost is asserted".into(),
        "utility records catalog quality, retrieval relevance, declared cost and latency contributions".into(),
    ] }, capabilities }))
}

fn score(
    candidate: &PhaseCandidate,
    model: &ModelSpec,
    policy: &PhasePolicy,
) -> Result<PhaseScore> {
    let quality = i128::from(model.quality_micros) * i128::from(policy.quality_weight);
    let relevance = i128::from(candidate.relevance_micros) * i128::from(policy.relevance_weight);
    let cost = i128::from(candidate.estimated_cost_microusd) * i128::from(policy.cost_weight);
    let latency = i128::from(candidate.estimated_elapsed_ms) * i128::from(policy.latency_weight);
    let convert =
        |value| i64::try_from(value).map_err(|_| PhaseRouteError::Limit("score arithmetic"));
    Ok(PhaseScore {
        quality_micros: convert(quality)?,
        relevance_micros: convert(relevance)?,
        cost_penalty_micros: convert(cost)?,
        latency_penalty_micros: convert(latency)?,
        utility_micros: convert(quality + relevance - cost - latency)?,
    })
}

fn validate_policy(policy: &PhasePolicy) -> Result<()> {
    if !matches!(policy.schema_version, 2 | 3)
        || (policy.schema_version == 2 && !policy.accepted_attestations.is_empty())
        || !identifier(&policy.version)
    {
        return Err(PhaseRouteError::Invalid("phase policy version"));
    }
    if [
        policy.quality_weight,
        policy.relevance_weight,
        policy.cost_weight,
        policy.latency_weight,
    ]
    .iter()
    .any(|weight| *weight > 1_000_000)
        || policy.max_alternatives > 8
        || policy.ambiguity_margin_micros > i64::MAX as u64
    {
        return Err(PhaseRouteError::Limit("phase policy"));
    }
    Ok(())
}

pub(crate) fn validate_request(request: &PhaseRouteRequest) -> Result<()> {
    if request.schema_version != 2
        || request.registry.schema_version != 1
        || !identifier(&request.registry.version)
    {
        return Err(PhaseRouteError::Invalid(
            "phase request or registry version",
        ));
    }
    if request.candidates.len() > MAX_PHASE_CANDIDATES
        || request.registry.assets.len() > MAX_PHASE_ASSETS
    {
        return Err(PhaseRouteError::Limit("phase pool or registry"));
    }
    let bytes = serde_json::to_vec(request).map_err(|_| PhaseRouteError::Serialization)?;
    if bytes.len() > MAX_PHASE_REQUEST_BYTES {
        return Err(PhaseRouteError::Limit("phase request bytes"));
    }
    let mut ids = BTreeSet::new();
    for candidate in &request.candidates {
        if !identifier(&candidate.id)
            || !identifier(candidate.model.as_str())
            || !ids.insert(&candidate.id)
        {
            return Err(PhaseRouteError::Invalid("candidate identifier"));
        }
        if candidate.skills.len() > 32
            || candidate.tools.len() > 32
            || candidate.relevance_micros > 1_000_000
            || candidate.estimated_cost_microusd > 1_000_000_000_000
            || candidate.estimated_tokens == 0
            || candidate.estimated_tokens > 1_000_000_000
            || candidate.estimated_elapsed_ms == 0
            || candidate.estimated_elapsed_ms > 1_000_000_000
        {
            return Err(PhaseRouteError::Limit("candidate bounds"));
        }
        if candidate.agent.as_ref().is_some_and(|id| !identifier(id))
            || candidate.tools.iter().any(|id| !identifier(id))
            || candidate.skills.iter().any(|id| !identifier(id.as_str()))
        {
            return Err(PhaseRouteError::Invalid("candidate asset identifier"));
        }
    }
    let mut assets = BTreeSet::new();
    for asset in &request.registry.assets {
        if !identifier(&asset.id)
            || !assets.insert((asset.kind, &asset.id))
            || !valid_hash(&asset.content_sha256)
            || asset.license.trim().is_empty()
            || asset.license.len() > 128
            || asset.license.chars().any(char::is_control)
        {
            return Err(PhaseRouteError::Invalid(
                "registered asset identity, hash or license",
            ));
        }
    }
    if request
        .previous_model
        .as_ref()
        .is_some_and(|model| !identifier(model.as_str()))
    {
        return Err(PhaseRouteError::Invalid("previous model"));
    }
    Ok(())
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn is_trusted(trust: SkillTrust) -> bool {
    matches!(
        trust,
        SkillTrust::Builtin | SkillTrust::TrustedLocal | SkillTrust::VerifiedThirdParty
    )
}
pub(crate) fn hash(domain: &str, value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| PhaseRouteError::Serialization)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}
