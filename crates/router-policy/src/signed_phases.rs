//! Current signed catalogs constrain routing; they do not authorize execution.
use crate::{
    PhaseAssetInputs, PhaseExecutionScope, PhaseRouteError, PhaseRouter, ValidatedPhaseContext,
    asset_authority_scope_digest, asset_phases::ValidatedPhaseAssets, phases,
};
use router_adapter_api::{EvidenceKind, ValidatedHostObservation};
use router_catalog::{
    CatalogAssetKind, SignedAssetKey, SignedAssetPayload, SignedCatalogEntry,
    TrustedCatalogPublishers,
};
use router_catalog_store::{CatalogHead, CurrentCatalogGuard, StoreIdentity};
use router_retrieval::{AssetKind, Bm25Index};
use router_types::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

type Result<T> = std::result::Result<T, PhaseRouteError>;

/// Caller choices and scope, never publisher permission or current authority.
/// Prompt IDs cover the exact candidate pool. No bodies are read during routing.
#[derive(Clone, Debug, Serialize)]
pub struct SignedPhaseInputs {
    pub host_asset_id: String,
    pub preset_asset_id: String,
    pub prompt_ids: BTreeMap<String, String>,
    pub execution_scope: PhaseExecutionScope,
}

#[derive(Clone, Debug)]
pub(crate) struct ValidatedPhaseCatalog {
    head: CatalogHead,
    authority_hash: String,
    inputs: SignedPhaseInputs,
    entries: BTreeMap<SignedAssetKey, SignedCatalogEntry>,
    trust: BTreeMap<SignedAssetKey, SkillTrust>,
    host: AssetHostBinding,
    plan: WorkflowPlan,
}

impl PhaseRouter {
    /// Build a v4 routing context only from a current opaque store guard. The
    /// returned snapshot is not a dispatch guard; current runtime APIs refuse it.
    #[allow(clippy::too_many_arguments)]
    pub fn context_with_signed_catalog(
        &self,
        request: PhaseRouteRequest,
        snapshot: &ValidatedHostObservation,
        guard: &CurrentCatalogGuard,
        publishers: &TrustedCatalogPublishers,
        inputs: SignedPhaseInputs,
        assets: Option<PhaseAssetInputs>,
        index: &Bm25Index,
        now: u64,
    ) -> Result<ValidatedPhaseContext> {
        phases::validate_request(&request)?;
        let scope_hash = asset_authority_scope_digest(&request, &inputs.execution_scope)?;
        let ids: BTreeSet<_> = request.candidates.iter().map(|c| &c.id).collect();
        if inputs.prompt_ids.keys().collect::<BTreeSet<_>>() != ids
            || !identifier(&inputs.host_asset_id)
            || !identifier(&inputs.preset_asset_id)
            || inputs.prompt_ids.values().any(|id| !identifier(id))
            || assets
                .as_ref()
                .is_some_and(|assets| assets.execution_scope != inputs.execution_scope)
        {
            return Err(PhaseRouteError::Invalid("signed catalog inputs"));
        }
        let access = guard
            .access(publishers, now)
            .map_err(|_| PhaseRouteError::Invalid("signed catalog current authority"))?;
        let signed = guard.catalog();
        signed
            .validate_retrieval(index, &access)
            .map_err(|_| PhaseRouteError::Invalid("signed catalog metadata"))?;
        let catalog = signed
            .catalog(&access)
            .map_err(|_| PhaseRouteError::Catalog)?;
        let definition = signed
            .host(&inputs.host_asset_id, &access)
            .map_err(|_| PhaseRouteError::Invalid("signed host"))?;
        // A model cache or a host declaration never proves the native version.
        // Conflicting observed versions cannot select whichever pin is convenient.
        let versions: BTreeSet<_> = snapshot
            .observation()
            .evidence
            .iter()
            .filter(|e| e.kind != EvidenceKind::CodexModelCache)
            .filter_map(|e| e.observed_version.as_ref())
            .collect();
        let version = versions
            .iter()
            .next()
            .filter(|_| versions.len() == 1)
            .ok_or(PhaseRouteError::Invalid(
                "signed host version unknown or conflicting",
            ))?;
        if definition.harness != snapshot.host().harness || !definition.versions.contains(*version)
        {
            return Err(PhaseRouteError::Invalid("signed host version mismatch"));
        }
        let host = AssetHostBinding {
            harness: snapshot.host().harness.clone(),
            version: (*version).clone(),
        };
        let projected = signed
            .build_plan(&inputs.preset_asset_id, &request.task, &host, &access)
            .map_err(|_| PhaseRouteError::Invalid("signed preset task"))?;
        // The caller must explicitly adopt any tighter task before routing.
        // No silent risk/budget/scope rewrite makes an existing request valid.
        if projected.plan().task != request.task {
            return Err(PhaseRouteError::Invalid(
                "signed preset requires restricted task",
            ));
        }
        let entries: BTreeMap<_, _> = signed
            .entries(&access)
            .map_err(|_| PhaseRouteError::Catalog)?
            .iter()
            .map(|entry| (entry.key(), entry.clone()))
            .collect();
        let trust = entries
            .iter()
            .filter_map(|(key, _)| {
                retrieval_kind(key.kind).and_then(|kind| {
                    index
                        .asset(kind, &key.id)
                        .map(|metadata| (key.clone(), metadata.trust))
                })
            })
            .collect();
        let head = guard.head().clone();
        let config_hash = StoreIdentity {
            schema_version: 1,
            store_id: head.store_id.clone(),
            catalog_id: head.catalog_id.clone(),
            locator_sha256: head.locator_sha256.clone(),
        }
        .content_hash()
        .map_err(|_| PhaseRouteError::Catalog)?;
        let authority_hash = phases::hash(
            "phase-signed-authority-v1",
            &(
                &config_hash,
                &head,
                &inputs,
                &scope_hash,
                projected.content_hash(),
                index.source_hash(),
                index.index_hash(),
            ),
        )?;
        let signed = ValidatedPhaseCatalog {
            head,
            authority_hash,
            inputs,
            entries,
            trust,
            host,
            plan: projected.plan().clone(),
        };
        let assets = assets
            .map(|inputs| ValidatedPhaseAssets::new(&request, snapshot, &catalog, inputs, now))
            .transpose()?;
        // Recheck filesystem identity/roots/time after bounded projection work.
        guard
            .access(publishers, now)
            .map_err(|_| PhaseRouteError::Invalid("signed catalog current authority"))?;
        self.context_inner(request, snapshot, &catalog, assets, Some(signed))
    }
}

impl PhaseRouter {
    /// Revalidate a routing snapshot against a currently held catalog read guard.
    /// This check is not a dispatch capability and does not make trust sticky.
    pub fn validate_signed_catalog_authority(
        &self,
        context: &ValidatedPhaseContext,
        guard: &CurrentCatalogGuard,
        publishers: &TrustedCatalogPublishers,
        index: &Bm25Index,
        now: u64,
    ) -> Result<()> {
        self.route(context)?;
        let signed = context
            .signed_catalog
            .as_ref()
            .ok_or(PhaseRouteError::Invalid("signed catalog context required"))?;
        let access = guard
            .access(publishers, now)
            .map_err(|_| PhaseRouteError::Invalid("signed catalog current authority"))?;
        if guard.head() != &signed.head {
            return Err(PhaseRouteError::Invalid("signed catalog head changed"));
        }
        guard
            .catalog()
            .validate_retrieval(index, &access)
            .map_err(|_| PhaseRouteError::Invalid("signed catalog metadata"))?;
        let projected = guard
            .catalog()
            .build_plan(
                &signed.inputs.preset_asset_id,
                &context.request().task,
                &signed.host,
                &access,
            )
            .map_err(|_| PhaseRouteError::Invalid("signed preset task"))?;
        let scope_hash =
            asset_authority_scope_digest(context.request(), &signed.inputs.execution_scope)?;
        let config_hash = StoreIdentity {
            schema_version: 1,
            store_id: signed.head.store_id.clone(),
            catalog_id: signed.head.catalog_id.clone(),
            locator_sha256: signed.head.locator_sha256.clone(),
        }
        .content_hash()
        .map_err(|_| PhaseRouteError::Catalog)?;
        let authority = phases::hash(
            "phase-signed-authority-v1",
            &(
                &config_hash,
                guard.head(),
                &signed.inputs,
                &scope_hash,
                projected.content_hash(),
                index.source_hash(),
                index.index_hash(),
            ),
        )?;
        if authority != signed.authority_hash || projected.plan() != &signed.plan {
            return Err(PhaseRouteError::Invalid("signed catalog authority changed"));
        }
        Ok(())
    }
}

impl ValidatedPhaseContext {
    /// Exact parent execution scope included in this signed routing snapshot.
    pub fn signed_execution_scope(&self) -> Option<&PhaseExecutionScope> {
        self.signed_catalog
            .as_ref()
            .map(|signed| &signed.inputs.execution_scope)
    }
    pub fn has_signed_catalog(&self) -> bool {
        self.signed_catalog.is_some()
    }
    pub fn signed_catalog_head(&self) -> Option<&CatalogHead> {
        self.signed_catalog.as_ref().map(|catalog| &catalog.head)
    }
    pub fn signed_catalog_authority_hash(&self) -> Option<&str> {
        self.signed_catalog
            .as_ref()
            .map(|catalog| catalog.authority_hash.as_str())
    }
    /// Descriptive plan projection. It is not a current execution capability.
    pub fn signed_plan(&self) -> Option<&WorkflowPlan> {
        self.signed_catalog.as_ref().map(|catalog| &catalog.plan)
    }
    pub fn signed_prompt_id(&self, candidate_id: &str) -> Option<&str> {
        self.signed_catalog
            .as_ref()?
            .inputs
            .prompt_ids
            .get(candidate_id)
            .map(String::as_str)
    }
}

impl ValidatedPhaseCatalog {
    pub(crate) fn binding_digest(&self) -> &str {
        &self.authority_hash
    }

    fn selected<'a>(
        &'a self,
        candidate: &PhaseCandidate,
    ) -> std::result::Result<Vec<&'a SignedCatalogEntry>, &'static str> {
        let prompt = self
            .inputs
            .prompt_ids
            .get(&candidate.id)
            .ok_or("signed.prompt.missing")?;
        let mut keys = vec![
            key(CatalogAssetKind::Model, candidate.model.as_str()),
            key(CatalogAssetKind::Host, &self.inputs.host_asset_id),
            key(CatalogAssetKind::Preset, &self.inputs.preset_asset_id),
            key(CatalogAssetKind::Prompt, prompt),
        ];
        keys.extend(
            candidate
                .agent
                .iter()
                .map(|id| key(CatalogAssetKind::Agent, id)),
        );
        keys.extend(
            candidate
                .skills
                .iter()
                .map(|id| key(CatalogAssetKind::Skill, id.as_str())),
        );
        keys.extend(
            candidate
                .tools
                .iter()
                .map(|id| key(CatalogAssetKind::Tool, id)),
        );
        keys.into_iter()
            .map(|key| {
                let entry = self.entries.get(&key).ok_or("signed.asset.missing")?;
                if entry.deprecated_by.is_some()
                    || self.trust.get(&key).is_some_and(|trust| !trusted(*trust))
                {
                    return Err("signed.asset.untrusted_or_deprecated");
                }
                Ok(entry)
            })
            .collect()
    }

    pub(crate) fn requirements(
        &self,
        candidate: &PhaseCandidate,
    ) -> std::result::Result<(BTreeSet<Capability>, BTreeSet<Mutation>), &'static str> {
        let mut capabilities = BTreeSet::new();
        let mut mutations = BTreeSet::new();
        for entry in self.selected(candidate)? {
            capabilities.extend(&entry.requirements.capabilities);
            mutations.extend(&entry.requirements.mutations);
        }
        Ok((capabilities, mutations))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn gate_candidate(
        &self,
        request: &PhaseRouteRequest,
        candidate: &PhaseCandidate,
        capabilities: &BTreeSet<Capability>,
        mutations: &BTreeSet<Mutation>,
        snapshot: &ValidatedHostObservation,
        acceptance: &router_adapter_api::CapabilityAcceptance,
        assets: Option<&ValidatedPhaseAssets>,
    ) -> std::result::Result<Vec<PhaseAssetEvidence>, &'static str> {
        if candidate.tool_policy == PhaseToolPolicy::NativeHost {
            return Err("signed.tools.unrepresented_native_policy");
        }
        if capabilities
            .iter()
            .any(|capability| !snapshot.permits_capability(*capability, acceptance))
        {
            return Err("signed.capability.unknown_or_unsupported");
        }
        let mut evidence = Vec::new();
        let mut reserved_context = 0u64;
        for entry in self.selected(candidate)? {
            if !entry.requirements.compatible_hosts.contains(&self.host) {
                return Err("signed.host.incompatible");
            }
            if !entry.requirements.tools.is_subset(&candidate.tools) {
                return Err("signed.tools.missing");
            }
            if !mutations.is_subset(&entry.restrictions.allowed_mutations) {
                return Err("signed.mutation.forbidden");
            }
            if !entry
                .restrictions
                .allowed_sandboxes
                .contains(&candidate.sandbox)
            {
                return Err("signed.sandbox.forbidden");
            }
            if request.task.sensitivity > entry.restrictions.maximum_sensitivity {
                return Err("signed.sensitivity.forbidden");
            }
            reserved_context = reserved_context
                .checked_add(entry.context_cost_estimate)
                .ok_or("signed.context.exceeded")?;
            match &entry.payload {
                SignedAssetPayload::Model(model) => {
                    if !capabilities.is_subset(&model.capabilities) {
                        return Err("signed.model.capability");
                    }
                }
                SignedAssetPayload::Skill(skill) => {
                    if let Some(assets) = assets {
                        let manifest = assets
                            .skill(&skill.id)
                            .ok_or("signed.skill.contract_missing")?;
                        let body = entry
                            .search
                            .as_ref()
                            .and_then(|metadata| metadata.body.as_ref())
                            .ok_or("signed.skill.body_missing")?;
                        if manifest.body_sha256 != body.sha256
                            || manifest.version != entry.version
                            || manifest.provenance != entry.provenance
                            || manifest.license_expression != entry.license_expression
                            || Some(&manifest.trust) != self.trust.get(&entry.key())
                        {
                            return Err("signed.skill.contract_changed");
                        }
                    }
                }
                SignedAssetPayload::Host(host) => {
                    if !host.compatible_models.contains(&candidate.model)
                        || !capabilities.is_subset(&host.declared_capabilities)
                    {
                        return Err("signed.host.model_or_capability");
                    }
                }
                SignedAssetPayload::Prompt(prompt) => {
                    if !prompt.compatible_models.contains(&candidate.model)
                        || !prompt.compatible_hosts.contains(self.host.harness.as_str())
                    {
                        return Err("signed.prompt.incompatible");
                    }
                }
                SignedAssetPayload::Preset(preset) => {
                    if !capabilities.is_subset(&preset.allowed_capabilities)
                        || request.task.risk < preset.minimum_risk
                        || request.task.budget.max_cost_microusd
                            > preset.maximum_budget.max_cost_microusd
                        || request.task.budget.max_tokens > preset.maximum_budget.max_tokens
                        || request.task.budget.max_elapsed_ms > preset.maximum_budget.max_elapsed_ms
                    {
                        return Err("signed.preset.forbidden");
                    }
                }
                SignedAssetPayload::Agent(declared) | SignedAssetPayload::Tool(declared) => {
                    let mut expected = declared.clone();
                    let parent = request
                        .registry
                        .assets
                        .iter()
                        .find(|asset| asset.kind == declared.kind && asset.id == entry.id)
                        .ok_or("signed.registry.missing")?;
                    expected.permission = parent.permission;
                    expected.trust = *self.trust.get(&entry.key()).ok_or("signed.asset.missing")?;
                    if parent != &expected {
                        return Err("signed.registry.changed");
                    }
                }
            }
            evidence.push(PhaseAssetEvidence {
                kind: match entry.payload.kind() {
                    CatalogAssetKind::Model => "model",
                    CatalogAssetKind::Agent => "agent",
                    CatalogAssetKind::Skill => "skill",
                    CatalogAssetKind::Prompt => "prompt",
                    CatalogAssetKind::Tool => "tool",
                    CatalogAssetKind::Host => "host",
                    CatalogAssetKind::Preset => "preset",
                }
                .into(),
                id: entry.id.clone(),
                content_sha256: entry.payload_sha256.clone(),
                authority: "signed_catalog_store_v1".into(),
            });
        }
        if reserved_context > candidate.estimated_tokens {
            return Err("signed.context.exceeded");
        }
        Ok(evidence)
    }
}
fn key(kind: CatalogAssetKind, id: &str) -> SignedAssetKey {
    SignedAssetKey {
        kind,
        id: id.into(),
    }
}
fn trusted(trust: SkillTrust) -> bool {
    matches!(
        trust,
        SkillTrust::Builtin | SkillTrust::TrustedLocal | SkillTrust::VerifiedThirdParty
    )
}
fn retrieval_kind(kind: CatalogAssetKind) -> Option<AssetKind> {
    Some(match kind {
        CatalogAssetKind::Model => AssetKind::Model,
        CatalogAssetKind::Agent => AssetKind::Agent,
        CatalogAssetKind::Skill => AssetKind::Skill,
        CatalogAssetKind::Prompt => AssetKind::Prompt,
        CatalogAssetKind::Tool => AssetKind::Tool,
        _ => return None,
    })
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
}
