//! V3 extension: keep v2 wire records stable, bind independently validated asset
//! contracts and recheck the exact prepared input before runtime dispatch.
use crate::{PhaseRouteError, PhaseRouter, ValidatedPhaseContext, phases};
use router_adapter_api::{ValidatedHostObservation, content_digest};
use router_asset_contracts::{
    ContractError, GateCode, GatedAssets, SkillBody, ValidatedAvailability, ValidatedContracts,
    approve_review, gate_with_capability_acceptance, preflight_with_capability_acceptance,
    review_skill,
};
use router_catalog::Catalog;
use router_types::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

type Result<T> = std::result::Result<T, PhaseRouteError>;

/// Intentionally not deserializable. JSON roots are validated separately and
/// Review digests come from parent-owned configuration, never from child output.
/// Bodies are loaded only after selection, when opaque reviews are reconstructed.
#[derive(Clone, Debug)]
pub struct PhaseAssetInputs {
    pub execution_scope: PhaseExecutionScope,
    pub contracts: ValidatedContracts,
    pub availability: ValidatedAvailability,
    pub policy: AssetGatePolicy,
    pub requests: BTreeMap<String, AssetGateRequest>,
    pub approved_review_digests: BTreeMap<SkillId, String>,
}

/// Parent-owned prospective execution authority, never inferred from asset text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseExecutionScope {
    pub workspace: String,
    pub source_state: String,
    pub scope: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct ValidatedPhaseAssets {
    inputs: PhaseAssetInputs,
    binding_digest: String,
    now: u64,
}

/// Deterministic parent review scope, computable before a v3 receipt exists.
/// The normal runtime approval still binds the final receipt/source/workspace.
pub fn asset_authority_scope_digest(
    request: &PhaseRouteRequest,
    execution_scope: &PhaseExecutionScope,
) -> Result<String> {
    phases::validate_request(request)?;
    validate_scope(request, execution_scope)?;
    let mut canonical = request.clone();
    canonical.candidates.sort_by(|a, b| a.id.cmp(&b.id));
    canonical
        .registry
        .assets
        .sort_by(|a, b| (a.kind, &a.id).cmp(&(b.kind, &b.id)));
    let mut scope = execution_scope.clone();
    scope.scope.sort();
    phases::hash("phase-asset-authority-v1", &(canonical, scope))
}

impl ValidatedPhaseAssets {
    pub(crate) fn new(
        request: &PhaseRouteRequest,
        snapshot: &ValidatedHostObservation,
        catalog: &Catalog,
        inputs: PhaseAssetInputs,
        now: u64,
    ) -> Result<Self> {
        let catalog_hash = catalog
            .content_hash()
            .map_err(|_| PhaseRouteError::Catalog)?;
        if inputs.contracts.catalog_hash() != catalog_hash
            || inputs.availability.snapshot_hash() != snapshot.hash()
        {
            return Err(PhaseRouteError::Invalid("asset document roots"));
        }
        let expected_ids: BTreeSet<_> = request.candidates.iter().map(|c| &c.id).collect();
        if inputs.requests.keys().collect::<BTreeSet<_>>() != expected_ids
            || inputs.approved_review_digests.len() > crate::MAX_PHASE_ASSETS
        {
            return Err(PhaseRouteError::Invalid("asset request pool"));
        }
        let scope = asset_authority_scope_digest(request, &inputs.execution_scope)?;
        for (skill, digest) in &inputs.approved_review_digests {
            if inputs.contracts.skill(skill).is_none()
                || digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(PhaseRouteError::Invalid("asset approvals"));
            }
        }
        for candidate in &request.candidates {
            let extension = inputs
                .requests
                .get(&candidate.id)
                .ok_or(PhaseRouteError::Invalid("asset request missing"))?;
            router_asset_contracts::parse_gate_request(
                &serde_json::to_vec(extension).map_err(|_| PhaseRouteError::Serialization)?,
            )?;
            if extension.candidate_id != candidate.id
                || extension.model != candidate.model
                || extension.effort != candidate.effort
                || extension.host.harness != snapshot.host().harness
                || extension.skills != candidate.skills
                || extension.tools != candidate.tools
                || extension.sandbox != candidate.sandbox
                || extension.sensitivity != request.task.sensitivity
                || extension.authority_scope_digest != scope
            {
                return Err(PhaseRouteError::Invalid("asset candidate binding"));
            }
        }
        router_asset_contracts::parse_gate_policy(
            &serde_json::to_vec(&inputs.policy).map_err(|_| PhaseRouteError::Serialization)?,
        )?;
        let binding_digest = phases::hash(
            "phase-asset-bindings-v1",
            &(
                inputs.contracts.document(),
                inputs.availability.document(),
                &inputs.policy,
                &inputs.requests,
                &inputs.execution_scope,
                &inputs.approved_review_digests,
            ),
        )?;
        Ok(Self {
            inputs,
            binding_digest,
            now,
        })
    }
    pub(crate) fn binding_digest(&self) -> &str {
        &self.binding_digest
    }
    pub(crate) fn skill(&self, id: &SkillId) -> Option<&SkillAssetManifest> {
        self.inputs.contracts.skill(id)
    }

    pub(crate) fn gate_candidate(
        &self,
        phase: &PhaseRouteRequest,
        candidate: &PhaseCandidate,
        base_capabilities: &BTreeSet<Capability>,
        base_mutations: &BTreeSet<Mutation>,
        acceptance: &router_adapter_api::CapabilityAcceptance,
    ) -> std::result::Result<(BTreeSet<Capability>, BTreeSet<Mutation>), ContractError> {
        let extension = self
            .inputs
            .requests
            .get(&candidate.id)
            .ok_or(ContractError::Binding)?;
        let mut capabilities = base_capabilities.clone();
        let mut mutations = base_mutations.clone();
        for id in &candidate.skills {
            let manifest = self
                .inputs
                .contracts
                .skill(id)
                .ok_or(ContractError::Gate(GateCode::SkillMissing))?;
            capabilities.extend(&manifest.required_capabilities);
            mutations.extend(&manifest.required_mutations);
        }
        if extension
            .required_features
            .contains(&AssetFeature::ImageInput)
        {
            capabilities.insert(Capability::Vision);
        }
        if capabilities.contains(&Capability::Network) {
            mutations.insert(Mutation::Network);
        }
        if capabilities.contains(&Capability::WorkspaceWrite) {
            mutations.insert(Mutation::WorkspaceWrite);
        }
        if mutations.contains(&Mutation::Network) {
            capabilities.insert(Capability::Network);
        }
        if mutations.contains(&Mutation::WorkspaceWrite) {
            capabilities.insert(Capability::WorkspaceWrite);
        }
        if extension.required_capabilities != capabilities
            || extension.required_mutations != mutations
        {
            return Err(ContractError::Binding);
        }
        if !mutations.is_subset(&phase.task.allowed_mutations)
            || phase
                .restrictions
                .allowed_mutations
                .as_ref()
                .is_some_and(|allowed| !mutations.is_subset(allowed))
        {
            return Err(ContractError::Gate(GateCode::MutationForbidden));
        }
        if phase
            .restrictions
            .allowed_capabilities
            .as_ref()
            .is_some_and(|allowed| !capabilities.is_subset(allowed))
        {
            return Err(ContractError::Gate(GateCode::CapabilityUnknownOrDenied));
        }
        let mut permissions = BTreeSet::new();
        for mutation in &mutations {
            permissions.insert(match mutation {
                Mutation::Network => PhasePermission::Network,
                Mutation::WorkspaceWrite => PhasePermission::WorkspaceWrite,
                Mutation::ExecuteSkills => PhasePermission::ExecuteSkills,
                Mutation::Integrate => PhasePermission::Integrate,
            });
        }
        if capabilities.contains(&Capability::Subagents) {
            permissions.insert(PhasePermission::Delegate);
        }
        if permissions
            .iter()
            .any(|p| phase.permissions.get(p) != Some(&CapabilitySupport::Supported))
        {
            return Err(ContractError::Gate(GateCode::CapabilityUnknownOrDenied));
        }
        let eligible = preflight_with_capability_acceptance(
            &self.inputs.contracts,
            &self.inputs.availability,
            extension,
            &self.inputs.policy,
            acceptance,
            self.now,
        )?;
        let reserved = eligible.reserved_context_upper_bound();
        if reserved > candidate.estimated_tokens
            || reserved > phase.task.budget.max_tokens
            || phase
                .restrictions
                .max_tokens
                .is_some_and(|max| reserved > max)
        {
            return Err(ContractError::Gate(GateCode::ContextExceeded));
        }
        Ok((capabilities, mutations))
    }
}

impl ValidatedPhaseContext {
    pub fn asset_skill_manifest(&self, skill: &SkillId) -> Option<&SkillAssetManifest> {
        self.assets.as_ref()?.skill(skill)
    }
    pub fn asset_requirements(&self, candidate_id: &str) -> Option<&AssetGateRequest> {
        self.assets.as_ref()?.inputs.requests.get(candidate_id)
    }
    pub fn asset_contracts_hash(&self) -> Option<&str> {
        self.assets.as_ref().map(|a| a.inputs.contracts.hash())
    }
    pub fn asset_availability_hash(&self) -> Option<&str> {
        self.assets.as_ref().map(|a| a.inputs.availability.hash())
    }
}

impl PhaseRouter {
    /// Revalidate the immutable v3 evidence bundle against the current signed
    /// catalog and wall clock before selected body I/O.
    pub fn validate_signed_assets_current(
        &self,
        context: &ValidatedPhaseContext,
        catalog: &Catalog,
        selected_candidate_id: &str,
        now: u64,
    ) -> Result<()> {
        let assets = context.assets.as_ref().ok_or(PhaseRouteError::Invalid(
            "signed v3 asset contracts required",
        ))?;
        let catalog_hash = catalog
            .content_hash()
            .map_err(|_| PhaseRouteError::Catalog)?;
        if assets.inputs.contracts.catalog_hash() != catalog_hash
            || assets.inputs.availability.snapshot_hash() != context.snapshot().snapshot_hash
            || assets.binding_digest
                != phases::hash(
                    "phase-asset-bindings-v1",
                    &(
                        assets.inputs.contracts.document(),
                        assets.inputs.availability.document(),
                        &assets.inputs.policy,
                        &assets.inputs.requests,
                        &assets.inputs.execution_scope,
                        &assets.inputs.approved_review_digests,
                    ),
                )?
        {
            return Err(PhaseRouteError::Invalid("signed v3 asset evidence changed"));
        }
        let selection = context
            .eligible_selection(selected_candidate_id)
            .ok_or(PhaseRouteError::Ineligible)?;
        let extension = assets
            .inputs
            .requests
            .get(&selection.candidate.id)
            .ok_or(PhaseRouteError::Invalid("asset request absent"))?;
        preflight_with_capability_acceptance(
            &assets.inputs.contracts,
            &assets.inputs.availability,
            extension,
            &assets.inputs.policy,
            context.capability_acceptance(),
            now,
        )?;
        Ok(())
    }

    pub fn context_with_assets(
        &self,
        request: PhaseRouteRequest,
        snapshot: &ValidatedHostObservation,
        catalog: &Catalog,
        inputs: PhaseAssetInputs,
        now: u64,
    ) -> Result<ValidatedPhaseContext> {
        let assets = ValidatedPhaseAssets::new(&request, snapshot, catalog, inputs, now)?;
        self.context_inner(request, snapshot, catalog, Some(assets), None)
    }

    /// Always call on the actual adapter-prepared stdin immediately before
    /// dispatch. None explicitly means a historical v2 context, never a v3 skip.
    pub fn validate_execution_assets(
        &self,
        context: &ValidatedPhaseContext,
        request: &ExecutionRequest,
        prepared_input_bytes: &[u8],
        now: u64,
    ) -> Result<Option<GatedAssets>> {
        let Some(assets) = &context.assets else {
            return Ok(None);
        };
        let selected = context
            .eligible_selection(&request.candidate_id)
            .ok_or(PhaseRouteError::Ineligible)?;
        self.validate_selection(context, selected)?;
        let candidate = &selected.candidate;
        let extension = assets
            .inputs
            .requests
            .get(&candidate.id)
            .ok_or(PhaseRouteError::Invalid("asset request absent"))?;
        // Existing ExecutionRequest can carry text instructions only. A caller
        // cannot turn an availability claim into unimplemented adapter support.
        if !extension.required_features.is_empty() || extension.output_schema_sha256.is_some() {
            return Err(PhaseRouteError::Invalid(
                "asset feature has no execution representation",
            ));
        }
        let sandbox = match candidate.sandbox {
            PhaseSandbox::ReadOnly => ExecutionSandbox::ReadOnly,
            PhaseSandbox::WorkspaceWrite => ExecutionSandbox::WorkspaceWrite,
        };
        let tools = match (&request.tools, candidate.tool_policy) {
            (ToolSelection::Disabled, PhaseToolPolicy::Restricted) => BTreeSet::new(),
            (ToolSelection::AllowList(tools), PhaseToolPolicy::Restricted) => {
                let unique: BTreeSet<_> = tools.iter().cloned().collect();
                if unique.len() != tools.len() {
                    return Err(PhaseRouteError::Invalid("duplicate execution tools"));
                }
                unique
            }
            (ToolSelection::HostPolicy, PhaseToolPolicy::NativeHost)
                if candidate.tools.is_empty() =>
            {
                BTreeSet::new()
            }
            _ => return Err(PhaseRouteError::Invalid("asset tool binding")),
        };
        let skill_ids: BTreeSet<_> = request.skills.iter().map(|s| s.id.clone()).collect();
        if request.schema_version != 1
            || request.model != candidate.model
            || request.effort != candidate.effort
            || request.host != extension.host.harness
            || request.phase != context.request().phase
            || request.workspace != assets.inputs.execution_scope.workspace
            || request.source_state != assets.inputs.execution_scope.source_state
            || request.scope.iter().collect::<BTreeSet<_>>()
                != assets
                    .inputs
                    .execution_scope
                    .scope
                    .iter()
                    .collect::<BTreeSet<_>>()
            || request.scope.len() != assets.inputs.execution_scope.scope.len()
            || request.agent != candidate.agent
            || request.sandbox != sandbox
            || tools != candidate.tools
            || skill_ids != candidate.skills
            || skill_ids.len() != request.skills.len()
            || request.required_capabilities != self.execution_capabilities(context, selected)?
            || request.scope.iter().any(|path| {
                !safe_scope(path)
                    || !context
                        .request()
                        .task
                        .scope
                        .iter()
                        .any(|allowed| path == allowed || path.starts_with(&format!("{allowed}/")))
            })
        {
            return Err(PhaseRouteError::Invalid("asset execution binding"));
        }
        for skill in &request.skills {
            let manifest = assets
                .skill(&skill.id)
                .ok_or(PhaseRouteError::Invalid("asset skill absent"))?;
            if manifest.kind != AssetSkillKind::Instruction
                || skill.kind != ExecutionSkillKind::Instruction
                || skill.trust != manifest.trust
                || skill.content_sha256 != manifest.body_sha256
                || content_digest(skill.body.as_bytes()) != manifest.body_sha256
            {
                return Err(PhaseRouteError::Invalid("asset skill body or kind"));
            }
        }
        let bodies: Vec<_> = request
            .skills
            .iter()
            .map(|s| SkillBody {
                skill: &s.id,
                bytes: s.body.as_bytes(),
            })
            .collect();
        let approvals = request
            .skills
            .iter()
            .map(|skill| {
                let expected = assets
                    .inputs
                    .approved_review_digests
                    .get(&skill.id)
                    .ok_or(ContractError::Gate(GateCode::ApprovalMissing))?;
                let review = review_skill(
                    &assets.inputs.contracts,
                    &skill.id,
                    skill.body.as_bytes(),
                    &assets.inputs.policy,
                    &extension.authority_scope_digest,
                )?;
                approve_review(&review, expected, &extension.authority_scope_digest)
            })
            .collect::<std::result::Result<Vec<_>, ContractError>>()?;
        Ok(Some(gate_with_capability_acceptance(
            &assets.inputs.contracts,
            &assets.inputs.availability,
            extension,
            &assets.inputs.policy,
            prepared_input_bytes,
            &bodies,
            &approvals,
            context.capability_acceptance(),
            now,
        )?))
    }
}

fn validate_scope(
    request: &PhaseRouteRequest,
    execution_scope: &PhaseExecutionScope,
) -> Result<()> {
    let workspace = std::path::Path::new(&execution_scope.workspace);
    if execution_scope.workspace.len() > 4096
        || execution_scope.workspace.contains(['\0', '\n', '\r', '\\'])
        || !workspace.is_absolute()
        || workspace.components().any(|part| {
            matches!(
                part,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || ![40, 64].contains(&execution_scope.source_state.len())
        || !execution_scope
            .source_state
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || execution_scope.scope.is_empty()
        || execution_scope.scope.len() > 64
        || execution_scope.scope.iter().collect::<BTreeSet<_>>().len()
            != execution_scope.scope.len()
        || execution_scope.scope.iter().any(|path| {
            path.len() > 4096
                || !safe_scope(path)
                || !request
                    .task
                    .scope
                    .iter()
                    .any(|allowed| path == allowed || path.starts_with(&format!("{allowed}/")))
        })
    {
        return Err(PhaseRouteError::Invalid("asset execution scope"));
    }
    Ok(())
}

fn safe_scope(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(['\\', '\0', '\n', '\r'])
        && !std::path::Path::new(path).is_absolute()
        && path
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}
