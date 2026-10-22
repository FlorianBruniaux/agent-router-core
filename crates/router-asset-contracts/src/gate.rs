use crate::*;
use router_adapter_api::{CapabilityAcceptance, content_digest};
use router_types::*;
use std::collections::BTreeSet;

/// Pre-ranking eligibility only. It is not an execution or body-loading permit.
#[derive(Clone, Debug)]
pub struct EligibleAssetPlan {
    request_hash: String,
    policy_hash: String,
    context_limit: u64,
    overhead_tokens: u64,
    reserved_context_upper_bound: u64,
}
impl EligibleAssetPlan {
    pub fn request_hash(&self) -> &str {
        &self.request_hash
    }
    pub fn context_limit(&self) -> u64 {
        self.context_limit
    }
    pub fn reserved_context_upper_bound(&self) -> u64 {
        self.reserved_context_upper_bound
    }
}

/// Result of the final asset gate. The runtime still validates its phase
/// receipt, approvals, exact prompt digest and sandbox before launching.
#[derive(Clone, Debug)]
pub struct GatedAssets {
    binding_digest: String,
    prompt_sha256: String,
    request_hash: String,
    policy_hash: String,
    contracts_hash: String,
    availability_hash: String,
    input_token_upper_bound: u64,
    total_context_upper_bound: u64,
}
impl GatedAssets {
    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }
    pub fn prompt_sha256(&self) -> &str {
        &self.prompt_sha256
    }
    pub fn request_hash(&self) -> &str {
        &self.request_hash
    }
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }
    pub fn contracts_hash(&self) -> &str {
        &self.contracts_hash
    }
    pub fn availability_hash(&self) -> &str {
        &self.availability_hash
    }
    pub fn input_token_upper_bound(&self) -> u64 {
        self.input_token_upper_bound
    }
    pub fn total_context_upper_bound(&self) -> u64 {
        self.total_context_upper_bound
    }
    pub fn verify_prompt(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_PROMPT_BYTES || content_digest(bytes) != self.prompt_sha256 {
            return Err(excluded(GateCode::PromptMismatch));
        }
        Ok(())
    }
}

pub struct SkillBody<'a> {
    pub skill: &'a SkillId,
    pub bytes: &'a [u8],
}
impl std::fmt::Debug for SkillBody<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkillBody")
            .field("bytes", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

pub fn parse_gate_request(bytes: &[u8]) -> Result<AssetGateRequest> {
    let request = documents::parse(bytes)?;
    validate_request(&request)?;
    Ok(request)
}
pub fn parse_gate_policy(bytes: &[u8]) -> Result<AssetGatePolicy> {
    let policy = documents::parse(bytes)?;
    policy_hash(&policy)?;
    Ok(policy)
}

fn validate_request(request: &AssetGateRequest) -> Result<()> {
    require(
        request.schema_version == 1
            && identifier(&request.candidate_id)
            && identifier(request.model.as_str())
            && identifier(&request.provider)
            && documents::valid_host(&request.host)
            && request.skills.len() <= MAX_SELECTED_SKILLS
            && request.skills.iter().all(|s| identifier(s.as_str()))
            && request.tools.len() <= 64
            && request.tools.iter().all(|s| identifier(s))
            && positive(request.input_token_budget)
            && positive(request.reserved_output_tokens)
            && is_digest(&request.authority_scope_digest)
            && request
                .output_schema_sha256
                .as_ref()
                .is_none_or(|v| is_digest(v)),
    )
}

pub fn preflight(
    contracts: &ValidatedContracts,
    availability: &ValidatedAvailability,
    request: &AssetGateRequest,
    policy: &AssetGatePolicy,
    now: u64,
) -> Result<EligibleAssetPlan> {
    preflight_with_capability_acceptance(
        contracts,
        availability,
        request,
        policy,
        &CapabilityAcceptance::proven_only(),
        now,
    )
}

/// Explicit phase-policy opt-in; the legacy entry point remains proven-only.
pub fn preflight_with_capability_acceptance(
    contracts: &ValidatedContracts,
    availability: &ValidatedAvailability,
    request: &AssetGateRequest,
    policy: &AssetGatePolicy,
    acceptance: &CapabilityAcceptance,
    now: u64,
) -> Result<EligibleAssetPlan> {
    validate_request(request)?;
    let policy_hash = policy_hash(policy)?;
    availability.check_fresh(now, policy.maximum_evidence_age_seconds)?;
    // Retained authenticated evidence still has its own lifetime. This checks
    // the caller's explicit clock; executable callers also need a live verifier.
    let snapshot = availability
        .snapshot()
        .revalidate_at(router_adapter_api::SnapshotValidation {
            now_unix_seconds: now,
            max_age_seconds: policy.maximum_evidence_age_seconds,
        })
        .map_err(|_| excluded(GateCode::EvidenceStale))?;
    let model = contracts
        .model(&request.model)
        .ok_or(excluded(GateCode::ModelMissing))?;
    if model.provider != request.provider || !policy.allowed_providers.contains(&request.provider) {
        return Err(excluded(GateCode::ProviderForbidden));
    }
    if !model.compatible_hosts.contains(&request.host)
        || !policy.allowed_hosts.contains(&request.host)
    {
        return Err(excluded(GateCode::HostForbidden));
    }
    let binding = availability
        .binding(request)
        .ok_or(excluded(GateCode::HostForbidden))?;
    if !binding.efforts.contains(&request.effort) {
        return Err(excluded(GateCode::EffortUnsupported));
    }
    match binding.authentication {
        AssetAuthStatus::Unknown => return Err(excluded(GateCode::AuthUnknown)),
        AssetAuthStatus::Unavailable => return Err(excluded(GateCode::AuthUnavailable)),
        AssetAuthStatus::Authenticated | AssetAuthStatus::NotRequired => {}
    }
    if request.reasoning_reuse != AssetReasoningReuse::None {
        return Err(excluded(GateCode::ReasoningReuseUnsupported));
    }
    if request
        .required_features
        .contains(&AssetFeature::JsonSchema)
        != request.output_schema_sha256.is_some()
    {
        return Err(excluded(GateCode::OutputSchemaMissing));
    }
    for feature in &request.required_features {
        if !policy.allowed_features.contains(feature)
            || model.features.get(feature) != Some(&CapabilitySupport::Supported)
            || binding.features.get(feature) != Some(&CapabilitySupport::Supported)
        {
            return Err(excluded(GateCode::FeatureUnknownOrDenied));
        }
    }
    if request.sensitivity > model.maximum_sensitivity {
        return Err(excluded(GateCode::DataForbidden));
    }
    let mut capabilities = request.required_capabilities.clone();
    let mut mutations = request.required_mutations.clone();
    if request
        .required_features
        .contains(&AssetFeature::ImageInput)
    {
        capabilities.insert(Capability::Vision);
    }
    if !request.tools.is_empty() {
        capabilities.insert(Capability::Tools);
    }
    for id in &request.skills {
        let skill = contracts
            .skill(id)
            .ok_or(excluded(GateCode::SkillMissing))?;
        check_manifest(skill, policy)?;
        if !skill.compatible_hosts.contains(&request.host) {
            return Err(excluded(GateCode::SkillHostForbidden));
        }
        if !skill.allowed_sandboxes.contains(&request.sandbox) {
            return Err(excluded(GateCode::SkillSandboxForbidden));
        }
        if request.sensitivity > skill.maximum_sensitivity {
            return Err(excluded(GateCode::DataForbidden));
        }
        if !skill.required_tools.is_subset(&request.tools) {
            return Err(excluded(GateCode::ToolsForbidden));
        }
        capabilities.extend(&skill.required_capabilities);
        mutations.extend(&skill.required_mutations);
    }
    if !request.tools.is_subset(&policy.allowed_tools) {
        return Err(excluded(GateCode::ToolsForbidden));
    }
    if request.sandbox == PhaseSandbox::WorkspaceWrite
        || capabilities.contains(&Capability::WorkspaceWrite)
    {
        capabilities.insert(Capability::WorkspaceWrite);
        mutations.insert(Mutation::WorkspaceWrite);
    }
    if capabilities.contains(&Capability::Network) {
        mutations.insert(Mutation::Network);
    }
    if mutations.contains(&Mutation::Network) {
        capabilities.insert(Capability::Network);
    }
    if mutations.contains(&Mutation::WorkspaceWrite) {
        capabilities.insert(Capability::WorkspaceWrite);
    }
    if !mutations.is_subset(&policy.allowed_mutations)
        || (request.sandbox == PhaseSandbox::ReadOnly
            && mutations.contains(&Mutation::WorkspaceWrite))
    {
        return Err(excluded(GateCode::MutationForbidden));
    }
    if !capabilities.is_subset(&policy.allowed_capabilities)
        || !contracts
            .model_capabilities(&request.model)
            .is_some_and(|allowed| capabilities.is_subset(allowed))
        || capabilities
            .iter()
            .any(|c| !snapshot.permits_capability(*c, acceptance))
    {
        return Err(excluded(GateCode::CapabilityUnknownOrDenied));
    }
    if model.token_accounting != AssetTokenAccounting::Utf8ByteUpperBound
        || binding.token_accounting != AssetTokenAccounting::Utf8ByteUpperBound
    {
        return Err(excluded(GateCode::AccountingUnknown));
    }
    let maximum = model
        .maximum_context_tokens
        .ok_or(excluded(GateCode::ContextUnknown))?
        .min(
            binding
                .maximum_context_tokens
                .ok_or(excluded(GateCode::ContextUnknown))?,
        )
        .min(policy.maximum_context_tokens);
    let overhead = binding
        .host_overhead_tokens
        .ok_or(excluded(GateCode::ContextUnknown))?;
    let total = request
        .input_token_budget
        .checked_add(request.reserved_output_tokens)
        .and_then(|v| v.checked_add(overhead))
        .ok_or(excluded(GateCode::ContextExceeded))?;
    if total > maximum
        || request.input_token_budget > policy.maximum_input_tokens
        || request.reserved_output_tokens > policy.maximum_output_tokens
    {
        return Err(excluded(GateCode::ContextExceeded));
    }
    Ok(EligibleAssetPlan {
        request_hash: digest("agent-router:asset-request:v1", request)?,
        policy_hash,
        context_limit: maximum,
        overhead_tokens: overhead,
        reserved_context_upper_bound: total,
    })
}

pub(crate) fn check_manifest(
    manifest: &SkillAssetManifest,
    policy: &AssetGatePolicy,
) -> Result<()> {
    if matches!(manifest.trust, SkillTrust::Untrusted | SkillTrust::Blocked)
        || (manifest.trust == SkillTrust::VerifiedThirdParty && !policy.allow_verified_third_party)
    {
        return Err(excluded(GateCode::SkillTrustForbidden));
    }
    if !policy
        .allowed_licenses
        .contains(&manifest.license_expression)
    {
        return Err(excluded(GateCode::LicenseForbidden));
    }
    if manifest.kind != AssetSkillKind::Instruction {
        return Err(excluded(GateCode::ExecutableUnsupported));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn gate(
    contracts: &ValidatedContracts,
    availability: &ValidatedAvailability,
    request: &AssetGateRequest,
    policy: &AssetGatePolicy,
    prompt: &[u8],
    bodies: &[SkillBody<'_>],
    approvals: &[SkillApproval],
    now: u64,
) -> Result<GatedAssets> {
    gate_with_capability_acceptance(
        contracts,
        availability,
        request,
        policy,
        prompt,
        bodies,
        approvals,
        &CapabilityAcceptance::proven_only(),
        now,
    )
}

/// Final gate with a policy-bound acceptance. The resulting binding additionally
/// includes that phase policy; skill-body approval remains bound to asset policy.
#[allow(clippy::too_many_arguments)]
pub fn gate_with_capability_acceptance(
    contracts: &ValidatedContracts,
    availability: &ValidatedAvailability,
    request: &AssetGateRequest,
    policy: &AssetGatePolicy,
    prompt: &[u8],
    bodies: &[SkillBody<'_>],
    approvals: &[SkillApproval],
    acceptance: &CapabilityAcceptance,
    now: u64,
) -> Result<GatedAssets> {
    let eligible = preflight_with_capability_acceptance(
        contracts,
        availability,
        request,
        policy,
        acceptance,
        now,
    )?;
    if prompt.is_empty()
        || prompt.len() > MAX_PROMPT_BYTES
        || bodies.len() > MAX_SELECTED_SKILLS
        || approvals.len() > MAX_SELECTED_SKILLS
    {
        return Err(ContractError::Limit);
    }
    if prompt.contains(&0) || std::str::from_utf8(prompt).is_err() {
        return Err(ContractError::Schema);
    }
    let body_ids: BTreeSet<_> = bodies.iter().map(|b| b.skill).collect();
    let approval_ids: BTreeSet<_> = approvals.iter().map(|a| &a.skill).collect();
    if body_ids.len() != bodies.len() || body_ids != request.skills.iter().collect() {
        return Err(excluded(GateCode::BodyMismatch));
    }
    if approval_ids.len() != approvals.len() || approval_ids != request.skills.iter().collect() {
        return Err(excluded(GateCode::ApprovalMissing));
    }
    let mut approval_digests = Vec::new();
    for id in &request.skills {
        let manifest = contracts
            .skill(id)
            .ok_or(excluded(GateCode::SkillMissing))?;
        let body = bodies
            .iter()
            .find(|b| b.skill == id)
            .ok_or(excluded(GateCode::BodyMismatch))?;
        if body.bytes.len() as u64 > manifest.maximum_context_tokens {
            return Err(excluded(GateCode::SkillContextExceeded));
        }
        let review = review_skill(
            contracts,
            id,
            body.bytes,
            policy,
            &request.authority_scope_digest,
        )?;
        if review.projection.scanner.truncated {
            return Err(excluded(GateCode::ScannerTruncated));
        }
        if review
            .projection
            .scanner
            .findings
            .iter()
            .any(|f| !policy.accepted_review_findings.contains(&f.code))
        {
            return Err(excluded(GateCode::ScannerReviewRequired));
        }
        let approval = approvals
            .iter()
            .find(|a| &a.skill == id)
            .ok_or(excluded(GateCode::ApprovalMissing))?;
        if approval.contracts_hash != contracts.hash()
            || approval.policy_hash != eligible.policy_hash
            || approval.scope_digest != request.authority_scope_digest
            || approval.body_sha256 != manifest.body_sha256
            || approval.manifest_sha256 != review.projection.manifest_sha256
            || approval.approval_digest != review.approval_digest()
        {
            return Err(excluded(GateCode::ApprovalMismatch));
        }
        approval_digests.push(&approval.approval_digest);
    }
    let input_bound = prompt.len() as u64;
    if input_bound > request.input_token_budget {
        return Err(excluded(GateCode::ContextExceeded));
    }
    let total_bound = input_bound
        .checked_add(request.reserved_output_tokens)
        .and_then(|v| v.checked_add(eligible.overhead_tokens))
        .ok_or(excluded(GateCode::ContextExceeded))?;
    let prompt_sha256 = content_digest(prompt);
    let binding_digest = digest(
        "agent-router:asset-gate:v1",
        &(
            contracts.hash(),
            availability.hash(),
            &eligible.request_hash,
            &eligible.policy_hash,
            &prompt_sha256,
            &approval_digests,
            input_bound,
            total_bound,
        ),
    )?;
    let binding_digest = if acceptance.accepted().is_empty() {
        binding_digest
    } else {
        digest(
            "agent-router:asset-gate:v2",
            &(
                &binding_digest,
                acceptance.policy_hash(),
                acceptance.accepted(),
            ),
        )?
    };
    Ok(GatedAssets {
        binding_digest,
        prompt_sha256,
        request_hash: eligible.request_hash,
        policy_hash: eligible.policy_hash,
        contracts_hash: contracts.hash().into(),
        availability_hash: availability.hash().into(),
        input_token_upper_bound: input_bound,
        total_context_upper_bound: total_bound,
    })
}
