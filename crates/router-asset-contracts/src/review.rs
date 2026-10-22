use crate::*;
use router_adapter_api::content_digest;
use router_types::*;

#[derive(Clone, Debug)]
pub struct PendingSkillReview {
    pub(crate) projection: AssetReviewProjection,
    pub(crate) contracts_hash: String,
}
impl PendingSkillReview {
    pub fn projection(&self) -> &AssetReviewProjection {
        &self.projection
    }
    pub fn approval_digest(&self) -> &str {
        &self.projection.approval_digest
    }
}

/// No Deserialize implementation: a JSON review or `approved: true` cannot
/// produce this token. Only the parent controller calls approve_review after
/// an authorized review action matching the displayed digest and scope.
#[derive(Clone, Debug)]
pub struct SkillApproval {
    pub(crate) skill: SkillId,
    pub(crate) contracts_hash: String,
    pub(crate) body_sha256: String,
    pub(crate) manifest_sha256: String,
    pub(crate) policy_hash: String,
    pub(crate) scope_digest: String,
    pub(crate) approval_digest: String,
}
impl SkillApproval {
    pub fn skill(&self) -> &SkillId {
        &self.skill
    }
    pub fn digest(&self) -> &str {
        &self.approval_digest
    }
}

pub fn scan_skill(bytes: &[u8]) -> Result<AssetScannerReport> {
    if bytes.is_empty() || bytes.len() > MAX_SKILL_BYTES {
        return Err(ContractError::Limit);
    }
    if bytes.contains(&0) || std::str::from_utf8(bytes).is_err() {
        return Err(ContractError::Schema);
    }
    let lowercase: Vec<_> = bytes.iter().map(u8::to_ascii_lowercase).collect();
    let patterns: &[(AssetFindingCode, &[u8])] = &[
        (
            AssetFindingCode::CredentialMarker,
            b"-----begin private key-----", // gitleaks:allow -- scanner marker, no key material
        ),
        (
            AssetFindingCode::CredentialMarker,
            b"-----begin rsa private key-----", // gitleaks:allow -- scanner marker, no key material
        ),
        (AssetFindingCode::CredentialMarker, b"api_key="),
        (
            AssetFindingCode::CredentialMarker,
            b"authorization: bearer ",
        ),
        (
            AssetFindingCode::InstructionOverride,
            b"ignore previous instructions",
        ),
        (
            AssetFindingCode::InstructionOverride,
            b"ignore all prior instructions",
        ),
        (AssetFindingCode::NetworkReference, b"https://"),
        (AssetFindingCode::NetworkReference, b"http://"),
        (AssetFindingCode::ProcessExecution, b"bash -c"),
        (AssetFindingCode::ProcessExecution, b"sh -c"),
        (AssetFindingCode::ProcessExecution, b"eval("),
        (AssetFindingCode::EncodedPayload, b"base64 --decode"),
        (AssetFindingCode::EncodedPayload, b"base64 -d"),
    ];
    let mut findings = Vec::new();
    let mut truncated = false;
    'patterns: for &(code, pattern) in patterns {
        for (offset, window) in lowercase.windows(pattern.len()).enumerate() {
            if window == pattern {
                if findings.len() == MAX_FINDINGS {
                    truncated = true;
                    break 'patterns;
                }
                findings.push(AssetScannerFinding {
                    code,
                    byte_offset: offset as u32,
                });
            }
        }
    }
    findings.sort_by_key(|v| (v.byte_offset, v.code));
    Ok(AssetScannerReport {
        schema_version: 1,
        scanner_version: "bounded-static-v1".into(),
        body_sha256: content_digest(bytes),
        findings,
        truncated,
        safety_not_established: true,
    })
}

pub fn review_skill(
    contracts: &ValidatedContracts,
    skill: &SkillId,
    body: &[u8],
    policy: &AssetGatePolicy,
    authority_scope_digest: &str,
) -> Result<PendingSkillReview> {
    let policy_hash = policy_hash(policy)?;
    require(is_digest(authority_scope_digest))?;
    let manifest = contracts
        .skill(skill)
        .ok_or(excluded(GateCode::SkillMissing))?;
    let scanner = scan_skill(body)?;
    if scanner.body_sha256 != manifest.body_sha256 {
        return Err(excluded(GateCode::BodyMismatch));
    }
    let mut projection = AssetReviewProjection {
        schema_version: 1,
        skill: skill.clone(),
        version: manifest.version.clone(),
        source: manifest.provenance.clone(),
        source_authentication_unknown: true,
        license_expression: manifest.license_expression.clone(),
        body_sha256: manifest.body_sha256.clone(),
        manifest_sha256: digest("agent-router:skill-manifest:v1", manifest)?,
        kind: manifest.kind,
        trust: manifest.trust,
        required_tools: manifest.required_tools.clone(),
        required_capabilities: manifest.required_capabilities.clone(),
        required_mutations: manifest.required_mutations.clone(),
        allowed_sandboxes: manifest.allowed_sandboxes.clone(),
        maximum_context_tokens: manifest.maximum_context_tokens,
        scanner,
        policy_hash,
        authority_scope_digest: authority_scope_digest.into(),
        approval_digest: String::new(),
    };
    projection.approval_digest = digest(
        "agent-router:asset-review:v1",
        &(contracts.hash(), &projection),
    )?;
    Ok(PendingSkillReview {
        projection,
        contracts_hash: contracts.hash().into(),
    })
}

pub fn approve_review(
    pending: &PendingSkillReview,
    displayed_digest: &str,
    authority_scope_digest: &str,
) -> Result<SkillApproval> {
    let review = &pending.projection;
    if !is_digest(displayed_digest)
        || displayed_digest != review.approval_digest
        || authority_scope_digest != review.authority_scope_digest
    {
        return Err(ContractError::Approval);
    }
    if matches!(review.trust, SkillTrust::Untrusted | SkillTrust::Blocked) {
        return Err(excluded(GateCode::SkillTrustForbidden));
    }
    if review.scanner.truncated {
        return Err(excluded(GateCode::ScannerTruncated));
    }
    if review
        .scanner
        .findings
        .iter()
        .any(|v| v.code == AssetFindingCode::CredentialMarker)
    {
        return Err(excluded(GateCode::ScannerReviewRequired));
    }
    Ok(SkillApproval {
        skill: review.skill.clone(),
        contracts_hash: pending.contracts_hash.clone(),
        body_sha256: review.body_sha256.clone(),
        manifest_sha256: review.manifest_sha256.clone(),
        policy_hash: review.policy_hash.clone(),
        scope_digest: review.authority_scope_digest.clone(),
        approval_digest: review.approval_digest.clone(),
    })
}
