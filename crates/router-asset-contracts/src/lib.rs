//! Bound asset contracts and fail-closed gates. Hashes establish integrity;
//! callers supply independently approved roots and own execution authority.
#![forbid(unsafe_code)]

mod documents;
mod gate;
mod modality;
mod review;

pub use documents::{ValidatedAvailability, ValidatedContracts, seal_availability, seal_contracts};
pub use gate::{
    EligibleAssetPlan, GatedAssets, SkillBody, gate, gate_with_capability_acceptance,
    parse_gate_policy, parse_gate_request, preflight, preflight_with_capability_acceptance,
};
pub use modality::{
    DigestCheckedJsonObject, FILE_MEDIA_TYPES, InputContract, JsonOutputContract,
    MAX_JSON_OUTPUT_BYTES, MAX_MEDIA_TYPE_LEN, MAX_MEDIA_TYPES, MAX_MODALITY_BYTES, Modality,
    ValidatedInput, parse_input_contract, parse_json_output_contract,
};
pub use review::{PendingSkillReview, SkillApproval, approve_review, review_skill, scan_skill};

use router_adapter_api::is_digest;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SKILL_BYTES: usize = 256 * 1024;
pub const MAX_PROMPT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SELECTED_SKILLS: usize = 16;
pub const MAX_FINDINGS: usize = 64;
pub const MAX_CONTEXT_TOKENS: u64 = 1_000_000_000;
pub const MAX_EVIDENCE_AGE_SECONDS: u64 = 86_400;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateCode {
    ModelMissing,
    ProviderForbidden,
    HostForbidden,
    EffortUnsupported,
    AuthUnknown,
    AuthUnavailable,
    EvidenceStale,
    FeatureUnknownOrDenied,
    ContextUnknown,
    ContextExceeded,
    AccountingUnknown,
    DataForbidden,
    CapabilityUnknownOrDenied,
    MutationForbidden,
    ToolsForbidden,
    SkillMissing,
    SkillTrustForbidden,
    LicenseForbidden,
    SkillHostForbidden,
    SkillSandboxForbidden,
    ExecutableUnsupported,
    ApprovalMissing,
    ApprovalMismatch,
    ScannerReviewRequired,
    ScannerTruncated,
    BodyMismatch,
    SkillContextExceeded,
    PromptMismatch,
    ReasoningReuseUnsupported,
    OutputSchemaMissing,
}
impl GateCode {
    pub fn code(self) -> &'static str {
        use GateCode::*;
        match self {
            ModelMissing => "asset_gate.model.missing",
            ProviderForbidden => "asset_gate.provider.forbidden",
            HostForbidden => "asset_gate.host.forbidden",
            EffortUnsupported => "asset_gate.effort.unsupported",
            AuthUnknown => "asset_gate.auth.unknown",
            AuthUnavailable => "asset_gate.auth.unavailable",
            EvidenceStale => "asset_gate.evidence.stale",
            FeatureUnknownOrDenied => "asset_gate.feature.unknown_or_denied",
            ContextUnknown => "asset_gate.context.unknown",
            ContextExceeded => "asset_gate.context.exceeded",
            AccountingUnknown => "asset_gate.accounting.unknown",
            DataForbidden => "asset_gate.data.forbidden",
            CapabilityUnknownOrDenied => "asset_gate.capability.unknown_or_denied",
            MutationForbidden => "asset_gate.mutation.forbidden",
            ToolsForbidden => "asset_gate.tools.forbidden",
            SkillMissing => "asset_gate.skill.missing",
            SkillTrustForbidden => "asset_gate.skill.trust_forbidden",
            LicenseForbidden => "asset_gate.skill.license_forbidden",
            SkillHostForbidden => "asset_gate.skill.host_forbidden",
            SkillSandboxForbidden => "asset_gate.skill.sandbox_forbidden",
            ExecutableUnsupported => "asset_gate.skill.executable_unsupported",
            ApprovalMissing => "asset_gate.approval.missing",
            ApprovalMismatch => "asset_gate.approval.mismatch",
            ScannerReviewRequired => "asset_gate.scanner.review_required",
            ScannerTruncated => "asset_gate.scanner.truncated",
            BodyMismatch => "asset_gate.skill.body_mismatch",
            SkillContextExceeded => "asset_gate.skill.context_exceeded",
            PromptMismatch => "asset_gate.prompt.mismatch",
            ReasoningReuseUnsupported => "asset_gate.reasoning_reuse.unsupported",
            OutputSchemaMissing => "asset_gate.output_schema.missing",
        }
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ContractError {
    #[error("asset_contract.schema.invalid")]
    Schema,
    #[error("asset_contract.input.limit")]
    Limit,
    #[error("asset_contract.binding.invalid")]
    Binding,
    #[error("asset_contract.integrity.invalid")]
    Integrity,
    #[error("asset_contract.approval.invalid")]
    Approval,
    #[error("asset_contract.gate: {0:?}")]
    Gate(GateCode),
}
impl ContractError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Schema => "asset_contract.schema.invalid",
            Self::Limit => "asset_contract.input.limit",
            Self::Binding => "asset_contract.binding.invalid",
            Self::Integrity => "asset_contract.integrity.invalid",
            Self::Approval => "asset_contract.approval.invalid",
            Self::Gate(code) => code.code(),
        }
    }
}
pub type Result<T> = std::result::Result<T, ContractError>;

fn digest<T: Serialize + ?Sized>(domain: &str, value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| ContractError::Schema)?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
}
fn public_label(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn positive(value: u64) -> bool {
    (1..=MAX_CONTEXT_TOKENS).contains(&value)
}
fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(ContractError::Schema)
    }
}
fn excluded(code: GateCode) -> ContractError {
    ContractError::Gate(code)
}

pub(crate) fn policy_hash(policy: &router_types::AssetGatePolicy) -> Result<String> {
    use router_types::AssetFindingCode;
    require(
        policy.schema_version == 1
            && positive(policy.maximum_context_tokens)
            && positive(policy.maximum_input_tokens)
            && positive(policy.maximum_output_tokens)
            && (1..=MAX_EVIDENCE_AGE_SECONDS).contains(&policy.maximum_evidence_age_seconds)
            && policy.allowed_providers.len() <= 64
            && policy.allowed_hosts.len() <= 64
            && policy.allowed_tools.len() <= 64
            && policy.allowed_licenses.len() <= 64
            && policy.allowed_providers.iter().all(|s| identifier(s))
            && policy.allowed_tools.iter().all(|s| identifier(s))
            && policy.allowed_hosts.iter().all(documents::valid_host)
            && policy
                .allowed_licenses
                .iter()
                .all(|s| documents::valid_license(s)),
    )?;
    // Credential-like content has no bypass via a broad accepted-findings list.
    require(
        !policy
            .accepted_review_findings
            .contains(&AssetFindingCode::CredentialMarker),
    )?;
    digest("agent-router:asset-policy:v1", policy)
}

fn valid_root(expected: &str, actual: &str) -> Result<()> {
    if !is_digest(expected) || expected != actual {
        Err(ContractError::Integrity)
    } else {
        Ok(())
    }
}
