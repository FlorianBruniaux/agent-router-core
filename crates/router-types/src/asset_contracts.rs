//! Additive asset contracts. Existing catalog, snapshot and phase wire versions
//! remain unchanged; a caller must bind these documents into its new receipt.
use crate::{
    Capability, CapabilitySupport, DataSensitivity, EffortLevel, HarnessId, ModelId, Mutation,
    PhaseSandbox, SkillId, SkillTrust,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetFeature {
    ImageInput,
    AudioInput,
    AudioOutput,
    FileInput,
    Citations,
    JsonObject,
    JsonSchema,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetTokenAccounting {
    Unknown,
    Utf8ByteUpperBound,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetSkillKind {
    Instruction,
    Executable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetReasoningReuse {
    None,
    ProviderBound,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetHostBinding {
    pub harness: HarnessId,
    pub version: String,
}

/// Source is a bounded public locator/identifier, never credentials or a local
/// absolute path. Declared provenance is not itself source authentication.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetSourceProvenance {
    pub source: String,
    pub revision: String,
    pub source_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelAssetContract {
    pub model: ModelId,
    pub provider: String,
    pub compatible_hosts: BTreeSet<AssetHostBinding>,
    pub maximum_context_tokens: Option<u64>,
    pub token_accounting: AssetTokenAccounting,
    pub features: BTreeMap<AssetFeature, CapabilitySupport>,
    pub maximum_sensitivity: DataSensitivity,
    pub provenance: AssetSourceProvenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SkillAssetManifest {
    pub skill: SkillId,
    pub version: String,
    pub provenance: AssetSourceProvenance,
    pub license_expression: String,
    pub body_sha256: String,
    pub kind: AssetSkillKind,
    pub trust: SkillTrust,
    pub compatible_hosts: BTreeSet<AssetHostBinding>,
    pub required_tools: BTreeSet<String>,
    pub required_capabilities: BTreeSet<Capability>,
    pub required_mutations: BTreeSet<Mutation>,
    pub allowed_sandboxes: BTreeSet<PhaseSandbox>,
    pub maximum_sensitivity: DataSensitivity,
    pub maximum_context_tokens: u64,
    pub triggers: Vec<String>,
    pub anti_triggers: Vec<String>,
    pub examples: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetContractsDocument {
    pub schema_version: u32,
    pub catalog_hash: String,
    pub models: Vec<ModelAssetContract>,
    pub skills: Vec<SkillAssetManifest>,
    pub content_hash: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetEvidenceKind {
    PrimaryDocumentation,
    NativeRuntime,
    NativeStatus,
    OperatorReview,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetConstraintEvidence {
    pub id: String,
    pub kind: AssetEvidenceKind,
    pub source_sha256: String,
    pub observed_at_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetAuthStatus {
    Unknown,
    Unavailable,
    Authenticated,
    NotRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelAssetAvailability {
    pub model: ModelId,
    pub provider: String,
    pub host: AssetHostBinding,
    pub efforts: BTreeSet<EffortLevel>,
    pub authentication: AssetAuthStatus,
    pub auth_evidence_ids: BTreeSet<String>,
    pub features: BTreeMap<AssetFeature, CapabilitySupport>,
    pub feature_evidence_ids: BTreeMap<AssetFeature, BTreeSet<String>>,
    pub maximum_context_tokens: Option<u64>,
    pub host_overhead_tokens: Option<u64>,
    pub token_accounting: AssetTokenAccounting,
    pub context_evidence_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetAvailabilityDocument {
    pub schema_version: u32,
    pub snapshot_hash: String,
    pub observed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub bindings: Vec<ModelAssetAvailability>,
    pub evidence: Vec<AssetConstraintEvidence>,
    pub content_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetGateRequest {
    pub schema_version: u32,
    pub candidate_id: String,
    pub model: ModelId,
    pub provider: String,
    pub host: AssetHostBinding,
    pub effort: EffortLevel,
    pub required_features: BTreeSet<AssetFeature>,
    pub output_schema_sha256: Option<String>,
    pub reasoning_reuse: AssetReasoningReuse,
    pub required_capabilities: BTreeSet<Capability>,
    pub required_mutations: BTreeSet<Mutation>,
    pub skills: BTreeSet<SkillId>,
    pub tools: BTreeSet<String>,
    pub sandbox: PhaseSandbox,
    pub sensitivity: DataSensitivity,
    /// Reservation for the complete rendered input. The final gate checks the
    /// actual bytes, including selected bodies, against this reservation.
    pub input_token_budget: u64,
    pub reserved_output_tokens: u64,
    /// Parent-owned receipt/source/scope authorization, not a child claim.
    pub authority_scope_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetGatePolicy {
    pub schema_version: u32,
    pub allowed_providers: BTreeSet<String>,
    pub allowed_hosts: BTreeSet<AssetHostBinding>,
    pub allowed_features: BTreeSet<AssetFeature>,
    pub allowed_capabilities: BTreeSet<Capability>,
    pub allowed_mutations: BTreeSet<Mutation>,
    pub allowed_tools: BTreeSet<String>,
    pub allowed_licenses: BTreeSet<String>,
    pub allow_verified_third_party: bool,
    pub maximum_context_tokens: u64,
    pub maximum_input_tokens: u64,
    pub maximum_output_tokens: u64,
    pub maximum_evidence_age_seconds: u64,
    /// Ambiguous scanner findings require an explicit policy disposition and a
    /// review approval bound to the complete finding report.
    pub accepted_review_findings: BTreeSet<AssetFindingCode>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetFindingCode {
    CredentialMarker,
    InstructionOverride,
    NetworkReference,
    ProcessExecution,
    EncodedPayload,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetScannerFinding {
    pub code: AssetFindingCode,
    pub byte_offset: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetScannerReport {
    pub schema_version: u32,
    pub scanner_version: String,
    pub body_sha256: String,
    pub findings: Vec<AssetScannerFinding>,
    pub truncated: bool,
    pub safety_not_established: bool,
}

/// Review UI data only. Deserializing it cannot construct a pending review or
/// approval accepted by the gate. No body or matched scanner text is included.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetReviewProjection {
    pub schema_version: u32,
    pub skill: SkillId,
    pub version: String,
    pub source: AssetSourceProvenance,
    pub source_authentication_unknown: bool,
    pub license_expression: String,
    pub body_sha256: String,
    pub manifest_sha256: String,
    pub kind: AssetSkillKind,
    pub trust: SkillTrust,
    pub required_tools: BTreeSet<String>,
    pub required_capabilities: BTreeSet<Capability>,
    pub required_mutations: BTreeSet<Mutation>,
    pub allowed_sandboxes: BTreeSet<PhaseSandbox>,
    pub maximum_context_tokens: u64,
    pub scanner: AssetScannerReport,
    pub policy_hash: String,
    pub authority_scope_digest: String,
    pub approval_digest: String,
}
