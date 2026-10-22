//! Redacted diagnostics and audit exchange contracts.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorArtifactKind {
    JsonConfiguration,
    Catalog,
    HostSnapshot,
    RetrievalIndex,
    Database,
    Hook,
    Plugin,
    ManagedFile,
    AuthMarker,
    Executable,
    Lease,
    BackendStatus,
    SandboxEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorArtifact {
    pub id: String,
    pub relative_path: String,
    pub kind: DoctorArtifactKind,
    pub expected_sha256: Option<String>,
    #[serde(default)]
    pub require_private: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorRequest {
    pub schema_version: u32,
    pub root: String,
    pub artifacts: Vec<DoctorArtifact>,
    pub max_snapshot_age_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticState {
    Pass,
    Warning,
    Fail,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorCode {
    NotConfigured,
    FileValidated,
    FileUnavailable,
    PathRejected,
    PermissionsBroad,
    DriftDetected,
    SchemaInvalid,
    InputLimit,
    SecretPatternDetected,
    AuthPresenceOnly,
    ExecutablePresenceOnly,
    DatabaseHeaderOnly,
    DatabaseSnapshotRequired,
    HookNotInvoked,
    PluginNotLoaded,
    ManagedFilePresent,
    HostObserved,
    HostEffortUnknown,
    RetrievalValidated,
    LeaseLivenessUnknown,
    LeaseStale,
    BackendHealthUnknown,
    SandboxEnforcementUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorCheck {
    pub subject_sha256: String,
    pub kind: DoctorArtifactKind,
    pub configuration: DiagnosticState,
    pub runtime: DiagnosticState,
    pub code: DoctorCode,
    pub content_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorReport {
    pub schema_version: u32,
    pub observed_at_unix_seconds: u64,
    pub checks: Vec<DoctorCheck>,
    pub overall: DiagnosticState,
    pub secrets_scan_is_heuristic: bool,
    pub network_requests: u32,
    pub processes_launched: u32,
    pub files_modified: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditArtifactKind {
    EffectiveConfig,
    Catalog,
    Decision,
    Events,
    Evidence,
    Versions,
}

/// Only fixed metadata and numbers survive projection. Arbitrary JSON values,
/// user labels, file paths, prompts and provider text cannot enter this type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditMetadata {
    pub schema_version: Option<u32>,
    pub top_level_entries: usize,
    pub contained_secret_pattern: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub sequence: u64,
    pub kind: AuditArtifactKind,
    pub content_sha256: String,
    pub byte_count: usize,
    pub metadata: AuditMetadata,
    /// Absent in v1. V2 is a typed projection of unverified input claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<AuditProjection>,
    pub previous_hash: String,
    pub record_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditBundle {
    pub schema_version: u32,
    pub records: Vec<AuditRecord>,
    pub root_hash: String,
    pub raw_content_included: bool,
    pub signature_verified: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditProvenance {
    UnverifiedInput,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditProjection {
    pub provenance: AuditProvenance,
    pub data: AuditProjectionData,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "type",
    content = "fields",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AuditProjectionData {
    EffectiveConfig(AuditConfiguration),
    Catalog(AuditCatalog),
    Decision(AuditDecision),
    Events(AuditEvents),
    Evidence(AuditEvidence),
    Versions(AuditVersions),
}

/// All free-form identities, including declared digest values, are hashed
/// again under an audit domain. They are correlation keys, not source proofs.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReferences {
    pub receipt_sha256: Option<String>,
    pub context_sha256: Option<String>,
    pub catalog_sha256: Option<String>,
    pub policy_sha256: Option<String>,
    pub snapshot_sha256: Option<String>,
    pub pool_sha256: Option<String>,
    pub registry_sha256: Option<String>,
    pub evidence_sha256: Option<String>,
    pub definition_sha256: Option<String>,
    pub approval_sha256: Option<String>,
    pub plan_sha256: Option<String>,
    pub node_sha256: Option<String>,
    pub artifact_sha256: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditBudget {
    pub max_cost_microusd: Option<u64>,
    pub max_tokens: Option<u64>,
    pub max_elapsed_ms: Option<u64>,
    pub max_concurrency: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfiguration {
    pub source_sha256: Vec<String>,
    pub allowed_model_sha256: Option<Vec<String>>,
    pub allowed_capabilities: Option<Vec<crate::Capability>>,
    pub allowed_mutations: Option<Vec<crate::Mutation>>,
    pub preferred_model_sha256: Option<String>,
    pub budget: AuditBudget,
    pub references: AuditReferences,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecisionVerdict {
    Selected,
    Abstained,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditDecision {
    pub verdict: AuditDecisionVerdict,
    pub phase: Option<crate::StageKind>,
    pub candidate_sha256: Option<String>,
    pub model_sha256: Option<String>,
    pub effort: Option<crate::EffortLevel>,
    pub sandbox: Option<crate::PhaseSandbox>,
    pub verification: Option<crate::PhaseVerification>,
    pub required_capabilities: Option<Vec<crate::Capability>>,
    pub required_mutations: Option<Vec<crate::Mutation>>,
    pub asset_count: Option<u64>,
    pub abstention: Option<crate::PhaseAbstention>,
    pub utility_micros: Option<i64>,
    pub estimated_cost_microusd: Option<u64>,
    pub estimated_tokens: Option<u64>,
    pub estimated_elapsed_ms: Option<u64>,
    pub alternatives: Option<u64>,
    pub exclusions: Option<u64>,
    pub unavailable: Option<u64>,
    pub references: AuditReferences,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditRunState {
    Planned,
    AwaitingApproval,
    Queued,
    Preparing,
    Running,
    SucceededTransport,
    Verifying,
    Verified,
    Failed,
    VerificationFailed,
    TimedOut,
    Cancelled,
    Blocked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    Planned,
    Transition,
    Approval,
    Queued,
    Started,
    Completed,
    Verification,
    Cancelled,
    Recovery,
    Integration,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditFailure {
    Authentication,
    RateLimit,
    Timeout,
    Crash,
    Network,
    Policy,
    Verification,
    Interrupted,
    OutputLimit,
    Spawn,
    Budget,
    Cancelled,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRuntimeItem {
    pub sequence: Option<u64>,
    pub run_sha256: Option<String>,
    pub event_sha256: Option<String>,
    pub state: Option<AuditRunState>,
    pub kind: Option<AuditEventKind>,
    pub transport_kind: Option<crate::TransportEventKind>,
    pub failure: Option<AuditFailure>,
    pub attempts: Option<u64>,
    pub recorded_at_unix_seconds: Option<u64>,
    pub termination: Option<crate::TransportTermination>,
    pub exit_code: Option<i32>,
    pub elapsed_ms: Option<u64>,
    pub stdout_bytes: Option<u64>,
    pub stderr_bytes: Option<u64>,
    pub stdout_sha256: Option<String>,
    pub stderr_sha256: Option<String>,
    pub validation: Option<crate::VerificationOutcome>,
    pub objective: Option<crate::VerificationOutcome>,
    pub requested_model_sha256: Option<String>,
    pub requested_effort: Option<crate::EffortLevel>,
    pub references: AuditReferences,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvents {
    pub total_entries: u64,
    pub omitted_entries: u64,
    pub entries: Vec<AuditRuntimeItem>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvidence {
    pub termination: Option<crate::TransportTermination>,
    pub exit_code: Option<i32>,
    pub elapsed_ms: Option<u64>,
    pub transport_success: Option<bool>,
    pub stream_complete: Option<bool>,
    pub validation: Option<crate::VerificationOutcome>,
    pub objective: Option<crate::VerificationOutcome>,
    pub model_sha256: Vec<String>,
    pub model_source_sha256: Vec<String>,
    pub observed_effort: Option<crate::EffortLevel>,
    pub event_count: Option<u64>,
    pub references: AuditReferences,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditBackendKind {
    Deterministic,
    Laya,
    Jev,
    Unknown,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditVersion {
    pub identity_sha256: Option<String>,
    pub major: Option<u32>,
    pub minor: Option<u32>,
    pub patch: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditVersions {
    pub policy: AuditVersion,
    pub backend: AuditBackendKind,
    pub backend_version: AuditVersion,
    pub producer: AuditVersion,
    pub references: AuditReferences,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCatalog {
    pub version: AuditVersion,
    pub model_count: Option<u64>,
    pub skill_count: Option<u64>,
    pub asset_count: Option<u64>,
    pub references: AuditReferences,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupplementalBridgeKind {
    GitHubCopilotCli,
    OpenCode,
    OpenAiCompatibleApi,
    AnthropicCompatibleApi,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeLayer {
    Harness,
    Provider,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeDescriptor {
    pub schema_version: u32,
    pub kind: SupplementalBridgeKind,
    pub layer: BridgeLayer,
    pub capabilities: std::collections::BTreeMap<crate::Capability, crate::CapabilitySupport>,
    pub transport: crate::CapabilitySupport,
    pub authentication: crate::CapabilitySupport,
    pub parent_model_change: crate::CapabilitySupport,
}

/// Context is kept outside the provider payload. Hashes bind the intended
/// values but do not authenticate the envelope; the provider gate must verify
/// runtime authority before using one. No raw context or credentials here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRouteEnvelope {
    pub schema_version: u32,
    pub run_id: String,
    pub receipt_id: String,
    pub provider: SupplementalBridgeKind,
    pub requested_model: crate::ModelId,
    pub requested_effort: crate::EffortLevel,
    pub mode: crate::ExecutionMode,
    pub payload_sha256: String,
    pub context_sha256: String,
    pub authorization_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProviderRouteEnvelope {
    pub envelope: ProviderRouteEnvelope,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PreparedProviderRequest {
    pub signed_route: SignedProviderRouteEnvelope,
    pub method: String,
    pub path: String,
    pub static_headers: std::collections::BTreeMap<String, String>,
    pub credential_header_name: String,
    #[serde(skip_serializing)]
    pub body: crate::PreparedInput,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
}

/// Explicit component validators for deep diagnostics. They do not execute the
/// supplied configuration or grant its declared permissions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorSchema {
    ConfigurationLayers,
    EffectiveRestrictions,
    PhasePolicy,
    NormalizedTask,
    WorkflowPlan,
    PromptTemplate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorSchemaBinding {
    pub artifact_id: String,
    pub schema: DoctorSchema,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorRetrievalBinding {
    pub index_artifact_id: String,
    pub catalog_artifact_id: String,
    /// Relative directory beneath DoctorRequest.root. None checks only metadata;
    /// Some reads every declared body, subject to the shared body/read limits.
    pub body_root: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeepDoctorRequest {
    pub schema_version: u32,
    pub base: DoctorRequest,
    #[serde(default)]
    pub schemas: Vec<DoctorSchemaBinding>,
    #[serde(default)]
    pub retrieval_bindings: Vec<DoctorRetrievalBinding>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeepDoctorCode {
    ComponentValidated,
    ComponentSchemaRequired,
    CatalogBindingRequired,
    CatalogBindingValidated,
    CatalogBindingMismatch,
    CatalogAssetRegistryUnavailable,
    AssetBodyValidated,
    AssetBodyUnavailable,
    AssetBodyUntrusted,
    AssetBodyMismatch,
    DatabaseIntegrityValidated,
    DatabaseIntegrityFailed,
    DatabaseSnapshotRequired,
    DatabaseReadOnlyUnsupported,
    InputChanged,
    InputUnavailable,
    InputLimit,
    SchemaInvalid,
    PathRejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeepDoctorCheck {
    pub subject_sha256: String,
    pub configuration: DiagnosticState,
    /// Runtime host/auth/hook/sandbox evidence is never established by this API.
    pub runtime: DiagnosticState,
    pub code: DeepDoctorCode,
    pub content_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeepDoctorReport {
    pub schema_version: u32,
    pub base: DoctorReport,
    pub checks: Vec<DeepDoctorCheck>,
    pub overall: DiagnosticState,
    pub examined_body_count: usize,
    pub database_queries: usize,
}
