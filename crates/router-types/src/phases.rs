use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Capability, CapabilitySupport, DataSensitivity, EffectiveRestrictions, EffortLevel, ModelId,
    Mutation, NormalizedTask, SkillId, SkillTrust, StageKind,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseSandbox {
    ReadOnly,
    WorkspaceWrite,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseVerification {
    None,
    Required,
    Independent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhasePermission {
    ModelInference,
    WorkspaceRead,
    WorkspaceWrite,
    Network,
    ExecuteSkills,
    Delegate,
    Integrate,
    NativeHostTools,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseToolPolicy {
    #[default]
    Restricted,
    NativeHost,
}
impl PhaseToolPolicy {
    pub fn is_restricted(&self) -> bool {
        *self == Self::Restricted
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseAssetKind {
    Agent,
    Tool,
}

/// Declared project authority, separate from the candidate pool. It is not proof
/// of native host discovery or execution. Its full bytes are bound to the context.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseRegisteredAsset {
    pub kind: PhaseAssetKind,
    pub id: String,
    pub content_sha256: String,
    pub trust: SkillTrust,
    pub license: String,
    pub permission: CapabilitySupport,
    pub required_capabilities: BTreeSet<Capability>,
    pub required_mutations: BTreeSet<Mutation>,
    pub allowed_sandboxes: BTreeSet<PhaseSandbox>,
    pub maximum_sensitivity: DataSensitivity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseAssetRegistry {
    pub schema_version: u32,
    pub version: String,
    pub assets: Vec<PhaseRegisteredAsset>,
}

impl Default for PhaseAssetRegistry {
    fn default() -> Self {
        Self {
            schema_version: 1,
            version: "empty-v1".into(),
            assets: vec![],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseCandidate {
    pub id: String,
    pub model: ModelId,
    pub effort: EffortLevel,
    pub agent: Option<String>,
    pub skills: BTreeSet<SkillId>,
    pub tools: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "PhaseToolPolicy::is_restricted")]
    pub tool_policy: PhaseToolPolicy,
    pub sandbox: PhaseSandbox,
    pub verification: PhaseVerification,
    pub required_capabilities: BTreeSet<Capability>,
    pub required_mutations: BTreeSet<Mutation>,
    pub estimated_cost_microusd: u64,
    pub estimated_tokens: u64,
    pub estimated_elapsed_ms: u64,
    pub relevance_micros: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseRouteRequest {
    pub schema_version: u32,
    pub task: NormalizedTask,
    pub phase: StageKind,
    pub restrictions: EffectiveRestrictions,
    /// Missing entries mean UNKNOWN, including for a low-risk task.
    #[serde(default)]
    pub permissions: BTreeMap<PhasePermission, CapabilitySupport>,
    #[serde(default)]
    pub registry: PhaseAssetRegistry,
    pub candidates: Vec<PhaseCandidate>,
    pub previous_model: Option<ModelId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhasePolicy {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub accepted_attestations: BTreeSet<Capability>,
    pub schema_version: u32,
    pub version: String,
    pub quality_weight: u32,
    pub relevance_weight: u32,
    pub cost_weight: u32,
    pub latency_weight: u32,
    pub minimum_utility_micros: i64,
    /// Absolute utility margin. An equal best utility always abstains.
    pub ambiguity_margin_micros: u64,
    pub max_alternatives: usize,
}

impl Default for PhasePolicy {
    fn default() -> Self {
        Self {
            accepted_attestations: BTreeSet::new(),
            schema_version: 2,
            version: "phase-v2".into(),
            quality_weight: 100,
            relevance_weight: 10,
            cost_weight: 1,
            latency_weight: 1,
            minimum_utility_micros: 0,
            ambiguity_margin_micros: 0,
            max_alternatives: 3,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PhaseExclusion {
    pub candidate_id: String,
    pub code: String,
    pub evidence: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PhaseScore {
    pub quality_micros: i64,
    pub relevance_micros: i64,
    pub cost_penalty_micros: i64,
    pub latency_penalty_micros: i64,
    pub utility_micros: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PhaseAssetEvidence {
    pub kind: String,
    pub id: String,
    pub content_sha256: String,
    pub authority: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PhaseSelection {
    pub candidate: PhaseCandidate,
    pub score: PhaseScore,
    pub assets: Vec<PhaseAssetEvidence>,
    pub reasons: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseAbstention {
    EmptyPool,
    NoEligibleCandidate,
    BelowThreshold,
    Ambiguous,
    AllUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PhaseReceipt {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub capability_evidence: BTreeMap<Capability, CapabilityReceiptEvidence>,
    pub schema_version: u32,
    pub receipt_id: String,
    pub phase: StageKind,
    pub context_hash: String,
    pub snapshot_hash: String,
    pub catalog_hash: String,
    pub policy_hash: String,
    pub pool_hash: String,
    pub registry_hash: String,
    pub selected: Option<PhaseSelection>,
    pub alternatives: Vec<PhaseSelection>,
    pub exclusions: Vec<PhaseExclusion>,
    pub abstention: Option<PhaseAbstention>,
    pub unavailable: BTreeSet<String>,
}

/// Provenance consumed by a v5 receipt; a receipt is never execution authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityReceiptEvidence {
    pub proof_sha256: String,
    pub tier: String,
    pub observed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}
