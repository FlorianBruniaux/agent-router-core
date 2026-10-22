use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Audit identity only. Reconstruct an opaque proof before accepting a choice.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedDecisionBinding {
    pub schema_version: u32,
    pub decision_id: String,
    pub baseline_receipt_id: String,
    pub context_hash: String,
    pub pool_hash: String,
    pub proposal_hash: String,
    pub input_hash: String,
    pub workflow_plan_id: String,
    pub execution_contract_sha256: String,
    pub instance_id: String,
    pub node_id: String,
    pub selection_sha256: String,
    pub planned_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationModelChoice {
    pub model: ModelId,
    pub effort: EffortLevel,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationToolChoice {
    pub tools: BTreeSet<String>,
    pub policy: PhaseToolPolicy,
}
/// Ranking order is explicit. Lists restrict existing eligible compatibility
/// rows; their Cartesian product never creates a new PhaseCandidate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationDimensions {
    pub models: Vec<GenerationModelChoice>,
    pub agents: Vec<Option<String>>,
    pub skill_bundles: Vec<BTreeSet<SkillId>>,
    pub tool_bundles: Vec<GenerationToolChoice>,
    pub sandboxes: Vec<PhaseSandbox>,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationTopK {
    pub models: usize,
    pub agents: usize,
    pub skill_bundles: usize,
    pub tool_bundles: usize,
    pub sandboxes: usize,
}
impl Default for GenerationTopK {
    fn default() -> Self {
        Self {
            models: 8,
            agents: 8,
            skill_bundles: 8,
            tool_bundles: 8,
            sandboxes: 2,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationProvenance {
    pub source_sha256: String,
    pub context_hash: String,
    pub execution_contract_sha256: String,
    pub observed_at_unix_seconds: u64,
}
/// Caller-attested soft evidence. A digest is not authentication of its claims.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum GenerationSignal {
    #[default]
    Unknown,
    Observed {
        value_micros: u32,
        provenance: GenerationProvenance,
    },
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum GenerationLabel {
    #[default]
    Unknown,
    Observed {
        value: String,
        provenance: GenerationProvenance,
    },
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationCandidateEvidence {
    pub historical_fit: GenerationSignal,
    pub cache_affinity: GenerationSignal,
    pub context_pressure: GenerationSignal,
    pub residual_risk: GenerationSignal,
    pub model_family: GenerationLabel,
    pub transport: GenerationLabel,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationEdgeCompatibility {
    pub source: String,
    pub target: String,
    /// None is UNKNOWN. An explicit empty set permits no combination.
    pub allowed_pairs: Option<BTreeSet<(String, String)>>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationWeights {
    /// Normalizer for the already validated PhaseScore quality contribution.
    pub phase_quality_scale: u64,
    pub quality: u32,
    pub relevance: u32,
    pub historical_fit: u32,
    pub cache_affinity: u32,
    pub cost: u32,
    pub latency: u32,
    pub context_pressure: u32,
    pub residual_risk: u32,
    pub coordination: u32,
    pub model_switch: u32,
}
impl Default for GenerationWeights {
    fn default() -> Self {
        Self {
            phase_quality_scale: 100_000_000,
            quality: 1_000_000,
            relevance: 100_000,
            historical_fit: 0,
            cache_affinity: 0,
            cost: 250_000,
            latency: 150_000,
            context_pressure: 200_000,
            residual_risk: 1_000_000,
            coordination: 100_000,
            model_switch: 100_000,
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationOverhead {
    pub cost_microusd: u64,
    pub tokens: u64,
    pub elapsed_ms: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanGenerationPolicy {
    pub schema_version: u32,
    pub version: String,
    pub top_k: GenerationTopK,
    pub beam_width: usize,
    pub max_alternatives: usize,
    pub max_work_units: u64,
    pub max_per_model_family: usize,
    pub max_per_transport: usize,
    pub maximum_evidence_age_seconds: u64,
    pub coordination_per_edge: GenerationOverhead,
    pub model_switch_per_edge: GenerationOverhead,
    pub weights_by_task_kind: BTreeMap<TaskKind, GenerationWeights>,
}
impl Default for PlanGenerationPolicy {
    fn default() -> Self {
        Self {
            schema_version: 1,
            version: "plan-generation-v1".into(),
            top_k: GenerationTopK::default(),
            beam_width: 16,
            max_alternatives: 4,
            max_work_units: 1_000_000,
            max_per_model_family: 16,
            max_per_transport: 16,
            maximum_evidence_age_seconds: 86_400,
            coordination_per_edge: GenerationOverhead::default(),
            model_switch_per_edge: GenerationOverhead::default(),
            weights_by_task_kind: [
                TaskKind::Explore,
                TaskKind::Implement,
                TaskKind::Review,
                TaskKind::Architecture,
                TaskKind::Security,
                TaskKind::Migration,
            ]
            .into_iter()
            .map(|kind| (kind, GenerationWeights::default()))
            .collect(),
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationEvidenceStatus {
    Unknown,
    Stale,
    Observed,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedChoice {
    pub node_id: String,
    pub context_hash: String,
    pub candidate_id: String,
    pub selection_sha256: String,
    pub scope: Vec<String>,
    pub signal_status: BTreeMap<String, GenerationEvidenceStatus>,
    pub model_family: Option<String>,
    pub transport: Option<String>,
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedResources {
    pub cost_microusd: u64,
    pub tokens: u64,
    pub elapsed_ms: u64,
    pub critical_path_elapsed_ms: u64,
    pub coordination: GenerationOverhead,
    pub model_switch: GenerationOverhead,
    pub model_switches: u64,
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationScore {
    pub quality_micros: i64,
    pub relevance_micros: i64,
    pub historical_fit_micros: i64,
    pub cache_affinity_micros: i64,
    pub cost_penalty_micros: i64,
    pub latency_penalty_micros: i64,
    pub context_penalty_micros: i64,
    pub risk_penalty_micros: i64,
    pub coordination_penalty_micros: i64,
    pub model_switch_penalty_micros: i64,
    pub utility_micros: i64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedPlan {
    pub schema_version: u32,
    pub proposal_hash: String,
    pub input_hash: String,
    pub workflow_plan_id: String,
    pub execution_contract_sha256: String,
    pub choices: Vec<GeneratedChoice>,
    pub resources: GeneratedResources,
    pub score: GenerationScore,
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationStatistics {
    pub work_units: u64,
    pub joined_candidates: usize,
    pub expanded_states: u64,
    pub budget_pruned: u64,
    pub compatibility_pruned: u64,
    pub dominance_pruned: u64,
    pub diversity_pruned: u64,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationAbstention {
    NoEligibleJoin,
    UnknownCompatibility,
    NoFeasiblePlan,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanGenerationReport {
    pub schema_version: u32,
    pub input_hash: String,
    pub policy_hash: String,
    pub selected: Option<GeneratedPlan>,
    pub alternatives: Vec<GeneratedPlan>,
    pub abstention: Option<GenerationAbstention>,
    pub statistics: GenerationStatistics,
}
