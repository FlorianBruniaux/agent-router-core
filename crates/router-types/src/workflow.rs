use crate::{Capability, ModelId, RiskLevel, TaskKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSensitivity {
    Public,
    Internal,
    Secret,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mutation {
    WorkspaceWrite,
    Network,
    ExecuteSkills,
    Integrate,
}

/// Restrictive configuration has fixed precedence. No source may regrant an
/// action removed by any other source. Preferences use task first precedence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationLayers {
    pub schema_version: u32,
    pub defaults: RestrictionLayer,
    pub active_offline_policy: Option<RestrictionLayer>,
    pub preset: Option<RestrictionLayer>,
    pub project: Option<RestrictionLayer>,
    pub organization: Option<RestrictionLayer>,
    pub task: Option<RestrictionLayer>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBudget {
    pub max_cost_microusd: u64,
    pub max_elapsed_ms: u64,
    pub max_tokens: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskInput {
    pub objective: String,
    pub kind: TaskKind,
    #[serde(default)]
    pub deliverables: Vec<String>,
    #[serde(default)]
    pub constraints: Vec<String>,
    #[serde(default)]
    pub scope: Vec<String>,
    pub risk: Option<RiskLevel>,
    pub sensitivity: Option<DataSensitivity>,
    pub budget: Option<TaskBudget>,
    pub allowed_mutations: Option<BTreeSet<Mutation>>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub acceptance: Vec<String>,
    #[serde(default)]
    pub required_capabilities: BTreeSet<Capability>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedTask {
    pub objective: String,
    pub kind: TaskKind,
    pub deliverables: Vec<String>,
    pub constraints: Vec<String>,
    pub scope: Vec<String>,
    pub risk: RiskLevel,
    pub sensitivity: DataSensitivity,
    pub budget: TaskBudget,
    pub allowed_mutations: BTreeSet<Mutation>,
    pub dependencies: Vec<String>,
    pub acceptance: Vec<String>,
    pub required_capabilities: BTreeSet<Capability>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Clarification {
    pub code: String,
    pub question: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskNormalization {
    pub schema_version: u32,
    pub task: Option<NormalizedTask>,
    pub questions: Vec<Clarification>,
    pub assumptions: Vec<String>,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowPreset {
    DirectSafe,
    PlanExecuteVerify,
    ExploreThenBuild,
    FanoutReview,
    Incident,
    Migration,
    SecurityReadonly,
    BulkMechanical,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeMode {
    ReadOnly,
    IsolatedWrite,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowNode {
    pub id: String,
    pub owner: String,
    pub purpose: String,
    pub mode: NodeMode,
    pub scope: Vec<String>,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub dependencies: Vec<String>,
    pub budget: TaskBudget,
    pub stop_rule: String,
    pub verification: Vec<String>,
    pub independent_verifier: bool,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPlan {
    pub schema_version: u32,
    pub plan_id: String,
    pub task: NormalizedTask,
    pub preset: WorkflowPreset,
    pub nodes: Vec<WorkflowNode>,
    pub max_depth: usize,
    pub max_width: usize,
    pub requires_explicit_integration: bool,
}

/// Explicit execution authority layered over the unchanged v1 plan contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowExecutionContract {
    pub schema_version: u32,
    pub instance_id: String,
    pub plan_id: String,
    pub workspace: String,
    pub source_state: String,
    pub nodes: BTreeMap<String, NodeExecutionContract>,
    pub contract_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeExecutionContract {
    pub phase: crate::StageKind,
    pub dependencies: BTreeMap<String, DependencyRequirement>,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyRequirement {
    Verified,
    ArtifactReadyForVerification,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestrictionLayer {
    pub name: String,
    pub allowed_models: Option<BTreeSet<ModelId>>,
    pub allowed_capabilities: Option<BTreeSet<Capability>>,
    pub allowed_mutations: Option<BTreeSet<Mutation>>,
    pub max_cost_microusd: Option<u64>,
    pub max_tokens: Option<u64>,
    pub max_concurrency: Option<usize>,
    pub preferred_model: Option<ModelId>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveRestrictions {
    pub schema_version: u32,
    pub sources: Vec<String>,
    pub allowed_models: Option<BTreeSet<ModelId>>,
    pub allowed_capabilities: Option<BTreeSet<Capability>>,
    pub allowed_mutations: Option<BTreeSet<Mutation>>,
    pub max_cost_microusd: Option<u64>,
    pub max_tokens: Option<u64>,
    pub max_concurrency: Option<usize>,
    pub preferred_model: Option<ModelId>,
    pub policy_hash: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptVariableType {
    Text,
    Integer,
    Boolean,
    RelativePath,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromptTemplate {
    pub schema_version: u32,
    pub id: String,
    pub version: String,
    pub template: String,
    pub variables: BTreeMap<String, PromptVariableType>,
    pub compatible_hosts: BTreeSet<String>,
    pub compatible_models: BTreeSet<ModelId>,
    pub max_rendered_bytes: usize,
    pub output_contract: String,
    pub content_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum PromptValue {
    Text(String),
    Integer(i64),
    Boolean(bool),
}
