//! Parent-owned shared concurrency policy. These DTOs never prove cleanup.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionPolicy {
    pub schema_version: u32,
    pub global_limit: u32,
    pub runtimes: BTreeMap<String, AdmissionRuntimePolicy>,
    /// Exact provider identities from validated v3 asset requirements.
    pub providers: BTreeMap<String, u32>,
    pub agents: BTreeMap<String, u32>,
    pub agent_mappings: Vec<AdmissionAgentMapping>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRuntimePolicy {
    pub root_sha256: String,
    pub limit: u32,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionAgentMapping {
    pub runtime_id: String,
    pub plan_owner: String,
    pub candidate_agent: Option<String>,
    pub quota_id: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_budget: Option<crate::SessionBudgetConfig>,
    pub schema_version: u32,
    pub registry: PathBuf,
    pub expected_policy_sha256: String,
    pub runtime_id: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionBinding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_budget: Option<crate::SessionBudgetBinding>,
    pub schema_version: u32,
    pub registry_sha256: String,
    pub policy_sha256: String,
    pub runtime_id: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionQueueReason {
    GlobalCapacity,
    RuntimeCapacity,
    ProviderCapacity,
    AgentCapacity,
    WorkflowCapacity,
    FairTurn,
    SessionCostBudget,
    SessionTokenBudget,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionStatus {
    pub schema_version: u32,
    pub policy_sha256: String,
    pub waiting: u32,
    pub granted: u32,
    pub released: u32,
    /// Released is a resource fact, never an objective-success claim.
    pub max_tickets: u32,
}
