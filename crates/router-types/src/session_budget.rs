//! Parent allocations. Serialized amounts never prove provider usage.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetAmount {
    pub cost_microusd: u64,
    pub tokens: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBudgetRule {
    pub initial_limit: BudgetAmount,
    pub parent_ceiling: BudgetAmount,
    pub warning_basis_points: Vec<u16>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBudgetPolicy {
    pub schema_version: u32,
    pub sessions: BTreeMap<String, SessionBudgetRule>,
    pub runtime_sessions: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBudgetConfig {
    pub schema_version: u32,
    pub expected_policy_sha256: String,
    pub session_id: String,
    pub approved_limit: BudgetAmount,
    pub attempt_allocation: BudgetAmount,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBudgetBinding {
    pub policy_sha256: String,
    pub session_id: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDimension {
    Cost,
    Tokens,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetWarning {
    pub limit_revision: u64,
    pub dimension: BudgetDimension,
    pub basis_points: u16,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBudgetStatus {
    pub schema_version: u32,
    pub binding: SessionBudgetBinding,
    pub registry_sha256: String,
    pub limit: BudgetAmount,
    pub parent_ceiling: BudgetAmount,
    pub limit_revision: u64,
    pub reserved_allocation: BudgetAmount,
    pub committed_allocation: BudgetAmount,
    pub observed_cost_microusd: Option<u64>,
    pub observed_tokens: Option<u64>,
    pub warnings: Vec<BudgetWarning>,
    pub ledger_head: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLimitPreview {
    pub schema_version: u32,
    pub current: SessionBudgetStatus,
    pub new_limit: BudgetAmount,
    pub approval_digest: String,
}
