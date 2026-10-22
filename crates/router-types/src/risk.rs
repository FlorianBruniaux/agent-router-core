use crate::{RiskLevel, TaskNormalization};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskEnvironment {
    Local,
    Test,
    Staging,
    Production,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskReversibility {
    Reversible,
    Irreversible,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskOperation {
    ReadOnly,
    WorkspaceChange,
    SecurityChange,
    CredentialHandling,
    DataMigration,
    DataDeletion,
    Deployment,
    FinancialTransfer,
    ExternalPublication,
}

/// Explicit facts supplied by the parent/operator. This document carries no
/// permissions and does not authenticate its caller or the truth of its claims.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRiskContext {
    pub schema_version: u32,
    pub environment: RiskEnvironment,
    pub reversibility: RiskReversibility,
    pub operations: BTreeSet<RiskOperation>,
}

/// A fixed rule code and lower bound, without source text or secret values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RiskFinding {
    pub code: String,
    pub floor: RiskLevel,
}

/// Explainable projection only. Deserializing this report grants no authority;
/// consumers must recompute classification from the original facts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RiskAssessment {
    pub schema_version: u32,
    pub rules_version: String,
    pub floor: RiskLevel,
    pub effective: Option<RiskLevel>,
    pub findings: Vec<RiskFinding>,
}

/// Additive v2 wrapper. The nested historical v1 wire contracts are unchanged.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRiskNormalization {
    pub schema_version: u32,
    pub normalization: TaskNormalization,
    pub assessment: RiskAssessment,
}
