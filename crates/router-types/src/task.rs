use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{Capability, HostSnapshot, SkillCandidate};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    Explore,
    Implement,
    Review,
    Architecture,
    Security,
    Migration,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySupport {
    Supported,
    Unsupported,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskContext {
    pub objective: String,
    pub kind: TaskKind,
    pub risk: RiskLevel,
    pub required_capabilities: BTreeSet<Capability>,
    pub acceptance: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRequest {
    pub task: TaskContext,
    pub host: HostSnapshot,
    pub skill_candidates: Vec<SkillCandidate>,
    #[serde(default)]
    pub capability_knowledge: BTreeMap<Capability, CapabilitySupport>,
}
