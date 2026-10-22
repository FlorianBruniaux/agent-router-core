use serde::{Deserialize, Serialize};

use crate::{EffortLevel, ModelId, SkillId, StageKind};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationIndependence {
    FreshInstance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PlanStage {
    pub kind: StageKind,
    pub model: ModelId,
    pub effort: EffortLevel,
    pub skills: Vec<SkillId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_independence: Option<VerificationIndependence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionPlan {
    pub preset: String,
    pub stages: Vec<PlanStage>,
    pub utility_micros: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Exclusion {
    pub stage: StageKind,
    pub model: ModelId,
    pub code: String,
    pub evidence: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteDecision {
    Selected {
        plan: ExecutionPlan,
        alternatives: Vec<ExecutionPlan>,
        exclusions: Vec<Exclusion>,
        missing_evidence: Vec<String>,
    },
    NoRoute {
        exclusions: Vec<Exclusion>,
        missing_evidence: Vec<String>,
    },
}

/// The only decision envelope schema this version reads and writes.
const DECISION_SCHEMA_VERSION: &str = "1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecisionEnvelope {
    pub schema_version: String,
    pub decision_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_snapshot_hash: Option<String>,
    pub catalog_version: String,
    pub policy_version: String,
    pub decision: RouteDecision,
}

impl DecisionEnvelope {
    /// Deserialization accepts any version string; a reader must refuse an
    /// envelope whose schema it does not implement instead of guessing.
    pub fn has_supported_schema(&self) -> bool {
        self.schema_version == DECISION_SCHEMA_VERSION
    }

    pub fn selected_plan(&self) -> Option<&ExecutionPlan> {
        match &self.decision {
            RouteDecision::Selected { plan, .. } => Some(plan),
            RouteDecision::NoRoute { .. } => None,
        }
    }

    pub fn exclusions(&self) -> &[Exclusion] {
        match &self.decision {
            RouteDecision::Selected { exclusions, .. }
            | RouteDecision::NoRoute { exclusions, .. } => exclusions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_implemented_decision_schema_is_supported() {
        let mut envelope = DecisionEnvelope {
            schema_version: "1".into(),
            decision_id: "decision".into(),
            host_snapshot_hash: None,
            catalog_version: "catalog".into(),
            policy_version: "policy".into(),
            decision: RouteDecision::NoRoute {
                exclusions: vec![],
                missing_evidence: vec![],
            },
        };
        assert!(envelope.has_supported_schema());
        for version in ["2", "", "01", " 1", "1.0"] {
            envelope.schema_version = version.into();
            assert!(!envelope.has_supported_schema(), "{version:?}");
        }
    }
}
