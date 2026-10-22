//! Strict intake of externally proposed plans (`router.plan_proposal.v1`).
//!
//! A proposal is untrusted data. The task, its scope, budgets and mutation
//! rights always come from the trusted caller, never from the proposal. The
//! `plan_id` is recomputed locally. An accepted proposal is not approved.
use crate::plan::{PlanLimits, build_plan, seal, validate_plan};
use crate::{Result, WorkflowError, text};
use router_adapter_api::strict_json;
use router_types::{NormalizedTask, WorkflowNode, WorkflowPlan, WorkflowPreset};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const PLAN_PROPOSAL_SCHEMA: &str = "router.plan_proposal.v1";
/// Upper bound on the raw proposal size, checked before any parsing.
pub const MAX_PROPOSAL_BYTES: usize = 256 * 1024;
const MAX_PROPOSER_BYTES: usize = 128;
const ALLOWED_FIELDS: [&str; 6] = [
    "schema",
    "proposer",
    "preset",
    "nodes",
    "max_depth",
    "max_width",
];

/// Difference between one proposed node and the node of the local baseline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeDivergence {
    pub node_id: String,
    pub changed_fields: Vec<&'static str>,
}

/// Human-review report against `build_plan(task, preset, limits)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanDivergence {
    /// Set when the local baseline could not be built; the other fields are then empty.
    pub baseline_error: Option<String>,
    pub missing_nodes: Vec<String>,
    pub extra_nodes: Vec<String>,
    pub changed_nodes: Vec<NodeDivergence>,
    pub max_depth_differs: bool,
    pub max_width_differs: bool,
}
impl PlanDivergence {
    pub fn is_identical(&self) -> bool {
        self.baseline_error.is_none()
            && self.missing_nodes.is_empty()
            && self.extra_nodes.is_empty()
            && self.changed_nodes.is_empty()
            && !self.max_depth_differs
            && !self.max_width_differs
    }
}

/// Accepted but never approved proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanProposalReview {
    /// Declared by the proposer. Data only; it grants nothing.
    pub proposer: String,
    /// Locally sealed and validated plan.
    pub plan: WorkflowPlan,
    pub waves: Vec<Vec<String>>,
    pub divergence: PlanDivergence,
}
impl PlanProposalReview {
    /// Always false: approval is a separate act bound to an approval digest.
    pub const fn is_approved(&self) -> bool {
        false
    }
}

fn invalid(reason: &'static str) -> WorkflowError {
    WorkflowError::Invalid(reason)
}

pub fn review_plan_proposal(
    bytes: &[u8],
    task: &NormalizedTask,
    limits: PlanLimits,
) -> Result<PlanProposalReview> {
    if bytes.len() > MAX_PROPOSAL_BYTES {
        return Err(WorkflowError::Limit("proposal size"));
    }
    // Rejects duplicate object keys, which `serde_json::Value` would silently merge.
    let value = strict_json(bytes).map_err(|_| invalid("proposal is not valid json"))?;
    let Value::Object(fields) = value else {
        return Err(invalid("proposal must be an object"));
    };
    if fields.contains_key("plan_id") {
        return Err(invalid("proposal must not supply plan_id"));
    }
    if fields
        .keys()
        .any(|key| !ALLOWED_FIELDS.contains(&key.as_str()))
    {
        return Err(invalid("proposal unknown field"));
    }
    let proposer = proposer_of(
        fields
            .get("proposer")
            .ok_or_else(|| invalid("proposal proposer missing"))?,
    )?;
    let plan = plan_from_fields(fields, task)?;
    if plan.max_depth > limits.max_depth
        || plan.max_width > limits.max_width
        || plan.nodes.len() > limits.max_nodes
    {
        return Err(WorkflowError::Limit("proposal exceeds caller limits"));
    }
    let waves = validate_plan(&plan)?;
    let baseline = build_plan(task, plan.preset, limits);
    Ok(PlanProposalReview {
        proposer,
        divergence: divergence(&plan, baseline),
        plan,
        waves,
    })
}

fn proposer_of(value: &Value) -> Result<String> {
    let name = value
        .as_str()
        .ok_or_else(|| invalid("proposal proposer type"))?;
    if !text(name) || name.len() > MAX_PROPOSER_BYTES || name.chars().any(char::is_control) {
        return Err(invalid("proposal proposer"));
    }
    Ok(name.to_owned())
}

fn plan_from_fields(mut fields: Map<String, Value>, task: &NormalizedTask) -> Result<WorkflowPlan> {
    if fields.get("schema").and_then(Value::as_str) != Some(PLAN_PROPOSAL_SCHEMA) {
        return Err(invalid("proposal schema"));
    }
    let mut take = |key: &'static str| {
        fields
            .remove(key)
            .ok_or_else(|| invalid("proposal field missing"))
    };
    let preset: WorkflowPreset =
        serde_json::from_value(take("preset")?).map_err(|_| invalid("proposal preset"))?;
    let nodes: Vec<WorkflowNode> =
        serde_json::from_value(take("nodes")?).map_err(|_| invalid("proposal nodes"))?;
    let bound = |value: Value| {
        value
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| invalid("proposal bound"))
    };
    let max_depth = bound(take("max_depth")?)?;
    let max_width = bound(take("max_width")?)?;
    seal(WorkflowPlan {
        schema_version: 1,
        plan_id: String::new(),
        task: task.clone(),
        preset,
        nodes,
        max_depth,
        max_width,
        requires_explicit_integration: true,
    })
}

fn changed_fields(a: &WorkflowNode, b: &WorkflowNode) -> Vec<&'static str> {
    let checks = [
        ("owner", a.owner != b.owner),
        ("purpose", a.purpose != b.purpose),
        ("mode", a.mode != b.mode),
        ("scope", a.scope != b.scope),
        ("inputs", a.inputs != b.inputs),
        ("outputs", a.outputs != b.outputs),
        ("dependencies", a.dependencies != b.dependencies),
        ("budget", a.budget != b.budget),
        ("stop_rule", a.stop_rule != b.stop_rule),
        ("verification", a.verification != b.verification),
        (
            "independent_verifier",
            a.independent_verifier != b.independent_verifier,
        ),
    ];
    checks
        .into_iter()
        .filter_map(|(name, differs)| differs.then_some(name))
        .collect()
}

fn divergence(proposed: &WorkflowPlan, baseline: Result<WorkflowPlan>) -> PlanDivergence {
    let baseline = match baseline {
        Ok(plan) => plan,
        Err(error) => {
            return PlanDivergence {
                baseline_error: Some(error.to_string()),
                missing_nodes: vec![],
                extra_nodes: vec![],
                changed_nodes: vec![],
                max_depth_differs: false,
                max_width_differs: false,
            };
        }
    };
    let base: BTreeMap<_, _> = baseline.nodes.iter().map(|n| (&n.id, n)).collect();
    let prop: BTreeMap<_, _> = proposed.nodes.iter().map(|n| (&n.id, n)).collect();
    PlanDivergence {
        baseline_error: None,
        missing_nodes: base
            .keys()
            .filter(|id| !prop.contains_key(*id))
            .map(|id| (*id).clone())
            .collect(),
        extra_nodes: prop
            .keys()
            .filter(|id| !base.contains_key(*id))
            .map(|id| (*id).clone())
            .collect(),
        changed_nodes: prop
            .iter()
            .filter_map(|(id, node)| {
                let fields = changed_fields(node, base.get(*id)?);
                (!fields.is_empty()).then(|| NodeDivergence {
                    node_id: (*id).clone(),
                    changed_fields: fields,
                })
            })
            .collect(),
        max_depth_differs: baseline.max_depth != proposed.max_depth,
        max_width_differs: baseline.max_width != proposed.max_width,
    }
}
