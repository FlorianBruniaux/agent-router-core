use crate::{Result, WorkflowError, hash, safe_path, text};
use router_types::{
    Mutation, NodeMode, NormalizedTask, RiskLevel, TaskBudget, WorkflowNode, WorkflowPlan,
    WorkflowPreset,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug)]
pub struct PlanLimits {
    pub max_depth: usize,
    pub max_width: usize,
    pub max_nodes: usize,
    /// Explicit reserve per node, not an estimate of model or human throughput.
    pub reserve_cost_microusd: u64,
    pub reserve_tokens: u64,
    pub reserve_elapsed_ms: u64,
}
impl Default for PlanLimits {
    fn default() -> Self {
        Self {
            max_depth: 16,
            max_width: 8,
            max_nodes: 64,
            reserve_cost_microusd: 0,
            reserve_tokens: 1,
            reserve_elapsed_ms: 1,
        }
    }
}

pub fn build_plan(
    task: &NormalizedTask,
    preset: WorkflowPreset,
    limits: PlanLimits,
) -> Result<WorkflowPlan> {
    crate::normalize::validate_task(task)?;
    if limits.max_nodes == 0
        || limits.max_nodes > 64
        || limits.max_width == 0
        || limits.max_width > 16
        || limits.max_depth == 0
        || limits.max_depth > 32
    {
        return Err(WorkflowError::Limit("planner bounds"));
    }
    if preset == WorkflowPreset::DirectSafe
        && matches!(task.risk, RiskLevel::High | RiskLevel::Critical)
    {
        return Err(WorkflowError::Authority(
            "direct-safe requires low or medium risk",
        ));
    }
    let mut nodes = Vec::new();
    let mut node = |id: &str,
                    purpose: &str,
                    mode: NodeMode,
                    deps: &[&str],
                    scope: Vec<String>,
                    independent: bool| {
        nodes.push(WorkflowNode { id: id.into(), owner: format!("worker-{id}"), purpose: purpose.into(), mode, scope,
            inputs: if deps.is_empty() { vec!["task".into()] } else { deps.iter().map(|id| format!("artifact:{id}")).collect() },
            outputs: vec![format!("artifact:{id}")], dependencies: deps.iter().map(|s| (*s).into()).collect(),
            budget: TaskBudget { max_cost_microusd: limits.reserve_cost_microusd, max_tokens: limits.reserve_tokens, max_elapsed_ms: limits.reserve_elapsed_ms },
            stop_rule: "Stop on cancellation, budget exhaustion, scope drift, unavailable evidence or failed prerequisites.".into(),
            verification: task.acceptance.clone(), independent_verifier: independent });
    };
    use NodeMode::{IsolatedWrite as W, ReadOnly as R};
    let write_mode = if task.allowed_mutations.contains(&Mutation::WorkspaceWrite) {
        W
    } else {
        R
    };
    let scope = &task.scope;
    match preset {
        WorkflowPreset::DirectSafe => {
            node(
                "execute",
                "Perform the bounded task",
                write_mode,
                &[],
                scope.clone(),
                false,
            );
            node(
                "verify",
                "Validate the result against explicit acceptance criteria",
                R,
                &["execute"],
                scope.clone(),
                false,
            );
        }
        WorkflowPreset::PlanExecuteVerify => {
            node(
                "plan",
                "Produce an implementation plan and acceptance checklist",
                R,
                &[],
                scope.clone(),
                false,
            );
            node(
                "execute",
                "Implement the approved scope",
                write_mode,
                &["plan"],
                scope.clone(),
                false,
            );
            node(
                "verify",
                "Independently review and validate the result",
                R,
                &["execute"],
                scope.clone(),
                true,
            );
        }
        WorkflowPreset::ExploreThenBuild => {
            node(
                "explore-code",
                "Map relevant code and dependencies",
                R,
                &[],
                scope.clone(),
                false,
            );
            node(
                "explore-tests",
                "Map regression tests and acceptance gaps",
                R,
                &[],
                scope.clone(),
                false,
            );
            node(
                "synthesize",
                "Consolidate evidence into one bounded change plan",
                R,
                &["explore-code", "explore-tests"],
                scope.clone(),
                false,
            );
            node(
                "execute",
                "Implement the consolidated change",
                write_mode,
                &["synthesize"],
                scope.clone(),
                false,
            );
            node(
                "verify",
                "Independently validate the change",
                R,
                &["execute"],
                scope.clone(),
                true,
            );
        }
        WorkflowPreset::FanoutReview => {
            node(
                "review-behavior",
                "Independently review behavior and correctness",
                R,
                &[],
                scope.clone(),
                true,
            );
            node(
                "review-security",
                "Independently review security and boundary conditions",
                R,
                &[],
                scope.clone(),
                true,
            );
            node(
                "synthesize",
                "Reconcile concrete findings and evidence",
                R,
                &["review-behavior", "review-security"],
                scope.clone(),
                false,
            );
        }
        WorkflowPreset::Incident => {
            node(
                "collect-code",
                "Collect bounded static evidence without mutation",
                R,
                &[],
                scope.clone(),
                false,
            );
            node(
                "collect-events",
                "Collect permitted event evidence without mutation",
                R,
                &[],
                scope.clone(),
                false,
            );
            node(
                "coordinate",
                "Correlate evidence, uncertainty and explicit stop rules",
                R,
                &["collect-code", "collect-events"],
                scope.clone(),
                false,
            );
        }
        WorkflowPreset::Migration => {
            if write_mode != W {
                return Err(WorkflowError::Authority(
                    "migration writes are not authorized",
                ));
            }
            node(
                "inventory",
                "Inventory source state and invariants",
                R,
                &[],
                scope.clone(),
                false,
            );
            node(
                "plan",
                "Prepare migration, rollback procedure and approval scope",
                R,
                &["inventory"],
                scope.clone(),
                false,
            );
            node(
                "simulate",
                "Simulate migration in an isolated worktree",
                W,
                &["plan"],
                scope.clone(),
                false,
            );
            node(
                "verify-simulation",
                "Independently verify simulation and rollback prerequisites",
                R,
                &["simulate"],
                scope.clone(),
                true,
            );
            node(
                "execute",
                "Apply migration only in the isolated worktree",
                W,
                &["verify-simulation"],
                scope.clone(),
                false,
            );
            node(
                "verify",
                "Independently verify migration; integration stays explicit",
                R,
                &["execute"],
                scope.clone(),
                true,
            );
        }
        WorkflowPreset::SecurityReadonly => {
            node(
                "security-review",
                "Inspect security boundaries without mutation",
                R,
                &[],
                scope.clone(),
                false,
            );
            node(
                "verify",
                "Independently assess concrete findings",
                R,
                &["security-review"],
                scope.clone(),
                true,
            );
        }
        WorkflowPreset::BulkMechanical => {
            if write_mode != W {
                return Err(WorkflowError::Authority("bulk writes are not authorized"));
            }
            for (index, path) in scope.iter().enumerate() {
                let id = format!("batch-{index}");
                node(
                    &id,
                    "Perform one bounded mechanical transformation",
                    W,
                    &[],
                    vec![path.clone()],
                    false,
                );
                node(
                    &format!("verify-{index}"),
                    "Run deterministic validation of this batch",
                    R,
                    &[&id],
                    vec![path.clone()],
                    true,
                );
            }
        }
    }
    if preset == WorkflowPreset::Incident
        && matches!(task.risk, RiskLevel::High | RiskLevel::Critical)
    {
        node(
            "verify",
            "Independently verify incident findings",
            R,
            &["coordinate"],
            scope.clone(),
            true,
        );
    }
    if preset == WorkflowPreset::FanoutReview
        && matches!(task.risk, RiskLevel::High | RiskLevel::Critical)
    {
        node(
            "verify-synthesis",
            "Independently verify the consolidated review findings",
            R,
            &["synthesize"],
            scope.clone(),
            true,
        );
    }
    let mut plan = WorkflowPlan {
        schema_version: 1,
        plan_id: String::new(),
        task: task.clone(),
        preset,
        nodes,
        max_depth: limits.max_depth,
        max_width: limits.max_width,
        requires_explicit_integration: true,
    };
    if plan.nodes.len() > limits.max_nodes {
        return Err(WorkflowError::Limit("node count"));
    }
    let count = plan.nodes.len() as u64;
    if limits
        .reserve_cost_microusd
        .checked_mul(count)
        .is_none_or(|sum| sum > task.budget.max_cost_microusd)
        || limits
            .reserve_tokens
            .checked_mul(count)
            .is_none_or(|sum| sum > task.budget.max_tokens)
        || limits
            .reserve_elapsed_ms
            .checked_mul(count)
            .is_none_or(|sum| sum > task.budget.max_elapsed_ms)
    {
        return Err(WorkflowError::Cost {
            suggested: if matches!(task.risk, RiskLevel::Low | RiskLevel::Medium) {
                "direct-safe"
            } else {
                "plan-execute-verify"
            },
        });
    }
    for node in &mut plan.nodes {
        node.budget = TaskBudget {
            max_cost_microusd: task.budget.max_cost_microusd / count,
            max_tokens: task.budget.max_tokens / count,
            max_elapsed_ms: task.budget.max_elapsed_ms / count,
        };
    }
    seal(plan)
}

pub(crate) fn seal(mut plan: WorkflowPlan) -> Result<WorkflowPlan> {
    validate_structure(&plan)?;
    plan.plan_id.clear();
    plan.plan_id =
        hash(&serde_json::to_vec(&plan).map_err(|_| WorkflowError::Invalid("plan serialization"))?);
    Ok(plan)
}
pub fn validate_plan(plan: &WorkflowPlan) -> Result<Vec<Vec<String>>> {
    let waves = validate_structure(plan)?;
    let mut copy = plan.clone();
    copy.plan_id.clear();
    if hash(&serde_json::to_vec(&copy).map_err(|_| WorkflowError::Invalid("plan serialization"))?)
        != plan.plan_id
    {
        return Err(WorkflowError::Integrity);
    }
    Ok(waves)
}
fn overlaps(a: &str, b: &str) -> bool {
    a == b
        || a.strip_prefix(b).is_some_and(|s| s.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|s| s.starts_with('/'))
}
fn validate_structure(plan: &WorkflowPlan) -> Result<Vec<Vec<String>>> {
    crate::normalize::validate_task(&plan.task)?;
    if plan.preset == WorkflowPreset::DirectSafe
        && matches!(plan.task.risk, RiskLevel::High | RiskLevel::Critical)
    {
        return Err(WorkflowError::Authority(
            "direct-safe requires low or medium risk",
        ));
    }
    if plan.schema_version != 1
        || plan.nodes.is_empty()
        || plan.nodes.len() > 64
        || plan.max_depth == 0
        || plan.max_depth > 32
        || plan.max_width == 0
        || plan.max_width > 16
    {
        return Err(WorkflowError::Limit("plan bounds"));
    }
    if !plan.requires_explicit_integration {
        return Err(WorkflowError::Authority("implicit integration"));
    }
    if plan.task.scope.is_empty()
        || plan.task.scope.iter().any(|path| !safe_path(path))
        || plan.task.acceptance.is_empty()
    {
        return Err(WorkflowError::Invalid("task scope or acceptance"));
    }
    let mut ids = BTreeMap::new();
    let mut owners = BTreeSet::new();
    let mut artifacts = BTreeSet::new();
    for node in &plan.nodes {
        if !text(&node.id)
            || node.id.len() > 128
            || !text(&node.owner)
            || !text(&node.purpose)
            || !text(&node.stop_rule)
            || node.scope.is_empty()
            || node.scope.len() > 64
            || node.dependencies.len() > 64
            || node.inputs.is_empty()
            || node.inputs.len() > 64
            || node.budget.max_tokens == 0
            || node.budget.max_elapsed_ms == 0
            || [
                node.inputs.as_slice(),
                node.outputs.as_slice(),
                node.verification.as_slice(),
            ]
            .into_iter()
            .flatten()
            .any(|value| !text(value))
            || node.outputs.iter().any(|output| !artifacts.insert(output))
            || (node.independent_verifier && node.mode != NodeMode::ReadOnly)
            || node.outputs.is_empty()
            || node.outputs.len() > 64
            || node.verification.is_empty()
            || node.verification.len() > 64
            || node.scope.iter().any(|path| {
                !safe_path(path)
                    || !plan.task.scope.iter().any(|parent| {
                        path == parent
                            || path
                                .strip_prefix(parent)
                                .is_some_and(|suffix| suffix.starts_with('/'))
                    })
            })
            || ids.insert(node.id.clone(), node).is_some()
            || !owners.insert(&node.owner)
        {
            return Err(WorkflowError::Invalid("node contract or ownership"));
        }
        if node.mode == NodeMode::IsolatedWrite
            && (!plan
                .task
                .allowed_mutations
                .contains(&Mutation::WorkspaceWrite)
                || matches!(
                    plan.preset,
                    WorkflowPreset::Incident
                        | WorkflowPreset::SecurityReadonly
                        | WorkflowPreset::FanoutReview
                ))
        {
            return Err(WorkflowError::Authority("write node without authority"));
        }
    }
    let mut cost = 0u64;
    let mut tokens = 0u64;
    let mut elapsed = 0u64;
    for node in &plan.nodes {
        if node
            .dependencies
            .iter()
            .any(|id| !ids.contains_key(id) || id == &node.id)
            || node.dependencies.iter().collect::<BTreeSet<_>>().len() != node.dependencies.len()
        {
            return Err(WorkflowError::Invalid("node dependencies"));
        }
        cost = cost
            .checked_add(node.budget.max_cost_microusd)
            .ok_or(WorkflowError::Limit("cost overflow"))?;
        tokens = tokens
            .checked_add(node.budget.max_tokens)
            .ok_or(WorkflowError::Limit("token overflow"))?;
        elapsed = elapsed
            .checked_add(node.budget.max_elapsed_ms)
            .ok_or(WorkflowError::Limit("elapsed overflow"))?;
    }
    if cost > plan.task.budget.max_cost_microusd
        || tokens > plan.task.budget.max_tokens
        || elapsed > plan.task.budget.max_elapsed_ms
    {
        return Err(WorkflowError::Authority("node budgets exceed task budget"));
    }
    let mut done = BTreeSet::new();
    let mut waves = vec![];
    while done.len() < ids.len() {
        let ready: Vec<_> = ids
            .values()
            .filter(|node| {
                !done.contains(&node.id) && node.dependencies.iter().all(|id| done.contains(id))
            })
            .copied()
            .collect();
        if ready.is_empty() {
            return Err(WorkflowError::Invalid("dependency cycle"));
        }
        if ready.len() > plan.max_width {
            return Err(WorkflowError::Limit(
                "parallel width; split or serialize the task",
            ));
        }
        if waves.len() >= plan.max_depth {
            return Err(WorkflowError::Limit("dependency depth"));
        }
        for (index, a) in ready.iter().enumerate() {
            if a.mode != NodeMode::IsolatedWrite {
                continue;
            }
            for b in ready
                .iter()
                .skip(index + 1)
                .filter(|b| b.mode == NodeMode::IsolatedWrite)
            {
                if a.scope
                    .iter()
                    .any(|left| b.scope.iter().any(|right| overlaps(left, right)))
                {
                    return Err(WorkflowError::Authority("overlapping writers in one wave"));
                }
            }
        }
        let wave: Vec<_> = ready.iter().map(|node| node.id.clone()).collect();
        done.extend(wave.iter().cloned());
        waves.push(wave);
    }
    let require_independent = matches!(plan.task.risk, RiskLevel::High | RiskLevel::Critical)
        || matches!(
            plan.preset,
            WorkflowPreset::PlanExecuteVerify
                | WorkflowPreset::ExploreThenBuild
                | WorkflowPreset::Migration
                | WorkflowPreset::BulkMechanical
                | WorkflowPreset::SecurityReadonly
        );
    if require_independent {
        let verifiers: Vec<_> = plan
            .nodes
            .iter()
            .filter(|node| node.independent_verifier && node.mode == NodeMode::ReadOnly)
            .collect();
        if verifiers.is_empty() {
            return Err(WorkflowError::Authority(
                "independent verification required",
            ));
        }
        let mut ancestors: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for wave in &waves {
            for id in wave {
                let node = ids.get(id).ok_or(WorkflowError::Invalid("unknown node"))?;
                let mut prior = BTreeSet::new();
                for dependency in &node.dependencies {
                    prior.insert(dependency.clone());
                    prior.extend(
                        ancestors
                            .get(dependency)
                            .ok_or(WorkflowError::Invalid("dependency order"))?
                            .iter()
                            .cloned(),
                    );
                }
                ancestors.insert(id.clone(), prior);
            }
        }
        let work: Vec<_> = plan
            .nodes
            .iter()
            .filter(|node| !node.independent_verifier)
            .collect();
        if work.is_empty() {
            return Err(WorkflowError::Authority(
                "independent verification requires work to verify",
            ));
        }
        // Read-only findings also need evidence from the actual completed work.
        // A verifier marker or a recomputed plan hash does not establish this.
        for node in work {
            let verified = verifiers.iter().any(|verifier| {
                ancestors
                    .get(&verifier.id)
                    .is_some_and(|prior| prior.contains(&node.id))
                    && node.scope.iter().all(|path| {
                        verifier.scope.iter().any(|scope| {
                            path == scope
                                || path
                                    .strip_prefix(scope)
                                    .is_some_and(|suffix| suffix.starts_with('/'))
                        })
                    })
                    && plan
                        .task
                        .acceptance
                        .iter()
                        .all(|criterion| verifier.verification.contains(criterion))
            });
            if !verified {
                return Err(WorkflowError::Authority(
                    "work lacks downstream independent verification",
                ));
            }
        }
    }
    Ok(waves)
}
