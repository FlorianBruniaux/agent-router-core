//! Bounded planning over eligible compatibility rows. No candidate construction,
//! provider call, body loading or execution authority is introduced here.
use crate::{PhaseRouteError, PhaseRouter, ValidatedPhaseContext};
use router_types::*;
use serde::Serialize;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

pub const MAX_GENERATION_NODES: usize = 64;
pub const MAX_GENERATION_ROWS: usize = 2048;
pub const MAX_GENERATION_EDGE_PAIRS: usize = 4096;
pub const MAX_GENERATION_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_GENERATION_WORK: u64 = 20_000_000;

#[derive(Debug, thiserror::Error)]
pub enum GenerationError {
    #[error("generation.invalid: {0}")]
    Invalid(&'static str),
    #[error("generation.limit: {0}")]
    Limit(&'static str),
    #[error("generation.work_limit: {used}/{limit}")]
    WorkLimit { used: u64, limit: u64 },
    #[error("generation.binding")]
    Binding,
    #[error("generation.evidence.expired")]
    Expired,
    #[error("generation.phase: {0}")]
    Phase(#[from] PhaseRouteError),
    #[error("generation.workflow: {0}")]
    Workflow(#[from] router_workflow::WorkflowError),
}
type Result<T> = std::result::Result<T, GenerationError>;

pub struct GenerationNode<'a> {
    pub node_id: &'a str,
    pub router: &'a PhaseRouter,
    pub context: &'a ValidatedPhaseContext,
    pub dimensions: GenerationDimensions,
    pub evidence: BTreeMap<String, GenerationCandidateEvidence>,
}
impl<'a> GenerationNode<'a> {
    /// Convenience ranks use validated local utility and canonical tie order.
    /// Callers may replace the ranked lists, but cannot add compatibility rows.
    pub fn from_context(
        node_id: &'a str,
        router: &'a PhaseRouter,
        context: &'a ValidatedPhaseContext,
    ) -> Self {
        let mut rows: Vec<_> = context
            .request()
            .candidates
            .iter()
            .filter_map(|c| context.eligible_selection(&c.id))
            .collect();
        rows.sort_by(|a, b| {
            b.score
                .utility_micros
                .cmp(&a.score.utility_micros)
                .then_with(|| a.candidate.id.cmp(&b.candidate.id))
        });
        let mut dimensions = GenerationDimensions {
            models: vec![],
            agents: vec![],
            skill_bundles: vec![],
            tool_bundles: vec![],
            sandboxes: vec![],
        };
        for row in rows {
            let c = &row.candidate;
            push_unique(&mut dimensions.models, model(c));
            push_unique(&mut dimensions.agents, c.agent.clone());
            push_unique(&mut dimensions.skill_bundles, c.skills.clone());
            push_unique(&mut dimensions.tool_bundles, tools(c));
            push_unique(&mut dimensions.sandboxes, c.sandbox);
        }
        Self {
            node_id,
            router,
            context,
            dimensions,
            evidence: BTreeMap::new(),
        }
    }
}
fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}
fn model(c: &PhaseCandidate) -> GenerationModelChoice {
    GenerationModelChoice {
        model: c.model.clone(),
        effort: c.effort,
    }
}
fn tools(c: &PhaseCandidate) -> GenerationToolChoice {
    GenerationToolChoice {
        tools: c.tools.clone(),
        policy: c.tool_policy,
    }
}

pub struct PlanGenerationInput<'a> {
    pub plan: &'a WorkflowPlan,
    pub execution: &'a WorkflowExecutionContract,
    pub nodes: &'a [GenerationNode<'a>],
    pub compatibility: &'a [GenerationEdgeCompatibility],
    pub policy: &'a PlanGenerationPolicy,
    pub now_unix_seconds: u64,
}

struct Work {
    stats: GenerationStatistics,
    limit: u64,
}
impl Work {
    fn charge(&mut self, amount: u64) -> Result<()> {
        self.stats.work_units = self
            .stats
            .work_units
            .checked_add(amount)
            .ok_or(GenerationError::Limit("work arithmetic"))?;
        if self.stats.work_units > self.limit {
            return Err(GenerationError::WorkLimit {
                used: self.stats.work_units,
                limit: self.limit,
            });
        }
        Ok(())
    }
}
fn encoded(value: &impl Serialize) -> Result<Vec<u8>> {
    struct BoundedBytes(Vec<u8>);
    impl std::io::Write for BoundedBytes {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_GENERATION_BYTES.saturating_sub(self.0.len()) {
                return Err(std::io::Error::other("generation document limit"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = BoundedBytes(Vec::new());
    serde_json::to_writer(&mut output, value).map_err(|error| {
        if error.is_io() {
            GenerationError::Limit("document bytes")
        } else {
            GenerationError::Invalid("serialization")
        }
    })?;
    Ok(output.0)
}
fn digest(value: &impl Serialize) -> Result<String> {
    Ok(router_adapter_api::content_digest(&encoded(value)?))
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.:/".contains(&c))
}
fn hash_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn policy_valid(policy: &PlanGenerationPolicy, kind: TaskKind) -> Result<&GenerationWeights> {
    if policy.schema_version != 1
        || !identifier(&policy.version)
        || policy.beam_width == 0
        || policy.beam_width > 64
        || policy.max_alternatives > 15
        || policy.max_work_units == 0
        || policy.max_work_units > MAX_GENERATION_WORK
        || policy.max_per_model_family == 0
        || policy.max_per_model_family > 64
        || policy.max_per_transport == 0
        || policy.max_per_transport > 64
        || policy.maximum_evidence_age_seconds > 30 * 86_400
        || policy.weights_by_task_kind.len() > 6
    {
        return Err(GenerationError::Invalid("policy"));
    }
    for k in [
        policy.top_k.models,
        policy.top_k.agents,
        policy.top_k.skill_bundles,
        policy.top_k.tool_bundles,
        policy.top_k.sandboxes,
    ] {
        if k == 0 || k > 64 {
            return Err(GenerationError::Limit("dimension top-k"));
        }
    }
    for weights in policy.weights_by_task_kind.values() {
        if weights.phase_quality_scale == 0
            || weights.phase_quality_scale > 1_000_000_000_000
            || [
                weights.quality,
                weights.relevance,
                weights.historical_fit,
                weights.cache_affinity,
                weights.cost,
                weights.latency,
                weights.context_pressure,
                weights.residual_risk,
                weights.coordination,
                weights.model_switch,
            ]
            .iter()
            .any(|w| *w > 1_000_000)
        {
            return Err(GenerationError::Invalid("class weights"));
        }
    }
    policy
        .weights_by_task_kind
        .get(&kind)
        .ok_or(GenerationError::Invalid("missing task class weights"))
}

struct Row<'a> {
    selection: &'a PhaseSelection,
    features: [u64; 6],
    statuses: BTreeMap<String, GenerationEvidenceStatus>,
    family: Option<String>,
    transport: Option<String>,
}
struct Pool<'a> {
    input: &'a GenerationNode<'a>,
    node: &'a WorkflowNode,
    rows: Vec<Row<'a>>,
    dependencies: Vec<usize>,
}
type CompatibilityEdges = BTreeMap<(String, String), Option<BTreeSet<(String, String)>>>;
struct Prepared<'a> {
    pools: Vec<Pool<'a>>,
    edges: CompatibilityEdges,
    frontiers: Vec<BTreeSet<usize>>,
    budget: TaskBudget,
    input_hash: String,
    policy_hash: String,
    unknown_compatibility: bool,
}
fn signal_provenance(
    value: &GenerationProvenance,
    node: &GenerationNode<'_>,
    input: &PlanGenerationInput<'_>,
) -> Result<GenerationEvidenceStatus> {
    if !hash_valid(&value.source_sha256)
        || value.context_hash != node.context.context_hash()
        || value.execution_contract_sha256 != input.execution.contract_sha256
    {
        return Err(GenerationError::Binding);
    }
    Ok(
        if value.observed_at_unix_seconds <= input.now_unix_seconds
            && input.now_unix_seconds - value.observed_at_unix_seconds
                <= input.policy.maximum_evidence_age_seconds
        {
            GenerationEvidenceStatus::Observed
        } else {
            GenerationEvidenceStatus::Stale
        },
    )
}
fn signal(
    value: &GenerationSignal,
    penalty: bool,
    node: &GenerationNode<'_>,
    input: &PlanGenerationInput<'_>,
) -> Result<(u64, GenerationEvidenceStatus, Option<GenerationProvenance>)> {
    if let GenerationSignal::Observed {
        value_micros,
        provenance,
    } = value
    {
        if *value_micros > 1_000_000 {
            return Err(GenerationError::Invalid("signal fraction"));
        }
        let status = signal_provenance(provenance, node, input)?;
        if status == GenerationEvidenceStatus::Observed {
            return Ok((u64::from(*value_micros), status, Some(provenance.clone())));
        }
        return Ok((if penalty { 1_000_000 } else { 0 }, status, None));
    }
    Ok((
        if penalty { 1_000_000 } else { 0 },
        GenerationEvidenceStatus::Unknown,
        None,
    ))
}
fn label(
    value: &GenerationLabel,
    node: &GenerationNode<'_>,
    input: &PlanGenerationInput<'_>,
) -> Result<(
    Option<String>,
    GenerationEvidenceStatus,
    Option<GenerationProvenance>,
)> {
    if let GenerationLabel::Observed { value, provenance } = value {
        if !identifier(value) {
            return Err(GenerationError::Invalid("diversity label"));
        }
        let status = signal_provenance(provenance, node, input)?;
        if status == GenerationEvidenceStatus::Observed {
            return Ok((Some(value.clone()), status, Some(provenance.clone())));
        }
        return Ok((None, status, None));
    }
    Ok((None, GenerationEvidenceStatus::Unknown, None))
}
fn dimension<T: PartialEq>(ranked: &[T], eligible: &[T], work: &mut Work) -> Result<()> {
    if ranked.len() > 64 {
        return Err(GenerationError::Limit("dimension rows"));
    }
    for (i, value) in ranked.iter().enumerate() {
        if contains(&ranked[..i], value, work)? || !contains(eligible, value, work)? {
            return Err(GenerationError::Invalid(
                "dimension outside eligible rows or duplicate",
            ));
        }
    }
    Ok(())
}
fn contains<T: PartialEq>(values: &[T], needle: &T, work: &mut Work) -> Result<bool> {
    for value in values {
        work.charge(1)?;
        if value == needle {
            return Ok(true);
        }
    }
    Ok(false)
}
fn top<T>(values: &[T], k: usize) -> &[T] {
    &values[..values.len().min(k)]
}

fn prepare<'a>(
    input: &'a PlanGenerationInput<'a>,
    weights: &GenerationWeights,
    work: &mut Work,
) -> Result<Prepared<'a>> {
    if input.plan.nodes.len() > MAX_GENERATION_NODES
        || input.nodes.len() != input.plan.nodes.len()
        || input.compatibility.len() > MAX_GENERATION_EDGE_PAIRS
    {
        return Err(GenerationError::Limit("nodes or edges"));
    }
    work.charge(encoded(input.plan)?.len() as u64)?;
    work.charge(encoded(input.execution)?.len() as u64)?;
    let waves = router_workflow::validate_plan(input.plan)?;
    router_workflow::validate_execution_contract(input.execution, input.plan)?;
    let order: Vec<_> = waves.into_iter().flatten().collect();
    let mut nodes = BTreeMap::new();
    let mut total_rows = 0;
    let mut budget = input.plan.task.budget.clone();
    let mut binding = Vec::new();
    for node in input.nodes {
        if nodes.insert(node.node_id, node).is_some()
            || !input.execution.nodes.contains_key(node.node_id)
        {
            return Err(GenerationError::Binding);
        }
        let restrictions = &node.context.request().restrictions;
        if let Some(maximum) = restrictions.max_cost_microusd {
            budget.max_cost_microusd = budget.max_cost_microusd.min(maximum);
        }
        if let Some(maximum) = restrictions.max_tokens {
            budget.max_tokens = budget.max_tokens.min(maximum);
        }
        let d = &node.dimensions;
        if [
            d.models.len(),
            d.agents.len(),
            d.skill_bundles.len(),
            d.tool_bundles.len(),
            d.sandboxes.len(),
        ]
        .iter()
        .any(|length| *length > 64)
        {
            return Err(GenerationError::Limit("dimension rows"));
        }
        total_rows += node.context.request().candidates.len();
        if total_rows > MAX_GENERATION_ROWS || node.evidence.len() > 64 {
            return Err(GenerationError::Limit("candidate rows"));
        }
        work.charge(encoded(node.context.request())?.len() as u64)?;
        if node.context.request().task != input.plan.task
            || node.context.request().phase != input.execution.nodes[node.node_id].phase
        {
            return Err(GenerationError::Binding);
        }
        for id in node.evidence.keys() {
            if !node
                .context
                .request()
                .candidates
                .iter()
                .any(|c| &c.id == id)
            {
                return Err(GenerationError::Binding);
            }
        }
        let bytes = encoded(&(
            node.node_id,
            node.context.context_hash(),
            &node.dimensions,
            &node.evidence,
        ))?;
        work.charge(bytes.len() as u64)?;
        binding.push((node.node_id, router_adapter_api::content_digest(&bytes)));
    }
    binding.sort();
    let mut edges = BTreeMap::new();
    let mut pairs = 0;
    let mut unknown_compatibility = false;
    for edge in input.compatibility {
        let target = input
            .plan
            .nodes
            .iter()
            .find(|n| n.id == edge.target)
            .ok_or(GenerationError::Binding)?;
        if !target.dependencies.contains(&edge.source)
            || edges.contains_key(&(edge.source.clone(), edge.target.clone()))
        {
            return Err(GenerationError::Binding);
        }
        if let Some(allowed) = &edge.allowed_pairs {
            pairs += allowed.len();
            if pairs > MAX_GENERATION_EDGE_PAIRS {
                return Err(GenerationError::Limit("compatibility pairs"));
            }
            for (from, to) in allowed {
                work.charge(1)?;
                if nodes[edge.source.as_str()]
                    .context
                    .eligible_selection(from)
                    .is_none()
                    || nodes[edge.target.as_str()]
                        .context
                        .eligible_selection(to)
                        .is_none()
                {
                    return Err(GenerationError::Binding);
                }
            }
        } else {
            unknown_compatibility = true;
        }
        edges.insert(
            (edge.source.clone(), edge.target.clone()),
            edge.allowed_pairs.clone(),
        );
    }
    for node in &input.plan.nodes {
        for source in &node.dependencies {
            if !edges.contains_key(&(source.clone(), node.id.clone())) {
                unknown_compatibility = true;
            }
        }
    }
    let edge_bindings: Vec<_> = edges.iter().collect();
    work.charge(encoded(&edge_bindings)?.len() as u64)?;
    let policy_hash = digest(input.policy)?;
    let input_hash = digest(&(
        "bounded-generation-v1",
        &input.plan.plan_id,
        &input.execution.contract_sha256,
        &policy_hash,
        input.now_unix_seconds,
        &binding,
        &edge_bindings,
    ))?;
    let mut pools = Vec::new();
    for (position, id) in order.iter().enumerate() {
        let node = *nodes.get(id.as_str()).ok_or(GenerationError::Binding)?;
        let workflow = input
            .plan
            .nodes
            .iter()
            .find(|n| &n.id == id)
            .ok_or(GenerationError::Binding)?;
        let eligible: Vec<_> = node
            .context
            .request()
            .candidates
            .iter()
            .filter_map(|c| node.context.eligible_selection(&c.id))
            .collect();
        let dims = &node.dimensions;
        let k = input.policy.top_k;
        dimension(
            &dims.models,
            &eligible
                .iter()
                .map(|s| model(&s.candidate))
                .collect::<Vec<_>>(),
            work,
        )?;
        dimension(
            &dims.agents,
            &eligible
                .iter()
                .map(|s| s.candidate.agent.clone())
                .collect::<Vec<_>>(),
            work,
        )?;
        dimension(
            &dims.skill_bundles,
            &eligible
                .iter()
                .map(|s| s.candidate.skills.clone())
                .collect::<Vec<_>>(),
            work,
        )?;
        dimension(
            &dims.tool_bundles,
            &eligible
                .iter()
                .map(|s| tools(&s.candidate))
                .collect::<Vec<_>>(),
            work,
        )?;
        dimension(
            &dims.sandboxes,
            &eligible
                .iter()
                .map(|s| s.candidate.sandbox)
                .collect::<Vec<_>>(),
            work,
        )?;
        let mut rows = vec![];
        for selected in eligible {
            work.charge(1)?;
            node.router.validate_selection(node.context, selected)?;
            let c = &selected.candidate;
            if !contains(top(&dims.models, k.models), &model(c), work)?
                || !contains(top(&dims.agents, k.agents), &c.agent, work)?
                || !contains(top(&dims.skill_bundles, k.skill_bundles), &c.skills, work)?
                || !contains(top(&dims.tool_bundles, k.tool_bundles), &tools(c), work)?
                || !contains(top(&dims.sandboxes, k.sandboxes), &c.sandbox, work)?
            {
                continue;
            }
            if (workflow.mode == NodeMode::IsolatedWrite)
                != (c.sandbox == PhaseSandbox::WorkspaceWrite)
                || (workflow.independent_verifier
                    && c.verification != PhaseVerification::Independent)
                || c.estimated_cost_microusd > workflow.budget.max_cost_microusd
                || c.estimated_tokens > workflow.budget.max_tokens
                || c.estimated_elapsed_ms > workflow.budget.max_elapsed_ms
            {
                work.stats.budget_pruned += 1;
                continue;
            }
            let empty = GenerationCandidateEvidence::default();
            let evidence = node.evidence.get(&c.id).unwrap_or(&empty);
            let quality = u64::try_from(selected.score.quality_micros)
                .map_err(|_| GenerationError::Invalid("negative phase quality"))?;
            let mut features = [
                ((u128::from(quality) * 1_000_000 / u128::from(weights.phase_quality_scale))
                    .min(1_000_000)) as u64,
                u64::from(c.relevance_micros),
                0,
                0,
                0,
                0,
            ];
            let mut statuses = BTreeMap::new();
            for (i, (name, value, penalty)) in [
                ("historical_fit", &evidence.historical_fit, false),
                ("cache_affinity", &evidence.cache_affinity, false),
                ("context_pressure", &evidence.context_pressure, true),
                ("residual_risk", &evidence.residual_risk, true),
            ]
            .into_iter()
            .enumerate()
            {
                let (value, status, _) = signal(value, penalty, node, input)?;
                features[i + 2] = value;
                statuses.insert(name.into(), status);
            }
            let (family, status, _) = label(&evidence.model_family, node, input)?;
            statuses.insert("model_family".into(), status);
            let (transport, status, _) = label(&evidence.transport, node, input)?;
            statuses.insert("transport".into(), status);
            rows.push(Row {
                selection: selected,
                features,
                statuses,
                family,
                transport,
            });
            work.stats.joined_candidates += 1;
        }
        let dependencies = workflow
            .dependencies
            .iter()
            .map(|id| {
                order[..position]
                    .iter()
                    .position(|value| value == id)
                    .ok_or(GenerationError::Binding)
            })
            .collect::<Result<Vec<_>>>()?;
        pools.push(Pool {
            input: node,
            node: workflow,
            rows,
            dependencies,
        });
    }
    let mut frontiers = Vec::with_capacity(pools.len() + 1);
    for assigned in 0..=pools.len() {
        let mut frontier = BTreeSet::new();
        for future in &pools[assigned..] {
            for &dependency in &future.dependencies {
                work.charge(1)?;
                if dependency < assigned {
                    frontier.insert(dependency);
                }
            }
        }
        frontiers.push(frontier);
    }
    Ok(Prepared {
        pools,
        edges,
        frontiers,
        budget,
        input_hash,
        policy_hash,
        unknown_compatibility,
    })
}

#[derive(Clone, Default)]
struct State {
    choices: Vec<usize>,
    finishes: Vec<u64>,
    features: [u64; 6],
    resources: GeneratedResources,
    score: GenerationScore,
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .ok_or(GenerationError::Limit("resource arithmetic"))
}
fn add_overhead(total: &mut GenerationOverhead, value: &GenerationOverhead) -> Result<()> {
    total.cost_microusd = add(total.cost_microusd, value.cost_microusd)?;
    total.tokens = add(total.tokens, value.tokens)?;
    total.elapsed_ms = add(total.elapsed_ms, value.elapsed_ms)?;
    Ok(())
}
fn scale(value: u64, maximum: u64) -> u64 {
    if maximum == 0 {
        0
    } else {
        (u128::from(value) * 1_000_000 / u128::from(maximum)).min(1_000_000) as u64
    }
}
fn score(
    state: &State,
    weights: &GenerationWeights,
    budget: &TaskBudget,
    edge_count: usize,
) -> GenerationScore {
    let weighted =
        |value: u64, weight: u32| ((u128::from(value) * u128::from(weight)) / 1_000_000) as i64;
    let count = state.choices.len() as u64;
    let mut result = GenerationScore {
        quality_micros: weighted(state.features[0] / count, weights.quality),
        relevance_micros: weighted(state.features[1] / count, weights.relevance),
        historical_fit_micros: weighted(state.features[2] / count, weights.historical_fit),
        cache_affinity_micros: weighted(state.features[3] / count, weights.cache_affinity),
        context_penalty_micros: weighted(state.features[4] / count, weights.context_pressure),
        risk_penalty_micros: weighted(state.features[5] / count, weights.residual_risk),
        cost_penalty_micros: weighted(
            scale(state.resources.cost_microusd, budget.max_cost_microusd),
            weights.cost,
        ),
        latency_penalty_micros: weighted(
            scale(state.resources.elapsed_ms, budget.max_elapsed_ms),
            weights.latency,
        ),
        coordination_penalty_micros: weighted(
            scale(
                state.resources.coordination.elapsed_ms,
                budget.max_elapsed_ms,
            ),
            weights.coordination,
        ),
        model_switch_penalty_micros: weighted(
            scale(state.resources.model_switches, edge_count as u64),
            weights.model_switch,
        ),
        utility_micros: 0,
    };
    result.utility_micros = result.quality_micros
        + result.relevance_micros
        + result.historical_fit_micros
        + result.cache_affinity_micros
        - result.context_penalty_micros
        - result.risk_penalty_micros
        - result.cost_penalty_micros
        - result.latency_penalty_micros
        - result.coordination_penalty_micros
        - result.model_switch_penalty_micros;
    result
}
fn extend(
    state: &State,
    row_index: usize,
    prepared: &Prepared<'_>,
    input: &PlanGenerationInput<'_>,
    weights: &GenerationWeights,
    work: &mut Work,
) -> Result<Option<State>> {
    work.charge(1)?;
    work.stats.expanded_states += 1;
    let position = state.choices.len();
    let pool = &prepared.pools[position];
    let row = &pool.rows[row_index];
    let candidate = &row.selection.candidate;
    let mut next = state.clone();
    let mut node_cost = candidate.estimated_cost_microusd;
    let mut node_tokens = candidate.estimated_tokens;
    let mut local_time = candidate.estimated_elapsed_ms;
    let mut start = 0;
    for &dependency in &pool.dependencies {
        work.charge(1)?;
        let producer = &prepared.pools[dependency].rows[state.choices[dependency]]
            .selection
            .candidate;
        let allowed = prepared
            .edges
            .get(&(
                prepared.pools[dependency].node.id.clone(),
                pool.node.id.clone(),
            ))
            .and_then(Option::as_ref);
        if !allowed
            .is_some_and(|pairs| pairs.contains(&(producer.id.clone(), candidate.id.clone())))
        {
            work.stats.compatibility_pruned += 1;
            return Ok(None);
        }
        if pool.node.independent_verifier
            && (pool.input.context.request().previous_model.as_ref() != Some(&producer.model)
                || candidate.model == producer.model
                || (producer.agent.is_some() && candidate.agent == producer.agent))
        {
            work.stats.compatibility_pruned += 1;
            return Ok(None);
        }
        let overhead = &input.policy.coordination_per_edge;
        add_overhead(&mut next.resources.coordination, overhead)?;
        node_cost = add(node_cost, overhead.cost_microusd)?;
        node_tokens = add(node_tokens, overhead.tokens)?;
        local_time = add(local_time, overhead.elapsed_ms)?;
        if producer.model != candidate.model {
            let overhead = &input.policy.model_switch_per_edge;
            add_overhead(&mut next.resources.model_switch, overhead)?;
            next.resources.model_switches += 1;
            node_cost = add(node_cost, overhead.cost_microusd)?;
            node_tokens = add(node_tokens, overhead.tokens)?;
            local_time = add(local_time, overhead.elapsed_ms)?;
        }
        start = start.max(state.finishes[dependency]);
    }
    next.resources.cost_microusd = add(next.resources.cost_microusd, node_cost)?;
    next.resources.tokens = add(next.resources.tokens, node_tokens)?;
    let finish = add(start, local_time)?;
    next.resources.elapsed_ms = add(next.resources.elapsed_ms, local_time)?;
    next.resources.critical_path_elapsed_ms = next.resources.critical_path_elapsed_ms.max(finish);
    let budget = &prepared.budget;
    if node_cost > pool.node.budget.max_cost_microusd
        || node_tokens > pool.node.budget.max_tokens
        || local_time > pool.node.budget.max_elapsed_ms
        || next.resources.cost_microusd > budget.max_cost_microusd
        || next.resources.tokens > budget.max_tokens
        || next.resources.elapsed_ms > budget.max_elapsed_ms
    {
        work.stats.budget_pruned += 1;
        return Ok(None);
    }
    next.choices.push(row_index);
    next.finishes.push(finish);
    for (total, value) in next.features.iter_mut().zip(row.features) {
        *total = add(*total, value)?;
    }
    next.score = score(&next, weights, budget, prepared.edges.len());
    Ok(Some(next))
}
fn dominates(a: &State, b: &State, prepared: &Prepared<'_>, work: &mut Work) -> Result<bool> {
    work.charge(1)?;
    let assigned = a.choices.len();
    let last = assigned - 1;
    let ar = &prepared.pools[last].rows[a.choices[last]];
    let br = &prepared.pools[last].rows[b.choices[last]];
    if ar.family != br.family || ar.transport != br.transport {
        return Ok(false);
    }
    // Exact frontier choices retain both future pair compatibility and switch
    // costs. Equal model IDs alone do not imply equivalent continuations.
    for &index in &prepared.frontiers[assigned] {
        work.charge(1)?;
        let pool = &prepared.pools[index];
        if pool.rows[a.choices[index]].selection.candidate.id
            != pool.rows[b.choices[index]].selection.candidate.id
            || a.finishes[index] > b.finishes[index]
        {
            return Ok(false);
        }
    }
    let av = [
        a.resources.cost_microusd,
        a.resources.tokens,
        a.resources.elapsed_ms,
        a.resources.critical_path_elapsed_ms,
        a.resources.coordination.elapsed_ms,
        a.resources.model_switches,
    ];
    let bv = [
        b.resources.cost_microusd,
        b.resources.tokens,
        b.resources.elapsed_ms,
        b.resources.critical_path_elapsed_ms,
        b.resources.coordination.elapsed_ms,
        b.resources.model_switches,
    ];
    let no_worse = av.iter().zip(bv).all(|(a, b)| *a <= b)
        && a.features[..4]
            .iter()
            .zip(&b.features[..4])
            .all(|(a, b)| a >= b)
        && a.features[4..]
            .iter()
            .zip(&b.features[4..])
            .all(|(a, b)| a <= b);
    let strict = av.iter().zip(bv).any(|(a, b)| *a < b)
        || a.features[..4]
            .iter()
            .zip(&b.features[..4])
            .any(|(a, b)| a > b)
        || a.features[4..]
            .iter()
            .zip(&b.features[4..])
            .any(|(a, b)| a < b);
    Ok(no_worse && strict)
}
fn order(a: &State, b: &State) -> Ordering {
    b.score
        .utility_micros
        .cmp(&a.score.utility_micros)
        .then_with(|| a.resources.cost_microusd.cmp(&b.resources.cost_microusd))
        .then_with(|| a.resources.elapsed_ms.cmp(&b.resources.elapsed_ms))
        .then_with(|| a.choices.cmp(&b.choices))
}
fn prune(
    mut candidates: Vec<State>,
    prepared: &Prepared<'_>,
    policy: &PlanGenerationPolicy,
    work: &mut Work,
) -> Result<Vec<State>> {
    // Insertion sort charges every comparison and stops immediately on the same
    // global budget used by joins, expansions and dominance.
    for i in 1..candidates.len() {
        let mut j = i;
        while j > 0 {
            work.charge(1)?;
            if order(&candidates[j], &candidates[j - 1]) != Ordering::Less {
                break;
            }
            candidates.swap(j, j - 1);
            j -= 1;
        }
    }
    let mut nondominated: Vec<State> = vec![];
    'candidate: for candidate in candidates {
        for other in &nondominated {
            if dominates(other, &candidate, prepared, work)? {
                work.stats.dominance_pruned += 1;
                continue 'candidate;
            }
        }
        let mut keep = Vec::new();
        for other in nondominated {
            if dominates(&candidate, &other, prepared, work)? {
                work.stats.dominance_pruned += 1;
            } else {
                keep.push(other);
            }
        }
        keep.push(candidate);
        nondominated = keep;
    }
    let mut families = BTreeMap::new();
    let mut transports = BTreeMap::new();
    let mut beam = vec![];
    for candidate in nondominated {
        work.charge(1)?;
        let last = candidate.choices.len() - 1;
        let row = &prepared.pools[last].rows[candidate.choices[last]];
        let family = families.entry(row.family.clone()).or_insert(0);
        let transport = transports.entry(row.transport.clone()).or_insert(0);
        if *family >= policy.max_per_model_family || *transport >= policy.max_per_transport {
            work.stats.diversity_pruned += 1;
            continue;
        }
        *family += 1;
        *transport += 1;
        beam.push(candidate);
        if beam.len() == policy.beam_width {
            break;
        }
    }
    Ok(beam)
}
fn proposal(
    state: &State,
    prepared: &Prepared<'_>,
    input: &PlanGenerationInput<'_>,
) -> Result<GeneratedPlan> {
    let choices = state
        .choices
        .iter()
        .enumerate()
        .map(|(index, &choice)| {
            let pool = &prepared.pools[index];
            let row = &pool.rows[choice];
            Ok(GeneratedChoice {
                node_id: pool.node.id.clone(),
                context_hash: pool.input.context.context_hash().into(),
                candidate_id: row.selection.candidate.id.clone(),
                selection_sha256: digest(row.selection)?,
                scope: pool.node.scope.clone(),
                signal_status: row.statuses.clone(),
                model_family: row.family.clone(),
                transport: row.transport.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut plan = GeneratedPlan {
        schema_version: 1,
        proposal_hash: String::new(),
        input_hash: prepared.input_hash.clone(),
        workflow_plan_id: input.plan.plan_id.clone(),
        execution_contract_sha256: input.execution.contract_sha256.clone(),
        choices,
        resources: state.resources.clone(),
        score: state.score.clone(),
    };
    plan.proposal_hash = digest(&("generated-plan-v1", &plan))?;
    Ok(plan)
}
pub fn generate_plans(input: &PlanGenerationInput<'_>) -> Result<PlanGenerationReport> {
    // A caller-supplied plan is not yet bound to the signed preset/node contract.
    if input
        .nodes
        .iter()
        .any(|node| node.context.has_signed_catalog())
    {
        return Err(GenerationError::Invalid(
            "signed catalog plan generation unavailable",
        ));
    }
    let weights = policy_valid(input.policy, input.plan.task.kind)?;
    let mut work = Work {
        stats: GenerationStatistics::default(),
        limit: input.policy.max_work_units,
    };
    let prepared = prepare(input, weights, &mut work)?;
    let mut abstention = if prepared.pools.iter().any(|pool| pool.rows.is_empty()) {
        Some(GenerationAbstention::NoEligibleJoin)
    } else if prepared.unknown_compatibility {
        Some(GenerationAbstention::UnknownCompatibility)
    } else {
        None
    };
    let mut beam = vec![State::default()];
    if abstention.is_none() {
        for pool in &prepared.pools {
            let mut candidates = vec![];
            for state in &beam {
                for row in 0..pool.rows.len() {
                    if let Some(next) = extend(state, row, &prepared, input, weights, &mut work)? {
                        candidates.push(next);
                    }
                }
            }
            beam = prune(candidates, &prepared, input.policy, &mut work)?;
            if beam.is_empty() {
                abstention = Some(GenerationAbstention::NoFeasiblePlan);
                break;
            }
        }
    } else {
        beam.clear();
    }
    let mut plans = beam
        .iter()
        .take(input.policy.max_alternatives + 1)
        .map(|state| proposal(state, &prepared, input))
        .collect::<Result<Vec<_>>>()?;
    let selected = if plans.is_empty() {
        None
    } else {
        Some(plans.remove(0))
    };
    let report = PlanGenerationReport {
        schema_version: 1,
        input_hash: prepared.input_hash,
        policy_hash: prepared.policy_hash,
        selected,
        alternatives: plans,
        abstention,
        statistics: work.stats,
    };
    encoded(&report)?;
    Ok(report)
}

/// Scope/choice proof only. This does not implement ActivationAuthority, does
/// not replace a phase execution decision, and is never deserializable.
#[derive(Clone, Debug)]
pub struct ValidatedGeneratedPlan {
    proposal: GeneratedPlan,
    execution: WorkflowExecutionContract,
    nodes: BTreeMap<String, ValidatedNode>,
    planned_at: u64,
    max_age: u64,
    provenance: Vec<GenerationProvenance>,
}
#[derive(Clone, Debug)]
struct ValidatedNode {
    selection: PhaseSelection,
    phase: StageKind,
    host: HarnessId,
    scope: Vec<String>,
    budget: TaskBudget,
    capabilities: BTreeSet<Capability>,
}
impl ValidatedGeneratedPlan {
    pub fn execution_contract(&self) -> &WorkflowExecutionContract {
        &self.execution
    }
    pub fn planned_at_unix_seconds(&self) -> u64 {
        self.planned_at
    }
    pub fn validate_current(&self, now: u64) -> Result<()> {
        if now < self.planned_at
            || now - self.planned_at > self.max_age
            || self.provenance.iter().any(|value| {
                value.observed_at_unix_seconds > now
                    || now - value.observed_at_unix_seconds > self.max_age
            })
        {
            return Err(GenerationError::Expired);
        }
        Ok(())
    }
    pub fn validate_workflow(
        &self,
        plan: &WorkflowPlan,
        contract: &WorkflowExecutionContract,
    ) -> Result<()> {
        router_workflow::validate_execution_contract(contract, plan)?;
        if contract != &self.execution || plan.plan_id != self.proposal.workflow_plan_id {
            return Err(GenerationError::Binding);
        }
        Ok(())
    }
    pub fn validate_context(
        &self,
        node_id: &str,
        router: &PhaseRouter,
        context: &ValidatedPhaseContext,
    ) -> Result<()> {
        let choice = self
            .proposal
            .choices
            .iter()
            .find(|c| c.node_id == node_id)
            .ok_or(GenerationError::Binding)?;
        let selected = self
            .selection_for(node_id)
            .ok_or(GenerationError::Binding)?;
        if choice.context_hash != context.context_hash() {
            return Err(GenerationError::Binding);
        }
        router.validate_selection(context, selected)?;
        Ok(())
    }
    pub fn proposal(&self) -> &GeneratedPlan {
        &self.proposal
    }
    pub fn selection_for(&self, node_id: &str) -> Option<&PhaseSelection> {
        self.nodes.get(node_id).map(|node| &node.selection)
    }
    /// Final bytes still require router asset gates and adapter/runtime approval.
    /// Receipt IDs are checked by the separate ExecutionDecision boundary.
    pub fn validate_execution(
        &self,
        node_id: &str,
        request: &ExecutionRequest,
        now_unix_seconds: u64,
    ) -> Result<()> {
        self.validate_current(now_unix_seconds)?;
        let node = self.nodes.get(node_id).ok_or(GenerationError::Binding)?;
        let c = &node.selection.candidate;
        let sandbox = if c.sandbox == PhaseSandbox::ReadOnly {
            ExecutionSandbox::ReadOnly
        } else {
            ExecutionSandbox::WorkspaceWrite
        };
        let tool_selection = if c.tool_policy == PhaseToolPolicy::NativeHost {
            ToolSelection::HostPolicy
        } else if c.tools.is_empty() {
            ToolSelection::Disabled
        } else {
            ToolSelection::AllowList(c.tools.iter().cloned().collect())
        };
        if request.schema_version != 1
            || request.workspace != self.execution.workspace
            || request.source_state != self.execution.source_state
            || request.scope != node.scope
            || request.candidate_id != c.id
            || request.model != c.model
            || request.effort != c.effort
            || request.phase != node.phase
            || request.host != node.host
            || request.sandbox != sandbox
            || request.agent != c.agent
            || request.tools != tool_selection
            || request.required_capabilities != node.capabilities
            || request.skills.len() != c.skills.len()
            || request
                .skills
                .iter()
                .map(|skill| &skill.id)
                .collect::<BTreeSet<_>>()
                != c.skills.iter().collect()
            || request.timeout_ms == 0
            || request.timeout_ms > node.budget.max_elapsed_ms
        {
            return Err(GenerationError::Binding);
        }
        Ok(())
    }
}
pub fn validate_generated_plan(
    input: &PlanGenerationInput<'_>,
    proposed: &GeneratedPlan,
) -> Result<ValidatedGeneratedPlan> {
    let report = generate_plans(input)?;
    if !report
        .selected
        .iter()
        .chain(&report.alternatives)
        .any(|known| known == proposed)
    {
        return Err(GenerationError::Binding);
    }
    let mut nodes = BTreeMap::new();
    let mut provenance = vec![];
    for choice in &proposed.choices {
        let source = input
            .nodes
            .iter()
            .find(|node| node.node_id == choice.node_id)
            .ok_or(GenerationError::Binding)?;
        let workflow = input
            .plan
            .nodes
            .iter()
            .find(|node| node.id == choice.node_id)
            .ok_or(GenerationError::Binding)?;
        let selection = source
            .context
            .eligible_selection(&choice.candidate_id)
            .ok_or(GenerationError::Binding)?
            .clone();
        // Every scoring row influences the choice, including alternatives.
        for evidence in source.evidence.values() {
            for signal in [
                &evidence.historical_fit,
                &evidence.cache_affinity,
                &evidence.context_pressure,
                &evidence.residual_risk,
            ] {
                if let GenerationSignal::Observed {
                    provenance: value, ..
                } = signal
                {
                    if signal_provenance(value, source, input)?
                        == GenerationEvidenceStatus::Observed
                    {
                        provenance.push(value.clone());
                    }
                }
            }
            for label in [&evidence.model_family, &evidence.transport] {
                if let GenerationLabel::Observed {
                    provenance: value, ..
                } = label
                {
                    if signal_provenance(value, source, input)?
                        == GenerationEvidenceStatus::Observed
                    {
                        provenance.push(value.clone());
                    }
                }
            }
        }
        nodes.insert(
            choice.node_id.clone(),
            ValidatedNode {
                capabilities: source
                    .router
                    .execution_capabilities(source.context, &selection)?,
                selection,
                phase: source.context.request().phase,
                host: source.context.snapshot().host.harness.clone(),
                scope: workflow.scope.clone(),
                budget: workflow.budget.clone(),
            },
        );
    }
    Ok(ValidatedGeneratedPlan {
        proposal: proposed.clone(),
        execution: input.execution.clone(),
        nodes,
        planned_at: input.now_unix_seconds,
        max_age: input.policy.maximum_evidence_age_seconds,
        provenance,
    })
}
