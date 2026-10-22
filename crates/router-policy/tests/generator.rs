//! Every host, estimate and soft observation in this suite is synthetic.
#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use router_adapter_api::{HostObservation, SnapshotValidation, content_digest};
use router_catalog::Catalog;
use router_policy::{
    GenerationError, GenerationNode, PhaseRouter, PlanGenerationInput, ValidatedPhaseContext,
    generate_plans, validate_generated_plan,
};
use router_types::*;
use router_workflow::{PlanLimits, build_plan, merge_restrictions, seal_execution_contract};
use std::collections::BTreeSet;

struct Fixture {
    plan: WorkflowPlan,
    execution: WorkflowExecutionContract,
    router: PhaseRouter,
    contexts: Vec<ValidatedPhaseContext>,
    compatibility: Vec<GenerationEdgeCompatibility>,
    policy: PlanGenerationPolicy,
}
impl Fixture {
    fn new(edit: impl Fn(usize, &mut PhaseRouteRequest)) -> Self {
        Self::with_preset(WorkflowPreset::DirectSafe, edit)
    }
    fn with_preset(preset: WorkflowPreset, edit: impl Fn(usize, &mut PhaseRouteRequest)) -> Self {
        let mut template: PhaseRouteRequest = serde_json::from_str(include_str!(
            "../../../fixtures/examples/phase-request.json"
        ))
        .unwrap();
        template.task.allowed_mutations.clear();
        template.task.budget = TaskBudget {
            max_cost_microusd: 10_000,
            max_tokens: 10_000,
            max_elapsed_ms: 10_000,
        };
        template.restrictions = restrictions(10_000, 10_000);
        let plan = build_plan(&template.task, preset, PlanLimits::default()).unwrap();
        let execution = seal_execution_contract(
            WorkflowExecutionContract {
                schema_version: 1,
                instance_id: "synthetic-generation".into(),
                plan_id: plan.plan_id.clone(),
                workspace: "/synthetic/workspace".into(),
                source_state: "a".repeat(64),
                contract_sha256: String::new(),
                nodes: plan
                    .nodes
                    .iter()
                    .map(|n| {
                        (
                            n.id.clone(),
                            NodeExecutionContract {
                                phase: if n.independent_verifier || n.id == "verify" {
                                    StageKind::Verify
                                } else {
                                    StageKind::Execute
                                },
                                dependencies: n
                                    .dependencies
                                    .iter()
                                    .cloned()
                                    .map(|id| (id, DependencyRequirement::Verified))
                                    .collect(),
                            },
                        )
                    })
                    .collect(),
            },
            &plan,
        )
        .unwrap();
        let observation: HostObservation = serde_json::from_str(include_str!(
            "../../../fixtures/examples/phase-snapshot.json"
        ))
        .unwrap();
        let snapshot = fixture_proofs::from_observation(
            observation,
            SnapshotValidation {
                now_unix_seconds: 110,
                max_age_seconds: 30,
            },
        )
        .unwrap();
        let mut catalog_json: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../fixtures/examples/phase-catalog.json"
        ))
        .unwrap();
        catalog_json["skills"] = serde_json::json!([{
            "id":"trusted-skill", "description":"synthetic metadata; no body is available",
            "task_kinds":["explore"], "required_capabilities":[], "trust":"trusted_local"
        }]);
        let catalog = Catalog::from_json(&serde_json::to_vec(&catalog_json).unwrap()).unwrap();
        let router = PhaseRouter::stable_v2();
        let contexts: Vec<_> = plan
            .nodes
            .iter()
            .enumerate()
            .map(|(i, node)| {
                let mut request = template.clone();
                request.phase = execution.nodes[&node.id].phase;
                edit(i, &mut request);
                router.context(request, &snapshot, &catalog).unwrap()
            })
            .collect();
        let compatibility = plan
            .nodes
            .iter()
            .flat_map(|n| {
                n.dependencies
                    .iter()
                    .map(|source| GenerationEdgeCompatibility {
                        source: source.clone(),
                        target: n.id.clone(),
                        allowed_pairs: Some(
                            [
                                ("primary", "primary"),
                                ("primary", "secondary"),
                                ("secondary", "primary"),
                                ("secondary", "secondary"),
                            ]
                            .into_iter()
                            .map(|(a, b)| (a.into(), b.into()))
                            .collect(),
                        ),
                    })
            })
            .collect();
        Self {
            plan,
            execution,
            router,
            contexts,
            compatibility,
            policy: PlanGenerationPolicy::default(),
        }
    }
    fn nodes(&self) -> Vec<GenerationNode<'_>> {
        self.plan
            .nodes
            .iter()
            .zip(&self.contexts)
            .map(|(n, c)| GenerationNode::from_context(&n.id, &self.router, c))
            .collect()
    }
    fn input<'a>(&'a self, nodes: &'a [GenerationNode<'a>]) -> PlanGenerationInput<'a> {
        PlanGenerationInput {
            plan: &self.plan,
            execution: &self.execution,
            nodes,
            compatibility: &self.compatibility,
            policy: &self.policy,
            now_unix_seconds: 110,
        }
    }
    fn provenance(&self, index: usize, at: u64) -> GenerationProvenance {
        GenerationProvenance {
            source_sha256: "b".repeat(64),
            context_hash: self.contexts[index].context_hash().into(),
            execution_contract_sha256: self.execution.contract_sha256.clone(),
            observed_at_unix_seconds: at,
        }
    }
    fn execution_request(&self, selected: &PhaseSelection, index: usize) -> ExecutionRequest {
        let candidate = &selected.candidate;
        ExecutionRequest {
            schema_version: 1,
            receipt_id: "separate-execution-decision".into(),
            candidate_id: candidate.id.clone(),
            phase: self.contexts[index].request().phase,
            host: HarnessId::parse("codex").unwrap(),
            model: candidate.model.clone(),
            effort: candidate.effort,
            workspace: self.execution.workspace.clone(),
            source_state: self.execution.source_state.clone(),
            scope: self.plan.nodes[index].scope.clone(),
            sandbox: ExecutionSandbox::ReadOnly,
            required_capabilities: self
                .router
                .execution_capabilities(&self.contexts[index], selected)
                .unwrap(),
            tools: ToolSelection::Disabled,
            agent: None,
            skills: vec![],
            prompt: "synthetic task".into(),
            mode: ExecutionMode::Execute,
            target: ExecutionTarget::ExternalWorker,
            allow_degradation: false,
            timeout_ms: 100,
            max_output_bytes: 1024,
        }
    }
}
fn restrictions(cost: u64, tokens: u64) -> EffectiveRestrictions {
    merge_restrictions(&[RestrictionLayer {
        name: "synthetic-generation-authority".into(),
        allowed_models: None,
        allowed_capabilities: Some(BTreeSet::new()),
        allowed_mutations: Some(BTreeSet::new()),
        max_cost_microusd: Some(cost),
        max_tokens: Some(tokens),
        max_concurrency: Some(1),
        preferred_model: None,
    }])
    .unwrap()
}
fn only_relevance() -> GenerationWeights {
    GenerationWeights {
        phase_quality_scale: 100_000_000,
        quality: 0,
        relevance: 1_000_000,
        historical_fit: 0,
        cache_affinity: 0,
        cost: 0,
        latency: 0,
        context_pressure: 0,
        residual_risk: 0,
        coordination: 0,
        model_switch: 0,
    }
}
fn selected(fixture: &Fixture) -> GeneratedPlan {
    generate_plans(&fixture.input(&fixture.nodes()))
        .unwrap()
        .selected
        .unwrap()
}
fn ids(plan: &GeneratedPlan) -> Vec<&str> {
    plan.choices
        .iter()
        .map(|c| c.candidate_id.as_str())
        .collect()
}
fn observed(value: u32, provenance: GenerationProvenance) -> GenerationSignal {
    GenerationSignal::Observed {
        value_micros: value,
        provenance,
    }
}

#[test]
fn deterministic_join_and_alternatives_bind_canonical_node_order() {
    let fixture = Fixture::new(|_, request| request.candidates[1].estimated_cost_microusd = 10);
    let mut nodes = fixture.nodes();
    let report = generate_plans(&fixture.input(&nodes)).unwrap();
    assert_eq!(
        ids(report.selected.as_ref().unwrap()),
        ["primary", "primary"]
    );
    assert!(!report.alternatives.is_empty());
    assert!(report.statistics.work_units <= fixture.policy.max_work_units);
    assert_eq!(report.statistics.joined_candidates, 4);
    nodes.reverse();
    assert_eq!(report, generate_plans(&fixture.input(&nodes)).unwrap());
    let roundtrip: PlanGenerationReport =
        serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
    assert_eq!(report, roundtrip);
}

#[test]
fn top_k_is_explicit_and_cannot_invent_candidates_or_dimensions() {
    let mut fixture = Fixture::new(|_, _| {});
    fixture.policy.top_k.models = 1;
    let mut nodes = fixture.nodes();
    for node in &mut nodes {
        node.dimensions.models.reverse();
    }
    let report = generate_plans(&fixture.input(&nodes)).unwrap();
    assert_eq!(
        ids(report.selected.as_ref().unwrap()),
        ["secondary", "secondary"]
    );
    assert_eq!(report.statistics.joined_candidates, 2);
    nodes[0].dimensions.models[0].model = ModelId::parse("invented-model").unwrap();
    assert!(matches!(
        generate_plans(&fixture.input(&nodes)),
        Err(GenerationError::Invalid(_))
    ));
    nodes = fixture.nodes();
    nodes[0].dimensions.agents = vec![Some("forged-agent".into())];
    assert!(matches!(
        generate_plans(&fixture.input(&nodes)),
        Err(GenerationError::Invalid(_))
    ));
    nodes = fixture.nodes();
    nodes[0].dimensions.skill_bundles.clear();
    assert_eq!(
        generate_plans(&fixture.input(&nodes)).unwrap().abstention,
        Some(GenerationAbstention::NoEligibleJoin)
    );
}

#[test]
fn unknown_compatibility_abstains_and_known_empty_pairs_reject_all_paths() {
    let mut fixture = Fixture::new(|_, _| {});
    fixture.compatibility[0].allowed_pairs = None;
    assert_eq!(
        generate_plans(&fixture.input(&fixture.nodes()))
            .unwrap()
            .abstention,
        Some(GenerationAbstention::UnknownCompatibility)
    );
    fixture.compatibility[0].allowed_pairs = Some(BTreeSet::new());
    let report = generate_plans(&fixture.input(&fixture.nodes())).unwrap();
    assert_eq!(
        report.abstention,
        Some(GenerationAbstention::NoFeasiblePlan)
    );
    assert_eq!(report.statistics.compatibility_pruned, 4);
    fixture.compatibility.clear();
    assert_eq!(
        generate_plans(&fixture.input(&fixture.nodes()))
            .unwrap()
            .abstention,
        Some(GenerationAbstention::UnknownCompatibility)
    );
}

#[test]
fn compatibility_cannot_resurrect_ineligible_rows_or_add_dag_edges() {
    let mut fixture = Fixture::new(|_, request| {
        request.candidates[1]
            .required_capabilities
            .insert(Capability::Network);
    });
    assert!(matches!(
        generate_plans(&fixture.input(&fixture.nodes())),
        Err(GenerationError::Binding)
    ));
    fixture.compatibility[0].allowed_pairs =
        Some(BTreeSet::from([("primary".into(), "primary".into())]));
    assert_eq!(ids(&selected(&fixture)), ["primary", "primary"]);
    fixture.compatibility[0].source = "verify".into();
    assert!(matches!(
        generate_plans(&fixture.input(&fixture.nodes())),
        Err(GenerationError::Binding)
    ));
}

#[test]
fn cumulative_budgets_include_every_coordination_and_switch_resource() {
    let mut fixture = Fixture::new(|_, _| {});
    fixture.compatibility[0].allowed_pairs =
        Some(BTreeSet::from([("primary".into(), "secondary".into())]));
    fixture.policy.coordination_per_edge = GenerationOverhead {
        cost_microusd: 17,
        tokens: 19,
        elapsed_ms: 23,
    };
    fixture.policy.model_switch_per_edge = GenerationOverhead {
        cost_microusd: 29,
        tokens: 31,
        elapsed_ms: 37,
    };
    let plan = selected(&fixture);
    assert_eq!(plan.resources.cost_microusd, 246);
    assert_eq!(plan.resources.tokens, 250);
    assert_eq!(plan.resources.elapsed_ms, 260);
    assert_eq!(plan.resources.critical_path_elapsed_ms, 260);
    assert_eq!(plan.resources.model_switches, 1);
    assert_eq!(
        plan.resources.coordination,
        fixture.policy.coordination_per_edge
    );
    assert_eq!(
        plan.resources.model_switch,
        fixture.policy.model_switch_per_edge
    );
    for dimension in 0..3 {
        let mut blocked = fixture.policy.clone();
        match dimension {
            0 => blocked.coordination_per_edge.cost_microusd = 5000,
            1 => blocked.coordination_per_edge.tokens = 5000,
            _ => blocked.coordination_per_edge.elapsed_ms = 5000,
        }
        let nodes = fixture.nodes();
        let mut input = fixture.input(&nodes);
        input.policy = &blocked;
        assert_eq!(
            generate_plans(&input).unwrap().abstention,
            Some(GenerationAbstention::NoFeasiblePlan)
        );
    }
    fixture.policy.coordination_per_edge.cost_microusd = u64::MAX;
    assert!(matches!(
        generate_plans(&fixture.input(&fixture.nodes())),
        Err(GenerationError::Limit("resource arithmetic"))
    ));
}

#[test]
fn effective_restriction_budgets_apply_to_the_whole_plan() {
    for dimension in 0..2 {
        let fixture = Fixture::new(|_, request| {
            request.restrictions = restrictions(
                if dimension == 0 { 150 } else { 10000 },
                if dimension == 1 { 150 } else { 10000 },
            )
        });
        let report = generate_plans(&fixture.input(&fixture.nodes())).unwrap();
        assert_eq!(
            report.statistics.joined_candidates, 4,
            "each row alone is hard eligible"
        );
        assert_eq!(
            report.abstention,
            Some(GenerationAbstention::NoFeasiblePlan)
        );
        assert!(report.statistics.budget_pruned > 0);
    }
}

#[test]
fn switching_cost_changes_globally_selected_path_despite_local_preferences() {
    let mut fixture = Fixture::new(|index, request| {
        request.candidates[index].relevance_micros = 1_000_000;
        request.candidates[1 - index].relevance_micros = 600_000;
    });
    fixture
        .policy
        .weights_by_task_kind
        .insert(TaskKind::Explore, only_relevance());
    assert_eq!(ids(&selected(&fixture)), ["primary", "secondary"]);
    fixture
        .policy
        .weights_by_task_kind
        .get_mut(&TaskKind::Explore)
        .unwrap()
        .cost = 1_000_000;
    fixture.policy.model_switch_per_edge.cost_microusd = 3000;
    let plan = selected(&fixture);
    assert_eq!(plan.resources.model_switches, 0);
    assert_eq!(ids(&plan), ["primary", "primary"]);
    assert!(plan.score.relevance_micros < 1_000_000);
}

#[test]
fn coordination_overhead_can_make_locally_preferred_choice_unaffordable() {
    let mut fixture = Fixture::new(|_, request| {
        request.candidates[0].estimated_cost_microusd = 4900;
        request.candidates[0].relevance_micros = 1_000_000;
        request.candidates[1].relevance_micros = 500_000;
    });
    fixture
        .policy
        .weights_by_task_kind
        .insert(TaskKind::Explore, only_relevance());
    assert_eq!(ids(&selected(&fixture)), ["primary", "primary"]);
    fixture.policy.coordination_per_edge.cost_microusd = 200;
    assert_eq!(ids(&selected(&fixture)), ["primary", "secondary"]);
}

#[test]
fn dominance_preserves_exact_frontier_compatibility_even_for_same_model() {
    let mut fixture = Fixture::new(|_, request| {
        request.candidates[1].model = request.candidates[0].model.clone();
        request.candidates[1].estimated_cost_microusd = 200;
    });
    // Secondary looks strictly worse at the first node, but it alone has a continuation.
    fixture.compatibility[0].allowed_pairs =
        Some(BTreeSet::from([("secondary".into(), "primary".into())]));
    assert_eq!(ids(&selected(&fixture)), ["secondary", "primary"]);
    fixture.compatibility[0].allowed_pairs = Some(
        [
            ("primary", "primary"),
            ("primary", "secondary"),
            ("secondary", "primary"),
            ("secondary", "secondary"),
        ]
        .into_iter()
        .map(|(a, b)| (a.into(), b.into()))
        .collect(),
    );
    let report = generate_plans(&fixture.input(&fixture.nodes())).unwrap();
    assert_eq!(
        ids(report.selected.as_ref().unwrap()),
        ["primary", "primary"]
    );
    assert!(report.statistics.dominance_pruned > 0);
}

#[test]
fn unknown_stale_and_future_signals_cannot_create_history_or_cache_benefits() {
    let mut fixture = Fixture::new(|_, _| {});
    fixture.policy.maximum_evidence_age_seconds = 20;
    let weights = fixture
        .policy
        .weights_by_task_kind
        .get_mut(&TaskKind::Explore)
        .unwrap();
    weights.historical_fit = 1_000_000;
    weights.cache_affinity = 1_000_000;
    for (at, status, wanted) in [
        (100, GenerationEvidenceStatus::Observed, "secondary"),
        (0, GenerationEvidenceStatus::Stale, "primary"),
        (111, GenerationEvidenceStatus::Stale, "primary"),
    ] {
        let mut nodes = fixture.nodes();
        for (i, node) in nodes.iter_mut().enumerate() {
            node.evidence.insert(
                "secondary".into(),
                GenerationCandidateEvidence {
                    historical_fit: observed(1_000_000, fixture.provenance(i, at)),
                    cache_affinity: observed(1_000_000, fixture.provenance(i, at)),
                    ..Default::default()
                },
            );
        }
        let report = generate_plans(&fixture.input(&nodes)).unwrap();
        let plan = report.selected.unwrap();
        assert_eq!(ids(&plan), [wanted, wanted]);
        if status == GenerationEvidenceStatus::Observed {
            assert_eq!(plan.choices[0].signal_status["historical_fit"], status);
        } else {
            assert_eq!(plan.score.historical_fit_micros, 0);
            assert_eq!(plan.score.cache_affinity_micros, 0);
        }
        assert_eq!(
            plan.choices[0].signal_status["context_pressure"],
            GenerationEvidenceStatus::Unknown
        );
        assert!(plan.score.context_penalty_micros > 0);
        for node in &mut nodes {
            node.dimensions
                .models
                .retain(|m| m.model.as_str() == "fixture-second");
        }
        let forced = generate_plans(&fixture.input(&nodes))
            .unwrap()
            .selected
            .unwrap();
        assert_eq!(forced.choices[0].signal_status["historical_fit"], status);
        assert_eq!(
            forced.score.historical_fit_micros > 0,
            status == GenerationEvidenceStatus::Observed
        );
    }
}

#[test]
fn evidence_provenance_and_fraction_are_checked_before_scoring() {
    let fixture = Fixture::new(|_, _| {});
    for kind in 0..4 {
        let mut nodes = fixture.nodes();
        let mut provenance = fixture.provenance(0, 100);
        match kind {
            0 => provenance.context_hash = "c".repeat(64),
            1 => provenance.execution_contract_sha256 = "d".repeat(64),
            2 => provenance.source_sha256 = "not-a-digest".into(),
            _ => {}
        }
        nodes[0].evidence.insert(
            "primary".into(),
            GenerationCandidateEvidence {
                cache_affinity: observed(if kind == 3 { 1_000_001 } else { 1_000_000 }, provenance),
                ..Default::default()
            },
        );
        assert!(generate_plans(&fixture.input(&nodes)).is_err());
    }
}

#[test]
fn diversity_retains_distinct_observed_families_and_transports() {
    let mut fixture = Fixture::new(|_, _| {});
    fixture.policy.max_per_model_family = 1;
    fixture.policy.max_per_transport = 1;
    let mut nodes = fixture.nodes();
    for (i, node) in nodes.iter_mut().enumerate() {
        for (id, label) in [("primary", "family-a"), ("secondary", "family-b")] {
            node.evidence.insert(
                id.into(),
                GenerationCandidateEvidence {
                    model_family: GenerationLabel::Observed {
                        value: label.into(),
                        provenance: fixture.provenance(i, 100),
                    },
                    transport: GenerationLabel::Observed {
                        value: label.into(),
                        provenance: fixture.provenance(i, 100),
                    },
                    ..Default::default()
                },
            );
        }
    }
    let report = generate_plans(&fixture.input(&nodes)).unwrap();
    assert_eq!(report.alternatives.len(), 1);
    assert_ne!(
        report
            .selected
            .as_ref()
            .unwrap()
            .choices
            .last()
            .unwrap()
            .model_family,
        report.alternatives[0].choices.last().unwrap().model_family
    );
    // UNKNOWN is one bucket, never invented distinct families.
    let unknown = generate_plans(&fixture.input(&fixture.nodes())).unwrap();
    assert!(unknown.alternatives.is_empty());
    assert!(unknown.statistics.diversity_pruned > 0);
}

#[test]
fn global_work_exhaustion_returns_error_without_partial_recommendation() {
    let mut fixture = Fixture::new(|_, request| request.candidates[1].estimated_cost_microusd = 1);
    let report = generate_plans(&fixture.input(&fixture.nodes())).unwrap();
    assert!(report.statistics.expanded_states > 2);
    let total = report.statistics.work_units;
    fixture.policy.max_work_units = total - 1;
    assert!(matches!(
        generate_plans(&fixture.input(&fixture.nodes())),
        Err(GenerationError::WorkLimit { .. })
    ));
    fixture.policy.max_work_units = 1;
    assert!(matches!(
        generate_plans(&fixture.input(&fixture.nodes())),
        Err(GenerationError::WorkLimit { .. })
    ));
}

#[test]
fn class_weights_can_change_decision_and_are_bounded() {
    let mut fixture =
        Fixture::new(|_, request| request.candidates[0].estimated_cost_microusd = 4900);
    fixture
        .policy
        .weights_by_task_kind
        .get_mut(&TaskKind::Explore)
        .unwrap()
        .cost = 0;
    assert_eq!(ids(&selected(&fixture)), ["primary", "primary"]);
    let mut weights = only_relevance();
    weights.cost = 1_000_000;
    fixture
        .policy
        .weights_by_task_kind
        .insert(TaskKind::Explore, weights);
    assert_eq!(ids(&selected(&fixture)), ["secondary", "secondary"]);
    fixture
        .policy
        .weights_by_task_kind
        .get_mut(&TaskKind::Explore)
        .unwrap()
        .cost = 1_000_001;
    assert!(matches!(
        generate_plans(&fixture.input(&fixture.nodes())),
        Err(GenerationError::Invalid("class weights"))
    ));
    fixture
        .policy
        .weights_by_task_kind
        .remove(&TaskKind::Explore);
    assert!(matches!(
        generate_plans(&fixture.input(&fixture.nodes())),
        Err(GenerationError::Invalid("missing task class weights"))
    ));
}

#[test]
fn opaque_validation_recomputes_proposal_and_exact_execution_scope() {
    let fixture = Fixture::new(|_, _| {});
    let nodes = fixture.nodes();
    let input = fixture.input(&nodes);
    let proposal = generate_plans(&input).unwrap().selected.unwrap();
    let validated = validate_generated_plan(&input, &proposal).unwrap();
    let request = fixture.execution_request(validated.selection_for("execute").unwrap(), 0);
    validated
        .validate_execution("execute", &request, 110)
        .unwrap();
    for field in 0..9 {
        let mut changed = request.clone();
        match field {
            0 => changed.workspace.push_str("-other"),
            1 => changed.source_state = "c".repeat(64),
            2 => changed.scope.push("other".into()),
            3 => changed.candidate_id = "secondary".into(),
            4 => changed.model = ModelId::parse("fixture-second").unwrap(),
            5 => changed.effort = EffortLevel::High,
            6 => changed.tools = ToolSelection::HostPolicy,
            7 => {
                changed.required_capabilities.insert(Capability::Network);
            }
            _ => changed.timeout_ms = 5001,
        }
        assert!(matches!(
            validated.validate_execution("execute", &changed, 110),
            Err(GenerationError::Binding)
        ));
    }
    let mut forged = proposal.clone();
    forged.resources.cost_microusd = 0;
    forged.proposal_hash.clear();
    forged.proposal_hash =
        content_digest(&serde_json::to_vec(&("generated-plan-v1", &forged)).unwrap());
    assert!(matches!(
        validate_generated_plan(&input, &forged),
        Err(GenerationError::Binding)
    ));
    let mut changed = fixture.execution.clone();
    changed.workspace = "/synthetic/other".into();
    changed = seal_execution_contract(changed, &fixture.plan).unwrap();
    let mut moved = fixture.input(&nodes);
    moved.execution = &changed;
    assert!(matches!(
        validate_generated_plan(&moved, &proposal),
        Err(GenerationError::Binding)
    ));
}

#[test]
fn used_soft_evidence_expires_before_execution_even_if_proposal_was_valid() {
    let mut fixture = Fixture::new(|_, _| {});
    fixture.policy.maximum_evidence_age_seconds = 20;
    let mut nodes = fixture.nodes();
    nodes[0].evidence.insert(
        "primary".into(),
        GenerationCandidateEvidence {
            cache_affinity: observed(500_000, fixture.provenance(0, 100)),
            ..Default::default()
        },
    );
    let input = fixture.input(&nodes);
    let proposal = generate_plans(&input).unwrap().selected.unwrap();
    let proof = validate_generated_plan(&input, &proposal).unwrap();
    let request = fixture.execution_request(proof.selection_for("execute").unwrap(), 0);
    proof.validate_execution("execute", &request, 120).unwrap();
    assert!(matches!(
        proof.validate_execution("execute", &request, 121),
        Err(GenerationError::Expired)
    ));
    assert!(matches!(
        proof.validate_execution("execute", &request, 109),
        Err(GenerationError::Expired)
    ));
}

#[test]
fn parallel_wave_keeps_conservative_total_and_separate_critical_path() {
    let mut fixture = Fixture::with_preset(WorkflowPreset::FanoutReview, |_, request| {
        if request.phase == StageKind::Verify {
            request.previous_model = Some(ModelId::parse("fixture-parent").unwrap());
            for candidate in &mut request.candidates {
                candidate.verification = PhaseVerification::Independent;
            }
        }
    });
    fixture.policy.coordination_per_edge.elapsed_ms = 10;
    let plan = selected(&fixture);
    assert_eq!(plan.choices.len(), 3);
    assert_eq!(plan.resources.elapsed_ms, 320);
    assert_eq!(plan.resources.critical_path_elapsed_ms, 220);
    assert_eq!(plan.resources.coordination.elapsed_ms, 20);
}

#[test]
fn task_phase_scope_and_policy_changes_invalidate_bound_proposals() {
    let mut fixture = Fixture::new(|_, _| {});
    let proposal = selected(&fixture);
    fixture.policy.model_switch_per_edge.tokens = 1;
    assert!(matches!(
        validate_generated_plan(&fixture.input(&fixture.nodes()), &proposal),
        Err(GenerationError::Binding)
    ));
    let mut nodes = fixture.nodes();
    nodes[0].context = &fixture.contexts[1];
    assert!(matches!(
        generate_plans(&fixture.input(&nodes)),
        Err(GenerationError::Binding)
    ));
    nodes = fixture.nodes();
    nodes[1].node_id = "execute";
    assert!(matches!(
        generate_plans(&fixture.input(&nodes)),
        Err(GenerationError::Binding)
    ));
    let mut contract = fixture.execution.clone();
    contract.nodes.get_mut("execute").unwrap().phase = StageKind::Plan;
    contract = seal_execution_contract(contract, &fixture.plan).unwrap();
    let nodes = fixture.nodes();
    let mut input = fixture.input(&nodes);
    input.execution = &contract;
    assert!(matches!(
        generate_plans(&input),
        Err(GenerationError::Binding)
    ));
}

#[test]
fn declared_dimensions_bytes_and_unknown_wire_fields_are_bounded() {
    let fixture = Fixture::new(|_, _| {});
    let mut nodes = fixture.nodes();
    nodes[0].dimensions.agents = vec![None; 65];
    assert!(matches!(
        generate_plans(&fixture.input(&nodes)),
        Err(GenerationError::Limit("dimension rows"))
    ));
    nodes = fixture.nodes();
    nodes[0].evidence.insert(
        "primary".into(),
        GenerationCandidateEvidence {
            model_family: GenerationLabel::Observed {
                value: "x".repeat(router_policy::MAX_GENERATION_BYTES + 1),
                provenance: fixture.provenance(0, 100),
            },
            ..Default::default()
        },
    );
    assert!(matches!(
        generate_plans(&fixture.input(&nodes)),
        Err(GenerationError::Limit("document bytes"))
    ));
    let mut wire = serde_json::to_value(&fixture.policy).unwrap();
    wire["force_allow"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<PlanGenerationPolicy>(wire).is_err());
}

#[test]
fn independent_dimension_lists_never_create_a_missing_composite() {
    let mut fixture = Fixture::new(|_, request| {
        request.candidates[0]
            .skills
            .insert(SkillId::parse("trusted-skill").unwrap());
    });
    fixture.policy.top_k.models = 1;
    fixture.policy.top_k.skill_bundles = 1;
    let mut nodes = fixture.nodes();
    // Primary's model and secondary's empty skill set both occur in eligible
    // dimensions, but their joined composite was never authorized.
    for node in &mut nodes {
        node.dimensions.skill_bundles.reverse();
    }
    let report = generate_plans(&fixture.input(&nodes)).unwrap();
    assert_eq!(
        report.abstention,
        Some(GenerationAbstention::NoEligibleJoin)
    );
    assert_eq!(report.statistics.joined_candidates, 0);
    assert!(report.selected.is_none());
}

#[test]
fn independent_workflow_node_rejects_ordinary_verification_candidate() {
    let fixture = Fixture::with_preset(WorkflowPreset::PlanExecuteVerify, |_, _| {});
    let report = generate_plans(&fixture.input(&fixture.nodes())).unwrap();
    assert_eq!(
        report.abstention,
        Some(GenerationAbstention::NoEligibleJoin)
    );
}

#[test]
fn independent_verifier_previous_model_must_match_the_chosen_producer() {
    let fixture = Fixture::with_preset(WorkflowPreset::PlanExecuteVerify, |_, request| {
        if request.phase == StageKind::Verify {
            request.previous_model = Some(ModelId::parse("different-parent").unwrap());
            for candidate in &mut request.candidates {
                candidate.verification = PhaseVerification::Independent;
            }
        }
    });
    let report = generate_plans(&fixture.input(&fixture.nodes())).unwrap();
    assert_eq!(
        report.abstention,
        Some(GenerationAbstention::NoFeasiblePlan)
    );
}

fn retain_eligible_pairs(fixture: &mut Fixture) {
    for edge in &mut fixture.compatibility {
        let candidates = |id: &str| {
            let i = fixture.plan.nodes.iter().position(|n| n.id == id).unwrap();
            let receipt = fixture.router.route(&fixture.contexts[i]).unwrap();
            receipt
                .selected
                .into_iter()
                .chain(receipt.alternatives)
                .map(|s| s.candidate.id)
                .collect::<BTreeSet<_>>()
        };
        let from = candidates(&edge.source);
        let to = candidates(&edge.target);
        edge.allowed_pairs
            .as_mut()
            .unwrap()
            .retain(|(a, b)| from.contains(a) && to.contains(b));
    }
}

#[test]
fn independent_verifier_cannot_share_the_producer_agent_identity() {
    let mut fixture = Fixture::with_preset(WorkflowPreset::PlanExecuteVerify, |_, request| {
        request.restrictions = merge_restrictions(&[RestrictionLayer {
            name: "synthetic-agent-authority".into(),
            allowed_models: None,
            allowed_capabilities: Some(BTreeSet::from([Capability::Subagents])),
            allowed_mutations: Some(BTreeSet::new()),
            max_cost_microusd: Some(10000),
            max_tokens: Some(10000),
            max_concurrency: Some(1),
            preferred_model: None,
        }])
        .unwrap();
        request.registry.assets.push(PhaseRegisteredAsset {
            kind: PhaseAssetKind::Agent,
            id: "shared-agent".into(),
            content_sha256: "c".repeat(64),
            trust: SkillTrust::TrustedLocal,
            license: "MIT".into(),
            permission: CapabilitySupport::Supported,
            required_capabilities: BTreeSet::new(),
            required_mutations: BTreeSet::new(),
            allowed_sandboxes: BTreeSet::from([PhaseSandbox::ReadOnly]),
            maximum_sensitivity: DataSensitivity::Public,
        });
        for candidate in &mut request.candidates {
            candidate.agent = Some("shared-agent".into());
        }
        if request.phase == StageKind::Verify {
            request.previous_model = Some(ModelId::parse("fixture-best").unwrap());
            for candidate in &mut request.candidates {
                candidate.verification = PhaseVerification::Independent;
            }
        }
    });
    retain_eligible_pairs(&mut fixture);
    let report = generate_plans(&fixture.input(&fixture.nodes())).unwrap();
    assert_eq!(
        report.abstention,
        Some(GenerationAbstention::NoFeasiblePlan)
    );
}

#[test]
fn independent_verifier_joins_only_its_actual_distinct_producer() {
    let mut fixture = Fixture::with_preset(WorkflowPreset::PlanExecuteVerify, |_, request| {
        if request.phase == StageKind::Verify {
            request.previous_model = Some(ModelId::parse("fixture-best").unwrap());
            for candidate in &mut request.candidates {
                candidate.verification = PhaseVerification::Independent;
            }
        }
    });
    retain_eligible_pairs(&mut fixture);
    let proposal = selected(&fixture);
    assert_eq!(
        proposal
            .choices
            .iter()
            .find(|c| c.node_id == "execute")
            .unwrap()
            .candidate_id,
        "primary"
    );
    assert_eq!(
        proposal
            .choices
            .iter()
            .find(|c| c.node_id == "verify")
            .unwrap()
            .candidate_id,
        "secondary"
    );
    assert!(validate_generated_plan(&fixture.input(&fixture.nodes()), &proposal).is_ok());
}
