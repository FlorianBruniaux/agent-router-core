use router_types::*;
use router_workflow::*;
use std::collections::{BTreeMap, BTreeSet};

fn input() -> TaskInput {
    TaskInput {
        objective: "  Implement parser  ".into(),
        kind: TaskKind::Implement,
        deliverables: vec![],
        constraints: vec![],
        scope: vec!["src/a.rs".into(), "src/b.rs".into()],
        risk: Some(RiskLevel::Medium),
        sensitivity: Some(DataSensitivity::Internal),
        budget: Some(TaskBudget {
            max_cost_microusd: 1000,
            max_elapsed_ms: 10000,
            max_tokens: 10000,
        }),
        allowed_mutations: Some(BTreeSet::from([Mutation::WorkspaceWrite])),
        dependencies: vec![],
        acceptance: vec!["Parser contracts pass".into()],
        required_capabilities: BTreeSet::new(),
    }
}
fn task() -> NormalizedTask {
    normalize(input()).unwrap().task.unwrap()
}

#[test]
fn fixed_configuration_precedence_never_regrants_organization_prohibitions() {
    let layer = |name: &str, preferred: &str, writes: bool| RestrictionLayer {
        name: name.into(),
        allowed_models: None,
        allowed_capabilities: None,
        allowed_mutations: Some(if writes {
            BTreeSet::from([Mutation::WorkspaceWrite])
        } else {
            BTreeSet::new()
        }),
        max_cost_microusd: None,
        max_tokens: None,
        max_concurrency: Some(4),
        preferred_model: Some(ModelId::parse(preferred).unwrap()),
    };
    let mut config = ConfigurationLayers {
        schema_version: 1,
        defaults: layer("default", "default-model", true),
        active_offline_policy: Some(layer("offline", "learned-model", true)),
        preset: Some(layer("preset", "preset-model", true)),
        project: Some(layer("project", "project-model", true)),
        organization: Some(layer("organization", "org-model", false)),
        task: Some(layer("explicit", "task-model", true)),
    };
    let resolved = resolve_configuration(&config).unwrap();
    assert_eq!(resolved.preferred_model.unwrap().as_str(), "task-model");
    assert_eq!(resolved.allowed_mutations, Some(BTreeSet::new()));
    assert_eq!(resolved.sources[0], "defaults:default");
    assert_eq!(resolved.sources[5], "task:explicit");
    config.organization.as_mut().unwrap().allowed_models =
        Some(BTreeSet::from([ModelId::parse("org-model").unwrap()]));
    assert!(matches!(
        resolve_configuration(&config),
        Err(WorkflowError::Authority(_))
    ));
}

#[test]
fn normalization_requires_missing_authority_cost_and_security_facts() {
    let mut draft = input();
    draft.budget = None;
    draft.allowed_mutations = None;
    draft.sensitivity = None;
    let result = normalize(draft).unwrap();
    assert!(result.task.is_none());
    assert_eq!(result.questions.len(), 3);
    assert_eq!(result.assumptions.len(), 1);
    assert_eq!(task().objective, "Implement parser");
    let mut draft = input();
    draft.scope = vec!["../secret".into()];
    assert!(normalize(draft).is_err());
}

#[test]
fn all_eight_presets_have_deterministic_dags_and_explicit_integration() {
    for preset in [
        WorkflowPreset::DirectSafe,
        WorkflowPreset::PlanExecuteVerify,
        WorkflowPreset::ExploreThenBuild,
        WorkflowPreset::FanoutReview,
        WorkflowPreset::Incident,
        WorkflowPreset::Migration,
        WorkflowPreset::SecurityReadonly,
        WorkflowPreset::BulkMechanical,
    ] {
        let plan = build_plan(&task(), preset, PlanLimits::default()).unwrap();
        assert_eq!(
            plan,
            build_plan(&task(), preset, PlanLimits::default()).unwrap()
        );
        assert!(!validate_plan(&plan).unwrap().is_empty());
        assert!(plan.requires_explicit_integration);
        if matches!(
            preset,
            WorkflowPreset::SecurityReadonly
                | WorkflowPreset::Incident
                | WorkflowPreset::FanoutReview
        ) {
            assert!(
                plan.nodes
                    .iter()
                    .all(|node| node.mode == NodeMode::ReadOnly)
            );
        }
    }
}

#[test]
fn modified_receipt_and_implicit_integration_fail_closed() {
    let mut plan = build_plan(
        &task(),
        WorkflowPreset::PlanExecuteVerify,
        PlanLimits::default(),
    )
    .unwrap();
    plan.nodes[0].purpose.push_str(" changed");
    assert!(matches!(
        validate_plan(&plan),
        Err(WorkflowError::Integrity)
    ));
    plan.requires_explicit_integration = false;
    assert!(matches!(
        validate_plan(&plan),
        Err(WorkflowError::Authority(_))
    ));
}

#[test]
fn overlapping_writers_and_cycles_are_rejected() {
    let mut task = task();
    task.scope = vec!["src".into(), "src/a.rs".into()];
    assert!(matches!(
        build_plan(&task, WorkflowPreset::BulkMechanical, PlanLimits::default()),
        Err(WorkflowError::Authority(_))
    ));
    let mut plan = build_plan(
        &task,
        WorkflowPreset::PlanExecuteVerify,
        PlanLimits::default(),
    )
    .unwrap();
    plan.nodes[0].dependencies.push("verify".into());
    assert!(matches!(
        validate_plan(&plan),
        Err(WorkflowError::Invalid("dependency cycle"))
    ));
}

#[test]
fn cost_failure_suggests_simplification_and_critical_risk_rejects_direct_safe() {
    let limits = PlanLimits {
        reserve_cost_microusd: 500,
        ..PlanLimits::default()
    };
    assert!(matches!(
        build_plan(&task(), WorkflowPreset::PlanExecuteVerify, limits),
        Err(WorkflowError::Cost { .. })
    ));
    let mut task = task();
    task.risk = RiskLevel::Critical;
    assert!(build_plan(&task, WorkflowPreset::DirectSafe, PlanLimits::default()).is_err());
}

fn layer(name: &str) -> RestrictionLayer {
    RestrictionLayer {
        name: name.into(),
        allowed_models: None,
        allowed_capabilities: None,
        allowed_mutations: None,
        max_cost_microusd: None,
        max_tokens: None,
        max_concurrency: None,
        preferred_model: None,
    }
}
#[test]
fn task_override_cannot_expand_restricted_models_mutations_or_budget() {
    let a = ModelId::parse("model-a").unwrap();
    let b = ModelId::parse("model-b").unwrap();
    let mut organization = layer("organization");
    organization.allowed_models = Some(BTreeSet::from([a.clone()]));
    organization.allowed_mutations = Some(BTreeSet::new());
    organization.max_cost_microusd = Some(100);
    let mut task = layer("task-override");
    task.allowed_models = Some(BTreeSet::from([a.clone(), b.clone()]));
    task.allowed_mutations = Some(BTreeSet::from([Mutation::WorkspaceWrite]));
    task.max_cost_microusd = Some(1000);
    let merged = merge_restrictions(&[organization.clone(), task.clone()]).unwrap();
    assert_eq!(merged.allowed_models, Some(BTreeSet::from([a])));
    assert!(merged.allowed_mutations.unwrap().is_empty());
    assert_eq!(merged.max_cost_microusd, Some(100));
    task.preferred_model = Some(b);
    assert!(matches!(
        merge_restrictions(&[organization, task]),
        Err(WorkflowError::Authority(_))
    ));
}

fn template() -> PromptTemplate {
    seal_prompt(PromptTemplate {
        schema_version: 1,
        id: "review".into(),
        version: "1".into(),
        template: "Review ${file}: ${content}".into(),
        variables: BTreeMap::from([
            ("file".into(), PromptVariableType::RelativePath),
            ("content".into(), PromptVariableType::Text),
        ]),
        compatible_hosts: BTreeSet::from(["codex".into()]),
        compatible_models: BTreeSet::from([ModelId::parse("model-a").unwrap()]),
        max_rendered_bytes: 100,
        output_contract: "JSON findings".into(),
        content_sha256: String::new(),
    })
    .unwrap()
}
#[test]
fn typed_prompt_checks_integrity_and_bounds_without_recursive_substitution() {
    let model = ModelId::parse("model-a").unwrap();
    let prompt = template();
    let mut values = BTreeMap::from([
        ("file".into(), PromptValue::Text("src/a.rs".into())),
        ("content".into(), PromptValue::Text("${file}".into())),
    ]);
    assert_eq!(
        render_prompt(&prompt, "codex", &model, &values).unwrap(),
        "Review src/a.rs: ${file}"
    );
    values.insert("file".into(), PromptValue::Text("../escape".into()));
    assert!(render_prompt(&prompt, "codex", &model, &values).is_err());
    values.insert("file".into(), PromptValue::Text("src/a.rs".into()));
    values.insert("content".into(), PromptValue::Text("x".repeat(100)));
    assert!(render_prompt(&prompt, "codex", &model, &values).is_err());
    values.remove("file");
    assert!(render_prompt(&prompt, "codex", &model, &values).is_err());
    let mut changed = prompt.clone();
    changed.output_contract.push('!');
    assert!(matches!(
        render_prompt(&changed, "codex", &model, &values),
        Err(WorkflowError::Integrity)
    ));
}

fn rehash(plan: &mut WorkflowPlan) {
    use sha2::{Digest, Sha256};
    plan.plan_id.clear();
    plan.plan_id = hex::encode(Sha256::digest(serde_json::to_vec(&plan).unwrap()));
}
#[test]
fn a_rehashed_high_risk_plan_cannot_remove_or_move_its_independent_verifier() {
    let mut task = task();
    task.risk = RiskLevel::High;
    let original = build_plan(
        &task,
        WorkflowPreset::PlanExecuteVerify,
        PlanLimits::default(),
    )
    .unwrap();
    let mut removed = original.clone();
    removed.nodes.retain(|node| !node.independent_verifier);
    rehash(&mut removed);
    assert!(matches!(
        validate_plan(&removed),
        Err(WorkflowError::Authority(_))
    ));
    let mut upstream = original;
    upstream
        .nodes
        .iter_mut()
        .find(|node| node.independent_verifier)
        .unwrap()
        .dependencies
        .clear();
    rehash(&mut upstream);
    assert!(matches!(
        validate_plan(&upstream),
        Err(WorkflowError::Authority(_))
    ));
}

#[test]
fn rehashed_readonly_plan_requires_downstream_scope_and_acceptance_verification() {
    for (preset, risk) in [
        (WorkflowPreset::SecurityReadonly, RiskLevel::Low),
        (WorkflowPreset::PlanExecuteVerify, RiskLevel::High),
        (WorkflowPreset::Incident, RiskLevel::Critical),
    ] {
        let mut input = input();
        input.kind = TaskKind::Explore;
        input.allowed_mutations = Some(BTreeSet::new());
        input.risk = Some(risk);
        let task = normalize(input).unwrap().task.unwrap();
        let original = build_plan(&task, preset, PlanLimits::default()).unwrap();
        assert!(
            original
                .nodes
                .iter()
                .all(|node| node.mode == NodeMode::ReadOnly)
        );
        for mutation in ["upstream", "scope", "acceptance", "all-verifiers"] {
            let mut plan = original.clone();
            if mutation == "all-verifiers" {
                for node in &mut plan.nodes {
                    node.independent_verifier = true;
                }
            } else {
                let verifier = plan
                    .nodes
                    .iter_mut()
                    .find(|node| node.independent_verifier)
                    .unwrap();
                match mutation {
                    "upstream" => {
                        verifier.dependencies.clear();
                        verifier.inputs = vec!["task".into()];
                    }
                    "scope" => verifier.scope = vec!["src/a.rs".into()],
                    _ => verifier.verification = vec!["unrelated criterion".into()],
                }
            }
            rehash(&mut plan);
            assert!(
                matches!(validate_plan(&plan), Err(WorkflowError::Authority(_))),
                "preset={preset:?} mutation={mutation}"
            );
        }
    }
}

#[test]
fn high_risk_fanout_has_independent_verification_after_synthesis() {
    let mut input = input();
    input.kind = TaskKind::Explore;
    input.allowed_mutations = Some(BTreeSet::new());
    input.risk = Some(RiskLevel::High);
    let task = normalize(input).unwrap().task.unwrap();
    let plan = build_plan(&task, WorkflowPreset::FanoutReview, PlanLimits::default()).unwrap();
    let waves = validate_plan(&plan).unwrap();
    let synthesis = waves
        .iter()
        .position(|wave| wave.iter().any(|id| id == "synthesize"))
        .unwrap();
    assert!(plan.nodes.iter().any(|node| {
        node.independent_verifier
            && waves
                .iter()
                .position(|wave| wave.contains(&node.id))
                .unwrap()
                > synthesis
    }));
    let mut missing = plan;
    missing.nodes.retain(|node| node.id != "verify-synthesis");
    rehash(&mut missing);
    assert!(matches!(
        validate_plan(&missing),
        Err(WorkflowError::Authority(_))
    ));
}
#[test]
fn empty_node_contracts_are_invalid_even_with_a_valid_hash() {
    for field in ["outputs", "verification", "inputs"] {
        let mut plan = build_plan(
            &task(),
            WorkflowPreset::PlanExecuteVerify,
            PlanLimits::default(),
        )
        .unwrap();
        match field {
            "outputs" => plan.nodes[0].outputs = vec![String::new()],
            "verification" => plan.nodes[0].verification = vec![String::new()],
            _ => plan.nodes[0].inputs = vec![String::new()],
        }
        rehash(&mut plan);
        assert!(matches!(
            validate_plan(&plan),
            Err(WorkflowError::Invalid(_))
        ));
    }
}

#[test]
fn execution_contract_is_explicit_hashed_and_does_not_change_v1_plan_bytes() {
    let plan = build_plan(
        &task(),
        WorkflowPreset::PlanExecuteVerify,
        PlanLimits::default(),
    )
    .unwrap();
    let original = serde_json::to_vec(&plan).unwrap();
    let contract = WorkflowExecutionContract {
        schema_version: 1,
        instance_id: "workflow-a".into(),
        plan_id: plan.plan_id.clone(),
        workspace: "/tmp/fixture".into(),
        source_state: "a".repeat(40),
        nodes: plan
            .nodes
            .iter()
            .map(|node| {
                (
                    node.id.clone(),
                    NodeExecutionContract {
                        phase: match node.id.as_str() {
                            "plan" => StageKind::Plan,
                            "verify" => StageKind::Verify,
                            _ => StageKind::Execute,
                        },
                        dependencies: node
                            .dependencies
                            .iter()
                            .map(|id| {
                                (
                                    id.clone(),
                                    if node.id == "verify" {
                                        DependencyRequirement::ArtifactReadyForVerification
                                    } else {
                                        DependencyRequirement::Verified
                                    },
                                )
                            })
                            .collect(),
                    },
                )
            })
            .collect(),
        contract_sha256: String::new(),
    };
    let sealed = seal_execution_contract(contract, &plan).unwrap();
    validate_execution_contract(&sealed, &plan).unwrap();
    assert_eq!(serde_json::to_vec(&plan).unwrap(), original);
    assert_eq!(
        seal_execution_contract(sealed.clone(), &plan).unwrap(),
        sealed
    );
    let mut other = sealed.clone();
    other.instance_id = "workflow-b".into();
    assert!(validate_execution_contract(&other, &plan).is_err());
    assert_ne!(
        seal_execution_contract(other, &plan)
            .unwrap()
            .contract_sha256,
        sealed.contract_sha256
    );
    let mut missing = sealed.clone();
    missing.nodes.remove("plan");
    assert!(seal_execution_contract(missing, &plan).is_err());
    let mut forged = sealed.clone();
    forged.nodes.get_mut("verify").unwrap().phase = StageKind::Execute;
    assert!(seal_execution_contract(forged, &plan).is_err());
    let mut premature = sealed.clone();
    premature
        .nodes
        .get_mut("execute")
        .unwrap()
        .dependencies
        .insert(
            "plan".into(),
            DependencyRequirement::ArtifactReadyForVerification,
        );
    assert!(seal_execution_contract(premature, &plan).is_err());
    let mut writer_plan = sealed;
    writer_plan.nodes.get_mut("execute").unwrap().phase = StageKind::Plan;
    assert!(seal_execution_contract(writer_plan, &plan).is_err());
}
