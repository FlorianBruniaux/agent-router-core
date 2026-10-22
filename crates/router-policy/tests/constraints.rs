use std::collections::{BTreeMap, BTreeSet};

use router_catalog::Catalog;
use router_policy::{
    CapabilityKnowledge, ConstraintEngine, ConstraintVerdict, EligibilityContext, Support,
    is_eligible,
};
use router_types::{
    Capability, EffortLevel, HarnessId, HostSnapshot, ModelId, ModelSpec, RiskLevel, StageKind,
    TaskContext, TaskKind,
};

#[test]
fn unavailable_high_quality_model_is_excluded() {
    let context = fixture_context(
        "gpt-5.6-sol",
        StageKind::Plan,
        EffortLevel::High,
        RiskLevel::Medium,
    );

    let verdicts = ConstraintEngine::default().evaluate(&context);

    assert!(!is_eligible(&verdicts));
    assert!(
        verdicts
            .iter()
            .any(|verdict| verdict.code() == "host.model.unavailable")
    );
}

#[test]
fn unsupported_effort_is_excluded() {
    let context = fixture_context(
        "gpt-5.6-terra",
        StageKind::Execute,
        EffortLevel::Max,
        RiskLevel::Medium,
    );

    let verdicts = ConstraintEngine::default().evaluate(&context);

    assert!(!is_eligible(&verdicts));
    assert!(
        verdicts
            .iter()
            .any(|verdict| verdict.code() == "host.effort.unsupported")
    );
}

#[test]
fn model_unsupported_effort_is_excluded_even_when_host_announces_it() {
    let mut context = fixture_context(
        "gpt-5.6-terra",
        StageKind::Execute,
        EffortLevel::Ultra,
        RiskLevel::Medium,
    );
    context.host.supported_efforts.insert(
        ModelId::parse("gpt-5.6-terra").unwrap(),
        BTreeSet::from([EffortLevel::Ultra]),
    );

    let verdicts = ConstraintEngine::default().evaluate(&context);

    assert!(!is_eligible(&verdicts));
    assert_eq!(
        evidence_for(&verdicts, "model.effort.unsupported"),
        "model 'gpt-5.6-terra' does not support effort 'ultra'"
    );
}

#[test]
fn missing_required_capability_is_excluded() {
    let mut context = fixture_context(
        "gpt-5.6-terra",
        StageKind::Execute,
        EffortLevel::High,
        RiskLevel::Medium,
    );
    context.task.required_capabilities = BTreeSet::from([Capability::Vision]);
    context.capabilities =
        CapabilityKnowledge::from(BTreeMap::from([(Capability::Vision, Support::Unsupported)]));

    let verdicts = ConstraintEngine::default().evaluate(&context);

    assert!(!is_eligible(&verdicts));
    assert!(
        verdicts
            .iter()
            .any(|verdict| verdict.code() == "host.capability.missing")
    );
    assert_eq!(
        evidence_for(&verdicts, "host.capability.missing"),
        "host 'codex-host' is known not to support capability 'vision'"
    );
}

#[test]
fn model_that_cannot_serve_stage_is_excluded() {
    let context = fixture_context(
        "gpt-5.6-luna",
        StageKind::Verify,
        EffortLevel::High,
        RiskLevel::Medium,
    );

    let verdicts = ConstraintEngine::default().evaluate(&context);

    assert!(!is_eligible(&verdicts));
    assert!(
        verdicts
            .iter()
            .any(|verdict| verdict.code() == "model.stage.unsupported")
    );
    assert_eq!(
        evidence_for(&verdicts, "model.stage.unsupported"),
        "model 'gpt-5.6-luna' cannot serve stage 'verify'"
    );
}

#[test]
fn unknown_high_risk_capability_closes_route() {
    let mut context = fixture_context(
        "gpt-5.6-terra",
        StageKind::Execute,
        EffortLevel::High,
        RiskLevel::High,
    );
    context.task.required_capabilities = BTreeSet::from([Capability::Vision]);
    context.capabilities =
        CapabilityKnowledge::from(BTreeMap::from([(Capability::Vision, Support::Unknown)]));

    let verdicts = ConstraintEngine::default().evaluate(&context);

    assert!(!is_eligible(&verdicts));
    assert!(
        verdicts
            .iter()
            .any(|verdict| verdict.code() == "host.capability.unknown_high_risk")
    );
}

#[test]
fn definite_unsupported_capability_is_not_hidden_by_an_earlier_unknown() {
    let mut context = fixture_context(
        "gpt-5.6-terra",
        StageKind::Execute,
        EffortLevel::High,
        RiskLevel::High,
    );
    // Tools sorts before Vision: the Unknown is met first.
    context.task.required_capabilities = BTreeSet::from([Capability::Tools, Capability::Vision]);
    context.capabilities = CapabilityKnowledge::from(BTreeMap::from([
        (Capability::Tools, Support::Unknown),
        (Capability::Vision, Support::Unsupported),
    ]));

    let verdicts = ConstraintEngine::default().evaluate(&context);

    assert_eq!(
        evidence_for(&verdicts, "host.capability.missing"),
        "host 'codex-host' is known not to support capability 'vision'"
    );
    assert!(
        !verdicts
            .iter()
            .any(|verdict| verdict.code() == "host.capability.unknown_high_risk")
    );
}

#[test]
fn engine_preserves_every_verdict_in_fixed_constraint_order() {
    let context = fixture_context(
        "gpt-5.6-sol",
        StageKind::Plan,
        EffortLevel::High,
        RiskLevel::Medium,
    );

    let verdicts = ConstraintEngine::default().evaluate(&context);

    assert_eq!(
        verdicts
            .iter()
            .map(|verdict| verdict.code())
            .collect::<Vec<_>>(),
        vec![
            "host.model.unavailable",
            "host.effort.unsupported",
            "model.stage.supported",
            "host.capability.satisfied",
        ]
    );
}

#[test]
fn empty_host_excludes_every_catalog_model_stage() {
    let catalog = Catalog::from_json(include_bytes!(
        "../../../assets/catalogs/codex-core-v1.json"
    ))
    .unwrap();
    let host = HostSnapshot {
        id: "empty-host".into(),
        harness: HarnessId::parse("codex").unwrap(),
        supported_models: BTreeSet::new(),
        supported_efforts: BTreeMap::new(),
        capabilities: BTreeSet::new(),
    };

    for (model_id, model) in catalog.models() {
        for stage in &model.stages {
            let effort = *model.efforts.iter().next().unwrap();
            let context = EligibilityContext {
                task: TaskContext {
                    objective: "catalog invariant".into(),
                    kind: TaskKind::Explore,
                    risk: RiskLevel::Low,
                    required_capabilities: BTreeSet::new(),
                    acceptance: vec![],
                },
                host: host.clone(),
                model: model.clone(),
                stage: *stage,
                effort,
                capabilities: CapabilityKnowledge::default(),
            };

            assert!(
                !is_eligible(&ConstraintEngine::default().evaluate(&context)),
                "{model_id} must not fall back for stage {stage:?}"
            );
        }
    }
}

fn evidence_for<'a>(verdicts: &'a [ConstraintVerdict], code: &str) -> &'a str {
    verdicts
        .iter()
        .find(|verdict| verdict.code() == code)
        .and_then(|verdict| match verdict {
            ConstraintVerdict::Excluded { evidence, .. }
            | ConstraintVerdict::Unknown { evidence, .. } => Some(evidence.as_str()),
            ConstraintVerdict::Eligible { .. } => None,
        })
        .unwrap_or_else(|| panic!("missing non-eligible verdict '{code}'"))
}

fn fixture_context(
    model_id: &str,
    stage: StageKind,
    effort: EffortLevel,
    risk: RiskLevel,
) -> EligibilityContext {
    let model = fixture_model(model_id);
    EligibilityContext {
        task: TaskContext {
            objective: "route fixture".into(),
            kind: TaskKind::Implement,
            risk,
            required_capabilities: BTreeSet::new(),
            acceptance: vec!["constraint verdicts".into()],
        },
        host: HostSnapshot {
            id: "codex-host".into(),
            harness: HarnessId::parse("codex").unwrap(),
            supported_models: BTreeSet::from([
                ModelId::parse("gpt-5.6-terra").unwrap(),
                ModelId::parse("gpt-5.6-luna").unwrap(),
            ]),
            supported_efforts: BTreeMap::from([
                (
                    ModelId::parse("gpt-5.6-terra").unwrap(),
                    BTreeSet::from([EffortLevel::Medium, EffortLevel::High]),
                ),
                (
                    ModelId::parse("gpt-5.6-luna").unwrap(),
                    BTreeSet::from([EffortLevel::Low, EffortLevel::Medium, EffortLevel::High]),
                ),
            ]),
            capabilities: BTreeSet::from([Capability::Tools, Capability::Subagents]),
        },
        model,
        stage,
        effort,
        capabilities: CapabilityKnowledge::from(BTreeMap::from([
            (Capability::Tools, Support::Supported),
            (Capability::Subagents, Support::Supported),
        ])),
    }
}

fn fixture_model(model_id: &str) -> ModelSpec {
    match model_id {
        "gpt-5.6-sol" => ModelSpec {
            id: ModelId::parse(model_id).unwrap(),
            stages: BTreeSet::from([StageKind::Plan, StageKind::Execute, StageKind::Verify]),
            efforts: BTreeSet::from([EffortLevel::High, EffortLevel::Xhigh, EffortLevel::Max]),
            capabilities: BTreeSet::from([Capability::Tools, Capability::Subagents]),
            quality_micros: 950_000,
            cost_micros: 900_000,
            latency_micros: 900_000,
            source: "fixture-policy-prior".into(),
        },
        "gpt-5.6-terra" => ModelSpec {
            id: ModelId::parse(model_id).unwrap(),
            stages: BTreeSet::from([StageKind::Execute, StageKind::Verify]),
            efforts: BTreeSet::from([EffortLevel::Medium, EffortLevel::High, EffortLevel::Xhigh]),
            capabilities: BTreeSet::from([Capability::Tools, Capability::Subagents]),
            quality_micros: 820_000,
            cost_micros: 550_000,
            latency_micros: 550_000,
            source: "fixture-policy-prior".into(),
        },
        "gpt-5.6-luna" => ModelSpec {
            id: ModelId::parse(model_id).unwrap(),
            stages: BTreeSet::from([StageKind::Execute]),
            efforts: BTreeSet::from([EffortLevel::Low, EffortLevel::Medium, EffortLevel::High]),
            capabilities: BTreeSet::from([Capability::Tools]),
            quality_micros: 650_000,
            cost_micros: 200_000,
            latency_micros: 200_000,
            source: "fixture-policy-prior".into(),
        },
        _ => panic!("unsupported fixture model {model_id}"),
    }
}
