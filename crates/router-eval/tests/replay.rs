#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)]
mod fixture_proofs;
use std::collections::{BTreeMap, BTreeSet};

use router_adapter_api::{EvidenceKind, EvidenceSource, HostObservation, SnapshotValidation};
use router_catalog::Catalog;
use router_eval::*;
use router_policy::PhaseRouter;
use router_types::*;
use router_workflow::merge_restrictions;
use serde_json::json;

fn model(id: &str) -> ModelId {
    ModelId::parse(id).unwrap()
}
fn validation() -> SnapshotValidation {
    SnapshotValidation {
        now_unix_seconds: 110,
        max_age_seconds: 60,
    }
}
fn candidate(id: &str, model_id: &str) -> PhaseCandidate {
    PhaseCandidate {
        tool_policy: router_types::PhaseToolPolicy::Restricted,
        id: id.into(),
        model: model(model_id),
        effort: EffortLevel::Medium,
        agent: None,
        skills: BTreeSet::new(),
        tools: BTreeSet::new(),
        sandbox: PhaseSandbox::ReadOnly,
        verification: PhaseVerification::Required,
        required_capabilities: BTreeSet::new(),
        required_mutations: BTreeSet::new(),
        estimated_cost_microusd: 100,
        estimated_tokens: 100,
        estimated_elapsed_ms: 100,
        relevance_micros: 0,
    }
}
fn input() -> ReplayInput {
    let catalog = json!({"schema_version":1,"version":"synthetic-prior","models":[
        {"id":"fixture-best","stages":["plan","execute","verify"],"efforts":["medium"],"capabilities":[],"quality_micros":900000,"cost_micros":100,"latency_micros":100,"source":"synthetic-test"},
        {"id":"fixture-second","stages":["plan","execute","verify"],"efforts":["medium"],"capabilities":[],"quality_micros":700000,"cost_micros":50,"latency_micros":50,"source":"synthetic-test"}],"skills":[]});
    let models = [model("fixture-best"), model("fixture-second")];
    let snapshot = HostObservation {
        attestations: None,
        schema_version: 1,
        host: HostSnapshot {
            id: "fixture-host".into(),
            harness: HarnessId::parse("codex").unwrap(),
            supported_models: models.iter().cloned().collect(),
            supported_efforts: models
                .into_iter()
                .map(|id| (id, BTreeSet::from([EffortLevel::Medium])))
                .collect(),
            capabilities: BTreeSet::new(),
        },
        capabilities: BTreeMap::new(),
        evidence: vec![EvidenceSource {
            id: "fixture-cache".into(),
            kind: EvidenceKind::CodexModelCache,
            observed_version: Some("fixture-v1".into()),
            observed_at_unix_seconds: 100,
            content_sha256: "a".repeat(64),
        }],
        observed_at_unix_seconds: 100,
        snapshot_hash: String::new(),
    }
    .seal()
    .unwrap();
    let restrictions = merge_restrictions(&[RestrictionLayer {
        name: "fixture-authority".into(),
        allowed_models: None,
        allowed_capabilities: None,
        allowed_mutations: Some(BTreeSet::new()),
        max_cost_microusd: Some(10000),
        max_tokens: Some(1000),
        max_concurrency: Some(1),
        preferred_model: None,
    }])
    .unwrap();
    let request = PhaseRouteRequest {
        schema_version: 2,
        task: NormalizedTask {
            objective: "Inspect the deterministic Rust contract".into(),
            kind: TaskKind::Explore,
            deliverables: vec!["contract report".into()],
            constraints: vec![],
            scope: vec!["src".into()],
            risk: RiskLevel::Low,
            sensitivity: DataSensitivity::Public,
            budget: TaskBudget {
                max_cost_microusd: 10000,
                max_elapsed_ms: 1000,
                max_tokens: 1000,
            },
            allowed_mutations: BTreeSet::new(),
            dependencies: vec![],
            acceptance: vec!["Cite an enforcing symbol".into()],
            required_capabilities: BTreeSet::new(),
        },
        phase: StageKind::Plan,
        restrictions,
        permissions: BTreeMap::from([
            (
                PhasePermission::ModelInference,
                CapabilitySupport::Supported,
            ),
            (PhasePermission::WorkspaceRead, CapabilitySupport::Supported),
        ]),
        registry: PhaseAssetRegistry::default(),
        candidates: vec![
            candidate("primary", "fixture-best"),
            candidate("secondary", "fixture-second"),
        ],
        previous_model: None,
    };
    let phase = |id: &str| RecordedPhase {
        usage: vec![TokenUsage {
            model: model(id),
            input_tokens: 100,
            cached_input_tokens: 0,
            output_tokens: 0,
        }],
        elapsed_ms: Some(10),
        fallback_reasons: vec![],
        outcomes: VerificationOutcomes::default(),
    };
    ReplayInput {
        schema_version: 1,
        case_id: "case-1".into(),
        family_id: "family-1".into(),
        split: DatasetSplit::HeldOut,
        out_of_domain: false,
        request,
        snapshot,
        catalog,
        policies: BTreeMap::from([
            (
                "baseline".into(),
                PhasePolicy {
                    version: "baseline-v1".into(),
                    ..PhasePolicy::default()
                },
            ),
            (
                "semantic".into(),
                PhasePolicy {
                    version: "recorded-shadow-v1".into(),
                    ..PhasePolicy::default()
                },
            ),
        ]),
        pricing: PricingTable {
            schema_version: 1,
            version: "synthetic-price-v1".into(),
            source: "synthetic-test-only-not-market-prices".into(),
            observed_at_unix_seconds: 100,
            models: BTreeMap::from([
                (
                    model("fixture-best"),
                    TokenPrice {
                        input_microusd_per_million: 2_000_000,
                        cached_input_microusd_per_million: 1_000_000,
                        output_microusd_per_million: 4_000_000,
                    },
                ),
                (
                    model("fixture-second"),
                    TokenPrice {
                        input_microusd_per_million: 1_000_000,
                        cached_input_microusd_per_million: 500_000,
                        output_microusd_per_million: 2_000_000,
                    },
                ),
            ]),
        },
        observations: BTreeMap::from([
            ("baseline".into(), phase("fixture-best")),
            ("semantic".into(), phase("fixture-second")),
        ]),
        label: None,
    }
}

fn shadow(record: &ReplayRecord) -> ReplayTrace {
    run_replay(record, "semantic", validation(), |context| {
        PhaseRouter::new(context.policy.clone())
            .unwrap()
            .fallback(context.phase_context, &BTreeSet::from(["primary".into()]))
            .map_err(|_| EvalError::Backend)
    })
    .unwrap()
}

fn pair(mut input: ReplayInput) -> PairedTrace {
    // Synthetic test attestations exercise the gate. They are never exported to
    // the project candidate corpus and represent no actual human review.
    input.label.get_or_insert(CaseLabel {
        human_validated: true,
        independent: true,
        reviewer_id: Some("synthetic-reviewer".into()),
        evidence_sha256: Some("b".repeat(64)),
        expected_candidate_ids: BTreeSet::from(["primary".into(), "secondary".into()]),
        expect_abstention: false,
    });
    let record = ReplayRecord::seal(input).unwrap();
    PairedTrace {
        baseline: replay_deterministic(&record, "baseline", validation()).unwrap(),
        semantic: shadow(&record),
    }
}

fn criteria(pairs: &[PairedTrace]) -> PromotionCriteria {
    PromotionCriteria {
        schema_version: 1,
        dataset_hash: dataset_hash(pairs).unwrap(),
        registered_at_unix_seconds: 99,
        registration_evidence_sha256: "c".repeat(64),
        minimum_cases: 1,
        minimum_families: 1,
        policy_authors: BTreeSet::from(["synthetic-policy-author".into()]),
        training_families: BTreeSet::new(),
        rules: vec![
            MetricRule {
                metric: PromotionMetric::RouteAccuracy,
                minimum_improvement_micros: 0,
                maximum_regression_micros: 0,
            },
            MetricRule {
                metric: PromotionMetric::Cost,
                minimum_improvement_micros: 100_000,
                maximum_regression_micros: 0,
            },
        ],
    }
}

#[test]
fn replay_roundtrip_and_traces_are_reproducible_from_all_inputs() {
    let record = ReplayRecord::seal(input()).unwrap();
    let decoded = ReplayRecord::from_json(&record.canonical_json().unwrap()).unwrap();
    assert_eq!(record, decoded);
    let first = replay_deterministic(&record, "baseline", validation()).unwrap();
    assert_eq!(
        first,
        replay_deterministic(&decoded, "baseline", validation()).unwrap()
    );
    assert_eq!(first.cost_microusd(), 200);
    assert!(first.violations().is_empty());
    assert_eq!(first.outcomes().functional, ObservedOutcome::Unknown);
    let mut changed = input();
    changed.catalog["models"][0]["cost_micros"] = 101.into();
    assert_ne!(
        record.input_hash(),
        ReplayRecord::seal(changed).unwrap().input_hash()
    );
}

#[test]
fn stored_input_tampering_and_stale_snapshots_fail() {
    let record = ReplayRecord::seal(input()).unwrap();
    let mut value = serde_json::to_value(&record).unwrap();
    value["input"]["request"]["task"]["objective"] = "changed".into();
    assert!(matches!(
        ReplayRecord::from_json(&serde_json::to_vec(&value).unwrap()),
        Err(EvalError::Integrity)
    ));
    assert!(matches!(
        replay_deterministic(
            &record,
            "baseline",
            SnapshotValidation {
                now_unix_seconds: 161,
                max_age_seconds: 60
            }
        ),
        Err(EvalError::Snapshot(_))
    ));
}

#[test]
fn unknown_prices_and_models_do_not_become_zero_cost() {
    let mut unknown = input();
    unknown.pricing.models.remove(&model("fixture-best"));
    assert!(matches!(
        replay_deterministic(
            &ReplayRecord::seal(unknown).unwrap(),
            "baseline",
            validation()
        ),
        Err(EvalError::UnknownPricing)
    ));
    let mut unknown = input();
    unknown.request.candidates[0].model = model("unknown-model");
    assert!(matches!(
        replay_deterministic(
            &ReplayRecord::seal(unknown).unwrap(),
            "baseline",
            validation()
        ),
        Err(EvalError::UnknownModel)
    ));
    let mut missing = input();
    missing
        .observations
        .get_mut("baseline")
        .unwrap()
        .usage
        .clear();
    assert!(matches!(
        replay_deterministic(
            &ReplayRecord::seal(missing).unwrap(),
            "baseline",
            validation()
        ),
        Err(EvalError::Invalid("selected model usage missing"))
    ));
}

#[test]
fn cached_pricing_rounds_up_and_checks_overflow_and_unknown_usage() {
    let input = input();
    let catalog = Catalog::from_json(&serde_json::to_vec(&input.catalog).unwrap()).unwrap();
    let usage = TokenUsage {
        model: model("fixture-best"),
        input_tokens: 3,
        cached_input_tokens: 2,
        output_tokens: 1,
    };
    assert_eq!(price_usage(&input.pricing, &[usage], &catalog).unwrap(), 8);
    let invalid = TokenUsage {
        model: model("fixture-best"),
        input_tokens: 1,
        cached_input_tokens: 2,
        output_tokens: 0,
    };
    assert!(price_usage(&input.pricing, &[invalid], &catalog).is_err());
    let mut pricing = input.pricing.clone();
    pricing
        .models
        .get_mut(&model("fixture-best"))
        .unwrap()
        .input_microusd_per_million = u64::MAX;
    let huge = TokenUsage {
        model: model("fixture-best"),
        input_tokens: u64::MAX,
        cached_input_tokens: 0,
        output_tokens: 0,
    };
    assert!(matches!(
        price_usage(&pricing, &[huge], &catalog),
        Err(EvalError::CostOverflow)
    ));
    pricing
        .models
        .get_mut(&model("fixture-best"))
        .unwrap()
        .input_microusd_per_million = 1;
    let one = TokenUsage {
        model: model("fixture-best"),
        input_tokens: 1,
        cached_input_tokens: 0,
        output_tokens: 0,
    };
    assert_eq!(price_usage(&pricing, &[one], &catalog).unwrap(), 1);
}

#[test]
fn transport_validation_and_functional_success_remain_separate() {
    let mut input = input();
    input.observations.get_mut("baseline").unwrap().outcomes = VerificationOutcomes {
        transport: ObservedOutcome::Passed,
        command_validation: ObservedOutcome::Passed,
        functional: ObservedOutcome::Failed,
    };
    let pairs = [pair(input)];
    let report = compare_shadow(&pairs, None).unwrap();
    assert_eq!(report.baseline.transport.passed, 1);
    assert_eq!(report.baseline.command_validation.passed, 1);
    assert_eq!(report.baseline.functional.failed, 1);
    assert!(!report.semantic_enabled);
}

#[test]
fn no_labels_or_preregistered_metrics_means_semantic_stays_disabled() {
    let record = ReplayRecord::seal(input()).unwrap();
    let pairs = [PairedTrace {
        baseline: replay_deterministic(&record, "baseline", validation()).unwrap(),
        semantic: shadow(&record),
    }];
    let report = compare_shadow(&pairs, None).unwrap();
    assert!(!report.semantic_enabled);
    assert!(
        report
            .promotion_blockers
            .contains(&"promotion.criteria_required".into())
    );
    assert!(
        report
            .promotion_blockers
            .contains(&"promotion.independent_human_labels_required".into())
    );
    let report = compare_shadow(&pairs, Some(&criteria(&pairs))).unwrap();
    assert!(!report.semantic_enabled);
}

#[test]
fn synthetic_independent_labels_and_cost_gain_exercise_positive_gate() {
    let pairs = [pair(input())];
    let report = compare_shadow(&pairs, Some(&criteria(&pairs))).unwrap();
    assert!(report.semantic_enabled, "{:?}", report.promotion_blockers);
    assert_eq!(report.baseline.total_cost_microusd, 200);
    assert_eq!(report.semantic.total_cost_microusd, 100);
}

#[test]
fn gate_rejects_training_leakage_author_labels_and_late_thresholds() {
    let pairs = [pair(input())];
    let original = criteria(&pairs);
    let mut c = original.clone();
    c.training_families.insert("family-1".into());
    assert!(
        compare_shadow(&pairs, Some(&c))
            .unwrap()
            .promotion_blockers
            .contains(&"promotion.family_leakage".into())
    );
    let mut c = original.clone();
    c.policy_authors.insert("synthetic-reviewer".into());
    assert!(
        compare_shadow(&pairs, Some(&c))
            .unwrap()
            .promotion_blockers
            .contains(&"promotion.independent_human_labels_required".into())
    );
    let mut c = original.clone();
    c.registered_at_unix_seconds = 110;
    assert!(
        compare_shadow(&pairs, Some(&c))
            .unwrap()
            .promotion_blockers
            .contains(&"promotion.criteria_not_preregistered".into())
    );
    let mut c = original;
    c.dataset_hash = "f".repeat(64);
    assert!(
        compare_shadow(&pairs, Some(&c))
            .unwrap()
            .promotion_blockers
            .contains(&"promotion.dataset_mismatch".into())
    );
}

#[test]
fn hard_constraint_violation_is_recorded_and_blocks_promotion() {
    use sha2::{Digest, Sha256};
    let mut input = input();
    input.request.candidates[1]
        .required_capabilities
        .insert(Capability::Network);
    input.label = Some(CaseLabel {
        human_validated: true,
        independent: true,
        reviewer_id: Some("synthetic-reviewer".into()),
        evidence_sha256: Some("b".repeat(64)),
        expected_candidate_ids: BTreeSet::from(["primary".into(), "secondary".into()]),
        expect_abstention: false,
    });
    let record = ReplayRecord::seal(input).unwrap();
    let semantic = run_replay(&record, "semantic", validation(), |context| {
        let router = PhaseRouter::new(context.policy.clone()).unwrap();
        let mut receipt = router.route(context.phase_context).unwrap();
        let mut selected = receipt.selected.take().unwrap();
        selected.candidate = context.request.candidates[1].clone();
        receipt.selected = Some(selected);
        receipt.alternatives.clear();
        receipt.receipt_id.clear();
        let mut hash = Sha256::new();
        hash.update(b"phase-receipt-v2\0");
        hash.update(serde_json::to_vec(&receipt).unwrap());
        receipt.receipt_id = hex::encode(hash.finalize());
        Ok(receipt)
    })
    .unwrap();
    assert!(!semantic.violations().is_empty());
    let pairs = [PairedTrace {
        baseline: replay_deterministic(&record, "baseline", validation()).unwrap(),
        semantic,
    }];
    let report = compare_shadow(&pairs, Some(&criteria(&pairs))).unwrap();
    assert!(
        report
            .promotion_blockers
            .contains(&"promotion.hard_constraint_violation".into())
    );
    assert!(!report.semantic_enabled);
}

#[test]
fn corpus_has_one_hundred_unreviewed_cases_and_keeps_families_in_one_split() {
    let bytes = include_bytes!("../../../tests/fixtures/evaluation/candidate-corpus-v1.json");
    let corpus = CandidateCorpus::from_json(bytes).unwrap();
    assert_eq!(corpus.cases.len(), 100);
    assert!(corpus.cases.iter().all(|case| !case.human_validated));
    assert!(corpus.cases.iter().any(|case| case.out_of_domain));
    assert_eq!(
        corpus
            .cases
            .iter()
            .map(|case| &case.family_id)
            .collect::<BTreeSet<_>>()
            .len(),
        20
    );
    let mut value = serde_json::to_value(corpus).unwrap();
    value["cases"][0]["human_validated"] = true.into();
    assert!(CandidateCorpus::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn no_gain_and_unknown_selected_metrics_keep_semantics_disabled() {
    let mut equal_cost = input();
    equal_cost.observations.get_mut("semantic").unwrap().usage[0].input_tokens = 200;
    let pairs = [pair(equal_cost)];
    let report = compare_shadow(&pairs, Some(&criteria(&pairs))).unwrap();
    assert!(!report.semantic_enabled);
    assert!(
        report
            .promotion_blockers
            .contains(&"promotion.no_demonstrated_gain".into())
    );

    let pairs = [pair(input())];
    let mut c = criteria(&pairs);
    c.rules.push(MetricRule {
        metric: PromotionMetric::FunctionalSuccess,
        minimum_improvement_micros: 0,
        maximum_regression_micros: 0,
    });
    let report = compare_shadow(&pairs, Some(&c)).unwrap();
    assert!(!report.semantic_enabled);
    assert!(
        report
            .promotion_blockers
            .contains(&"promotion.metric_unknown.FunctionalSuccess".into())
    );

    let mut missing_latency = input();
    missing_latency
        .observations
        .get_mut("semantic")
        .unwrap()
        .elapsed_ms = None;
    let pairs = [pair(missing_latency)];
    let mut c = criteria(&pairs);
    c.rules.push(MetricRule {
        metric: PromotionMetric::Latency,
        minimum_improvement_micros: 0,
        maximum_regression_micros: 0,
    });
    let report = compare_shadow(&pairs, Some(&c)).unwrap();
    assert_eq!(report.semantic.mean_elapsed_ms, None);
    assert_eq!(report.semantic.p95_elapsed_ms, None);
    assert!(!report.semantic_enabled);
}

#[test]
fn lower_cost_cannot_compensate_for_route_accuracy_regression() {
    let mut input = input();
    input.label = Some(CaseLabel {
        human_validated: true,
        independent: true,
        reviewer_id: Some("synthetic-reviewer".into()),
        evidence_sha256: Some("b".repeat(64)),
        expected_candidate_ids: BTreeSet::from(["primary".into()]),
        expect_abstention: false,
    });
    let pairs = [pair(input)];
    let report = compare_shadow(&pairs, Some(&criteria(&pairs))).unwrap();
    assert_eq!(report.baseline.route_accuracy_micros, Some(1_000_000));
    assert_eq!(report.semantic.route_accuracy_micros, Some(0));
    assert!(
        report
            .promotion_blockers
            .contains(&"promotion.metric_regression.RouteAccuracy".into())
    );
    assert!(!report.semantic_enabled);
}

#[test]
fn training_examples_duplicates_and_changed_contexts_are_not_heldout_evidence() {
    let mut training = input();
    training.split = DatasetSplit::Training;
    let pairs = [pair(training)];
    assert!(
        compare_shadow(&pairs, Some(&criteria(&pairs)))
            .unwrap()
            .promotion_blockers
            .contains(&"promotion.heldout_required".into())
    );
    let first = pair(input());
    assert!(dataset_hash(&[first.clone(), first.clone()]).is_err());
    let mut other = input();
    other.case_id = "different-context".into();
    let other = pair(other);
    assert!(
        dataset_hash(&[PairedTrace {
            baseline: first.baseline,
            semantic: other.semantic
        }])
        .is_err()
    );
}

#[test]
fn latency_gate_uses_exact_total_not_truncated_average() {
    let mut one = input();
    one.observations.get_mut("baseline").unwrap().elapsed_ms = Some(1);
    one.observations.get_mut("semantic").unwrap().elapsed_ms = Some(0);
    let mut two = input();
    two.case_id = "case-2".into();
    two.family_id = "family-2".into();
    two.observations.get_mut("baseline").unwrap().elapsed_ms = Some(2);
    two.observations.get_mut("semantic").unwrap().elapsed_ms = Some(1);
    let pairs = [pair(one), pair(two)];
    let mut c = criteria(&pairs);
    c.rules.push(MetricRule {
        metric: PromotionMetric::Latency,
        minimum_improvement_micros: 900_000,
        maximum_regression_micros: 0,
    });
    let report = compare_shadow(&pairs, Some(&c)).unwrap();
    assert_eq!(report.baseline.total_elapsed_ms, Some(3));
    assert_eq!(report.semantic.total_elapsed_ms, Some(1));
    assert_eq!(report.baseline.p95_elapsed_ms, Some(2));
    assert!(
        report
            .promotion_blockers
            .contains(&"promotion.insufficient_gain.Latency".into())
    );
    assert!(!report.semantic_enabled);
}

#[test]
fn replay_rejects_modified_receipts_before_using_their_cost_or_outcomes() {
    let record = ReplayRecord::seal(input()).unwrap();
    let result = run_replay(&record, "baseline", validation(), |context| {
        let mut receipt = PhaseRouter::new(context.policy.clone())
            .unwrap()
            .route(context.phase_context)
            .unwrap();
        receipt.context_hash = "f".repeat(64);
        Ok(receipt)
    });
    assert!(matches!(result, Err(EvalError::Integrity)));
    assert!(matches!(
        replay_deterministic(&record, "unknown", validation()),
        Err(EvalError::UnknownPolicy)
    ));
}

#[test]
fn unlisted_metrics_still_block_regressions_and_only_a_recorded_allowance_waives_one() {
    // Criteria list only RouteAccuracy (no regression) and Cost (gain).
    let mut slower = input();
    slower.observations.get_mut("semantic").unwrap().elapsed_ms = Some(20);
    let pairs = [pair(slower.clone())];
    let report = compare_shadow(&pairs, Some(&criteria(&pairs))).unwrap();
    assert!(!report.semantic_enabled);
    assert_eq!(
        report.promotion_blockers,
        ["promotion.metric_regression.Latency"]
    );

    let mut failing = input();
    failing
        .observations
        .get_mut("baseline")
        .unwrap()
        .outcomes
        .functional = ObservedOutcome::Passed;
    failing
        .observations
        .get_mut("semantic")
        .unwrap()
        .outcomes
        .functional = ObservedOutcome::Failed;
    let pairs = [pair(failing)];
    let report = compare_shadow(&pairs, Some(&criteria(&pairs))).unwrap();
    assert!(!report.semantic_enabled);
    assert_eq!(
        report.promotion_blockers,
        ["promotion.metric_regression.FunctionalSuccess"]
    );

    // The explicit rule is the recorded allowance: it lives in the criteria hash.
    let pairs = [pair(slower)];
    let mut allowed = criteria(&pairs);
    allowed.rules.push(MetricRule {
        metric: PromotionMetric::Latency,
        minimum_improvement_micros: 0,
        maximum_regression_micros: 1_000_000,
    });
    let report = compare_shadow(&pairs, Some(&allowed)).unwrap();
    assert!(report.semantic_enabled, "{:?}", report.promotion_blockers);
}

#[test]
fn an_unlisted_cost_regression_blocks_even_with_a_latency_gain() {
    let mut input = input();
    // Criteria: RouteAccuracy (no regression) and Latency (gain). Cost is unlisted.
    input.observations.get_mut("semantic").unwrap().elapsed_ms = Some(5);
    input.observations.get_mut("semantic").unwrap().usage[0].input_tokens = 1_000;
    let pairs = [pair(input)];
    let mut c = criteria(&pairs);
    c.rules[1] = MetricRule {
        metric: PromotionMetric::Latency,
        minimum_improvement_micros: 100_000,
        maximum_regression_micros: 0,
    };
    let report = compare_shadow(&pairs, Some(&c)).unwrap();
    assert!(!report.semantic_enabled);
    assert_eq!(
        report.promotion_blockers,
        ["promotion.metric_regression.Cost"]
    );
}

// Explicit authentication for this synthetic replay corpus only.
fn replay_deterministic(
    record: &ReplayRecord,
    policy: &str,
    validation: SnapshotValidation,
) -> router_eval::Result<ReplayTrace> {
    router_eval::replay_deterministic_with_verifier(
        record,
        policy,
        validation,
        Some(&fixture_proofs::FixtureVerifier),
    )
}
fn run_replay<P>(
    record: &ReplayRecord,
    policy: &str,
    validation: SnapshotValidation,
    route: P,
) -> router_eval::Result<ReplayTrace>
where
    P: FnOnce(&ReplayContext<'_>) -> router_eval::Result<PhaseReceipt>,
{
    router_eval::run_replay_with_verifier(
        record,
        policy,
        validation,
        Some(&fixture_proofs::FixtureVerifier),
        route,
    )
}

#[test]
fn offline_replay_without_store_never_promotes_handwritten_capabilities() {
    let mut input = input();
    input.snapshot.evidence[0].kind = EvidenceKind::HostRuntime;
    let source_id = input.snapshot.evidence[0].id.clone();
    input
        .snapshot
        .host
        .capabilities
        .insert(Capability::WorkspaceWrite);
    input.snapshot.capabilities.insert(
        Capability::WorkspaceWrite,
        router_adapter_api::CapabilityEvidence {
            support: CapabilitySupport::Supported,
            source_ids: BTreeSet::from([source_id]),
        },
    );
    input.snapshot = input.snapshot.seal().unwrap();
    let record = ReplayRecord::seal(input).unwrap();
    let trace = router_eval::replay_deterministic(&record, "baseline", validation()).unwrap();
    assert_eq!(
        trace.capability_evidence(),
        CapabilityEvidenceVerification::Unverified
    );
    assert!(
        trace
            .violations()
            .iter()
            .any(|v| v.code == "capability.evidence.unverified")
    );
    assert!(trace.receipt().capability_evidence.is_empty());
}
