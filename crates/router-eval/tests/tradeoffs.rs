use std::collections::BTreeMap;

use router_adapter_api::content_digest;
use router_eval::*;
use router_types::{ModelId, PhasePolicy};

fn model() -> ModelId {
    ModelId::parse("fixture-best").unwrap()
}
fn record(id: &str, outcomes: [ObservedOutcome; 2]) -> ReplayRecord {
    record_costs(id, outcomes, [10, 10])
}
fn record_costs(id: &str, outcomes: [ObservedOutcome; 2], tokens: [u64; 2]) -> ReplayRecord {
    let policy = PhasePolicy::default();
    let observation = |outcome, token_count| RecordedPhase {
        usage: vec![TokenUsage {
            model: model(),
            input_tokens: token_count,
            cached_input_tokens: 0,
            output_tokens: 0,
        }],
        elapsed_ms: Some(10),
        fallback_reasons: vec![],
        outcomes: VerificationOutcomes {
            functional: outcome,
            ..Default::default()
        },
    };
    ReplayRecord::seal(ReplayInput {
        schema_version: 1,
        case_id: id.into(),
        family_id: "tradeoff-fixture".into(),
        split: DatasetSplit::HeldOut,
        out_of_domain: false,
        request: serde_json::from_str(include_str!(
            "../../../fixtures/examples/phase-request.json"
        ))
        .unwrap(),
        snapshot: serde_json::from_str(include_str!(
            "../../../fixtures/examples/phase-snapshot.json"
        ))
        .unwrap(),
        catalog: serde_json::from_str(include_str!(
            "../../../fixtures/examples/phase-catalog.json"
        ))
        .unwrap(),
        policies: BTreeMap::from([("a".into(), policy.clone()), ("b".into(), policy)]),
        pricing: PricingTable {
            schema_version: 1,
            version: "fixture".into(),
            source: "fixture".into(),
            observed_at_unix_seconds: 100,
            models: BTreeMap::from([(
                model(),
                TokenPrice {
                    input_microusd_per_million: 1_000_000,
                    cached_input_microusd_per_million: 1_000_000,
                    output_microusd_per_million: 1_000_000,
                },
            )]),
        },
        observations: BTreeMap::from([
            ("a".into(), observation(outcomes[0], tokens[0])),
            ("b".into(), observation(outcomes[1], tokens[1])),
        ]),
        label: None,
    })
    .unwrap()
}
fn cohort(records: &[ReplayRecord], cells: &[bool], selected: &str) -> TradeoffCohort {
    let policy = PhasePolicy::default();
    let sha = content_digest(&serde_json::to_vec(&policy).unwrap());
    TradeoffCohort {
        schema_version: 1,
        analysis_authorized: true,
        provenance: MetricsProvenance::Synthetic,
        policies: vec![
            TradeoffPolicy {
                policy_id: "a".into(),
                policy_sha256: sha.clone(),
            },
            TradeoffPolicy {
                policy_id: "b".into(),
                policy_sha256: sha,
            },
        ],
        cases: records
            .iter()
            .zip(cells.chunks_exact(2))
            .map(|(r, complete)| TradeoffCase {
                case_id: r.input().case_id.clone(),
                input_hash: r.input_hash().into(),
                budget: MetricsBudget {
                    max_cost_microusd: u64::MAX,
                    max_tokens: u64::MAX,
                    max_elapsed_ms: u64::MAX,
                },
                selected_policy_id: selected.into(),
                cells: vec!["a", "b"]
                    .into_iter()
                    .zip(complete)
                    .map(|(id, complete)| TradeoffCell {
                        policy_id: id.into(),
                        usage_complete: *complete,
                        usage_evidence_sha256: complete.then(|| "a".repeat(64)),
                    })
                    .collect(),
            })
            .collect(),
    }
}
#[test]
fn exact_policy_metrics_and_tied_complete_frontier_are_preserved() {
    let records = vec![record(
        "case",
        [ObservedOutcome::Passed, ObservedOutcome::Passed],
    )];
    let c = cohort(&records, &[true, true], "a");
    let report = evaluate_tradeoffs(&c, &records).unwrap();
    let metric_cohort = MetricsCohort {
        schema_version: 1,
        analysis_authorized: true,
        provenance: MetricsProvenance::Synthetic,
        cases: vec![MetricsCase {
            case_id: "case".into(),
            input_hash: records[0].input_hash().into(),
            policy_id: "a".into(),
            policy_sha256: c.policies[0].policy_sha256.clone(),
            budget: c.cases[0].budget.clone(),
            predicted_success_micros: None,
            usage_complete: true,
            usage_evidence_sha256: Some("a".repeat(64)),
        }],
    };
    assert_eq!(
        report.policies[0].metrics,
        evaluate_metrics(&metric_cohort, &records).unwrap()
    );
    assert_eq!(report.frontier, vec!["a", "b"]);
    assert!(!report.partial_frontier);
}
#[test]
fn failed_choice_has_functional_regret_and_cost_not_applicable() {
    let records = vec![record(
        "case",
        [ObservedOutcome::Failed, ObservedOutcome::Passed],
    )];
    let report = evaluate_tradeoffs(&cohort(&records, &[true, true], "a"), &records).unwrap();
    let a = &report.policies[0];
    assert_eq!(a.functional_regret_sum_micros, 1_000_000);
    assert_eq!(a.cost_regret_not_applicable_cases, 1);
}
#[test]
fn dominance_requires_both_axes_and_keeps_quality_cost_compromise() {
    let better = vec![record_costs(
        "dominated",
        [ObservedOutcome::Passed, ObservedOutcome::Passed],
        [10, 20],
    )];
    let report = evaluate_tradeoffs(&cohort(&better, &[true, true], "a"), &better).unwrap();
    assert_eq!(report.policies[1].dominated_by, vec!["a"]);

    let compromise = vec![record_costs(
        "compromise",
        [ObservedOutcome::Passed, ObservedOutcome::Failed],
        [20, 10],
    )];
    let report = evaluate_tradeoffs(&cohort(&compromise, &[true, true], "a"), &compromise).unwrap();
    assert_eq!(report.frontier, vec!["a", "b"]);
}
#[test]
fn unknown_competitor_keeps_cost_regret_unknown_and_frontier_partial() {
    let records = vec![record(
        "unknown",
        [ObservedOutcome::Passed, ObservedOutcome::Unknown],
    )];
    let report = evaluate_tradeoffs(&cohort(&records, &[true, false], "a"), &records).unwrap();
    assert!(report.partial_frontier);
    assert_eq!(report.policies[0].cost_regret_unknown_cases, 1);
}
#[test]
fn policy_pins_matrix_and_record_substitution_are_enforced_across_cases() {
    let first = record("first", [ObservedOutcome::Passed, ObservedOutcome::Passed]);
    let mut changed_input = record("second", [ObservedOutcome::Passed, ObservedOutcome::Passed])
        .input()
        .clone();
    changed_input.policies.get_mut("b").unwrap().quality_weight += 1;
    let second = ReplayRecord::seal(changed_input).unwrap();
    let records = vec![first, second];
    let c = cohort(&records, &[true, true, true, true], "a");
    assert!(matches!(
        evaluate_tradeoffs(&c, &records),
        Err(EvalError::Integrity)
    ));

    let clean = vec![record(
        "clean",
        [ObservedOutcome::Passed, ObservedOutcome::Passed],
    )];
    let mut substituted = cohort(&clean, &[true, true], "a");
    substituted.cases[0].input_hash = "b".repeat(64);
    assert!(matches!(
        evaluate_tradeoffs(&substituted, &clean),
        Err(EvalError::Integrity)
    ));
    let mut malformed = cohort(&clean, &[true, true], "a");
    malformed.cases[0].cells[1].policy_id = "a".into();
    assert!(evaluate_tradeoffs(&malformed, &clean).is_err());
}
#[test]
fn functional_unknown_and_cost_not_applicable_keep_separate_denominators() {
    let records = vec![record(
        "unknown-choice",
        [ObservedOutcome::Unknown, ObservedOutcome::Passed],
    )];
    let report = evaluate_tradeoffs(&cohort(&records, &[true, true], "a"), &records).unwrap();
    let a = &report.policies[0];
    assert_eq!(a.selected_cases, 1);
    assert_eq!(a.functional_regret_unknown_cases, 1);
    assert_eq!(a.cost_regret_unknown_cases, 1);
    assert_eq!(a.cost_regret_not_applicable_cases, 0);

    let records = vec![record(
        "failed-choice",
        [ObservedOutcome::Failed, ObservedOutcome::Passed],
    )];
    let report = evaluate_tradeoffs(&cohort(&records, &[true, false], "a"), &records).unwrap();
    let a = &report.policies[0];
    assert_eq!(a.functional_regret_sum_micros, 1_000_000);
    assert_eq!(a.cost_regret_not_applicable_cases, 1);
    assert_eq!(a.cost_regret_unknown_cases, 0);

    let records = vec![record(
        "unknown-cost-of-failure",
        [ObservedOutcome::Passed, ObservedOutcome::Failed],
    )];
    let report = evaluate_tradeoffs(&cohort(&records, &[true, false], "a"), &records).unwrap();
    assert_eq!(report.policies[0].cost_regret_known_cases, 1);
    assert_eq!(report.policies[0].cost_regret_sum_microusd, 0);
}
#[test]
fn input_order_is_stable_and_case_token_overflow_refuses_the_cohort() {
    let records = vec![
        record("a", [ObservedOutcome::Passed, ObservedOutcome::Failed]),
        record_costs(
            "b",
            [ObservedOutcome::Failed, ObservedOutcome::Passed],
            [20, 10],
        ),
    ];
    let c = cohort(&records, &[true, true, true, true], "a");
    let forward = serde_json::to_vec(&evaluate_tradeoffs(&c, &records).unwrap()).unwrap();
    let mut reversed_cohort = c.clone();
    reversed_cohort.cases.reverse();
    let reverse = serde_json::to_vec(
        &evaluate_tradeoffs(
            &reversed_cohort,
            &records.iter().rev().cloned().collect::<Vec<_>>(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(forward, reverse);

    let mut input = record(
        "overflow",
        [ObservedOutcome::Passed, ObservedOutcome::Passed],
    )
    .input()
    .clone();
    input.observations.get_mut("a").unwrap().usage[0].input_tokens = u64::MAX;
    input.observations.get_mut("a").unwrap().usage[0].output_tokens = 1;
    let overflow = vec![ReplayRecord::seal(input).unwrap()];
    assert!(matches!(
        evaluate_tradeoffs(&cohort(&overflow, &[true, true], "a"), &overflow),
        Err(EvalError::Limit("metrics arithmetic"))
    ));

    let mut too_many = cohort(&records[..1], &[true, true], "a");
    let template = too_many.cases[0].clone();
    too_many.cases = (0..=MAX_EVALUATION_CASES)
        .map(|n| {
            let mut case = template.clone();
            case.case_id = format!("case-{n:04}");
            case
        })
        .collect();
    assert!(matches!(
        evaluate_tradeoffs(&too_many, &[]),
        Err(EvalError::Limit("tradeoffs dimensions"))
    ));
}
#[test]
fn missing_cell_and_missing_record_are_refused() {
    let records = vec![record(
        "case",
        [ObservedOutcome::Passed, ObservedOutcome::Unknown],
    )];
    let mut c = cohort(&records, &[true, false], "a");
    c.cases[0].cells.pop();
    assert!(evaluate_tradeoffs(&c, &records).is_err());
    assert!(evaluate_tradeoffs(&cohort(&records, &[true, false], "a"), &[]).is_err());
}
