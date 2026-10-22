//! Synthetic observations only. These tests do not establish measured vendor
//! usage, independent human labels, or authorization to promote a policy.
use std::collections::BTreeMap;

use router_adapter_api::content_digest;
use router_eval::*;
use router_types::{ModelId, PhasePolicy};
use serde_json::{Value, json};

fn model() -> ModelId {
    ModelId::parse("fixture-best").unwrap()
}
fn input(id: &str, tokens: u64, elapsed: Option<u64>, outcome: ObservedOutcome) -> ReplayInput {
    ReplayInput {
        schema_version: 1,
        case_id: id.into(),
        family_id: "synthetic-metrics-family".into(),
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
        policies: BTreeMap::from([("baseline".into(), PhasePolicy::default())]),
        pricing: PricingTable {
            schema_version: 1,
            version: "synthetic-price-v1".into(),
            source: "fixture-only-not-provider-measurements".into(),
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
        observations: BTreeMap::from([(
            "baseline".into(),
            RecordedPhase {
                usage: vec![TokenUsage {
                    model: model(),
                    input_tokens: tokens,
                    cached_input_tokens: 0,
                    output_tokens: 0,
                }],
                elapsed_ms: elapsed,
                fallback_reasons: vec![],
                outcomes: VerificationOutcomes {
                    functional: outcome,
                    ..VerificationOutcomes::default()
                },
            },
        )]),
        label: None,
    }
}
fn seal(input: ReplayInput) -> ReplayRecord {
    ReplayRecord::seal(input).unwrap()
}
fn cohort(records: &[ReplayRecord], predictions: &[Option<u32>]) -> MetricsCohort {
    assert_eq!(records.len(), predictions.len());
    MetricsCohort {
        schema_version: 1,
        analysis_authorized: true,
        provenance: MetricsProvenance::Synthetic,
        cases: records
            .iter()
            .zip(predictions)
            .map(|(record, prediction)| MetricsCase {
                case_id: record.input().case_id.clone(),
                input_hash: record.input_hash().into(),
                policy_id: "baseline".into(),
                policy_sha256: content_digest(
                    &serde_json::to_vec(&record.input().policies["baseline"]).unwrap(),
                ),
                budget: MetricsBudget {
                    max_cost_microusd: u64::MAX,
                    max_tokens: u64::MAX,
                    max_elapsed_ms: u64::MAX,
                },
                predicted_success_micros: *prediction,
                usage_complete: true,
                usage_evidence_sha256: Some("a".repeat(64)),
            })
            .collect(),
    }
}
fn ratio(numerator: u64, denominator: u64) -> ExactRatio {
    ExactRatio {
        numerator,
        denominator,
    }
}
fn counts(value: &OutcomeCounts, passed: usize, failed: usize, unknown: usize) {
    assert_eq!(
        (value.passed, value.failed, value.unknown),
        (passed, failed, unknown)
    );
}
fn only_record() -> Vec<ReplayRecord> {
    vec![seal(input("one", 10, Some(20), ObservedOutcome::Passed))]
}

#[test]
fn golden_costs_include_failures_and_calibration_uses_functional_outcomes() {
    let records = vec![
        seal(input("a", 10, Some(20), ObservedOutcome::Passed)),
        seal(input("b", 30, Some(30), ObservedOutcome::Failed)),
        seal(input("c", 20, Some(40), ObservedOutcome::Passed)),
    ];
    let mut c = cohort(&records, &[Some(800_000), Some(200_000), Some(600_000)]);
    c.cases[0].budget = MetricsBudget {
        max_cost_microusd: 10,
        max_tokens: 10,
        max_elapsed_ms: 20,
    };
    let report = evaluate_metrics(&c, &records).unwrap();
    counts(&report.functional, 2, 1, 0);
    counts(&report.success_at_budget, 2, 1, 0);
    assert_eq!(report.known_cost_microusd, 60);
    assert_eq!(
        report.cost_microusd_per_functional_success,
        Some(ratio(60, 2))
    );
    assert_eq!(
        report.total_execution_ms_per_functional_success,
        Some(ratio(90, 2))
    );
    assert_eq!(report.success_at_budget_rate, Some(ratio(2, 3)));
    assert_eq!(
        report.calibration.brier,
        Some(ratio(240_000_000_000, 3_000_000_000_000))
    );
    assert_eq!(report.calibration.ece, Some(ratio(800_000, 3_000_000)));
}

#[test]
fn unknown_outcomes_and_predictions_preserve_the_full_denominator() {
    let records = vec![
        seal(input("pass", 1, Some(1), ObservedOutcome::Passed)),
        seal(input("unknown", 2, None, ObservedOutcome::Unknown)),
        seal(input("failed", 3, Some(3), ObservedOutcome::Failed)),
    ];
    let c = cohort(&records, &[Some(1_000_000), None, None]);
    let report = evaluate_metrics(&c, &records).unwrap();
    counts(&report.functional, 1, 1, 1);
    counts(&report.success_at_budget, 1, 1, 1);
    assert_eq!(report.success_at_budget_rate, None);
    assert_eq!(report.success_at_budget_lower, ratio(1, 3));
    assert_eq!(report.success_at_budget_upper, ratio(2, 3));
    assert_eq!(report.calibration.known_pairs, 1);
    assert_eq!(report.calibration.missing_predictions, 2);
    assert_eq!(report.calibration.missing_outcomes, 1);
    assert_eq!(report.calibration.brier, None);
    assert_eq!(report.calibration.ece, None);
    assert_eq!(report.cost_microusd_per_functional_success, None);
    assert_eq!(report.total_execution_ms_per_functional_success, None);
    assert_eq!(report.known_cost_cases, 3);
    assert_eq!(report.known_latency_cases, 2);
}

#[test]
fn transport_success_never_fills_an_unknown_functional_label() {
    let mut i = input("unknown", 0, Some(0), ObservedOutcome::Unknown);
    i.observations
        .get_mut("baseline")
        .unwrap()
        .outcomes
        .transport = ObservedOutcome::Passed;
    i.observations
        .get_mut("baseline")
        .unwrap()
        .outcomes
        .command_validation = ObservedOutcome::Passed;
    let records = vec![seal(i)];
    let report = evaluate_metrics(&cohort(&records, &[Some(1_000_000)]), &records).unwrap();
    counts(&report.functional, 0, 0, 1);
    counts(&report.success_at_budget, 0, 0, 1);
    assert_eq!(report.calibration.known_pairs, 0);
    assert_eq!(report.calibration.brier, None);
}

#[test]
fn a_missing_prediction_does_not_erase_other_valid_metrics() {
    let records = only_record();
    let report = evaluate_metrics(&cohort(&records, &[None]), &records).unwrap();
    assert_eq!(report.success_at_budget_rate, Some(ratio(1, 1)));
    assert_eq!(
        report.cost_microusd_per_functional_success,
        Some(ratio(10, 1))
    );
    assert_eq!(
        report.total_execution_ms_per_functional_success,
        Some(ratio(20, 1))
    );
    assert_eq!(report.calibration.brier, None);
}

#[test]
fn budget_equality_is_success_and_each_one_unit_excess_is_failure() {
    let records = only_record();
    let mut c = cohort(&records, &[Some(1_000_000)]);
    c.cases[0].budget = MetricsBudget {
        max_cost_microusd: 10,
        max_tokens: 10,
        max_elapsed_ms: 20,
    };
    counts(
        &evaluate_metrics(&c, &records).unwrap().success_at_budget,
        1,
        0,
        0,
    );
    for budget in [
        MetricsBudget {
            max_cost_microusd: 9,
            max_tokens: 10,
            max_elapsed_ms: 20,
        },
        MetricsBudget {
            max_cost_microusd: 10,
            max_tokens: 9,
            max_elapsed_ms: 20,
        },
        MetricsBudget {
            max_cost_microusd: 10,
            max_tokens: 10,
            max_elapsed_ms: 19,
        },
    ] {
        c.cases[0].budget = budget;
        let report = evaluate_metrics(&c, &records).unwrap();
        counts(&report.functional, 1, 0, 0);
        counts(&report.success_at_budget, 0, 1, 0);
        assert_eq!(report.calibration.brier, Some(ratio(0, 1_000_000_000_000)));
    }
}

#[test]
fn known_failure_or_partial_usage_excess_is_not_masked_by_unknown_data() {
    for (outcome, tokens, max_tokens) in [
        (ObservedOutcome::Failed, 0, 100),
        (ObservedOutcome::Unknown, 11, 10),
    ] {
        let records = vec![seal(input("one", tokens, None, outcome))];
        let mut c = cohort(&records, &[None]);
        c.cases[0].usage_complete = false;
        c.cases[0].usage_evidence_sha256 = None;
        c.cases[0].budget.max_tokens = max_tokens;
        let report = evaluate_metrics(&c, &records).unwrap();
        counts(&report.success_at_budget, 0, 1, 0);
        assert_eq!(report.success_at_budget_rate, Some(ratio(0, 1)));
        assert_eq!(report.known_cost_cases, 0);
    }
}

#[test]
fn zero_successes_produce_no_division_and_failed_costs_remain_visible() {
    let records = vec![seal(input("failed", 17, Some(99), ObservedOutcome::Failed))];
    let report = evaluate_metrics(&cohort(&records, &[Some(0)]), &records).unwrap();
    assert_eq!(report.known_cost_microusd, 17);
    assert_eq!(report.known_total_execution_ms, 99);
    assert_eq!(report.cost_microusd_per_functional_success, None);
    assert_eq!(report.total_execution_ms_per_functional_success, None);
    assert_eq!(report.calibration.brier, Some(ratio(0, 1_000_000_000_000)));
}

#[test]
fn explicitly_complete_zero_usage_is_distinct_from_absent_usage() {
    let mut i = input("one", 0, Some(0), ObservedOutcome::Passed);
    i.observations.get_mut("baseline").unwrap().usage.clear();
    let records = vec![seal(i)];
    let mut c = cohort(&records, &[Some(1_000_000)]);
    c.cases[0].budget = MetricsBudget {
        max_cost_microusd: 0,
        max_tokens: 0,
        max_elapsed_ms: 0,
    };
    let known = evaluate_metrics(&c, &records).unwrap();
    assert_eq!(known.known_cost_cases, 1);
    assert_eq!(
        known.cost_microusd_per_functional_success,
        Some(ratio(0, 1))
    );
    counts(&known.success_at_budget, 1, 0, 0);
    c.cases[0].usage_complete = false;
    c.cases[0].usage_evidence_sha256 = None;
    let unknown = evaluate_metrics(&c, &records).unwrap();
    assert_eq!(unknown.known_cost_cases, 0);
    assert_eq!(unknown.cost_unknown_reasons["usage_incomplete"], 1);
    assert_eq!(unknown.cost_microusd_per_functional_success, None);
    counts(&unknown.success_at_budget, 0, 0, 1);
}

#[test]
fn missing_price_is_unknown_but_explicit_zero_price_is_known() {
    let mut i = input("one", 100, Some(0), ObservedOutcome::Passed);
    i.pricing.models.clear();
    let records = vec![seal(i.clone())];
    let missing = evaluate_metrics(&cohort(&records, &[None]), &records).unwrap();
    assert_eq!(missing.known_cost_cases, 0);
    assert_eq!(missing.cost_unknown_reasons["pricing_missing"], 1);
    counts(&missing.success_at_budget, 0, 0, 1);
    i.pricing.models.insert(
        model(),
        TokenPrice {
            input_microusd_per_million: 0,
            cached_input_microusd_per_million: 0,
            output_microusd_per_million: 0,
        },
    );
    let records = vec![seal(i)];
    let zero = evaluate_metrics(&cohort(&records, &[None]), &records).unwrap();
    assert_eq!(zero.known_cost_cases, 1);
    assert_eq!(zero.cost_microusd_per_functional_success, Some(ratio(0, 1)));
}

#[test]
fn cached_tokens_are_discounted_in_cost_without_double_counting_budget_tokens() {
    let mut i = input("cached", 3, Some(1), ObservedOutcome::Passed);
    let usage = &mut i.observations.get_mut("baseline").unwrap().usage[0];
    usage.cached_input_tokens = 2;
    usage.output_tokens = 1;
    i.pricing.models.insert(
        model(),
        TokenPrice {
            input_microusd_per_million: 2_000_000,
            cached_input_microusd_per_million: 500_000,
            output_microusd_per_million: 4_000_000,
        },
    );
    let records = vec![seal(i)];
    let mut c = cohort(&records, &[None]);
    c.cases[0].budget.max_tokens = 4;
    c.cases[0].budget.max_cost_microusd = 7;
    let report = evaluate_metrics(&c, &records).unwrap();
    assert_eq!(report.known_cost_microusd, 7);
    counts(&report.success_at_budget, 1, 0, 0);
}

#[test]
fn sub_microusd_costs_follow_the_existing_ceiling_rule() {
    let mut i = input("rounding", 1, Some(1), ObservedOutcome::Passed);
    i.pricing
        .models
        .get_mut(&model())
        .unwrap()
        .input_microusd_per_million = 1;
    let records = vec![seal(i)];
    let mut c = cohort(&records, &[None]);
    c.cases[0].budget.max_cost_microusd = 0;
    let report = evaluate_metrics(&c, &records).unwrap();
    assert_eq!(report.known_cost_microusd, 1);
    counts(&report.success_at_budget, 0, 1, 0);
}

#[test]
fn ece_is_weighted_by_cases_and_prediction_endpoints_have_exact_bins() {
    let records = vec![
        seal(input("a", 0, Some(0), ObservedOutcome::Failed)),
        seal(input("b", 0, Some(0), ObservedOutcome::Passed)),
        seal(input("c", 0, Some(0), ObservedOutcome::Passed)),
        seal(input("d", 0, Some(0), ObservedOutcome::Passed)),
    ];
    let report = evaluate_metrics(
        &cohort(
            &records,
            &[Some(0), Some(99_999), Some(100_000), Some(1_000_000)],
        ),
        &records,
    )
    .unwrap();
    assert_eq!(report.calibration.bins[0].known_pairs, 2);
    assert_eq!(report.calibration.bins[0].predicted_sum_micros, 99_999);
    assert_eq!(report.calibration.bins[0].functional_successes, 1);
    assert_eq!(report.calibration.bins[1].known_pairs, 1);
    assert_eq!(report.calibration.bins[9].known_pairs, 1);
    assert_eq!(
        report.calibration.brier,
        Some(ratio(1_620_001_800_001, 4_000_000_000_000))
    );
    assert_eq!(report.calibration.ece, Some(ratio(1_800_001, 4_000_000)));
}

#[test]
fn within_bin_signed_errors_cancel_for_ece_but_not_brier() {
    let records = vec![
        seal(input("a", 0, Some(0), ObservedOutcome::Passed)),
        seal(input("b", 0, Some(0), ObservedOutcome::Failed)),
    ];
    let report =
        evaluate_metrics(&cohort(&records, &[Some(500_000), Some(500_000)]), &records).unwrap();
    assert_eq!(report.calibration.ece, Some(ratio(0, 2_000_000)));
    assert_eq!(
        report.calibration.brier,
        Some(ratio(500_000_000_000, 2_000_000_000_000))
    );
}

#[test]
fn every_ece_boundary_is_left_closed_and_one_is_in_the_last_bin() {
    let predictions: Vec<_> = (0..=10).map(|n| Some(n * 100_000)).collect();
    let records: Vec<_> = (0..=10)
        .map(|n| {
            seal(input(
                &format!("case-{n}"),
                0,
                Some(0),
                ObservedOutcome::Passed,
            ))
        })
        .collect();
    let report = evaluate_metrics(&cohort(&records, &predictions), &records).unwrap();
    for n in 0..10 {
        assert_eq!(
            report.calibration.bins[n].known_pairs,
            if n == 9 { 2 } else { 1 }
        );
    }
    assert_eq!(report.calibration.known_pairs, 11);
}

#[test]
fn case_and_record_order_do_not_change_report_bytes() {
    let mut records = vec![
        seal(input("z", 1, Some(2), ObservedOutcome::Passed)),
        seal(input("a", 3, Some(4), ObservedOutcome::Failed)),
    ];
    let mut c = cohort(&records, &[Some(700_000), Some(200_000)]);
    let first = serde_json::to_vec(&evaluate_metrics(&c, &records).unwrap()).unwrap();
    c.cases.reverse();
    records.reverse();
    assert_eq!(
        first,
        serde_json::to_vec(&evaluate_metrics(&c, &records).unwrap()).unwrap()
    );
}

#[test]
fn budget_prediction_completeness_evidence_and_provenance_are_hashed() {
    let records = only_record();
    let c = cohort(&records, &[Some(700_000)]);
    let base = evaluate_metrics(&c, &records).unwrap().cohort_hash;
    let mut variants = vec![];
    let mut v = c.clone();
    v.cases[0].budget.max_tokens -= 1;
    variants.push(v);
    let mut v = c.clone();
    v.cases[0].predicted_success_micros = Some(700_001);
    variants.push(v);
    let mut v = c.clone();
    v.cases[0].usage_complete = false;
    variants.push(v);
    let mut v = c.clone();
    v.cases[0].usage_evidence_sha256 = Some("b".repeat(64));
    variants.push(v);
    let mut v = c.clone();
    v.provenance = MetricsProvenance::Supplied;
    variants.push(v);
    for variant in variants {
        assert_ne!(
            base,
            evaluate_metrics(&variant, &records).unwrap().cohort_hash
        );
    }
}

#[test]
fn duplicate_missing_extra_or_swapped_case_records_are_rejected() {
    let a = seal(input("a", 1, Some(1), ObservedOutcome::Passed));
    let b = seal(input("b", 2, Some(2), ObservedOutcome::Failed));
    let records = vec![a.clone(), b.clone()];
    let c = cohort(&records, &[None, None]);
    assert!(evaluate_metrics(&c, &[a.clone()]).is_err());
    assert!(evaluate_metrics(&c, &[a.clone(), b.clone(), b]).is_err());
    assert!(evaluate_metrics(&c, &[a.clone(), a]).is_err());
    let mut duplicate = c.clone();
    duplicate.cases[1] = duplicate.cases[0].clone();
    assert!(evaluate_metrics(&duplicate, &records).is_err());
    let mut swapped = c.clone();
    swapped.cases[0].input_hash = c.cases[1].input_hash.clone();
    swapped.cases[1].input_hash = c.cases[0].input_hash.clone();
    assert!(matches!(
        evaluate_metrics(&swapped, &records),
        Err(EvalError::Integrity)
    ));
}

#[test]
fn source_policy_hash_and_unchecked_deserialization_cannot_bypass_integrity() {
    let records = only_record();
    let c = cohort(&records, &[None]);
    let mut wrong = c.clone();
    wrong.cases[0].policy_sha256 = "b".repeat(64);
    assert!(matches!(
        evaluate_metrics(&wrong, &records),
        Err(EvalError::Integrity)
    ));
    let mut wrong = c.clone();
    wrong.cases[0].policy_id = "unregistered".into();
    assert!(matches!(
        evaluate_metrics(&wrong, &records),
        Err(EvalError::UnknownPolicy)
    ));
    let mut changed = records[0].input().clone();
    changed.observations.get_mut("baseline").unwrap().elapsed_ms = Some(21);
    assert!(matches!(
        evaluate_metrics(&c, &[seal(changed)]),
        Err(EvalError::Integrity)
    ));
    let mut raw = serde_json::to_value(&records[0]).unwrap();
    raw["input"]["observations"]["baseline"]["outcomes"]["functional"] = json!("failed");
    let forged: ReplayRecord = serde_json::from_value(raw).unwrap();
    assert!(matches!(
        evaluate_metrics(&c, &[forged]),
        Err(EvalError::Integrity)
    ));
}

#[test]
fn unknown_models_and_impossible_cached_usage_are_errors_even_when_incomplete() {
    for invalid_model in [false, true] {
        let mut i = input("bad", 1, Some(1), ObservedOutcome::Passed);
        let usage = &mut i.observations.get_mut("baseline").unwrap().usage[0];
        if invalid_model {
            usage.model = ModelId::parse("unregistered").unwrap();
        } else {
            usage.cached_input_tokens = 2;
        }
        let records = vec![seal(i)];
        let mut c = cohort(&records, &[None]);
        c.cases[0].usage_complete = false;
        if invalid_model {
            assert!(matches!(
                evaluate_metrics(&c, &records),
                Err(EvalError::UnknownModel)
            ));
        } else {
            assert!(matches!(
                evaluate_metrics(&c, &records),
                Err(EvalError::Invalid(_))
            ));
        }
    }
}

#[test]
fn strict_json_rejects_unknown_duplicate_and_fractional_fields() {
    let records = only_record();
    let c = cohort(&records, &[Some(500_000)]);
    for path in [vec![], vec!["cases", "0"], vec!["cases", "0", "budget"]] {
        let mut v = serde_json::to_value(&c).unwrap();
        let mut node = &mut v;
        for key in path {
            node = if key == "0" {
                &mut node[0]
            } else {
                &mut node[key]
            };
        }
        node.as_object_mut()
            .unwrap()
            .insert("unexpected".into(), json!(true));
        assert!(MetricsCohort::from_json(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    let serialized = serde_json::to_string(&c).unwrap();
    for text in [
        serialized.replace(
            "\"analysis_authorized\":true",
            "\"analysis_authorized\":true,\"analysis_authorized\":true",
        ),
        serialized.replace(
            "\"predicted_success_micros\":500000",
            "\"predicted_success_micros\":1.5",
        ),
        serialized.replace(
            "\"max_tokens\":18446744073709551615",
            "\"max_tokens\":1,\"max_tokens\":1",
        ),
    ] {
        assert!(MetricsCohort::from_json(text.as_bytes()).is_err());
    }
    assert!(MetricsCohort::from_json(&serde_json::to_vec(&c).unwrap()).is_ok());
}

#[test]
fn invalid_authorization_schema_predictions_and_evidence_are_rejected() {
    let records = only_record();
    let c = cohort(&records, &[Some(0)]);
    let mut variants = vec![];
    let mut v = c.clone();
    v.analysis_authorized = false;
    variants.push(v);
    let mut v = c.clone();
    v.schema_version = 2;
    variants.push(v);
    let mut v = c.clone();
    v.cases[0].predicted_success_micros = Some(1_000_001);
    variants.push(v);
    let mut v = c.clone();
    v.cases[0].usage_evidence_sha256 = None;
    variants.push(v);
    let mut v = c.clone();
    v.cases[0].usage_evidence_sha256 = Some("not-a-hash".into());
    variants.push(v);
    let mut v = c.clone();
    v.cases[0].input_hash = "A".repeat(64);
    variants.push(v);
    let mut v = c.clone();
    v.cases[0].case_id = "bad\ncase".into();
    variants.push(v);
    for variant in variants {
        assert!(evaluate_metrics(&variant, &records).is_err());
        assert!(MetricsCohort::from_json(&serde_json::to_vec(&variant).unwrap()).is_err());
    }
}

#[test]
fn cost_token_and_elapsed_overflows_return_errors() {
    let mut token = input("overflow", u64::MAX, Some(0), ObservedOutcome::Passed);
    token.observations.get_mut("baseline").unwrap().usage[0].output_tokens = 1;
    let records = vec![seal(token)];
    assert!(matches!(
        evaluate_metrics(&cohort(&records, &[None]), &records),
        Err(EvalError::Limit(_))
    ));
    let mut expensive = input("overflow", u64::MAX, Some(0), ObservedOutcome::Passed);
    expensive
        .pricing
        .models
        .get_mut(&model())
        .unwrap()
        .input_microusd_per_million = u64::MAX;
    let records = vec![seal(expensive)];
    assert!(matches!(
        evaluate_metrics(&cohort(&records, &[None]), &records),
        Err(EvalError::CostOverflow)
    ));
    for records in [
        vec![
            seal(input("a", u64::MAX, Some(0), ObservedOutcome::Passed)),
            seal(input("b", 1, Some(0), ObservedOutcome::Failed)),
        ],
        vec![
            seal(input("a", 0, Some(u64::MAX), ObservedOutcome::Passed)),
            seal(input("b", 0, Some(1), ObservedOutcome::Failed)),
        ],
    ] {
        assert!(matches!(
            evaluate_metrics(&cohort(&records, &[None, None]), &records),
            Err(EvalError::Limit(_))
        ));
    }
}

#[test]
fn empty_oversized_case_sets_and_cohort_bytes_are_rejected() {
    let records = only_record();
    let base = cohort(&records, &[None]);
    let mut empty = base.clone();
    empty.cases.clear();
    assert!(matches!(
        evaluate_metrics(&empty, &[]),
        Err(EvalError::Limit(_))
    ));
    let mut too_many = base.clone();
    too_many.cases = vec![base.cases[0].clone(); MAX_EVALUATION_CASES + 1];
    assert!(matches!(
        evaluate_metrics(&too_many, &[]),
        Err(EvalError::Limit(_))
    ));
    assert!(matches!(
        MetricsCohort::from_json(&vec![b' '; MAX_METRICS_COHORT_BYTES + 1]),
        Err(EvalError::Limit(_))
    ));
    let mut too_wide = base;
    let template = too_wide.cases[0].clone();
    too_wide.cases = (0..MAX_EVALUATION_CASES)
        .map(|index| {
            let mut row = template.clone();
            row.case_id = format!("{index:04}-{}", "x".repeat(500));
            row.policy_id = "p".repeat(500);
            row
        })
        .collect();
    assert!(matches!(
        evaluate_metrics(&too_wide, &[]),
        Err(EvalError::Limit("metrics cohort bytes"))
    ));
}

#[test]
fn record_bytes_have_an_aggregate_limit_not_only_per_record_limits() {
    let records: Vec<_> = (0..10)
        .map(|index| {
            let mut i = input(
                &format!("large-{index}"),
                0,
                Some(0),
                ObservedOutcome::Passed,
            );
            i.request.task.objective = "x".repeat(1_800_000);
            seal(i)
        })
        .collect();
    let total: usize = records
        .iter()
        .map(|r| r.canonical_json().unwrap().len())
        .sum();
    assert!(total > MAX_METRICS_RECORD_BYTES);
    assert!(
        records
            .iter()
            .all(|r| r.canonical_json().unwrap().len() <= MAX_REPLAY_BYTES)
    );
    assert!(matches!(
        evaluate_metrics(&cohort(&records, &[None; 10]), &records),
        Err(EvalError::Limit("metrics records bytes"))
    ));
}

#[test]
fn report_is_redacted_and_has_no_human_or_activation_assertion() {
    let mut i = input("one", 1, Some(1), ObservedOutcome::Passed);
    i.request.task.objective = "CANARY_PROMPT_MUST_NOT_LEAK".into();
    let records = vec![seal(i)];
    let report = evaluate_metrics(&cohort(&records, &[Some(1_000_000)]), &records).unwrap();
    let output = serde_json::to_string(&report).unwrap();
    assert!(!output.contains("CANARY_PROMPT_MUST_NOT_LEAK"));
    let value: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(value["provenance"], "synthetic");
    for field in [
        "human_validated",
        "semantic_enabled",
        "promotion",
        "request",
        "snapshot",
        "catalog",
    ] {
        assert!(value.get(field).is_none());
    }
}
