use router_eval::*;

fn fixture() -> EvaluatorQualificationInput {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/evaluation/evaluator-qualification/rare-case-permutation.json"
    ))
    .unwrap()
}
fn report(
    input: &EvaluatorQualificationInput,
) -> std::result::Result<EvaluatorQualificationReport, EvaluatorQualificationError> {
    evaluator_qualification_report(&serde_json::to_vec(input).unwrap())
}

#[test]
fn rare_case_permutation_blocks_equal_aggregate_and_lower_cost() {
    let input = fixture();
    for verdict in &input.verdicts {
        assert_eq!(
            verdict
                .cases
                .iter()
                .filter(|case| case.outcome == ObservedOutcome::Passed)
                .count(),
            1
        );
    }
    let report = report(&input).unwrap();
    assert_eq!(
        report.comparisons[0].status,
        EvaluatorComparisonStatus::Regression
    );
    assert_eq!(report.comparisons[0].regressed_case_ids, ["rare"]);
    assert_eq!(report.supplied_reference_cost_microusd, Some(100));
    assert_eq!(report.supplied_candidate_cost_microusd, Some(1));
    assert!(!report.adoption_authorized);
    assert_eq!(report.oracle_authenticity, "supplied_unverified");
}

#[test]
fn malformed_json_never_echoes_sensitive_input() {
    let error =
        evaluator_qualification_report(br#"{"secret":"private-token","schema_version":999}"#)
            .unwrap_err()
            .to_string();
    assert!(error.starts_with("eval.evaluator_qualification."));
    assert!(!error.contains("private-token"));
}

fn reseal(input: &mut EvaluatorQualificationInput) {
    input.cohort_sha256 = evaluator_cohort_sha256(&input.cohort).unwrap();
    for q in &mut input.qualifications {
        q.corpus_sha256 = evaluator_qualification_corpus_sha256(&q.witnesses).unwrap();
    }
    for verdict in &mut input.verdicts {
        if let Some(task) = input
            .cohort
            .iter()
            .find(|t| t.instance_id == verdict.instance_id)
        {
            verdict.task_contract_sha256 = evaluator_task_contract_sha256(task).unwrap();
            verdict.cohort_sha256 = input.cohort_sha256.clone();
        }
    }
}
fn inconclusive(input: &EvaluatorQualificationInput, blocker: &str) {
    let r = report(input).unwrap();
    assert_eq!(
        r.comparisons[0].status,
        EvaluatorComparisonStatus::Inconclusive
    );
    assert!(
        r.comparisons[0].blockers.iter().any(|b| b == blocker),
        "{:?}",
        r.comparisons[0]
    );
    assert!(!r.adoption_authorized);
}

#[test]
fn satisfied_cases_are_only_supplied_structural_evidence() {
    let mut input = fixture();
    for case in &mut input.verdicts[1].cases {
        case.outcome = ObservedOutcome::Passed;
    }
    let r = report(&input).unwrap();
    assert_eq!(
        r.comparisons[0].status,
        EvaluatorComparisonStatus::RequiredCasesSatisfied
    );
    assert!(r.qualifications[0].structurally_consistent);
    assert_eq!(r.oracle_authenticity, "supplied_unverified");
    assert!(!r.adoption_authorized);
    assert_eq!(report(&input).unwrap(), r);
}

#[test]
fn infrastructure_and_unknown_are_never_functional_failure() {
    let mut input = fixture();
    input.verdicts[1].cases[0].execution = EvaluatorExecution::InfrastructureFailure;
    let r = report(&input).unwrap();
    assert_eq!(
        r.comparisons[0].cases[0].candidate,
        ObservedOutcome::Unknown
    );
    assert!(r.comparisons[0].regressed_case_ids.is_empty());
    inconclusive(&input, "required_case_unknown");
    input.verdicts[1].cases[0].execution = EvaluatorExecution::Completed;
    input.verdicts[1].cases[0].outcome = ObservedOutcome::Unknown;
    inconclusive(&input, "required_case_unknown");
}

#[test]
fn missing_case_verdict_and_instance_remain_inconclusive() {
    let mut input = fixture();
    input.verdicts[1].cases.remove(0);
    inconclusive(&input, "required_case_set_mismatch");
    let mut input = fixture();
    input.verdicts.pop();
    inconclusive(&input, "missing_verdict");
    let mut input = fixture();
    input.comparisons.clear();
    inconclusive(&input, "missing_verdict");
    assert_eq!(
        report(&input).unwrap().supplied_candidate_cost_microusd,
        None
    );
}

#[test]
fn duplicate_cases_instances_verdicts_selections_and_evaluators_are_invalid() {
    for mutation in 0..6 {
        let mut input = fixture();
        match mutation {
            0 => {
                let duplicate = input.verdicts[0].cases[0].clone();
                input.verdicts[0].cases.push(duplicate);
            }
            1 => input.cohort.push(input.cohort[0].clone()),
            2 => input.verdicts.push(input.verdicts[0].clone()),
            3 => input.comparisons.push(input.comparisons[0].clone()),
            4 => input.qualifications.push(input.qualifications[0].clone()),
            _ => input.cohort[0].required_case_ids.push("rare".into()),
        }
        assert!(
            matches!(report(&input), Err(EvaluatorQualificationError::Invalid)),
            "{mutation}"
        );
    }
}

#[test]
fn strict_json_rejects_keys_fields_versions_and_oversize_without_echo() {
    for bytes in [
        br#"{"schema_version":1,"schema_version":1}"#.as_slice(),
        br#"{"secret":"private-token","schema_version":999}"#.as_slice(),
        br#"{"schema_version":18446744073709551616}"#.as_slice(),
    ] {
        assert_eq!(
            evaluator_qualification_report(bytes)
                .unwrap_err()
                .to_string(),
            "eval.evaluator_qualification.invalid"
        );
    }
    let mut value = serde_json::to_value(fixture()).unwrap();
    value["qualifications"][0]["independent"] = true.into();
    assert!(matches!(
        evaluator_qualification_report(&serde_json::to_vec(&value).unwrap()),
        Err(EvaluatorQualificationError::Invalid)
    ));
    let mut input = fixture();
    input.schema_version = 2;
    assert!(matches!(
        report(&input),
        Err(EvaluatorQualificationError::Invalid)
    ));
    let large = vec![b' '; MAX_EVALUATOR_QUALIFICATION_BYTES + 1];
    assert!(matches!(
        evaluator_qualification_report(&large),
        Err(EvaluatorQualificationError::Limit)
    ));
}

#[test]
fn row_and_identifier_and_declared_execution_limits_are_enforced() {
    let mut input = fixture();
    input.verdicts[0].cases = vec![input.verdicts[0].cases[0].clone(); 4097];
    assert!(matches!(
        report(&input),
        Err(EvaluatorQualificationError::Limit)
    ));
    for field in 0..3 {
        let mut input = fixture();
        match field {
            0 => input.qualifications[0].max_duration_ms = u64::MAX,
            1 => input.qualifications[0].max_output_bytes = 0,
            _ => input.cohort[0].instance_id = "x".repeat(129),
        }
        assert!(matches!(
            report(&input),
            Err(EvaluatorQualificationError::Invalid)
        ));
    }
}

#[test]
fn exact_seals_cannot_be_replaced_by_syntactically_valid_hashes() {
    for target in 0..2 {
        let mut input = fixture();
        if target == 0 {
            input.cohort_sha256 = "a".repeat(64);
        } else {
            input.qualifications[0].corpus_sha256 = "a".repeat(64);
        }
        assert!(matches!(
            report(&input),
            Err(EvaluatorQualificationError::Integrity)
        ));
    }
}

#[test]
fn changed_identity_binding_applicability_and_unpermitted_differences_are_inconclusive() {
    for field in 0..8 {
        let mut input = fixture();
        let blocker = match field {
            0 => {
                input.verdicts[1].evaluator.version = "v2".into();
                "evaluator_changed"
            }
            1 => {
                input.verdicts[1].evaluator.configuration_sha256 = "b".repeat(64);
                "evaluator_changed"
            }
            2 => {
                input.verdicts[1].task_contract_sha256 = "b".repeat(64);
                "binding_mismatch"
            }
            3 => {
                input.verdicts[1].cohort_sha256 = "b".repeat(64);
                "binding_mismatch"
            }
            4 => {
                input.qualifications[0].applicable_criteria_sha256 = vec!["b".repeat(64)];
                "evaluator_unqualified_or_inapplicable"
            }
            5 => {
                input.permitted_differences.clear();
                "unpermitted_difference"
            }
            6 => {
                input.qualifications.clear();
                "evaluator_unqualified_or_inapplicable"
            }
            _ => {
                input.verdicts[1].instance_id = "other".into();
                "binding_mismatch"
            }
        };
        inconclusive(&input, blocker);
    }
}

#[test]
fn changed_evaluator_is_inconclusive_even_with_its_own_consistent_qualification() {
    let mut input = fixture();
    let mut qualification = input.qualifications[0].clone();
    qualification.evaluator.version = "v2".into();
    input.verdicts[1].evaluator = qualification.evaluator.clone();
    input.qualifications.push(qualification);
    inconclusive(&input, "evaluator_changed");
}

#[test]
fn source_input_criteria_and_intention_changes_do_not_reuse_old_verdicts() {
    for field in 0..4 {
        let mut input = fixture();
        match field {
            0 => input.cohort[0].source_sha256 = "b".repeat(64),
            1 => input.cohort[0].input_sha256 = "b".repeat(64),
            2 => input.cohort[0].criteria_sha256 = "b".repeat(64),
            _ => input.cohort[0].intention = TaskIntention::Design,
        }
        input.cohort_sha256 = evaluator_cohort_sha256(&input.cohort).unwrap();
        inconclusive(&input, "binding_mismatch");
    }
}

#[test]
fn qualification_requires_all_witness_kinds_consistency_and_non_author_reviewer() {
    for mutation in 0..4 {
        let mut input = fixture();
        match mutation {
            0 => {
                input.qualifications[0].witnesses.pop();
            }
            1 => input.qualifications[0].witnesses[0].observed = ObservedOutcome::Failed,
            2 => input.qualifications[0].witnesses[2].observed = ObservedOutcome::Failed,
            _ => input.qualifications[0].witnesses[0].reviewer_id = "author".into(),
        }
        reseal(&mut input);
        assert!(!report(&input).unwrap().qualifications[0].structurally_consistent);
        inconclusive(&input, "evaluator_unqualified_or_inapplicable");
    }
}

#[test]
fn held_out_outputs_cannot_overlap_qualification_or_tuning() {
    let mut input = fixture();
    input.verdicts[1].output_sha256 = input.qualifications[0].witnesses[0].output_sha256.clone();
    inconclusive(&input, "decision_corpus_overlap");
    let mut input = fixture();
    input.qualifications[0]
        .tuning_output_sha256
        .push(input.verdicts[1].output_sha256.clone());
    inconclusive(&input, "decision_corpus_overlap");
}

#[test]
fn reevaluation_preserves_previous_version_and_never_adds_cost() {
    let mut input = fixture();
    let original = input.verdicts[1].clone();
    let mut later = original.clone();
    later.verdict_id = "candidate-v2".into();
    later.evaluator.version = "v2".into();
    later.reevaluates = Some(original.verdict_id.clone());
    input.verdicts.push(later.clone());
    let r = report(&input).unwrap();
    assert_eq!(r.verdict_history[1], original);
    assert_eq!(r.verdict_history[2], later);
    assert_eq!(
        r.comparisons[0].candidate_verdict_id.as_deref(),
        Some("candidate")
    );
    assert_eq!(
        r.comparisons[0].task_contract_sha256,
        original.task_contract_sha256
    );
    assert_eq!(r.supplied_candidate_cost_microusd, Some(1));
    input.comparisons[0].candidate_verdict_id = Some(later.verdict_id);
    inconclusive(&input, "evaluator_changed");
    input.verdicts[2].output_sha256 = "b".repeat(64);
    assert!(matches!(
        report(&input),
        Err(EvaluatorQualificationError::Integrity)
    ));
}

#[test]
fn missing_cost_stays_unknown_and_sum_overflow_is_rejected() {
    let mut input = fixture();
    input.comparisons[0].candidate_cost_microusd = None;
    assert_eq!(
        report(&input).unwrap().supplied_candidate_cost_microusd,
        None
    );
    let mut input = fixture();
    let mut task = input.cohort[0].clone();
    task.instance_id = "task-b".into();
    input.cohort.push(task);
    let mut selection = input.comparisons[0].clone();
    selection.instance_id = "task-b".into();
    selection.candidate_cost_microusd = Some(u64::MAX);
    input.comparisons.push(selection);
    reseal(&mut input);
    assert!(matches!(
        report(&input),
        Err(EvaluatorQualificationError::CostOverflow)
    ));
}

#[test]
fn held_out_case_identity_cannot_overlap_qualification_with_different_output() {
    let mut input = fixture();
    for case in &mut input.verdicts[1].cases {
        case.outcome = ObservedOutcome::Passed;
    }
    input.qualifications[0].witnesses[0].case_id = "rare".into();
    reseal(&mut input);
    inconclusive(&input, "decision_corpus_overlap");
}

#[test]
fn legacy_tuning_without_case_identity_is_inconclusive_even_with_disjoint_output() {
    let mut input = fixture();
    input.qualifications[0]
        .tuning_output_sha256
        .push("b".repeat(64));
    inconclusive(&input, "tuning_case_identity_unknown");
}

fn v2_tuning(case_ids: serde_json::Value, outputs: serde_json::Value) -> serde_json::Value {
    let mut input = fixture();
    for case in &mut input.verdicts[1].cases {
        case.outcome = ObservedOutcome::Passed;
    }
    let mut value = serde_json::to_value(input).unwrap();
    value["schema_version"] = 2.into();
    value["qualifications"][0]["tuning_case_ids"] = case_ids;
    value["qualifications"][0]["tuning_output_sha256"] = outputs;
    value
}

fn value_report(
    value: &serde_json::Value,
) -> std::result::Result<EvaluatorQualificationReport, EvaluatorQualificationError> {
    evaluator_qualification_report(&serde_json::to_vec(value).unwrap())
}

#[test]
fn v2_reused_tuning_case_blocks_changed_output_even_from_another_evaluator_version() {
    for other_evaluator in [false, true] {
        let mut value = v2_tuning(
            serde_json::json!(["rare"]),
            serde_json::json!(["b".repeat(64)]),
        );
        if other_evaluator {
            let mut other = value["qualifications"][0].clone();
            other["evaluator"]["version"] = "earlier".into();
            value["qualifications"][0]["tuning_case_ids"] = serde_json::json!([]);
            value["qualifications"][0]["tuning_output_sha256"] = serde_json::json!([]);
            value["qualifications"].as_array_mut().unwrap().push(other);
        }
        let r = value_report(&value).expect("v2 evidence must be readable");
        assert_eq!(r.schema_version, 2);
        assert_eq!(
            r.comparisons[0].status,
            EvaluatorComparisonStatus::Inconclusive
        );
        assert_eq!(r.comparisons[0].blockers, ["decision_corpus_overlap"]);
        assert_eq!(r.comparisons[0].cases[0].candidate, ObservedOutcome::Passed);
        assert!(!r.adoption_authorized);
    }
}

#[test]
fn v2_disjoint_or_explicitly_empty_tuning_preserves_supplied_only_comparison() {
    for (ids, outputs) in [
        (serde_json::json!([]), serde_json::json!([])),
        (
            serde_json::json!(["training-case"]),
            serde_json::json!(["b".repeat(64), "c".repeat(64)]),
        ),
    ] {
        let value = v2_tuning(ids, outputs);
        let r = value_report(&value).unwrap();
        assert_eq!(
            r.comparisons[0].status,
            EvaluatorComparisonStatus::RequiredCasesSatisfied
        );
        assert!(r.comparisons[0].blockers.is_empty());
        assert_eq!(r.oracle_authenticity, "supplied_unverified");
        assert!(!r.adoption_authorized);
        assert_eq!(value_report(&value).unwrap(), r);
    }
}

#[test]
fn v2_tuning_output_overlap_still_blocks_reference_and_candidate() {
    for index in 0..2 {
        let hash = fixture().verdicts[index].output_sha256.clone();
        let value = v2_tuning(
            serde_json::json!(["training-case"]),
            serde_json::json!([hash]),
        );
        let r = value_report(&value).unwrap();
        assert_eq!(
            r.comparisons[0].status,
            EvaluatorComparisonStatus::Inconclusive
        );
        assert_eq!(r.comparisons[0].blockers, ["decision_corpus_overlap"]);
    }
}

#[test]
fn tuning_identity_requires_explicit_versioned_bounded_valid_sets() {
    for mutation in 0..9 {
        let mut value = v2_tuning(
            serde_json::json!(["training-case"]),
            serde_json::json!(["b".repeat(64)]),
        );
        match mutation {
            0 => {
                value["qualifications"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("tuning_case_ids");
            }
            1 => value["qualifications"][0]["tuning_case_ids"] = serde_json::Value::Null,
            2 => {
                value["qualifications"][0]["tuning_case_ids"] =
                    serde_json::json!(["training-case", "training-case"])
            }
            3 => {
                value["qualifications"][0]["tuning_case_ids"] =
                    serde_json::json!(["private / invalid"])
            }
            4 => value["qualifications"][0]["tuning_case_ids"] = serde_json::json!([]),
            5 => value["qualifications"][0]["tuning_output_sha256"] = serde_json::json!([]),
            6 => value["schema_version"] = 1.into(),
            7 => value["schema_version"] = 3.into(),
            _ => {
                value["qualifications"][0]["tuning_case_ids"] = serde_json::json!(["x".repeat(129)])
            }
        }
        assert!(
            matches!(
                value_report(&value),
                Err(EvaluatorQualificationError::Invalid)
            ),
            "mutation {mutation}"
        );
    }
    let ids: Vec<_> = (0..4097).map(|i| format!("training-{i}")).collect();
    let value = v2_tuning(serde_json::json!(ids), serde_json::json!(["b".repeat(64)]));
    assert!(matches!(
        value_report(&value),
        Err(EvaluatorQualificationError::Limit)
    ));
}
