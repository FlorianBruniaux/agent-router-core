use router_feedback::accepted_changes_report;
use serde_json::{Value, json};

// Synthetic supplied evidence only. Costs are hand-picked integers, not live usage.
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/evaluation/accepted-changes-v1.json"
    ))
    .unwrap()
}
fn report(v: &Value) -> Value {
    serde_json::to_value(accepted_changes_report(&serde_json::to_vec(v).unwrap()).unwrap()).unwrap()
}
fn refuses(v: &Value) {
    assert!(accepted_changes_report(&serde_json::to_vec(v).unwrap()).is_err());
}
fn select_a(v: &mut Value) {
    v["selections"][0]["revision_sha256"] = v["revisions"][0]["binding"]["revision_sha256"].clone();
}

#[test]
fn a_then_b_does_not_inherit_acceptance_or_change_a_frontier() {
    let r = report(&fixture());
    assert_eq!(r["selected_accepted_changes"], 0);
    assert_eq!(r["selected"][0]["status"], "rejected"); // assignment IDs sorted
    assert_eq!(r["selected"][1]["status"], "unknown");
    assert_eq!(r["selected"][2]["status"], "unknown");
    assert_eq!(
        r["acceptance_history"][0]["cohort_costs_at_frontier"]["model"]["total_microusd"],
        300
    );
    assert_eq!(r["cohort_costs"]["model"]["total_microusd"], 700);
    assert_eq!(r["cost_per_selected_accepted_change"]["model"], Value::Null);
}
#[test]
fn accepted_denominator_includes_all_failed_and_later_cohort_work() {
    let mut v = fixture();
    select_a(&mut v);
    let r = report(&v);
    assert_eq!(r["selected_accepted_changes"], 1);
    assert_eq!(
        r["cost_per_selected_accepted_change"]["model"],
        json!({"numerator_microusd":700,"denominator":1})
    );
    assert_eq!(r["cohort_costs"]["ci"]["total_microusd"], 50);
    assert_eq!(r["cohort_costs"]["human"]["total_microusd"], 30);
}
#[test]
fn revocation_is_exact_append_only_and_retains_acceptance_history() {
    let mut v = fixture();
    select_a(&mut v);
    let mut revoked = v["verdicts"][0].clone();
    revoked["sequence"] = json!(14);
    revoked["status"] = json!("revoked");
    revoked["acceptance_sequence"] = json!(10);
    revoked["cost_frontier_sequence"] = Value::Null;
    v["verdicts"].as_array_mut().unwrap().push(revoked);
    let r = report(&v);
    assert_eq!(r["selected"][1]["status"], "revoked");
    assert_eq!(r["selected_accepted_changes"], 0);
    assert_eq!(r["acceptance_history"].as_array().unwrap().len(), 1);
    assert_eq!(r["verdict_history"].as_array().unwrap().len(), 3);
    v["verdicts"][2]["binding"] = v["revisions"][2]["binding"].clone();
    refuses(&v);
}
#[test]
fn rejects_patch_criteria_source_candidate_and_predecessor_substitution() {
    for field in [
        "revision_sha256",
        "criteria_sha256",
        "source_sha256",
        "candidate_sha256",
    ] {
        let mut v = fixture();
        v["verdicts"][0]["binding"][field] = json!("f".repeat(64));
        refuses(&v);
    }
    let mut v = fixture();
    v["revisions"][2]["predecessor_sha256"] = Value::Null;
    refuses(&v);
    let mut v = fixture();
    v["cohort"]["assignments"][0]["criteria_sha256"] = json!("f".repeat(64));
    refuses(&v);
}
#[test]
fn refuses_acceptance_without_passed_independent_evidence_and_bad_frontiers() {
    for field in ["verifier_sha256", "reviewer_sha256"] {
        let mut v = fixture();
        v["verdicts"][0][field] = Value::Null;
        refuses(&v);
    }
    let mut v = fixture();
    v["verdicts"][0]["verifier_outcome"] = json!("unknown");
    refuses(&v);
    for frontier in [3, 11, 21] {
        let mut v = fixture();
        v["verdicts"][0]["cost_frontier_sequence"] = json!(frontier);
        refuses(&v);
    }
    let mut v = fixture();
    v["analysis_sequence"] = json!(9);
    refuses(&v);
}
#[test]
fn physical_duplicates_count_once_but_retry_same_external_id_counts_twice() {
    let mut v = fixture();
    let original = v["observations"][0].clone();
    v["observations"]
        .as_array_mut()
        .unwrap()
        .push(original.clone());
    assert_eq!(report(&v)["cohort_costs"]["model"]["total_microusd"], 700);
    let mut retry = original;
    retry["key"]["physical_sha256"] = json!("d".repeat(64));
    retry["sequence"] = json!(15);
    let expected = json!({"key":retry["key"],"sequence":15});
    v["inventories"][0]["expected"]
        .as_array_mut()
        .unwrap()
        .push(expected);
    v["observations"].as_array_mut().unwrap().push(retry);
    let r = report(&v);
    assert_eq!(r["cohort_costs"]["model"]["total_microusd"], 800);
    assert_eq!(
        r["acceptance_history"][0]["cohort_costs_at_frontier"]["model"]["total_microusd"],
        300
    );
}
#[test]
fn conflicting_physical_identity_never_last_wins() {
    for field in [
        "cost_microusd",
        "kind",
        "links",
        "evidence_sha256",
        "attribution",
        "agent_outcome",
    ] {
        let mut v = fixture();
        let mut conflict = v["observations"][0].clone();
        conflict[field] = match field {
            "cost_microusd" => json!(999),
            "kind" => json!("human"),
            "links" => json!([v["revisions"][0]["binding"]]),
            "attribution" => json!("per_task"),
            "agent_outcome" => json!("exited"),
            _ => json!("e".repeat(64)),
        };
        v["observations"].as_array_mut().unwrap().push(conflict);
        refuses(&v);
    }
}
#[test]
fn shared_ci_counts_once_preserving_both_links() {
    let r = report(&fixture());
    assert_eq!(r["cohort_costs"]["ci"]["observation_count"], 1);
    let rows = r["observations"].as_array().unwrap();
    let ci = rows.iter().find(|o| o["kind"] == "ci").unwrap();
    assert_eq!(ci["links"].as_array().unwrap().len(), 2);
}
#[test]
fn missing_observation_and_partial_inventory_propagate_unknown_with_subtotal() {
    let mut v = fixture();
    v["observations"].as_array_mut().unwrap().remove(0);
    let r = report(&v);
    assert_eq!(r["cohort_costs"]["model"]["known_subtotal_microusd"], 600);
    assert_eq!(r["cohort_costs"]["model"]["total_microusd"], Value::Null);
    assert_eq!(
        r["acceptance_history"][0]["cohort_costs_at_frontier"]["model"]["total_microusd"],
        Value::Null
    );
    let mut v = fixture();
    v["inventories"][0]["coverage"] = json!("partial");
    assert_eq!(
        report(&v)["cohort_costs"]["model"]["total_microusd"],
        Value::Null
    );
    let mut v = fixture();
    v["inventories"].as_array_mut().unwrap().remove(0);
    assert_eq!(
        report(&v)["cohort_costs"]["model"]["known_subtotal_microusd"],
        700
    );
    assert_eq!(
        report(&v)["cohort_costs"]["model"]["total_microusd"],
        Value::Null
    );
}
#[test]
fn last_turn_and_partial_pricing_never_claim_complete_model_total() {
    for (field, value) in [
        ("usage_coverage", "last_turn_only"),
        ("usage_coverage", "partial"),
        ("pricing_coverage", "unknown"),
    ] {
        let mut v = fixture();
        v["observations"][0][field] = json!(value);
        let r = report(&v);
        assert_eq!(r["cohort_costs"]["model"]["total_microusd"], Value::Null);
        assert_eq!(r["cohort_costs"]["model"]["known_subtotal_microusd"], 700);
    }
    let mut v = fixture();
    v["observations"][0]["cost_microusd"] = Value::Null;
    assert_eq!(
        report(&v)["cohort_costs"]["model"]["known_subtotal_microusd"],
        600
    );
}
#[test]
fn off_cohort_observations_are_retained_but_excluded() {
    let mut v = fixture();
    let mut off = v["observations"][0].clone();
    off["key"]["physical_sha256"] = json!("a".repeat(64));
    off["cohort_sha256"] = json!("b".repeat(64));
    off["sequence"] = json!(16);
    off["cost_microusd"] = json!(9000);
    v["observations"].as_array_mut().unwrap().push(off);
    let r = report(&v);
    assert_eq!(r["off_cohort_observation_count"], 1);
    assert_eq!(r["observations"].as_array().unwrap().len(), 6);
    assert_eq!(r["cohort_costs"]["model"]["total_microusd"], 700);
}
#[test]
fn strict_bounded_versioned_input_is_deterministic() {
    let bytes = serde_json::to_vec(&fixture()).unwrap();
    let a = serde_json::to_vec(&accepted_changes_report(&bytes).unwrap()).unwrap();
    assert_eq!(
        a,
        serde_json::to_vec(&accepted_changes_report(&bytes).unwrap()).unwrap()
    );
    for path in ["schema_version", "extra"] {
        let mut v = fixture();
        v[path] = json!(2);
        refuses(&v);
    }
    let mut v = fixture();
    v["observations"][0]["extra"] = json!(true);
    refuses(&v);
    let duplicate = String::from_utf8(bytes.clone()).unwrap().replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    assert!(accepted_changes_report(duplicate.as_bytes()).is_err());
    assert!(accepted_changes_report(&vec![b' '; 4 * 1024 * 1024 + 1]).is_err());
    assert!(accepted_changes_report(b"{").is_err());
}

#[test]
fn failed_attempt_without_output_counts_and_does_not_invent_a_revision() {
    let mut v = fixture();
    let mut attempt = v["observations"][0].clone();
    attempt["key"]["physical_sha256"] = json!("9".repeat(64));
    attempt["sequence"] = json!(17);
    attempt["links"][0]["assignment_id"] = json!("no-run");
    attempt["links"][0]["revision_sha256"] = Value::Null;
    attempt["links"][0]["candidate_sha256"] = Value::Null;
    v["inventories"][0]["expected"]
        .as_array_mut()
        .unwrap()
        .push(json!({"key":attempt["key"],"sequence":17}));
    v["observations"].as_array_mut().unwrap().push(attempt);
    let r = report(&v);
    assert_eq!(r["selected"][2]["status"], "unknown");
    assert_eq!(r["cohort_costs"]["model"]["total_microusd"], 800);
}
#[test]
fn empty_known_inventory_is_zero_but_missing_inventory_is_unknown() {
    let mut v = fixture();
    v["observations"]
        .as_array_mut()
        .unwrap()
        .retain(|o| o["kind"] != "human");
    v["inventories"][2]["expected"] = json!([]);
    assert_eq!(report(&v)["cohort_costs"]["human"]["total_microusd"], 0);
    v["inventories"].as_array_mut().unwrap().remove(2);
    assert_eq!(
        report(&v)["cohort_costs"]["human"]["total_microusd"],
        Value::Null
    );
}
#[test]
fn overflow_and_mismatched_expected_identity_refuse_instead_of_wrapping() {
    let mut v = fixture();
    v["observations"][0]["cost_microusd"] = json!(u64::MAX);
    refuses(&v);
    let mut v = fixture();
    v["inventories"][0]["expected"][0]["sequence"] = json!(19);
    refuses(&v);
    let mut v = fixture();
    v["inventories"][0]["expected"][0]["key"]["authority_sha256"] = json!("0".repeat(64));
    refuses(&v);
}
#[test]
fn missing_later_expected_cost_does_not_contaminate_prior_acceptance() {
    let mut v = fixture();
    v["observations"].as_array_mut().unwrap().pop();
    let r = report(&v);
    assert_eq!(r["cohort_costs"]["model"]["total_microusd"], Value::Null);
    assert_eq!(
        r["acceptance_history"][0]["cohort_costs_at_frontier"]["model"]["total_microusd"],
        300
    );
}

#[test]
fn accepted_assignment_cost_excludes_unrelated_failures_but_cohort_includes_them() {
    let r = report(&fixture());
    assert_eq!(
        r["acceptance_history"][0]["assignment_model_cost_at_frontier"]["total_microusd"],
        200
    );
    assert_eq!(
        r["acceptance_history"][0]["cohort_costs_at_frontier"]["model"]["total_microusd"],
        300
    );
    let mut v = fixture();
    v["observations"].as_array_mut().unwrap().remove(0);
    let r = report(&v);
    assert_eq!(
        r["acceptance_history"][0]["assignment_model_cost_at_frontier"]["known_subtotal_microusd"],
        200
    );
    assert_eq!(
        r["acceptance_history"][0]["assignment_model_cost_at_frontier"]["total_microusd"],
        Value::Null
    );
}

#[test]
fn same_physical_digest_in_independent_authority_namespaces_counts_separately() {
    let mut v = fixture();
    let mut other = v["observations"][0].clone();
    other["key"]["authority_sha256"] = json!("1".repeat(64));
    other["sequence"] = json!(17);
    v["inventories"][0]["expected"]
        .as_array_mut()
        .unwrap()
        .push(json!({"key":other["key"],"sequence":17}));
    v["observations"].as_array_mut().unwrap().push(other);
    assert_eq!(report(&v)["cohort_costs"]["model"]["total_microusd"], 800);
}
#[test]
fn corrections_include_prior_failed_work_for_same_assignment() {
    let mut v = fixture();
    v["observations"][0]["links"][0] = v["revisions"][0]["binding"].clone();
    let r = report(&v);
    assert_eq!(
        r["acceptance_history"][0]["assignment_model_cost_at_frontier"]["total_microusd"],
        300
    );
}
#[test]
fn selections_histories_and_complete_cohort_cannot_be_omitted_or_reordered() {
    let mut v = fixture();
    v["selections"].as_array_mut().unwrap().pop();
    refuses(&v);
    let mut v = fixture();
    v["revisions"].as_array_mut().unwrap().swap(0, 1);
    refuses(&v);
    let mut v = fixture();
    v["verdicts"].as_array_mut().unwrap().swap(0, 1);
    refuses(&v);
    let mut v = fixture();
    v["cohort"]["complete"] = json!(false);
    refuses(&v);
    let mut v = fixture();
    v["observations"][0]["links"][0]["candidate_sha256"] = Value::Null;
    refuses(&v);
}

#[test]
fn revocation_targets_current_acceptance_and_reacceptance_is_explicit() {
    let mut v = fixture();
    select_a(&mut v);
    let mut reaccept = v["verdicts"][0].clone();
    reaccept["sequence"] = json!(14);
    v["verdicts"].as_array_mut().unwrap().push(reaccept.clone());
    let mut revoke = reaccept.clone();
    revoke["sequence"] = json!(15);
    revoke["status"] = json!("revoked");
    revoke["cost_frontier_sequence"] = Value::Null;
    revoke["acceptance_sequence"] = json!(10);
    v["verdicts"].as_array_mut().unwrap().push(revoke);
    refuses(&v);
    v["verdicts"][3]["acceptance_sequence"] = json!(14);
    assert_eq!(report(&v)["selected"][1]["status"], "revoked");
    reaccept["sequence"] = json!(16);
    v["verdicts"].as_array_mut().unwrap().push(reaccept);
    assert_eq!(report(&v)["selected"][1]["status"], "accepted");
    assert_eq!(
        report(&v)["acceptance_history"].as_array().unwrap().len(),
        3
    );
}
