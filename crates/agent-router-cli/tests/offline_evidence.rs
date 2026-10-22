use serde_json::Value;
use std::{fs, process::Command};

const QUALIFICATION: &str = include_str!(
    "../../../tests/fixtures/evaluation/evaluator-qualification/rare-case-permutation.json"
);
const PRICING: &str =
    include_str!("../../../tests/fixtures/evaluation/supplied-usage-pricing/complete.json");

fn run(command: &str, input: &std::path::Path, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agent-router"))
        .current_dir(input.parent().unwrap())
        .env("HOME", input.parent().unwrap())
        .args(["eval", command, "--input"])
        .arg(input)
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn required_case_regression_is_reported_without_adoption_or_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.json");
    fs::write(&path, QUALIFICATION).unwrap();
    let a = run("evaluator-qualification", &path, &["--json"]);
    let b = run("evaluator-qualification", &path, &["--json"]);
    assert!(a.status.success(), "{}", String::from_utf8_lossy(&a.stderr));
    assert!(b.status.success());
    assert_eq!(a.stdout, b.stdout);
    let report: Value = serde_json::from_slice(&a.stdout).unwrap();
    assert_eq!(
        report["comparisons"][0]["regressed_case_ids"],
        serde_json::json!(["rare"])
    );
    assert_eq!(report["adoption_authorized"], false);
    assert_eq!(report["oracle_authenticity"], "supplied_unverified");
    assert_eq!(report["supplied_reference_cost_microusd"], 100);
    assert_eq!(report["supplied_candidate_cost_microusd"], 1);
    let human = run("evaluator-qualification", &path, &[]);
    assert!(human.status.success());
    assert!(String::from_utf8_lossy(&human.stdout).contains("Evaluation"));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn portable_pricing_selects_only_allowlisted_projection_and_counts_failed_work() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.json");
    fs::write(&path, PRICING).unwrap();
    let full = run("supplied-usage-pricing", &path, &["--json"]);
    let portable = run("supplied-usage-pricing", &path, &["--portable", "--json"]);
    assert!(
        full.status.success(),
        "{}",
        String::from_utf8_lossy(&full.stderr)
    );
    assert!(
        portable.status.success(),
        "{}",
        String::from_utf8_lossy(&portable.stderr)
    );
    let full: Value = serde_json::from_slice(&full.stdout).unwrap();
    let portable: Value = serde_json::from_slice(&portable.stdout).unwrap();
    assert_eq!(
        full["accounting"]["cohort_costs"]["model"]["total_microusd"],
        450
    );
    assert_eq!(portable, full["portable_pricing"]);
    assert!(portable.get("accounting").is_none());
    assert_eq!(portable["physical_usage"].as_array().unwrap().len(), 3);
    assert_eq!(portable["evidence_trust"], "supplied_unverified");
    let human = run("supplied-usage-pricing", &path, &["--portable"]);
    assert!(human.status.success());
    assert!(String::from_utf8_lossy(&human.stdout).contains("Evaluation"));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn evidence_commands_refuse_missing_and_oversized_input_without_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.json");
    for command in ["evaluator-qualification", "supplied-usage-pricing"] {
        assert!(!run(command, &path, &["--json"]).status.success());
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    fs::write(&path, vec![b' '; 4 * 1024 * 1024 + 1]).unwrap();
    for command in ["evaluator-qualification", "supplied-usage-pricing"] {
        assert!(!run(command, &path, &["--json"]).status.success());
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn offline_evidence_commands_refuse_malformed_documents_without_exposing_contents() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.json");
    fs::write(
        &path,
        r#"{"secret":"PRIVATE_CONTENT_SENTINEL","schema_version":1,"schema_version":1}"#,
    )
    .unwrap();
    for (command, expected) in [
        (
            "evaluator-qualification",
            "eval.evaluator_qualification.invalid",
        ),
        (
            "supplied-usage-pricing",
            "eval.supplied_usage_pricing.invalid",
        ),
    ] {
        let output = run(command, &path, &["--json"]);
        assert!(!output.status.success());
        let exposed = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(exposed.contains(expected), "{exposed}");
        assert!(!exposed.contains("PRIVATE_CONTENT_SENTINEL"));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

#[test]
fn tuning_case_contamination_is_inconclusive_without_creating_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.json");
    let mut input: Value = serde_json::from_str(QUALIFICATION).unwrap();
    input["schema_version"] = 2.into();
    input["qualifications"][0]["tuning_case_ids"] = serde_json::json!(["rare"]);
    input["qualifications"][0]["tuning_output_sha256"] = serde_json::json!(["b".repeat(64)]);
    fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
    let output = run("evaluator-qualification", &path, &["--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 2);
    assert_eq!(report["comparisons"][0]["status"], "inconclusive");
    assert_eq!(
        report["comparisons"][0]["blockers"],
        serde_json::json!(["decision_corpus_overlap"])
    );
    assert_eq!(report["adoption_authorized"], false);
    assert_eq!(report["oracle_authenticity"], "supplied_unverified");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}
