use assert_cmd::Command;
use router_adapter_api::content_digest;
use router_eval::ReplayRecord;
use router_types::PhasePolicy;
use serde_json::{Value, json};
use std::{fs, path::Path};

fn fixture(name: &str) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/examples");
    serde_json::from_slice(&fs::read(root.join(name)).unwrap()).unwrap()
}
fn input(id: &str, tokens: u64, elapsed: u64, outcome: &str) -> Value {
    json!({"schema_version":1,"case_id":id,"family_id":"synthetic-metrics",
        "split":"held_out","out_of_domain":false,"request":fixture("phase-request.json"),
        "snapshot":fixture("phase-snapshot.json"),"catalog":fixture("phase-catalog.json"),
        "policies":{"baseline":PhasePolicy::default()},
        "pricing":{"schema_version":1,"version":"synthetic","source":"fixture-only",
            "observed_at_unix_seconds":100,"models":{"fixture-best":{
            "input_microusd_per_million":1000000,"cached_input_microusd_per_million":1000000,
            "output_microusd_per_million":1000000}}},
        "observations":{"baseline":{"usage":[{"model":"fixture-best","input_tokens":tokens,
            "cached_input_tokens":0,"output_tokens":0}],"elapsed_ms":elapsed,"fallback_reasons":[],
            "outcomes":{"transport":"unknown","command_validation":"unknown","functional":outcome}}},"label":null})
}
fn write(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn setup(root: &Path) -> Value {
    let mut cases = Vec::new();
    for (id, tokens, elapsed, outcome, prediction) in [
        ("a", 10, 20, "passed", 800000),
        ("b", 30, 30, "failed", 200000),
        ("c", 20, 40, "passed", 600000),
    ] {
        let record = ReplayRecord::seal(
            serde_json::from_value(input(id, tokens, elapsed, outcome)).unwrap(),
        )
        .unwrap();
        write(&root.join(format!("{id}.json")), &record);
        cases.push(
            json!({"case_id":id,"input_hash":record.input_hash(),"policy_id":"baseline",
            "policy_sha256":content_digest(&serde_json::to_vec(&PhasePolicy::default()).unwrap()),
            "budget":{"max_cost_microusd":tokens,"max_tokens":tokens,"max_elapsed_ms":elapsed},
            "predicted_success_micros":prediction,"usage_complete":true,
            "usage_evidence_sha256":"a".repeat(64)}),
        );
    }
    let cohort = json!({"schema_version":1,"analysis_authorized":true,"provenance":"synthetic","cases":cases});
    write(&root.join("cohort.json"), &cohort);
    cohort
}
fn command(root: &Path) -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("agent-router"));
    command
        .args(["eval", "metrics", "--cohort"])
        .arg(root.join("cohort.json"))
        .arg("--records")
        .args([
            root.join("a.json"),
            root.join("b.json"),
            root.join("c.json"),
        ]);
    command
}
#[test]
fn metrics_reports_exact_cost_calibration_and_budget_on_frozen_cohort() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path());
    let output = command(dir.path()).arg("--json").assert().success();
    let report: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
    assert_eq!(report["cases"], 3);
    assert_eq!(report["success_at_budget"]["passed"], 2);
    assert_eq!(report["success_at_budget"]["failed"], 1);
    assert_eq!(report["success_at_budget"]["unknown"], 0);
    assert_eq!(
        report["cost_microusd_per_functional_success"],
        json!({"numerator":60,"denominator":2})
    );
    assert_eq!(
        report["total_execution_ms_per_functional_success"],
        json!({"numerator":90,"denominator":2})
    );
    assert_eq!(
        report["calibration"]["brier"],
        json!({"numerator":240000000000u64,"denominator":3000000000000u64})
    );
    assert_eq!(
        report["calibration"]["ece"],
        json!({"numerator":800000,"denominator":3000000})
    );
    assert!(
        !String::from_utf8_lossy(&output.get_output().stdout).contains("Inspect the Rust contract")
    );
    let mut cohort = setup(dir.path());
    cohort["cases"].as_array_mut().unwrap().reverse();
    write(&dir.path().join("cohort.json"), &cohort);
    let reordered = command(dir.path()).arg("--json").assert().success();
    assert_eq!(output.get_output().stdout, reordered.get_output().stdout);
    let human = command(dir.path()).assert().success();
    let text = String::from_utf8_lossy(&human.get_output().stdout);
    assert!(text.starts_with("Evaluation\n"));
    assert!(text.contains("Cost microusd per functional success"));
}
#[test]
fn substituted_or_unauthorized_cohort_has_no_partial_report() {
    let dir = tempfile::tempdir().unwrap();
    let mut cohort = setup(dir.path());
    cohort["cases"][0]["input_hash"] = json!("b".repeat(64));
    write(&dir.path().join("cohort.json"), &cohort);
    let result = command(dir.path()).arg("--json").assert().failure();
    assert!(result.get_output().stdout.is_empty());
    let mut cohort = setup(dir.path());
    cohort["analysis_authorized"] = json!(false);
    write(&dir.path().join("cohort.json"), &cohort);
    let result = command(dir.path()).arg("--json").assert().failure();
    assert!(result.get_output().stdout.is_empty());
}

#[test]
fn incomplete_analysis_preserves_unknowns_without_failing_or_enabling_promotion() {
    let dir = tempfile::tempdir().unwrap();
    let mut cohort = setup(dir.path());
    let path = dir.path().join("c.json");
    let record = ReplayRecord::from_json(&fs::read(&path).unwrap()).unwrap();
    let mut input = record.input().clone();
    input
        .observations
        .get_mut("baseline")
        .unwrap()
        .outcomes
        .functional = router_eval::ObservedOutcome::Unknown;
    let record = ReplayRecord::seal(input).unwrap();
    write(&path, &record);
    cohort["cases"][2]["input_hash"] = json!(record.input_hash());
    cohort["cases"][2]["predicted_success_micros"] = Value::Null;
    write(&dir.path().join("cohort.json"), &cohort);
    let output = command(dir.path()).arg("--json").assert().success();
    let report: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
    assert_eq!(report["functional"]["unknown"], 1);
    assert!(report["success_at_budget_rate"].is_null());
    assert_eq!(
        report["success_at_budget_lower"],
        json!({"numerator":1,"denominator":3})
    );
    assert_eq!(
        report["success_at_budget_upper"],
        json!({"numerator":2,"denominator":3})
    );
    assert!(report["cost_microusd_per_functional_success"].is_null());
    assert!(report["calibration"]["brier"].is_null());
    assert_eq!(report["calibration"]["known_pairs"], 2);
    assert_eq!(report["calibration"]["missing_predictions"], 1);
    assert_eq!(report["calibration"]["missing_outcomes"], 1);
    assert!(report.get("semantic_enabled").is_none());
    assert!(report.get("approval_digest").is_none());
}
