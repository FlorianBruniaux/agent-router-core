use serde_json::Value;
use std::{fs, process::Command};

const FIXTURE: &str = include_str!("../../../tests/fixtures/evaluation/accepted-changes-v1.json");

#[test]
fn exact_revision_history_is_offline_and_creates_no_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("supplied.json");
    fs::write(&path, FIXTURE).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agent-router"))
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .args(["eval", "accepted-changes", "--input"])
        .arg(&path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["selected_accepted_changes"], 0);
    assert_eq!(
        report["acceptance_history"][0]["cohort_costs_at_frontier"]["model"]["total_microusd"],
        300
    );
    assert_eq!(report["cohort_costs"]["model"]["total_microusd"], 700);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn malformed_or_tampered_input_refuses_and_human_view_creates_no_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("supplied.json");
    for input in [
        "{".to_owned(),
        FIXTURE.replacen(
            "\"schema_version\": 1",
            "\"schema_version\": 1, \"schema_version\": 1",
            1,
        ),
        FIXTURE.replacen("\"complete\": true", "\"complete\": false", 1),
    ] {
        fs::write(&path, input).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_agent-router"))
            .current_dir(dir.path())
            .env("HOME", dir.path())
            .args(["eval", "accepted-changes", "--input"])
            .arg(&path)
            .arg("--json")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
    fs::write(&path, FIXTURE).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agent-router"))
        .current_dir(dir.path())
        .args(["eval", "accepted-changes", "--input"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Evaluation")
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn accepted_selection_has_exact_ratio_and_deterministic_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("supplied.json");
    let mut input: Value = serde_json::from_str(FIXTURE).unwrap();
    input["selections"][0]["revision_sha256"] =
        input["revisions"][0]["binding"]["revision_sha256"].clone();
    fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_agent-router"))
            .current_dir(dir.path())
            .env("HOME", dir.path())
            .args(["eval", "accepted-changes", "--input"])
            .arg(&path)
            .arg("--json")
            .output()
            .unwrap()
    };
    let a = run();
    let b = run();
    assert!(a.status.success());
    assert!(b.status.success());
    assert_eq!(a.stdout, b.stdout);
    let r: Value = serde_json::from_slice(&a.stdout).unwrap();
    assert_eq!(
        r["cost_per_selected_accepted_change"]["model"],
        serde_json::json!({"numerator_microusd":700,"denominator":1})
    );
    assert_eq!(
        r["cost_per_selected_accepted_change"]["ci"],
        serde_json::json!({"numerator_microusd":50,"denominator":1})
    );
    assert_eq!(
        r["acceptance_history"][0]["assignment_model_cost_at_frontier"]["total_microusd"],
        200
    );
}
