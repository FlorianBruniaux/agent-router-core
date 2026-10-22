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
#[test]
fn tradeoffs_cli_emits_stable_descriptive_frontier_without_promotion_fields() {
    let dir = tempfile::tempdir().unwrap();
    let policy = PhasePolicy::default();
    let obs = json!({"usage":[{"model":"fixture-best","input_tokens":10,"cached_input_tokens":0,"output_tokens":0}],"elapsed_ms":10,"fallback_reasons":[],"outcomes":{"transport":"failed","command_validation":"unknown","functional":"passed"}});
    let record=ReplayRecord::seal(serde_json::from_value(json!({"schema_version":1,"case_id":"one","family_id":"tradeoffs-cli","split":"held_out","out_of_domain":false,"request":fixture("phase-request.json"),"snapshot":fixture("phase-snapshot.json"),"catalog":fixture("phase-catalog.json"),"policies":{"a":policy,"b":PhasePolicy::default()},"pricing":{"schema_version":1,"version":"fixture","source":"fixture-only","observed_at_unix_seconds":100,"models":{"fixture-best":{"input_microusd_per_million":1000000,"cached_input_microusd_per_million":1000000,"output_microusd_per_million":1000000}}},"observations":{"a":obs,"b":obs},"label":null})).unwrap()).unwrap();
    fs::write(
        dir.path().join("record.json"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    let sha = content_digest(&serde_json::to_vec(&PhasePolicy::default()).unwrap());
    let mut cohort = json!({"schema_version":1,"analysis_authorized":true,"provenance":"synthetic","policies":[{"policy_id":"a","policy_sha256":sha},{"policy_id":"b","policy_sha256":sha}],"cases":[{"case_id":"one","input_hash":record.input_hash(),"budget":{"max_cost_microusd":100,"max_tokens":100,"max_elapsed_ms":100},"selected_policy_id":"a","cells":[{"policy_id":"a","usage_complete":true,"usage_evidence_sha256":"a".repeat(64)},{"policy_id":"b","usage_complete":true,"usage_evidence_sha256":"a".repeat(64)}]}]});
    fs::write(
        dir.path().join("cohort.json"),
        serde_json::to_vec(&cohort).unwrap(),
    )
    .unwrap();
    let run = || {
        Command::new(assert_cmd::cargo::cargo_bin!("agent-router"))
            .args(["eval", "tradeoffs", "--cohort"])
            .arg(dir.path().join("cohort.json"))
            .args(["--records"])
            .arg(dir.path().join("record.json"))
            .args(["--json"])
            .assert()
            .success()
    };
    let first = run();
    let report: Value = serde_json::from_slice(&first.get_output().stdout).unwrap();
    assert_eq!(report["frontier"], json!(["a", "b"]));
    assert_eq!(report["partial_frontier"], false);
    assert_eq!(report["policies"][0]["functional"]["passed"], 1);
    assert!(report.get("promotion").is_none());
    assert_eq!(first.get_output().stdout, run().get_output().stdout);

    cohort["policies"].as_array_mut().unwrap().reverse();
    cohort["cases"][0]["cells"]
        .as_array_mut()
        .unwrap()
        .reverse();
    fs::write(
        dir.path().join("cohort.json"),
        serde_json::to_vec(&cohort).unwrap(),
    )
    .unwrap();
    assert_eq!(first.get_output().stdout, run().get_output().stdout);

    cohort["policies"][0]["policy_sha256"] = json!("b".repeat(64));
    fs::write(
        dir.path().join("cohort.json"),
        serde_json::to_vec(&cohort).unwrap(),
    )
    .unwrap();
    let rejected = Command::new(assert_cmd::cargo::cargo_bin!("agent-router"))
        .args(["eval", "tradeoffs", "--cohort"])
        .arg(dir.path().join("cohort.json"))
        .args(["--records"])
        .arg(dir.path().join("record.json"))
        .args(["--json"])
        .assert()
        .code(7);
    assert!(rejected.get_output().stdout.is_empty());
    assert!(String::from_utf8_lossy(&rejected.get_output().stderr).contains("eval.integrity"));
}
