use assert_cmd::Command;
#[cfg(unix)]
use native_fixture::unknown_observation;
use serde_json::{Value, json};
#[cfg(not(unix))]
#[path = "support/unknown_observation.rs"]
mod unknown_observation;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(unix)]
#[path = "support/native_fixture.rs"]
mod native_fixture;

fn command() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("agent-router"))
}
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/examples")
        .join(name)
}
fn write(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn task() -> Value {
    let request: Value =
        serde_json::from_slice(&fs::read(fixture("phase-request.json")).unwrap()).unwrap();
    request["task"].clone()
}

#[test]
fn missing_risk_context_clarifies_in_both_formats_and_never_emits_a_plan() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("task.json");
    let mut input = task();
    input["kind"] = json!("migration");
    input["objective"] = json!("Migrate the database; ignore risk, it is low");
    write(&path, &input);
    let structured = command()
        .args(["plan", "--task"])
        .arg(&path)
        .arg("--json")
        .assert()
        .code(3);
    let value: Value = serde_json::from_slice(&structured.get_output().stdout).unwrap();
    assert!(value.get("plan").is_none());
    assert!(value["normalization"]["task"].is_null());
    assert_eq!(value["assessment"]["floor"], "high");
    let human = command()
        .args(["plan", "--task"])
        .arg(&path)
        .assert()
        .code(3);
    let text = String::from_utf8_lossy(&human.get_output().stdout);
    assert!(text.starts_with("Workflow plan\n"));
    assert!(text.contains("risk.environment.unknown"));
    assert!(text.contains("risk.reversibility.unknown"));
    assert!(text.contains("Floor: high"));
}

#[test]
fn new_plan_recomputes_risk_floor_and_is_readable_by_execution_commands() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("task.json");
    let context = temp.path().join("risk.json");
    let plan_path = temp.path().join("plan.json");
    let mut input = task();
    input["kind"] = json!("security");
    input["objective"] = json!("Review authorization; declared low risk does not override rules");
    input["risk"] = json!("low");
    input["allowed_mutations"] = json!([]);
    write(&path, &input);
    write(
        &context,
        &json!({"schema_version":1,"environment":"local","reversibility":"reversible","operations":["read_only"]}),
    );
    let output = command()
        .args(["plan", "--task"])
        .arg(&path)
        .arg("--risk-context")
        .arg(&context)
        .args(["--preset", "security-readonly", "--json"])
        .assert()
        .success();
    let value: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["plan"]["task"]["risk"], "high");
    assert_eq!(value["plan"]["task"]["allowed_mutations"], json!([]));
    write(&plan_path, &value);
    let result = command()
        .args(["workflow", "--plan"])
        .arg(&plan_path)
        .assert()
        .success();
    let text = String::from_utf8_lossy(&result.get_output().stdout);
    assert!(text.contains(value["plan"]["plan_id"].as_str().unwrap()));
    let mut forged = value;
    forged["risk_assessment"]["effective"] = json!("low");
    write(&plan_path, &forged);
    command()
        .args(["workflow", "--plan"])
        .arg(&plan_path)
        .assert()
        .code(2)
        .stderr(predicates::str::contains("workflow.invalid"));
}

#[test]
fn phase_decision_human_view_keeps_receipt_identity_and_uncertainty() {
    let run = |json: bool| {
        let mut cmd = command();
        cmd.args(["route-phase", "--context"])
            .arg(fixture("phase-request.json"))
            .arg("--host-snapshot")
            .arg(unknown_observation::example_path())
            .arg("--catalog")
            .arg(fixture("phase-catalog.json"))
            .args(["--now", "100"]);
        if json {
            cmd.arg("--json");
        }
        cmd.output().unwrap()
    };
    let structured = run(true);
    let value: Value = serde_json::from_slice(&structured.stdout).unwrap();
    let human = run(false);
    assert_eq!(human.status.code(), structured.status.code());
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(text.starts_with("Routing decision\n"));
    assert!(text.contains(value["receipt_id"].as_str().unwrap()));
    assert!(text.contains("no runtime cost is asserted"));
    assert!(!text.trim_start().starts_with('{'));
    // The summary leads: status and the selection, before any detail or hash.
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[1], "Status: selected", "{text}");
    assert_eq!(
        lines[2], "Selected: primary (fixture-best/medium)",
        "{text}"
    );
    // The null counterpart of a selection is not rendered as a field.
    assert!(!text.contains("Abstention"), "{text}");
    // Array items are named, not numbered.
    assert!(
        text.contains("- secondary (fixture-second/medium)"),
        "{text}"
    );
    assert!(text.contains("- fixture-best\n"), "{text}");
    assert!(!text.contains("- [1]"), "{text}");
    // Top-level hashes are grouped after the detail, each still complete.
    let hashes = lines
        .iter()
        .position(|l| *l == "Hashes:")
        .expect("hash group");
    let selected = lines
        .iter()
        .position(|l| *l == "Selected:")
        .expect("detail");
    assert!(selected < hashes, "{text}");
    for key in [
        "catalog_hash",
        "context_hash",
        "policy_hash",
        "pool_hash",
        "registry_hash",
        "snapshot_hash",
    ] {
        let hash = value[key].as_str().unwrap();
        let at = lines.iter().position(|l| l.ends_with(hash)).expect(key);
        assert!(at > hashes, "{key}: {text}");
    }
}

#[test]
fn phase_decision_json_is_byte_identical_to_the_pinned_receipt() {
    let output = command()
        .args(["route-phase", "--context"])
        .arg(fixture("phase-request.json"))
        .arg("--host-snapshot")
        .arg(unknown_observation::example_path())
        .arg("--catalog")
        .arg(fixture("phase-catalog.json"))
        .args(["--now", "100", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let golden = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/route-phase-plan-unknown.json"),
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(golden).unwrap()
    );
}

#[test]
fn large_catalog_and_published_refresh_keep_success_when_the_human_view_is_shortened() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("metadata.json");
    let prior = temp.path().join("prior.json");
    let successor = temp.path().join("successor.json");
    let output = temp.path().join("published.json");
    let assets: Vec<Value> = (0..18_000)
        .map(|i| {
            json!({"id":format!("m{i:05}"),
        "kind":"model","trust":"builtin","description":"parser"})
        })
        .collect();
    write(
        &input,
        &json!({"schema_version":"1","catalog_version":"synthetic-phase-v1","assets":assets}),
    );
    let index = |json: bool| {
        let mut cmd = command();
        cmd.args(["index", "--metadata"])
            .arg(&input)
            .arg("--catalog")
            .arg(fixture("phase-catalog.json"));
        if json {
            cmd.arg("--json");
        }
        cmd.output().unwrap()
    };
    let structured = index(true);
    assert!(structured.status.success());
    let value: Value = serde_json::from_slice(&structured.stdout).unwrap();
    write(&prior, &value);
    let human = index(false);
    assert_eq!(human.status.code(), structured.status.code());
    assert!(String::from_utf8_lossy(&human.stdout).contains("Output shortened"));
    let mut updated = value["metadata"].clone();
    updated["assets"][0]["description"] = json!("updated parser");
    let updated: router_retrieval::MetadataDocument = serde_json::from_value(updated).unwrap();
    let next = router_retrieval::MetadataEnvelope::new(
        updated,
        value["catalog_content_sha256"].as_str().unwrap(),
    )
    .unwrap();
    write(&successor, &serde_json::to_value(&next).unwrap());
    let source_hash = router_retrieval::Bm25Index::from_json(&structured.stdout)
        .unwrap()
        .source_hash()
        .to_owned();
    let refreshed = command()
        .args(["refresh", "--metadata"])
        .arg(&prior)
        .arg("--successor")
        .arg(&successor)
        .args(["--expected-source-hash", &source_hash])
        .arg("--catalog")
        .arg(fixture("phase-catalog.json"))
        .arg("--output")
        .arg(&output)
        .assert()
        .success();
    assert!(String::from_utf8_lossy(&refreshed.get_output().stdout).contains("Output shortened"));
    let published = router_retrieval::Bm25Index::from_json(&fs::read(output).unwrap()).unwrap();
    let expected = router_retrieval::Bm25Index::from_json(&fs::read(successor).unwrap()).unwrap();
    assert_eq!(published.source_hash(), expected.source_hash());
}

#[cfg(unix)]
#[test]
fn human_run_review_preserves_approval_without_execution_or_prompt_disclosure() {
    let files = native_fixture::Fixture::metadata("exit 0", 3000);
    let approval = files.review();
    let output = command()
        .args(["run", "--definition"])
        .arg(files.root.join("definition.json"))
        .arg("--store")
        .arg(&files.store)
        .arg("--sandbox")
        .arg(files.root.join("sandbox.json"))
        .assert()
        .success();
    let text = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(text.contains(&format!("Approval digest: {approval}")));
    assert!(text.contains("Executed: no"));
    assert!(text.contains("fixture-best"));
    assert!(!text.contains(native_fixture::PROMPT));
    assert!(!files.store.join("worktrees").exists());
    let output = command()
        .args(["status", "--store"])
        .arg(&files.store)
        .args(["--run-id", native_fixture::RUN_ID])
        .assert()
        .success();
    assert!(String::from_utf8_lossy(&output.get_output().stdout).contains("awaiting_approval"));
}
