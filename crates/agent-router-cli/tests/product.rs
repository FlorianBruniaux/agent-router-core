use assert_cmd::Command;
use serde_json::{Value, json};
#[path = "support/unknown_observation.rs"]
mod unknown_observation;
use std::{
    fs,
    path::{Path, PathBuf},
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn command() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("agent-router"))
}
fn fixture(name: &str) -> PathBuf {
    root().join("fixtures/examples").join(name)
}
fn phase(name: &str) -> Command {
    let mut cmd = command();
    cmd.arg(name)
        .arg("--context")
        .arg(fixture("phase-request.json"))
        .arg("--host-snapshot")
        .arg(unknown_observation::example_path())
        .arg("--catalog")
        .arg(fixture("phase-catalog.json"))
        .args(["--now", "100", "--json"]);
    cmd
}
fn parsed(assert: assert_cmd::assert::Assert) -> Value {
    serde_json::from_slice(&assert.get_output().stdout).unwrap()
}
fn write(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

#[test]
fn active_policy_store_changes_routing_and_explicit_file_overrides_it() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let store = root.join("feedback");
    let path = root.join("strict-policy.json");
    let policy = router_types::PhasePolicy {
        minimum_utility_micros: i64::MAX,
        version: "strict-test".into(),
        ..Default::default()
    };
    write(&path, &serde_json::to_value(policy).unwrap());
    command()
        .args(["policy", "--store"])
        .arg(&store)
        .args(["baseline", "--policy"])
        .arg(&path)
        .args(["--now", "100", "--json"])
        .assert()
        .success();
    let receipt = parsed(
        phase("route-phase")
            .arg("--policy-store")
            .arg(&store)
            .assert()
            .code(3),
    );
    assert_eq!(receipt["abstention"], "below_threshold");
    assert!(receipt["selected"].is_null());
    let override_receipt = parsed(
        phase("route-phase")
            .arg("--policy-store")
            .arg(&store)
            .arg("--policy")
            .arg(fixture("phase-policy.json"))
            .assert()
            .success(),
    );
    assert!(!override_receipt["selected"].is_null());
    assert_ne!(receipt["policy_hash"], override_receipt["policy_hash"]);
}

#[test]
fn catalog_content_change_invalidates_bound_metadata_even_with_same_version() {
    let temp = tempfile::tempdir().unwrap();
    let metadata = temp.path().join("metadata.json");
    let catalog = temp.path().join("catalog.json");
    let bound = temp.path().join("bound.json");
    write(
        &metadata,
        &json!({"schema_version":"1","catalog_version":"fixture","assets":[]}),
    );
    let mut contents: Value =
        serde_json::from_slice(&fs::read(fixture("phase-catalog.json")).unwrap()).unwrap();
    write(&catalog, &contents);
    let envelope = parsed(
        command()
            .args(["index", "--metadata"])
            .arg(&metadata)
            .arg("--catalog")
            .arg(&catalog)
            .arg("--json")
            .assert()
            .success(),
    );
    write(&bound, &envelope);
    contents["models"][0]["quality_micros"] =
        json!(contents["models"][0]["quality_micros"].as_u64().unwrap() - 1);
    write(&catalog, &contents);
    command()
        .args(["search", "--metadata"])
        .arg(&bound)
        .arg("--catalog")
        .arg(&catalog)
        .args(["--query", "Rust", "--json"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("retrieval.catalog.mismatch"));
    command()
        .args(["search", "--metadata"])
        .arg(&bound)
        .args(["--query", "Rust", "--json"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("retrieval.catalog.required"));
}

#[test]
fn doctor_and_audit_never_echo_private_artifact_content() {
    let dir = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(dir.path()).unwrap();
    let artifact = directory.join("config.json");
    write(
        &artifact,
        &json!({"schema_version":1,"private_note":"private-project-context-value"}),
    );
    let request = directory.join("doctor.json");
    write(
        &request,
        &json!({"schema_version":1,"root":directory,"max_snapshot_age_seconds":60,"artifacts":[
            {"id":"local-config","relative_path":"config.json","kind":"json_configuration","expected_sha256":null,"require_private":false}
        ]}),
    );
    let output = command()
        .args(["doctor", "--request"])
        .arg(&request)
        .args(["--now", "100", "--json"])
        .output()
        .unwrap();
    assert!(matches!(output.status.code(), Some(0 | 3)), "{:?}", output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["files_modified"], 0);
    assert_eq!(report["network_requests"], 0);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-project-context-value"));
    let inputs = directory.join("audit-inputs.json");
    write(
        &inputs,
        &json!({"schema_version":1,"inputs":[{"kind":"effective_config","path":artifact}]}),
    );
    let bundle = parsed(
        command()
            .args(["audit", "export", "--inputs"])
            .arg(&inputs)
            .arg("--json")
            .assert()
            .success(),
    );
    assert_eq!(bundle["raw_content_included"], false);
    assert!(!bundle.to_string().contains("private-project-context-value"));
    let bundle_path = directory.join("audit.json");
    write(&bundle_path, &bundle);
    command()
        .args(["audit", "verify", "--bundle"])
        .arg(&bundle_path)
        .arg("--expected-root")
        .arg(bundle["root_hash"].as_str().unwrap())
        .arg("--json")
        .assert()
        .success();
    command()
        .args(["audit", "verify", "--bundle"])
        .arg(bundle_path)
        .arg("--expected-root")
        .arg("0".repeat(64))
        .arg("--json")
        .assert()
        .code(7)
        .stderr(predicates::str::contains("doctor.audit.integrity"));
}

#[test]
fn audit_verify_accepts_a_bundle_above_the_snapshot_cap_below_its_own_bound() {
    let dir = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(dir.path()).unwrap();
    let artifact = directory.join("config.json");
    write(&artifact, &json!({"schema_version":1}));
    let inputs = directory.join("audit-inputs.json");
    write(
        &inputs,
        &json!({"schema_version":1,"inputs":[{"kind":"effective_config","path":artifact}]}),
    );
    let bundle = command()
        .args(["audit", "export", "--inputs"])
        .arg(&inputs)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(bundle.status.code(), Some(0));
    // Valid JSON padded with whitespace to 5 MiB: above the 4 MiB snapshot cap,
    // below the 32 MiB documented bundle bound.
    let mut padded = bundle.stdout;
    padded.resize(padded.len() + 5 * 1024 * 1024, b' ');
    let path = directory.join("big-audit.json");
    fs::write(&path, padded).unwrap();
    command()
        .args(["audit", "verify", "--bundle"])
        .arg(&path)
        .arg("--json")
        .assert()
        .success();
}

#[test]
fn deep_doctor_checks_the_declared_schema_without_running_processes() {
    let dir = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(dir.path()).unwrap();
    let artifact = directory.join("policy.json");
    write(&artifact, &json!(router_types::PhasePolicy::default()));
    let request = directory.join("deep.json");
    write(
        &request,
        &json!({"schema_version":1,"base":{"schema_version":1,"root":directory,"max_snapshot_age_seconds":60,"artifacts":[{"id":"policy","relative_path":"policy.json","kind":"json_configuration","expected_sha256":null,"require_private":false}]},"schemas":[{"artifact_id":"policy","schema":"phase_policy"}],"retrieval_bindings":[]}),
    );
    let run = || {
        command()
            .args(["doctor", "--deep", "--request"])
            .arg(&request)
            .args(["--now", "100", "--json"])
            .output()
            .unwrap()
    };
    let valid = run();
    assert!(matches!(valid.status.code(), Some(0 | 3)), "{valid:?}");
    let report: Value = serde_json::from_slice(&valid.stdout).unwrap();
    assert_eq!(report["base"]["files_modified"], 0);
    assert_eq!(report["base"]["processes_launched"], 0);
    assert_eq!(report["base"]["network_requests"], 0);
    assert!(!report["checks"].as_array().unwrap().is_empty());
    write(
        &artifact,
        &json!({"schema_version":2,"private_note":"PRIVATE_INVALID_POLICY"}),
    );
    let invalid = run();
    assert_eq!(invalid.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&invalid.stdout).contains("PRIVATE_INVALID_POLICY"));
}

#[test]
fn feedback_requires_consent_and_policy_baseline_is_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(dir.path()).unwrap();
    let store = directory.join("feedback");
    let consent = parsed(
        command()
            .args(["feedback", "--store"])
            .arg(&store)
            .args(["consent", "--json"])
            .assert()
            .success(),
    );
    assert_eq!(consent["preferences"]["collection_enabled"], false);
    assert_eq!(consent["preferences"]["learning_enabled"], false);
    command()
        .args(["feedback", "--store"])
        .arg(&store)
        .args(["statistics", "--now", "100", "--json"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("feedback.learning_disabled"));
    let preferences = directory.join("preferences.json");
    write(
        &preferences,
        &json!({"schema_version":1,"collection_enabled":true,"learning_enabled":true,"retention_seconds":3600}),
    );
    command()
        .args(["feedback", "--store"])
        .arg(&store)
        .args(["configure", "--preferences"])
        .arg(preferences)
        .args(["--now", "100", "--json"])
        .assert()
        .success();
    let before = parsed(
        command()
            .args(["policy", "--store"])
            .arg(&store)
            .args(["active", "--now", "100", "--json"])
            .assert()
            .success(),
    );
    assert!(before["active"].is_null());
    // An empty trusted-key set is invalid input (2), not a signature mismatch (7).
    let keys = directory.join("trusted-keys.json");
    write(&keys, &json!([]));
    command()
        .args(["policy", "--store"])
        .arg(&store)
        .args(["apply", "--approval"])
        .arg(&keys)
        .arg("--trusted-keys")
        .arg(&keys)
        .args(["--now", "100", "--json"])
        .assert()
        .code(2)
        .stderr("{\"schema_version\":1,\"error\":\"feedback.invalid\"}\n");
    command()
        .args(["policy", "--store"])
        .arg(&store)
        .args(["baseline", "--policy"])
        .arg(fixture("phase-policy.json"))
        .args(["--now", "100", "--json"])
        .assert()
        .success();
    let after = parsed(
        command()
            .args(["policy", "--store"])
            .arg(&store)
            .args(["active", "--now", "101", "--json"])
            .assert()
            .success(),
    );
    assert!(after["active"].is_object());
    command()
        .args(["feedback", "--store"])
        .arg(&store)
        .args(["purge", "--now", "102", "--json"])
        .assert()
        .success();
    let exported = parsed(
        command()
            .args(["feedback", "--store"])
            .arg(&store)
            .args(["export", "--now", "103", "--json"])
            .assert()
            .success(),
    );
    assert_eq!(exported["events"], json!([]));
}

#[test]
fn phase_route_and_backend_keep_immutable_baseline_and_versioned_output() {
    let first = parsed(phase("route-phase").assert().success());
    let second = parsed(phase("route-phase").assert().success());
    assert_eq!(first, second);
    assert_eq!(first["schema_version"], 2);
    assert_eq!(first["selected"]["candidate"]["id"], "primary");
    let shadow = parsed(phase("backend").assert().success());
    assert_eq!(shadow["baseline_receipt_id"], first["receipt_id"]);
    assert_eq!(shadow["semantic_execution_enabled"], false);
    assert_eq!(shadow["active_candidate_id"], "primary");
    phase("route-phase")
        .arg("--policy")
        .arg(fixture("phase-policy.json"))
        .assert()
        .success();
}
#[test]
fn duplicate_permission_keys_and_stale_phase_evidence_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("duplicate.json");
    let source = fs::read_to_string(fixture("phase-request.json"))
        .unwrap()
        .replace(
            "\"model_inference\": \"supported\"",
            "\"model_inference\": \"unsupported\", \"model_inference\": \"supported\"",
        );
    fs::write(&path, source).unwrap();
    command()
        .arg("route-phase")
        .arg("--context")
        .arg(path)
        .arg("--host-snapshot")
        .arg(unknown_observation::example_path())
        .arg("--catalog")
        .arg(fixture("phase-catalog.json"))
        .args(["--now", "100", "--json"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("request.json.invalid"));
    command()
        .arg("route-phase")
        .arg("--context")
        .arg(fixture("phase-request.json"))
        .arg("--host-snapshot")
        .arg(unknown_observation::example_path())
        .arg("--catalog")
        .arg(fixture("phase-catalog.json"))
        .args(["--now", "200", "--snapshot-max-age-seconds", "1", "--json"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("snapshot.stale"));
}
#[test]
fn catalog_refresh_is_deterministic_and_alias_lookup_has_explicit_failure() {
    let dir = tempfile::tempdir().unwrap();
    let mut refresh = command();
    refresh
        .args(["catalog", "refresh", "--host-snapshot"])
        .arg(unknown_observation::example_path())
        .arg("--prior")
        .arg(fixture("phase-catalog.json"))
        .args(["--now", "100", "--json"]);
    let generated = parsed(refresh.assert().success());
    let path = dir.path().join("generated.json");
    write(&path, &generated);
    let valid = parsed(
        command()
            .args(["catalog", "validate", "--catalog"])
            .arg(&path)
            .args(["--now", "100", "--json"])
            .assert()
            .success(),
    );
    assert_eq!(valid["catalog_schema_version"], 2);
    let assets = parsed(
        command()
            .args(["catalog", "list", "--catalog"])
            .arg(&path)
            .args(["--now", "100", "--json"])
            .assert()
            .success(),
    );
    assert_eq!(assets["assets"].as_array().unwrap().len(), 2);
    command()
        .args(["catalog", "show", "--catalog"])
        .arg(&path)
        .args(["--id", "fixture-best", "--now", "100", "--json"])
        .assert()
        .success();
    command()
        .args(["catalog", "show", "--catalog"])
        .arg(&path)
        .args(["--id", "invented", "--now", "100", "--json"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("catalog.asset.unknown"));
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap(),
        generated
    );
}
#[test]
fn normalize_clarifies_missing_authority_then_plan_emits_a_verified_dag() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("task.json");
    let request: Value =
        serde_json::from_slice(&fs::read(fixture("phase-request.json")).unwrap()).unwrap();
    let mut task = request["task"].clone();
    task.as_object_mut().unwrap().remove("allowed_mutations");
    write(&path, &task);
    let result = parsed(
        command()
            .args(["normalize", "--task"])
            .arg(&path)
            .arg("--json")
            .assert()
            .code(3),
    );
    assert!(result["normalization"]["task"].is_null());
    assert!(
        !result["normalization"]["questions"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    write(&path, &request["task"]);
    let context = dir.path().join("risk-context.json");
    write(
        &context,
        &json!({"schema_version":1,"environment":"local","reversibility":"reversible","operations":["workspace_change"]}),
    );
    let result = parsed(
        command()
            .args(["plan", "--task"])
            .arg(&path)
            .arg("--risk-context")
            .arg(&context)
            .arg("--json")
            .assert()
            .success(),
    );
    let plan: router_types::WorkflowPlan = serde_json::from_value(result["plan"].clone()).unwrap();
    assert!(plan.requires_explicit_integration);
    assert_eq!(router_workflow::validate_plan(&plan).unwrap().len(), 3);
}
#[test]
fn search_keeps_untrusted_results_out_of_selected_pool_and_abstains_on_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.json");
    write(
        &path,
        &json!({"schema_version":"1","catalog_version":"fixture-v1","assets":[
            {"id":"rust-contract","kind":"skill","trust":"trusted_local","task_kinds":[],"triggers":["regression"],"description":"Rust parser regression tests","examples":[],"tags":[],"paths":[],"anti_triggers":[],"body":null},
            {"id":"remote","kind":"skill","trust":"untrusted","task_kinds":[],"triggers":["regression"],"description":"regression regression regression","examples":[],"tags":[],"paths":[],"anti_triggers":[],"body":null}
        ]}),
    );
    let result = parsed(
        command()
            .args(["search", "--metadata"])
            .arg(&path)
            .args(["--query", "regression", "--json"])
            .assert()
            .success(),
    );
    assert_eq!(result["selected"]["id"], "rust-contract");
    let empty = parsed(
        command()
            .args(["search", "--metadata"])
            .arg(path)
            .args(["--query", "", "--json"])
            .assert()
            .code(3),
    );
    assert!(empty["selected"].is_null());
}
#[test]
fn eval_seal_replay_compare_never_treats_synthetic_input_as_a_promotion() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.json");
    let record_path = dir.path().join("record.json");
    let request: Value =
        serde_json::from_slice(&fs::read(fixture("phase-request.json")).unwrap()).unwrap();
    let snapshot: Value =
        serde_json::from_slice(&fs::read(unknown_observation::example_path()).unwrap()).unwrap();
    let catalog: Value =
        serde_json::from_slice(&fs::read(fixture("phase-catalog.json")).unwrap()).unwrap();
    let policy = serde_json::to_value(router_types::PhasePolicy::default()).unwrap();
    let observed = json!({"usage":[{"model":"fixture-best","input_tokens":10,"cached_input_tokens":0,"output_tokens":5}],"elapsed_ms":10,"fallback_reasons":[],"outcomes":{"transport":"unknown","command_validation":"unknown","functional":"unknown"}});
    let price = json!({"input_microusd_per_million":1000000,"cached_input_microusd_per_million":500000,"output_microusd_per_million":2000000});
    write(
        &input,
        &json!({"schema_version":1,"case_id":"cli-test","family_id":"cli-family","split":"held_out","out_of_domain":false,
        "request":request,"snapshot":snapshot,"catalog":catalog,"policies":{"baseline":policy,"candidate":policy},
        "pricing":{"schema_version":1,"version":"synthetic-price","source":"synthetic-test-only","observed_at_unix_seconds":100,"models":{"fixture-best":price,"fixture-second":price}},
        "observations":{"baseline":observed,"candidate":observed},"label":null}),
    );
    let record = parsed(
        command()
            .args(["eval", "seal", "--input"])
            .arg(input)
            .arg("--json")
            .assert()
            .success(),
    );
    write(&record_path, &record);
    let trace = parsed(
        command()
            .args(["replay", "--record"])
            .arg(&record_path)
            .args(["--policy", "baseline", "--now", "100", "--json"])
            .assert()
            .success(),
    );
    assert_eq!(trace["outcomes"]["functional"], "unknown");
    let report = parsed(
        command()
            .args(["eval", "compare", "--records"])
            .arg(&record_path)
            .args([
                "--baseline",
                "baseline",
                "--candidate",
                "candidate",
                "--now",
                "100",
                "--json",
            ])
            .assert()
            .code(3),
    );
    assert_eq!(report["semantic_enabled"], false);
    assert!(
        report["promotion_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "promotion.independent_human_labels_required")
    );
    let mut damaged = record;
    damaged["input"]["request"]["candidates"][0]["model"] = json!("forged");
    write(&record_path, &damaged);
    command()
        .args(["replay", "--record"])
        .arg(&record_path)
        .args(["--policy", "baseline", "--now", "100", "--json"])
        .assert()
        .code(7)
        .stderr("{\"schema_version\":1,\"error\":\"eval.integrity\"}\n");
}
#[cfg(feature = "claude")]
#[test]
fn claude_stream_probe_preserves_unknown_effort_and_does_not_leak_content() {
    let path = root().join("crates/adapter-claude/tests/fixtures/claude.jsonl");
    let result = parsed(
        command()
            .args(["inspect", "--host", "claude", "--native-stream"])
            .arg(path)
            .args(["--observed-at", "100", "--now", "100", "--json"])
            .assert()
            .success(),
    );
    assert_eq!(result["host"]["harness"], "claude-code");
    assert!(
        result["host"]["supported_efforts"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    let encoded = result.to_string();
    assert!(!encoded.contains("secret-provider-output"));
    assert!(!encoded.contains("forged-model"));
}

#[test]
fn feedback_report_needs_collection_consent_and_is_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(dir.path()).unwrap();
    let store = directory.join("feedback");
    let report = |extra: &[&Path]| {
        let mut cmd = command();
        cmd.args(["feedback", "--store"])
            .arg(&store)
            .arg("report")
            .args(["--now", "200", "--json"]);
        for path in extra {
            cmd.arg("--pricing").arg(path);
        }
        cmd
    };
    report(&[])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("feedback.consent_required"));
    let preferences = directory.join("preferences.json");
    write(
        &preferences,
        &json!({"schema_version":1,"collection_enabled":true,"learning_enabled":false,"retention_seconds":3600}),
    );
    command()
        .args(["feedback", "--store"])
        .arg(&store)
        .args(["configure", "--preferences"])
        .arg(&preferences)
        .args(["--now", "100", "--json"])
        .assert()
        .success();
    command()
        .args(["feedback", "--store"])
        .arg(&store)
        .args(["record", "--input"])
        .arg(root().join("tests/fixtures/feedback/automated-unknown-v1.json"))
        .args(["--now", "102", "--json"])
        .assert()
        .success();
    let pricing = directory.join("pricing.json");
    write(
        &pricing,
        &json!({"schema_version":1,"version":"cli-test-v1","source":"synthetic","observed_at_unix_seconds":90,"models":{"fixture-model":{"input_microusd_per_million":1,"cached_input_microusd_per_million":1,"output_microusd_per_million":1}}}),
    );
    let first = report(&[&pricing]).assert().success();
    let first_bytes = first.get_output().stdout.clone();
    let second = report(&[&pricing]).assert().success();
    assert_eq!(first_bytes, second.get_output().stdout);
    let value: Value = serde_json::from_slice(&first_bytes).unwrap();
    assert_eq!(value["pricing"]["version"], "cli-test-v1");
    assert_eq!(value["automated_events"], 1);
    assert_eq!(value["unlinked"], 1);
    assert_eq!(value["advisory"]["reason"], "learning_disabled");
    // The recorded event carries no usage, so its cost is unknown, never zero.
    assert_eq!(value["groups"][0]["cost"]["cost_unknown"], 1);
    assert!(value["groups"][0]["cost"]["total_microusd"].is_null());
    let bad = directory.join("bad-pricing.json");
    write(&bad, &json!({"schema_version":1,"unexpected":true}));
    report(&[&bad]).assert().failure();
}
