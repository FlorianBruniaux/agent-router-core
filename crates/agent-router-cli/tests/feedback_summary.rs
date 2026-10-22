//! `feedback summary`: the global total of `feedback report`, through the binary.
use assert_cmd::Command;
use serde_json::{Value, json};
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
fn write(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

/// A store with three automated runs without a run key, in two model groups.
/// Without a run key no late fact can exist, so every run has no verdict.
fn store_with_runs(directory: &Path) -> PathBuf {
    let store = directory.join("feedback");
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
    let base: Value = serde_json::from_slice(
        &fs::read(root().join("tests/fixtures/feedback/automated-unknown-v1.json")).unwrap(),
    )
    .unwrap();
    for (index, model) in ["fixture-model", "fixture-model", "other-model"]
        .into_iter()
        .enumerate()
    {
        let mut input = base.clone();
        input["context"]["model"] = json!(model);
        input["binding"]["run_hash"] = json!(format!("{index:064x}"));
        let path = directory.join(format!("input-{index}.json"));
        write(&path, &input);
        command()
            .args(["feedback", "--store"])
            .arg(&store)
            .args(["record", "--input"])
            .arg(&path)
            .args(["--now", "102", "--json"])
            .assert()
            .success();
    }
    store
}

fn feedback(store: &Path, subcommand: &str, extra: &[&str]) -> Command {
    let mut cmd = command();
    cmd.args(["feedback", "--store"])
        .arg(store)
        .arg(subcommand)
        .args(["--now", "200"])
        .args(extra);
    cmd
}

#[test]
fn summary_needs_collection_consent() {
    let dir = tempfile::tempdir().unwrap();
    let store = fs::canonicalize(dir.path()).unwrap().join("feedback");
    feedback(&store, "summary", &["--json"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("feedback.consent_required"));
}

#[test]
fn summary_is_byte_identical_and_its_totals_equal_the_sum_of_the_report_groups() {
    let dir = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(dir.path()).unwrap();
    let store = store_with_runs(&directory);
    let pricing = directory.join("pricing.json");
    write(
        &pricing,
        &json!({"schema_version":1,"version":"cli-test-v1","source":"synthetic","observed_at_unix_seconds":90,"models":{"fixture-model":{"input_microusd_per_million":1,"cached_input_microusd_per_million":1,"output_microusd_per_million":1}}}),
    );
    let pricing = pricing.to_str().unwrap();
    let run = |subcommand: &str| {
        feedback(&store, subcommand, &["--pricing", pricing, "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    };
    let first = run("summary");
    assert_eq!(first, run("summary"));
    let summary: Value = serde_json::from_slice(&first).unwrap();
    let report: Value = serde_json::from_slice(&run("report")).unwrap();

    let groups = report["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 2);
    for key in ["runs", "accepted", "rejected", "unknown"] {
        let sum: u64 = groups.iter().map(|g| g[key].as_u64().unwrap()).sum();
        assert_eq!(summary[key].as_u64().unwrap(), sum, "{key}");
    }
    assert_eq!(summary["runs"], 3);
    assert_eq!(summary["report_content_hash"], report["content_hash"]);
    assert_eq!(summary["event_set_hash"], report["event_set_hash"]);
    assert_eq!(summary["schema_version"], 2);
    assert_eq!(summary["attribution"], "not_established");
    assert!(
        summary["attribution_note"]
            .as_str()
            .unwrap()
            .contains("A/B")
    );
    // No run carries usage: every cost is unknown, never zero.
    assert_eq!(summary["cost"]["cost_unknown"], 3);
    assert!(summary["cost"]["total_microusd"].is_null());
    assert!(summary["cost"]["per_accepted_microusd"].is_null());
    assert_eq!(summary["unknown_counts"]["cost"], 3);
}

#[test]
fn summary_counts_runs_without_a_verdict_as_unknown_not_as_failures() {
    let dir = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(dir.path()).unwrap();
    let store = store_with_runs(&directory);
    let out = feedback(&store, "summary", &["--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let summary: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(summary["unknown"], 3);
    assert_eq!(summary["rejected"], 0);
    assert_eq!(summary["accepted"], 0);
    assert_eq!(summary["unknown_counts"]["verdict"], 3);
    assert_eq!(summary["unknown_counts"]["unlinked"], 3);
    // No decided run: the rate is null, not 0.
    assert!(summary["accepted_rate"].is_null());
    assert_eq!(summary["cost"]["reason"], "no_pricing_table");
}

#[test]
fn summary_has_a_human_view_that_keeps_null_and_unknown_visible() {
    let dir = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(dir.path()).unwrap();
    let store = store_with_runs(&directory);
    let out = feedback(&store, "summary", &[])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("Attribution: not_established"), "{text}");
    assert!(text.contains("not set (null)"), "{text}");
    assert!(!text.trim_start().starts_with('{'), "{text}");
}

#[test]
fn report_human_and_json_views_keep_each_task_outcome_and_source() {
    use router_feedback::FeedbackStore;
    use router_types::{FeedbackFact, FeedbackInput, FeedbackPreferences};
    let dir = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(dir.path()).unwrap();
    let path = directory.join("feedback");
    let store = FeedbackStore::open(&path).unwrap();
    store
        .configure(
            FeedbackPreferences {
                collection_enabled: true,
                ..Default::default()
            },
            100,
        )
        .unwrap();
    let base: Value = serde_json::from_slice(
        &fs::read(root().join("tests/fixtures/feedback/automated-unknown-v1.json")).unwrap(),
    )
    .unwrap();
    for index in 1..=3 {
        let mut input = base.clone();
        let key = format!("{index:064x}");
        input["binding"]["task_hash"] = json!(key);
        input["binding"]["run_hash"] = json!(key);
        input["run_key_sha256"] = json!(key);
        if index == 2 {
            input["transport"] = json!("failed");
            input["failure"] = json!("timeout");
        }
        store
            .record(serde_json::from_value::<FeedbackInput>(input).unwrap(), 120)
            .unwrap();
        if index != 3 {
            let fact = json!({
                "schema_version":1,"run_key_sha256":key,"observed_at_unix_seconds":110,
                "kind":{"type":"verification","validation":if index == 1 {"passed"} else {"failed"},
                    "objective":if index == 1 {"passed"} else {"failed"},"evidence_sha256":"9".repeat(64)}
            });
            store
                .record_fact(serde_json::from_value::<FeedbackFact>(fact).unwrap(), 120)
                .unwrap();
        }
        if index == 1 {
            let fact = json!({"schema_version":1,"run_key_sha256":key,"observed_at_unix_seconds":115,
                "kind":{"type":"integration","outcome":"applied"}});
            store
                .record_fact(serde_json::from_value::<FeedbackFact>(fact).unwrap(), 120)
                .unwrap();
        }
    }
    drop(store);
    let first = feedback(&path, "report", &["--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let second = feedback(&path, "report", &["--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(first, second);
    let report: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(report["schema_version"], 3);
    let rows = report["runs"].as_array().unwrap();
    assert_eq!(
        rows.iter()
            .map(|r| r["verdict"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["accepted", "rejected", "unknown"]
    );
    assert!(rows.iter().all(|r| r["usage"].is_null()));
    let output = feedback(&path, "report", &[])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    for expected in [
        "Verdict: accepted",
        "Verdict: rejected",
        "Verdict: UNKNOWN",
        "Failure: timeout",
        "Source: feedback_store",
        "Runtime evidence: UNKNOWN",
        "Native external evidence: UNKNOWN",
        "Usage: not set (null)",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert!(
        text.contains(&format!("{:064x}", 3)),
        "missing task identity: {text}"
    );
}

#[test]
fn qualified_prices_reach_report_and_summary_without_double_counting_subsets() {
    use router_types::*;
    let dir = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(dir.path()).unwrap();
    let store = directory.join("feedback");
    let feedback_store = router_feedback::FeedbackStore::open(&store).unwrap();
    feedback_store
        .configure(
            FeedbackPreferences {
                collection_enabled: true,
                ..FeedbackPreferences::default()
            },
            100,
        )
        .unwrap();
    let mut input: Value = serde_json::from_slice(
        &fs::read(root().join("tests/fixtures/feedback/automated-unknown-v1.json")).unwrap(),
    )
    .unwrap();
    input["measurements"]["usage_scope"] = json!("per_attempt");
    input["measurements"]["usage"] = serde_json::to_value(HostUsage {
        input_tokens: UsageField::host_reported(100),
        cached_input_tokens: UsageField::host_reported(20),
        cache_write_input_tokens: UsageField::host_reported(30),
        output_tokens: UsageField::host_reported(40),
        reasoning_output_tokens: UsageField::host_reported(10),
    })
    .unwrap();
    feedback_store
        .record(serde_json::from_value(input).unwrap(), 102)
        .unwrap();
    drop(feedback_store);
    let pricing = directory.join("qualified-pricing.json");
    write(
        &pricing,
        &json!({"schema_version":2,"version":"synthetic-v2","source":"synthetic-test-only","observed_at_unix_seconds":90,"models":{"fixture-model":{
            "input_microusd_per_million":1000000,"cache_read_microusd_per_million":500000,
            "cache_write_microusd_per_million":2000000,"cache_write_scope":"all_reported_writes",
            "output_microusd_per_million":3000000,"reasoning":{"mode":"separate","microusd_per_million":4000000}
        }}}),
    );
    for subcommand in ["report", "summary"] {
        let output = feedback(
            &store,
            subcommand,
            &["--pricing", pricing.to_str().unwrap(), "--json"],
        )
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
        let report: Value = serde_json::from_slice(&output).unwrap();
        let cost = if subcommand == "report" {
            &report["groups"][0]["cost"]
        } else {
            &report["cost"]
        };
        // 50 ordinary input + 10 reads + 60 writes + 90 output + 40 reasoning.
        assert_eq!(cost["total_microusd"], 250);
        assert_eq!(cost["known_subtotal_microusd"], 250);
        assert_eq!(cost["runs_with_cache_writes_priced_as_input"], 0);
        assert_eq!(report["pricing"]["contract_version"], 2);
    }
}
