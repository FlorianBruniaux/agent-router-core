//! `schema`: every embedded output schema is structurally valid, and real
//! outputs of its contract conform to it. The checker is a small local one (see
//! `support/json_schema.rs`), not a full JSON Schema validator.
#[path = "support/json_schema.rs"]
mod json_schema;

use assert_cmd::Command;
use router_eval::{PricingTable, TokenPrice};
use router_feedback::{FeedbackStore, redacted_digest};
use router_runtime::{Runtime, RuntimeLimits};
use router_types::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

const NAMES: [&str; 6] = [
    "error",
    "feedback-report",
    "feedback-summary",
    "route-decision",
    "run-observation",
    "version",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn command() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("agent-router"))
}
fn stdout(mut command: Command) -> Vec<u8> {
    command.assert().success().get_output().stdout.clone()
}
fn schema(name: &str) -> Value {
    let mut cmd = command();
    cmd.args(["schema", name]);
    serde_json::from_slice(&stdout(cmd)).unwrap()
}
fn assert_conforms(name: &str, value: &Value) {
    let found = json_schema::violations(&schema(name), value);
    assert!(found.is_empty(), "{name}: {found:#?}\n{value}");
}

#[test]
fn list_names_every_contract_with_its_supported_versions() {
    let mut cmd = command();
    cmd.args(["schema", "--list"]);
    let out = stdout(cmd);
    let listing: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(listing["schema_version"], 1);
    let entries = listing["schemas"].as_array().unwrap();
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, NAMES);
    // The decision envelope carries a string version, every other output a number.
    let versions =
        |name: &str| entries.iter().find(|e| e["name"] == name).unwrap()["schema_versions"].clone();
    assert_eq!(versions("route-decision"), json!(["1"]));
    assert_eq!(versions("feedback-report"), json!([1, 2, 3, 4, 5]));
    assert_eq!(versions("run-observation"), json!([1, 2, 3]));
    assert_eq!(
        entries
            .iter()
            .find(|e| e["name"] == "run-observation")
            .unwrap()["command"],
        "observe --json"
    );
    let mut again = command();
    again.args(["schema", "--list"]);
    assert_eq!(out, stdout(again));
}

#[test]
fn every_listed_schema_is_structurally_valid_and_named_by_its_id() {
    for name in NAMES {
        let document = schema(name);
        json_schema::check_schema(&document);
        let id = document["$id"].as_str().unwrap();
        assert!(
            id.starts_with(&format!("urn:agent-router:schema:{name}:")),
            "{name}: {id}"
        );
    }
}

#[test]
fn schema_output_is_the_embedded_file_and_byte_identical() {
    for name in NAMES {
        let mut first = command();
        first.args(["schema", name]);
        let mut second = command();
        second.args(["schema", name]);
        let bytes = stdout(first);
        assert_eq!(bytes, stdout(second));
        let file = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/schemas")
                .join(format!("{name}.schema.json")),
        )
        .unwrap();
        assert_eq!(bytes, file, "{name}");
    }
}

#[test]
fn unknown_or_missing_names_are_refused_with_stable_errors() {
    command()
        .args(["schema", "nope"])
        .assert()
        .code(2)
        .stderr("error: schema.unknown\n");
    command()
        .args(["schema", "nope", "--json"])
        .assert()
        .code(2)
        .stderr("{\"schema_version\":1,\"error\":\"schema.unknown\"}\n");
    command()
        .arg("schema")
        .assert()
        .code(2)
        .stderr(predicates::str::starts_with("error: cli.invalid\n"));
    command()
        .args(["schema", "error", "--list"])
        .assert()
        .code(2)
        .stderr(predicates::str::starts_with("error: cli.invalid\n"));
}

fn route(request: &str) -> (Value, i32) {
    let output = command()
        .args(["route", "--request"])
        .arg(root().join("tests/fixtures/requests").join(request))
        .arg("--catalog")
        .arg(root().join("assets/catalogs/codex-core-v1.json"))
        .arg("--json")
        .output()
        .unwrap();
    (
        serde_json::from_slice(&output.stdout).unwrap(),
        output.status.code().unwrap(),
    )
}

#[test]
fn route_decisions_conform_to_the_route_decision_schema() {
    let (selected, code) = route("codex-implementation.json");
    assert_eq!(code, 0);
    assert!(selected["decision"]["selected"].is_object());
    assert_conforms("route-decision", &selected);
    let (no_route, code) = route("no-compatible-plan.json");
    assert_eq!(code, 3);
    assert!(no_route["decision"]["no_route"].is_object());
    assert_conforms("route-decision", &no_route);
    let stored: Value = serde_json::from_slice(
        &fs::read(root().join("tests/fixtures/decisions/codex-implementation.json")).unwrap(),
    )
    .unwrap();
    assert_conforms("route-decision", &stored);
}

#[test]
fn error_lines_conform_to_the_error_schema() {
    for args in [
        vec!["schema", "nope", "--json"],
        vec!["bogus-command", "--json"],
        vec!["route", "--json"],
    ] {
        let output = command().args(&args).output().unwrap();
        assert!(!output.status.success(), "{args:?}");
        let line: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_conforms("error", &line);
    }
}

#[test]
fn version_output_conforms_to_the_version_schema() {
    let mut cmd = command();
    cmd.args(["version", "--json"]);
    assert_conforms("version", &serde_json::from_slice(&stdout(cmd)).unwrap());
}

/// Synthetic durable history, following the runtime observation fixtures. No
/// provider is started. The JSON being validated comes from the real CLI reader.
fn observation_json(
    state: RunState,
    failure: Option<RunFailure>,
    cleanup: Option<ProcessCleanupEvidence>,
) -> Value {
    observation_json_version(state, failure, cleanup, None)
}
fn observation_json_version(
    state: RunState,
    failure: Option<RunFailure>,
    cleanup: Option<ProcessCleanupEvidence>,
    version: Option<&str>,
) -> Value {
    const PRIVATE: &str = "SCHEMA_PRIVATE_PROMPT_PATH_PROVIDER_CANARY";
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().canonicalize().unwrap().join("runtime");
    drop(Runtime::open(&store, RuntimeLimits::default()).unwrap());
    let attempts = u32::from(state != RunState::AwaitingApproval);
    let summary = RunSummary {
        run_id: PRIVATE.into(),
        definition_hash: "a".repeat(64),
        approval_digest: "b".repeat(64),
        receipt_id: PRIVATE.into(),
        plan_id: PRIVATE.into(),
        node_id: PRIVATE.into(),
        state,
        attempts,
        failure,
        worktree: Some(PRIVATE.into()),
        artifact_sha256: None,
        output_retention: OutputRetentionPolicy::Disabled,
        workflow: None,
        artifact_contract_sha256: None,
    };
    let mut db = rusqlite::Connection::open(store.join("runtime.sqlite3")).unwrap();
    let tx = db.transaction().unwrap();
    tx.execute(
        "INSERT INTO runs VALUES(?1,?2,?3,?4)",
        rusqlite::params![
            PRIVATE,
            PRIVATE,
            PRIVATE,
            serde_json::to_string(&summary).unwrap()
        ],
    )
    .unwrap();
    if attempts != 0 {
        tx.execute(
            "INSERT INTO run_attempts VALUES(?1,1,'finished')",
            [PRIVATE],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO attempt_leases VALUES(?1,1,?2,?3,?4)",
            rusqlite::params![
                PRIVATE,
                PRIVATE,
                u32::from(cleanup.is_some()),
                cleanup.map(|e| serde_json::to_string(&e).unwrap())
            ],
        )
        .unwrap();
    }
    let mut previous = String::new();
    let events = if attempts == 0 {
        vec![(RunState::Planned, "registered"), (state, "transition")]
    } else {
        vec![
            (RunState::Running, "attempt.started"),
            (state, "transition"),
        ]
    };
    for (index, (event_state, kind)) in events.into_iter().enumerate() {
        let sequence = index as u64 + 1;
        let mut hash = Sha256::new();
        hash.update(b"runtime-event-v1\0");
        hash.update(
            serde_json::to_vec(&(sequence, PRIVATE, kind, event_state, PRIVATE, &previous))
                .unwrap(),
        );
        let digest = hex::encode(hash.finalize());
        tx.execute(
            "INSERT INTO events VALUES(?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![
                sequence,
                PRIVATE,
                kind,
                serde_json::to_string(&event_state).unwrap(),
                PRIVATE,
                previous,
                digest
            ],
        )
        .unwrap();
        previous = digest;
    }
    tx.commit().unwrap();
    drop(db);
    let mut cmd = command();
    cmd.args(["observe", "--store"])
        .arg(&store)
        .args(["--run-id", PRIVATE, "--json"]);
    if let Some(version) = version {
        cmd.args(["--schema-version", version]);
    }
    let bytes = stdout(cmd);
    if version == Some("2") && attempts > 0 {
        let mut human = command();
        human.args(["observe", "--store"]).arg(&store).args([
            "--run-id",
            PRIVATE,
            "--schema-version",
            "2",
        ]);
        let human = String::from_utf8(stdout(human)).unwrap();
        for expected in [
            "Aggregate fields remain unknown",
            "Attempt 1",
            "Requested model: unknown",
            "Supervisor termination: unknown",
            "Exit code: unknown",
            "Evidence: unknown",
            "Capture: unknown",
            "Protocol: unknown",
        ] {
            assert!(human.contains(expected), "missing {expected}: {human}");
        }
    }
    assert!(!String::from_utf8_lossy(&bytes).contains(PRIVATE));
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn run_observation_schema_accepts_emitted_failures_and_persisted_cleanup() {
    for (state, failure, cleanup, expected) in [
        (RunState::AwaitingApproval, None, None, "unknown"),
        (RunState::Failed, Some(RunFailure::Crash), None, "unknown"),
        (
            RunState::Failed,
            Some(RunFailure::Spawn),
            Some(ProcessCleanupEvidence::NotStarted),
            "not_started",
        ),
        (
            RunState::Cancelled,
            None,
            Some(ProcessCleanupEvidence::GroupTerminated),
            "group_terminated",
        ),
        (
            RunState::Cancelled,
            None,
            Some(ProcessCleanupEvidence::NamespaceTerminated),
            "namespace_terminated",
        ),
    ] {
        let output = observation_json(state, failure, cleanup);
        assert_eq!(
            output["known"]["state"],
            serde_json::to_value(state).unwrap()
        );
        assert_eq!(
            output["known"]["failure"],
            serde_json::to_value(failure).unwrap()
        );
        assert_eq!(output["known"]["cleanup"], expected);
        assert_eq!(output["unknown"]["objective"], "unknown");
        assert_conforms("run-observation", &output);
    }
}

#[test]
fn run_observation_schema_rejects_private_fields_and_invalid_contract_values() {
    let document = schema("run-observation");
    let output = observation_json(RunState::Failed, Some(RunFailure::Crash), None);
    assert!(json_schema::violations(&document, &output).is_empty());
    let rejects = |pointer: &str, value: Value| {
        let mut invalid = output.clone();
        *invalid.pointer_mut(pointer).unwrap() = value;
        assert!(
            !json_schema::violations(&document, &invalid).is_empty(),
            "accepted invalid {pointer}: {invalid}"
        );
    };
    for pointer in [
        "/snapshot_sha256",
        "/identity/run_key_sha256",
        "/identity/definition_sha256",
        "/identity/receipt_id_sha256",
        "/identity/plan_id_sha256",
        "/identity/node_id_sha256",
        "/horizon/event_sha256",
        "/known/events/0/event_sha256",
    ] {
        for digest in [
            "G".repeat(64),
            "A".repeat(64),
            "a".repeat(63),
            "a".repeat(65),
        ] {
            rejects(pointer, json!(digest));
        }
    }
    for (pointer, invalid) in [
        ("/schema_version", json!(2)),
        ("/known/state", json!("successful")),
        ("/known/failure", json!("provider_failed")),
        ("/known/cleanup", json!("process_stopped")),
        ("/known/events/0/state", json!("successful")),
        ("/known/attempts", json!(-1)),
        ("/known/attempts", json!(6)),
        ("/known/attempts", json!(1.5)),
        ("/horizon/sequence", json!(-1)),
        ("/horizon/sequence", json!(100_001)),
        ("/known/events/0/sequence", json!(0)),
        ("/known/events/0/sequence", json!(100_001)),
        ("/unknown/observed_model", json!("host-reported-model")),
        ("/unknown/duration", json!(12)),
        ("/completeness/journal", json!("truncated")),
        ("/completeness/external_observations", json!("complete")),
        ("/completeness/detail", json!("private")),
    ] {
        rejects(pointer, invalid);
    }
    for pointer in [
        "",
        "/identity",
        "/horizon",
        "/known",
        "/known/events/0",
        "/unknown",
        "/completeness",
    ] {
        let mut invalid = output.clone();
        invalid
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "private_detail".into(),
                json!("prompt/path/provider-response"),
            );
        assert!(
            !json_schema::violations(&document, &invalid).is_empty(),
            "{pointer}"
        );
        for name in output.pointer(pointer).unwrap().as_object().unwrap().keys() {
            let mut missing = output.clone();
            missing
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(name);
            assert!(
                !json_schema::violations(&document, &missing).is_empty(),
                "accepted missing {pointer}/{name}"
            );
        }
    }
    for name in output["unknown"].as_object().unwrap().keys() {
        rejects(&format!("/unknown/{name}"), json!("known"));
        rejects(&format!("/unknown/{name}"), Value::Null);
    }
    let event = output["known"]["events"][0].clone();
    rejects("/known/events", json!([]));
    rejects("/known/events", json!(vec![event.clone(); 4097]));
    let mut at_limit = output.clone();
    at_limit["known"]["events"] = json!(vec![event; 4096]);
    assert!(json_schema::violations(&document, &at_limit).is_empty());
    at_limit["horizon"]["event_sha256"] = Value::Null;
    assert!(json_schema::violations(&document, &at_limit).is_empty());
}

#[test]
fn bounded_schema_checker_checks_digest_patterns_and_exact_integer_maxima() {
    let document = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:test:bounded-checker",
        "type": "object",
        "properties": {
            "digest": {"type":"string", "pattern":"^[0-9a-f]{64}$"},
            "events": {"type":"array", "maxItems":1},
            "ordinal": {"type":"integer", "maximum":u64::MAX - 1}
        }
    });
    json_schema::check_schema(&document);
    let valid = json!({"digest":"a".repeat(64), "events":[0], "ordinal":u64::MAX - 1});
    assert!(json_schema::violations(&document, &valid).is_empty());
    for (key, value) in [
        ("digest", json!("G".repeat(64))),
        ("digest", json!("é".repeat(64))),
        ("digest", json!("a".repeat(64) + "\n")),
        ("events", json!([0, 1])),
        ("ordinal", json!(u64::MAX)),
    ] {
        let mut invalid = valid.clone();
        invalid[key] = value;
        assert!(
            !json_schema::violations(&document, &invalid).is_empty(),
            "{key}"
        );
    }
}

fn key(c: char) -> String {
    c.to_string().repeat(64)
}
fn automated(run: &str, run_key: char, model: &str) -> FeedbackInput {
    FeedbackInput {
        schema_version: 1,
        observed_at_unix_seconds: 130,
        started_at_unix_seconds: Some(120),
        run_key_sha256: Some(key(run_key)),
        binding: FeedbackBinding {
            task_hash: "a".repeat(64),
            run_hash: redacted_digest(run).unwrap(),
            receipt_hash: "b".repeat(64),
            policy_hash: "c".repeat(64),
            catalog_hash: "d".repeat(64),
            snapshot_hash: "e".repeat(64),
            producer_version: "synthetic-v1".into(),
            provenance_sha256: "f".repeat(64),
        },
        context: FeedbackContext {
            task_kind: TaskKind::Explore,
            risk: RiskLevel::Low,
            model: ModelId::parse(model).unwrap(),
            effort: EffortLevel::Medium,
            harness: HarnessId::parse("fixture-host").unwrap(),
            transport: "subprocess-jsonl".into(),
            agent: None,
            skills: BTreeSet::new(),
            plan: "single-pass".into(),
            propensity_micros: None,
            route: None,
        },
        origin: FeedbackOrigin::Automated,
        transport: VerificationOutcome::Passed,
        validation: VerificationOutcome::Unknown,
        objective: VerificationOutcome::Unknown,
        verification_evidence_sha256: None,
        human: None,
        failure: None,
        measurements: FeedbackMeasurements {
            usage_scope: None,
            cost_microusd: None,
            latency_ms: Some(100),
            tokens: Some(1500),
            attempts: 1,
            escalations: 0,
            usage: Some(HostUsage {
                input_tokens: UsageField::host_reported(1000),
                cached_input_tokens: UsageField::host_reported(0),
                cache_write_input_tokens: UsageField::UNKNOWN,
                output_tokens: UsageField::host_reported(500),
                reasoning_output_tokens: UsageField::UNKNOWN,
            }),
        },
        comment_sha256: None,
    }
}
fn fact(run_key: char, kind: FeedbackFactKind, at: u64) -> FeedbackFact {
    FeedbackFact {
        schema_version: 1,
        run_key_sha256: key(run_key),
        observed_at_unix_seconds: at,
        kind,
    }
}

/// A store holding accepted, rejected and unknown runs over two models, built
/// with the library because the CLI records no late fact.
fn populated_store(directory: &Path) -> PathBuf {
    let path = directory.join("feedback");
    let store = FeedbackStore::open(&path).unwrap();
    store
        .configure(
            FeedbackPreferences {
                collection_enabled: true,
                learning_enabled: true,
                ..Default::default()
            },
            100,
        )
        .unwrap();
    for (run, run_key, model) in [
        ("r1", '1', "model-a"),
        ("r2", '2', "model-a"),
        ("r3", '3', "model-b"),
    ] {
        store.record(automated(run, run_key, model), 200).unwrap();
    }
    let passed = |c| {
        fact(
            c,
            FeedbackFactKind::Verification {
                validation: VerificationOutcome::Passed,
                objective: VerificationOutcome::Passed,
                evidence_sha256: "9".repeat(64),
            },
            250,
        )
    };
    let applied = |c, at| {
        fact(
            c,
            FeedbackFactKind::Integration {
                outcome: IntegrationOutcome::Applied,
            },
            at,
        )
    };
    let discarded = fact(
        '2',
        FeedbackFactKind::Integration {
            outcome: IntegrationOutcome::Discarded,
        },
        260,
    );
    for f in [passed('1'), applied('1', 260), discarded, passed('3')] {
        store.record_fact(f, 270).unwrap();
    }
    path
}

fn write_pricing(directory: &Path) -> PathBuf {
    let pricing = directory.join("pricing.json");
    let table = PricingTable {
        schema_version: 1,
        version: "schema-test-v1".into(),
        source: "synthetic".into(),
        observed_at_unix_seconds: 90,
        models: [(
            ModelId::parse("model-a").unwrap(),
            TokenPrice {
                input_microusd_per_million: 3_000_000,
                cached_input_microusd_per_million: 300_000,
                output_microusd_per_million: 15_000_000,
            },
        )]
        .into(),
    };
    fs::write(&pricing, serde_json::to_vec(&table).unwrap()).unwrap();
    pricing
}

fn feedback_json(store: &Path, subcommand: &str, pricing: Option<&Path>) -> Value {
    let mut cmd = command();
    cmd.args(["feedback", "--store"])
        .arg(store)
        .arg(subcommand)
        .args(["--now", "300", "--json"]);
    if let Some(pricing) = pricing {
        cmd.arg("--pricing").arg(pricing);
    }
    serde_json::from_slice(&stdout(cmd)).unwrap()
}

#[test]
fn feedback_report_and_summary_conform_to_their_schemas() {
    let dir = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(dir.path()).unwrap();
    let store = populated_store(&directory);
    let pricing = write_pricing(&directory);
    for priced in [false, true] {
        let pricing = priced.then_some(pricing.as_path());
        let report = feedback_json(&store, "report", pricing);
        assert_eq!(report["groups"].as_array().unwrap().len(), 2);
        assert_conforms("feedback-report", &report);
        let summary = feedback_json(&store, "summary", pricing);
        assert_eq!(summary["runs"], 3);
        assert_eq!(summary["accepted"], 1);
        assert_eq!(summary["rejected"], 1);
        assert_eq!(summary["unknown"], 1);
        assert!(summary["accepted_rate"].is_object());
        assert_conforms("feedback-summary", &summary);
    }
    // Model-b is unpriced: retain the known subtotal but no complete total or ratio.
    let summary = feedback_json(&store, "summary", Some(&pricing));
    assert!(summary["cost"]["known_subtotal_microusd"].is_u64());
    assert!(summary["cost"]["total_microusd"].is_null());
    assert!(summary["cost"]["per_accepted_microusd"].is_null());
    assert_eq!(summary["cost"]["reason"], "cost_unknown_runs");
}

/// Learning disabled, a human event, and a group whose runs have no verdict.
/// With `with_accepted` a second group holds one accepted run.
fn undecided_store(directory: &Path, with_accepted: bool) -> PathBuf {
    let path = directory.join("feedback");
    let store = FeedbackStore::open(&path).unwrap();
    store
        .configure(
            FeedbackPreferences {
                collection_enabled: true,
                learning_enabled: false,
                ..Default::default()
            },
            100,
        )
        .unwrap();
    let pending = automated("pending", '4', "model-c");
    store.record(pending.clone(), 200).unwrap();
    let mut human = pending;
    human.origin = FeedbackOrigin::Human;
    human.human = Some(HumanVerdict {
        success: VerificationOutcome::Passed,
        quality: Some(80),
        perceived_cost: PerceivedCost::Low,
        correction_required: None,
        reviewer_sha256: "2".repeat(64),
    });
    store.record(human, 200).unwrap();
    if with_accepted {
        store
            .record(automated("done", '1', "model-a"), 200)
            .unwrap();
        for f in [
            fact(
                '1',
                FeedbackFactKind::Verification {
                    validation: VerificationOutcome::Passed,
                    objective: VerificationOutcome::Passed,
                    evidence_sha256: "9".repeat(64),
                },
                250,
            ),
            fact(
                '1',
                FeedbackFactKind::Integration {
                    outcome: IntegrationOutcome::Applied,
                },
                260,
            ),
        ] {
            store.record_fact(f, 270).unwrap();
        }
    }
    path
}

#[test]
fn feedback_outputs_with_null_figures_and_disabled_learning_conform() {
    for with_accepted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let directory = fs::canonicalize(dir.path()).unwrap();
        let store = undecided_store(&directory, with_accepted);
        let report = feedback_json(&store, "report", None);
        assert_eq!(report["human_events"], 1);
        assert!(report["advisory"]["advisory"].is_null());
        assert_eq!(report["advisory"]["reason"], "learning_disabled");
        let group = report["groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["model"] == "model-c")
            .unwrap();
        assert!(group["accepted_rate"].is_null());
        assert!(group["time_to_acceptance_seconds"]["p50"].is_null());
        assert_eq!(group["human"]["passed"], 1);
        assert_conforms("feedback-report", &report);
        let summary = feedback_json(&store, "summary", None);
        assert_eq!(summary["human"]["passed"], 1);
        assert_eq!(summary["accepted_rate"].is_null(), !with_accepted);
        assert_eq!(
            summary["time_to_acceptance_seconds"]["p50"].is_null(),
            !with_accepted
        );
        assert_conforms("feedback-summary", &summary);
    }
}

#[test]
fn the_feedback_schemas_reject_outputs_that_break_their_contract() {
    let dir = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(dir.path()).unwrap();
    let store = populated_store(&directory);
    let pricing = write_pricing(&directory);
    for (name, subcommand) in [
        ("feedback-report", "report"),
        ("feedback-summary", "summary"),
    ] {
        let real = feedback_json(&store, subcommand, Some(&pricing));
        assert_conforms(name, &real);
        let broken = |mutate: &dyn Fn(&mut Value)| {
            let mut value = real.clone();
            mutate(&mut value);
            json_schema::violations(&schema(name), &value)
        };
        assert!(
            !broken(&|v| v["extra"] = json!(1)).is_empty(),
            "{name}: extra key"
        );
        assert!(
            !broken(&|v| v["schema_version"] = json!(99)).is_empty(),
            "{name}: version"
        );
        assert!(
            !broken(&|v| drop(v.as_object_mut().unwrap().remove("content_hash"))).is_empty(),
            "{name}: missing field"
        );
        assert!(
            !broken(&|v| v["content_hash"] = json!("short")).is_empty(),
            "{name}: hash length"
        );
        assert!(
            !broken(&|v| v["cost_placeholder"] = json!(null)).is_empty(),
            "{name}: unknown key"
        );
    }
    let report = feedback_json(&store, "report", Some(&pricing));
    let mut nested = report.clone();
    nested["groups"][0]["cost"]["total_microusd"] = json!("9");
    assert!(!json_schema::violations(&schema("feedback-report"), &nested).is_empty());
    let mut nested = report;
    nested["groups"][0]["accepted"] = json!(-1);
    assert!(!json_schema::violations(&schema("feedback-report"), &nested).is_empty());
    let mut summary = feedback_json(&store, "summary", Some(&pricing));
    summary["attribution"] = json!("established");
    assert!(!json_schema::violations(&schema("feedback-summary"), &summary).is_empty());
    let mut summary = feedback_json(&store, "summary", Some(&pricing));
    summary["unknown_counts"]["verdict"] = json!(null);
    assert!(!json_schema::violations(&schema("feedback-summary"), &summary).is_empty());
}

#[test]
fn the_checker_rejects_outputs_that_break_their_contract() {
    let (selected, _) = route("codex-implementation.json");
    let broken = |mutate: &dyn Fn(&mut Value)| {
        let mut value = selected.clone();
        mutate(&mut value);
        json_schema::violations(&schema("route-decision"), &value)
    };
    assert!(!broken(&|v| v["extra"] = json!(1)).is_empty());
    assert!(!broken(&|v| v["schema_version"] = json!(1)).is_empty());
    assert!(!broken(&|v| drop(v.as_object_mut().unwrap().remove("decision_id"))).is_empty());
    assert!(!broken(&|v| v["decision"] = json!({"selected": {}, "no_route": {}})).is_empty());
    let error = json_schema::violations(&schema("error"), &json!({"schema_version": 1}));
    assert!(!error.is_empty());
    let version = json_schema::violations(
        &schema("version"),
        &json!({"schema_version":1,"version":"1","target":"t","features":[],"contracts":{"x":{"command":"c","schema_versions":[]}}}),
    );
    assert!(!version.is_empty());
}

#[test]
fn feedback_schema_keeps_legacy_shapes_strict_and_requires_attempt_coverage() {
    let dir = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(dir.path()).unwrap();
    let store = populated_store(&directory);
    let report = feedback_json(&store, "report", None);
    assert_eq!(report["schema_version"], 3);
    assert_conforms("feedback-report", &report);
    let coverage = [
        "known_subtotal_microusd",
        "expected_attempts",
        "observed_attempts",
        "priced_attempts",
        "missing_attempts",
        "conflicting_attempts",
        "scope_unknown_runs",
    ];
    // Published v2 costs retain their shape; the current fields cannot sneak
    // into historical contracts by changing only the version number.
    let mut legacy = report.clone();
    legacy["schema_version"] = json!(2);
    assert!(!json_schema::violations(&schema("feedback-report"), &legacy).is_empty());
    for group in legacy["groups"].as_array_mut().unwrap() {
        for field in coverage {
            group["cost"].as_object_mut().unwrap().remove(field);
        }
    }
    for run in legacy["runs"].as_array_mut().unwrap() {
        run.as_object_mut().unwrap().remove("cost");
    }
    assert_conforms("feedback-report", &legacy);
    let mut summary = feedback_json(&store, "summary", None);
    assert_eq!(summary["schema_version"], 2);
    assert_conforms("feedback-summary", &summary);
    summary["schema_version"] = json!(1);
    assert!(!json_schema::violations(&schema("feedback-summary"), &summary).is_empty());
    for field in coverage {
        summary["cost"].as_object_mut().unwrap().remove(field);
    }
    assert_conforms("feedback-summary", &summary);
    // The historical v1 output shape remains accepted, with no run rows.
    legacy.as_object_mut().unwrap().remove("runs");
    legacy["schema_version"] = json!(1);
    assert_conforms("feedback-report", &legacy);
    legacy["runs"] = report["runs"].clone();
    assert!(!json_schema::violations(&schema("feedback-report"), &legacy).is_empty());
    for mutate in [
        (|v: &mut Value| {
            v.as_object_mut().unwrap().remove("runs");
        }) as fn(&mut Value),
        |v| v["runs"][0]["evidence"]["runtime_evidence"] = json!("passed"),
        |v| v["runs"][0]["evidence"]["native_external_evidence"] = json!("passed"),
        |v| v["runs"][0]["evidence"]["source"] = json!("native_external"),
        |v| v["runs"][0]["binding"]["receipt_hash"] = json!("invented"),
        |v| v["runs"][0]["verdict"] = json!("success"),
        |v| {
            v["runs"][0]["cost"]
                .as_object_mut()
                .unwrap()
                .remove("missing_attempts");
        },
        |v| v["groups"][0]["cost"]["priced_attempts"] = json!(-1),
        |v| v["runs"][0]["usage"]["input_tokens"]["tokens"] = json!(null),
    ] {
        let mut invalid = report.clone();
        mutate(&mut invalid);
        assert!(
            !json_schema::violations(&schema("feedback-report"), &invalid).is_empty(),
            "{invalid}"
        );
    }
}

#[test]
fn runtime_reconciled_reports_have_strict_versioned_public_schemas() {
    let dir = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(dir.path()).unwrap();
    let store = populated_store(&directory);
    let runtime_path = directory.join("runtime");
    drop(
        router_runtime::Runtime::open(&runtime_path, router_runtime::RuntimeLimits::default())
            .unwrap(),
    );
    for (name, subcommand, version) in [
        ("feedback-report", "report", 4),
        ("feedback-summary", "summary", 3),
    ] {
        let mut cmd = command();
        cmd.args(["feedback", "--store"])
            .arg(&store)
            .arg(subcommand)
            .arg("--runtime-store")
            .arg(&runtime_path)
            .args(["--now", "300", "--json"]);
        let output: Value = serde_json::from_slice(&stdout(cmd)).unwrap();
        assert_eq!(output["schema_version"], version);
        assert_conforms(name, &output);
        let mut missing = output.clone();
        missing.as_object_mut().unwrap().remove("task_measurement");
        assert!(!json_schema::violations(&schema(name), &missing).is_empty());
        let mut legacy = output.clone();
        legacy["schema_version"] = json!(version - 1);
        assert!(!json_schema::violations(&schema(name), &legacy).is_empty());
        let mut malformed = output;
        malformed["task_measurement"]["expected_attempts"] = json!(-1);
        assert!(!json_schema::violations(&schema(name), &malformed).is_empty());
    }
}

#[test]
fn qualified_pricing_reports_publish_a_distinct_schema_with_explicit_contract_version() {
    let dir = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(dir.path()).unwrap();
    let store = populated_store(&directory);
    let pricing = directory.join("qualified.json");
    fs::write(&pricing,serde_json::to_vec(&json!({"schema_version":2,"version":"fixture-v2","source":"synthetic","observed_at_unix_seconds":90,"models":{}})).unwrap()).unwrap();
    for (name, subcommand, version) in [
        ("feedback-report", "report", 5),
        ("feedback-summary", "summary", 4),
    ] {
        let output = feedback_json(&store, subcommand, Some(&pricing));
        assert_eq!(output["schema_version"], version);
        assert_conforms(name, &output);
        let mut invalid = output.clone();
        invalid["pricing"]
            .as_object_mut()
            .unwrap()
            .remove("contract_version");
        assert!(!json_schema::violations(&schema(name), &invalid).is_empty());
        let mut legacy = output;
        legacy["schema_version"] = json!(version - 1);
        assert!(!json_schema::violations(&schema(name), &legacy).is_empty());
    }
}

#[test]
fn run_observation_v2_schema_requires_complete_strict_attempt_branches() {
    let document = schema("run-observation");
    let mut v2 = observation_json(RunState::Failed, Some(RunFailure::Crash), None);
    v2["schema_version"] = json!(2);
    let digest = "a".repeat(64);
    let mut attempt = json!({
        "ordinal": 1, "attempt_key_sha256": digest,
        "evidence": "unknown", "requested": null, "transport": null,
        "sources": {"started_event_sha256": digest, "attempt_evidence_sha256": null,
            "finished_event_sha256": null, "transition_event_sha256": null,
            "output_incomplete_event_sha256": null, "protocol_event_sha256": null},
        "capture": "unknown", "protocol": "unknown",
        "native": {"observed_model": "unknown", "observed_effort": "unknown",
        "thread_id": "unknown", "turn_id": "unknown", "usage": "unknown",
        "notification_delivery": "unknown", "lost_notifications": "unknown",
        "duration": "unknown", "validation": "unknown", "objective": "unknown"}
    });
    v2["attempts"] = json!([attempt]);
    assert!(
        json_schema::violations(&document, &v2).is_empty(),
        "missing evidence is visible"
    );
    attempt["evidence"] = json!("durable_attempt");
    attempt["requested"] = json!({"model": "provider/model-v1", "effort": "high"});
    attempt["transport"] = json!({"termination": "exited", "exit_code": 0});
    for name in [
        "attempt_evidence_sha256",
        "finished_event_sha256",
        "transition_event_sha256",
    ] {
        attempt["sources"][name] = json!(digest);
    }
    v2["attempts"] = json!([attempt]);
    assert!(json_schema::violations(&document, &v2).is_empty());
    for termination in ["exited", "timed_out", "cancelled", "killed", "spawn_failed"] {
        v2["attempts"][0]["transport"]["termination"] = json!(termination);
        for exit in [json!(null), json!(0), json!(-1)] {
            v2["attempts"][0]["transport"]["exit_code"] = exit;
            assert!(json_schema::violations(&document, &v2).is_empty());
        }
    }
    for capture in [
        "unknown",
        "incomplete",
        "output_limit",
        "output_limit_incomplete",
    ] {
        v2["attempts"][0]["capture"] = json!(capture);
        v2["attempts"][0]["sources"]["output_incomplete_event_sha256"] =
            if capture.contains("incomplete") {
                json!(digest)
            } else {
                Value::Null
            };
        assert!(json_schema::violations(&document, &v2).is_empty());
    }
    let rejects = |pointer: &str, replacement: Value| {
        let mut bad = v2.clone();
        *bad.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            !json_schema::violations(&document, &bad).is_empty(),
            "accepted {pointer}: {bad}"
        );
    };
    for (pointer, value) in [
        ("/schema_version", json!(3)),
        ("/attempts", json!(null)),
        ("/attempts/0/ordinal", json!(0)),
        ("/attempts/0/ordinal", json!(6)),
        ("/attempts/0/attempt_key_sha256", json!("private")),
        ("/attempts/0/evidence", json!("native")),
        ("/attempts/0/requested", json!(null)),
        ("/attempts/0/requested/model", json!("unsafe model")),
        ("/attempts/0/requested/model", json!("model\n")),
        ("/attempts/0/requested/model", json!("a".repeat(257))),
        ("/attempts/0/requested/model", json!("")),
        ("/attempts/0/requested/effort", json!("superhigh")),
        ("/attempts/0/transport", json!(null)),
        ("/attempts/0/transport/termination", json!("success")),
        ("/attempts/0/transport/exit_code", json!(2147483648u64)),
        ("/attempts/0/sources/attempt_evidence_sha256", json!(null)),
        ("/attempts/0/sources/protocol_event_sha256", json!(digest)),
        (
            "/attempts/0/sources/output_incomplete_event_sha256",
            json!(null),
        ),
        ("/attempts/0/capture", json!("complete")),
        ("/attempts/0/protocol", json!("observed")),
        ("/attempts/0/native/usage", json!(0)),
        ("/attempts/0/native/duration", json!(1)),
        ("/attempts/0/native/validation", json!("passed")),
        ("/attempts/0/native/objective", json!("passed")),
    ] {
        rejects(pointer, value);
    }
    for pointer in [
        "",
        "/attempts/0",
        "/attempts/0/requested",
        "/attempts/0/transport",
        "/attempts/0/sources",
        "/attempts/0/native",
    ] {
        let mut bad = v2.clone();
        bad.pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("private".into(), json!("leak"));
        assert!(!json_schema::violations(&document, &bad).is_empty());
    }
    for pointer in [
        "",
        "/attempts/0",
        "/attempts/0/requested",
        "/attempts/0/transport",
        "/attempts/0/sources",
        "/attempts/0/native",
    ] {
        for name in v2.pointer(pointer).unwrap().as_object().unwrap().keys() {
            let mut bad = v2.clone();
            bad.pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(name);
            assert!(
                !json_schema::violations(&document, &bad).is_empty(),
                "accepted missing {pointer}/{name}"
            );
        }
    }
}

#[test]
fn run_observation_v2_emits_missing_evidence_without_inferred_native_facts() {
    let output =
        observation_json_version(RunState::Failed, Some(RunFailure::Crash), None, Some("2"));
    assert_eq!(output["schema_version"], 2);
    assert_eq!(output["attempts"][0]["evidence"], "unknown");
    assert_eq!(output["attempts"][0]["requested"], Value::Null);
    assert_eq!(output["attempts"][0]["transport"], Value::Null);
    assert_eq!(output["attempts"][0]["native"]["usage"], "unknown");
    assert_conforms("run-observation", &output);
}

#[test]
fn run_observation_v3_schema_qualifies_only_local_intervals() {
    let document = schema("run-observation");
    let output =
        observation_json_version(RunState::Failed, Some(RunFailure::Crash), None, Some("3"));
    assert_eq!(output["schema_version"], 3);
    assert_eq!(
        output["timings"][0]["measurement"],
        json!({"status":"unknown","reason":"missing_record"})
    );
    assert_conforms("run-observation", &output);
    let mut known = output.clone();
    known["timings"][0]["measurement"] = json!({"status":"known","duration_ms":0});
    known["timings"][0]["timing_event_sha256"] = json!("a".repeat(64));
    assert!(json_schema::violations(&document, &known).is_empty());
    for (pointer, value) in [
        ("/timings/0/measurement/duration_ms", json!(-1)),
        ("/timings/0/measurement/status", json!("estimated")),
        ("/timings/0/scope", json!("native_model")),
        ("/timings/0/clock", json!("wall_clock")),
        ("/timings/0/ordinal", json!(6)),
        ("/timings/0/timing_event_sha256", json!("not-a-hash")),
        ("/attempts/0/native/duration", json!(0)),
        ("/unknown/duration", json!(0)),
    ] {
        let mut invalid = known.clone();
        *invalid.pointer_mut(pointer).unwrap() = value;
        assert!(
            !json_schema::violations(&document, &invalid).is_empty(),
            "accepted {pointer}"
        );
    }
    for key in known["timings"][0].as_object().unwrap().keys() {
        let mut invalid = known.clone();
        invalid["timings"][0].as_object_mut().unwrap().remove(key);
        assert!(
            !json_schema::violations(&document, &invalid).is_empty(),
            "accepted missing {key}"
        );
    }
}
