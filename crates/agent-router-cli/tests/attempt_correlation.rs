use router_feedback::{
    AttemptCorrelationInput, attempt_correlation_report, calculate_attempt_correlation,
};
use router_runtime::{Runtime, RuntimeLimits, observe_run_v2, observe_run_v3};
use router_types::{OutputRetentionPolicy, RunState, RunSummary, RuntimeEvent};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

const FIXTURE: &str =
    include_str!("../../../tests/fixtures/evaluation/attempt-correlation-v1.json");
const PRIVATE: &str = "PRIVATE_PROMPT_PROVIDER_SECRET_CANARY";
const REJECTED_SECRET: &str = "REJECTED_UNKNOWN_FIELD_SECRET_CANARY";

fn digest(label: &str) -> String {
    hex::encode(Sha256::digest(label.as_bytes()))
}

fn invoke(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agent-router"))
        .current_dir(dir)
        .env("HOME", dir)
        .args(args)
        .output()
        .unwrap()
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn append(db: &Connection, state: RunState, kind: &str, detail: &str) {
    let (sequence, previous): (u64, String) = db
        .query_row(
            "SELECT sequence,event_hash FROM events ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or((0, String::new()));
    let mut event = RuntimeEvent {
        sequence: sequence + 1,
        run_id: PRIVATE.into(),
        kind: kind.into(),
        state,
        detail: detail.into(),
        previous_hash: previous,
        event_hash: String::new(),
    };
    let mut hasher = Sha256::new();
    hasher.update(b"runtime-event-v1\0");
    hasher.update(
        serde_json::to_vec(&(
            event.sequence,
            &event.run_id,
            &event.kind,
            event.state,
            &event.detail,
            &event.previous_hash,
        ))
        .unwrap(),
    );
    event.event_hash = hex::encode(hasher.finalize());
    db.execute(
        "INSERT INTO events VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            event.sequence,
            event.run_id,
            event.kind,
            serde_json::to_string(&event.state).unwrap(),
            event.detail,
            event.previous_hash,
            event.event_hash,
        ],
    )
    .unwrap();
}

fn seeded_runtime_store() -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("runtime");
    drop(Runtime::open(&root, RuntimeLimits::default()).unwrap());
    let db = Connection::open(root.join("runtime.sqlite3")).unwrap();
    let summary = RunSummary {
        run_id: PRIVATE.into(),
        definition_hash: "a".repeat(64),
        approval_digest: "b".repeat(64),
        receipt_id: PRIVATE.into(),
        plan_id: PRIVATE.into(),
        node_id: PRIVATE.into(),
        state: RunState::SucceededTransport,
        attempts: 1,
        failure: None,
        worktree: Some(PRIVATE.into()),
        artifact_sha256: None,
        output_retention: OutputRetentionPolicy::Disabled,
        workflow: None,
        artifact_contract_sha256: None,
    };
    db.execute(
        "INSERT INTO runs VALUES(?1,?1,?1,?2)",
        params![PRIVATE, serde_json::to_string(&summary).unwrap()],
    )
    .unwrap();
    db.execute("INSERT INTO run_attempts VALUES(?1,1,'started')", [PRIVATE])
        .unwrap();
    append(&db, RunState::Preparing, "attempt.started", "");
    append(&db, RunState::Running, "transition", "prepared");
    append(&db, RunState::Running, "attempt.finished", "observed");
    append(
        &db,
        RunState::SucceededTransport,
        "transition",
        "transport_observed",
    );
    drop(db);
    (temp, root)
}

fn emitted_observation() -> Value {
    let (_temp, root) = seeded_runtime_store();
    serde_json::to_value(observe_run_v2(&root, PRIVATE).unwrap()).unwrap()
}

fn durable_observation() -> Value {
    let mut observation = emitted_observation();
    let attempt = &mut observation["attempts"][0];
    attempt["evidence"] = json!("durable_attempt");
    attempt["requested"] = json!({"model":"gpt-5.6-sol","effort":"high"});
    attempt["transport"] = json!({"termination":"exited","exit_code":0});
    attempt["sources"]["attempt_evidence_sha256"] = json!(digest("evidence"));
    attempt["sources"]["finished_event_sha256"] = json!(digest("finished"));
    attempt["sources"]["transition_event_sha256"] = json!(digest("transition"));
    observation
}

// A synthetic journal passed through the real v3 producer. No process is spawned.
fn timed_observation(measurement: Value) -> Value {
    let (_temp, root) = seeded_runtime_store();
    let db = Connection::open(root.join("runtime.sqlite3")).unwrap();
    let event_hash = |kind: &str| -> String {
        db.query_row(
            "SELECT event_hash FROM events WHERE kind=?1 ORDER BY sequence DESC LIMIT 1",
            [kind],
            |row| row.get(0),
        )
        .unwrap()
    };
    let evidence = json!({
        "schema_version":1, "identity":{"run_id":PRIVATE,"attempt":1},
        "definition_hash":"a".repeat(64), "authorization_id":PRIVATE,
        "decision_origin":"deterministic", "sandbox":"read_only",
        "context_hash":"c".repeat(64), "pool_hash":"d".repeat(64),
        "source_state":PRIVATE, "task_execution_sha256":"e".repeat(64),
        "candidate_id":PRIVATE, "model":"gpt-5.6-sol", "effort":"high", "workflow":null,
        "state":"succeeded_transport", "failure":null,
        "transport":{"termination":"exited","exit_code":0,"elapsed_ms":0},
        "cleanup":"unknown", "observed_cost_microusd":null, "observed_tokens":null,
        "started_event_hash":event_hash("attempt.started"),
        "finished_event_hash":event_hash("attempt.finished"),
        "transition_event_hash":event_hash("transition")
    });
    db.execute("UPDATE run_attempts SET status='observed'", [])
        .unwrap();
    append(
        &db,
        RunState::SucceededTransport,
        "attempt.evidence.v1",
        &evidence.to_string(),
    );
    let timing = json!({"schema_version":1,"ordinal":1,
        "attempt_evidence_sha256":event_hash("attempt.evidence.v1"),
        "producer":"capture_guarded_v1","scope":"supervisor_capture",
        "clock":"monotonic_same_invocation","start_boundary":"before_dispatch_validation",
        "end_boundary":"after_reap_and_both_output_drains","precision":"milliseconds_truncated",
        "measurement":measurement});
    append(
        &db,
        RunState::SucceededTransport,
        "attempt.timing.v1",
        &timing.to_string(),
    );
    drop(db);
    serde_json::to_value(observe_run_v3(&root, PRIVATE).unwrap()).unwrap()
}

#[test]
fn observe_v3_qualified_timings_keep_the_existing_b1_report_contract() {
    let dir = tempfile::tempdir().unwrap();
    let observation_path = dir.path().join("observation.json");
    let physical_path = dir.path().join("physical.json");
    let authority = digest("runtime-authority");
    write_json(&physical_path, &json!({"schema_version":1,"physical":[]}));
    for measurement in [
        json!({"status":"known","duration_ms":0}),
        json!({"status":"unknown","reason":"clock_regression"}),
        json!({"status":"unknown","reason":"duration_overflow"}),
    ] {
        let observation = timed_observation(measurement.clone());
        assert_eq!(observation["timings"][0]["measurement"], measurement);
        write_json(&observation_path, &observation);
        let original = fs::read(&observation_path).unwrap();
        let expected: AttemptCorrelationInput = serde_json::from_value(json!({
            "schema_version":1,"runtime":{
                "authority_sha256":authority,"snapshot_sha256":observation["snapshot_sha256"],
                "run_key_sha256":observation["identity"]["run_key_sha256"],
                "definition_sha256":observation["identity"]["definition_sha256"],
                "attempts":[{"ordinal":1,"attempt_key_sha256":observation["attempts"][0]["attempt_key_sha256"],
                    "evidence":"durable_attempt","requested":{"model":"gpt-5.6-sol","effort":"high"}}]
            },"physical":[]
        })).unwrap();
        let output = invoke(
            dir.path(),
            &projection_args(&observation_path, &physical_path, &authority),
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            report,
            serde_json::to_value(calculate_attempt_correlation(&expected).unwrap()).unwrap()
        );
        assert_eq!(report["attempts"][0]["physical_sends"], "unknown");
        assert_eq!(fs::read(&observation_path).unwrap(), original);
        assert!(!report.to_string().contains(PRIVATE));
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn observe_v3_projection_preserves_unknowns_and_source_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let observation_path = dir.path().join("observation.json");
    let physical_path = dir.path().join("physical.json");
    let (_store_temp, root) = seeded_runtime_store();
    let observation = serde_json::to_value(observe_run_v3(&root, PRIVATE).unwrap()).unwrap();
    assert_eq!(
        observation["timings"][0]["measurement"],
        json!({
            "status": "unknown", "reason": "missing_record"
        })
    );
    write_json(&observation_path, &observation);
    let original = fs::read(&observation_path).unwrap();
    write_json(
        &physical_path,
        &json!({"schema_version": 1, "physical": []}),
    );
    let output = invoke(
        dir.path(),
        &projection_args(
            &observation_path,
            &physical_path,
            &digest("runtime-authority"),
        ),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["runtime"]["snapshot_sha256"],
        observation["snapshot_sha256"]
    );
    assert_eq!(report["evidence_trust"], "supplied_unverified");
    assert_eq!(report["attempts"][0]["physical_sends"], "unknown");
    assert_eq!(report["attempts"][0]["requested"], Value::Null);
    assert_eq!(fs::read(&observation_path).unwrap(), original);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn observe_v3_rejects_malformed_timing_shapes_and_substituted_joins() {
    let dir = tempfile::tempdir().unwrap();
    let observation_path = dir.path().join("observation.json");
    let physical_path = dir.path().join("physical.json");
    let authority = digest("runtime-authority");
    write_json(&physical_path, &json!({"schema_version":1,"physical":[]}));
    let base = timed_observation(json!({"status":"known","duration_ms":0}));
    let mut cases = Vec::new();
    for (field, replacement) in [
        ("schema_version", json!(4)),
        ("schema_version", json!(2)),
        ("timings", Value::Null),
        ("timings", json!([])),
        ("timings", json!([base["timings"][0], base["timings"][0]])),
    ] {
        let mut value = base.clone();
        value[field] = replacement;
        cases.push(value);
    }
    let mut value = base.clone();
    value.as_object_mut().unwrap().remove("timings");
    cases.push(value);
    for field in base["timings"][0].as_object().unwrap().keys() {
        let mut value = base.clone();
        value["timings"][0].as_object_mut().unwrap().remove(field);
        cases.push(value);
    }
    for (field, replacement) in [
        ("ordinal", json!(0)),
        ("ordinal", json!(2)),
        ("attempt_key_sha256", json!(digest("another-attempt"))),
        ("timing_event_sha256", json!("bad-digest")),
        ("timing_event_sha256", json!(digest("absent-timing-event"))),
        (
            "timing_event_sha256",
            base["attempts"][0]["sources"]["attempt_evidence_sha256"].clone(),
        ),
        ("timing_event_sha256", Value::Null),
        ("scope", json!("provider")),
        ("clock", json!("wall_clock")),
        ("start_boundary", json!("before_spawn")),
        ("end_boundary", json!("after_reap")),
        ("precision", json!("seconds")),
        (REJECTED_SECRET, json!(REJECTED_SECRET)),
        ("measurement", json!({"status":"known","duration_ms":-1})),
        ("measurement", json!({"status":"known","duration_ms":1.5})),
        ("measurement", json!({"status":"known","duration_ms":null})),
        ("measurement", json!({"status":"known"})),
        (
            "measurement",
            json!({"status":"known","duration_ms":0,"reason":"clock_regression"}),
        ),
        (
            "measurement",
            json!({"status":"unknown","reason":"missing_record"}),
        ),
        (
            "measurement",
            json!({"status":"unknown","reason":"unsupported"}),
        ),
        (
            "measurement",
            json!({"status":"unknown","reason":{"clock_regression":null}}),
        ),
        (
            "measurement",
            json!({"status":"unknown","reason":"clock_regression","duration_ms":0}),
        ),
        (
            "measurement",
            json!({"status":"unknown","reason":"clock_regression",(REJECTED_SECRET):REJECTED_SECRET}),
        ),
    ] {
        let mut value = base.clone();
        value["timings"][0][field] = replacement;
        cases.push(value);
    }
    // A qualified timing cannot be attached to an attempt with no durable evidence.
    let mut value = emitted_observation();
    value["schema_version"] = json!(3);
    value["timings"] = base["timings"].clone();
    cases.push(value);
    // A timing event hash cannot qualify two different attempts.
    let mut value = base.clone();
    let mut second = base["attempts"][0].clone();
    second["ordinal"] = json!(2);
    second["attempt_key_sha256"] = json!(digest("second-attempt"));
    value["attempts"].as_array_mut().unwrap().push(second);
    value["known"]["attempts"] = json!(2);
    let mut second = base["timings"][0].clone();
    second["ordinal"] = json!(2);
    second["attempt_key_sha256"] = json!(digest("second-attempt"));
    value["timings"].as_array_mut().unwrap().push(second);
    cases.push(value);
    for field in ["sequence", "state", "event_sha256"] {
        let mut value = base.clone();
        let event = value["known"]["events"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap();
        event[field] = match field {
            "sequence" => json!(100),
            "state" => json!("failed"),
            _ => json!(digest("substituted-event")),
        };
        cases.push(value);
    }
    let mut value = base.clone();
    let event = value["known"]["events"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    value["known"]["events"].as_array_mut().unwrap().push(event);
    cases.push(value);
    for (index, value) in cases.into_iter().enumerate() {
        write_json(&observation_path, &value);
        let output = invoke(
            dir.path(),
            &projection_args(&observation_path, &physical_path, &authority),
        );
        assert!(
            !output.status.success(),
            "accepted mutation {index}: {value}"
        );
        assert_static_rejection(output);
    }
    let duplicate = serde_json::to_string(&base).unwrap().replacen(
        "\"duration_ms\":0",
        "\"duration_ms\":0,\"duration_ms\":0",
        1,
    );
    fs::write(&observation_path, duplicate).unwrap();
    assert_static_rejection(invoke(
        dir.path(),
        &projection_args(&observation_path, &physical_path, &authority),
    ));
}

#[test]
fn observe_v3_still_rejects_conflicting_physical_calls_and_absent_claims() {
    let dir = tempfile::tempdir().unwrap();
    let observation_path = dir.path().join("observation.json");
    let physical_path = dir.path().join("physical.json");
    let authority = digest("runtime-authority");
    let observation = timed_observation(json!({"status":"known","duration_ms":0}));
    write_json(&observation_path, &observation);
    let call = json!({
        "key":{"authority_sha256":digest("physical-authority"),"physical_sha256":digest("physical")},
        "sequence":1,"evidence_sha256":digest("evidence"),"external_request_id":null,
        "declared_model":null,"claimed_attempt_key_sha256":observation["attempts"][0]["attempt_key_sha256"]
    });
    let mut conflict = call.clone();
    conflict["evidence_sha256"] = json!(digest("conflict"));
    let mut absent = call.clone();
    absent["claimed_attempt_key_sha256"] = json!(digest("absent-attempt"));
    for physical in [json!([call, conflict]), json!([absent])] {
        write_json(
            &physical_path,
            &json!({"schema_version":1,"physical":physical}),
        );
        assert_static_rejection(invoke(
            dir.path(),
            &projection_args(&observation_path, &physical_path, &authority),
        ));
    }
}

fn projection_args<'a>(
    observation: &'a Path,
    physical: &'a Path,
    authority: &'a str,
) -> Vec<&'a str> {
    vec![
        "eval",
        "attempt-correlation",
        "--observation",
        observation.to_str().unwrap(),
        "--physical",
        physical.to_str().unwrap(),
        "--runtime-authority-sha256",
        authority,
        "--json",
    ]
}

fn assert_static_rejection(output: Output) {
    assert!(!output.status.success());
    let exposed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!exposed.contains(REJECTED_SECRET), "{exposed}");
    assert!(
        exposed.contains("eval.attempt_correlation.invalid") || exposed.contains("cli.invalid"),
        "{exposed}"
    );
}

#[test]
fn direct_input_matches_the_b1_library_and_creates_no_state() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("attempt-correlation.json");
    fs::write(&input, FIXTURE).unwrap();
    let expected = attempt_correlation_report(FIXTURE.as_bytes()).unwrap();

    let output = invoke(
        dir.path(),
        &[
            "eval",
            "attempt-correlation",
            "--input",
            input.to_str().unwrap(),
            "--json",
        ],
    );

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn observe_v2_projection_matches_independently_assembled_b1_input() {
    let dir = tempfile::tempdir().unwrap();
    let observation_path = dir.path().join("observation.json");
    let physical_path = dir.path().join("physical.json");
    let observation = durable_observation();
    let authority = digest("runtime-authority");
    let attempt_key = observation["attempts"][0]["attempt_key_sha256"]
        .as_str()
        .unwrap();
    let physical = json!({"schema_version":1,"physical":[{
        "key":{"authority_sha256":digest("physical-authority"),"physical_sha256":digest("physical-id")},
        "sequence":1,"evidence_sha256":digest("physical-evidence"),
        "external_request_id":"request-1","declared_model":"gpt-5.6-sol",
        "claimed_attempt_key_sha256":attempt_key
    }]});
    write_json(&observation_path, &observation);
    write_json(&physical_path, &physical);

    let expected: AttemptCorrelationInput = serde_json::from_value(json!({
        "schema_version":1,
        "runtime":{
            "authority_sha256":authority,
            "snapshot_sha256":observation["snapshot_sha256"],
            "run_key_sha256":observation["identity"]["run_key_sha256"],
            "definition_sha256":observation["identity"]["definition_sha256"],
            "attempts":[{
                "ordinal":1,"attempt_key_sha256":attempt_key,
                "evidence":"durable_attempt",
                "requested":{"model":"gpt-5.6-sol","effort":"high"}
            }]
        },
        "physical":physical["physical"]
    }))
    .unwrap();
    let expected = serde_json::to_value(calculate_attempt_correlation(&expected).unwrap()).unwrap();
    let output = invoke(
        dir.path(),
        &projection_args(&observation_path, &physical_path, &authority),
    );

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        expected
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn actual_runtime_observation_keeps_absent_physical_claims_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let observation_path = dir.path().join("observe-v2.json");
    let physical_path = dir.path().join("physical-v1.json");
    let (_store_temp, store) = seeded_runtime_store();
    let observed = invoke(
        dir.path(),
        &[
            "observe",
            "--store",
            store.to_str().unwrap(),
            "--run-id",
            PRIVATE,
            "--schema-version",
            "2",
            "--json",
        ],
    );
    assert!(
        observed.status.success(),
        "{}",
        String::from_utf8_lossy(&observed.stderr)
    );
    let observation: Value = serde_json::from_slice(&observed.stdout).unwrap();
    let physical = json!({"schema_version":1,"physical":[]});
    let authority = digest("runtime-authority");
    write_json(&observation_path, &observation);
    write_json(&physical_path, &physical);
    if let Some(capture) = std::env::var_os("AR_B1B_CAPTURE_DIR") {
        let capture = Path::new(&capture);
        fs::create_dir_all(capture).unwrap();
        write_json(&capture.join("observe-v2.json"), &observation);
        write_json(&capture.join("physical-v1.json"), &physical);
        fs::write(capture.join("runtime-authority-sha256.txt"), &authority).unwrap();
    }

    let output = invoke(
        dir.path(),
        &projection_args(&observation_path, &physical_path, &authority),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["evidence_trust"], "supplied_unverified");
    assert_eq!(report["attempts"][0]["physical_sends"], "unknown");
    assert_eq!(report["attempts"][0]["requested"], Value::Null);
    assert!(!report.to_string().contains(PRIVATE));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn strict_projection_rejects_versions_counts_collisions_and_secret_fields() {
    let dir = tempfile::tempdir().unwrap();
    let observation_path = dir.path().join("observation.json");
    let physical_path = dir.path().join("physical.json");
    let authority = digest("runtime-authority");
    let base = durable_observation();
    let empty = json!({"schema_version":1,"physical":[]});
    write_json(&physical_path, &empty);

    let mut cases = Vec::new();
    for version in [1, 3] {
        let mut value = base.clone();
        value["schema_version"] = json!(version);
        cases.push(value);
    }
    let mut value = base.clone();
    value["known"]["attempts"] = json!(0);
    cases.push(value);
    let mut value = base.clone();
    value["unknown"][REJECTED_SECRET] = json!(REJECTED_SECRET);
    cases.push(value);
    let mut value = base.clone();
    value["attempts"][0]["native"][REJECTED_SECRET] = json!(REJECTED_SECRET);
    cases.push(value);
    let mut value = base.clone();
    value["known"].as_object_mut().unwrap().remove("failure");
    cases.push(value);
    let mut value = base.clone();
    value["horizon"]
        .as_object_mut()
        .unwrap()
        .remove("event_sha256");
    cases.push(value);
    let mut value = base.clone();
    value["attempts"][0]
        .as_object_mut()
        .unwrap()
        .remove("requested");
    cases.push(value);
    let mut value = base.clone();
    value["attempts"][0]["transport"]
        .as_object_mut()
        .unwrap()
        .remove("exit_code");
    cases.push(value);
    for field in [
        "attempt_evidence_sha256",
        "finished_event_sha256",
        "transition_event_sha256",
        "output_incomplete_event_sha256",
        "protocol_event_sha256",
    ] {
        let mut value = base.clone();
        value["attempts"][0]["sources"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        cases.push(value);
    }
    let mut value = base.clone();
    value["attempts"][0]["native"]["observed_model"] = json!("gpt-5.6-sol");
    cases.push(value);
    for (path, replacement) in [
        ("state", json!({"succeeded_transport":null})),
        ("cleanup", json!({"unknown":null})),
        ("failure", json!({"network":null})),
    ] {
        let mut value = base.clone();
        value["known"][path] = replacement;
        cases.push(value);
    }
    let mut value = base.clone();
    value["completeness"]["journal"] = json!({"complete":null});
    cases.push(value);
    let mut value = base.clone();
    value["attempts"][0]["evidence"] = json!({"durable_attempt":null});
    cases.push(value);
    let mut value = base.clone();
    value["attempts"][0]["requested"]["effort"] = json!({"high":null});
    cases.push(value);
    let mut value = base.clone();
    value["attempts"][0]["transport"]["termination"] = json!({"exited":null});
    cases.push(value);
    let mut value = base.clone();
    value["attempts"][0]["capture"] = json!({"unknown":null});
    cases.push(value);
    let mut value = base.clone();
    value["attempts"][0]["protocol"] = json!({"unknown":null});
    cases.push(value);
    let mut value = base.clone();
    value["attempts"][0]["native"]["usage"] = json!({"unknown":null});
    cases.push(value);
    for value in cases {
        write_json(&observation_path, &value);
        assert_static_rejection(invoke(
            dir.path(),
            &projection_args(&observation_path, &physical_path, &authority),
        ));
    }

    let complete_observation = serde_json::to_string(&base).unwrap();
    let duplicate_observation = complete_observation.replacen(
        "\"schema_version\":2",
        "\"schema_version\":2,\"schema_version\":2",
        1,
    );
    fs::write(&observation_path, duplicate_observation).unwrap();
    assert_static_rejection(invoke(
        dir.path(),
        &projection_args(&observation_path, &physical_path, &authority),
    ));
    fs::write(
        &observation_path,
        format!("{{\"schema_version\":2,\"{REJECTED_SECRET}\":"),
    )
    .unwrap();
    assert_static_rejection(invoke(
        dir.path(),
        &projection_args(&observation_path, &physical_path, &authority),
    ));

    write_json(&observation_path, &base);
    let claim = base["attempts"][0]["attempt_key_sha256"].clone();
    let call = json!({
        "key":{"authority_sha256":digest("physical-authority"),"physical_sha256":digest("physical")},
        "sequence":1,"evidence_sha256":digest("evidence"),"external_request_id":null,
        "declared_model":null,"claimed_attempt_key_sha256":claim
    });
    let mut conflicting = call.clone();
    conflicting["sequence"] = json!(2);
    for physical in [
        json!({"schema_version":1,"physical":[call,conflicting]}),
        json!({"schema_version":1,"physical":[{
            "key":{"authority_sha256":digest("physical-authority-2"),"physical_sha256":digest("physical-2")},
            "sequence":1,"evidence_sha256":digest("evidence-2"),"external_request_id":null,
            "declared_model":null,"claimed_attempt_key_sha256":digest("absent-attempt")
        }]}),
        json!({"schema_version":1,"physical":[],(REJECTED_SECRET):REJECTED_SECRET}),
    ] {
        write_json(&physical_path, &physical);
        assert_static_rejection(invoke(
            dir.path(),
            &projection_args(&observation_path, &physical_path, &authority),
        ));
    }
    let complete_physical = serde_json::to_string(&empty).unwrap();
    let duplicate_physical = complete_physical.replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    fs::write(&physical_path, duplicate_physical).unwrap();
    assert_static_rejection(invoke(
        dir.path(),
        &projection_args(&observation_path, &physical_path, &authority),
    ));

    let direct_path = dir.path().join("direct.json");
    let duplicate_direct = FIXTURE.replacen(
        "\"schema_version\": 1",
        "\"schema_version\": 1, \"schema_version\": 1",
        1,
    );
    fs::write(&direct_path, duplicate_direct).unwrap();
    assert_static_rejection(invoke(
        dir.path(),
        &[
            "eval",
            "attempt-correlation",
            "--input",
            direct_path.to_str().unwrap(),
            "--json",
        ],
    ));
}

#[test]
fn mode_contract_and_each_file_bound_are_enforced_without_state() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.json");
    let observation = dir.path().join("observation.json");
    let physical = dir.path().join("physical.json");
    fs::write(&input, FIXTURE).unwrap();
    write_json(&observation, &emitted_observation());
    write_json(&physical, &json!({"schema_version":1,"physical":[]}));
    let authority = digest("runtime-authority");

    for args in [
        vec!["eval", "attempt-correlation", "--json"],
        vec![
            "eval",
            "attempt-correlation",
            "--observation",
            observation.to_str().unwrap(),
            "--json",
        ],
        vec![
            "eval",
            "attempt-correlation",
            "--input",
            input.to_str().unwrap(),
            "--observation",
            observation.to_str().unwrap(),
            "--physical",
            physical.to_str().unwrap(),
            "--runtime-authority-sha256",
            &authority,
            "--json",
        ],
    ] {
        assert_static_rejection(invoke(dir.path(), &args));
    }

    let oversized = dir.path().join("oversized.json");
    fs::write(&oversized, vec![b' '; 4 * 1024 * 1024 + 1]).unwrap();
    assert_static_rejection(invoke(
        dir.path(),
        &[
            "eval",
            "attempt-correlation",
            "--input",
            oversized.to_str().unwrap(),
            "--json",
        ],
    ));
    assert_static_rejection(invoke(
        dir.path(),
        &projection_args(&oversized, &physical, &authority),
    ));
    assert_static_rejection(invoke(
        dir.path(),
        &projection_args(&observation, &oversized, &authority),
    ));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 4);
}
