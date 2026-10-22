//! Independent synthetic-store contracts. No providers, credentials or subprocesses.
//! Mutation fixtures rebuild every journal hash and all evidence references, so
//! semantic refusals cannot pass merely because the attacker broke the chain.
use router_runtime::{Runtime, RuntimeError, RuntimeLimits, observe_run, observe_run_v2};
use router_types::{OutputRetentionPolicy, RunState, RunSummary};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Barrier},
    thread,
};

const PRIVATE: &str = "PRIVATE_PROMPT_PATH_CREDENTIAL_CANARY";
const MODEL: &str = "vendor/model-v2:2026_10.08";

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().join("runtime");
        drop(Runtime::open(&root, RuntimeLimits::default()).unwrap());
        Self { _temp: temp, root }
    }
    fn db(&self) -> Connection {
        let db = Connection::open(self.root.join("runtime.sqlite3")).unwrap();
        db.busy_timeout(std::time::Duration::from_secs(3)).unwrap();
        db
    }
    fn seed(s: Scenario) -> Self {
        let f = Self::new();
        let mut db = f.db();
        let tx = db.transaction().unwrap();
        let attempts = if s.next_start_before_evidence { 2 } else { 1 };
        save_summary(&tx, s.final_state, attempts, true);
        tx.execute(
            "INSERT INTO run_attempts VALUES(?1,1,?2)",
            params![PRIVATE, if s.omit_evidence { "started" } else { s.status }],
        )
        .unwrap();
        if s.stale_capture {
            append(
                &tx,
                RunState::Preparing,
                "output.incomplete",
                "stream_reader_deadline",
            );
        }
        if s.stale_protocol {
            append(
                &tx,
                RunState::Preparing,
                "protocol.observed",
                "decoded_not_verified",
            );
        }
        let start = append(&tx, s.start_state, "attempt.started", s.start_detail);
        append(&tx, RunState::Running, "transition", "prepared");
        for _ in 0..s.incomplete_count {
            append(
                &tx,
                RunState::Running,
                "output.incomplete",
                "stream_reader_deadline",
            );
        }
        let finish = append(&tx, s.finish_state, "attempt.finished", s.finish_detail);
        let transition = append(&tx, s.final_state, "transition", s.transition_detail);
        let mut evidence = json!({
            "schema_version":1, "identity":{"run_id":PRIVATE,"attempt":1},
            "definition_hash":"a".repeat(64), "authorization_id":PRIVATE,
            "decision_origin":"deterministic", "sandbox":"read_only",
            "context_hash":"c".repeat(64), "pool_hash":"d".repeat(64),
            "source_state":PRIVATE, "task_execution_sha256":"e".repeat(64),
            "candidate_id":PRIVATE, "model":MODEL, "effort":"high", "workflow":null,
            "state":s.final_state, "failure":null,
            "transport":{"termination":"exited","exit_code":0,"elapsed_ms":987654321},
            "cleanup":"unknown", "observed_cost_microusd":123456789,
            "observed_tokens":987654321, "started_event_hash":start,
            "finished_event_hash":finish, "transition_event_hash":transition
        });
        (s.change)(&mut evidence);
        if s.next_start_before_evidence {
            tx.execute("INSERT INTO run_attempts VALUES(?1,2,'started')", [PRIVATE])
                .unwrap();
            append(&tx, RunState::Preparing, "attempt.started", "");
        }
        if !s.omit_evidence {
            append(
                &tx,
                s.final_state,
                "attempt.evidence.v1",
                &evidence.to_string(),
            );
            if s.duplicate_evidence {
                append(
                    &tx,
                    s.final_state,
                    "attempt.evidence.v1",
                    &evidence.to_string(),
                );
            }
        }
        if s.late_capture {
            append(
                &tx,
                s.final_state,
                "output.incomplete",
                "stream_reader_deadline",
            );
        }
        if s.late_protocol {
            append(
                &tx,
                s.final_state,
                "protocol.observed",
                "decoded_not_verified",
            );
        }
        tx.commit().unwrap();
        f
    }
    fn read(&self) -> Value {
        serde_json::to_value(observe_run_v2(&self.root, PRIVATE).unwrap()).unwrap()
    }
    fn semantic_refusal(&self) {
        observe_run(&self.root, PRIVATE).expect("mutation retains a valid v1 chain and history");
        self.refusal();
    }
    fn refusal(&self) {
        let error = observe_run_v2(&self.root, PRIVATE).unwrap_err();
        assert!(
            matches!(error, RuntimeError::Integrity(_)),
            "wrong refusal: {error:?}"
        );
        assert!(!format!("{error} {error:?}").contains(PRIVATE));
    }
}
struct Scenario {
    start_state: RunState,
    start_detail: &'static str,
    finish_state: RunState,
    finish_detail: &'static str,
    final_state: RunState,
    transition_detail: &'static str,
    status: &'static str,
    incomplete_count: usize,
    stale_capture: bool,
    late_capture: bool,
    stale_protocol: bool,
    late_protocol: bool,
    omit_evidence: bool,
    duplicate_evidence: bool,
    next_start_before_evidence: bool,
    change: fn(&mut Value),
}
impl Default for Scenario {
    fn default() -> Self {
        Self {
            start_state: RunState::Preparing,
            start_detail: "",
            finish_state: RunState::Running,
            finish_detail: "observed",
            final_state: RunState::SucceededTransport,
            transition_detail: "transport_observed",
            status: "observed",
            incomplete_count: 0,
            stale_capture: false,
            late_capture: false,
            stale_protocol: false,
            late_protocol: false,
            omit_evidence: false,
            duplicate_evidence: false,
            next_start_before_evidence: false,
            change: |_| {},
        }
    }
}
fn save_summary(db: &Connection, state: RunState, attempts: u32, insert: bool) {
    let run = RunSummary {
        run_id: PRIVATE.into(),
        definition_hash: "a".repeat(64),
        approval_digest: "b".repeat(64),
        receipt_id: PRIVATE.into(),
        plan_id: PRIVATE.into(),
        node_id: PRIVATE.into(),
        state,
        attempts,
        failure: None,
        worktree: Some(PRIVATE.into()),
        artifact_sha256: None,
        output_retention: OutputRetentionPolicy::Disabled,
        workflow: None,
        artifact_contract_sha256: None,
    };
    let data = serde_json::to_string(&run).unwrap();
    if insert {
        db.execute(
            "INSERT INTO runs VALUES(?1,?1,?1,?2)",
            params![PRIVATE, data],
        )
        .unwrap();
    } else {
        db.execute(
            "UPDATE runs SET summary=?1 WHERE run_id=?2",
            params![data, PRIVATE],
        )
        .unwrap();
    }
}
fn append(db: &Connection, state: RunState, kind: &str, detail: &str) -> String {
    let (sequence, previous): (u64, String) = db
        .query_row(
            "SELECT sequence,event_hash FROM events ORDER BY sequence DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap_or((0, String::new()));
    let mut hasher = Sha256::new();
    hasher.update(b"runtime-event-v1\0");
    hasher.update(
        serde_json::to_vec(&(sequence + 1, PRIVATE, kind, state, detail, &previous)).unwrap(),
    );
    let hash = hex::encode(hasher.finalize());
    db.execute(
        "INSERT INTO events VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            sequence + 1,
            PRIVATE,
            kind,
            serde_json::to_string(&state).unwrap(),
            detail,
            previous,
            hash
        ],
    )
    .unwrap();
    hash
}
fn assert_unknown_native(attempt: &Value) {
    let native = attempt["native"]
        .as_object()
        .expect("explicit native evidence object");
    assert_eq!(native.len(), 10);
    assert!(native.values().all(|value| value == "unknown"));
    assert_eq!(attempt["protocol"], "unknown");
    assert!(attempt["sources"]["protocol_event_sha256"].is_null());
}
fn reject_change(change: fn(&mut Value)) {
    Fixture::seed(Scenario {
        change,
        ..Scenario::default()
    })
    .semantic_refusal();
}

#[test]
fn valid_durable_control_is_redacted_deterministic_and_preserves_v1() {
    let f = Fixture::seed(Scenario::default());
    let observation = f.read();
    assert_eq!(observation, f.read());
    assert_eq!(observation["schema_version"], 2);
    let v1 = serde_json::to_value(observe_run(&f.root, PRIVATE).unwrap()).unwrap();
    for field in ["identity", "horizon", "known", "unknown", "completeness"] {
        assert_eq!(observation[field], v1[field], "{field}");
    }
    let attempt = &observation["attempts"][0];
    assert_eq!(observation["attempts"].as_array().unwrap().len(), 1);
    assert_eq!(attempt["ordinal"], 1);
    assert_eq!(attempt["evidence"], "durable_attempt");
    assert_eq!(attempt["requested"], json!({"model":MODEL,"effort":"high"}));
    assert_eq!(
        attempt["transport"],
        json!({"termination":"exited","exit_code":0})
    );
    assert_eq!(attempt["capture"], "unknown");
    for field in [
        "started_event_sha256",
        "attempt_evidence_sha256",
        "finished_event_sha256",
        "transition_event_sha256",
    ] {
        assert_eq!(attempt["sources"][field].as_str().unwrap().len(), 64);
    }
    assert_eq!(attempt["attempt_key_sha256"].as_str().unwrap().len(), 64);
    assert_unknown_native(attempt);
    let serialized = observation.to_string();
    for private in [
        PRIVATE,
        "987654321",
        "123456789",
        "elapsed_ms",
        "candidate_id",
        "source_state",
    ] {
        assert!(!serialized.contains(private), "leak: {private}");
    }
}
#[test]
fn missing_durable_evidence_retains_start_without_inventing_transport() {
    let f = Fixture::seed(Scenario {
        omit_evidence: true,
        incomplete_count: 1,
        ..Scenario::default()
    });
    let value = f.read();
    let attempt = &value["attempts"][0];
    assert_eq!(attempt["ordinal"], 1);
    assert_eq!(attempt["evidence"], "unknown");
    assert!(attempt["requested"].is_null());
    assert!(attempt["transport"].is_null());
    assert_eq!(attempt["capture"], "unknown");
    assert!(attempt["sources"]["attempt_evidence_sha256"].is_null());
    assert_unknown_native(attempt);
}
#[test]
fn rehashed_start_state_running_is_refused() {
    Fixture::seed(Scenario {
        start_state: RunState::Running,
        ..Scenario::default()
    })
    .semantic_refusal();
}
#[test]
fn rehashed_start_detail_is_refused() {
    Fixture::seed(Scenario {
        start_detail: PRIVATE,
        ..Scenario::default()
    })
    .semantic_refusal();
}
#[test]
fn rehashed_finish_state_is_refused() {
    Fixture::seed(Scenario {
        finish_state: RunState::Preparing,
        ..Scenario::default()
    })
    .semantic_refusal();
}
#[test]
fn rehashed_finish_detail_is_refused() {
    Fixture::seed(Scenario {
        finish_detail: "cancelled",
        ..Scenario::default()
    })
    .semantic_refusal();
}
#[test]
fn rehashed_transition_detail_is_refused() {
    Fixture::seed(Scenario {
        transition_detail: "approved",
        ..Scenario::default()
    })
    .semantic_refusal();
}
#[test]
fn rehashed_impossible_transport_transition_is_refused() {
    Fixture::seed(Scenario {
        final_state: RunState::Verified,
        ..Scenario::default()
    })
    .semantic_refusal();
}
#[test]
fn rehashed_identity_and_binding_corruption_is_refused() {
    for change in [
        (|e: &mut Value| e["identity"]["run_id"] = json!("other-run")) as fn(&mut Value),
        |e| e["identity"]["attempt"] = json!(0),
        |e| e["identity"]["attempt"] = json!(2),
        |e| e["definition_hash"] = json!("f".repeat(64)),
        |e| e["authorization_id"] = json!("other-receipt"),
        |e| e["started_event_hash"] = json!("f".repeat(64)),
        |e| e["finished_event_hash"] = e["started_event_hash"].clone(),
        |e| e["transition_event_hash"] = e["finished_event_hash"].clone(),
        |e| e["schema_version"] = json!(2),
        |e| e["state"] = json!("failed"),
    ] {
        reject_change(change);
    }
}
#[test]
fn rehashed_duplicate_durable_evidence_is_refused() {
    Fixture::seed(Scenario {
        duplicate_evidence: true,
        ..Scenario::default()
    })
    .semantic_refusal();
}
#[test]
fn later_attempt_cannot_start_before_prior_evidence() {
    Fixture::seed(Scenario {
        next_start_before_evidence: true,
        ..Scenario::default()
    })
    .semantic_refusal();
}
#[test]
fn durable_evidence_requires_observed_attempt_status() {
    Fixture::seed(Scenario {
        status: "started",
        ..Scenario::default()
    })
    .semantic_refusal();
}
#[test]
fn incomplete_capture_requires_validated_interval_and_unique_source() {
    let f = Fixture::seed(Scenario {
        incomplete_count: 1,
        ..Scenario::default()
    });
    let v = f.read();
    assert_eq!(v["attempts"][0]["capture"], "incomplete");
    assert_eq!(
        v["attempts"][0]["sources"]["output_incomplete_event_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    Fixture::seed(Scenario {
        incomplete_count: 2,
        ..Scenario::default()
    })
    .semantic_refusal();
}
#[test]
fn stale_or_post_finish_capture_and_unbound_protocol_do_not_upgrade_evidence() {
    let f = Fixture::seed(Scenario {
        stale_capture: true,
        late_capture: true,
        stale_protocol: true,
        late_protocol: true,
        ..Scenario::default()
    });
    let v = f.read();
    let attempt = &v["attempts"][0];
    assert_eq!(attempt["capture"], "unknown");
    assert!(attempt["sources"]["output_incomplete_event_sha256"].is_null());
    assert_unknown_native(attempt);
}
#[test]
fn output_limit_and_incomplete_remain_separate_facts() {
    for (count, expected) in [(0, "output_limit"), (1, "output_limit_incomplete")] {
        let f = Fixture::seed(Scenario {
            final_state: RunState::Failed,
            incomplete_count: count,
            change: |e| e["failure"] = json!("output_limit"),
            ..Scenario::default()
        });
        assert_eq!(f.read()["attempts"][0]["capture"], expected);
    }
}
#[test]
fn model_names_are_bounded_printable_tokens() {
    for model in ["provider/model:1-2_3.4".to_owned(), "x".repeat(256)] {
        let f = Fixture::seed(Scenario::default());
        replace_model(&f, &model);
        assert_eq!(f.read()["attempts"][0]["requested"]["model"], model);
    }
    for model in [
        "x".repeat(257),
        "native\nSECRET".into(),
        "native model".into(),
        "モデル".into(),
        "native\u{001b}[31m".into(),
        "native@host".into(),
    ] {
        let f = Fixture::seed(Scenario::default());
        replace_model(&f, &model);
        f.semantic_refusal();
    }
}
// The evidence event is last. Recompute its own hash without touching its bound
// predecessor references, preserving a valid journal for unsafe-model tests.
fn replace_model(f: &Fixture, model: &str) {
    let db = f.db();
    // Hostile on-disk fixture: bypass only the write guard needed for mutation.
    db.execute_batch("DROP TRIGGER events_no_delete;").unwrap();
    let (sequence, detail): (u64, String) = db
        .query_row(
            "SELECT sequence,detail FROM events WHERE kind='attempt.evidence.v1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let mut evidence: Value = serde_json::from_str(&detail).unwrap();
    evidence["model"] = json!(model);
    db.execute("DELETE FROM events WHERE sequence=?1", [sequence])
        .unwrap();
    append(
        &db,
        RunState::SucceededTransport,
        "attempt.evidence.v1",
        &evidence.to_string(),
    );
}
#[test]
fn missing_and_future_stores_are_passive() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("absent");
    assert!(observe_run_v2(&missing, PRIVATE).is_err());
    assert!(!missing.exists());
    let f = Fixture::seed(Scenario::default());
    f.db().pragma_update(None, "user_version", 100).unwrap();
    f.refusal();
    assert_eq!(
        f.db()
            .pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
            .unwrap(),
        100
    );
}
#[test]
fn oversized_durable_status_is_rejected_before_decoding() {
    let f = Fixture::seed(Scenario::default());
    f.db()
        .execute("UPDATE run_attempts SET status=?1", ["x".repeat(65_537)])
        .unwrap();
    assert!(matches!(
        observe_run_v2(&f.root, PRIVATE),
        Err(RuntimeError::Limit)
    ));
}
#[test]
fn corrupt_chain_and_oversized_event_are_refused() {
    let f = Fixture::seed(Scenario::default());
    f.db()
        .execute_batch("DROP TRIGGER events_no_update;")
        .unwrap();
    f.db()
        .execute(
            "UPDATE events SET event_hash='corrupt' WHERE sequence=1",
            [],
        )
        .unwrap();
    f.refusal();
    let f = Fixture::seed(Scenario::default());
    f.db()
        .execute_batch("DROP TRIGGER events_no_update;")
        .unwrap();
    f.db()
        .execute(
            "UPDATE events SET detail=?1 WHERE sequence=1",
            ["x".repeat(65_537)],
        )
        .unwrap();
    assert!(matches!(
        observe_run_v2(&f.root, PRIVATE),
        Err(RuntimeError::Limit)
    ));
}
#[test]
fn passive_reads_preserve_private_records_and_files() {
    let f = Fixture::seed(Scenario::default());
    let db = f.db();
    db.execute(
        "INSERT INTO attempt_leases VALUES(?1,1,?2,0,NULL)",
        params![PRIVATE, PRIVATE],
    )
    .unwrap();
    db.execute("INSERT INTO cleanup_blocks VALUES(?1)", [PRIVATE])
        .unwrap();
    let private_file = f.root.join("private-output");
    fs::write(&private_file, PRIVATE).unwrap();
    let dump = || {
        db.query_row("SELECT (SELECT summary FROM runs),(SELECT record FROM attempt_leases),(SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM cleanup_blocks)",[],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,u64>(2)?,r.get::<_,u64>(3)?))).unwrap()
    };
    let before = dump();
    for _ in 0..8 {
        f.read();
    }
    assert_eq!(before, dump());
    assert_eq!(fs::read_to_string(private_file).unwrap(), PRIVATE);
}
#[test]
fn coherent_writer_commits_never_mix_attempts_with_summary_or_horizon() {
    let f = Fixture::seed(Scenario::default());
    let root = f.root.clone();
    let barrier = Arc::new(Barrier::new(2));
    let writer_barrier = barrier.clone();
    let writer = thread::spawn(move || {
        let mut db = Connection::open(root.join("runtime.sqlite3")).unwrap();
        db.busy_timeout(std::time::Duration::from_secs(3)).unwrap();
        writer_barrier.wait();
        for ordinal in 2..=5 {
            let tx = db.transaction().unwrap();
            save_summary(&tx, RunState::Preparing, ordinal, false);
            tx.execute(
                "INSERT INTO run_attempts VALUES(?1,?2,'started')",
                params![PRIVATE, ordinal],
            )
            .unwrap();
            append(&tx, RunState::Preparing, "attempt.started", "");
            tx.commit().unwrap();
            thread::yield_now();
        }
    });
    barrier.wait();
    for _ in 0..40 {
        let v = f.read();
        let attempts = v["attempts"].as_array().unwrap();
        assert_eq!(
            v["known"]["attempts"].as_u64().unwrap(),
            attempts.len() as u64
        );
        assert_eq!(
            v["horizon"]["sequence"],
            v["known"]["events"].as_array().unwrap().last().unwrap()["sequence"]
        );
        assert_eq!(
            v["known"]["state"],
            v["known"]["events"].as_array().unwrap().last().unwrap()["state"]
        );
        for (index, attempt) in attempts.iter().enumerate() {
            assert_eq!(attempt["ordinal"], index + 1);
            assert_eq!(
                attempt["evidence"],
                if index == 0 {
                    "durable_attempt"
                } else {
                    "unknown"
                }
            );
        }
    }
    writer.join().unwrap();
    assert_eq!(f.read()["attempts"].as_array().unwrap().len(), 5);
}

// Timing markers are synthetic, fully rehashed journal entries. Legacy evidence
// deliberately contains a large elapsed value, which alone must never qualify.
fn timing_marker(f: &Fixture) -> Value {
    let hash: String = f
        .db()
        .query_row(
            "SELECT event_hash FROM events WHERE kind='attempt.evidence.v1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    json!({"schema_version":1,"ordinal":1,"attempt_evidence_sha256":hash,
        "producer":"capture_guarded_v1","scope":"supervisor_capture",
        "clock":"monotonic_same_invocation","start_boundary":"before_dispatch_validation",
        "end_boundary":"after_reap_and_both_output_drains","precision":"milliseconds_truncated",
        "measurement":{"status":"known","duration_ms":987654321}})
}
fn read_v3(f: &Fixture) -> Value {
    serde_json::to_value(router_runtime::observe_run_v3(&f.root, PRIVATE).unwrap()).unwrap()
}
#[test]
fn timing_legacy_elapsed_is_unknown_and_v3_reads_do_not_change_v1_v2() {
    let f = Fixture::seed(Scenario::default());
    let v1 = serde_json::to_vec(&observe_run(&f.root, PRIVATE).unwrap()).unwrap();
    let v2 = serde_json::to_vec(&observe_run_v2(&f.root, PRIVATE).unwrap()).unwrap();
    let v3 = read_v3(&f);
    assert_eq!(
        v3["timings"][0]["measurement"],
        json!({"status":"unknown","reason":"missing_record"})
    );
    assert_eq!(v3, read_v3(&f));
    assert_eq!(
        v1,
        serde_json::to_vec(&observe_run(&f.root, PRIVATE).unwrap()).unwrap()
    );
    assert_eq!(
        v2,
        serde_json::to_vec(&observe_run_v2(&f.root, PRIVATE).unwrap()).unwrap()
    );
}
#[test]
fn timing_qualified_interval_survives_reopen_without_becoming_native_duration() {
    let f = Fixture::seed(Scenario::default());
    let marker = timing_marker(&f);
    let hash = append(
        &f.db(),
        RunState::SucceededTransport,
        "attempt.timing.v1",
        &marker.to_string(),
    );
    let first = read_v3(&f);
    assert_eq!(
        first["timings"][0]["measurement"],
        json!({"status":"known","duration_ms":987654321})
    );
    assert_eq!(first["timings"][0]["timing_event_sha256"], hash);
    assert_eq!(
        first["timings"][0]["attempt_key_sha256"],
        first["attempts"][0]["attempt_key_sha256"]
    );
    assert_eq!(first["unknown"]["duration"], "unknown");
    assert_unknown_native(&first["attempts"][0]);
    assert!(!first.to_string().contains(PRIVATE));
    drop(Runtime::open(&f.root, RuntimeLimits::default()).unwrap());
    assert_eq!(first["timings"], read_v3(&f)["timings"]);
    assert_eq!(read_v3(&f), read_v3(&f));
}
#[test]
fn timing_rejects_malformed_substituted_or_conflicting_markers() {
    let changes: &[fn(&mut Value)] = &[
        |v| v["ordinal"] = json!(0),
        |v| v["ordinal"] = json!(2),
        |v| v["attempt_evidence_sha256"] = json!("f".repeat(64)),
        |v| v["schema_version"] = json!(2),
        |v| v["producer"] = json!("legacy_elapsed"),
        |v| v["clock"] = json!("wall_clock"),
        |v| v["end_boundary"] = json!("native_exit"),
        |v| v["measurement"]["duration_ms"] = json!(0),
        |v| v["measurement"]["duration_ms"] = json!(-1),
        |v| v["measurement"] = json!({"status":"unknown","reason":"missing_record"}),
        |v| v[PRIVATE] = json!(PRIVATE),
    ];
    for change in changes {
        let f = Fixture::seed(Scenario::default());
        let mut marker = timing_marker(&f);
        change(&mut marker);
        append(
            &f.db(),
            RunState::SucceededTransport,
            "attempt.timing.v1",
            &marker.to_string(),
        );
        observe_run_v2(&f.root, PRIVATE).unwrap();
        let error = router_runtime::observe_run_v3(&f.root, PRIVATE).unwrap_err();
        assert!(matches!(error, RuntimeError::Integrity(_)), "{error:?}");
        assert!(!format!("{error:?}").contains(PRIVATE));
    }
    for (kind, state, duplicate, intervening) in [
        (
            "attempt.timing.v2",
            RunState::SucceededTransport,
            false,
            false,
        ),
        ("attempt.timing.v1", RunState::Failed, false, false),
        (
            "attempt.timing.v1",
            RunState::SucceededTransport,
            true,
            false,
        ),
        (
            "attempt.timing.v1",
            RunState::SucceededTransport,
            false,
            true,
        ),
    ] {
        let f = Fixture::seed(Scenario::default());
        let marker = timing_marker(&f).to_string();
        if intervening {
            append(
                &f.db(),
                RunState::SucceededTransport,
                "protocol.observed",
                "decoded_not_verified",
            );
        }
        append(&f.db(), state, kind, &marker);
        if duplicate {
            append(&f.db(), state, kind, &marker);
        }
        assert!(router_runtime::observe_run_v3(&f.root, PRIVATE).is_err());
    }
}
#[test]
fn timing_unknown_clock_and_missing_endpoints_are_not_zero() {
    for reason in ["clock_regression", "duration_overflow"] {
        let f = Fixture::seed(Scenario::default());
        let mut marker = timing_marker(&f);
        marker["measurement"] = json!({"status":"unknown","reason":reason});
        append(
            &f.db(),
            RunState::SucceededTransport,
            "attempt.timing.v1",
            &marker.to_string(),
        );
        assert_eq!(
            read_v3(&f)["timings"][0]["measurement"],
            marker["measurement"]
        );
    }
    let f = Fixture::seed(Scenario {
        omit_evidence: true,
        ..Scenario::default()
    });
    let report = read_v3(&f);
    assert_eq!(
        report["timings"][0]["measurement"]["reason"],
        "missing_record"
    );
    assert!(
        report["timings"][0]["measurement"]
            .get("duration_ms")
            .is_none()
    );
}
