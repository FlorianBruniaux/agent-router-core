//! Late facts: schema v2 migration, one immutable fact per `(run key, kind)`,
//! consent, retention, purge and export.
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use router_feedback::*;
use router_types::*;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

/// Stored by the code before route facts existed: the fixture recorded at 102.
const V1_EVENT: &str = r#"{"sequence":1,"consent_revision":1,"recorded_at_unix_seconds":102,"input":{"schema_version":1,"observed_at_unix_seconds":101,"binding":{"task_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","run_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","receipt_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","policy_hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","catalog_hash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","snapshot_hash":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","producer_version":"synthetic-contract-v1","provenance_sha256":"1111111111111111111111111111111111111111111111111111111111111111"},"context":{"task_kind":"explore","risk":"low","model":"fixture-model","effort":"medium","harness":"fixture-host","transport":"subprocess-jsonl","agent":null,"skills":[],"plan":"single-pass","propensity_micros":null},"origin":"automated","transport":"passed","validation":"unknown","objective":"unknown","verification_evidence_sha256":null,"human":null,"failure":null,"measurements":{"cost_microusd":null,"latency_ms":100,"tokens":null,"attempts":1,"escalations":0},"comment_sha256":null},"event_hash":"fabf1fb43c1aa19cf1c1487d90bc4ac8f41e5a4af32d96f1cf0fa1f996f9f539"}"#;

/// The schema exactly as the version 1 code created it.
const V1_SCHEMA: &str = "CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE feedback(sequence INTEGER PRIMARY KEY AUTOINCREMENT, run_hash TEXT NOT NULL, origin TEXT NOT NULL, observed_at INTEGER NOT NULL, event TEXT NOT NULL, UNIQUE(run_hash,origin));
    CREATE TRIGGER feedback_immutable BEFORE UPDATE ON feedback BEGIN SELECT RAISE(ABORT,'immutable feedback'); END;
    CREATE TABLE policies(id TEXT PRIMARY KEY, artifact TEXT NOT NULL, state TEXT NOT NULL);
    CREATE TRIGGER policy_artifacts_immutable BEFORE UPDATE OF artifact ON policies BEGIN SELECT RAISE(ABORT,'immutable policy artifact'); END;
    CREATE TABLE policy_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT, artifact_id TEXT NOT NULL REFERENCES policies(id), event TEXT NOT NULL);
    CREATE TRIGGER policy_events_immutable BEFORE UPDATE ON policy_events BEGIN SELECT RAISE(ABORT,'immutable policy event'); END;
    PRAGMA user_version=1;";

const DAY: u64 = 86400;

fn prefs() -> FeedbackPreferences {
    FeedbackPreferences {
        collection_enabled: true,
        learning_enabled: true,
        ..Default::default()
    }
}
fn setup() -> (TempDir, FeedbackStore) {
    let temp = TempDir::new().unwrap();
    let store = FeedbackStore::open(&temp.path().join("feedback")).unwrap();
    store.configure(prefs(), 100).unwrap();
    (temp, store)
}
fn db(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path.join("feedback.sqlite3")).unwrap()
}
fn verification(key: &str, validation: VerificationOutcome) -> FeedbackFact {
    FeedbackFact {
        schema_version: 1,
        run_key_sha256: key.repeat(64),
        observed_at_unix_seconds: 150,
        kind: FeedbackFactKind::Verification {
            validation,
            objective: VerificationOutcome::Unknown,
            evidence_sha256: "9".repeat(64),
        },
    }
}
fn integration(key: &str, outcome: IntegrationOutcome) -> FeedbackFact {
    FeedbackFact {
        schema_version: 1,
        run_key_sha256: key.repeat(64),
        observed_at_unix_seconds: 160,
        kind: FeedbackFactKind::Integration { outcome },
    }
}
fn fixture() -> FeedbackInput {
    parse_feedback(include_bytes!(
        "../../../tests/fixtures/feedback/automated-unknown-v1.json"
    ))
    .unwrap()
}

/// A database made by the version 1 code, holding one v1 event.
fn v1_database(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    let db = db(path);
    db.execute_batch(V1_SCHEMA).unwrap();
    let consent = FeedbackConsent {
        preferences: prefs(),
        revision: 1,
        updated_at_unix_seconds: 100,
    };
    db.execute(
        "INSERT INTO settings VALUES('consent',?1)",
        [serde_json::to_string(&consent).unwrap()],
    )
    .unwrap();
    db.execute(
        "INSERT INTO feedback(sequence,run_hash,origin,observed_at,event) VALUES(1,?1,'\"automated\"',101,?2)",
        ["b".repeat(64), V1_EVENT.to_string()],
    )
    .unwrap();
    drop(db);
    fs::set_permissions(
        path.join("feedback.sqlite3"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}
fn user_version(path: &Path) -> u32 {
    db(path)
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap()
}

#[test]
fn version_1_database_migrates_and_keeps_its_events_byte_identical() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("feedback");
    v1_database(&path);
    assert_eq!(user_version(&path), 1);
    let store = FeedbackStore::open(&path).unwrap();
    drop(store);
    assert_eq!(user_version(&path), 2);
    let stored: String = db(&path)
        .query_row("SELECT event FROM feedback", [], |r| r.get(0))
        .unwrap();
    assert_eq!(stored, V1_EVENT);
    let store = FeedbackStore::open(&path).unwrap();
    let events = store.events(200).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(serde_json::to_string(&events[0]).unwrap(), V1_EVENT);
    assert_eq!(
        events[0].event_hash,
        "fabf1fb43c1aa19cf1c1487d90bc4ac8f41e5a4af32d96f1cf0fa1f996f9f539"
    );
    assert!(events[0].input.started_at_unix_seconds.is_none());
    assert!(events[0].input.run_key_sha256.is_none());
    // The migrated store accepts facts.
    store
        .record_fact(integration("a", IntegrationOutcome::Applied), 200)
        .unwrap();
}

#[test]
fn a_fresh_database_reaches_version_2() {
    let (temp, store) = setup();
    drop(store);
    assert_eq!(user_version(&temp.path().join("feedback")), 2);
}

#[test]
fn version_3_is_refused() {
    let (temp, store) = setup();
    drop(store);
    let path = temp.path().join("feedback");
    db(&path).pragma_update(None, "user_version", 3).unwrap();
    assert!(matches!(
        FeedbackStore::open(&path),
        Err(FeedbackError::Integrity("future schema"))
    ));
}

#[test]
fn an_identical_fact_is_idempotent() {
    let (_temp, store) = setup();
    let first = store
        .record_fact(verification("a", VerificationOutcome::Passed), 200)
        .unwrap();
    let again = store
        .record_fact(verification("a", VerificationOutcome::Passed), 300)
        .unwrap();
    assert_eq!(first, again);
    assert_eq!(store.facts(300).unwrap(), vec![first]);
}

#[test]
fn a_conflicting_fact_is_refused_and_the_first_stays() {
    let (_temp, store) = setup();
    let first = store
        .record_fact(integration("a", IntegrationOutcome::Applied), 200)
        .unwrap();
    assert!(matches!(
        store.record_fact(integration("a", IntegrationOutcome::Discarded), 201),
        Err(FeedbackError::Integrity("immutable fact"))
    ));
    assert_eq!(store.facts(202).unwrap(), vec![first]);
    // Another kind or another run is a different key.
    store
        .record_fact(verification("a", VerificationOutcome::Passed), 203)
        .unwrap();
    store
        .record_fact(integration("b", IntegrationOutcome::Discarded), 204)
        .unwrap();
    assert_eq!(store.facts(205).unwrap().len(), 3);
}

#[test]
fn a_fact_needs_consent_and_no_matching_event() {
    let temp = TempDir::new().unwrap();
    let store = FeedbackStore::open(&temp.path().join("feedback")).unwrap();
    assert!(matches!(
        store.record_fact(integration("a", IntegrationOutcome::Applied), 100),
        Err(FeedbackError::Consent)
    ));
    store.configure(prefs(), 100).unwrap();
    assert!(store.events(120).unwrap().is_empty());
    store
        .record_fact(integration("a", IntegrationOutcome::Applied), 160)
        .unwrap();
}

#[test]
fn an_invalid_fact_is_refused() {
    let (_temp, store) = setup();
    let mut inconclusive = verification("a", VerificationOutcome::Unknown);
    assert!(store.record_fact(inconclusive.clone(), 200).is_err());
    inconclusive.kind = FeedbackFactKind::Verification {
        validation: VerificationOutcome::Failed,
        objective: VerificationOutcome::Passed,
        evidence_sha256: "9".repeat(64),
    };
    assert!(store.record_fact(inconclusive, 200).is_err());
    let mut bad_evidence = verification("a", VerificationOutcome::Passed);
    bad_evidence.kind = FeedbackFactKind::Verification {
        validation: VerificationOutcome::Passed,
        objective: VerificationOutcome::Passed,
        evidence_sha256: "nothash".into(),
    };
    assert!(store.record_fact(bad_evidence, 200).is_err());
    let mut bad_key = integration("a", IntegrationOutcome::Applied);
    bad_key.run_key_sha256 = "short".into();
    assert!(store.record_fact(bad_key, 200).is_err());
    let mut bad_version = integration("a", IntegrationOutcome::Applied);
    bad_version.schema_version = 2;
    assert!(store.record_fact(bad_version, 200).is_err());
    let mut early = integration("a", IntegrationOutcome::Applied);
    early.observed_at_unix_seconds = 99;
    assert!(store.record_fact(early, 200).is_err());
    let mut future = integration("a", IntegrationOutcome::Applied);
    future.observed_at_unix_seconds = 201;
    assert!(store.record_fact(future, 200).is_err());
    assert!(store.facts(200).unwrap().is_empty());
}

#[test]
fn purge_all_and_consent_off_delete_facts() {
    let (temp, store) = setup();
    store
        .record_fact(integration("a", IntegrationOutcome::Applied), 200)
        .unwrap();
    store
        .configure(
            FeedbackPreferences {
                collection_enabled: false,
                learning_enabled: false,
                ..prefs()
            },
            210,
        )
        .unwrap();
    assert!(store.facts(220).unwrap().is_empty());
    let count: u64 = db(&temp.path().join("feedback"))
        .query_row("SELECT COUNT(*) FROM facts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);

    store.configure(prefs(), 230).unwrap();
    let mut later = integration("b", IntegrationOutcome::Discarded);
    later.observed_at_unix_seconds = 235;
    store.record_fact(later, 240).unwrap();
    assert_eq!(store.purge_all(250).unwrap(), 1);
    assert!(store.facts(260).unwrap().is_empty());
}

#[test]
fn retention_expires_facts_by_observation_time() {
    let (_temp, store) = setup();
    store
        .record_fact(verification("a", VerificationOutcome::Passed), 200)
        .unwrap();
    store
        .record_fact(integration("a", IntegrationOutcome::Applied), 200)
        .unwrap();
    // Observed at 150 and 160, retained 30 days.
    assert_eq!(store.facts(150 + 30 * DAY).unwrap().len(), 2);
    let remaining = store.facts(150 + 30 * DAY + 1).unwrap();
    assert_eq!(remaining.len(), 1);
    assert!(matches!(
        remaining[0].fact.kind,
        FeedbackFactKind::Integration { .. }
    ));
    assert_eq!(store.purge_expired(160 + 30 * DAY + 1).unwrap(), 1);
    assert!(store.facts(160 + 30 * DAY + 2).unwrap().is_empty());
}

#[test]
fn an_export_without_facts_keeps_the_earlier_bytes_and_hash() {
    #[derive(serde::Serialize)]
    struct Version1Export<'a> {
        schema_version: u32,
        exported_at_unix_seconds: u64,
        consent: &'a FeedbackConsent,
        events: &'a [FeedbackEvent],
        content_hash: &'a str,
    }
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("feedback");
    v1_database(&path);
    let store = FeedbackStore::open(&path).unwrap();
    let export = store.export(300).unwrap();
    assert!(export.facts.is_empty());
    let old = Version1Export {
        schema_version: 1,
        exported_at_unix_seconds: 300,
        consent: &export.consent,
        events: &export.events,
        content_hash: "",
    };
    let mut hasher = Sha256::new();
    hasher.update(b"feedback-export-v1\0");
    hasher.update(serde_json::to_vec(&old).unwrap());
    assert_eq!(export.content_hash, hex::encode(hasher.finalize()));
    assert!(!serde_json::to_string(&export).unwrap().contains("facts"));
}

#[test]
fn an_export_with_facts_lists_them_under_the_hash() {
    let (_temp, store) = setup();
    let fact = store
        .record_fact(integration("a", IntegrationOutcome::Applied), 200)
        .unwrap();
    let export = store.export(300).unwrap();
    assert_eq!(export.facts, vec![fact]);
    let mut sealed = export.clone();
    sealed.content_hash.clear();
    let mut hasher = Sha256::new();
    hasher.update(b"feedback-export-v1\0");
    hasher.update(serde_json::to_vec(&sealed).unwrap());
    assert_eq!(export.content_hash, hex::encode(hasher.finalize()));
    assert!(
        serde_json::to_string(&sealed)
            .unwrap()
            .contains("\"facts\"")
    );
}

#[test]
fn the_clock_watermark_covers_the_latest_fact() {
    let (temp, store) = setup();
    store
        .record_fact(integration("a", IntegrationOutcome::Applied), 200)
        .unwrap();
    // Without the watermark row, only the fact itself can refuse an earlier clock.
    db(&temp.path().join("feedback"))
        .execute("DELETE FROM settings WHERE key='last_seen_time'", [])
        .unwrap();
    assert!(matches!(
        store.record_fact(integration("b", IntegrationOutcome::Applied), 190),
        Err(FeedbackError::Invalid("clock moved backwards"))
    ));
}

#[test]
fn stored_facts_are_immutable_and_revalidated() {
    let (temp, store) = setup();
    let event = store
        .record_fact(integration("a", IntegrationOutcome::Applied), 200)
        .unwrap();
    drop(store);
    let path = temp.path().join("feedback");
    assert!(db(&path).execute("UPDATE facts SET fact='{}'", []).is_err());
    // A row that is not what its columns and hash claim is refused on open.
    let mut forged = event.clone();
    forged.fact.kind = FeedbackFactKind::Integration {
        outcome: IntegrationOutcome::Discarded,
    };
    db(&path)
        .execute(
            "UPDATE facts SET fact=?1",
            [serde_json::to_string(&forged).unwrap()],
        )
        .expect_err("update trigger");
    let conn = db(&path);
    conn.execute_batch("DROP TRIGGER facts_immutable").unwrap();
    conn.execute(
        "UPDATE facts SET fact=?1",
        [serde_json::to_string(&forged).unwrap()],
    )
    .unwrap();
    drop(conn);
    assert!(matches!(
        FeedbackStore::open(&path),
        Err(FeedbackError::Integrity("fact"))
    ));
}

#[test]
fn a_start_after_the_observation_is_refused() {
    let (_temp, store) = setup();
    let mut input = fixture();
    input.observed_at_unix_seconds = 150;
    input.started_at_unix_seconds = Some(151);
    assert!(matches!(
        store.record(input.clone(), 200),
        Err(FeedbackError::Invalid("run identity"))
    ));
    input.started_at_unix_seconds = Some(150);
    store.record(input, 200).unwrap();
}

#[test]
fn the_run_identity_fields_are_optional_and_validated() {
    let (_temp, store) = setup();
    let mut input = fixture();
    input.observed_at_unix_seconds = 150;
    input.run_key_sha256 = Some("nothash".into());
    assert!(matches!(
        store.record(input.clone(), 200),
        Err(FeedbackError::Invalid("run identity"))
    ));
    input.run_key_sha256 = Some("7".repeat(64));
    input.started_at_unix_seconds = Some(120);
    let event = store.record(input, 200).unwrap();
    let text = serde_json::to_string(&event).unwrap();
    assert!(text.contains("\"started_at_unix_seconds\":120"));
    assert!(text.contains(&format!("\"run_key_sha256\":\"{}\"", "7".repeat(64))));
    // Absent fields stay absent, so a v1 event keeps its bytes.
    let plain = serde_json::to_string(&fixture()).unwrap();
    assert!(!plain.contains("started_at") && !plain.contains("run_key"));
}
