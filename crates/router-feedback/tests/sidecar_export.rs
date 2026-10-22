#[path = "support/sidecar.rs"]
mod fixture;
use fixture::*;
use router_feedback::{FeedbackStore, SidecarExportProjection};
use std::{
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};
#[test]
fn projection_omits_all_free_identifiers_and_preserves_outcome_boundaries() {
    for human in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let store = FeedbackStore::open(&dir.path().join("feedback")).unwrap();
        store.configure(preferences(), 100).unwrap();
        let event = store.record(input(100, human), 100).unwrap();
        let guard = store
            .authorize_sidecar_export(event.sequence, &event.event_hash, 1, 100)
            .unwrap();
        let value = match guard.projection() {
            SidecarExportProjection::Outcome(p) => {
                assert!(!human);
                serde_json::to_value(p).unwrap()
            }
            SidecarExportProjection::Feedback(p) => {
                assert!(human);
                serde_json::to_value(p).unwrap()
            }
        };
        let text = serde_json::to_string(&value).unwrap();
        assert!(!text.contains("private-"));
        assert!(!text.contains("comment"));
        assert!(!text.contains("producer"));
        assert_eq!(value["observation"]["objective"], "unknown");
        assert_eq!(value["observation"]["validation"], "unknown");
        assert!(value["observation"]["measurements"]["tokens"].is_null());
        assert_eq!(value["observation"]["event_sha256"], event.event_hash);
    }
}
#[test]
fn event_hash_revision_retention_and_learning_optout_are_hard_gates() {
    let dir = tempfile::tempdir().unwrap();
    let store = FeedbackStore::open(&dir.path().join("feedback")).unwrap();
    store.configure(preferences(), 100).unwrap();
    let event = store.record(input(100, false), 100).unwrap();
    assert!(
        store
            .authorize_sidecar_export(event.sequence, &"f".repeat(64), 1, 100)
            .is_err()
    );
    assert!(
        store
            .authorize_sidecar_export(event.sequence, &event.event_hash, 2, 100)
            .is_err()
    );
    assert!(
        store
            .authorize_sidecar_export(event.sequence, &event.event_hash, 1, 161)
            .is_err()
    );
    let mut p = preferences();
    p.learning_enabled = false;
    store.configure(p, 101).unwrap();
    assert!(
        store
            .authorize_sidecar_export(event.sequence, &event.event_hash, 2, 101)
            .is_err()
    );
    store.configure(preferences(), 102).unwrap();
    assert!(
        store
            .authorize_sidecar_export(event.sequence, &event.event_hash, 3, 102)
            .is_err(),
        "new consent cannot silently reauthorize old events"
    );
    store.purge_all(103).unwrap();
    assert!(
        store
            .authorize_sidecar_export(event.sequence, &event.event_hash, 1, 103)
            .is_err()
    );
}
#[test]
fn export_guard_serializes_consent_revocation_until_drop() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FeedbackStore::open(&dir.path().join("feedback")).unwrap());
    store.configure(preferences(), 100).unwrap();
    let event = store.record(input(100, false), 100).unwrap();
    let guard = store
        .authorize_sidecar_export(event.sequence, &event.event_hash, 1, 100)
        .unwrap();
    let other = store.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let join = thread::spawn(move || {
        started_tx.send(()).unwrap();
        other.configure(Default::default(), 101).unwrap();
        done_tx.send(()).unwrap();
    });
    started_rx.recv().unwrap();
    assert!(done_rx.recv_timeout(Duration::from_millis(30)).is_err());
    drop(guard);
    done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    join.join().unwrap();
    assert!(
        store
            .authorize_sidecar_export(event.sequence, &event.event_hash, 1, 101)
            .is_err()
    );
}
#[test]
fn changed_record_is_rejected_before_projection_and_guard_failure_releases_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("feedback");
    let store = FeedbackStore::open(&path).unwrap();
    store.configure(preferences(), 100).unwrap();
    let event = store.record(input(100, false), 100).unwrap();
    let db = rusqlite::Connection::open(path.join("feedback.sqlite3")).unwrap();
    db.execute_batch("DROP TRIGGER feedback_immutable;")
        .unwrap();
    let mut forged = event.clone();
    forged.input.context.model = router_types::ModelId::parse("changed-model-canary").unwrap();
    db.execute(
        "UPDATE feedback SET event=?1 WHERE sequence=?2",
        rusqlite::params![serde_json::to_string(&forged).unwrap(), event.sequence],
    )
    .unwrap();
    assert!(
        store
            .authorize_sidecar_export(event.sequence, &event.event_hash, 1, 100)
            .is_err()
    );
    assert!(store.consent().is_ok());
}

#[test]
fn collection_without_learning_does_not_authorize_current_revision_export() {
    let dir = tempfile::tempdir().unwrap();
    let store = FeedbackStore::open(&dir.path().join("feedback")).unwrap();
    let mut preferences = preferences();
    preferences.learning_enabled = false;
    store.configure(preferences, 100).unwrap();
    let event = store.record(input(100, false), 100).unwrap();
    assert!(matches!(
        store.authorize_sidecar_export(
            event.sequence,
            &event.event_hash,
            event.consent_revision,
            100
        ),
        Err(router_feedback::FeedbackError::LearningDisabled)
    ));
}

#[test]
fn reentry_from_the_guard_holding_thread_is_locked_not_a_deadlock() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FeedbackStore::open(&dir.path().join("feedback")).unwrap());
    store.configure(preferences(), 100).unwrap();
    let event = store.record(input(100, false), 100).unwrap();
    let (result_tx, result_rx) = mpsc::channel();
    let worker = store.clone();
    // A regression would deadlock, so the reentrant calls run on a thread that
    // the test can give up on.
    thread::spawn(move || {
        let guard = worker
            .authorize_sidecar_export(event.sequence, &event.event_hash, 1, 100)
            .unwrap();
        let configure = worker.configure(Default::default(), 101);
        let consent = worker.consent();
        let second = worker
            .authorize_sidecar_export(event.sequence, &event.event_hash, 1, 100)
            .map(|_| ());
        drop(guard);
        let after = worker.consent().map(|_| ());
        result_tx
            .send((configure.map(|_| ()), consent.map(|_| ()), second, after))
            .unwrap();
    });
    let (configure, consent, second, after) =
        result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(matches!(
        configure,
        Err(router_feedback::FeedbackError::Locked)
    ));
    assert!(matches!(
        consent,
        Err(router_feedback::FeedbackError::Locked)
    ));
    assert!(matches!(
        second,
        Err(router_feedback::FeedbackError::Locked)
    ));
    assert!(after.is_ok());
}
#[test]
fn projection_drops_the_local_token_split() {
    let dir = tempfile::tempdir().unwrap();
    let store = FeedbackStore::open(&dir.path().join("feedback")).unwrap();
    store.configure(preferences(), 100).unwrap();
    let field = router_types::UsageField::host_reported;
    let mut with_usage = input(100, false);
    with_usage.measurements.usage = Some(router_types::HostUsage {
        input_tokens: field(10),
        cached_input_tokens: field(2),
        cache_write_input_tokens: router_types::UsageField::UNKNOWN,
        output_tokens: field(5),
        reasoning_output_tokens: router_types::UsageField::UNKNOWN,
    });
    let event = store.record(with_usage, 100).unwrap();
    // The stored event keeps the split; only the projection drops it.
    assert!(event.input.measurements.usage.is_some());
    let guard = store
        .authorize_sidecar_export(event.sequence, &event.event_hash, 1, 100)
        .unwrap();
    let SidecarExportProjection::Outcome(p) = guard.projection() else {
        panic!("automated event");
    };
    let value = serde_json::to_value(p).unwrap();
    assert!(value["observation"]["measurements"].get("usage").is_none());
}
