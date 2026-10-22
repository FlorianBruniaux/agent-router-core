//! Route facts in automated feedback: optional, textless and readable from v1 stores.
use std::collections::BTreeSet;

use router_feedback::*;
use router_types::*;
use tempfile::TempDir;

/// Stored by the code before route facts existed: the fixture recorded at 102.
const V1_EVENT: &str = r#"{"sequence":1,"consent_revision":1,"recorded_at_unix_seconds":102,"input":{"schema_version":1,"observed_at_unix_seconds":101,"binding":{"task_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","run_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","receipt_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","policy_hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","catalog_hash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","snapshot_hash":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","producer_version":"synthetic-contract-v1","provenance_sha256":"1111111111111111111111111111111111111111111111111111111111111111"},"context":{"task_kind":"explore","risk":"low","model":"fixture-model","effort":"medium","harness":"fixture-host","transport":"subprocess-jsonl","agent":null,"skills":[],"plan":"single-pass","propensity_micros":null},"origin":"automated","transport":"passed","validation":"unknown","objective":"unknown","verification_evidence_sha256":null,"human":null,"failure":null,"measurements":{"cost_microusd":null,"latency_ms":100,"tokens":null,"attempts":1,"escalations":0},"comment_sha256":null},"event_hash":"fabf1fb43c1aa19cf1c1487d90bc4ac8f41e5a4af32d96f1cf0fa1f996f9f539"}"#;

fn fixture() -> FeedbackInput {
    parse_feedback(include_bytes!(
        "../../../tests/fixtures/feedback/automated-unknown-v1.json"
    ))
    .unwrap()
}
fn prefs() -> FeedbackPreferences {
    FeedbackPreferences {
        collection_enabled: true,
        learning_enabled: true,
        ..Default::default()
    }
}
fn route(abstention: Option<PhaseAbstention>) -> FeedbackRoute {
    FeedbackRoute {
        candidate_id: "fixture-best".into(),
        rank: Some(1),
        margin_micros: Some(200_000),
        alternatives: 2,
        abstention,
    }
}
fn with_route(run: &str, route: FeedbackRoute) -> FeedbackInput {
    let mut value = fixture();
    value.binding.run_hash = redacted_digest(run).unwrap();
    value.context.route = Some(route);
    value
}
fn setup() -> (TempDir, FeedbackStore) {
    let temp = TempDir::new().unwrap();
    let store = FeedbackStore::open(&temp.path().join("feedback")).unwrap();
    store.configure(prefs(), 100).unwrap();
    (temp, store)
}

#[test]
fn v1_database_opens_and_its_events_have_no_route() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("feedback");
    let store = FeedbackStore::open(&path).unwrap();
    store.configure(prefs(), 100).unwrap();
    drop(store);
    let db = rusqlite::Connection::open(path.join("feedback.sqlite3")).unwrap();
    db.execute(
        "INSERT INTO feedback(sequence,run_hash,origin,observed_at,event) VALUES(1,?1,'\"automated\"',101,?2)",
        ["b".repeat(64), V1_EVENT.to_string()],
    )
    .unwrap();
    drop(db);
    let store = FeedbackStore::open(&path).unwrap();
    let stats = store.statistics(102).unwrap();
    assert_eq!(stats.events, 1);
    assert_eq!(stats.transport.passed, 1);
    assert_eq!((stats.route.recorded, stats.route.abstained), (0, 0));
    assert_eq!(stats.unknown_propensities, 1);
    // Replaying the same v1 input matches the stored v1 event hash.
    let replay = store.record(fixture(), 103).unwrap();
    assert_eq!(replay.input.context.route, None);
    assert!(
        !serde_json::to_string(&replay.input)
            .unwrap()
            .contains("route")
    );
    assert!(!serde_json::to_string(&stats).unwrap().contains("route"));
}

#[test]
fn route_facts_are_stored_and_abstentions_are_counted_apart() {
    let (temp, store) = setup();
    let plain = store.record(with_route("one", route(None)), 102).unwrap();
    assert_eq!(plain.input.context.route, Some(route(None)));
    store
        .record(
            with_route("two", route(Some(PhaseAbstention::Ambiguous))),
            102,
        )
        .unwrap();
    store.record(fixture(), 102).unwrap();
    let stats = store.statistics(102).unwrap();
    assert_eq!(stats.events, 3);
    assert_eq!((stats.route.recorded, stats.route.abstained), (2, 1));
    drop(store);
    // The stored text reopens with integrity checks and carries numbers only.
    let store = FeedbackStore::open(&temp.path().join("feedback")).unwrap();
    assert_eq!(store.statistics(102).unwrap().route, stats.route);
    let db = rusqlite::Connection::open(temp.path().join("feedback/feedback.sqlite3")).unwrap();
    let text: String = db
        .query_row("SELECT event FROM feedback WHERE sequence=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(text.contains(
        r#""route":{"candidate_id":"fixture-best","rank":1,"margin_micros":200000,"alternatives":2,"abstention":null}"#
    ));
}

#[test]
fn candidate_ids_up_to_the_policy_bound_are_recorded() {
    let (_temp, store) = setup();
    for (index, len) in [97usize, 128].into_iter().enumerate() {
        let value = FeedbackRoute {
            candidate_id: "c".repeat(len),
            margin_micros: Some(-1),
            ..route(None)
        };
        store
            .record(with_route(&format!("long{index}"), value), 102)
            .unwrap();
    }
    let too_long = FeedbackRoute {
        candidate_id: "c".repeat(129),
        ..route(None)
    };
    assert!(store.record(with_route("long-bad", too_long), 102).is_err());
}

#[test]
fn invalid_route_facts_are_rejected() {
    let (_temp, store) = setup();
    let bad = [
        FeedbackRoute {
            candidate_id: "a\nsecret".into(),
            ..route(None)
        },
        FeedbackRoute {
            candidate_id: String::new(),
            ..route(None)
        },
        FeedbackRoute {
            rank: Some(0),
            ..route(None)
        },
        FeedbackRoute {
            rank: Some(4),
            ..route(None)
        },
        FeedbackRoute {
            alternatives: 65,
            ..route(None)
        },
    ];
    for (index, value) in bad.into_iter().enumerate() {
        assert!(
            store
                .record(with_route(&format!("bad{index}"), value), 102)
                .is_err(),
            "invalid route {index}"
        );
    }
}

#[test]
fn route_facts_hold_no_free_text() {
    // Fails when a String field is added: the only string-valued keys allowed
    // are the existing registered identifiers plus the candidate id.
    let mut value = with_route("one", route(Some(PhaseAbstention::Ambiguous)));
    value.context.agent = Some("agent".into());
    value.context.skills = BTreeSet::from(["skill".to_string()]);
    let json = serde_json::to_value(&value.context).unwrap();
    let mut strings = BTreeSet::new();
    fn walk(prefix: &str, value: &serde_json::Value, out: &mut BTreeSet<String>) {
        match value {
            serde_json::Value::String(_) => {
                out.insert(prefix.to_string());
            }
            serde_json::Value::Object(map) => map
                .iter()
                .for_each(|(k, v)| walk(&format!("{prefix}.{k}"), v, out)),
            serde_json::Value::Array(items) => items
                .iter()
                .for_each(|v| walk(&format!("{prefix}[]"), v, out)),
            _ => {}
        }
    }
    walk("context", &json, &mut strings);
    let expected: BTreeSet<String> = [
        "context.task_kind",
        "context.risk",
        "context.model",
        "context.effort",
        "context.harness",
        "context.transport",
        "context.agent",
        "context.skills[]",
        "context.plan",
        "context.route.candidate_id",
        "context.route.abstention",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(strings, expected);
}

#[test]
fn an_escalated_run_reports_its_real_escalation() {
    let (_temp, store) = setup();
    let mut value = with_route("escalated", route(None));
    value.measurements.escalations = 1;
    let event = store.record(value, 102).unwrap();
    assert_eq!(event.input.measurements.escalations, 1);
    let mut too_many = with_route("too-many", route(None));
    too_many.measurements.escalations = 2;
    assert!(store.record(too_many, 102).is_err());
}
