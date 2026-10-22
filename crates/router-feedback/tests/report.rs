//! `feedback report`: classification, join by run key, cost from stored usage,
//! determinism and consent. Every figure is checked against a hand computation.
use std::collections::BTreeSet;

use router_eval::{PricingTable, TokenPrice};
use router_feedback::*;
use router_types::*;
use tempfile::TempDir;

/// An event stored before `usage` existed: it must round-trip byte for byte.
const V1_EVENT: &str = r#"{"sequence":1,"consent_revision":1,"recorded_at_unix_seconds":102,"input":{"schema_version":1,"observed_at_unix_seconds":101,"binding":{"task_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","run_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","receipt_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","policy_hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","catalog_hash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","snapshot_hash":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","producer_version":"synthetic-contract-v1","provenance_sha256":"1111111111111111111111111111111111111111111111111111111111111111"},"context":{"task_kind":"explore","risk":"low","model":"fixture-model","effort":"medium","harness":"fixture-host","transport":"subprocess-jsonl","agent":null,"skills":[],"plan":"single-pass","propensity_micros":null},"origin":"automated","transport":"passed","validation":"unknown","objective":"unknown","verification_evidence_sha256":null,"human":null,"failure":null,"measurements":{"cost_microusd":null,"latency_ms":100,"tokens":null,"attempts":1,"escalations":0},"comment_sha256":null},"event_hash":"fabf1fb43c1aa19cf1c1487d90bc4ac8f41e5a4af32d96f1cf0fa1f996f9f539"}"#;

fn key(c: char) -> String {
    c.to_string().repeat(64)
}
fn model(name: &str) -> ModelId {
    ModelId::parse(name).unwrap()
}
fn usage(input: u64, cached: u64, output: u64) -> HostUsage {
    HostUsage {
        input_tokens: UsageField::host_reported(input),
        cached_input_tokens: UsageField::host_reported(cached),
        cache_write_input_tokens: UsageField::UNKNOWN,
        output_tokens: UsageField::host_reported(output),
        reasoning_output_tokens: UsageField::UNKNOWN,
    }
}
/// An automated event as the writer records it: verdicts unknown, transport passed.
fn automated(run: &str, run_key: Option<char>, model_name: &str) -> FeedbackInput {
    FeedbackInput {
        schema_version: 1,
        observed_at_unix_seconds: 130,
        started_at_unix_seconds: Some(120),
        run_key_sha256: run_key.map(key),
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
            model: model(model_name),
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
            tokens: None,
            attempts: 1,
            escalations: 0,
            usage: None,
        },
        comment_sha256: None,
    }
}
fn with_usage(mut input: FeedbackInput, usage: HostUsage) -> FeedbackInput {
    input.measurements.tokens = usage.total_tokens();
    input.measurements.usage = Some(usage);
    input
}
fn verification(run_key: char, objective: VerificationOutcome) -> FeedbackFact {
    FeedbackFact {
        schema_version: 1,
        run_key_sha256: key(run_key),
        observed_at_unix_seconds: 150,
        kind: FeedbackFactKind::Verification {
            validation: match objective {
                VerificationOutcome::Passed => VerificationOutcome::Passed,
                _ => VerificationOutcome::Failed,
            },
            objective,
            evidence_sha256: "9".repeat(64),
        },
    }
}
fn integration(run_key: char, outcome: IntegrationOutcome, at: u64) -> FeedbackFact {
    FeedbackFact {
        schema_version: 1,
        run_key_sha256: key(run_key),
        observed_at_unix_seconds: at,
        kind: FeedbackFactKind::Integration { outcome },
    }
}
fn pricing() -> PricingTable {
    PricingTable {
        schema_version: 1,
        version: "test-pricing-v1".into(),
        source: "synthetic".into(),
        observed_at_unix_seconds: 90,
        models: [
            (
                model("model-a"),
                TokenPrice {
                    input_microusd_per_million: 3_000_000,
                    cached_input_microusd_per_million: 300_000,
                    output_microusd_per_million: 15_000_000,
                },
            ),
            (
                model("model-c"),
                TokenPrice {
                    input_microusd_per_million: 1,
                    cached_input_microusd_per_million: 1,
                    output_microusd_per_million: 1,
                },
            ),
        ]
        .into(),
    }
}
fn store(learning: bool) -> (TempDir, FeedbackStore) {
    let temp = TempDir::new().unwrap();
    let store = FeedbackStore::open(&temp.path().join("feedback")).unwrap();
    store
        .configure(
            FeedbackPreferences {
                collection_enabled: true,
                learning_enabled: learning,
                ..Default::default()
            },
            100,
        )
        .unwrap();
    (temp, store)
}
fn json(report: &impl serde::Serialize) -> serde_json::Value {
    serde_json::to_value(report).unwrap()
}
fn group<'a>(report: &'a serde_json::Value, model: &str) -> &'a serde_json::Value {
    report["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["model"] == model)
        .unwrap()
}

/// Seven runs of one model covering every classification.
fn classified() -> (TempDir, FeedbackStore) {
    let (temp, store) = store(true);
    for (run, run_key) in [
        ("accepted", Some('1')),
        ("verification-only", Some('2')),
        ("applied-only", Some('3')),
        ("discarded", Some('4')),
        ("failed-objective", Some('5')),
        ("applied-but-failed", Some('6')),
        ("no-key", None),
    ] {
        store
            .record(automated(run, run_key, "model-a"), 200)
            .unwrap();
    }
    let facts = [
        verification('1', VerificationOutcome::Passed),
        integration('1', IntegrationOutcome::Applied, 200),
        verification('2', VerificationOutcome::Passed),
        integration('3', IntegrationOutcome::Applied, 200),
        integration('4', IntegrationOutcome::Discarded, 200),
        verification('5', VerificationOutcome::Failed),
        verification('6', VerificationOutcome::Failed),
        integration('6', IntegrationOutcome::Applied, 200),
        // A fact whose automated event was never recorded.
        integration('7', IntegrationOutcome::Applied, 200),
    ];
    for fact in facts {
        store.record_fact(fact, 250).unwrap();
    }
    (temp, store)
}

#[test]
fn report_is_byte_identical_for_the_same_inputs() {
    let (_temp, store) = classified();
    let table = pricing();
    let first = serde_json::to_vec(&store.report(Some(&table), 300).unwrap()).unwrap();
    let second = serde_json::to_vec(&store.report(Some(&table), 300).unwrap()).unwrap();
    assert_eq!(first, second);
    let without = serde_json::to_vec(&store.report(None, 300).unwrap()).unwrap();
    assert_ne!(first, without);
}

#[test]
fn outcomes_are_accepted_rejected_or_unknown_and_unknown_is_never_a_failure() {
    let (_temp, store) = classified();
    let report = json(&store.report(None, 300).unwrap());
    let g = group(&report, "model-a");
    assert_eq!(g["runs"], 7);
    // accepted: applied and passed. rejected: discarded, failed objective, and
    // applied with a failed objective. unknown: verification only, applied only,
    // and the run without a key.
    assert_eq!(g["accepted"], 1);
    assert_eq!(g["rejected"], 3);
    assert_eq!(g["unknown"], 3);
    assert_eq!(g["unlinked"], 1);
    assert_eq!(report["unlinked"], 1);
    assert_eq!(report["orphan_facts"], 1);
    // The rate is over decided runs: 1 accepted of 4, the 3 unknown excluded.
    let rate = &g["accepted_rate"];
    assert_eq!(
        (rate["accepted"].clone(), rate["rejected"].clone()),
        (1.into(), 3.into())
    );
    assert_eq!(rate["point_micros"], 250_000);
    assert_eq!(rate["prior"], "jeffreys");
    assert_eq!(rate["level_micros"], 950_000);
    // 3 applied, 1 discarded, 3 without an integration fact.
    assert_eq!(g["integration"]["applied"], 3);
    assert_eq!(g["integration"]["discarded"], 1);
    assert_eq!(g["integration"]["unknown"], 3);
    assert_eq!(g["integration"]["rate_micros"], 750_000);
}

#[test]
fn a_group_with_only_unknown_runs_has_no_rate() {
    let (_temp, store) = store(true);
    store
        .record(automated("pending", Some('1'), "model-a"), 200)
        .unwrap();
    store
        .record_fact(verification('1', VerificationOutcome::Passed), 250)
        .unwrap();
    let report = json(&store.report(None, 300).unwrap());
    let g = group(&report, "model-a");
    assert_eq!(
        (
            g["accepted"].clone(),
            g["rejected"].clone(),
            g["unknown"].clone()
        ),
        (0.into(), 0.into(), 1.into())
    );
    assert!(g["accepted_rate"].is_null());
    assert!(g["integration"]["rate_micros"].is_null());
}

#[test]
fn cost_is_computed_from_stored_usage_and_unknown_without_it() {
    let (_temp, store) = store(true);
    // 600 uncached at 3.0, 400 cached at 0.3, 500 output at 15.0 per million,
    // in micro-dollars: 1_800_000_000 + 120_000_000 + 7_500_000_000 = 9_420 exactly.
    store
        .record(
            with_usage(automated("r1", Some('1'), "model-a"), usage(1000, 400, 500)),
            200,
        )
        .unwrap();
    // 1000 * 3_000_000 + 1 * 15_000_000 = 3_015_000_000 -> 3015.
    store
        .record(
            with_usage(automated("r2", Some('2'), "model-a"), usage(1000, 0, 1)),
            200,
        )
        .unwrap();
    // One token at one micro-dollar per million rounds up to one micro-dollar.
    store
        .record(
            with_usage(automated("r3", Some('3'), "model-c"), usage(1, 0, 0)),
            200,
        )
        .unwrap();
    // No usage stored: unknown, never zero.
    store
        .record(automated("r4", Some('4'), "model-b"), 200)
        .unwrap();
    // Model absent from the table: unknown.
    store
        .record(
            with_usage(automated("r5", Some('5'), "model-d"), usage(10, 0, 10)),
            200,
        )
        .unwrap();
    for run_key in ['1', '3'] {
        store
            .record_fact(verification(run_key, VerificationOutcome::Passed), 250)
            .unwrap();
        store
            .record_fact(integration(run_key, IntegrationOutcome::Applied, 200), 250)
            .unwrap();
    }
    let report = json(&store.report(Some(&pricing()), 300).unwrap());
    assert_eq!(report["pricing"]["version"], "test-pricing-v1");
    assert_eq!(report["pricing"]["source"], "synthetic");

    let a = &group(&report, "model-a")["cost"];
    assert_eq!(a["priced_runs"], 2);
    assert_eq!(a["cost_unknown"], 0);
    assert_eq!(a["total_microusd"], 9_420 + 3_015);
    // One accepted task carries the cost of both runs.
    assert_eq!(a["per_accepted_microusd"], 9_420 + 3_015);

    let c = &group(&report, "model-c")["cost"];
    assert_eq!(c["total_microusd"], 1);
    assert_eq!(c["per_accepted_microusd"], 1);

    for unknown in ["model-b", "model-d"] {
        let cost = &group(&report, unknown)["cost"];
        assert_eq!(cost["priced_runs"], 0);
        assert_eq!(cost["cost_unknown"], 1);
        assert!(cost["total_microusd"].is_null());
        assert_eq!(cost["reason"], "no_priced_runs");
    }
}

#[test]
fn per_accepted_cost_is_null_while_a_run_of_the_group_is_unpriced() {
    let (_temp, store) = store(true);
    store
        .record(
            with_usage(automated("r1", Some('1'), "model-a"), usage(1000, 400, 500)),
            200,
        )
        .unwrap();
    store
        .record(automated("r2", Some('2'), "model-a"), 200)
        .unwrap();
    store
        .record_fact(verification('1', VerificationOutcome::Passed), 250)
        .unwrap();
    store
        .record_fact(integration('1', IntegrationOutcome::Applied, 200), 250)
        .unwrap();
    let report = json(&store.report(Some(&pricing()), 300).unwrap());
    let cost = &group(&report, "model-a")["cost"];
    assert!(cost["total_microusd"].is_null());
    assert_eq!(cost["known_subtotal_microusd"], 9_420);
    assert!(cost["per_accepted_microusd"].is_null());
    assert_eq!(cost["reason"], "cost_unknown_runs");
}

#[test]
fn without_a_pricing_table_every_cost_is_null_with_a_reason() {
    let (_temp, store) = store(true);
    store
        .record(
            with_usage(automated("r1", Some('1'), "model-a"), usage(1000, 400, 500)),
            200,
        )
        .unwrap();
    let report = json(&store.report(None, 300).unwrap());
    assert!(report["pricing"].is_null());
    let cost = &group(&report, "model-a")["cost"];
    assert!(cost["total_microusd"].is_null());
    assert!(cost["per_accepted_microusd"].is_null());
    assert_eq!(cost["reason"], "no_pricing_table");
}

#[test]
fn an_unusable_pricing_table_is_refused() {
    let (_temp, store) = store(true);
    let mut table = pricing();
    table.source = " ".into();
    assert!(matches!(
        store.report(Some(&table), 300),
        Err(FeedbackError::Invalid("pricing"))
    ));
}

#[test]
fn time_to_acceptance_needs_a_start_time_and_counts_the_missing() {
    let (_temp, store) = store(true);
    // Started at 120 and applied at 200: 80 seconds.
    store
        .record(automated("timed", Some('1'), "model-a"), 200)
        .unwrap();
    let mut untimed = automated("untimed", Some('2'), "model-a");
    untimed.started_at_unix_seconds = None;
    store.record(untimed, 200).unwrap();
    for run_key in ['1', '2'] {
        store
            .record_fact(verification(run_key, VerificationOutcome::Passed), 250)
            .unwrap();
        store
            .record_fact(integration(run_key, IntegrationOutcome::Applied, 200), 250)
            .unwrap();
    }
    let report = json(&store.report(None, 300).unwrap());
    let t = &group(&report, "model-a")["time_to_acceptance_seconds"];
    assert_eq!(t["samples"], 1);
    assert_eq!(t["missing"], 1);
    assert_eq!(t["p50"], 80);
    assert_eq!(t["p90"], 80);
}

#[test]
fn human_verdicts_are_counted_apart_from_automated_outcomes() {
    let (_temp, store) = store(true);
    let run = automated("reviewed", Some('1'), "model-a");
    store.record(run.clone(), 200).unwrap();
    let mut human = run;
    human.origin = FeedbackOrigin::Human;
    human.human = Some(HumanVerdict {
        success: VerificationOutcome::Passed,
        quality: Some(80),
        perceived_cost: PerceivedCost::Low,
        correction_required: None,
        reviewer_sha256: "2".repeat(64),
    });
    store.record(human, 200).unwrap();
    let report = json(&store.report(None, 300).unwrap());
    let g = group(&report, "model-a");
    assert_eq!(report["human_events"], 1);
    assert_eq!(report["automated_events"], 1);
    assert_eq!(g["runs"], 1);
    assert_eq!(g["human"]["passed"], 1);
    // A human verdict never makes an automated run accepted.
    assert_eq!(g["accepted"], 0);
    assert_eq!(g["unknown"], 1);
}

#[test]
fn report_requires_collection_consent() {
    let temp = TempDir::new().unwrap();
    let store = FeedbackStore::open(&temp.path().join("feedback")).unwrap();
    assert!(matches!(
        store.report(None, 300),
        Err(FeedbackError::Consent)
    ));
    store
        .configure(
            FeedbackPreferences {
                collection_enabled: true,
                ..Default::default()
            },
            100,
        )
        .unwrap();
    assert!(store.report(None, 300).is_ok());
    store
        .configure(FeedbackPreferences::default(), 310)
        .unwrap();
    assert!(matches!(
        store.report(None, 320),
        Err(FeedbackError::Consent)
    ));
}

#[test]
fn advisory_needs_learning_and_never_carries_a_suggestion() {
    let (_temp, disabled) = store(false);
    let report = json(&disabled.report(None, 300).unwrap());
    assert_eq!(
        report["advisory"],
        serde_json::json!({"advisory": null, "reason": "learning_disabled"})
    );
    let (_temp, enabled) = store(true);
    let report = json(&enabled.report(None, 300).unwrap());
    assert_eq!(report["advisory"]["advisory"], true);
    assert!(report["advisory"]["suggestion"].is_null());
    assert!(report["advisory"].get("suggestion").is_some());
    assert!(report["catalog_estimate_ratio"]["value"].is_null());
    assert_eq!(
        report["catalog_estimate_ratio"]["reason"],
        "no_catalog_estimate_stored_in_feedback"
    );
}

#[test]
fn an_event_without_usage_keeps_its_bytes() {
    let event: FeedbackEvent = serde_json::from_str(V1_EVENT).unwrap();
    assert!(event.input.measurements.usage.is_none());
    assert_eq!(serde_json::to_string(&event).unwrap(), V1_EVENT);
    assert!(event.input.measurements.usage_scope.is_none());
    let (_temp, store) = store(false);
    assert_eq!(
        store.record(event.input.clone(), 102).unwrap().event_hash,
        event.event_hash
    );
}

#[test]
fn usage_is_stored_and_read_back_and_inconsistent_usage_is_refused() {
    let (_temp, store) = store(true);
    let stored = store
        .record(
            with_usage(automated("r1", Some('1'), "model-a"), usage(1000, 400, 500)),
            200,
        )
        .unwrap();
    assert_eq!(stored.input.measurements.usage, Some(usage(1000, 400, 500)));
    assert_eq!(store.events(300).unwrap()[0], stored);

    let cached_over_input = with_usage(automated("r2", Some('2'), "model-a"), usage(10, 11, 5));
    assert!(matches!(
        store.record(cached_over_input, 200),
        Err(FeedbackError::Invalid("usage"))
    ));
    let mut reasoning_over_output = usage(10, 0, 5);
    reasoning_over_output.reasoning_output_tokens = UsageField::host_reported(6);
    assert!(matches!(
        store.record(
            with_usage(automated("r3", Some('3'), "model-a"), reasoning_over_output),
            200
        ),
        Err(FeedbackError::Invalid("usage"))
    ));
    let mut over_bound = usage(10, 0, 5);
    over_bound.input_tokens = UsageField::host_reported(MAX_VALUE + 1);
    assert!(matches!(
        store.record(
            with_usage(automated("r4", Some('4'), "model-a"), over_bound),
            200
        ),
        Err(FeedbackError::Invalid("usage"))
    ));
    let mut disagreeing = usage(10, 0, 5);
    disagreeing.output_tokens = UsageField {
        tokens: Some(5),
        provenance: UsageProvenance::Unknown,
    };
    assert!(matches!(
        store.record(
            with_usage(automated("r5", Some('5'), "model-a"), disagreeing),
            200
        ),
        Err(FeedbackError::Invalid("usage"))
    ));
}

#[test]
fn a_run_key_is_counted_once_on_its_latest_event() {
    let (_temp, store) = store(true);
    // Same run key, different run_hash: the second event carries a later state.
    store
        .record(
            with_usage(
                automated("state-1", Some('1'), "model-a"),
                usage(1000, 400, 500),
            ),
            200,
        )
        .unwrap();
    store
        .record(
            with_usage(
                automated("state-2", Some('1'), "model-a"),
                usage(1000, 0, 1),
            ),
            200,
        )
        .unwrap();
    store
        .record_fact(verification('1', VerificationOutcome::Passed), 250)
        .unwrap();
    store
        .record_fact(integration('1', IntegrationOutcome::Applied, 200), 250)
        .unwrap();
    let report = json(&store.report(Some(&pricing()), 300).unwrap());
    let g = group(&report, "model-a");
    assert_eq!(report["superseded_events"], 1);
    assert_eq!(report["automated_events"], 1);
    let rows = report["runs"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["binding"]["run_hash"],
        redacted_digest("state-2").unwrap()
    );
    assert_eq!(rows[0]["usage"]["cached_input_tokens"]["tokens"], 0);
    assert_eq!(rows[0]["verdict"], "accepted");
    assert_eq!(
        (g["runs"].clone(), g["accepted"].clone()),
        (1.into(), 1.into())
    );
    assert_eq!(g["integration"]["applied"], 1);
    // Only the latest event is priced: 3015, not 3015 + 9420.
    assert_eq!(g["cost"]["total_microusd"], 3_015);
    assert_eq!(report["orphan_facts"], 0);
}

#[test]
fn cache_writes_are_priced_as_input_once_and_counted() {
    let (_temp, store) = store(true);
    let mut split = usage(1000, 300, 100);
    split.cache_write_input_tokens = UsageField::host_reported(200);
    // 700 non cached input (writes included) at 3.0, 300 cached at 0.3, 100
    // output at 15.0: 2_100_000_000 + 90_000_000 + 1_500_000_000 = 3_690 micros.
    // Charging the 200 writes again would give 3_690 + 600 = 4_290.
    store
        .record(
            with_usage(automated("r1", Some('1'), "model-a"), split),
            200,
        )
        .unwrap();
    store
        .record(
            with_usage(automated("r2", Some('2'), "model-a"), usage(1000, 0, 1)),
            200,
        )
        .unwrap();
    let report = json(&store.report(Some(&pricing()), 300).unwrap());
    let cost = &group(&report, "model-a")["cost"];
    assert_eq!(cost["total_microusd"], 3_690 + 3_015);
    assert_eq!(cost["runs_with_cache_writes_priced_as_input"], 1);
}

#[test]
fn per_accepted_cost_is_null_when_no_task_was_accepted() {
    let (_temp, store) = store(true);
    store
        .record(
            with_usage(automated("r1", Some('1'), "model-a"), usage(1000, 400, 500)),
            200,
        )
        .unwrap();
    store
        .record_fact(integration('1', IntegrationOutcome::Discarded, 200), 250)
        .unwrap();
    let report = json(&store.report(Some(&pricing()), 300).unwrap());
    let cost = &group(&report, "model-a")["cost"];
    assert_eq!(cost["total_microusd"], 9_420);
    assert!(cost["per_accepted_microusd"].is_null());
    assert_eq!(cost["reason"], "no_accepted_task");
}

#[test]
fn a_passed_objective_needs_a_passed_validation_so_objective_alone_decides() {
    let (_temp, store) = store(true);
    let fact = FeedbackFact {
        schema_version: 1,
        run_key_sha256: key('1'),
        observed_at_unix_seconds: 150,
        kind: FeedbackFactKind::Verification {
            validation: VerificationOutcome::Failed,
            objective: VerificationOutcome::Passed,
            evidence_sha256: "9".repeat(64),
        },
    };
    assert!(matches!(
        store.record_fact(fact, 250),
        Err(FeedbackError::Invalid("verification fact"))
    ));
}

#[test]
fn usage_must_agree_with_itself_and_with_the_total() {
    let (_temp, store) = store(true);
    // Reads and writes are disjoint subsets of input: 600 + 500 > 1000.
    let mut overlapping = usage(1000, 600, 10);
    overlapping.cache_write_input_tokens = UsageField::host_reported(500);
    assert!(matches!(
        store.record(
            with_usage(automated("r1", Some('1'), "model-a"), overlapping),
            200
        ),
        Err(FeedbackError::Invalid("usage"))
    ));
    let mut fits = usage(1000, 600, 10);
    fits.cache_write_input_tokens = UsageField::host_reported(400);
    store
        .record(with_usage(automated("r2", Some('2'), "model-a"), fits), 200)
        .unwrap();
    // A total that is not the split's total.
    let mut wrong_total = with_usage(automated("r3", Some('3'), "model-a"), usage(1000, 0, 10));
    wrong_total.measurements.tokens = Some(1);
    assert!(matches!(
        store.record(wrong_total, 200),
        Err(FeedbackError::Invalid("usage"))
    ));
    // A total beside a split whose output is unknown has no total to match.
    let mut unknown_output = usage(1000, 0, 10);
    unknown_output.output_tokens = UsageField::UNKNOWN;
    let mut input = automated("r4", Some('4'), "model-a");
    input.measurements.usage = Some(unknown_output);
    input.measurements.tokens = Some(1010);
    assert!(matches!(
        store.record(input, 200),
        Err(FeedbackError::Invalid("usage"))
    ));
    // A split alone, and a total alone, stay valid.
    let mut split_only = automated("r5", Some('5'), "model-a");
    split_only.measurements.usage = Some(unknown_output);
    store.record(split_only, 200).unwrap();
    let mut total_only = automated("r6", Some('6'), "model-a");
    total_only.measurements.tokens = Some(42);
    store.record(total_only, 200).unwrap();
}

/// `classified()` plus two more groups, so the total spans three groups.
fn multi_group() -> (TempDir, FeedbackStore) {
    let (temp, store) = classified();
    // model-c: accepted after 60 s, priced. model-b: accepted after 10 s, no usage.
    store
        .record(
            with_usage(automated("c1", Some('8'), "model-c"), usage(1, 0, 0)),
            260,
        )
        .unwrap();
    store
        .record(automated("b1", Some('9'), "model-b"), 260)
        .unwrap();
    for (run_key, at) in [('8', 180), ('9', 130)] {
        store
            .record_fact(verification(run_key, VerificationOutcome::Passed), 270)
            .unwrap();
        store
            .record_fact(integration(run_key, IntegrationOutcome::Applied, at), 270)
            .unwrap();
    }
    (temp, store)
}

fn sum(report: &serde_json::Value, key: &str) -> u64 {
    report["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g[key].as_u64().unwrap())
        .sum()
}

#[test]
fn summary_is_byte_identical_for_the_same_inputs() {
    let (_temp, store) = multi_group();
    let table = pricing();
    let first = serde_json::to_vec(&store.summary(Some(&table), 300).unwrap()).unwrap();
    let second = serde_json::to_vec(&store.summary(Some(&table), 300).unwrap()).unwrap();
    assert_eq!(first, second);
    let without = serde_json::to_vec(&store.summary(None, 300).unwrap()).unwrap();
    assert_ne!(first, without);
}

#[test]
fn summary_totals_equal_the_sum_of_the_report_groups() {
    let (_temp, store) = multi_group();
    let (report, summary) = store.report_and_summary(Some(&pricing()), 300).unwrap();
    let report_json = json(&report);
    let summary_json = serde_json::to_value(&summary).unwrap();
    assert_eq!(report_json["groups"].as_array().unwrap().len(), 3);
    for key in ["runs", "accepted", "rejected", "unknown"] {
        assert_eq!(
            summary_json[key].as_u64().unwrap(),
            sum(&report_json, key),
            "{key}"
        );
    }
    // Hand count: model-a 7 runs (1 accepted, 3 rejected, 3 unknown), model-c
    // 1 accepted, model-b 1 accepted.
    assert_eq!(
        (
            summary.runs,
            summary.accepted,
            summary.rejected,
            summary.unknown
        ),
        (9, 3, 3, 3)
    );
    assert_eq!(summary.unknown_counts.unlinked, report.unlinked);
    assert_eq!(summary.unknown_counts.orphan_facts, report.orphan_facts);
    assert_eq!(
        summary.unknown_counts.superseded_events,
        report.superseded_events
    );
    assert_eq!(summary.event_set_hash, report.event_set_hash);
    assert_eq!(summary.fact_set_hash, report.fact_set_hash);
    assert_eq!(summary.report_content_hash, report.content_hash);
    // The rate is over decided runs of every group: 3 accepted of 6.
    let rate = summary.accepted_rate.as_ref().unwrap();
    assert_eq!(
        (rate.accepted, rate.rejected, rate.point_micros),
        (3, 3, 500_000)
    );
    assert_eq!(rate.prior, "jeffreys");
    // Percentiles come from the merged accepted runs (started at 120):
    // model-a 200 - 120 = 80, model-c 180 - 120 = 60, model-b 130 - 120 = 10.
    let p = &summary.time_to_acceptance_seconds;
    assert_eq!(
        (p.samples, p.missing, p.p50, p.p90),
        (3, 0, Some(60), Some(80))
    );
    // Cost: only the model-c run is priced; model-a runs carry no usage and
    // model-b is not in the table, so those 8 runs stay unknown.
    let priced: u64 = report_json["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["cost"]["priced_runs"].as_u64().unwrap())
        .sum();
    assert_eq!(summary.cost.priced_runs, priced);
    assert_eq!(summary.cost.priced_runs, 1);
    assert_eq!(summary.cost.cost_unknown, 8);
    assert_eq!(summary.unknown_counts.cost, 8);
}

#[test]
fn summary_unknown_is_never_counted_as_a_failure() {
    let (_temp, store) = classified();
    let summary = store.summary(None, 300).unwrap();
    // 3 of the 7 runs have no verdict: they are neither accepted nor rejected,
    // and they stay out of the rate denominator.
    assert_eq!(summary.unknown, 3);
    assert_eq!(summary.unknown_counts.verdict, 3);
    let rate = summary.accepted_rate.unwrap();
    assert_eq!((rate.accepted, rate.rejected), (1, 3));
    assert_eq!(rate.point_micros, 250_000);
    assert_eq!(summary.attribution, "not_established");
}

#[test]
fn summary_cost_per_accepted_is_null_with_a_reason_while_any_run_is_unpriced() {
    let (_temp, store) = multi_group();
    // model-a runs have no usage and model-b is not in the table.
    let with_table = store.summary(Some(&pricing()), 300).unwrap();
    assert_eq!(with_table.cost.total_microusd, None);
    assert_eq!(with_table.cost.known_subtotal_microusd, Some(1));
    assert_eq!(with_table.cost.per_accepted_microusd, None);
    assert_eq!(with_table.cost.reason, Some("cost_unknown_runs"));
    let without_table = store.summary(None, 300).unwrap();
    assert_eq!(without_table.cost.total_microusd, None);
    assert_eq!(without_table.cost.reason, Some("no_pricing_table"));

    // Every run priced: the total over all runs is divided by accepted tasks.
    let (_temp, store) = self::store(true);
    for (run, run_key, u) in [
        ("r1", '1', usage(1000, 400, 500)),
        ("r2", '2', usage(1000, 0, 1)),
    ] {
        store
            .record(with_usage(automated(run, Some(run_key), "model-a"), u), 200)
            .unwrap();
    }
    store
        .record_fact(verification('1', VerificationOutcome::Passed), 250)
        .unwrap();
    store
        .record_fact(integration('1', IntegrationOutcome::Applied, 200), 250)
        .unwrap();
    let priced = store.summary(Some(&pricing()), 300).unwrap();
    assert_eq!(priced.cost.total_microusd, Some(9_420 + 3_015));
    assert_eq!(priced.cost.per_accepted_microusd, Some(9_420 + 3_015));
    assert_eq!(priced.cost.reason, None);
}

#[test]
fn summary_of_an_empty_store_has_no_rate_and_needs_consent() {
    let (_temp, store) = self::store(true);
    let summary = store.summary(None, 300).unwrap();
    assert_eq!(
        (summary.runs, summary.accepted, summary.rejected),
        (0, 0, 0)
    );
    assert!(summary.accepted_rate.is_none());
    assert_eq!(summary.time_to_acceptance_seconds.p50, None);
    let temp = TempDir::new().unwrap();
    let closed = FeedbackStore::open(&temp.path().join("feedback")).unwrap();
    assert!(matches!(
        closed.summary(None, 300),
        Err(FeedbackError::Consent)
    ));
}

#[test]
fn run_rows_preserve_outcomes_missing_usage_and_feedback_provenance() {
    let (_temp, store) = store(false);
    let accepted = store
        .record(
            with_usage(automated("accepted", Some('1'), "model-a"), usage(10, 0, 5)),
            200,
        )
        .unwrap();
    let mut failed = automated("failed", Some('2'), "model-a");
    failed.binding.task_hash = key('2');
    failed.transport = VerificationOutcome::Failed;
    failed.failure = Some(FeedbackFailure::Timeout);
    let failed = store.record(failed, 200).unwrap();
    let mut missing = automated("missing", None, "model-a");
    missing.binding.task_hash = key('3');
    let missing = store.record(missing, 200).unwrap();
    let verified = store
        .record_fact(verification('1', VerificationOutcome::Passed), 250)
        .unwrap();
    let applied = store
        .record_fact(integration('1', IntegrationOutcome::Applied, 200), 250)
        .unwrap();
    store
        .record_fact(verification('2', VerificationOutcome::Failed), 250)
        .unwrap();
    let report = json(&store.report(None, 300).unwrap());
    let rows = report["runs"]
        .as_array()
        .expect("report must expose retained run rows");
    assert_eq!(rows.len(), 3);
    for (row, event) in rows.iter().zip([&accepted, &failed, &missing]) {
        assert_eq!(
            row["binding"],
            serde_json::to_value(&event.input.binding).unwrap()
        );
        assert_eq!(row["evidence"]["feedback_event_hash"], event.event_hash);
        assert_eq!(row["evidence"]["source"], "feedback_store");
        assert_eq!(row["evidence"]["runtime_evidence"], "unknown");
        assert_eq!(row["evidence"]["native_external_evidence"], "unknown");
        assert_eq!(row["model"], "model-a");
    }
    assert_eq!(rows[0]["verdict"], "accepted");
    assert_eq!(
        rows[0]["evidence"]["verification_fact_hash"],
        verified.fact_hash
    );
    assert_eq!(
        rows[0]["evidence"]["integration_fact_hash"],
        applied.fact_hash
    );
    assert_eq!(rows[0]["usage"]["input_tokens"]["tokens"], 10);
    assert_eq!(
        rows[0]["usage"]["input_tokens"]["provenance"],
        "host_reported"
    );
    assert_eq!(
        rows[0]["usage"]["cache_write_input_tokens"]["provenance"],
        "unknown"
    );
    assert_eq!(rows[1]["verdict"], "rejected");
    assert_eq!(rows[1]["transport"], "failed");
    assert_eq!(rows[1]["failure"], "timeout");
    assert!(rows[1]["usage"].is_null());
    assert_eq!(rows[2]["verdict"], "unknown");
    assert_eq!(rows[2]["transport"], "passed");
    assert!(rows[2]["usage"].is_null());
    assert!(rows[2]["run_key_sha256"].is_null());
    assert!(rows[2]["evidence"]["verification_fact_hash"].is_null());
    assert!(rows[2]["evidence"]["integration_fact_hash"].is_null());
    assert_eq!(report, json(&store.report(None, 300).unwrap()));
}

// Regressions: dropping earlier attempts, pricing duplicate snapshots twice,
// and presenting incomplete retry coverage as a complete total.
fn attempt(snapshot: &str, ordinal: u32, split: HostUsage) -> FeedbackInput {
    let mut value =
        serde_json::to_value(with_usage(automated(snapshot, Some('1'), "model-a"), split)).unwrap();
    value["measurements"]["attempts"] = ordinal.into();
    value["measurements"]["usage_scope"] = "per_attempt".into();
    serde_json::from_value(value).unwrap()
}

#[test]
fn attempts_are_priced_once_while_the_run_keeps_one_verdict() {
    let (_temp, store) = store(true);
    let mut first = attempt("failed-attempt-1", 1, usage(10, 0, 2));
    first.transport = VerificationOutcome::Failed;
    first.failure = Some(FeedbackFailure::Timeout);
    store.record(first, 200).unwrap();
    store
        .record(attempt("attempt-2", 2, usage(20, 0, 3)), 200)
        .unwrap();
    store
        .record(attempt("attempt-2-later-state", 2, usage(20, 0, 3)), 200)
        .unwrap();
    store
        .record_fact(verification('1', VerificationOutcome::Passed), 250)
        .unwrap();
    store
        .record_fact(integration('1', IntegrationOutcome::Applied, 200), 250)
        .unwrap();
    let report = store.report(Some(&pricing()), 300).unwrap();
    let summary = store.summary(Some(&pricing()), 300).unwrap();
    let cost = json(&summary.cost);
    assert_eq!(
        (report.runs.len(), summary.runs, summary.accepted),
        (1, 1, 1)
    );
    assert_eq!(cost["total_microusd"], 165); // (10*3 + 2*15) + (20*3 + 3*15)
    assert_eq!(cost["known_subtotal_microusd"], 165);
    assert_eq!(cost["priced_attempts"], 2);
    assert_eq!(cost["expected_attempts"], 2);
    assert_eq!(cost["missing_attempts"], 0);
    assert_eq!(cost["per_accepted_microusd"], 165);
    assert_eq!(json(&report.groups[0].cost), cost);
}

#[test]
fn missing_attempts_keep_known_cost_without_claiming_a_total() {
    let (_temp, store) = store(true);
    store
        .record(attempt("attempt-3-only", 3, usage(20, 0, 3)), 200)
        .unwrap();
    let cost = json(&store.summary(Some(&pricing()), 300).unwrap().cost);
    assert!(cost["total_microusd"].is_null());
    assert_eq!(cost["known_subtotal_microusd"], 105);
    assert_eq!(cost["expected_attempts"], 3);
    assert_eq!(cost["priced_attempts"], 1);
    assert_eq!(cost["missing_attempts"], 2);
    assert_eq!(cost["cost_unknown"], 1);
}

#[test]
fn conflicting_attempt_snapshots_are_unknown_not_last_writer_wins() {
    let (_temp, store) = store(true);
    store
        .record(attempt("attempt-1", 1, usage(10, 0, 2)), 200)
        .unwrap();
    store
        .record(attempt("conflicting-attempt-1", 1, usage(11, 0, 2)), 200)
        .unwrap();
    store
        .record(attempt("attempt-2", 2, usage(20, 0, 3)), 200)
        .unwrap();
    let cost = json(&store.summary(Some(&pricing()), 300).unwrap().cost);
    assert!(cost["total_microusd"].is_null());
    assert_eq!(cost["known_subtotal_microusd"], 105);
    assert_eq!(cost["conflicting_attempts"], 1);
    assert_eq!(cost["priced_attempts"], 1);
    assert_eq!(cost["missing_attempts"], 0);
}

#[test]
fn legacy_multi_attempt_usage_cannot_claim_complete_cost() {
    let (_temp, store) = store(true);
    let mut input = with_usage(
        automated("legacy-retry", Some('1'), "model-a"),
        usage(20, 0, 3),
    );
    input.measurements.attempts = 2;
    store.record(input, 200).unwrap();
    let cost = store.summary(Some(&pricing()), 300).unwrap().cost;
    assert_eq!(cost.total_microusd, None);
    assert_eq!(cost.cost_unknown, 1);
}

#[test]
fn rejected_attempts_retain_cost_with_no_accepted_denominator() {
    let (_temp, store) = store(true);
    store
        .record(attempt("attempt-1", 1, usage(10, 0, 2)), 200)
        .unwrap();
    store
        .record(attempt("attempt-2", 2, usage(20, 0, 3)), 200)
        .unwrap();
    store
        .record_fact(integration('1', IntegrationOutcome::Discarded, 200), 250)
        .unwrap();
    let summary = store.summary(Some(&pricing()), 300).unwrap();
    assert_eq!(summary.rejected, 1);
    assert_eq!(summary.cost.total_microusd, Some(165));
    assert_eq!(summary.cost.per_accepted_microusd, None);
    assert_eq!(summary.cost.reason, Some("no_accepted_task"));
}

#[test]
fn attempt_coverage_keeps_cost_when_usage_or_price_is_missing() {
    for missing_price in [false, true] {
        let (_temp, store) = store(true);
        store
            .record(attempt("first", 1, usage(10, 0, 2)), 200)
            .unwrap();
        let mut unknown = attempt("second", 2, usage(20, 0, 3));
        if missing_price {
            unknown.context.model = model("not-priced");
        } else {
            unknown.measurements.usage = None;
            unknown.measurements.tokens = None;
        }
        store.record(unknown, 200).unwrap();
        let summary = store.summary(Some(&pricing()), 300).unwrap();
        assert_eq!(summary.cost.known_subtotal_microusd, Some(60));
        assert_eq!(summary.cost.total_microusd, None);
        assert_eq!(
            (
                summary.cost.observed_attempts,
                summary.cost.priced_attempts,
                summary.cost.missing_attempts
            ),
            (2, 1, 0)
        );
    }
}

#[test]
fn attempt_models_are_priced_individually_under_latest_run_group() {
    let (_temp, store) = store(true);
    store
        .record(attempt("first", 1, usage(10, 0, 2)), 200)
        .unwrap();
    let mut second = attempt("second", 2, usage(20, 0, 3));
    second.context.model = model("model-c");
    store.record(second, 200).unwrap();
    let report = store.report(Some(&pricing()), 300).unwrap();
    assert_eq!(report.groups.len(), 1);
    assert_eq!(report.groups[0].model, "model-c");
    assert_eq!(report.groups[0].cost.total_microusd, Some(61));
    assert_eq!(report.runs[0].cost, report.groups[0].cost);
}

#[test]
fn a_later_snapshot_cannot_hide_the_highest_attempt_ordinal() {
    let (_temp, store) = store(true);
    store
        .record(attempt("third", 3, usage(20, 0, 3)), 200)
        .unwrap();
    store
        .record(attempt("first-arrived-late", 1, usage(10, 0, 2)), 200)
        .unwrap();
    let cost = store.summary(Some(&pricing()), 300).unwrap().cost;
    assert_eq!(cost.expected_attempts, 3);
    assert_eq!(cost.missing_attempts, 1);
    assert_eq!(cost.known_subtotal_microusd, Some(165));
    assert_eq!(cost.total_microusd, None);
}

#[test]
fn mixed_scope_conflicting_first_attempt_is_unknown() {
    let (_temp, store) = store(true);
    store
        .record(
            with_usage(
                automated("legacy-first", Some('1'), "model-a"),
                usage(10, 0, 2),
            ),
            200,
        )
        .unwrap();
    store
        .record(attempt("marked-first", 1, usage(20, 0, 3)), 200)
        .unwrap();
    let cost = store.summary(Some(&pricing()), 300).unwrap().cost;
    assert_eq!(cost.total_microusd, None);
    assert_eq!(cost.conflicting_attempts, 1);
}

#[test]
fn mixed_scope_unmarked_retry_blocks_complete_total() {
    let (_temp, store) = store(true);
    store
        .record(attempt("first", 1, usage(10, 0, 2)), 200)
        .unwrap();
    store
        .record(attempt("second", 2, usage(20, 0, 3)), 200)
        .unwrap();
    let mut legacy = with_usage(
        automated("legacy-retry", Some('1'), "model-a"),
        usage(100, 0, 20),
    );
    legacy.measurements.attempts = 2;
    store.record(legacy, 200).unwrap();
    let cost = store.summary(Some(&pricing()), 300).unwrap().cost;
    assert_eq!(cost.total_microusd, None);
    assert_eq!(cost.known_subtotal_microusd, Some(165));
    assert_eq!(cost.scope_unknown_runs, 1);
}

#[test]
fn mixed_scope_preserves_an_unambiguous_legacy_first_attempt() {
    let (_temp, store) = store(true);
    store
        .record(
            with_usage(
                automated("legacy-first", Some('1'), "model-a"),
                usage(10, 0, 2),
            ),
            200,
        )
        .unwrap();
    store
        .record(attempt("marked-second", 2, usage(20, 0, 3)), 200)
        .unwrap();
    let cost = store.summary(Some(&pricing()), 300).unwrap().cost;
    assert_eq!(cost.total_microusd, Some(165));
    assert_eq!(cost.priced_attempts, 2);
}

fn inventory_run(
    run: char,
    occurrence: char,
    attempts: u32,
    state: RunState,
) -> FeedbackRuntimeRun {
    FeedbackRuntimeRun {
        run_key_sha256: key(run),
        feedback_run_keys_sha256: vec![key(run)],
        occurrence_sha256: key(occurrence),
        predecessor_run_key_sha256: None,
        attempts,
        state,
    }
}

#[test]
fn runtime_reconciliation_keeps_escalation_abandonment_and_missing_feedback_separate() {
    let (_temp, store) = store(false);
    for (name, run_key, count) in [("failed", '1', 10), ("success", '2', 20)] {
        let mut event = with_usage(
            automated(name, Some(run_key), "model-a"),
            usage(count, 0, 0),
        );
        event.measurements.usage_scope = Some(FeedbackUsageScope::PerAttempt);
        store.record(event, 130).unwrap();
    }
    store
        .record_fact(verification('2', VerificationOutcome::Passed), 160)
        .unwrap();
    store
        .record_fact(integration('2', IntegrationOutcome::Applied, 160), 160)
        .unwrap();
    let mut escalation = inventory_run('2', 'a', 1, RunState::Verified);
    escalation.predecessor_run_key_sha256 = Some(key('1'));
    let inventory = FeedbackRuntimeInventory {
        schema_version: 1,
        journal_sha256: key('f'),
        runs: vec![
            inventory_run('1', 'a', 1, RunState::Failed),
            escalation,
            inventory_run('3', 'b', 1, RunState::Cancelled),
            inventory_run('4', 'c', 1, RunState::Verified),
        ],
    };
    let (report, summary) = store
        .report_and_summary_with_inventory(Some(&pricing()), Some(&inventory), 200)
        .unwrap();
    let tasks = report.task_measurement.unwrap();
    assert_eq!(summary.task_measurement, Some(tasks.clone()));
    assert_eq!(tasks.occurrences.len(), 3);
    assert_eq!(tasks.occurrences[0].status, "accepted");
    assert_eq!(tasks.occurrences[0].escalations, 1);
    assert_eq!(tasks.occurrences[1].status, "abandoned");
    // Verification is not task acceptance, and missing feedback is not failure.
    assert_eq!(tasks.occurrences[2].status, "unknown");
    assert_eq!(tasks.expected_attempts, 4);
    assert_eq!(tasks.feedback_attempts, 2);
    assert_eq!(tasks.missing_feedback_attempts, 2);
    assert_eq!(tasks.accepted_occurrences, 1);
    assert!(tasks.known_subtotal_microusd.unwrap() > 0);
    assert_eq!(tasks.total_microusd, None);
    assert_eq!(tasks.per_accepted_microusd, None);
}

#[test]
fn verified_recovery_without_acceptance_feedback_is_not_reported_as_failed() {
    let (_temp, store) = store(false);
    let inventory = FeedbackRuntimeInventory {
        schema_version: 1,
        journal_sha256: key('f'),
        runs: vec![
            inventory_run('1', 'a', 1, RunState::Failed),
            inventory_run('2', 'a', 1, RunState::Verified),
        ],
    };
    let (report, _) = store
        .report_and_summary_with_inventory(None, Some(&inventory), 200)
        .unwrap();
    assert_eq!(
        report.task_measurement.unwrap().occurrences[0].status,
        "unknown"
    );
}
