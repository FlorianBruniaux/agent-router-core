use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

use router_feedback::*;
use router_types::*;
use tempfile::TempDir;

mod common;

fn input(run: &str, observed: u64) -> FeedbackInput {
    FeedbackInput {
        schema_version: 1,
        observed_at_unix_seconds: observed,
        started_at_unix_seconds: None,
        run_key_sha256: None,
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
            model: ModelId::parse("fixture-model").unwrap(),
            effort: EffortLevel::Medium,
            harness: HarnessId::parse("fixture-host").unwrap(),
            transport: "subprocess-jsonl".into(),
            agent: Some("fixture-agent".into()),
            skills: BTreeSet::from(["fixture-skill".into()]),
            plan: "single-pass".into(),
            propensity_micros: Some(1_000_000),
            route: None,
        },
        origin: FeedbackOrigin::Automated,
        transport: VerificationOutcome::Passed,
        validation: VerificationOutcome::Passed,
        objective: VerificationOutcome::Passed,
        verification_evidence_sha256: Some("1".repeat(64)),
        human: None,
        failure: None,
        measurements: FeedbackMeasurements {
            usage_scope: None,
            cost_microusd: Some(10),
            latency_ms: Some(100),
            tokens: Some(1000),
            attempts: 1,
            escalations: 0,
            usage: None,
        },
        comment_sha256: None,
    }
}
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
fn rules() -> LearningRules {
    LearningRules {
        schema_version: 1,
        minimum_verified_samples: 1,
        drift_window_seconds: 10,
        minimum_drift_micros: 250_000,
        maximum_weight_delta: 5,
        maximum_canary_cases: 5,
    }
}

#[test]
fn consent_is_off_by_default_and_persists() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("feedback");
    let store = FeedbackStore::open(&path).unwrap();
    assert!(!store.consent().unwrap().preferences.collection_enabled);
    assert!(matches!(
        store.record(input("one", 100), 100),
        Err(FeedbackError::Consent)
    ));
    assert!(matches!(
        store.statistics(100),
        Err(FeedbackError::LearningDisabled)
    ));
    assert!(
        store
            .configure(
                FeedbackPreferences {
                    learning_enabled: true,
                    ..Default::default()
                },
                100
            )
            .is_err()
    );
    let consent = store.configure(prefs(), 100).unwrap();
    drop(store);
    let store = FeedbackStore::open(&path).unwrap();
    assert_eq!(store.consent().unwrap(), consent);
    assert!(matches!(
        FeedbackStore::open(&path),
        Err(FeedbackError::Locked)
    ));
    assert!(store.configure(prefs(), 99).is_err());
}

#[test]
fn events_are_immutable_idempotent_and_bound_to_frozen_receipts() {
    let (_temp, store) = setup();
    let value = input("one", 101);
    let original = serde_json::to_vec(&value).unwrap();
    let first = store.record(value.clone(), 102).unwrap();
    assert_eq!(store.record(value.clone(), 103).unwrap(), first);
    let mut changed = value.clone();
    changed.objective = VerificationOutcome::Failed;
    assert!(matches!(
        store.record(changed, 103),
        Err(FeedbackError::Integrity(_))
    ));
    assert_eq!(serde_json::to_vec(&value).unwrap(), original);
    let mut human = value.clone();
    human.origin = FeedbackOrigin::Human;
    human.human = Some(HumanVerdict {
        success: VerificationOutcome::Failed,
        quality: Some(20),
        perceived_cost: PerceivedCost::High,
        correction_required: Some(true),
        reviewer_sha256: "9".repeat(64),
    });
    let mut mismatched = human.clone();
    mismatched.binding.receipt_hash = "8".repeat(64);
    assert!(store.record(mismatched, 104).is_err());
    store.record(human, 104).unwrap();
    let stats = store.statistics(104).unwrap();
    assert_eq!(stats.objective.passed, 1);
    assert_eq!(stats.human_success.failed, 1);
    assert_eq!(stats.performance[0].cost_microusd.samples, 1);
    let competence = stats.competence.values().next().unwrap();
    assert_eq!(competence.automated.alpha, 2);
    assert_eq!(competence.human.beta, 2);
}

#[test]
fn transport_success_and_unknown_prices_never_become_objective_success_or_zero_cost() {
    let (_temp, store) = setup();
    let mut value = input("one", 101);
    value.objective = VerificationOutcome::Unknown;
    value.validation = VerificationOutcome::Unknown;
    value.verification_evidence_sha256 = None;
    value.measurements.cost_microusd = None;
    value.context.propensity_micros = None;
    store.record(value, 101).unwrap();
    let stats = store.statistics(101).unwrap();
    assert_eq!(stats.transport.passed, 1);
    assert_eq!(stats.objective.passed, 0);
    assert_eq!(stats.objective.unknown, 1);
    assert_eq!(stats.performance[0].cost_microusd.samples, 0);
    assert_eq!(stats.performance[0].cost_microusd.missing, 1);
    assert_eq!(stats.unknown_propensities, 1);
    let competence = stats.competence.values().next().unwrap();
    assert_eq!(
        (
            competence.automated.alpha,
            competence.automated.beta,
            competence.automated.unknown
        ),
        (1, 1, 1)
    );
    store
        .register_baseline(PhasePolicy::default(), 101)
        .unwrap();
    assert!(matches!(
        store.propose_policy(
            PhasePolicy {
                version: "candidate".into(),
                ..Default::default()
            },
            rules(),
            101
        ),
        Err(FeedbackError::Gate(_))
    ));
}

#[test]
fn strict_input_limits_and_proof_requirements() {
    let (_temp, store) = setup();
    for index in 0..9 {
        let mut value = input("one", 101);
        match index {
            0 => value.verification_evidence_sha256 = None,
            1 => value.validation = VerificationOutcome::Unknown,
            2 => value.context.propensity_micros = Some(0),
            3 => value.measurements.attempts = 0,
            4 => value.measurements.escalations = 2,
            5 => value.measurements.cost_microusd = Some(MAX_VALUE + 1),
            6 => value.binding.task_hash = "not-a-hash".into(),
            7 => value.context.plan = "a\nsecret".into(),
            _ => value.origin = FeedbackOrigin::Human,
        }
        assert!(store.record(value, 102).is_err(), "invalid input {index}");
    }
    assert!(store.record(input("future", 103), 102).is_err());
    assert!(store.record(input("before-consent", 99), 102).is_err());
    let bytes = serde_json::to_vec(&input("one", 101)).unwrap();
    assert!(parse_feedback(&bytes).is_ok());
    let mut object: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    object["prompt"] = "sensitive".into();
    assert!(parse_feedback(&serde_json::to_vec(&object).unwrap()).is_err());
    assert!(parse_feedback(br#"{"schema_version":1,"schema_version":1}"#).is_err());
    assert!(parse_feedback(&vec![b' '; MAX_INPUT_BYTES + 1]).is_err());
    let mut duplicate: serde_json::Value = serde_json::to_value(input("one", 101)).unwrap();
    duplicate["context"]["skills"] = serde_json::json!(["same", "same"]);
    assert!(parse_feedback(&serde_json::to_vec(&duplicate).unwrap()).is_err());
}

#[test]
fn unknown_fixture_is_executable_and_backwards_clock_cannot_include_future_events() {
    let (_temp, store) = setup();
    let value = parse_feedback(include_bytes!(
        "../../../tests/fixtures/feedback/automated-unknown-v1.json"
    ))
    .unwrap();
    store.record(value, 102).unwrap();
    assert!(store.statistics(101).is_err());
    assert!(store.record(input("second", 101), 101).is_err());
    let stats = store.statistics(102).unwrap();
    assert_eq!(
        (
            stats.transport.passed,
            stats.objective.passed,
            stats.objective.unknown
        ),
        (1, 0, 1)
    );
}

#[test]
fn clock_watermark_survives_expiration_reopen_optout_and_full_purge() {
    let (temp, store) = setup();
    store
        .configure(
            FeedbackPreferences {
                retention_seconds: 10,
                ..prefs()
            },
            100,
        )
        .unwrap();
    let old = input("expired-run", 101);
    store.record(old.clone(), 101).unwrap();
    assert_eq!(store.purge_expired(112).unwrap(), 1);
    assert!(store.record(old.clone(), 101).is_err());
    drop(store);
    let store = FeedbackStore::open(&temp.path().join("feedback")).unwrap();
    assert!(store.record(old.clone(), 101).is_err());
    assert!(store.configure(prefs(), 101).is_err());
    store
        .configure(FeedbackPreferences::default(), 113)
        .unwrap();
    assert!(store.configure(prefs(), 101).is_err());
    store.purge_all(114).unwrap();
    assert!(store.configure(prefs(), 101).is_err());
    store.configure(prefs(), 115).unwrap();
    assert!(store.record(old, 115).is_err());
    assert!(store.purge_all(113).is_err());
}

#[test]
fn comments_are_explicit_digests_never_raw_text_in_storage_or_export() {
    let (temp, store) = setup();
    let mut value = input("one", 101);
    let secret = "synthetic-only-secret-DO-NOT-PERSIST";
    value.comment_sha256 = Some(comment_digest(secret).unwrap());
    store.record(value, 101).unwrap();
    let exported = serde_json::to_vec(&store.export(101).unwrap()).unwrap();
    assert!(!String::from_utf8(exported).unwrap().contains(secret));
    for entry in fs::read_dir(temp.path().join("feedback")).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
    }
}

#[test]
fn retention_opt_out_and_full_purge_remove_data_and_restore_baseline() {
    let (temp, store) = setup();
    store
        .configure(
            FeedbackPreferences {
                retention_seconds: 10,
                ..prefs()
            },
            100,
        )
        .unwrap();
    let old = store.record(input("one", 101), 101).unwrap();
    assert_eq!(store.events(111).unwrap().len(), 1); // Inclusive source-age bound.
    assert_eq!(store.events(112).unwrap().len(), 0);
    let baseline = store
        .register_baseline(PhasePolicy::default(), 112)
        .unwrap();
    store.record(input("two", 113), 113).unwrap();
    let candidate = store
        .propose_policy(
            PhasePolicy {
                version: "offline-v1".into(),
                cost_weight: 2,
                ..Default::default()
            },
            rules(),
            114,
        )
        .unwrap();
    assert_ne!(candidate.artifact_id, baseline.artifact_id);
    store
        .configure(
            FeedbackPreferences {
                learning_enabled: false,
                ..prefs()
            },
            115,
        )
        .unwrap();
    assert_eq!(store.policies().unwrap().len(), 1);
    assert_eq!(store.active_policy().unwrap().unwrap(), baseline);
    assert!(store.statistics(115).is_err());
    assert_eq!(store.events(115).unwrap().len(), 1); // Separate collection consent.
    store
        .configure(FeedbackPreferences::default(), 116)
        .unwrap();
    assert!(store.events(116).unwrap().is_empty());
    drop(store);
    let store = FeedbackStore::open(&temp.path().join("feedback")).unwrap();
    assert_eq!(store.active_policy().unwrap().unwrap(), baseline);
    store.purge_all(117).unwrap();
    assert!(store.policies().unwrap().is_empty());
    assert!(store.active_policy().unwrap().is_none());
    let db = fs::read(temp.path().join("feedback/feedback.sqlite3")).unwrap();
    assert!(
        !db.windows(old.event_hash.len())
            .any(|w| w == old.event_hash.as_bytes())
    );
    assert!(!store.consent().unwrap().preferences.collection_enabled);
}

#[test]
fn redacted_statistics_are_reproducible_and_measurement_moments_are_exact() {
    let (_temp, store) = setup();
    store.record(input("one", 101), 101).unwrap();
    let mut two = input("two", 102);
    two.measurements.cost_microusd = Some(30);
    two.measurements.attempts = 3;
    two.measurements.escalations = 2;
    store.record(two, 102).unwrap();
    let stats = store.statistics(102).unwrap();
    assert_eq!(stats, store.statistics(102).unwrap());
    let cost = &stats.performance[0].cost_microusd;
    assert_eq!(
        (cost.samples, cost.sum, cost.sum_squares, cost.p95),
        (2, 40, 1000, Some(30))
    );
    assert_eq!(stats.performance[0].attempts, 4);
    assert_eq!(stats.performance[0].escalations, 2);
    assert_eq!(store.export(102).unwrap(), store.export(102).unwrap());
}

#[test]
fn drift_uses_verified_objectives_and_only_recommends_quarantine() {
    let (_temp, store) = setup();
    let baseline = store
        .register_baseline(PhasePolicy::default(), 100)
        .unwrap();
    store.record(input("previous", 101), 101).unwrap();
    let mut recent = input("recent", 115);
    recent.objective = VerificationOutcome::Failed;
    recent.failure = Some(FeedbackFailure::Objective);
    store.record(recent, 115).unwrap();
    let finding = store.drift(&rules(), 120).unwrap().pop().unwrap();
    assert!(finding.quarantine_recommended);
    assert_eq!(finding.previous.passed, 1);
    assert_eq!(finding.recent.failed, 1);
    assert_eq!(store.active_policy().unwrap().unwrap(), baseline);
    let mut strict = rules();
    strict.minimum_verified_samples = 2;
    assert!(!store.drift(&strict, 120).unwrap()[0].quarantine_recommended);
}

#[test]
fn policy_proposals_are_bounded_immutable_and_do_not_activate() {
    let (_temp, store) = setup();
    store.record(input("one", 101), 101).unwrap();
    let base = store
        .register_baseline(PhasePolicy::default(), 101)
        .unwrap();
    let mut candidate = base.policy.clone();
    candidate.version = "bounded-candidate".into();
    candidate.cost_weight += 1;
    let proposal = store
        .propose_policy(candidate.clone(), rules(), 102)
        .unwrap();
    assert_eq!(
        store
            .propose_policy(candidate.clone(), rules(), 102)
            .unwrap(),
        proposal
    );
    let mut conflicting = candidate.clone();
    conflicting.cost_weight += 1;
    assert!(matches!(
        store.propose_policy(conflicting, rules(), 102),
        Err(FeedbackError::Integrity(_))
    ));
    assert_eq!(store.active_policy().unwrap().unwrap(), base);
    assert_eq!(
        store.policy(&proposal.artifact_id).unwrap().state,
        PolicyState::Proposed
    );
    candidate.minimum_utility_micros = -1;
    assert!(
        store
            .propose_policy(candidate.clone(), rules(), 103)
            .is_err()
    );
    candidate.minimum_utility_micros = 0;
    candidate.cost_weight = 100;
    assert!(store.propose_policy(candidate, rules(), 103).is_err());
    let trial = TrialEvidence {
        stage: TrialStage::Shadow,
        evidence_sha256: "1".repeat(64),
        reviewer_sha256: "2".repeat(64),
        independent: true,
        cases: 1,
        hard_constraint_violations: 0,
        subgroup_regressions: 0,
        accepted: true,
        started_at_unix_seconds: 102,
        completed_at_unix_seconds: 103,
    };
    assert!(
        store
            .record_trial(&proposal.artifact_id, trial, 103)
            .is_err()
    );
}

#[test]
fn private_storage_rejects_world_readable_dirs_symlinks_and_future_schema() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("public");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(FeedbackStore::open(&dir).is_err());
    let path = temp.path().join("private");
    let store = FeedbackStore::open(&path).unwrap();
    drop(store);
    assert_eq!(
        fs::metadata(path.join("feedback.sqlite3"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let alias = temp.path().join("alias");
    symlink(&path, &alias).unwrap();
    assert!(FeedbackStore::open(&alias).is_err());
    let db = rusqlite::Connection::open(path.join("feedback.sqlite3")).unwrap();
    db.execute_batch("PRAGMA user_version=999").unwrap();
    drop(db);
    assert!(matches!(
        FeedbackStore::open(&path),
        Err(FeedbackError::Integrity("future schema"))
    ));
}

#[test]
fn altered_database_event_is_detected_before_reuse() {
    let (temp, store) = setup();
    store.record(input("one", 101), 101).unwrap();
    drop(store);
    let path = temp.path().join("feedback");
    let db = rusqlite::Connection::open(path.join("feedback.sqlite3")).unwrap();
    assert!(db.execute("UPDATE feedback SET event='{}'", []).is_err());
    db.execute_batch("DROP TRIGGER feedback_immutable; UPDATE feedback SET observed_at=99;")
        .unwrap();
    drop(db);
    assert!(matches!(
        FeedbackStore::open(&path),
        Err(FeedbackError::Integrity("event"))
    ));
}

#[test]
fn symlink_database_or_wal_is_never_followed() {
    for name in ["feedback.sqlite3", "feedback.sqlite3-wal"] {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("feedback");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let victim = temp.path().join("victim");
        fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, path.join(name)).unwrap();
        assert!(FeedbackStore::open(&path).is_err());
        assert_eq!(fs::read(victim).unwrap(), b"untouched");
    }
}

fn prepared_candidate(
    store: &FeedbackStore,
) -> (
    PolicyArtifact,
    PolicyArtifact,
    Vec<router_eval::PairedTrace>,
) {
    store.record(input("one", 101), 101).unwrap();
    let mut replay = common::input();
    let base = store
        .register_baseline(replay.policies["baseline"].clone(), 101)
        .unwrap();
    let mut policy = replay.policies["semantic"].clone();
    policy.cost_weight += 1;
    let candidate = store.propose_policy(policy.clone(), rules(), 102).unwrap();
    replay.policies.insert("semantic".into(), policy);
    (base, candidate, vec![common::pair(replay)])
}
fn trial(stage: TrialStage, start: u64, end: u64) -> TrialEvidence {
    TrialEvidence {
        stage,
        evidence_sha256: "1".repeat(64),
        reviewer_sha256: "2".repeat(64),
        independent: true,
        cases: 1,
        hard_constraint_violations: 0,
        subgroup_regressions: 0,
        accepted: true,
        started_at_unix_seconds: start,
        completed_at_unix_seconds: end,
    }
}
fn sign(
    store: &FeedbackStore,
    id: &str,
    action: PolicyAction,
    now: u64,
    key: &ed25519_dalek::SigningKey,
) -> SignedPolicyApproval {
    use ed25519_dalek::Signer;
    let mut approval = SignedPolicyApproval {
        schema_version: 1,
        action,
        artifact_id: id.into(),
        expected_active_artifact_id: store.active_policy().unwrap().unwrap().artifact_id,
        gate_hash: store.promotion_digest(id).unwrap(),
        issued_at_unix_seconds: now,
        expires_at_unix_seconds: now + 60,
        nonce_sha256: redacted_digest(&format!("synthetic:{id}:{action:?}:{now}")).unwrap(),
        public_key_hex: hex::encode(key.verifying_key().to_bytes()),
        signature_hex: String::new(),
    };
    approval.signature_hex =
        hex::encode(key.sign(&approval_message(&approval).unwrap()).to_bytes());
    approval
}

#[test]
fn full_signed_replay_shadow_canary_activation_and_rollback_is_reversible() {
    let (temp, store) = setup();
    let (base, candidate, pairs) = prepared_candidate(&store);
    let criteria = common::criteria(&pairs);
    assert!(
        store
            .evaluate_proposal(&candidate.artifact_id, &pairs, &criteria, 111)
            .unwrap()
            .semantic_enabled
    );
    assert_eq!(store.active_policy().unwrap().unwrap(), base);
    store
        .record_trial(
            &candidate.artifact_id,
            trial(TrialStage::Shadow, 111, 112),
            112,
        )
        .unwrap();
    let mut oversized = trial(TrialStage::Canary, 112, 113);
    oversized.cases = 6;
    assert!(
        store
            .record_trial(&candidate.artifact_id, oversized, 113)
            .is_err()
    );
    store
        .record_trial(
            &candidate.artifact_id,
            trial(TrialStage::Canary, 112, 113),
            113,
        )
        .unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let trusted = BTreeSet::from([hex::encode(key.verifying_key().to_bytes())]);
    let approval = sign(
        &store,
        &candidate.artifact_id,
        PolicyAction::Activate,
        114,
        &key,
    );
    let accepted = store.apply_signed_action(&approval, &trusted, 114).unwrap();
    assert_eq!(accepted.state, PolicyState::Active);
    assert_eq!(store.active_policy().unwrap().unwrap(), candidate);
    assert!(store.apply_signed_action(&approval, &trusted, 114).is_err());
    let rollback = sign(&store, &base.artifact_id, PolicyAction::Rollback, 115, &key);
    store.apply_signed_action(&rollback, &trusted, 115).unwrap();
    assert_eq!(store.active_policy().unwrap().unwrap(), base);
    assert_eq!(
        store.policy(&candidate.artifact_id).unwrap().state,
        PolicyState::Retired
    );
    drop(store);
    let store = FeedbackStore::open(&temp.path().join("feedback")).unwrap();
    assert_eq!(store.active_policy().unwrap().unwrap(), base);
    assert_eq!(
        store.policy(&candidate.artifact_id).unwrap().artifact,
        candidate
    );
}

#[test]
fn signatures_trust_expiry_and_incomplete_gates_fail_closed() {
    let (_temp, store) = setup();
    let (base, candidate, pairs) = prepared_candidate(&store);
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let trusted = BTreeSet::from([hex::encode(key.verifying_key().to_bytes())]);
    let approval = sign(
        &store,
        &candidate.artifact_id,
        PolicyAction::Activate,
        111,
        &key,
    );
    assert!(matches!(
        store.apply_signed_action(&approval, &trusted, 111),
        Err(FeedbackError::Gate(_))
    ));
    assert!(matches!(
        store.apply_signed_action(&approval, &BTreeSet::new(), 111),
        Err(FeedbackError::Signature)
    ));
    let mut tampered = approval.clone();
    tampered.action = PolicyAction::Quarantine;
    assert!(matches!(
        store.apply_signed_action(&tampered, &trusted, 111),
        Err(FeedbackError::Signature)
    ));
    assert!(matches!(
        store.apply_signed_action(&approval, &trusted, 172),
        Err(FeedbackError::Signature)
    ));
    let mut impossible = common::criteria(&pairs);
    impossible.rules[1].minimum_improvement_micros = 900_000;
    let blocked = store
        .evaluate_proposal(&candidate.artifact_id, &pairs, &impossible, 111)
        .unwrap();
    assert!(!blocked.semantic_enabled);
    assert_eq!(
        store.policy(&candidate.artifact_id).unwrap().state,
        PolicyState::Proposed
    );
    assert_eq!(store.active_policy().unwrap().unwrap(), base);
}

#[test]
fn replay_policy_substitution_and_trial_regression_cannot_pass() {
    let (_temp, store) = setup();
    let (_base, candidate, pairs) = prepared_candidate(&store);
    let mut wrong = common::input();
    wrong.policies.get_mut("semantic").unwrap().version = "other-candidate".into();
    let wrong_pairs = vec![common::pair(wrong)];
    assert!(
        store
            .evaluate_proposal(
                &candidate.artifact_id,
                &wrong_pairs,
                &common::criteria(&wrong_pairs),
                111
            )
            .is_err()
    );
    store
        .evaluate_proposal(
            &candidate.artifact_id,
            &pairs,
            &common::criteria(&pairs),
            111,
        )
        .unwrap();
    for index in 0..4 {
        let mut evidence = trial(TrialStage::Shadow, 111, 112);
        match index {
            0 => evidence.hard_constraint_violations = 1,
            1 => evidence.subgroup_regressions = 1,
            2 => evidence.independent = false,
            _ => evidence.started_at_unix_seconds = 110,
        }
        assert!(
            store
                .record_trial(&candidate.artifact_id, evidence, 112)
                .is_err()
        );
    }
}

#[test]
fn quarantine_is_explicit_signed_and_returns_to_the_accepted_predecessor() {
    let (_temp, store) = setup();
    let (base, candidate, pairs) = prepared_candidate(&store);
    store
        .evaluate_proposal(
            &candidate.artifact_id,
            &pairs,
            &common::criteria(&pairs),
            111,
        )
        .unwrap();
    store
        .record_trial(
            &candidate.artifact_id,
            trial(TrialStage::Shadow, 111, 112),
            112,
        )
        .unwrap();
    store
        .record_trial(
            &candidate.artifact_id,
            trial(TrialStage::Canary, 112, 113),
            113,
        )
        .unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let trusted = BTreeSet::from([hex::encode(key.verifying_key().to_bytes())]);
    store
        .apply_signed_action(
            &sign(
                &store,
                &candidate.artifact_id,
                PolicyAction::Activate,
                114,
                &key,
            ),
            &trusted,
            114,
        )
        .unwrap();
    store
        .apply_signed_action(
            &sign(
                &store,
                &candidate.artifact_id,
                PolicyAction::Quarantine,
                115,
                &key,
            ),
            &trusted,
            115,
        )
        .unwrap();
    assert_eq!(store.active_policy().unwrap().unwrap(), base);
    assert_eq!(
        store.policy(&candidate.artifact_id).unwrap().state,
        PolicyState::Quarantined
    );
    assert!(
        store
            .apply_signed_action(
                &sign(
                    &store,
                    &candidate.artifact_id,
                    PolicyAction::Activate,
                    116,
                    &key
                ),
                &trusted,
                116
            )
            .is_err()
    );
}

#[test]
fn a_refused_proposal_gate_still_persists_expiry_and_stats_hash_matches_statistics() {
    let (temp, store) = setup();
    store
        .configure(
            FeedbackPreferences {
                retention_seconds: 10,
                ..prefs()
            },
            100,
        )
        .unwrap();
    let old = store.record(input("old", 101), 101).unwrap();
    store
        .register_baseline(PhasePolicy::default(), 101)
        .unwrap();
    let candidate = PhasePolicy {
        version: "offline-v1".into(),
        cost_weight: 2,
        ..Default::default()
    };
    let strict = LearningRules {
        minimum_verified_samples: 5,
        ..rules()
    };
    // The only event has expired by 200: the gate refuses, and the expiry it
    // computed is committed and scrubbed anyway.
    assert!(matches!(
        store.propose_policy(candidate.clone(), strict, 200),
        Err(FeedbackError::Gate("insufficient verified samples"))
    ));
    let db = fs::read(temp.path().join("feedback/feedback.sqlite3")).unwrap();
    assert!(
        !db.windows(old.event_hash.len())
            .any(|w| w == old.event_hash.as_bytes())
    );
    // Accepted proposals commit to the statistics the gate counted.
    store.record(input("fresh", 201), 201).unwrap();
    let proposal = store.propose_policy(candidate, rules(), 202).unwrap();
    assert_eq!(
        proposal.statistics_hash.as_deref(),
        Some(store.statistics(202).unwrap().content_hash.as_str())
    );
}
