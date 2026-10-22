#![cfg(unix)]
include!("support/fixture.rs");
use router_backend_store::{AuthorityKey, BackendStore, StoreConfig, StoreError};
use router_execution_decision::{ActivationAuthority, ActivationGuard, ExecutionDecision};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
};

fn config(fixture: &Fixture) -> StoreConfig {
    StoreConfig {
        schema_version: 1,
        baseline_policy_hash: fixture.context.policy_hash().into(),
        scope_sha256: "9".repeat(64),
        authorities: [
            (AuthorityRole::Backend, "backend", &fixture.keys.backend),
            (
                AuthorityRole::HumanReviewer,
                "reviewer",
                &fixture.keys.reviewer,
            ),
            (AuthorityRole::GateOwner, "gate", &fixture.keys.gate),
            (AuthorityRole::Approver, "approver", &fixture.keys.approver),
        ]
        .into_iter()
        .map(|(role, id, key)| AuthorityKey {
            role,
            id: id.into(),
            public_key_hex: hex::encode(key.verifying_key().as_bytes()),
        })
        .collect(),
    }
}
fn setup(fixture: &Fixture) -> (tempfile::TempDir, PathBuf, BackendStore) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("backend-state");
    let store = BackendStore::create(&root, config(fixture))
        .map(|store| {
            store.with_capability_proof_verifier(std::sync::Arc::new(
                fixture_proofs::FixtureVerifier,
            ))
        })
        .unwrap();
    (temp, root, store)
}
fn activate(store: &BackendStore, fixture: &Fixture) -> String {
    let review = store
        .review(&fixture.artifact, &fixture.evidence, 120)
        .unwrap();
    let guard = store.read_guard(120).unwrap();
    let approval = fixture.approval(
        guard.state(),
        ActivationAction::Activate,
        &review.projection().promotion_hash,
        120,
        "1",
    );
    drop(guard);
    store.activate(&approval, &review, 120).unwrap().state_hash
}
fn rollback(store: &BackendStore, fixture: &Fixture, at: u64) -> Signed<ActivationApproval> {
    let guard = store.read_guard(at).unwrap();
    fixture.approval(
        guard.state(),
        ActivationAction::Rollback,
        fixture.context.policy_hash(),
        at,
        "2",
    )
}

#[test]
fn explicit_create_review_atomic_activation_restart_and_expired_history() {
    let fixture = Fixture::new();
    let (_temp, root, store) = setup(&fixture);
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(root.join("state.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(matches!(
        BackendStore::create(&root, config(&fixture)).map(|store| store
            .with_capability_proof_verifier(std::sync::Arc::new(fixture_proofs::FixtureVerifier))),
        Err(StoreError::Exists)
    ));
    let before = fs::read(root.join("state.json")).unwrap();
    let review = store
        .review(&fixture.artifact, &fixture.evidence, 120)
        .unwrap();
    assert_eq!(review.projection().heldout_families, 2);
    assert_eq!(before, fs::read(root.join("state.json")).unwrap());
    let active = activate(&store, &fixture);
    assert_eq!(active, fixture.active().state_hash());
    let reopened = BackendStore::open_with_capability_verifier(
        &root,
        store.config_hash(),
        Some(&active),
        Some(std::sync::Arc::new(fixture_proofs::FixtureVerifier)),
    )
    .unwrap();
    let status = reopened.status(2000).unwrap();
    assert_eq!(status.event_count, 1);
    assert_eq!(status.active_expired, Some(true));
    assert!(status.external_anchor_checked);
    // Restore validates historical evidence at its original time, but does not
    // renew an expired proposal or promotion. Explicit rollback remains usable.
    let approval = rollback(&reopened, &fixture, 2000);
    let result = reopened.rollback(&approval, 2000).unwrap();
    assert_eq!(result.event_count, 2);
    assert!(result.active_promotion_hash.is_none());
    let after = BackendStore::open_with_capability_verifier(
        &root,
        store.config_hash(),
        Some(&active),
        Some(std::sync::Arc::new(fixture_proofs::FixtureVerifier)),
    )
    .unwrap();
    assert_eq!(after.status(2000).unwrap(), result);
}

#[test]
fn shared_guard_blocks_other_handles_until_drop_and_stale_cas_never_replays() {
    let fixture = Fixture::new();
    let (_temp, root, store) = setup(&fixture);
    let review = store
        .review(&fixture.artifact, &fixture.evidence, 120)
        .unwrap();
    let guard = store.read_guard(120).unwrap();
    let approval = fixture.approval(
        guard.state(),
        ActivationAction::Activate,
        &review.projection().promotion_hash,
        120,
        "1",
    );
    let second = BackendStore::open_with_capability_verifier(
        &root,
        store.config_hash(),
        None,
        Some(std::sync::Arc::new(fixture_proofs::FixtureVerifier)),
    )
    .unwrap();
    assert!(matches!(
        second.activate(&approval, &review, 120),
        Err(StoreError::Busy)
    ));
    assert_eq!(second.status(120).unwrap().event_count, 0);
    drop(guard);
    second.activate(&approval, &review, 120).unwrap();
    assert!(matches!(
        store.activate(&approval, &review, 121),
        Err(StoreError::Conflict)
    ));
    let old_hash = fs::read(root.join("state.json")).unwrap();
    let cancel = rollback(&store, &fixture, 123);
    let dispatch = store.acquire().unwrap();
    assert!(matches!(
        second.rollback(&cancel, 123),
        Err(StoreError::Busy)
    ));
    assert_eq!(old_hash, fs::read(root.join("state.json")).unwrap());
    drop(dispatch);
    second.rollback(&cancel, 123).unwrap();
    assert_eq!(store.status(124).unwrap().event_count, 2);
}

#[test]
fn revocation_between_review_and_spawn_invalidates_effective_selection() {
    let fixture = Fixture::new();
    let (_temp, _root, store) = setup(&fixture);
    activate(&store, &fixture);
    let guard = store.read_guard(122).unwrap();
    let signed = proposal(
        &fixture.keys,
        &fixture.artifact,
        &fixture.router,
        &fixture.context,
        ProposalPurpose::Active(guard.state().state_hash().into()),
        120,
        150,
        Some("c01"),
    );
    let proof = decide_active(
        guard.state(),
        &fixture.router,
        &fixture.context,
        Some(&signed),
        guard.authorities(),
        122,
    )
    .unwrap();
    let decision =
        ExecutionDecision::activated(&fixture.router, &fixture.context, &proof, &guard, 122)
            .unwrap();
    drop(guard);
    let approval = rollback(&store, &fixture, 123);
    store.rollback(&approval, 123).unwrap();
    assert!(
        decision
            .acquire_dispatch(&fixture.router, &fixture.context, Some(&store), 124)
            .is_err()
    );
}

#[test]
fn wrong_external_configuration_roots_or_history_checkpoint_fail_closed() {
    let fixture = Fixture::new();
    let (_temp, root, store) = setup(&fixture);
    let initial = fs::read(root.join("state.json")).unwrap();
    assert!(matches!(
        BackendStore::open_with_capability_verifier(
            &root,
            &"0".repeat(64),
            None,
            Some(std::sync::Arc::new(fixture_proofs::FixtureVerifier))
        ),
        Err(StoreError::Configuration)
    ));
    let mut changed = config(&fixture);
    changed.authorities[1].public_key_hex =
        hex::encode(SigningKey::from_bytes(&[8; 32]).verifying_key().as_bytes());
    assert_ne!(changed.content_hash().unwrap(), store.config_hash());
    assert!(
        BackendStore::open_with_capability_verifier(
            &root,
            &changed.content_hash().unwrap(),
            None,
            Some(std::sync::Arc::new(fixture_proofs::FixtureVerifier))
        )
        .is_err()
    );
    let active = activate(&store, &fixture);
    let anchored = BackendStore::open_with_capability_verifier(
        &root,
        store.config_hash(),
        Some(&active),
        Some(std::sync::Arc::new(fixture_proofs::FixtureVerifier)),
    )
    .unwrap();
    // Same-UID arbitrary rollback can restore intact old bytes. An independently
    // retained checkpoint detects it; the self-contained hash cannot.
    fs::write(root.join("state.json"), initial).unwrap();
    assert!(matches!(anchored.status(124), Err(StoreError::Anchor)));
    assert!(matches!(
        BackendStore::open_with_capability_verifier(
            &root,
            store.config_hash(),
            Some(&active),
            Some(std::sync::Arc::new(fixture_proofs::FixtureVerifier))
        ),
        Err(StoreError::Anchor)
    ));
    assert_eq!(
        BackendStore::open_with_capability_verifier(
            &root,
            store.config_hash(),
            None,
            Some(std::sync::Arc::new(fixture_proofs::FixtureVerifier))
        )
        .unwrap()
        .status(124)
        .unwrap()
        .event_count,
        0
    );
}

#[test]
fn corrupt_tampered_or_oversized_snapshot_never_authorizes() {
    let fixture = Fixture::new();
    for mutate in 0..4 {
        let (_temp, root, store) = setup(&fixture);
        activate(&store, &fixture);
        let path = root.join("state.json");
        match mutate {
            0 => {
                fs::write(&path, b"{\"schema_version\":").unwrap();
            }
            1 => {
                let mut document: serde_json::Value =
                    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                document["events"][0]["approval"]["signature_hex"] =
                    serde_json::json!("0".repeat(128));
                fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
            }
            2 => {
                let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
                file.set_len(router_backend_store::MAX_SNAPSHOT_BYTES as u64 + 1)
                    .unwrap();
            }
            _ => {
                fs::write(&path, b"{\"schema_version\":1,\"schema_version\":1}").unwrap();
            }
        }
        assert!(store.status(124).is_err());
        assert!(store.acquire().is_err());
    }
}

#[test]
fn crashed_staging_write_is_ignored_then_replaced_without_partial_publication() {
    let fixture = Fixture::new();
    let (_temp, root, store) = setup(&fixture);
    let before = fs::read(root.join("state.json")).unwrap();
    let pending = root.join("state.pending");
    fs::write(&pending, b"incomplete-crashed-candidate").unwrap();
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
    let reopened = BackendStore::open_with_capability_verifier(
        &root,
        store.config_hash(),
        None,
        Some(std::sync::Arc::new(fixture_proofs::FixtureVerifier)),
    )
    .unwrap();
    assert_eq!(reopened.status(120).unwrap().event_count, 0);
    assert_eq!(before, fs::read(root.join("state.json")).unwrap());
    activate(&reopened, &fixture);
    assert!(!pending.exists());
    assert_eq!(
        BackendStore::open_with_capability_verifier(
            &root,
            store.config_hash(),
            None,
            Some(std::sync::Arc::new(fixture_proofs::FixtureVerifier))
        )
        .unwrap()
        .status(124)
        .unwrap()
        .event_count,
        1
    );
}

#[test]
fn private_modes_symlinks_hardlinks_and_replaced_lock_are_rejected() {
    let fixture = Fixture::new();
    for mutation in 0..5 {
        let (_temp, root, store) = setup(&fixture);
        match mutation {
            0 => fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap(),
            1 => fs::set_permissions(root.join("state.json"), fs::Permissions::from_mode(0o644))
                .unwrap(),
            2 => {
                fs::rename(root.join("state.json"), root.join("original")).unwrap();
                symlink("original", root.join("state.json")).unwrap();
            }
            3 => fs::hard_link(root.join("state.json"), root.join("linked")).unwrap(),
            _ => {
                fs::rename(root.join("activation.lock"), root.join("old-lock")).unwrap();
                fs::write(root.join("activation.lock"), "").unwrap();
                fs::set_permissions(
                    root.join("activation.lock"),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
        }
        assert!(store.status(120).is_err(), "mutation {mutation}");
    }
    let (temp, root, store) = setup(&fixture);
    let alias = temp.path().canonicalize().unwrap().join("alias");
    symlink(&root, &alias).unwrap();
    assert!(matches!(
        BackendStore::open_with_capability_verifier(
            &alias,
            store.config_hash(),
            None,
            Some(std::sync::Arc::new(fixture_proofs::FixtureVerifier))
        ),
        Err(StoreError::Path)
    ));
    assert!(
        BackendStore::create(&alias.join("child"), config(&fixture))
            .map(
                |store| store.with_capability_proof_verifier(std::sync::Arc::new(
                    fixture_proofs::FixtureVerifier
                ))
            )
            .is_err()
    );
}

#[test]
fn status_and_errors_do_not_export_raw_evidence_or_key_material() {
    let fixture = Fixture::new();
    let (_temp, _root, store) = setup(&fixture);
    let state = activate(&store, &fixture);
    let output = serde_json::to_string(&store.status(124).unwrap()).unwrap();
    assert!(output.contains(&state));
    for forbidden in [
        "fixture-best",
        "fixture-second",
        "synthetic",
        "reviewer",
        "signature_hex",
        "objective",
        "public_key_hex",
    ] {
        assert!(!output.contains(forbidden), "{forbidden}");
    }
    for key in config(&fixture).authorities {
        assert!(!output.contains(&key.public_key_hex));
    }
    assert_eq!(StoreError::Io.to_string(), "backend_store.io");
    assert_eq!(
        StoreError::PublishedDurabilityUnknown.to_string(),
        "backend_store.published_durability_unknown"
    );
    assert_eq!(
        StoreError::Promotion(PromotionError::Signature).to_string(),
        "backend_store.promotion"
    );
}

#[test]
fn subprocess_shared_guard_helper() {
    let Ok(root) = std::env::var("AR_BACKEND_STORE_TEST_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    let expected = std::env::var("AR_BACKEND_STORE_TEST_CONFIG").unwrap();
    let marker = root.parent().unwrap().join("reader-ready");
    let release = root.parent().unwrap().join("reader-release");
    let store = BackendStore::open_with_capability_verifier(
        root,
        &expected,
        None,
        Some(std::sync::Arc::new(fixture_proofs::FixtureVerifier)),
    )
    .unwrap();
    let guard = store.acquire().unwrap();
    fs::write(marker, b"shared-guard-held").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !release.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "reader release deadline"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    drop(guard);
}

#[test]
fn another_process_holding_dispatch_guard_excludes_activation_until_exit() {
    let fixture = Fixture::new();
    let (_temp, root, store) = setup(&fixture);
    activate(&store, &fixture);
    let approval = rollback(&store, &fixture, 123);
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "subprocess_shared_guard_helper", "--nocapture"])
        .env("AR_BACKEND_STORE_TEST_ROOT", &root)
        .env("AR_BACKEND_STORE_TEST_CONFIG", store.config_hash())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let marker = root.parent().unwrap().join("reader-ready");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !marker.exists() {
        if child.try_wait().unwrap().is_some() {
            panic!("guard subprocess exited before ready");
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("guard subprocess readiness deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let busy = matches!(store.rollback(&approval, 123), Err(StoreError::Busy));
    fs::write(root.parent().unwrap().join("reader-release"), b"release").unwrap();
    let exited = child.wait().unwrap().success();
    assert!(busy);
    assert!(exited);
    store.rollback(&approval, 123).unwrap();
}

#[test]
fn bounded_history_fails_without_purging_signed_events() {
    let fixture = Fixture::new();
    let (_temp, root, store) = setup(&fixture);
    let review = store
        .review(&fixture.artifact, &fixture.evidence, 120)
        .unwrap();
    for index in 0..router_backend_store::MAX_EVENTS {
        let at = 120 + index as u64;
        let guard = store.read_guard(at).unwrap();
        let action = if index % 2 == 0 {
            ActivationAction::Activate
        } else {
            ActivationAction::Rollback
        };
        let target = if index % 2 == 0 {
            &review.projection().promotion_hash
        } else {
            fixture.context.policy_hash()
        };
        let mut statement = fixture
            .approval(guard.state(), action, target, at, "1")
            .statement;
        statement.nonce_sha256 = format!("{index:064x}");
        let approval = fixture.keys.sign(AuthorityRole::Approver, statement);
        drop(guard);
        if index % 2 == 0 {
            store.activate(&approval, &review, at).unwrap();
        } else {
            store.rollback(&approval, at).unwrap();
        }
    }
    let before = fs::read(root.join("state.json")).unwrap();
    let guard = store.read_guard(300).unwrap();
    let mut statement = fixture
        .approval(
            guard.state(),
            ActivationAction::Activate,
            &review.projection().promotion_hash,
            300,
            "2",
        )
        .statement;
    statement.nonce_sha256 = format!("{:064x}", 128);
    let approval = fixture.keys.sign(AuthorityRole::Approver, statement);
    drop(guard);
    assert!(matches!(
        store.activate(&approval, &review, 300),
        Err(StoreError::Limit)
    ));
    assert_eq!(before, fs::read(root.join("state.json")).unwrap());
    assert_eq!(store.status(300).unwrap().event_count, 128);
}

#[test]
fn signed_but_invalid_human_labels_do_not_enter_storage() {
    let fixture = Fixture::new();
    let (_temp, root, store) = setup(&fixture);
    let before = fs::read(root.join("state.json")).unwrap();
    let mut evidence = fixture.evidence.clone();
    let mut input = evidence.cases[0].record.input().clone();
    input.label.as_mut().unwrap().human_validated = false;
    evidence.cases[0].record = ReplayRecord::seal(input).unwrap();
    fixture.resign_evaluation(&mut evidence);
    assert!(matches!(
        store.review(&fixture.artifact, &evidence, 120),
        Err(StoreError::Promotion(PromotionError::Gate))
    ));
    assert_eq!(before, fs::read(root.join("state.json")).unwrap());
}

#[derive(serde::Deserialize, Serialize)]
struct WirePromotion {
    artifact: BackendArtifact,
    evidence: PromotionEvidence,
    validated_at_unix_seconds: u64,
    promotion_hash: String,
}
#[derive(serde::Deserialize, Serialize)]
struct WireSnapshot {
    schema_version: u32,
    config: StoreConfig,
    config_hash: String,
    promotions: BTreeMap<String, WirePromotion>,
    events: Vec<ActivationEvent>,
    head: String,
    document_hash: String,
}
fn snapshot_hash(document: &WireSnapshot) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"agent-router:backend-store-snapshot:v1\0");
    hash.update(
        serde_json::to_vec(&(
            document.schema_version,
            &document.config,
            &document.config_hash,
            &document.promotions,
            &document.events,
            &document.head,
        ))
        .unwrap(),
    );
    hex::encode(hash.finalize())
}
#[test]
fn rehashing_forged_signed_history_or_validation_times_cannot_authorize() {
    let fixture = Fixture::new();
    for mutation in 0..3 {
        let (_temp, root, store) = setup(&fixture);
        activate(&store, &fixture);
        let path = root.join("state.json");
        let mut document: WireSnapshot = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(document.document_hash, snapshot_hash(&document));
        match mutation {
            0 => document.events[0].approval.signature_hex = "0".repeat(128),
            1 => {
                document
                    .promotions
                    .values_mut()
                    .next()
                    .unwrap()
                    .validated_at_unix_seconds = 121
            }
            _ => {
                document
                    .promotions
                    .values_mut()
                    .next()
                    .unwrap()
                    .evidence
                    .cases[0]
                    .label
                    .signature_hex = "0".repeat(128)
            }
        }
        document.document_hash = snapshot_hash(&document);
        fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(store.read_guard(124).is_err(), "mutation {mutation}");
        assert!(store.acquire().is_err());
    }
}

#[test]
fn historical_prefix_reopens_original_decision_but_cannot_dispatch_after_rollback() {
    let fixture = Fixture::new();
    let (_temp, _root, store) = setup(&fixture);
    let genesis = store.status(119).unwrap().state_hash;
    let active = activate(&store, &fixture);
    let current = store.read_guard(122).unwrap();
    let signed = proposal(
        &fixture.keys,
        &fixture.artifact,
        &fixture.router,
        &fixture.context,
        ProposalPurpose::Active(active.clone()),
        120,
        150,
        Some("c01"),
    );
    let proof = decide_active(
        current.state(),
        &fixture.router,
        &fixture.context,
        Some(&signed),
        current.authorities(),
        122,
    )
    .unwrap();
    drop(current);
    let approval = rollback(&store, &fixture, 123);
    store.rollback(&approval, 123).unwrap();
    let historical = store.historical_guard(&active, 122).unwrap();
    assert_eq!(historical.original_time(), 122);
    let reconstructed =
        ExecutionDecision::activated(&fixture.router, &fixture.context, &proof, &historical, 122)
            .unwrap();
    assert_eq!(reconstructed.selection().candidate.id, "secondary");
    // Historical proof can explain/reopen, never authorize against current state.
    assert!(
        reconstructed
            .acquire_dispatch(&fixture.router, &fixture.context, Some(&store), 124)
            .is_err()
    );
    assert!(store.historical_guard(&active, 124).is_err());
    assert!(store.historical_guard(&active, 119).is_err());
    assert!(store.historical_guard(&genesis, 121).is_err());
    assert!(
        store
            .historical_guard(&genesis, 119)
            .unwrap()
            .state()
            .active_promotion()
            .is_none()
    );
    assert!(store.historical_guard(&"0".repeat(64), 122).is_err());
}

#[test]
fn same_second_activation_and_rollback_preserve_head_order_for_history_only() {
    let fixture = Fixture::new();
    let (_temp, _root, store) = setup(&fixture);
    let active = activate(&store, &fixture);
    let current = store.read_guard(120).unwrap();
    let signed = proposal(
        &fixture.keys,
        &fixture.artifact,
        &fixture.router,
        &fixture.context,
        ProposalPurpose::Active(active.clone()),
        120,
        150,
        Some("c01"),
    );
    let proof = decide_active(
        current.state(),
        &fixture.router,
        &fixture.context,
        Some(&signed),
        current.authorities(),
        120,
    )
    .unwrap();
    drop(current);
    let approval = rollback(&store, &fixture, 120);
    store.rollback(&approval, 120).unwrap();
    let historical = store.historical_guard(&active, 120).unwrap();
    let reconstructed =
        ExecutionDecision::activated(&fixture.router, &fixture.context, &proof, &historical, 120)
            .unwrap();
    assert!(
        reconstructed
            .acquire_dispatch(&fixture.router, &fixture.context, Some(&store), 120)
            .is_err()
    );
}

/// Activates and rolls back `count` distinct promotions, then reopens the store.
fn cycle_promotions(count: usize) -> (tempfile::TempDir, BackendStore, u32) {
    let first = Fixture::new();
    let (temp, root, store) = setup(&first);
    let mut nonce = 0u32;
    let mut next_nonce = || {
        nonce += 1;
        format!("{nonce:02x}").repeat(32)
    };
    let mut head = String::new();
    for i in 0..count {
        let fixture = Fixture::with_version(&format!("test-v{i}"));
        let review = store
            .review(&fixture.artifact, &fixture.evidence, 120)
            .unwrap();
        let guard = store.read_guard(120).unwrap();
        let approval = fixture.approval_with_nonce(
            guard.state(),
            ActivationAction::Activate,
            &review.projection().promotion_hash,
            120,
            next_nonce(),
        );
        drop(guard);
        store.activate(&approval, &review, 120).unwrap();
        let guard = store.read_guard(120).unwrap();
        let approval = fixture.approval_with_nonce(
            guard.state(),
            ActivationAction::Rollback,
            fixture.context.policy_hash(),
            120,
            next_nonce(),
        );
        drop(guard);
        head = store.rollback(&approval, 120).unwrap().state_hash;
    }
    let status = store.status(120).unwrap();
    assert_eq!(status.promotion_count, count);
    assert_eq!(status.event_count, count * 2);
    // Every promotion is still replayable after a restart.
    let reopened = BackendStore::open_with_capability_verifier(
        &root,
        store.config_hash(),
        Some(&head),
        Some(std::sync::Arc::new(fixture_proofs::FixtureVerifier)),
    )
    .unwrap();
    let after = reopened.status(120).unwrap();
    assert_eq!(after.state_hash, status.state_hash);
    assert_eq!(after.promotion_count, count);
    (temp, store, nonce)
}

#[test]
fn more_promotions_than_the_old_cap_of_16_activate_roll_back_and_replay() {
    use router_backend_store::MAX_PROMOTIONS;
    assert_eq!(MAX_PROMOTIONS, router_backend_store::MAX_EVENTS / 2);
    let (_temp, store, _) = cycle_promotions(17);
    assert_eq!(store.status(120).unwrap().promotion_count, 17);
}

/// About five minutes in a debug build: every write re-verifies all promotions.
/// Run with `cargo test -p router-backend-store -- --ignored`.
#[test]
#[ignore = "slow: activates the full derived bound of promotions"]
fn promotions_reach_the_derived_bound_and_only_the_event_cap_remains() {
    use router_backend_store::{MAX_EVENTS, MAX_PROMOTIONS};
    let (_temp, store, _nonce) = cycle_promotions(MAX_PROMOTIONS);
    assert_eq!(store.status(120).unwrap().event_count, MAX_EVENTS);
    // One more distinct promotion is refused at review, before any approval.
    let extra = Fixture::with_version("test-extra");
    assert!(matches!(
        store.review(&extra.artifact, &extra.evidence, 120),
        Err(StoreError::Limit)
    ));
}

const EVENT_ROOM: usize = 1024 + "reviewer".len();
fn nonce_hex(n: u32) -> String {
    format!("{n:02x}").repeat(32)
}
fn act(
    store: &BackendStore,
    fixture: &Fixture,
    review: &router_backend_store::ReviewedPromotion,
    nonce: u32,
) -> std::result::Result<router_backend_store::StoreStatus, StoreError> {
    let guard = store.read_guard(120).unwrap();
    let approval = fixture.approval_with_nonce(
        guard.state(),
        ActivationAction::Activate,
        &review.projection().promotion_hash,
        120,
        nonce_hex(nonce),
    );
    drop(guard);
    store.activate(&approval, review, 120)
}
fn roll(store: &BackendStore, fixture: &Fixture, nonce: u32) -> router_backend_store::StoreStatus {
    let guard = store.read_guard(120).unwrap();
    let approval = fixture.approval_with_nonce(
        guard.state(),
        ActivationAction::Rollback,
        fixture.context.policy_hash(),
        120,
        nonce_hex(nonce),
    );
    drop(guard);
    store.rollback(&approval, 120).unwrap()
}
fn state_len(root: &Path) -> usize {
    fs::metadata(root.join("state.json")).unwrap().len() as usize
}

#[test]
fn review_refuses_beyond_the_promotion_count_but_accepts_a_retained_promotion() {
    let first = Fixture::new();
    let (_temp, _root, store) = setup(&first);
    let store = store.with_promotion_limit(1);
    let review = store.review(&first.artifact, &first.evidence, 120).unwrap();
    act(&store, &first, &review, 1).unwrap();
    roll(&store, &first, 2);
    let second = Fixture::with_version("test-second");
    assert!(matches!(
        store.review(&second.artifact, &second.evidence, 120),
        Err(StoreError::Limit)
    ));
    // Review is idempotent for a promotion the store already retains.
    store.review(&first.artifact, &first.evidence, 120).unwrap();
}

#[test]
fn stale_double_review_cannot_activate_without_room_for_its_own_rollback() {
    let (f1, f2) = (Fixture::new(), Fixture::with_version("test-second"));
    // Probe with the default bound: size after R1 cycle and R2 activation.
    let (_t, probe_root, probe) = setup(&f1);
    let r1 = probe.review(&f1.artifact, &f1.evidence, 120).unwrap();
    let r2 = probe.review(&f2.artifact, &f2.evidence, 120).unwrap();
    act(&probe, &f1, &r1, 1).unwrap();
    roll(&probe, &f1, 2);
    act(&probe, &f2, &r2, 3).unwrap();
    let full = state_len(&probe_root);
    // One byte short of leaving room for R2's rollback.
    let (_t2, _root, store) = setup(&f1);
    let store = store.with_snapshot_limit(full + EVENT_ROOM - 1);
    let r1 = store.review(&f1.artifact, &f1.evidence, 120).unwrap();
    let r2 = store.review(&f2.artifact, &f2.evidence, 120).unwrap();
    act(&store, &f1, &r1, 1).unwrap();
    roll(&store, &f1, 2);
    assert!(matches!(act(&store, &f2, &r2, 3), Err(StoreError::Limit)));
    assert_eq!(store.status(120).unwrap().active_promotion_hash, None);
}

#[test]
fn reactivating_a_retained_promotion_near_the_bound_keeps_rollback_possible() {
    let f1 = Fixture::new();
    let (_t, probe_root, probe) = setup(&f1);
    let r = probe.review(&f1.artifact, &f1.evidence, 120).unwrap();
    act(&probe, &f1, &r, 1).unwrap();
    roll(&probe, &f1, 2);
    act(&probe, &f1, &r, 3).unwrap();
    let full = state_len(&probe_root);
    // Refused when the bound leaves no room for the rollback event.
    let (_t2, _root, store) = setup(&f1);
    let store = store.with_snapshot_limit(full + EVENT_ROOM - 1);
    let r = store.review(&f1.artifact, &f1.evidence, 120).unwrap();
    act(&store, &f1, &r, 1).unwrap();
    roll(&store, &f1, 2);
    let r = store.review(&f1.artifact, &f1.evidence, 120).unwrap();
    assert!(matches!(act(&store, &f1, &r, 3), Err(StoreError::Limit)));
    // Accepted with exactly that room, and the rollback then always writes.
    let (_t3, _root3, store) = setup(&f1);
    let store = store.with_snapshot_limit(full + EVENT_ROOM);
    let r = store.review(&f1.artifact, &f1.evidence, 120).unwrap();
    act(&store, &f1, &r, 1).unwrap();
    roll(&store, &f1, 2);
    let r = store.review(&f1.artifact, &f1.evidence, 120).unwrap();
    act(&store, &f1, &r, 3).unwrap();
    let status = roll(&store, &f1, 4);
    assert!(status.active_promotion_hash.is_none());
}

#[test]
fn review_refuses_a_promotion_that_would_push_the_snapshot_over_its_bound() {
    let fixture = Fixture::new();
    let (_temp, root, store) = setup(&fixture);
    let genesis = fs::metadata(root.join("state.json")).unwrap().len() as usize;
    // Room for the empty snapshot but not for the retained promotion.
    let tight = store.with_snapshot_limit(genesis + 1024);
    let before = fs::read(root.join("state.json")).unwrap();
    assert!(matches!(
        tight.review(&fixture.artifact, &fixture.evidence, 120),
        Err(StoreError::Limit)
    ));
    assert_eq!(before, fs::read(root.join("state.json")).unwrap());
}

#[test]
fn reviewed_promotion_near_the_snapshot_bound_applies_and_can_always_roll_back() {
    let fixture = Fixture::new();
    let (_temp, root, store) = setup(&fixture);
    activate(&store, &fixture);
    let rolled = rollback(&store, &fixture, 120);
    store.rollback(&rolled, 120).unwrap();
    let raw = fs::read(root.join("state.json")).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let events = serde_json::to_vec(&value["events"]).unwrap().len();
    // Snapshot with the promotion retained but no event yet.
    let base = raw.len() - (events - 2);
    let longest_id = "reviewer".len();
    let one_event = 1024 + longest_id;
    for event in value["events"].as_array().unwrap() {
        assert!(serde_json::to_vec(event).unwrap().len() <= one_event);
    }
    // Two real events do not fit in one event's room: a reserve covering only
    // the activation event would let rollback hit the bound.
    assert!(events - 2 > one_event, "test must discriminate: {events}");
    // Room for the activation event only: review must refuse rather than admit
    // a promotion whose rollback could not be written.
    let (_temp1, _root1, short) = setup(&fixture);
    let short = short.with_snapshot_limit(base + one_event + 1);
    assert!(matches!(
        short.review(&fixture.artifact, &fixture.evidence, 120),
        Err(StoreError::Limit)
    ));
    // Fresh store whose bound leaves exactly the two-event reserve spare.
    let (_temp2, _root2, fresh) = setup(&fixture);
    let fresh = fresh.with_snapshot_limit(base + 2 * one_event);
    let review = fresh
        .review(&fixture.artifact, &fixture.evidence, 120)
        .unwrap();
    let guard = fresh.read_guard(120).unwrap();
    let approval = fixture.approval(
        guard.state(),
        ActivationAction::Activate,
        &review.projection().promotion_hash,
        120,
        "1",
    );
    drop(guard);
    fresh.activate(&approval, &review, 120).unwrap();
    let rolled = rollback(&fresh, &fixture, 120);
    let status = fresh.rollback(&rolled, 120).unwrap();
    assert!(status.active_promotion_hash.is_none());
}
