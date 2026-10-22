use super::*;

// Real durable store and producer-owned files; no native process or OS claim.
fn finite_review(f: &Fixture, limits: ResourceLimits) -> FiniteClientReview {
    finite_review_mode(f, limits, false)
}
fn finite_review_mode(f: &Fixture, limits: ResourceLimits, tools: bool) -> FiniteClientReview {
    use std::{net::TcpListener, os::unix::fs::PermissionsExt};
    let private_root = f.temp.path().canonicalize().unwrap();
    let snapshot = fixture_proofs::from_observation(
        f.context.snapshot().clone(),
        SnapshotValidation {
            now_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            max_age_seconds: 300,
        },
    )
    .unwrap();
    let auth = router_adapter_api::execution_authorization_digest_with_capability_acceptance(
        &f.request,
        &snapshot,
        &f.context.request().restrictions,
        f.context.capability_acceptance(),
    )
    .unwrap();
    let validated = router_adapter_api::authorize_execution_with_capability_acceptance(
        f.request.clone(),
        &snapshot,
        &f.context.request().restrictions,
        f.context.capability_acceptance(),
        Some(&auth),
    )
    .unwrap();
    let mut run =
        prepared_run(&validated, "finite-client", vec!["--worker".into()], vec![]).unwrap();
    // This fixture models the separate finite-client preparation contract.
    run.missing_runtime_evidence.clear();
    let broker = OwnedBroker::from_listener(TcpListener::bind(("127.0.0.1", 0)).unwrap()).unwrap();
    let state = if tools {
        broker.prepare_codex_tools_state(&private_root.join("runtime"), &run)
    } else {
        broker.prepare_codex_state(&private_root.join("runtime"), &run)
    }
    .unwrap();
    let pin = |name: &str, executable: bool| {
        let path = private_root.join(name);
        fs::write(&path, name).unwrap();
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(if executable { 0o500 } else { 0o400 }),
        )
        .unwrap();
        FiniteClientFile {
            path: path.to_str().unwrap().into(),
            sha256: router_adapter_api::content_digest(name.as_bytes()),
        }
    };
    let manifest = FiniteClientManifest {
        schema_version: 1,
        task_id: "finite-1".into(),
        host_snapshot_id: snapshot.host().id.clone(),
        client: pin("finite-client", true),
        native: pin("finite-native", true),
        helper: pin("finite-helper", true),
        wrapper: pin("finite-wrapper", true),
        profile: pin("finite-profile", false),
        configuration: state.configuration().clone(),
        private_state: state.path().to_str().unwrap().into(),
        native_version: "fixture-v1".into(),
        broker_endpoint: broker.endpoint().into(),
        broker_instance_sha256: broker.instance_sha256().into(),
    };
    FiniteClientReview::with_codex_state(manifest, &run, broker, limits, state).unwrap()
}

#[tokio::test]
async fn runtime_finite_approval_binds_the_owned_review_in_the_existing_store() {
    let f =
        Fixture::new_at_with_network(false, tempfile::tempdir().unwrap(), false, true, true).await;
    let runtime = f.runtime();
    let client = finite_review(&f, ResourceLimits::default());
    let client_digest = client.approval_digest().to_owned();
    let pending = runtime
        .review_finite_client(
            "finite-1",
            &f.router,
            &f.context,
            f.request.clone(),
            f.plan.clone(),
            "execute",
            client,
        )
        .await
        .unwrap();
    assert_eq!(
        runtime.summary("finite-1").unwrap().state,
        RunState::AwaitingApproval
    );
    assert_ne!(pending.approval_digest(), client_digest);
    let digest = pending.approval_digest().to_owned();
    let approved = runtime.approve_finite_client(pending, &digest).unwrap();
    assert_eq!(approved.summary().approval_digest, digest);
    assert_eq!(runtime.summary("finite-1").unwrap().state, RunState::Queued);
    assert_eq!(runtime.summary("finite-1").unwrap().attempts, 0);
    let events = observe_events(&f.temp.path().join("runtime"), "finite-1").unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.kind == "finite_client.review.v1" && e.detail == client_digest)
    );
    assert!(
        !serde_json::to_string(&events)
            .unwrap()
            .contains("private fixture prompt")
    );
    assert!(!f.temp.path().join("runtime/worktrees").exists());
    assert!(matches!(
        runtime
            .review(
                "finite-1",
                &f.router,
                &f.context,
                f.request.clone(),
                f.plan.clone(),
                "execute"
            )
            .await,
        Err(RuntimeError::Integrity(_))
    ));
    drop(approved);
    drop(runtime);
    let reopened = f.runtime();
    assert_eq!(
        reopened.summary("finite-1").unwrap().approval_digest,
        digest
    );
    assert_eq!(
        reopened.summary("finite-1").unwrap().state,
        RunState::Queued
    );
}

#[tokio::test]
async fn runtime_finite_approval_refuses_the_preparation_digest_alone() {
    let f =
        Fixture::new_at_with_network(false, tempfile::tempdir().unwrap(), false, true, true).await;
    let runtime = f.runtime();
    let client = finite_review(&f, ResourceLimits::default());
    let digest = client.approval_digest().to_owned();
    let pending = runtime
        .review_finite_client(
            "finite-1",
            &f.router,
            &f.context,
            f.request.clone(),
            f.plan.clone(),
            "execute",
            client,
        )
        .await
        .unwrap();
    assert!(matches!(
        runtime.approve_finite_client(pending, &digest),
        Err(RuntimeError::Approval)
    ));
    assert_eq!(
        runtime.summary("finite-1").unwrap().state,
        RunState::AwaitingApproval
    );
    assert_eq!(runtime.summary("finite-1").unwrap().attempts, 0);
}

#[tokio::test]
async fn runtime_finite_review_refuses_cross_task_request_and_memory_changes() {
    for change in 0..8 {
        let mut f =
            Fixture::new_at_with_network(false, tempfile::tempdir().unwrap(), false, true, true)
                .await;
        let runtime = f.runtime();
        let limits = match change {
            6 => ResourceLimits {
                address_space_bytes: None,
                ..ResourceLimits::default()
            },
            7 => ResourceLimits {
                address_space_bytes: Some(9 * 1024 * 1024 * 1024),
                ..ResourceLimits::default()
            },
            _ => ResourceLimits::default(),
        };
        let client = finite_review(&f, limits);
        match change {
            0 => f.request.prompt.push_str(" different"),
            1 => f.request.timeout_ms += 1,
            2 => f.request.max_output_bytes += 1,
            3 => f.request.scope = vec!["src/base.txt".into()],
            4 => f.request.source_state = "a".repeat(40),
            _ => {}
        }
        let run_id = if change == 5 {
            "different-task"
        } else {
            "finite-1"
        };
        assert!(
            runtime
                .review_finite_client(
                    run_id,
                    &f.router,
                    &f.context,
                    f.request.clone(),
                    f.plan.clone(),
                    "execute",
                    client
                )
                .await
                .is_err(),
            "change {change} accepted"
        );
        assert!(matches!(
            runtime.summary(run_id),
            Err(RuntimeError::NotFound)
        ));
        assert!(!f.temp.path().join("runtime/worktrees").exists());
    }
}

#[tokio::test]
async fn runtime_finite_approval_rechecks_files_before_queueing() {
    let f =
        Fixture::new_at_with_network(false, tempfile::tempdir().unwrap(), false, true, true).await;
    let runtime = f.runtime();
    let client = finite_review(&f, ResourceLimits::default());
    let pending = runtime
        .review_finite_client(
            "finite-1",
            &f.router,
            &f.context,
            f.request.clone(),
            f.plan.clone(),
            "execute",
            client,
        )
        .await
        .unwrap();
    let digest = pending.approval_digest().to_owned();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            f.temp.path().join("finite-profile"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(f.temp.path().join("finite-profile"), "changed").unwrap();
    }
    assert!(runtime.approve_finite_client(pending, &digest).is_err());
    assert_eq!(
        runtime.summary("finite-1").unwrap().state,
        RunState::AwaitingApproval
    );
}

fn runtime_finite_proof(
    f: &Fixture,
    approved: &ApprovedFiniteClientRun,
    age: u64,
) -> (
    router_adapter_api::EvidenceSource,
    StoredCapabilityProofVerifier,
    router_adapter_api::CapabilityProofRecord,
) {
    use router_adapter_api::{
        CapabilityAttemptOutcome, CapabilityNetworkScope, CapabilityProofKey,
        CapabilityProofRecord, CapabilityProofTier, EvidenceKind, EvidenceSource,
    };
    use std::os::unix::fs::PermissionsExt;
    let dir = f.temp.path().canonicalize().unwrap().join("proofs");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let mut store = CapabilityProofStore::create(&dir).unwrap();
    let key = CapabilityProofKey::derive(&[19; 32], store.store_id()).unwrap();
    let binding = approved.proof_binding().unwrap();
    let observed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - age;
    let record = CapabilityProofRecord {
        schema_version: 1,
        proof_id: "finite-proof".into(),
        sequence: 1,
        store_id: store.store_id().into(),
        capability: Capability::Network,
        tier: CapabilityProofTier::Proven,
        network_scope: Some(CapabilityNetworkScope::LoopbackFetch),
        binding: binding.clone(),
        model_id: f.request.model.to_string(),
        nonce_sha256: "e".repeat(64),
        expected_effect_sha256: "f".repeat(64),
        started_at_unix_seconds: observed,
        ended_at_unix_seconds: observed,
        max_age_seconds: 60,
        outcome: CapabilityAttemptOutcome::Succeeded,
    };
    let proof = key.authenticate(record.clone()).unwrap();
    let hash = proof.digest().unwrap();
    store.append(&proof, &[19; 32]).unwrap();
    drop(store);
    let source = EvidenceSource {
        id: "finite-proof".into(),
        kind: EvidenceKind::HostRuntime,
        observed_version: Some("fixture-v1".into()),
        observed_at_unix_seconds: observed,
        content_sha256: hash,
    };
    let verifier =
        StoredCapabilityProofVerifier::open_existing(&dir, [19; 32], vec![binding]).unwrap();
    (source, verifier, record)
}

#[tokio::test]
async fn runtime_finite_validation_reopens_live_proofs_and_keeps_the_listener_owned() {
    use router_adapter_api::{CapabilityAttemptOutcome, CapabilityProofKey};
    use std::net::TcpListener;
    let f =
        Fixture::new_at_with_network(false, tempfile::tempdir().unwrap(), false, true, true).await;
    let runtime = f.runtime();
    let client = finite_review(&f, ResourceLimits::default());
    let pending = runtime
        .review_finite_client(
            "finite-1",
            &f.router,
            &f.context,
            f.request.clone(),
            f.plan.clone(),
            "execute",
            client,
        )
        .await
        .unwrap();
    let digest = pending.approval_digest().to_owned();
    let approved = runtime.approve_finite_client(pending, &digest).unwrap();
    let (source, verifier, mut record) = runtime_finite_proof(&f, &approved, 0);
    let guard = runtime
        .validate_finite_client(&approved, &source, &verifier)
        .unwrap();
    let address = guard
        .broker_endpoint()
        .strip_prefix("tcp://")
        .unwrap()
        .to_owned();
    assert!(TcpListener::bind(&address).is_err());
    let historical = StoredCapabilityProofVerifier::open_existing(
        &f.temp.path().canonicalize().unwrap().join("proofs"),
        [19; 32],
        vec![approved.proof_binding().unwrap()],
    )
    .unwrap()
    .through_sequence(1);
    assert!(
        runtime
            .validate_finite_client(&approved, &source, &historical)
            .is_err()
    );
    let mut forged = source.clone();
    forged.content_sha256 = "0".repeat(64);
    assert!(
        runtime
            .validate_finite_client(&approved, &forged, &verifier)
            .is_err()
    );
    record.sequence = 2;
    record.proof_id = "revoked-finite-proof".into();
    record.outcome = CapabilityAttemptOutcome::Failed;
    let mut store =
        CapabilityProofStore::create(&f.temp.path().canonicalize().unwrap().join("proofs"))
            .unwrap();
    let key = CapabilityProofKey::derive(&[19; 32], store.store_id()).unwrap();
    store
        .append(&key.authenticate(record).unwrap(), &[19; 32])
        .unwrap();
    assert!(
        runtime
            .validate_finite_client(&approved, &source, &verifier)
            .is_err()
    );
    assert_eq!(runtime.summary("finite-1").unwrap().attempts, 0);
    assert!(!f.temp.path().join("runtime/worktrees").exists());
    drop(approved);
    assert!(TcpListener::bind(&address).is_ok());
}

#[tokio::test]
async fn runtime_finite_validation_refuses_expired_evidence_and_cancelled_approval() {
    for expired in [false, true] {
        let f =
            Fixture::new_at_with_network(false, tempfile::tempdir().unwrap(), false, true, true)
                .await;
        let runtime = f.runtime();
        let client = finite_review(&f, ResourceLimits::default());
        let pending = runtime
            .review_finite_client(
                "finite-1",
                &f.router,
                &f.context,
                f.request.clone(),
                f.plan.clone(),
                "execute",
                client,
            )
            .await
            .unwrap();
        let digest = pending.approval_digest().to_owned();
        let approved = runtime.approve_finite_client(pending, &digest).unwrap();
        let (source, verifier, _) =
            runtime_finite_proof(&f, &approved, if expired { 61 } else { 0 });
        if !expired {
            runtime.cancel_queued("finite-1").unwrap();
        }
        assert!(
            runtime
                .validate_finite_client(&approved, &source, &verifier)
                .is_err()
        );
        assert_eq!(runtime.summary("finite-1").unwrap().attempts, 0);
    }
}

#[tokio::test]
async fn runtime_finite_review_cannot_replace_an_existing_plain_definition() {
    let f =
        Fixture::new_at_with_network(false, tempfile::tempdir().unwrap(), false, true, true).await;
    let runtime = f.runtime();
    let plain = runtime
        .review(
            "finite-1",
            &f.router,
            &f.context,
            f.request.clone(),
            f.plan.clone(),
            "execute",
        )
        .await
        .unwrap();
    let original_digest = plain.approval_digest().to_owned();
    let client = finite_review(&f, ResourceLimits::default());
    assert!(matches!(
        runtime
            .review_finite_client(
                "finite-1",
                &f.router,
                &f.context,
                f.request.clone(),
                f.plan.clone(),
                "execute",
                client
            )
            .await,
        Err(RuntimeError::Integrity(_))
    ));
    assert_eq!(
        runtime.summary("finite-1").unwrap().approval_digest,
        original_digest
    );
    assert_eq!(
        runtime.summary("finite-1").unwrap().state,
        RunState::AwaitingApproval
    );
    runtime.approve(plain, &original_digest).unwrap();
}

#[tokio::test]
async fn finite_execution_requires_durable_admission_before_any_probe_or_attempt() {
    let f =
        Fixture::new_at_with_network(false, tempfile::tempdir().unwrap(), false, true, true).await;
    let runtime = f.runtime();
    let review = finite_review(&f, ResourceLimits::default());
    let pending = runtime
        .review_finite_client(
            "finite-1",
            &f.router,
            &f.context,
            f.request.clone(),
            f.plan.clone(),
            "execute",
            review,
        )
        .await
        .unwrap();
    let digest = pending.approval_digest().to_owned();
    let approved = runtime.approve_finite_client(pending, &digest).unwrap();
    assert!(matches!(
        runtime
            .execute_finite_client(approved, &FakeAdapter("exit 99"), Cancellation::default())
            .await,
        Err(RuntimeError::Invalid("finite client durable admission"))
    ));
    assert_eq!(runtime.summary("finite-1").unwrap().state, RunState::Queued);
    assert_eq!(runtime.summary("finite-1").unwrap().attempts, 0);
    let events = observe_events(&f.temp.path().join("runtime"), "finite-1").unwrap();
    assert!(
        !events
            .iter()
            .any(|e| e.kind == "preparation.cycle.v1" || e.kind == "admission.intent.v1")
    );
}

#[tokio::test]
async fn finite_write_without_the_actual_preapproved_view_refuses_before_registering() {
    let f =
        Fixture::new_at_with_network(true, tempfile::tempdir().unwrap(), false, true, true).await;
    let runtime = f.runtime();
    let client = finite_review(&f, ResourceLimits::default());
    assert!(matches!(
        runtime
            .review_finite_client(
                "finite-1",
                &f.router,
                &f.context,
                f.request.clone(),
                f.plan.clone(),
                "execute",
                client
            )
            .await,
        Err(RuntimeError::Sandbox)
    ));
    assert!(matches!(
        runtime.summary("finite-1"),
        Err(RuntimeError::NotFound)
    ));
    assert!(!f.temp.path().join("runtime/worktrees").exists());
}

#[tokio::test]
async fn runtime_refuses_mcp_startup_before_creating_a_run_or_attempt() {
    let f =
        Fixture::new_at_with_network(false, tempfile::tempdir().unwrap(), false, true, true).await;
    let runtime = f.runtime();
    let client = finite_review_mode(&f, ResourceLimits::default(), true);
    let refused = runtime
        .review_finite_client(
            "finite-1",
            &f.router,
            &f.context,
            f.request.clone(),
            f.plan.clone(),
            "execute",
            client,
        )
        .await;
    assert!(matches!(refused, Err(RuntimeError::Sandbox)));
    assert!(matches!(
        runtime.summary("finite-1"),
        Err(RuntimeError::NotFound)
    ));
}

#[tokio::test]
async fn finite_verifier_requires_this_approved_definition_and_refuses_before_execution() {
    let f =
        Fixture::new_at_with_network(false, tempfile::tempdir().unwrap(), false, true, true).await;
    let runtime = f.runtime();
    let client = finite_review(&f, ResourceLimits::default());
    let pending = runtime
        .review_finite_client(
            "finite-1",
            &f.router,
            &f.context,
            f.request.clone(),
            f.plan.clone(),
            "execute",
            client,
        )
        .await
        .unwrap();
    let digest = pending.approval_digest().to_owned();
    let approved = runtime.approve_finite_client(pending, &digest).unwrap();
    let verifier = runtime.finite_client_verifier(&approved).unwrap();
    let other_root = tempfile::tempdir().unwrap();
    let other = Runtime::open(&other_root.path().join("store"), Default::default()).unwrap();
    assert!(other.finite_client_verifier(&approved).is_err());
    assert!(verifier.artifact().is_err());
    assert!(
        verifier
            .record(VerificationRecord {
                verifier: "explicit-checker".into(),
                evidence_sha256: "e".repeat(64),
                artifact_sha256: None,
                validation: VerificationOutcome::Passed,
                objective: VerificationOutcome::Passed,
            })
            .is_err()
    );
    assert_eq!(runtime.summary("finite-1").unwrap().attempts, 0);
    assert_eq!(runtime.verification_record("finite-1").unwrap(), None);
    request_cancel(&f.temp.path().join("runtime"), "finite-1").unwrap();
    assert!(runtime.finite_client_verifier(&approved).is_err());
    assert!(verifier.artifact().is_err());
}
