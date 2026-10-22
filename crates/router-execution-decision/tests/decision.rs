#[path = "support/synthetic.rs"]
mod synthetic;
use router_backend_policy::*;
use router_execution_decision::*;
use synthetic::*;

#[test]
fn secondary_selection_has_distinct_binding_and_unchanged_baseline() {
    let fixture = Fixture::new();
    let authority = TestAuthority::new(fixture.active(), fixture.keys.authorities());
    let decision = decision(
        &fixture,
        &fixture.router,
        &fixture.context,
        &authority,
        124,
        125,
    );
    assert_eq!(
        decision.baseline(),
        &fixture.router.route(&fixture.context).unwrap()
    );
    assert_eq!(
        decision.baseline().selected.as_ref().unwrap().candidate.id,
        "primary"
    );
    assert_eq!(decision.selection().candidate.id, "secondary");
    assert!(decision.baseline().unavailable.is_empty());
    assert_ne!(decision.authorization_id(), decision.baseline().receipt_id);
    let binding = decision.binding().unwrap();
    let bytes = serde_json::to_vec(binding).unwrap();
    let decoded: router_types::ExecutionDecisionBinding = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(&decoded, binding); // Audit deserialization supplies no opaque proof.
    assert_eq!(
        binding.backend.activation_state_hash,
        authority.state.state_hash()
    );
    assert_eq!(
        binding.backend.authority_roots_sha256,
        authority.roots.fingerprint().unwrap()
    );
    let lease = decision
        .acquire_dispatch(&fixture.router, &fixture.context, Some(&authority), 124)
        .unwrap()
        .unwrap();
    assert_eq!(
        authority.guards.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert!(matches!(lease.validate_at(125), Err(DecisionError::Stale)));
    drop(lease);
    assert_eq!(
        authority.guards.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert!(matches!(
        decision.acquire_dispatch(&fixture.router, &fixture.context, None, 124),
        Err(DecisionError::AuthorityRequired)
    ));
}

#[test]
fn rollback_and_root_rotation_reject_same_previously_valid_selection() {
    let fixture = Fixture::new();
    let mut authority = TestAuthority::new(fixture.active(), fixture.keys.authorities());
    let decision = decision(
        &fixture,
        &fixture.router,
        &fixture.context,
        &authority,
        124,
        150,
    );
    let approval = fixture.approval(
        &authority.state,
        ActivationAction::Rollback,
        fixture.context.policy_hash(),
        125,
        "2",
    );
    authority
        .state
        .apply(&approval, None, &authority.roots, 125)
        .unwrap();
    assert!(matches!(
        decision.acquire_dispatch(&fixture.router, &fixture.context, Some(&authority), 125),
        Err(DecisionError::Stale)
    ));
    decision
        .validate_identity(&fixture.router, &fixture.context)
        .unwrap(); // historical reopen only
    let mut keys = Keys::new();
    keys.gate = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let rotated = TestAuthority::new(fixture.active(), keys.authorities());
    assert!(matches!(
        decision.acquire_dispatch(&fixture.router, &fixture.context, Some(&rotated), 124),
        Err(DecisionError::Stale)
    ));
}

#[test]
fn deterministic_receipt_and_explicit_fallback_keep_existing_identity() {
    let fixture = Fixture::new();
    let baseline = fixture.router.route(&fixture.context).unwrap();
    let proof = fixture
        .router
        .validate_receipt(&fixture.context, &baseline)
        .unwrap();
    let decision =
        ExecutionDecision::deterministic(&fixture.router, &fixture.context, &proof).unwrap();
    assert_eq!(decision.authorization_id(), baseline.receipt_id);
    assert!(decision.binding().is_none());
    assert!(
        decision
            .acquire_dispatch(&fixture.router, &fixture.context, None, 124)
            .unwrap()
            .is_none()
    );
}
