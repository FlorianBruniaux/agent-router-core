#[path = "support/synthetic.rs"]
mod synthetic;
use router_backend_policy::*;
use router_execution_decision::*;
use router_types::*;
use synthetic::*;

struct Untrusted(EscalationDecisionBinding);
impl EscalationAuthority for Untrusted {
    fn escalation_binding(&self) -> &EscalationDecisionBinding {
        &self.0
    }
}

fn binding(fixture: &Fixture, baseline: &PhaseReceipt) -> EscalationDecisionBinding {
    EscalationDecisionBinding {
        schema_version: 1,
        decision_id: "e".repeat(64),
        baseline_receipt_id: baseline.receipt_id.clone(),
        context_hash: fixture.context.context_hash().into(),
        pool_hash: fixture.context.pool_hash().into(),
        source_run_id: "source-run".into(),
        source_definition_hash: "a".repeat(64),
        source_authorization_id: "b".repeat(64),
        source_candidate_id: "primary".into(),
        source_model: baseline.selected.as_ref().unwrap().candidate.model.clone(),
        source_effort: baseline.selected.as_ref().unwrap().candidate.effort,
        source_state: "c".repeat(40),
        task_execution_sha256: "d".repeat(64),
        ledger_hash: "f".repeat(64),
        policy: EscalationPolicy {
            schema_version: 1,
            minimum_failed_attempts: 1,
            retryable_failures: vec![],
            transitions: vec![],
        },
        attempts: vec![],
        remaining_budget: TaskBudget {
            max_cost_microusd: 1000,
            max_elapsed_ms: 1000,
            max_tokens: 1000,
        },
        uses_parent_accounting_bounds: false,
        selection: baseline.selected.clone().unwrap(),
    }
}

#[test]
fn escalated_binds_only_a_binding_that_matches_context_baseline_and_selection() {
    let fixture = Fixture::new();
    let baseline = fixture.router.route(&fixture.context).unwrap();
    let good = binding(&fixture, &baseline);
    let decision = ExecutionDecision::escalated(
        &fixture.router,
        &fixture.context,
        &baseline,
        &Untrusted(good.clone()),
    )
    .unwrap();
    assert_eq!(decision.origin(), ExecutionDecisionOrigin::Escalated);
    assert_eq!(decision.authorization_id(), good.decision_id);
    assert_eq!(decision.selection(), &good.selection);
    assert_eq!(decision.baseline(), &baseline);
    assert_eq!(decision.escalation_binding(), Some(&good));
    decision
        .validate_identity(&fixture.router, &fixture.context)
        .unwrap();

    let mut wrong_schema = good.clone();
    wrong_schema.schema_version = 2;
    let mut wrong_context = good.clone();
    wrong_context.context_hash = "0".repeat(64);
    let mut wrong_pool = good.clone();
    wrong_pool.pool_hash = "0".repeat(64);
    let mut wrong_baseline = good.clone();
    wrong_baseline.baseline_receipt_id = "0".repeat(64);
    let mut wrong_selection = good.clone();
    wrong_selection.selection.candidate.id = "not-a-candidate".into();
    for forged in [
        wrong_schema,
        wrong_context,
        wrong_pool,
        wrong_baseline,
        wrong_selection,
    ] {
        assert!(matches!(
            ExecutionDecision::escalated(
                &fixture.router,
                &fixture.context,
                &baseline,
                &Untrusted(forged)
            ),
            Err(DecisionError::Context)
        ));
    }
    let mut other_baseline = baseline.clone();
    other_baseline.receipt_id = "0".repeat(64);
    assert!(matches!(
        ExecutionDecision::escalated(
            &fixture.router,
            &fixture.context,
            &other_baseline,
            &Untrusted(good)
        ),
        Err(DecisionError::Context)
    ));
}

#[test]
fn abstained_backend_decision_cannot_become_an_execution_decision() {
    let fixture = Fixture::with_failure(0, BackendFailurePolicy::Abstain);
    let authority = TestAuthority::new(fixture.active(), fixture.keys.authorities());
    let proof = decide_active(
        &authority.state,
        &fixture.router,
        &fixture.context,
        None,
        &authority.roots,
        122,
    )
    .unwrap();
    assert_eq!(proof.evidence().mode, ActiveDecisionMode::Abstained);
    let guard = ActivationAuthority::acquire(&authority).unwrap();
    assert!(matches!(
        ExecutionDecision::activated(&fixture.router, &fixture.context, &proof, &*guard, 122),
        Err(DecisionError::Abstained)
    ));
}

#[test]
fn activated_rejects_an_expired_proposal() {
    let fixture = Fixture::new();
    let authority = TestAuthority::new(fixture.active(), fixture.keys.authorities());
    let signed = proposal(
        &fixture.keys,
        &fixture.artifact,
        &fixture.router,
        &fixture.context,
        ProposalPurpose::Active(authority.state.state_hash().into()),
        124,
        125,
        Some("c01"),
    );
    let proof = decide_active(
        &authority.state,
        &fixture.router,
        &fixture.context,
        Some(&signed),
        &authority.roots,
        124,
    )
    .unwrap();
    let guard = ActivationAuthority::acquire(&authority).unwrap();
    ExecutionDecision::activated(&fixture.router, &fixture.context, &proof, &*guard, 124).unwrap();
    assert!(matches!(
        ExecutionDecision::activated(&fixture.router, &fixture.context, &proof, &*guard, 125),
        Err(DecisionError::Stale)
    ));
}
