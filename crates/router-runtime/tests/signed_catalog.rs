//! Signed routing snapshots deliberately cannot enter the legacy runtime.
#[path = "../../router-policy/tests/support/signed_fixture.rs"]
mod signed_fixture;
#[path = "../../router-prepare/tests/support/signed_preparation_fixture.rs"]
mod signed_preparation_fixture;
use router_execution_decision::ExecutionDecision;
use router_runtime::{Runtime, RuntimeError, RuntimeLimits};
use router_types::*;
use signed_fixture::Fixture;
use signed_preparation_fixture::Fixture as PreparationFixture;

fn request(decision: &ExecutionDecision, fixture: &Fixture) -> ExecutionRequest {
    let candidate = &decision.selection().candidate;
    ExecutionRequest {
        schema_version: 1,
        receipt_id: decision.authorization_id().into(),
        candidate_id: candidate.id.clone(),
        phase: fixture.request.phase,
        host: HarnessId::parse("codex").unwrap(),
        model: candidate.model.clone(),
        effort: candidate.effort,
        workspace: fixture.inputs.execution_scope.workspace.clone(),
        source_state: fixture.inputs.execution_scope.source_state.clone(),
        scope: vec!["src".into()],
        sandbox: ExecutionSandbox::ReadOnly,
        required_capabilities: Default::default(),
        tools: ToolSelection::Disabled,
        agent: None,
        skills: vec![],
        prompt: "synthetic private content".into(),
        mode: ExecutionMode::Execute,
        target: ExecutionTarget::ExternalWorker,
        allow_degradation: false,
        timeout_ms: 100,
        max_output_bytes: 1024,
    }
}
fn refused<T>(result: Result<T, RuntimeError>) {
    assert!(matches!(
        result,
        Err(RuntimeError::Invalid(
            "signed catalog dispatch authority unavailable"
        ))
    ));
}
#[tokio::test]
async fn all_review_and_reopen_entries_refuse_signed_context_before_git_or_registration() {
    let f = Fixture::new();
    f.activate(100);
    let context = f.context(100).unwrap();
    let receipt = f.router.route(&context).unwrap();
    let proof = f.router.validate_receipt(&context, &receipt).unwrap();
    let decision = ExecutionDecision::deterministic(&f.router, &context, &proof).unwrap();
    // Deliberately not a repository. Reaching source_state would fail differently.
    assert!(!std::path::Path::new(&f.inputs.execution_scope.workspace).exists());
    let plan = context.signed_plan().unwrap().clone();
    let runtime = Runtime::open(&f.temp.path().join("runtime"), RuntimeLimits::default()).unwrap();
    let before = runtime.events().unwrap();
    refused(
        runtime
            .review(
                "signed",
                &f.router,
                &context,
                request(&decision, &f),
                plan.clone(),
                "plan",
            )
            .await,
    );
    refused(
        runtime
            .review_selected(
                "signed",
                &f.router,
                &context,
                &proof,
                request(&decision, &f),
                plan.clone(),
                "plan",
                None,
            )
            .await,
    );
    refused(
        runtime
            .review_with_artifacts(
                "signed",
                &f.router,
                &context,
                &proof,
                request(&decision, &f),
                plan.clone(),
                "plan",
                None,
                None,
            )
            .await,
    );
    refused(
        runtime
            .review_decision(
                "signed",
                &f.router,
                &context,
                &decision,
                request(&decision, &f),
                plan.clone(),
                "plan",
                None,
                None,
            )
            .await,
    );
    refused(runtime.reopen(
        "signed",
        &f.router,
        &context,
        request(&decision, &f),
        plan.clone(),
        "plan",
    ));
    refused(runtime.reopen_selected(
        "signed",
        &f.router,
        &context,
        &proof,
        request(&decision, &f),
        plan.clone(),
        "plan",
        None,
    ));
    refused(runtime.reopen_with_artifacts(
        "signed",
        &f.router,
        &context,
        &proof,
        request(&decision, &f),
        plan.clone(),
        "plan",
        None,
        None,
    ));
    refused(runtime.reopen_decision(
        "signed",
        &f.router,
        &context,
        &decision,
        request(&decision, &f),
        plan.clone(),
        "plan",
        None,
        None,
    ));
    assert_eq!(runtime.events().unwrap(), before);
    assert!(runtime.summary("signed").is_err());
    runtime.verify_integrity().unwrap();
    // No PendingRun or ApprovedRun is constructible by these public APIs.
    // execute_decision retains the same gate as defense against future callers.
}

#[tokio::test]
async fn runtime_refuses_a_real_signed_prepared_execution_without_journal_or_spawn() {
    let f = PreparationFixture::new();
    let prepared = f.prepare().unwrap();
    let runtime = Runtime::open(
        &f.source.temp.path().join("runtime"),
        RuntimeLimits::default(),
    )
    .unwrap();
    let before = runtime.events().unwrap();
    let plan = f.context.signed_plan().unwrap().clone();
    let result = runtime
        .review_decision(
            "signed-prepared",
            f.router(),
            &f.context,
            prepared.decision(),
            prepared.request().clone(),
            plan,
            "plan",
            Some((&f.execution, 0)),
            None,
        )
        .await;
    refused(result);
    assert_eq!(runtime.events().unwrap(), before);
    assert!(runtime.summary("signed-prepared").is_err());
    runtime.verify_integrity().unwrap();
}
#[test]
fn signed_execution_decision_cannot_validate_against_a_legacy_context() {
    let f = Fixture::new();
    let head = f.activate(100);
    let context = f.context(100).unwrap();
    let proof = f
        .router
        .validate_receipt(&context, &f.router.route(&context).unwrap())
        .unwrap();
    let decision = ExecutionDecision::deterministic(&f.router, &context, &proof).unwrap();
    let guard = f
        .store
        .acquire_current(&head.head_hash, &f.roots, 100)
        .unwrap();
    let catalog = guard
        .catalog()
        .catalog(&guard.access(&f.roots, 100).unwrap())
        .unwrap();
    let legacy = f
        .router
        .context(f.request.clone(), &f.snapshot(), &catalog)
        .unwrap();
    assert!(decision.validate_identity(&f.router, &legacy).is_err());
}
