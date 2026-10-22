//! Two real local worker attempts and durable accounting. No provider calls.
#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use router_adapter_api::{
    AdapterError, HarnessAdapter, HostObservation, SnapshotValidation, StreamDialect,
    ValidatedExecutionRequest, decode_transport, prepared_run,
};
use router_catalog::Catalog;
use router_policy::{PhaseRouter, ValidatedPhaseContext};
use router_runtime::*;
use router_types::*;
use router_workflow::{PlanLimits, build_plan};
#[cfg(target_os = "linux")]
use std::path::Path;
use std::{
    collections::BTreeMap,
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture {
    temp: tempfile::TempDir,
    router: PhaseRouter,
    context: ValidatedPhaseContext,
    request: ExecutionRequest,
    plan: WorkflowPlan,
}
impl Fixture {
    async fn new(write: bool) -> Self {
        Self::new_at(write, tempfile::tempdir().unwrap()).await
    }
    async fn new_at(write: bool, temp: tempfile::TempDir) -> Self {
        let root = fs::canonicalize(temp.path()).unwrap().join("repo");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("src")).unwrap();
        fs::write(root.join("src/base.txt"), "base\n").unwrap();
        for args in [
            vec!["init", "-q"],
            vec!["add", "src"],
            vec![
                "-c",
                "user.name=Runtime Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "-q",
                "--no-gpg-sign",
                "-m",
                "fixture",
            ],
        ] {
            assert!(
                Command::new("/usr/bin/git")
                    .arg("-C")
                    .arg(&root)
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let mut request: PhaseRouteRequest = serde_json::from_str(include_str!(
            "../../../fixtures/examples/phase-request.json"
        ))
        .unwrap();
        request.phase = StageKind::Execute;
        request.task.budget.max_elapsed_ms = 60_000;
        if !write {
            request
                .task
                .allowed_mutations
                .remove(&Mutation::WorkspaceWrite);
        }

        let candidate = &mut request.candidates[0];
        candidate.sandbox = if write {
            PhaseSandbox::WorkspaceWrite
        } else {
            PhaseSandbox::ReadOnly
        };
        let plan = build_plan(
            &request.task,
            WorkflowPreset::DirectSafe,
            PlanLimits {
                reserve_elapsed_ms: 1_000,
                ..PlanLimits::default()
            },
        )
        .unwrap();
        let mut observation: HostObservation = serde_json::from_str(include_str!(
            "../../../fixtures/examples/phase-snapshot.json"
        ))
        .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        observation.observed_at_unix_seconds = now;
        for evidence in &mut observation.evidence {
            evidence.observed_at_unix_seconds = now;
        }
        let snapshot = fixture_proofs::from_observation(
            observation.seal().unwrap(),
            SnapshotValidation {
                now_unix_seconds: now,
                max_age_seconds: 300,
            },
        )
        .unwrap();
        let catalog = Catalog::from_json(include_bytes!(
            "../../../fixtures/examples/phase-catalog.json"
        ))
        .unwrap();
        let router = PhaseRouter::stable_v2();
        let context = router.context(request, &snapshot, &catalog).unwrap();
        let receipt = router.route(&context).unwrap();
        let selected = &receipt.selected.as_ref().unwrap().candidate;
        let request = ExecutionRequest {
            schema_version: 1,
            receipt_id: receipt.receipt_id.clone(),
            candidate_id: selected.id.clone(),
            phase: receipt.phase,
            host: snapshot.host().harness.clone(),
            model: selected.model.clone(),
            effort: selected.effort,
            workspace: root.to_str().unwrap().into(),
            source_state: source_state(&root).await.unwrap(),
            scope: vec!["src".into()],
            sandbox: if write {
                ExecutionSandbox::WorkspaceWrite
            } else {
                ExecutionSandbox::ReadOnly
            },
            required_capabilities: router
                .execution_capabilities(&context, receipt.selected.as_ref().unwrap())
                .unwrap(),
            tools: ToolSelection::Disabled,
            agent: None,
            skills: vec![],
            prompt: "private fixture prompt never stored".into(),
            mode: ExecutionMode::Execute,
            target: ExecutionTarget::ExternalWorker,
            allow_degradation: false,
            timeout_ms: 2_000,
            max_output_bytes: 16_384,
        };
        Self {
            temp,
            router,
            context,
            request,
            plan,
        }
    }
    fn runtime(&self) -> Runtime {
        Runtime::open(
            &self.temp.path().join("runtime"),
            RuntimeLimits {
                max_attempts: 5,
                ..RuntimeLimits::default()
            },
        )
        .map(|runtime| {
            runtime.with_capability_proof_verifier(std::sync::Arc::new(
                fixture_proofs::FixtureVerifier,
            ))
        })
        .unwrap()
    }
    async fn review(&self, runtime: &Runtime) -> PendingRun {
        runtime
            .review(
                "run-1",
                &self.router,
                &self.context,
                self.request.clone(),
                self.plan.clone(),
                "execute",
            )
            .await
            .unwrap()
    }
}

/// Prints a Codex stream whose `turn.completed` declares usage, decoded by the
/// real shared decoder.
struct UsageAdapter;
impl HarnessAdapter for UsageAdapter {
    fn host(&self) -> &'static str {
        "codex"
    }
    fn prepare(
        &self,
        request: &ValidatedExecutionRequest,
    ) -> std::result::Result<PreparedRun, AdapterError> {
        prepared_run(
            request,
            "/bin/sh",
            vec![
                "-c".into(),
                r#"printf '%s\n' '{"type":"turn.completed","usage":{"input_tokens":700,"output_tokens":30}}'"#.into(),
            ],
            vec![],
        )
    }
    fn decode_stream(
        &self,
        bytes: &[u8],
        outcome: TransportOutcome,
        max_bytes: usize,
    ) -> std::result::Result<RuntimeEvidence, AdapterError> {
        decode_transport(bytes, outcome, max_bytes, StreamDialect::Codex)
    }
}

struct Adapter {
    succeeds: bool,
}
impl HarnessAdapter for Adapter {
    fn host(&self) -> &'static str {
        "codex"
    }
    fn prepare(
        &self,
        request: &ValidatedExecutionRequest,
    ) -> std::result::Result<PreparedRun, AdapterError> {
        prepared_run(
            request,
            "/bin/sh",
            vec![
                "-c".into(),
                if self.succeeds {
                    "printf completed"
                } else {
                    "printf 'two error messages do not make two attempts'; exit 1"
                }
                .into(),
            ],
            vec![],
        )
    }
    fn decode_stream(
        &self,
        _: &[u8],
        _: TransportOutcome,
        _: usize,
    ) -> std::result::Result<RuntimeEvidence, AdapterError> {
        Err(AdapterError::Unsupported("synthetic"))
    }
}
struct LocalProcess;
impl SandboxSupervisor for LocalProcess {
    fn resource_limits_enforced(&self) -> bool {
        true
    }
    fn command(&self, run: &PreparedRun, _: &SandboxPolicy) -> Result<tokio::process::Command> {
        let mut cmd = tokio::process::Command::new(&run.program);
        cmd.args(&run.argv)
            .current_dir(&run.cwd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        Ok(cmd)
    }
}
fn policy() -> EscalationPolicy {
    EscalationPolicy {
        schema_version: 1,
        minimum_failed_attempts: 2,
        retryable_failures: vec![RunFailure::Crash],
        transitions: vec![EscalationTransition {
            from_candidate_id: "primary".into(),
            to_candidate_id: "secondary".into(),
        }],
    }
}

fn contract(fixture: &Fixture, instance: &str) -> WorkflowExecutionContract {
    router_workflow::seal_execution_contract(
        WorkflowExecutionContract {
            schema_version: 1,
            instance_id: instance.into(),
            plan_id: fixture.plan.plan_id.clone(),
            workspace: fixture.request.workspace.clone(),
            source_state: fixture.request.source_state.clone(),
            nodes: fixture
                .plan
                .nodes
                .iter()
                .map(|node| {
                    (
                        node.id.clone(),
                        NodeExecutionContract {
                            phase: if node.independent_verifier {
                                StageKind::Verify
                            } else {
                                StageKind::Execute
                            },
                            dependencies: node
                                .dependencies
                                .iter()
                                .map(|id| (id.clone(), DependencyRequirement::Verified))
                                .collect(),
                        },
                    )
                })
                .collect(),
            contract_sha256: String::new(),
        },
        &fixture.plan,
    )
    .unwrap()
}
async fn review_generation(
    fixture: &Fixture,
    runtime: &Runtime,
    id: &str,
    contract: &WorkflowExecutionContract,
    generation: u32,
) -> PendingRun {
    let receipt = fixture.router.route(&fixture.context).unwrap();
    let proof = fixture
        .router
        .validate_receipt(&fixture.context, &receipt)
        .unwrap();
    runtime
        .review_selected(
            id,
            &fixture.router,
            &fixture.context,
            &proof,
            fixture.request.clone(),
            fixture.plan.clone(),
            "execute",
            Some((contract, generation)),
        )
        .await
        .unwrap()
}
async fn finish(
    runtime: &Runtime,
    pending: &PendingRun,
    supervisor: &dyn SandboxSupervisor,
    succeeds: bool,
) -> RunCompletion {
    let approved = runtime
        .approve(pending.clone(), pending.approval_digest())
        .unwrap();
    runtime
        .execute(
            approved,
            &Adapter { succeeds },
            supervisor,
            Cancellation::default(),
        )
        .await
        .unwrap()
}
fn account(runtime: &Runtime, pending: &PendingRun, amount: u64) {
    for attempt in runtime.attempt_evidence(&pending.summary().run_id).unwrap() {
        let reviewed = runtime
            .review_attempt_bound(
                pending,
                &attempt.identity,
                AccountingUpperBound {
                    cost_microusd: amount,
                    tokens: amount,
                },
            )
            .unwrap();
        assert!(matches!(
            runtime.approve_attempt_bound(&reviewed, "wrong"),
            Err(EscalationError::Approval)
        ));
        runtime
            .approve_attempt_bound(&reviewed, reviewed.approval_digest())
            .unwrap();
    }
}
async fn native_supervisor(fixture: &Fixture) -> ResourceSupervisor<impl SandboxSupervisor> {
    let test_binary = std::env::current_exe().unwrap();
    let helper = fs::canonicalize(
        test_binary
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(format!(
                "router-sandbox-helper{}",
                std::env::consts::EXE_SUFFIX
            )),
    )
    .unwrap();
    let root = fs::canonicalize(fixture.temp.path()).unwrap();
    let programs = BTreeMap::from([("/bin/sh".into(), fs::canonicalize("/bin/sh").unwrap())]);
    #[cfg(target_os = "macos")]
    let sandbox = SeatbeltSandbox::probe(&root, programs, vec![], BTreeMap::new())
        .await
        .unwrap();
    #[cfg(target_os = "linux")]
    let sandbox = BubblewrapSandbox::probe(
        &root,
        Path::new("/usr/bin/bwrap"),
        programs,
        vec![],
        BTreeMap::new(),
    )
    .await
    .unwrap();
    ResourceSupervisor::probe(
        &helper,
        ResourceLimits {
            address_space_bytes: None,
            max_processes: 4096,
            ..ResourceLimits::default()
        },
        sandbox,
    )
    .await
    .unwrap()
}
#[tokio::test]
async fn host_declared_usage_is_reported_but_never_enters_admission_accounting() {
    let fixture = Fixture::new(false).await;
    let runtime = fixture.runtime();
    let pending = fixture.review(&runtime).await;
    let approved = runtime
        .approve(pending.clone(), pending.approval_digest())
        .unwrap();
    let completion = runtime
        .execute(
            approved,
            &UsageAdapter,
            &LocalProcess,
            Cancellation::default(),
        )
        .await
        .unwrap();
    let usage = completion.runtime_evidence.unwrap().host_usage.unwrap();
    assert_eq!(usage.input_tokens, UsageField::host_reported(700));
    assert_eq!(usage.total_tokens(), Some(730));
    let evidence = runtime.attempt_evidence("run-1").unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].observed_cost_microusd, None);
    assert_eq!(evidence[0].observed_tokens, None);
}

#[tokio::test]
async fn one_real_attempt_with_two_errors_is_insufficient_and_metadata_stays_private() {
    let fixture = Fixture::new(false).await;
    let runtime = fixture.runtime();
    let pending = fixture.review(&runtime).await;
    finish(&runtime, &pending, &LocalProcess, false).await;
    assert!(matches!(
        runtime.review_escalation(&pending, &policy()),
        Err(EscalationError::Attempts)
    ));
    let evidence = runtime.attempt_evidence("run-1").unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].identity.attempt, 1);
    assert_eq!(evidence[0].observed_cost_microusd, None);
    assert_eq!(evidence[0].observed_tokens, None);
    assert!(
        !serde_json::to_string(&runtime.events().unwrap())
            .unwrap()
            .contains("two error messages")
    );
    assert!(
        !serde_json::to_string(&runtime.events().unwrap())
            .unwrap()
            .contains("private fixture prompt")
    );
    runtime.verify_integrity().unwrap();
}
#[tokio::test]
async fn unknown_cleanup_and_invalid_policy_block_even_with_parent_accounting() {
    let fixture = Fixture::new(false).await;
    let runtime = fixture.runtime();
    let pending = fixture.review(&runtime).await;
    finish(&runtime, &pending, &LocalProcess, false).await;
    let pending = runtime.retry(pending).unwrap();
    finish(&runtime, &pending, &LocalProcess, false).await;
    account(&runtime, &pending, 1);
    assert!(matches!(
        runtime.review_escalation(&pending, &policy()),
        Err(EscalationError::Evidence)
    ));
    let mut invalid = policy();
    invalid.minimum_failed_attempts = 1;
    assert!(matches!(
        runtime.review_escalation(&pending, &invalid),
        Err(EscalationError::Policy)
    ));
    invalid = policy();
    invalid.retryable_failures = vec![RunFailure::Authentication];
    assert!(matches!(
        runtime.review_escalation(&pending, &invalid),
        Err(EscalationError::Policy)
    ));
}
#[tokio::test]
async fn accounting_review_cannot_be_replayed_after_another_attempt() {
    let fixture = Fixture::new(false).await;
    let runtime = fixture.runtime();
    let pending = fixture.review(&runtime).await;
    finish(&runtime, &pending, &LocalProcess, false).await;
    let review = runtime
        .review_attempt_bound(
            &pending,
            &AttemptIdentity {
                run_id: "run-1".into(),
                attempt: 1,
            },
            AccountingUpperBound {
                cost_microusd: 1,
                tokens: 1,
            },
        )
        .unwrap();
    let pending = runtime.retry(pending).unwrap();
    assert!(
        runtime
            .approve_attempt_bound(&review, review.approval_digest())
            .is_err()
    );
    finish(&runtime, &pending, &LocalProcess, false).await;
    assert!(
        runtime
            .review_attempt_bound(
                &pending,
                &AttemptIdentity {
                    run_id: "other-instance".into(),
                    attempt: 1
                },
                AccountingUpperBound {
                    cost_microusd: 1,
                    tokens: 1
                }
            )
            .is_err()
    );
}
#[tokio::test]
#[ignore = "requires built native helper and OS sandbox"]
async fn native_two_attempts_accounting_new_approval_and_secondary_dispatch_survive_restart() {
    let mut fixture = Fixture::new(false).await;
    fixture.enable_semantic_assets();
    let supervisor = native_supervisor(&fixture).await;
    let runtime = fixture.runtime();
    let pending = fixture.review(&runtime).await;
    let original_approval = pending.approval_digest().to_owned();
    let first = finish(&runtime, &pending, &supervisor, false).await;
    assert_eq!(first.run.failure, Some(RunFailure::Crash));
    let pending = runtime.retry(pending).unwrap();
    finish(&runtime, &pending, &supervisor, false).await;
    assert!(matches!(
        runtime.review_escalation(&pending, &policy()),
        Err(EscalationError::AccountingUnknown)
    ));
    account(&runtime, &pending, 10);
    let proof = runtime.review_escalation(&pending, &policy()).unwrap();
    assert_eq!(proof.binding().attempts.len(), 2);
    assert!(proof.binding().uses_parent_accounting_bounds);
    let budget = &fixture
        .plan
        .nodes
        .iter()
        .find(|n| n.id == "execute")
        .unwrap()
        .budget;
    assert_eq!(
        proof.binding().remaining_budget.max_cost_microusd,
        budget.max_cost_microusd - 20
    );
    let decision = proof.decision(&fixture.router, &fixture.context).unwrap();
    assert_eq!(
        decision.baseline(),
        &fixture.router.route(&fixture.context).unwrap()
    );
    assert!(decision.baseline().unavailable.is_empty());
    assert_eq!(decision.selection().candidate.id, "secondary");
    let mut request = fixture.request.clone();
    request.candidate_id = "secondary".into();
    request.model = decision.selection().candidate.model.clone();
    request.receipt_id = decision.authorization_id().into();
    struct UntrustedBinding(EscalationDecisionBinding);
    impl router_execution_decision::EscalationAuthority for UntrustedBinding {
        fn escalation_binding(&self) -> &EscalationDecisionBinding {
            &self.0
        }
    }
    let mut forged = proof.binding().clone();
    forged.remaining_budget.max_tokens += 1;
    let forged = router_execution_decision::ExecutionDecision::escalated(
        &fixture.router,
        &fixture.context,
        decision.baseline(),
        &UntrustedBinding(forged),
    )
    .unwrap();
    assert!(
        runtime
            .review_decision(
                "forged-proof",
                &fixture.router,
                &fixture.context,
                &forged,
                request.clone(),
                fixture.plan.clone(),
                "execute",
                None,
                None
            )
            .await
            .is_err()
    );
    let mut changed_request = request.clone();
    changed_request.prompt.push_str(" different task");
    assert!(
        runtime
            .review_decision(
                "changed-prompt",
                &fixture.router,
                &fixture.context,
                &decision,
                changed_request,
                fixture.plan.clone(),
                "execute",
                None,
                None
            )
            .await
            .is_err()
    );
    let target = runtime
        .review_decision(
            "escalated",
            &fixture.router,
            &fixture.context,
            &decision,
            request.clone(),
            fixture.plan.clone(),
            "execute",
            None,
            None,
        )
        .await
        .unwrap();
    assert!(runtime.approve(target.clone(), &original_approval).is_err());
    assert!(runtime.retry(pending.clone()).is_err());
    assert!(
        runtime
            .review_decision(
                "double-spend",
                &fixture.router,
                &fixture.context,
                &decision,
                request.clone(),
                fixture.plan.clone(),
                "execute",
                None,
                None
            )
            .await
            .is_err()
    );
    let digest = target.approval_digest().to_owned();
    drop(runtime);
    let runtime = fixture.runtime();
    let target = runtime
        .reopen_decision(
            "escalated",
            &fixture.router,
            &fixture.context,
            &decision,
            request,
            fixture.plan.clone(),
            "execute",
            None,
            None,
        )
        .unwrap();
    assert_eq!(target.approval_digest(), digest);
    let result = finish(&runtime, &target, &supervisor, true).await;
    assert_eq!(result.run.state, RunState::Verifying);
    assert_eq!(result.objective, VerificationOutcome::Unknown);
    assert_eq!(decision.baseline().schema_version, 3);
    assert!(
        runtime
            .events()
            .unwrap()
            .iter()
            .any(|event| event.run_id == "escalated" && event.kind == "assets.final_gate")
    );
    assert!(runtime.retry(target).is_err());
    runtime.verify_integrity().unwrap();
}
#[tokio::test]
#[ignore = "requires built native helper and OS sandbox"]
async fn native_budget_pool_failures_and_cumulative_limit_are_enforced() {
    let fixture = Fixture::new(false).await;
    let supervisor = native_supervisor(&fixture).await;
    let runtime = fixture.runtime();
    let pending = fixture.review(&runtime).await;
    finish(&runtime, &pending, &supervisor, false).await;
    let pending = runtime.retry(pending).unwrap();
    finish(&runtime, &pending, &supervisor, false).await;
    account(&runtime, &pending, 10);
    let mut wrong = policy();
    wrong.transitions[0].to_candidate_id = "outside-pool".into();
    let rejected = runtime.review_escalation(&pending, &wrong);
    assert!(
        matches!(rejected, Err(EscalationError::Target)),
        "{rejected:?}"
    );
    wrong = policy();
    wrong.retryable_failures = vec![RunFailure::Network];
    assert!(matches!(
        runtime.review_escalation(&pending, &wrong),
        Err(EscalationError::Attempts)
    ));
    let proof = runtime.review_escalation(&pending, &policy()).unwrap();
    let decision = proof.decision(&fixture.router, &fixture.context).unwrap();
    let next = runtime.retry(pending.clone()).unwrap();
    assert!(runtime.review_escalation(&pending, &policy()).is_err());
    let mut request = fixture.request.clone();
    request.candidate_id = "secondary".into();
    request.model = decision.selection().candidate.model.clone();
    request.receipt_id = decision.authorization_id().into();
    assert!(
        runtime
            .review_decision(
                "stale",
                &fixture.router,
                &fixture.context,
                &decision,
                request,
                fixture.plan.clone(),
                "execute",
                None,
                None
            )
            .await
            .is_err()
    );
    finish(&runtime, &next, &supervisor, false).await;
    let third = AttemptIdentity {
        run_id: "run-1".into(),
        attempt: 3,
    };
    let review = runtime
        .review_attempt_bound(
            &next,
            &third,
            AccountingUpperBound {
                cost_microusd: u64::MAX,
                tokens: 1,
            },
        )
        .unwrap();
    runtime
        .approve_attempt_bound(&review, review.approval_digest())
        .unwrap();
    assert!(matches!(
        runtime.review_escalation(&next, &policy()),
        Err(EscalationError::Budget)
    ));
    drop(runtime);
    let runtime = Runtime::open(
        &fixture.temp.path().join("runtime"),
        RuntimeLimits {
            max_attempts: 3,
            ..RuntimeLimits::default()
        },
    )
    .map(|runtime| {
        runtime.with_capability_proof_verifier(std::sync::Arc::new(fixture_proofs::FixtureVerifier))
    })
    .unwrap();
    assert!(matches!(
        runtime.review_escalation(&next, &policy()),
        Err(EscalationError::Attempts)
    ));
}

#[tokio::test]
#[ignore = "requires built native helper and OS sandbox"]
async fn native_distinct_runs_count_only_within_the_same_instance_and_node() {
    let fixture = Fixture::new(false).await;
    let supervisor = native_supervisor(&fixture).await;
    let runtime = fixture.runtime();
    let a = contract(&fixture, "a");
    let b = contract(&fixture, "b");
    let first = review_generation(&fixture, &runtime, "a-first", &a, 0).await;
    finish(&runtime, &first, &supervisor, false).await;
    let foreign = review_generation(&fixture, &runtime, "b-first", &b, 0).await;
    finish(&runtime, &foreign, &supervisor, false).await;
    assert!(matches!(
        runtime.review_escalation(&first, &policy()),
        Err(EscalationError::Attempts)
    ));
    let second = review_generation(&fixture, &runtime, "a-second", &a, 1).await;
    finish(&runtime, &second, &supervisor, false).await;
    account(&runtime, &second, 1);
    let proof = runtime.review_escalation(&second, &policy()).unwrap();
    assert_eq!(
        proof.binding().attempts,
        vec![
            AttemptIdentity {
                run_id: "a-first".into(),
                attempt: 1
            },
            AttemptIdentity {
                run_id: "a-second".into(),
                attempt: 1
            }
        ]
    );
    let decision = proof.decision(&fixture.router, &fixture.context).unwrap();
    let mut request = fixture.request.clone();
    request.candidate_id = "secondary".into();
    request.model = decision.selection().candidate.model.clone();
    request.receipt_id = decision.authorization_id().into();
    assert!(
        runtime
            .review_decision(
                "wrong-instance",
                &fixture.router,
                &fixture.context,
                &decision,
                request.clone(),
                fixture.plan.clone(),
                "execute",
                Some((&b, 1)),
                None
            )
            .await
            .is_err()
    );
    let target = runtime
        .review_decision(
            "a-escalated",
            &fixture.router,
            &fixture.context,
            &decision,
            request,
            fixture.plan.clone(),
            "execute",
            Some((&a, 2)),
            None,
        )
        .await
        .unwrap();
    let completion = finish(&runtime, &target, &supervisor, true).await;
    assert_eq!(completion.run.state, RunState::Verifying);
}

#[path = "../../router-execution-decision/tests/support/assets.rs"]
mod asset_fixture;
impl Fixture {
    fn enable_semantic_assets(&mut self) {
        let mut route = self.context.request().clone();
        for c in &mut route.candidates {
            c.estimated_tokens = 800;
        }
        route.task.budget.max_tokens = 10_000;
        self.plan = build_plan(
            &route.task,
            WorkflowPreset::DirectSafe,
            PlanLimits {
                reserve_elapsed_ms: 1000,
                ..PlanLimits::default()
            },
        )
        .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let snapshot = fixture_proofs::from_observation(
            self.context.snapshot().clone(),
            SnapshotValidation {
                now_unix_seconds: now,
                max_age_seconds: 300,
            },
        )
        .unwrap();
        let catalog = Catalog::from_json(include_bytes!(
            "../../../fixtures/examples/phase-catalog.json"
        ))
        .unwrap();
        let inputs = asset_fixture::inputs(
            &route,
            &snapshot,
            &catalog,
            router_policy::PhaseExecutionScope {
                workspace: self.request.workspace.clone(),
                source_state: self.request.source_state.clone(),
                scope: self.request.scope.clone(),
            },
            &BTreeMap::new(),
            512,
        );
        self.context = self
            .router
            .context_with_assets(route, &snapshot, &catalog, inputs, now)
            .unwrap();
        self.request.receipt_id = self.router.route(&self.context).unwrap().receipt_id;
    }
}

#[tokio::test]
#[ignore = "requires built native helper and OS sandbox"]
async fn native_discarded_writing_generations_never_become_readonly_failure_evidence() {
    let fixture = Fixture::new(true).await;
    let supervisor = native_supervisor(&fixture).await;
    let runtime = fixture.runtime();
    let execution = contract(&fixture, "writing");
    let first = review_generation(&fixture, &runtime, "write-first", &execution, 0).await;
    finish(&runtime, &first, &supervisor, false).await;
    runtime
        .discard(&first, first.approval_digest())
        .await
        .unwrap();
    let second = review_generation(&fixture, &runtime, "write-second", &execution, 1).await;
    finish(&runtime, &second, &supervisor, false).await;
    runtime
        .discard(&second, second.approval_digest())
        .await
        .unwrap();
    assert!(runtime.summary("write-first").unwrap().worktree.is_none());
    assert!(runtime.summary("write-second").unwrap().worktree.is_none());
    account(&runtime, &second, 1);
    let attempts = runtime.attempt_evidence("write-second").unwrap();
    assert_eq!(attempts.len(), 2);
    assert!(
        attempts
            .iter()
            .all(|a| a.sandbox == ExecutionSandbox::WorkspaceWrite)
    );
    assert!(matches!(
        runtime.review_escalation(&second, &policy()),
        Err(EscalationError::Evidence)
    ));
}
