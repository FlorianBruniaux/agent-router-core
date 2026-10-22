//! Fake native streams emitted by real local processes; no provider evidence.
#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use router_adapter_api::{
    AdapterError, HarnessAdapter, HostObservation, SnapshotValidation, ValidatedExecutionRequest,
    prepared_run,
};
use router_catalog::Catalog;
use router_policy::{PhaseRouter, ValidatedPhaseContext};
use router_runtime::*;
use router_types::*;
use router_workflow::{PlanLimits, build_plan};
use std::{
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
        request.task.budget.max_elapsed_ms = 10_000;
        if !write {
            request
                .task
                .allowed_mutations
                .remove(&Mutation::WorkspaceWrite);
        }
        request.candidates.truncate(1);
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
            timeout_ms: 500,
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
                max_attempts: 2,
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
        let review_started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
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
            .unwrap_or_else(|error| {
                eprintln!("original runtime review error: {error:?}");
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let snapshot = fixture_proofs::from_observation(
                    self.context.snapshot().clone(),
                    SnapshotValidation { now_unix_seconds: now, max_age_seconds: 300 },
                );
                let receipt = self.router.route(&self.context).unwrap();
                let receipt_error = self.router.validate_receipt(&self.context, &receipt).err();
                let selection = receipt.selected.as_ref().unwrap();
                let candidate = &selection.candidate;
                let node = self.plan.nodes.iter().find(|node| node.id == "execute").unwrap();
                let binding = [
                    ("task", self.context.request().task == self.plan.task),
                    ("receipt", self.request.receipt_id == receipt.receipt_id),
                    ("candidate", self.request.candidate_id == candidate.id),
                    ("phase", self.request.phase == receipt.phase),
                    ("model", self.request.model == candidate.model),
                    ("effort", self.request.effort == candidate.effort),
                    ("agent", self.request.agent == candidate.agent),
                    ("scope", self.request.scope == node.scope),
                    ("capabilities", self.request.required_capabilities == self.router.execution_capabilities(&self.context, selection).unwrap()),
                    ("timeout", self.request.timeout_ms <= node.budget.max_elapsed_ms),
                    ("cost", candidate.estimated_cost_microusd <= node.budget.max_cost_microusd),
                    ("tokens", candidate.estimated_tokens <= node.budget.max_tokens),
                    ("elapsed", candidate.estimated_elapsed_ms <= node.budget.max_elapsed_ms),
                ];
                let mismatches: Vec<_> = binding.iter().filter_map(|(field, valid)| (!valid).then_some(field)).collect();
                let permissions_error = snapshot.as_ref().ok().and_then(|snapshot| {
                    let mut request = self.request.clone();
                    request.mode = ExecutionMode::DryRun;
                    router_adapter_api::authorize_execution(request, snapshot, &self.context.request().restrictions, None).err()
                });
                panic!("review failed: {error:?}; started={review_started}; now={now}; observed={}; snapshot={:?}; receipt={receipt_error:?}; mismatches={mismatches:?}; permissions={permissions_error:?}", self.context.snapshot().observed_at_unix_seconds, snapshot.err());
            })
    }
}

#[path = "../../router-adapter-api/tests/support/native_failures.rs"]
mod streams;

struct NativeFixtureAdapter {
    script: String,
    protocol: router_adapter_api::NativeFailureProtocol,
    classifications: std::sync::atomic::AtomicUsize,
}
impl NativeFixtureAdapter {
    fn new(
        events: &[serde_json::Value],
        protocol: router_adapter_api::NativeFailureProtocol,
    ) -> Self {
        let output = String::from_utf8(streams::encode(events)).unwrap();
        Self {
            script: format!("printf '%s' '{}'; exit 1", output.replace('\'', "'\"'\"'")),
            protocol,
            classifications: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}
impl HarnessAdapter for NativeFixtureAdapter {
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
            vec!["-c".into(), self.script.clone()],
            vec![],
        )
    }
    fn classify_failure(
        &self,
        bytes: &[u8],
        outcome: TransportOutcome,
        max: usize,
    ) -> std::result::Result<Option<router_adapter_api::NativeFailureEvidence>, AdapterError> {
        self.classifications
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        router_adapter_api::classify_native_failure(bytes, outcome, max, self.protocol)
    }
    fn decode_stream(
        &self,
        _: &[u8],
        _: TransportOutcome,
        _: usize,
    ) -> std::result::Result<RuntimeEvidence, AdapterError> {
        Err(AdapterError::Unsupported("synthetic-classification-test"))
    }
}
// Test-only code permits local fixture processes. These tests establish durable
// runtime policy and observation precedence, not native OS sandbox enforcement.
struct FixtureSupervisor;
impl SandboxSupervisor for FixtureSupervisor {
    fn resource_limits_enforced(&self) -> bool {
        true
    }
    fn command(&self, run: &PreparedRun, _: &SandboxPolicy) -> Result<tokio::process::Command> {
        let mut command = tokio::process::Command::new(&run.program);
        command
            .args(&run.argv)
            .current_dir(&run.cwd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        Ok(command)
    }
}

#[tokio::test]
async fn native_auth_blocks_retry_while_rate_and_network_require_fresh_bounded_approval() {
    use router_adapter_api::NativeFailureProtocol as P;
    use serde_json::json;
    for (events, protocol, expected, retryable) in [
        (
            vec![
                streams::claude_error("authentication_failed"),
                streams::claude_result(),
            ],
            P::Claude,
            RunFailure::Authentication,
            false,
        ),
        (
            vec![streams::opencode_rate()],
            P::OpenCode,
            RunFailure::RateLimit,
            true,
        ),
        (
            vec![streams::opencode_error(
                "APIError",
                json!({"message":"PRIVATE","isRetryable":true,"metadata":{"code":"ECONNRESET"}}),
            )],
            P::OpenCode,
            RunFailure::Network,
            true,
        ),
    ] {
        let fixture = Fixture::new(false).await;
        let runtime = fixture.runtime();
        let pending = fixture.review(&runtime).await;
        let old_digest = pending.approval_digest().to_owned();
        let adapter = NativeFixtureAdapter::new(&events, protocol);
        let approved = runtime.approve(pending.clone(), &old_digest).unwrap();
        let completion = runtime
            .execute(
                approved,
                &adapter,
                &FixtureSupervisor,
                Cancellation::default(),
            )
            .await
            .unwrap();
        assert_eq!(completion.run.state, RunState::Failed);
        assert_eq!(completion.run.failure, Some(expected));
        assert_eq!(completion.validation, VerificationOutcome::Unknown);
        assert_eq!(completion.objective, VerificationOutcome::Unknown);
        let audit = serde_json::to_string(&runtime.events().unwrap()).unwrap();
        assert!(audit.contains("failure.native_classified"));
        assert!(audit.contains(&completion.stdout_sha256));
        assert!(!audit.contains("PRIVATE"));
        if retryable {
            let next = runtime.retry(pending).unwrap();
            assert_ne!(next.approval_digest(), old_digest);
            assert!(runtime.approve(next.clone(), &old_digest).is_err());
            let approved = runtime
                .approve(next.clone(), next.approval_digest())
                .unwrap();
            let completion = runtime
                .execute(
                    approved,
                    &adapter,
                    &FixtureSupervisor,
                    Cancellation::default(),
                )
                .await
                .unwrap();
            assert_eq!(completion.run.attempts, 2);
            assert_eq!(completion.run.failure, Some(expected));
            assert!(runtime.retry(next).is_err());
        } else {
            assert!(runtime.retry(pending).is_err());
        }
        runtime.verify_integrity().unwrap();
    }
}

#[tokio::test]
async fn untyped_stderr_and_malformed_native_output_keep_generic_crash() {
    use router_adapter_api::NativeFailureProtocol as P;
    for script in [
        "printf 'authentication rate_limit ECONNRESET' >&2; exit 1".to_owned(),
        "printf '{\"type\":'; exit 1".to_owned(),
    ] {
        let fixture = Fixture::new(false).await;
        let runtime = fixture.runtime();
        let pending = fixture.review(&runtime).await;
        let approved = runtime
            .approve(pending.clone(), pending.approval_digest())
            .unwrap();
        let mut adapter = NativeFixtureAdapter::new(&[], P::Claude);
        adapter.script = script;
        let completion = runtime
            .execute(
                approved,
                &adapter,
                &FixtureSupervisor,
                Cancellation::default(),
            )
            .await
            .unwrap();
        assert_eq!(completion.run.failure, Some(RunFailure::Crash));
        assert!(
            !runtime
                .events()
                .unwrap()
                .iter()
                .any(|e| e.kind == "failure.native_classified")
        );
    }
}

#[tokio::test]
async fn supervisor_timeout_limits_and_signals_take_precedence_over_native_claims() {
    use router_adapter_api::NativeFailureProtocol as P;
    for (tail, expected) in [
        ("sleep 30", RunFailure::Timeout),
        (
            "while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done",
            RunFailure::OutputLimit,
        ),
        ("kill -KILL $$", RunFailure::Crash),
    ] {
        let mut fixture = Fixture::new(false).await;
        fixture.request.timeout_ms = 150;
        fixture.request.max_output_bytes = 1024;
        let runtime = fixture.runtime();
        let pending = fixture.review(&runtime).await;
        let approved = runtime
            .approve(pending.clone(), pending.approval_digest())
            .unwrap();
        let mut adapter = NativeFixtureAdapter::new(&[streams::opencode_rate()], P::OpenCode);
        adapter.script = adapter.script.replace("exit 1", tail);
        let completion = runtime
            .execute(
                approved,
                &adapter,
                &FixtureSupervisor,
                Cancellation::default(),
            )
            .await
            .unwrap();
        assert_eq!(completion.run.failure, Some(expected));
        assert_eq!(
            adapter
                .classifications
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert!(
            !runtime
                .events()
                .unwrap()
                .iter()
                .any(|e| e.kind == "failure.native_classified")
        );
    }
}

#[tokio::test]
async fn successful_transport_never_becomes_a_retryable_native_failure() {
    let fixture = Fixture::new(false).await;
    let runtime = fixture.runtime();
    let pending = fixture.review(&runtime).await;
    let approved = runtime
        .approve(pending.clone(), pending.approval_digest())
        .unwrap();
    let mut adapter = NativeFixtureAdapter::new(
        &[streams::opencode_rate()],
        router_adapter_api::NativeFailureProtocol::OpenCode,
    );
    adapter.script = adapter.script.replace("exit 1", "exit 0");
    let completion = runtime
        .execute(
            approved,
            &adapter,
            &FixtureSupervisor,
            Cancellation::default(),
        )
        .await
        .unwrap();
    assert_eq!(completion.run.state, RunState::Verifying);
    assert_eq!(completion.run.failure, None);
    assert_eq!(completion.objective, VerificationOutcome::Unknown);
    assert_eq!(
        adapter
            .classifications
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert!(runtime.retry(pending).is_err());
}
