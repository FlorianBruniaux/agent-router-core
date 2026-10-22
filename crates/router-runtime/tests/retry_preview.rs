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
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[allow(dead_code)]
struct Fixture {
    temp: tempfile::TempDir,
    root: PathBuf,
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
            root,
            router,
            context,
            request,
            plan,
        }
    }
    fn runtime(&self) -> Runtime {
        Runtime::open(&self.temp.path().join("runtime"), RuntimeLimits::default())
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
struct FakeAdapter(&'static str);
impl HarnessAdapter for FakeAdapter {
    fn host(&self) -> &'static str {
        "codex"
    }
    fn prepare(
        &self,
        request: &ValidatedExecutionRequest,
    ) -> std::result::Result<PreparedRun, AdapterError> {
        prepared_run(request, "/bin/sh", vec!["-c".into(), self.0.into()], vec![])
    }
    fn decode_stream(
        &self,
        _: &[u8],
        _: TransportOutcome,
        _: usize,
    ) -> std::result::Result<RuntimeEvidence, AdapterError> {
        Err(AdapterError::Protocol)
    }
}
// Deliberately test-only trusted code, never a production sandbox claim.
struct FakeSupervisor;
impl SandboxSupervisor for FakeSupervisor {
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

async fn timed_out(fixture: &Fixture, runtime: &Runtime) -> PendingRun {
    let pending = fixture.review(runtime).await;
    let approved = runtime
        .approve(pending.clone(), pending.approval_digest())
        .unwrap();
    let out = runtime
        .execute(
            approved,
            &FakeAdapter("sleep 30"),
            &FakeSupervisor,
            Cancellation::default(),
        )
        .await
        .unwrap();
    assert_eq!(out.run.state, RunState::TimedOut);
    pending
}

#[tokio::test]
async fn preview_retry_persists_nothing_and_predicts_the_real_retry_digest() {
    let mut fixture = Fixture::new(false).await;
    fixture.request.timeout_ms = 80;
    let runtime = fixture.runtime();
    let pending = timed_out(&fixture, &runtime).await;
    let database = fixture.temp.path().join("runtime/runtime.sqlite3");
    let events = serde_json::to_string(&runtime.events().unwrap()).unwrap();
    let summary = runtime.summary("run-1").unwrap();
    let file = fs::read(&database).unwrap();

    let preview = runtime.preview_retry(&pending).unwrap();
    assert_eq!(preview.summary().state, RunState::AwaitingApproval);
    assert_ne!(preview.approval_digest(), summary.approval_digest);
    assert_eq!(runtime.summary("run-1").unwrap(), summary);
    assert_eq!(runtime.summary("run-1").unwrap().state, RunState::TimedOut);
    assert_eq!(
        serde_json::to_string(&runtime.events().unwrap()).unwrap(),
        events
    );
    assert_eq!(fs::read(&database).unwrap(), file);

    let real = runtime.retry(pending).unwrap();
    assert_eq!(real.approval_digest(), preview.approval_digest());
    assert_eq!(real.summary(), preview.summary());
}

#[tokio::test]
async fn preview_retry_applies_the_same_guards_as_retry() {
    let fixture = Fixture::new(false).await;
    let runtime = fixture.runtime();
    let pending = fixture.review(&runtime).await;
    // A run that never failed is not retryable, so nothing can be previewed.
    assert!(matches!(
        runtime.preview_retry(&pending),
        Err(RuntimeError::Invalid(
            "retry requires a bounded read-only attempt"
        ))
    ));
    assert!(matches!(
        runtime.retry(pending),
        Err(RuntimeError::Invalid(
            "retry requires a bounded read-only attempt"
        ))
    ));
}

#[tokio::test]
async fn retry_approved_refuses_and_persists_nothing_when_the_run_changed_since_the_preview() {
    let mut fixture = Fixture::new(false).await;
    fixture.request.timeout_ms = 80;
    let runtime = fixture.runtime();
    let pending = timed_out(&fixture, &runtime).await;
    let preview = runtime.preview_retry(&pending).unwrap();
    let expected = preview.approval_digest().to_owned();

    // Another process changes the attempt count between preview and approval.
    let database = fixture.temp.path().join("runtime/runtime.sqlite3");
    rusqlite::Connection::open(&database)
        .unwrap()
        .execute(
            "UPDATE runs SET summary=json_set(summary,'$.attempts',0)",
            [],
        )
        .unwrap();
    let events = serde_json::to_string(&runtime.events().unwrap()).unwrap();
    let summary = runtime.summary("run-1").unwrap();

    assert!(matches!(
        runtime.retry_approved(pending.clone(), &expected),
        Err(RuntimeError::Approval)
    ));
    assert_eq!(runtime.summary("run-1").unwrap(), summary);
    assert_eq!(runtime.summary("run-1").unwrap().state, RunState::TimedOut);
    assert_eq!(
        serde_json::to_string(&runtime.events().unwrap()).unwrap(),
        events
    );
    let current = runtime.preview_retry(&pending).unwrap();
    assert!(
        runtime
            .retry_approved(pending, current.approval_digest())
            .is_ok()
    );
}
