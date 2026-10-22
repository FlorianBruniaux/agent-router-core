#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use router_adapter_api::{
    AdapterError, HarnessAdapter, HostObservation, SnapshotValidation, StreamDialect,
    ValidatedExecutionRequest, ValidatedHostObservation, decode_transport, prepared_run,
};
use router_catalog::Catalog;
use router_coordinator::*;
use router_policy::{PhaseRouter, ValidatedPhaseContext};
use router_runtime::{Runtime, RuntimeLimits, SandboxPolicy, SandboxSupervisor};
use router_types::*;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct Fixture {
    temp: tempfile::TempDir,
    root: PathBuf,
    router: PhaseRouter,
    snapshot: ValidatedHostObservation,
    catalog: Catalog,
    request: PhaseRouteRequest,
    definition: WorkflowDefinition,
}
impl Fixture {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap().join("repo");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("src")).unwrap();
        fs::write(root.join("src/base.txt"), "base\n").unwrap();
        for args in [
            vec!["init", "-q"],
            vec!["add", "src"],
            vec![
                "-c",
                "user.name=Coordinator Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "-q",
                "--no-gpg-sign",
                "-m",
                "base",
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
        request.task.budget.max_elapsed_ms = 30_000;
        request.task.budget.max_tokens = 10_000;
        request.restrictions.max_tokens = Some(10_000);
        request.restrictions = router_workflow::merge_restrictions(&[RestrictionLayer {
            name: "fixture".into(),
            allowed_models: None,
            allowed_capabilities: request.restrictions.allowed_capabilities.clone(),
            allowed_mutations: request.restrictions.allowed_mutations.clone(),
            max_cost_microusd: Some(10_000),
            max_tokens: Some(10_000),
            max_concurrency: Some(2),
            preferred_model: None,
        }])
        .unwrap();
        let plan = router_workflow::build_plan(
            &request.task,
            WorkflowPreset::PlanExecuteVerify,
            router_workflow::PlanLimits::default(),
        )
        .unwrap();
        let execution = router_workflow::seal_execution_contract(
            WorkflowExecutionContract {
                schema_version: 1,
                instance_id: "fixture-workflow".into(),
                plan_id: plan.plan_id.clone(),
                workspace: root.to_str().unwrap().into(),
                source_state: router_runtime::source_state(&root).await.unwrap(),
                nodes: plan
                    .nodes
                    .iter()
                    .map(|n| {
                        (
                            n.id.clone(),
                            NodeExecutionContract {
                                phase: phase(&n.id),
                                dependencies: n
                                    .dependencies
                                    .iter()
                                    .map(|d| {
                                        (
                                            d.clone(),
                                            if n.id == "verify" {
                                                DependencyRequirement::ArtifactReadyForVerification
                                            } else {
                                                DependencyRequirement::Verified
                                            },
                                        )
                                    })
                                    .collect(),
                            },
                        )
                    })
                    .collect(),
                contract_sha256: String::new(),
            },
            &plan,
        )
        .unwrap();
        let artifacts = plan
            .nodes
            .iter()
            .map(|n| {
                (
                    n.id.clone(),
                    NodeArtifactDeclaration {
                        outputs: vec![OutputDeclaration {
                            label: n.outputs[0].clone(),
                            source: if n.id == "execute" {
                                DeclaredOutputSource::Patch
                            } else {
                                DeclaredOutputSource::NativeFinalText
                            },
                            max_bytes: 8192,
                            retention_seconds: 3600,
                        }],
                        inputs: n
                            .dependencies
                            .iter()
                            .map(|d| ArtifactEdge {
                                producer: d.clone(),
                                label: format!("artifact:{d}"),
                                exposure: if n.id == "verify" {
                                    ArtifactExposure::ReadOnlyWorkspacePatch
                                } else {
                                    ArtifactExposure::PromptData
                                },
                            })
                            .collect(),
                    },
                )
            })
            .collect();
        let definition = seal_definition(WorkflowDefinition {
            schema_version: 1,
            plan,
            execution,
            artifacts,
            failure_policy: WorkflowFailurePolicy::ContinueIndependent,
            max_input_bytes: 32 * 1024,
            definition_sha256: String::new(),
        })
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
        Self {
            temp,
            root,
            router: PhaseRouter::stable_v2(),
            snapshot,
            catalog: Catalog::from_json(include_bytes!(
                "../../../fixtures/examples/phase-catalog.json"
            ))
            .unwrap(),
            request,
            definition,
        }
    }
    fn runtime(&self) -> Arc<Runtime> {
        Arc::new(
            Runtime::open(&self.temp.path().join("runtime"), RuntimeLimits::default())
                .map(|runtime| {
                    runtime.with_capability_proof_verifier(std::sync::Arc::new(
                        fixture_proofs::FixtureVerifier,
                    ))
                })
                .unwrap(),
        )
    }
    fn coordinator(&self, runtime: Arc<Runtime>) -> Coordinator {
        Coordinator::open(&self.temp.path().join("coordinator"), runtime).unwrap()
    }
    fn material(&self, node: &str) -> (ValidatedPhaseContext, ExecutionRequest) {
        let mut route = self.request.clone();
        route.phase = self.definition.execution.nodes[node].phase;
        route.candidates.truncate(1);
        route.candidates[0].sandbox = if node == "execute" {
            PhaseSandbox::WorkspaceWrite
        } else {
            PhaseSandbox::ReadOnly
        };
        if node == "verify" {
            route.previous_model = Some(ModelId::parse("fixture-best").unwrap());
            route.candidates[0].model = ModelId::parse("fixture-second").unwrap();
            route.candidates[0].verification = PhaseVerification::Independent;
        }
        let context = self
            .router
            .context(route, &self.snapshot, &self.catalog)
            .unwrap();
        let receipt = self.router.route(&context).unwrap();
        let selected = receipt.selected.as_ref().unwrap();
        let request = ExecutionRequest {
            schema_version: 1,
            receipt_id: receipt.receipt_id.clone(),
            candidate_id: selected.candidate.id.clone(),
            phase: receipt.phase,
            host: self.snapshot.host().harness.clone(),
            model: selected.candidate.model.clone(),
            effort: selected.candidate.effort,
            workspace: self.root.to_str().unwrap().into(),
            source_state: self.definition.execution.source_state.clone(),
            scope: vec!["src".into()],
            sandbox: if node == "execute" {
                ExecutionSandbox::WorkspaceWrite
            } else {
                ExecutionSandbox::ReadOnly
            },
            required_capabilities: self
                .router
                .execution_capabilities(&context, selected)
                .unwrap(),
            tools: ToolSelection::Disabled,
            agent: None,
            skills: vec![],
            prompt: format!("private prompt for {node}"),
            mode: ExecutionMode::Execute,
            target: ExecutionTarget::ExternalWorker,
            allow_degradation: false,
            timeout_ms: 3000,
            max_output_bytes: 32 * 1024,
        };
        (context, request)
    }
    async fn review(&self, coordinator: &Coordinator, node: &str) -> PendingStep {
        let (context, request) = self.material(node);
        let proof = self
            .router
            .validate_receipt(&context, &self.router.route(&context).unwrap())
            .unwrap();
        coordinator
            .review_step(
                &self.definition,
                node,
                0,
                &self.router,
                &context,
                &proof,
                request,
            )
            .await
            .unwrap()
    }
}
fn phase(node: &str) -> StageKind {
    match node {
        "plan" => StageKind::Plan,
        "execute" => StageKind::Execute,
        _ => StageKind::Verify,
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
        bytes: &[u8],
        outcome: TransportOutcome,
        max: usize,
    ) -> std::result::Result<RuntimeEvidence, AdapterError> {
        decode_transport(bytes, outcome, max, StreamDialect::Codex)
    }
}
struct FakeSupervisor;
impl SandboxSupervisor for FakeSupervisor {
    fn resource_limits_enforced(&self) -> bool {
        true
    }
    fn command(
        &self,
        run: &PreparedRun,
        _: &SandboxPolicy,
    ) -> router_runtime::Result<tokio::process::Command> {
        let mut command = tokio::process::Command::new(&run.program);
        command
            .args(&run.argv)
            .current_dir(&run.cwd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        Ok(command)
    }
}
const PLAN: &str = "printf '%s\\n' '{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"Proposal: change src/base.txt; validate changed content.\"}}' '{\"type\":\"turn.completed\"}'";
const EXECUTE: &str =
    "printf 'changed\\n' > src/base.txt; printf '%s\\n' '{\"type\":\"turn.completed\"}'";
const VERIFY: &str = "IFS= read -r value < src/base.txt; test \"$value\" = changed || exit 9; printf '%s\\n' '{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"Independent patch view inspected.\"}}' '{\"type\":\"turn.completed\"}'";
fn record(runtime: &Runtime, step: &PendingStep) -> VerificationRecord {
    VerificationRecord {
        verifier: "explicit-parent".into(),
        evidence_sha256: "a".repeat(64),
        artifact_sha256: runtime
            .summary(&step.summary().run_id)
            .unwrap()
            .artifact_sha256,
        validation: VerificationOutcome::Passed,
        objective: VerificationOutcome::Passed,
    }
}
async fn run(
    coordinator: &Coordinator,
    definition: &WorkflowDefinition,
    step: &PendingStep,
    script: &'static str,
    supervisor: &dyn SandboxSupervisor,
) -> RunCompletion {
    let approved = coordinator
        .approve_step(definition, step.clone(), step.approval_digest())
        .unwrap();
    coordinator
        .run_ready(
            definition,
            vec![StepExecution {
                step: approved,
                adapter: &FakeAdapter(script),
                supervisor,
            }],
        )
        .await
        .unwrap()
        .completions
        .remove(0)
}

async fn pipeline(
    f: &Fixture,
    runtime: Arc<Runtime>,
    coordinator: &Coordinator,
    supervisor: &dyn SandboxSupervisor,
) {
    coordinator.register(&f.definition).unwrap();
    assert!(matches!(
        coordinator.inputs(&f.definition, "execute"),
        Err(CoordinatorError::DependenciesPending)
    ));
    let planner = f.review(coordinator, "plan").await;
    let outcome = run(coordinator, &f.definition, &planner, PLAN, supervisor).await;
    assert_eq!(outcome.run.state, RunState::Verifying);
    assert_eq!(outcome.objective, VerificationOutcome::Unknown);
    assert!(matches!(
        coordinator.inputs(&f.definition, "execute"),
        Err(CoordinatorError::DependenciesPending)
    ));
    let output = runtime
        .declared_artifacts(&planner.summary().run_id)
        .unwrap()
        .remove(0);
    assert_eq!(
        runtime.read_declared_artifact(&output.artifact_id).unwrap(),
        b"Proposal: change src/base.txt; validate changed content."
    );
    assert!(!runtime.storage_root().join("outputs").exists());
    coordinator
        .verify_step(&f.definition, &planner, record(&runtime, &planner))
        .unwrap();
    let executor = f.review(coordinator, "execute").await;
    assert!(executor.final_request().prompt.contains("untrusted_data"));
    assert!(
        executor
            .final_request()
            .prompt
            .contains("Proposal: change src/base.txt")
    );
    run(coordinator, &f.definition, &executor, EXECUTE, supervisor).await;
    let verifier = f.review(coordinator, "verify").await;
    let outcome = run(coordinator, &f.definition, &verifier, VERIFY, supervisor).await;
    assert_eq!(
        runtime.summary(&executor.summary().run_id).unwrap().state,
        RunState::Verifying
    );
    assert_ne!(
        outcome.run.worktree,
        runtime
            .summary(&executor.summary().run_id)
            .unwrap()
            .worktree
    );
    assert_eq!(
        fs::read_to_string(f.root.join("src/base.txt")).unwrap(),
        "base\n"
    );
    coordinator
        .verify_step(&f.definition, &verifier, record(&runtime, &verifier))
        .unwrap();
    coordinator
        .verify_step(&f.definition, &executor, record(&runtime, &executor))
        .unwrap();
    assert!(coordinator.status(&f.definition).unwrap().all_verified);
    let preview = coordinator.integration_preview(&executor).await.unwrap();
    assert!(coordinator.apply(&executor, "wrong").await.is_err());
    coordinator
        .apply(&executor, &preview.approval_digest)
        .await
        .unwrap();
    assert_eq!(
        fs::read_to_string(f.root.join("src/base.txt")).unwrap(),
        "changed\n"
    );
    assert!(
        !serde_json::to_string(&runtime.events().unwrap())
            .unwrap()
            .contains("Proposal:")
    );
}
#[tokio::test]
async fn plan_requires_parent_approval_and_verifier_gets_the_immutable_patch_view() {
    let f = Fixture::new().await;
    let runtime = f.runtime();
    let coordinator = f.coordinator(runtime.clone());
    pipeline(&f, runtime, &coordinator, &FakeSupervisor).await;
}

#[tokio::test]
async fn durable_reopen_preserves_verified_steps_and_rejects_changed_material() {
    let f = Fixture::new().await;
    let runtime = f.runtime();
    let coordinator = f.coordinator(runtime.clone());
    coordinator.register(&f.definition).unwrap();
    let planner = f.review(&coordinator, "plan").await;
    run(&coordinator, &f.definition, &planner, PLAN, &FakeSupervisor).await;
    let final_request = planner.final_request().clone();
    let artifacts = planner.artifact_contract().clone();
    let id = planner.summary().run_id.clone();
    let approval = planner.approval_digest().to_owned();
    request_verification(
        &f.temp.path().join("coordinator"),
        &f.definition.execution.instance_id,
        "plan",
        0,
        &approval,
        record(&runtime, &planner),
    )
    .unwrap();
    drop(planner);
    drop(coordinator);
    drop(runtime);
    let runtime = f.runtime();
    let coordinator = f.coordinator(runtime.clone());
    coordinator.register(&f.definition).unwrap();
    assert_eq!(coordinator.service_controls(&f.definition).unwrap(), 0);
    let (context, _) = f.material("plan");
    let proof = f
        .router
        .validate_receipt(&context, &f.router.route(&context).unwrap())
        .unwrap();
    let before = runtime.summary(&id).unwrap();
    for mutation in ["prompt", "source", "scope", "artifact contract"] {
        let mut changed = final_request.clone();
        let mut changed_artifacts = artifacts.clone();
        match mutation {
            "prompt" => changed.prompt.push_str("modified"),
            "source" => changed.source_state = "different-revision".into(),
            "scope" => changed.scope.push("src/unapproved.rs".into()),
            _ => changed_artifacts.max_input_bytes -= 1,
        }
        assert!(
            coordinator
                .reopen_step(
                    &f.definition,
                    "plan",
                    0,
                    &f.router,
                    &context,
                    &proof,
                    changed,
                    changed_artifacts,
                )
                .is_err(),
            "resumed with changed {mutation}"
        );
        let after = runtime.summary(&id).unwrap();
        assert_eq!(after.state, before.state, "changed {mutation}");
        assert_eq!(after.attempts, before.attempts, "changed {mutation}");
        assert_eq!(coordinator.service_controls(&f.definition).unwrap(), 0);
    }
    let reopened = coordinator
        .reopen_step(
            &f.definition,
            "plan",
            0,
            &f.router,
            &context,
            &proof,
            final_request,
            artifacts,
        )
        .unwrap();
    assert_eq!(coordinator.service_controls(&f.definition).unwrap(), 1);
    assert_eq!(runtime.summary(&id).unwrap().state, RunState::Verified);
    assert!(
        coordinator
            .approve_step(&f.definition, reopened, &approval)
            .is_err()
    );
    assert_eq!(runtime.summary(&id).unwrap().attempts, 1);
}

#[tokio::test]
async fn live_owner_accepts_durable_approval_and_cancellation_without_reopening_runtime() {
    let f = Fixture::new().await;
    let runtime = f.runtime();
    let coordinator = f.coordinator(runtime.clone());
    coordinator.register(&f.definition).unwrap();
    let pending = f.review(&coordinator, "plan").await;
    assert!(Coordinator::open(&f.temp.path().join("coordinator"), runtime.clone()).is_err());
    assert!(
        request_approval(
            &f.temp.path().join("coordinator"),
            &f.definition.execution.instance_id,
            "plan",
            0,
            "wrong"
        )
        .is_err()
    );
    request_approval(
        &f.temp.path().join("coordinator"),
        &f.definition.execution.instance_id,
        "plan",
        0,
        pending.approval_digest(),
    )
    .unwrap();
    assert_eq!(coordinator.service_controls(&f.definition).unwrap(), 1);
    assert_eq!(
        runtime.summary(&pending.summary().run_id).unwrap().state,
        RunState::Queued
    );
    request_cancel(
        &f.temp.path().join("coordinator"),
        &f.definition.execution.instance_id,
    )
    .unwrap();
    assert_eq!(
        runtime.summary(&pending.summary().run_id).unwrap().state,
        RunState::Cancelled
    );
    assert!(
        observe(&f.temp.path().join("coordinator"), &f.definition)
            .unwrap()
            .cancelled
    );
}

fn parallel_definition(f: &mut Fixture) {
    use sha2::Digest;
    let mut plan = f.definition.plan.clone();
    let base = plan.nodes[0].clone();
    plan.nodes = ["first", "second"]
        .into_iter()
        .map(|id| {
            let mut node = base.clone();
            node.id = id.into();
            node.owner = format!("owner-{id}");
            node.outputs = vec![format!("artifact:{id}")];
            node
        })
        .collect();
    plan.preset = WorkflowPreset::DirectSafe;
    plan.max_width = 2;
    plan.plan_id.clear();
    plan.plan_id = hex::encode(sha2::Sha256::digest(serde_json::to_vec(&plan).unwrap()));
    let mut execution = f.definition.execution.clone();
    execution.plan_id = plan.plan_id.clone();
    execution.nodes = plan
        .nodes
        .iter()
        .map(|n| {
            (
                n.id.clone(),
                NodeExecutionContract {
                    phase: StageKind::Plan,
                    dependencies: BTreeMap::new(),
                },
            )
        })
        .collect();
    execution = router_workflow::seal_execution_contract(execution, &plan).unwrap();
    let outputs = f.definition.artifacts["plan"].outputs[0].clone();
    let artifacts = plan
        .nodes
        .iter()
        .map(|node| {
            let mut output = outputs.clone();
            output.label = node.outputs[0].clone();
            (
                node.id.clone(),
                NodeArtifactDeclaration {
                    outputs: vec![output],
                    inputs: vec![],
                },
            )
        })
        .collect();
    f.definition = seal_definition(WorkflowDefinition {
        plan,
        execution,
        artifacts,
        definition_sha256: String::new(),
        ..f.definition.clone()
    })
    .unwrap();
}
#[tokio::test]
async fn partial_wave_keeps_successful_completion_and_typed_error() {
    let mut f = Fixture::new().await;
    parallel_definition(&mut f);
    let runtime = f.runtime();
    let c = f.coordinator(runtime.clone());
    c.register(&f.definition).unwrap();
    let first = f.review(&c, "first").await;
    let second = f.review(&c, "second").await;
    let wave = c
        .run_ready(
            &f.definition,
            vec![
                StepExecution {
                    step: c
                        .approve_step(&f.definition, first.clone(), first.approval_digest())
                        .unwrap(),
                    adapter: &FakeAdapter(PLAN),
                    supervisor: &router_runtime::DenySandbox,
                },
                StepExecution {
                    step: c
                        .approve_step(&f.definition, second.clone(), second.approval_digest())
                        .unwrap(),
                    adapter: &FakeAdapter(PLAN),
                    supervisor: &FakeSupervisor,
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(wave.errors.len(), 1);
    assert_eq!(wave.errors[0].run_id, first.summary().run_id);
    assert_eq!(
        wave.errors[0].code,
        StepExecutionErrorCode::PreparationDenied
    );
    assert_eq!(wave.completions.len(), 1);
    assert_eq!(wave.completions[0].run.run_id, second.summary().run_id);
    assert!(!wave.cancelled);
}
#[tokio::test]
async fn two_nodes_overlap_and_verification_controls_work_during_another_active_run() {
    let mut f = Fixture::new().await;
    parallel_definition(&mut f);
    let runtime = f.runtime();
    let c = f.coordinator(runtime.clone());
    c.register(&f.definition).unwrap();
    let first = f.review(&c, "first").await;
    let second = f.review(&c, "second").await;
    let jobs = vec![
        StepExecution {
            step: c
                .approve_step(&f.definition, first.clone(), first.approval_digest())
                .unwrap(),
            adapter: &FakeAdapter(PLAN),
            supervisor: &FakeSupervisor,
        },
        StepExecution {
            step: c
                .approve_step(&f.definition, second.clone(), second.approval_digest())
                .unwrap(),
            adapter: &FakeAdapter(
                "/bin/sleep 0.7; printf '%s\\n' '{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"Second result\"}}' '{\"type\":\"turn.completed\"}'",
            ),
            supervisor: &FakeSupervisor,
        },
    ];
    let (wave, ()) = tokio::join!(c.run_ready(&f.definition, jobs), async {
        for _ in 0..200 {
            if runtime.summary(&first.summary().run_id).unwrap().state == RunState::Verifying
                && runtime.summary(&second.summary().run_id).unwrap().state == RunState::Running
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            runtime.summary(&second.summary().run_id).unwrap().state,
            RunState::Running
        );
        request_verification(
            &f.temp.path().join("coordinator"),
            &f.definition.execution.instance_id,
            "first",
            0,
            first.approval_digest(),
            record(&runtime, &first),
        )
        .unwrap();
        for _ in 0..200 {
            if runtime.summary(&first.summary().run_id).unwrap().state == RunState::Verified {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            runtime.summary(&first.summary().run_id).unwrap().state,
            RunState::Verified
        );
        assert_eq!(
            runtime.summary(&second.summary().run_id).unwrap().state,
            RunState::Running
        );
    });
    let wave = wave.unwrap();
    assert_eq!(wave.completions.len(), 2);
    assert!(wave.errors.is_empty());
}

#[tokio::test]
async fn artifact_grants_reject_cross_instance_tampering_and_purge_symlinks() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let f = Fixture::new().await;
    let runtime = f.runtime();
    let c = f.coordinator(runtime.clone());
    c.register(&f.definition).unwrap();
    let planner = f.review(&c, "plan").await;
    run(&c, &f.definition, &planner, PLAN, &FakeSupervisor).await;
    c.verify_step(&f.definition, &planner, record(&runtime, &planner))
        .unwrap();
    let input = c.inputs(&f.definition, "execute").unwrap();
    let id = &input.inputs[0].artifact_id;
    let path = runtime
        .storage_root()
        .join("results")
        .join(format!("{id}.blob"));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let (context, mut request) = f.material("execute");
    request
        .prompt
        .push_str(&runtime.render_dependency_context(&input).unwrap());
    let proof = f
        .router
        .validate_receipt(&context, &f.router.route(&context).unwrap())
        .unwrap();
    let mut wrong = input.clone();
    wrong.inputs[0].workflow.instance_id = "different".into();
    assert!(
        runtime
            .review_with_artifacts(
                "wrong-grant",
                &f.router,
                &context,
                &proof,
                request.clone(),
                f.definition.plan.clone(),
                "execute",
                Some((&f.definition.execution, 0)),
                Some(&wrong)
            )
            .await
            .is_err()
    );
    fs::write(&path, b"tampered").unwrap();
    assert!(runtime.render_dependency_context(&input).is_err());
    fs::remove_file(&path).unwrap();
    let outside = f.temp.path().join("unowned");
    fs::write(&outside, "keep").unwrap();
    symlink(&outside, &path).unwrap();
    assert!(runtime.purge_declared_artifact(id).is_err());
    assert_eq!(fs::read_to_string(outside).unwrap(), "keep");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
#[ignore = "requires real Seatbelt or bubblewrap and built native resource helper"]
async fn native_sandbox_plan_execute_verify_handoff() {
    use router_runtime::{ResourceLimits, ResourceSupervisor};
    let f = Fixture::new().await;
    let runtime = f.runtime();
    let c = f.coordinator(runtime.clone());
    let root = fs::canonicalize(f.temp.path()).unwrap();
    let helper = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("router-sandbox-helper");
    let program = fs::canonicalize("/bin/sh").unwrap();
    #[cfg(target_os = "macos")]
    let wrapper = Path::new("/usr/bin/sandbox-exec");
    #[cfg(target_os = "linux")]
    let wrapper = Path::new("/usr/bin/bwrap");
    let hashes: BTreeMap<PathBuf, String> = [helper.as_path(), program.as_path(), wrapper]
        .into_iter()
        .map(|path| {
            (
                path.into(),
                router_adapter_api::content_digest(&fs::read(path).unwrap()),
            )
        })
        .collect();
    #[cfg(target_os = "macos")]
    let sandbox = router_runtime::SeatbeltSandbox::probe_expected(
        &root,
        BTreeMap::from([("/bin/sh".into(), program)]),
        vec![],
        BTreeMap::new(),
        &hashes,
    )
    .await
    .unwrap();
    #[cfg(target_os = "linux")]
    let sandbox = router_runtime::BubblewrapSandbox::probe_expected(
        &root,
        wrapper,
        BTreeMap::from([("/bin/sh".into(), program)]),
        vec![],
        BTreeMap::new(),
        &hashes,
    )
    .await
    .unwrap();
    let supervisor = ResourceSupervisor::probe_expected(
        &helper,
        ResourceLimits {
            address_space_bytes: if cfg!(target_os = "macos") {
                None
            } else {
                Some(256 * 1024 * 1024)
            },
            ..ResourceLimits::default()
        },
        sandbox,
        &hashes,
    )
    .await
    .unwrap();
    pipeline(&f, runtime, &c, &supervisor).await;
}

#[path = "../../router-policy/tests/support/asset_fixture.rs"]
mod asset_fixture;

#[tokio::test]
async fn expired_v3_asset_authority_is_rechecked_before_any_native_process() {
    use router_asset_contracts::{ValidatedAvailability, seal_availability};
    let f = Fixture::new().await;
    let runtime = f.runtime();
    let (legacy, mut request) = f.material("plan");
    let mut route = legacy.request().clone();
    route.candidates[0].estimated_tokens = 900;
    let old: HostObservation = serde_json::from_str(include_str!(
        "../../../fixtures/examples/phase-snapshot.json"
    ))
    .unwrap();
    let old_snapshot = fixture_proofs::from_observation(
        old,
        SnapshotValidation {
            now_unix_seconds: 100,
            max_age_seconds: 100,
        },
    )
    .unwrap();
    let mut inputs = asset_fixture::inputs(
        &route,
        &old_snapshot,
        &f.catalog,
        router_policy::PhaseExecutionScope {
            workspace: request.workspace.clone(),
            source_state: request.source_state.clone(),
            scope: request.scope.clone(),
        },
        &BTreeMap::new(),
        512,
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut availability = inputs.availability.document().clone();
    availability.snapshot_hash = f.snapshot.hash().into();
    availability.observed_at_unix_seconds = f.snapshot.observation().observed_at_unix_seconds;
    availability.expires_at_unix_seconds = now + 2;
    for evidence in &mut availability.evidence {
        evidence.observed_at_unix_seconds = availability.observed_at_unix_seconds;
    }
    let availability = seal_availability(availability, &f.snapshot).unwrap();
    inputs.availability = ValidatedAvailability::from_json(
        &serde_json::to_vec(&availability).unwrap(),
        &f.snapshot,
        &availability.content_hash,
        now,
    )
    .unwrap();
    let context = f
        .router
        .context_with_assets(route, &f.snapshot, &f.catalog, inputs, now)
        .unwrap();
    let receipt = f.router.route(&context).unwrap();
    request.receipt_id = receipt.receipt_id.clone();
    assert!(
        f.router
            .validate_execution_assets(&context, &request, request.prompt.as_bytes(), now)
            .unwrap()
            .is_some()
    );
    let pending = runtime
        .review(
            "stale-v3",
            &f.router,
            &context,
            request,
            f.definition.plan.clone(),
            "plan",
        )
        .await
        .unwrap();
    let approved = runtime
        .approve(pending.clone(), pending.approval_digest())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert!(matches!(
        runtime
            .execute(
                approved,
                &FakeAdapter("printf unexpected > src/unexpected.txt"),
                &FakeSupervisor,
                router_runtime::Cancellation::default()
            )
            .await,
        Err(router_runtime::RuntimeError::Route)
    ));
    assert_eq!(
        runtime.summary("stale-v3").unwrap().state,
        RunState::Blocked
    );
    assert!(!f.root.join("src/unexpected.txt").exists());
    assert!(
        !runtime
            .events()
            .unwrap()
            .iter()
            .any(|event| event.state == RunState::Running)
    );
}

#[tokio::test]
async fn fail_fast_reports_jobs_cancelled_before_they_start() {
    use sha2::Digest;
    let mut f = Fixture::new().await;
    parallel_definition(&mut f);
    let mut plan = f.definition.plan.clone();
    let mut children = Vec::new();
    for id in ["third", "fourth"] {
        let mut node = plan.nodes[0].clone();
        node.id = id.into();
        node.owner = format!("owner-{id}");
        node.dependencies = vec!["first".into()];
        node.inputs = vec!["artifact:first".into()];
        node.outputs = vec![format!("artifact:{id}")];
        children.push(node);
    }
    plan.nodes.extend(children);
    for node in &mut plan.nodes {
        node.budget.max_cost_microusd = 2000;
        node.budget.max_tokens = 2000;
        node.budget.max_elapsed_ms = 6000;
    }
    plan.plan_id.clear();
    plan.plan_id = hex::encode(sha2::Sha256::digest(serde_json::to_vec(&plan).unwrap()));
    let mut execution = f.definition.execution.clone();
    execution.plan_id = plan.plan_id.clone();
    execution.nodes = plan
        .nodes
        .iter()
        .map(|n| {
            (
                n.id.clone(),
                NodeExecutionContract {
                    phase: StageKind::Plan,
                    dependencies: n
                        .dependencies
                        .iter()
                        .map(|id| (id.clone(), DependencyRequirement::Verified))
                        .collect(),
                },
            )
        })
        .collect();
    execution = router_workflow::seal_execution_contract(execution, &plan).unwrap();
    let declaration = f.definition.artifacts["first"].outputs[0].clone();
    let artifacts = plan
        .nodes
        .iter()
        .map(|n| {
            let mut output = declaration.clone();
            output.label = n.outputs[0].clone();
            (
                n.id.clone(),
                NodeArtifactDeclaration {
                    outputs: vec![output],
                    inputs: n
                        .dependencies
                        .iter()
                        .map(|id| ArtifactEdge {
                            producer: id.clone(),
                            label: format!("artifact:{id}"),
                            exposure: ArtifactExposure::PromptData,
                        })
                        .collect(),
                },
            )
        })
        .collect();
    f.definition = seal_definition(WorkflowDefinition {
        plan,
        execution,
        artifacts,
        failure_policy: WorkflowFailurePolicy::FailFast,
        definition_sha256: String::new(),
        ..f.definition.clone()
    })
    .unwrap();
    let runtime = f.runtime();
    let c = f.coordinator(runtime.clone());
    c.register(&f.definition).unwrap();
    let first = f.review(&c, "first").await;
    run(&c, &f.definition, &first, PLAN, &FakeSupervisor).await;
    c.verify_step(&f.definition, &first, record(&runtime, &first))
        .unwrap();
    let second = f.review(&c, "second").await;
    let third = f.review(&c, "third").await;
    let fourth = f.review(&c, "fourth").await;
    let jobs = vec![
        StepExecution {
            step: c
                .approve_step(&f.definition, second.clone(), second.approval_digest())
                .unwrap(),
            adapter: &FakeAdapter(PLAN),
            supervisor: &router_runtime::DenySandbox,
        },
        StepExecution {
            step: c
                .approve_step(&f.definition, third.clone(), third.approval_digest())
                .unwrap(),
            adapter: &FakeAdapter("/bin/sleep 2"),
            supervisor: &FakeSupervisor,
        },
        StepExecution {
            step: c
                .approve_step(&f.definition, fourth.clone(), fourth.approval_digest())
                .unwrap(),
            adapter: &FakeAdapter(PLAN),
            supervisor: &FakeSupervisor,
        },
    ];
    let wave = c.run_ready(&f.definition, jobs).await.unwrap();
    assert!(wave.cancelled);
    assert_eq!(wave.completions.len() + wave.errors.len(), 3);
    assert!(
        wave.errors
            .iter()
            .any(|error| error.run_id == fourth.summary().run_id
                && error.code == StepExecutionErrorCode::Cancelled)
    );
    assert_eq!(
        runtime.summary(&fourth.summary().run_id).unwrap().attempts,
        0
    );
}

#[path = "../../router-execution-decision/tests/support/synthetic.rs"]
mod semantic_fixture;

#[tokio::test]
async fn semantic_step_binds_secondary_and_reopens_without_rerouting_baseline() {
    let f = Fixture::new().await;
    let (baseline_context, mut request) = f.material("plan");
    let mut route = baseline_context.request().clone();
    let mut secondary = route.candidates[0].clone();
    secondary.id = "secondary".into();
    secondary.model = ModelId::parse("fixture-second").unwrap();
    route.candidates.push(secondary);
    let context = f.router.context(route, &f.snapshot, &f.catalog).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let promotion = semantic_fixture::Fixture::new_at(now - 124);
    let authority =
        semantic_fixture::TestAuthority::new(promotion.active(), promotion.keys.authorities());
    let decision =
        semantic_fixture::decision(&promotion, &f.router, &context, &authority, now, now + 60);
    request.receipt_id = decision.authorization_id().into();
    request.candidate_id = decision.selection().candidate.id.clone();
    request.model = decision.selection().candidate.model.clone();
    request.effort = decision.selection().candidate.effort;
    let runtime = f.runtime();
    let coordinator = f.coordinator(runtime.clone());
    coordinator.register(&f.definition).unwrap();
    let pending = coordinator
        .review_step_decision(
            &f.definition,
            "plan",
            0,
            &f.router,
            &context,
            &decision,
            request,
        )
        .await
        .unwrap();
    assert_eq!(pending.decision().baseline(), decision.baseline());
    let approved = coordinator
        .approve_step(&f.definition, pending.clone(), pending.approval_digest())
        .unwrap();
    let completion = coordinator
        .run_ready_decisions(
            &f.definition,
            vec![DecisionStepExecution {
                execution: StepExecution {
                    step: approved,
                    adapter: &FakeAdapter(PLAN),
                    supervisor: &FakeSupervisor,
                },
                authority: Some(&authority),
            }],
        )
        .await
        .unwrap();
    assert!(completion.errors.is_empty());
    assert_eq!(completion.completions.len(), 1);
    assert_eq!(completion.completions[0].run.state, RunState::Verifying);
    let reopened = coordinator
        .reopen_step_decision(
            &f.definition,
            "plan",
            0,
            &f.router,
            &context,
            &decision,
            pending.final_request().clone(),
            pending.artifact_contract().clone(),
        )
        .unwrap();
    assert_eq!(reopened.approval_digest(), pending.approval_digest());
    assert_eq!(reopened.final_request().candidate_id, "secondary");
    assert_eq!(
        reopened
            .decision()
            .baseline()
            .selected
            .as_ref()
            .unwrap()
            .candidate
            .id,
        "primary"
    );
    assert!(
        !runtime
            .declared_artifacts(&pending.summary().run_id)
            .unwrap()
            .is_empty()
    );
}

fn control_states(f: &Fixture) -> Vec<String> {
    let db =
        rusqlite::Connection::open(f.temp.path().join("coordinator/coordinator.sqlite3")).unwrap();
    let mut query = db
        .prepare("SELECT state FROM controls ORDER BY rowid")
        .unwrap();
    query
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

#[tokio::test]
async fn rejected_control_can_be_requested_again() {
    let f = Fixture::new().await;
    let runtime = f.runtime();
    let coordinator = f.coordinator(runtime.clone());
    coordinator.register(&f.definition).unwrap();
    let pending = f.review(&coordinator, "plan").await;
    let root = f.temp.path().join("coordinator");
    let instance = &f.definition.execution.instance_id;
    let id = request_approval(&root, instance, "plan", 0, pending.approval_digest()).unwrap();
    // The control ended rejected, for example after a transient service error.
    rusqlite::Connection::open(root.join("coordinator.sqlite3"))
        .unwrap()
        .execute("UPDATE controls SET state='rejected'", [])
        .unwrap();
    assert_eq!(coordinator.service_controls(&f.definition).unwrap(), 0);
    let again = request_approval(&root, instance, "plan", 0, pending.approval_digest()).unwrap();
    assert_eq!(again, id);
    assert_eq!(control_states(&f), ["pending"]);
    assert_eq!(coordinator.service_controls(&f.definition).unwrap(), 1);
    assert_eq!(control_states(&f), ["applied"]);
    assert_eq!(
        runtime.summary(&pending.summary().run_id).unwrap().state,
        RunState::Queued
    );
}

#[tokio::test]
async fn approval_applied_before_a_crash_is_not_recorded_as_rejected() {
    let f = Fixture::new().await;
    let runtime = f.runtime();
    let coordinator = f.coordinator(runtime.clone());
    coordinator.register(&f.definition).unwrap();
    let pending = f.review(&coordinator, "plan").await;
    let root = f.temp.path().join("coordinator");
    request_approval(
        &root,
        &f.definition.execution.instance_id,
        "plan",
        0,
        pending.approval_digest(),
    )
    .unwrap();
    // The approval and the run happen, but the control was never settled.
    rusqlite::Connection::open(root.join("coordinator.sqlite3"))
        .unwrap()
        .execute("UPDATE controls SET state='pending'", [])
        .unwrap();
    let outcome = run(&coordinator, &f.definition, &pending, PLAN, &FakeSupervisor).await;
    assert_eq!(outcome.run.state, RunState::Verifying);
    rusqlite::Connection::open(root.join("coordinator.sqlite3"))
        .unwrap()
        .execute("UPDATE controls SET state='pending'", [])
        .unwrap();
    assert_eq!(coordinator.service_controls(&f.definition).unwrap(), 1);
    assert_eq!(control_states(&f), ["applied"]);
}

#[tokio::test]
async fn definition_rejects_producer_outputs_above_the_consumer_input_limit() {
    let f = Fixture::new().await;
    let mut definition = f.definition.clone();
    // execute consumes plan output (max_bytes 8192) plus nothing else.
    definition.max_input_bytes = 8191;
    definition.definition_sha256.clear();
    assert!(matches!(
        seal_definition(definition.clone()),
        Err(CoordinatorError::Invalid("input bytes"))
    ));
    definition.max_input_bytes = 32 * 1024;
    seal_definition(definition).unwrap();
}

#[tokio::test]
async fn material_limit_is_checked_before_side_effects_and_terminal_steps_release_it() {
    let mut f = Fixture::new().await;
    parallel_definition(&mut f);
    let runtime = f.runtime();
    let c = f.coordinator(runtime.clone()).with_material_limit(1);
    c.register(&f.definition).unwrap();
    let first = f.review(&c, "first").await;
    let (context, request) = f.material("second");
    let proof = f
        .router
        .validate_receipt(&context, &f.router.route(&context).unwrap())
        .unwrap();
    let refused = c
        .review_step(
            &f.definition,
            "second",
            0,
            &f.router,
            &context,
            &proof,
            request,
        )
        .await;
    assert!(matches!(refused, Err(CoordinatorError::Limit)));
    let status = c.status(&f.definition).unwrap();
    let second = status.nodes.iter().find(|n| n.node_id == "second").unwrap();
    assert_eq!((second.run_id.clone(), second.state), (None, None));
    // A verified (terminal) step releases its material.
    run(&c, &f.definition, &first, PLAN, &FakeSupervisor).await;
    c.verify_step(&f.definition, &first, record(&runtime, &first))
        .unwrap();
    f.review(&c, "second").await;
}

fn reset_controls_pending(f: &Fixture) {
    rusqlite::Connection::open(f.temp.path().join("coordinator/coordinator.sqlite3"))
        .unwrap()
        .execute("UPDATE controls SET state='pending'", [])
        .unwrap();
}

#[tokio::test]
async fn terminal_step_without_material_settles_its_controls() {
    // Approve control on a run cancelled before approval: rejected.
    let f = Fixture::new().await;
    let runtime = f.runtime();
    let coordinator = f.coordinator(runtime.clone());
    coordinator.register(&f.definition).unwrap();
    let pending = f.review(&coordinator, "plan").await;
    let root = f.temp.path().join("coordinator");
    request_approval(
        &root,
        &f.definition.execution.instance_id,
        "plan",
        0,
        pending.approval_digest(),
    )
    .unwrap();
    router_runtime::request_cancel(runtime.storage_root(), &pending.summary().run_id).unwrap();
    assert_eq!(
        runtime.summary(&pending.summary().run_id).unwrap().state,
        RunState::Cancelled
    );
    drop(coordinator);
    let reopened = f.coordinator(runtime.clone());
    assert_eq!(reopened.retained_materials(), 0);
    assert_eq!(reopened.service_controls(&f.definition).unwrap(), 0);
    assert_eq!(control_states(&f), ["rejected"]);
}

#[tokio::test]
async fn verified_step_without_material_settles_a_recorded_verification_as_applied() {
    let f = Fixture::new().await;
    let runtime = f.runtime();
    let coordinator = f.coordinator(runtime.clone());
    coordinator.register(&f.definition).unwrap();
    let planner = f.review(&coordinator, "plan").await;
    run(&coordinator, &f.definition, &planner, PLAN, &FakeSupervisor).await;
    let root = f.temp.path().join("coordinator");
    let verification = record(&runtime, &planner);
    request_verification(
        &root,
        &f.definition.execution.instance_id,
        "plan",
        0,
        planner.approval_digest(),
        verification.clone(),
    )
    .unwrap();
    coordinator
        .verify_step(&f.definition, &planner, verification)
        .unwrap();
    // Reset whatever the live loop settled, as if the owner crashed first.
    reset_controls_pending(&f);
    drop(coordinator);
    let reopened = f.coordinator(runtime.clone());
    assert_eq!(reopened.service_controls(&f.definition).unwrap(), 1);
    assert_eq!(control_states(&f), ["applied"]);
}

#[tokio::test]
async fn unreadable_run_does_not_abort_the_other_controls() {
    let f = Fixture::new().await;
    let runtime = f.runtime();
    let coordinator = f.coordinator(runtime.clone());
    coordinator.register(&f.definition).unwrap();
    let pending = f.review(&coordinator, "plan").await;
    let root = f.temp.path().join("coordinator");
    // A control row whose run the runtime cannot read, older than the real one.
    rusqlite::Connection::open(root.join("coordinator.sqlite3"))
        .unwrap()
        .execute(
            "INSERT INTO controls VALUES('bogus',?1,'wf-missing',?2,'pending')",
            rusqlite::params![
                f.definition.execution.instance_id,
                r#"{"kind":"approve","digest":"x"}"#
            ],
        )
        .unwrap();
    coordinator.service_controls(&f.definition).unwrap();
    drop(coordinator);
    let coordinator = f.coordinator(runtime.clone());
    let pending = {
        // Reconstruct material by reviewing the identical step again.
        let again = f.review(&coordinator, "plan").await;
        assert_eq!(again.summary().run_id, pending.summary().run_id);
        again
    };
    request_approval(
        &root,
        &f.definition.execution.instance_id,
        "plan",
        0,
        pending.approval_digest(),
    )
    .unwrap();
    assert_eq!(coordinator.service_controls(&f.definition).unwrap(), 1);
    assert_eq!(control_states(&f), ["pending", "applied"]);
}

#[tokio::test]
async fn terminal_steps_release_their_material() {
    let mut f = Fixture::new().await;
    parallel_definition(&mut f);
    let runtime = f.runtime();
    let c = f.coordinator(runtime.clone());
    c.register(&f.definition).unwrap();
    let first = f.review(&c, "first").await;
    let second = f.review(&c, "second").await;
    assert_eq!(c.retained_materials(), 2);
    run(&c, &f.definition, &first, PLAN, &FakeSupervisor).await;
    assert_eq!(c.retained_materials(), 2, "Verifying is not terminal");
    c.verify_step(&f.definition, &first, record(&runtime, &first))
        .unwrap();
    assert_eq!(c.retained_materials(), 1, "verified step released");
    let failed = run(&c, &f.definition, &second, "exit 3", &FakeSupervisor).await;
    assert!(failed.run.state.terminal());
    assert_eq!(c.retained_materials(), 0, "failed wave step released");
}

const SLOW_PLAN: &str = "sleep 1; printf '%s\\n' '{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"Proposal: change src/base.txt; validate changed content.\"}}' '{\"type\":\"turn.completed\"}'";

#[tokio::test]
async fn supervision_ticks_validate_the_definition_once_per_wave() {
    let f = Fixture::new().await;
    let coordinator = f.coordinator(f.runtime());
    coordinator.register(&f.definition).unwrap();
    let pending = f.review(&coordinator, "plan").await;
    let approved = coordinator
        .approve_step(&f.definition, pending.clone(), pending.approval_digest())
        .unwrap();
    let before = validations_on_this_thread();
    let started = std::time::Instant::now();
    let wave = coordinator
        .run_ready(
            &f.definition,
            vec![StepExecution {
                step: approved,
                adapter: &FakeAdapter(SLOW_PLAN),
                supervisor: &FakeSupervisor,
            }],
        )
        .await
        .unwrap();
    let validations = validations_on_this_thread() - before;
    // One second at a 20 ms tick is dozens of ticks; none may re-hash.
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert_eq!(wave.completions[0].run.state, RunState::Verifying);
    assert_eq!(validations, 1);
}

#[tokio::test]
async fn altered_definition_is_refused_by_every_entry_point() {
    let f = Fixture::new().await;
    let coordinator = f.coordinator(f.runtime());
    coordinator.register(&f.definition).unwrap();
    let pending = f.review(&coordinator, "plan").await;
    let approved = coordinator
        .approve_step(&f.definition, pending.clone(), pending.approval_digest())
        .unwrap();
    // Structurally valid but not the sealed bytes: the hash no longer matches.
    let mut altered = f.definition.clone();
    altered.max_input_bytes -= 1;
    assert!(matches!(
        validate_definition(&altered),
        Err(CoordinatorError::Integrity)
    ));
    assert!(matches!(
        coordinator.service_controls(&altered),
        Err(CoordinatorError::Integrity)
    ));
    assert!(matches!(
        coordinator
            .run_ready(
                &altered,
                vec![StepExecution {
                    step: approved,
                    adapter: &FakeAdapter(PLAN),
                    supervisor: &FakeSupervisor,
                }],
            )
            .await,
        Err(CoordinatorError::Integrity)
    ));
    // The sealed definition is still accepted.
    assert!(validate_definition(&f.definition).is_ok());
}

#[tokio::test]
async fn control_request_does_not_hold_the_coordinator_lock_while_observing_the_runtime() {
    let f = Fixture::new().await;
    let runtime = f.runtime();
    let coordinator = f.coordinator(runtime.clone());
    coordinator.register(&f.definition).unwrap();
    let pending = f.review(&coordinator, "plan").await;
    let root = f.temp.path().join("coordinator");
    // Point the instance at a private copy of the runtime store, then lock the
    // copy so the runtime observation blocks (the live runtime owner would
    // otherwise keep its own locks on the original).
    let copy = f.temp.path().join("runtime-copy");
    fs::DirBuilder::new().mode(0o700).create(&copy).unwrap();
    rusqlite::Connection::open(runtime.storage_root().join("runtime.sqlite3"))
        .unwrap()
        .execute(
            "VACUUM INTO ?1",
            [copy.join("runtime.sqlite3").to_str().unwrap()],
        )
        .unwrap();
    fs::set_permissions(
        copy.join("runtime.sqlite3"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    rusqlite::Connection::open(root.join("coordinator.sqlite3"))
        .unwrap()
        .execute(
            "UPDATE workflows SET runtime_root=?1",
            [copy.to_str().unwrap()],
        )
        .unwrap();
    let blocker = rusqlite::Connection::open(copy.join("runtime.sqlite3")).unwrap();
    // BEGIN EXCLUSIVE blocks readers only outside WAL; VACUUM INTO does not keep WAL.
    assert_eq!(
        blocker
            .pragma_query_value(None, "journal_mode", |r| r.get::<_, String>(0))
            .unwrap(),
        "delete"
    );
    blocker.execute_batch("BEGIN EXCLUSIVE;").unwrap();
    let request = {
        let root = root.clone();
        let instance = f.definition.execution.instance_id.clone();
        let digest = pending.approval_digest().to_owned();
        std::thread::spawn(move || request_approval(&root, &instance, "plan", 0, &digest))
    };
    // The blocker holds the copy for 1.5 s (busy timeout 2 s): the request must
    // still be inside the runtime observation when the probe runs.
    std::thread::sleep(Duration::from_millis(400));
    assert!(
        !request.is_finished(),
        "request must be blocked in the observation before the probe"
    );
    let probe = rusqlite::Connection::open(root.join("coordinator.sqlite3")).unwrap();
    probe.busy_timeout(Duration::ZERO).unwrap();
    probe
        .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
        .expect("coordinator write lock must be free while the runtime is observed");
    assert!(
        !request.is_finished(),
        "request must still be blocked after the probe"
    );
    std::thread::sleep(Duration::from_millis(1100));
    blocker.execute_batch("ROLLBACK").unwrap();
    drop(blocker);
    request.join().unwrap().unwrap();
    assert_eq!(control_states(&f), ["pending"]);
}

#[tokio::test]
async fn request_cancel_leaves_runs_that_cannot_be_cancelled_untouched() {
    let f = Fixture::new().await;
    let runtime = f.runtime();
    let coordinator = f.coordinator(runtime.clone());
    coordinator.register(&f.definition).unwrap();
    let planner = f.review(&coordinator, "plan").await;
    let outcome = run(&coordinator, &f.definition, &planner, PLAN, &FakeSupervisor).await;
    assert_eq!(outcome.run.state, RunState::Verifying);
    let root = f.temp.path().join("coordinator");
    request_cancel(&root, &f.definition.execution.instance_id).unwrap();
    assert_eq!(
        runtime.summary(&planner.summary().run_id).unwrap().state,
        RunState::Verifying
    );
    assert!(coordinator.status(&f.definition).unwrap().cancelled);
}

#[tokio::test]
async fn cancel_skips_a_verifying_run_and_cancels_the_queued_one() {
    let mut f = Fixture::new().await;
    parallel_definition(&mut f);
    let runtime = f.runtime();
    let c = f.coordinator(runtime.clone());
    c.register(&f.definition).unwrap();
    let first = f.review(&c, "first").await;
    let second = f.review(&c, "second").await;
    let outcome = run(&c, &f.definition, &first, PLAN, &FakeSupervisor).await;
    assert_eq!(outcome.run.state, RunState::Verifying);
    c.approve_step(&f.definition, second.clone(), second.approval_digest())
        .unwrap();
    assert_eq!(
        runtime.summary(&second.summary().run_id).unwrap().state,
        RunState::Queued
    );
    let root = f.temp.path().join("coordinator");
    request_cancel(&root, &f.definition.execution.instance_id).unwrap();
    assert_eq!(
        runtime.summary(&first.summary().run_id).unwrap().state,
        RunState::Verifying
    );
    assert_eq!(
        runtime.summary(&second.summary().run_id).unwrap().state,
        RunState::Cancelled
    );
}

#[tokio::test]
async fn cancel_succeeds_next_to_verified_and_failed_runs() {
    for (script, verify) in [(PLAN, true), ("exit 9", false)] {
        let mut f = Fixture::new().await;
        parallel_definition(&mut f);
        let runtime = f.runtime();
        let c = f.coordinator(runtime.clone());
        c.register(&f.definition).unwrap();
        let first = f.review(&c, "first").await;
        let second = f.review(&c, "second").await;
        run(&c, &f.definition, &first, script, &FakeSupervisor).await;
        if verify {
            c.verify_step(&f.definition, &first, record(&runtime, &first))
                .unwrap();
        }
        let terminal = runtime.summary(&first.summary().run_id).unwrap().state;
        assert!(terminal.terminal(), "{terminal:?}");
        let root = f.temp.path().join("coordinator");
        request_cancel(&root, &f.definition.execution.instance_id).unwrap();
        assert_eq!(
            runtime.summary(&first.summary().run_id).unwrap().state,
            terminal
        );
        assert_eq!(
            runtime.summary(&second.summary().run_id).unwrap().state,
            RunState::Cancelled
        );
    }
}

#[tokio::test]
async fn cancel_continues_after_a_failing_run_and_returns_the_first_error() {
    let mut f = Fixture::new().await;
    parallel_definition(&mut f);
    let runtime = f.runtime();
    let c = f.coordinator(runtime.clone());
    c.register(&f.definition).unwrap();
    let first = f.review(&c, "first").await;
    let root = f.temp.path().join("coordinator");
    let instance = &f.definition.execution.instance_id;
    // A registered run the runtime does not know sorts before the real ones.
    rusqlite::Connection::open(root.join("coordinator.sqlite3"))
        .unwrap()
        .execute(
            "INSERT INTO steps VALUES(?1,'aaa',0,'missing-run','x',0,0)",
            [instance],
        )
        .unwrap();
    assert!(request_cancel(&root, instance).is_err());
    assert_eq!(
        runtime.summary(&first.summary().run_id).unwrap().state,
        RunState::Cancelled
    );
}
