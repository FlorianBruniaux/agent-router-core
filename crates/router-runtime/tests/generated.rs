//! Synthetic planning evidence. These tests never invoke a model or a host CLI.
#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use router_adapter_api::{
    AdapterError, HarnessAdapter, HostObservation, SnapshotValidation, ValidatedExecutionRequest,
};
use router_catalog::Catalog;
use router_execution_decision::ExecutionDecision;
use router_policy::{
    GenerationNode, PhaseRouter, PlanGenerationInput, ValidatedGeneratedPlan,
    ValidatedPhaseContext, generate_plans, validate_generated_plan,
};
use router_runtime::*;
use router_types::*;
use router_workflow::{PlanLimits, build_plan, seal_execution_contract};
use rusqlite::Connection;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture {
    temp: tempfile::TempDir,
    root: PathBuf,
    router: PhaseRouter,
    contexts: Vec<ValidatedPhaseContext>,
    plan: WorkflowPlan,
    contract: WorkflowExecutionContract,
    compatibility: Vec<GenerationEdgeCompatibility>,
    policy: PlanGenerationPolicy,
    planned_at: u64,
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
                "user.name=Synthetic Fixture",
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
        let planned_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut observation: HostObservation = serde_json::from_str(include_str!(
            "../../../fixtures/examples/phase-snapshot.json"
        ))
        .unwrap();
        observation.observed_at_unix_seconds = planned_at;
        for evidence in &mut observation.evidence {
            evidence.observed_at_unix_seconds = planned_at;
        }
        let snapshot = fixture_proofs::from_observation(
            observation.seal().unwrap(),
            SnapshotValidation {
                now_unix_seconds: planned_at,
                max_age_seconds: 300,
            },
        )
        .unwrap();
        let catalog = Catalog::from_json(include_bytes!(
            "../../../fixtures/examples/phase-catalog.json"
        ))
        .unwrap();
        let mut template: PhaseRouteRequest = serde_json::from_str(include_str!(
            "../../../fixtures/examples/phase-request.json"
        ))
        .unwrap();
        template.task.allowed_mutations.clear();
        // Keep a cheaper alternative on the non-dominated frontier.
        template.candidates[1].estimated_cost_microusd = 10;
        let plan = build_plan(
            &template.task,
            WorkflowPreset::DirectSafe,
            PlanLimits::default(),
        )
        .unwrap();
        let contract = seal_execution_contract(
            WorkflowExecutionContract {
                schema_version: 1,
                instance_id: "synthetic-global-plan".into(),
                plan_id: plan.plan_id.clone(),
                workspace: root.to_str().unwrap().into(),
                source_state: source_state(&root).await.unwrap(),
                nodes: plan
                    .nodes
                    .iter()
                    .map(|node| {
                        (
                            node.id.clone(),
                            NodeExecutionContract {
                                phase: if node.id == "verify" {
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
            &plan,
        )
        .unwrap();
        let router = PhaseRouter::stable_v2();
        let contexts = plan
            .nodes
            .iter()
            .map(|node| {
                let mut request = template.clone();
                request.phase = contract.nodes[&node.id].phase;
                router.context(request, &snapshot, &catalog).unwrap()
            })
            .collect();
        let compatibility = plan
            .nodes
            .iter()
            .flat_map(|node| {
                node.dependencies
                    .iter()
                    .map(|source| GenerationEdgeCompatibility {
                        source: source.clone(),
                        target: node.id.clone(),
                        allowed_pairs: Some(
                            [
                                ("primary", "primary"),
                                ("primary", "secondary"),
                                ("secondary", "primary"),
                                ("secondary", "secondary"),
                            ]
                            .into_iter()
                            .map(|(a, b)| (a.into(), b.into()))
                            .collect(),
                        ),
                    })
            })
            .collect();
        Self {
            temp,
            root,
            router,
            contexts,
            plan,
            contract,
            compatibility,
            policy: PlanGenerationPolicy::default(),
            planned_at,
        }
    }
    fn storage(&self) -> PathBuf {
        self.temp.path().join("runtime")
    }
    fn runtime(&self) -> Runtime {
        Runtime::open(&self.storage(), RuntimeLimits::default())
            .map(|runtime| {
                runtime.with_capability_proof_verifier(std::sync::Arc::new(
                    fixture_proofs::FixtureVerifier,
                ))
            })
            .unwrap()
    }
    fn nodes(&self) -> Vec<GenerationNode<'_>> {
        self.plan
            .nodes
            .iter()
            .zip(&self.contexts)
            .map(|(node, context)| GenerationNode::from_context(&node.id, &self.router, context))
            .collect()
    }
    fn proofs(&self) -> Vec<ValidatedGeneratedPlan> {
        let nodes = self.nodes();
        let input = PlanGenerationInput {
            plan: &self.plan,
            execution: &self.contract,
            nodes: &nodes,
            compatibility: &self.compatibility,
            policy: &self.policy,
            now_unix_seconds: self.planned_at,
        };
        let report = generate_plans(&input).unwrap();
        report
            .selected
            .iter()
            .chain(&report.alternatives)
            .map(|proposal| validate_generated_plan(&input, proposal).unwrap())
            .collect()
    }
    fn decision(&self, proof: &ValidatedGeneratedPlan, index: usize) -> ExecutionDecision {
        ExecutionDecision::generated(
            &self.router,
            &self.contexts[index],
            &self.router.route(&self.contexts[index]).unwrap(),
            proof,
            &self.plan.nodes[index].id,
        )
        .unwrap()
    }
    fn request(&self, decision: &ExecutionDecision, index: usize) -> ExecutionRequest {
        let c = &decision.selection().candidate;
        ExecutionRequest {
            schema_version: 1,
            receipt_id: decision.authorization_id().into(),
            candidate_id: c.id.clone(),
            phase: self.contexts[index].request().phase,
            host: HarnessId::parse("codex").unwrap(),
            model: c.model.clone(),
            effort: c.effort,
            workspace: self.contract.workspace.clone(),
            source_state: self.contract.source_state.clone(),
            scope: self.plan.nodes[index].scope.clone(),
            sandbox: ExecutionSandbox::ReadOnly,
            required_capabilities: self
                .router
                .execution_capabilities(&self.contexts[index], decision.selection())
                .unwrap(),
            tools: ToolSelection::Disabled,
            agent: None,
            skills: vec![],
            prompt: "synthetic private input".into(),
            mode: ExecutionMode::Execute,
            target: ExecutionTarget::ExternalWorker,
            allow_degradation: false,
            timeout_ms: 100,
            max_output_bytes: 1024,
        }
    }
    async fn review(
        &self,
        runtime: &Runtime,
        id: &str,
        decision: &ExecutionDecision,
        index: usize,
    ) -> Result<PendingRun> {
        runtime
            .review_decision(
                id,
                &self.router,
                &self.contexts[index],
                decision,
                self.request(decision, index),
                self.plan.clone(),
                &self.plan.nodes[index].id,
                Some((&self.contract, 0)),
                None,
            )
            .await
    }
    fn reopen(
        &self,
        runtime: &Runtime,
        id: &str,
        decision: &ExecutionDecision,
        index: usize,
    ) -> Result<PendingRun> {
        runtime.reopen_decision(
            id,
            &self.router,
            &self.contexts[index],
            decision,
            self.request(decision, index),
            self.plan.clone(),
            &self.plan.nodes[index].id,
            Some((&self.contract, 0)),
            None,
        )
    }
    fn legacy(&self, index: usize) -> ExecutionDecision {
        let receipt = self.router.route(&self.contexts[index]).unwrap();
        ExecutionDecision::deterministic(
            &self.router,
            &self.contexts[index],
            &self
                .router
                .validate_receipt(&self.contexts[index], &receipt)
                .unwrap(),
        )
        .unwrap()
    }
}

#[tokio::test]
async fn generated_pin_survives_reopen_and_idempotence_and_rejects_other_proposals_or_legacy() {
    let fixture = Fixture::new().await;
    let proofs = fixture.proofs();
    assert!(proofs.len() > 1);
    let first = fixture.decision(&proofs[0], 0);
    let runtime = fixture.runtime();
    let pending = fixture
        .review(&runtime, "execute", &first, 0)
        .await
        .unwrap();
    let events = runtime.events().unwrap();
    let duplicate = fixture
        .review(&runtime, "execute", &first, 0)
        .await
        .unwrap();
    assert_eq!(pending.summary(), duplicate.summary());
    assert_eq!(events, runtime.events().unwrap());
    assert!(runtime.retry(pending.clone()).is_err());
    drop(runtime);
    let runtime = fixture.runtime();
    let reopened = fixture.reopen(&runtime, "execute", &first, 0).unwrap();
    assert_eq!(pending.summary(), reopened.summary());
    assert_eq!(events, runtime.events().unwrap());
    let alternative = fixture.decision(&proofs[1], 1);
    assert!(matches!(
        fixture
            .review(&runtime, "mixed-proposal", &alternative, 1)
            .await,
        Err(RuntimeError::Integrity("workflow plan authority changed"))
    ));
    assert!(matches!(
        fixture
            .review(&runtime, "mixed-legacy", &fixture.legacy(1), 1)
            .await,
        Err(RuntimeError::Integrity("workflow plan authority changed"))
    ));
    assert_eq!(events, runtime.events().unwrap());
    let second = fixture.decision(&proofs[0], 1);
    let consumer = fixture
        .review(&runtime, "verify", &second, 1)
        .await
        .unwrap();
    assert!(!runtime.dependencies_ready(&consumer).unwrap());
    assert!(runtime.summary("mixed-proposal").is_err());
    assert!(runtime.summary("mixed-legacy").is_err());
}

#[tokio::test]
async fn sqlite_v6_migration_preserves_runs_events_instances_and_legacy_pins_across_reopens() {
    let fixture = Fixture::new().await;
    let decision = fixture.legacy(0);
    let runtime = fixture.runtime();
    let original = fixture
        .review(&runtime, "legacy", &decision, 0)
        .await
        .unwrap();
    let events = runtime.events().unwrap();
    drop(runtime);
    // v6 predates both authority and preparation tables. Keep real runs,
    // events, contract and node association bytes from the legacy runtime path.
    let db = Connection::open(fixture.storage().join("runtime.sqlite3")).unwrap();
    db.execute_batch(
        "DROP TABLE admission_intents; DROP TABLE admission_binding; DROP TABLE preparation_cycles; DROP TABLE workflow_plan_authority; PRAGMA user_version=6;",
    )
    .unwrap();
    let before: Vec<(String, String)> = db
        .prepare("SELECT instance_id,record FROM workflow_instances ORDER BY instance_id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap();
    assert_eq!(
        db.pragma_query_value::<u32, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        6
    );
    drop(db);
    for _ in 0..2 {
        let runtime = fixture.runtime();
        assert_eq!(runtime.summary("legacy").unwrap(), *original.summary());
        assert_eq!(runtime.events().unwrap(), events);
        assert_eq!(
            fixture
                .reopen(&runtime, "legacy", &decision, 0)
                .unwrap()
                .summary(),
            original.summary()
        );
        let proof = fixture.proofs().remove(0);
        let generated = fixture.decision(&proof, 1);
        assert!(matches!(
            fixture.review(&runtime, "reassigned", &generated, 1).await,
            Err(RuntimeError::Integrity("workflow plan authority changed"))
        ));
        drop(runtime);
        let db = Connection::open(fixture.storage().join("runtime.sqlite3")).unwrap();
        assert_eq!(
            db.pragma_query_value::<u32, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            9
        );
        let after: Vec<(String, String)> = db
            .prepare("SELECT instance_id,record FROM workflow_instances ORDER BY instance_id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(
            db.query_row(
                "SELECT pin FROM workflow_plan_authority WHERE instance_id=?1",
                [&fixture.contract.instance_id],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "legacy"
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM workflow_plan_authority", [], |r| r
                .get::<_, u32>(0))
                .unwrap(),
            1
        );
        assert!(
            !db.prepare("PRAGMA foreign_key_check")
                .unwrap()
                .exists([])
                .unwrap()
        );
        assert_eq!(
            db.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        assert!(
            db.execute("UPDATE events SET detail='changed'", [])
                .is_err()
        );
    }
}

#[tokio::test]
async fn forged_request_scope_source_contract_and_generation_fail_before_registration() {
    let fixture = Fixture::new().await;
    let proof = fixture.proofs().remove(0);
    let decision = fixture.decision(&proof, 0);
    let runtime = fixture.runtime();
    for mutation in 0..6 {
        let mut request = fixture.request(&decision, 0);
        let mut contract = fixture.contract.clone();
        let mut generation = 0;
        match mutation {
            0 => request.scope = vec![".".into()],
            1 => request.source_state = "b".repeat(64),
            2 => request
                .required_capabilities
                .insert(Capability::Network)
                .then_some(())
                .unwrap(),
            3 => request.tools = ToolSelection::HostPolicy,
            4 => {
                contract.instance_id = "different-instance".into();
                contract = seal_execution_contract(contract, &fixture.plan).unwrap();
            }
            _ => generation = 1,
        }
        assert!(
            runtime
                .review_decision(
                    "forged",
                    &fixture.router,
                    &fixture.contexts[0],
                    &decision,
                    request,
                    fixture.plan.clone(),
                    &fixture.plan.nodes[0].id,
                    Some((&contract, generation)),
                    None
                )
                .await
                .is_err()
        );
        assert!(runtime.summary("forged").is_err());
        assert!(runtime.events().unwrap().is_empty());
    }
    assert!(
        runtime
            .review_decision(
                "missing-contract",
                &fixture.router,
                &fixture.contexts[0],
                &decision,
                fixture.request(&decision, 0),
                fixture.plan.clone(),
                &fixture.plan.nodes[0].id,
                None,
                None
            )
            .await
            .is_err()
    );
    fs::write(fixture.root.join("src/base.txt"), "changed\n").unwrap();
    assert!(matches!(
        fixture.review(&runtime, "stale-source", &decision, 0).await,
        Err(RuntimeError::SourceChanged)
    ));
    assert!(runtime.events().unwrap().is_empty());
}

struct NeverAdapter;
impl HarnessAdapter for NeverAdapter {
    fn host(&self) -> &'static str {
        "codex"
    }
    fn prepare(
        &self,
        _: &ValidatedExecutionRequest,
    ) -> std::result::Result<PreparedRun, AdapterError> {
        panic!("expired plan must stop before adapter preparation")
    }
    fn decode_stream(
        &self,
        _: &[u8],
        _: TransportOutcome,
        _: usize,
    ) -> std::result::Result<RuntimeEvidence, AdapterError> {
        panic!("no child may start")
    }
}
struct NeverSupervisor;
impl SandboxSupervisor for NeverSupervisor {
    fn command(&self, _: &PreparedRun, _: &SandboxPolicy) -> Result<tokio::process::Command> {
        panic!("no child may start")
    }
}
#[tokio::test]
async fn expired_proposal_can_reopen_history_but_never_dispatch_or_bypass_approval() {
    let mut fixture = Fixture::new().await;
    fixture.planned_at -= 10;
    fixture.policy.maximum_evidence_age_seconds = 1;
    let decision = fixture.decision(&fixture.proofs().remove(0), 0);
    let runtime = fixture.runtime();
    let pending = fixture
        .review(&runtime, "expired", &decision, 0)
        .await
        .unwrap();
    assert!(matches!(
        runtime.approve(pending.clone(), &"0".repeat(64)),
        Err(RuntimeError::Approval)
    ));
    let approved = runtime
        .approve(pending.clone(), pending.approval_digest())
        .unwrap();
    drop(runtime);
    let runtime = fixture.runtime();
    let historical = fixture.reopen(&runtime, "expired", &decision, 0).unwrap();
    assert_eq!(historical.summary().state, RunState::Queued);
    assert!(
        runtime
            .execute(
                approved,
                &NeverAdapter,
                &NeverSupervisor,
                Cancellation::default()
            )
            .await
            .is_err()
    );
    assert_eq!(runtime.summary("expired").unwrap().attempts, 0);
    assert_eq!(runtime.summary("expired").unwrap().state, RunState::Blocked);
}

#[tokio::test]
async fn missing_pin_is_not_recreated_to_accept_a_different_proposal() {
    let fixture = Fixture::new().await;
    let proofs = fixture.proofs();
    let runtime = fixture.runtime();
    fixture
        .review(&runtime, "first", &fixture.decision(&proofs[0], 0), 0)
        .await
        .unwrap();
    let before = runtime.events().unwrap();
    let db = Connection::open(fixture.storage().join("runtime.sqlite3")).unwrap();
    db.execute(
        "DELETE FROM workflow_plan_authority WHERE instance_id=?1",
        [&fixture.contract.instance_id],
    )
    .unwrap();
    let result = fixture
        .review(&runtime, "replacement", &fixture.decision(&proofs[1], 1), 1)
        .await;
    assert!(
        result.is_err(),
        "missing durable pin allowed replacement proposal registration"
    );
    assert!(matches!(
        result,
        Err(RuntimeError::Integrity("workflow plan authority changed"))
    ));
    assert!(runtime.summary("replacement").is_err());
    assert_eq!(before, runtime.events().unwrap());
    assert_eq!(
        db.query_row("SELECT count(*) FROM workflow_plan_authority", [], |r| r
            .get::<_, u32>(0))
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn corrupted_pin_after_queue_blocks_dispatch_before_adapter_or_child() {
    let fixture = Fixture::new().await;
    let decision = fixture.decision(&fixture.proofs().remove(0), 0);
    let runtime = fixture.runtime();
    let pending = fixture
        .review(&runtime, "queued", &decision, 0)
        .await
        .unwrap();
    let approved = runtime
        .approve(pending.clone(), pending.approval_digest())
        .unwrap();
    let db = Connection::open(fixture.storage().join("runtime.sqlite3")).unwrap();
    db.execute(
        "UPDATE workflow_plan_authority SET pin='legacy' WHERE instance_id=?1",
        [&fixture.contract.instance_id],
    )
    .unwrap();
    assert!(matches!(
        runtime
            .execute(
                approved,
                &NeverAdapter,
                &NeverSupervisor,
                Cancellation::default()
            )
            .await,
        Err(RuntimeError::Integrity("workflow plan authority changed"))
    ));
    assert_eq!(runtime.summary("queued").unwrap().attempts, 0);
    assert_eq!(runtime.summary("queued").unwrap().state, RunState::Blocked);
}

#[tokio::test]
async fn failed_v6_migration_rolls_back_schema_and_preserves_history() {
    let fixture = Fixture::new().await;
    let runtime = fixture.runtime();
    fixture
        .review(&runtime, "legacy", &fixture.legacy(0), 0)
        .await
        .unwrap();
    let events = runtime.events().unwrap();
    drop(runtime);
    let db = Connection::open(fixture.storage().join("runtime.sqlite3")).unwrap();
    // A conflicting object simulates an incomplete/corrupted external migration.
    db.execute_batch("DROP TABLE admission_intents; DROP TABLE admission_binding; DROP TABLE preparation_cycles; DROP TABLE workflow_plan_authority; CREATE VIEW workflow_plan_authority AS SELECT instance_id,'legacy' AS pin FROM workflow_instances; PRAGMA user_version=6;").unwrap();
    drop(db);
    assert!(
        Runtime::open(&fixture.storage(), RuntimeLimits::default())
            .map(
                |runtime| runtime.with_capability_proof_verifier(std::sync::Arc::new(
                    fixture_proofs::FixtureVerifier
                ))
            )
            .is_err()
    );
    let db = Connection::open(fixture.storage().join("runtime.sqlite3")).unwrap();
    assert_eq!(
        db.pragma_query_value::<u32, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        6
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM events", [], |r| r.get::<_, usize>(0))
            .unwrap(),
        events.len()
    );
    db.execute_batch("DROP VIEW workflow_plan_authority;")
        .unwrap();
    drop(db);
    let runtime = fixture.runtime();
    assert_eq!(runtime.events().unwrap(), events);
    assert_eq!(
        runtime.summary("legacy").unwrap().state,
        RunState::AwaitingApproval
    );
}

#[tokio::test]
async fn valid_replacement_pin_cannot_change_the_event_anchored_proposal() {
    let fixture = Fixture::new().await;
    let proofs = fixture.proofs();
    let runtime = fixture.runtime();
    fixture
        .review(&runtime, "first", &fixture.decision(&proofs[0], 0), 0)
        .await
        .unwrap();
    let before = runtime.events().unwrap();
    let replacement = fixture.decision(&proofs[1], 1);
    let g = replacement.generated_binding().unwrap();
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"runtime-global-plan-pin-v1\0");
    digest.update(
        serde_json::to_vec(&(
            g.schema_version,
            &g.instance_id,
            &g.workflow_plan_id,
            &g.execution_contract_sha256,
            &g.input_hash,
            &g.proposal_hash,
        ))
        .unwrap(),
    );
    let pin = hex::encode(digest.finalize());
    let db = Connection::open(fixture.storage().join("runtime.sqlite3")).unwrap();
    db.execute(
        "UPDATE workflow_plan_authority SET pin=?1 WHERE instance_id=?2",
        rusqlite::params![pin, fixture.contract.instance_id],
    )
    .unwrap();
    let result = fixture
        .review(&runtime, "replacement", &replacement, 1)
        .await;
    assert!(
        result.is_err(),
        "valid replacement pin must not override original event authority"
    );
    assert!(runtime.summary("replacement").is_err());
    assert_eq!(before, runtime.events().unwrap());
    drop(runtime);
    assert!(
        Runtime::open(&fixture.storage(), RuntimeLimits::default())
            .map(
                |runtime| runtime.with_capability_proof_verifier(std::sync::Arc::new(
                    fixture_proofs::FixtureVerifier
                ))
            )
            .is_err(),
        "reopening must not legitimize a substituted pin"
    );
}
