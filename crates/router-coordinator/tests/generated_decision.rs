//! Synthetic generated-plan decisions. Lives here because this crate already
//! depends on the workflow builder; router-execution-decision does not.
#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use router_adapter_api::{HostObservation, SnapshotValidation};
use router_catalog::Catalog;
use router_execution_decision::{DecisionError, ExecutionDecision};
use router_policy::{
    GenerationNode, PhaseRouter, PlanGenerationInput, ValidatedGeneratedPlan,
    ValidatedPhaseContext, generate_plans, validate_generated_plan,
};
use router_runtime::source_state;
use router_types::*;
use router_workflow::{PlanLimits, build_plan, seal_execution_contract};
use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture {
    _temp: tempfile::TempDir,
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
            _temp: temp,
            router,
            contexts,
            plan,
            contract,
            compatibility,
            policy: PlanGenerationPolicy::default(),
            planned_at,
        }
    }
    fn nodes(&self) -> Vec<GenerationNode<'_>> {
        self.plan
            .nodes
            .iter()
            .zip(&self.contexts)
            .map(|(node, context)| GenerationNode::from_context(&node.id, &self.router, context))
            .collect()
    }
    fn proof(&self) -> ValidatedGeneratedPlan {
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
        validate_generated_plan(&input, report.selected.as_ref().unwrap()).unwrap()
    }
}

#[tokio::test]
async fn generated_decision_binds_plan_node_context_and_baseline() {
    let f = Fixture::new().await;
    let proof = f.proof();
    let node = f.plan.nodes[0].id.clone();
    let baseline = f.router.route(&f.contexts[0]).unwrap();
    let decision =
        ExecutionDecision::generated(&f.router, &f.contexts[0], &baseline, &proof, &node).unwrap();
    assert_eq!(decision.origin(), ExecutionDecisionOrigin::Generated);
    let binding = decision.generated_binding().unwrap();
    assert_eq!(binding.node_id, node);
    assert_eq!(binding.baseline_receipt_id, baseline.receipt_id);
    assert_eq!(binding.context_hash, f.contexts[0].context_hash());
    assert_eq!(binding.pool_hash, f.contexts[0].pool_hash());
    assert_eq!(binding.instance_id, f.contract.instance_id);
    assert_eq!(decision.authorization_id(), binding.decision_id);
    assert_ne!(decision.authorization_id(), baseline.receipt_id);
    assert_eq!(decision.selection(), proof.selection_for(&node).unwrap());
    assert_eq!(decision.baseline(), &baseline);
    decision
        .validate_identity(&f.router, &f.contexts[0])
        .unwrap();
    // The same inputs give the same decision id.
    let again =
        ExecutionDecision::generated(&f.router, &f.contexts[0], &baseline, &proof, &node).unwrap();
    assert_eq!(again.authorization_id(), decision.authorization_id());
}

#[tokio::test]
async fn generated_decision_rejects_a_foreign_baseline_node_or_context() {
    let f = Fixture::new().await;
    let proof = f.proof();
    let node = f.plan.nodes[0].id.clone();
    let baseline = f.router.route(&f.contexts[0]).unwrap();
    let mut forged = baseline.clone();
    forged.receipt_id = "0".repeat(64);
    assert!(matches!(
        ExecutionDecision::generated(&f.router, &f.contexts[0], &forged, &proof, &node),
        Err(DecisionError::Context)
    ));
    assert!(matches!(
        ExecutionDecision::generated(&f.router, &f.contexts[0], &baseline, &proof, "not-a-node"),
        Err(DecisionError::Context)
    ));
    assert!(f.contexts.len() > 1, "fixture needs a second node context");
    let other = f.router.route(&f.contexts[1]).unwrap();
    assert!(matches!(
        ExecutionDecision::generated(&f.router, &f.contexts[1], &other, &proof, &node),
        Err(DecisionError::Context)
    ));
}

#[tokio::test]
async fn generated_dispatch_lease_expires_with_the_plan() {
    let f = Fixture::new().await;
    let proof = f.proof();
    let node = f.plan.nodes[0].id.clone();
    let baseline = f.router.route(&f.contexts[0]).unwrap();
    let decision =
        ExecutionDecision::generated(&f.router, &f.contexts[0], &baseline, &proof, &node).unwrap();
    let lease = decision
        .acquire_dispatch(&f.router, &f.contexts[0], None, f.planned_at)
        .unwrap()
        .unwrap();
    lease.validate_at(f.planned_at).unwrap();
    assert!(matches!(
        lease.validate_at(f.planned_at + 10_000_000_000),
        Err(DecisionError::Stale)
    ));
    assert!(matches!(
        decision.acquire_dispatch(
            &f.router,
            &f.contexts[0],
            None,
            f.planned_at + 10_000_000_000
        ),
        Err(DecisionError::Stale)
    ));
}
