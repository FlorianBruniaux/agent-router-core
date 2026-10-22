//! Authenticated generation inputs, with local files only and no native dispatch.
#[path = "support/native_fixture.rs"]
mod native_fixture;
use native_fixture::{Fixture, checked, command, write};
use router_types::*;
use serde_json::{Value, json};
use std::fs;

fn generated_fixture() -> (Fixture, Value) {
    let f = Fixture::metadata("exit 90", 500);
    let plan: WorkflowPlan =
        serde_json::from_slice(&fs::read(f.root.join("plan.json")).unwrap()).unwrap();
    let execution: ExecutionRequest =
        serde_json::from_slice(&fs::read(f.root.join("request.json")).unwrap()).unwrap();
    let contract = router_workflow::seal_execution_contract(
        WorkflowExecutionContract {
            schema_version: 1,
            instance_id: "authenticated-generation".into(),
            plan_id: plan.plan_id.clone(),
            workspace: execution.workspace,
            source_state: execution.source_state,
            contract_sha256: String::new(),
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
        },
        &plan,
    )
    .unwrap();
    write(&f.root.join("contract.json"), &contract);
    let original: PhaseRouteRequest =
        serde_json::from_slice(&fs::read(f.root.join("context.json")).unwrap()).unwrap();
    let examples: PhaseRouteRequest = serde_json::from_str(include_str!(
        "../../../fixtures/examples/phase-request.json"
    ))
    .unwrap();
    let nodes: Vec<_> = plan.nodes.iter().map(|node| {
        let mut request = original.clone();
        request.phase = contract.nodes[&node.id].phase;
        if node.id == "verify" {
            let mut candidate = examples.candidates[1].clone();
            candidate.estimated_tokens = 4500;
            candidate.sandbox = PhaseSandbox::ReadOnly;
            candidate.verification = PhaseVerification::Independent;
            request.candidates = vec![candidate];
            request.previous_model = Some(original.candidates[0].model.clone());
        }
        write(&f.root.join(format!("node-{}.json", node.id)), &request);
        json!({"node_id":node.id,"context":format!("node-{}.json",node.id),"host_snapshot":"snapshot.json",
            "catalog":"catalog.json","capability_store":"store","execution_config":"sandbox.json"})
    }).collect();
    let compatibility: Vec<_> = plan
        .nodes
        .iter()
        .flat_map(|node| {
            node.dependencies.iter().map(|source|
        json!({"source":source,"target":node.id,"allowed_pairs":[["primary","secondary"]]}))
        })
        .collect();
    let manifest = json!({"schema_version":1,"plan":"plan.json","workflow_contract":"contract.json",
        "policy":PlanGenerationPolicy::default(),"nodes":nodes,"compatibility":compatibility,"snapshot_max_age_seconds":300});
    (f, manifest)
}
fn generate(f: &Fixture, manifest: &Value) -> std::process::Output {
    write(&f.root.join("generation.json"), manifest);
    command()
        .args(["generate-plan", "--manifest"])
        .arg(f.root.join("generation.json"))
        .arg("--json")
        .output()
        .unwrap()
}
#[test]
fn generation_requires_explicit_proof_store_and_binds_effective_configuration() {
    let (f, mut manifest) = generated_fixture();
    let explicit = manifest.clone();
    for node in manifest["nodes"].as_array_mut().unwrap() {
        node.as_object_mut().unwrap().remove("capability_store");
        node.as_object_mut().unwrap().remove("execution_config");
    }
    let denied = generate(&f, &manifest);
    assert_eq!(denied.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&denied.stderr).unwrap()["error"],
        "capability.evidence.unauthenticated"
    );
    let positive = generate(&f, &explicit);
    assert_eq!(
        positive.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&positive.stderr)
    );
    let document: Value = serde_json::from_slice(&positive.stdout).unwrap();
    assert!(!document["report"]["selected"].is_null());
    let mut incomplete = explicit.clone();
    incomplete["nodes"][0]
        .as_object_mut()
        .unwrap()
        .remove("execution_config");
    let denied = generate(&f, &incomplete);
    assert_eq!(denied.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&denied.stderr).unwrap()["error"],
        "capability.evidence.configuration_required"
    );
    // Whitespace changes no config semantics/pins, but belongs to the captured
    // generation source set and must change source_sha256 on fresh generation.
    let config = f.root.join("sandbox.json");
    let mut bytes = fs::read(&config).unwrap();
    bytes.push(b'\n');
    fs::write(&config, bytes).unwrap();
    write(&f.root.join("generation.json"), &explicit);
    let changed = checked(
        command()
            .args(["generate-plan", "--manifest"])
            .arg(f.root.join("generation.json"))
            // The report input hash includes the generation clock. Reuse the
            // first run's clock so this assertion isolates config semantics.
            .arg("--now")
            .arg(
                document["planned_at_unix_seconds"]
                    .as_u64()
                    .unwrap()
                    .to_string(),
            )
            .arg("--json"),
        0,
    );
    assert_ne!(document["source_sha256"], changed["source_sha256"]);
    assert_eq!(
        document["report"]["input_hash"],
        changed["report"]["input_hash"]
    );
    assert!(!f.store.join("worktrees").exists());
}
