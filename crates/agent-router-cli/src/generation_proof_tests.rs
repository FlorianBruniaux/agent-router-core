use super::*;
use std::{collections::BTreeSet, fs};
#[path = "../../../tests/support/capability_store.rs"]
mod capability_store;
fn write(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
#[test]
fn historical_generation_uses_referenced_sequence_and_not_current_binary() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let binary = root.join("fake-program");
    fs::write(&binary, b"synthetic native bytes, never executed").unwrap();
    let config = serde_json::json!({"schema_version":1,"programs":{"codex":binary},"helper":binary,
        "bubblewrap":if cfg!(target_os="linux") { Some(&binary) } else { None },
        "read_roots":[],"environment_names":[],"limits":{"cpu_seconds":1,"address_space_bytes":null,
        "max_open_files":64,"max_processes":64,"max_file_bytes":1048576}});
    write(&root.join("sandbox.json"), &config);
    let mut observation: router_adapter_api::HostObservation = serde_json::from_str(include_str!(
        "../../../fixtures/examples/phase-snapshot.json"
    ))
    .unwrap();
    observation.host.capabilities = BTreeSet::from([Capability::WorkspaceWrite]);
    for (capability, evidence) in &mut observation.capabilities {
        if *capability != Capability::WorkspaceWrite {
            evidence.support = CapabilitySupport::Unknown;
            evidence.source_ids.clear();
        }
    }
    let (observation, _) = capability_store::provision(
        &observation.seal().unwrap(),
        &config,
        &["src".into()],
        false,
        &root.join("store"),
        "fixture-v1",
    );
    // Mixed provenance remains legal: only the runtime proof grants authority.
    let mut observation = observation;
    observation
        .evidence
        .push(router_adapter_api::EvidenceSource {
            id: "additional-model-cache".into(),
            kind: router_adapter_api::EvidenceKind::CodexModelCache,
            observed_version: Some("fixture-v1".into()),
            observed_at_unix_seconds: 100,
            content_sha256: "c".repeat(64),
        });
    observation
        .capabilities
        .get_mut(&Capability::WorkspaceWrite)
        .unwrap()
        .source_ids
        .insert("additional-model-cache".into());
    let observation = observation.seal().unwrap();
    write(&root.join("snapshot.json"), &observation);
    fs::write(
        root.join("catalog.json"),
        include_bytes!("../../../fixtures/examples/phase-catalog.json"),
    )
    .unwrap();
    let mut request: PhaseRouteRequest = serde_json::from_str(include_str!(
        "../../../fixtures/examples/phase-request.json"
    ))
    .unwrap();
    request.task.allowed_mutations.clear();
    let plan = router_workflow::build_plan(
        &request.task,
        WorkflowPreset::DirectSafe,
        router_workflow::PlanLimits::default(),
    )
    .unwrap();
    let contract = router_workflow::seal_execution_contract(
        WorkflowExecutionContract {
            schema_version: 1,
            instance_id: "historical-generation".into(),
            plan_id: plan.plan_id.clone(),
            workspace: root.to_string_lossy().into(),
            source_state: "a".repeat(64),
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
    write(&root.join("plan.json"), &plan);
    write(&root.join("contract.json"), &contract);
    let nodes:Vec<_> = plan.nodes.iter().map(|node| {
        let mut node_request=request.clone();node_request.phase=contract.nodes[&node.id].phase;
        write(&root.join(format!("{}.json",node.id)), &node_request);
        serde_json::json!({"node_id":node.id,"context":format!("{}.json",node.id),"host_snapshot":"snapshot.json",
            "catalog":"catalog.json","capability_store":"store","execution_config":"sandbox.json"})
    }).collect();
    let compatibility:Vec<_>=plan.nodes.iter().flat_map(|node|node.dependencies.iter().map(|source|
        serde_json::json!({"source":source,"target":node.id,"allowed_pairs":[["primary","primary"],["primary","secondary"],["secondary","primary"],["secondary","secondary"]]}))).collect();
    let manifest = root.join("generation.json");
    write(
        &manifest,
        &serde_json::json!({"schema_version":1,"plan":"plan.json","workflow_contract":"contract.json",
        "policy":PlanGenerationPolicy::default(),"nodes":nodes,"compatibility":compatibility,"snapshot_max_age_seconds":300}),
    );
    let before = load(&manifest, 110).unwrap_or_else(|e| panic!("{}", e.code()));
    let report = generate_plans(&before.input(&before.nodes(), 110)).unwrap();
    let mut store = router_runtime::CapabilityProofStore::create(&root.join("store")).unwrap();
    let key = router_adapter_api::CapabilityProofKey::derive(
        &capability_store::FIXTURE_SECRET,
        store.store_id(),
    )
    .unwrap();
    let failed = key
        .authenticate(router_adapter_api::CapabilityProofRecord {
            schema_version: 1,
            proof_id: "same-second-later-failure".into(),
            sequence: 2,
            store_id: store.store_id().into(),
            capability: Capability::WorkspaceWrite,
            tier: router_adapter_api::CapabilityProofTier::Proven,
            network_scope: None,
            binding: capability_store::binding(
                &observation.host,
                &config,
                &["src".into()],
                false,
                "fixture-v1",
            ),
            model_id: observation
                .host
                .supported_models
                .first()
                .unwrap()
                .to_string(),
            nonce_sha256: "7".repeat(64),
            expected_effect_sha256: "8".repeat(64),
            started_at_unix_seconds: 110,
            ended_at_unix_seconds: 110,
            max_age_seconds: 86400,
            outcome: router_adapter_api::CapabilityAttemptOutcome::Failed,
        })
        .unwrap();
    store
        .append(&failed, &capability_store::FIXTURE_SECRET)
        .unwrap();
    assert!(
        load(&manifest, 110).is_err(),
        "fresh generation must observe revocation"
    );
    fs::remove_file(&binary).unwrap();
    let historical = load_mode(&manifest, 110, true).unwrap_or_else(|e| panic!("{}", e.code()));
    assert_eq!(historical.source_sha256, before.source_sha256);
    assert_eq!(
        generate_plans(&historical.input(&historical.nodes(), 110)).unwrap(),
        report
    );
    assert!(
        load(&manifest, 110).is_err(),
        "historical reconstruction cannot authorize a fresh request"
    );
}
