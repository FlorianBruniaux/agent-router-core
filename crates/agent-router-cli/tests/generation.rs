//! Synthetic metadata only. No provider, credentials or executable skills.
use assert_cmd::Command;
#[cfg(all(feature = "claude", any(target_os = "macos", target_os = "linux")))]
use native_fixture::unknown_observation;
use router_types::*;
use router_workflow::{PlanLimits, build_plan, seal_execution_contract};
use serde_json::{Value, json};
#[cfg(not(all(feature = "claude", any(target_os = "macos", target_os = "linux"))))]
#[path = "support/unknown_observation.rs"]
mod unknown_observation;
use std::{
    fs,
    path::{Path, PathBuf},
};

fn write(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    manifest: Value,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/examples");
        let mut request: PhaseRouteRequest =
            serde_json::from_slice(&fs::read(fixtures.join("phase-request.json")).unwrap())
                .unwrap();
        request.task.allowed_mutations.clear();
        let plan = build_plan(
            &request.task,
            WorkflowPreset::DirectSafe,
            PlanLimits::default(),
        )
        .unwrap();
        let contract = seal_execution_contract(
            WorkflowExecutionContract {
                schema_version: 1,
                instance_id: "synthetic-cli-generation".into(),
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
        let observation: router_adapter_api::HostObservation =
            serde_json::from_slice(&fs::read(fixtures.join("phase-snapshot.json")).unwrap())
                .unwrap();
        write(
            &root.join("snapshot.json"),
            &unknown_observation::from_example(observation),
        );
        let nodes:Vec<_> = plan.nodes.iter().map(|node| {
            let mut request=request.clone();
            request.phase=contract.nodes[&node.id].phase;
            write(&root.join(format!("{}.json",node.id)), &request);
            json!({"node_id":node.id,"context":format!("{}.json",node.id),"host_snapshot":"snapshot.json","catalog":fixtures.join("phase-catalog.json"),"policy":null,"asset_authority":null,"dimensions":null})
        }).collect();
        let compatibility:Vec<_>=plan.nodes.iter().flat_map(|node|node.dependencies.iter().map(|source|json!({"source":source,"target":node.id,"allowed_pairs":[["primary","primary"],["primary","secondary"],["secondary","primary"],["secondary","secondary"]]}))).collect();
        let manifest = json!({"schema_version":1,"plan":"plan.json","workflow_contract":"contract.json","policy":PlanGenerationPolicy::default(),"nodes":nodes,"compatibility":compatibility,"snapshot_max_age_seconds":30});
        Self {
            _temp: temp,
            root,
            manifest,
        }
    }
    fn command(&self) -> Command {
        write(&self.root.join("generation.json"), &self.manifest);
        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("agent-router"));
        cmd.args(["generate-plan", "--manifest"])
            .arg(self.root.join("generation.json"))
            .args(["--now", "110", "--json"]);
        cmd
    }
    fn report(&self) -> Value {
        let output = self.command().assert().success();
        serde_json::from_slice(&output.get_output().stdout).unwrap()
    }
}
#[test]
fn generates_stable_global_choices_and_binds_every_source() {
    let fixture = Fixture::new();
    let before = fixture.report();
    assert_eq!(before, fixture.report());
    assert_eq!(
        before["report"]["selected"]["choices"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        before["report"]["selected"]["choices"][0]["candidate_id"],
        "primary"
    );
    let path = fixture.root.join("execute.json");
    let mut request: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    request["candidates"][0]["estimated_cost_microusd"] = json!(101);
    write(&path, &request);
    let after = fixture.report();
    assert_ne!(before["source_sha256"], after["source_sha256"]);
    assert_ne!(
        before["report"]["input_hash"],
        after["report"]["input_hash"]
    );
}
#[test]
fn unknown_compatibility_abstains_and_never_creates_a_run() {
    let mut fixture = Fixture::new();
    fixture.manifest["compatibility"][0]["allowed_pairs"] = Value::Null;
    let output = fixture.command().assert().code(3);
    let value: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
    assert_eq!(value["report"]["abstention"], "unknown_compatibility");
    assert!(value["report"]["selected"].is_null());
    assert!(!fixture.root.join("runs.sqlite3").exists());
}
#[test]
fn unknown_fields_stale_snapshots_and_invalid_node_scope_fail_closed() {
    let mut fixture = Fixture::new();
    fixture.manifest["unexpected_grant"] = json!(true);
    fixture.command().assert().code(2);
    fixture
        .manifest
        .as_object_mut()
        .unwrap()
        .remove("unexpected_grant");
    fixture.manifest["snapshot_max_age_seconds"] = json!(1);
    fixture.command().assert().code(2);
    fixture.manifest["snapshot_max_age_seconds"] = json!(30);
    fixture.manifest["nodes"][0]["node_id"] = json!("not-authorized");
    fixture.command().assert().code(2);
}

impl Fixture {
    fn for_preparation(age: u64, maximum_age: u64) -> (Self, Value) {
        use std::collections::{BTreeMap, BTreeSet};
        let mut fixture = Self::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let planned_at = now - age;
        let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/examples");
        let mut observation: router_adapter_api::HostObservation =
            serde_json::from_slice(&fs::read(fixture.root.join("snapshot.json")).unwrap()).unwrap();
        observation.observed_at_unix_seconds = planned_at;
        for evidence in &mut observation.evidence {
            evidence.observed_at_unix_seconds = planned_at;
        }
        write(
            &fixture.root.join("snapshot.json"),
            &observation.seal().unwrap(),
        );
        fs::copy(
            examples.join("phase-catalog.json"),
            fixture.root.join("catalog.json"),
        )
        .unwrap();
        for node in fixture.manifest["nodes"].as_array_mut().unwrap() {
            node["host_snapshot"] = json!("snapshot.json");
            node["catalog"] = json!("catalog.json");
        }
        fixture.manifest["snapshot_max_age_seconds"] = json!(300);
        fixture.manifest["policy"]["maximum_evidence_age_seconds"] = json!(maximum_age);
        write(&fixture.root.join("generation.json"), &fixture.manifest);
        let output = Command::new(assert_cmd::cargo::cargo_bin!("agent-router"))
            .args(["generate-plan", "--manifest"])
            .arg(fixture.root.join("generation.json"))
            .args(["--now", &planned_at.to_string(), "--json"])
            .assert()
            .success();
        let document: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
        write(&fixture.root.join("proposal.json"), &document);
        let catalog = router_catalog::Catalog::from_json(
            &fs::read(fixture.root.join("catalog.json")).unwrap(),
        )
        .unwrap();
        let template = router_workflow::seal_prompt(PromptTemplate {
            schema_version: 1,
            id: "generation-template".into(),
            version: "1".into(),
            template: "Inspect ${subject}".into(),
            variables: BTreeMap::from([("subject".into(), PromptVariableType::Text)]),
            compatible_hosts: BTreeSet::from(["codex".into()]),
            compatible_models: catalog.models().map(|(id, _)| id.clone()).collect(),
            max_rendered_bytes: 4096,
            output_contract: "Report findings".into(),
            content_sha256: String::new(),
        })
        .unwrap();
        write(&fixture.root.join("prompt.json"), &template);
        let metadata: router_retrieval::MetadataDocument = serde_json::from_value(json!({"schema_version":"1","catalog_version":catalog.version(),"assets":[{"kind":"prompt","id":template.id,"trust":"trusted_local","description":"report","body":{"path":"prompt.json","sha256":router_adapter_api::content_digest(&fs::read(fixture.root.join("prompt.json")).unwrap())}}]})).unwrap();
        let envelope =
            router_retrieval::MetadataEnvelope::new(metadata, &catalog.content_hash().unwrap())
                .unwrap();
        write(&fixture.root.join("metadata.json"), &envelope);
        write(
            &fixture.root.join("variables.json"),
            &BTreeMap::from([(
                "subject".to_string(),
                PromptValue::Text("private generation fixture".into()),
            )]),
        );
        write(
            &fixture.root.join("options.json"),
            &json!({"schema_version":1,"workspace":fixture.root,"source_state":"a".repeat(64),"target":"external_worker","allow_degradation":false,"timeout_ms":100,"max_output_bytes":1024,"max_input_bytes":65536,"now_unix_seconds":0,"max_snapshot_age_seconds":300}),
        );
        write(
            &fixture.root.join("prepare.json"),
            &json!({"schema_version":1,"run_id":"generated-fixture","context":"execute.json","host_snapshot":"snapshot.json","catalog":"catalog.json","policy":null,"policy_store":null,"asset_authority":null,"backend_decision":null,"generated_plan":"proposal.json","plan":"plan.json","node_id":"execute","metadata":"metadata.json","body_root":".","template":"prompt.json","variables":"variables.json","options":"options.json","receipt":null,"workflow_contract":"contract.json","generation":0}),
        );
        (fixture, document)
    }
    fn prepare(&self) -> Command {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("agent-router"));
        command
            .args(["prepare", "--manifest"])
            .arg(self.root.join("prepare.json"))
            .args(["--output-directory"])
            .arg(self.root.join("bundle"))
            .arg("--json");
        command
    }
    fn rejected_preparation(&self, expected: &str) {
        let output = self.prepare().assert().code(2);
        assert!(
            String::from_utf8_lossy(&output.get_output().stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&output.get_output().stderr)
        );
        assert!(output.get_output().stdout.is_empty());
        assert!(!self.root.join("bundle").exists());
        assert!(!self.root.join("runtime.sqlite3").exists());
    }
}

#[test]
fn generated_preparation_preserves_the_proposal_binding_without_approval_or_execution() {
    let (fixture, document) = Fixture::for_preparation(0, 300);
    let output = fixture.prepare().assert().success();
    let text = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(!text.contains("private generation fixture"));
    let value: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
    assert_eq!(value["executed"], false);
    assert_eq!(value["approved"], false);
    assert_eq!(value["preview"]["execution_started"], false);
    assert_eq!(value["preview"]["approval_required"], true);
    let definition: Value =
        serde_json::from_slice(&fs::read(fixture.root.join("bundle/definition.json")).unwrap())
            .unwrap();
    assert_eq!(
        definition["generated_plan"],
        json!(fixture.root.join("proposal.json"))
    );
    assert_eq!(definition["workflow_contract"], "workflow-contract.json");
    let request: ExecutionRequest =
        serde_json::from_slice(&fs::read(fixture.root.join("bundle/request.json")).unwrap())
            .unwrap();
    let choice = document["report"]["selected"]["choices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|choice| choice["node_id"] == "execute")
        .unwrap();
    assert_eq!(request.candidate_id, choice["candidate_id"]);
    assert!(request.prompt.contains("private generation fixture"));
    assert!(!fixture.root.join("runtime.sqlite3").exists());
}

#[test]
fn generated_preparation_recomputes_report_and_rejects_forged_proposal_or_source() {
    for mutation in 0..5 {
        let (fixture, mut document) = Fixture::for_preparation(0, 300);
        let expected = match mutation {
            0 => {
                document["source_sha256"] = json!("0".repeat(64));
                "generation.source.changed"
            }
            1 => {
                document["report"]["selected"]["proposal_hash"] = json!("1".repeat(64));
                "generation.report.changed"
            }
            2 => {
                document["report"]["selected"]["choices"][0]["candidate_id"] =
                    json!("outside-pool");
                "generation.report.changed"
            }
            3 => {
                document["selected_proposal_hash"] = json!("2".repeat(64));
                "generation.abstained"
            }
            _ => {
                document["planned_at_unix_seconds"] = json!(u64::MAX);
                "generation.document"
            }
        };
        write(&fixture.root.join("proposal.json"), &document);
        fixture.rejected_preparation(expected);
    }
}

#[test]
fn generated_preparation_detects_changed_manifest_and_unselected_node_sources() {
    for name in ["generation.json", "verify.json"] {
        let (fixture, _) = Fixture::for_preparation(0, 300);
        let path = fixture.root.join(name);
        let mut source: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        if name == "generation.json" {
            source["policy"]["version"] = json!("changed-policy-same-plan");
        } else {
            source["candidates"][0]["estimated_cost_microusd"] = json!(101);
        }
        write(&path, &source);
        fixture.rejected_preparation("generation.source.changed");
    }
}

#[test]
fn expired_generation_and_missing_workflow_authority_never_publish_a_bundle() {
    let (fixture, _) = Fixture::for_preparation(10, 1);
    fixture.rejected_preparation("generation.evidence.expired");
    let (fixture, _) = Fixture::for_preparation(0, 300);
    let path = fixture.root.join("prepare.json");
    let mut source: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    source["workflow_contract"] = Value::Null;
    source["generation"] = Value::Null;
    write(&path, &source);
    fixture.rejected_preparation("generation.workflow.required");
}

#[cfg(all(feature = "claude", any(target_os = "macos", target_os = "linux")))]
#[path = "support/native_fixture.rs"]
mod native_fixture;

/// Real OS isolation with synthetic v3 availability and a fake Claude protocol.
/// This proves generated dispatch binding, not live model availability or quality.
#[cfg(all(feature = "claude", any(target_os = "macos", target_os = "linux")))]
#[test]
#[ignore = "requires native OS sandbox and built helper; no live provider"]
fn native_generated_plan_prepare_approve_and_execute_preserves_v3_authority() {
    use native_fixture::{STREAM, checked, command, shell_quote};
    use router_adapter_api::content_digest;
    use std::{
        collections::{BTreeMap, BTreeSet},
        time::{SystemTime, UNIX_EPOCH},
    };
    let body = format!(
        "printf generated > src/generated.txt\nprintf '%s:%s' \"$model\" \"$effort\" > src/argv.txt\nprintf '%s' {}",
        shell_quote(STREAM)
    );
    let mut fixture = native_fixture::Fixture::new(&body, 3_000);
    // Rebind the synthetic proof after changing the fake native program bytes.
    let script = fs::read_to_string(fixture.root.join("fake-claude")).unwrap();
    assert!(script.contains("fixture-best"));
    fs::write(
        fixture.root.join("fake-claude"),
        script.replace("fixture-best", "fixture-second"),
    )
    .unwrap();
    let observation: router_adapter_api::HostObservation =
        serde_json::from_slice(&fs::read(fixture.root.join("snapshot.json")).unwrap()).unwrap();
    let snapshot = fixture.reprovision(&observation, "fixture-v1");
    let root = &fixture.root;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let read = |name: &str| fs::read(root.join(name)).unwrap();
    let execution: ExecutionRequest = serde_json::from_slice(&read("request.json")).unwrap();
    let mut request: PhaseRouteRequest = serde_json::from_slice(&read("context.json")).unwrap();
    let plan: WorkflowPlan = serde_json::from_slice(&read("plan.json")).unwrap();
    let catalog = router_catalog::Catalog::from_json(&read("catalog.json")).unwrap();
    let contract = seal_execution_contract(
        WorkflowExecutionContract {
            schema_version: 1,
            instance_id: "native-generated-instance".into(),
            plan_id: plan.plan_id.clone(),
            workspace: execution.workspace.clone(),
            source_state: execution.source_state.clone(),
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
    write(&root.join("contract.json"), &contract);
    // Both execution models are eligible, with primary winning the independent
    // phase route. Explicit global edge compatibility forces secondary instead.
    let original: PhaseRouteRequest = serde_json::from_str(include_str!(
        "../../../fixtures/examples/phase-request.json"
    ))
    .unwrap();
    let mut secondary = original.candidates[1].clone();
    secondary.estimated_tokens = 4500;
    secondary.sandbox = PhaseSandbox::WorkspaceWrite;
    let generated_model = secondary.model.clone();
    request.candidates.push(secondary);
    write(&root.join("context.json"), &request);
    native_fixture::write_asset_authority(
        root,
        &native_fixture::asset_inputs(
            &request,
            &snapshot,
            &catalog,
            &fixture.repo,
            &execution.source_state,
            now,
        ),
    );
    assert_eq!(generated_model.as_str(), "fixture-second");
    // The verifier participates in assignment but is not executed here.
    let mut verifier = request.clone();
    verifier.phase = StageKind::Verify;
    verifier.previous_model = Some(generated_model.clone());
    let mut primary = request.candidates[0].clone();
    primary.sandbox = PhaseSandbox::ReadOnly;
    primary.verification = PhaseVerification::Independent;
    verifier.candidates = vec![primary];
    write(&root.join("verify-context.json"), &verifier);
    fs::create_dir(root.join("verify-assets")).unwrap();
    native_fixture::write_asset_authority(
        &root.join("verify-assets"),
        &native_fixture::asset_inputs(
            &verifier,
            &snapshot,
            &catalog,
            &fixture.repo,
            &execution.source_state,
            now,
        ),
    );
    let manifest = json!({"schema_version":1,"plan":"plan.json","workflow_contract":"contract.json","policy":PlanGenerationPolicy::default(),
        "nodes":[
            {"node_id":"execute","context":"context.json","host_snapshot":"snapshot.json","catalog":"catalog.json","capability_store":fixture.store,"execution_config":"sandbox.json","policy":null,"asset_authority":"asset-authority.json","dimensions":null},
            {"node_id":"verify","context":"verify-context.json","host_snapshot":"snapshot.json","catalog":"catalog.json","capability_store":fixture.store,"execution_config":"sandbox.json","policy":null,"asset_authority":"verify-assets/asset-authority.json","dimensions":null}],
        "compatibility":[{"source":"execute","target":"verify","allowed_pairs":[["secondary","primary"]]}],"snapshot_max_age_seconds":300});
    write(&root.join("generation.json"), &manifest);
    let document = checked(
        command()
            .args(["generate-plan", "--manifest"])
            .arg(root.join("generation.json"))
            .arg("--json"),
        0,
    );
    assert_eq!(
        document["report"]["selected"]["choices"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let execute_choice = document["report"]["selected"]["choices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|choice| choice["node_id"] == "execute")
        .unwrap();
    assert_eq!(execute_choice["candidate_id"], "secondary");
    write(&root.join("proposal.json"), &document);
    let template = router_workflow::seal_prompt(PromptTemplate {
        schema_version: 1,
        id: "native-generated-prompt".into(),
        version: "1".into(),
        template: "Inspect ${subject}".into(),
        variables: BTreeMap::from([("subject".into(), PromptVariableType::Text)]),
        compatible_hosts: BTreeSet::from(["claude-code".into()]),
        compatible_models: BTreeSet::from([generated_model.clone()]),
        max_rendered_bytes: 4096,
        output_contract: "Report findings".into(),
        content_sha256: String::new(),
    })
    .unwrap();
    write(&root.join("prompt.json"), &template);
    let metadata = serde_json::from_value(json!({"schema_version":"1","catalog_version":catalog.version(),"assets":[{"kind":"prompt","id":template.id,"trust":"trusted_local","description":"synthetic report","body":{"path":"prompt.json","sha256":content_digest(&read("prompt.json"))}}]})).unwrap();
    write(
        &root.join("metadata.json"),
        &router_retrieval::MetadataEnvelope::new(metadata, &catalog.content_hash().unwrap())
            .unwrap(),
    );
    write(
        &root.join("variables.json"),
        &BTreeMap::from([("subject", PromptValue::Text(native_fixture::PROMPT.into()))]),
    );
    write(
        &root.join("options.json"),
        &json!({"schema_version":1,"workspace":execution.workspace,"source_state":execution.source_state,"target":"external_worker","allow_degradation":false,"timeout_ms":3000,"max_output_bytes":16384,"max_input_bytes":65536,"now_unix_seconds":0,"max_snapshot_age_seconds":300}),
    );
    write(
        &root.join("prepare.json"),
        &json!({"schema_version":1,"run_id":native_fixture::RUN_ID,"context":"context.json","host_snapshot":"snapshot.json","catalog":"catalog.json","capability_store":fixture.store,"execution_config":"sandbox.json","policy":null,"policy_store":null,"asset_authority":"asset-authority.json","backend_decision":null,"generated_plan":"proposal.json","plan":"plan.json","node_id":"execute","metadata":"metadata.json","body_root":".","template":"prompt.json","variables":"variables.json","options":"options.json","receipt":null,"workflow_contract":"contract.json","generation":0}),
    );
    let bundle = root.join("generated-bundle");
    let prepared = checked(
        command()
            .args(["prepare", "--manifest"])
            .arg(root.join("prepare.json"))
            .arg("--output-directory")
            .arg(&bundle)
            .arg("--json"),
        0,
    );
    assert_eq!(prepared["executed"], false);
    assert_eq!(prepared["approved"], false);
    assert!(!prepared.to_string().contains(native_fixture::PROMPT));
    let receipt: Value =
        serde_json::from_slice(&fs::read(bundle.join("receipt.json")).unwrap()).unwrap();
    assert_eq!(receipt["schema_version"], 5);
    assert_eq!(receipt["selected"]["candidate"]["id"], "primary");
    assert_eq!(receipt["selected"]["candidate"]["model"], "fixture-best");
    let generated_request: ExecutionRequest =
        serde_json::from_slice(&fs::read(bundle.join("request.json")).unwrap()).unwrap();
    assert_eq!(generated_request.candidate_id, "secondary");
    assert_eq!(generated_request.model, generated_model);
    assert_ne!(generated_request.model, execution.model);
    let definition: Value =
        serde_json::from_slice(&fs::read(bundle.join("definition.json")).unwrap()).unwrap();
    assert_eq!(
        definition["asset_authority"],
        json!(root.join("asset-authority.json"))
    );
    assert_eq!(
        definition["generated_plan"],
        json!(root.join("proposal.json"))
    );
    let run = || {
        let mut cmd = command();
        cmd.args(["run", "--definition"])
            .arg(bundle.join("definition.json"))
            .arg("--store")
            .arg(&fixture.store)
            .arg("--sandbox")
            .arg(root.join("sandbox.json"))
            .arg("--json");
        cmd
    };
    let review = checked(&mut run(), 0);
    assert_eq!(review["executed"], false);
    assert_eq!(review["request"]["model"], generated_model.as_str());
    assert_eq!(review["request"]["effort"], "medium");
    assert_eq!(review["run"]["state"], "awaiting_approval");
    assert_eq!(
        review["generated_decision"]["proposal_hash"],
        document["report"]["selected"]["proposal_hash"]
    );
    assert_eq!(
        review["generated_decision"]["input_hash"],
        document["report"]["input_hash"]
    );
    assert_eq!(
        review["generated_decision"]["instance_id"],
        contract.instance_id
    );
    assert_eq!(review["generated_decision"]["node_id"], "execute");
    assert_eq!(
        review["run"]["receipt_id"],
        review["generated_decision"]["decision_id"]
    );
    assert_ne!(review["run"]["receipt_id"], receipt["receipt_id"]);
    // Removing the explicit v3 authority cannot be papered over by the proposal.
    let mut legacy_definition = definition.clone();
    legacy_definition["asset_authority"] = Value::Null;
    write(&bundle.join("without-assets.json"), &legacy_definition);
    let denied = command()
        .args(["run", "--definition"])
        .arg(bundle.join("without-assets.json"))
        .arg("--store")
        .arg(&fixture.store)
        .arg("--sandbox")
        .arg(root.join("sandbox.json"))
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(2));
    assert!(denied.stdout.is_empty());
    assert_eq!(fixture.status()["run"]["attempts"], 0);
    let output = checked(
        run().args(["--approve", review["approval_digest"].as_str().unwrap()]),
        0,
    );
    let completion = &output["completion"];
    assert_eq!(completion["run"]["state"], "verifying");
    assert_eq!(
        completion["run"]["receipt_id"],
        review["generated_decision"]["decision_id"]
    );
    assert_eq!(completion["transport"]["termination"], "exited");
    assert_eq!(completion["transport"]["exit_code"], 0);
    assert_eq!(completion["validation"], "unknown");
    assert_eq!(completion["objective"], "unknown");
    assert_eq!(completion["runtime_evidence"]["executed_models"], json!([]));
    assert_eq!(
        completion["stdout_sha256"],
        content_digest(STREAM.as_bytes())
    );
    let worktree = Path::new(completion["run"]["worktree"].as_str().unwrap());
    assert_eq!(
        fs::read(worktree.join("src/generated.txt")).unwrap(),
        b"generated"
    );
    assert_eq!(
        fs::read(worktree.join("src/argv.txt")).unwrap(),
        b"fixture-second:medium"
    );
    assert!(!fixture.repo.join("src/argv.txt").exists());
    assert!(!fixture.repo.join("src/generated.txt").exists());
    assert!(!worktree.join("outside.txt").exists());
    let outputs = checked(
        command()
            .args(["artifacts", "--definition"])
            .arg(bundle.join("definition.json"))
            .arg("--store")
            .arg(&fixture.store)
            .args(["--json", "outputs"]),
        0,
    );
    let stdout = Path::new(outputs["outputs"][0]["stdout"]["path"].as_str().unwrap());
    assert_eq!(fs::read(stdout).unwrap(), STREAM.as_bytes());
    for value in [&prepared, &review, &output, &outputs] {
        assert!(!value.to_string().contains(native_fixture::PROMPT));
        assert!(!value.to_string().contains("synthetic-private-result"));
    }
}

#[test]
fn final_assembly_failures_report_their_own_typed_code() {
    // Appended whitespace keeps the template valid JSON but breaks the body hash
    // pinned by the metadata: the retrieval class.
    let (fixture, _) = Fixture::for_preparation(0, 300);
    let path = fixture.root.join("prompt.json");
    let mut bytes = fs::read(&path).unwrap();
    bytes.push(b'\n');
    fs::write(&path, bytes).unwrap();
    fixture.rejected_preparation("prepare.retrieval.invalid");

    // A one-byte input bound: a different class, hence a different code.
    let (fixture, _) = Fixture::for_preparation(0, 300);
    let path = fixture.root.join("options.json");
    let mut options: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    options["max_input_bytes"] = json!(1);
    write(&path, &options);
    fixture.rejected_preparation("prepare.input.limit");
}
