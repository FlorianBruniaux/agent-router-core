use assert_cmd::Command;
use router_adapter_api::{HostObservation, SnapshotValidation, ValidatedHostObservation};
use router_catalog::Catalog;
use router_policy::PhaseRouter;
use router_types::*;
use router_workflow::{PlanLimits, build_plan};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn command() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("agent-router"))
}
fn write(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn output(assert: assert_cmd::assert::Assert) -> Value {
    serde_json::from_slice(&assert.get_output().stdout).unwrap()
}

// Synthetic test contracts only. Native tests below establish OS containment,
// not provider authentication, model limits or live model availability.
#[path = "../../router-policy/tests/support/asset_fixture.rs"]
mod asset_fixture;
#[path = "support/unknown_observation.rs"]
mod unknown_observation;

fn asset_inputs(
    request: &PhaseRouteRequest,
    snapshot: &ValidatedHostObservation,
    catalog: &Catalog,
    workspace: &Path,
    source_state: &str,
    now: u64,
) -> router_policy::PhaseAssetInputs {
    let mut historical = snapshot.observation().clone();
    historical.observed_at_unix_seconds = 100;
    for evidence in &mut historical.evidence {
        evidence.observed_at_unix_seconds = 100;
    }
    let historical = ValidatedHostObservation::from_observation(
        unknown_observation::from_example(historical),
        SnapshotValidation {
            now_unix_seconds: 100,
            max_age_seconds: 300,
        },
    )
    .unwrap();
    let mut inputs = asset_fixture::inputs(
        request,
        &historical,
        catalog,
        router_policy::PhaseExecutionScope {
            workspace: workspace.to_str().unwrap().into(),
            source_state: source_state.into(),
            scope: vec!["src".into()],
        },
        &std::collections::BTreeMap::new(),
        4000,
    );
    let mut availability = inputs.availability.document().clone();
    availability.snapshot_hash = snapshot.hash().into();
    availability.observed_at_unix_seconds = now;
    availability.expires_at_unix_seconds = now + 300;
    for evidence in &mut availability.evidence {
        evidence.observed_at_unix_seconds = now;
    }
    let availability = router_asset_contracts::seal_availability(availability, snapshot).unwrap();
    inputs.availability = router_asset_contracts::ValidatedAvailability::from_json(
        &serde_json::to_vec(&availability).unwrap(),
        snapshot,
        &availability.content_hash,
        now,
    )
    .unwrap();
    inputs.policy.maximum_evidence_age_seconds = 300;
    for candidate in &request.candidates {
        let extension = inputs.requests.get_mut(&candidate.id).unwrap();
        extension
            .required_capabilities
            .extend(&request.task.required_capabilities);
        if candidate.sandbox == PhaseSandbox::WorkspaceWrite {
            extension
                .required_capabilities
                .insert(Capability::WorkspaceWrite);
            extension
                .required_mutations
                .insert(Mutation::WorkspaceWrite);
        }
    }
    inputs
}

fn write_asset_authority(root: &Path, inputs: &router_policy::PhaseAssetInputs) {
    write(
        &root.join("asset-contracts.json"),
        inputs.contracts.document(),
    );
    write(
        &root.join("asset-availability.json"),
        inputs.availability.document(),
    );
    write(&root.join("asset-policy.json"), &inputs.policy);
    write(&root.join("asset-requests.json"), &inputs.requests);
    write(
        &root.join("asset-authority.json"),
        &json!({"schema_version":1,
        "contracts":{"path":"asset-contracts.json","expected_hash":inputs.contracts.hash()},
        "availability":{"path":"asset-availability.json","expected_hash":inputs.availability.hash()},
        "policy":"asset-policy.json","requests":"asset-requests.json","execution_scope":inputs.execution_scope,
        "approved_review_digests":inputs.approved_review_digests,"metadata":null,"body_root":null}),
    );
}

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    store: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let repo = root.join("repo");
        fs::create_dir(&repo).unwrap();
        fs::create_dir(repo.join("src")).unwrap();
        fs::write(repo.join("src/a"), "base").unwrap();
        for args in [
            vec!["init", "-q"],
            vec!["add", "src"],
            vec![
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--no-gpg-sign",
                "-qm",
                "fixture",
            ],
        ] {
            assert!(
                std::process::Command::new("/usr/bin/git")
                    .arg("-C")
                    .arg(&repo)
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let source = output(
            command()
                .args(["source-state", "--workspace"])
                .arg(&repo)
                .arg("--json")
                .assert()
                .success(),
        );
        let mut request: PhaseRouteRequest = serde_json::from_str(include_str!(
            "../../../fixtures/examples/phase-request.json"
        ))
        .unwrap();
        request.phase = StageKind::Execute;
        request.task.budget.max_tokens = 30_000;
        request.restrictions.max_tokens = Some(30_000);
        request.restrictions.policy_hash.clear();
        request.restrictions.policy_hash =
            router_adapter_api::content_digest(&serde_json::to_vec(&request.restrictions).unwrap());
        request.candidates[0].estimated_tokens = 4500;
        request
            .task
            .allowed_mutations
            .remove(&Mutation::WorkspaceWrite);
        request.candidates.truncate(1);
        request.candidates[0].sandbox = PhaseSandbox::ReadOnly;
        let plan = build_plan(
            &request.task,
            WorkflowPreset::DirectSafe,
            PlanLimits::default(),
        )
        .unwrap();
        let mut snapshot: HostObservation = serde_json::from_str(include_str!(
            "../../../fixtures/examples/phase-snapshot.json"
        ))
        .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        snapshot.observed_at_unix_seconds = now;
        for e in &mut snapshot.evidence {
            e.observed_at_unix_seconds = now;
        }
        let snapshot = unknown_observation::from_example(snapshot);
        let validated = ValidatedHostObservation::from_observation(
            snapshot.clone(),
            SnapshotValidation {
                now_unix_seconds: now,
                max_age_seconds: 300,
            },
        )
        .unwrap();
        let catalog_bytes = include_bytes!("../../../fixtures/examples/phase-catalog.json");
        let catalog = Catalog::from_json(catalog_bytes).unwrap();
        let router = PhaseRouter::stable_v2();
        let assets = asset_inputs(
            &request,
            &validated,
            &catalog,
            &repo,
            source["source_state"].as_str().unwrap(),
            now,
        );
        let context = router
            .context_with_assets(request.clone(), &validated, &catalog, assets.clone(), now)
            .unwrap();
        write_asset_authority(&root, &assets);
        let receipt = router.route(&context).unwrap();
        let selected = &receipt.selected.as_ref().unwrap().candidate;
        let execution = ExecutionRequest {
            schema_version: 1,
            receipt_id: receipt.receipt_id.clone(),
            candidate_id: selected.id.clone(),
            phase: StageKind::Execute,
            host: validated.host().harness.clone(),
            model: selected.model.clone(),
            effort: selected.effort,
            workspace: repo.to_str().unwrap().into(),
            source_state: source["source_state"].as_str().unwrap().into(),
            scope: vec!["src".into()],
            sandbox: ExecutionSandbox::ReadOnly,
            required_capabilities: router
                .execution_capabilities(&context, receipt.selected.as_ref().unwrap())
                .unwrap(),
            tools: ToolSelection::Disabled,
            agent: None,
            skills: vec![],
            prompt: "private runtime prompt".into(),
            mode: ExecutionMode::Execute,
            target: ExecutionTarget::ExternalWorker,
            allow_degradation: false,
            timeout_ms: 500,
            max_output_bytes: 16384,
        };
        write(&root.join("context.json"), &request);
        write(&root.join("snapshot.json"), &snapshot);
        write(&root.join("request.json"), &execution);
        write(
            &root.join("plan.json"),
            &json!({"schema_version":1,"plan":plan,"assumptions":[]}),
        );
        fs::write(root.join("catalog.json"), catalog_bytes).unwrap();
        write(
            &root.join("definition.json"),
            &json!({"schema_version":1,"run_id":"cli-run","context":"context.json","host_snapshot":"snapshot.json","catalog":"catalog.json","policy":null,"asset_authority":"asset-authority.json","plan":"plan.json","node_id":"execute","request":"request.json"}),
        );
        write(
            &root.join("sandbox.json"),
            &json!({"schema_version":1,"programs":{"codex":"/bin/cat"},"read_roots":[],"environment_names":[],"helper":"/bin/cat","bubblewrap":null,"limits":{"cpu_seconds":1,"address_space_bytes":null,"max_open_files":64,"max_processes":64,"max_file_bytes":1048576}}),
        );
        Self {
            _temp: temp,
            store: root.join("store"),
            root,
        }
    }
    fn run(&self) -> Command {
        let mut c = command();
        c.args(["run", "--definition"])
            .arg(self.root.join("definition.json"))
            .arg("--store")
            .arg(&self.store)
            .arg("--sandbox")
            .arg(self.root.join("sandbox.json"))
            .arg("--json");
        c
    }
}

#[test]
fn legacy_review_is_readable_but_execution_requires_asset_authority_before_launch() {
    let f = Fixture::new();
    let phase: PhaseRouteRequest =
        serde_json::from_slice(&fs::read(f.root.join("context.json")).unwrap()).unwrap();
    let observation: HostObservation =
        serde_json::from_slice(&fs::read(f.root.join("snapshot.json")).unwrap()).unwrap();
    let snapshot = ValidatedHostObservation::from_observation(
        observation.clone(),
        SnapshotValidation {
            now_unix_seconds: observation.observed_at_unix_seconds,
            max_age_seconds: 300,
        },
    )
    .unwrap();
    let catalog = Catalog::from_json(&fs::read(f.root.join("catalog.json")).unwrap()).unwrap();
    let router = PhaseRouter::stable_v2();
    let context = router.context(phase, &snapshot, &catalog).unwrap();
    let receipt = router.route(&context).unwrap();
    assert_eq!(receipt.schema_version, 2);
    let mut request: ExecutionRequest =
        serde_json::from_slice(&fs::read(f.root.join("request.json")).unwrap()).unwrap();
    request.receipt_id = receipt.receipt_id;
    write(&f.root.join("request.json"), &request);
    let mut definition: Value =
        serde_json::from_slice(&fs::read(f.root.join("definition.json")).unwrap()).unwrap();
    definition
        .as_object_mut()
        .unwrap()
        .remove("asset_authority");
    write(&f.root.join("definition.json"), &definition);
    let review = output(f.run().assert().success());
    assert_eq!(review["executed"], false);
    assert_eq!(review["run"]["state"], "awaiting_approval");
    f.run()
        .args(["--approve", review["approval_digest"].as_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicates::str::contains(
            "runtime.asset_authority.required",
        ));
    assert!(!f.store.join("worktrees").exists());
    let status = output(
        command()
            .args(["status", "--store"])
            .arg(&f.store)
            .args(["--run-id", "cli-run", "--json"])
            .assert()
            .success(),
    );
    assert_eq!(status["run"]["state"], "awaiting_approval");
}

#[test]
fn review_binds_definition_and_sandbox_then_cancel_is_observable() {
    let f = Fixture::new();
    let review = output(f.run().assert().success());
    assert_eq!(review["executed"], false);
    assert_eq!(review["run"]["state"], "awaiting_approval");
    assert!(!review.to_string().contains("private runtime prompt"));
    assert_ne!(review["approval_digest"], review["run"]["approval_digest"]);
    f.run()
        .args([
            "--approve",
            review["run"]["approval_digest"].as_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicates::str::contains(
            "runtime.approval.required_or_changed",
        ));
    let mut config: Value =
        serde_json::from_slice(&fs::read(f.root.join("sandbox.json")).unwrap()).unwrap();
    config["limits"]["cpu_seconds"] = json!(2);
    write(&f.root.join("sandbox.json"), &config);
    f.run()
        .args(["--approve", review["approval_digest"].as_str().unwrap()])
        .assert()
        .code(2);
    command()
        .args(["cancel", "--store"])
        .arg(&f.store)
        .args(["--run-id", "cli-run", "--json"])
        .assert()
        .success();
    let status = output(
        command()
            .args(["status", "--store"])
            .arg(&f.store)
            .args(["--run-id", "cli-run", "--json"])
            .assert()
            .success(),
    );
    assert_eq!(status["run"]["state"], "cancelled");
    let events = output(
        command()
            .args(["events", "--store"])
            .arg(&f.store)
            .args(["--run-id", "cli-run", "--json"])
            .assert()
            .success(),
    );
    assert!(events["events"].as_array().unwrap().len() >= 3);
    command()
        .args(["artifacts", "--definition"])
        .arg(f.root.join("definition.json"))
        .arg("--store")
        .arg(&f.store)
        .args(["keep", "--json"])
        .assert()
        .success();
}

#[test]
fn explicit_fallback_receipt_survives_review_and_cannot_be_removed() {
    let f = Fixture::new();
    let mut phase: PhaseRouteRequest =
        serde_json::from_slice(&fs::read(f.root.join("context.json")).unwrap()).unwrap();
    let mut alternative = phase.candidates[0].clone();
    alternative.id = "explicit-fallback".into();
    let unavailable = std::collections::BTreeSet::from([phase.candidates[0].id.clone()]);
    phase.candidates.push(alternative);
    let snapshot: HostObservation =
        serde_json::from_slice(&fs::read(f.root.join("snapshot.json")).unwrap()).unwrap();
    let validated = ValidatedHostObservation::from_observation(
        snapshot.clone(),
        SnapshotValidation {
            now_unix_seconds: snapshot.observed_at_unix_seconds,
            max_age_seconds: 300,
        },
    )
    .unwrap();
    let catalog = Catalog::from_json(&fs::read(f.root.join("catalog.json")).unwrap()).unwrap();
    let router = PhaseRouter::stable_v2();
    let mut request: ExecutionRequest =
        serde_json::from_slice(&fs::read(f.root.join("request.json")).unwrap()).unwrap();
    let assets = asset_inputs(
        &phase,
        &validated,
        &catalog,
        Path::new(&request.workspace),
        &request.source_state,
        snapshot.observed_at_unix_seconds,
    );
    let context = router
        .context_with_assets(
            phase.clone(),
            &validated,
            &catalog,
            assets.clone(),
            snapshot.observed_at_unix_seconds,
        )
        .unwrap();
    write_asset_authority(&f.root, &assets);
    assert!(router.route(&context).unwrap().selected.is_none());
    let receipt = router.fallback(&context, &unavailable).unwrap();
    request.candidate_id = "explicit-fallback".into();
    request.receipt_id = receipt.receipt_id.clone();
    write(&f.root.join("context.json"), &phase);
    write(&f.root.join("request.json"), &request);
    write(&f.root.join("receipt.json"), &receipt);
    let mut definition: Value =
        serde_json::from_slice(&fs::read(f.root.join("definition.json")).unwrap()).unwrap();
    definition["receipt"] = json!("receipt.json");
    write(&f.root.join("definition.json"), &definition);
    let review = output(f.run().assert().success());
    assert_eq!(review["run"]["receipt_id"], receipt.receipt_id);
    command()
        .args(["artifacts", "--definition"])
        .arg(f.root.join("definition.json"))
        .arg("--store")
        .arg(&f.store)
        .args(["keep", "--json"])
        .assert()
        .success();
    definition.as_object_mut().unwrap().remove("receipt");
    write(&f.root.join("definition.json"), &definition);
    f.run()
        .args(["--approve", review["approval_digest"].as_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("runtime.receipt.invalid"));
}

#[test]
fn execution_contract_seals_instances_and_review_binds_generation() {
    let f = Fixture::new();
    let plan: Value = serde_json::from_slice(&fs::read(f.root.join("plan.json")).unwrap()).unwrap();
    let request: ExecutionRequest =
        serde_json::from_slice(&fs::read(f.root.join("request.json")).unwrap()).unwrap();
    let nodes: serde_json::Map<String,Value> = plan["plan"]["nodes"].as_array().unwrap().iter().map(|node| {
        let dependencies: serde_json::Map<String,Value> = node["dependencies"].as_array().unwrap().iter().map(|id| (id.as_str().unwrap().into(),json!("verified"))).collect();
        (node["id"].as_str().unwrap().into(),json!({"phase":if node["independent_verifier"] == true {"verify"} else {"execute"},"dependencies":dependencies}))
    }).collect();
    let contract = json!({"schema_version":1,"instance_id":"instance-a","plan_id":plan["plan"]["plan_id"],"workspace":request.workspace,"source_state":request.source_state,"nodes":nodes,"contract_sha256":""});
    write(&f.root.join("contract.json"), &contract);
    let sealed = output(
        command()
            .args(["workflow", "--plan"])
            .arg(f.root.join("plan.json"))
            .arg("--execution-contract")
            .arg(f.root.join("contract.json"))
            .args(["--seal-contract", "--json"])
            .assert()
            .success(),
    );
    assert_eq!(sealed["approved"], false);
    write(&f.root.join("contract.json"), &sealed["execution_contract"]);
    let mut definition: Value =
        serde_json::from_slice(&fs::read(f.root.join("definition.json")).unwrap()).unwrap();
    definition["workflow_contract"] = json!("contract.json");
    definition["generation"] = json!(0);
    write(&f.root.join("definition.json"), &definition);
    let review = output(f.run().assert().success());
    assert_eq!(review["run"]["workflow"]["instance_id"], "instance-a");
    assert_eq!(review["run"]["workflow"]["generation"], 0);
    definition["generation"] = json!(1);
    write(&f.root.join("definition.json"), &definition);
    f.run()
        .args(["--approve", review["approval_digest"].as_str().unwrap()])
        .assert()
        .code(7)
        .stderr("{\"schema_version\":1,\"error\":\"runtime.integrity\"}\n");
}

/// Rewrites the fixture into the execute node of a plan/execute/verify
/// workflow, so an approved run stays queued behind its prerequisites and
/// never reaches a native launch.
fn queue_behind_dependencies(f: &Fixture) {
    let context: PhaseRouteRequest =
        serde_json::from_slice(&fs::read(f.root.join("context.json")).unwrap()).unwrap();
    let plan = build_plan(
        &context.task,
        WorkflowPreset::PlanExecuteVerify,
        PlanLimits::default(),
    )
    .unwrap();
    let mut request: ExecutionRequest =
        serde_json::from_slice(&fs::read(f.root.join("request.json")).unwrap()).unwrap();
    request.timeout_ms = 100;
    write(&f.root.join("request.json"), &request);
    let contract = router_workflow::seal_execution_contract(
        WorkflowExecutionContract {
            schema_version: 1,
            instance_id: "queued-instance".into(),
            plan_id: plan.plan_id.clone(),
            workspace: request.workspace,
            source_state: request.source_state,
            nodes: plan
                .nodes
                .iter()
                .map(|node| {
                    (
                        node.id.clone(),
                        NodeExecutionContract {
                            phase: match node.id.as_str() {
                                "plan" => StageKind::Plan,
                                "verify" => StageKind::Verify,
                                _ => StageKind::Execute,
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
    write(&f.root.join("plan.json"), &plan);
    write(&f.root.join("contract.json"), &contract);
    let mut definition: Value =
        serde_json::from_slice(&fs::read(f.root.join("definition.json")).unwrap()).unwrap();
    definition["workflow_contract"] = json!("contract.json");
    definition["generation"] = json!(0);
    write(&f.root.join("definition.json"), &definition);
}

#[test]
fn approved_dependency_wait_releases_cli_owner_and_stays_resumable() {
    let f = Fixture::new();
    queue_behind_dependencies(&f);
    let review = output(f.run().assert().success());
    let approval = review["approval_digest"].as_str().unwrap();
    for _ in 0..2 {
        let queued = output(
            f.run()
                .args(["--approve", approval])
                .timeout(std::time::Duration::from_secs(10))
                .assert()
                .code(3),
        );
        assert_eq!(queued["run"]["state"], "queued");
        assert_eq!(queued["dependencies_pending"], true);
        assert_eq!(queued["executed"], false);
        // This operation needs the owner lock; it would fail if run still held it.
        command()
            .args(["artifacts", "--definition"])
            .arg(f.root.join("definition.json"))
            .arg("--store")
            .arg(&f.store)
            .args(["keep", "--json"])
            .assert()
            .success();
    }
}

#[test]
fn memory_limit_omission_is_not_implicit_authorization_to_drop_it() {
    let f = Fixture::new();
    let mut config: Value =
        serde_json::from_slice(&fs::read(f.root.join("sandbox.json")).unwrap()).unwrap();
    config["limits"]
        .as_object_mut()
        .unwrap()
        .remove("address_space_bytes");
    write(&f.root.join("sandbox.json"), &config);
    f.run()
        .assert()
        .code(2)
        .stderr(predicates::str::contains("request.json.invalid"));
    assert!(!f.store.exists());
}

#[test]
fn status_of_missing_store_does_not_create_it() {
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("missing");
    command()
        .args(["status", "--store"])
        .arg(&store)
        .args(["--run-id", "none", "--json"])
        .assert()
        .code(2);
    assert!(!store.exists());
}

#[test]
fn prepare_assembles_private_request_bundle_without_running_or_overwriting() {
    use std::collections::{BTreeMap, BTreeSet};
    let f = Fixture::new();
    let request: ExecutionRequest =
        serde_json::from_slice(&fs::read(f.root.join("request.json")).unwrap()).unwrap();
    let template = router_workflow::seal_prompt(PromptTemplate {
        schema_version: 1,
        id: "cli-template".into(),
        version: "v1".into(),
        template: "Report ${subject}".into(),
        variables: BTreeMap::from([("subject".into(), PromptVariableType::Text)]),
        compatible_hosts: BTreeSet::from(["codex".into()]),
        compatible_models: BTreeSet::from([request.model.clone()]),
        max_rendered_bytes: 4096,
        output_contract: "Evidence".into(),
        content_sha256: String::new(),
    })
    .unwrap();
    write(&f.root.join("prompt.json"), &template);
    let body = fs::read(f.root.join("prompt.json")).unwrap();
    let metadata = router_retrieval::MetadataDocument {
        schema_version: "1".into(),
        catalog_version: "fixture".into(),
        assets: vec![router_retrieval::AssetMetadata {
            id: "cli-template".into(),
            kind: router_retrieval::AssetKind::Prompt,
            trust: SkillTrust::TrustedLocal,
            task_kinds: vec![],
            triggers: vec![],
            description: "Report".into(),
            examples: vec![],
            tags: vec![],
            paths: vec![],
            anti_triggers: vec![],
            body: Some(router_retrieval::BodyReference {
                path: "prompt.json".into(),
                sha256: router_adapter_api::content_digest(&body),
            }),
        }],
    };
    write(&f.root.join("metadata.json"), &metadata);
    let index = output(
        command()
            .args(["index", "--metadata"])
            .arg(f.root.join("metadata.json"))
            .arg("--catalog")
            .arg(f.root.join("catalog.json"))
            .arg("--json")
            .assert()
            .success(),
    );
    write(&f.root.join("index.json"), &index);
    write(
        &f.root.join("variables.json"),
        &BTreeMap::from([(
            "subject".to_string(),
            PromptValue::Text("private input marker".into()),
        )]),
    );
    write(
        &f.root.join("options.json"),
        &json!({"schema_version":1,"workspace":request.workspace,"source_state":request.source_state,"target":"external_worker","allow_degradation":false,"timeout_ms":500,"max_output_bytes":16384,"max_input_bytes":65536,"now_unix_seconds":0,"max_snapshot_age_seconds":300}),
    );
    write(
        &f.root.join("prepare.json"),
        &json!({"schema_version":1,"run_id":"prepared-run","context":"context.json","host_snapshot":"snapshot.json","catalog":"catalog.json","policy":null,"policy_store":null,"asset_authority":"asset-authority.json","plan":"plan.json","node_id":"execute","metadata":"index.json","body_root":".","template":"prompt.json","variables":"variables.json","options":"options.json"}),
    );
    let directory = f.root.join("prepared");
    let preview = output(
        command()
            .args(["prepare", "--manifest"])
            .arg(f.root.join("prepare.json"))
            .arg("--output-directory")
            .arg(&directory)
            .arg("--json")
            .assert()
            .success(),
    );
    assert_eq!(preview["executed"], false);
    assert_eq!(preview["approved"], false);
    assert!(!preview.to_string().contains("private input marker"));
    let prepared: ExecutionRequest =
        serde_json::from_slice(&fs::read(directory.join("request.json")).unwrap()).unwrap();
    assert!(prepared.prompt.contains("private input marker"));
    let receipt: PhaseReceipt =
        serde_json::from_slice(&fs::read(directory.join("receipt.json")).unwrap()).unwrap();
    assert_eq!(receipt.schema_version, 3);
    let prepared_definition: Value =
        serde_json::from_slice(&fs::read(directory.join("definition.json")).unwrap()).unwrap();
    assert!(prepared_definition["asset_authority"].is_string());
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(directory.join("request.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    command()
        .args(["prepare", "--manifest"])
        .arg(f.root.join("prepare.json"))
        .arg("--output-directory")
        .arg(&directory)
        .arg("--json")
        .assert()
        .code(2);
    let review = output(
        command()
            .args(["run", "--definition"])
            .arg(directory.join("definition.json"))
            .arg("--store")
            .arg(&f.store)
            .arg("--sandbox")
            .arg(f.root.join("sandbox.json"))
            .arg("--json")
            .assert()
            .success(),
    );
    assert_eq!(review["run"]["state"], "awaiting_approval");
    let feedback_store = f.root.join("policies");
    let active = router_feedback::FeedbackStore::open(&feedback_store)
        .unwrap()
        .register_baseline(
            PhasePolicy::default(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(f.root.join("prepare.json")).unwrap()).unwrap();
    manifest["policy_store"] = json!(feedback_store);
    write(&f.root.join("prepare.json"), &manifest);
    let active_directory = f.root.join("prepared-active");
    command()
        .args(["prepare", "--manifest"])
        .arg(f.root.join("prepare.json"))
        .arg("--output-directory")
        .arg(&active_directory)
        .arg("--json")
        .assert()
        .success();
    let definition_path = active_directory.join("definition.json");
    let mut definition: Value =
        serde_json::from_slice(&fs::read(&definition_path).unwrap()).unwrap();
    assert!(definition["policy"].is_null());
    assert_eq!(definition["policy_artifact_id"], active.artifact_id);
    let active_review = output(
        command()
            .args(["run", "--definition"])
            .arg(&definition_path)
            .arg("--store")
            .arg(&f.store)
            .arg("--sandbox")
            .arg(f.root.join("sandbox.json"))
            .arg("--json")
            .assert()
            .success(),
    );
    definition["policy_artifact_id"] = json!("0".repeat(64));
    write(&definition_path, &definition);
    command()
        .args(["run", "--definition"])
        .arg(&definition_path)
        .arg("--store")
        .arg(&f.store)
        .arg("--sandbox")
        .arg(f.root.join("sandbox.json"))
        .arg("--json")
        .assert()
        .code(2)
        .stderr(predicates::str::contains("policy.active.changed"));
    definition["policy"] = json!("policy.json");
    definition["policy_store"] = Value::Null;
    definition["policy_artifact_id"] = Value::Null;
    write(&definition_path, &definition);
    command()
        .args(["run", "--definition"])
        .arg(&definition_path)
        .arg("--store")
        .arg(&f.store)
        .arg("--sandbox")
        .arg(f.root.join("sandbox.json"))
        .args([
            "--approve",
            active_review["approval_digest"].as_str().unwrap(),
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicates::str::contains(
            "runtime.approval.required_or_changed",
        ));
}

fn fail_run(f: &Fixture) {
    // Force the persisted run into a retryable failure. Real failures need a
    // native sandbox that is unavailable to ordinary tests.
    let db = rusqlite::Connection::open(f.store.join("runtime.sqlite3")).unwrap();
    let changed = db
        .execute(
            "UPDATE runs SET summary=json_set(summary,'$.state','failed','$.failure','crash','$.attempts',1)",
            [],
        )
        .unwrap();
    assert_eq!(changed, 1);
}
fn store_state(f: &Fixture) -> (Vec<u8>, Value, Value) {
    let run = |name: &str| {
        output(
            command()
                .args([name, "--store"])
                .arg(&f.store)
                .args(["--run-id", "cli-run", "--json"])
                .assert()
                .success(),
        )
    };
    (
        fs::read(f.store.join("runtime.sqlite3")).unwrap(),
        run("status"),
        run("events"),
    )
}

#[test]
fn retry_without_approve_is_a_read_only_preview() {
    let f = Fixture::new();
    let review = output(f.run().assert().success());
    fail_run(&f);
    let before = store_state(&f);
    assert_eq!(before.1["run"]["state"], "failed");
    let preview = output(f.run().arg("--retry").assert().success());
    assert_eq!(preview["executed"], false);
    assert_eq!(preview["run"]["state"], "awaiting_approval");
    assert_ne!(preview["approval_digest"], review["approval_digest"]);
    assert_eq!(store_state(&f), before);
}

#[test]
fn retry_with_a_wrong_digest_is_refused_and_changes_nothing() {
    let f = Fixture::new();
    let review = output(f.run().assert().success());
    fail_run(&f);
    let before = store_state(&f);
    for wrong in [
        review["approval_digest"].as_str().unwrap().to_owned(),
        "0".repeat(64),
    ] {
        f.run()
            .args(["--retry", "--approve", &wrong])
            .assert()
            .code(2)
            .stderr(predicates::str::contains(
                "runtime.approval.required_or_changed",
            ));
    }
    assert_eq!(store_state(&f), before);
}

#[test]
fn plain_approve_on_a_failed_run_requires_retry_approve() {
    let f = Fixture::new();
    let review = output(f.run().assert().success());
    fail_run(&f);
    let before = store_state(&f);
    f.run()
        .args(["--approve", review["approval_digest"].as_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("runtime.retry.use_retry_approve"));
    assert_eq!(store_state(&f), before);
}

#[test]
fn retry_approve_with_the_preview_digest_performs_the_transition() {
    let f = Fixture::new();
    output(f.run().assert().success());
    fail_run(&f);
    let preview = output(f.run().arg("--retry").assert().success());
    let digest = preview["approval_digest"].as_str().unwrap();
    // Execution itself needs a native sandbox; the transition is persisted first.
    let outcome = f
        .run()
        .args(["--retry", "--approve", digest])
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&outcome.stderr).contains("runtime.approval.required_or_changed")
    );
    let (_, status, events) = store_state(&f);
    assert_ne!(status["run"]["state"], "failed");
    assert!(events.to_string().contains("retry.awaiting_fresh_approval"));
}

#[test]
fn retry_approve_with_a_digest_from_before_the_run_changed_is_refused() {
    let f = Fixture::new();
    output(f.run().assert().success());
    fail_run(&f);
    let preview = output(f.run().arg("--retry").assert().success());
    let old = preview["approval_digest"].as_str().unwrap().to_owned();
    rusqlite::Connection::open(f.store.join("runtime.sqlite3"))
        .unwrap()
        .execute(
            "UPDATE runs SET summary=json_set(summary,'$.attempts',0)",
            [],
        )
        .unwrap();
    let before = store_state(&f);
    f.run()
        .args(["--retry", "--approve", &old])
        .assert()
        .code(2)
        .stderr(predicates::str::contains(
            "runtime.approval.required_or_changed",
        ));
    assert_eq!(store_state(&f), before);
}

#[test]
fn approval_binds_environment_values_without_exposing_secrets() {
    let f = Fixture::new();
    queue_behind_dependencies(&f);
    let mut config: Value =
        serde_json::from_slice(&fs::read(f.root.join("sandbox.json")).unwrap()).unwrap();
    config["environment_names"] = json!(["HOME", "SSL_CERT_FILE", "OPENAI_API_KEY"]);
    write(&f.root.join("sandbox.json"), &config);
    let home = f.root.join("home-a");
    let certificates = f.root.join("certificates.pem");
    let secret = "sk-fixture-secret-value-1";
    let with = |home: &Path, key: Option<&str>, certificates: Option<&Path>| {
        let mut command = f.run();
        command.env("HOME", home);
        match key {
            Some(value) => command.env("OPENAI_API_KEY", value),
            None => command.env_remove("OPENAI_API_KEY"),
        };
        match certificates {
            Some(path) => command.env("SSL_CERT_FILE", path),
            None => command.env_remove("SSL_CERT_FILE"),
        };
        command
    };
    let review = with(&home, Some(secret), Some(&certificates))
        .output()
        .unwrap();
    assert!(review.status.success(), "{review:?}");
    let digest = serde_json::from_slice::<Value>(&review.stdout).unwrap()["approval_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    // The first secret binding creates the store's private approval key once.
    let key_path = f.store.join("approval.key");
    let key = fs::read(&key_path).unwrap();
    assert_eq!(key.len(), 32);
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::symlink_metadata(&key_path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let again = with(&home, Some(secret), Some(&certificates))
        .output()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&again.stdout).unwrap()["approval_digest"],
        digest.as_str(),
        "same environment and same key give the same digest"
    );
    assert_eq!(fs::read(&key_path).unwrap(), key, "the key is reused");
    let mut observed = vec![review, again];
    for changed in [
        with(&f.root.join("home-b"), Some(secret), Some(&certificates)),
        with(
            &home,
            Some("sk-fixture-secret-value-2"),
            Some(&certificates),
        ),
        with(&home, None, Some(&certificates)),
        with(&home, Some(secret), Some(&f.root.join("other.pem"))),
        with(&home, Some(secret), None),
    ] {
        let mut changed = changed;
        let outcome = changed.args(["--approve", &digest]).output().unwrap();
        assert_eq!(outcome.status.code(), Some(2), "{outcome:?}");
        assert_eq!(
            outcome.stderr,
            b"{\"schema_version\":1,\"error\":\"runtime.approval.required_or_changed\"}\n"
        );
        observed.push(outcome);
    }
    // Positive control: the unchanged environment passes the approval check
    // and queues behind its prerequisites without launching.
    let queued = with(&home, Some(secret), Some(&certificates))
        .args(["--approve", &digest])
        .timeout(std::time::Duration::from_secs(10))
        .output()
        .unwrap();
    assert_eq!(queued.status.code(), Some(3), "{queued:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&queued.stdout).unwrap()["dependencies_pending"],
        true
    );
    observed.push(queued);
    // Another key changes the digest, and the original key restores it.
    let approve = || {
        with(&home, Some(secret), Some(&certificates))
            .args(["--approve", &digest])
            .timeout(std::time::Duration::from_secs(10))
            .output()
            .unwrap()
    };
    fs::write(&key_path, [7u8; 32]).unwrap();
    let rekeyed = approve();
    assert_eq!(rekeyed.status.code(), Some(2), "{rekeyed:?}");
    assert_eq!(
        rekeyed.stderr,
        b"{\"schema_version\":1,\"error\":\"runtime.approval.required_or_changed\"}\n"
    );
    fs::write(&key_path, &key).unwrap();
    assert_eq!(approve().status.code(), Some(3));
    // Deleting the key creates a new one: pending approvals become stale.
    fs::remove_file(&key_path).unwrap();
    let deleted = approve();
    assert_eq!(deleted.status.code(), Some(2), "{deleted:?}");
    assert_ne!(fs::read(&key_path).unwrap(), key);
    observed.extend([rekeyed, deleted]);
    // Neither the value nor its per-variable HMAC is ever printed.
    let mac = {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
        mac.update(b"agent-router.approval.environment-hmac.v1\0OPENAI_API_KEY\0");
        mac.update(secret.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    };
    for outcome in &observed {
        for stream in [&outcome.stdout, &outcome.stderr] {
            assert!(!String::from_utf8_lossy(stream).contains(&mac));
        }
    }
    for outcome in &observed {
        for stream in [&outcome.stdout, &outcome.stderr] {
            let text = String::from_utf8_lossy(stream);
            assert!(!text.contains("sk-fixture-secret-value"), "{text}");
        }
    }
    let events = output(
        command()
            .args(["events", "--store"])
            .arg(&f.store)
            .args(["--run-id", "cli-run", "--json"])
            .assert()
            .success(),
    );
    assert!(!events.to_string().contains("sk-fixture-secret-value"));
    assert!(!events.to_string().contains(&mac));
}

#[test]
fn definition_naming_policy_file_and_policy_store_is_refused() {
    let f = Fixture::new();
    // A valid policy file: before the refusal, the store was silently ignored.
    write(
        &f.root.join("policy.json"),
        &router_types::PhasePolicy::default(),
    );
    let mut definition: Value =
        serde_json::from_slice(&fs::read(f.root.join("definition.json")).unwrap()).unwrap();
    definition["policy"] = json!("policy.json");
    definition["policy_store"] = json!("feedback");
    definition["policy_artifact_id"] = json!("artifact-1");
    write(&f.root.join("definition.json"), &definition);
    f.run()
        .assert()
        .code(2)
        .stdout(predicates::str::is_empty())
        .stderr("{\"schema_version\":1,\"error\":\"policy.composition.denied\"}\n");
    assert!(!f.store.exists());
}

#[test]
fn broken_event_chain_exits_with_the_integrity_class() {
    let f = Fixture::new();
    output(f.run().assert().success());
    rusqlite::Connection::open(f.store.join("runtime.sqlite3"))
        .unwrap()
        .execute_batch(
            "DROP TRIGGER events_no_update;
             UPDATE events SET detail='tampered' WHERE sequence=(SELECT MIN(sequence) FROM events);",
        )
        .unwrap();
    command()
        .args(["status", "--store"])
        .arg(&f.store)
        .args(["--run-id", "cli-run", "--json"])
        .assert()
        .code(7)
        .stdout(predicates::str::is_empty())
        .stderr("{\"schema_version\":1,\"error\":\"runtime.integrity\"}\n");
}

#[test]
fn sqlite_contention_exits_with_the_retryable_class() {
    let f = Fixture::new();
    output(f.run().assert().success());
    let holder = rusqlite::Connection::open(f.store.join("runtime.sqlite3")).unwrap();
    holder.execute_batch("BEGIN IMMEDIATE").unwrap();
    let cancel = || {
        let mut command = command();
        command
            .args(["cancel", "--store"])
            .arg(&f.store)
            .args(["--run-id", "cli-run", "--json"]);
        command
    };
    cancel()
        .assert()
        .code(5)
        .stdout(predicates::str::is_empty())
        .stderr("{\"schema_version\":1,\"error\":\"runtime.busy\"}\n");
    holder.execute_batch("ROLLBACK").unwrap();
    // Relaunching once the contention is gone succeeds.
    cancel().assert().success();
}

#[test]
fn a_store_database_that_is_not_sqlite_exits_with_the_integrity_class() {
    let f = Fixture::new();
    output(f.run().assert().success());
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(f.store.join(format!("runtime.sqlite3{suffix}")));
    }
    // Overwriting keeps the private 0600 mode; only the content is replaced.
    let noise: Vec<u8> = (0..8192u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    fs::write(f.store.join("runtime.sqlite3"), noise).unwrap();
    command()
        .args(["status", "--store"])
        .arg(&f.store)
        .args(["--run-id", "cli-run", "--json"])
        .assert()
        .code(7)
        .stdout(predicates::str::is_empty())
        .stderr("{\"schema_version\":1,\"error\":\"runtime.storage_corrupt\"}\n");
}

#[test]
fn observation_reads_one_redacted_snapshot_without_changing_legacy_state() {
    let f = Fixture::new();
    f.run().assert().success();
    let legacy = |verb| {
        command()
            .args([verb, "--store"])
            .arg(&f.store)
            .args(["--run-id", "cli-run", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    };
    let before_status = legacy("status");
    let before_events = legacy("events");
    let read = || {
        command()
            .args(["observe", "--store"])
            .arg(&f.store)
            .args(["--run-id", "cli-run", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    };
    let first = read();
    assert_eq!(first, read());
    let report: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["known"]["state"], "awaiting_approval");
    assert_eq!(report["known"]["attempts"], 0);
    assert_eq!(report["unknown"]["observed_model"], "unknown");
    assert_eq!(report["unknown"]["duration"], "unknown");
    assert_eq!(report["completeness"]["journal"], "complete");
    assert_eq!(report["completeness"]["external_observations"], "unknown");
    assert_eq!(report["completeness"]["detail"], "redacted");
    let human = command()
        .args(["observe", "--store"])
        .arg(&f.store)
        .args(["--run-id", "cli-run"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let human = String::from_utf8(human).unwrap();
    assert!(human.contains(report["snapshot_sha256"].as_str().unwrap()));
    assert!(human.contains("awaiting_approval"));
    assert!(human.contains("Duration: unknown"));
    assert!(human.lines().count() <= 32);
    for text in [String::from_utf8(first).unwrap(), human] {
        assert!(!text.contains("private runtime prompt"));
        assert!(!text.contains("cli-run"));
        assert!(!text.contains(f.root.to_str().unwrap()));
    }
    assert_eq!(before_status, legacy("status"));
    assert_eq!(before_events, legacy("events"));
}

#[test]
fn observation_refuses_absent_store_without_creating_it() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing");
    let result = command()
        .args(["observe", "--store"])
        .arg(&missing)
        .args(["--run-id", "missing", "--json"])
        .assert()
        .code(2)
        .get_output()
        .clone();
    assert!(result.stdout.is_empty());
    let error: Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(error["error"], "runtime.io");
    assert!(!missing.exists());
}

#[test]
fn observation_refuses_corrupt_journal_without_leaking_private_detail() {
    let f = Fixture::new();
    f.run().assert().success();
    let conn = rusqlite::Connection::open(f.store.join("runtime.sqlite3")).unwrap();
    conn.execute_batch(
        "DROP TRIGGER events_no_update; UPDATE events SET detail='observation-secret-canary';",
    )
    .unwrap();
    for json in [true, false] {
        let mut cmd = command();
        cmd.args(["observe", "--store"])
            .arg(&f.store)
            .args(["--run-id", "cli-run"]);
        if json {
            cmd.arg("--json");
        }
        let result = cmd.assert().code(7).get_output().clone();
        assert!(result.stdout.is_empty());
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert!(stderr.contains("runtime.integrity"));
        assert!(!stderr.contains("observation-secret-canary"));
    }
}

#[test]
fn observation_schema_version_is_explicit_and_default_stays_v1() {
    let f = Fixture::new();
    f.run().assert().success();
    let read = |version: Option<&str>| {
        let mut cmd = command();
        cmd.args(["observe", "--store"])
            .arg(&f.store)
            .args(["--run-id", "cli-run", "--json"]);
        if let Some(version) = version {
            cmd.args(["--schema-version", version]);
        }
        cmd.assert().success().get_output().stdout.clone()
    };
    assert_eq!(read(None), read(Some("1")));
    let v2: Value = serde_json::from_slice(&read(Some("2"))).unwrap();
    assert_eq!(v2["schema_version"], 2);
    assert_eq!(v2["attempts"], serde_json::json!([]));
    assert_eq!(v2["unknown"]["transport"], "unknown");
    let v3: Value = serde_json::from_slice(&read(Some("3"))).unwrap();
    assert_eq!(v3["schema_version"], 3);
    assert_eq!(v3["attempts"], serde_json::json!([]));
    assert_eq!(v3["unknown"]["duration"], "unknown");
    assert_eq!(read(None), read(Some("1")));
    command()
        .args(["observe", "--store"])
        .arg(&f.store)
        .args(["--run-id", "cli-run", "--schema-version", "4", "--json"])
        .assert()
        .code(2);
}
