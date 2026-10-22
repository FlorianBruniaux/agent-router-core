//! Lot-9 CLI boundary: a local declaration is authenticated but never a host
//! observation. The executable is synthetic; these tests never call a provider.
#![cfg(all(feature = "claude", any(target_os = "macos", target_os = "linux")))]

#[path = "support/attestation_fixture.rs"]
mod attestation_fixture;
#[path = "support/native_fixture.rs"]
mod native_fixture;
use attestation_fixture::{AttestationFixture, RuntimeAttestationFixture, permissions, rejected};
use native_fixture::{checked, command, write};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

#[test]
fn issuer_records_only_a_declared_workspace_capability_and_inspect_keeps_unknown() {
    let fixture = AttestationFixture::new();
    let original_snapshot = fs::read(&fixture.snapshot).unwrap();
    let granted = checked(&mut fixture.attest(), 0);
    assert_eq!(granted["tier"], "attested");
    assert_eq!(granted["action"], "grant");
    assert_eq!(granted["capability"], "workspace_write");
    assert_eq!(granted["sequence"], 1);
    assert_eq!(granted["executed"], false);
    assert_eq!(granted["content_sha256"].as_str().unwrap().len(), 64);
    assert!(
        granted["expires_at_unix_seconds"].as_u64().unwrap()
            > granted["created_at_unix_seconds"].as_u64().unwrap()
    );
    assert_eq!(permissions(&fixture.files.store), 0o700);
    assert_eq!(
        permissions(&fixture.files.store.join("approval.key")),
        0o600
    );
    assert_eq!(fs::read(&fixture.snapshot).unwrap(), original_snapshot);
    fixture.assert_no_host_invocation();

    let observed = checked(&mut fixture.inspect(), 0);
    assert_eq!(observed["schema_version"], 2);
    assert_eq!(
        observed["capabilities"]["workspace_write"]["support"],
        "unknown"
    );
    assert!(
        !observed["host"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|capability| capability == "workspace_write")
    );
    assert_eq!(observed["attestations"]["schema_version"], 1);
    let entry = &observed["attestations"]["entries"][0];
    assert_eq!(entry["record_id"], granted["record_id"]);
    assert_eq!(entry["content_sha256"], granted["content_sha256"]);
    assert_eq!(entry["capability"], "workspace_write");
    fixture.assert_no_host_invocation();
}

#[test]
fn network_declaration_is_refused_before_any_store_or_host_effect() {
    let fixture = AttestationFixture::new();
    let mut request = fixture.request_value();
    request["capability"] = json!("network");
    request["network"] = json!(true);
    write(&fixture.request, &request);
    rejected(
        &mut fixture.attest(),
        "capability.attestation.network_admission_required",
    );
    assert!(!fixture.files.store.exists());
    fixture.assert_no_host_invocation();
}

#[test]
fn revocation_remains_possible_after_the_declared_binary_is_deleted() {
    let fixture = AttestationFixture::new();
    let grant = checked(&mut fixture.attest(), 0);
    fs::remove_file(&fixture.program).unwrap();
    let revoked = checked(
        command()
            .args(["capability", "revoke", "--store"])
            .arg(&fixture.files.store)
            .arg("--record-id")
            .arg(grant["record_id"].as_str().unwrap())
            .args([
                "--operator-label",
                "synthetic-operator",
                "--reason",
                "Fixture executable removed",
                "--json",
            ]),
        0,
    );
    assert_eq!(revoked["tier"], "attested");
    assert_eq!(revoked["action"], "revoke");
    assert_eq!(revoked["capability"], "workspace_write");
    assert_eq!(revoked["sequence"], 2);
    assert_eq!(revoked["executed"], false);
    assert_eq!(revoked["expires_at_unix_seconds"], Value::Null);
    fixture.assert_no_host_invocation();
}

#[test]
fn default_and_empty_policies_refuse_while_explicit_policy_selects_attested() {
    let fixture = AttestationFixture::for_routing();
    let granted = checked(&mut fixture.attest(), 0);
    fixture.attach_grant(&granted);
    let default = checked(&mut fixture.route(None), 3);
    assert!(default["selected"].is_null());
    let empty_policy = fixture.policy(false);
    let empty = checked(&mut fixture.route(Some(&empty_policy)), 3);
    assert!(empty["selected"].is_null());

    let allowed_policy = fixture.policy(true);
    let allowed = checked(&mut fixture.route(Some(&allowed_policy)), 0);
    assert_eq!(allowed["schema_version"], 6);
    assert_eq!(allowed["selected"]["candidate"]["id"], "primary");
    assert_eq!(
        allowed["capability_evidence"]["workspace_write"]["tier"],
        "attested"
    );
    assert_eq!(
        allowed["capability_evidence"]["workspace_write"]["proof_sha256"],
        granted["content_sha256"]
    );
    assert_ne!(allowed["policy_hash"], default["policy_hash"]);
    fixture.assert_no_host_invocation();
}

#[test]
fn review_digest_is_invalid_after_policy_change_or_attestation_revoke() {
    let fixture = RuntimeAttestationFixture::new(false);
    let digest = fixture.files.review();
    let mut policy: Value = serde_json::from_slice(&fs::read(&fixture.policy).unwrap()).unwrap();
    policy["accepted_attestations"] = json!([]);
    write(&fixture.policy, &policy);
    rejected(
        fixture.files.run().args(["--approve", &digest]),
        "runtime.receipt.invalid",
    );
    assert!(!fixture.files.store.join("worktrees").exists());
    assert!(!fixture.files.repo.join("src/attested-run-marker").exists());

    policy["accepted_attestations"] = json!(["workspace_write"]);
    write(&fixture.policy, &policy);
    let fresh = fixture.files.review();
    let revoke = fixture.revoke();
    assert_eq!(revoke["action"], "revoke");
    rejected(
        fixture.files.run().args(["--approve", &fresh]),
        "capability.evidence.revoked",
    );
    assert!(!fixture.files.store.join("worktrees").exists());
    assert!(!fixture.files.repo.join("src/attested-run-marker").exists());
}

#[test]
#[ignore = "requires native sandbox and built helper; synthetic Claude script only"]
fn approved_attested_workspace_run_executes_only_the_synthetic_private_worker() {
    let fixture = RuntimeAttestationFixture::new(true);
    let digest = fixture.files.review();
    let done = checked(fixture.files.run().args(["--approve", &digest]), 0);
    assert_eq!(done["completion"]["run"]["state"], "verifying");
    assert_eq!(done["completion"]["run"]["attempts"], 1);
    let worktree = done["completion"]["run"]["worktree"].as_str().unwrap();
    assert_eq!(
        fs::read(std::path::Path::new(worktree).join("src/attested-run-marker")).unwrap(),
        b"attested"
    );
    assert!(!fixture.files.repo.join("src/attested-run-marker").exists());
}

#[test]
fn prepare_exports_the_same_attested_receipt_and_reviewable_private_bundle() {
    use router_types::{PromptTemplate, PromptValue, PromptVariableType, SkillTrust};
    let fixture = RuntimeAttestationFixture::new(false);
    let root = &fixture.files.root;
    let execution: router_types::ExecutionRequest =
        serde_json::from_slice(&fs::read(root.join("request.json")).unwrap()).unwrap();
    let template = router_workflow::seal_prompt(PromptTemplate {
        schema_version: 1,
        id: "attested-template".into(),
        version: "v1".into(),
        template: "Report ${subject}".into(),
        variables: BTreeMap::from([("subject".into(), PromptVariableType::Text)]),
        compatible_hosts: BTreeSet::from(["claude-code".into()]),
        compatible_models: BTreeSet::from([execution.model.clone()]),
        max_rendered_bytes: 4096,
        output_contract: "Evidence".into(),
        content_sha256: String::new(),
    })
    .unwrap();
    write(&root.join("prompt.json"), &template);
    let catalog =
        router_catalog::Catalog::from_json(&fs::read(root.join("catalog.json")).unwrap()).unwrap();
    let metadata = router_retrieval::MetadataDocument {
        schema_version: "1".into(),
        catalog_version: catalog.version().into(),
        assets: vec![router_retrieval::AssetMetadata {
            id: template.id.clone(),
            kind: router_retrieval::AssetKind::Prompt,
            trust: SkillTrust::TrustedLocal,
            task_kinds: vec![],
            triggers: vec![],
            description: "Synthetic attested prompt".into(),
            examples: vec![],
            tags: vec![],
            paths: vec![],
            anti_triggers: vec![],
            body: Some(router_retrieval::BodyReference {
                path: "prompt.json".into(),
                sha256: router_adapter_api::content_digest(
                    &fs::read(root.join("prompt.json")).unwrap(),
                ),
            }),
        }],
    };
    write(&root.join("metadata.json"), &metadata);
    let index = checked(
        command()
            .args(["index", "--metadata"])
            .arg(root.join("metadata.json"))
            .arg("--catalog")
            .arg(root.join("catalog.json"))
            .arg("--json"),
        0,
    );
    write(&root.join("index.json"), &index);
    write(
        &root.join("variables.json"),
        &BTreeMap::from([(
            "subject",
            PromptValue::Text("private attested fixture".into()),
        )]),
    );
    write(
        &root.join("options.json"),
        &json!({"schema_version":1,"workspace":fixture.files.repo,
            "source_state":execution.source_state,"target":"external_worker",
            "allow_degradation":false,"timeout_ms":500,"max_output_bytes":16384,
            "max_input_bytes":65536,"now_unix_seconds":0,"max_snapshot_age_seconds":300}),
    );
    write(
        &root.join("prepare.json"),
        &json!({"schema_version":1,"run_id":"attested-prepared","context":"context.json",
            "host_snapshot":"snapshot.json","catalog":"catalog.json",
            "capability_store":fixture.files.store,"execution_config":"sandbox.json",
            "policy":"policy-allow.json","asset_authority":"asset-authority.json",
            "plan":"plan.json","node_id":"execute","metadata":"index.json",
            "body_root":".","template":"prompt.json","variables":"variables.json",
            "options":"options.json"}),
    );
    let output = root.join("attested-prepared");
    let preview = checked(
        command()
            .args(["prepare", "--manifest"])
            .arg(root.join("prepare.json"))
            .arg("--output-directory")
            .arg(&output)
            .arg("--json"),
        0,
    );
    assert_eq!(preview["executed"], false);
    assert_eq!(preview["approved"], false);
    let receipt: Value =
        serde_json::from_slice(&fs::read(output.join("receipt.json")).unwrap()).unwrap();
    assert_eq!(receipt["schema_version"], 6);
    assert_eq!(
        receipt["capability_evidence"]["workspace_write"]["tier"],
        "attested"
    );
    let snapshot: Value =
        serde_json::from_slice(&fs::read(output.join("snapshot.json")).unwrap()).unwrap();
    assert_eq!(snapshot["schema_version"], 2);
    assert_eq!(
        snapshot["capabilities"]["workspace_write"]["support"],
        "unknown"
    );
    let review = checked(
        command()
            .args(["run", "--definition"])
            .arg(output.join("definition.json"))
            .arg("--store")
            .arg(&fixture.files.store)
            .arg("--sandbox")
            .arg(root.join("sandbox.json"))
            .arg("--json"),
        0,
    );
    assert_eq!(review["run"]["state"], "awaiting_approval");
    assert!(!fixture.files.store.join("worktrees").exists());
    assert!(!fixture.files.repo.join("src/attested-run-marker").exists());
}

#[test]
fn offline_replay_and_comparison_distinguish_authenticated_from_unverified_attestations() {
    let fixture = AttestationFixture::for_routing();
    let grant = checked(&mut fixture.attest(), 0);
    fixture.attach_grant(&grant);
    let policy_path = fixture.policy(true);
    let root = &fixture.files.root;
    let policy: Value = serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
    let read = |name: &str| -> Value {
        serde_json::from_slice(&fs::read(root.join(name)).unwrap()).unwrap()
    };
    let observation = json!({
        "usage":[{"model":"fixture-best","input_tokens":10,
            "cached_input_tokens":0,"output_tokens":1}],
        "elapsed_ms":10,"fallback_reasons":[],
        "outcomes":{"transport":"passed","command_validation":"passed",
            "functional":"unknown"}
    });
    let now = grant["created_at_unix_seconds"].as_u64().unwrap();
    let input = json!({
        "schema_version":1,"case_id":"attested-cli","family_id":"synthetic-attestation",
        "split":"held_out","out_of_domain":false,
        "request":read("context.json"),"snapshot":read("attested-snapshot.json"),
        "catalog":read("catalog.json"),
        "policies":{"baseline":router_types::PhasePolicy::default(),"candidate":policy},
        "pricing":{"schema_version":1,"version":"fixture","source":"synthetic",
            "observed_at_unix_seconds":now,
            "models":{"fixture-best":{"input_microusd_per_million":1000,
                "cached_input_microusd_per_million":100,
                "output_microusd_per_million":5000}}},
        "observations":{"baseline":observation,"candidate":observation},"label":null
    });
    let record = router_eval::ReplayRecord::seal(serde_json::from_value(input).unwrap()).unwrap();
    let record_path = root.join("attested-replay.json");
    write(&record_path, &record);

    let replay = |store: bool| {
        let mut command = command();
        command
            .args(["replay", "--record"])
            .arg(&record_path)
            .args([
                "--policy",
                "candidate",
                "--now",
                &now.to_string(),
                "--snapshot-max-age-seconds",
                "300",
                "--json",
            ]);
        if store {
            command.arg("--store").arg(&fixture.files.store);
        }
        checked(&mut command, 0)
    };
    let verified = replay(true);
    assert_eq!(verified["capability_evidence"], "verified");
    assert_eq!(verified["receipt"]["schema_version"], 6);
    assert_eq!(
        verified["receipt"]["capability_evidence"]["workspace_write"]["tier"],
        "attested"
    );
    assert!(
        verified["hard_constraint_violations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let unverified = replay(false);
    assert_eq!(unverified["capability_evidence"], "unverified");
    assert!(unverified["receipt"]["selected"].is_null());
    assert!(
        unverified["hard_constraint_violations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|violation| violation["code"] == "capability.evidence.unverified")
    );

    let compare = |store: bool| {
        let mut command = command();
        command
            .args(["eval", "compare", "--records"])
            .arg(&record_path)
            .args([
                "--baseline",
                "baseline",
                "--candidate",
                "candidate",
                "--now",
                &now.to_string(),
                "--snapshot-max-age-seconds",
                "300",
                "--json",
            ]);
        if store {
            command.arg("--store").arg(&fixture.files.store);
        }
        checked(&mut command, 3)
    };
    let verified_report = compare(true);
    assert_eq!(verified_report["semantic"]["hard_constraint_violations"], 0);
    let unverified_report = compare(false);
    assert!(
        unverified_report["semantic"]["hard_constraint_violations"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(verified_report["semantic_enabled"], false);
    assert_eq!(unverified_report["semantic_enabled"], false);
    fixture.assert_no_host_invocation();
}

#[test]
fn coordinator_refuses_revoked_attestation_before_wave_spawn_and_keeps_history() {
    use router_types::*;
    let fixture = RuntimeAttestationFixture::for_coordinator();
    let root = &fixture.files.root;
    let store = fixture.files.store.parent().unwrap();
    let plan: WorkflowPlan =
        serde_json::from_slice(&fs::read(root.join("plan.json")).unwrap()).unwrap();
    let request: ExecutionRequest =
        serde_json::from_slice(&fs::read(root.join("request.json")).unwrap()).unwrap();
    let execution = router_workflow::seal_execution_contract(
        WorkflowExecutionContract {
            schema_version: 1,
            instance_id: "attested-coordinator-fixture".into(),
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
                            phase: if node.id == "verify" {
                                StageKind::Verify
                            } else {
                                StageKind::Execute
                            },
                            dependencies: node
                                .dependencies
                                .iter()
                                .map(|dependency| {
                                    (dependency.clone(), DependencyRequirement::Verified)
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
    let artifacts: BTreeMap<_, _> = plan
        .nodes
        .iter()
        .map(|node| {
            (
                node.id.clone(),
                NodeArtifactDeclaration {
                    outputs: node
                        .outputs
                        .iter()
                        .map(|label| OutputDeclaration {
                            label: label.clone(),
                            source: DeclaredOutputSource::NativeFinalText,
                            max_bytes: 16384,
                            retention_seconds: 60,
                        })
                        .collect(),
                    inputs: node
                        .dependencies
                        .iter()
                        .map(|dependency| ArtifactEdge {
                            producer: dependency.clone(),
                            label: format!("artifact:{dependency}"),
                            exposure: ArtifactExposure::PromptData,
                        })
                        .collect(),
                },
            )
        })
        .collect();
    let workflow = root.join("attested-workflow.json");
    write(
        &workflow,
        &WorkflowDefinition {
            schema_version: 1,
            plan,
            execution,
            artifacts,
            failure_policy: WorkflowFailurePolicy::FailFast,
            max_input_bytes: 65536,
            definition_sha256: String::new(),
        },
    );
    let sealed = checked(
        command()
            .args(["coordinate", "seal", "--definition"])
            .arg(&workflow)
            .arg("--json"),
        0,
    );
    write(&workflow, &sealed["definition"]);
    let bundle_dir = root.join("attested-bundle");
    let review = checked(
        command()
            .args(["coordinate", "review", "--definition"])
            .arg(&workflow)
            .arg("--store")
            .arg(store)
            .arg("--source-definition")
            .arg(root.join("definition.json"))
            .arg("--sandbox")
            .arg(root.join("sandbox.json"))
            .args(["--node-id", "execute", "--output-directory"])
            .arg(&bundle_dir)
            .arg("--json"),
        0,
    );
    assert_eq!(review["executed"], false);
    assert_eq!(review["run"]["state"], "awaiting_approval");
    let bundle = bundle_dir.join("bundle.json");
    let historical = checked(
        command()
            .args(["coordinate", "artifacts", "--bundle"])
            .arg(&bundle)
            .arg("--store")
            .arg(store)
            .args(["--json", "keep"]),
        0,
    );
    assert_eq!(fixture.revoke()["action"], "revoke");
    let retained = checked(
        command()
            .args(["coordinate", "artifacts", "--bundle"])
            .arg(&bundle)
            .arg("--store")
            .arg(store)
            .args(["--json", "keep"]),
        0,
    );
    assert_eq!(retained["run"], historical["run"]);
    let wave = root.join("attested-wave.json");
    write(
        &wave,
        &json!({"schema_version":1,"steps":[{"bundle":bundle,
        "approval":review["approval_digest"]}]}),
    );
    rejected(
        command()
            .args(["coordinate", "run-wave", "--definition"])
            .arg(&workflow)
            .arg("--store")
            .arg(store)
            .arg("--wave")
            .arg(&wave)
            .arg("--json"),
        "capability.evidence.revoked",
    );
    assert!(!fixture.files.store.join("worktrees").exists());
    assert!(!fixture.files.repo.join("src/attested-run-marker").exists());
}
