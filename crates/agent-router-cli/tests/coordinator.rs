//! Public CLI lifecycle with synthetic authority. The ignored test additionally
//! runs a real native sandbox; no live model identity or authentication is claimed.
#![cfg(all(feature = "claude", any(target_os = "macos", target_os = "linux")))]

#[path = "support/native_fixture.rs"]
mod native_fixture;
use native_fixture::*;
use router_adapter_api::content_digest;
use router_types::*;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command,
};

struct WorkflowFixture {
    native: Fixture,
    definition: PathBuf,
    bundle: PathBuf,
}
impl WorkflowFixture {
    fn new(native: Fixture) -> Self {
        native.provision_coordinator_runtime();
        let plan: WorkflowPlan =
            serde_json::from_slice(&fs::read(native.root.join("plan.json")).unwrap()).unwrap();
        let request: ExecutionRequest =
            serde_json::from_slice(&fs::read(native.root.join("request.json")).unwrap()).unwrap();
        let execution = router_workflow::seal_execution_contract(
            WorkflowExecutionContract {
                schema_version: 1,
                instance_id: "cli-workflow-fixture".into(),
                plan_id: plan.plan_id.clone(),
                workspace: request.workspace,
                source_state: request.source_state,
                nodes: plan
                    .nodes
                    .iter()
                    .map(|n| {
                        (
                            n.id.clone(),
                            NodeExecutionContract {
                                phase: if n.id == "verify" {
                                    StageKind::Verify
                                } else {
                                    StageKind::Execute
                                },
                                dependencies: n
                                    .dependencies
                                    .iter()
                                    .map(|d| (d.clone(), DependencyRequirement::Verified))
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
            .map(|n| {
                (
                    n.id.clone(),
                    NodeArtifactDeclaration {
                        outputs: n
                            .outputs
                            .iter()
                            .map(|label| OutputDeclaration {
                                label: label.clone(),
                                source: DeclaredOutputSource::NativeFinalText,
                                max_bytes: 16384,
                                retention_seconds: 60,
                            })
                            .collect(),
                        inputs: n
                            .dependencies
                            .iter()
                            .map(|p| ArtifactEdge {
                                producer: p.clone(),
                                label: format!("artifact:{p}"),
                                exposure: ArtifactExposure::PromptData,
                            })
                            .collect(),
                    },
                )
            })
            .collect();
        let definition = native.root.join("workflow.json");
        write(
            &definition,
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
                .arg(&definition)
                .arg("--json"),
            0,
        );
        assert_eq!(sealed["approved"], false);
        write(&definition, &sealed["definition"]);
        let bundle = native.root.join("bundle/bundle.json");
        Self {
            native,
            definition,
            bundle,
        }
    }
    fn action(&self, action: &str) -> Command {
        let mut cmd = command();
        cmd.args(["coordinate", action, "--definition"])
            .arg(&self.definition)
            .arg("--store")
            .arg(&self.native.store)
            .arg("--json");
        cmd
    }
    fn review(&self) -> Value {
        checked(
            self.action("review")
                .arg("--source-definition")
                .arg(self.native.root.join("definition.json"))
                .arg("--sandbox")
                .arg(self.native.root.join("sandbox.json"))
                .args(["--node-id", "execute", "--output-directory"])
                .arg(self.bundle.parent().unwrap()),
            0,
        )
    }
    fn wave(&self, approval: &str) -> Command {
        let path = self.native.root.join("wave.json");
        write(
            &path,
            &json!({"schema_version":1,"steps":[{"bundle":self.bundle,"approval":approval}]}),
        );
        let mut cmd = self.action("run-wave");
        cmd.arg("--wave").arg(path);
        cmd
    }
    fn artifact(&self, action: &str) -> Command {
        let mut cmd = command();
        cmd.args(["coordinate", "artifacts", "--bundle"])
            .arg(&self.bundle)
            .arg("--store")
            .arg(&self.native.store)
            .args(["--json", action]);
        cmd
    }
    fn artifact_recording(&self, action: &str) -> Command {
        let mut cmd = command();
        cmd.args(["coordinate", "artifacts", "--bundle"])
            .arg(&self.bundle)
            .arg("--store")
            .arg(&self.native.store)
            .arg("--config")
            .arg(self.native.root.join("sandbox.json"))
            .args(["--json", action]);
        cmd
    }
}

#[test]
fn coordinator_private_review_restart_and_cancel_do_not_execute() {
    let f = WorkflowFixture::new(Fixture::metadata("exit 93", 3000));
    let review = f.review();
    assert_eq!(review["executed"], false);
    assert_eq!(review["run"]["state"], "awaiting_approval");
    assert!(!review.to_string().contains(PROMPT));
    assert!(!f.native.store.join("runtime/worktrees").exists());
    for path in [
        &f.bundle,
        &f.bundle.parent().unwrap().join("request.json"),
        &f.bundle.parent().unwrap().join("artifacts.json"),
    ] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        fs::metadata(f.bundle.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let status = checked(&mut f.action("status"), 0);
    assert_eq!(status["all_verified"], false);
    assert_eq!(status["nodes"][0]["run_id"], review["run"]["run_id"]);
    let bad = f.wave("wrong-digest").output().unwrap();
    assert_eq!(bad.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("coordinator.approval.required_or_changed")
    );
    assert!(!f.native.store.join("runtime/worktrees").exists());
    assert_eq!(
        checked(&mut f.action("cancel"), 0)["cancellation_requested"],
        true
    );
    assert_eq!(checked(&mut f.action("status"), 0)["cancelled"], true);
}

#[test]
fn coordinator_reopen_rejects_changed_final_prompt_and_seal_rejects_unknown_fields() {
    let f = WorkflowFixture::new(Fixture::metadata("exit 93", 3000));
    let review = f.review();
    let path = f.bundle.parent().unwrap().join("request.json");
    let mut request: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    request["prompt"] = json!("changed-after-approval");
    write(&path, &request);
    let changed = f
        .wave(review["approval_digest"].as_str().unwrap())
        .output()
        .unwrap();
    // The changed final request no longer matches the stored run: integrity class.
    assert_eq!(changed.status.code(), Some(7));
    assert_eq!(
        changed.stderr,
        b"{\"schema_version\":1,\"error\":\"runtime.integrity\"}\n"
    );
    assert!(!String::from_utf8_lossy(&changed.stderr).contains("changed-after-approval"));
    assert!(!f.native.store.join("runtime/worktrees").exists());
    let mut definition: Value = serde_json::from_slice(&fs::read(&f.definition).unwrap()).unwrap();
    definition["child_grants_permission"] = json!(true);
    write(&f.definition, &definition);
    let output = command()
        .args(["coordinate", "seal", "--definition"])
        .arg(&f.definition)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn coordinator_revoked_proof_blocks_wave_but_preserves_historical_artifacts() {
    let f = WorkflowFixture::new(Fixture::metadata(
        "printf started > src/coordinator-should-not-run\nexit 93",
        3000,
    ));
    let review = f.review();
    let approval = review["approval_digest"].as_str().unwrap();
    let before = checked(&mut f.artifact("keep"), 0);
    assert_eq!(before["run"]["run_id"], review["run"]["run_id"]);

    f.native.fail_coordinator_capability_after_review();
    let historical = checked(&mut f.artifact("keep"), 0);
    assert_eq!(historical["run"], before["run"]);
    let denied = f.wave(approval).output().unwrap();
    assert_eq!(denied.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("capability.evidence.revoked"),
        "{}",
        String::from_utf8_lossy(&denied.stderr)
    );
    assert_eq!(
        checked(&mut f.action("status"), 0)["nodes"][0]["run_id"],
        review["run"]["run_id"]
    );
    assert!(!f.native.store.join("runtime/worktrees").exists());
    assert!(
        !f.native
            .repo
            .join("src/coordinator-should-not-run")
            .exists()
    );
}

#[test]
#[ignore = "requires native OS sandbox and built helper; no live model"]
fn native_coordinator_cli_run_verify_service_apply_and_purge() {
    let body = format!(
        "printf isolated > src/result.txt\nprintf '%s' {}",
        shell_quote(STREAM)
    );
    let f = WorkflowFixture::new(Fixture::new(&body, 3000));
    let review = f.review();
    let approval = review["approval_digest"].as_str().unwrap();
    let output = checked(&mut f.wave(approval), 0);
    assert_eq!(output["wave"]["errors"], json!([]));
    let completion = &output["wave"]["completions"][0];
    assert_eq!(completion["run"]["state"], "verifying");
    assert_eq!(output["workflow"]["all_verified"], false);
    assert!(!f.native.repo.join("src/result.txt").exists());
    let declared = checked(&mut f.artifact("declared"), 0);
    assert_eq!(declared["artifacts"][0]["state"], "retained");
    assert_eq!(
        declared["artifacts"][0]["sha256"],
        content_digest(b"synthetic-private-result")
    );
    for value in [&review, &output, &declared] {
        assert!(!value.to_string().contains("synthetic-private-result"));
        assert!(!value.to_string().contains(PROMPT));
    }
    let evidence = f.native.root.join("verification.json");
    write(
        &evidence,
        &json!({"verifier":"cli-coordinator-test","evidence_sha256":content_digest(b"private result hash and isolated source assertions passed"),"artifact_sha256":completion["run"]["artifact_sha256"],"validation":"passed","objective":"passed"}),
    );
    let control = checked(
        command()
            .args(["coordinate", "verify", "--bundle"])
            .arg(&f.bundle)
            .arg("--store")
            .arg(&f.native.store)
            .arg("--evidence")
            .arg(&evidence)
            .args(["--approval", approval, "--json"]),
        0,
    );
    assert_eq!(control["queued"], true);
    assert_eq!(control["verified"], false);
    let serviced = checked(f.action("service").arg("--bundle").arg(&f.bundle), 0);
    assert_eq!(serviced["applied_controls"], 1);
    assert_eq!(serviced["feedback"][0]["feedback"]["recorded"], true);
    let recorded = f.native.exported_feedback();
    assert_eq!(recorded["facts"].as_array().unwrap().len(), 1);
    assert_eq!(
        recorded["facts"][0]["fact"]["run_key_sha256"],
        recorded["events"][0]["input"]["run_key_sha256"]
    );
    assert_eq!(recorded["facts"][0]["fact"]["kind"]["type"], "verification");
    assert_eq!(serviced["workflow"]["nodes"][0]["state"], "verified");
    assert_eq!(
        checked(f.action("service").arg("--bundle").arg(&f.bundle), 0)["applied_controls"],
        0
    );
    let preview = checked(&mut f.artifact("preview"), 0);
    let applied = checked(
        f.artifact_recording("apply").args([
            "--approve",
            preview["preview"]["approval_digest"].as_str().unwrap(),
        ]),
        0,
    );
    assert!(applied["applied"].is_object());
    assert_eq!(applied["feedback"]["recorded"], true);
    let late = f.native.exported_feedback();
    let key = &late["events"][0]["input"]["run_key_sha256"];
    let integration = late["facts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|fact| fact["fact"]["kind"]["type"] == "integration")
        .expect("integration fact recorded after apply");
    assert_eq!(integration["fact"]["run_key_sha256"], *key);
    assert_eq!(integration["fact"]["kind"]["outcome"], "applied");
    assert_eq!(
        fs::read(f.native.repo.join("src/result.txt")).unwrap(),
        b"isolated"
    );
    let purged = checked(
        f.artifact("purge-declared").args([
            "--id",
            declared["artifacts"][0]["artifact_id"].as_str().unwrap(),
        ]),
        0,
    );
    assert_eq!(purged["purged"]["state"], "purged");
}

#[path = "support/admission_fixture.rs"]
mod admission_fixture;
#[test]
fn coordinator_review_and_reopen_keep_the_shared_registry_pin() {
    let f = WorkflowFixture::new(Fixture::metadata("exit 99", 3000));
    assert!(
        f.native.store.join("runtime").is_dir(),
        "fixture provisions the coordinator runtime proof store"
    );
    let registry = f.native.root.join("registry");
    let (_, hash) = admission_fixture::bind(
        &registry,
        &[(
            &f.native.root,
            &f.native.store.join("runtime"),
            "coordinator",
        )],
    );
    let review = f.review();
    assert_eq!(review["executed"], false);
    let bad = f.wave("wrong").output().unwrap();
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("coordinator.approval.required_or_changed")
    );
    let mut source: Value =
        serde_json::from_slice(&fs::read(f.native.root.join("definition.json")).unwrap()).unwrap();
    source.as_object_mut().unwrap().remove("admission");
    write(&f.native.root.join("definition.json"), &source);
    let bad = f
        .wave(review["approval_digest"].as_str().unwrap())
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("runtime.approval.required_or_changed"));
    let registry = router_runtime::AdmissionStore::open(&registry, &hash).unwrap();
    assert_eq!(registry.status().unwrap().granted, 0);
    assert!(!f.native.store.join("runtime/worktrees").exists());
}
