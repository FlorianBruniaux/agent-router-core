//! Public CLI publication with a fixed fake worker. No native sandbox/model claim.
#![cfg(all(feature = "claude", any(target_os = "macos", target_os = "linux")))]
#[path = "support/native_fixture.rs"]
mod native_fixture;
use native_fixture::*;
use router_adapter_api::{AdapterError, HarnessAdapter, ValidatedExecutionRequest, prepared_run};
use router_catalog::Catalog;
use router_policy::PhaseRouter;
use router_runtime::{Cancellation, Runtime, RuntimeLimits, SandboxPolicy, SandboxSupervisor};
use router_types::*;
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command, sync::Arc};
struct FakeWorker;
impl HarnessAdapter for FakeWorker {
    fn host(&self) -> &'static str {
        "claude-code"
    }
    fn prepare(&self, request: &ValidatedExecutionRequest) -> Result<PreparedRun, AdapterError> {
        prepared_run(
            request,
            "/bin/sh",
            vec!["-c".into(), "printf 'changed\\n' > src/base.txt".into()],
            vec![],
        )
    }
    fn decode_stream(
        &self,
        _: &[u8],
        _: TransportOutcome,
        _: usize,
    ) -> Result<RuntimeEvidence, AdapterError> {
        Err(AdapterError::Protocol)
    }
}
// Test-only authority for one fixed script; this never certifies an OS sandbox.
struct FixedScriptSupervisor;
impl SandboxSupervisor for FixedScriptSupervisor {
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
async fn seed_verified(f: &Fixture) {
    let snapshot: router_adapter_api::HostObservation =
        serde_json::from_slice(&fs::read(f.root.join("snapshot.json")).unwrap()).unwrap();
    let now = snapshot.observed_at_unix_seconds;
    let validated = f.validated_snapshot(now);
    let config: Value =
        serde_json::from_slice(&fs::read(f.root.join("sandbox.json")).unwrap()).unwrap();
    let binding = capability_store::binding(
        &snapshot.host,
        &config,
        &["src".into()],
        false,
        "fixture-v1",
    );
    let secret: [u8; 32] = fs::read(f.store.join("approval.key"))
        .unwrap()
        .try_into()
        .unwrap();
    let proofs = router_runtime::CapabilityProofStore::open_existing(&f.store)
        .unwrap()
        .verifier(&secret, vec![binding])
        .unwrap();
    let runtime = Runtime::open(&f.store, RuntimeLimits::default())
        .unwrap()
        .with_capability_proof_verifier(Arc::new(proofs));
    let request: PhaseRouteRequest =
        serde_json::from_slice(&fs::read(f.root.join("context.json")).unwrap()).unwrap();
    let execution: ExecutionRequest =
        serde_json::from_slice(&fs::read(f.root.join("request.json")).unwrap()).unwrap();
    let plan: WorkflowPlan =
        serde_json::from_slice(&fs::read(f.root.join("plan.json")).unwrap()).unwrap();
    let catalog = Catalog::from_json(&fs::read(f.root.join("catalog.json")).unwrap()).unwrap();
    let assets = asset_inputs(
        &request,
        &validated,
        &catalog,
        &f.repo,
        &execution.source_state,
        now,
    );
    let router = PhaseRouter::stable_v2();
    let context = router
        .context_with_assets(request, &validated, &catalog, assets, now)
        .unwrap();
    let pending = runtime
        .review(RUN_ID, &router, &context, execution, plan, "execute")
        .await
        .unwrap();
    let approved = runtime
        .approve(pending.clone(), pending.approval_digest())
        .unwrap();
    let out = runtime
        .execute(
            approved,
            &FakeWorker,
            &FixedScriptSupervisor,
            Cancellation::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        fs::read(Path::new(out.run.worktree.as_ref().unwrap()).join("src/base.txt")).unwrap(),
        b"changed\n"
    );
    runtime
        .record_verification(
            &pending,
            VerificationRecord {
                verifier: "cli-independent-fixture".into(),
                evidence_sha256: router_adapter_api::content_digest(
                    b"actual candidate file equals changed newline",
                ),
                artifact_sha256: out.run.artifact_sha256,
                validation: VerificationOutcome::Passed,
                objective: VerificationOutcome::Passed,
            },
        )
        .unwrap();
}
fn artifact(f: &Fixture, action: &str) -> Command {
    let mut c = command();
    c.args(["artifacts", "--definition"])
        .arg(f.root.join("definition.json"))
        .arg("--store")
        .arg(&f.store)
        .args(["--json", action]);
    c
}
#[tokio::test]
async fn cli_checks_the_saved_diff_publishes_once_and_reports_changed_ref_as_unknown() {
    let f = Fixture::metadata("exit 0", 3000);
    seed_verified(&f).await;
    let review = checked(&mut artifact(&f, "review-publication"), 0)["review"].clone();
    let saved = f.root.join("review.json");
    write(&saved, &review);
    assert_eq!(
        checked(
            artifact(&f, "check-publication-review")
                .arg("--review")
                .arg(&saved),
            0
        )["review"],
        review
    );
    let mut replaced = review.clone();
    replaced["diff"] = json!("not the reviewed candidate");
    write(&saved, &replaced);
    let invalid = artifact(&f, "check-publication-review")
        .arg("--review")
        .arg(&saved)
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert_eq!(
        checked(&mut artifact(&f, "publication-status"), 0)["publication"]["state"],
        "not_attempted"
    );
    let missing_config = artifact(&f, "publish")
        .args(["--approve", review["approval_digest"].as_str().unwrap()])
        .output()
        .unwrap();
    assert!(!missing_config.status.success());
    let mut publish = command();
    publish
        .args(["artifacts", "--definition"])
        .arg(f.root.join("definition.json"))
        .arg("--store")
        .arg(&f.store)
        .arg("--config")
        .arg(f.root.join("sandbox.json"))
        .args([
            "--json",
            "publish",
            "--approve",
            review["approval_digest"].as_str().unwrap(),
        ]);
    let configuration_path = f.root.join("sandbox.json");
    let configuration_bytes = fs::read(&configuration_path).unwrap();
    let mut changed: Value = serde_json::from_slice(&configuration_bytes).unwrap();
    changed["limits"]["max_file_bytes"] = json!(2048);
    write(&configuration_path, &changed);
    let changed_configuration = publish.output().unwrap();
    assert!(!changed_configuration.status.success());
    assert_eq!(
        checked(&mut artifact(&f, "publication-status"), 0)["publication"]["state"],
        "not_attempted"
    );
    fs::write(&configuration_path, configuration_bytes).unwrap();
    let receipt = checked(&mut publish, 0)["publication"].clone();
    assert_eq!(fs::read(f.repo.join("src/base.txt")).unwrap(), b"base\n");
    assert_eq!(
        checked(&mut artifact(&f, "publication-status"), 0)["publication"]["state"],
        "published"
    );
    let duplicate = publish.output().unwrap();
    assert!(!duplicate.status.success());
    let refname = receipt["target_ref"].as_str().unwrap();
    let published = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(&f.repo)
        .args(["show", &format!("{refname}:src/base.txt")])
        .output()
        .unwrap();
    assert!(published.status.success());
    assert_eq!(published.stdout, b"changed\n");
    assert!(
        Command::new("/usr/bin/git")
            .arg("-C")
            .arg(&f.repo)
            .args([
                "update-ref",
                "-d",
                refname,
                receipt["result_revision"].as_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        checked(&mut artifact(&f, "publication-status"), 3)["publication"]["state"],
        "unknown"
    );
    assert_eq!(fs::read(f.repo.join("src/base.txt")).unwrap(), b"base\n");
}
