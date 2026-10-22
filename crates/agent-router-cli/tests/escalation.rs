//! Synthetic attempts and private local journals. No provider or real model.
#![cfg(all(unix, feature = "claude"))]
#[path = "support/native_fixture.rs"]
mod native_fixture;
use native_fixture::{Fixture as Files, checked, command, write};
use router_adapter_api::{
    AdapterError, HarnessAdapter, SnapshotValidation, ValidatedExecutionRequest,
    ValidatedHostObservation, prepared_run,
};
use router_catalog::Catalog;
use router_policy::{PhaseRouter, ValidatedPhaseContext};
use router_runtime::{Cancellation, Runtime, RuntimeLimits, SandboxPolicy, SandboxSupervisor};
use router_types::*;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Command,
};

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn proof_store_fingerprints(path: &Path) -> BTreeMap<String, String> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            (
                entry.file_name().to_string_lossy().into_owned(),
                router_adapter_api::content_digest(&fs::read(entry.path()).unwrap()),
            )
        })
        .collect()
}
#[track_caller]
fn rejected(cmd: &mut Command, expected: &str) {
    let output = cmd.output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected),
        "expected {expected}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
}
struct Fixture {
    files: Files,
    router: PhaseRouter,
    context: ValidatedPhaseContext,
    plan: WorkflowPlan,
}
impl Fixture {
    fn new() -> Self {
        Self::build(false)
    }
    fn native() -> Self {
        Self::build(true)
    }
    fn build(native: bool) -> Self {
        let files = if native {
            Files::new("exit 1", 5_000)
        } else {
            Files::metadata("exit 1", 5_000)
        };
        let root = &files.root;
        let mut route: PhaseRouteRequest = read(&root.join("context.json"));
        route
            .task
            .allowed_mutations
            .remove(&Mutation::WorkspaceWrite);
        route.candidates[0].sandbox = PhaseSandbox::ReadOnly;
        let mut second = route.candidates[0].clone();
        second.id = "secondary".into();
        second.model = ModelId::parse("fixture-second").unwrap();
        route.candidates.push(second);
        let snapshot = ValidatedHostObservation::from_observation(
            native_fixture::unknown_observation::from_example(read(&root.join("snapshot.json"))),
            SnapshotValidation {
                now_unix_seconds: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                max_age_seconds: 300,
            },
        )
        .unwrap();
        write(&root.join("snapshot.json"), snapshot.observation());
        let catalog = Catalog::from_json(&fs::read(root.join("catalog.json")).unwrap()).unwrap();
        let original: ExecutionRequest = read(&root.join("request.json"));
        let assets = native_fixture::asset_inputs(
            &route,
            &snapshot,
            &catalog,
            &files.repo,
            &original.source_state,
            snapshot.observation().observed_at_unix_seconds,
        );
        native_fixture::write_asset_authority(root, &assets);
        let router = PhaseRouter::stable_v2();
        let context = router
            .context_with_assets(
                route.clone(),
                &snapshot,
                &catalog,
                assets,
                snapshot.observation().observed_at_unix_seconds,
            )
            .unwrap();
        let plan = router_workflow::build_plan(
            &route.task,
            WorkflowPreset::DirectSafe,
            router_workflow::PlanLimits::default(),
        )
        .unwrap();
        write(&root.join("context.json"), &route);
        write(&root.join("plan.json"), &plan);
        let prompt = router_workflow::seal_prompt(PromptTemplate {
            schema_version: 1,
            id: "escalation-template".into(),
            version: "1".into(),
            template: "Inspect ${subject}".into(),
            variables: BTreeMap::from([("subject".into(), PromptVariableType::Text)]),
            compatible_hosts: BTreeSet::from(["claude-code".into()]),
            compatible_models: catalog.models().map(|(id, _)| id.clone()).collect(),
            max_rendered_bytes: 4096,
            output_contract: "Report findings".into(),
            content_sha256: String::new(),
        })
        .unwrap();
        write(&root.join("prompt.json"), &prompt);
        let metadata: router_retrieval::MetadataDocument = serde_json::from_value(json!({"schema_version":"1","catalog_version":catalog.version(),"assets":[{"kind":"prompt","id":prompt.id,"trust":"trusted_local","description":"report","body":{"path":"prompt.json","sha256":router_adapter_api::content_digest(&fs::read(root.join("prompt.json")).unwrap())}}]})).unwrap();
        write(
            &root.join("metadata.json"),
            &router_retrieval::MetadataEnvelope::new(metadata, &catalog.content_hash().unwrap())
                .unwrap(),
        );
        write(
            &root.join("variables.json"),
            &BTreeMap::from([(
                "subject",
                PromptValue::Text("PRIVATE_ESCALATION_SUBJECT".into()),
            )]),
        );
        write(
            &root.join("options.json"),
            &json!({"schema_version":1,"workspace":files.repo,"source_state":original.source_state,"target":"external_worker","allow_degradation":false,"timeout_ms":5000,"max_output_bytes":16384,"max_input_bytes":65536,"now_unix_seconds":0,"max_snapshot_age_seconds":300}),
        );
        write(
            &root.join("prepare.json"),
            &json!({"schema_version":1,"run_id":"source","context":"context.json","host_snapshot":"snapshot.json","catalog":"catalog.json","policy":null,"asset_authority":"asset-authority.json","plan":"plan.json","node_id":"execute","metadata":"metadata.json","body_root":".","template":"prompt.json","variables":"variables.json","options":"options.json"}),
        );
        checked(
            command()
                .args(["prepare", "--manifest"])
                .arg(root.join("prepare.json"))
                .arg("--output-directory")
                .arg(root.join("source"))
                .arg("--json"),
            0,
        );
        write(
            &root.join("escalation-policy.json"),
            &EscalationPolicy {
                schema_version: 1,
                minimum_failed_attempts: 2,
                retryable_failures: vec![RunFailure::Crash],
                transitions: vec![EscalationTransition {
                    from_candidate_id: "primary".into(),
                    to_candidate_id: "secondary".into(),
                }],
            },
        );
        let mut sandbox: Value = read(&root.join("sandbox.json"));
        sandbox["output_retention"] = json!({"mode":"disabled"});
        sandbox["feedback_store"] = Value::Null;
        write(&root.join("sandbox.json"), &sandbox);
        // A fixed binary handles both candidates, so changing the selection never
        // changes the approved executable hash between review and dispatch.
        fs::write(root.join("fake-claude"), format!("#!/bin/sh\nset -eu\nmodel=\nwhile [ \"$#\" -gt 0 ]; do\ncase \"$1\" in --model) model=\"$2\"; shift 2;; *) shift;; esac\ndone\n/bin/cat >/dev/null\n[ \"$model\" = fixture-best ] && exit 1\n[ \"$model\" = fixture-second ] || exit 42\nprintf '%s' {}\n", native_fixture::shell_quote(native_fixture::STREAM))).unwrap();
        Self {
            files,
            router,
            context,
            plan,
        }
    }
    fn source(&self) -> std::path::PathBuf {
        self.files.root.join("source/definition.json")
    }
    fn bound(&self, attempt: u32) -> Command {
        let mut cmd = command();
        cmd.args(["escalation", "bound", "--store"])
            .arg(&self.files.store)
            .arg("--source-definition")
            .arg(self.source())
            .args([
                "--attempt-run-id",
                "source",
                "--attempt",
                &attempt.to_string(),
                "--max-cost-microusd",
                "10",
                "--max-tokens",
                "10",
                "--json",
            ]);
        cmd
    }
    fn propose(&self) -> Command {
        let mut cmd = command();
        cmd.args(["escalation", "propose", "--store"])
            .arg(&self.files.store)
            .arg("--source-definition")
            .arg(self.source())
            .arg("--policy")
            .arg(self.files.root.join("escalation-policy.json"))
            .args(["--max-attempts", "3", "--json"]);
        cmd
    }
    fn attempts(&self) -> Vec<RunCompletion> {
        self.attempt_sequence(false)
    }
    fn attempt_sequence(&self, succeed_on_retry: bool) -> Vec<RunCompletion> {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let runtime = Runtime::open(&self.files.store, RuntimeLimits::default()).unwrap();
            let request = read(&self.files.root.join("source/request.json"));
            let pending = runtime
                .review(
                    "source",
                    &self.router,
                    &self.context,
                    request,
                    self.plan.clone(),
                    "execute",
                )
                .await
                .unwrap();
            let mut pending = pending;
            let mut completions = Vec::new();
            for attempt in 1..=2 {
                let approved = runtime
                    .approve(pending.clone(), pending.approval_digest())
                    .unwrap();
                let worker: &dyn HarnessAdapter = if succeed_on_retry && attempt == 2 {
                    &SuccessfulWorker
                } else {
                    &FailedWorker
                };
                let completion = runtime
                    .execute(approved, worker, &TestSupervisor, Cancellation::default())
                    .await
                    .unwrap();
                assert_eq!(
                    completion.run.failure,
                    if succeed_on_retry && attempt == 2 {
                        None
                    } else {
                        Some(RunFailure::Crash)
                    }
                );
                assert_eq!(completion.run.attempts, attempt);
                if succeed_on_retry && attempt == 2 {
                    runtime
                        .record_verification(
                            &pending,
                            VerificationRecord {
                                verifier: "synthetic-review".into(),
                                evidence_sha256: "a".repeat(64),
                                artifact_sha256: None,
                                validation: VerificationOutcome::Passed,
                                objective: VerificationOutcome::Passed,
                            },
                        )
                        .unwrap();
                }
                completions.push(completion);
                if attempt == 1 {
                    pending = runtime.retry(pending).unwrap();
                }
            }
            completions
        })
    }
    fn account(&self) {
        for attempt in 1..=2 {
            let preview = checked(&mut self.bound(attempt), 0);
            assert_eq!(preview["approved"], false);
            let digest = preview["preview"]["approval_digest"].as_str().unwrap();
            checked(self.bound(attempt).args(["--approve", digest]), 0);
        }
    }
}
struct FailedWorker;
impl HarnessAdapter for FailedWorker {
    fn host(&self) -> &'static str {
        "claude-code"
    }
    fn prepare(&self, request: &ValidatedExecutionRequest) -> Result<PreparedRun, AdapterError> {
        prepared_run(
            request,
            "/bin/sh",
            vec!["-c".into(), "exit 1".into()],
            vec![],
        )
    }
    fn decode_stream(
        &self,
        _: &[u8],
        _: TransportOutcome,
        _: usize,
    ) -> Result<RuntimeEvidence, AdapterError> {
        Err(AdapterError::Unsupported("synthetic-test"))
    }
}
struct SuccessfulWorker;
impl HarnessAdapter for SuccessfulWorker {
    fn host(&self) -> &'static str {
        "claude-code"
    }
    fn prepare(&self, request: &ValidatedExecutionRequest) -> Result<PreparedRun, AdapterError> {
        prepared_run(
            request,
            "/bin/sh",
            vec!["-c".into(), "exit 0".into()],
            vec![],
        )
    }
    fn decode_stream(
        &self,
        bytes: &[u8],
        outcome: TransportOutcome,
        limit: usize,
    ) -> Result<RuntimeEvidence, AdapterError> {
        FailedWorker.decode_stream(bytes, outcome, limit)
    }
}
// Intentionally test-only. These ordinary tests establish journal/CLI behavior,
// not native OS sandbox enforcement; the separate ignored canary exercises it.
struct TestSupervisor;
impl SandboxSupervisor for TestSupervisor {
    fn resource_limits_enforced(&self) -> bool {
        true
    }
    fn command(
        &self,
        run: &PreparedRun,
        _: &SandboxPolicy,
    ) -> router_runtime::Result<tokio::process::Command> {
        let mut cmd = tokio::process::Command::new(&run.program);
        cmd.args(&run.argv).current_dir(&run.cwd).env_clear();
        Ok(cmd)
    }
}
#[test]
fn parent_accounting_approval_never_upgrades_unknown_cleanup() {
    let fixture = Fixture::new();
    fixture.attempts();
    rejected(
        &mut fixture.propose(),
        "escalation.attempt_evidence.missing_or_changed",
    );
    let preview = checked(&mut fixture.bound(1), 0);
    rejected(
        fixture.bound(1).args(["--approve", &"0".repeat(64)]),
        "escalation.approval.required_or_changed",
    );
    rejected(
        &mut fixture.propose(),
        "escalation.attempt_evidence.missing_or_changed",
    );
    checked(
        fixture.bound(1).args([
            "--approve",
            preview["preview"]["approval_digest"].as_str().unwrap(),
        ]),
        0,
    );
    let second = checked(&mut fixture.bound(2), 0);
    checked(
        fixture.bound(2).args([
            "--approve",
            second["preview"]["approval_digest"].as_str().unwrap(),
        ]),
        0,
    );
    rejected(
        &mut fixture.propose(),
        "escalation.attempt_evidence.missing_or_changed",
    );
    assert_eq!(preview["observed_cost_microusd"], Value::Null);
    assert_eq!(preview["observed_tokens"], Value::Null);
}

impl Fixture {
    fn run(&self, definition: &Path) -> Command {
        let mut cmd = command();
        cmd.args(["run", "--definition"])
            .arg(definition)
            .arg("--store")
            .arg(&self.files.store)
            .arg("--sandbox")
            .arg(self.files.root.join("sandbox.json"))
            .arg("--json");
        cmd
    }
    fn prepare_target(&self) -> Command {
        let mut manifest: Value = read(&self.files.root.join("prepare.json"));
        manifest["run_id"] = json!("target");
        manifest["escalation_decision"] = json!("proposal.json");
        write(&self.files.root.join("prepare-target.json"), &manifest);
        let mut cmd = command();
        cmd.args(["prepare", "--manifest"])
            .arg(self.files.root.join("prepare-target.json"))
            .arg("--output-directory")
            .arg(self.files.root.join("target"))
            .arg("--json");
        cmd
    }
    fn native_attempts(&self) {
        for attempt in 1..=2 {
            let mut cmd = self.run(&self.source());
            if attempt == 2 {
                cmd.arg("--retry");
            }
            let preview = checked(&mut cmd, 0);
            let mut approved = self.run(&self.source());
            if attempt == 2 {
                approved.arg("--retry");
            }
            let done = checked(
                approved.args(["--approve", preview["approval_digest"].as_str().unwrap()]),
                3,
            );
            assert_eq!(done["completion"]["run"]["failure"], "crash");
            assert_eq!(done["completion"]["run"]["attempts"], attempt);
        }
    }
}
#[test]
#[ignore = "requires built native helper and real OS sandbox; no provider"]
fn native_cli_bounds_proposal_preparation_approval_dispatch_and_restart() {
    let fixture = Fixture::native();
    fixture.native_attempts();
    rejected(&mut fixture.propose(), "escalation.accounting.unknown");
    fixture.account();
    let proposal = checked(
        fixture
            .propose()
            .arg("--output")
            .arg(fixture.files.root.join("proposal.json")),
        0,
    );
    assert_eq!(
        proposal["preview"]["selection"]["candidate"]["id"],
        "secondary"
    );
    assert_eq!(proposal["preview"]["uses_parent_accounting_bounds"], true);
    let prepared = checked(&mut fixture.prepare_target(), 0);
    assert_eq!(prepared["executed"], false);
    let baseline: PhaseReceipt = read(&fixture.files.root.join("source/receipt.json"));
    let target_baseline: PhaseReceipt = read(&fixture.files.root.join("target/receipt.json"));
    assert_eq!(target_baseline, baseline);
    let request: ExecutionRequest = read(&fixture.files.root.join("target/request.json"));
    let source_request: ExecutionRequest = read(&fixture.files.root.join("source/request.json"));
    assert_eq!(request.prompt, source_request.prompt);
    assert_eq!(request.model.as_str(), "fixture-second");
    let target = fixture.files.root.join("target/definition.json");
    let review = checked(&mut fixture.run(&target), 0);
    assert_eq!(review["decision_origin"], "escalated");
    assert_eq!(review["baseline_receipt_id"], baseline.receipt_id);
    assert_eq!(
        review["escalation_decision"]["attempts"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    rejected(
        fixture.run(&target).args(["--approve", &"0".repeat(64)]),
        "runtime.approval.required_or_changed",
    );
    let completion = checked(
        fixture
            .run(&target)
            .args(["--approve", review["approval_digest"].as_str().unwrap()]),
        0,
    );
    assert_eq!(completion["completion"]["run"]["state"], "verifying");
    assert_eq!(completion["completion"]["run"]["attempts"], 1);
    assert_eq!(completion["completion"]["objective"], "unknown");
    // A new CLI invocation must reconstruct the historical escalation for artifacts.
    checked(
        command()
            .args(["artifacts", "--definition"])
            .arg(&target)
            .arg("--store")
            .arg(&fixture.files.store)
            .args(["outputs", "--json"]),
        0,
    );
    rejected(fixture.run(&target).arg("--retry"), "runtime.invalid");
    for output in [proposal, prepared, review, completion] {
        assert!(!output.to_string().contains("PRIVATE_ESCALATION_SUBJECT"));
    }
}

#[test]
fn accounting_previews_are_single_use_and_bound_to_the_current_ledger() {
    let fixture = Fixture::new();
    fixture.attempts();
    let a = checked(&mut fixture.bound(1), 0);
    let b = checked(&mut fixture.bound(2), 0);
    checked(
        fixture.bound(1).args([
            "--approve",
            a["preview"]["approval_digest"].as_str().unwrap(),
        ]),
        0,
    );
    rejected(
        fixture.bound(1).args([
            "--approve",
            a["preview"]["approval_digest"].as_str().unwrap(),
        ]),
        "escalation.approval.required_or_changed",
    );
    rejected(
        fixture.bound(2).args([
            "--approve",
            b["preview"]["approval_digest"].as_str().unwrap(),
        ]),
        "escalation.approval.required_or_changed",
    );
    let fresh = checked(&mut fixture.bound(2), 0);
    assert_ne!(
        fresh["preview"]["approval_digest"],
        b["preview"]["approval_digest"]
    );
    checked(
        fixture.bound(2).args([
            "--approve",
            fresh["preview"]["approval_digest"].as_str().unwrap(),
        ]),
        0,
    );
}
#[test]
fn composition_and_recursive_sources_are_rejected_before_opening_the_store() {
    let fixture = Fixture::new();
    let store_before = proof_store_fingerprints(&fixture.files.store);
    let original: Value = read(&fixture.source());
    for field in ["generated_plan", "escalation_decision"] {
        let mut source = original.clone();
        source[field] = json!("not-a-readable-authority.json");
        write(&fixture.source(), &source);
        rejected(&mut fixture.bound(1), "escalation.source.origin_denied");
        assert_eq!(proof_store_fingerprints(&fixture.files.store), store_before);
        assert!(!fixture.files.store.join("runtime.sqlite3").exists());
    }
    let mut source = original;
    source["escalation_decision"] = json!("unused");
    source["backend_decision"] = json!("unused");
    write(&fixture.source(), &source);
    rejected(&mut fixture.bound(1), "escalation.composition.denied");
    assert_eq!(proof_store_fingerprints(&fixture.files.store), store_before);
    assert!(!fixture.files.store.join("runtime.sqlite3").exists());
}
#[test]
fn third_attempt_ceiling_is_required_and_bounded() {
    for limit in ["0", "1", "2", "6", "4294967295"] {
        rejected(
            command().args([
                "escalation",
                "propose",
                "--store",
                "unused",
                "--source-definition",
                "unused",
                "--policy",
                "unused",
                "--max-attempts",
                limit,
                "--json",
            ]),
            "cli.invalid",
        );
    }
    rejected(
        command().args([
            "escalation",
            "propose",
            "--store",
            "unused",
            "--source-definition",
            "unused",
            "--policy",
            "unused",
            "--json",
        ]),
        "cli.invalid",
    );
}
fn copy_store(source: &Path, target: &Path) {
    fs::create_dir(target).unwrap();
    fs::set_permissions(target, fs::metadata(source).unwrap().permissions()).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let next = target.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_store(&entry.path(), &next);
        } else {
            fs::copy(entry.path(), next).unwrap();
        }
    }
}
#[test]
#[ignore = "requires native helper and OS sandbox; pins, prompt and claim regressions"]
fn native_cli_escalation_rejects_changed_sources_stores_prompts_and_approval_limits() {
    let fixture = Fixture::native();
    fixture.native_attempts();
    fixture.account();
    checked(
        fixture
            .propose()
            .arg("--output")
            .arg(fixture.files.root.join("proposal.json")),
        0,
    );
    let path = fixture.files.root.join("proposal.json");
    let original: Value = read(&path);
    let variables = fixture.files.root.join("variables.json");
    let saved = fs::read(&variables).unwrap();
    write(
        &variables,
        &BTreeMap::from([("subject", PromptValue::Text("changed task".into()))]),
    );
    rejected(&mut fixture.prepare_target(), "runtime.invalid");
    assert!(!fixture.files.root.join("target").exists());
    fs::write(&variables, saved).unwrap();
    for (field, value, expected) in [
        (
            "expected_ledger_hash",
            json!("0".repeat(64)),
            "escalation.evidence.changed",
        ),
        (
            "source_material_sha256",
            json!("0".repeat(64)),
            "escalation.source.changed",
        ),
        (
            "expected_decision_id",
            json!("0".repeat(64)),
            "escalation.evidence.changed",
        ),
        ("max_attempts", json!(6), "escalation.document.invalid"),
        ("unexpected", json!(true), "request.json.invalid"),
    ] {
        let mut altered = original.clone();
        altered[field] = value;
        write(&path, &altered);
        rejected(&mut fixture.prepare_target(), expected);
        assert!(!fixture.files.root.join("target").exists());
    }
    write(&path, &original);
    let alias = fixture.files.root.join("source/alias.json");
    fs::copy(fixture.source(), &alias).unwrap();
    let mut altered = original.clone();
    altered["source_definition"] = json!(alias);
    write(&path, &altered);
    rejected(&mut fixture.prepare_target(), "escalation.source.changed");
    let clone = fixture.files.root.join("runtime-copy");
    copy_store(&fixture.files.store, &clone);
    altered = original.clone();
    altered["runtime_store"] = json!(clone);
    write(&path, &altered);
    rejected(&mut fixture.prepare_target(), "escalation.evidence.changed");
    write(&path, &original);
    checked(&mut fixture.prepare_target(), 0);
    let target = fixture.files.root.join("target/definition.json");
    let review = checked(&mut fixture.run(&target), 0);
    altered = original.clone();
    altered["max_attempts"] = json!(4);
    write(&path, &altered);
    rejected(
        fixture
            .run(&target)
            .args(["--approve", review["approval_digest"].as_str().unwrap()]),
        "runtime.approval.required_or_changed",
    );
    write(&path, &original);
    let mut duplicate: Value = read(&target);
    duplicate["run_id"] = json!("second-target");
    write(
        &fixture.files.root.join("target/second-definition.json"),
        &duplicate,
    );
    rejected(
        &mut fixture.run(&fixture.files.root.join("target/second-definition.json")),
        "runtime.approval.required_or_changed",
    );
    // Reopening the original after the rejected competing claim remains valid.
    assert_eq!(
        checked(&mut fixture.run(&target), 0)["approval_digest"],
        review["approval_digest"]
    );
    rejected(
        fixture.run(&fixture.source()).arg("--retry"),
        "runtime.invalid",
    );
}

#[test]
#[ignore = "requires native helper and OS sandbox; durable source ledger regression"]
fn native_cli_escalation_rejects_a_proposal_after_source_history_changes() {
    let fixture = Fixture::native();
    fixture.native_attempts();
    fixture.account();
    checked(
        fixture
            .propose()
            .arg("--output")
            .arg(fixture.files.root.join("proposal.json")),
        0,
    );
    // Trusted test caller explicitly authorizes a third ordinary source attempt.
    // This changes durable history, without forging or editing SQLite events.
    {
        let runtime = Runtime::open(
            &fixture.files.store,
            RuntimeLimits {
                max_attempts: 3,
                ..RuntimeLimits::default()
            },
        )
        .unwrap();
        let request = read(&fixture.files.root.join("source/request.json"));
        let pending = runtime
            .reopen(
                "source",
                &fixture.router,
                &fixture.context,
                request,
                fixture.plan.clone(),
                "execute",
            )
            .unwrap();
        runtime.retry(pending).unwrap();
    }
    rejected(
        &mut fixture.prepare_target(),
        "escalation.attempts.insufficient_or_not_retryable",
    );
    assert!(!fixture.files.root.join("target").exists());
}

#[test]
fn coordinator_bundle_source_is_a_distinct_exclusive_input() {
    let f = Fixture::new();
    let store_before = proof_store_fingerprints(&f.files.store);
    let missing = f.files.root.join("missing-coordinator-bundle.json");
    let mut input = command();
    input
        .args(["escalation", "propose", "--source-bundle"])
        .arg(&missing)
        .arg("--store")
        .arg(&f.files.store)
        .arg("--policy")
        .arg(f.files.root.join("escalation-policy.json"))
        .args(["--max-attempts", "3", "--json"]);
    let output = input.output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("cli.invalid"),
        "source bundle must be parsed, then rejected for missing source: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(proof_store_fingerprints(&f.files.store), store_before);
    assert!(!f.files.store.join("runtime.sqlite3").exists());
    input.arg("--source-definition").arg(f.source());
    rejected(&mut input, "cli.invalid");
}

struct CoordinatedFixture {
    base: Fixture,
    workflow: std::path::PathBuf,
}
impl CoordinatedFixture {
    fn new(native: bool) -> Self {
        Self::with_budget(native, 45_000)
    }
    fn with_budget(native: bool, max_tokens: u64) -> Self {
        let mut base = Fixture::build(native);
        let root = &base.files.root;
        let mut route = base.context.request().clone();
        route.task.budget.max_tokens = max_tokens;
        let snapshot = ValidatedHostObservation::from_observation(
            native_fixture::unknown_observation::from_example(read(&root.join("snapshot.json"))),
            SnapshotValidation {
                now_unix_seconds: base.context.snapshot().observed_at_unix_seconds,
                max_age_seconds: 300,
            },
        )
        .unwrap();
        let catalog = Catalog::from_json(&fs::read(root.join("catalog.json")).unwrap()).unwrap();
        let source_request: ExecutionRequest = read(&root.join("source/request.json"));
        let assets = native_fixture::asset_inputs(
            &route,
            &snapshot,
            &catalog,
            &base.files.repo,
            &source_request.source_state,
            snapshot.observation().observed_at_unix_seconds,
        );
        native_fixture::write_asset_authority(root, &assets);
        base.context = base
            .router
            .context_with_assets(
                route.clone(),
                &snapshot,
                &catalog,
                assets,
                snapshot.observation().observed_at_unix_seconds,
            )
            .unwrap();
        let receipt = base.router.route(&base.context).unwrap();
        assert!(
            receipt.selected.is_some(),
            "coordinator fixture eligibility: {:?}",
            receipt.abstention
        );
        write(&root.join("context.json"), &route);
        let plan = router_workflow::build_plan(
            &base.context.request().task,
            WorkflowPreset::PlanExecuteVerify,
            router_workflow::PlanLimits::default(),
        )
        .unwrap();
        write(&root.join("plan.json"), &plan);
        let request: ExecutionRequest = read(&root.join("source/request.json"));
        let contract = router_workflow::seal_execution_contract(
            WorkflowExecutionContract {
                schema_version: 1,
                instance_id: "coordinator-escalation-fixture".into(),
                plan_id: plan.plan_id.clone(),
                workspace: request.workspace.clone(),
                source_state: request.source_state.clone(),
                nodes: plan
                    .nodes
                    .iter()
                    .map(|n| {
                        (
                            n.id.clone(),
                            NodeExecutionContract {
                                phase: match n.id.as_str() {
                                    "plan" => StageKind::Plan,
                                    "verify" => StageKind::Verify,
                                    _ => StageKind::Execute,
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
        write(&root.join("workflow-contract.json"), &contract);
        let definition = router_coordinator::seal_definition(WorkflowDefinition {
            schema_version: 1,
            execution: contract,
            artifacts: plan
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
                                    retention_seconds: 300,
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
                .collect(),
            plan,
            failure_policy: WorkflowFailurePolicy::ContinueIndependent,
            max_input_bytes: 65536,
            definition_sha256: String::new(),
        })
        .unwrap();
        let workflow = root.join("workflow.json");
        write(&workflow, &definition);
        let mut manifest: Value = read(&root.join("prepare.json"));
        manifest["workflow_contract"] = json!("workflow-contract.json");
        manifest["generation"] = json!(0);
        write(&root.join("co-prepare.json"), &manifest);
        checked(
            command()
                .args(["prepare", "--manifest"])
                .arg(root.join("co-prepare.json"))
                .arg("--output-directory")
                .arg(root.join("co-source"))
                .arg("--json"),
            0,
        );
        let mut route = base.context.request().clone();
        route.phase = StageKind::Plan;
        write(&root.join("plan-context.json"), &route);
        let snapshot = ValidatedHostObservation::from_observation(
            native_fixture::unknown_observation::from_example(read(&root.join("snapshot.json"))),
            SnapshotValidation {
                now_unix_seconds: base.context.snapshot().observed_at_unix_seconds,
                max_age_seconds: 300,
            },
        )
        .unwrap();
        let catalog = Catalog::from_json(&fs::read(root.join("catalog.json")).unwrap()).unwrap();
        let asset_dir = root.join("plan-assets");
        fs::create_dir(&asset_dir).unwrap();
        let assets = native_fixture::asset_inputs(
            &route,
            &snapshot,
            &catalog,
            &base.files.repo,
            &request.source_state,
            snapshot.observation().observed_at_unix_seconds,
        );
        native_fixture::write_asset_authority(&asset_dir, &assets);
        write(
            &root.join("plan-variables.json"),
            &BTreeMap::from([("subject", PromptValue::Text("PREDECESSOR".into()))]),
        );
        manifest["context"] = json!("plan-context.json");
        manifest["asset_authority"] = json!("plan-assets/asset-authority.json");
        manifest["node_id"] = json!("plan");
        manifest["variables"] = json!("plan-variables.json");
        write(&root.join("plan-prepare.json"), &manifest);
        checked(
            command()
                .args(["prepare", "--manifest"])
                .arg(root.join("plan-prepare.json"))
                .arg("--output-directory")
                .arg(root.join("co-plan"))
                .arg("--json"),
            0,
        );
        let stream = native_fixture::STREAM.replace(
            "synthetic-private-result",
            "DEPENDENCY_NONEMPTY_SYNTHETIC_DATA",
        );
        fs::write(root.join("fake-claude"),format!("#!/bin/sh\nset -eu\nmodel=\neffort=\nwhile [ \"$#\" -gt 0 ]; do\ncase \"$1\" in --model) model=\"$2\"; shift 2;; --effort) effort=\"$2\"; shift 2;; *) shift;; esac\ndone\n[ \"$effort\" = medium ] || exit 43\nprompt=$(/bin/cat)\ncase \"$prompt\" in *PREDECESSOR*) printf '%s' {}; exit 0;; esac\ncase \"$prompt\" in *DEPENDENCY_NONEMPTY_SYNTHETIC_DATA*) :;; *) exit 44;; esac\n[ \"$model\" = fixture-best ] && exit 1\n[ \"$model\" = fixture-second ] || exit 42\nprintf '%s' {}\n",native_fixture::shell_quote(&stream),native_fixture::shell_quote(native_fixture::STREAM))).unwrap();
        Self { base, workflow }
    }
    fn action(&self, action: &str) -> Command {
        let mut c = command();
        c.args(["coordinate", action, "--definition"])
            .arg(&self.workflow)
            .arg("--store")
            .arg(&self.base.files.store)
            .arg("--json");
        c
    }
    fn review(&self, node: &str, generation: u32, source: &str, out: &str) -> Value {
        checked(
            self.action("review")
                .args([
                    "--node-id",
                    node,
                    "--generation",
                    &generation.to_string(),
                    "--source-definition",
                ])
                .arg(self.base.files.root.join(source))
                .arg("--sandbox")
                .arg(self.base.files.root.join("sandbox.json"))
                .arg("--output-directory")
                .arg(self.base.files.root.join(out)),
            0,
        )
    }
    fn wave_command(&self, bundle: &str, approval: &str) -> Command {
        write(
            &self.base.files.root.join("co-wave.json"),
            &json!({"schema_version":1,"steps":[{"bundle":self.base.files.root.join(bundle),"approval":approval}]}),
        );
        let mut cmd = self.action("run-wave");
        cmd.arg("--wave")
            .arg(self.base.files.root.join("co-wave.json"));
        cmd
    }
    fn wave(&self, bundle: &str, approval: &str, code: i32) -> Value {
        checked(&mut self.wave_command(bundle, approval), code)
    }
    fn prepare_target(&self) -> Command {
        let mut cmd = command();
        cmd.args(["prepare", "--manifest"])
            .arg(self.base.files.root.join("co-target-prepare.json"))
            .arg("--output-directory")
            .arg(self.base.files.root.join("co-target"))
            .arg("--json");
        cmd
    }
    fn verify(&self, bundle: &str, approval: &str) {
        let root = &self.base.files.root;
        write(
            &root.join("co-evidence.json"),
            &json!({"verifier":"explicit-fixture-reviewer","evidence_sha256":router_adapter_api::content_digest(b"synthetic assertions"),"artifact_sha256":null,"validation":"passed","objective":"passed"}),
        );
        let result = checked(
            command()
                .args(["coordinate", "verify", "--bundle"])
                .arg(root.join(bundle))
                .arg("--store")
                .arg(&self.base.files.store)
                .arg("--evidence")
                .arg(root.join("co-evidence.json"))
                .args(["--approval", approval, "--json"]),
            0,
        );
        assert_eq!(result["verified"], false);
        let service = checked(
            self.action("service")
                .arg("--bundle")
                .arg(root.join(bundle)),
            0,
        );
        assert_eq!(service["applied_controls"], 1);
    }
    fn bound(&self, run: &str) -> Command {
        let mut c = command();
        c.args(["escalation", "bound", "--source-bundle"])
            .arg(self.base.files.root.join("failed1/bundle.json"))
            .arg("--store")
            .arg(&self.base.files.store)
            .args([
                "--attempt-run-id",
                run,
                "--attempt",
                "1",
                "--max-cost-microusd",
                "10",
                "--max-tokens",
                "10",
                "--json",
            ]);
        c
    }
    fn failed_sources(&self) -> (Value, Value) {
        let f = self;
        let root = &self.base.files.root;
        let parent = f.review("plan", 0, "co-plan/definition.json", "parent");
        let parent_approval = parent["approval_digest"].as_str().unwrap();
        f.wave("parent/bundle.json", parent_approval, 0);
        f.verify("parent/bundle.json", parent_approval);
        let mut attempts = Vec::new();
        for generation in 0..2 {
            let review = f.review(
                "execute",
                generation,
                "co-source/definition.json",
                &format!("failed{generation}"),
            );
            let request: ExecutionRequest =
                read(&root.join(format!("failed{generation}/request.json")));
            assert!(
                request
                    .prompt
                    .contains("DEPENDENCY_NONEMPTY_SYNTHETIC_DATA")
            );
            assert_eq!(
                request
                    .prompt
                    .matches("Agent Router dependency data")
                    .count(),
                1
            );
            let done = f.wave(
                &format!("failed{generation}/bundle.json"),
                review["approval_digest"].as_str().unwrap(),
                3,
            );
            assert_eq!(done["wave"]["completions"][0]["run"]["failure"], "crash");
            attempts.push(review["run"]["run_id"].as_str().unwrap().to_string());
        }
        rejected(&mut f.proposal(), "escalation.accounting.unknown");
        for id in &attempts {
            let preview = checked(&mut f.bound(id), 0);
            checked(
                f.bound(id).args([
                    "--approve",
                    preview["preview"]["approval_digest"].as_str().unwrap(),
                ]),
                0,
            );
        }
        let proposed = checked(
            f.proposal()
                .arg("--output")
                .arg(root.join("co-proposal.json")),
            0,
        );
        assert_eq!(proposed["document"]["schema_version"], 2);
        (parent, proposed)
    }
    fn proposal(&self) -> Command {
        let mut c = command();
        c.args(["escalation", "propose", "--source-bundle"])
            .arg(self.base.files.root.join("failed1/bundle.json"))
            .arg("--store")
            .arg(&self.base.files.store)
            .arg("--policy")
            .arg(self.base.files.root.join("escalation-policy.json"))
            .args(["--max-attempts", "3", "--json"]);
        c
    }
}
#[test]
#[ignore = "real native sandbox, synthetic host, nonempty predecessor artifact handoff"]
fn native_coordinator_escalation_preserves_handoff_approval_and_restart() {
    let f = CoordinatedFixture::new(true);
    let root = &f.base.files.root;
    let (parent, proposed) = f.failed_sources();
    let parent_approval = parent["approval_digest"].as_str().unwrap();
    let mut manifest: Value = read(&root.join("co-prepare.json"));
    manifest["escalation_decision"] = json!("co-proposal.json");
    manifest["generation"] = json!(2);
    manifest["run_id"] = json!("co-target");
    write(&root.join("co-target-prepare.json"), &manifest);
    // A same-byte bundle copied to another locator cannot reuse the proposal.
    let proposal: Value = read(&root.join("co-proposal.json"));
    fs::copy(
        root.join("failed1/bundle.json"),
        root.join("failed1/alias.json"),
    )
    .unwrap();
    let mut changed = proposal.clone();
    changed["source_bundle"] = json!(root.join("failed1/alias.json"));
    write(&root.join("co-proposal.json"), &changed);
    rejected(&mut f.prepare_target(), "escalation.source.changed");
    write(&root.join("co-proposal.json"), &proposal);
    // Same content hash, different artifact identity is still a changed grant.
    let original_grants: Value = read(&root.join("failed1/artifacts.json"));
    let mut forged = original_grants.clone();
    forged["inputs"][0]["artifact_id"] = json!("different-artifact-same-content");
    write(&root.join("failed1/artifacts.json"), &forged);
    let refused = f.prepare_target().output().unwrap();
    assert_eq!(
        refused.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(!root.join("co-target").exists());
    write(&root.join("failed1/artifacts.json"), &original_grants);
    // The saved final request must never receive its footer a second time.
    let original_request: ExecutionRequest = read(&root.join("failed1/request.json"));
    let mut changed_request = original_request.clone();
    changed_request.prompt.push_str(&original_request.prompt);
    write(&root.join("failed1/request.json"), &changed_request);
    let refused = f.prepare_target().output().unwrap();
    assert_eq!(
        refused.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(
        refused.stderr,
        b"{\"schema_version\":1,\"error\":\"runtime.integrity\"}\n"
    );
    assert!(!root.join("co-target").exists());
    write(&root.join("failed1/request.json"), &original_request);
    let mut wrong_generation = manifest.clone();
    wrong_generation["generation"] = json!(3);
    write(&root.join("co-target-prepare.json"), &wrong_generation);
    rejected(&mut f.prepare_target(), "escalation.workflow.changed");
    write(&root.join("co-target-prepare.json"), &manifest);
    checked(&mut f.prepare_target(), 0);
    let prepared: ExecutionRequest = read(&root.join("co-target/request.json"));
    assert!(!prepared.prompt.contains("Agent Router dependency data"));
    assert_eq!(prepared.model.as_str(), "fixture-second");
    let baseline: Value = read(&root.join("co-source/receipt.json"));
    assert_eq!(
        read::<Value>(&root.join("co-target/receipt.json")),
        baseline
    );
    rejected(
        &mut f.base.run(&root.join("co-target/definition.json")),
        "escalation.source.coordinator_required",
    );
    // Simulate a crash after the runtime durably claimed the exact target but
    // before the coordinator committed its step row. The next CLI review must
    // recover this same reservation, never mint a second claim.
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let runtime = Runtime::open(
            &f.base.files.store.join("runtime"),
            RuntimeLimits {
                max_attempts: 3,
                ..RuntimeLimits::default()
            },
        )
        .unwrap();
        let workflow: WorkflowDefinition = read(&f.workflow);
        let baseline = f.base.router.route(&f.base.context).unwrap();
        let receipt = f
            .base
            .router
            .validate_receipt(&f.base.context, &baseline)
            .unwrap();
        let original = router_execution_decision::ExecutionDecision::deterministic(
            &f.base.router,
            &f.base.context,
            &receipt,
        )
        .unwrap();
        let artifacts: RunArtifactContract = read(&root.join("failed1/artifacts.json"));
        let source = router_coordinator::reopen_recorded_step(
            &f.base.files.store.join("coordinator"),
            &runtime,
            &workflow,
            "execute",
            1,
            &f.base.router,
            &f.base.context,
            &original,
            read(&root.join("failed1/request.json")),
            artifacts.clone(),
        )
        .unwrap();
        let proof = runtime
            .review_escalation(&source, &read(&root.join("escalation-policy.json")))
            .unwrap();
        let decision = proof.decision(&f.base.router, &f.base.context).unwrap();
        let mut final_request = prepared.clone();
        final_request
            .prompt
            .push_str(&runtime.render_dependency_context(&artifacts).unwrap());
        let mut id_bytes = b"coordinator-run-id-v1\0".to_vec();
        id_bytes
            .extend(serde_json::to_vec(&(&workflow.definition_sha256, "execute", 2_u32)).unwrap());
        let id = format!("wf-{}", router_adapter_api::content_digest(&id_bytes));
        runtime
            .review_decision(
                &id,
                &f.base.router,
                &f.base.context,
                &decision,
                final_request,
                workflow.plan.clone(),
                "execute",
                Some((&workflow.execution, 2)),
                Some(&artifacts),
            )
            .await
            .unwrap();
        assert_eq!(
            runtime
                .events()
                .unwrap()
                .iter()
                .filter(|event| event.kind == "escalation.claim.v1")
                .count(),
            1
        );
    });
    let review = f.review("execute", 2, "co-target/definition.json", "target-bundle");
    assert_eq!(review["decision_origin"], "escalated");
    assert_eq!(review["baseline_receipt_id"], baseline["receipt_id"]);
    assert_eq!(
        read::<Value>(&root.join("target-bundle/artifacts.json")),
        read::<Value>(&root.join("failed1/artifacts.json"))
    );
    let final_request: ExecutionRequest = read(&root.join("target-bundle/request.json"));
    assert_eq!(
        final_request.prompt,
        read::<ExecutionRequest>(&root.join("failed1/request.json")).prompt
    );
    let approval = review["approval_digest"].as_str().unwrap();
    rejected(
        &mut f.wave_command("target-bundle/bundle.json", parent_approval),
        "coordinator.approval.required_or_changed",
    );
    // Wave limits cannot silently raise another step's default attempt ceiling.
    write(
        &root.join("mixed-wave.json"),
        &json!({"schema_version":1,"steps":[
        {"bundle":root.join("parent/bundle.json"),"approval":parent_approval},
        {"bundle":root.join("target-bundle/bundle.json"),"approval":approval}]}),
    );
    rejected(
        f.action("run-wave")
            .arg("--wave")
            .arg(root.join("mixed-wave.json")),
        "coordinator.wave.attempt_limit_mismatch",
    );
    let done = f.wave("target-bundle/bundle.json", approval, 0);
    assert_eq!(done["wave"]["completions"][0]["run"]["state"], "verifying");
    assert_eq!(
        done["wave"]["completions"][0]["runtime_evidence"]["objective"],
        "unknown"
    );
    f.verify("target-bundle/bundle.json", approval);
    let restarted = checked(
        f.action("service")
            .arg("--bundle")
            .arg(root.join("target-bundle/bundle.json")),
        0,
    );
    assert_eq!(restarted["applied_controls"], 0);
    let runtime = Runtime::open(
        &f.base.files.store.join("runtime"),
        RuntimeLimits::default(),
    )
    .unwrap();
    assert_eq!(
        runtime
            .summary(parent["run"]["run_id"].as_str().unwrap())
            .unwrap()
            .attempts,
        1
    );
    assert_eq!(
        runtime
            .summary(review["run"]["run_id"].as_str().unwrap())
            .unwrap()
            .attempts,
        1
    );
    drop(runtime);
    let replay = f
        .wave_command("target-bundle/bundle.json", approval)
        .output()
        .unwrap();
    assert_eq!(replay.status.code(), Some(2));
    for value in [&parent, &proposed, &review, &done, &restarted] {
        assert!(
            !value
                .to_string()
                .contains("DEPENDENCY_NONEMPTY_SYNTHETIC_DATA")
        );
        assert!(!value.to_string().contains("PRIVATE_ESCALATION_SUBJECT"));
    }
    let runtime = Runtime::open(
        &f.base.files.store.join("runtime"),
        RuntimeLimits::default(),
    )
    .unwrap();
    let parent_artifact = runtime
        .declared_artifacts(parent["run"]["run_id"].as_str().unwrap())
        .unwrap()
        .remove(0);
    runtime
        .purge_declared_artifact(&parent_artifact.artifact_id)
        .unwrap();
    drop(runtime);
    let unavailable = command()
        .args(["prepare", "--manifest"])
        .arg(root.join("co-target-prepare.json"))
        .arg("--output-directory")
        .arg(root.join("purged-input-target"))
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(unavailable.status.code(), Some(2));
    assert!(!root.join("purged-input-target").exists());
}

#[test]
fn coordinator_escalation_fixture_prepares_reviewable_source_material() {
    let f = CoordinatedFixture::new(false);
    let review = f.review("plan", 0, "co-plan/definition.json", "parent");
    assert_eq!(review["executed"], false);
    assert_eq!(review["decision_origin"], "deterministic");
}

#[test]
#[ignore = "real sandbox; cumulative coordinator budget must fail before a new claim"]
fn native_coordinator_cumulative_reservation_refuses_before_claim() {
    let f = CoordinatedFixture::with_budget(true, 36_000);
    f.failed_sources();
    let root = &f.base.files.root;
    let mut manifest: Value = read(&root.join("co-prepare.json"));
    manifest["escalation_decision"] = json!("co-proposal.json");
    manifest["generation"] = json!(2);
    manifest["run_id"] = json!("co-target");
    write(&root.join("co-target-prepare.json"), &manifest);
    checked(&mut f.prepare_target(), 0);
    let mut review = f.action("review");
    review
        .args([
            "--node-id",
            "execute",
            "--generation",
            "2",
            "--source-definition",
        ])
        .arg(root.join("co-target/definition.json"))
        .arg("--sandbox")
        .arg(root.join("sandbox.json"))
        .arg("--output-directory")
        .arg(root.join("target-bundle"));
    rejected(&mut review, "coordinator.limit");
    assert!(!root.join("target-bundle").exists());
    let runtime = Runtime::open(
        &f.base.files.store.join("runtime"),
        RuntimeLimits {
            max_attempts: 3,
            ..RuntimeLimits::default()
        },
    )
    .unwrap();
    assert!(
        !runtime
            .events()
            .unwrap()
            .iter()
            .any(|e| e.kind == "escalation.claim.v1")
    );
    drop(runtime);
    checked(&mut f.action("cancel"), 0);
    rejected(&mut review, "coordinator.cancelled");
    let runtime = Runtime::open(
        &f.base.files.store.join("runtime"),
        RuntimeLimits {
            max_attempts: 3,
            ..RuntimeLimits::default()
        },
    )
    .unwrap();
    assert!(
        !runtime
            .events()
            .unwrap()
            .iter()
            .any(|e| e.kind == "escalation.claim.v1")
    );
}

#[test]
fn coordinator_source_origins_are_rejected_before_following_decision_files() {
    let f = CoordinatedFixture::new(false);
    f.review("plan", 0, "co-plan/definition.json", "parent");
    let path = f.base.files.root.join("co-plan/definition.json");
    let original: Value = read(&path);
    for field in ["generated_plan", "escalation_decision"] {
        let mut changed = original.clone();
        changed[field] = json!("missing-recursive-file.json");
        write(&path, &changed);
        rejected(
            command()
                .args(["escalation", "bound", "--store"])
                .arg(&f.base.files.store)
                .arg("--source-bundle")
                .arg(f.base.files.root.join("parent/bundle.json"))
                .args([
                    "--attempt-run-id",
                    "unknown",
                    "--attempt",
                    "1",
                    "--max-cost-microusd",
                    "1",
                    "--max-tokens",
                    "1",
                    "--json",
                ]),
            "escalation.source.origin_denied",
        );
    }
}

#[test]
#[ignore = "real native sandbox; shared session allocations across workflow handoff and escalation"]
fn native_coordinator_session_budget_charges_predecessor_failures_and_escalated_target() {
    let f = CoordinatedFixture::new(true);
    let root = &f.base.files.root;
    let runtime_root = f.base.files.store.join("runtime");
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&runtime_root)
        .unwrap();
    let workflow: WorkflowDefinition = read(&f.workflow);
    let policy = AdmissionPolicy {
        schema_version: 1,
        global_limit: 4,
        runtimes: BTreeMap::from([(
            "fixture".into(),
            AdmissionRuntimePolicy {
                root_sha256: router_runtime::admission_runtime_root_hash(&runtime_root).unwrap(),
                limit: 4,
            },
        )]),
        providers: BTreeMap::from([("synthetic-provider".into(), 4)]),
        agents: BTreeMap::from([("workers".into(), 4)]),
        agent_mappings: workflow
            .plan
            .nodes
            .iter()
            .map(|n| AdmissionAgentMapping {
                runtime_id: "fixture".into(),
                plan_owner: n.owner.clone(),
                candidate_agent: None,
                quota_id: "workers".into(),
            })
            .collect(),
    };
    let registry = root.join("session-registry");
    let hash = router_runtime::admission_policy_hash(&policy).unwrap();
    let mut store = router_runtime::AdmissionStore::create(&registry, &policy).unwrap();
    let amount = |cost, tokens| BudgetAmount {
        cost_microusd: cost,
        tokens,
    };
    let budget = SessionBudgetPolicy {
        schema_version: 1,
        sessions: BTreeMap::from([(
            "session".into(),
            SessionBudgetRule {
                initial_limit: amount(400, 20000),
                parent_ceiling: amount(400, 20000),
                warning_basis_points: vec![5000, 9000],
            },
        )]),
        runtime_sessions: BTreeMap::from([("fixture".into(), "session".into())]),
    };
    let bh = store.initialize_session_budgets(&budget).unwrap();
    drop(store);
    let config = AdmissionConfig {
        schema_version: 1,
        registry: registry.clone(),
        expected_policy_sha256: hash.clone(),
        runtime_id: "fixture".into(),
        session_budget: Some(SessionBudgetConfig {
            schema_version: 1,
            expected_policy_sha256: bh.clone(),
            session_id: "session".into(),
            approved_limit: amount(400, 20000),
            attempt_allocation: amount(100, 4500),
        }),
    };
    for path in [
        "co-source/definition.json",
        "co-plan/definition.json",
        "co-prepare.json",
    ] {
        let path = root.join(path);
        let mut v: Value = read(&path);
        v["admission"] = json!(config);
        write(&path, &v);
    }
    let (parent, _) = f.failed_sources();
    let status = || {
        router_runtime::AdmissionStore::open(&registry, &hash)
            .unwrap()
            .session_budget_status("session", &bh)
            .unwrap()
    };
    assert_eq!(
        status().committed_allocation,
        amount(300, 13500),
        "small parent bounds for failures do not refund committed allocations"
    );
    let mut manifest: Value = read(&root.join("co-prepare.json"));
    manifest["escalation_decision"] = json!("co-proposal.json");
    manifest["generation"] = json!(2);
    manifest["run_id"] = json!("co-target");
    write(&root.join("co-target-prepare.json"), &manifest);
    checked(&mut f.prepare_target(), 0);
    assert_eq!(
        read::<Value>(&root.join("co-target/definition.json"))["admission"],
        json!(config)
    );
    let reviewed = f.review("execute", 2, "co-target/definition.json", "budget-target");
    let done = f.wave(
        "budget-target/bundle.json",
        reviewed["approval_digest"].as_str().unwrap(),
        0,
    );
    assert_eq!(done["wave"]["completions"][0]["run"]["state"], "verifying");
    let end = status();
    assert_eq!(end.committed_allocation, amount(400, 18000));
    assert_eq!(end.reserved_allocation, amount(0, 0));
    assert_eq!(end.observed_cost_microusd, None);
    assert_eq!(end.observed_tokens, None);
    let parent_id = parent["run"]["run_id"].as_str().unwrap();
    assert_eq!(
        router_runtime::observe(&runtime_root, parent_id)
            .unwrap()
            .attempts,
        1,
        "verified predecessor must not be executed again"
    );
}

#[test]
fn task_report_retains_durable_attempts_when_feedback_was_never_written() {
    let fixture = Fixture::new();
    fixture.attempts();
    let feedback_path = fixture.files.root.join("measurement-feedback");
    let feedback = router_feedback::FeedbackStore::open(&feedback_path).unwrap();
    feedback
        .configure(
            FeedbackPreferences {
                collection_enabled: true,
                ..FeedbackPreferences::default()
            },
            100,
        )
        .unwrap();
    drop(feedback);
    let mut cmd = command();
    cmd.args(["feedback", "--store"])
        .arg(&feedback_path)
        .args(["report", "--runtime-store"])
        .arg(&fixture.files.store)
        .args(["--now", "200", "--json"]);
    let report = checked(&mut cmd, 0);
    let tasks = &report["task_measurement"];
    assert_eq!(tasks["occurrences"].as_array().unwrap().len(), 1);
    assert_eq!(tasks["expected_attempts"], 2);
    assert_eq!(tasks["feedback_attempts"], 0);
    assert_eq!(tasks["missing_feedback_attempts"], 2);
    assert_eq!(tasks["occurrences"][0]["status"], "failed");
    assert!(tasks["total_microusd"].is_null());
    assert_eq!(tasks["source"], "runtime_journal");
    assert_eq!(report, checked(&mut cmd, 0));
}

#[test]
fn task_report_merges_real_retry_approval_keys_without_counting_snapshots_twice() {
    let fixture = Fixture::new();
    let completions = fixture.attempt_sequence(true);
    assert_ne!(
        completions[0].run.approval_digest,
        completions[1].run.approval_digest
    );
    let feedback_path = fixture.files.root.join("measurement-feedback");
    let feedback = router_feedback::FeedbackStore::open(&feedback_path).unwrap();
    feedback
        .configure(
            FeedbackPreferences {
                collection_enabled: true,
                ..FeedbackPreferences::default()
            },
            100,
        )
        .unwrap();
    let base: Value = read(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/feedback/automated-unknown-v1.json"),
    );
    for (index, completion) in completions
        .iter()
        .chain(std::iter::repeat_n(&completions[1], 3))
        .enumerate()
    {
        let run = &completion.run;
        let mut input = base.clone();
        input["binding"]["run_hash"] = json!(format!("{index:064x}"));
        input["run_key_sha256"] = json!(router_adapter_api::content_digest(
            &serde_json::to_vec(&(&run.run_id, &run.definition_hash, &run.approval_digest))
                .unwrap()
        ));
        input["measurements"]["attempts"] = json!(run.attempts);
        input["measurements"]["usage_scope"] = json!("per_attempt");
        input["measurements"]["usage"] = serde_json::to_value(HostUsage {
            input_tokens: UsageField::host_reported(u64::from(run.attempts) * 10),
            cached_input_tokens: UsageField::host_reported(0),
            cache_write_input_tokens: UsageField::host_reported(0),
            output_tokens: UsageField::host_reported(0),
            reasoning_output_tokens: UsageField::UNKNOWN,
        })
        .unwrap();
        feedback
            .record(serde_json::from_value(input).unwrap(), 102)
            .unwrap();
    }
    let accepted = &completions[1].run;
    let accepted_key = router_adapter_api::content_digest(
        &serde_json::to_vec(&(
            &accepted.run_id,
            &accepted.definition_hash,
            &accepted.approval_digest,
        ))
        .unwrap(),
    );
    for kind in [
        FeedbackFactKind::Verification {
            validation: VerificationOutcome::Passed,
            objective: VerificationOutcome::Passed,
            evidence_sha256: "a".repeat(64),
        },
        FeedbackFactKind::Integration {
            outcome: IntegrationOutcome::Applied,
        },
    ] {
        feedback
            .record_fact(
                FeedbackFact {
                    schema_version: 1,
                    run_key_sha256: accepted_key.clone(),
                    observed_at_unix_seconds: 120,
                    kind,
                },
                120,
            )
            .unwrap();
    }
    drop(feedback);
    let pricing = fixture.files.root.join("measurement-pricing.json");
    write(
        &pricing,
        &json!({"schema_version":1,"version":"synthetic-v1","source":"synthetic","observed_at_unix_seconds":90,"models":{"fixture-model":{"input_microusd_per_million":1000000,"cached_input_microusd_per_million":0,"output_microusd_per_million":0}}}),
    );
    let mut cmd = command();
    cmd.args(["feedback", "--store"])
        .arg(&feedback_path)
        .args(["report", "--runtime-store"])
        .arg(&fixture.files.store)
        .arg("--pricing")
        .arg(&pricing)
        .args(["--now", "200", "--json"]);
    let report = checked(&mut cmd, 0);
    let tasks = &report["task_measurement"];
    assert_eq!(tasks["expected_attempts"], 2);
    assert_eq!(tasks["feedback_attempts"], 2);
    assert_eq!(tasks["missing_feedback_attempts"], 0);
    assert_eq!(tasks["unmatched_feedback_runs"], 0);
    assert_eq!(tasks["total_microusd"], 30);
    assert_eq!(tasks["accepted_occurrences"], 1);
    assert_eq!(tasks["per_accepted_microusd"], 30);
    assert_eq!(report, checked(&mut cmd, 0));
    let mut qualified = serde_json::json!({"schema_version":2,"version":"synthetic-v2","source":"synthetic","observed_at_unix_seconds":90,"models":{"fixture-model":{
        "input_microusd_per_million":1000000,"cache_read_microusd_per_million":0,"cache_write_microusd_per_million":2000000,"cache_write_scope":"all_reported_writes","output_microusd_per_million":0,"reasoning":{"mode":"included_in_output"}
    }}});
    write(&pricing, &qualified);
    let qualified_report = checked(&mut cmd, 0);
    assert_eq!(qualified_report["schema_version"], 5);
    assert_eq!(qualified_report["task_measurement"]["total_microusd"], 30);
    assert_eq!(
        qualified_report["task_measurement"]["per_accepted_microusd"],
        30
    );
    qualified["models"]["fixture-model"]["cache_write_scope"] = Value::Null;
    write(&pricing, &qualified);
    let incomplete = checked(&mut cmd, 0);
    assert!(incomplete["task_measurement"]["total_microusd"].is_null());
    assert_eq!(
        incomplete["task_measurement"]["known_subtotal_microusd"],
        30
    );
}
