//! Explicit local OS qualification. No fixture verifier and no model transport.
//! The controller root is intentionally not a TempDir: a panic must never
//! recursively delete resources whose namespace cleanup remains UNKNOWN.
use super::*;
use crate::{AdmissionStore, RuntimeLimits, leases::LeaseStorage};
use router_adapter_api::{
    AdapterError, CapabilityEvidence, HostObservation, SnapshotValidation,
    authorize_execution_with_capability_acceptance,
    execution_authorization_digest_with_capability_acceptance,
};
use router_catalog::Catalog;
use router_policy::PhaseRouter;
use router_types::*;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Instant,
};

const VERSION: &str = "0.159.2-linux-arm64-musl";
fn mkdir(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn pin(path: &Path) -> FiniteClientFile {
    FiniteClientFile {
        path: path.to_str().unwrap().into(),
        sha256: content_digest(&fs::read(path).unwrap()),
    }
}
fn owned_review_mode(
    root: &Path,
    run: &PreparedRun,
    listener: TcpListener,
    id: &str,
    workspace: Option<FiniteClientWorkspace>,
    tools: bool,
) -> FiniteClientReview {
    owned_review_profile(root, run, listener, id, workspace, tools, None)
}
fn owned_review_profile(
    root: &Path,
    run: &PreparedRun,
    listener: TcpListener,
    id: &str,
    workspace: Option<FiniteClientWorkspace>,
    tools: bool,
    subscription: Option<&SubscriptionControllerBinding>,
) -> FiniteClientReview {
    let programs = PathBuf::from(std::env::var("AR_FINITE_PROGRAMS").unwrap());
    let broker = if listener.local_addr().unwrap().ip().is_unspecified() {
        OwnedBroker::from_isolated_listener(listener).unwrap()
    } else {
        OwnedBroker::from_listener(listener).unwrap()
    };
    let state = if let Some(binding) = subscription {
        broker.prepare_codex_subscription_tools_state(
            root,
            run,
            &binding.account_sha256,
            &binding.controller_sha256,
        )
    } else if tools {
        broker.prepare_codex_tools_state(root, run)
    } else {
        broker.prepare_codex_state(root, run)
    }
    .unwrap();
    let manifest = FiniteClientManifest {
        schema_version: 1,
        task_id: id.into(),
        host_snapshot_id: "q01-linux-local".into(),
        client: pin(&programs.join("client")),
        native: pin(&programs.join("native")),
        helper: pin(&programs.join("helper")),
        wrapper: pin(&programs.join("guard")),
        profile: pin(&programs.join("profile")),
        configuration: state.configuration().clone(),
        private_state: state.path().to_str().unwrap().into(),
        native_version: VERSION.into(),
        broker_endpoint: broker.endpoint().into(),
        broker_instance_sha256: broker.instance_sha256().into(),
    };
    let review = FiniteClientReview::with_codex_state(
        manifest,
        run,
        broker,
        ResourceLimits::default(),
        state,
    )
    .unwrap();
    let review = if let Some(workspace) = workspace {
        review.with_write_workspace(workspace).unwrap()
    } else {
        review
    };
    let review = review
        .with_linux_namespace(pin(&programs.join("namespace")))
        .unwrap();
    if tools {
        let public = ["AGENTS.md", "statement.md", "lib.rs"]
            .into_iter()
            .map(|name| {
                (
                    name.into(),
                    content_digest(&fs::read(Path::new(&run.cwd).join(name)).unwrap()),
                )
            })
            .collect();
        review
            .with_mcp_tools(
                public,
                crate::finite_tools::Limits {
                    max_calls: 8,
                    max_file_bytes: 32768,
                    max_output_bytes: 8192,
                    max_total_output_bytes: 32768,
                    max_exec_ms: 5000,
                    max_total_exec_ms: 15000,
                    max_session_ms: run.timeout_ms,
                    max_scratch_entries: 64,
                    max_scratch_bytes: 16777216,
                },
            )
            .unwrap()
    } else {
        review
    }
}
fn owned_review(
    root: &Path,
    run: &PreparedRun,
    listener: TcpListener,
    id: &str,
    workspace: Option<FiniteClientWorkspace>,
) -> FiniteClientReview {
    owned_review_mode(root, run, listener, id, workspace, false)
}
fn seed_run(workspace: &Path) -> PreparedRun {
    PreparedRun {
        schema_version: 1,
        receipt_id: "a".repeat(64),
        source_state: "b".repeat(40),
        scope: vec!["review.rs".into()],
        authorization_digest: "c".repeat(64),
        snapshot_hash: "d".repeat(64),
        host: HarnessId::parse("codex").unwrap(),
        requested_model: ModelId::parse("gpt-6-luna").unwrap(),
        requested_effort: EffortLevel::Medium,
        program: "finite-client".into(),
        argv: vec!["--worker".into()],
        cwd: workspace.to_str().unwrap().into(),
        stdin: PreparedInput::new(vec![]),
        mode: ExecutionMode::Execute,
        target: ExecutionTarget::ExternalWorker,
        sandbox: ExecutionSandbox::ReadOnly,
        timeout_ms: 25_000,
        max_output_bytes: 65536,
        degradations: vec![],
        missing_runtime_evidence: vec![],
        parent_model_changed: false,
    }
}
fn git(root: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("/usr/bin/git")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            "-C",
        ])
        .arg(root)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}
fn user_text(value: &Value) -> String {
    let mut text = String::new();
    for message in value["input"].as_array().unwrap() {
        if message["role"] != "user" {
            continue;
        }
        if let Some(content) = message["content"].as_str() {
            text.push_str(content);
        }
        if let Some(content) = message["content"].as_array() {
            for item in content {
                if let Some(s) = item["text"].as_str() {
                    text.push_str(s);
                }
            }
        }
    }
    text
}
fn serve(
    listener: TcpListener,
    contract: Value,
    response: Vec<u8>,
    posts: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    hold: bool,
    root: PathBuf,
) -> std::thread::JoinHandle<()> {
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        // Two fixed OS canaries and retained-asset hashing happen before the
        // first request. The actual worker still has its separate 5s/25s limit.
        let deadline = Instant::now() + Duration::from_secs(300);
        while Instant::now() < deadline {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            let (mut stream, _) = match listener.accept() {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(e) => panic!("accept: {e}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let request = line.clone();
            let mut length = 0;
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                assert!(!line.is_empty() && line.len() < 8192);
                let lower = line.to_ascii_lowercase();
                assert!(!lower.starts_with("authorization:"));
                if let Some(n) = lower.strip_prefix("content-length:") {
                    length = n.trim().parse::<usize>().unwrap();
                }
            }
            if request.starts_with("GET /__router_probe__ ") {
                stream
                    .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .unwrap();
                continue;
            }
            assert!(
                request.starts_with("POST /v1/responses "),
                "unexpected local endpoint"
            );
            assert!((1..=262144).contains(&length));
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let v = router_adapter_api::strict_json_limited(&body, 262144).unwrap();
            assert_eq!(v["model"], contract["expected_model"]);
            assert_eq!(v["reasoning"]["effort"], contract["expected_effort"]);
            assert_eq!(v["stream"], true);
            assert!(v.get("store").is_none_or(|v| v == false));
            assert!(
                user_text(&v).contains(
                    contract["required_request_input_fragment"]
                        .as_str()
                        .unwrap()
                )
            );
            assert_eq!(
                posts.fetch_add(1, Ordering::SeqCst),
                0,
                "exactly one authored response"
            );
            fs::write(root.join("provider.json"),serde_json::to_vec_pretty(&json!({
                "model":v["model"],"effort":v["reasoning"]["effort"],"request_sha256":content_digest(&body),
                "auth_header_present":false,"authored_local_requests":1,"model_calls_started":0
            })).unwrap()).unwrap();
            if hold {
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(20));
                }
                return;
            }
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",response.len()).unwrap();
            stream.write_all(&response).unwrap();
            return;
        }
        panic!("local fixture never received approved request");
    })
}
async fn discovery(
    root: &Path,
    run: &PreparedRun,
    listener: TcpListener,
    asset_store: &Path,
    workspace: Option<FiniteClientWorkspace>,
    tools: bool,
) -> (ValidatedHostObservation, StoredCapabilityProofVerifier) {
    // This is an actual, separate diagnostic run. Its receipt is not dispatch
    // authority. The admitted Runtime must repeat canaries with its own owners.
    let review = owned_review_mode(asset_store, run, listener, "discovery", workspace, tools);
    let binding = review.proof_binding("q01-linux-local").unwrap();
    let digest = review.approval_digest().to_owned();
    let mut state = review
        .approve(&digest)
        .unwrap()
        .into_namespace_state()
        .unwrap();
    let home = state.path().to_owned();
    let control = home.join("tmp/discovery");
    mkdir(&control);
    let hidden = root.join("controller-private");
    fs::write(&hidden, b"never mounted").unwrap();
    let other = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    drop(TcpStream::connect(other.local_addr().unwrap()).unwrap());
    let mut entropy = [0; 32];
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut entropy)
        .unwrap();
    let nonce = content_digest(&entropy);
    let write = run.sandbox == ExecutionSandbox::WorkspaceWrite;
    if write {
        fs::write(home.join("tmp/scoped-file"), b"private write canary").unwrap();
    }
    let mut view = ProbeView {
        tools: None,
        temporary: home.join("tmp"),
        control: control.clone(),
        hidden: hidden.clone(),
        denied_port: other.local_addr().unwrap().port(),
        nonce: nonce.clone(),
    };
    if tools {
        view.tools = Some(ToolsProbeView::prepare(&state, &view).unwrap());
    }
    let mut command = composition_command(&state, Some(&view)).unwrap();
    let leases = LeaseStorage::open(root).unwrap();
    let (mut record, path) = leases.create("discovery", 1).unwrap();
    record.require_namespace(true);
    state.arm_cleanup(Some(&path), true).unwrap();
    command.env("ROUTER_RUNTIME_LEASE", path);
    let captured = crate::process::capture(
        command,
        vec![],
        10_000,
        65536,
        100,
        &Cancellation::default(),
    )
    .await
    .unwrap();
    fs::write(root.join("discovery.stdout"), &captured.stdout).unwrap();
    fs::write(root.join("discovery.stderr"), &captured.stderr).unwrap();
    let proof = leases.cleanup_proof("discovery", 1, &record).unwrap();
    assert_eq!(proof.evidence, ProcessCleanupEvidence::NamespaceTerminated);
    let success = captured.outcome.exit_code == Some(0);
    let effects = if success {
        let a = fs::metadata(control.join("heartbeat")).unwrap().len();
        std::thread::sleep(Duration::from_millis(60));
        let b = fs::metadata(control.join("heartbeat")).unwrap().len();
        a > 1
            && a == b
            && fs::read(control.join("control")).unwrap() == nonce.as_bytes()
            && (tools
                || !write
                || fs::read(home.join("tmp/scoped-file")).unwrap() == nonce.as_bytes())
    } else {
        false
    };
    if tools && success {
        view.tools.as_ref().unwrap().verify(&nonce).unwrap();
    }
    state.cleanup_with_proof(&proof).unwrap();
    assert!(!home.exists());
    assert!(
        success,
        "discovery rejected; inspect private discovery.stderr"
    );
    assert!(effects);
    let lines: Vec<_> = captured
        .stdout
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(lines.len(), if tools { 3 } else { 2 });
    let canary: Value = serde_json::from_slice(lines[0]).unwrap();
    assert_eq!(canary["memory_bytes"], 8589934592u64);
    assert_eq!(canary["nonce"], nonce);
    assert_eq!(canary["workspace_write"], write && !tools);
    let version: Value = serde_json::from_slice(lines[1]).unwrap();
    assert_eq!(
        version,
        json!({"finite_client_probe":"v1","native_version":"codex-cli 0.159.2"})
    );
    let proof_root = root.join("baseline-proofs");
    mkdir(&proof_root);
    let mut store = crate::CapabilityProofStore::create(&proof_root).unwrap();
    let mut secret = [0; 32];
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut secret)
        .unwrap();
    let now = crate::now().unwrap();
    let capabilities = if tools {
        vec![
            Capability::Network,
            Capability::WorkspaceWrite,
            Capability::Tools,
        ]
    } else if write {
        vec![Capability::Network, Capability::WorkspaceWrite]
    } else {
        vec![Capability::Network]
    };
    let mut sources = vec![];
    let mut evidence = BTreeMap::new();
    for capability in &capabilities {
        let capability = *capability;
        let record = CapabilityProofRecord {
            schema_version: 1,
            proof_id: format!(
                "live-local-{}",
                if capability == Capability::Network {
                    "network"
                } else if capability == Capability::Tools {
                    "tools"
                } else {
                    "write"
                }
            ),
            sequence: store.next_sequence(&secret).unwrap(),
            store_id: store.store_id().into(),
            capability,
            tier: CapabilityProofTier::Proven,
            network_scope: (capability == Capability::Network)
                .then_some(CapabilityNetworkScope::LoopbackFetch),
            binding: binding.clone(),
            model_id: run.requested_model.to_string(),
            nonce_sha256: content_digest(nonce.as_bytes()),
            expected_effect_sha256: content_digest(&captured.stdout),
            started_at_unix_seconds: now,
            ended_at_unix_seconds: now,
            max_age_seconds: 300,
            outcome: CapabilityAttemptOutcome::Succeeded,
        };
        let auth = CapabilityProofKey::derive(&secret, store.store_id())
            .unwrap()
            .authenticate(record)
            .unwrap();
        let source = EvidenceSource {
            id: auth.record.proof_id.clone(),
            kind: EvidenceKind::HostRuntime,
            observed_version: Some(VERSION.into()),
            observed_at_unix_seconds: now,
            content_sha256: auth.digest().unwrap(),
        };
        store.append(&auth, &secret).unwrap();
        evidence.insert(
            capability,
            CapabilityEvidence {
                support: CapabilitySupport::Supported,
                source_ids: [source.id.clone()].into(),
            },
        );
        sources.push(source);
    }
    drop(store);
    let verifier =
        StoredCapabilityProofVerifier::open_existing(&proof_root, secret, vec![binding]).unwrap();
    let host = HostSnapshot {
        id: "q01-linux-local".into(),
        harness: run.host.clone(),
        supported_models: [run.requested_model.clone()].into(),
        supported_efforts: BTreeMap::from([(
            run.requested_model.clone(),
            [run.requested_effort].into(),
        )]),
        capabilities: capabilities.into_iter().collect(),
    };
    let observation = HostObservation {
        schema_version: 1,
        host,
        capabilities: evidence,
        evidence: sources,
        observed_at_unix_seconds: now,
        snapshot_hash: String::new(),
        attestations: None,
    }
    .seal()
    .unwrap();
    let snapshot = ValidatedHostObservation::from_observation_with_verifier(
        observation,
        SnapshotValidation {
            now_unix_seconds: now,
            max_age_seconds: 300,
        },
        Some(&verifier),
    )
    .unwrap();
    (snapshot, verifier)
}
struct Collect(Mutex<Vec<u8>>);
impl HarnessAdapter for Collect {
    fn host(&self) -> &'static str {
        "codex"
    }
    fn prepare(
        &self,
        _: &ValidatedExecutionRequest,
    ) -> std::result::Result<PreparedRun, AdapterError> {
        panic!("frozen preparation must be used")
    }
    fn decode_stream(
        &self,
        bytes: &[u8],
        outcome: TransportOutcome,
        max: usize,
    ) -> std::result::Result<RuntimeEvidence, AdapterError> {
        *self.0.lock().unwrap() = bytes.to_vec();
        adapter_codex::CodexAdapter.decode_stream(bytes, outcome, max)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    ReadOnly,
    Write,
    McpWrite,
    McpCreate,
    McpTimeout,
    McpCancel,
    McpEofHold,
    Timeout,
    Cancel,
    EofHold,
}
fn replacement_stream(template: &[u8], replacement: &str) -> Vec<u8> {
    let body = serde_json::to_string(&json!({"replacement":replacement})).unwrap();
    let mut result = String::new();
    for line in std::str::from_utf8(template).unwrap().lines() {
        if let Some(data) = line.strip_prefix("data: ") {
            let mut row: Value = serde_json::from_str(data).unwrap();
            match row["type"].as_str().unwrap() {
                "response.output_text.delta" => row["delta"] = body.clone().into(),
                "response.output_text.done" => row["text"] = body.clone().into(),
                "response.output_item.done" => {
                    row["item"]["content"][0]["text"] = body.clone().into()
                }
                "response.completed" => {
                    row["response"]["output"][0]["content"][0]["text"] = body.clone().into()
                }
                _ => {}
            }
            result.push_str("data: ");
            result.push_str(&serde_json::to_string(&row).unwrap());
            result.push('\n');
        } else {
            result.push_str(line);
            result.push('\n');
        }
    }
    result.into_bytes()
}
async fn run_case(case: Case) {
    run_case_mode(case, false).await;
}
async fn run_case_mode(case: Case, subscription: bool) {
    run_case_profile(case, subscription, false).await;
}
async fn run_case_profile(case: Case, subscription: bool, unknown: bool) {
    let external = subscription && std::env::var_os("AR_SUBSCRIPTION_EXTERNAL").is_some();
    let tools = matches!(
        case,
        Case::McpWrite | Case::McpCreate | Case::McpTimeout | Case::McpCancel | Case::McpEofHold
    );
    let create = case == Case::McpCreate;
    let write = case == Case::Write || tools;
    let run_id = if write { "q02" } else { "q01" };
    let name = if create {
        "result.rs"
    } else if write {
        "lib.rs"
    } else {
        "review.rs"
    };
    assert_eq!(std::env::consts::ARCH, "aarch64");
    assert_eq!(
        fs::read_to_string("/sys/fs/cgroup/memory.max")
            .unwrap()
            .trim(),
        "8589934592"
    );
    assert_eq!(
        fs::read_to_string("/sys/fs/cgroup/memory.swap.max")
            .unwrap()
            .trim(),
        "0"
    );
    let root = PathBuf::from(std::env::var("AR_FINITE_ROOT").unwrap());
    mkdir(&root);
    let fixture = PathBuf::from(std::env::var("AR_FINITE_FIXTURE").unwrap());
    let mut contract: Value =
        serde_json::from_slice(&fs::read(fixture.join("contract.json")).unwrap()).unwrap();
    let template = fs::read(fixture.join("controller/response.sse")).unwrap();
    assert_eq!(
        content_digest(&template),
        "a2832efdf5d80f5b5de8f99a7deb2e1f1850fdd593eea613ec34c7b15eb3a999"
    );
    let source_workspace = root.join("candidate");
    mkdir(&source_workspace);
    let (response, expected) = if write {
        let bundle = PathBuf::from(std::env::var("AR_FINITE_WRITE_FIXTURE").unwrap());
        let mut prompt = if tools {
            format!(
                "R2-LOCAL-TOOLS-V1\nComplete the public task using the three advertised finite tools. Write the complete result to {name} only. Use .scratch for temporary checks. Return a short completion message. This is authored local qualification, not a model trial.\n"
            )
        } else {
            String::from(
                "BOUNDED-REPLACEMENT-V1\nImplement lib.rs according to the public statement. Return only JSON with one replacement string containing the complete updated lib.rs. Do not use tools or modify other files.\n",
            )
        };
        for name in ["AGENTS.md", "statement.md", "lib.rs"] {
            let bytes = fs::read(bundle.join("candidate").join(name)).unwrap();
            assert!(bytes.len() <= 32768);
            prompt.push_str(&format!(
                "\nPUBLIC FILE {name}\n{}",
                std::str::from_utf8(&bytes).unwrap()
            ));
            fs::write(source_workspace.join(name), bytes).unwrap();
        }
        let control: Value = router_adapter_api::strict_json_limited(
            &fs::read(bundle.join("controller/control-output.json")).unwrap(),
            65536,
        )
        .unwrap();
        let expected = control["lib.rs"].as_str().unwrap().to_owned();
        assert!(!expected.is_empty() && expected.len() <= 32768);
        contract["prompt"] = prompt.into();
        contract["required_request_input_fragment"] =
            String::from_utf8(fs::read(source_workspace.join("lib.rs")).unwrap())
                .unwrap()
                .into();
        (replacement_stream(&template, &expected), Some(expected))
    } else {
        let code = fs::read(fixture.join("candidate/review.rs")).unwrap();
        assert_eq!(
            content_digest(&code),
            "fffb14b9a431b05c30fc518f5af9b7ad15d63fe831a9c5514685acae871344b8"
        );
        fs::write(source_workspace.join(name), code).unwrap();
        (template, None)
    };
    let before: BTreeMap<String, String> = fs::read_dir(&source_workspace)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().to_str().unwrap().into(),
                content_digest(&fs::read(entry.path()).unwrap()),
            )
        })
        .collect();
    git(&source_workspace, &["init", "-q"]);
    git(&source_workspace, &["add", "--all"]);
    git(
        &source_workspace,
        &[
            "-c",
            "user.name=Local qualification",
            "-c",
            "user.email=qualification@example.invalid",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "public fixture input",
        ],
    );
    let source = crate::source_state(&source_workspace).await.unwrap();
    let mut phase: PhaseRouteRequest = serde_json::from_slice(include_bytes!(
        "../../../../fixtures/examples/phase-request.json"
    ))
    .unwrap();
    phase.phase = StageKind::Execute;
    phase.task.scope = vec![name.into()];
    phase.task.required_capabilities = if tools {
        [
            Capability::Network,
            Capability::WorkspaceWrite,
            Capability::Tools,
        ]
        .into()
    } else if write {
        [Capability::Network, Capability::WorkspaceWrite].into()
    } else {
        [Capability::Network].into()
    };
    phase.task.allowed_mutations = if write {
        [Mutation::Network, Mutation::WorkspaceWrite].into()
    } else {
        [Mutation::Network].into()
    };
    if write {
        phase.task.kind = TaskKind::Implement;
        phase.task.objective = "Correct the public bounded score function".into();
    }
    phase.task.budget.max_elapsed_ms = 60_000;
    phase.task.budget.max_tokens = 8192;
    phase.restrictions.allowed_mutations = Some(phase.task.allowed_mutations.clone());
    phase.restrictions.allowed_capabilities = Some(phase.task.required_capabilities.clone());
    phase.restrictions.max_tokens = Some(8192);
    phase.restrictions.policy_hash.clear();
    phase.restrictions.policy_hash =
        content_digest(&serde_json::to_vec(&phase.restrictions).unwrap());
    phase.candidates.truncate(1);
    phase.candidates[0].model = ModelId::parse("gpt-6-luna").unwrap();
    phase.candidates[0].estimated_cost_microusd = 0;
    if write && !external {
        phase.candidates[0].verification = PhaseVerification::Independent;
    }
    if subscription {
        phase.candidates[0].effort = EffortLevel::Xhigh;
    }
    if tools {
        phase.candidates[0].tools = [
            "mcp__finite__read_file",
            "mcp__finite__write_file",
            "mcp__finite__exec",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        for id in &phase.candidates[0].tools {
            phase.registry.assets.push(PhaseRegisteredAsset {
                kind: PhaseAssetKind::Tool,
                id: id.clone(),
                content_sha256: content_digest(include_bytes!("../finite_tools/transport.rs")),
                trust: SkillTrust::TrustedLocal,
                license: "FSL-1.1-ALv2".into(),
                permission: CapabilitySupport::Supported,
                required_capabilities: [Capability::Tools].into(),
                required_mutations: BTreeSet::new(),
                allowed_sandboxes: [PhaseSandbox::WorkspaceWrite].into(),
                maximum_sensitivity: DataSensitivity::Public,
            });
        }
    }
    phase.candidates[0].sandbox = if write {
        PhaseSandbox::WorkspaceWrite
    } else {
        PhaseSandbox::ReadOnly
    };
    let plan = router_workflow::build_plan(
        &phase.task,
        WorkflowPreset::DirectSafe,
        router_workflow::PlanLimits {
            reserve_elapsed_ms: 1000,
            ..Default::default()
        },
    )
    .unwrap();
    let store = root.join("runtime");
    mkdir(&store);
    let registry = root.join("admission");
    let policy = AdmissionPolicy {
        schema_version: 1,
        global_limit: 1,
        runtimes: BTreeMap::from([(
            "fixture".into(),
            AdmissionRuntimePolicy {
                root_sha256: crate::admission_runtime_root_hash(&store).unwrap(),
                limit: 1,
            },
        )]),
        providers: BTreeMap::from([(
            if subscription {
                "codex_subscription_relay"
            } else {
                "local_fixture"
            }
            .into(),
            1,
        )]),
        agents: BTreeMap::from([("worker".into(), 1)]),
        agent_mappings: vec![AdmissionAgentMapping {
            runtime_id: "fixture".into(),
            plan_owner: plan
                .nodes
                .iter()
                .find(|n| n.id == "execute")
                .unwrap()
                .owner
                .clone(),
            candidate_agent: None,
            quota_id: "worker".into(),
        }],
    };
    let admission = AdmissionStore::create(&registry, &policy).unwrap();
    let config = AdmissionConfig {
        schema_version: 1,
        registry,
        expected_policy_sha256: admission.policy_hash().into(),
        runtime_id: "fixture".into(),
        session_budget: None,
    };
    fs::write(
        root.join("admission-config.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let runtime = Runtime::open_with_admission(
        &store,
        RuntimeLimits {
            output_retention: OutputRetentionPolicy::PrivateArtifacts {
                retention_seconds: 3600,
            },
            ..Default::default()
        },
        &config,
    )
    .unwrap();
    let listener = TcpListener::bind(("0.0.0.0", 0)).unwrap();
    rustix::net::sockopt::set_socket_reuseaddr(&listener, false).unwrap();
    rustix::net::sockopt::set_socket_reuseport(&listener, false).unwrap();
    let address =
        std::net::SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
    let posts = Arc::new(AtomicUsize::new(0));
    let stop_server = Arc::new(AtomicBool::new(false));
    let mut server = Some(
        if !subscription && matches!(case, Case::McpWrite | Case::McpCreate) {
            let script = root.join("authored-tools.json");
            let updated = expected.as_ref().unwrap();
            let steps = json!([
                {"tool":"mcp__finite__read_file","arguments":{"path":"statement.md"},"expected":{"exit_code":0,"termination":"exited","truncated":false}},
                {"tool":"mcp__finite__write_file","arguments":{"path":name,"content":updated,"create_new":create},"expected":{"exit_code":0,"termination":"exited","truncated":false}},
                {"tool":"mcp__finite__read_file","arguments":{"path":name},"expected":{"exit_code":0,"termination":"exited","truncated":false}}
            ]);
            fs::write(&script,serde_json::to_vec(&json!({"model":"gpt-6-luna","effort":"medium","marker":"R2-LOCAL-TOOLS-V1","steps":steps})).unwrap()).unwrap();
            crate::finite_client::native_tools_tests::broker(
                listener.try_clone().unwrap(),
                PathBuf::from(std::env::var("AR_MCP_NATIVE_INPUTS").unwrap()),
                script,
                PathBuf::from(std::env::var("AR_MCP_NATIVE_ADAPTER").unwrap()),
                root.clone(),
                4,
            )
        } else {
            serve(
                listener.try_clone().unwrap(),
                contract.clone(),
                response,
                posts.clone(),
                stop_server.clone(),
                matches!(
                    case,
                    Case::Timeout
                        | Case::Cancel
                        | Case::EofHold
                        | Case::McpTimeout
                        | Case::McpCancel
                        | Case::McpEofHold
                ),
                root.clone(),
            )
        },
    );
    let discovery_root = root.join("discovery");
    mkdir(&discovery_root);
    let diagnostic_view = if write {
        Some(
            runtime
                .prepare_finite_output_workspace(
                    &source_workspace,
                    "discovery",
                    name,
                    if create {
                        FiniteOutputMode::CreateNew
                    } else {
                        FiniteOutputMode::ReplaceExisting
                    },
                )
                .await
                .unwrap(),
        )
    } else {
        None
    };
    let diagnostic_path = diagnostic_view
        .as_ref()
        .map_or(source_workspace.as_path(), |v| v.path());
    let mut seed = seed_run(diagnostic_path);
    if subscription {
        seed.requested_effort = EffortLevel::Xhigh;
    }
    seed.scope = vec![name.into()];
    seed.source_state = source.clone();
    seed.sandbox = if write {
        ExecutionSandbox::WorkspaceWrite
    } else {
        ExecutionSandbox::ReadOnly
    };
    let (snapshot, verifier) = discovery(
        &discovery_root,
        &seed,
        listener.try_clone().unwrap(),
        &store,
        diagnostic_view,
        tools,
    )
    .await;
    let runtime = runtime.with_capability_proof_verifier(Arc::new(verifier));
    let view = if write {
        Some(
            runtime
                .prepare_finite_output_workspace(
                    &source_workspace,
                    run_id,
                    name,
                    if create {
                        FiniteOutputMode::CreateNew
                    } else {
                        FiniteOutputMode::ReplaceExisting
                    },
                )
                .await
                .unwrap(),
        )
    } else {
        None
    };
    let workspace = view
        .as_ref()
        .map_or_else(|| source_workspace.clone(), |v| v.path().to_owned());
    let caps = phase.task.required_capabilities.clone();
    let catalog=Catalog::from_json(&serde_json::to_vec(&json!({"schema_version":1,"version":"local-authored-fixture","models":[{"id":"gpt-6-luna","stages":["execute"],"efforts":[if subscription {"xhigh"} else {"medium"}],"capabilities":caps,"quality_micros":1,"cost_micros":0,"latency_micros":1,"source":"Authored local SSE; no real model availability or price claim"}],"skills":[]})).unwrap()).unwrap();
    let router = PhaseRouter::stable_v2();
    let context = router.context(phase, &snapshot, &catalog).unwrap();
    let receipt = router.route(&context).unwrap();
    let selected = receipt.selected.as_ref().expect("local route must select");
    let request = ExecutionRequest {
        schema_version: 1,
        receipt_id: receipt.receipt_id.clone(),
        candidate_id: selected.candidate.id.clone(),
        phase: receipt.phase,
        host: snapshot.host().harness.clone(),
        model: selected.candidate.model.clone(),
        effort: selected.candidate.effort,
        workspace: workspace.to_str().unwrap().into(),
        source_state: source.clone(),
        scope: vec![name.into()],
        sandbox: if write {
            ExecutionSandbox::WorkspaceWrite
        } else {
            ExecutionSandbox::ReadOnly
        },
        required_capabilities: router.execution_capabilities(&context, selected).unwrap(),
        tools: if tools {
            ToolSelection::AllowList(vec![
                "mcp__finite__read_file".into(),
                "mcp__finite__write_file".into(),
                "mcp__finite__exec".into(),
            ])
        } else {
            ToolSelection::Disabled
        },
        agent: None,
        skills: vec![],
        prompt: contract["prompt"].as_str().unwrap().into(),
        mode: ExecutionMode::Execute,
        target: ExecutionTarget::ExternalWorker,
        allow_degradation: false,
        timeout_ms: if matches!(case, Case::Timeout | Case::McpTimeout) {
            5000
        } else {
            25_000
        },
        max_output_bytes: 65536,
    };
    let auth = execution_authorization_digest_with_capability_acceptance(
        &request,
        &snapshot,
        &context.request().restrictions,
        context.capability_acceptance(),
    )
    .unwrap();
    let authorized = authorize_execution_with_capability_acceptance(
        request.clone(),
        &snapshot,
        &context.request().restrictions,
        context.capability_acceptance(),
        Some(&auth),
    )
    .unwrap();
    let mut prepared = router_adapter_api::prepared_run(
        &authorized,
        "finite-client",
        vec!["--worker".into()],
        vec![],
    )
    .unwrap();
    prepared.missing_runtime_evidence.clear();
    let mut parent_peer = None;
    let mut descriptor = None;
    let client = if subscription {
        stop_server.store(true, Ordering::SeqCst);
        server.take().unwrap().join().unwrap();
        let driver = PathBuf::from(std::env::var("AR_SUBSCRIPTION_DRIVER").unwrap());
        let packet = json!({"qualification_only":true,"assignment_id":"t02-Lx-r1-H0",
            "model":"gpt-6-luna","effort":"xhigh","marker":"R2-LOCAL-TOOLS-V1",
            "output_file":"lib.rs","output_content":expected.as_ref().unwrap(),
            "account_sha256":"b".repeat(64),"budget_microcredits":200000000u64,
            "evidence_directory":root.to_str().unwrap()});
        let path = root.join("subscription-descriptor.json");
        fs::write(&path, serde_json::to_vec(&packet).unwrap()).unwrap();
        let configuration: Value = if external {
            println!(
                "\nAR_RELAY_PREPARE {}",
                serde_json::to_string(&packet).unwrap()
            );
            std::io::stdout().flush().unwrap();
            json!({"configuration_sha256":std::env::var("AR_SUBSCRIPTION_CONFIG_SHA").unwrap(),
                "controller_sha256":std::env::var("AR_SUBSCRIPTION_CONTROLLER_SHA").unwrap()})
        } else {
            let output = std::process::Command::new("python3")
                .args([
                    "-B",
                    driver.to_str().unwrap(),
                    "prepare",
                    path.to_str().unwrap(),
                ])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "subscription prepare: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stdout.len() < 65536);
            serde_json::from_slice(&output.stdout).unwrap()
        };
        let (controller, peer) = OwnedSubscriptionController::pair(
            "t02-Lx-r1-H0",
            configuration["configuration_sha256"].as_str().unwrap(),
            &"b".repeat(64),
            configuration["controller_sha256"].as_str().unwrap(),
        )
        .unwrap();
        let review = owned_review_profile(
            &store,
            &prepared,
            listener,
            run_id,
            view,
            tools,
            Some(controller.binding()),
        );
        descriptor = Some((
            driver,
            path,
            serde_json::to_value(controller.binding()).unwrap(),
        ));
        parent_peer = Some(peer);
        review.with_subscription_controller(controller).unwrap()
    } else {
        owned_review_mode(&store, &prepared, listener, run_id, view, tools)
    };
    fs::write(root.join("pins.json"),serde_json::to_vec_pretty(&json!({
        "manifest":&client.manifest,"copies":&client.owned_assets.as_ref().unwrap().pins,
        "namespace":&client.owned_namespace.as_ref().unwrap().pin,
        "network_namespace":client.broker.isolation.as_ref().unwrap().identity(),
        "network_reservation":"exclusive-wildcard-v4-no-reuse",
        "catalog":&client.owned_state.as_ref().unwrap().startup.catalog,
        "resource_arguments":&client.resource_arguments,"client_review_digest":client.approval_digest(),
        "prepared_digest":prepared_digest(&prepared).unwrap(),"stdin_sha256":content_digest(prepared.stdin.as_bytes()),
        "original_source":source_workspace,"actual_workspace":workspace,"original_files":before
    })).unwrap()).unwrap();
    let home = PathBuf::from(&client.manifest.private_state);
    let reopen_request = request.clone();
    let reopen_plan = plan.clone();
    let worker_owner = plan
        .nodes
        .iter()
        .find(|n| n.id == "execute")
        .unwrap()
        .owner
        .clone();
    let pending = runtime
        .review_finite_client(run_id, &router, &context, request, plan, "execute", client)
        .await
        .unwrap();
    assert_eq!(runtime.summary(run_id).unwrap().attempts, 0);
    assert_eq!(posts.load(Ordering::SeqCst), 0);
    let digest = pending.approval_digest().to_owned();
    let approved = runtime.approve_finite_client(pending, &digest).unwrap();
    let verifier = runtime.finite_client_verifier(&approved).unwrap();
    assert!(
        verifier.artifact().is_err(),
        "queued is not a captured artifact"
    );
    let mut external_parent = None;
    let subscription_parent =
        if let (Some(peer), Some((driver, path, mut binding))) = (parent_peer, descriptor) {
            binding["run_id"] = run_id.into();
            binding["attempt"] = 1.into();
            binding["approval_digest"] = digest.clone().into();
            let expected_path = root.join("subscription-expected-binding.json");
            fs::write(&expected_path, serde_json::to_vec(&binding).unwrap()).unwrap();
            if external {
                println!(
                    "\nAR_RELAY_BINDING {}",
                    serde_json::to_string(&binding).unwrap()
                );
                std::io::stdout().flush().unwrap();
                external_parent = Some(external_relay(peer));
                None
            } else {
                let mut child = std::process::Command::new("python3")
                    .args([
                        "-B",
                        driver.to_str().unwrap(),
                        if unknown { "run-unknown" } else { "run" },
                        path.to_str().unwrap(),
                        expected_path.to_str().unwrap(),
                    ])
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::from(
                        fs::File::create(root.join("subscription-driver.stderr")).unwrap(),
                    ))
                    .spawn()
                    .unwrap();
                let stream = peer.into_transport();
                let mut write = stream.try_clone().unwrap();
                let mut read = stream;
                let mut input = child.stdin.take().unwrap();
                let mut output = child.stdout.take().unwrap();
                let a = std::thread::spawn(move || relay(&mut read, &mut input));
                let b = std::thread::spawn(move || {
                    let result = relay(&mut output, &mut write);
                    let _ = write.shutdown(std::net::Shutdown::Write);
                    result
                });
                Some((child, a, b))
            }
        } else {
            None
        };
    let collector = Collect(Mutex::new(vec![]));
    let cancel = Cancellation::default();
    let watcher = if matches!(case, Case::Cancel | Case::McpCancel) {
        let counter = posts.clone();
        let cancellation = cancel.clone();
        Some(tokio::spawn(async move {
            while counter.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            cancellation.cancel();
        }))
    } else {
        None
    };
    let result = runtime
        .execute_finite_client(approved, &collector, cancel)
        .await;
    if let Some(watcher) = watcher {
        watcher.abort();
    }
    if subscription {
        fs::write(root.join("subscription-runtime-return.json"),serde_json::to_vec_pretty(&json!({"error":result.as_ref().err().map(ToString::to_string),"summary":runtime.summary(run_id).ok()})).unwrap()).unwrap();
    }
    if let Some((a, b)) = external_parent {
        a.join().unwrap().unwrap();
        b.join().unwrap().unwrap();
    }
    if let Some((mut child, a, b)) = subscription_parent {
        let status = child.wait().unwrap();
        assert!(status.success(), "inspect subscription-driver.stderr");
        a.join().unwrap().unwrap();
        b.join().unwrap().unwrap();
    }
    stop_server.store(true, Ordering::SeqCst);
    assert!(
        !matches!(case, Case::EofHold | Case::McpEofHold),
        "EOF controller must be stopped externally while Running"
    );
    fs::write(root.join("result.json"),serde_json::to_vec_pretty(&json!({"result":result.as_ref().ok(),"error":result.as_ref().err().map(ToString::to_string),"summary":runtime.summary(run_id).ok(),"events":crate::observe_events(&store,run_id).ok(),"cleanup":runtime.cleanup_evidence(run_id).ok(),"admission":admission.status().ok(),"attempts":runtime.attempt_evidence(run_id).ok()})).unwrap()).unwrap();
    if let Ok(records) = runtime.output_artifacts(run_id) {
        for record in records {
            if record.state == OutputArtifactsState::Retained {
                fs::write(
                    root.join("stderr.txt"),
                    fs::read(&record.stderr.path).unwrap(),
                )
                .unwrap();
            }
        }
    }
    if unknown {
        let completion = result.unwrap();
        assert!(matches!(
            completion.run.state,
            RunState::Cancelled | RunState::Failed
        ));
        assert_eq!(
            runtime.cleanup_evidence(run_id).unwrap(),
            ProcessCleanupEvidence::NamespaceTerminated
        );
        assert_eq!(admission.status().unwrap().granted, 0);
        assert_eq!(admission.status().unwrap().released, 1);
        assert!(!home.exists());
        let summary: Value =
            serde_json::from_slice(&fs::read(root.join("host-summary.json")).unwrap()).unwrap();
        assert_eq!(summary["coded_responses"], 2);
        assert_eq!(summary["provider_requests"], 0);
        let ledger: Value = serde_json::from_slice(
            &fs::read(
                Path::new(summary["results_directory"].as_str().unwrap()).join("results.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(ledger["rows"][0]["usage"]["total_tokens"], 600);
        assert_eq!(ledger["rows"][0]["cost_microcredits"], 3275);
        assert_eq!(ledger["rows"][0]["status"], "stopped");
        assert_eq!(ledger["rows"][0]["relay_results"]["usage_unknown"], true);
        assert!(
            ledger["rows"]
                .as_array()
                .unwrap()
                .iter()
                .skip(1)
                .all(|r| r["status"] == "not_run")
        );
        assert_eq!(
            ledger["rows"][0]["relay_results"]["cleanup_confirmation"]["writers_excluded"],
            true
        );
        assert!(
            !store
                .join("artifacts")
                .join(format!("{run_id}.patch"))
                .exists()
        );
        for (file, hash) in &before {
            assert_eq!(
                content_digest(&fs::read(source_workspace.join(file)).unwrap()),
                *hash
            );
        }
        fs::write(root.join("receipt.json"),serde_json::to_vec_pretty(&json!({"qualification":"subscription_unknown_usage_stop",
            "model_calls_started":0,"synthetic_usage":true,"provider_requests":0,"cleanup":runtime.cleanup_evidence(run_id).unwrap(),
            "known_tokens":600,"known_equivalent_microcredits":3275,"unknown_cost":true,"memory_bytes":8589934592u64,
            "admission":admission.status().unwrap(),"completion":completion,"source_unchanged":true})).unwrap()).unwrap();
        return;
    }
    let completion = result.unwrap();
    let stdout = collector.0.lock().unwrap().clone();
    fs::write(root.join("stdout.jsonl"), &stdout).unwrap();
    assert_eq!(content_digest(&stdout), completion.stdout_sha256);
    if matches!(case, Case::ReadOnly | Case::Write) {
        // A successful native exit is insufficient: q01's independent oracle
        // rejects tool activity and startup errors inside an otherwise complete
        // stream. Keep the same refusal here rather than calling capture PASS.
        let rows: Vec<Value> = stdout
            .split(|b| *b == b'\n')
            .filter(|b| !b.is_empty())
            .map(|line| router_adapter_api::strict_json_limited(line, 65536).unwrap())
            .collect();
        assert_eq!(rows.last().unwrap()["type"], "turn.completed");
        assert_eq!(
            rows.iter()
                .filter(|r| r["type"] == "item.completed" && r["item"]["type"] == "agent_message")
                .count(),
            1
        );
        for row in &rows {
            match row["type"].as_str().unwrap() {
                "thread.started" | "turn.started" | "turn.completed" => {}
                "item.started" | "item.updated" | "item.completed" => assert!(
                    matches!(
                        row["item"]["type"].as_str(),
                        Some("agent_message" | "reasoning")
                    ),
                    "q01 refuses native tools or startup errors"
                ),
                _ => panic!("q01 refuses failed or unknown native events"),
            }
        }
    }
    assert!(
        completion.runtime_evidence.is_some(),
        "production Codex decoder must run inside Runtime"
    );
    assert_eq!(
        completion.run.state,
        match case {
            Case::Timeout | Case::McpTimeout => RunState::TimedOut,
            Case::Cancel | Case::McpCancel => RunState::Cancelled,
            _ => RunState::Verifying,
        }
    );
    assert_eq!(completion.run.attempts, 1);
    assert_eq!(completion.objective, VerificationOutcome::Unknown);
    assert_eq!(completion.memory_enforcement, MemoryEnforcement::Enforced);
    assert_eq!(
        runtime.cleanup_evidence(run_id).unwrap(),
        ProcessCleanupEvidence::NamespaceTerminated
    );
    assert!(!home.exists());
    assert_eq!(admission.status().unwrap().granted, 0);
    assert_eq!(admission.status().unwrap().released, 1);
    for (file, hash) in &before {
        assert_eq!(
            content_digest(&fs::read(source_workspace.join(file)).unwrap()),
            *hash
        );
        if file != name || !write {
            assert_eq!(
                content_digest(&fs::read(workspace.join(file)).unwrap()),
                *hash
            );
        }
    }
    assert_eq!(
        crate::source_state(&source_workspace).await.unwrap(),
        source
    );
    runtime.verify_integrity().unwrap();
    let reopen = runtime.reopen(
        run_id,
        &router,
        &context,
        reopen_request,
        reopen_plan,
        "execute",
    );
    assert!(
        reopen.is_err(),
        "finite definition must not become a generic publication handle"
    );
    fs::write(
        root.join("generic-reopen-refusal.txt"),
        reopen.err().unwrap().to_string(),
    )
    .unwrap();
    if let Some(expected) = expected.filter(|_| !matches!(case, Case::McpTimeout | Case::McpCancel))
    {
        assert_eq!(fs::read(workspace.join(name)).unwrap(), expected.as_bytes());
        if create {
            assert!(!before.contains_key(name));
        } else {
            assert_ne!(content_digest(expected.as_bytes()), before[name]);
        }
        let patch = fs::read(store.join("artifacts").join(format!("{run_id}.patch"))).unwrap();
        assert_eq!(Some(content_digest(&patch)), completion.run.artifact_sha256);
        assert_eq!(verifier.artifact().unwrap(), patch);
        // Exercise only the explicit UNKNOWN bridge here. These lifecycle
        // fixtures do not evaluate a useful task or grant human acceptance.
        if !external {
            assert!(
                verifier
                    .record(VerificationRecord {
                        verifier: worker_owner,
                        evidence_sha256: content_digest(
                            b"worker cannot attest an independent phase"
                        ),
                        artifact_sha256: completion.run.artifact_sha256.clone(),
                        validation: VerificationOutcome::Passed,
                        objective: VerificationOutcome::Passed,
                    })
                    .is_err()
            );
            assert_eq!(runtime.verification_record(run_id).unwrap(), None);
            let summary = verifier
                .record(VerificationRecord {
                    verifier: "explicit-lifecycle-fixture".into(),
                    evidence_sha256: content_digest(b"lifecycle fixture; objective unknown"),
                    artifact_sha256: completion.run.artifact_sha256.clone(),
                    validation: VerificationOutcome::Unknown,
                    objective: VerificationOutcome::Unknown,
                })
                .unwrap();
            assert_eq!(summary.state, RunState::Verifying);
        }
        fs::write(root.join("change.patch"), patch).unwrap();
        let exported = root.join("submission");
        mkdir(&exported);
        for file in before.keys() {
            fs::copy(workspace.join(file), exported.join(file)).unwrap();
        }
        if create {
            assert!(!source_workspace.join(name).exists());
            fs::copy(workspace.join(name), exported.join(name)).unwrap();
        }
    }
    if !matches!(case, Case::McpWrite | Case::McpCreate) {
        assert_eq!(posts.load(Ordering::SeqCst), 1);
    }
    if let Some(server) = server {
        server.join().unwrap();
    }
    if !subscription && matches!(case, Case::McpWrite | Case::McpCreate) {
        let broker: Value =
            serde_json::from_slice(&fs::read(root.join("broker.json")).unwrap()).unwrap();
        assert_eq!(broker["requests"].as_array().unwrap().len(), 4);
        assert_eq!(broker["observed_tool_results"], 3);
        let events = crate::observe_events(&store, run_id).unwrap();
        assert!(
            events
                .iter()
                .any(|event| event.kind == "finite_tools.stopped.v1")
        );
    }
    if subscription && !external {
        let summary: Value =
            serde_json::from_slice(&fs::read(root.join("host-summary.json")).unwrap()).unwrap();
        assert_eq!(summary["coded_responses"], 4);
        assert_eq!(summary["observed_tool_results"], 3);
        assert_eq!(summary["synthetic_usage"], true);
        assert_eq!(summary["provider_requests"], 0);
        assert!(
            crate::observe_events(&store, run_id)
                .unwrap()
                .iter()
                .any(|event| event.kind == "finite_subscription.stopped.v1")
        );
        let ledger: Value = serde_json::from_slice(
            &fs::read(
                Path::new(summary["results_directory"].as_str().unwrap()).join("results.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(ledger["rows"][0]["usage"]["total_tokens"], 2400);
        assert_eq!(ledger["rows"][0]["cost_microcredits"], 13100);
        assert!(
            ledger["rows"]
                .as_array()
                .unwrap()
                .iter()
                .skip(1)
                .all(|r| r["status"] == "not_run")
        );
        assert_eq!(
            ledger["rows"][0]["relay_results"]["cleanup_confirmation"]["writers_excluded"],
            true
        );
        assert_eq!(ledger["model_calls_started"], 0);
    }
    // Completed HTTP connections may retain TIME_WAIT even after every
    // listener is closed. Refused new connections test listener ownership
    // without mistaking a kernel TIME_WAIT entry for a leaked broker.
    assert!(TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err());
    fs::write(root.join("receipt.json"),serde_json::to_vec_pretty(&json!({"schema_version":1,"qualification":match case {Case::Write=>"q02-bounded-replacement",Case::Timeout=>"q01-timeout",Case::Cancel=>"q01-cancel",Case::McpWrite=>"q03-mcp-replacement",Case::McpCreate=>"q04-mcp-create",Case::McpTimeout=>"q03-mcp-timeout",Case::McpCancel=>"q03-mcp-cancel",_=>"q01"},"model_calls_started":0,"authored_local_requests":if matches!(case,Case::McpWrite|Case::McpCreate){4}else{1},"tools":tools,"memory_bytes":8589934592u64,"swap_bytes":0,"completion":completion,"cleanup":runtime.cleanup_evidence(run_id).unwrap(),"admission":admission.status().unwrap(),"source_unchanged":true,"human_acceptance":null,"scripted_usage_is_accounting":false,"controller_location":if external {"external_mac_private_channel"} else {"linux"},"availability":if subscription {"operator_simulated_subscription_relay"} else {"operator_simulated_local_fixture"},"context_overhead":"unknown","attempts":runtime.attempt_evidence(run_id).unwrap()})).unwrap()).unwrap();
}

#[tokio::test]
#[ignore = "explicit offline ARM64 Linux qualification; no model or remote provider"]
async fn q01_real_approved_local_report() {
    run_case(Case::ReadOnly).await;
}
#[tokio::test]
#[ignore = "explicit offline ARM64 Linux bounded replacement with authored t02 response; not a benchmark cell"]
async fn q02_real_approved_bounded_replacement() {
    run_case(Case::Write).await;
}

#[tokio::test]
#[ignore = "explicit offline Linux timeout with one local request and no model"]
async fn q01_real_timeout_keeps_namespace_cleanup_and_releases_admission() {
    run_case(Case::Timeout).await;
}
#[tokio::test]
#[ignore = "explicit offline Linux cancellation after local request; no model"]
async fn q01_real_cancel_keeps_namespace_cleanup_and_releases_admission() {
    run_case(Case::Cancel).await;
}
#[tokio::test]
#[ignore = "external controller stops this test after provider.json; no model"]
async fn q01_parent_eof_controller() {
    run_case(Case::EofHold).await;
}
#[test]
#[ignore = "reopens only the externally stopped EOF controller store; never executes"]
fn q01_parent_eof_recovery_retains_unknown_private_cleanup() {
    let root = PathBuf::from(std::env::var("AR_FINITE_ROOT").unwrap());
    let config: AdmissionConfig =
        serde_json::from_slice(&fs::read(root.join("admission-config.json")).unwrap()).unwrap();
    let pins: Value = serde_json::from_slice(&fs::read(root.join("pins.json")).unwrap()).unwrap();
    let home = PathBuf::from(pins["manifest"]["private_state"].as_str().unwrap());
    for _ in 0..2 {
        let runtime =
            Runtime::open_with_admission(&root.join("runtime"), RuntimeLimits::default(), &config)
                .unwrap();
        assert_eq!(
            runtime.cleanup_evidence("q01").unwrap(),
            ProcessCleanupEvidence::Unknown
        );
        let admission =
            AdmissionStore::open(&config.registry, &config.expected_policy_sha256).unwrap();
        assert_eq!(admission.status().unwrap().granted, 1);
        assert_eq!(admission.status().unwrap().released, 0);
        assert!(home.is_dir());
        assert_eq!(runtime.summary("q01").unwrap().attempts, 1);
        fs::write(root.join("eof-recovery.json"),serde_json::to_vec_pretty(&json!({"case":"parent_eof","cleanup":"unknown","private_state_retained":true,"admission":admission.status().unwrap(),"model_calls_started":0,"attempts":runtime.attempt_evidence("q01").ok()})).unwrap()).unwrap();
    }
}

#[test]
#[ignore = "explicit offline Linux legacy broker refusal; never invokes native"]
fn q01_legacy_loopback_broker_cannot_construct_a_dispatch_command() {
    let root = PathBuf::from(std::env::var("AR_FINITE_ROOT").unwrap());
    mkdir(&root);
    let workspace = root.join("candidate");
    mkdir(&workspace);
    fs::write(workspace.join("review.rs"), b"legacy refusal\n").unwrap();
    let store = root.join("runtime");
    mkdir(&store);
    let run = seed_run(&workspace);
    assert!(
        OwnedBroker::from_isolated_listener(TcpListener::bind(("127.0.0.1", 0)).unwrap()).is_err()
    );
    let review = owned_review(
        &store,
        &run,
        TcpListener::bind(("127.0.0.1", 0)).unwrap(),
        "legacy",
        None,
    );
    assert!(review.broker.isolation.is_none());
    let digest = review.approval_digest().to_owned();
    let state = review
        .approve(&digest)
        .unwrap()
        .into_namespace_state()
        .unwrap();
    assert!(matches!(
        composition_command(&state, None),
        Err(RuntimeError::Sandbox)
    ));
    fs::write(
        root.join("legacy-refusal.json"),
        b"{\"dispatch_command_constructed\":false,\"model_calls_started\":0}\n",
    )
    .unwrap();
}

#[tokio::test]
#[ignore = "explicit offline Linux Runtime MCP lifecycle; no model, no subscription request"]
async fn q03_real_approved_tools_runtime_captures_only_private_output() {
    run_case(Case::McpWrite).await;
}

#[tokio::test]
#[ignore = "explicit offline Linux Runtime MCP creation lifecycle; no model"]
async fn q04_real_approved_tools_runtime_preserves_absence_and_captures_new_output() {
    run_case(Case::McpCreate).await;
}

#[tokio::test]
#[ignore = "explicit offline Linux Runtime MCP timeout; no model"]
async fn q03_tools_timeout_keeps_cleanup_and_releases_admission() {
    run_case(Case::McpTimeout).await;
}
#[tokio::test]
#[ignore = "explicit offline Linux Runtime MCP cancellation; no model"]
async fn q03_tools_cancel_keeps_cleanup_and_releases_admission() {
    run_case(Case::McpCancel).await;
}
#[tokio::test]
#[ignore = "external controller stops this MCP Runtime test; no model"]
async fn q03_tools_parent_eof_controller() {
    run_case(Case::McpEofHold).await;
}
#[test]
#[ignore = "reopens the stopped MCP Runtime store only; never executes a model"]
fn q03_tools_parent_eof_recovery_retains_unknown_private_cleanup() {
    let root = PathBuf::from(std::env::var("AR_FINITE_ROOT").unwrap());
    let config: AdmissionConfig =
        serde_json::from_slice(&fs::read(root.join("admission-config.json")).unwrap()).unwrap();
    let pins: Value = serde_json::from_slice(&fs::read(root.join("pins.json")).unwrap()).unwrap();
    let home = PathBuf::from(pins["manifest"]["private_state"].as_str().unwrap());
    for _ in 0..2 {
        let runtime =
            Runtime::open_with_admission(&root.join("runtime"), RuntimeLimits::default(), &config)
                .unwrap();
        assert_eq!(
            runtime.cleanup_evidence("q02").unwrap(),
            ProcessCleanupEvidence::Unknown
        );
        let admission =
            AdmissionStore::open(&config.registry, &config.expected_policy_sha256).unwrap();
        assert_eq!(admission.status().unwrap().granted, 1);
        assert_eq!(admission.status().unwrap().released, 0);
        assert!(home.is_dir());
        assert_eq!(runtime.summary("q02").unwrap().attempts, 1);
        fs::write(root.join("eof-recovery.json"),serde_json::to_vec_pretty(&json!({"case":"MCP parent EOF","cleanup":"unknown","private_state_retained":true,"admission":admission.status().unwrap(),"model_calls_started":0})).unwrap()).unwrap();
    }
}

#[tokio::test]
#[ignore = "offline subscription profile with real native MCP, private controller and synthetic upstream only"]
async fn subscription_runtime_tools_usage_and_cleanup_are_connected_without_models() {
    run_case_mode(Case::McpWrite, true).await;
}

#[tokio::test]
#[ignore = "offline subscription profile: second coded response has unknown usage; no models"]
async fn subscription_unknown_usage_stops_and_preserves_known_cost_without_models() {
    run_case_profile(Case::McpWrite, true, true).await;
}

fn relay<R: Read, W: Write>(input: &mut R, output: &mut W) -> std::io::Result<u64> {
    let mut bytes = [0; 8192];
    let mut count = 0;
    loop {
        let n = input.read(&mut bytes)?;
        if n == 0 {
            return Ok(count);
        }
        output.write_all(&bytes[..n])?;
        output.flush()?;
        count += n as u64;
    }
}

// Qualification-only bridge. Native stdout stays captured by Runtime and cannot
// write this framing channel. The external parent owns the Docker process/FDs.
fn external_relay(
    peer: SubscriptionControllerPeer,
) -> (
    std::thread::JoinHandle<std::io::Result<()>>,
    std::thread::JoinHandle<std::io::Result<()>>,
) {
    let stream = peer.into_transport();
    let mut write = stream.try_clone().unwrap();
    let out = std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        loop {
            let mut line = String::new();
            let n = Read::by_ref(&mut reader)
                .take(300001)
                .read_line(&mut line)?;
            if n == 0 {
                break;
            }
            if n > 300000 || !line.ends_with('\n') {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "frame_bound",
                ));
            }
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(b"\nAR_RELAY_V1 ")?;
            stdout.write_all(line.as_bytes())?;
            stdout.flush()?;
        }
        Ok(())
    });
    let input = std::thread::spawn(move || {
        let mut reader = std::io::stdin().lock();
        loop {
            let mut line = String::new();
            let n = Read::by_ref(&mut reader)
                .take(300001)
                .read_line(&mut line)?;
            if n == 0 {
                break;
            }
            if n > 300000 || !line.ends_with('\n') {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "frame_bound",
                ));
            }
            write.write_all(line.as_bytes())?;
            write.flush()?;
        }
        let _ = write.shutdown(std::net::Shutdown::Write);
        Ok(())
    });
    (out, input)
}
