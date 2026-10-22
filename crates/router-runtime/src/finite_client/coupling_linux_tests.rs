use super::*;
use crate::{finite_tools::Limits, leases::LeaseStorage};
use router_types::*;

fn pin(path: &Path) -> FiniteClientFile {
    FiniteClientFile {
        path: path.to_str().unwrap().into(),
        sha256: content_digest(&fs::read(path).unwrap()),
    }
}

#[tokio::test]
#[ignore = "explicit offline Linux qualification of approved public-only tools composition; no model"]
async fn tools_probe_uses_sacrificial_public_view_and_stops_descendants() {
    let root = PathBuf::from(std::env::var("AR_COUPLING_ROOT").unwrap());
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let programs = PathBuf::from(std::env::var("AR_COUPLING_PROGRAMS").unwrap());
    let source = root.join("source");
    fs::DirBuilder::new().mode(0o700).create(&source).unwrap();
    fs::write(source.join("statement.md"), b"Public fixture only\n").unwrap();
    fs::write(source.join("allowed.rs"), b"before\n").unwrap();
    for args in [
        vec!["init", "-q"],
        vec!["add", "statement.md", "allowed.rs"],
        vec![
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "public",
        ],
    ] {
        crate::workspace::git(&source, &args, vec![]).await.unwrap();
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root.join("runtime"))
        .unwrap();
    let runtime = Runtime::open(&root.join("runtime"), Default::default()).unwrap();
    let workspace = runtime
        .prepare_finite_workspace(&source, "probe", &["allowed.rs".into()])
        .await
        .unwrap();
    let public = BTreeMap::from([
        (
            "statement.md".into(),
            content_digest(b"Public fixture only\n"),
        ),
        ("allowed.rs".into(), content_digest(b"before\n")),
    ]);
    let run = PreparedRun {
        schema_version: 1,
        receipt_id: "a".repeat(64),
        source_state: workspace.source_state().into(),
        scope: vec!["allowed.rs".into()],
        authorization_digest: "b".repeat(64),
        snapshot_hash: "c".repeat(64),
        host: HarnessId::parse("codex").unwrap(),
        requested_model: ModelId::parse("gpt-6-luna").unwrap(),
        requested_effort: EffortLevel::Medium,
        program: "finite-client".into(),
        argv: vec!["--worker".into()],
        cwd: workspace.path().to_str().unwrap().into(),
        stdin: PreparedInput::new(vec![]),
        mode: ExecutionMode::Execute,
        target: ExecutionTarget::ExternalWorker,
        sandbox: ExecutionSandbox::WorkspaceWrite,
        timeout_ms: 25_000,
        max_output_bytes: 65536,
        degradations: vec![],
        missing_runtime_evidence: vec![],
        parent_model_changed: false,
    };
    let view_path = workspace.path().to_owned();
    let listener = TcpListener::bind(("0.0.0.0", 0)).unwrap();
    rustix::net::sockopt::set_socket_reuseaddr(&listener, false).unwrap();
    rustix::net::sockopt::set_socket_reuseport(&listener, false).unwrap();
    let probe_listener = listener.try_clone().unwrap();
    let responder = std::thread::spawn(move || {
        let (mut socket, _) = probe_listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() <= 256);
        }
        assert_eq!(
            request,
            b"GET /__router_probe__ HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"
        );
        socket
            .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .unwrap();
    });
    let broker = OwnedBroker::from_isolated_listener(listener).unwrap();
    let state = broker
        .prepare_codex_tools_state(&runtime.store.root, &run)
        .unwrap();
    let manifest = FiniteClientManifest {
        schema_version: 1,
        task_id: "probe".into(),
        host_snapshot_id: "linux-local".into(),
        client: pin(&programs.join("client")),
        native: pin(&programs.join("native")),
        helper: pin(&programs.join("helper")),
        wrapper: pin(&programs.join("guard")),
        profile: pin(&programs.join("profile")),
        configuration: state.configuration().clone(),
        private_state: state.path().to_str().unwrap().into(),
        native_version: "0.159.2-linux-arm64-musl".into(),
        broker_endpoint: broker.endpoint().into(),
        broker_instance_sha256: broker.instance_sha256().into(),
    };
    let review = FiniteClientReview::with_codex_state(
        manifest,
        &run,
        broker,
        ResourceLimits::default(),
        state,
    )
    .unwrap()
    .with_write_workspace(workspace)
    .unwrap()
    .with_linux_namespace(pin(&programs.join("namespace")))
    .unwrap()
    .with_mcp_tools(
        public,
        Limits {
            max_calls: 8,
            max_file_bytes: 32768,
            max_output_bytes: 8192,
            max_total_output_bytes: 32768,
            max_exec_ms: 5000,
            max_total_exec_ms: 15000,
            max_session_ms: 25000,
            max_scratch_entries: 64,
            max_scratch_bytes: 16777216,
        },
    )
    .unwrap();
    let digest = review.approval_digest().to_owned();
    let mut state = review
        .approve(&digest)
        .unwrap()
        .into_namespace_state()
        .unwrap();
    let scratch = root.join("sacrificial");
    fs::DirBuilder::new().mode(0o700).create(&scratch).unwrap();
    let control = scratch.join("control");
    fs::DirBuilder::new().mode(0o700).create(&control).unwrap();
    let hidden = root.join("private-control");
    fs::write(&hidden, b"never mounted").unwrap();
    let denied = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let mut entropy = [0; 32];
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut entropy)
        .unwrap();
    let nonce = content_digest(&entropy);
    let mut probe = ProbeView {
        tools: None,
        temporary: scratch,
        control: control.clone(),
        hidden,
        denied_port: denied.local_addr().unwrap().port(),
        nonce: nonce.clone(),
    };
    probe.tools = Some(ToolsProbeView::prepare(&state, &probe).unwrap());
    let mut command = composition_command(&state, Some(&probe)).unwrap();
    let leases = LeaseStorage::open(&root).unwrap();
    let (mut record, lease) = leases.create("probe", 1).unwrap();
    record.require_namespace(true);
    state.arm_cleanup(Some(&lease), true).unwrap();
    command.env("ROUTER_RUNTIME_LEASE", lease);
    let capture = crate::process::capture(
        command,
        vec![],
        20_000,
        65536,
        100,
        &Cancellation::default(),
    )
    .await
    .unwrap();
    fs::write(root.join("stdout"), &capture.stdout).unwrap();
    fs::write(root.join("stderr"), &capture.stderr).unwrap();
    let stopped = leases.cleanup_proof("probe", 1, &record).unwrap();
    assert_eq!(
        stopped.evidence,
        ProcessCleanupEvidence::NamespaceTerminated
    );
    assert_eq!(
        capture.outcome.exit_code,
        Some(0),
        "inspect private stderr witness"
    );
    probe.tools.as_ref().unwrap().verify(&nonce).unwrap();
    let before = fs::metadata(control.join("heartbeat")).unwrap().len();
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(
        fs::metadata(control.join("heartbeat")).unwrap().len(),
        before
    );
    assert!(before > 1);
    assert_eq!(fs::read(source.join("allowed.rs")).unwrap(), b"before\n");
    assert_eq!(fs::read(view_path.join("allowed.rs")).unwrap(), b"before\n");
    state.cleanup_with_proof(&stopped).unwrap();
    responder.join().unwrap();
}
