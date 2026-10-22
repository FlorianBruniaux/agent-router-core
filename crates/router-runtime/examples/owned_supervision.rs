//! Opt-in composition diagnostic, never a native task or capability grant.
//! It uses the actual public runtime supervisors and never submits a model turn.

use router_runtime::{
    Cancellation, NetworkAuthority, ResourceLimits, ResourceSupervisor, RuntimeError,
    SandboxPolicy, SandboxSupervisor, SeatbeltSandbox, probe_native_version,
};
use router_types::*;
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const NATIVE_PIN: &str = "16593cc2f422d5f398a8e40f550ebbaf1245392528957be342c295920a300704";

fn prepared(cwd: &Path) -> PreparedRun {
    PreparedRun {
        schema_version: 1,
        receipt_id: "a".repeat(64),
        source_state: "b".repeat(40),
        scope: vec![],
        authorization_digest: "c".repeat(64),
        snapshot_hash: "d".repeat(64),
        host: HarnessId::parse("codex").unwrap(),
        requested_model: ModelId::parse("fixture-model-no-turn").unwrap(),
        requested_effort: EffortLevel::Low,
        program: "codex".into(),
        argv: vec!["app-server".into(), "--listen".into(), "stdio://".into()],
        cwd: cwd.to_str().unwrap().into(),
        stdin: PreparedInput::new(vec![]),
        mode: ExecutionMode::Execute,
        target: ExecutionTarget::ExternalWorker,
        sandbox: ExecutionSandbox::ReadOnly,
        timeout_ms: 5_000,
        max_output_bytes: 65_536,
        degradations: vec![],
        missing_runtime_evidence: vec![],
        parent_model_changed: false,
    }
}

async fn seatbelt(root: &Path, binary: &Path) -> SeatbeltSandbox {
    SeatbeltSandbox::probe(
        root,
        BTreeMap::from([("codex".into(), binary.to_path_buf())]),
        vec![],
        BTreeMap::new(),
    )
    .await
    .unwrap()
}

#[tokio::main]
async fn main() {
    assert!(
        cfg!(target_os = "macos"),
        "macOS-only composition diagnostic"
    );
    let binary = fs::canonicalize(std::env::var_os("AR_CODEX_NATIVE").unwrap()).unwrap();
    let helper = fs::canonicalize(std::env::var_os("AR_SANDBOX_HELPER").unwrap()).unwrap();
    let root = PathBuf::from(std::env::var_os("AR_F12_PRIVATE").unwrap());
    assert!(root.is_absolute());
    assert_eq!(
        router_adapter_api::content_digest(&fs::read(&binary).unwrap()),
        NATIVE_PIN
    );
    let helper_hash = router_adapter_api::content_digest(&fs::read(&helper).unwrap());
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let root = fs::canonicalize(root).unwrap();
    let workspace = root.join("worktrees/diagnostic");
    fs::create_dir(root.join("worktrees")).unwrap();
    fs::create_dir(&workspace).unwrap();
    let run = prepared(&workspace);

    // Observe the full memory request first. A diagnostic without that bound
    // below is explicit and does not qualify or silently weaken admission.
    let memory = ResourceSupervisor::probe(
        &helper,
        ResourceLimits::default(),
        seatbelt(&root, &binary).await,
    )
    .await;
    let address_space = match memory {
        Ok(_) => "probe_applied_not_allocation_qualified",
        Err(RuntimeError::ResourceUnsupported("address_space")) => "unsupported",
        Err(error) => panic!("unexpected resource probe: {error}"),
    };
    let supervisor = ResourceSupervisor::probe(
        &helper,
        ResourceLimits {
            address_space_bytes: None,
            ..ResourceLimits::default()
        },
        seatbelt(&root, &binary).await,
    )
    .await
    .unwrap();
    let version = probe_native_version(&supervisor, &run, &root, &Cancellation::default())
        .await
        .unwrap();
    assert_eq!(version.stdout(), b"codex-cli 0.159.2\n");
    assert_eq!(version.outcome.exit_code, Some(0));

    let state = supervisor.create_host_state(&root, &run).unwrap();
    let broker_refused = matches!(
        supervisor.command(
            &run,
            &SandboxPolicy {
                network: NetworkAuthority::ControllerBrokerOnly,
                host_state: state.as_ref(),
            }
        ),
        Err(RuntimeError::Sandbox)
    );
    assert!(
        broker_refused,
        "update the qualification if broker composition becomes supported"
    );

    // Send only initialize. There is no thread/start or turn/start, account
    // import, provider server or approval request. The outer sandbox denies
    // socket networking. The actual framed-v1 helper owns process teardown.
    let mut command = supervisor
        .command(
            &run,
            &SandboxPolicy {
                network: NetworkAuthority::Deny,
                host_state: state.as_ref(),
            },
        )
        .unwrap();
    let lease = root.join("appserver.lease");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&lease)
        .unwrap();
    file.write_all(b"router-runtime-lease-v1:pending\n")
        .unwrap();
    file.sync_all().unwrap();
    command
        .env("ROUTER_RUNTIME_LEASE", &lease)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let mut life = child.stdin.take().unwrap();
    let payload = b"{\"id\":1,\"method\":\"initialize\",\"params\":{\"clientInfo\":{\"name\":\"ar-f12-diagnostic\",\"version\":\"1.0\"},\"capabilities\":{\"experimentalApi\":true}}}\n";
    life.write_all(b"ARLIFE01").await.unwrap();
    for value in [payload.len() as u64, 5_000, 20] {
        life.write_all(&value.to_be_bytes()).await.unwrap();
    }
    life.write_all(payload).await.unwrap();
    life.flush().await.unwrap();
    let mut stdout = child.stdout.take().unwrap().take(65_537);
    let mut stderr = child.stderr.take().unwrap().take(65_537);
    let out = tokio::spawn(async move {
        let mut bytes = vec![];
        stdout.read_to_end(&mut bytes).await.unwrap();
        bytes
    });
    let err = tokio::spawn(async move {
        let mut bytes = vec![];
        stderr.read_to_end(&mut bytes).await.unwrap();
        bytes
    });
    let waited = tokio::time::timeout(Duration::from_secs(8), child.wait()).await;
    if waited.is_err() {
        drop(life);
        let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
        panic!("supervisor failed its bounded completion; private state retained");
    }
    let status = waited.unwrap().unwrap();
    let output = tokio::time::timeout(Duration::from_secs(2), out)
        .await
        .unwrap()
        .unwrap();
    let errors = tokio::time::timeout(Duration::from_secs(2), err)
        .await
        .unwrap()
        .unwrap();
    assert!(output.len() <= 65_536 && errors.len() <= 65_536);
    assert_eq!(
        fs::read(&lease).unwrap(),
        b"router-runtime-lease-v1:group-clean\n"
    );
    assert!(status.success());
    // A still-open controller life pipe did not keep the native RPC session
    // open. No interactive second command can be sent through this protocol.
    let replies: Vec<serde_json::Value> = output
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(|b| serde_json::from_slice(b).unwrap())
        .collect();
    assert!(
        replies
            .iter()
            .any(|row| row["id"] == 1 && row["result"].is_object())
    );
    drop(life);
    drop(state);
    assert_eq!(
        router_adapter_api::content_digest(&fs::read(&binary).unwrap()),
        NATIVE_PIN
    );
    assert_eq!(
        router_adapter_api::content_digest(&fs::read(&helper).unwrap()),
        helper_hash
    );
    let report = json!({
        "schema_version": 1, "evidence_kind": "local_native_supervisor_composition_diagnostic",
        "platform": "macos", "native_version": "0.159.2", "native_sha256": NATIVE_PIN,
        "helper_sha256": helper_hash, "runtime_version_probe": "passed", "version_cleanup": version.cleanup,
        "seatbelt_canaries": "passed", "full_address_space_request": address_space,
        "diagnostic_memory_enforcement": "not_requested", "broker_only_command": "refused_before_spawn",
        "appserver_initialize_reply": "observed", "appserver_eof_with_controller_life_pipe_open": true,
        "helper_exit_code": status.code(), "lease": "group_clean_not_exhaustive_containment",
        "native_output_bytes": output.len(), "native_stderr_bytes": errors.len(),
        "turn_submissions": 0, "provider_servers": 0, "paid_provider_calls": 0,
        "F12a": "NO_GO", "F02b": "NOT_ATTEMPTED",
        "blockers": ["broker_endpoint_not_supported_by_product_sandbox", "framed_v1_is_finite_input_not_duplex"]
    });
    let mut report_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("report.json"))
        .unwrap();
    serde_json::to_writer_pretty(&mut report_file, &report).unwrap();
    report_file.write_all(b"\n").unwrap();
    report_file.sync_all().unwrap();
    println!("{}", serde_json::to_string(&report).unwrap());
}
