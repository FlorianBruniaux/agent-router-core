//! Opt-in copied-client OS diagnostic. Never stores a capability proof or admits a product run.
use super::*;
use router_types::*;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
const NATIVE: &str = "113aa5d5952a6fd3950a88323219747d0c91978ebee948509a540c8a460e59a3";
fn pin(path: &Path) -> FiniteClientFile {
    let path = path.canonicalize().unwrap();
    let mut bytes = Vec::new();
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)
        .unwrap();
    assert!(file.metadata().unwrap().len() < 256 * 1024 * 1024);
    file.take(256 * 1024 * 1024)
        .read_to_end(&mut bytes)
        .unwrap();
    FiniteClientFile {
        path: path.to_str().unwrap().into(),
        sha256: content_digest(&bytes),
    }
}
fn listener() -> TcpListener {
    TcpListener::bind(("127.0.0.1", 0)).unwrap()
}
fn serve(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    count: Arc<AtomicUsize>,
) -> thread::JoinHandle<()> {
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut s, _)) => {
                    count.fetch_add(1, Ordering::SeqCst);
                    s.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
                    let _ = s.write_all(b"F12-local-canary\n");
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(_) => break,
            }
        }
    })
}
fn reachable(port: u16) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut b = [0];
    s.read_exact(&mut b).unwrap();
    assert_eq!(b, b"F"[..]);
}
#[test]
#[ignore = "explicit Linux Docker diagnostic with pinned native/client/helper/wrapper and owned heartbeat volume; never part of automatic native batch"]
fn copied_client_os_qualification() {
    qualify(false);
}
#[test]
#[ignore = "explicit pinned Linux namespace-owner diagnostic; never product run admission"]
fn namespace_owned_client_os_qualification() {
    qualify(true);
}
fn qualify(namespace_owner: bool) {
    assert_eq!(
        std::env::var("AR_LINUX_DIAGNOSTIC").unwrap(),
        if namespace_owner {
            "namespace-owned-v1"
        } else {
            "owned-copies-v1"
        }
    );
    let case = std::env::var("AR_LINUX_CASE").unwrap();
    assert!(["normal", "deadline", "eof", "helper-kill"].contains(&case.as_str()));
    let root = Path::new("/work/task");
    fs::DirBuilder::new().mode(0o700).create(root).unwrap();
    let work = root.join("work");
    fs::create_dir(&work).unwrap();
    let workspace = work.join("workspace");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&workspace)
        .unwrap();
    let store = root.join("store");
    fs::DirBuilder::new().mode(0o700).create(&store).unwrap();
    let denied_read = root.join("denied-read");
    fs::write(&denied_read, b"inert-private-store-control").unwrap();
    fs::write(workspace.join("read-control"), b"F12-readable").unwrap();
    let allowed = workspace.join("patch.txt");
    fs::write(&allowed, b"before").unwrap();
    // Outside-policy positive controls: same UID can change a 0400 file on this writable tmpfs.
    let control = root.join("mode-control");
    fs::write(&control, b"before").unwrap();
    fs::set_permissions(&control, fs::Permissions::from_mode(0o400)).unwrap();
    fs::set_permissions(&control, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&control, b"after").unwrap();
    fs::remove_file(&control).unwrap();
    let broker = OwnedBroker::from_listener(listener()).unwrap();
    let broker_port = broker.listener.local_addr().unwrap().port();
    let other = listener();
    let other_port = other.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let broker_count = Arc::new(AtomicUsize::new(0));
    let other_count = Arc::new(AtomicUsize::new(0));
    let server = serve(
        broker.listener.try_clone().unwrap(),
        stop.clone(),
        broker_count.clone(),
    );
    let denied_server = serve(other, stop.clone(), other_count.clone());
    reachable(broker_port);
    reachable(other_port);
    let source = Path::new("/work/input");
    let native = pin(&source.join("native"));
    assert_eq!(native.sha256, NATIVE);
    let client = pin(&source.join("client"));
    let helper = pin(&source.join("helper"));
    let wrapper = pin(&source.join("wrapper"));
    let run = PreparedRun {
        schema_version: 1,
        receipt_id: "a".repeat(64),
        source_state: "b".repeat(40),
        scope: vec!["patch.txt".into()],
        authorization_digest: "c".repeat(64),
        snapshot_hash: "d".repeat(64),
        host: HarnessId::parse("codex").unwrap(),
        requested_model: ModelId::parse("gpt-6.1-sol").unwrap(),
        requested_effort: EffortLevel::Low,
        program: "finite-client".into(),
        argv: vec!["--worker".into()],
        cwd: workspace.to_str().unwrap().into(),
        stdin: PreparedInput::new(b"Linux copied-client qualification only".to_vec()),
        mode: ExecutionMode::Execute,
        target: ExecutionTarget::ExternalWorker,
        sandbox: ExecutionSandbox::WorkspaceWrite,
        timeout_ms: 25000,
        max_output_bytes: 65536,
        degradations: vec![],
        missing_runtime_evidence: vec![],
        parent_model_changed: false,
    };
    let limits = ResourceLimits::default();
    assert_eq!(limits.address_space_bytes, Some(8589934592));
    let state = broker.prepare_codex_state(&store, &run).unwrap();
    let home = state.path().to_str().unwrap().to_string();
    let native_environment = state.native_environment();
    let startup_binding = state.startup_binding().unwrap();
    let native_environment_sha256 =
        content_digest(&serde_json::to_vec(&native_environment).unwrap());
    let mut namespace = if namespace_owner {
        let source = pin(&source.join("namespace"));
        Some(
            crate::private_program::PrivateProgram::copy(
                Path::new(&source.path),
                &source.sha256,
                &store,
            )
            .unwrap(),
        )
    } else {
        None
    };
    let namespace_pin = namespace
        .as_ref()
        .map(|program| pin(&program.directory().join("program")));
    let namespace_args: Vec<String> = if namespace_owner {
        vec![
            "--die-with-parent".into(),
            "--new-session".into(),
            "--unshare-all".into(),
            "--share-net".into(),
            "--cap-drop".into(),
            "ALL".into(),
            "--ro-bind".into(),
            "/".into(),
            "/".into(),
            "--proc".into(),
            "/proc".into(),
            "--dev".into(),
            "/dev".into(),
            "--bind".into(),
            format!("{home}/tmp"),
            format!("{home}/tmp"),
            "--bind".into(),
            allowed.to_str().unwrap().into(),
            allowed.to_str().unwrap().into(),
            "--bind".into(),
            "/evidence/heartbeat".into(),
            "/evidence/heartbeat".into(),
            "--".into(),
        ]
    } else {
        vec![]
    };
    let profile_path = root.join("profile.json");
    fs::write(&profile_path, serde_json::to_vec(&json!({"diagnostic":"landlock-abi6-seccomp-aarch64-v1","network":"ipv4-tcp-exact-port","address_space_bytes":8589934592u64,"namespace_owner":namespace_pin,"namespace_args":namespace_args})).unwrap()).unwrap();
    fs::set_permissions(&profile_path, fs::Permissions::from_mode(0o400)).unwrap();
    let profile = pin(&profile_path);
    let manifest = FiniteClientManifest {
        schema_version: 1,
        task_id: "linux-copied-client-diagnostic".into(),
        host_snapshot_id: "not-a-host-proof".into(),
        client: client.clone(),
        native: native.clone(),
        helper: helper.clone(),
        wrapper: wrapper.clone(),
        profile: profile.clone(),
        configuration: state.configuration().clone(),
        private_state: home.clone(),
        native_version: "0.159.2-linux-arm64-musl".into(),
        broker_endpoint: broker.endpoint().into(),
        broker_instance_sha256: broker.instance_sha256().into(),
    };
    let review =
        FiniteClientReview::with_codex_state(manifest, &run, broker, limits.clone(), state)
            .unwrap();
    let digest = review.approval_digest().to_owned();
    let approved = review.approve(&digest).unwrap(); // preparation-only, never Runtime::approve
    let r = &approved.reviewed;
    r.check_files().unwrap();
    let assets = r.owned_assets.as_ref().unwrap();
    let pins = assets.pins.clone();
    let copies: Vec<_> = assets
        .copies
        .iter()
        .map(|p| p.directory().to_owned())
        .collect();
    let (review_owner, mut host_owner) = if namespace_owner {
        (None, Some(approved.into_namespace_state().unwrap()))
    } else {
        (Some(approved), None)
    };
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60;
    let payload=serde_json::to_vec(&json!({"native":pins[1].path,"native_sha256":NATIVE,"home":home,"workspace":workspace,"config_sha256":pins[5].sha256,"broker_port":broker_port,"denied_port":other_port,"expires_at":expires,"linux_canary":{"assets":pins,"native_environment":native_environment,"heartbeat":"/evidence/heartbeat","allowed_file":allowed,"denied_read":denied_read,"hold":namespace_owner || case!="normal","release_after_canary":namespace_owner && case=="normal","namespace_owner":namespace_pin.as_ref().map(|p| &p.path)}})).unwrap();
    assert!(payload.len() <= 8192);
    let payload_digest = content_digest(&payload);
    let leases = crate::leases::LeaseStorage::open(root).unwrap();
    let (record, lease) = leases.create("linux-qualification", 1).unwrap();
    if let Some(owner) = host_owner.as_mut() {
        owner.arm_cleanup(Some(&lease), true).unwrap();
    }
    let mut command = Command::new(&pins[2].path);
    command.args(limits.args().unwrap()).arg("--supervise-v1");
    if let Some(owner) = namespace.as_ref() {
        let path = owner
            .verify(&namespace_pin.as_ref().unwrap().sha256)
            .unwrap();
        command.arg(path).args(&namespace_args);
    }
    command.args([&pins[3].path, "--restrict", &broker_port.to_string()]);
    for p in &pins {
        command.arg(Path::new(&p.path).parent().unwrap());
    }
    command.args([
        Path::new(&home).join("tmp"),
        allowed.clone(),
        "/evidence/heartbeat".into(),
    ]);
    command.args([&pins[0].path, "--worker", &payload_digest]);
    command
        .current_dir(&workspace)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", Path::new(&home).join("tmp"))
        .env("ROUTER_RUNTIME_SUPERVISION", "framed-v1")
        .env("ROUTER_RUNTIME_LEASE", &lease)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(root.join("worker-errors"))
                .unwrap(),
        ));
    if namespace_owner {
        command.env("ROUTER_RUNTIME_CONTAINMENT", "pid-namespace-v1");
    }
    // Once armed, preserve this extra retained diagnostic wrapper on any failure.
    // The HostState bundle itself uses the same conservative exposed-drop rule.
    let namespace = namespace.take().map(|owner| NamespaceCopy(Some(owner)));
    let mut namespace = namespace;
    let mut child = command.spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(b"ARLIFE01").unwrap();
    input
        .write_all(&(payload.len() as u64).to_be_bytes())
        .unwrap();
    input.write_all(&25000u64.to_be_bytes()).unwrap();
    input.write_all(&10u64.to_be_bytes()).unwrap();
    input.write_all(&payload).unwrap();
    input.flush().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap().take(65537));
    let mut ready = String::new();
    assert!(output.read_line(&mut ready).unwrap() < 65536);
    assert!(
        ready.starts_with("AR_LINUX_READY:"),
        "copied worker did not reach ready: {ready}"
    );
    let canary: Value =
        serde_json::from_str(ready.trim().strip_prefix("AR_LINUX_READY:").unwrap()).unwrap();
    assert_eq!(canary["memory"], "8GiB");
    assert_eq!(
        canary["protected_assets"],
        if namespace_owner { 7 } else { 6 }
    );
    let heartbeat_before = if namespace_owner {
        let first = fs::metadata("/evidence/heartbeat").unwrap().len();
        thread::sleep(Duration::from_millis(100));
        let second = fs::metadata("/evidence/heartbeat").unwrap().len();
        assert!(
            second > first,
            "detached writer must be observed before stopping"
        );
        if case == "normal" {
            fs::write(&allowed, b"namespace-release").unwrap();
        }
        vec![first, second]
    } else {
        vec![]
    };
    let input = if case == "eof" {
        drop(input);
        None
    } else if case == "helper-kill" {
        child.kill().unwrap();
        drop(input);
        None
    } else {
        Some(input)
    };
    let status = child.wait().unwrap();
    drop(input);
    if case == "normal" {
        assert!(status.success());
    } else if case == "deadline" {
        assert_eq!(status.code(), Some(124));
    } else if case == "eof" {
        assert_eq!(status.code(), Some(125));
    } else {
        assert!(!status.success());
    }
    let state = fs::read_to_string(&lease).unwrap();
    assert_eq!(
        state,
        if case == "helper-kill" {
            "router-runtime-lease-v1:active\n"
        } else if namespace_owner {
            "router-runtime-lease-v1:namespace-clean\n"
        } else {
            "router-runtime-lease-v1:group-clean\n"
        }
    );
    if let Some(owner) = &host_owner {
        owner.check_owned_resources().unwrap();
    }
    if let Some(review) = &review_owner {
        review.reviewed.check_files().unwrap();
    }
    let heartbeat_after = if namespace_owner {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let mut observations = vec![];
            for _ in 0..3 {
                observations.push(fs::metadata("/evidence/heartbeat").unwrap().len());
                thread::sleep(Duration::from_millis(100));
            }
            if observations.windows(2).all(|p| p[0] == p[1]) {
                break observations;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "namespace still has a live detached writer"
            );
        }
    } else {
        vec![]
    };
    assert_eq!(fs::read(&allowed).unwrap(), b"scope-ok");
    assert_eq!(
        fs::read(&denied_read).unwrap(),
        b"inert-private-store-control"
    );
    assert_eq!(other_count.load(Ordering::SeqCst), 1);
    assert_eq!(broker_count.load(Ordering::SeqCst), 3);
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    denied_server.join().unwrap();
    let cleanup = if namespace_owner {
        assert!(TcpListener::bind(("127.0.0.1", broker_port)).is_err());
        if case == "helper-kill" {
            assert!(
                leases
                    .cleanup_proof("linux-qualification", 1, &record)
                    .is_err()
            );
            assert!(Path::new(&home).is_dir() && copies.iter().all(|p| p.is_dir()));
            "UNKNOWN_RETAINED"
        } else {
            let proof = leases
                .cleanup_proof("linux-qualification", 1, &record)
                .unwrap();
            assert_eq!(proof.evidence, ProcessCleanupEvidence::NamespaceTerminated);
            host_owner
                .take()
                .unwrap()
                .cleanup_with_proof(&proof)
                .unwrap();
            namespace
                .as_mut()
                .unwrap()
                .0
                .take()
                .unwrap()
                .cleanup()
                .unwrap();
            assert!(!Path::new(&home).exists() && copies.iter().all(|p| !p.exists()));
            assert!(
                !Path::new(&namespace_pin.as_ref().unwrap().path)
                    .parent()
                    .unwrap()
                    .exists()
            );
            let _released = TcpListener::bind(("127.0.0.1", broker_port)).unwrap();
            "COMPLETE"
        }
    } else {
        "PENDING_EXTERNAL_OWNER"
    };
    println!(
        "AR_LINUX_REPORT:{}",
        json!({"diagnostic_only":true,"f12a":"NO_GO","case":case,"address_space_bytes":8589934592u64,"preparation_digest":digest,"copy_hashes":pins.iter().map(|p|&p.sha256).collect::<Vec<_>>(),"canary":canary,"native_rpc":"initialize-and-thread-start-only","provider_turns":0,"other_listener_connections":other_count.load(Ordering::SeqCst),"broker_connections":broker_count.load(Ordering::SeqCst),"helper_exit_code":status.code(),"lease":state.trim(),"protected_identities_after":"unchanged","startup_contract":"producer-owned-v1","startup_binding_sha256":startup_binding,"native_environment_sha256":native_environment_sha256,"controller_still_owns_copies":cleanup!="COMPLETE","namespace_cleanup":cleanup,"namespace_owner":namespace_pin,"namespace_args":namespace_args,"heartbeat_before_stop":heartbeat_before,"heartbeat_after_stop":heartbeat_after,"preparation_owner_transferred":namespace_owner})
    );
    std::io::stdout().flush().unwrap();
    // Retain any ambiguous owners until the outer fallback namespace is destroyed.
    // Even COMPLETE here never settles or admits a durable product run.
    thread::sleep(Duration::from_secs(30));
    panic!("external diagnostic owner did not terminate the namespace");
}

// A failed diagnostic must not dispose its namespace program while it may run.
struct NamespaceCopy(Option<crate::private_program::PrivateProgram>);
impl Drop for NamespaceCopy {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            owner.preserve();
        }
    }
}
