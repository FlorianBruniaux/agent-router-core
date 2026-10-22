//! Inert ownership fixtures. Marker tests do not qualify an OS namespace.
use super::*;
use crate::leases::LeaseStorage;
use router_types::*;
use std::{net::SocketAddr, path::PathBuf};

#[test]
fn subscription_preparation_binds_account_and_relay_without_credentials_or_launch() {
    let f = fixture();
    let mut run = f.run.clone();
    run.requested_model = ModelId::parse("gpt-6-luna").unwrap();
    run.requested_effort = EffortLevel::Medium;
    let broker = &f.approved.reviewed.broker;
    let state = broker
        .prepare_codex_subscription_tools_state(&f.store, &run, &"a".repeat(64), &"b".repeat(64))
        .unwrap();
    state.check(&run, broker).unwrap();
    let config = fs::read_to_string(&state.configuration().path).unwrap();
    assert!(config.contains("model_provider = \"codex_subscription_relay\""));
    assert!(!config.contains("local_fixture"));
    assert!(!state.path().join("auth.json").exists());
    let catalog = fs::read_to_string(&state.startup.catalog.path).unwrap();
    assert!(!catalog.contains("No model ran"));
    assert!(!catalog.contains("Authored local fixture"));
    let other = broker
        .prepare_codex_subscription_tools_state(&f.store, &run, &"c".repeat(64), &"b".repeat(64))
        .unwrap();
    assert_ne!(
        state.startup_binding().unwrap(),
        other.startup_binding().unwrap()
    );
    let mut wrong = run.clone();
    wrong.requested_model = ModelId::parse("fixture-model").unwrap();
    assert!(
        broker
            .prepare_codex_subscription_tools_state(
                &f.store,
                &wrong,
                &"a".repeat(64),
                &"b".repeat(64)
            )
            .is_err()
    );
    assert!(
        broker
            .prepare_codex_subscription_tools_state(&f.store, &run, "invalid", &"b".repeat(64))
            .is_err()
    );
    assert!(
        TcpListener::bind(f.address).is_err(),
        "preparation retains the same exclusive broker"
    );
}

struct Fixture {
    _root: tempfile::TempDir,
    store: PathBuf,
    run: PreparedRun,
    approved: ApprovedFiniteClient,
    copies: Vec<PathBuf>,
    home: PathBuf,
    address: SocketAddr,
}
fn fixture() -> Fixture {
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let path = root.path().canonicalize().unwrap();
    let store = path.join("store");
    let workspace = path.join("workspace");
    for directory in [&store, &workspace] {
        fs::DirBuilder::new().mode(0o700).create(directory).unwrap();
    }
    let run = PreparedRun {
        schema_version: 1,
        receipt_id: "a".repeat(64),
        source_state: "b".repeat(40),
        scope: vec!["patch.txt".into()],
        authorization_digest: "c".repeat(64),
        snapshot_hash: "d".repeat(64),
        host: HarnessId::parse("codex").unwrap(),
        requested_model: ModelId::parse("fixture-model").unwrap(),
        requested_effort: EffortLevel::Low,
        program: "finite-client".into(),
        argv: vec!["--worker".into()],
        cwd: workspace.to_str().unwrap().into(),
        stdin: PreparedInput::new(b"inert task".to_vec()),
        mode: ExecutionMode::Execute,
        target: ExecutionTarget::ExternalWorker,
        sandbox: ExecutionSandbox::WorkspaceWrite,
        timeout_ms: 3000,
        max_output_bytes: 4096,
        degradations: vec![],
        missing_runtime_evidence: vec![],
        parent_model_changed: false,
    };
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let broker = OwnedBroker::from_listener(listener).unwrap();
    let state = broker.prepare_codex_state(&store, &run).unwrap();
    let home = state.path().to_owned();
    let pin = |name: &str, executable: bool| {
        let path = path.join(name);
        fs::write(&path, name).unwrap();
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(if executable { 0o500 } else { 0o400 }),
        )
        .unwrap();
        FiniteClientFile {
            path: path.to_str().unwrap().into(),
            sha256: content_digest(name.as_bytes()),
        }
    };
    let manifest = FiniteClientManifest {
        schema_version: 1,
        task_id: "owned-namespace-test".into(),
        host_snapshot_id: "fixture-host".into(),
        client: pin("client", true),
        native: pin("native", true),
        helper: pin("helper", true),
        wrapper: pin("wrapper", true),
        profile: pin("profile", false),
        configuration: state.configuration().clone(),
        private_state: home.to_str().unwrap().into(),
        native_version: "fixture-1".into(),
        broker_endpoint: broker.endpoint().into(),
        broker_instance_sha256: broker.instance_sha256().into(),
    };
    let reviewed = FiniteClientReview::with_codex_state(
        manifest,
        &run,
        broker,
        ResourceLimits::default(),
        state,
    )
    .unwrap();
    let copies = reviewed
        .owned_assets
        .as_ref()
        .unwrap()
        .copies
        .iter()
        .map(|p| p.directory().to_owned())
        .collect();
    let digest = reviewed.approval_digest().to_owned();
    Fixture {
        _root: root,
        store,
        run,
        approved: reviewed.approve(&digest).unwrap(),
        copies,
        home,
        address,
    }
}

fn transfer(approved: ApprovedFiniteClient) -> HostState {
    approved.into_namespace_state().unwrap()
}

// A closed ephemeral port can be reassigned by another concurrent test before
// this assertion binds it. A retained broker never becomes bindable at all.
fn broker_released(address: SocketAddr, bound: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + bound;
    loop {
        if TcpListener::bind(address).is_ok() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}
#[test]
fn broker_release_wait_still_refuses_a_retained_listener() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    assert!(!broker_released(
        address,
        std::time::Duration::from_millis(25)
    ));
    drop(listener);
    assert!(broker_released(address, std::time::Duration::from_secs(1)));
}

#[test]
fn namespace_handoff_keeps_every_copy_and_the_bound_broker() {
    let f = fixture();
    let state = transfer(f.approved);
    assert!(f.home.is_dir());
    assert!(
        f.copies.iter().all(|p| p.join("program").is_file()),
        "copies cannot be disposed while the namespace owner holds the state"
    );
    assert!(
        TcpListener::bind(f.address).is_err(),
        "the exact broker must stay reserved"
    );
    drop(state);
    assert!(!f.home.exists());
    assert!(f.copies.iter().all(|p| !p.exists()));
    assert!(broker_released(
        f.address,
        std::time::Duration::from_secs(1)
    ));
}

#[test]
fn matching_stop_proof_disposes_the_complete_client_and_releases_the_broker() {
    for marker in [None, Some("router-runtime-lease-v1:namespace-clean\n")] {
        let f = fixture();
        let mut state = transfer(f.approved);
        let leases = LeaseStorage::open(&f.store).unwrap();
        let (record, path) = leases.create("finite-test", 1).unwrap();
        state.arm_cleanup(Some(&path), true).unwrap();
        if let Some(marker) = marker {
            fs::write(path, marker).unwrap();
        }
        let proof = leases.cleanup_proof("finite-test", 1, &record).unwrap();
        state.cleanup_with_proof(&proof).unwrap();
        assert!(!f.home.exists());
        assert!(f.copies.iter().all(|p| !p.exists()));
        assert!(broker_released(
            f.address,
            std::time::Duration::from_secs(1)
        ));
    }
}

#[test]
fn finite_client_state_cannot_gain_the_generic_native_home_write_grant() {
    let f = fixture();
    let state = transfer(f.approved);
    let mut reads = vec![];
    let mut writes = vec![];
    let mut environment = BTreeMap::new();
    assert!(matches!(
        state.extend(
            "codex",
            Path::new(&f.run.cwd),
            &mut reads,
            &mut writes,
            &mut environment
        ),
        Err(RuntimeError::Sandbox)
    ));
    assert!(reads.is_empty() && writes.is_empty() && environment.is_empty());
}

// Each deliberate quarantine runs in a fresh process whose temporary root is
// wholly owned by the parent. Child exit closes retained descriptors; only then
// may the parent discard the inert fixture. No workload is spawned by the body.
fn isolated_quarantine(case: &str, test: impl FnOnce()) {
    const KEY: &str = "AR_FINITE_OWNER_FIXTURE";
    if std::env::var(KEY).ok().as_deref() == Some(case) {
        test();
        return;
    }
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let tmp = root.path().join("tmp");
    fs::create_dir(&tmp).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("finite_client::ownership_tests::{case}"),
            "--test-threads=1",
            "--nocapture",
        ])
        .env(KEY, case)
        .env("TMPDIR", &tmp)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn abandoned_exposed_owner_keeps_the_complete_bundle_reserved() {
    isolated_quarantine(
        "abandoned_exposed_owner_keeps_the_complete_bundle_reserved",
        || {
            let f = fixture();
            let mut state = transfer(f.approved);
            let leases = LeaseStorage::open(&f.store).unwrap();
            let (_, path) = leases.create("abandoned", 1).unwrap();
            state.arm_cleanup(Some(&path), true).unwrap();
            fs::write(path, b"router-runtime-lease-v1:active\n").unwrap();
            drop(state);
            assert!(f.home.is_dir());
            assert!(f.copies.iter().all(|p| p.join("program").is_file()));
            assert!(TcpListener::bind(f.address).is_err());
        },
    );
}

#[test]
fn group_only_proof_cannot_dispose_the_client_or_release_its_broker() {
    isolated_quarantine(
        "group_only_proof_cannot_dispose_the_client_or_release_its_broker",
        || {
            let f = fixture();
            let mut state = transfer(f.approved);
            let leases = LeaseStorage::open(&f.store).unwrap();
            let (record, path) = leases.create("group", 1).unwrap();
            state.arm_cleanup(Some(&path), true).unwrap();
            fs::write(path, b"router-runtime-lease-v1:group-clean\n").unwrap();
            let proof = leases.cleanup_proof("group", 1, &record).unwrap();
            assert!(matches!(
                state.cleanup_with_proof(&proof),
                Err(RuntimeError::CleanupUnknown)
            ));
            assert!(f.home.is_dir());
            assert!(f.copies.iter().all(|p| p.join("program").is_file()));
            assert!(TcpListener::bind(f.address).is_err());
        },
    );
}

#[test]
fn startup_substitution_after_handoff_is_refused_before_exposure() {
    isolated_quarantine(
        "startup_substitution_after_handoff_is_refused_before_exposure",
        || {
            let f = fixture();
            let mut state = transfer(f.approved);
            let leases = LeaseStorage::open(&f.store).unwrap();
            let (_, path) = leases.create("changed-startup", 1).unwrap();
            let alias = f.home.join("installation_id");
            fs::remove_file(&alias).unwrap();
            std::os::unix::fs::symlink("tmp/installation_id", &alias).unwrap();
            assert!(matches!(
                state.arm_cleanup(Some(&path), true),
                Err(RuntimeError::Integrity("finite client startup state"))
            ));
            drop(state);
            assert!(f.home.is_dir());
            assert!(f.copies.iter().all(|p| p.join("program").is_file()));
            assert!(TcpListener::bind(f.address).is_err());
        },
    );
}

#[test]
fn arming_the_bundle_requires_namespace_mode_but_pending_can_be_invalidated() {
    let f = fixture();
    let mut state = transfer(f.approved);
    let leases = LeaseStorage::open(&f.store).unwrap();
    let (record, path) = leases.create("no-namespace", 1).unwrap();
    assert!(matches!(
        state.arm_cleanup(Some(&path), false),
        Err(RuntimeError::CleanupUnknown)
    ));
    assert!(f.copies.iter().all(|p| p.join("program").is_file()));
    let proof = leases.cleanup_proof("no-namespace", 1, &record).unwrap();
    assert_eq!(proof.evidence, ProcessCleanupEvidence::NotStarted);
    state.cleanup_with_proof(&proof).unwrap();
    assert!(!f.home.exists());
    assert!(f.copies.iter().all(|p| !p.exists()));
    assert!(broker_released(
        f.address,
        std::time::Duration::from_secs(1)
    ));
}

#[test]
fn namespace_copy_is_bound_and_disposed_with_the_unexposed_bundle() {
    let f = fixture();
    let source = f.store.parent().unwrap().join("namespace");
    fs::write(&source, b"namespace fixture").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o500)).unwrap();
    let old_binding = f.approved.proof_binding("fixture-host").unwrap();
    let reviewed = f
        .approved
        .reviewed
        .with_linux_namespace(FiniteClientFile {
            path: source.to_str().unwrap().into(),
            sha256: content_digest(b"namespace fixture"),
        })
        .unwrap();
    let namespace = reviewed.owned_namespace.as_ref().unwrap().pin.path.clone();
    let digest = reviewed.approval_digest().to_owned();
    let approved = reviewed.approve(&digest).unwrap();
    assert_ne!(approved.proof_binding("fixture-host").unwrap(), old_binding);
    let state = approved.into_namespace_state().unwrap();
    assert!(Path::new(&namespace).is_file());
    assert!(TcpListener::bind(f.address).is_err());
    drop(state);
    assert!(!Path::new(&namespace).exists());
    assert!(!f.home.exists());
    assert!(f.copies.iter().all(|path| !path.exists()));
    assert!(broker_released(
        f.address,
        std::time::Duration::from_secs(1)
    ));
}

#[test]
fn changed_retained_namespace_refuses_handoff() {
    let f = fixture();
    let source = f.store.parent().unwrap().join("namespace");
    fs::write(&source, b"namespace fixture").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o500)).unwrap();
    let reviewed = f
        .approved
        .reviewed
        .with_linux_namespace(FiniteClientFile {
            path: source.to_str().unwrap().into(),
            sha256: content_digest(b"namespace fixture"),
        })
        .unwrap();
    let pin = &reviewed.owned_namespace.as_ref().unwrap().pin;
    fs::set_permissions(&pin.path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&pin.path, b"replaced namespace").unwrap();
    fs::set_permissions(&pin.path, fs::Permissions::from_mode(0o500)).unwrap();
    let digest = reviewed.approval_digest().to_owned();
    assert!(
        reviewed
            .approve(&digest)
            .unwrap()
            .into_namespace_state()
            .is_err()
    );
}

#[test]
fn read_only_probe_requires_exact_namespace_exit_before_rearming_for_the_task() {
    let f = fixture();
    let mut state = transfer(f.approved);
    let leases = LeaseStorage::open(&f.store).unwrap();
    let (first, path) = leases.create("readonly-probe", 0).unwrap();
    state.arm_cleanup(Some(&path), true).unwrap();
    fs::write(&path, "router-runtime-lease-v1:group-clean\n").unwrap();
    let group = leases.cleanup_proof("readonly-probe", 0, &first).unwrap();
    assert!(state.finish_read_only_probe(&group).is_err());
    drop(group);
    fs::write(&path, "router-runtime-lease-v1:namespace-clean\n").unwrap();
    let proof = leases.cleanup_proof("readonly-probe", 0, &first).unwrap();
    state.finish_read_only_probe(&proof).unwrap();
    assert!(f.home.is_dir() && f.copies.iter().all(|p| p.is_dir()));
    drop(proof);
    let (second, path) = leases.create("real-task", 1).unwrap();
    state.arm_cleanup(Some(&path), true).unwrap();
    fs::write(&path, "router-runtime-lease-v1:namespace-clean\n").unwrap();
    let proof = leases.cleanup_proof("real-task", 1, &second).unwrap();
    state.cleanup_with_proof(&proof).unwrap();
    assert!(!f.home.exists() && f.copies.iter().all(|p| !p.exists()));
}
