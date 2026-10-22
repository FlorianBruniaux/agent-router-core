//! Synthetic files, authenticated private proof store, real loopback listeners.
//! No native binary, provider turn or global configuration is used.
use router_adapter_api::{
    CapabilityAttemptOutcome, CapabilityNetworkScope, CapabilityProofKey, CapabilityProofRecord,
    CapabilityProofTier, EvidenceKind, EvidenceSource, content_digest,
};
use router_runtime::{
    ApprovedFiniteClient, CapabilityProofStore, FiniteClientReview, OwnedBroker, ResourceLimits,
    StoredCapabilityProofVerifier,
};
use router_types::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::TcpListener,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    manifest: FiniteClientManifest,
    run: PreparedRun,
    broker: Option<OwnedBroker>,
    host: HostSnapshot,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let root = temp.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        fs::create_dir(&workspace).unwrap();
        let state = root.join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let pin = |name: &str, executable: bool| {
            let path = root.join(name);
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
        let broker =
            OwnedBroker::from_listener(TcpListener::bind(("127.0.0.1", 0)).unwrap()).unwrap();
        let manifest = FiniteClientManifest {
            schema_version: 1,
            task_id: "task-1".into(),
            host_snapshot_id: "fixture-host".into(),
            client: pin("client", true),
            native: pin("native", true),
            helper: pin("helper", true),
            wrapper: pin("wrapper", true),
            profile: pin("profile", false),
            configuration: pin("configuration", false),
            private_state: state.to_str().unwrap().into(),
            native_version: "fixture-1".into(),
            broker_endpoint: broker.endpoint().to_owned(),
            broker_instance_sha256: broker.instance_sha256().into(),
        };
        let model = ModelId::parse("fixture-model").unwrap();
        let host = HostSnapshot {
            id: "fixture-host".into(),
            harness: HarnessId::parse("codex").unwrap(),
            supported_models: BTreeSet::from([model.clone()]),
            supported_efforts: BTreeMap::from([(
                model.clone(),
                BTreeSet::from([EffortLevel::Low]),
            )]),
            capabilities: BTreeSet::from([Capability::Network]),
        };
        let run = PreparedRun {
            schema_version: 1,
            receipt_id: "a".repeat(64),
            source_state: "b".repeat(40),
            scope: vec!["patch.txt".into()],
            authorization_digest: "c".repeat(64),
            snapshot_hash: "d".repeat(64),
            host: host.harness.clone(),
            requested_model: model,
            requested_effort: EffortLevel::Low,
            program: "finite-client".into(),
            argv: vec!["--worker".into()],
            cwd: workspace.to_str().unwrap().into(),
            stdin: PreparedInput::new(b"PRIVATE_TASK_CANARY".to_vec()),
            mode: ExecutionMode::Execute,
            target: ExecutionTarget::ExternalWorker,
            sandbox: ExecutionSandbox::WorkspaceWrite,
            timeout_ms: 3000,
            max_output_bytes: 4096,
            degradations: vec![],
            missing_runtime_evidence: vec![],
            parent_model_changed: false,
        };
        Self {
            _temp: temp,
            root,
            manifest,
            run,
            broker: Some(broker),
            host,
        }
    }
    fn review(&mut self) -> FiniteClientReview {
        FiniteClientReview::new(
            self.manifest.clone(),
            &self.run,
            self.broker.take().unwrap(),
        )
        .unwrap()
    }
    fn approve(&mut self) -> ApprovedFiniteClient {
        let review = self.review();
        let digest = review.approval_digest().to_owned();
        review.approve(&digest).unwrap()
    }
    fn approve_codex(&mut self, limits: ResourceLimits) -> ApprovedFiniteClient {
        let broker = self.broker.take().unwrap();
        let store = self.root.join("preparation");
        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        let state = broker.prepare_codex_state(&store, &self.run).unwrap();
        self.manifest.configuration = state.configuration().clone();
        self.manifest.private_state = state.path().to_str().unwrap().into();
        let review = FiniteClientReview::with_codex_state(
            self.manifest.clone(),
            &self.run,
            broker,
            limits,
            state,
        )
        .unwrap();
        let digest = review.approval_digest().to_owned();
        review.approve(&digest).unwrap()
    }
    fn proof(
        &self,
        approved: &ApprovedFiniteClient,
    ) -> (
        EvidenceSource,
        StoredCapabilityProofVerifier,
        CapabilityProofRecord,
    ) {
        let dir = self.root.join("proofs");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = CapabilityProofStore::create(&dir).unwrap();
        let key = CapabilityProofKey::derive(&[19; 32], store.store_id()).unwrap();
        let binding = approved.proof_binding(&self.host.id).unwrap();
        let record = CapabilityProofRecord {
            schema_version: 1,
            proof_id: "first".into(),
            sequence: 1,
            store_id: store.store_id().into(),
            capability: Capability::Network,
            tier: CapabilityProofTier::Proven,
            network_scope: Some(CapabilityNetworkScope::LoopbackFetch),
            binding: binding.clone(),
            model_id: "fixture-model".into(),
            nonce_sha256: "e".repeat(64),
            expected_effect_sha256: "f".repeat(64),
            started_at_unix_seconds: 99,
            ended_at_unix_seconds: 100,
            max_age_seconds: 60,
            outcome: CapabilityAttemptOutcome::Succeeded,
        };
        let proof = key.authenticate(record.clone()).unwrap();
        let hash = proof.digest().unwrap();
        store.append(&proof, &[19; 32]).unwrap();
        drop(store);
        let source = EvidenceSource {
            id: "first".into(),
            kind: EvidenceKind::HostRuntime,
            observed_version: Some("fixture-1".into()),
            observed_at_unix_seconds: 100,
            content_sha256: hash,
        };
        let verifier =
            StoredCapabilityProofVerifier::open_existing(&dir, [19; 32], vec![binding]).unwrap();
        (source, verifier, record)
    }
}

#[test]
fn validates_exact_preparation_without_launching_or_releasing_listener() {
    let mut f = Fixture::new();
    let endpoint = f.manifest.broker_endpoint.clone();
    let a = f.approve();
    let (s, v, _) = f.proof(&a);
    let guard = a.validate(&f.run, &f.host, &s, &v, 101).unwrap();
    assert_eq!(guard.broker_endpoint(), endpoint);
    assert!(TcpListener::bind(endpoint.strip_prefix("tcp://").unwrap()).is_err());
    let _ = guard;
    drop(a);
    assert!(TcpListener::bind(endpoint.strip_prefix("tcp://").unwrap()).is_ok());
}
#[test]
fn changed_stdin_is_refused_even_when_serialized_prepared_preview_is_equal() {
    let mut f = Fixture::new();
    let a = f.approve();
    let (s, v, _) = f.proof(&a);
    let mut changed = f.run.clone();
    changed.stdin = PreparedInput::new(b"REPLACED_TASK".to_vec());
    assert_eq!(
        serde_json::to_value(&changed).unwrap(),
        serde_json::to_value(&f.run).unwrap()
    );
    assert!(a.validate(&changed, &f.host, &s, &v, 101).is_err());
}
#[test]
fn wrong_review_digest_cannot_approve() {
    let mut f = Fixture::new();
    assert!(f.review().approve(&"0".repeat(64)).is_err());
}
#[test]
fn loopback_address_alone_cannot_replace_listener_instance() {
    let mut f = Fixture::new();
    f.manifest.broker_instance_sha256 = "0".repeat(64);
    assert!(FiniteClientReview::new(f.manifest, &f.run, f.broker.take().unwrap()).is_err());
}
#[test]
fn wrong_endpoint_is_refused_before_any_preparation() {
    let mut f = Fixture::new();
    f.manifest.broker_endpoint = "tcp://127.0.0.1:1".into();
    assert!(FiniteClientReview::new(f.manifest, &f.run, f.broker.take().unwrap()).is_err());
}
#[test]
fn changed_assets_and_file_permissions_refuse_old_approval() {
    for name in [
        "client",
        "native",
        "helper",
        "wrapper",
        "profile",
        "configuration",
    ] {
        let mut f = Fixture::new();
        let a = f.approve();
        let (s, v, _) = f.proof(&a);
        let path = f.root.join(name);
        let original_mode = fs::metadata(&path).unwrap().permissions();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b"REPLACED").unwrap();
        fs::set_permissions(&path, original_mode).unwrap();
        assert!(a.validate(&f.run, &f.host, &s, &v, 101).is_err(), "{name}");
    }
    let mut f = Fixture::new();
    let a = f.approve();
    let (s, v, _) = f.proof(&a);
    fs::set_permissions(f.root.join("native"), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(a.validate(&f.run, &f.host, &s, &v, 101).is_err());
}
#[test]
fn identical_replacement_and_symlink_are_not_old_file_identity() {
    for link in [false, true] {
        let mut f = Fixture::new();
        let a = f.approve();
        let (s, v, _) = f.proof(&a);
        fs::rename(
            f.root.join("configuration"),
            f.root.join("old-configuration"),
        )
        .unwrap();
        if link {
            symlink(
                f.root.join("old-configuration"),
                f.root.join("configuration"),
            )
            .unwrap();
        } else {
            fs::copy(
                f.root.join("old-configuration"),
                f.root.join("configuration"),
            )
            .unwrap();
        }
        assert!(a.validate(&f.run, &f.host, &s, &v, 101).is_err());
    }
}
#[test]
fn private_state_replacement_or_shared_permissions_refuse() {
    for replace in [false, true] {
        let mut f = Fixture::new();
        let a = f.approve();
        let (s, v, _) = f.proof(&a);
        let state = f.root.join("state");
        if replace {
            fs::rename(&state, f.root.join("old-state")).unwrap();
            fs::create_dir(&state).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        } else {
            fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert!(a.validate(&f.run, &f.host, &s, &v, 101).is_err());
    }
}
#[test]
fn changed_task_scope_model_effort_or_host_refuse() {
    let mut f = Fixture::new();
    let a = f.approve();
    let (s, v, _) = f.proof(&a);
    let mutations: [fn(&mut PreparedRun); 6] = [
        |r| r.scope.push("extra.txt".into()),
        |r| r.requested_model = ModelId::parse("other-model").unwrap(),
        |r| r.requested_effort = EffortLevel::High,
        |r| r.argv.push("--extra".into()),
        |r| r.receipt_id = "e".repeat(64),
        |r| r.authorization_digest = "e".repeat(64),
    ];
    for mutate in mutations {
        let mut changed = f.run.clone();
        mutate(&mut changed);
        assert!(a.validate(&changed, &f.host, &s, &v, 101).is_err());
    }
    let mut host = f.host.clone();
    host.id = "other-host".into();
    assert!(a.validate(&f.run, &host, &s, &v, 101).is_err());
}
#[test]
fn stale_future_or_historical_proof_cannot_validate_preparation() {
    let mut f = Fixture::new();
    let a = f.approve();
    let (s, v, _) = f.proof(&a);
    for now in [98, 160, 161] {
        assert!(a.validate(&f.run, &f.host, &s, &v, now).is_err(), "{now}");
    }
    assert!(
        a.validate(&f.run, &f.host, &s, &v.through_sequence(1), 101)
            .is_err()
    );
}
#[test]
fn later_authenticated_failure_is_seen_on_revalidation() {
    let mut f = Fixture::new();
    let a = f.approve();
    let (s, v, mut record) = f.proof(&a);
    assert!(a.validate(&f.run, &f.host, &s, &v, 101).is_ok());
    record.sequence = 2;
    record.proof_id = "later-failure".into();
    record.outcome = CapabilityAttemptOutcome::Failed;
    record.started_at_unix_seconds = 101;
    record.ended_at_unix_seconds = 101;
    let mut store = CapabilityProofStore::create(&f.root.join("proofs")).unwrap();
    let key = CapabilityProofKey::derive(&[19; 32], store.store_id()).unwrap();
    store
        .append(&key.authenticate(record).unwrap(), &[19; 32])
        .unwrap();
    assert!(a.validate(&f.run, &f.host, &s, &v, 101).is_err());
}
#[test]
fn forged_source_and_missing_store_fail_closed() {
    let mut f = Fixture::new();
    let a = f.approve();
    let (mut s, v, _) = f.proof(&a);
    s.content_sha256 = "0".repeat(64);
    assert!(a.validate(&f.run, &f.host, &s, &v, 101).is_err());
    fs::rename(f.root.join("proofs"), f.root.join("old-proofs")).unwrap();
    assert!(a.validate(&f.run, &f.host, &s, &v, 101).is_err());
}
#[test]
fn bound_contract_does_not_enable_product_broker_sandbox() {
    use router_runtime::{DenySandbox, NetworkAuthority, SandboxPolicy, SandboxSupervisor};
    let mut f = Fixture::new();
    let a = f.approve();
    let (s, v, _) = f.proof(&a);
    let _guard = a.validate(&f.run, &f.host, &s, &v, 101).unwrap();
    assert!(
        DenySandbox
            .command(
                &f.run,
                &SandboxPolicy {
                    network: NetworkAuthority::ControllerBrokerOnly,
                    host_state: None
                }
            )
            .is_err()
    );
}

#[test]
fn held_broker_is_the_listener_that_accepts_the_controller_connection() {
    let mut f = Fixture::new();
    let a = f.approve();
    let (s, v, _) = f.proof(&a);
    let guard = a.validate(&f.run, &f.host, &s, &v, 101).unwrap();
    let control =
        std::net::TcpStream::connect(guard.broker_endpoint().strip_prefix("tcp://").unwrap())
            .unwrap();
    let (accepted, peer) = guard.broker_listener().accept().unwrap();
    assert_eq!(peer, control.local_addr().unwrap());
    assert_eq!(accepted.local_addr().unwrap(), control.peer_addr().unwrap());
}
#[test]
fn wildcard_listener_is_never_a_loopback_broker() {
    assert!(OwnedBroker::from_listener(TcpListener::bind(("0.0.0.0", 0)).unwrap()).is_err());
}
#[test]
fn malformed_manifest_and_oversized_input_refuse_at_review() {
    let mutations: [fn(&mut FiniteClientManifest); 4] = [
        |m| m.schema_version = 2,
        |m| m.task_id = "../task".into(),
        |m| m.native.sha256 = "bad-hash".into(),
        |m| m.private_state = "relative-state".into(),
    ];
    for mutate in mutations {
        let mut f = Fixture::new();
        mutate(&mut f.manifest);
        assert!(FiniteClientReview::new(f.manifest, &f.run, f.broker.take().unwrap()).is_err());
    }
    let mut f = Fixture::new();
    f.run.stdin = PreparedInput::new(vec![b'x'; 32769]);
    assert!(FiniteClientReview::new(f.manifest, &f.run, f.broker.take().unwrap()).is_err());
    let f = Fixture::new();
    let mut value = serde_json::to_value(&f.manifest).unwrap();
    value["extra"] = "unexpected".into();
    assert!(serde_json::from_value::<FiniteClientManifest>(value).is_err());
}
#[test]
fn assets_inside_writable_workspace_and_oversized_configuration_refuse() {
    let mut f = Fixture::new();
    let replacement = PathBuf::from(&f.run.cwd).join("configuration");
    fs::copy(&f.manifest.configuration.path, &replacement).unwrap();
    f.manifest.configuration.path = replacement.to_str().unwrap().into();
    assert!(FiniteClientReview::new(f.manifest, &f.run, f.broker.take().unwrap()).is_err());
    let mut f = Fixture::new();
    fs::set_permissions(
        &f.manifest.configuration.path,
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(&f.manifest.configuration.path, vec![0; 65537]).unwrap();
    f.manifest.configuration.sha256 = content_digest(&vec![0; 65537]);
    assert!(FiniteClientReview::new(f.manifest, &f.run, f.broker.take().unwrap()).is_err());
}
#[test]
fn nonregular_asset_refuses_without_waiting_for_fifo_writer() {
    let mut f = Fixture::new();
    let fifo = f.root.join("fifo");
    nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
    f.manifest.configuration.path = fifo.to_str().unwrap().into();
    assert!(FiniteClientReview::new(f.manifest, &f.run, f.broker.take().unwrap()).is_err());
}
#[test]
fn authenticated_proof_for_another_preparation_is_not_reusable() {
    let mut f = Fixture::new();
    let a = f.approve();
    let (mut s, _v, mut record) = f.proof(&a);
    record.sequence = 2;
    record.proof_id = "different-binding".into();
    record.binding.argument_template_sha256 = "0".repeat(64);
    let mut store = CapabilityProofStore::create(&f.root.join("proofs")).unwrap();
    let key = CapabilityProofKey::derive(&[19; 32], store.store_id()).unwrap();
    let proof = key.authenticate(record.clone()).unwrap();
    s.id = record.proof_id;
    s.content_sha256 = proof.digest().unwrap();
    store.append(&proof, &[19; 32]).unwrap();
    drop(store);
    let v = StoredCapabilityProofVerifier::open_existing(
        &f.root.join("proofs"),
        [19; 32],
        vec![record.binding],
    )
    .unwrap();
    assert!(a.validate(&f.run, &f.host, &s, &v, 101).is_err());
}

#[test]
fn authenticated_proof_for_another_host_does_not_change_reviewed_host_identity() {
    let mut f = Fixture::new();
    let a = f.approve();
    let (mut s, _v, mut record) = f.proof(&a);
    let mut other = f.host.clone();
    other.id = "replacement-host".into();
    record.sequence = 2;
    record.proof_id = "replacement-host-proof".into();
    record.binding.host_snapshot_id = other.id.clone();
    let mut store = CapabilityProofStore::create(&f.root.join("proofs")).unwrap();
    let key = CapabilityProofKey::derive(&[19; 32], store.store_id()).unwrap();
    let proof = key.authenticate(record.clone()).unwrap();
    s.id = record.proof_id;
    s.content_sha256 = proof.digest().unwrap();
    store.append(&proof, &[19; 32]).unwrap();
    drop(store);
    let v = StoredCapabilityProofVerifier::open_existing(
        &f.root.join("proofs"),
        [19; 32],
        vec![record.binding],
    )
    .unwrap();
    assert!(a.validate(&f.run, &other, &s, &v, 101).is_err());
}

#[test]
fn concrete_resource_limits_are_checked_before_review() {
    let mut f = Fixture::new();
    let limits = ResourceLimits {
        cpu_seconds: 0,
        ..ResourceLimits::default()
    };
    assert!(
        FiniteClientReview::with_resources(
            f.manifest.clone(),
            &f.run,
            f.broker.take().unwrap(),
            limits
        )
        .is_err()
    );
}

#[test]
fn each_changed_resource_limit_is_refused_by_fresh_preparation() {
    let mut f = Fixture::new();
    let a = f.approve();
    let (s, v, _) = f.proof(&a);
    let limits = ResourceLimits::default();
    assert!(
        a.validate_with_resources(&f.run, &f.host, &s, &v, 101, &limits)
            .is_ok()
    );
    for changed in [
        ResourceLimits {
            cpu_seconds: 301,
            ..limits.clone()
        },
        ResourceLimits {
            address_space_bytes: None,
            ..limits.clone()
        },
        ResourceLimits {
            max_open_files: 257,
            ..limits.clone()
        },
        ResourceLimits {
            max_processes: 257,
            ..limits.clone()
        },
        ResourceLimits {
            max_file_bytes: 1024,
            ..limits.clone()
        },
    ] {
        assert!(
            a.validate_with_resources(&f.run, &f.host, &s, &v, 101, &changed)
                .is_err()
        );
    }
}

#[test]
fn owned_codex_state_produces_private_config_and_survives_until_approval_drop() {
    let mut f = Fixture::new();
    let broker = f.broker.take().unwrap();
    let store = f.root.join("preparation");
    fs::DirBuilder::new()
        .recursive(false)
        .create(&store)
        .unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    let state = broker.prepare_codex_state(&store, &f.run).unwrap();
    let home = state.path().to_owned();
    let config = state.configuration().clone();
    assert_eq!(
        fs::metadata(&home).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&config.path).unwrap().permissions().mode() & 0o777,
        0o400
    );
    let text = fs::read_to_string(&config.path).unwrap();
    assert!(text.contains("model = \"fixture-model\""));
    assert!(text.contains("model_reasoning_effort = \"low\""));
    assert!(text.contains(&format!(
        "base_url = \"http://{}/v1\"",
        broker.endpoint().strip_prefix("tcp://").unwrap()
    )));
    assert!(text.contains("request_max_retries = 0"));
    assert!(text.contains("shell_tool = false"));
    assert!(text.contains("code_mode.enabled = false"));
    assert!(text.contains("code_mode_host = false"));
    assert!(text.contains("code_mode_only = false"));
    assert!(text.contains("model_catalog_json = \"local-model-catalog.json\""));
    let catalog_path = home.join("local-model-catalog.json");
    let catalog: serde_json::Value =
        serde_json::from_slice(&fs::read(&catalog_path).unwrap()).unwrap();
    assert_eq!(catalog["models"][0]["slug"], "fixture-model");
    assert_eq!(catalog["models"][0]["tool_mode"], "direct");
    assert!(catalog["models"][0]["apply_patch_tool_type"].is_null());
    assert_eq!(
        fs::metadata(catalog_path).unwrap().permissions().mode() & 0o777,
        0o400
    );
    assert!(!home.join("auth.json").exists());
    f.manifest.configuration = config;
    f.manifest.private_state = home.to_str().unwrap().into();
    let review = FiniteClientReview::with_codex_state(
        f.manifest.clone(),
        &f.run,
        broker,
        ResourceLimits::default(),
        state,
    )
    .unwrap();
    let digest = review.approval_digest().to_owned();
    let a = review.approve(&digest).unwrap();
    let (s, v, _) = f.proof(&a);
    let guard = a.validate(&f.run, &f.host, &s, &v, 101).unwrap();
    if cfg!(target_os = "macos") {
        let plan = guard.launch_plan().unwrap();
        let value = serde_json::to_value(&plan).unwrap();
        assert_eq!(
            value["supervised"]["program"],
            value["read_only_assets"][2]["path"]
        );
        assert_eq!(
            value["supervised"]["argv"],
            serde_json::json!([
                "--cpu-seconds",
                "300",
                "--address-space-bytes",
                "8589934592",
                "--max-open-files",
                "256",
                "--max-processes",
                "256",
                "--max-file-bytes",
                "16777216",
                "--supervise-v1",
                value["read_only_assets"][3]["path"],
                "-f",
                value["read_only_assets"][4]["path"],
                value["read_only_assets"][0]["path"],
                "--worker"
            ])
        );
        assert_eq!(
            value["native"]["program"],
            value["read_only_assets"][1]["path"]
        );
        assert_eq!(
            value["native"]["argv"],
            serde_json::json!(["app-server", "--listen", "stdio://"])
        );
        assert_eq!(
            value["native"]["environment"]["CODEX_HOME"],
            f.manifest.private_state
        );
        assert_eq!(value["native"]["environment"].as_object().unwrap().len(), 5);
        assert_eq!(
            value["stdin_sha256"],
            content_digest(f.run.stdin.as_bytes())
        );
        assert!(
            !serde_json::to_string(&plan)
                .unwrap()
                .contains("PRIVATE_TASK_CANARY")
        );
    } else {
        assert!(guard.launch_plan().is_err());
    }
    assert!(home.exists());
    drop(a);
    assert!(!home.exists());
}

#[test]
fn state_production_refuses_task_workspace_before_creating_files() {
    let f = Fixture::new();
    let broker = f.broker.as_ref().unwrap();
    fs::set_permissions(&f.run.cwd, fs::Permissions::from_mode(0o700)).unwrap();
    let before = fs::read_dir(&f.run.cwd).unwrap().count();
    assert!(
        broker
            .prepare_codex_state(PathBuf::from(&f.run.cwd).as_path(), &f.run)
            .is_err()
    );
    assert_eq!(fs::read_dir(&f.run.cwd).unwrap().count(), before);
}

#[test]
fn manifest_only_review_cannot_present_a_native_launch_plan() {
    let mut f = Fixture::new();
    let a = f.approve();
    let (s, v, _) = f.proof(&a);
    assert!(
        a.validate(&f.run, &f.host, &s, &v, 101)
            .unwrap()
            .launch_plan()
            .is_err()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn launch_preview_refuses_workspace_change_after_guard_validation() {
    let mut f = Fixture::new();
    let a = f.approve_codex(ResourceLimits::default());
    let (s, v, _) = f.proof(&a);
    let guard = a.validate(&f.run, &f.host, &s, &v, 101).unwrap();
    assert!(guard.launch_plan().is_ok());
    fs::set_permissions(&f.run.cwd, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(guard.launch_plan().is_err());
}

#[test]
fn generated_tmp_directory_substitution_and_shared_modes_refuse() {
    for mode_change in [false, true] {
        let mut f = Fixture::new();
        let a = f.approve_codex(ResourceLimits::default());
        let (s, v, _) = f.proof(&a);
        assert!(a.validate(&f.run, &f.host, &s, &v, 101).is_ok());
        let tmp = PathBuf::from(&f.manifest.private_state).join("tmp");
        if mode_change {
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).unwrap();
        } else {
            fs::rename(&tmp, tmp.with_file_name("previous-tmp")).unwrap();
            fs::create_dir(&tmp).unwrap();
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert!(a.validate(&f.run, &f.host, &s, &v, 101).is_err());
    }
}

#[test]
fn configuration_generated_for_another_model_or_listener_cannot_be_reviewed() {
    for changed_listener in [false, true] {
        let mut f = Fixture::new();
        let broker = f.broker.take().unwrap();
        let store = f.root.join("preparation");
        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        let state = broker.prepare_codex_state(&store, &f.run).unwrap();
        f.manifest.configuration = state.configuration().clone();
        f.manifest.private_state = state.path().to_str().unwrap().into();
        let broker = if changed_listener {
            let b =
                OwnedBroker::from_listener(TcpListener::bind(("127.0.0.1", 0)).unwrap()).unwrap();
            f.manifest.broker_endpoint = b.endpoint().into();
            f.manifest.broker_instance_sha256 = b.instance_sha256().into();
            b
        } else {
            f.run.requested_model = ModelId::parse("other-model").unwrap();
            broker
        };
        assert!(
            FiniteClientReview::with_codex_state(
                f.manifest,
                &f.run,
                broker,
                ResourceLimits::default(),
                state
            )
            .is_err()
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn launch_preview_uses_owned_asset_copies_and_releases_them_with_approval() {
    let mut f = Fixture::new();
    let a = f.approve_codex(ResourceLimits::default());
    let (s, v, _) = f.proof(&a);
    let guard = a.validate(&f.run, &f.host, &s, &v, 101).unwrap();
    let value = serde_json::to_value(guard.launch_plan().unwrap()).unwrap();
    assert_ne!(value["native"]["program"], f.manifest.native.path);
    assert_ne!(value["supervised"]["program"], f.manifest.helper.path);
    let assets = value["read_only_assets"].as_array().unwrap();
    assert_eq!(assets.len(), 6);
    let expected = [
        (&f.manifest.client, 0o500),
        (&f.manifest.native, 0o500),
        (&f.manifest.helper, 0o500),
        (&f.manifest.wrapper, 0o500),
        (&f.manifest.profile, 0o400),
        (&f.manifest.configuration, 0o400),
    ];
    let mut copies = Vec::new();
    for (asset, (original, mode)) in assets.iter().zip(expected) {
        let path = PathBuf::from(asset["path"].as_str().unwrap());
        assert_eq!(content_digest(&fs::read(&path).unwrap()), original.sha256);
        assert_eq!(asset["sha256"], original.sha256);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            mode
        );
        assert!(!path.starts_with(&f.run.cwd));
        if original != &f.manifest.configuration {
            assert_ne!(path.to_str().unwrap(), original.path);
            copies.push(path.clone());
        }
    }
    let argv = value["supervised"]["argv"].as_array().unwrap();
    let offset = argv.iter().position(|arg| arg == "--supervise-v1").unwrap();
    assert_eq!(argv[offset + 1], assets[3]["path"]);
    assert_eq!(argv[offset + 2], "-f");
    assert_eq!(argv[offset + 3], assets[4]["path"]);
    assert_eq!(argv[offset + 4], assets[0]["path"]);
    assert_eq!(value["native"]["program"], assets[1]["path"]);
    assert_eq!(value["supervised"]["program"], assets[2]["path"]);
    drop(a);
    for path in copies {
        assert!(!path.exists());
        assert!(!path.parent().unwrap().exists());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn every_owned_asset_substitution_is_refused_when_presenting_the_plan() {
    for index in 0..6 {
        for symlink_change in [false, true] {
            let mut f = Fixture::new();
            let a = f.approve_codex(ResourceLimits::default());
            let (s, v, _) = f.proof(&a);
            let guard = a.validate(&f.run, &f.host, &s, &v, 101).unwrap();
            let value = serde_json::to_value(guard.launch_plan().unwrap()).unwrap();
            let assets = value["read_only_assets"].as_array().unwrap();
            let path = PathBuf::from(assets[index]["path"].as_str().unwrap());
            if symlink_change {
                fs::remove_file(&path).unwrap();
                symlink(&f.manifest.profile.path, &path).unwrap();
            } else {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                fs::write(&path, b"SUBSTITUTED_ASSET").unwrap();
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(if index < 4 { 0o500 } else { 0o400 }),
                )
                .unwrap();
            }
            assert!(
                guard.launch_plan().is_err(),
                "asset {index} symlink {symlink_change}"
            );
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn identical_copy_replacement_cannot_reuse_the_reviewed_inode() {
    let mut f = Fixture::new();
    let a = f.approve_codex(ResourceLimits::default());
    let (s, v, _) = f.proof(&a);
    let guard = a.validate(&f.run, &f.host, &s, &v, 101).unwrap();
    let value = serde_json::to_value(guard.launch_plan().unwrap()).unwrap();
    let path = PathBuf::from(value["native"]["program"].as_str().unwrap());
    let original = fs::read(&path).unwrap();
    fs::rename(&path, path.with_file_name("previous")).unwrap();
    fs::write(&path, &original).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(guard.launch_plan().is_err());
}

#[test]
fn owned_copy_preparation_is_separate_from_manifest_only_proofs() {
    let mut f = Fixture::new();
    let a = f.approve_codex(ResourceLimits::default());
    assert_eq!(
        a.proof_binding(&f.host.id).unwrap().adapter_id,
        "finite-client-contract-v4"
    );
    let (s, v, _) = f.proof(&a);
    assert!(a.validate(&f.run, &f.host, &s, &v, 101).is_ok());
    // Mutating an original after its owned copy was prepared is still refused.
    // Copies do not widen freshness policy or let a stale original pass review.
    fs::set_permissions(&f.manifest.native.path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&f.manifest.native.path, b"changed native").unwrap();
    assert!(a.validate(&f.run, &f.host, &s, &v, 101).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn substituted_copy_directory_is_preserved_when_approval_is_dropped() {
    let mut f = Fixture::new();
    let a = f.approve_codex(ResourceLimits::default());
    let (s, v, _) = f.proof(&a);
    let guard = a.validate(&f.run, &f.host, &s, &v, 101).unwrap();
    let value = serde_json::to_value(guard.launch_plan().unwrap()).unwrap();
    let path = PathBuf::from(value["native"]["program"].as_str().unwrap());
    let directory = path.parent().unwrap().to_owned();
    let moved = f.root.join("moved-owned-copy");
    fs::rename(&directory, &moved).unwrap();
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let unrelated = directory.join("unrelated");
    fs::write(&unrelated, b"CONCURRENT_USER_CANARY").unwrap();
    assert!(guard.launch_plan().is_err());
    drop(a);
    let preserved = fs::read(&unrelated).ok();
    // Reconcile only paths created by this test, after observing production Drop.
    if directory.exists() {
        fs::remove_dir_all(&directory).unwrap();
    }
    assert_eq!(
        preserved.as_deref(),
        Some(b"CONCURRENT_USER_CANARY".as_slice())
    );
    assert!(moved.join("program").exists());
}

#[test]
fn authenticated_prior_bindings_cannot_validate_owned_startup() {
    for version in ["v2", "v3"] {
        let mut f = Fixture::new();
        let a = f.approve_codex(ResourceLimits::default());
        let (current, v, mut record) = f.proof(&a);
        a.validate(&f.run, &f.host, &current, &v, 101).unwrap();
        record.proof_id = format!("old-{version}");
        record.sequence = 2;
        record.binding.adapter_id = format!("finite-client-contract-{version}");
        let mut store = CapabilityProofStore::create(&f.root.join("proofs")).unwrap();
        let key = CapabilityProofKey::derive(&[19; 32], store.store_id()).unwrap();
        let proof = key.authenticate(record).unwrap();
        let source = EvidenceSource {
            id: format!("old-{version}"),
            kind: EvidenceKind::HostRuntime,
            observed_version: Some("fixture-1".into()),
            observed_at_unix_seconds: 100,
            content_sha256: proof.digest().unwrap(),
        };
        store.append(&proof, &[19; 32]).unwrap();
        drop(store);
        assert!(a.validate(&f.run, &f.host, &source, &v, 101).is_err());
    }
}

// Synthetic trusted helper scripts verify preflight wiring, not OS enforcement.
fn resource_helper(f: &mut Fixture, body: &str) {
    let path = PathBuf::from(&f.manifest.helper.path);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
    f.manifest.helper.sha256 = content_digest(&fs::read(path).unwrap());
}
fn successful_probe() -> &'static str {
    "printf 'router-sandbox-helper-v1:limits-applied:address-space=enforced\\n'"
}

// These fixtures launch real copied shell helpers against the production 3 s
// deadline. Share a fixture slot to bound concurrent helper startup while the
// remaining finite-client tests retain libtest's normal parallel execution.
static RESOURCE_PROBE_SLOT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn owned_resource_probe_runs_copied_helper_with_exact_limits_only() {
    let _slot = RESOURCE_PROBE_SLOT.lock().await;
    let mut f = Fixture::new();
    let marker = f.root.join("helper-invocation");
    resource_helper(
        &mut f,
        &format!(
            "printf '%s\\n' \"$0\" \"$@\" > '{}'; {}",
            marker.display(),
            successful_probe()
        ),
    );
    let a = f.approve_codex(ResourceLimits::default());
    a.probe_owned_resources(&ResourceLimits::default())
        .await
        .unwrap();
    let text = fs::read_to_string(&marker).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_ne!(lines[0], f.manifest.helper.path);
    assert_eq!(
        content_digest(&fs::read(lines[0]).unwrap()),
        f.manifest.helper.sha256
    );
    assert_eq!(
        &lines[1..],
        &[
            "--cpu-seconds",
            "300",
            "--address-space-bytes",
            "8589934592",
            "--max-open-files",
            "256",
            "--max-processes",
            "256",
            "--max-file-bytes",
            "16777216",
            "--probe"
        ]
    );
    assert_eq!(lines.len(), 12);
}
#[tokio::test]
async fn owned_resource_probe_keeps_memory_refusal_and_rejects_bad_protocol() {
    let _slot = RESOURCE_PROBE_SLOT.lock().await;
    for body in [
        "echo sandbox-helper.setrlimit.address_space >&2; exit 125",
        "echo malformed",
        "echo sandbox-helper.other >&2; exit 125",
    ] {
        let mut f = Fixture::new();
        let marker = f.root.join("probe-executed");
        resource_helper(&mut f, &format!("touch '{}'; {body}", marker.display()));
        let a = f.approve_codex(ResourceLimits::default());
        let result = a.probe_owned_resources(&ResourceLimits::default()).await;
        assert!(marker.exists(), "helper did not execute before {result:?}");
        if body.contains("address_space") {
            assert!(matches!(
                result,
                Err(router_runtime::RuntimeError::ResourceUnsupported(
                    "address_space"
                ))
            ));
        } else {
            assert!(matches!(result, Err(router_runtime::RuntimeError::Sandbox)));
        }
    }
}
#[tokio::test]
async fn resource_probe_refuses_unowned_or_changed_limits_before_helper_effect() {
    let mut f = Fixture::new();
    let marker = f.root.join("must-not-exist");
    resource_helper(
        &mut f,
        &format!("touch '{}'; {}", marker.display(), successful_probe()),
    );
    let a = f.approve();
    assert!(
        a.probe_owned_resources(&ResourceLimits::default())
            .await
            .is_err()
    );
    assert!(!marker.exists());
    drop(a);
    let mut f = Fixture::new();
    let marker = f.root.join("must-not-exist");
    resource_helper(
        &mut f,
        &format!("touch '{}'; {}", marker.display(), successful_probe()),
    );
    let a = f.approve_codex(ResourceLimits::default());
    assert!(
        a.probe_owned_resources(&ResourceLimits {
            address_space_bytes: None,
            ..ResourceLimits::default()
        })
        .await
        .is_err()
    );
    assert!(!marker.exists());
}
#[tokio::test]
async fn resource_probe_refuses_source_drift_before_effect_and_during_probe() {
    let _slot = RESOURCE_PROBE_SLOT.lock().await;
    for during in [false, true] {
        let mut f = Fixture::new();
        let source = PathBuf::from(&f.manifest.client.path);
        let marker = f.root.join("helper-effect");
        let body = if during {
            format!(
                "chmod 700 '{}'; printf changed > '{}'; touch '{}'; {}",
                source.display(),
                source.display(),
                marker.display(),
                successful_probe()
            )
        } else {
            format!("touch '{}'; {}", marker.display(), successful_probe())
        };
        resource_helper(&mut f, &body);
        let a = f.approve_codex(ResourceLimits::default());
        if !during {
            fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(&source, b"changed").unwrap();
        }
        assert!(
            a.probe_owned_resources(&ResourceLimits::default())
                .await
                .is_err()
        );
        assert_eq!(marker.exists(), during);
    }
}

#[tokio::test]
async fn resource_probe_detects_copy_drift_before_a_second_helper_effect() {
    let _slot = RESOURCE_PROBE_SLOT.lock().await;
    let mut f = Fixture::new();
    let marker = f.root.join("invocation");
    resource_helper(
        &mut f,
        &format!(
            "printf '%s' \"$0\" > '{}'; {}",
            marker.display(),
            successful_probe()
        ),
    );
    let a = f.approve_codex(ResourceLimits::default());
    a.probe_owned_resources(&ResourceLimits::default())
        .await
        .unwrap();
    let copied = PathBuf::from(fs::read_to_string(&marker).unwrap());
    fs::remove_file(&marker).unwrap();
    fs::set_permissions(&copied, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&copied, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&copied, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(
        a.probe_owned_resources(&ResourceLimits::default())
            .await
            .is_err()
    );
    assert!(!marker.exists());
}

#[test]
fn owned_state_prepares_native_startup_without_opening_configuration_parent() {
    let mut f = Fixture::new();
    let broker = f.broker.take().unwrap();
    let store = f.root.join("startup-store");
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    let state = broker.prepare_codex_state(&store, &f.run).unwrap();
    let home = state.path().to_owned();
    let slot = home.join("tmp/installation_id");
    assert!(
        slot.exists(),
        "native mutable installation state must be produced before review"
    );
    assert_eq!(
        fs::read_link(home.join("installation_id")).unwrap(),
        PathBuf::from("tmp/installation_id")
    );
    let id = fs::read_to_string(&slot).unwrap();
    assert_eq!(id.len(), 36);
    for i in [8, 13, 18, 23] {
        assert_eq!(id.as_bytes()[i], b'-');
    }
    assert_eq!(id.as_bytes()[14], b'4');
    assert_eq!(id.as_bytes()[19], b'8');
    assert_eq!(
        fs::metadata(&slot).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(
        fs::metadata(home.join("config.toml"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o400
    );
    assert!(!home.join("auth.json").exists());
    f.manifest.configuration = state.configuration().clone();
    f.manifest.private_state = home.to_str().unwrap().into();
    let review = FiniteClientReview::with_codex_state(
        f.manifest.clone(),
        &f.run,
        broker,
        ResourceLimits::default(),
        state,
    )
    .unwrap();
    let digest = review.approval_digest().to_owned();
    let approved = review.approve(&digest).unwrap();
    assert!(slot.exists());
    drop(approved);
    assert!(
        !home.exists(),
        "startup and its alias follow the existing owner cleanup"
    );
}

#[test]
fn corrupted_startup_is_refused_before_review() {
    let mut f = Fixture::new();
    let broker = f.broker.take().unwrap();
    let store = f.root.join("startup-store");
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    let state = broker.prepare_codex_state(&store, &f.run).unwrap();
    fs::write(state.path().join("tmp/installation_id"), b"tampered").unwrap();
    f.manifest.configuration = state.configuration().clone();
    f.manifest.private_state = state.path().to_str().unwrap().into();
    assert!(
        FiniteClientReview::with_codex_state(
            f.manifest.clone(),
            &f.run,
            broker,
            ResourceLimits::default(),
            state
        )
        .is_err()
    );
}

#[test]
fn startup_substitution_refuses_fresh_validation() {
    for attack in [
        "catalog-content",
        "catalog-inode",
        "catalog-mode",
        "content",
        "slot-symlink",
        "slot-inode",
        "slot-mode",
        "alias-target",
        "alias-inode",
    ] {
        let mut f = Fixture::new();
        let a = f.approve_codex(ResourceLimits::default());
        let (s, v, _) = f.proof(&a);
        a.validate(&f.run, &f.host, &s, &v, 101).unwrap();
        let home = PathBuf::from(&f.manifest.private_state);
        let slot = home.join("tmp/installation_id");
        let alias = home.join("installation_id");
        let outside = f.root.join("outside-control");
        fs::write(&outside, b"untouched").unwrap();
        match attack {
            "catalog-content" => {
                let path = home.join("local-model-catalog.json");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                fs::write(&path, b"{}").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
            }
            "catalog-inode" => {
                let path = home.join("local-model-catalog.json");
                let bytes = fs::read(&path).unwrap();
                fs::remove_file(&path).unwrap();
                fs::write(&path, bytes).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
            }
            "catalog-mode" => fs::set_permissions(
                home.join("local-model-catalog.json"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap(),

            "content" => fs::write(&slot, b"tampered").unwrap(),
            "slot-symlink" => {
                if slot.exists() {
                    fs::remove_file(&slot).unwrap();
                }
                symlink(&outside, &slot).unwrap();
            }
            "slot-inode" => {
                let bytes = fs::read(&slot).unwrap_or_else(|_| b"initial".to_vec());
                fs::write(home.join("tmp/replacement"), bytes).unwrap();
                fs::set_permissions(
                    home.join("tmp/replacement"),
                    fs::Permissions::from_mode(0o644),
                )
                .unwrap();
                fs::rename(home.join("tmp/replacement"), &slot).unwrap();
            }
            "slot-mode" => {
                if !slot.exists() {
                    fs::write(&slot, b"initial").unwrap();
                }
                fs::set_permissions(&slot, fs::Permissions::from_mode(0o666)).unwrap();
            }
            "alias-target" => {
                if fs::symlink_metadata(&alias).is_ok() {
                    fs::remove_file(&alias).unwrap();
                }
                symlink(&outside, &alias).unwrap();
            }
            "alias-inode" => {
                if fs::symlink_metadata(&alias).is_ok() {
                    fs::remove_file(&alias).unwrap();
                }
                symlink("tmp/installation_id", &alias).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            a.validate(&f.run, &f.host, &s, &v, 101).is_err(),
            "startup change must invalidate approval: {attack}"
        );
        assert_eq!(fs::read(&outside).unwrap(), b"untouched");
    }
}

#[test]
#[cfg(target_os = "macos")]
fn native_preview_keeps_sqlite_in_the_private_tmp() {
    let mut f = Fixture::new();
    let a = f.approve_codex(ResourceLimits::default());
    let (s, v, _) = f.proof(&a);
    let guard = a.validate(&f.run, &f.host, &s, &v, 101).unwrap();
    let value = serde_json::to_value(guard.launch_plan().unwrap()).unwrap();
    assert_eq!(
        value["native"]["environment"]["CODEX_SQLITE_HOME"],
        format!("{}/tmp", f.manifest.private_state)
    );
    assert_eq!(value["native"]["environment"].as_object().unwrap().len(), 5);
    assert!(
        value["native"]["environment"]
            .get("OPENAI_API_KEY")
            .is_none()
    );
}

#[test]
fn manifest_only_review_cannot_construct_a_namespace_state_owner() {
    let mut f = Fixture::new();
    let approved = f.approve();
    assert!(matches!(
        approved.into_namespace_state(),
        Err(router_runtime::RuntimeError::Sandbox)
    ));
    assert!(f.root.join("client").is_file());
    assert!(f.root.join("state").is_dir());
}

#[test]
fn owned_mcp_startup_has_only_the_fixed_server_and_no_authentication() {
    let mut f = Fixture::new();
    let broker = f.broker.take().unwrap();
    let store = f.root.join("mcp-preparation");
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    let state = broker.prepare_codex_tools_state(&store, &f.run).unwrap();
    let text = fs::read_to_string(&state.configuration().path).unwrap();
    let sections: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("[mcp_servers."))
        .collect();
    assert_eq!(
        sections,
        [
            "[mcp_servers.finite]",
            "[mcp_servers.finite.tools.read_file]",
            "[mcp_servers.finite.tools.write_file]",
            "[mcp_servers.finite.tools.exec]",
        ]
    );
    assert_eq!(text.matches("approval_mode = \"approve\"").count(), 3);
    for expected in [
        "command = \"/finite-client\"",
        "args = [\"--mcp-tools\"]",
        "enabled_tools = [\"read_file\", \"write_file\", \"exec\"]",
        "env_vars = []",
        "required = true",
        "startup_readiness = \"connection\"",
        "shell_tool = false",
        "unified_exec = false",
        "apps = false",
        "request_max_retries = 0",
    ] {
        assert!(text.contains(expected), "missing {expected}");
    }
    assert!(!state.path().join("auth.json").exists());
    let catalog: serde_json::Value =
        serde_json::from_slice(&fs::read(state.path().join("local-model-catalog.json")).unwrap())
            .unwrap();
    assert_eq!(catalog["models"][0]["tool_mode"], "direct");
    assert!(
        catalog["models"][0]["base_instructions"]
            .as_str()
            .unwrap()
            .contains("three advertised finite tools")
    );
}
