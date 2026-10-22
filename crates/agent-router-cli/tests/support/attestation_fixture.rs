//! Synthetic attestation fixtures: local MAC authority without a provider call.
use crate::native_fixture::{self, Fixture, checked, command, write};
use router_adapter_api::{
    CapabilityAttestationReference, CapabilityAttestationReferences, HostObservation,
    SnapshotValidation, ValidatedHostObservation,
};
use router_catalog::Catalog;
use router_policy::PhaseRouter;
use router_types::{ExecutionRequest, PhaseRouteRequest};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) struct AttestationFixture {
    pub(crate) files: Fixture,
    pub(crate) request: PathBuf,
    pub(crate) snapshot: PathBuf,
    pub(crate) marker: PathBuf,
    pub(crate) program: PathBuf,
    pub(crate) now: u64,
}

fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl AttestationFixture {
    pub(crate) fn new() -> Self {
        let mut files = Fixture::metadata("exit 99", 3_000);
        // Fixture::metadata's proven canary belongs to another store identity.
        // This empty store exercises attested-only authority.
        files.store = files.root.join("attested-store");
        let marker = files.root.join("issuer-executed-program");
        let program = files.root.join("fake-claude");
        fs::write(
            &program,
            format!(
                "#!/bin/sh\nprintf invoked > {}\nexit 91\n",
                native_fixture::shell_quote(marker.to_str().unwrap())
            ),
        )
        .unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        let stream = files.root.join("native-stream.jsonl");
        fs::write(
            &stream,
            concat!(
                "{\"type\":\"system\",\"subtype\":\"init\",\"model\":\"fixture-best\",\"claude_code_version\":\"fixture-v1\"}\n",
                "{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\"type\":\"message\",\"model\":\"fixture-best\"}}\n",
            ),
        )
        .unwrap();
        let now = current_time();
        let snapshot = files.root.join("attested-snapshot.json");
        let observed = checked(
            command()
                .args(["inspect", "--host", "claude", "--native-stream"])
                .arg(&stream)
                .args([
                    "--observed-at",
                    &now.to_string(),
                    "--now",
                    &now.to_string(),
                    "--json",
                ]),
            0,
        );
        assert!(
            observed["capabilities"]
                .as_object()
                .unwrap()
                .values()
                .all(|capability| capability["support"] == "unknown")
        );
        write(&snapshot, &observed);
        let request = files.root.join("attest-request.json");
        write(
            &request,
            &json!({"schema_version":1,"execution_config":"sandbox.json",
                "host_snapshot":"attested-snapshot.json","capability":"workspace_write",
                "scope":["src"],"network":false,"declared_version":"fixture-v1",
                "operator_label":"synthetic-operator","reason":"Bounded local test declaration",
                "max_age_seconds":300}),
        );
        Self {
            files,
            request,
            snapshot,
            marker,
            program,
            now,
        }
    }

    pub(crate) fn attest(&self) -> Command {
        let mut command = command();
        command
            .args(["capability", "attest", "--store"])
            .arg(&self.files.store)
            .arg("--request")
            .arg(&self.request)
            .arg("--json");
        command
    }

    pub(crate) fn for_routing() -> Self {
        let fixture = Self::new();
        let original: HostObservation =
            serde_json::from_slice(&fs::read(fixture.files.root.join("snapshot.json")).unwrap())
                .unwrap();
        write(
            &fixture.snapshot,
            &native_fixture::unknown_observation::from_example(original),
        );
        fixture
    }

    pub(crate) fn attach_grant(&self, grant: &Value) {
        let mut snapshot: HostObservation =
            serde_json::from_slice(&fs::read(&self.snapshot).unwrap()).unwrap();
        snapshot.schema_version = 2;
        snapshot.attestations = Some(CapabilityAttestationReferences {
            schema_version: 1,
            entries: vec![CapabilityAttestationReference {
                record_id: grant["record_id"].as_str().unwrap().into(),
                content_sha256: grant["content_sha256"].as_str().unwrap().into(),
                capability: router_types::Capability::WorkspaceWrite,
                created_at_unix_seconds: grant["created_at_unix_seconds"].as_u64().unwrap(),
            }],
        });
        write(&self.snapshot, &snapshot.seal().unwrap());
    }

    pub(crate) fn policy(&self, allow_workspace_write: bool) -> PathBuf {
        let mut policy = router_types::PhasePolicy {
            schema_version: 3,
            version: "synthetic-attestation-v3".into(),
            ..Default::default()
        };
        if allow_workspace_write {
            policy
                .accepted_attestations
                .insert(router_types::Capability::WorkspaceWrite);
        }
        let path = self.files.root.join(if allow_workspace_write {
            "policy-allow.json"
        } else {
            "policy-empty.json"
        });
        write(&path, &policy);
        path
    }

    pub(crate) fn route(&self, policy: Option<&Path>) -> Command {
        let mut command = command();
        command
            .args(["route-phase", "--context"])
            .arg(self.files.root.join("context.json"))
            .arg("--host-snapshot")
            .arg(&self.snapshot)
            .arg("--catalog")
            .arg(self.files.root.join("catalog.json"))
            .arg("--store")
            .arg(&self.files.store)
            .arg("--execution-config")
            .arg(self.files.root.join("sandbox.json"))
            .args([
                "--now",
                &current_time().to_string(),
                "--snapshot-max-age-seconds",
                "300",
            ]);
        if let Some(policy) = policy {
            command.arg("--policy").arg(policy);
        }
        command.arg("--json");
        command
    }

    pub(crate) fn inspect(&self) -> Command {
        let mut command = command();
        command
            .args(["inspect", "--host", "claude", "--native-stream"])
            .arg(self.files.root.join("native-stream.jsonl"))
            .args([
                "--observed-at",
                &self.now.to_string(),
                "--now",
                &current_time().to_string(),
            ])
            .arg("--store")
            .arg(&self.files.store)
            .arg("--execution-config")
            .arg(self.files.root.join("sandbox.json"))
            .arg("--json");
        command
    }

    pub(crate) fn request_value(&self) -> Value {
        serde_json::from_slice(&fs::read(&self.request).unwrap()).unwrap()
    }

    pub(crate) fn assert_no_host_invocation(&self) {
        assert!(!self.marker.exists());
        assert!(!self.files.store.join("runtime.sqlite3").exists());
        assert!(!self.files.store.join("worktrees").exists());
    }
}

pub(crate) fn rejected(command: &mut Command, code: &str) {
    let output = command.output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) fn permissions(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

pub(crate) struct RuntimeAttestationFixture {
    pub(crate) files: Fixture,
    pub(crate) grant: Value,
    pub(crate) policy: PathBuf,
}

impl RuntimeAttestationFixture {
    pub(crate) fn new(native_sandbox: bool) -> Self {
        Self::build(native_sandbox, false)
    }

    pub(crate) fn for_coordinator() -> Self {
        Self::build(false, true)
    }

    fn build(native_sandbox: bool, coordinator: bool) -> Self {
        let body = format!(
            "printf attested > src/attested-run-marker\nprintf '%s' {}",
            native_fixture::shell_quote(native_fixture::STREAM)
        );
        let mut files = if native_sandbox {
            Fixture::new(&body, 3_000)
        } else {
            Fixture::metadata(&body, 3_000)
        };
        files.store = if coordinator {
            let root = files.root.join("attested-coordinator-store");
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            root.join("runtime")
        } else {
            files.root.join("attested-runtime-store")
        };
        let snapshot_path = files.root.join("snapshot.json");
        let original: HostObservation =
            serde_json::from_slice(&fs::read(&snapshot_path).unwrap()).unwrap();
        write(
            &snapshot_path,
            &native_fixture::unknown_observation::from_example(original),
        );
        let request_path = files.root.join("attest-request.json");
        write(
            &request_path,
            &json!({"schema_version":1,"execution_config":"sandbox.json",
                "host_snapshot":"snapshot.json","capability":"workspace_write",
                "scope":["src"],"network":false,"declared_version":"fixture-v1",
                "operator_label":"synthetic-operator","reason":"Synthetic workspace permission",
                "max_age_seconds":300}),
        );
        let grant = checked(
            command()
                .args(["capability", "attest", "--store"])
                .arg(&files.store)
                .arg("--request")
                .arg(&request_path)
                .arg("--json"),
            0,
        );
        assert_eq!(grant["executed"], false);
        let mut snapshot: HostObservation =
            serde_json::from_slice(&fs::read(&snapshot_path).unwrap()).unwrap();
        snapshot.schema_version = 2;
        snapshot.attestations = Some(CapabilityAttestationReferences {
            schema_version: 1,
            entries: vec![CapabilityAttestationReference {
                record_id: grant["record_id"].as_str().unwrap().into(),
                content_sha256: grant["content_sha256"].as_str().unwrap().into(),
                capability: router_types::Capability::WorkspaceWrite,
                created_at_unix_seconds: grant["created_at_unix_seconds"].as_u64().unwrap(),
            }],
        });
        let snapshot = snapshot.seal().unwrap();
        write(&snapshot_path, &snapshot);

        let mut policy = router_types::PhasePolicy {
            schema_version: 3,
            version: "synthetic-workspace-attestation".into(),
            ..Default::default()
        };
        policy
            .accepted_attestations
            .insert(router_types::Capability::WorkspaceWrite);
        let policy_path = files.root.join("policy-allow.json");
        write(&policy_path, &policy);
        let secret: [u8; 32] = fs::read(files.store.join("approval.key"))
            .unwrap()
            .try_into()
            .unwrap();
        let store = router_runtime::CapabilityProofStore::open_existing(&files.store).unwrap();
        let attestation = store
            .attestation(&secret, grant["record_id"].as_str().unwrap())
            .unwrap();
        let verifier = store
            .verifier(&secret, vec![attestation.record.binding.execution_pins()])
            .unwrap();
        let now = grant["created_at_unix_seconds"].as_u64().unwrap();
        let validated = ValidatedHostObservation::from_observation_with_verifier(
            snapshot,
            SnapshotValidation {
                now_unix_seconds: now,
                max_age_seconds: 300,
            },
            Some(&verifier),
        )
        .unwrap();
        let request: PhaseRouteRequest =
            serde_json::from_slice(&fs::read(files.root.join("context.json")).unwrap()).unwrap();
        let catalog =
            Catalog::from_json(&fs::read(files.root.join("catalog.json")).unwrap()).unwrap();
        let mut execution: ExecutionRequest =
            serde_json::from_slice(&fs::read(files.root.join("request.json")).unwrap()).unwrap();
        // The shared asset fixture constructs an unauthenticated historical
        // observation. Strip declaration references only for that synthetic
        // historical source, then rebind its availability to the real v2
        // snapshot validated above with the store verifier.
        let mut asset_snapshot = validated.observation().clone();
        asset_snapshot.schema_version = 1;
        asset_snapshot.attestations = None;
        let asset_snapshot = ValidatedHostObservation::from_observation(
            asset_snapshot.seal().unwrap(),
            SnapshotValidation {
                now_unix_seconds: now,
                max_age_seconds: 300,
            },
        )
        .unwrap();
        let mut assets = native_fixture::asset_inputs(
            &request,
            &asset_snapshot,
            &catalog,
            &files.repo,
            &execution.source_state,
            now,
        );
        let mut availability = assets.availability.document().clone();
        availability.snapshot_hash = validated.hash().into();
        let availability =
            router_asset_contracts::seal_availability(availability, &validated).unwrap();
        assets.availability = router_asset_contracts::ValidatedAvailability::from_json(
            &serde_json::to_vec(&availability).unwrap(),
            &validated,
            &availability.content_hash,
            now,
        )
        .unwrap();
        let router = PhaseRouter::new(policy).unwrap();
        let context = router
            .context_with_assets(request, &validated, &catalog, assets.clone(), now)
            .unwrap();
        let receipt = router.route(&context).unwrap();
        assert_eq!(receipt.schema_version, 6);
        let selected = receipt
            .selected
            .as_ref()
            .expect("attested candidate selected");
        execution.receipt_id = receipt.receipt_id;
        execution.required_capabilities =
            router.execution_capabilities(&context, selected).unwrap();
        write(&files.root.join("request.json"), &execution);
        native_fixture::write_asset_authority(&files.root, &assets);
        let mut definition: Value =
            serde_json::from_slice(&fs::read(files.root.join("definition.json")).unwrap()).unwrap();
        definition["policy"] = json!("policy-allow.json");
        write(&files.root.join("definition.json"), &definition);
        Self {
            files,
            grant,
            policy: policy_path,
        }
    }

    pub(crate) fn revoke(&self) -> Value {
        checked(
            command()
                .args(["capability", "revoke", "--store"])
                .arg(&self.files.store)
                .arg("--record-id")
                .arg(self.grant["record_id"].as_str().unwrap())
                .args([
                    "--operator-label",
                    "synthetic-operator",
                    "--reason",
                    "Revoked in test",
                    "--json",
                ]),
            0,
        )
    }
}
