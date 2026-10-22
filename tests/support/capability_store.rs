//! Synthetic MAC fixture provisioning. Tests only, never a production issuer.
//! The caller must keep only capabilities used by its test. In particular a
//! network=false fixture cannot mint a supported Network capability.
#![allow(dead_code)]
use router_adapter_api::*;
use router_runtime::CapabilityProofStore;
use router_types::{CapabilitySupport, HostSnapshot};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, os::unix::fs::PermissionsExt, path::Path};

pub const FIXTURE_SECRET: [u8; 32] = [42; 32];

/// Mirrors the published binding preimage, not a snapshot's asserted digest.
pub fn binding(
    host: &HostSnapshot,
    config: &Value,
    scope: &[String],
    network: bool,
    version: &str,
) -> CapabilityProofBinding {
    let mut config = config.clone();
    let object = config.as_object_mut().unwrap();
    object.entry("bubblewrap").or_insert(Value::Null);
    object.entry("feedback_store").or_insert(Value::Null);
    object
        .entry("output_retention")
        .or_insert(json!({"mode":"disabled"}));
    // Optional adapter configs are omitted by SandboxConfig when absent.
    for key in ["opencode", "copilot"] {
        if object.get(key) == Some(&Value::Null) {
            object.remove(key);
        }
    }
    let (program, template) = match host.harness.as_str() {
        "codex" => (
            "codex",
            include_str!("../../crates/adapter-codex/src/execution.rs"),
        ),
        "claude-code" => (
            "claude",
            include_str!("../../crates/adapter-claude/src/execution.rs"),
        ),
        "opencode" => (
            "opencode",
            include_str!("../../crates/adapter-opencode/src/lib.rs"),
        ),
        "copilot" => (
            "copilot",
            include_str!("../../crates/adapter-copilot/src/lib.rs"),
        ),
        other => panic!("unsupported fixture host {other}"),
    };
    let digest = |path: &str| content_digest(&fs::read(path).unwrap());
    let roots: BTreeSet<String> = scope.iter().cloned().collect();
    let profile = serde_json::to_vec(&(
        "capability-profile-v1",
        include_str!("../../crates/router-runtime/src/sandbox.rs"),
        include_str!("../../crates/router-runtime/src/bubblewrap.rs"),
        include_str!("../../crates/router-runtime/src/host_state.rs"),
        include_str!("../../crates/router-runtime/src/private_program.rs"),
        &config,
        &roots,
        network,
    ))
    .unwrap();
    #[cfg(target_os = "macos")]
    let wrapper = "/usr/bin/sandbox-exec";
    #[cfg(not(target_os = "macos"))]
    let wrapper = config["bubblewrap"].as_str().unwrap();
    CapabilityProofBinding {
        harness_id: host.harness.to_string(),
        host_snapshot_id: host.id.clone(),
        binary_sha256: digest(config["programs"][program].as_str().unwrap()),
        observed_version: version.into(),
        adapter_id: host.harness.to_string(),
        argument_template_sha256: content_digest(template.as_bytes()),
        sandbox_helper_sha256: digest(config["helper"].as_str().unwrap()),
        sandbox_wrapper_sha256: digest(wrapper),
        sandbox_profile_sha256: content_digest(&profile),
        write_roots: roots,
        network,
        os: std::env::consts::OS.into(),
    }
}

/// Returns a sealed observation and a verifier for in-process preparation tests.
/// Persist the sealed result to exercise the actual CLI loader with --store.
pub fn provision(
    observation: &HostObservation,
    config: &Value,
    scope: &[String],
    network: bool,
    root: &Path,
    version: &str,
) -> (HostObservation, CapabilityProofSet) {
    if !root.exists() {
        fs::create_dir(root).unwrap();
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    let key_path = root.join("approval.key");
    if !key_path.exists() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .unwrap();
        file.write_all(&FIXTURE_SECRET).unwrap();
    }
    let secret: [u8; 32] = fs::read(&key_path).unwrap().try_into().unwrap();
    let mut store = CapabilityProofStore::create(root).unwrap();
    let binding = binding(&observation.host, config, scope, network, version);
    let key = CapabilityProofKey::derive(&secret, store.store_id()).unwrap();
    let mut snapshot = observation.clone();
    snapshot
        .evidence
        .retain(|e| e.kind != EvidenceKind::HostRuntime);
    // Each call provisions a new isolated fixture store; never rewrite rows.
    let mut sequence = 0;
    for (capability, evidence) in &mut snapshot.capabilities {
        evidence
            .source_ids
            .retain(|id| snapshot.evidence.iter().any(|e| e.id == *id));
        if evidence.support == CapabilitySupport::Unknown {
            continue;
        }
        assert_eq!(
            evidence.support,
            CapabilitySupport::Supported,
            "failed observations must be UNKNOWN"
        );
        sequence += 1;
        let record = CapabilityProofRecord {
            schema_version: 1,
            proof_id: format!("synthetic-proof-{sequence}"),
            sequence,
            store_id: store.store_id().into(),
            capability: *capability,
            tier: CapabilityProofTier::Proven,
            network_scope: (*capability == router_types::Capability::Network)
                .then_some(CapabilityNetworkScope::LoopbackFetch),
            binding: binding.clone(),
            model_id: snapshot.host.supported_models.first().unwrap().to_string(),
            nonce_sha256: "7".repeat(64),
            expected_effect_sha256: "8".repeat(64),
            started_at_unix_seconds: snapshot.observed_at_unix_seconds,
            ended_at_unix_seconds: snapshot.observed_at_unix_seconds,
            max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            outcome: CapabilityAttemptOutcome::Succeeded,
        };
        let proof = key.authenticate(record).unwrap();
        store.append(&proof, &secret).unwrap();
        evidence.source_ids = BTreeSet::from([proof.record.proof_id.clone()]);
        snapshot.evidence.push(EvidenceSource {
            id: proof.record.proof_id.clone(),
            kind: EvidenceKind::HostRuntime,
            observed_version: Some(version.into()),
            observed_at_unix_seconds: snapshot.observed_at_unix_seconds,
            content_sha256: proof.digest().unwrap(),
        });
    }
    let snapshot = snapshot.seal().unwrap();
    let verifier = store.verifier(&secret, vec![binding]).unwrap();
    (snapshot, verifier)
}
