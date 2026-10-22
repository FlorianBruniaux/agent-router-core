//! Explicit store-backed proof loading. No host execution and no proof issuer.
use crate::{CliError, execution::SandboxConfig};
use router_adapter_api::{CapabilityProofVerifier, HostObservation};
use router_runtime::{CapabilityProofStore, StoredCapabilityProofVerifier};
use std::{path::Path, sync::Arc};

pub(crate) fn has_claims(observation: &HostObservation) -> bool {
    observation
        .capabilities
        .values()
        .any(|e| e.support != router_types::CapabilitySupport::Unknown)
        || observation
            .attestations
            .as_ref()
            .is_some_and(|value| !value.entries.is_empty())
}

fn secret(store: &Path) -> Result<[u8; 32], CliError> {
    crate::approval_key::load_existing(store)?
        .bytes()
        .try_into()
        .map_err(|_| CliError::Internal)
}

/// Current pins come from executable bytes, compiled adapter/profile code and
/// configuration, never from a caller-supplied digest. inspect uses the proof's
/// bound relative scope; routing and execution replace it with the actual scope.
pub(crate) fn fresh(
    store: &Path,
    config: &SandboxConfig,
    observation: &HostObservation,
    scope: Option<(&[String], bool)>,
) -> Result<Arc<StoredCapabilityProofVerifier>, CliError> {
    let secret = secret(store)?;
    let proofs = CapabilityProofStore::open_existing(store)
        .map_err(|e| CliError::Product(e.code()))?
        .verifier(&secret, vec![])
        .map_err(|e| CliError::Product(e.code()))?;
    let mut expected = Vec::new();
    for binding in proofs.authenticated_bindings() {
        if binding.harness_id != observation.host.harness.as_str()
            || binding.host_snapshot_id != observation.host.id
        {
            continue;
        }
        // A conflicting explicit observation voids the pin. Missing model-cache
        // version is UNKNOWN; the exact executable is still hashed and native
        // dispatch must independently observe the proof's version.
        if observation.evidence.iter().any(|e| {
            e.kind != router_adapter_api::EvidenceKind::HostRuntime
                && e.observed_version
                    .as_ref()
                    .is_some_and(|v| v != &binding.observed_version)
        }) {
            continue;
        }
        let (roots, network) = match scope {
            Some((roots, network)) => (roots.iter().cloned().collect(), network),
            None => (binding.write_roots.clone(), binding.network),
        };
        let binding = crate::execution::capability_binding(
            config,
            &observation.host,
            &binding.observed_version,
            roots,
            network,
        )?;
        if !expected.contains(&binding) {
            expected.push(binding);
        }
    }
    Ok(Arc::new(
        StoredCapabilityProofVerifier::open_existing(store, secret, expected)
            .map_err(|e| CliError::Product(e.code()))?,
    ))
}

/// Declared historical reconstruction for a validated replay document only.
/// The record's input hash binds its snapshot, but does not prove that a live
/// run produced it. This verifier is never used to authorize fresh execution.
pub(crate) fn historical_replay(
    store: &Path,
    record: &router_eval::ReplayRecord,
) -> Result<Arc<dyn CapabilityProofVerifier>, CliError> {
    let observation = &record.input().snapshot;
    let references: std::collections::BTreeSet<_> = observation
        .capabilities
        .values()
        .filter(|evidence| evidence.support != router_types::CapabilitySupport::Unknown)
        .flat_map(|evidence| evidence.source_ids.iter())
        .collect();
    let mut sources: Vec<_> = observation
        .evidence
        .iter()
        .filter(|source| references.contains(&source.id))
        .cloned()
        .collect();
    if sources.len() != references.len() {
        return Err(CliError::Product("capability.evidence.unauthenticated"));
    }
    sources.retain(|source| source.kind == router_adapter_api::EvidenceKind::HostRuntime);
    let secret = secret(store)?;
    let proofs = CapabilityProofStore::open_existing(store)
        .map_err(|error| CliError::Product(error.code()))?
        .verifier(&secret, vec![])
        .map_err(|error| CliError::Product(error.code()))?;
    let sequence = proofs
        .referenced_sequence(&observation.host, &sources)
        .map_err(|error| CliError::Product(error.code()))?;
    let attestation_sequence = proofs
        .referenced_attestation_sequence(
            &observation.host,
            observation
                .attestations
                .as_ref()
                .map_or(&[], |value| value.entries.as_slice()),
        )
        .map_err(|error| CliError::Product(error.code()))?;
    let sequence = sequence.max(attestation_sequence);
    historical_through(store, Some(sequence))
}
pub(crate) fn historical_through(
    store: &Path,
    sequence: Option<u64>,
) -> Result<Arc<dyn CapabilityProofVerifier>, CliError> {
    let secret = secret(store)?;
    let proofs = CapabilityProofStore::open_existing(store)
        .map_err(|e| CliError::Product(e.code()))?
        .verifier(&secret, vec![])
        .map_err(|e| CliError::Product(e.code()))?;
    let bindings = match sequence {
        Some(sequence) => proofs.through_sequence(sequence).authenticated_bindings(),
        None => proofs.authenticated_bindings(),
    };
    let verifier = StoredCapabilityProofVerifier::open_existing(store, secret, bindings)
        .map_err(|e| CliError::Product(e.code()))?;
    Ok(Arc::new(match sequence {
        Some(sequence) => verifier.through_sequence(sequence),
        None => verifier,
    }))
}

#[cfg(all(test, feature = "codex"))]
mod tests {
    use super::*;
    use router_adapter_api::*;
    use router_types::*;
    use serde_json::json;
    use std::{collections::BTreeSet, fs, os::unix::fs::PermissionsExt, path::PathBuf};

    struct Fixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        store: PathBuf,
        config: PathBuf,
        cache: PathBuf,
        binary: PathBuf,
        key: [u8; 32],
        proof: AuthenticatedCapabilityProof,
    }
    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap();
            let root = fs::canonicalize(temp.path()).unwrap();
            let store = root.join("store");
            fs::create_dir(&store).unwrap();
            fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
            let key = [42; 32];
            fs::write(store.join("approval.key"), key).unwrap();
            fs::set_permissions(
                store.join("approval.key"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let binary = root.join("fixture-host");
            fs::write(&binary, b"synthetic executable bytes, never executed").unwrap();
            let helper = root.join("fixture-helper");
            fs::write(&helper, b"synthetic helper bytes, never executed").unwrap();
            let config = root.join("sandbox.json");
            fs::write(&config, serde_json::to_vec(&json!({"schema_version":1,
                "programs":{"codex":binary},"helper":helper,"bubblewrap":helper,
                "read_roots":[],"environment_names":[],
                "limits":{"cpu_seconds":1,"address_space_bytes":null,"max_open_files":64,"max_processes":8,"max_file_bytes":8192},
                "feedback_store":null})).unwrap()).unwrap();
            let cache = root.join("models.json");
            fs::write(&cache, serde_json::to_vec(&json!({"fetched_at":"1970-01-01T00:01:40Z","client_version":"0.1.0",
                "models":[{"slug":"fixture-best","supported_reasoning_levels":[{"effort":"medium"}]}]})).unwrap()).unwrap();
            let observation = Self::inspect_paths(&cache, None, None, 120);
            let configuration = crate::execution::sandbox(&config)
                .unwrap_or_else(|_| panic!("fixture configuration"));
            let binding = crate::execution::capability_binding(
                &configuration,
                &observation.host,
                "0.1.0",
                BTreeSet::from(["src".into()]),
                false,
            )
            .unwrap_or_else(|_| panic!("fixture binding"));
            let mut db = CapabilityProofStore::create(&store).unwrap();
            let proof = CapabilityProofKey::derive(&key, db.store_id())
                .unwrap()
                .authenticate(CapabilityProofRecord {
                    schema_version: 1,
                    proof_id: "synthetic-write-proof".into(),
                    sequence: 1,
                    store_id: db.store_id().into(),
                    capability: Capability::WorkspaceWrite,
                    tier: CapabilityProofTier::Proven,
                    network_scope: None,
                    binding,
                    model_id: "fixture-best".into(),
                    nonce_sha256: "7".repeat(64),
                    expected_effect_sha256: "8".repeat(64),
                    started_at_unix_seconds: 105,
                    ended_at_unix_seconds: 110,
                    max_age_seconds: 1000,
                    outcome: CapabilityAttemptOutcome::Succeeded,
                })
                .unwrap();
            db.append(&proof, &key).unwrap();
            Self {
                _temp: temp,
                root,
                store,
                config,
                cache,
                binary,
                key,
                proof,
            }
        }
        fn inspect_paths(
            cache: &Path,
            store: Option<&Path>,
            config: Option<&Path>,
            now: u64,
        ) -> HostObservation {
            let outcome = crate::inspect::inspect(
                crate::inspect::InspectArgs {
                    store: store.map(Path::to_owned),
                    execution_config: config.map(Path::to_owned),
                    host: crate::command::HostChoice::Codex,
                    model_cache: Some(cache.to_owned()),
                    native_stream: None,
                    observed_at: None,
                    observed_version: Some("0.1.0".into()),
                    now: Some(now),
                },
                true,
            )
            .unwrap_or_else(|e| panic!("inspect {}", e.code()));
            serde_json::from_str(&outcome.output).unwrap()
        }
        fn inspected(&self, now: u64) -> HostObservation {
            Self::inspect_paths(&self.cache, Some(&self.store), Some(&self.config), now)
        }
        fn inputs(&self, observation: &HostObservation, now: u64) -> crate::command::PhaseArgs {
            let mut request: PhaseRouteRequest = serde_json::from_str(include_str!(
                "../../../fixtures/examples/phase-request.json"
            ))
            .unwrap();
            request.phase = StageKind::Execute;
            request.task.required_capabilities = BTreeSet::from([Capability::WorkspaceWrite]);
            request.candidates.truncate(1);
            request.candidates[0].sandbox = PhaseSandbox::WorkspaceWrite;
            request.candidates[0].required_capabilities =
                BTreeSet::from([Capability::WorkspaceWrite]);
            request.candidates[0].required_mutations = BTreeSet::from([Mutation::WorkspaceWrite]);
            let context = self.root.join("context.json");
            fs::write(&context, serde_json::to_vec(&request).unwrap()).unwrap();
            let host_snapshot = self.root.join("snapshot.json");
            fs::write(&host_snapshot, serde_json::to_vec(observation).unwrap()).unwrap();
            let catalog = self.root.join("catalog.json");
            fs::write(
                &catalog,
                include_bytes!("../../../fixtures/examples/phase-catalog.json"),
            )
            .unwrap();
            crate::command::PhaseArgs {
                store: Some(self.store.clone()),
                execution_config: Some(self.config.clone()),
                context,
                host_snapshot,
                catalog,
                policy: None,
                policy_store: None,
                asset_authority: None,
                now: Some(now),
                snapshot_max_age_seconds: 300,
            }
        }
    }

    #[test]
    fn inspect_folds_authenticated_proven_proof_and_write_phase_passes_shared_policy() {
        let f = Fixture::new();
        let observation = f.inspected(120);
        assert_eq!(
            observation.capabilities[&Capability::WorkspaceWrite].support,
            CapabilitySupport::Supported
        );
        assert_eq!(
            observation.capabilities[&Capability::Network].support,
            CapabilitySupport::Unknown
        );
        let (router, context) = crate::phases::load(&f.inputs(&observation, 120))
            .unwrap_or_else(|e| panic!("route {}", e.code()));
        let receipt = router.route(&context).unwrap();
        assert!(receipt.selected.is_some(), "{:?}", receipt.exclusions);
        assert_eq!(receipt.schema_version, 5);
        let evidence = &receipt.capability_evidence[&Capability::WorkspaceWrite];
        assert_eq!(evidence.proof_sha256, f.proof.digest().unwrap());
        assert_eq!(evidence.tier, "proven");
        assert_eq!(evidence.expires_at_unix_seconds, 1110);
        // The snapshot is fresh but the proof may be older than the 300s bound.
        let mut cache: serde_json::Value =
            serde_json::from_slice(&fs::read(&f.cache).unwrap()).unwrap();
        cache["fetched_at"] = "1970-01-01T00:08:20Z".into();
        fs::write(&f.cache, serde_json::to_vec(&cache).unwrap()).unwrap();
        let old_proof = f.inspected(500);
        assert!(crate::phases::load(&f.inputs(&old_proof, 500)).is_ok());
    }

    #[test]
    fn shared_cli_loader_refuses_handwritten_relabelled_sources_and_changed_binary() {
        let f = Fixture::new();
        let valid = f.inspected(120);
        for mutate in [
            (|o: &mut HostObservation| {
                o.evidence
                    .iter_mut()
                    .find(|e| e.kind == EvidenceKind::HostRuntime)
                    .unwrap()
                    .content_sha256 = "f".repeat(64);
            }) as fn(&mut HostObservation),
            |o| {
                o.evidence
                    .iter_mut()
                    .find(|e| e.kind == EvidenceKind::HostRuntime)
                    .unwrap()
                    .observed_version = Some("0.2.0".into());
            },
            |o| {
                o.evidence
                    .iter_mut()
                    .find(|e| e.kind == EvidenceKind::HostRuntime)
                    .unwrap()
                    .observed_at_unix_seconds += 1;
            },
            |o| {
                o.host.id = "another-host".into();
            },
            |o| {
                let evidence = o.capabilities.remove(&Capability::WorkspaceWrite).unwrap();
                o.host.capabilities.remove(&Capability::WorkspaceWrite);
                o.host.capabilities.insert(Capability::Network);
                o.capabilities.insert(Capability::Network, evidence);
            },
        ] {
            let mut changed = valid.clone();
            mutate(&mut changed);
            let changed = changed.seal().unwrap();
            assert!(crate::phases::load(&f.inputs(&changed, 120)).is_err());
        }
        let mut inputs = f.inputs(&valid, 120);
        inputs.store = None;
        inputs.execution_config = None;
        assert_eq!(
            crate::phases::load(&inputs).err().unwrap().code(),
            "capability.evidence.unauthenticated"
        );
        fs::write(&f.binary, b"changed executable bytes").unwrap();
        assert_eq!(
            f.inspected(120).capabilities[&Capability::WorkspaceWrite].support,
            CapabilitySupport::Unknown
        );
        assert!(crate::phases::load(&f.inputs(&valid, 120)).is_err());
    }

    #[test]
    fn failed_attempt_revokes_inspection_but_history_at_run_clock_survives() {
        let f = Fixture::new();
        let observation = f.inspected(120);
        let mut store = CapabilityProofStore::create(&f.store).unwrap();
        let mut record = f.proof.record.clone();
        record.sequence = 2;
        record.proof_id = "synthetic-failure".into();
        record.started_at_unix_seconds = 150;
        record.ended_at_unix_seconds = 160;
        record.outcome = CapabilityAttemptOutcome::Failed;
        let proof = CapabilityProofKey::derive(&f.key, store.store_id())
            .unwrap()
            .authenticate(record)
            .unwrap();
        store.append(&proof, &f.key).unwrap();
        assert_eq!(
            f.inspected(170).capabilities[&Capability::WorkspaceWrite].support,
            CapabilitySupport::Unknown
        );
        assert!(crate::phases::load(&f.inputs(&observation, 170)).is_err());
        let verifier = historical_through(&f.store, Some(1))
            .unwrap_or_else(|e| panic!("history {}", e.code()));
        assert!(
            ValidatedHostObservation::from_observation_with_verifier(
                observation.clone(),
                SnapshotValidation {
                    now_unix_seconds: 120,
                    max_age_seconds: 86_400,
                },
                Some(verifier.as_ref())
            )
            .is_ok()
        );
        assert!(
            ValidatedHostObservation::from_observation_with_verifier(
                observation,
                SnapshotValidation {
                    now_unix_seconds: 1200,
                    max_age_seconds: 86_400,
                },
                Some(verifier.as_ref())
            )
            .is_err()
        );
    }
    #[test]
    fn many_previous_scopes_do_not_exhaust_current_or_historical_binding_bounds() {
        let f = Fixture::new();
        let observation = f.inspected(120);
        let config = crate::execution::sandbox(&f.config).unwrap_or_else(|_| panic!("config"));
        let mut store = CapabilityProofStore::create(&f.store).unwrap();
        let key = CapabilityProofKey::derive(&f.key, store.store_id()).unwrap();
        for sequence in 2..=66 {
            let mut record = f.proof.record.clone();
            record.sequence = sequence;
            record.proof_id = format!("other-scope-{sequence}");
            record.binding = crate::execution::capability_binding(
                &config,
                &observation.host,
                "0.1.0",
                BTreeSet::from([format!("scope-{sequence}")]),
                false,
            )
            .unwrap_or_else(|_| panic!("binding"));
            store
                .append(&key.authenticate(record).unwrap(), &f.key)
                .unwrap();
        }
        assert!(crate::phases::load(&f.inputs(&observation, 120)).is_ok());
        let verifier = historical_through(&f.store, Some(1))
            .unwrap_or_else(|e| panic!("historical {}", e.code()));
        assert!(
            ValidatedHostObservation::from_observation_with_verifier(
                observation,
                SnapshotValidation {
                    now_unix_seconds: 120,
                    max_age_seconds: 300,
                },
                Some(verifier.as_ref())
            )
            .is_ok()
        );
    }
    #[test]
    fn replay_and_comparison_keep_per_record_authenticated_horizons_without_binary() {
        let f = Fixture::new();
        let old = f.inspected(120);
        let inputs = f.inputs(&old, 120);
        let request: serde_json::Value =
            serde_json::from_slice(&fs::read(&inputs.context).unwrap()).unwrap();
        let catalog: serde_json::Value =
            serde_json::from_slice(&fs::read(&inputs.catalog).unwrap()).unwrap();
        let make_record = |snapshot: &HostObservation, case: &str| {
            let observation = json!({"usage":[{"model":"fixture-best","input_tokens":10,"cached_input_tokens":0,"output_tokens":1}],"elapsed_ms":10,"fallback_reasons":[],
                "outcomes":{"transport":"passed","command_validation":"passed","functional":"unknown"}});
            router_eval::ReplayRecord::seal(serde_json::from_value(json!({"schema_version":1,"case_id":case,"family_id":"synthetic-proof-history","split":"held_out","out_of_domain":false,
                "request":request,"snapshot":snapshot,"catalog":catalog,
                "policies":{"baseline":PhasePolicy::default(),"candidate":PhasePolicy::default()},
                "pricing":{"schema_version":1,"version":"fixture","source":"synthetic","observed_at_unix_seconds":120,
                    "models":{"fixture-best":{"input_microusd_per_million":1000,"cached_input_microusd_per_million":100,"output_microusd_per_million":5000}}},
                "observations":{"baseline":observation,"candidate":observation},"label":null})).unwrap()).unwrap()
        };
        let old_record = make_record(&old, "old-case");
        let old_path = f.root.join("old-replay.json");
        fs::write(&old_path, old_record.canonical_json().unwrap()).unwrap();
        let replay = |path: &Path, store: Option<&Path>| {
            crate::evaluation::replay(path, "candidate", store, Some(120), 300, true)
                .unwrap_or_else(|error| panic!("historical replay: {}", error.code()))
                .output
        };
        let before = replay(&old_path, Some(&f.store));
        let parsed: serde_json::Value = serde_json::from_str(&before).unwrap();
        assert_eq!(parsed["capability_evidence"], "verified");
        assert!(parsed["receipt"]["selected"].is_object());
        let compare = |records: Vec<PathBuf>| {
            crate::evaluation::run(crate::command::EvalCommand::Compare {
                store: Some(f.store.clone()),
                records,
                baseline: "baseline".into(),
                candidate: "candidate".into(),
                criteria: None,
                now: Some(120),
                snapshot_max_age_seconds: 300,
                json: true,
            })
            .unwrap_or_else(|error| panic!("historical compare: {}", error.code()))
            .output
        };
        let report_before = compare(vec![old_path.clone()]);
        let mut store = CapabilityProofStore::create(&f.store).unwrap();
        let key = CapabilityProofKey::derive(&f.key, store.store_id()).unwrap();
        for (sequence, outcome) in [
            (2, CapabilityAttemptOutcome::Failed),
            (3, CapabilityAttemptOutcome::Succeeded),
        ] {
            let mut record = f.proof.record.clone();
            record.sequence = sequence;
            record.proof_id = format!("subsequent-{sequence}");
            record.started_at_unix_seconds = 120;
            record.ended_at_unix_seconds = 120;
            record.outcome = outcome;
            store
                .append(&key.authenticate(record).unwrap(), &f.key)
                .unwrap();
            assert!(
                crate::phases::load(&f.inputs(&old, 120)).is_err(),
                "fresh routing must not reuse an earlier proof"
            );
            assert_eq!(replay(&old_path, Some(&f.store)), before);
            assert_eq!(compare(vec![old_path.clone()]), report_before);
        }
        let newer = f.inspected(120);
        let new_path = f.root.join("new-replay.json");
        fs::write(
            &new_path,
            make_record(&newer, "new-case").canonical_json().unwrap(),
        )
        .unwrap();
        let new_before = replay(&new_path, Some(&f.store));
        // A common maximum across records would invalidate the old source.
        let paired_before = compare(vec![old_path.clone(), new_path.clone()]);
        fs::remove_file(&f.binary).unwrap();
        assert!(crate::phases::load(&f.inputs(&old, 120)).is_err());
        assert_eq!(replay(&old_path, Some(&f.store)), before);
        assert_eq!(replay(&new_path, Some(&f.store)), new_before);
        assert_eq!(compare(vec![old_path.clone(), new_path]), paired_before);
        let no_store: serde_json::Value = serde_json::from_str(&replay(&old_path, None)).unwrap();
        assert_eq!(no_store["capability_evidence"], "unverified");
        assert!(no_store["receipt"]["selected"].is_null());
        let other = Fixture::new();
        assert!(
            crate::evaluation::replay(
                &old_path,
                "candidate",
                Some(&other.store),
                Some(120),
                300,
                true
            )
            .is_err()
        );
        for change in 0..3 {
            let mut changed = old.clone();
            match change {
                0 => {
                    changed
                        .evidence
                        .iter_mut()
                        .find(|source| source.id == f.proof.record.proof_id)
                        .unwrap()
                        .content_sha256 = "9".repeat(64)
                }
                1 => changed.host.id = "wrong-host".into(),
                _ => {
                    changed
                        .capabilities
                        .get_mut(&Capability::WorkspaceWrite)
                        .unwrap()
                        .source_ids = BTreeSet::from(["missing".into()])
                }
            }
            if change != 2 {
                changed = changed.seal().unwrap();
            }
            let path = f.root.join(format!("tampered-{change}.json"));
            fs::write(
                &path,
                make_record(&changed, "invalid-case")
                    .canonical_json()
                    .unwrap(),
            )
            .unwrap();
            assert!(
                crate::evaluation::replay(&path, "candidate", Some(&f.store), Some(120), 300, true)
                    .is_err()
            );
        }
    }
}
