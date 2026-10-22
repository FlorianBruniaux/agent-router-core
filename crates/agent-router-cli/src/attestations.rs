//! Explicit local operator declarations. No host or provider is executed.
use crate::{CliError, Outcome, approval_key, execution, inspect, phases, product};
use router_adapter_api::*;
use router_runtime::CapabilityProofStore;
use router_types::Capability;
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(clap::Subcommand)]
pub enum CapabilityCommand {
    /// Authenticate an operator declaration. This does not prove a native effect.
    Attest {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Revoke an existing declaration by authenticated record id, without reading its executable.
    Revoke {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        record_id: String,
        #[arg(long)]
        operator_label: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        json: bool,
    },
}
impl CapabilityCommand {
    pub(crate) fn json(&mut self) -> &mut bool {
        match self {
            Self::Attest { json, .. } | Self::Revoke { json, .. } => json,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestRequest {
    schema_version: u32,
    execution_config: PathBuf,
    host_snapshot: PathBuf,
    capability: Capability,
    scope: Vec<String>,
    network: bool,
    declared_version: String,
    operator_label: String,
    reason: String,
    max_age_seconds: u64,
}
fn proof_error(error: CapabilityProofError) -> CliError {
    CliError::Product(error.code())
}
fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    }
}
fn record_id() -> Result<String, CliError> {
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| CliError::Product("capability.store.unavailable"))?;
    use std::fmt::Write;
    let mut id = String::from("attestation-");
    for byte in bytes {
        write!(&mut id, "{byte:02x}").map_err(|_| CliError::Internal)?;
    }
    Ok(id)
}
fn output(proof: &AuthenticatedCapabilityAttestation) -> Result<Outcome, CliError> {
    product::json_output(
        &serde_json::json!({"schema_version":1,"tier":"attested","record_id":proof.record.record_id,
        "sequence":proof.record.sequence,"content_sha256":proof.digest().map_err(proof_error)?,"capability":proof.record.capability,
        "action":match proof.record.action {CapabilityAttestationAction::Grant {..}=>"grant",CapabilityAttestationAction::Revoke {..}=>"revoke"},
        "created_at_unix_seconds":proof.record.created_at_unix_seconds,"expires_at_unix_seconds":proof.record.expires_at(),"executed":false}),
        ExitCode::SUCCESS,
    )
}
pub(crate) fn run(command: CapabilityCommand) -> Result<Outcome, CliError> {
    match command {
        CapabilityCommand::Attest {
            store,
            request,
            json,
        } => {
            if !json {
                return Err(CliError::JsonOutputRequired);
            }
            let request_path = fs::canonicalize(&request).map_err(|_| CliError::RequestRead)?;
            let base = request_path.parent().ok_or(CliError::RequestRead)?;
            let input: AttestRequest = phases::read_json(&request_path, 64 * 1024)?;
            // No egress broker/admission exists in this batch. Even an operator
            // allowlist and a valid MAC cannot grant Network through attestation.
            if input.capability == Capability::Network {
                return Err(proof_error(CapabilityProofError::NetworkAdmissionRequired));
            }
            if input.schema_version != 1
                || input.scope.len() > 64
                || input.scope.iter().any(|root| {
                    root.is_empty()
                        || root.starts_with('/')
                        || root.split('/').any(|part| matches!(part, "" | "." | ".."))
                })
            {
                return Err(CliError::Product("capability.attestation.input.invalid"));
            }
            let config_path = resolve(base, &input.execution_config);
            let config = execution::sandbox(&config_path)?;
            let observation: HostObservation =
                phases::read_json(&resolve(base, &input.host_snapshot), MAX_SNAPSHOT_BYTES)?;
            let now = inspect::current_time(None)?;
            let store = if store.is_absolute() {
                store
            } else {
                std::env::current_dir()
                    .map_err(|_| CliError::RequestRead)?
                    .join(store)
            };
            let verifier = if crate::capability_proofs::has_claims(&observation) {
                Some(crate::capability_proofs::fresh(
                    &store,
                    &config,
                    &observation,
                    Some((&input.scope, input.network)),
                )?)
            } else {
                None
            };
            let snapshot = ValidatedHostObservation::from_observation_with_verifier(
                observation,
                SnapshotValidation {
                    now_unix_seconds: now,
                    max_age_seconds: 300,
                },
                verifier
                    .as_deref()
                    .map(|value| value as &dyn CapabilityProofVerifier),
            )
            .map_err(|error| CliError::Snapshot(error.code()))?;
            let pins = execution::capability_binding(
                &config,
                snapshot.host(),
                &input.declared_version,
                input.scope.iter().cloned().collect::<BTreeSet<_>>(),
                input.network,
            )?;
            let mut record = CapabilityAttestationRecord {
                schema_version: 2,
                record_id: record_id()?,
                sequence: 1,
                store_id: "0".repeat(64),
                capability: input.capability,
                binding: CapabilityAttestationBinding::from_execution_pins(pins.clone()),
                operator_label: input.operator_label,
                reason: input.reason,
                created_at_unix_seconds: now,
                action: CapabilityAttestationAction::Grant {
                    max_age_seconds: input.max_age_seconds,
                },
            };
            record.validate().map_err(proof_error)?;
            // Inputs and pins are checked before any store/key creation.
            match fs::symlink_metadata(&store) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&store)
                    .map_err(|_| CliError::Product("capability.store.unavailable"))?,
                Err(_) => return Err(CliError::Product("capability.store.unavailable")),
            }
            let secret: [u8; 32] = approval_key::load_or_create(&store)?
                .bytes()
                .try_into()
                .map_err(|_| CliError::Internal)?;
            let mut db = CapabilityProofStore::create(&store)
                .map_err(|error| CliError::Product(error.code()))?;
            db.enable_attestations(&secret)
                .map_err(|error| CliError::Product(error.code()))?;
            record.store_id = db.store_id().into();
            record.sequence = db
                .next_sequence(&secret)
                .map_err(|error| CliError::Product(error.code()))?;
            let current = execution::capability_binding(
                &execution::sandbox(&config_path)?,
                snapshot.host(),
                &input.declared_version,
                input.scope.into_iter().collect(),
                input.network,
            )?;
            if current != pins {
                return Err(proof_error(CapabilityProofError::BindingMismatch));
            }
            let proof = CapabilityAttestationKey::derive(&secret, db.store_id())
                .map_err(proof_error)?
                .authenticate(record)
                .map_err(proof_error)?;
            db.append_attestation(&proof, &secret)
                .map_err(|error| CliError::Product(error.code()))?;
            output(&proof)
        }
        CapabilityCommand::Revoke {
            store,
            record_id: target_id,
            operator_label,
            reason,
            json,
        } => {
            if !json {
                return Err(CliError::JsonOutputRequired);
            }
            let store = if store.is_absolute() {
                store
            } else {
                std::env::current_dir()
                    .map_err(|_| CliError::RequestRead)?
                    .join(store)
            };
            let secret: [u8; 32] = approval_key::load_existing(&store)?
                .bytes()
                .try_into()
                .map_err(|_| CliError::Internal)?;
            let target = CapabilityProofStore::open_existing(&store)
                .map_err(|error| CliError::Product(error.code()))?
                .attestation(&secret, &target_id)
                .map_err(|error| CliError::Product(error.code()))?;
            let mut db = CapabilityProofStore::create(&store)
                .map_err(|error| CliError::Product(error.code()))?;
            if !matches!(
                target.record.action,
                CapabilityAttestationAction::Grant { .. }
            ) {
                return Err(CliError::Product("capability.attestation.revoke.invalid"));
            }
            let record = CapabilityAttestationRecord {
                schema_version: 2,
                record_id: record_id()?,
                sequence: db
                    .next_sequence(&secret)
                    .map_err(|error| CliError::Product(error.code()))?,
                store_id: db.store_id().into(),
                capability: target.record.capability,
                binding: target.record.binding.clone(),
                operator_label,
                reason,
                created_at_unix_seconds: inspect::current_time(None)?,
                action: CapabilityAttestationAction::Revoke {
                    record_id: target_id,
                    content_sha256: target.digest().map_err(proof_error)?,
                },
            };
            let proof = CapabilityAttestationKey::derive(&secret, db.store_id())
                .map_err(proof_error)?
                .authenticate(record)
                .map_err(proof_error)?;
            db.append_attestation(&proof, &secret)
                .map_err(|error| CliError::Product(error.code()))?;
            output(&proof)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn network_attestation_is_refused_before_store_creation_or_program_access() {
        let root = tempfile::tempdir().unwrap();
        let store = root.path().join("new-store");
        let request = root.path().join("request.json");
        fs::write(&request,serde_json::to_vec(&serde_json::json!({"schema_version":1,
            "execution_config":"missing-config","host_snapshot":"missing-snapshot","capability":"network",
            "scope":[],"network":true,"declared_version":"fixture-v1","operator_label":"fixture-operator",
            "reason":"Offline negative declaration","max_age_seconds":100})).unwrap()).unwrap();
        let result = run(CapabilityCommand::Attest {
            store: store.clone(),
            request,
            json: true,
        });
        assert!(matches!(
            result,
            Err(CliError::Product(
                "capability.attestation.network_admission_required"
            ))
        ));
        assert!(!store.exists());
    }
}
