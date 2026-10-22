use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "codex")]
use adapter_codex::{CodexProbe, CodexProbeConfig};
#[cfg(any(feature = "codex", feature = "claude"))]
use router_adapter_api::HostProbe;
use router_adapter_api::{MAX_SNAPSHOT_BYTES, SnapshotValidation, ValidatedHostObservation};

use crate::{CliError, Outcome, command::HostChoice, read_bounded};

pub(crate) fn current_time(override_time: Option<u64>) -> Result<u64, CliError> {
    override_time.map_or_else(
        || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|time| time.as_secs())
                .map_err(|_| CliError::Internal)
        },
        Ok,
    )
}

pub(crate) struct InspectArgs {
    pub store: Option<PathBuf>,
    pub execution_config: Option<PathBuf>,
    pub host: HostChoice,
    pub model_cache: Option<PathBuf>,
    pub native_stream: Option<PathBuf>,
    pub observed_at: Option<u64>,
    pub observed_version: Option<String>,
    pub now: Option<u64>,
}
pub(crate) fn inspect(args: InspectArgs, json: bool) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    // An installed executable or a cache alone is not evidence of an active host.
    if matches!(args.host, HostChoice::Auto) && std::env::var_os("CODEX_THREAD_ID").is_none() {
        return Err(CliError::HostUnknown);
    }
    let now = current_time(args.now)?;
    let mut observation = if matches!(args.host, HostChoice::Claude) {
        if args.model_cache.is_some() || args.observed_version.is_some() {
            return Err(CliError::InvalidCommand);
        }
        let stream = args
            .native_stream
            .ok_or(CliError::Product("probe.native_stream.required"))?;
        let observed_at = args
            .observed_at
            .ok_or(CliError::Product("probe.observed_at.required"))?;
        probe_claude(&stream, observed_at)?
    } else {
        if args.native_stream.is_some() || args.observed_at.is_some() {
            return Err(CliError::InvalidCommand);
        }
        let model_cache_path = args
            .model_cache
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|home| PathBuf::from(home).join(".codex/models_cache.json"))
            })
            .ok_or(CliError::HostUnknown)?;
        probe(model_cache_path, args.observed_version, now)?
    };
    let verifier = match (&args.store, &args.execution_config) {
        (Some(store), Some(config)) => {
            let config = crate::execution::sandbox(config)?;
            let verifier = crate::capability_proofs::fresh(store, &config, &observation, None)?;
            let proofs = verifier
                .snapshot()
                .map_err(|e| CliError::Product(e.code()))?;
            let deciding = proofs.deciding_proofs(&observation.host, now);
            let attestations = proofs.deciding_attestations(&observation.host, now);
            let chosen_binding = deciding
                .iter()
                .map(|(_, proof)| (proof.sequence, proof.binding.clone()))
                .chain(
                    attestations
                        .iter()
                        .map(|(_, proof)| (proof.sequence, proof.binding.clone())),
                )
                .max_by_key(|(sequence, _)| *sequence)
                .map(|(_, binding)| binding);
            for (proof, _) in deciding {
                if chosen_binding.as_ref() != Some(&proof.record.binding) {
                    continue;
                }
                let record = &proof.record;
                // Later attempts under distinct bindings are not merged into one
                // capability claim; all pins are checked again on actual routing.
                if observation.host.capabilities.contains(&record.capability) {
                    continue;
                }
                observation.host.capabilities.insert(record.capability);
                observation.capabilities.insert(
                    record.capability,
                    router_adapter_api::CapabilityEvidence {
                        support: router_types::CapabilitySupport::Supported,
                        source_ids: std::collections::BTreeSet::from([record.proof_id.clone()]),
                    },
                );
                observation
                    .evidence
                    .push(router_adapter_api::EvidenceSource {
                        id: record.proof_id.clone(),
                        kind: router_adapter_api::EvidenceKind::HostRuntime,
                        observed_version: Some(record.binding.observed_version.clone()),
                        observed_at_unix_seconds: record.ended_at_unix_seconds,
                        content_sha256: proof.digest().map_err(|e| CliError::Product(e.code()))?,
                    });
            }
            let mut references = Vec::new();
            for (proof, verified) in attestations {
                if chosen_binding.as_ref() == Some(&verified.binding)
                    && !observation.host.capabilities.contains(&verified.capability)
                {
                    references.push(
                        proof
                            .reference()
                            .map_err(|error| CliError::Product(error.code()))?,
                    );
                }
            }
            if !references.is_empty() {
                observation.schema_version = 2;
                observation.attestations =
                    Some(router_adapter_api::CapabilityAttestationReferences {
                        schema_version: 1,
                        entries: references,
                    });
            }
            observation.observed_at_unix_seconds = now;
            observation = observation
                .seal()
                .map_err(|e| CliError::Snapshot(e.code()))?;
            Some(verifier)
        }
        (None, None) => None,
        _ => {
            return Err(CliError::Product(
                "capability.evidence.configuration_required",
            ));
        }
    };
    let validated = ValidatedHostObservation::from_observation_with_verifier(
        observation,
        SnapshotValidation {
            now_unix_seconds: now,
            max_age_seconds: router_adapter_api::DEFAULT_MAX_AGE_SECONDS,
        },
        verifier
            .as_deref()
            .map(|v| v as &dyn router_adapter_api::CapabilityProofVerifier),
    )
    .map_err(|error| CliError::Snapshot(error.code()))?;
    let output =
        serde_json::to_string_pretty(validated.observation()).map_err(|_| CliError::Internal)?;
    Ok(Outcome {
        output: format!("{output}\n"),
        exit_code: ExitCode::SUCCESS,
    })
}

#[cfg(feature = "claude")]
fn probe_claude(
    path: &Path,
    observed_at: u64,
) -> Result<router_adapter_api::HostObservation, CliError> {
    let bytes = read_bounded(
        path,
        router_adapter_api::MAX_TRANSPORT_BYTES,
        CliError::RequestRead,
        CliError::RequestTooLarge,
    )?;
    adapter_claude::ClaudeStreamProbe::from_native_stream(&bytes)
        .probe(observed_at)
        .map_err(|error| CliError::Probe(error.code()))
}
#[cfg(not(feature = "claude"))]
fn probe_claude(_: &Path, _: u64) -> Result<router_adapter_api::HostObservation, CliError> {
    Err(CliError::Probe("probe.feature.disabled"))
}

pub(crate) fn read_snapshot(
    path: &Path,
    now: Option<u64>,
    max_age_seconds: u64,
) -> Result<ValidatedHostObservation, CliError> {
    read_snapshot_with_verifier(path, now, max_age_seconds, None)
}
pub(crate) fn read_snapshot_with_verifier(
    path: &Path,
    now: Option<u64>,
    max_age_seconds: u64,
    verifier: Option<&dyn router_adapter_api::CapabilityProofVerifier>,
) -> Result<ValidatedHostObservation, CliError> {
    let bytes = read_bounded(
        path,
        MAX_SNAPSHOT_BYTES,
        CliError::SnapshotRead,
        CliError::SnapshotTooLarge,
    )?;
    ValidatedHostObservation::from_json_with_verifier(
        &bytes,
        SnapshotValidation {
            now_unix_seconds: current_time(now)?,
            max_age_seconds,
        },
        verifier,
    )
    .map_err(|error| CliError::Snapshot(error.code()))
}

#[cfg(all(feature = "local-api", unix))]
pub(crate) fn parse_snapshot(
    bytes: &[u8],
    now: Option<u64>,
    max_age_seconds: u64,
) -> Result<ValidatedHostObservation, CliError> {
    ValidatedHostObservation::from_json(
        bytes,
        SnapshotValidation {
            now_unix_seconds: current_time(now)?,
            max_age_seconds,
        },
    )
    .map_err(|error| CliError::Snapshot(error.code()))
}

#[cfg(feature = "codex")]
fn probe(
    model_cache_path: PathBuf,
    observed_version: Option<String>,
    now: u64,
) -> Result<router_adapter_api::HostObservation, CliError> {
    CodexProbe::new(CodexProbeConfig {
        model_cache_path,
        observed_version,
    })
    .probe(now)
    .map_err(|error| CliError::Probe(error.code()))
}

#[cfg(not(feature = "codex"))]
fn probe(
    _: PathBuf,
    _: Option<String>,
    _: u64,
) -> Result<router_adapter_api::HostObservation, CliError> {
    Err(CliError::Probe("probe.feature.disabled"))
}
