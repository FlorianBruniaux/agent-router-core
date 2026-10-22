use crate::{
    CliError, MAX_CATALOG_BYTES, Outcome,
    command::{CatalogCommand, ProofArgs},
    inspect,
    product::json_output,
    read_bounded, read_catalog,
};
use router_adapter_api::{
    CapabilityProofVerifier, HostObservation, SnapshotValidation, ValidatedHostObservation,
};
use router_catalog::{AssetKind, Catalog, GeneratedCatalog, GenerationConfig};
use std::{path::Path, process::ExitCode, sync::Arc};

fn bytes(path: &Path) -> Result<Vec<u8>, CliError> {
    read_bounded(
        path,
        MAX_CATALOG_BYTES,
        CliError::CatalogRead,
        CliError::CatalogTooLarge,
    )
}
fn validation(now: Option<u64>, max_age_seconds: u64) -> Result<SnapshotValidation, CliError> {
    Ok(SnapshotValidation {
        now_unix_seconds: inspect::current_time(now)?,
        max_age_seconds,
    })
}
fn generated(
    bytes: &[u8],
    now: Option<u64>,
    max_age: u64,
    verifier: Option<&dyn router_adapter_api::CapabilityProofVerifier>,
) -> Result<Option<GeneratedCatalog>, CliError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| CliError::CatalogInvalid)?;
    if value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        == Some(2)
    {
        Ok(Some(
            GeneratedCatalog::from_json_with_verifier(bytes, validation(now, max_age)?, verifier)
                .map_err(|_| CliError::CatalogInvalid)?,
        ))
    } else {
        Ok(None)
    }
}
fn verifier(
    proof: &ProofArgs,
    observation: &HostObservation,
) -> Result<Option<Arc<dyn CapabilityProofVerifier>>, CliError> {
    match (&proof.store, &proof.execution_config) {
        (Some(store), Some(path)) => {
            let config = crate::execution::sandbox(path)?;
            Ok(Some(crate::capability_proofs::fresh(
                store,
                &config,
                observation,
                None,
            )?))
        }
        (None, None) => Ok(None),
        _ => Err(CliError::Product(
            "capability.evidence.configuration_required",
        )),
    }
}

pub(crate) fn read_snapshot_with_proofs(
    path: &Path,
    now: Option<u64>,
    max_age: u64,
    proof: &ProofArgs,
) -> Result<ValidatedHostObservation, CliError> {
    let bytes = read_bounded(
        path,
        router_adapter_api::MAX_SNAPSHOT_BYTES,
        CliError::SnapshotRead,
        CliError::SnapshotTooLarge,
    )?;
    let value =
        router_adapter_api::strict_json_limited(&bytes, router_adapter_api::MAX_SNAPSHOT_BYTES)
            .map_err(|_| CliError::Snapshot("snapshot.json.invalid"))?;
    let observation: HostObservation =
        serde_json::from_value(value).map_err(|_| CliError::Snapshot("snapshot.json.invalid"))?;
    let verifier = verifier(proof, &observation)?;
    ValidatedHostObservation::from_json_with_verifier(
        &bytes,
        validation(now, max_age)?,
        verifier.as_deref(),
    )
    .map_err(|error| CliError::Snapshot(error.code()))
}

fn generated_with_proofs(
    bytes: &[u8],
    now: Option<u64>,
    max_age: u64,
    proof: &ProofArgs,
) -> Result<Option<GeneratedCatalog>, CliError> {
    let value = router_adapter_api::strict_json_limited(bytes, MAX_CATALOG_BYTES)
        .map_err(|_| CliError::CatalogInvalid)?;
    if value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(2)
    {
        return Ok(None);
    }
    let observation: HostObservation = serde_json::from_value(
        value
            .get("snapshot")
            .cloned()
            .ok_or(CliError::CatalogInvalid)?,
    )
    .map_err(|_| CliError::CatalogInvalid)?;
    let verifier = verifier(proof, &observation)?;
    generated(bytes, now, max_age, verifier.as_deref())
}

pub(crate) fn load_with_proofs(
    path: &Path,
    now: Option<u64>,
    max_age: u64,
    proof: &ProofArgs,
) -> Result<(Catalog, Option<ValidatedHostObservation>), CliError> {
    load_bytes_with_proofs(&bytes(path)?, now, max_age, proof)
}

fn load_bytes_with_proofs(
    bytes: &[u8],
    now: Option<u64>,
    max_age: u64,
    proof: &ProofArgs,
) -> Result<(Catalog, Option<ValidatedHostObservation>), CliError> {
    if let Some(generated) = generated_with_proofs(bytes, now, max_age, proof)? {
        let observation = generated.snapshot().clone();
        let verifier = verifier(proof, &observation)?;
        let snapshot = ValidatedHostObservation::from_observation_with_verifier(
            observation,
            validation(now, max_age)?,
            verifier.as_deref(),
        )
        .map_err(|error| CliError::Snapshot(error.code()))?;
        Ok((generated.catalog().clone(), Some(snapshot)))
    } else {
        Ok((
            Catalog::from_json(bytes).map_err(|_| CliError::CatalogInvalid)?,
            None,
        ))
    }
}
pub(crate) fn load(
    path: &Path,
    now: Option<u64>,
    max_age: u64,
) -> Result<(Catalog, Option<ValidatedHostObservation>), CliError> {
    load_bytes(&bytes(path)?, now, max_age)
}

pub(crate) fn load_bytes(
    bytes: &[u8],
    now: Option<u64>,
    max_age: u64,
) -> Result<(Catalog, Option<ValidatedHostObservation>), CliError> {
    load_bytes_with_verifier(bytes, now, max_age, None)
}
pub(crate) fn load_with_verifier(
    path: &Path,
    now: Option<u64>,
    max_age: u64,
    verifier: Option<&dyn router_adapter_api::CapabilityProofVerifier>,
) -> Result<(Catalog, Option<ValidatedHostObservation>), CliError> {
    load_bytes_with_verifier(&bytes(path)?, now, max_age, verifier)
}
fn load_bytes_with_verifier(
    bytes: &[u8],
    now: Option<u64>,
    max_age: u64,
    verifier: Option<&dyn router_adapter_api::CapabilityProofVerifier>,
) -> Result<(Catalog, Option<ValidatedHostObservation>), CliError> {
    if let Some(generated) = generated(bytes, now, max_age, verifier)? {
        let snapshot = ValidatedHostObservation::from_observation_with_verifier(
            generated.snapshot().clone(),
            validation(now, max_age)?,
            verifier,
        )
        .map_err(|error| CliError::Snapshot(error.code()))?;
        Ok((generated.catalog().clone(), Some(snapshot)))
    } else {
        Ok((
            Catalog::from_json(bytes).map_err(|_| CliError::CatalogInvalid)?,
            None,
        ))
    }
}

/// Always called with `json` forced on by `Commands::structured_output`, which
/// renders the human view from this JSON result: no `--json` guard applies here.
pub(crate) fn run(command: CatalogCommand) -> Result<Outcome, CliError> {
    let max_age = router_adapter_api::DEFAULT_MAX_AGE_SECONDS;
    match command {
        CatalogCommand::Refresh {
            proof,
            host_snapshot,
            prior,
            registry,
            now,
            json: _,
        } => {
            let snapshot = read_snapshot_with_proofs(&host_snapshot, now, max_age, &proof)?;
            let prior = read_catalog(&prior)?;
            let config = registry
                .map(|path| {
                    GenerationConfig::from_json(&bytes(&path)?)
                        .map_err(|_| CliError::CatalogInvalid)
                })
                .transpose()?
                .unwrap_or_default();
            let generated = GeneratedCatalog::generate(&snapshot, &prior, &config)
                .map_err(|_| CliError::CatalogInvalid)?;
            let document: serde_json::Value = serde_json::from_slice(
                &generated
                    .canonical_json()
                    .map_err(|_| CliError::CatalogInvalid)?,
            )
            .map_err(|_| CliError::Internal)?;
            json_output(&document, ExitCode::SUCCESS)
        }
        CatalogCommand::Validate {
            proof,
            catalog,
            now,
            ..
        } => {
            let bytes = bytes(&catalog)?;
            let (version, hash, schema) = if let Some(generated) =
                generated_with_proofs(&bytes, now, max_age, &proof)?
            {
                (
                    generated.catalog().version().to_owned(),
                    generated.content_hash().to_owned(),
                    2,
                )
            } else {
                let catalog = Catalog::from_json(&bytes).map_err(|_| CliError::CatalogInvalid)?;
                (
                    catalog.version().to_owned(),
                    catalog
                        .content_hash()
                        .map_err(|_| CliError::CatalogInvalid)?,
                    1,
                )
            };
            json_output(
                &serde_json::json!({"schema_version":1,"valid":true,"catalog_schema_version":schema,"catalog_version":version,"content_hash":hash}),
                ExitCode::SUCCESS,
            )
        }
        CatalogCommand::List {
            proof,
            catalog,
            now,
            ..
        } => {
            let bytes = bytes(&catalog)?;
            if let Some(generated) = generated_with_proofs(&bytes, now, max_age, &proof)? {
                json_output(
                    &serde_json::json!({"schema_version":1,"content_hash":generated.content_hash(),"assets":generated.assets()}),
                    ExitCode::SUCCESS,
                )
            } else {
                let catalog = Catalog::from_json(&bytes).map_err(|_| CliError::CatalogInvalid)?;
                let assets: Vec<_> = catalog
                    .models()
                    .map(|(id, _)| serde_json::json!({"kind":"model","id":id}))
                    .chain(
                        catalog
                            .skills()
                            .map(|(id, _)| serde_json::json!({"kind":"skill","id":id})),
                    )
                    .collect();
                json_output(
                    &serde_json::json!({"schema_version":1,"assets":assets}),
                    ExitCode::SUCCESS,
                )
            }
        }
        CatalogCommand::Show {
            proof,
            catalog,
            id,
            kind,
            now,
            json: _,
        } => {
            let bytes = bytes(&catalog)?;
            let kind: AssetKind = serde_json::from_value(serde_json::json!(kind))
                .map_err(|_| CliError::InvalidCommand)?;
            if let Some(generated) = generated_with_proofs(&bytes, now, max_age, &proof)? {
                let canonical = generated
                    .resolve(kind, &id)
                    .map_err(|_| CliError::Product("catalog.asset.unknown"))?;
                let asset = generated
                    .assets()
                    .iter()
                    .find(|asset| asset.kind == kind && asset.id == canonical)
                    .ok_or(CliError::Product("catalog.asset.unknown"))?;
                json_output(
                    &serde_json::json!({"schema_version":1,"requested_id":id,"asset":asset}),
                    ExitCode::SUCCESS,
                )
            } else {
                let catalog = Catalog::from_json(&bytes).map_err(|_| CliError::CatalogInvalid)?;
                let asset = match kind {
                    AssetKind::Model => catalog
                        .models()
                        .find(|(key, _)| key.as_str() == id)
                        .map(|(_, value)| serde_json::to_value(value)),
                    AssetKind::Skill => catalog
                        .skills()
                        .find(|(key, _)| key.as_str() == id)
                        .map(|(_, value)| serde_json::to_value(value)),
                    _ => None,
                }
                .ok_or(CliError::Product("catalog.asset.unknown"))?
                .map_err(|_| CliError::Internal)?;
                json_output(
                    &serde_json::json!({"schema_version":1,"asset":asset}),
                    ExitCode::SUCCESS,
                )
            }
        }
    }
}
