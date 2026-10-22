use crate::{
    DoctorError, MAX_ARTIFACTS, MAX_FILE_BYTES, MAX_TOTAL_BYTES, Result, diagnose,
    files::{ReadRoot, relative},
};
use router_adapter_api::{SnapshotValidation, content_digest, strict_json};
use router_catalog::{Catalog, GeneratedCatalog};
use router_retrieval::{Bm25Index, MetadataDocument, MetadataEnvelope, MetadataEnvelopeV3};
use router_types::*;
use serde::{Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Seek, SeekFrom},
};

/// Additional deep reads are bounded independently from the legacy pass. No
/// external process, network request, repair, migration or hook is performed.
pub fn diagnose_deep(request: &DeepDoctorRequest, now: u64) -> Result<DeepDoctorReport> {
    validate_request(request)?;
    let mut base_request = request.base.clone();
    // A component-specific schema replaces the generic v1 JSON test only. Its
    // pathname, permissions, hash and secret checks still run unchanged.
    for artifact in &mut base_request.artifacts {
        if request
            .schemas
            .iter()
            .any(|binding| binding.artifact_id == artifact.id)
        {
            artifact.kind = DoctorArtifactKind::ManagedFile;
        }
    }
    let mut base = diagnose(&base_request, now)?;
    for check in &mut base.checks {
        if let Some(artifact) = request
            .base
            .artifacts
            .iter()
            .find(|artifact| content_digest(artifact.id.as_bytes()) == check.subject_sha256)
        {
            check.kind = artifact.kind;
        }
    }
    let root = ReadRoot::open(&request.base.root)?;
    let artifacts: BTreeMap<_, _> = request
        .base
        .artifacts
        .iter()
        .map(|artifact| (artifact.id.as_str(), artifact))
        .collect();
    let mut state = DeepState {
        root: &root,
        base: &base,
        total: 0,
        bodies: 0,
        queries: 0,
        checks: vec![],
    };
    for binding in &request.schemas {
        let artifact = artifacts[binding.artifact_id.as_str()];
        let outcome = state.read(artifact).and_then(|(_, bytes)| {
            validate_schema(binding.schema, &bytes)?;
            Ok((
                DeepDoctorCode::ComponentValidated,
                Some(content_digest(&bytes)),
            ))
        });
        state.record(&format!("schema:{}", binding.artifact_id), outcome);
    }
    for artifact in &request.base.artifacts {
        if artifact.kind == DoctorArtifactKind::JsonConfiguration
            && !request
                .schemas
                .iter()
                .any(|binding| binding.artifact_id == artifact.id)
        {
            state.record(
                &format!("schema:{}", artifact.id),
                Ok((DeepDoctorCode::ComponentSchemaRequired, None)),
            );
        }
        if artifact.kind == DoctorArtifactKind::RetrievalIndex
            && !request
                .retrieval_bindings
                .iter()
                .any(|binding| binding.index_artifact_id == artifact.id)
        {
            state.record(
                &format!("binding:{}", artifact.id),
                Ok((DeepDoctorCode::CatalogBindingRequired, None)),
            );
        }
        if artifact.kind == DoctorArtifactKind::Database {
            let outcome = crate::diagnose::inspect_database(state.root, artifact).and_then(
                |(configuration, _, _)| {
                    if configuration == DiagnosticState::Fail {
                        return Err(DoctorError::Path);
                    }
                    Ok((DeepDoctorCode::DatabaseSnapshotRequired, None))
                },
            );
            state.record(&format!("database:{}", artifact.id), outcome);
        }
    }
    for binding in &request.retrieval_bindings {
        let outcome = inspect_binding(
            &mut state,
            binding,
            &artifacts,
            request.base.max_snapshot_age_seconds,
            now,
        );
        state.record(&format!("binding:{}", binding.index_artifact_id), outcome);
    }
    state
        .checks
        .sort_by(|left, right| left.subject_sha256.cmp(&right.subject_sha256));
    let overall = if base.overall == DiagnosticState::Fail
        || state
            .checks
            .iter()
            .any(|check| check.configuration == DiagnosticState::Fail)
    {
        DiagnosticState::Fail
    } else if base.overall == DiagnosticState::Warning
        || state
            .checks
            .iter()
            .any(|check| check.configuration == DiagnosticState::Warning)
    {
        DiagnosticState::Warning
    } else {
        DiagnosticState::Unknown
    };
    let checks = std::mem::take(&mut state.checks);
    let examined_body_count = state.bodies;
    let database_queries = state.queries;
    Ok(DeepDoctorReport {
        schema_version: 1,
        base,
        checks,
        overall,
        examined_body_count,
        database_queries,
    })
}

fn validate_request(request: &DeepDoctorRequest) -> Result<()> {
    if request.schema_version != 1
        || request.base.artifacts.len() > MAX_ARTIFACTS
        || request.schemas.len() > MAX_ARTIFACTS
        || request.retrieval_bindings.len() > 16
    {
        return Err(DoctorError::Invalid);
    }
    let mut schemas = BTreeSet::new();
    for binding in &request.schemas {
        if !schemas.insert(&binding.artifact_id)
            || !request.base.artifacts.iter().any(|artifact| {
                artifact.id == binding.artifact_id
                    && matches!(
                        artifact.kind,
                        DoctorArtifactKind::JsonConfiguration | DoctorArtifactKind::ManagedFile
                    )
            })
        {
            return Err(DoctorError::Invalid);
        }
    }
    let mut indexes = BTreeSet::new();
    for binding in &request.retrieval_bindings {
        if !indexes.insert(&binding.index_artifact_id)
            || binding
                .body_root
                .as_ref()
                .is_some_and(|path| !relative(path))
            || !request.base.artifacts.iter().any(|artifact| {
                artifact.id == binding.index_artifact_id
                    && artifact.kind == DoctorArtifactKind::RetrievalIndex
            })
            || !request.base.artifacts.iter().any(|artifact| {
                artifact.id == binding.catalog_artifact_id
                    && artifact.kind == DoctorArtifactKind::Catalog
            })
        {
            return Err(DoctorError::Invalid);
        }
    }
    Ok(())
}

struct DeepState<'a> {
    root: &'a ReadRoot,
    base: &'a DoctorReport,
    total: usize,
    bodies: usize,
    queries: usize,
    checks: Vec<DeepDoctorCheck>,
}
impl DeepState<'_> {
    fn read(&mut self, artifact: &DoctorArtifact) -> Result<(File, Vec<u8>)> {
        let before = self
            .base
            .checks
            .iter()
            .find(|check| check.subject_sha256 == content_digest(artifact.id.as_bytes()))
            .ok_or(DoctorError::Invalid)?;
        if before.configuration == DiagnosticState::Fail {
            return Err(DoctorError::Invalid);
        }
        let mut file = self.root.file(&artifact.relative_path)?;
        let bytes = read_file(&mut file, &mut self.total)?;
        if before.content_sha256.as_deref() != Some(content_digest(&bytes).as_str()) {
            return Err(DoctorError::Integrity);
        }
        Ok((file, bytes))
    }
    fn record(&mut self, subject: &str, outcome: Result<(DeepDoctorCode, Option<String>)>) {
        let (code, hash) = outcome.unwrap_or_else(|error| {
            (
                match error {
                    DoctorError::Path => DeepDoctorCode::PathRejected,
                    DoctorError::Read => DeepDoctorCode::InputUnavailable,
                    DoctorError::Limit => DeepDoctorCode::InputLimit,
                    DoctorError::Integrity => DeepDoctorCode::InputChanged,
                    _ => DeepDoctorCode::SchemaInvalid,
                },
                None,
            )
        });
        let configuration = match code {
            DeepDoctorCode::ComponentValidated
            | DeepDoctorCode::CatalogBindingValidated
            | DeepDoctorCode::AssetBodyValidated
            | DeepDoctorCode::DatabaseIntegrityValidated => DiagnosticState::Pass,
            DeepDoctorCode::ComponentSchemaRequired
            | DeepDoctorCode::CatalogBindingRequired
            | DeepDoctorCode::CatalogAssetRegistryUnavailable
            | DeepDoctorCode::DatabaseSnapshotRequired
            | DeepDoctorCode::DatabaseReadOnlyUnsupported => DiagnosticState::Unknown,
            _ => DiagnosticState::Fail,
        };
        self.checks.push(DeepDoctorCheck {
            subject_sha256: content_digest(subject.as_bytes()),
            configuration,
            runtime: DiagnosticState::Unknown,
            code,
            content_sha256: hash,
        });
    }
}

fn read_file(file: &mut File, total: &mut usize) -> Result<Vec<u8>> {
    let remaining = MAX_TOTAL_BYTES.saturating_sub(*total).min(MAX_FILE_BYTES);
    if remaining == 0 || file.metadata().map_err(|_| DoctorError::Read)?.len() > remaining as u64 {
        return Err(DoctorError::Limit);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| DoctorError::Read)?;
    let mut bytes = vec![];
    file.take(remaining as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| DoctorError::Read)?;
    *total = total.checked_add(bytes.len()).ok_or(DoctorError::Limit)?;
    if bytes.len() > remaining {
        return Err(DoctorError::Limit);
    }
    Ok(bytes)
}

fn parse<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let value = strict_json(bytes).map_err(|_| DoctorError::Schema)?;
    let parsed = serde_json::from_value::<T>(value.clone()).map_err(|_| DoctorError::Schema)?;
    let accepted = serde_json::to_value(&parsed).map_err(|_| DoctorError::Schema)?;
    // Some component DTOs still tolerate unknown fields (the routing, catalog
    // and restriction contracts now reject them).
    // Deep diagnostics must not silently certify fields ignored by a validator.
    if !known_fields(&value, &accepted) {
        return Err(DoctorError::Schema);
    }
    Ok(parsed)
}
fn known_fields(input: &serde_json::Value, accepted: &serde_json::Value) -> bool {
    match (input, accepted) {
        (serde_json::Value::Object(input), serde_json::Value::Object(accepted)) => {
            input.iter().all(|(key, value)| {
                accepted
                    .get(key)
                    .is_some_and(|known| known_fields(value, known))
            })
        }
        (serde_json::Value::Array(input), serde_json::Value::Array(accepted)) => {
            input.len() == accepted.len()
                && input
                    .iter()
                    .zip(accepted)
                    .all(|(value, known)| known_fields(value, known))
        }
        _ => true,
    }
}
fn validate_schema(schema: DoctorSchema, bytes: &[u8]) -> Result<()> {
    let invalid = |_| DoctorError::Schema;
    match schema {
        DoctorSchema::ConfigurationLayers => {
            router_workflow::resolve_configuration(&parse(bytes)?).map_err(invalid)?;
        }
        DoctorSchema::EffectiveRestrictions => {
            router_workflow::validate_restrictions(&parse(bytes)?).map_err(invalid)?
        }
        DoctorSchema::NormalizedTask => {
            router_workflow::validate_task(&parse(bytes)?).map_err(invalid)?
        }
        DoctorSchema::WorkflowPlan => {
            router_workflow::validate_plan(&parse(bytes)?).map_err(invalid)?;
        }
        DoctorSchema::PromptTemplate => {
            let template: PromptTemplate = parse(bytes)?;
            if router_workflow::seal_prompt(template.clone()).map_err(invalid)? != template {
                return Err(DoctorError::Integrity);
            }
        }
        DoctorSchema::PhasePolicy => {
            router_policy::PhaseRouter::new(parse(bytes)?).map_err(|_| DoctorError::Schema)?;
        }
    }
    Ok(())
}

fn inspect_binding(
    state: &mut DeepState<'_>,
    binding: &DoctorRetrievalBinding,
    artifacts: &BTreeMap<&str, &DoctorArtifact>,
    max_age: u64,
    now: u64,
) -> Result<(DeepDoctorCode, Option<String>)> {
    let (_, catalog_bytes) = state.read(artifacts[binding.catalog_artifact_id.as_str()])?;
    let value = strict_json(&catalog_bytes).map_err(|_| DoctorError::Schema)?;
    let (catalog, generated) = match value.get("schema_version").and_then(|value| value.as_u64()) {
        Some(1) => (
            Catalog::from_json(&catalog_bytes).map_err(|_| DoctorError::Schema)?,
            None,
        ),
        Some(2) => {
            let generated = GeneratedCatalog::from_json(
                &catalog_bytes,
                SnapshotValidation {
                    now_unix_seconds: now,
                    max_age_seconds: max_age,
                },
            )
            .map_err(|_| DoctorError::Schema)?;
            (generated.catalog().clone(), Some(generated))
        }
        _ => return Err(DoctorError::Schema),
    };
    // The routing context binds the policy projection, not the outer generated
    // envelope digest. This is the same hash expected by preparation/runtime.
    let catalog_hash = catalog.content_hash().map_err(|_| DoctorError::Schema)?;
    let (_, index_bytes) = state.read(artifacts[binding.index_artifact_id.as_str()])?;
    let index = Bm25Index::from_json(&index_bytes).map_err(|_| DoctorError::Schema)?;
    if index.catalog_hash().is_none() {
        return Ok((DeepDoctorCode::CatalogBindingRequired, None));
    }
    if index.validate_catalog_hash(&catalog_hash).is_err() {
        return Ok((DeepDoctorCode::CatalogBindingMismatch, None));
    }
    let source = strict_json(&index_bytes).map_err(|_| DoctorError::Schema)?;
    let metadata: MetadataDocument = match source.get("schema_version").and_then(|v| v.as_str()) {
        Some("2") => parse::<MetadataEnvelope>(&index_bytes)?.metadata,
        Some("3") => parse::<MetadataEnvelopeV3>(&index_bytes)?.metadata,
        _ => return Err(DoctorError::Schema),
    };
    if metadata.catalog_version != catalog.version() {
        return Ok((DeepDoctorCode::CatalogBindingMismatch, None));
    }
    for asset in &metadata.assets {
        if asset.kind == router_retrieval::AssetKind::Skill {
            let id = SkillId::parse(&asset.id).map_err(|_| DoctorError::Schema)?;
            let Some(skill) = catalog.skill(&id) else {
                return Ok((DeepDoctorCode::CatalogBindingMismatch, None));
            };
            if skill.trust != asset.trust {
                return Ok((DeepDoctorCode::AssetBodyUntrusted, None));
            }
        } else if generated.is_none() {
            return Ok((DeepDoctorCode::CatalogAssetRegistryUnavailable, None));
        }
        if let Some(generated) = &generated {
            let kind = catalog_kind(asset.kind);
            let Some(entry) = generated
                .assets()
                .iter()
                .find(|entry| entry.kind == kind && entry.id == asset.id)
            else {
                return Ok((DeepDoctorCode::CatalogBindingMismatch, None));
            };
            if asset
                .body
                .as_ref()
                .is_some_and(|body| body.sha256 != entry.content_sha256)
            {
                return Ok((DeepDoctorCode::AssetBodyMismatch, None));
            }
        }
    }
    if let Some(body_root) = &binding.body_root {
        if metadata.assets.len() > MAX_ARTIFACTS.saturating_sub(state.bodies) {
            return Err(DoctorError::Limit);
        }
        for asset in &metadata.assets {
            let subject = format!(
                "body:{}:{:?}:{}",
                binding.index_artifact_id, asset.kind, asset.id
            );
            let outcome = (|| {
                if !matches!(
                    asset.trust,
                    SkillTrust::Builtin | SkillTrust::TrustedLocal | SkillTrust::VerifiedThirdParty
                ) {
                    return Ok((DeepDoctorCode::AssetBodyUntrusted, None));
                }
                let Some(body) = &asset.body else {
                    return Ok((DeepDoctorCode::AssetBodyUnavailable, None));
                };
                let mut file = state.root.file(&format!("{body_root}/{}", body.path))?;
                if file.metadata().map_err(|_| DoctorError::Read)?.len()
                    > router_retrieval::MAX_BODY_BYTES as u64
                {
                    return Err(DoctorError::Limit);
                }
                let bytes = read_file(&mut file, &mut state.total)?;
                state.bodies += 1;
                if bytes.len() > router_retrieval::MAX_BODY_BYTES {
                    return Err(DoctorError::Limit);
                }
                let hash = content_digest(&bytes);
                if hash != body.sha256 {
                    return Ok((DeepDoctorCode::AssetBodyMismatch, Some(hash)));
                }
                Ok((DeepDoctorCode::AssetBodyValidated, Some(hash)))
            })();
            state.record(&subject, outcome);
        }
    }
    Ok((DeepDoctorCode::CatalogBindingValidated, Some(catalog_hash)))
}

fn catalog_kind(kind: router_retrieval::AssetKind) -> router_catalog::AssetKind {
    match kind {
        router_retrieval::AssetKind::Model => router_catalog::AssetKind::Model,
        router_retrieval::AssetKind::Agent => router_catalog::AssetKind::Agent,
        router_retrieval::AssetKind::Skill => router_catalog::AssetKind::Skill,
        router_retrieval::AssetKind::Prompt => router_catalog::AssetKind::Prompt,
        router_retrieval::AssetKind::Tool => router_catalog::AssetKind::Tool,
    }
}
