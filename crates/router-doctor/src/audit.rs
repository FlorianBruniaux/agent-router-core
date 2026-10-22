use crate::{
    DoctorError, MAX_ARTIFACTS, MAX_FILE_BYTES, MAX_TOTAL_BYTES, Result,
    diagnose::contains_secret_pattern,
};
use router_adapter_api::{content_digest, is_digest, strict_json};
use router_types::*;
use serde_json::Value;

const MAX_PROJECTED_ENTRIES: usize = 64;
const MAX_AUDIT_NUMBER: u64 = 1_000_000_000_000;
const MAX_AUDIT_SCORE: i64 = 1_000_000_000_000_000_000;

/// Raw content is transient input only. Debug never exposes it.
pub struct AuditInput<'a> {
    pub kind: AuditArtifactKind,
    pub bytes: &'a [u8],
}
impl std::fmt::Debug for AuditInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditInput")
            .field("kind", &self.kind)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

pub fn build_audit_bundle(inputs: &[AuditInput<'_>]) -> Result<AuditBundle> {
    if inputs.len() > MAX_ARTIFACTS {
        return Err(DoctorError::Limit);
    }
    let mut total = 0usize;
    let mut records = Vec::new();
    let mut previous_hash = "0".repeat(64);
    for (index, input) in inputs.iter().enumerate() {
        total = total
            .checked_add(input.bytes.len())
            .ok_or(DoctorError::Limit)?;
        if input.bytes.len() > MAX_FILE_BYTES || total > MAX_TOTAL_BYTES {
            return Err(DoctorError::Limit);
        }
        let value = strict_json(input.bytes).map_err(|_| DoctorError::Schema)?;
        let entries = match &value {
            serde_json::Value::Object(fields) => fields.len(),
            serde_json::Value::Array(items) => items.len(),
            _ => return Err(DoctorError::Schema),
        };
        let metadata = AuditMetadata {
            schema_version: value
                .get("schema_version")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok()),
            top_level_entries: entries,
            contained_secret_pattern: contains_secret_pattern(input.bytes),
        };
        let mut record = AuditRecord {
            sequence: index as u64 + 1,
            kind: input.kind,
            content_sha256: content_digest(input.bytes),
            byte_count: input.bytes.len(),
            metadata,
            projection: Some(project(input.kind, &value)),
            previous_hash,
            record_hash: String::new(),
        };
        record.record_hash = digest_record(&record, 2)?;
        previous_hash = record.record_hash.clone();
        records.push(record);
    }
    Ok(AuditBundle {
        schema_version: 2,
        records,
        root_hash: previous_hash,
        raw_content_included: false,
        signature_verified: false,
    })
}

/// Check against an independently retained root to detect replacement/truncation.
/// Without that trust anchor this establishes internal integrity only, not
/// authenticity: a party can rewrite the chain and compute a different root.
pub fn verify_audit_bundle(bundle: &AuditBundle, expected_root: Option<&str>) -> Result<()> {
    if !matches!(bundle.schema_version, 1 | 2)
        || bundle.raw_content_included
        || bundle.signature_verified
        || bundle.records.len() > MAX_ARTIFACTS
        || !is_digest(&bundle.root_hash)
    {
        return Err(DoctorError::Integrity);
    }
    let mut previous = "0".repeat(64);
    let mut total = 0usize;
    for (index, record) in bundle.records.iter().enumerate() {
        match (bundle.schema_version, &record.projection) {
            (1, None) => {}
            (2, Some(projection)) => validate_projection(record.kind, projection)?,
            _ => return Err(DoctorError::Integrity),
        }
        total = total
            .checked_add(record.byte_count)
            .ok_or(DoctorError::Limit)?;
        if record.byte_count > MAX_FILE_BYTES
            || total > MAX_TOTAL_BYTES
            || record.metadata.top_level_entries > MAX_FILE_BYTES
        {
            return Err(DoctorError::Limit);
        }
        if record.sequence != index as u64 + 1
            || record.previous_hash != previous
            || !is_digest(&record.content_sha256)
            || digest_record(record, bundle.schema_version)? != record.record_hash
        {
            return Err(DoctorError::Integrity);
        }
        previous = record.record_hash.clone();
    }
    if previous != bundle.root_hash || expected_root.is_some_and(|root| root != bundle.root_hash) {
        return Err(DoctorError::Integrity);
    }
    Ok(())
}

fn digest_record(record: &AuditRecord, version: u32) -> Result<String> {
    let mut payload = if version == 1 {
        b"agent-router:redacted-audit:v1\0".to_vec()
    } else {
        b"agent-router:redacted-audit:v2\0".to_vec()
    };
    payload.extend(
        serde_json::to_vec(&(
            record.sequence,
            record.kind,
            &record.content_sha256,
            record.byte_count,
            &record.metadata,
            &record.previous_hash,
        ))
        .map_err(|_| DoctorError::Schema)?,
    );
    if version == 2 {
        payload.push(0);
        payload.extend(serde_json::to_vec(&record.projection).map_err(|_| DoctorError::Schema)?);
    }
    Ok(content_digest(&payload))
}

fn claim(value: Option<&Value>) -> Option<String> {
    let value = value?.as_str()?;
    if value.is_empty() || value.len() > 16_384 {
        return None;
    }
    let mut bytes = b"agent-router:audit-reference:v2\0".to_vec();
    bytes.extend(value.as_bytes());
    Some(content_digest(&bytes))
}

fn number(value: Option<&Value>) -> Option<u64> {
    value?.as_u64().filter(|n| *n <= MAX_AUDIT_NUMBER)
}

fn typed<T: serde::de::DeserializeOwned>(value: Option<&Value>) -> Option<T> {
    let value = value?;
    if value.as_str()?.len() > 64 {
        return None;
    }
    serde_json::from_value(value.clone()).ok()
}

fn count(value: Option<&Value>) -> Option<u64> {
    value?.as_array().map(|items| items.len() as u64)
}

fn claims(value: Option<&Value>) -> Option<Vec<String>> {
    let items = value?.as_array()?;
    if items.len() > MAX_PROJECTED_ENTRIES {
        return None;
    }
    items.iter().map(|item| claim(Some(item))).collect()
}

fn typed_list<T: serde::de::DeserializeOwned>(value: Option<&Value>) -> Option<Vec<T>> {
    let items = value?.as_array()?;
    if items.len() > MAX_PROJECTED_ENTRIES {
        return None;
    }
    items.iter().map(|item| typed(Some(item))).collect()
}

fn references(value: &Value) -> AuditReferences {
    AuditReferences {
        receipt_sha256: claim(
            value
                .get("receipt_id")
                .or_else(|| value.get("baseline_receipt_id")),
        ),
        context_sha256: claim(value.get("context_hash")),
        catalog_sha256: claim(
            value
                .get("catalog_hash")
                .or_else(|| value.get("catalog_content_sha256")),
        ),
        policy_sha256: claim(value.get("policy_hash")),
        snapshot_sha256: claim(value.get("snapshot_hash")),
        pool_sha256: claim(value.get("pool_hash")),
        registry_sha256: claim(value.get("registry_hash")),
        evidence_sha256: claim(
            value
                .get("evidence_sha256")
                .or_else(|| value.get("provenance_sha256")),
        ),
        definition_sha256: claim(value.get("definition_hash")),
        approval_sha256: claim(value.get("approval_digest")),
        plan_sha256: claim(value.get("plan_id")),
        node_sha256: claim(value.get("node_id")),
        artifact_sha256: claim(value.get("artifact_sha256")),
    }
}

fn version(value: Option<&Value>) -> AuditVersion {
    let mut result = AuditVersion {
        identity_sha256: claim(value),
        ..AuditVersion::default()
    };
    if let Some(text) = value
        .and_then(Value::as_str)
        .filter(|text| text.len() <= 32)
    {
        let parts: Vec<_> = text.split('.').collect();
        if (1..=3).contains(&parts.len())
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.len() <= 4 && p.bytes().all(|b| b.is_ascii_digit()))
        {
            result.major = parts.first().and_then(|p| p.parse().ok());
            result.minor = parts.get(1).and_then(|p| p.parse().ok());
            result.patch = parts.get(2).and_then(|p| p.parse().ok());
        }
    }
    result
}

fn runtime_item(value: &Value) -> AuditRuntimeItem {
    let run = value.get("run").filter(|v| v.is_object()).unwrap_or(value);
    let transport = value
        .get("transport")
        .filter(|v| v.is_object())
        .unwrap_or(value);
    AuditRuntimeItem {
        sequence: number(value.get("sequence")),
        run_sha256: claim(run.get("run_id")),
        event_sha256: claim(value.get("event_hash")),
        state: typed(run.get("state")),
        kind: typed(value.get("kind")),
        transport_kind: typed(value.get("kind")),
        failure: typed(run.get("failure")),
        attempts: number(run.get("attempts")),
        recorded_at_unix_seconds: number(
            value
                .get("recorded_at_unix_seconds")
                .or_else(|| value.get("observed_at_unix_seconds")),
        ),
        termination: typed(transport.get("termination")),
        exit_code: transport
            .get("exit_code")
            .and_then(Value::as_i64)
            .and_then(|v| i32::try_from(v).ok()),
        elapsed_ms: number(transport.get("elapsed_ms")),
        stdout_bytes: number(value.get("stdout_bytes")),
        stderr_bytes: number(value.get("stderr_bytes")),
        stdout_sha256: claim(value.get("stdout_sha256")),
        stderr_sha256: claim(value.get("stderr_sha256")),
        validation: typed(value.get("validation")),
        objective: typed(value.get("objective")),
        requested_model_sha256: claim(value.get("requested_model")),
        requested_effort: typed(value.get("requested_effort")),
        references: references(run),
    }
}

fn project(kind: AuditArtifactKind, value: &Value) -> AuditProjection {
    let data = match kind {
        AuditArtifactKind::EffectiveConfig => {
            AuditProjectionData::EffectiveConfig(AuditConfiguration {
                source_sha256: claims(value.get("sources")).unwrap_or_default(),
                allowed_model_sha256: claims(value.get("allowed_models")),
                allowed_capabilities: typed_list(value.get("allowed_capabilities")),
                allowed_mutations: typed_list(value.get("allowed_mutations")),
                preferred_model_sha256: claim(value.get("preferred_model")),
                budget: AuditBudget {
                    max_cost_microusd: number(value.get("max_cost_microusd")),
                    max_tokens: number(value.get("max_tokens")),
                    max_elapsed_ms: number(value.get("max_elapsed_ms")),
                    max_concurrency: number(value.get("max_concurrency")),
                },
                references: references(value),
            })
        }
        AuditArtifactKind::Decision => {
            let receipt = value
                .get("receipt")
                .filter(|v| v.is_object())
                .unwrap_or(value);
            let selected = receipt.get("selected");
            let candidate = selected.and_then(|v| v.get("candidate"));
            let field = |name| candidate.and_then(|v| v.get(name));
            let abstention = typed(receipt.get("abstention"));
            let verdict = if selected.is_some_and(Value::is_object)
                && receipt.get("abstention").is_none_or(Value::is_null)
            {
                AuditDecisionVerdict::Selected
            } else if selected.is_none_or(Value::is_null) && abstention.is_some() {
                AuditDecisionVerdict::Abstained
            } else {
                AuditDecisionVerdict::Unknown
            };
            AuditProjectionData::Decision(AuditDecision {
                verdict,
                phase: typed(receipt.get("phase")),
                candidate_sha256: claim(field("id")),
                model_sha256: claim(field("model")),
                effort: typed(field("effort")),
                sandbox: typed(field("sandbox")),
                verification: typed(field("verification")),
                required_capabilities: typed_list(field("required_capabilities")),
                required_mutations: typed_list(field("required_mutations")),
                asset_count: count(selected.and_then(|v| v.get("assets"))),
                abstention,
                utility_micros: selected
                    .and_then(|v| v.get("score"))
                    .and_then(|v| v.get("utility_micros"))
                    .and_then(Value::as_i64)
                    .filter(|v| (-MAX_AUDIT_SCORE..=MAX_AUDIT_SCORE).contains(v)),
                estimated_cost_microusd: number(field("estimated_cost_microusd")),
                estimated_tokens: number(field("estimated_tokens")),
                estimated_elapsed_ms: number(field("estimated_elapsed_ms")),
                alternatives: count(receipt.get("alternatives")),
                exclusions: count(receipt.get("exclusions")),
                unavailable: count(receipt.get("unavailable")),
                references: references(receipt),
            })
        }
        AuditArtifactKind::Events => {
            let entries = value
                .as_array()
                .or_else(|| value.get("events").and_then(Value::as_array));
            let (total_entries, entries) = match entries {
                Some(entries) => (
                    entries.len() as u64,
                    entries
                        .iter()
                        .take(MAX_PROJECTED_ENTRIES)
                        .map(runtime_item)
                        .collect(),
                ),
                None => (1, vec![runtime_item(value)]),
            };
            AuditProjectionData::Events(AuditEvents {
                total_entries,
                omitted_entries: total_entries - entries.len() as u64,
                entries,
            })
        }
        AuditArtifactKind::Evidence => {
            let evidence = value
                .get("runtime_evidence")
                .filter(|v| v.is_object())
                .unwrap_or(value);
            let transport = evidence
                .get("transport")
                .filter(|v| v.is_object())
                .unwrap_or(evidence);
            let models = evidence
                .get("executed_models")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let model_sha256 = models
                .iter()
                .take(MAX_PROJECTED_ENTRIES)
                .filter_map(|v| claim(v.get("model")))
                .collect();
            let model_source_sha256 = models
                .iter()
                .take(MAX_PROJECTED_ENTRIES)
                .filter_map(|v| claim(v.get("source_sha256")))
                .collect();
            AuditProjectionData::Evidence(AuditEvidence {
                termination: typed(transport.get("termination")),
                exit_code: transport
                    .get("exit_code")
                    .and_then(Value::as_i64)
                    .and_then(|v| i32::try_from(v).ok()),
                elapsed_ms: number(transport.get("elapsed_ms")),
                transport_success: evidence.get("transport_success").and_then(Value::as_bool),
                stream_complete: evidence.get("stream_complete").and_then(Value::as_bool),
                validation: typed(
                    value
                        .get("validation")
                        .or_else(|| evidence.get("validation")),
                ),
                objective: typed(value.get("objective").or_else(|| evidence.get("objective"))),
                model_sha256,
                model_source_sha256,
                observed_effort: typed(evidence.get("executed_effort")),
                event_count: count(evidence.get("events")),
                references: references(value),
            })
        }
        AuditArtifactKind::Versions => {
            let backend = match value.get("backend").and_then(Value::as_str) {
                Some("deterministic") => AuditBackendKind::Deterministic,
                Some("laya" | "laya-local") => AuditBackendKind::Laya,
                Some("jev" | "jev-sidecar") => AuditBackendKind::Jev,
                _ => AuditBackendKind::Unknown,
            };
            AuditProjectionData::Versions(AuditVersions {
                policy: version(
                    value
                        .get("policy_version")
                        .or_else(|| value.get("policy").and_then(|v| v.get("version"))),
                ),
                backend,
                backend_version: version(value.get("backend_version")),
                producer: version(value.get("producer_version")),
                references: references(value),
            })
        }
        AuditArtifactKind::Catalog => AuditProjectionData::Catalog(AuditCatalog {
            version: version(value.get("version")),
            model_count: count(value.get("models")),
            skill_count: count(value.get("skills")),
            asset_count: count(value.get("assets")),
            references: references(value),
        }),
    };
    AuditProjection {
        provenance: AuditProvenance::UnverifiedInput,
        data,
    }
}

fn validate_projection(kind: AuditArtifactKind, projection: &AuditProjection) -> Result<()> {
    let matches = matches!(
        (kind, &projection.data),
        (
            AuditArtifactKind::EffectiveConfig,
            AuditProjectionData::EffectiveConfig(_)
        ) | (AuditArtifactKind::Catalog, AuditProjectionData::Catalog(_))
            | (
                AuditArtifactKind::Decision,
                AuditProjectionData::Decision(_)
            )
            | (AuditArtifactKind::Events, AuditProjectionData::Events(_))
            | (
                AuditArtifactKind::Evidence,
                AuditProjectionData::Evidence(_)
            )
            | (
                AuditArtifactKind::Versions,
                AuditProjectionData::Versions(_)
            )
    );
    if !matches {
        return Err(DoctorError::Integrity);
    }
    if let AuditProjectionData::Events(events) = &projection.data {
        if events
            .total_entries
            .checked_sub(events.entries.len() as u64)
            != Some(events.omitted_entries)
        {
            return Err(DoctorError::Integrity);
        }
    }
    // DTO string members are digest references only. Enum values have a closed
    // vocabulary through Deserialize; unknown JSON fields cannot enter the DTO.
    fn bounds(value: &Value, field: &str) -> Result<()> {
        match value {
            Value::String(s) if field.ends_with("sha256") && !is_digest(s) => {
                return Err(DoctorError::Integrity);
            }
            Value::Array(items) => {
                if items.len() > MAX_PROJECTED_ENTRIES {
                    return Err(DoctorError::Limit);
                }
                for item in items {
                    bounds(item, field)?;
                }
            }
            Value::Object(fields) => {
                for (field, value) in fields {
                    bounds(value, field)?;
                }
            }
            Value::Number(n) => {
                let valid = if field == "utility_micros" {
                    n.as_i64()
                        .is_some_and(|v| (-MAX_AUDIT_SCORE..=MAX_AUDIT_SCORE).contains(&v))
                } else if field == "exit_code" {
                    n.as_i64().is_some_and(|v| i32::try_from(v).is_ok())
                } else if matches!(field, "major" | "minor" | "patch") {
                    n.as_u64().is_some_and(|v| v <= 9_999)
                } else {
                    n.as_u64().is_some_and(|v| v <= MAX_AUDIT_NUMBER)
                };
                if !valid {
                    return Err(DoctorError::Limit);
                }
            }
            _ => {}
        }
        Ok(())
    }
    bounds(
        &serde_json::to_value(projection).map_err(|_| DoctorError::Schema)?,
        "",
    )
}
