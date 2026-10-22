use crate::{
    DoctorError, MAX_ARTIFACTS, MAX_FILE_BYTES, MAX_TOTAL_BYTES, Result,
    files::{ReadRoot, relative},
};
use router_adapter_api::{
    SnapshotValidation, ValidatedHostObservation, content_digest, is_digest, strict_json,
};
use router_catalog::{Catalog, GeneratedCatalog};
use router_retrieval::Bm25Index;
use router_types::*;
use std::{collections::BTreeSet, io::Read};

pub fn diagnose(request: &DoctorRequest, now_unix_seconds: u64) -> Result<DoctorReport> {
    if request.schema_version != 1
        || request.artifacts.len() > MAX_ARTIFACTS
        || request.max_snapshot_age_seconds > 86_400 * 30
    {
        return Err(DoctorError::Invalid);
    }
    let mut ids = BTreeSet::new();
    for artifact in &request.artifacts {
        if artifact.id.is_empty()
            || artifact.id.len() > 256
            || !ids.insert(&artifact.id)
            || !relative(&artifact.relative_path)
            || artifact
                .expected_sha256
                .as_ref()
                .is_some_and(|hash| !is_digest(hash))
        {
            return Err(DoctorError::Invalid);
        }
    }
    let root = ReadRoot::open(&request.root)?;
    let mut checks = Vec::new();
    let mut total = 0;
    for artifact in &request.artifacts {
        let mut check = DoctorCheck {
            subject_sha256: content_digest(artifact.id.as_bytes()),
            kind: artifact.kind,
            configuration: DiagnosticState::Pass,
            runtime: DiagnosticState::Unknown,
            code: DoctorCode::FileValidated,
            content_sha256: None,
        };
        match inspect(
            &root,
            artifact,
            request.max_snapshot_age_seconds,
            now_unix_seconds,
            &mut total,
        ) {
            Ok((state, code, hash)) => {
                check.configuration = state;
                check.code = code;
                check.content_sha256 = hash;
            }
            Err(error) => {
                check.configuration = DiagnosticState::Fail;
                check.code = match error {
                    DoctorError::Path => DoctorCode::PathRejected,
                    DoctorError::Read => DoctorCode::FileUnavailable,
                    DoctorError::Limit => DoctorCode::InputLimit,
                    _ => DoctorCode::SchemaInvalid,
                };
            }
        }
        checks.push(check);
    }
    for kind in [
        DoctorArtifactKind::JsonConfiguration,
        DoctorArtifactKind::Catalog,
        DoctorArtifactKind::HostSnapshot,
        DoctorArtifactKind::RetrievalIndex,
        DoctorArtifactKind::Database,
        DoctorArtifactKind::Hook,
        DoctorArtifactKind::Plugin,
        DoctorArtifactKind::ManagedFile,
        DoctorArtifactKind::AuthMarker,
        DoctorArtifactKind::Executable,
        DoctorArtifactKind::Lease,
        DoctorArtifactKind::BackendStatus,
        DoctorArtifactKind::SandboxEvidence,
    ] {
        if !checks.iter().any(|check| check.kind == kind) {
            checks.push(DoctorCheck {
                subject_sha256: content_digest(format!("unconfigured:{kind:?}").as_bytes()),
                kind,
                configuration: DiagnosticState::Unknown,
                runtime: DiagnosticState::Unknown,
                code: DoctorCode::NotConfigured,
                content_sha256: None,
            });
        }
    }
    checks.sort_by(|a, b| a.subject_sha256.cmp(&b.subject_sha256));
    let overall = if checks
        .iter()
        .any(|check| check.configuration == DiagnosticState::Fail)
    {
        DiagnosticState::Fail
    } else if checks
        .iter()
        .any(|check| check.configuration == DiagnosticState::Warning)
    {
        DiagnosticState::Warning
    } else {
        DiagnosticState::Unknown
    };
    Ok(DoctorReport {
        schema_version: 1,
        observed_at_unix_seconds: now_unix_seconds,
        checks,
        overall,
        secrets_scan_is_heuristic: true,
        network_requests: 0,
        processes_launched: 0,
        files_modified: 0,
    })
}

fn inspect(
    root: &ReadRoot,
    artifact: &DoctorArtifact,
    max_age: u64,
    now: u64,
    total: &mut usize,
) -> Result<(DiagnosticState, DoctorCode, Option<String>)> {
    if artifact.kind == DoctorArtifactKind::Database {
        return inspect_database(root, artifact);
    }
    let file = root.file(&artifact.relative_path)?;
    let metadata = file.metadata().map_err(|_| DoctorError::Read)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if (artifact.require_private || artifact.kind == DoctorArtifactKind::AuthMarker)
            && mode & 0o077 != 0
        {
            return Ok((DiagnosticState::Fail, DoctorCode::PermissionsBroad, None));
        }
        if artifact.kind == DoctorArtifactKind::Executable && mode & 0o111 == 0 {
            return Ok((DiagnosticState::Fail, DoctorCode::FileUnavailable, None));
        }
    }
    if matches!(
        artifact.kind,
        DoctorArtifactKind::AuthMarker | DoctorArtifactKind::Executable
    ) {
        return Ok((
            DiagnosticState::Pass,
            if artifact.kind == DoctorArtifactKind::AuthMarker {
                DoctorCode::AuthPresenceOnly
            } else {
                DoctorCode::ExecutablePresenceOnly
            },
            None,
        ));
    }
    let remaining = MAX_TOTAL_BYTES.saturating_sub(*total).min(MAX_FILE_BYTES);
    if remaining == 0 || metadata.len() > remaining as u64 {
        return Err(DoctorError::Limit);
    }
    let mut bytes = Vec::new();
    file.take(remaining as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| DoctorError::Read)?;
    *total = total.checked_add(bytes.len()).ok_or(DoctorError::Limit)?;
    if bytes.len() > MAX_FILE_BYTES || *total > MAX_TOTAL_BYTES {
        return Err(DoctorError::Limit);
    }
    let hash = content_digest(&bytes);
    if artifact
        .expected_sha256
        .as_ref()
        .is_some_and(|expected| expected != &hash)
    {
        return Ok((DiagnosticState::Fail, DoctorCode::DriftDetected, Some(hash)));
    }
    let secret_pattern = contains_secret_pattern(&bytes);
    let code = match artifact.kind {
        DoctorArtifactKind::Catalog => {
            let value = strict_json(&bytes).map_err(|_| DoctorError::Schema)?;
            match value.get("schema_version").and_then(|value| value.as_u64()) {
                Some(1) => {
                    Catalog::from_json(&bytes).map_err(|_| DoctorError::Schema)?;
                }
                Some(2) => {
                    GeneratedCatalog::from_json(
                        &bytes,
                        SnapshotValidation {
                            now_unix_seconds: now,
                            max_age_seconds: max_age,
                        },
                    )
                    .map_err(|_| DoctorError::Schema)?;
                }
                _ => return Err(DoctorError::Schema),
            }
            DoctorCode::FileValidated
        }
        DoctorArtifactKind::HostSnapshot => {
            let snapshot = ValidatedHostObservation::from_json(
                &bytes,
                SnapshotValidation {
                    now_unix_seconds: now,
                    max_age_seconds: max_age,
                },
            )
            .map_err(|_| DoctorError::Schema)?;
            if snapshot.host().supported_models.iter().any(|model| {
                snapshot
                    .host()
                    .supported_efforts
                    .get(model)
                    .is_none_or(|efforts| efforts.is_empty())
            }) {
                DoctorCode::HostEffortUnknown
            } else {
                DoctorCode::HostObserved
            }
        }
        DoctorArtifactKind::RetrievalIndex => {
            strict_json(&bytes).map_err(|_| DoctorError::Schema)?;
            Bm25Index::from_json(&bytes).map_err(|_| DoctorError::Schema)?;
            DoctorCode::RetrievalValidated
        }
        DoctorArtifactKind::Database => {
            return Err(DoctorError::Invalid);
        }
        DoctorArtifactKind::Hook => DoctorCode::HookNotInvoked,
        DoctorArtifactKind::ManagedFile => DoctorCode::ManagedFilePresent,
        DoctorArtifactKind::Plugin => {
            json_object(&bytes)?;
            DoctorCode::PluginNotLoaded
        }
        DoctorArtifactKind::JsonConfiguration => {
            let value = json_object(&bytes)?;
            if value.get("schema_version").and_then(|v| v.as_u64()) != Some(1) {
                return Err(DoctorError::Schema);
            }
            DoctorCode::FileValidated
        }
        DoctorArtifactKind::Lease => {
            let value = json_object(&bytes)?;
            let updated = value
                .get("updated_at_unix_seconds")
                .and_then(|v| v.as_u64())
                .ok_or(DoctorError::Schema)?;
            let age = value
                .get("max_age_seconds")
                .and_then(|v| v.as_u64())
                .ok_or(DoctorError::Schema)?;
            if value
                .get("pid")
                .and_then(|v| v.as_u64())
                .is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
                || updated > now
                || age > 86_400 * 30
            {
                return Err(DoctorError::Schema);
            }
            if now - updated > age {
                return Ok((DiagnosticState::Warning, DoctorCode::LeaseStale, Some(hash)));
            }
            DoctorCode::LeaseLivenessUnknown
        }
        DoctorArtifactKind::BackendStatus => {
            json_object(&bytes)?;
            DoctorCode::BackendHealthUnknown
        }
        DoctorArtifactKind::SandboxEvidence => {
            json_object(&bytes)?;
            DoctorCode::SandboxEnforcementUnknown
        }
        DoctorArtifactKind::AuthMarker | DoctorArtifactKind::Executable => {
            return Err(DoctorError::Invalid);
        }
    };
    if secret_pattern {
        return Ok((
            DiagnosticState::Warning,
            DoctorCode::SecretPatternDetected,
            Some(hash),
        ));
    }
    Ok((DiagnosticState::Pass, code, Some(hash)))
}

pub(crate) fn inspect_database(
    root: &ReadRoot,
    artifact: &DoctorArtifact,
) -> Result<(DiagnosticState, DoctorCode, Option<String>)> {
    let metadata = root.database_metadata(&artifact.relative_path)?;
    if artifact.require_private && !metadata.private {
        return Ok((DiagnosticState::Fail, DoctorCode::PermissionsBroad, None));
    }
    if metadata.bytes > MAX_FILE_BYTES as u64 {
        return Err(DoctorError::Limit);
    }
    // No content, expected digest or secret scan is claimed from metadata.
    Ok((
        DiagnosticState::Unknown,
        DoctorCode::DatabaseSnapshotRequired,
        None,
    ))
}

fn json_object(bytes: &[u8]) -> Result<serde_json::Value> {
    let value = strict_json(bytes).map_err(|_| DoctorError::Schema)?;
    if !value.is_object() {
        return Err(DoctorError::Schema);
    }
    Ok(value)
}

pub(crate) fn contains_secret_pattern(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    [
        "-----begin private key",
        "-----begin rsa private key",
        "sk-proj-",
        "sk-ant-",
        "ghp_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
    ]
    .iter()
    .any(|pattern| text.contains(pattern))
        || strict_json(bytes)
            .ok()
            .is_some_and(|value| sensitive_keys(&value))
}

fn sensitive_keys(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(fields) => fields.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase().replace(['_', '-'], "");
            ([
                "apikey",
                "accesstoken",
                "refreshtoken",
                "password",
                "clientsecret",
                "authorization",
                "privatekey",
            ]
            .contains(&key.as_str())
                && value.as_str().is_some_and(|value| !value.is_empty()))
                || sensitive_keys(value)
        }),
        serde_json::Value::Array(items) => items.iter().any(sensitive_keys),
        _ => false,
    }
}
