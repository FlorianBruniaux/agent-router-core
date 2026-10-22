use router_adapter_api::content_digest;
use router_doctor::{DoctorError, MAX_FILE_BYTES, diagnose};
use router_types::*;
use std::fs;

fn request(root: &std::path::Path, artifacts: Vec<DoctorArtifact>) -> DoctorRequest {
    DoctorRequest {
        schema_version: 1,
        root: root.canonicalize().unwrap().to_str().unwrap().into(),
        artifacts,
        max_snapshot_age_seconds: 100,
    }
}
fn artifact(path: &str, kind: DoctorArtifactKind) -> DoctorArtifact {
    DoctorArtifact {
        id: path.into(),
        relative_path: path.into(),
        kind,
        expected_sha256: None,
        require_private: false,
    }
}
fn check<'a>(report: &'a DoctorReport, name: &str) -> &'a DoctorCheck {
    report
        .checks
        .iter()
        .find(|check| check.subject_sha256 == content_digest(name.as_bytes()))
        .unwrap()
}

#[test]
fn diagnostics_are_read_only_redacted_and_unknown_is_not_pass() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("private-name.json"),
        br#"{"schema_version":1,"prompt":"DO_NOT_EXPORT_THIS"}"#,
    )
    .unwrap();
    let before = fs::read(temp.path().join("private-name.json")).unwrap();
    let request = request(
        temp.path(),
        vec![artifact(
            "private-name.json",
            DoctorArtifactKind::JsonConfiguration,
        )],
    );
    let report = diagnose(&request, 100).unwrap();
    let item = check(&report, "private-name.json");
    assert_eq!(item.configuration, DiagnosticState::Pass);
    assert_eq!(item.runtime, DiagnosticState::Unknown);
    assert_eq!(report.overall, DiagnosticState::Unknown);
    assert!(report.secrets_scan_is_heuristic);
    assert_eq!(
        (
            report.network_requests,
            report.processes_launched,
            report.files_modified
        ),
        (0, 0, 0)
    );
    let output = serde_json::to_string(&report).unwrap();
    for forbidden in [
        "DO_NOT_EXPORT_THIS",
        "private-name.json",
        request.root.as_str(),
    ] {
        assert!(!output.contains(forbidden));
    }
    assert_eq!(
        before,
        fs::read(temp.path().join("private-name.json")).unwrap()
    );
    assert_eq!(report, diagnose(&request, 100).unwrap());
}

#[test]
fn drift_secret_patterns_schema_errors_and_missing_files_are_separate() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("secret.json"),
        br#"{"schema_version":1,"api_key":"PRIVATE_VALUE"}"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("bad.json"),
        br#"{"schema_version":1,"schema_version":2}"#,
    )
    .unwrap();
    fs::write(temp.path().join("drift.txt"), "modified").unwrap();
    let mut drift = artifact("drift.txt", DoctorArtifactKind::ManagedFile);
    drift.expected_sha256 = Some(content_digest(b"original"));
    let report = diagnose(
        &request(
            temp.path(),
            vec![
                artifact("secret.json", DoctorArtifactKind::JsonConfiguration),
                artifact("bad.json", DoctorArtifactKind::JsonConfiguration),
                artifact("missing", DoctorArtifactKind::Hook),
                drift,
            ],
        ),
        10,
    )
    .unwrap();
    assert_eq!(
        check(&report, "secret.json").code,
        DoctorCode::SecretPatternDetected
    );
    assert_eq!(check(&report, "bad.json").code, DoctorCode::SchemaInvalid);
    assert_eq!(check(&report, "missing").code, DoctorCode::FileUnavailable);
    assert_eq!(check(&report, "drift.txt").code, DoctorCode::DriftDetected);
    assert_eq!(report.overall, DiagnosticState::Fail);
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("PRIVATE_VALUE")
    );
}

#[test]
fn limits_and_unsafe_paths_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("large"), vec![b'x'; MAX_FILE_BYTES + 1]).unwrap();
    let report = diagnose(
        &request(
            temp.path(),
            vec![artifact("large", DoctorArtifactKind::ManagedFile)],
        ),
        0,
    )
    .unwrap();
    assert_eq!(check(&report, "large").code, DoctorCode::InputLimit);
    for path in [
        "../escape",
        "/absolute",
        "a/../escape",
        "a/./file",
        "a//file",
        ".",
    ] {
        assert_eq!(
            diagnose(
                &request(
                    temp.path(),
                    vec![artifact(path, DoctorArtifactKind::ManagedFile)]
                ),
                0
            )
            .unwrap_err(),
            DoctorError::Invalid
        );
    }
}

#[cfg(unix)]
#[test]
fn symlink_parents_leaf_and_private_permissions_fail_closed() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret"), "PRIVATE_VALUE").unwrap();
    symlink(outside.path(), temp.path().join("parent")).unwrap();
    symlink(outside.path().join("secret"), temp.path().join("leaf")).unwrap();
    let report = diagnose(
        &request(
            temp.path(),
            vec![
                artifact("parent/secret", DoctorArtifactKind::ManagedFile),
                artifact("leaf", DoctorArtifactKind::ManagedFile),
            ],
        ),
        0,
    )
    .unwrap();
    assert!(
        report
            .checks
            .iter()
            .filter(|c| c.kind == DoctorArtifactKind::ManagedFile)
            .all(|c| c.configuration == DiagnosticState::Fail && c.content_sha256.is_none())
    );
    assert_eq!(
        check(&report, "parent/secret").code,
        DoctorCode::PathRejected
    );
    assert_eq!(check(&report, "leaf").code, DoctorCode::PathRejected);
    fs::write(temp.path().join("auth"), "UNREAD_CREDENTIAL").unwrap();
    fs::set_permissions(temp.path().join("auth"), fs::Permissions::from_mode(0o644)).unwrap();
    let request = request(
        temp.path(),
        vec![artifact("auth", DoctorArtifactKind::AuthMarker)],
    );
    assert_eq!(
        check(&diagnose(&request, 0).unwrap(), "auth").code,
        DoctorCode::PermissionsBroad
    );
    fs::set_permissions(temp.path().join("auth"), fs::Permissions::from_mode(0o600)).unwrap();
    let report = diagnose(&request, 0).unwrap();
    assert_eq!(check(&report, "auth").code, DoctorCode::AuthPresenceOnly);
    assert_eq!(check(&report, "auth").content_sha256, None);
    assert_eq!(check(&report, "auth").runtime, DiagnosticState::Unknown);
}

#[test]
fn hook_plugin_database_lease_and_backend_do_not_claim_runtime() {
    let temp = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("hook", "echo inert"),
        ("plugin", "{}"),
        ("backend", "{\"healthy\":true}"),
        ("sandbox", "{\"enforced\":true}"),
        (
            "lease",
            "{\"pid\":42,\"updated_at_unix_seconds\":1,\"max_age_seconds\":10}",
        ),
    ] {
        fs::write(temp.path().join(name), bytes).unwrap();
    }
    fs::write(
        temp.path().join("database"),
        b"SQLite format 3\0synthetic header only",
    )
    .unwrap();
    let report = diagnose(
        &request(
            temp.path(),
            vec![
                artifact("hook", DoctorArtifactKind::Hook),
                artifact("plugin", DoctorArtifactKind::Plugin),
                artifact("backend", DoctorArtifactKind::BackendStatus),
                artifact("sandbox", DoctorArtifactKind::SandboxEvidence),
                artifact("lease", DoctorArtifactKind::Lease),
                artifact("database", DoctorArtifactKind::Database),
            ],
        ),
        100,
    )
    .unwrap();
    assert_eq!(check(&report, "hook").code, DoctorCode::HookNotInvoked);
    assert_eq!(check(&report, "plugin").code, DoctorCode::PluginNotLoaded);
    assert_eq!(
        check(&report, "backend").code,
        DoctorCode::BackendHealthUnknown
    );
    assert_eq!(
        check(&report, "sandbox").code,
        DoctorCode::SandboxEnforcementUnknown
    );
    assert_eq!(check(&report, "lease").code, DoctorCode::LeaseStale);
    assert_eq!(
        check(&report, "database").code,
        DoctorCode::DatabaseSnapshotRequired
    );
    assert!(
        report
            .checks
            .iter()
            .all(|check| check.runtime == DiagnosticState::Unknown)
    );
}
