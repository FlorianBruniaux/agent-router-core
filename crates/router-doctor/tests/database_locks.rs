#![cfg(unix)]

use router_doctor::{DoctorError, diagnose, diagnose_deep};
use router_types::{
    DeepDoctorCode, DeepDoctorRequest, DiagnosticState, DoctorArtifact, DoctorArtifactKind,
    DoctorCode, DoctorRequest, DoctorSchema, DoctorSchemaBinding,
};
use rusqlite::Connection;
use std::{fs, path::Path, process::Command};

const PROBE_PATH: &str = "ROUTER_DOCTOR_TEST_LOCK_PATH";

#[test]
fn lock_probe_child() {
    let Some(path) = std::env::var_os(PROBE_PATH) else {
        return;
    };
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let locked =
        match rustix::fs::fcntl_lock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => false,
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::ACCESS) => true,
            Err(error) => panic!("unexpected lock probe error: {error}"),
        };
    println!("DOCTOR_LOCK_PROBE={locked}");
}

fn probe_locked(path: &Path) -> bool {
    let output = Command::new(std::env::current_exe().unwrap())
        // Sequential libtest prefixes uncaptured stdout on the same line.
        // Keep the single child test's marker framing independent of the parent.
        .args([
            "--exact",
            "lock_probe_child",
            "--nocapture",
            "--test-threads=2",
        ])
        .env(PROBE_PATH, path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "lock probe failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    if stdout.lines().any(|line| line == "DOCTOR_LOCK_PROBE=true") {
        true
    } else {
        assert!(stdout.lines().any(|line| line == "DOCTOR_LOCK_PROBE=false"));
        false
    }
}

fn assert_locked(path: &Path, expected: bool) {
    assert_eq!(probe_locked(path), expected);
}

fn request(root: &Path) -> DoctorRequest {
    DoctorRequest {
        schema_version: 1,
        root: root.to_str().unwrap().into(),
        artifacts: ["source.db", "source.db-wal", "source.db-shm"]
            .into_iter()
            .map(|name| DoctorArtifact {
                id: name.into(),
                relative_path: name.into(),
                kind: DoctorArtifactKind::Database,
                expected_sha256: None,
                require_private: false,
            })
            .collect(),
        max_snapshot_age_seconds: 60,
    }
}

fn preserve_locks(deep: bool) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let path = root.join("source.db");
    let shm = root.join("source.db-shm");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE proof(id); BEGIN IMMEDIATE;")
        .unwrap();
    assert_locked(&path, true);
    assert_locked(&shm, true);
    // SQLite coordinates its own descriptor lifetime. Metadata does not open
    // the inode. Neither control should release this process's POSIX locks.
    let other = Connection::open(&path).unwrap();
    let _: u64 = other
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
        .unwrap();
    drop(other);
    fs::symlink_metadata(&path).unwrap();
    assert_locked(&path, true);
    assert_locked(&shm, true);
    let request = request(&root);
    // A schema binding must not change a Database into ManagedFile and reopen
    // it through the ordinary byte reader before the database gate.
    assert_eq!(
        diagnose_deep(
            &DeepDoctorRequest {
                schema_version: 1,
                base: request.clone(),
                schemas: vec![DoctorSchemaBinding {
                    artifact_id: "source.db".into(),
                    schema: DoctorSchema::NormalizedTask,
                }],
                retrieval_bindings: vec![],
            },
            100,
        ),
        Err(DoctorError::Invalid)
    );
    assert_locked(&path, true);
    assert_locked(&shm, true);
    if deep {
        diagnose_deep(
            &DeepDoctorRequest {
                schema_version: 1,
                base: request,
                schemas: vec![],
                retrieval_bindings: vec![],
            },
            100,
        )
        .unwrap();
    } else {
        diagnose(&request, 100).unwrap();
    }
    assert!(!connection.is_autocommit());
    let main_locked = probe_locked(&path);
    let shm_locked = probe_locked(&shm);
    connection.execute_batch("ROLLBACK").unwrap();
    drop(connection);
    assert_locked(&path, false);
    assert!(
        main_locked && shm_locked,
        "after doctor: main={main_locked}, shm={shm_locked}"
    );
}

#[test]
fn passive_database_checks_preserve_same_process_sqlite_locks() {
    preserve_locks(false);
}

#[test]
fn deep_database_checks_preserve_same_process_sqlite_locks() {
    preserve_locks(true);
}

fn single_request(root: &Path) -> DoctorRequest {
    let mut request = request(root);
    request.artifacts.truncate(1);
    request
}

#[test]
fn database_metadata_never_certifies_content_hash_header_or_secret_scan() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::write(
        root.join("source.db"),
        b"not SQLite: PRIVATE_DATABASE_CONTENT",
    )
    .unwrap();
    let mut request = single_request(&root);
    request.artifacts[0].expected_sha256 = Some("a".repeat(64));
    let report = diagnose(&request, 100).unwrap();
    let check = report
        .checks
        .iter()
        .find(|c| c.kind == DoctorArtifactKind::Database)
        .unwrap();
    assert_eq!(check.code, DoctorCode::DatabaseSnapshotRequired);
    assert_eq!(check.configuration, DiagnosticState::Unknown);
    assert_eq!(check.content_sha256, None);
    assert_eq!(report.files_modified, 0);
    let deep = diagnose_deep(
        &DeepDoctorRequest {
            schema_version: 1,
            base: request,
            schemas: vec![],
            retrieval_bindings: vec![],
        },
        100,
    )
    .unwrap();
    assert_eq!(deep.database_queries, 0);
    assert_eq!(
        deep.checks[0].code,
        DeepDoctorCode::DatabaseSnapshotRequired
    );
    assert_eq!(deep.checks[0].content_sha256, None);
    let output = serde_json::to_string(&deep).unwrap();
    assert!(!output.contains("PRIVATE_DATABASE_CONTENT"));
    assert!(!output.contains("source.db"));
    assert!(!output.contains(root.to_str().unwrap()));
}

#[test]
fn database_metadata_preserves_path_permissions_and_size_refusals() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let path = root.join("source.db");
    let mut request = single_request(&root);
    let check = |request: &DoctorRequest| {
        diagnose(request, 100)
            .unwrap()
            .checks
            .into_iter()
            .find(|c| c.kind == DoctorArtifactKind::Database)
            .unwrap()
    };
    assert_eq!(check(&request).code, DoctorCode::FileUnavailable);
    assert!(!path.exists());
    fs::write(root.join("other"), b"PRIVATE_OUTSIDE").unwrap();
    symlink(root.join("other"), &path).unwrap();
    assert_eq!(check(&request).code, DoctorCode::PathRejected);
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert_eq!(check(&request).code, DoctorCode::PathRejected);
    fs::remove_dir(&path).unwrap();
    assert!(
        Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(check(&request).code, DoctorCode::PathRejected);
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"private").unwrap();
    request.artifacts[0].require_private = true;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(check(&request).code, DoctorCode::PermissionsBroad);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(check(&request).code, DoctorCode::DatabaseSnapshotRequired);
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(router_doctor::MAX_FILE_BYTES as u64 + 1)
        .unwrap();
    assert_eq!(check(&request).code, DoctorCode::InputLimit);
    request.artifacts[0].relative_path = "../source.db".into();
    assert_eq!(diagnose(&request, 100), Err(DoctorError::Invalid));
    symlink(&root, root.join("linked-parent")).unwrap();
    request.artifacts[0].relative_path = "linked-parent/source.db".into();
    assert_eq!(check(&request).configuration, DiagnosticState::Fail);
}
