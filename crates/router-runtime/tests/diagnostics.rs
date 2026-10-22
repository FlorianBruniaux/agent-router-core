use router_doctor::DoctorError;
use router_runtime::{
    OwnerLockState, Runtime, RuntimeLimits, RuntimeSchemaState, diagnose_runtime_storage,
};
use router_types::{DiagnosticState, OutputRetentionPolicy, RunState, RunSummary};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().join("runtime");
        drop(Runtime::open(&root, RuntimeLimits::default()).unwrap());
        Self { _temp: temp, root }
    }
    fn db(&self) -> Connection {
        Connection::open(self.root.join("runtime.sqlite3")).unwrap()
    }
}
fn run(db: &Connection) {
    let summary = RunSummary {
        run_id: "PRIVATE_RUN".into(),
        definition_hash: "a".repeat(64),
        approval_digest: "b".repeat(64),
        receipt_id: "receipt".into(),
        plan_id: "plan".into(),
        node_id: "node".into(),
        state: RunState::Running,
        attempts: 1,
        failure: None,
        worktree: None,
        artifact_sha256: None,
        output_retention: OutputRetentionPolicy::Disabled,
        workflow: None,
        artifact_contract_sha256: None,
    };
    db.execute(
        "INSERT INTO runs VALUES(?1,'plan','node',?2)",
        params![summary.run_id, serde_json::to_string(&summary).unwrap()],
    )
    .unwrap();
}
fn digest(domain: &str, value: &impl serde::Serialize) -> String {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(serde_json::to_vec(value).unwrap());
    hex::encode(hash.finalize())
}
fn pending_lease(root: &Path, db: &Connection) -> PathBuf {
    let name = format!(
        "{}.lease",
        digest("runtime-lease-v1", &("PRIVATE_RUN", 1u32))
    );
    let path = root.join("leases").join(&name);
    fs::write(&path, b"router-runtime-lease-v1:pending\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let m = fs::metadata(&path).unwrap();
    let record = serde_json::json!({"name":name,"identity":{"device":m.dev(),"inode":m.ino()}});
    db.execute(
        "INSERT INTO attempt_leases VALUES('PRIVATE_RUN',1,?1,0,NULL)",
        [record.to_string()],
    )
    .unwrap();
    path
}

#[test]
fn cold_and_owned_runtime_can_be_inspected_without_taking_ownership() {
    let f = Fixture::new();
    let cold = diagnose_runtime_storage(&f.root, 100).unwrap();
    assert_eq!(cold.overall, DiagnosticState::Pass);
    assert_eq!(cold.owner_lock, OwnerLockState::Available);
    assert_eq!(cold.schema_layout, RuntimeSchemaState::RecognizedReadLayout);
    assert_eq!(cold.database.unwrap().database_queries, 69);
    let runtime = Runtime::open(&f.root, RuntimeLimits::default()).unwrap();
    let live = diagnose_runtime_storage(&f.root, 101).unwrap();
    assert_eq!(live.owner_lock, OwnerLockState::Busy);
    assert_eq!(live.overall, DiagnosticState::Pass);
    assert_eq!(live.journal_authenticity, DiagnosticState::Unknown);
    assert_eq!(live.process_liveness, DiagnosticState::Unknown);
    assert_eq!(live.shared_admission_accounting, DiagnosticState::Unknown);
    assert_eq!(live.cleanup_authority, DiagnosticState::Unknown);
    assert!(!live.database_and_leases_atomic);
    runtime.verify_integrity().unwrap();
}

#[test]
fn committed_wal_reservations_and_pending_lease_are_reported_without_recovery() {
    let f = Fixture::new();
    let db = f.db();
    db.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    run(&db);
    let lease = pending_lease(&f.root, &db);
    db.execute_batch("INSERT INTO writer_locks VALUES('PRIVATE_RUN','PRIVATE_WORKSPACE','PRIVATE_SCOPE'); INSERT INTO cleanup_blocks VALUES('PRIVATE_RUN');").unwrap();
    let database = fs::read(f.root.join("runtime.sqlite3")).unwrap();
    let wal = fs::read(f.root.join("runtime.sqlite3-wal")).unwrap();
    let report = diagnose_runtime_storage(&f.root, 101).unwrap();
    assert_eq!(report.overall, DiagnosticState::Warning);
    let counts = report.counts.as_ref().unwrap();
    assert_eq!(
        (
            counts.runs,
            counts.writer_reservations,
            counts.cleanup_blocks,
            counts.recorded_resolved_leases
        ),
        (1, 1, 1, 0)
    );
    assert_eq!(report.leases.as_ref().unwrap().pending, 1);
    assert_eq!(
        fs::read(&lease).unwrap(),
        b"router-runtime-lease-v1:pending\n"
    );
    assert_eq!(fs::read(f.root.join("runtime.sqlite3")).unwrap(), database);
    assert_eq!(fs::read(f.root.join("runtime.sqlite3-wal")).unwrap(), wal);
    let retained: RunSummary = serde_json::from_str(
        &db.query_row("SELECT summary FROM runs", [], |r| r.get::<_, String>(0))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(retained.state, RunState::Running);
    let json = serde_json::to_string(&report).unwrap();
    for private in [
        "PRIVATE_RUN",
        "PRIVATE_WORKSPACE",
        "PRIVATE_SCOPE",
        f.root.to_str().unwrap(),
    ] {
        assert!(!json.contains(private));
    }
}

#[test]
fn old_future_and_fake_current_schemas_never_migrate() {
    for (version, expected) in [
        (5, RuntimeSchemaState::MigrationRequired),
        (8, RuntimeSchemaState::MigrationRequired),
        (10, RuntimeSchemaState::FutureVersion),
        (9, RuntimeSchemaState::InvalidLayout),
    ] {
        let f = Fixture::new();
        let db = f.db();
        db.pragma_update(None, "user_version", version).unwrap();
        if version == 8 {
            db.execute_batch("DROP TABLE admission_intents; DROP TABLE admission_binding;")
                .unwrap();
        }
        if version == 9 {
            db.execute_batch("DROP TABLE preparation_cycles;").unwrap();
        }
        let before = db
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| {
                r.get::<_, u64>(0)
            })
            .unwrap();
        let report = diagnose_runtime_storage(&f.root, 100).unwrap();
        assert_eq!(report.schema_layout, expected);
        assert!(report.counts.is_none());
        assert!(report.leases.is_none());
        assert_eq!(
            db.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                .unwrap(),
            version
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            before
        );
    }
}

#[test]
fn broken_chain_and_foreign_keys_fail_separately_without_echoing_data() {
    let f = Fixture::new();
    let db = f.db();
    run(&db);
    db.execute("INSERT INTO events VALUES(1,'PRIVATE_RUN','PRIVATE_KIND','\"running\"','PRIVATE_DETAIL','','bad')",[]).unwrap();
    let report = diagnose_runtime_storage(&f.root, 100).unwrap();
    assert_eq!(report.overall, DiagnosticState::Fail);
    assert_eq!(report.journal_integrity, DiagnosticState::Fail);
    assert_eq!(
        report.database.as_ref().unwrap().integrity,
        router_types::DeepDoctorCode::DatabaseIntegrityValidated
    );
    assert!(!serde_json::to_string(&report).unwrap().contains("PRIVATE_"));
    db.execute_batch(
        "PRAGMA foreign_keys=OFF; INSERT INTO cleanup_blocks VALUES('MISSING_PARENT');",
    )
    .unwrap();
    assert_eq!(
        diagnose_runtime_storage(&f.root, 100)
            .unwrap()
            .database
            .unwrap()
            .integrity,
        router_types::DeepDoctorCode::DatabaseIntegrityFailed
    );
}

#[test]
fn missing_paths_are_not_created_and_links_or_broad_modes_are_rejected() {
    let f = Fixture::new();
    let absent = f.root.join("absent");
    assert!(diagnose_runtime_storage(&absent, 0).is_err());
    assert!(!absent.exists());
    let alias = f.root.with_file_name("alias");
    symlink(&f.root, &alias).unwrap();
    assert!(matches!(
        diagnose_runtime_storage(&alias, 0),
        Err(DoctorError::Path)
    ));
    let db = f.root.join("runtime.sqlite3");
    fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        diagnose_runtime_storage(&f.root, 0),
        Err(DoctorError::Path)
    ));
    fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&db, f.root.join("alias.sqlite3")).unwrap();
    assert!(matches!(
        diagnose_runtime_storage(&f.root, 0),
        Err(DoctorError::Path)
    ));
}

#[test]
fn sidecar_symlinks_and_fifo_are_refused_without_blocking() {
    for fifo in [false, true] {
        let f = Fixture::new();
        let path = f.root.join("runtime.sqlite3-wal");
        if fifo {
            nix::unistd::mkfifo(
                &path,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )
            .unwrap();
        } else {
            symlink(f.root.join("runtime.sqlite3"), &path).unwrap();
        }
        assert!(matches!(
            diagnose_runtime_storage(&f.root, 0),
            Err(DoctorError::Path)
        ));
    }
}

#[test]
fn missing_and_held_lease_observations_do_not_resolve_cleanup() {
    let f = Fixture::new();
    let db = f.db();
    run(&db);
    let path = pending_lease(&f.root, &db);
    let file = fs::File::open(&path).unwrap();
    let _lock = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock).unwrap();
    assert_eq!(
        diagnose_runtime_storage(&f.root, 100)
            .unwrap()
            .leases
            .unwrap()
            .held,
        1
    );
    fs::remove_file(&path).unwrap();
    assert_eq!(
        diagnose_runtime_storage(&f.root, 100)
            .unwrap()
            .leases
            .unwrap()
            .missing,
        1
    );
    assert_eq!(
        db.query_row("SELECT resolved FROM attempt_leases", [], |r| r
            .get::<_, u32>(0))
            .unwrap(),
        0
    );
}

#[test]
fn many_small_rows_are_inspected_and_snapshot_size_is_the_bound() {
    let f = Fixture::new();
    let db = f.db();
    db.execute_batch("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<4097) INSERT INTO runs SELECT CAST(i AS TEXT),'p','n','{}' FROM n;").unwrap();
    let report = diagnose_runtime_storage(&f.root, 100).unwrap();
    assert_eq!(report.counts.unwrap().runs, 4097);
    // Rows under the per-field cap can still exceed the 4 MiB snapshot cap.
    db.execute_batch("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<100) INSERT INTO runs SELECT 'big'||i,'p','n',zeroblob(60000) FROM n;").unwrap();
    let report = serde_json::to_value(diagnose_runtime_storage(&f.root, 100).unwrap()).unwrap();
    assert_eq!(report["overall"], "unknown");
    assert_eq!(
        report["partial_reason"],
        "database_exceeds_inspection_limit"
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM runs", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        4197
    );
}

#[test]
fn inspecting_does_not_release_same_process_sqlite_writer_locks() {
    let f = Fixture::new();
    let db = f.db();
    run(&db);
    db.execute_batch("BEGIN IMMEDIATE; INSERT INTO control_requests VALUES('PRIVATE_RUN',1);")
        .unwrap();
    let report = diagnose_runtime_storage(&f.root, 100).unwrap();
    assert_eq!(report.counts.unwrap().events, 0);
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "sqlite_writer_child", "--nocapture"])
        .env("AR_DOCTOR_WRITER_ROOT", &f.root)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    db.execute_batch("ROLLBACK").unwrap();
    router_runtime::request_cancel(&f.root, "PRIVATE_RUN").unwrap();
    let after = diagnose_runtime_storage(&f.root, 101).unwrap();
    assert_eq!(after.counts.unwrap().events, 1);
    assert_eq!(after.journal_integrity, DiagnosticState::Pass);
}
#[test]
fn sqlite_writer_child() {
    let Some(root) = std::env::var_os("AR_DOCTOR_WRITER_ROOT") else {
        return;
    };
    let db = Connection::open(Path::new(&root).join("runtime.sqlite3")).unwrap();
    db.busy_timeout(std::time::Duration::ZERO).unwrap();
    let error = db
        .execute(
            "INSERT OR REPLACE INTO control_requests VALUES('PRIVATE_RUN',1)",
            [],
        )
        .unwrap_err();
    assert!(
        matches!(error,rusqlite::Error::SqliteFailure(e,_) if e.code==rusqlite::ErrorCode::DatabaseBusy)
    );
}

#[test]
fn lease_markers_and_invalid_records_never_become_cleanup_authority() {
    let f = Fixture::new();
    let db = f.db();
    run(&db);
    let path = pending_lease(&f.root, &db);
    for (bytes, expected) in [
        (b"router-runtime-lease-v1:group-clean\n".as_slice(), true),
        (
            b"router-runtime-lease-v1:namespace-clean\n".as_slice(),
            true,
        ),
        (b"router-runtime-lease-v1:recovered\n".as_slice(), true),
        (b"forged-clean\n".as_slice(), false),
    ] {
        fs::write(&path, bytes).unwrap();
        let report = diagnose_runtime_storage(&f.root, 100).unwrap();
        assert_eq!(report.cleanup_authority, DiagnosticState::Unknown);
        let leases = report.leases.unwrap();
        assert_eq!(leases.cleanup_marked, u64::from(expected));
        assert_eq!(leases.ambiguous, u64::from(!expected));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(
            db.query_row("SELECT resolved FROM attempt_leases", [], |r| r
                .get::<_, u32>(0))
                .unwrap(),
            0
        );
    }
    db.execute(
        "UPDATE attempt_leases SET record=?1",
        ["{\"name\":\"../../PRIVATE\",\"identity\":{\"device\":0,\"inode\":0}}"],
    )
    .unwrap();
    assert_eq!(
        diagnose_runtime_storage(&f.root, 100)
            .unwrap()
            .leases
            .unwrap()
            .ambiguous,
        1
    );
}

#[test]
fn oversized_fields_and_source_files_are_bounded() {
    let f = Fixture::new();
    let db = f.db();
    run(&db);
    db.execute("UPDATE runs SET summary=?1", ["x".repeat(65537)])
        .unwrap();
    assert!(matches!(
        diagnose_runtime_storage(&f.root, 100),
        Err(DoctorError::Limit)
    ));
    drop(db);
    let f = Fixture::new();
    let file = fs::OpenOptions::new()
        .write(true)
        .open(f.root.join("runtime.sqlite3"))
        .unwrap();
    file.set_len((router_doctor::MAX_FILE_BYTES + 1) as u64)
        .unwrap();
    let report = serde_json::to_value(diagnose_runtime_storage(&f.root, 100).unwrap()).unwrap();
    assert_eq!(report["overall"], "unknown");
    assert_eq!(
        report["partial_reason"],
        "database_exceeds_inspection_limit"
    );
}

#[test]
fn snapshot_over_the_cap_through_the_wal_is_partial_while_the_main_file_is_small() {
    let f = Fixture::new();
    let db = f.db();
    let mode: String = db
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    // Keep growth in the WAL: no automatic checkpoint while `db` is open.
    db.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    db.execute_batch("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<100) INSERT INTO runs SELECT 'big'||i,'p','n',zeroblob(60000) FROM n;").unwrap();
    let main = fs::metadata(f.root.join("runtime.sqlite3")).unwrap().len();
    let wal = fs::metadata(f.root.join("runtime.sqlite3-wal"))
        .unwrap()
        .len();
    let cap = router_doctor::MAX_FILE_BYTES as u64;
    assert!(main < cap && main + wal > cap, "{main} {wal}");
    assert!(wal < router_doctor::MAX_TOTAL_BYTES as u64);
    let report = serde_json::to_value(diagnose_runtime_storage(&f.root, 5).unwrap()).unwrap();
    assert_eq!(report["overall"], "unknown");
    assert_eq!(
        report["partial_reason"],
        "database_exceeds_inspection_limit"
    );
    assert_eq!(report["database"], serde_json::Value::Null);
    assert_eq!(report["schema_version"], 2);
}

#[test]
fn oversized_main_file_that_is_a_link_or_broad_is_a_path_error_not_partial() {
    let large = |f: &Fixture| {
        fs::OpenOptions::new()
            .write(true)
            .open(f.root.join("runtime.sqlite3"))
            .unwrap()
            .set_len((router_doctor::MAX_FILE_BYTES + 1) as u64)
            .unwrap();
    };
    let f = Fixture::new();
    large(&f);
    let db = f.root.join("runtime.sqlite3");
    fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        diagnose_runtime_storage(&f.root, 0),
        Err(DoctorError::Path)
    ));
    fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&db, f.root.join("alias.sqlite3")).unwrap();
    assert!(matches!(
        diagnose_runtime_storage(&f.root, 0),
        Err(DoctorError::Path)
    ));
    let f = Fixture::new();
    let target = f.root.join("target.sqlite3");
    fs::rename(f.root.join("runtime.sqlite3"), &target).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&target)
        .unwrap()
        .set_len((router_doctor::MAX_FILE_BYTES + 1) as u64)
        .unwrap();
    symlink(&target, f.root.join("runtime.sqlite3")).unwrap();
    assert!(matches!(
        diagnose_runtime_storage(&f.root, 0),
        Err(DoctorError::Path)
    ));
}

#[test]
fn database_over_the_inspection_cap_gives_a_partial_unknown_report() {
    let f = Fixture::new();
    let db = f.db();
    db.execute_batch("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<100) INSERT INTO runs SELECT 'big'||i,'p','n',zeroblob(60000) FROM n;").unwrap();
    let size = fs::metadata(f.root.join("runtime.sqlite3")).unwrap().len();
    assert!(size > router_doctor::MAX_FILE_BYTES as u64, "{size}");
    // Not a copy of a cap-sized file: a much larger database is partial too.
    let report = serde_json::to_value(diagnose_runtime_storage(&f.root, 7).unwrap()).unwrap();
    assert_eq!(report["overall"], "unknown");
    assert_eq!(
        report["partial_reason"],
        "database_exceeds_inspection_limit"
    );
    assert_eq!(report["schema_layout"], "not_inspected");
    assert_eq!(report["database"], serde_json::Value::Null);
    assert_eq!(report["counts"], serde_json::Value::Null);
    assert_eq!(report["journal_integrity"], "unknown");
    assert_eq!(report["observed_at_unix_seconds"], 7);
    // The owner lock does not depend on the snapshot and is still reported.
    assert_eq!(report["owner_lock"], "available");
    // Hostile-input limits stay errors: a small database with one huge cell.
    let f = Fixture::new();
    let db = f.db();
    run(&db);
    db.execute("UPDATE runs SET summary=?1", ["x".repeat(65537)])
        .unwrap();
    assert!(matches!(
        diagnose_runtime_storage(&f.root, 100),
        Err(DoctorError::Limit)
    ));
}
