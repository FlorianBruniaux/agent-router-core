use router_runtime::{Runtime, RuntimeLimits};
use router_types::DeepDoctorCode;
use std::fs;

#[test]
fn runtime_diagnoses_its_owned_wal_connection_without_reopening_or_mutating_records() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("runtime");
    let runtime = Runtime::open(&root, RuntimeLimits::default()).unwrap();
    let healthy = runtime.diagnose_storage().unwrap();
    assert_eq!(
        healthy.integrity,
        DeepDoctorCode::DatabaseIntegrityValidated
    );
    assert!(healthy.snapshot_bytes > 100);
    assert!(runtime.events().unwrap().is_empty());
    runtime.verify_integrity().unwrap();

    // A deliberately corrupt fixture commits an orphan only into the live WAL.
    // SQLite integrity and runtime hash-chain checks are different evidence.
    let external = rusqlite::Connection::open(root.join("runtime.sqlite3")).unwrap();
    external.execute_batch("PRAGMA foreign_keys=OFF; INSERT INTO control_requests(run_id,cancel_requested) VALUES('PRIVATE_ORPHAN_FIXTURE',1);").unwrap();
    let before_database = fs::read(root.join("runtime.sqlite3")).unwrap();
    let before_wal = fs::read(root.join("runtime.sqlite3-wal")).unwrap();
    let before_files = fs::read_dir(&root).unwrap().count();
    let report = runtime.diagnose_storage().unwrap();
    assert_eq!(report.integrity, DeepDoctorCode::DatabaseIntegrityFailed);
    assert_ne!(healthy.snapshot_sha256, report.snapshot_sha256);
    assert!(runtime.events().unwrap().is_empty());
    assert_eq!(
        before_database,
        fs::read(root.join("runtime.sqlite3")).unwrap()
    );
    assert_eq!(
        before_wal,
        fs::read(root.join("runtime.sqlite3-wal")).unwrap()
    );
    assert_eq!(before_files, fs::read_dir(&root).unwrap().count());
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("PRIVATE_ORPHAN_FIXTURE"));
    assert!(!json.contains(root.to_str().unwrap()));
}
