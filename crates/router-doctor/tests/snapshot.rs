use router_doctor::{DoctorError, diagnose_database_snapshot};
use router_types::DeepDoctorCode;
use rusqlite::{Connection, TransactionBehavior};
use std::fs;

#[test]
fn committed_wal_is_inspected_without_checkpoint_or_exposing_contents() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source.db");
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER REFERENCES parent(id));").unwrap();
    let source =
        Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let first = diagnose_database_snapshot(&source).unwrap();
    assert_eq!(first.integrity, DeepDoctorCode::DatabaseIntegrityValidated);
    // This committed violation resides in WAL. Inspecting only source.db would
    // miss the entire schema or validate an outdated database.
    writer
        .execute_batch("PRAGMA foreign_keys=OFF; INSERT INTO child VALUES(735);")
        .unwrap();
    let db_before = fs::read(&path).unwrap();
    let wal_before = fs::read(temp.path().join("source.db-wal")).unwrap();
    let second = diagnose_database_snapshot(&source).unwrap();
    assert_eq!(second.integrity, DeepDoctorCode::DatabaseIntegrityFailed);
    assert_ne!(first.snapshot_sha256, second.snapshot_sha256);
    assert!(second.snapshot_bytes > 100);
    assert_eq!(fs::read(&path).unwrap(), db_before);
    assert_eq!(
        fs::read(temp.path().join("source.db-wal")).unwrap(),
        wal_before
    );
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 3);
    let json = serde_json::to_string(&second).unwrap();
    for private in ["source.db", "parent", "child"] {
        assert!(!json.contains(private));
    }
    assert!(source.is_autocommit());
}

#[test]
fn source_connections_keep_their_permissions_and_uncommitted_rows_are_excluded() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source.db");
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER REFERENCES parent(id));").unwrap();
    let source =
        Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let before = diagnose_database_snapshot(&source).unwrap();
    writer
        .execute_batch("PRAGMA foreign_keys=OFF; BEGIN; INSERT INTO child VALUES(87);")
        .unwrap();
    let during = diagnose_database_snapshot(&source).unwrap();
    assert_eq!(before.snapshot_sha256, during.snapshot_sha256);
    assert_eq!(during.integrity, DeepDoctorCode::DatabaseIntegrityValidated);
    assert!(!writer.is_autocommit());
    writer.execute_batch("COMMIT").unwrap();
    let after = diagnose_database_snapshot(&source).unwrap();
    assert_eq!(after.integrity, DeepDoctorCode::DatabaseIntegrityFailed);
    assert_ne!(during.snapshot_sha256, after.snapshot_sha256);
    assert!(source.is_readonly("main").unwrap());
    assert!(source.execute("INSERT INTO parent VALUES(87)", []).is_err());
}

#[test]
fn oversized_snapshot_is_refused_and_the_source_transaction_is_released() {
    let source = Connection::open_in_memory().unwrap();
    source
        .execute_batch("CREATE TABLE large(payload); INSERT INTO large VALUES(zeroblob(4194304));")
        .unwrap();
    assert!(matches!(
        diagnose_database_snapshot(&source),
        Err(DoctorError::DatabaseTooLarge)
    ));
    assert!(source.is_autocommit());
    assert_eq!(
        source
            .query_row("SELECT length(payload) FROM large", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        4194304
    );
}

#[test]
fn small_and_large_sqlite_pages_are_copied_without_changing_the_source() {
    for size in [512, 4096, 65536] {
        let source = Connection::open_in_memory().unwrap();
        source.pragma_update(None, "page_size", size).unwrap();
        source.execute_batch("CREATE TABLE private_data(secret); INSERT INTO private_data VALUES('PRIVATE_DATABASE_SNAPSHOT_CANARY');").unwrap();
        let report = diagnose_database_snapshot(&source).unwrap();
        assert_eq!(report.integrity, DeepDoctorCode::DatabaseIntegrityValidated);
        assert_eq!(report.snapshot_bytes % size as usize, 0);
        assert_eq!(report.database_queries, 8);
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("PRIVATE_DATABASE_SNAPSHOT_CANARY")
        );
        assert_eq!(
            source
                .query_row("SELECT secret FROM private_data", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "PRIVATE_DATABASE_SNAPSHOT_CANARY"
        );
        assert!(source.is_autocommit());
    }
}

#[test]
fn locked_source_is_unavailable_and_a_later_snapshot_can_succeed() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source.db");
    let owner = Connection::open(&path).unwrap();
    owner.execute_batch("CREATE TABLE proof(id);").unwrap();
    let source =
        Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    source.busy_timeout(std::time::Duration::ZERO).unwrap();
    owner.execute_batch("BEGIN EXCLUSIVE;").unwrap();
    assert!(matches!(
        diagnose_database_snapshot(&source),
        Err(DoctorError::Read)
    ));
    assert!(source.is_autocommit());
    assert!(!owner.is_autocommit());
    owner.execute_batch("ROLLBACK;").unwrap();
    assert_eq!(
        diagnose_database_snapshot(&source).unwrap().integrity,
        DeepDoctorCode::DatabaseIntegrityValidated
    );
}

#[test]
fn multi_batch_copy_covers_the_complete_database_and_releases_the_read_view() {
    let source = Connection::open_in_memory().unwrap();
    source.execute_batch("PRAGMA page_size=4096; CREATE TABLE data(id INTEGER PRIMARY KEY, payload); INSERT INTO data VALUES(1,zeroblob(1048576));").unwrap();
    let pages: i64 = source
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .unwrap();
    assert!(pages > 16);
    let first = diagnose_database_snapshot(&source).unwrap();
    assert_eq!(first.integrity, DeepDoctorCode::DatabaseIntegrityValidated);
    assert_eq!(first.snapshot_bytes, pages as usize * 4096);
    source
        .execute("INSERT INTO data VALUES(2,'later committed row')", [])
        .unwrap();
    let second = diagnose_database_snapshot(&source).unwrap();
    assert_ne!(first.snapshot_sha256, second.snapshot_sha256);
    assert!(source.is_autocommit());
}

#[test]
fn incomplete_caller_transaction_is_refused_without_rollback() {
    let source = Connection::open_in_memory().unwrap();
    source
        .execute_batch("CREATE TABLE proof(id); BEGIN; INSERT INTO proof VALUES(7);")
        .unwrap();
    assert!(matches!(
        diagnose_database_snapshot(&source),
        Err(DoctorError::Invalid)
    ));
    assert!(!source.is_autocommit());
    assert_eq!(
        source
            .query_row("SELECT count(*) FROM proof", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    source.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn write_transaction_defaults_do_not_change_readonly_snapshot_behavior() {
    for behavior in [
        TransactionBehavior::Immediate,
        TransactionBehavior::Exclusive,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source.db");
        let writer = Connection::open(&path).unwrap();
        writer.execute_batch("CREATE TABLE proof(id);").unwrap();
        let mut source = Connection::open(&path).unwrap();
        source.set_transaction_behavior(behavior);
        let report = diagnose_database_snapshot(&source);
        assert!(source.is_autocommit());
        assert_eq!(
            report.unwrap().integrity,
            DeepDoctorCode::DatabaseIntegrityValidated
        );
        // The caller's configured default is still in force: with an existing
        // writer, its next Immediate/Exclusive transaction must remain blocked.
        writer.execute_batch("BEGIN IMMEDIATE;").unwrap();
        source.busy_timeout(std::time::Duration::ZERO).unwrap();
        assert!(source.unchecked_transaction().is_err());
        assert!(source.is_autocommit());
        writer.execute_batch("ROLLBACK;").unwrap();
    }
}

#[test]
fn callback_sees_same_committed_copy_and_cannot_normally_write() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source.db");
    let writer = Connection::open(&path).unwrap();
    writer
        .execute_batch(
            "PRAGMA journal_mode=WAL; CREATE TABLE proof(value); INSERT INTO proof VALUES(11);",
        )
        .unwrap();
    let source =
        Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let (report, seen) =
        router_doctor::diagnose_database_snapshot_with(&source, |copy, queries| {
            // Commit on the original after capture: the inspection must still see 11.
            writer.execute("UPDATE proof SET value=23", []).unwrap();
            *queries += 1;
            let value: i64 = copy
                .query_row("SELECT value FROM proof", [], |r| r.get(0))
                .unwrap();
            assert!(copy.execute("UPDATE proof SET value=42", []).is_err());
            Ok(value)
        })
        .unwrap();
    assert_eq!(seen, 11);
    assert_eq!(report.database_queries, 9);
    let next = diagnose_database_snapshot(&source).unwrap();
    assert_ne!(report.snapshot_sha256, next.snapshot_sha256);
    assert!(source.is_autocommit());
}

#[test]
fn trusted_callback_drift_and_open_transactions_are_rejected() {
    let source = Connection::open_in_memory().unwrap();
    source
        .execute_batch("CREATE TABLE proof(value); INSERT INTO proof VALUES(11);")
        .unwrap();
    let before = diagnose_database_snapshot(&source).unwrap();
    for sql in [
        "PRAGMA query_only=OFF; UPDATE proof SET value=42;",
        "BEGIN;",
    ] {
        let result = router_doctor::diagnose_database_snapshot_with(&source, |copy, _| {
            copy.execute_batch(sql).unwrap();
            Ok(())
        });
        assert!(matches!(result, Err(DoctorError::Integrity)));
    }
    assert_eq!(
        before.snapshot_sha256,
        diagnose_database_snapshot(&source).unwrap().snapshot_sha256
    );
    assert!(source.is_autocommit());
}

#[test]
fn a_dense_valid_database_near_the_size_cap_is_not_refused_as_oversized() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("dense.db");
    let source = Connection::open(&path).unwrap();
    source
        .execute_batch(
            "PRAGMA page_size=4096; CREATE TABLE t(id INTEGER PRIMARY KEY, a TEXT, b TEXT); \
             CREATE INDEX ia ON t(a); CREATE INDEX ib ON t(b);",
        )
        .unwrap();
    let mut n = 0u64;
    // Small indexed rows maximize integrity_check work per byte. Stop below the
    // 4 MiB cap (1,024 pages of 4,096 bytes).
    while source
        .pragma_query_value(None, "page_count", |row| row.get::<_, u64>(0))
        .unwrap()
        < 1_000
    {
        let tx = source.unchecked_transaction().unwrap();
        for _ in 0..200 {
            tx.execute(
                "INSERT INTO t(a,b) VALUES(?1,?2)",
                (format!("{n:04}"), format!("{:x}", n * 7919)),
            )
            .unwrap();
            n += 1;
        }
        tx.commit().unwrap();
    }
    // Guard the premise: this database needs more work than the former budget
    // of 1,000 ticks (1,000 VDBE steps each) and less than the current 4,000.
    let ticks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = ticks.clone();
    source
        .progress_handler(
            1000,
            Some(move || {
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                false
            }),
        )
        .unwrap();
    let check: String = source
        .query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))
        .unwrap();
    source.progress_handler(1000, None::<fn() -> bool>).unwrap();
    assert_eq!(check, "ok");
    let ticks = ticks.load(std::sync::atomic::Ordering::Relaxed);
    assert!((1_001..4_000).contains(&ticks), "{ticks} ticks");
    let report = diagnose_database_snapshot(&source).unwrap();
    assert_eq!(report.integrity, DeepDoctorCode::DatabaseIntegrityValidated);
    assert!(report.snapshot_bytes > 3_900_000);
}
