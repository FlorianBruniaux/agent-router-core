//! Passive storage inspection. No Runtime::open, migrations or cleanup recovery.
mod files;
use crate::{
    leases::{LeaseObservation, LeaseRecord, observe_lease},
    store,
};
use router_doctor::{DatabaseSnapshotReport, DoctorError, Result, diagnose_database_snapshot_with};
use router_types::{DeepDoctorCode, DiagnosticState};
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use std::{path::Path, time::Duration};

const CURRENT_SCHEMA: u32 = store::SCHEMA_VERSION;
/// No writer bounds `runs`, `events` or lease rows per store, so a row count
/// is not a health signal. Work is bounded by the snapshot byte cap (4 MiB,
/// enforced before any inspection; a larger database yields a partial report),
/// the per-cell length cap and the SQLite work budget; events are verified as a stream and leases inspected once per row.

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OwnerLockState {
    Available,
    Busy,
    Missing,
    Unknown,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSchemaState {
    RecognizedReadLayout,
    MigrationRequired,
    FutureVersion,
    InvalidLayout,
    /// The database was not read, see `RuntimeStorageReport::partial_reason`.
    NotInspected,
}
/// Why a report is partial. Absent on a complete inspection.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStoragePartialReason {
    /// The database exceeds the inspection cap and was not inspected. Checks
    /// that do not read it (owner lock) are still reported.
    DatabaseExceedsInspectionLimit,
}
#[derive(Debug, Serialize)]
pub struct RuntimeStorageCounts {
    pub runs: u64,
    pub events: u64,
    pub writer_reservations: u64,
    pub cleanup_blocks: u64,
    pub preparation_cycles: u64,
    pub recorded_leases: u64,
    pub recorded_resolved_leases: u64,
}
#[derive(Debug, Default, Serialize)]
pub struct RuntimeLeaseObservations {
    pub held: u64,
    pub pending: u64,
    pub cleanup_marked: u64,
    pub missing: u64,
    pub ambiguous: u64,
}
#[derive(Debug, Serialize)]
pub struct RuntimeStorageReport {
    pub schema_version: u32,
    pub observed_at_unix_seconds: u64,
    pub overall: DiagnosticState,
    pub partial_reason: Option<RuntimeStoragePartialReason>,
    pub database: Option<DatabaseSnapshotReport>,
    pub storage_schema_version: Option<u32>,
    pub supported_storage_schema_version: u32,
    pub schema_layout: RuntimeSchemaState,
    pub journal_integrity: DiagnosticState,
    pub journal_authenticity: DiagnosticState,
    pub shared_admission_accounting: DiagnosticState,
    pub owner_lock: OwnerLockState,
    pub counts: Option<RuntimeStorageCounts>,
    pub leases: Option<RuntimeLeaseObservations>,
    pub database_and_leases_atomic: bool,
    pub process_liveness: DiagnosticState,
    pub cleanup_authority: DiagnosticState,
}
struct Inspection {
    version: u32,
    layout: RuntimeSchemaState,
    journal: DiagnosticState,
    counts: Option<RuntimeStorageCounts>,
    leases: Vec<(String, u32, String)>,
}

/// Inspect a private existing runtime. Read-only SQLite may coordinate its
/// WAL-index and read marks; this does not promise a filesystem with zero writes.
/// The supplied private directory and its ancestors must be operator-controlled.
/// No run recovery, schema migration, checkpoint or lease resolution is invoked.
pub fn diagnose_runtime_storage(root: &Path, now: u64) -> Result<RuntimeStorageReport> {
    let files = files::Files::open(root)?;
    let owner_lock = files.owner()?;
    if files.database_oversized() {
        return Ok(partial_report(now, owner_lock));
    }
    let source = Connection::open_with_flags(
        files.path.join("runtime.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| DoctorError::Read)?;
    source
        .busy_timeout(Duration::ZERO)
        .map_err(|_| DoctorError::Read)?;
    // Only "too big to copy" becomes a partial report. Hostile-input limits
    // (long cells, copy deadline, SQL work budget) stay `DoctorError::Limit`.
    let captured = files
        .check()
        .and_then(|()| diagnose_database_snapshot_with(&source, inspect))
        .and_then(|captured| files.check().map(|()| captured));
    let (database, inspected) = match captured {
        Err(DoctorError::DatabaseTooLarge) => return Ok(partial_report(now, owner_lock)),
        other => other?,
    };
    // Keep SQLite's own descriptor lifetime intact, including during checks.
    drop(source);
    let leases = inspected.counts.as_ref().map(|_| {
        let mut observations = RuntimeLeaseObservations::default();
        for (id, attempt, encoded) in &inspected.leases {
            let observed = serde_json::from_str::<LeaseRecord>(encoded)
                .ok()
                .map(|record| observe_lease(&files.root, id, *attempt, &record))
                .unwrap_or(LeaseObservation::Ambiguous);
            match observed {
                LeaseObservation::Held => observations.held += 1,
                LeaseObservation::Pending => observations.pending += 1,
                LeaseObservation::CleanupMarked => observations.cleanup_marked += 1,
                LeaseObservation::Missing => observations.missing += 1,
                LeaseObservation::Ambiguous => observations.ambiguous += 1,
            }
        }
        observations
    });
    let overall = if database.integrity != DeepDoctorCode::DatabaseIntegrityValidated
        || matches!(
            inspected.layout,
            RuntimeSchemaState::FutureVersion | RuntimeSchemaState::InvalidLayout
        )
        || inspected.journal == DiagnosticState::Fail
    {
        DiagnosticState::Fail
    } else if inspected.layout != RuntimeSchemaState::RecognizedReadLayout
        || matches!(
            owner_lock,
            OwnerLockState::Missing | OwnerLockState::Unknown
        )
        || inspected
            .counts
            .as_ref()
            .is_some_and(|c| c.cleanup_blocks > 0)
        || leases
            .as_ref()
            .is_some_and(|l| l.pending + l.missing + l.ambiguous > 0)
    {
        DiagnosticState::Warning
    } else {
        DiagnosticState::Pass
    };
    Ok(RuntimeStorageReport {
        schema_version: 2,
        observed_at_unix_seconds: now,
        overall,
        partial_reason: None,
        database: Some(database),
        storage_schema_version: Some(inspected.version),
        supported_storage_schema_version: CURRENT_SCHEMA,
        schema_layout: inspected.layout,
        journal_integrity: inspected.journal,
        journal_authenticity: DiagnosticState::Unknown,
        shared_admission_accounting: DiagnosticState::Unknown,
        owner_lock,
        counts: inspected.counts,
        leases,
        database_and_leases_atomic: false,
        process_liveness: DiagnosticState::Unknown,
        cleanup_authority: DiagnosticState::Unknown,
    })
}

/// Report for a database over the inspection cap: nothing read from it is
/// claimed, so `overall` is unknown rather than a pass or a failure.
fn partial_report(now: u64, owner_lock: OwnerLockState) -> RuntimeStorageReport {
    RuntimeStorageReport {
        schema_version: 2,
        observed_at_unix_seconds: now,
        overall: DiagnosticState::Unknown,
        partial_reason: Some(RuntimeStoragePartialReason::DatabaseExceedsInspectionLimit),
        database: None,
        storage_schema_version: None,
        supported_storage_schema_version: CURRENT_SCHEMA,
        schema_layout: RuntimeSchemaState::NotInspected,
        journal_integrity: DiagnosticState::Unknown,
        journal_authenticity: DiagnosticState::Unknown,
        shared_admission_accounting: DiagnosticState::Unknown,
        owner_lock,
        counts: None,
        leases: None,
        database_and_leases_atomic: false,
        process_liveness: DiagnosticState::Unknown,
        cleanup_authority: DiagnosticState::Unknown,
    }
}

fn inspect(db: &Connection, queries: &mut usize) -> Result<Inspection> {
    *queries += 1;
    let version: u32 = db
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(sql_error)?;
    let mut result = Inspection {
        version,
        layout: RuntimeSchemaState::InvalidLayout,
        journal: DiagnosticState::Unknown,
        counts: None,
        leases: Vec::new(),
    };
    if version != CURRENT_SCHEMA {
        result.layout = if version < CURRENT_SCHEMA {
            RuntimeSchemaState::MigrationRequired
        } else {
            RuntimeSchemaState::FutureVersion
        };
        return Ok(result);
    }
    // This establishes the read layout, not the authenticity of the schema or
    // the complete runtime write invariants. Never run user-provided SQL/views.
    for (table, columns) in TABLES {
        *queries += 1;
        let is_table: bool = db
            .query_row(
                "SELECT count(*)=1 FROM sqlite_schema WHERE name=?1 AND type='table'",
                [table],
                |r| r.get(0),
            )
            .map_err(sql_error)?;
        if !is_table {
            return Ok(result);
        }
        *queries += 1;
        let mut query = db
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(sql_error)?;
        let names = query
            .query_map([], |r| r.get::<_, String>(1))
            .map_err(sql_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql_error)?;
        if names.iter().map(String::as_str).collect::<Vec<_>>() != *columns {
            return Ok(result);
        }
        // Bound each cell before deserializing or hashing.
        let lengths = columns
            .iter()
            .map(|c| format!("coalesce(length(CAST({c} AS BLOB)),0)"))
            .collect::<Vec<_>>()
            .join(",");
        *queries += 1;
        let longest: u64 = db
            .query_row(
                &format!("SELECT coalesce(max(max(0,{lengths})),0) FROM {table}"),
                [],
                |r| r.get(0),
            )
            .map_err(sql_error)?;
        if longest > 65536 {
            return Err(DoctorError::Limit);
        }
    }
    result.layout = RuntimeSchemaState::RecognizedReadLayout;
    // The existing verifier counts its statements, including early failures.
    result.journal = match store::verify_diagnostic_events(db, queries) {
        Ok(()) => DiagnosticState::Pass,
        Err(crate::RuntimeError::Storage(error)) => return Err(sql_error(error)),
        Err(crate::RuntimeError::Limit) => return Err(DoctorError::Limit),
        Err(_) => DiagnosticState::Fail,
    };
    *queries += 1;
    result.counts = Some(db.query_row("SELECT (SELECT count(*) FROM runs),(SELECT count(*) FROM events),(SELECT count(*) FROM writer_locks),(SELECT count(*) FROM cleanup_blocks),(SELECT count(*) FROM preparation_cycles),(SELECT count(*) FROM attempt_leases),(SELECT count(*) FROM attempt_leases WHERE resolved=1)", [], |r| Ok(RuntimeStorageCounts {
        runs:r.get(0)?, events:r.get(1)?, writer_reservations:r.get(2)?, cleanup_blocks:r.get(3)?,
        preparation_cycles:r.get(4)?, recorded_leases:r.get(5)?, recorded_resolved_leases:r.get(6)?,
    })).map_err(sql_error)?);
    *queries += 1;
    let mut query = db
        .prepare("SELECT run_id,attempt,record FROM attempt_leases ORDER BY run_id,attempt")
        .map_err(sql_error)?;
    result.leases = query
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map_err(sql_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(sql_error)?;
    Ok(result)
}
fn sql_error(error: rusqlite::Error) -> DoctorError {
    match error {
        rusqlite::Error::SqliteFailure(error, _)
            if error.code == rusqlite::ErrorCode::OperationInterrupted =>
        {
            DoctorError::Limit
        }
        // A concurrent writer is not evidence about the layout.
        rusqlite::Error::SqliteFailure(error, _)
            if matches!(
                error.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            DoctorError::Read
        }
        _ => DoctorError::Schema,
    }
}
const TABLES: &[(&str, &[&str])] = &[
    ("runs", &["run_id", "plan_id", "node_id", "summary"]),
    ("run_attempts", &["run_id", "attempt", "status"]),
    (
        "events",
        &[
            "sequence",
            "run_id",
            "kind",
            "state",
            "detail",
            "previous_hash",
            "event_hash",
        ],
    ),
    ("writer_locks", &["run_id", "workspace", "scope"]),
    ("artifacts", &["run_id", "sha256", "kind"]),
    ("verifications", &["run_id", "record"]),
    ("control_requests", &["run_id", "cancel_requested"]),
    (
        "output_artifacts",
        &["run_id", "attempt", "expires_at", "state", "record"],
    ),
    ("output_files", &["run_id", "attempt", "stream", "identity"]),
    (
        "workflow_instances",
        &["instance_id", "contract_hash", "record"],
    ),
    (
        "workflow_node_runs",
        &[
            "instance_id",
            "node_id",
            "generation",
            "run_id",
            "model",
            "agent",
        ],
    ),
    (
        "declared_artifacts",
        &[
            "artifact_id",
            "run_id",
            "attempt",
            "label",
            "record",
            "identity",
        ],
    ),
    (
        "attempt_leases",
        &["run_id", "attempt", "record", "resolved", "evidence"],
    ),
    ("cleanup_blocks", &["run_id"]),
    ("workflow_plan_authority", &["instance_id", "pin"]),
    ("preparation_cycles", &["run_id", "sequence", "record"]),
    ("admission_binding", &["id", "binding"]),
    ("admission_intents", &["run_id", "record"]),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use std::collections::BTreeMap;

    fn failure(code: std::ffi::c_int) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None)
    }
    #[test]
    fn sql_errors_keep_busy_locked_interrupted_and_layout_apart() {
        assert!(matches!(
            sql_error(failure(rusqlite::ffi::SQLITE_BUSY)),
            DoctorError::Read
        ));
        assert!(matches!(
            sql_error(failure(rusqlite::ffi::SQLITE_LOCKED)),
            DoctorError::Read
        ));
        assert!(matches!(
            sql_error(failure(rusqlite::ffi::SQLITE_INTERRUPT)),
            DoctorError::Limit
        ));
        assert!(matches!(
            sql_error(failure(rusqlite::ffi::SQLITE_ERROR)),
            DoctorError::Schema
        ));
        assert!(matches!(
            sql_error(rusqlite::Error::QueryReturnedNoRows),
            DoctorError::Schema
        ));
    }
    #[test]
    fn doctor_tables_match_the_tables_the_migrations_create() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().join("runtime");
        let store = Store::open(&root).unwrap();
        drop(store);
        let db = Connection::open(root.join("runtime.sqlite3")).unwrap();
        assert_eq!(
            db.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                .unwrap(),
            CURRENT_SCHEMA
        );
        let mut names = db
            .prepare(
                "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            )
            .unwrap();
        let names = names
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let mut migrated = BTreeMap::new();
        for name in names {
            let mut info = db.prepare(&format!("PRAGMA table_info({name})")).unwrap();
            let columns = info
                .query_map([], |r| r.get::<_, String>(1))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            migrated.insert(name, columns);
        }
        let listed = TABLES
            .iter()
            .map(|(name, columns)| {
                (
                    name.to_string(),
                    columns.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(listed.len(), TABLES.len(), "duplicate doctor table");
        assert_eq!(listed, migrated);
    }
    #[test]
    fn healthy_store_with_more_than_the_row_cap_of_events_is_inspected() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().join("runtime");
        let store = Store::open(&root).unwrap();
        store
            .register(&crate::store::tests::summary("run"))
            .unwrap();
        store.append_events_for_test("run", 4096 + 200);
        assert!(store.events().unwrap().len() as u64 > 4096);
        // The snapshot copy has a 250 ms wall-clock budget that a loaded test
        // machine can exceed; a row cap would fail every attempt, not one.
        let report = (0..3)
            .find_map(|_| match diagnose_runtime_storage(&root, 1) {
                Err(DoctorError::Limit) => None,
                other => Some(other),
            })
            .expect("three consecutive Limit results")
            .unwrap();
        assert_eq!(report.journal_integrity, DiagnosticState::Pass);
        assert!(report.counts.unwrap().events > 4096);
    }
}
