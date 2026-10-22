//! Explicit inspection through an existing application-owned SQLite connection.
//! No pathname is accepted or reopened and no snapshot file is written.
use crate::{DoctorError, MAX_FILE_BYTES, Result, database};
use router_adapter_api::content_digest;
use router_types::DeepDoctorCode;
use rusqlite::{
    Connection, Transaction, TransactionBehavior,
    backup::{Backup, StepResult},
};
use serde::Serialize;
use std::time::{Duration, Instant};

const PAGES_PER_STEP: i32 = 16;
const MAX_STEPS: usize = MAX_FILE_BYTES / 512 / PAGES_PER_STEP as usize + 1;
const COPY_BUDGET: Duration = Duration::from_millis(250);

#[derive(Debug, Serialize)]
pub struct DatabaseSnapshotReport {
    pub schema_version: u32,
    pub integrity: DeepDoctorCode,
    pub snapshot_sha256: String,
    pub snapshot_bytes: usize,
    pub database_queries: usize,
}

/// Capture committed state, including WAL, through a caller-owned connection.
/// The caller authorizes this connection and bounds its I/O and busy handler.
/// Copy work is checked between batches; this is not an OS execution deadline.
/// An existing transaction is refused without modifying or rolling it back.
pub fn diagnose_database_snapshot(source: &Connection) -> Result<DatabaseSnapshotReport> {
    diagnose_database_snapshot_with(source, |_, _| Ok(())).map(|(report, ())| report)
}

/// Inspect the same hardened in-memory copy used by the integrity report.
/// `inspect` is trusted, linked Rust code, not a sandbox for user SQL or code.
/// It must count its SQL statements in `queries` and preserve connection limits.
/// The callback shares the SQLite work budget; arbitrary Rust work is not timed.
/// Persistent changes or an open transaction are refused before returning data.
pub fn diagnose_database_snapshot_with<T>(
    source: &Connection,
    inspect: impl FnOnce(&Connection, &mut usize) -> Result<T>,
) -> Result<(DatabaseSnapshotReport, T)> {
    let snapshot = capture(source, COPY_BUDGET)?;
    let mut queries = 3;
    let integrity = database::inspect_connection(&snapshot, &mut queries)?;
    let (snapshot_sha256, snapshot_bytes) = fingerprint(&snapshot)?;
    let value = inspect(&snapshot, &mut queries)?;
    if !snapshot.is_autocommit()
        || fingerprint(&snapshot)? != (snapshot_sha256.clone(), snapshot_bytes)
    {
        return Err(DoctorError::Integrity);
    }
    Ok((
        DatabaseSnapshotReport {
            schema_version: 1,
            integrity,
            snapshot_sha256,
            snapshot_bytes,
            database_queries: queries,
        },
        value,
    ))
}

fn fingerprint(connection: &Connection) -> Result<(String, usize)> {
    let bytes = connection
        .serialize("main")
        .map_err(|_| DoctorError::Read)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(DoctorError::Limit);
    }
    Ok((content_digest(&bytes), bytes.len()))
}

fn capture(source: &Connection, budget: Duration) -> Result<Connection> {
    if !source.is_autocommit() {
        return Err(DoctorError::Invalid);
    }
    let started = Instant::now();
    // The first read pins a SQLite transaction. Other connections can append to
    // WAL, but every batch copies this same read view. Drop releases the read
    // transaction on all failure paths; this function never executes source DML.
    // Do not inherit a caller's Immediate/Exclusive default: diagnostics must
    // acquire only a read view, including on read-only source connections.
    let read = Transaction::new_unchecked(source, TransactionBehavior::Deferred)
        .map_err(|_| DoctorError::Read)?;
    let pages: i64 = read
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .map_err(|_| DoctorError::Read)?;
    let page_size: i64 = read
        .pragma_query_value(None, "page_size", |row| row.get(0))
        .map_err(|_| DoctorError::Read)?;
    if pages < 1 || !(512..=65536).contains(&page_size) || !(page_size as u64).is_power_of_two() {
        return Err(DoctorError::Invalid);
    }
    let size = pages.checked_mul(page_size).ok_or(DoctorError::Limit)?;
    if size > MAX_FILE_BYTES as i64 {
        return Err(DoctorError::DatabaseTooLarge);
    }
    if started.elapsed() >= budget {
        return Err(DoctorError::Limit);
    }
    let mut snapshot = Connection::open_in_memory().map_err(|_| DoctorError::Read)?;
    snapshot
        .busy_timeout(Duration::ZERO)
        .map_err(|_| DoctorError::Read)?;
    snapshot
        .pragma_update(None, "page_size", page_size)
        .map_err(|_| DoctorError::Read)?;
    {
        let copy = Backup::new(&read, &mut snapshot).map_err(|_| DoctorError::Read)?;
        let mut complete = false;
        for _ in 0..MAX_STEPS {
            if started.elapsed() >= budget {
                return Err(DoctorError::Limit);
            }
            let step = copy.step(PAGES_PER_STEP).map_err(|_| DoctorError::Read)?;
            if matches!(step, StepResult::Busy | StepResult::Locked) {
                return Err(DoctorError::Read);
            }
            let progress = copy.progress();
            if i64::from(progress.pagecount) != pages
                || progress.remaining < 0
                || progress.remaining > progress.pagecount
            {
                return Err(DoctorError::Integrity);
            }
            match step {
                StepResult::Done => {
                    complete = true;
                    break;
                }
                StepResult::More => {}
                _ => return Err(DoctorError::Read),
            }
        }
        if !complete || started.elapsed() >= budget {
            return Err(DoctorError::Limit);
        }
    }
    read.rollback().map_err(|_| DoctorError::Read)?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_deadline_refuses_without_leaving_a_transaction() {
        let source = Connection::open_in_memory().unwrap();
        source.execute_batch("CREATE TABLE proof(id);").unwrap();
        assert!(matches!(
            capture(&source, Duration::ZERO),
            Err(DoctorError::Limit)
        ));
        assert!(source.is_autocommit());
    }
}
