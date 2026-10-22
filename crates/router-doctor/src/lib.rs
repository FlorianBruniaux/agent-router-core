//! Read-only, explicitly scoped diagnostics and redacted audit export.
#![forbid(unsafe_code)]

mod audit;
mod database;
mod deep;
mod diagnose;
mod files;
mod snapshot;

pub use audit::{AuditInput, build_audit_bundle, verify_audit_bundle};
pub use deep::diagnose_deep;
pub use diagnose::diagnose;
pub use snapshot::{
    DatabaseSnapshotReport, diagnose_database_snapshot, diagnose_database_snapshot_with,
};

pub const MAX_ARTIFACTS: usize = 128;
pub const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum DoctorError {
    #[error("doctor.input.invalid")]
    Invalid,
    #[error("doctor.path.rejected")]
    Path,
    #[error("doctor.file.unavailable")]
    Read,
    #[error("doctor.input.limit")]
    Limit,
    #[error("doctor.schema.invalid")]
    Schema,
    /// The database is larger than the inspection cap. This is a size
    /// observation, not a sign of hostile input, so callers may report a
    /// partial result instead of refusing.
    #[error("doctor.database.too_large")]
    DatabaseTooLarge,
    #[error("doctor.audit.integrity")]
    Integrity,
    #[error("doctor.platform.unsupported")]
    Unsupported,
}
pub type Result<T> = std::result::Result<T, DoctorError>;
