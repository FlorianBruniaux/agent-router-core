//! A durable cleanup claim never follows from a PID or a process-group signal.
use crate::{Result, RuntimeError, digest, outputs::FileIdentity};
use nix::fcntl::{Flock, FlockArg};
use rustix::fs::{AtFlags, Mode, OFlags, mkdirat, openat, statat, unlinkat};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const PENDING: &[u8] = b"router-runtime-lease-v1:pending\n";
const GROUP_CLEAN: &[u8] = b"router-runtime-lease-v1:group-clean\n";
const NAMESPACE_CLEAN: &[u8] = b"router-runtime-lease-v1:namespace-clean\n";
const RECOVERED: &[u8] = b"router-runtime-lease-v1:recovered\n";

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct LeaseRecord {
    name: String,
    identity: FileIdentity,
    #[serde(default)]
    namespace_required: bool,
    #[serde(default)]
    host_state_pending: bool,
}
impl LeaseRecord {
    pub(crate) fn require_namespace(&mut self, required: bool) {
        self.namespace_required = required;
        self.host_state_pending = required;
    }
    pub(crate) fn needs_host_cleanup(&self) -> bool {
        self.host_state_pending
    }
    pub(crate) fn host_state_cleaned(&mut self) {
        self.host_state_pending = false;
    }
}
pub(crate) struct LeaseStorage {
    directory: File,
    path: PathBuf,
}
pub(crate) struct CleanupProof {
    _lock: Flock<File>,
    pub evidence: router_types::ProcessCleanupEvidence,
}
impl LeaseStorage {
    pub fn open(root: &Path) -> Result<Self> {
        let root_file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(root)?;
        match mkdirat(&root_file, "leases", Mode::RWXU) {
            Ok(()) => root_file.sync_all()?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(e) => return Err(std::io::Error::from(e).into()),
        }
        let directory = File::from(
            openat(
                &root_file,
                "leases",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)?,
        );
        if directory.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(RuntimeError::Integrity("lease directory"));
        }
        Ok(Self {
            directory,
            path: root.join("leases"),
        })
    }
    fn name(id: &str, attempt: u32) -> Result<String> {
        Ok(format!(
            "{}.lease",
            digest("runtime-lease-v1", &(id, attempt))?
        ))
    }
    pub fn create(&self, id: &str, attempt: u32) -> Result<(LeaseRecord, PathBuf)> {
        let name = Self::name(id, attempt)?;
        let mut file = File::from(
            openat(
                &self.directory,
                &name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(std::io::Error::from)?,
        );
        file.write_all(PENDING)?;
        file.sync_all()?;
        self.directory.sync_all()?;
        Ok((
            LeaseRecord {
                name: name.clone(),
                identity: FileIdentity::from_file(&file)?,
                namespace_required: false,
                host_state_pending: false,
            },
            self.path.join(name),
        ))
    }
    /// Removes the lease file of `(id, attempt)` only when it is provably a
    /// lease created and never committed: a regular, single-link, private file
    /// of this user, holding exactly the pending marker, with no other holder.
    /// The caller must hold the journal write transaction and have observed no
    /// `attempt_leases` row, so no helper can have been handed this file.
    /// Anything else, including a lookup failure, is left untouched.
    pub fn reclaim_uncommitted(&self, id: &str, attempt: u32) -> Result<bool> {
        let name = Self::name(id, attempt)?;
        let Ok(fd) = openat(
            &self.directory,
            &name,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) else {
            return Ok(false);
        };
        let file = File::from(fd);
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.mode() & 0o077 != 0
            || meta.uid() != rustix::process::getuid().as_raw()
            || meta.len() != PENDING.len() as u64
        {
            return Ok(false);
        }
        let Ok(mut lock) = Flock::lock(file, FlockArg::LockExclusiveNonblock) else {
            return Ok(false);
        };
        let mut bytes = Vec::new();
        (&mut *lock).take(96).read_to_end(&mut bytes)?;
        if bytes != PENDING {
            return Ok(false);
        }
        // The name must still designate the file we hold and locked.
        let current = statat(&self.directory, &name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(std::io::Error::from)?;
        let same = FileIdentity {
            device: current.st_dev as u64,
            inode: current.st_ino as u64,
        }
        .matches(&lock)?;
        if !same {
            return Ok(false);
        }
        unlinkat(&self.directory, &name, AtFlags::empty()).map_err(std::io::Error::from)?;
        self.directory.sync_all()?;
        Ok(true)
    }
    /// The caller retains this lock through the durable terminal transition.
    /// Invalidating pending under the lock prevents a delayed helper spawning.
    /// Recovery has no live HostState owner. A process-stop marker cannot prove
    /// that a refused/interrupted filesystem cleanup completed.
    pub(crate) fn recovery_proof(
        &self,
        id: &str,
        attempt: u32,
        record: &LeaseRecord,
    ) -> Result<CleanupProof> {
        if record.needs_host_cleanup() {
            return Err(RuntimeError::CleanupUnknown);
        }
        self.cleanup_proof(id, attempt, record)
    }

    pub fn cleanup_proof(
        &self,
        id: &str,
        attempt: u32,
        record: &LeaseRecord,
    ) -> Result<CleanupProof> {
        if record.name != Self::name(id, attempt)? {
            return Err(RuntimeError::CleanupUnknown);
        }
        let file = File::from(
            openat(
                &self.directory,
                &record.name,
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| RuntimeError::CleanupUnknown)?,
        );
        let proof = lock_cleanup(file, &record.identity)?;
        if record.namespace_required && !proof.excludes_writers() {
            return Err(RuntimeError::CleanupUnknown);
        }
        Ok(proof)
    }
}

/// Retain the exact helper lease before any process can receive the home.
/// The opaque proof owns its lock throughout the caller's deletion operation.
pub(crate) struct CleanupLease {
    #[cfg(test)]
    directory: File,
    #[cfg(test)]
    name: std::ffi::OsString,
    file: File,
    identity: FileIdentity,
}
impl CleanupLease {
    pub(crate) fn pin(path: &Path) -> Result<Self> {
        if !path.is_absolute() || std::fs::canonicalize(path)? != path {
            return Err(RuntimeError::CleanupUnknown);
        }
        let parent = path.parent().ok_or(RuntimeError::CleanupUnknown)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(parent)?;
        let meta = directory.metadata()?;
        if meta.uid() != rustix::process::geteuid().as_raw() || meta.mode() & 0o077 != 0 {
            return Err(RuntimeError::CleanupUnknown);
        }
        let name = path
            .file_name()
            .ok_or(RuntimeError::CleanupUnknown)?
            .to_owned();
        let file = open_lease_at(&directory, &name)?;
        let identity = FileIdentity::from_file(&file)?;
        // No helper has been dispatched yet. Validate/invalidate pending under
        // the normal protocol only when cleanup is actually requested.
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.mode() & 0o077 != 0
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.len() != PENDING.len() as u64
        {
            return Err(RuntimeError::CleanupUnknown);
        }
        let mut bytes = Vec::new();
        (&file).take(96).read_to_end(&mut bytes)?;
        if bytes != PENDING {
            return Err(RuntimeError::CleanupUnknown);
        }
        Ok(Self {
            #[cfg(test)]
            directory,
            #[cfg(test)]
            name,
            file,
            identity,
        })
    }
    pub(crate) fn matches(&self, proof: &CleanupProof) -> Result<bool> {
        Ok(self.identity.matches(&self.file)? && self.identity.matches(&proof._lock)?)
    }
    #[cfg(test)]
    pub(crate) fn proof(&self) -> Result<CleanupProof> {
        // Reopen, never dup: flock on a dup would share the helper's lock.
        let file = open_lease_at(&self.directory, &self.name)?;
        if !self.identity.matches(&self.file)? {
            return Err(RuntimeError::CleanupUnknown);
        }
        lock_cleanup(file, &self.identity)
    }
}
fn open_lease_at(directory: &File, name: &std::ffi::OsStr) -> Result<File> {
    openat(
        directory,
        name,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| RuntimeError::CleanupUnknown)
}
impl CleanupProof {
    pub(crate) fn excludes_writers(&self) -> bool {
        matches!(
            self.evidence,
            router_types::ProcessCleanupEvidence::NotStarted
                | router_types::ProcessCleanupEvidence::NamespaceTerminated
        )
    }
}
fn lock_cleanup(file: File, identity: &FileIdentity) -> Result<CleanupProof> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || !identity.matches(&file)?
    {
        return Err(RuntimeError::CleanupUnknown);
    }
    let mut lock = Flock::lock(file, FlockArg::LockExclusiveNonblock)
        .map_err(|_| RuntimeError::CleanupUnknown)?;
    let mut status = Vec::new();
    (&mut *lock).take(96).read_to_end(&mut status)?;
    let evidence = if status == PENDING {
        lock.seek(SeekFrom::Start(0))?;
        lock.write_all(RECOVERED)?;
        lock.set_len(RECOVERED.len() as u64)?;
        lock.sync_all()?;
        router_types::ProcessCleanupEvidence::NotStarted
    } else if status == RECOVERED {
        router_types::ProcessCleanupEvidence::NotStarted
    } else if status == GROUP_CLEAN {
        router_types::ProcessCleanupEvidence::GroupTerminated
    } else if status == NAMESPACE_CLEAN {
        router_types::ProcessCleanupEvidence::NamespaceTerminated
    } else {
        return Err(RuntimeError::CleanupUnknown);
    };
    Ok(CleanupProof {
        _lock: lock,
        evidence,
    })
}

/// Observation only: even a cleanup marker is not an opaque cleanup proof.
pub(crate) enum LeaseObservation {
    Held,
    Pending,
    CleanupMarked,
    Missing,
    Ambiguous,
}
pub(crate) fn observe_lease(
    root: &File,
    id: &str,
    attempt: u32,
    record: &LeaseRecord,
) -> LeaseObservation {
    observe_lease_checked(root, id, attempt, record).unwrap_or(LeaseObservation::Ambiguous)
}
fn observe_lease_checked(
    root: &File,
    id: &str,
    attempt: u32,
    record: &LeaseRecord,
) -> Result<LeaseObservation> {
    if attempt == 0 || attempt > 5 || record.name != LeaseStorage::name(id, attempt)? {
        return Ok(LeaseObservation::Ambiguous);
    }
    let open = |directory: &File, name: &str, flags: OFlags| -> std::io::Result<File> {
        openat(
            directory,
            name,
            flags | OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(std::io::Error::from)
    };
    let directory = match open(root, "leases", OFlags::DIRECTORY) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(LeaseObservation::Missing),
        Err(e) => return Err(e.into()),
    };
    let meta = directory.metadata()?;
    if meta.permissions().mode() & 0o077 != 0 || meta.uid() != rustix::process::getuid().as_raw() {
        return Ok(LeaseObservation::Ambiguous);
    }
    let file = match open(&directory, &record.name, OFlags::empty()) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(LeaseObservation::Missing),
        Err(e) => return Err(e.into()),
    };
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.len() > 96
        || meta.mode() & 0o077 != 0
        || meta.uid() != rustix::process::getuid().as_raw()
        || !record.identity.matches(&file)?
    {
        return Ok(LeaseObservation::Ambiguous);
    }
    let mut lock = match Flock::lock(file, FlockArg::LockSharedNonblock) {
        Ok(lock) => lock,
        Err((_, nix::errno::Errno::EWOULDBLOCK)) => return Ok(LeaseObservation::Held),
        Err(_) => return Ok(LeaseObservation::Ambiguous),
    };
    let mut bytes = Vec::new();
    (&mut *lock).take(97).read_to_end(&mut bytes)?;
    Ok(if bytes == PENDING {
        LeaseObservation::Pending
    } else if bytes == GROUP_CLEAN || bytes == NAMESPACE_CLEAN || bytes == RECOVERED {
        LeaseObservation::CleanupMarked
    } else {
        LeaseObservation::Ambiguous
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // router-sandbox-helper cannot depend on this crate, and this crate cannot
    // link the helper binary, so the two spellings are pinned against each
    // other by reading the helper source.
    const HELPER: &str = include_str!("../../router-sandbox-helper/src/watchdog.rs");

    fn literal(marker: &[u8]) -> String {
        format!(
            "b\"{}\"",
            std::str::from_utf8(marker).unwrap().replace('\n', "\\n")
        )
    }
    #[test]
    fn historical_lease_records_do_not_invent_host_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let storage = LeaseStorage::open(&root).unwrap();
        let (mut record, path) = storage.create("legacy", 1).unwrap();
        let mut value = serde_json::to_value(&record).unwrap();
        value.as_object_mut().unwrap().remove("namespace_required");
        value.as_object_mut().unwrap().remove("host_state_pending");
        let legacy: LeaseRecord = serde_json::from_value(value).unwrap();
        assert!(!legacy.needs_host_cleanup());
        std::fs::write(&path, GROUP_CLEAN).unwrap();
        assert_eq!(
            storage
                .recovery_proof("legacy", 1, &legacy)
                .unwrap()
                .evidence,
            router_types::ProcessCleanupEvidence::GroupTerminated
        );
        record.require_namespace(true);
        assert!(storage.cleanup_proof("legacy", 1, &record).is_err());
        std::fs::write(&path, NAMESPACE_CLEAN).unwrap();
        assert!(storage.recovery_proof("legacy", 1, &record).is_err());
        record.host_state_cleaned();
        assert_eq!(
            storage
                .recovery_proof("legacy", 1, &record)
                .unwrap()
                .evidence,
            router_types::ProcessCleanupEvidence::NamespaceTerminated
        );
    }

    #[test]
    fn helper_lease_markers_equal_the_runtime_markers() {
        for (name, marker) in [
            ("PENDING", PENDING),
            ("GROUP_CLEAN", GROUP_CLEAN),
            ("NAMESPACE_CLEAN", NAMESPACE_CLEAN),
        ] {
            assert!(
                HELPER.contains(&literal(marker)),
                "helper watchdog no longer spells {name} as {}",
                literal(marker)
            );
        }
        // The active marker exists only in the helper, but must stay in the
        // same versioned family as the markers the runtime reads.
        assert!(HELPER.contains(&literal(b"router-runtime-lease-v1:active\n")));
    }
}
