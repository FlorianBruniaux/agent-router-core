//! The private operator-selected directory is pinned; SQLite retains its own FDs.
use super::OwnerLockState;
use nix::fcntl::{Flock, FlockArg};
use router_doctor::{DoctorError, MAX_FILE_BYTES, MAX_TOTAL_BYTES, Result};
use rustix::fs::{AtFlags, Mode, OFlags, Stat, openat, statat};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const NAMES: [&str; 4] = [
    "runtime.sqlite3",
    "runtime.sqlite3-wal",
    "runtime.sqlite3-shm",
    "runtime.sqlite3-journal",
];
pub(super) struct Files {
    pub root: File,
    pub path: PathBuf,
    initial: [Option<Stat>; 4],
    /// The main database file was already over the inspection cap when opened.
    oversized: bool,
}
impl Files {
    pub fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(DoctorError::Path);
        }
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| DoctorError::Path)?;
        let meta = root.metadata().map_err(|_| DoctorError::Read)?;
        if !meta.is_dir()
            || meta.mode() & 0o077 != 0
            || meta.uid() != rustix::process::getuid().as_raw()
        {
            return Err(DoctorError::Path);
        }
        // Ancestors belong to the operator trust boundary. Do not accept a
        // substituted final directory when resolving the SQLite pathname.
        let path = path.canonicalize().map_err(|_| DoctorError::Path)?;
        let initial = Self::inspect(&root)?;
        let oversized = initial[0].as_ref().is_some_and(is_oversized);
        let files = Self {
            root,
            path,
            initial,
            oversized,
        };
        files.check()?;
        Ok(files)
    }
    fn inspect(root: &File) -> Result<[Option<Stat>; 4]> {
        let mut found = [None; 4];
        let mut total = 0u64;
        for (index, name) in NAMES.iter().enumerate() {
            // Do not open/close descriptors for SQLite inodes here: on POSIX a
            // close can release another connection's process-wide fcntl locks.
            match statat(root, *name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => {
                    private_regular(&stat)?;
                    let length = u64::try_from(stat.st_size).map_err(|_| DoctorError::Limit)?;
                    // An oversized main file is reported by the caller as a partial
                    // result; it is never read, so it does not count toward the total.
                    if index == 0 && is_oversized(&stat) {
                        found[index] = Some(stat);
                        continue;
                    }
                    let limit = if index == 0 {
                        MAX_FILE_BYTES
                    } else {
                        MAX_TOTAL_BYTES
                    };
                    if length > limit as u64 {
                        return Err(DoctorError::Limit);
                    }
                    total = total.checked_add(length).ok_or(DoctorError::Limit)?;
                    if total > MAX_TOTAL_BYTES as u64 {
                        return Err(DoctorError::Limit);
                    }
                    found[index] = Some(stat);
                }
                Err(rustix::io::Errno::NOENT) if index != 0 => {}
                Err(_) => return Err(DoctorError::Read),
            }
        }
        Ok(found)
    }
    pub fn check(&self) -> Result<()> {
        let pinned = self.root.metadata().map_err(|_| DoctorError::Read)?;
        let current = std::fs::symlink_metadata(&self.path).map_err(|_| DoctorError::Path)?;
        if !current.is_dir()
            || current.file_type().is_symlink()
            || current.dev() != pinned.dev()
            || current.ino() != pinned.ino()
            || current.uid() != rustix::process::getuid().as_raw()
            || current.mode() & 0o077 != 0
        {
            return Err(DoctorError::Path);
        }
        let now = Self::inspect(&self.root)?;
        if !self.oversized && now[0].as_ref().is_some_and(is_oversized) {
            return Err(DoctorError::DatabaseTooLarge);
        }
        for (before, after) in self.initial.iter().zip(now.iter()) {
            if let Some(before) = before {
                let after = after.as_ref().ok_or(DoctorError::Path)?;
                if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
                    return Err(DoctorError::Path);
                }
            }
        }
        Ok(())
    }
    pub fn database_oversized(&self) -> bool {
        self.oversized
    }
    pub fn owner(&self) -> Result<OwnerLockState> {
        let stat = match statat(&self.root, "runtime.lock", AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) => return Ok(OwnerLockState::Missing),
            Err(_) => return Err(DoctorError::Read),
        };
        private_regular(&stat)?;
        if stat.st_size > 1024 {
            return Err(DoctorError::Limit);
        }
        let file = File::from(
            openat(
                &self.root,
                "runtime.lock",
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| DoctorError::Path)?,
        );
        let actual = file.metadata().map_err(|_| DoctorError::Read)?;
        if (actual.dev(), actual.ino()) != stat_identity(&stat) {
            return Err(DoctorError::Path);
        }
        match Flock::lock(file, FlockArg::LockSharedNonblock) {
            Ok(_lock) => Ok(OwnerLockState::Available),
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => Ok(OwnerLockState::Busy),
            Err(_) => Ok(OwnerLockState::Unknown),
        }
    }
}
#[allow(clippy::unnecessary_cast)] // Stat integer widths differ on Linux/macOS.
fn stat_identity(stat: &Stat) -> (u64, u64) {
    (stat.st_dev as u64, stat.st_ino as u64)
}

fn is_oversized(stat: &Stat) -> bool {
    u64::try_from(stat.st_size).map_or(true, |length| length > MAX_FILE_BYTES as u64)
}

fn private_regular(stat: &Stat) -> Result<()> {
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || stat.st_mode & 0o077 != 0
        || stat.st_nlink != 1
        || stat.st_uid != rustix::process::getuid().as_raw()
    {
        return Err(DoctorError::Path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Runtime, RuntimeLimits};
    use std::os::unix::fs::symlink;
    #[test]
    fn replacement_and_new_unsafe_sidecars_are_refused_by_recheck() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().join("runtime");
        drop(Runtime::open(&root, RuntimeLimits::default()).unwrap());
        let files = Files::open(&root).unwrap();
        let db = root.join("runtime.sqlite3");
        let retained = root.join("retained");
        std::fs::rename(&db, &retained).unwrap();
        std::fs::copy(&retained, &db).unwrap();
        assert!(matches!(files.check(), Err(DoctorError::Path)));
        std::fs::remove_file(&db).unwrap();
        std::fs::rename(&retained, &db).unwrap();
        files.check().unwrap();
        symlink(&db, root.join("runtime.sqlite3-shm")).unwrap();
        assert!(matches!(files.check(), Err(DoctorError::Path)));
    }
}
