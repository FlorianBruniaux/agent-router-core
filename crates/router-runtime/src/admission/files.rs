use crate::{Result, RuntimeError, outputs::FileIdentity};
use nix::fcntl::{Flock, FlockArg};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat, openat, statat};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub(super) struct Files {
    pub path: PathBuf,
    dir: File,
    identity: FileIdentity,
    db_identity: FileIdentity,
}
pub(super) struct Owner(Option<Flock<File>>);
impl Drop for Owner {
    fn drop(&mut self) {
        if let Some(lock) = self.0.take() {
            let _ = lock.unlock();
        }
    }
}
impl Files {
    pub fn open(root: &Path, create: bool) -> Result<Self> {
        if !root.is_absolute() {
            return Err(RuntimeError::Invalid("admission registry path"));
        }
        if create {
            std::fs::DirBuilder::new().mode(0o700).create(root)?;
        }
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(root)?;
        if dir.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(RuntimeError::Invalid("admission private directory"));
        }
        let path = std::fs::canonicalize(root)?;
        let identity = FileIdentity::from_file(&dir)?;
        // A second open/close of an inode used by SQLite releases this process's
        // POSIX locks, even when SQLite's own descriptor remains open.
        if create {
            drop(private(&dir, "admission.sqlite3", true)?);
        }
        let db_identity = stat_identity(&private_stat(&dir, "admission.sqlite3")?);
        // SQLite creates its auxiliaries with the private database mode. Never
        // open/close existing WAL or SHM descriptors outside SQLite.
        check_auxiliaries(&dir)?;
        Ok(Self {
            path,
            dir,
            identity,
            db_identity,
        })
    }
    pub fn binding_hash(&self) -> Result<String> {
        crate::digest(
            "runtime-admission-registry-v1",
            &(&self.path, &self.identity, &self.db_identity),
        )
    }
    pub fn check(&self) -> Result<()> {
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(&self.path)?;
        if !self.identity.matches(&dir)? || dir.metadata()?.permissions().mode() & 0o077 != 0 || {
            let identity = stat_identity(&private_stat(&dir, "admission.sqlite3")?);
            self.db_identity.device != identity.device || self.db_identity.inode != identity.inode
        } {
            return Err(RuntimeError::Integrity("admission registry replaced"));
        }
        check_auxiliaries(&dir)?;
        Ok(())
    }
    fn owner_file(&self, id: &str) -> Result<File> {
        private(
            &self.dir,
            &format!("{}.owner", crate::digest("admission-owner-v1", &id)?),
            true,
        )
    }
    pub fn budget_guard(&self, shared: bool) -> Result<Owner> {
        self.check()?;
        let file = private(&self.dir, "session-budget.lock", true)?;
        Ok(Owner(Some(
            Flock::lock(
                file,
                if shared {
                    FlockArg::LockSharedNonblock
                } else {
                    FlockArg::LockExclusiveNonblock
                },
            )
            .map_err(|_| RuntimeError::Locked)?,
        )))
    }
    pub fn owner(&self, id: &str) -> Result<Owner> {
        Ok(Owner(Some(
            Flock::lock(self.owner_file(id)?, FlockArg::LockExclusiveNonblock)
                .map_err(|_| RuntimeError::Locked)?,
        )))
    }
    pub fn owner_alive(&self, id: &str) -> Result<bool> {
        match Flock::lock(self.owner_file(id)?, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => {
                lock.unlock().map_err(|_| RuntimeError::Locked)?;
                Ok(false)
            }
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => Ok(true),
            Err(_) => Err(RuntimeError::Locked),
        }
    }
}
fn private(dir: &File, name: &str, create: bool) -> Result<File> {
    let flags = OFlags::RDWR
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | OFlags::CLOEXEC
        | if create {
            OFlags::CREATE
        } else {
            OFlags::empty()
        };
    let file = File::from(
        openat(dir, name, flags, Mode::RUSR | Mode::WUSR).map_err(std::io::Error::from)?,
    );
    let m = file.metadata()?;
    if !m.is_file() || m.nlink() != 1 || m.permissions().mode() & 0o077 != 0 {
        return Err(RuntimeError::Invalid("admission private file"));
    }
    Ok(file)
}

#[allow(clippy::unnecessary_cast)] // Stat integer widths differ on Linux/macOS.
fn stat_identity(stat: &Stat) -> FileIdentity {
    FileIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    }
}
fn private_stat(dir: &File, name: &str) -> Result<Stat> {
    let stat = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(std::io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_mode & 0o077 != 0
    {
        return Err(RuntimeError::Invalid("admission private file"));
    }
    Ok(stat)
}
fn check_auxiliaries(dir: &File) -> Result<()> {
    for name in ["admission.sqlite3-wal", "admission.sqlite3-shm"] {
        match private_stat(dir, name) {
            Ok(_) => {}
            Err(RuntimeError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
