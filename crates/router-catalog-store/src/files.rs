use crate::{MAX_SNAPSHOT_BYTES, Operation, Result, StoreError};
use std::path::Path;
#[cfg(unix)]
use std::{fs::File, path::PathBuf};

/// Wrap an OS error with the failed operation. The errno is diagnostic only
/// and carries no path, key or document content.
pub(crate) fn io<E: Into<std::io::Error>>(operation: Operation) -> impl FnOnce(E) -> StoreError {
    move |error| StoreError::Io {
        operation,
        errno: error.into().raw_os_error(),
    }
}
pub(crate) fn path_error<E: Into<std::io::Error>>(
    operation: Operation,
) -> impl FnOnce(E) -> StoreError {
    move |error| StoreError::Path {
        operation,
        errno: error.into().raw_os_error(),
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use rustix::fs::{
        AtFlags, FlockOperation, Mode, OFlags, flock, mkdirat, openat, renameat, unlinkat,
    };
    use std::{
        io::{Read, Write},
        os::unix::fs::MetadataExt,
        path::Component,
    };

    pub(crate) struct Root {
        directory: File,
        path: PathBuf,
        lock_identity: (u64, u64),
    }
    pub(crate) struct Guard {
        _file: File,
        directory: File,
        path: PathBuf,
        exclusive: bool,
    }
    impl Guard {
        /// A lock protects cooperating users only while its named inode and
        /// containing directory still identify the descriptors held here.
        pub(crate) fn validate_identity(&self) -> Result<()> {
            check_directory(&self.directory)?;
            check_file(&self._file)?;
            let directory = traverse(&self.path)?;
            check_directory(&directory)?;
            let named = directory.metadata().map_err(io(Operation::Stat))?;
            let original = self.directory.metadata().map_err(io(Operation::Stat))?;
            if (named.dev(), named.ino()) != (original.dev(), original.ino()) {
                return Err(StoreError::Integrity);
            }
            let named = private_file(&directory, "catalog.lock")?
                .metadata()
                .map_err(io(Operation::Stat))?;
            let original = self._file.metadata().map_err(io(Operation::Stat))?;
            if (named.dev(), named.ino()) != (original.dev(), original.ino()) {
                return Err(StoreError::Integrity);
            }
            Ok(())
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            // A concurrent fork may retain this open file description until
            // exec despite CLOEXEC. End authority at the guard's lifetime,
            // rather than waiting for every inherited descriptor to close.
            let _ = flock(&self._file, FlockOperation::Unlock);
        }
    }
    impl Root {
        pub(crate) fn create(path: &Path) -> Result<Self> {
            let parent = path.parent().ok_or(StoreError::path(Operation::Locator))?;
            let name = path
                .file_name()
                .ok_or(StoreError::path(Operation::Locator))?;
            let parent = traverse(parent)?;
            let fresh = match mkdirat(&parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                Ok(()) => true,
                Err(rustix::io::Errno::EXIST) => false,
                Err(error) => return Err(io(Operation::Mkdir)(error)),
            };
            // A crash after mkdir leaves a private directory with at most the
            // lock and one staging file. Adopt only that shape; anything else
            // is a foreign or already published store.
            let directory = match open_directory(&parent, name) {
                Ok(directory) => directory,
                Err(_) if !fresh => return Err(StoreError::Exists),
                Err(error) => return Err(error),
            };
            if !fresh {
                if check_directory(&directory).is_err() {
                    return Err(StoreError::Exists);
                }
                ensure_resumable(&directory)?;
            } else {
                check_directory(&directory)?;
            }
            let lock = match private_file(&directory, "catalog.lock") {
                Ok(lock) => lock,
                Err(StoreError::Missing) => create_file(&directory, "catalog.lock")?,
                Err(error) => return Err(error),
            };
            lock.sync_all().map_err(io(Operation::Fsync))?;
            directory.sync_all().map_err(io(Operation::Fsync))?;
            parent.sync_all().map_err(io(Operation::Fsync))?;
            let metadata = lock.metadata().map_err(io(Operation::Stat))?;
            Ok(Self {
                directory,
                path: path.to_path_buf(),
                lock_identity: (metadata.dev(), metadata.ino()),
            })
        }
        pub(crate) fn open(path: &Path) -> Result<Self> {
            let directory = traverse(path)?;
            check_directory(&directory)?;
            let lock = private_file(&directory, "catalog.lock")?;
            let metadata = lock.metadata().map_err(io(Operation::Stat))?;
            Ok(Self {
                directory,
                path: path.to_path_buf(),
                lock_identity: (metadata.dev(), metadata.ino()),
            })
        }
        pub(crate) fn lock(&self, exclusive: bool) -> Result<Guard> {
            check_directory(&self.directory)?;
            let named = traverse(&self.path)?
                .metadata()
                .map_err(io(Operation::Stat))?;
            let original = self.directory.metadata().map_err(io(Operation::Stat))?;
            if (named.dev(), named.ino()) != (original.dev(), original.ino()) {
                return Err(StoreError::Integrity);
            }
            let file = private_file(&self.directory, "catalog.lock")?;
            let metadata = file.metadata().map_err(io(Operation::Stat))?;
            if (metadata.dev(), metadata.ino()) != self.lock_identity {
                return Err(StoreError::Integrity);
            }
            let directory = self.directory.try_clone().map_err(io(Operation::Open))?;
            flock(
                &file,
                if exclusive {
                    FlockOperation::NonBlockingLockExclusive
                } else {
                    FlockOperation::NonBlockingLockShared
                },
            )
            .map_err(|error| {
                if error == rustix::io::Errno::WOULDBLOCK {
                    StoreError::Busy
                } else {
                    io(Operation::Lock)(error)
                }
            })?;
            let guard = Guard {
                _file: file,
                directory,
                path: self.path.clone(),
                exclusive,
            };
            // Detect observed replacement before admitting a reader/writer.
            guard.validate_identity()?;
            Ok(guard)
        }
        pub(crate) fn read(&self) -> Result<Vec<u8>> {
            let file = private_file(&self.directory, "state.json")?;
            if file.metadata().map_err(io(Operation::Stat))?.len() > MAX_SNAPSHOT_BYTES as u64 {
                return Err(StoreError::Limit);
            }
            let mut bytes = Vec::new();
            file.take(MAX_SNAPSHOT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(io(Operation::Read))?;
            if bytes.len() > MAX_SNAPSHOT_BYTES {
                return Err(StoreError::Limit);
            }
            Ok(bytes)
        }
        /// Caller retains the exclusive lock through durable publication.
        ///
        /// A failure before the rename leaves the previous state published. A
        /// failure of the final directory fsync returns
        /// `PublishedDurabilityUnknown`: the new state is visible but its
        /// durability is UNKNOWN, and the caller must not retry blindly.
        pub(crate) fn commit(
            &self,
            guard: &Guard,
            bytes: &[u8],
            expected: Option<&[u8]>,
        ) -> Result<()> {
            self.commit_with(guard, bytes, expected, &|directory| directory.sync_all())
        }
        fn commit_with(
            &self,
            guard: &Guard,
            bytes: &[u8],
            expected: Option<&[u8]>,
            sync_directory: &dyn Fn(&File) -> std::io::Result<()>,
        ) -> Result<()> {
            if bytes.len() > MAX_SNAPSHOT_BYTES {
                return Err(StoreError::Limit);
            }
            self.check_writer(guard)?;
            if let Some(expected) = expected {
                if self.read()? != expected {
                    return Err(StoreError::Conflict);
                }
            } else {
                match openat(
                    &self.directory,
                    "state.json",
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                    Mode::empty(),
                ) {
                    Err(rustix::io::Errno::NOENT) => {}
                    _ => return Err(StoreError::Exists),
                }
            }
            // A crashed writer may leave this one staging file. Remove only a
            // verified private regular file, under the exclusive store lock.
            match private_file(&self.directory, "state.pending") {
                Ok(_) => unlinkat(&self.directory, "state.pending", AtFlags::empty())
                    .map_err(io(Operation::Unlink))?,
                Err(StoreError::Missing) => {}
                Err(error) => return Err(error),
            }
            let mut file = create_file(&self.directory, "state.pending")?;
            file.write_all(bytes).map_err(io(Operation::Write))?;
            file.sync_all().map_err(io(Operation::Fsync))?;
            // Recheck the preimage after staging before the sole publication.
            if let Some(expected) = expected {
                if self.read()? != expected {
                    return Err(StoreError::Conflict);
                }
            }
            // The named directory and lock must still be the ones this guard
            // holds when the state is published, not only when it was locked.
            guard.validate_identity()?;
            renameat(
                &self.directory,
                "state.pending",
                &self.directory,
                "state.json",
            )
            .map_err(io(Operation::Rename))?;
            sync_directory(&self.directory).map_err(|_| StoreError::PublishedDurabilityUnknown)
        }
        fn check_writer(&self, guard: &Guard) -> Result<()> {
            if !guard.exclusive {
                return Err(StoreError::Authority);
            }
            let held = guard.directory.metadata().map_err(io(Operation::Stat))?;
            let root = self.directory.metadata().map_err(io(Operation::Stat))?;
            if (held.dev(), held.ino()) != (root.dev(), root.ino()) {
                return Err(StoreError::Integrity);
            }
            guard.validate_identity()
        }
    }
    /// A directory left by a crashed `create` holds at most the lock and one
    /// staging file, and never a published `state.json`.
    fn ensure_resumable(directory: &File) -> Result<()> {
        let entries = rustix::fs::Dir::read_from(directory).map_err(io(Operation::List))?;
        for entry in entries {
            let entry = entry.map_err(io(Operation::List))?;
            match entry.file_name().to_bytes() {
                b"." | b".." | b"catalog.lock" | b"state.pending" => {}
                _ => return Err(StoreError::Exists),
            }
        }
        Ok(())
    }
    fn traverse(path: &Path) -> Result<File> {
        if !path.is_absolute() || path.as_os_str().len() > 4096 {
            return Err(StoreError::path(Operation::Locator));
        }
        let mut file = File::open("/").map_err(io(Operation::Open))?;
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => file = open_directory(&file, name)?,
                _ => return Err(StoreError::path(Operation::Locator)),
            }
        }
        Ok(file)
    }
    fn open_directory(parent: &File, name: &std::ffi::OsStr) -> Result<File> {
        openat(
            parent,
            name,
            OFlags::RDONLY
                | OFlags::DIRECTORY
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(path_error(Operation::Traverse))
    }
    fn check_directory(file: &File) -> Result<()> {
        let metadata = file.metadata().map_err(io(Operation::Stat))?;
        if !metadata.is_dir()
            || metadata.mode() & 0o7777 != 0o700
            || metadata.uid() != rustix::process::getuid().as_raw()
        {
            return Err(StoreError::Permissions);
        }
        Ok(())
    }
    fn check_file(file: &File) -> Result<()> {
        let metadata = file.metadata().map_err(io(Operation::Stat))?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.uid() != rustix::process::getuid().as_raw()
        {
            return Err(StoreError::Permissions);
        }
        Ok(())
    }
    fn private_file(directory: &File, name: &str) -> Result<File> {
        let file = openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            if error == rustix::io::Errno::NOENT {
                StoreError::Missing
            } else {
                path_error(Operation::Open)(error)
            }
        })?;
        check_file(&file)?;
        Ok(file)
    }
    pub(super) fn read_private_external(path: &Path, limit: usize) -> Result<Vec<u8>> {
        let parent = path.parent().ok_or(StoreError::path(Operation::Locator))?;
        let name = path
            .file_name()
            .ok_or(StoreError::path(Operation::Locator))?;
        let directory = traverse(parent)?;
        let file = private_file(
            &directory,
            name.to_str().ok_or(StoreError::path(Operation::Locator))?,
        )?;
        if file.metadata().map_err(io(Operation::Stat))?.len() > limit as u64 {
            return Err(StoreError::Limit);
        }
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io(Operation::Read))?;
        if bytes.len() > limit {
            return Err(StoreError::Limit);
        }
        Ok(bytes)
    }
    fn create_file(directory: &File, name: &str) -> Result<File> {
        let file = openat(
            directory,
            name,
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
        .map_err(io(Operation::Create))?;
        check_file(&file)?;
        Ok(file)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn releasing_guard_unlocks_even_with_an_inherited_file_description() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().canonicalize().unwrap().join("store");
            let root = Root::create(&path).unwrap();
            let guard = root.lock(false).unwrap();
            // dup, like fork before exec, retains the same open file description.
            // CLOEXEC alone does not release that inherited reference yet.
            let inherited = guard._file.try_clone().unwrap();
            assert!(matches!(root.lock(true), Err(StoreError::Busy)));
            drop(guard);
            let writer = root.lock(true).expect("guard lifetime ends the lock");
            drop(inherited);
            assert!(matches!(root.lock(false), Err(StoreError::Busy)));
            drop(writer);
            assert!(root.lock(false).is_ok());
        }

        fn fresh_root() -> (tempfile::TempDir, PathBuf, Root) {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().canonicalize().unwrap().join("store");
            let root = Root::create(&path).unwrap();
            (temp, path, root)
        }

        #[test]
        fn failed_directory_sync_after_rename_reports_published_durability_unknown() {
            let (_temp, path, root) = fresh_root();
            let guard = root.lock(true).unwrap();
            let error = root
                .commit_with(&guard, b"published", None, &|_| {
                    Err(std::io::Error::other("fsync"))
                })
                .unwrap_err();
            assert!(matches!(error, StoreError::PublishedDurabilityUnknown));
            // The rename happened: the new state is visible despite the error.
            assert_eq!(
                std::fs::read(path.join("state.json")).unwrap(),
                b"published"
            );
            // A failure before publication stays a plain, distinct I/O failure.
            std::fs::remove_file(path.join("state.json")).unwrap();
            std::fs::create_dir(path.join("state.pending")).unwrap();
            let error = root.commit(&guard, b"never", None).unwrap_err();
            assert!(!matches!(error, StoreError::PublishedDurabilityUnknown));
            assert!(!path.join("state.json").exists());
        }

        #[test]
        fn commit_revalidates_guard_identity_and_requires_the_exclusive_lock() {
            let (temp, path, root) = fresh_root();
            {
                let shared = root.lock(false).unwrap();
                assert!(matches!(
                    root.commit(&shared, b"x", None),
                    Err(StoreError::Authority)
                ));
            }
            let guard = root.lock(true).unwrap();
            let moved = temp.path().join("moved");
            std::fs::rename(&path, &moved).unwrap();
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .unwrap();
            assert!(matches!(
                root.commit(&guard, b"x", None),
                Err(StoreError::Integrity)
            ));
            assert!(!moved.join("state.json").exists());
            assert!(!path.join("state.json").exists());
        }
    }
}
#[cfg(unix)]
pub(crate) use unix::{Guard, Root};

#[cfg(unix)]
pub(crate) fn read_private_external(path: &Path, limit: usize) -> Result<Vec<u8>> {
    unix::read_private_external(path, limit)
}

#[cfg(not(unix))]
pub(crate) struct Root;
#[cfg(not(unix))]
pub(crate) struct Guard;
#[cfg(not(unix))]
impl Guard {
    pub(crate) fn validate_identity(&self) -> Result<()> {
        Err(StoreError::Unsupported)
    }
}
#[cfg(not(unix))]
impl Root {
    pub(crate) fn create(_: &Path) -> Result<Self> {
        Err(StoreError::Unsupported)
    }
    pub(crate) fn open(_: &Path) -> Result<Self> {
        Err(StoreError::Unsupported)
    }
    pub(crate) fn lock(&self, _: bool) -> Result<Guard> {
        Err(StoreError::Unsupported)
    }
    pub(crate) fn read(&self) -> Result<Vec<u8>> {
        Err(StoreError::Unsupported)
    }
    pub(crate) fn commit(&self, _: &Guard, _: &[u8], _: Option<&[u8]>) -> Result<()> {
        Err(StoreError::Unsupported)
    }
}
#[cfg(not(unix))]
pub(crate) fn read_private_external(_: &Path, _: usize) -> Result<Vec<u8>> {
    Err(StoreError::Unsupported)
}
