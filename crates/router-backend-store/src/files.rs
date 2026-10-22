use crate::{MAX_SNAPSHOT_BYTES, Result, StoreError};
use std::{fs::File, path::Path};

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
        lock_identity: (u64, u64),
    }
    pub(crate) struct Guard {
        _file: File,
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
            let parent = path.parent().ok_or(StoreError::Path)?;
            let name = path.file_name().ok_or(StoreError::Path)?;
            let parent = traverse(parent)?;
            mkdirat(&parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(|error| {
                if error == rustix::io::Errno::EXIST {
                    StoreError::Exists
                } else {
                    StoreError::Io
                }
            })?;
            let directory = open_directory(&parent, name)?;
            check_directory(&directory)?;
            let lock = create_file(&directory, "activation.lock")?;
            lock.sync_all().map_err(|_| StoreError::Io)?;
            directory.sync_all().map_err(|_| StoreError::Io)?;
            parent.sync_all().map_err(|_| StoreError::Io)?;
            let metadata = lock.metadata().map_err(|_| StoreError::Io)?;
            Ok(Self {
                directory,
                lock_identity: (metadata.dev(), metadata.ino()),
            })
        }
        pub(crate) fn open(path: &Path) -> Result<Self> {
            let directory = traverse(path)?;
            check_directory(&directory)?;
            let lock = private_file(&directory, "activation.lock")?;
            let metadata = lock.metadata().map_err(|_| StoreError::Io)?;
            Ok(Self {
                directory,
                lock_identity: (metadata.dev(), metadata.ino()),
            })
        }
        pub(crate) fn lock(&self, exclusive: bool) -> Result<Guard> {
            check_directory(&self.directory)?;
            let file = private_file(&self.directory, "activation.lock")?;
            let metadata = file.metadata().map_err(|_| StoreError::Io)?;
            if (metadata.dev(), metadata.ino()) != self.lock_identity {
                return Err(StoreError::Integrity);
            }
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
                    StoreError::Io
                }
            })?;
            let guard = Guard { _file: file };
            // Detect observed replacement before admitting a reader/writer.
            let named = private_file(&self.directory, "activation.lock")?
                .metadata()
                .map_err(|_| StoreError::Io)?;
            if (named.dev(), named.ino()) != self.lock_identity {
                return Err(StoreError::Integrity);
            }
            Ok(guard)
        }
        pub(crate) fn read(&self) -> Result<Vec<u8>> {
            let file = private_file(&self.directory, "state.json")?;
            if file.metadata().map_err(|_| StoreError::Io)?.len() > MAX_SNAPSHOT_BYTES as u64 {
                return Err(StoreError::Limit);
            }
            let mut bytes = Vec::new();
            file.take(MAX_SNAPSHOT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| StoreError::Io)?;
            if bytes.len() > MAX_SNAPSHOT_BYTES {
                return Err(StoreError::Limit);
            }
            Ok(bytes)
        }
        /// Caller retains the exclusive lock through durable publication.
        pub(crate) fn commit(&self, bytes: &[u8], expected: Option<&[u8]>) -> Result<()> {
            if bytes.len() > MAX_SNAPSHOT_BYTES {
                return Err(StoreError::Limit);
            }
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
                    .map_err(|_| StoreError::Io)?,
                Err(StoreError::Missing) => {}
                Err(error) => return Err(error),
            }
            let mut file = create_file(&self.directory, "state.pending")?;
            file.write_all(bytes).map_err(|_| StoreError::Io)?;
            file.sync_all().map_err(|_| StoreError::Io)?;
            // Recheck the preimage after staging before the sole publication.
            if let Some(expected) = expected {
                if self.read()? != expected {
                    return Err(StoreError::Conflict);
                }
            }
            publish(
                || {
                    renameat(
                        &self.directory,
                        "state.pending",
                        &self.directory,
                        "state.json",
                    )
                    .map_err(|_| ())
                },
                || self.directory.sync_all().map_err(|_| ()),
            )
        }
    }
    /// A failed rename published nothing (`Io`). Once the rename succeeded the new
    /// head is visible, so a failed directory sync is `PublishedDurabilityUnknown`:
    /// callers must reopen and inspect the head, never retry blindly.
    fn publish(
        rename: impl FnOnce() -> std::result::Result<(), ()>,
        sync: impl FnOnce() -> std::result::Result<(), ()>,
    ) -> Result<()> {
        rename().map_err(|()| StoreError::Io)?;
        sync().map_err(|()| StoreError::PublishedDurabilityUnknown)
    }
    fn traverse(path: &Path) -> Result<File> {
        if !path.is_absolute() || path.as_os_str().len() > 4096 {
            return Err(StoreError::Path);
        }
        let mut file = File::open("/").map_err(|_| StoreError::Io)?;
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => file = open_directory(&file, name)?,
                _ => return Err(StoreError::Path),
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
        .map_err(|_| StoreError::Path)
    }
    fn check_directory(file: &File) -> Result<()> {
        let metadata = file.metadata().map_err(|_| StoreError::Io)?;
        if !metadata.is_dir()
            || metadata.mode() & 0o7777 != 0o700
            || metadata.uid() != rustix::process::getuid().as_raw()
        {
            return Err(StoreError::Permissions);
        }
        Ok(())
    }
    fn check_file(file: &File) -> Result<()> {
        let metadata = file.metadata().map_err(|_| StoreError::Io)?;
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
                StoreError::Path
            }
        })?;
        check_file(&file)?;
        Ok(file)
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
        .map_err(|_| StoreError::Io)?;
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

        #[test]
        fn only_a_sync_failure_after_rename_is_durability_unknown() {
            assert!(matches!(publish(|| Ok(()), || Ok(())), Ok(())));
            assert!(matches!(
                publish(|| Err(()), || Ok(())),
                Err(StoreError::Io)
            ));
            assert!(matches!(
                publish(|| Ok(()), || Err(())),
                Err(StoreError::PublishedDurabilityUnknown)
            ));
            // A failed rename must never reach the directory sync.
            let mut synced = false;
            let _ = publish(
                || Err(()),
                || {
                    synced = true;
                    Ok(())
                },
            );
            assert!(!synced);
        }
    }
}
#[cfg(unix)]
pub(crate) use unix::{Guard, Root};

#[cfg(not(unix))]
pub(crate) struct Root;
#[cfg(not(unix))]
pub(crate) struct Guard;
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
    pub(crate) fn commit(&self, _: &[u8], _: Option<&[u8]>) -> Result<()> {
        Err(StoreError::Unsupported)
    }
}
