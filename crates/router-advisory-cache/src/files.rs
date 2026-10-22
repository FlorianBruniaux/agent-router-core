//! Private, immutable entry files. Unix only; other platforms report Unsupported.
use crate::{CacheError, MAX_ENTRIES, MAX_ENTRY_BYTES, Result};
use std::{fs::File, path::Path};

#[cfg(unix)]
mod unix {
    use super::*;
    use rustix::fs::{
        AtFlags, Dir, FlockOperation, Mode, OFlags, flock, mkdirat, openat, renameat, unlinkat,
    };
    use std::{
        io::{Read, Write},
        os::unix::fs::MetadataExt,
        path::Component,
    };

    const STAGING: &str = "staging.pending";
    const LOCK: &str = "cache.lock";

    pub(crate) struct Root {
        directory: File,
    }
    impl Root {
        pub(crate) fn create(path: &Path) -> Result<Self> {
            let parent = path.parent().ok_or(CacheError::Path)?;
            let name = path.file_name().ok_or(CacheError::Path)?;
            let parent = traverse(parent)?;
            mkdirat(&parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(|error| {
                if error == rustix::io::Errno::EXIST {
                    CacheError::Exists
                } else {
                    CacheError::Io
                }
            })?;
            let directory = open_directory(&parent, name)?;
            check_directory(&directory)?;
            parent.sync_all().map_err(|_| CacheError::Io)?;
            Ok(Self { directory })
        }
        pub(crate) fn open(path: &Path) -> Result<Self> {
            let directory = traverse(path)?;
            check_directory(&directory)?;
            Ok(Self { directory })
        }
        /// Reads at most MAX_ENTRY_BYTES; a missing file is `Ok(None)`.
        pub(crate) fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
            check_directory(&self.directory)?;
            let file = match openat(
                &self.directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            ) {
                Ok(file) => File::from(file),
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                Err(_) => return Err(CacheError::Path),
            };
            check_file(&file)?;
            let mut bytes = Vec::new();
            file.take(MAX_ENTRY_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| CacheError::Io)?;
            if bytes.len() > MAX_ENTRY_BYTES {
                return Err(CacheError::Limit);
            }
            Ok(Some(bytes))
        }
        /// Publishes an entry under an exclusive directory lock, so writers are
        /// serialized. An existing entry is kept unless it is unreadable or
        /// `may_replace` accepts it (expired, malformed or unauthenticated).
        /// A kept entry yields `Exists`, so a live entry is never overwritten.
        /// When the directory is full, entries for which `is_stale(key, bytes)`
        /// holds are removed first; only then is `Limit` reported.
        pub(crate) fn publish(
            &self,
            name: &str,
            bytes: &[u8],
            may_replace: &dyn Fn(&[u8]) -> bool,
            is_stale: &dyn Fn(&str, &[u8]) -> bool,
        ) -> Result<()> {
            check_directory(&self.directory)?;
            if bytes.len() > MAX_ENTRY_BYTES {
                return Err(CacheError::Limit);
            }
            let _guard = self.lock()?;
            let replacing = match self.read(name) {
                Ok(None) => false,
                Ok(Some(existing)) => {
                    if !may_replace(&existing) {
                        return Err(CacheError::Exists);
                    }
                    true
                }
                // A symlink, wrong mode or oversized file cannot be a valid
                // entry. rename replaces the name itself, never a link target.
                Err(CacheError::Path | CacheError::Permissions | CacheError::Limit) => true,
                Err(error) => return Err(error),
            };
            if !replacing && self.count()? >= MAX_ENTRIES {
                self.sweep(is_stale)?;
                if self.count()? >= MAX_ENTRIES {
                    return Err(CacheError::Limit);
                }
            }
            // Only the lock holder writes staging files, so any that remain
            // were orphaned by a crashed writer. unlinkat never follows a link.
            self.purge_staging()?;
            let file = openat(
                &self.directory,
                STAGING,
                OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| CacheError::Io)?;
            let mut file = File::from(file);
            check_file(&file)?;
            file.write_all(bytes).map_err(|_| CacheError::Io)?;
            file.sync_all().map_err(|_| CacheError::Io)?;
            renameat(&self.directory, STAGING, &self.directory, name)
                .map_err(|_| CacheError::Io)?;
            self.directory.sync_all().map_err(|_| CacheError::Io)
        }
        fn lock(&self) -> Result<Guard> {
            let flags = OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
            let mut opened = None;
            // Open first, create exclusively only when missing. A concurrent
            // O_CREAT open can report ENOENT spuriously (seen on macOS), so a
            // lost creation race is retried rather than reported.
            for _ in 0..8 {
                match openat(&self.directory, LOCK, flags, Mode::empty()) {
                    Ok(file) => {
                        opened = Some(File::from(file));
                        break;
                    }
                    Err(rustix::io::Errno::NOENT) => {
                        let _ = openat(
                            &self.directory,
                            LOCK,
                            flags | OFlags::CREATE | OFlags::EXCL,
                            Mode::RUSR | Mode::WUSR,
                        );
                    }
                    Err(_) => return Err(CacheError::Path),
                }
            }
            let file = opened.ok_or(CacheError::Io)?;
            check_file(&file)?;
            flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
                if error == rustix::io::Errno::WOULDBLOCK {
                    CacheError::Busy
                } else {
                    CacheError::Io
                }
            })?;
            Ok(Guard { file })
        }
        /// A fresh descriptor, so the scan never shares an offset with another.
        fn names(&self, mut visit: impl FnMut(&str) -> bool) -> Result<()> {
            let handle = openat(
                &self.directory,
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| CacheError::Io)?;
            for entry in Dir::read_from(handle).map_err(|_| CacheError::Io)? {
                let entry = entry.map_err(|_| CacheError::Io)?;
                if let Ok(name) = entry.file_name().to_str() {
                    if !visit(name) {
                        break;
                    }
                }
            }
            Ok(())
        }
        /// Counts published entries only, never staging or lock files.
        fn count(&self) -> Result<usize> {
            let mut count = 0usize;
            self.names(|name| {
                if name.ends_with(".json") {
                    count += 1;
                }
                count <= MAX_ENTRIES
            })?;
            Ok(count)
        }
        /// Removes entries `is_stale` rejects. Unreadable or unstale files stay.
        fn sweep(&self, is_stale: &dyn Fn(&str, &[u8]) -> bool) -> Result<()> {
            let mut names = Vec::new();
            self.names(|name| {
                if name.ends_with(".json") {
                    names.push(name.to_owned());
                }
                names.len() <= MAX_ENTRIES
            })?;
            for name in names {
                let Some(key) = name.strip_suffix(".json") else {
                    continue;
                };
                if let Ok(Some(bytes)) = self.read(&name) {
                    if is_stale(key, &bytes) {
                        unlinkat(&self.directory, name.as_str(), AtFlags::empty())
                            .map_err(|_| CacheError::Io)?;
                    }
                }
            }
            Ok(())
        }
        fn purge_staging(&self) -> Result<()> {
            let mut orphans = Vec::new();
            self.names(|name| {
                if name.ends_with(".pending") && orphans.len() < MAX_ENTRIES {
                    orphans.push(name.to_owned());
                }
                true
            })?;
            for name in orphans {
                unlinkat(&self.directory, name.as_str(), AtFlags::empty())
                    .map_err(|_| CacheError::Io)?;
            }
            Ok(())
        }
    }
    struct Guard {
        file: File,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            // End authority at the guard's lifetime even if a forked child
            // still holds this open file description.
            let _ = flock(&self.file, FlockOperation::Unlock);
        }
    }
    fn traverse(path: &Path) -> Result<File> {
        if !path.is_absolute() || path.as_os_str().len() > 4096 {
            return Err(CacheError::Path);
        }
        let mut file = File::open("/").map_err(|_| CacheError::Io)?;
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => file = open_directory(&file, name)?,
                _ => return Err(CacheError::Path),
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
        .map_err(|_| CacheError::Path)
    }
    fn check_directory(file: &File) -> Result<()> {
        let metadata = file.metadata().map_err(|_| CacheError::Io)?;
        if !metadata.is_dir()
            || metadata.mode() & 0o7777 != 0o700
            || metadata.uid() != rustix::process::getuid().as_raw()
        {
            return Err(CacheError::Permissions);
        }
        Ok(())
    }
    fn check_file(file: &File) -> Result<()> {
        let metadata = file.metadata().map_err(|_| CacheError::Io)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.uid() != rustix::process::getuid().as_raw()
        {
            return Err(CacheError::Permissions);
        }
        Ok(())
    }
}
#[cfg(unix)]
pub(crate) use unix::Root;

#[cfg(not(unix))]
pub(crate) struct Root;
#[cfg(not(unix))]
impl Root {
    pub(crate) fn create(_: &Path) -> Result<Self> {
        Err(CacheError::Unsupported)
    }
    pub(crate) fn open(_: &Path) -> Result<Self> {
        Err(CacheError::Unsupported)
    }
    pub(crate) fn read(&self, _: &str) -> Result<Option<Vec<u8>>> {
        Err(CacheError::Unsupported)
    }
    pub(crate) fn publish(
        &self,
        _: &str,
        _: &[u8],
        _: &dyn Fn(&[u8]) -> bool,
        _: &dyn Fn(&str, &[u8]) -> bool,
    ) -> Result<()> {
        Err(CacheError::Unsupported)
    }
}
