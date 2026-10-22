//! Descriptor-relative O_NOFOLLOW traversal prevents concurrent parent symlink
//! replacement from redirecting reads. No directory is created or modified.

use crate::{DoctorError, Result};
use std::{
    fs::File,
    path::{Component, Path},
};

pub(crate) fn relative(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 2048
        && !path.contains(['\0', '\n', '\r', '\\'])
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

#[cfg(unix)]
pub(crate) struct ReadRoot(File);
#[cfg(not(unix))]
pub(crate) struct ReadRoot;

pub(crate) struct DatabaseMetadata {
    pub bytes: u64,
    pub private: bool,
}

#[cfg(unix)]
impl ReadRoot {
    pub(crate) fn open(path: &str) -> Result<Self> {
        if !Path::new(path).is_absolute() || path.len() > 4096 || path.contains('\0') {
            return Err(DoctorError::Path);
        }
        let mut directory = File::open("/").map_err(|_| DoctorError::Read)?;
        for part in Path::new(path).components() {
            match part {
                Component::RootDir => {}
                Component::Normal(name) => directory = open_at(&directory, name, true)?,
                _ => return Err(DoctorError::Path),
            }
        }
        Ok(Self(directory))
    }

    pub(crate) fn file(&self, path: &str) -> Result<File> {
        self.optional_file(path)?.ok_or(DoctorError::Read)
    }

    /// Opening and then closing any descriptor of a SQLite inode can release
    /// another connection's process-wide POSIX locks. Inspect only metadata.
    pub(crate) fn database_metadata(&self, path: &str) -> Result<DatabaseMetadata> {
        use rustix::fs::{AtFlags, FileType, statat};
        if !relative(path) {
            return Err(DoctorError::Path);
        }
        let mut directory = self.0.try_clone().map_err(|_| DoctorError::Read)?;
        let parts: Vec<_> = Path::new(path).components().collect();
        for (index, part) in parts.iter().enumerate() {
            let Component::Normal(name) = part else {
                return Err(DoctorError::Path);
            };
            if index + 1 == parts.len() {
                let stat = statat(&directory, *name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| DoctorError::Read)?;
                if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
                    return Err(DoctorError::Path);
                }
                return Ok(DatabaseMetadata {
                    bytes: stat.st_size.try_into().map_err(|_| DoctorError::Limit)?,
                    private: stat.st_mode & 0o077 == 0,
                });
            }
            directory = open_at(&directory, name, true)?;
        }
        Err(DoctorError::Path)
    }

    /// Distinguish a missing final entry from a rejected entry without following
    /// symlinks or reopening a parent by pathname.
    pub(crate) fn optional_file(&self, path: &str) -> Result<Option<File>> {
        if !relative(path) {
            return Err(DoctorError::Path);
        }
        let mut directory = self.0.try_clone().map_err(|_| DoctorError::Read)?;
        let parts: Vec<_> = Path::new(path).components().collect();
        for (index, part) in parts.iter().enumerate() {
            let Component::Normal(name) = part else {
                return Err(DoctorError::Path);
            };
            let last = index + 1 == parts.len();
            if last {
                use rustix::fs::{Mode, OFlags, openat};
                let file = match openat(
                    &directory,
                    *name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                ) {
                    Ok(file) => File::from(file),
                    Err(rustix::io::Errno::NOENT) => return Ok(None),
                    Err(error) => return Err(open_error(error, false)),
                };
                if !file.metadata().map_err(|_| DoctorError::Read)?.is_file() {
                    return Err(DoctorError::Path);
                }
                return Ok(Some(file));
            }
            directory = open_at(&directory, name, true)?;
        }
        Err(DoctorError::Path)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, io::Read, os::unix::fs::symlink, sync::mpsc, time::Duration};

    #[test]
    fn renamed_root_cannot_redirect_an_open_descriptor() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().canonicalize().unwrap();
        let original = parent.join("root");
        let outside = parent.join("outside");
        fs::create_dir(&original).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(original.join("artifact"), "original").unwrap();
        fs::write(outside.join("artifact"), "outside-secret").unwrap();
        let root = ReadRoot::open(original.to_str().unwrap()).unwrap();
        fs::rename(&original, parent.join("moved-root")).unwrap();
        symlink(&outside, &original).unwrap();
        assert_eq!(
            fs::read_to_string(original.join("artifact")).unwrap(),
            "outside-secret"
        );
        let mut content = String::new();
        root.file("artifact")
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "original");
        assert!(ReadRoot::open(original.to_str().unwrap()).is_err());
    }

    #[test]
    fn renamed_intermediate_directory_stays_bound_to_its_descriptor() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().canonicalize().unwrap();
        fs::create_dir(parent.join("inner")).unwrap();
        fs::create_dir(parent.join("outside")).unwrap();
        fs::write(parent.join("inner/artifact"), "original").unwrap();
        fs::write(parent.join("outside/artifact"), "outside-secret").unwrap();
        let root = ReadRoot::open(parent.to_str().unwrap()).unwrap();
        let directory = open_at(&root.0, std::ffi::OsStr::new("inner"), true).unwrap();
        fs::rename(parent.join("inner"), parent.join("moved-inner")).unwrap();
        symlink(parent.join("outside"), parent.join("inner")).unwrap();
        let mut content = String::new();
        open_at(&directory, std::ffi::OsStr::new("artifact"), false)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "original");
        assert!(root.file("inner/artifact").is_err());
    }

    #[test]
    fn symlinks_are_path_rejections_not_unreadable_files() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().canonicalize().unwrap();
        fs::create_dir(parent.join("real")).unwrap();
        fs::write(parent.join("real/artifact"), "content").unwrap();
        symlink(parent.join("real"), parent.join("linked")).unwrap();
        symlink(parent.join("real/artifact"), parent.join("leaf")).unwrap();
        let root = ReadRoot::open(parent.to_str().unwrap()).unwrap();
        assert!(matches!(root.file("leaf"), Err(DoctorError::Path)));
        assert!(matches!(
            root.file("linked/artifact"),
            Err(DoctorError::Path)
        ));
        assert!(matches!(
            ReadRoot::open(parent.join("linked").to_str().unwrap()),
            Err(DoctorError::Path)
        ));
        assert!(matches!(root.file("missing"), Err(DoctorError::Read)));
    }

    #[test]
    fn fifo_and_directory_are_rejected_without_waiting_for_a_writer() {
        use rustix::fs::{Mode, OFlags, openat};
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().canonicalize().unwrap();
        let root = ReadRoot::open(parent.to_str().unwrap()).unwrap();
        fs::create_dir(parent.join("directory")).unwrap();
        assert!(matches!(root.file("directory"), Err(DoctorError::Path)));
        // rustix exposes mkfifoat on Linux but not Apple platforms. Only test
        // fixture setup launches this POSIX utility; the reader never spawns.
        assert!(
            std::process::Command::new("mkfifo")
                .arg(parent.join("fifo"))
                .status()
                .unwrap()
                .success()
        );
        let directory = root.0.try_clone().unwrap();
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ = sender.send(matches!(root.file("fifo"), Err(DoctorError::Path)));
        });
        let result = receiver.recv_timeout(Duration::from_secs(5));
        if matches!(result, Err(mpsc::RecvTimeoutError::Timeout)) {
            // Unblock a regressed blocking reader before failing this test.
            let _writer = openat(
                &directory,
                "fifo",
                OFlags::WRONLY | OFlags::NONBLOCK,
                Mode::empty(),
            );
            panic!("FIFO read did not return without a writer");
        }
        assert_eq!(result, Ok(true));
        worker.join().unwrap();
    }
}

#[cfg(unix)]
fn open_at(directory: &File, name: &std::ffi::OsStr, is_directory: bool) -> Result<File> {
    use rustix::fs::{Mode, OFlags, openat};
    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    if is_directory {
        flags |= OFlags::DIRECTORY;
    }
    // The descriptor stays borrowed for the call. OwnedFd transfers ownership
    // to File without raw descriptor conversion or unsafe application code.
    openat(directory, name, flags, Mode::empty())
        .map(File::from)
        .map_err(|error| open_error(error, is_directory))
}

/// A symlink under `O_NOFOLLOW` is a rejected path, not an unreadable file.
/// Linux reports a symlink opened with `O_DIRECTORY` as `ENOTDIR`.
#[cfg(unix)]
fn open_error(error: rustix::io::Errno, is_directory: bool) -> DoctorError {
    use rustix::io::Errno;
    if error == Errno::LOOP || (is_directory && error == Errno::NOTDIR) {
        DoctorError::Path
    } else {
        DoctorError::Read
    }
}

#[cfg(not(unix))]
impl ReadRoot {
    pub(crate) fn open(_: &str) -> Result<Self> {
        Err(DoctorError::Unsupported)
    }
    pub(crate) fn file(&self, _: &str) -> Result<File> {
        Err(DoctorError::Unsupported)
    }
    pub(crate) fn optional_file(&self, _: &str) -> Result<Option<File>> {
        Err(DoctorError::Unsupported)
    }
    pub(crate) fn database_metadata(&self, _: &str) -> Result<DatabaseMetadata> {
        Err(DoctorError::Unsupported)
    }
}
