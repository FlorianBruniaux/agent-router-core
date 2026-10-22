//! Fixed-name probe scratch must neither accumulate nor block later probes. A
//! private directory serves one probing runtime at a time: stale entries under
//! the fixed names are removed, so two concurrent probes would discard each
//! other's scratch.
use crate::{Result, RuntimeError};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

/// Remove a leftover entry only if it is owned by this user and is a regular
/// file or a real directory. A symlink or foreign entry is refused, never
/// followed, so a planted name cannot redirect a deletion.
pub(crate) fn remove_stale(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if meta.file_type().is_symlink() || meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(RuntimeError::Integrity("stale scratch entry"));
    }
    if meta.is_dir() {
        fs::remove_dir_all(path)?;
    } else if meta.is_file() {
        fs::remove_file(path)?;
    } else {
        return Err(RuntimeError::Integrity("stale scratch entry"));
    }
    Ok(())
}

/// A private (0600) canary file, replacing a stale one from a killed probe.
pub(crate) fn create_canary(path: &Path, bytes: &[u8]) -> Result<()> {
    remove_stale(path)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

/// Removes every tracked path on every exit path, including early returns and
/// a dropped future. Track a path before creating it.
#[derive(Default)]
pub(crate) struct Scratch(Vec<PathBuf>);
impl Scratch {
    /// Clears a stale entry under the same name, then tracks it for removal.
    pub(crate) fn claim(&mut self, path: &Path) -> Result<()> {
        remove_stale(path)?;
        self.0.push(path.into());
        Ok(())
    }
    /// Attempts every removal, then reports the first failure.
    pub(crate) fn cleanup(&mut self) -> Result<()> {
        let mut first = None;
        for path in self.0.drain(..) {
            if let Err(error) = remove_stale(&path) {
                first.get_or_insert(error);
            }
        }
        first.map_or(Ok(()), Err)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn stale_file_and_directory_are_replaced_but_a_symlink_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("canary");
        fs::write(&file, b"stale").unwrap();
        create_canary(&file, b"fresh").unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"fresh");
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let dir = temp.path().join("probe");
        fs::create_dir_all(dir.join("allowed")).unwrap();
        fs::write(dir.join("allowed/yes"), b"x").unwrap();
        remove_stale(&dir).unwrap();
        assert!(!dir.exists());
        let target = temp.path().join("target");
        fs::write(&target, b"keep").unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            remove_stale(&link),
            Err(RuntimeError::Integrity("stale scratch entry"))
        ));
        assert!(matches!(
            create_canary(&link, b"x"),
            Err(RuntimeError::Integrity("stale scratch entry"))
        ));
        assert_eq!(fs::read(&target).unwrap(), b"keep");
    }
    #[test]
    fn scratch_is_removed_on_drop_and_cleanup_removes_every_path() {
        let temp = tempfile::tempdir().unwrap();
        let (a, b) = (temp.path().join("a"), temp.path().join("b"));
        {
            let mut scratch = Scratch::default();
            scratch.claim(&a).unwrap();
            scratch.claim(&b).unwrap();
            fs::create_dir(&a).unwrap();
            fs::write(&b, b"x").unwrap();
        }
        assert!(!a.exists() && !b.exists());
        let mut scratch = Scratch::default();
        scratch.claim(&a).unwrap();
        scratch.claim(&b).unwrap();
        fs::write(&a, b"x").unwrap();
        fs::write(&b, b"x").unwrap();
        scratch.cleanup().unwrap();
        assert!(!a.exists() && !b.exists());
    }
}
