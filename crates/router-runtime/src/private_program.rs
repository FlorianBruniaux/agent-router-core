//! Per-attempt executable copy. The child may read and execute it, never write it.
use crate::{Result, RuntimeError, sandbox::binary_hash};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions, Permissions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const MAX_PROGRAM_BYTES: u64 = 256 * 1024 * 1024;

pub(crate) struct PrivateProgram {
    directory: Option<tempfile::TempDir>,
    directory_path: PathBuf,
    directory_file: File,
    path: PathBuf,
    mode: u32,
}

impl PrivateProgram {
    pub(crate) fn copy(source: &Path, expected_hash: &str, store: &Path) -> Result<Self> {
        Self::copy_inner(source, expected_hash, store, MAX_PROGRAM_BYTES, 0o500)
    }

    pub(crate) fn copy_profile(source: &Path, expected_hash: &str, store: &Path) -> Result<Self> {
        Self::copy_inner(source, expected_hash, store, 64 * 1024, 0o400)
    }

    fn copy_inner(
        source: &Path,
        expected_hash: &str,
        store: &Path,
        max_bytes: u64,
        mode: u32,
    ) -> Result<Self> {
        let mut source_file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(source)?;
        let source_meta = source_file.metadata()?;
        if !source_meta.is_file() {
            return Err(RuntimeError::Sandbox);
        }
        if source_meta.len() > max_bytes {
            return Err(RuntimeError::Limit);
        }
        let temp_root = fs::canonicalize(std::env::temp_dir())?;
        let directory = tempfile::Builder::new()
            .prefix("agent-router-program-")
            .permissions(Permissions::from_mode(0o700))
            .tempdir_in(temp_root)?;
        let directory_path = directory.path().to_owned();
        let directory_file = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
            .open(&directory_path)
        {
            Ok(file) => file,
            Err(error) => {
                let _ = directory.keep();
                return Err(error.into());
            }
        };
        let copy = Self {
            path: directory_path.join("program"),
            directory: Some(directory),
            directory_path,
            directory_file,
            mode,
        };
        let dir_path = copy.directory_path.as_path();
        let dir_meta = copy.directory_file.metadata()?;
        if fs::canonicalize(dir_path)? != dir_path
            || dir_path.starts_with(store)
            || !copy.same_directory()
            || !dir_meta.is_dir()
            || dir_meta.uid() != rustix::process::geteuid().as_raw()
            || dir_meta.permissions().mode() & 0o777 != 0o700
        {
            return Err(RuntimeError::Sandbox);
        }
        let mut destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&copy.path)?;
        let mut hash = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0; 16_384];
        loop {
            let count = source_file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total.checked_add(count as u64).ok_or(RuntimeError::Limit)?;
            if total > max_bytes {
                return Err(RuntimeError::Limit);
            }
            hash.update(&buffer[..count]);
            destination.write_all(&buffer[..count])?;
        }
        if hex::encode(hash.finalize()) != expected_hash {
            return Err(RuntimeError::Integrity(
                "approved binary changed before copy",
            ));
        }
        destination.set_permissions(Permissions::from_mode(mode))?;
        destination.sync_all()?;
        drop(destination);
        copy.verify(expected_hash)?;
        Ok(copy)
    }

    pub(crate) fn verify(&self, expected_hash: &str) -> Result<&Path> {
        let dir_path = self.directory_path.as_path();
        let dir_meta = fs::symlink_metadata(dir_path)?;
        let file_meta = fs::symlink_metadata(&self.path)?;
        if fs::canonicalize(dir_path)? != dir_path
            || !self.same_directory()
            || !dir_meta.is_dir()
            || dir_meta.uid() != rustix::process::geteuid().as_raw()
            || dir_meta.permissions().mode() & 0o777 != 0o700
            || !file_meta.is_file()
            || file_meta.uid() != rustix::process::geteuid().as_raw()
            || file_meta.nlink() != 1
            || file_meta.permissions().mode() & 0o777 != self.mode
            || binary_hash(&self.path)? != expected_hash
        {
            return Err(RuntimeError::Integrity("private program changed"));
        }
        Ok(&self.path)
    }

    pub(crate) fn directory(&self) -> &Path {
        &self.directory_path
    }

    fn same_directory(&self) -> bool {
        let Ok(current) = fs::symlink_metadata(&self.directory_path) else {
            return false;
        };
        let Ok(owned) = self.directory_file.metadata() else {
            return false;
        };
        current.is_dir() && current.dev() == owned.dev() && current.ino() == owned.ino()
    }

    pub(crate) fn preserve(mut self) {
        if let Some(directory) = self.directory.take() {
            let _ = directory.keep();
        }
    }

    pub(crate) fn cleanup(mut self) -> Result<()> {
        let unchanged = self.same_directory();
        if let Some(directory) = self.directory.take() {
            if !unchanged {
                let _ = directory.keep();
                return Err(RuntimeError::Integrity(
                    "private program cleanup directory changed",
                ));
            }
            directory.close()?;
        }
        Ok(())
    }
}

impl Drop for PrivateProgram {
    fn drop(&mut self) {
        let unchanged = self.same_directory();
        if let Some(directory) = self.directory.take() {
            if unchanged {
                drop(directory);
            } else {
                // Do not recursively delete a replacement at the old pathname.
                // The moved/ambiguous owner needs manual reconciliation. This
                // check does not exclude a trusted concurrent writer after it.
                let _ = directory.keep();
            }
        }
    }
}
