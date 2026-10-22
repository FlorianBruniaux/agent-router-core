//! Declared result payloads are distinct from opt-in diagnostic streams.
use crate::{Result, RuntimeError, outputs::FileIdentity};
use router_adapter_api::{content_digest, is_digest};
use router_types::DeclaredArtifact;
use rustix::fs::{AtFlags, Mode, OFlags, mkdirat, openat, statat, unlinkat};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
pub(crate) struct ArtifactStorage {
    root: File,
}
impl ArtifactStorage {
    pub fn open(root: &Path) -> Result<Self> {
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(root)?;
        if root.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(RuntimeError::Scope);
        }
        Ok(Self { root })
    }
    fn directory(&self, create: bool) -> Result<File> {
        if create {
            match mkdirat(&self.root, "results", Mode::RWXU) {
                Ok(()) => self.root.sync_all()?,
                Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(std::io::Error::from(e).into()),
            }
        }
        let file = File::from(
            openat(
                &self.root,
                "results",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)?,
        );
        if file.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(RuntimeError::Scope);
        }
        Ok(file)
    }
    fn name(metadata: &DeclaredArtifact) -> Result<String> {
        if !is_digest(&metadata.artifact_id) || metadata.bytes > 16 * 1024 * 1024 {
            return Err(RuntimeError::Integrity("result identity"));
        }
        Ok(format!("{}.blob", metadata.artifact_id))
    }
    pub fn write(
        &self,
        metadata: &DeclaredArtifact,
        bytes: &[u8],
        register: impl FnOnce(FileIdentity) -> Result<()>,
    ) -> Result<()> {
        if bytes.len() != metadata.bytes || content_digest(bytes) != metadata.sha256 {
            return Err(RuntimeError::Integrity("result content"));
        }
        let directory = self.directory(true)?;
        let mut file = File::from(
            openat(
                &directory,
                Self::name(metadata)?,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(std::io::Error::from)?,
        );
        register(FileIdentity::from_file(&file)?)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        directory.sync_all()?;
        Ok(())
    }
    fn file(
        &self,
        directory: &File,
        metadata: &DeclaredArtifact,
        identity: &FileIdentity,
    ) -> Result<File> {
        let file = File::from(
            openat(
                directory,
                Self::name(metadata)?,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)?,
        );
        let actual = file.metadata()?;
        if !actual.is_file()
            || actual.nlink() != 1
            || actual.permissions().mode() & 0o077 != 0
            || actual.len() > metadata.bytes as u64
            || !identity.matches(&file)?
        {
            return Err(RuntimeError::Integrity("result file"));
        }
        Ok(file)
    }
    pub fn read(&self, metadata: &DeclaredArtifact, identity: &FileIdentity) -> Result<Vec<u8>> {
        let directory = self.directory(false)?;
        let file = self.file(&directory, metadata, identity)?;
        let mut bytes = Vec::new();
        file.take(metadata.bytes as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() != metadata.bytes || content_digest(&bytes) != metadata.sha256 {
            return Err(RuntimeError::Integrity("result changed"));
        }
        Ok(bytes)
    }
    pub fn purge(&self, metadata: &DeclaredArtifact, identity: &FileIdentity) -> Result<()> {
        let directory = self.directory(false)?;
        let file = match self.file(&directory, metadata, identity) {
            Ok(v) => v,
            Err(RuntimeError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let current = statat(&directory, Self::name(metadata)?, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(std::io::Error::from)?;
        let actual = file.metadata()?;
        if current.st_ino as u64 != actual.ino() || current.st_dev as u64 != actual.dev() {
            return Err(RuntimeError::Integrity("result replaced"));
        }
        unlinkat(&directory, Self::name(metadata)?, AtFlags::empty())
            .map_err(std::io::Error::from)?;
        directory.sync_all()?;
        Ok(())
    }
}
