//! Opt-in payload storage. File operations stay below pinned directory handles;
//! API callers provide run/attempt identifiers, never paths to delete.
use crate::{Result, RuntimeError};
use router_adapter_api::content_digest;
use router_types::{OutputArtifact, OutputArtifacts, OutputArtifactsState};
use rustix::fs::{AtFlags, Mode, OFlags, mkdirat, openat, statat, unlinkat};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}
impl FileIdentity {
    pub(crate) fn from_file(file: &File) -> Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    pub(crate) fn matches(&self, file: &File) -> Result<bool> {
        let metadata = file.metadata()?;
        Ok(self.device == metadata.dev() && self.inode == metadata.ino())
    }
}

pub(crate) struct OutputStorage {
    root: PathBuf,
    root_dir: File,
}
impl OutputStorage {
    pub fn open(root: &Path) -> Result<Self> {
        let root_dir = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(root)?;
        private_directory(&root_dir)?;
        Ok(Self {
            root: root.into(),
            root_dir,
        })
    }
    pub fn metadata(
        &self,
        run_id: &str,
        attempt: u32,
        created: u64,
        retention: u64,
        streams: (&[u8], &[u8]),
        truncated: bool,
    ) -> Result<OutputArtifacts> {
        let (stdout, stderr) = streams;
        if attempt == 0
            || attempt > 5
            || stdout.len().saturating_add(stderr.len()) > 16 * 1024 * 1024
        {
            return Err(RuntimeError::Limit);
        }
        let artifact = |stream: &str, bytes: &[u8]| -> Result<OutputArtifact> {
            Ok(OutputArtifact {
                path: self
                    .path(run_id, attempt, stream)?
                    .to_str()
                    .ok_or(RuntimeError::Invalid("output path"))?
                    .into(),
                sha256: content_digest(bytes),
                bytes: bytes.len(),
            })
        };
        Ok(OutputArtifacts {
            schema_version: 1,
            run_id: run_id.into(),
            attempt,
            state: OutputArtifactsState::Pending,
            created_at_unix_seconds: created,
            expires_at_unix_seconds: created.checked_add(retention).ok_or(RuntimeError::Limit)?,
            truncated,
            stdout: artifact("stdout", stdout)?,
            stderr: artifact("stderr", stderr)?,
        })
    }
    pub fn write(
        &self,
        metadata: &OutputArtifacts,
        stdout: &[u8],
        stderr: &[u8],
        mut register: impl FnMut(&str, FileIdentity) -> Result<()>,
    ) -> Result<()> {
        self.validate(metadata)?;
        let dir = self.directory(true)?.ok_or(RuntimeError::NotFound)?;
        for (stream, artifact, bytes) in [
            ("stdout", &metadata.stdout, stdout),
            ("stderr", &metadata.stderr, stderr),
        ] {
            if bytes.len() != artifact.bytes || content_digest(bytes) != artifact.sha256 {
                return Err(RuntimeError::Integrity("output artifact bytes"));
            }
            let name = Path::new(&artifact.path)
                .file_name()
                .ok_or(RuntimeError::Invalid("output path"))?;
            let fd = openat(
                &dir,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(std::io::Error::from)?;
            let mut file = File::from(fd);
            private_file(&file)?;
            // Commit ownership before writing any payload. A crash in the
            // preceding gap can leave an empty file, never untracked secrets.
            register(stream, FileIdentity::from_file(&file)?)?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        dir.sync_all()?;
        Ok(())
    }
    pub fn verify(
        &self,
        metadata: &OutputArtifacts,
        identities: &BTreeMap<String, FileIdentity>,
    ) -> Result<()> {
        self.validate(metadata)?;
        if metadata.state != OutputArtifactsState::Retained {
            return Ok(());
        }
        let dir = self
            .directory(false)?
            .ok_or(RuntimeError::Integrity("output artifacts missing"))?;
        for (stream, artifact) in [("stdout", &metadata.stdout), ("stderr", &metadata.stderr)] {
            self.read_checked(
                &dir,
                artifact,
                identities
                    .get(stream)
                    .ok_or(RuntimeError::Integrity("output identity missing"))?,
                true,
            )?;
        }
        Ok(())
    }
    pub fn purge(
        &self,
        metadata: &OutputArtifacts,
        identities: &BTreeMap<String, FileIdentity>,
    ) -> Result<()> {
        self.validate(metadata)?;
        let Some(dir) = self.directory(false)? else {
            return Ok(());
        };
        // Inspect both names before any deletion; a symlink cannot partially
        // redirect or authorize purging the other stream.
        let mut owned = Vec::new();
        for (stream, artifact) in [("stdout", &metadata.stdout), ("stderr", &metadata.stderr)] {
            let Some(identity) = identities.get(stream) else {
                continue;
            };
            match self.read_checked(&dir, artifact, identity, false) {
                Ok(file) => owned.push((artifact, file)),
                Err(RuntimeError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        for (artifact, file) in owned {
            let name = Path::new(&artifact.path)
                .file_name()
                .ok_or(RuntimeError::Invalid("output path"))?;
            let current =
                statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(std::io::Error::from)?;
            let meta = file.metadata()?;
            if current.st_ino as u64 != meta.ino() || current.st_dev as u64 != meta.dev() {
                return Err(RuntimeError::Integrity("output artifact changed"));
            }
            unlinkat(&dir, name, AtFlags::empty()).map_err(std::io::Error::from)?;
        }
        dir.sync_all()?;
        Ok(())
    }
    fn read_checked(
        &self,
        dir: &File,
        artifact: &OutputArtifact,
        identity: &FileIdentity,
        verify_digest: bool,
    ) -> Result<File> {
        let name = Path::new(&artifact.path)
            .file_name()
            .ok_or(RuntimeError::Invalid("output path"))?;
        let fd = openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        let mut file = File::from(fd);
        private_file(&file)?;
        if !identity.matches(&file)? {
            return Err(RuntimeError::Integrity("output artifact identity"));
        }
        if file.metadata()?.len() > artifact.bytes as u64 {
            return Err(RuntimeError::Integrity("output artifact size"));
        }
        if verify_digest {
            let mut bytes = Vec::new();
            std::io::Read::by_ref(&mut file)
                .take(artifact.bytes as u64 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() != artifact.bytes || content_digest(&bytes) != artifact.sha256 {
                return Err(RuntimeError::Integrity("output artifact changed"));
            }
        }
        Ok(file)
    }
    fn directory(&self, create: bool) -> Result<Option<File>> {
        if create {
            match mkdirat(&self.root_dir, "outputs", Mode::RWXU) {
                Ok(()) => self.root_dir.sync_all()?,
                Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(std::io::Error::from(e).into()),
            }
        }
        match openat(
            &self.root_dir,
            "outputs",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => {
                let file = File::from(fd);
                private_directory(&file)?;
                Ok(Some(file))
            }
            Err(rustix::io::Errno::NOENT) if !create => Ok(None),
            Err(e) => Err(std::io::Error::from(e).into()),
        }
    }
    fn path(&self, run_id: &str, attempt: u32, stream: &str) -> Result<PathBuf> {
        if run_id.is_empty() || run_id.len() > 96 || attempt == 0 || attempt > 5 {
            return Err(RuntimeError::Invalid("output identity"));
        }
        Ok(self.root.join("outputs").join(format!(
            "{}-{attempt}-{stream}.bin",
            content_digest(run_id.as_bytes())
        )))
    }
    fn validate(&self, metadata: &OutputArtifacts) -> Result<()> {
        if metadata.schema_version != 1
            || metadata.stdout.bytes.saturating_add(metadata.stderr.bytes) > 16 * 1024 * 1024
            || metadata.expires_at_unix_seconds <= metadata.created_at_unix_seconds
        {
            return Err(RuntimeError::Integrity("output metadata"));
        }
        for (stream, artifact) in [("stdout", &metadata.stdout), ("stderr", &metadata.stderr)] {
            if Path::new(&artifact.path) != self.path(&metadata.run_id, metadata.attempt, stream)?
                || !router_adapter_api::is_digest(&artifact.sha256)
            {
                return Err(RuntimeError::Integrity("output artifact path"));
            }
        }
        Ok(())
    }
}
fn private_directory(file: &File) -> Result<()> {
    let meta = file.metadata()?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
        return Err(RuntimeError::Invalid("private output directory"));
    }
    Ok(())
}
fn private_file(file: &File) -> Result<()> {
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || meta.permissions().mode() & 0o077 != 0 {
        return Err(RuntimeError::Integrity("private output file"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_write_purge_preserves_a_preexisting_unowned_name() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let storage = OutputStorage::open(temp.path()).unwrap();
        let metadata = storage
            .metadata("run", 1, 10, 60, (b"private", b"errors"), false)
            .unwrap();
        storage.directory(true).unwrap();
        std::fs::write(&metadata.stderr.path, b"foreign").unwrap();
        let mut identities = BTreeMap::new();
        assert!(
            storage
                .write(&metadata, b"private", b"errors", |stream, identity| {
                    identities.insert(stream.into(), identity);
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(identities.len(), 1);
        storage.purge(&metadata, &identities).unwrap();
        assert!(!Path::new(&metadata.stdout.path).exists());
        assert_eq!(std::fs::read(&metadata.stderr.path).unwrap(), b"foreign");
    }
    #[test]
    fn purge_rejects_forged_path_or_replaced_inode() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let storage = OutputStorage::open(temp.path()).unwrap();
        let metadata = storage
            .metadata("run", 1, 10, 60, (b"private", b"errors"), false)
            .unwrap();
        let mut identities = BTreeMap::new();
        storage
            .write(&metadata, b"private", b"errors", |stream, identity| {
                identities.insert(stream.into(), identity);
                Ok(())
            })
            .unwrap();
        let foreign = temp.path().join("foreign");
        std::fs::write(&foreign, b"private").unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut forged = metadata.clone();
        forged.stdout.path = foreign.to_str().unwrap().into();
        assert!(matches!(
            storage.purge(&forged, &identities),
            Err(RuntimeError::Integrity("output artifact path"))
        ));
        std::fs::rename(&foreign, &metadata.stdout.path).unwrap();
        assert!(matches!(
            storage.purge(&metadata, &identities),
            Err(RuntimeError::Integrity("output artifact identity"))
        ));
        assert_eq!(std::fs::read(&metadata.stdout.path).unwrap(), b"private");
        assert!(Path::new(&metadata.stderr.path).exists());
    }
}
