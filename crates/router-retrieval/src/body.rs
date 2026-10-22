use crate::{
    AssetKind, Bm25Index, MAX_BODY_BYTES, Result, RetrievalError, SelectedBody, digest, trusted,
};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

pub(crate) fn validate_relative(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 512
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || Path::new(path)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(RetrievalError::UnsafePath);
    }
    Ok(())
}

fn checked_path(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_relative(relative)?;
    let mut path = root.to_path_buf();
    for part in Path::new(relative).components() {
        path.push(part);
        let meta = fs::symlink_metadata(&path).map_err(|source| RetrievalError::Io {
            operation: "inspect selected path",
            source,
        })?;
        if meta.file_type().is_symlink() {
            return Err(RetrievalError::UnsafePath);
        }
    }
    Ok(path)
}

impl Bm25Index {
    /// Read one explicitly selected trusted asset. Search itself never reads bodies.
    /// The caller supplies the authorized root and must prevent concurrent hostile
    /// filesystem replacement; path checks are not an operating-system sandbox.
    pub fn load_body(&self, root: &Path, kind: AssetKind, id: &str) -> Result<SelectedBody> {
        self.require_unbound()?;
        self.load_body_validated(root, kind, id)
    }

    /// Verify the current authoritative catalog digest before selecting any
    /// body metadata or performing filesystem I/O.
    pub fn load_body_with_catalog(
        &self,
        root: &Path,
        kind: AssetKind,
        id: &str,
        catalog_hash: &str,
    ) -> Result<SelectedBody> {
        self.validate_catalog_hash(catalog_hash)?;
        self.load_body_validated(root, kind, id)
    }

    fn load_body_validated(&self, root: &Path, kind: AssetKind, id: &str) -> Result<SelectedBody> {
        let asset = self.asset(kind, id).ok_or(RetrievalError::Selection)?;
        if !trusted(asset.trust) {
            return Err(RetrievalError::Selection);
        }
        let body = asset.body.as_ref().ok_or(RetrievalError::Selection)?;
        let root_meta = fs::symlink_metadata(root).map_err(|source| RetrievalError::Io {
            operation: "inspect body root",
            source,
        })?;
        if !root_meta.is_dir() || root_meta.file_type().is_symlink() {
            return Err(RetrievalError::UnsafePath);
        }
        let root = root.canonicalize().map_err(|source| RetrievalError::Io {
            operation: "resolve body root",
            source,
        })?;
        let path = checked_path(&root, &body.path)?;
        let meta = fs::symlink_metadata(&path).map_err(|source| RetrievalError::Io {
            operation: "inspect selected body",
            source,
        })?;
        if !meta.is_file() {
            return Err(RetrievalError::UnsafePath);
        }
        if meta.len() > MAX_BODY_BYTES as u64 {
            return Err(RetrievalError::Limit("body bytes"));
        }
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(&path).map_err(|source| RetrievalError::Io {
            operation: "open selected body",
            source,
        })?;
        if !file
            .metadata()
            .map_err(|source| RetrievalError::Io {
                operation: "inspect opened body",
                source,
            })?
            .is_file()
        {
            return Err(RetrievalError::UnsafePath);
        }
        checked_path(&root, &body.path)?;
        let mut bytes = Vec::new();
        file.take(MAX_BODY_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| RetrievalError::Io {
                operation: "read selected body",
                source,
            })?;
        if bytes.len() > MAX_BODY_BYTES {
            return Err(RetrievalError::Limit("body bytes"));
        }
        if digest(&bytes) != body.sha256 {
            return Err(RetrievalError::BodyHashMismatch);
        }
        let text = String::from_utf8(bytes).map_err(|_| RetrievalError::Invalid("body UTF-8"))?;
        Ok(SelectedBody {
            asset: asset.key(),
            sha256: body.sha256.clone(),
            text,
        })
    }
}
