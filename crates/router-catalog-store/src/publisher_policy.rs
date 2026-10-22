use crate::{MAX_PUBLISHER_POLICY_BYTES, Result, StoreError, files};
use router_adapter_api::content_digest;
use std::path::{Path, PathBuf};

/// Parent-owned serialized publisher policy protected by a stable sibling
/// lock directory. The lock is separate from the policy file.
pub struct PublisherPolicyAuthority {
    path: PathBuf,
    lock_root: files::Root,
}

/// Exact current policy bytes while holding the shared interprocess lock.
/// Acquire this before a catalog guard and retain it through the operation.
pub struct PublisherPolicyGuard {
    path: PathBuf,
    lock: files::Guard,
    bytes: Vec<u8>,
    content_sha256: String,
}

impl PublisherPolicyAuthority {
    /// Open the parent policy file and create its stable `<file>.authority`
    /// lock directory if absent. Writers must take its exclusive catalog lock.
    pub fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() || path.as_os_str().len() > 4096 {
            return Err(StoreError::path(crate::Operation::Locator));
        }
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".authority");
        let lock_path = PathBuf::from(lock_path);
        let lock_root = match files::Root::create(&lock_path) {
            Ok(root) => root,
            Err(StoreError::Exists) => files::Root::open(&lock_path)?,
            Err(error) => return Err(error),
        };
        Ok(Self {
            path: path.to_path_buf(),
            lock_root,
        })
    }

    /// Read bounded bytes on every acquisition while retaining a shared lock.
    pub fn acquire(&self) -> Result<PublisherPolicyGuard> {
        let lock = self.lock_root.lock(false)?;
        let bytes = files::read_private_external(&self.path, MAX_PUBLISHER_POLICY_BYTES)?;
        let content_sha256 = content_digest(&bytes);
        Ok(PublisherPolicyGuard {
            path: self.path.clone(),
            lock,
            bytes,
            content_sha256,
        })
    }
}

impl PublisherPolicyGuard {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }
    /// Recheck the named lock and reread the policy before using its grants.
    pub fn validate_current(&self) -> Result<()> {
        self.lock.validate_identity()?;
        let current = files::read_private_external(&self.path, MAX_PUBLISHER_POLICY_BYTES)?;
        if current != self.bytes {
            return Err(StoreError::Authority);
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn policy_bytes_are_bounded_pinned_and_revalidated_under_shared_lock() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap().join("publishers.json");
        fs::write(&path, b"{\"schema_version\":1}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let authority = PublisherPolicyAuthority::open(&path).unwrap();
        let guard = authority.acquire().unwrap();
        assert_eq!(guard.bytes(), b"{\"schema_version\":1}");
        assert_eq!(guard.content_sha256(), content_digest(guard.bytes()));
        guard.validate_current().unwrap();

        let mut changed = path.as_os_str().to_os_string();
        changed.push(".next");
        let changed = PathBuf::from(changed);
        fs::write(&changed, b"{\"schema_version\":2}").unwrap();
        fs::set_permissions(&changed, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&changed, &path).unwrap();
        assert!(matches!(
            guard.validate_current(),
            Err(StoreError::Authority)
        ));
    }

    #[test]
    fn policy_shared_lock_blocks_exclusive_catalog_lock() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap().join("publishers.json");
        fs::write(&path, b"policy").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let authority = PublisherPolicyAuthority::open(&path).unwrap();
        let guard = authority.acquire().unwrap();
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".authority");
        let lock_root = files::Root::open(&PathBuf::from(lock_path)).unwrap();
        assert!(matches!(lock_root.lock(true), Err(StoreError::Busy)));
        drop(guard);
        assert!(lock_root.lock(true).is_ok());
    }

    #[test]
    fn replacing_policy_lock_locator_invalidates_existing_guard() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap().join("publishers.json");
        fs::write(&path, b"policy").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let authority = PublisherPolicyAuthority::open(&path).unwrap();
        let guard = authority.acquire().unwrap();
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".authority");
        let lock_path = PathBuf::from(lock_path);
        let mut moved_path = lock_path.as_os_str().to_os_string();
        moved_path.push(".old");
        fs::rename(&lock_path, PathBuf::from(moved_path)).unwrap();
        let _replacement = files::Root::create(&lock_path).unwrap();
        assert!(matches!(
            guard.validate_current(),
            Err(StoreError::Integrity)
        ));
    }
}
