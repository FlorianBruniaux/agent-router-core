//! Per-store secret keying the approval binding of secret environment values.
//! The approval digest is displayed and pasted, and its other inputs are known,
//! so a bare hash of an API key would let its reader confirm a guess offline.
use crate::CliError;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub(crate) const KEY_FILE: &str = "approval.key";
pub(crate) const KEY_BYTES: usize = 32;

const UNSAFE: CliError = CliError::Product("runtime.approval_key.unsafe");
const UNAVAILABLE: CliError = CliError::Product("runtime.approval_key.unavailable");
const INTEGRITY: CliError = CliError::Product("runtime.approval_key.integrity");
/// The key is published but the store directory could not be synced: it may
/// not survive a crash, which would only make the new approval stale.
const DURABILITY_UNKNOWN: CliError =
    CliError::Product("runtime.approval_key.published_durability_unknown");

/// Never serialized, displayed or logged.
pub(crate) struct ApprovalKey([u8; KEY_BYTES]);

impl ApprovalKey {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
    #[cfg(test)]
    pub(crate) fn fixed(byte: u8) -> Self {
        Self([byte; KEY_BYTES])
    }
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Private to the effective user: a regular directory or file, not a symlink,
/// owned by the caller, with no group or other permission bits.
fn private(meta: &fs::Metadata) -> bool {
    !meta.file_type().is_symlink() && meta.uid() == euid() && meta.permissions().mode() & 0o077 == 0
}

/// Reads the key of an existing runtime store, creating it once. The store
/// directory must already exist; it is never created here.
pub(crate) fn load_or_create(store: &Path) -> Result<ApprovalKey, CliError> {
    let meta = fs::symlink_metadata(store).map_err(|_| UNAVAILABLE)?;
    if !meta.is_dir() || !private(&meta) {
        return Err(UNSAFE);
    }
    let path = store.join(KEY_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create(store, &path)?,
        Err(_) => return Err(UNAVAILABLE),
    }
    read(&path)
}

/// Evidence reads never create a missing secret or repair an unsafe store.
pub(crate) fn load_existing(store: &Path) -> Result<ApprovalKey, CliError> {
    let meta = fs::symlink_metadata(store).map_err(|_| UNAVAILABLE)?;
    if !meta.is_dir() || !private(&meta) {
        return Err(UNSAFE);
    }
    read(&store.join(KEY_FILE))
}

fn read(path: &Path) -> Result<ApprovalKey, CliError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| match error.raw_os_error() {
            Some(libc::ELOOP) => UNSAFE,
            _ => UNAVAILABLE,
        })?;
    let meta = file.metadata().map_err(|_| UNAVAILABLE)?;
    if !meta.is_file() || !private(&meta) {
        return Err(UNSAFE);
    }
    let mut bytes = Vec::with_capacity(KEY_BYTES + 1);
    file.take(KEY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| UNAVAILABLE)?;
    let key: [u8; KEY_BYTES] = bytes.as_slice().try_into().map_err(|_| INTEGRITY)?;
    Ok(ApprovalKey(key))
}

/// Writes the complete key to a private temporary file, then publishes it with
/// `hard_link`, which never replaces an existing key. A crash or a concurrent
/// first approval can therefore never expose a partial key.
fn create(store: &Path, path: &Path) -> Result<(), CliError> {
    let mut random = [0u8; KEY_BYTES + 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(|_| UNAVAILABLE)?;
    let mut suffix = String::with_capacity(32);
    for byte in &random[KEY_BYTES..] {
        suffix.push_str(&format!("{byte:02x}"));
    }
    let temporary = store.join(format!(".{KEY_FILE}-{suffix}"));
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        // The creation mode is reduced by the umask; make the final mode explicit.
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&random[..KEY_BYTES])?;
        file.sync_all()?;
        fs::hard_link(&temporary, path)
    })();
    let _ = fs::remove_file(&temporary);
    match written {
        // Persist the new directory entry (and the temporary's removal).
        Ok(()) => File::open(store)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| DURABILITY_UNKNOWN),
        // Another approval published its key first; read that one.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(_) => Err(UNAVAILABLE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("runtime");
        fs::DirBuilder::new().create(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        (temp, store)
    }

    #[test]
    fn the_key_is_created_once_privately_and_then_reread() {
        let (_temp, store) = store();
        let first = load_or_create(&store).unwrap_or_else(|_| panic!("created"));
        let meta = fs::symlink_metadata(store.join(KEY_FILE)).unwrap();
        assert!(meta.is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(meta.len(), KEY_BYTES as u64);
        let again = load_or_create(&store).unwrap_or_else(|_| panic!("reread"));
        assert_eq!(first.bytes(), again.bytes());
        assert_ne!(first.bytes(), [0u8; KEY_BYTES]);
        let names: Vec<_> = fs::read_dir(&store)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [KEY_FILE], "no temporary file left behind");
    }

    #[test]
    fn unsafe_or_damaged_keys_are_refused() {
        let code = |store: &Path| load_or_create(store).map(|_| ()).map_err(CliError::code);
        let (_temp, store) = store();
        let path = store.join(KEY_FILE);

        fs::write(&path, [1u8; KEY_BYTES]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(code(&store), Err("runtime.approval_key.unsafe"), "mode");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, [1u8; KEY_BYTES - 1]).unwrap();
        assert_eq!(code(&store), Err("runtime.approval_key.integrity"), "short");
        fs::write(&path, [1u8; KEY_BYTES + 1]).unwrap();
        assert_eq!(code(&store), Err("runtime.approval_key.integrity"), "long");

        fs::remove_file(&path).unwrap();
        let elsewhere = store.parent().unwrap().join("planted");
        fs::write(&elsewhere, [1u8; KEY_BYTES]).unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        assert_eq!(code(&store), Err("runtime.approval_key.unsafe"), "symlink");

        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(
            code(&store),
            Err("runtime.approval_key.unsafe"),
            "directory"
        );

        fs::set_permissions(&store, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            code(&store),
            Err("runtime.approval_key.unsafe"),
            "store mode"
        );
        let missing = store.join("missing");
        assert_eq!(code(&missing), Err("runtime.approval_key.unavailable"));
        assert!(!missing.exists(), "the store is never created here");
    }
}
