use crate::error::Error;
use std::{
    fmt::Write as _,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
};

pub(crate) const TOKEN_FILE: &str = "token";
pub(crate) const SOCKET_FILE: &str = "router.sock";
pub(crate) const LOCK_FILE: &str = "lock";
const MIN_TOKEN_BYTES: usize = 32;
const MAX_TOKEN_BYTES: usize = 256;
/// `sockaddr_un.sun_path` is 104 bytes on macOS and 108 on Linux.
const MAX_SOCKET_PATH_BYTES: usize = 100;

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub(crate) fn prepare_state_dir(dir: &Path) -> Result<(), Error> {
    if !dir.is_absolute() {
        return Err(Error::StateDir("local_api.state_dir.relative"));
    }
    match fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .map_err(|_| Error::StateDir("local_api.state_dir.create"))?;
        }
        Err(_) => return Err(Error::StateDir("local_api.state_dir.metadata")),
    }
    // Inspect after creation as well, so a raced or pre-existing entry gets
    // the same checks. An unsafe directory is refused, never repaired.
    let meta =
        fs::symlink_metadata(dir).map_err(|_| Error::StateDir("local_api.state_dir.metadata"))?;
    if meta.file_type().is_symlink() {
        return Err(Error::StateDir("local_api.state_dir.symlink"));
    }
    if !meta.is_dir() {
        return Err(Error::StateDir("local_api.state_dir.not_directory"));
    }
    if meta.uid() != euid() {
        return Err(Error::StateDir("local_api.state_dir.owner"));
    }
    if meta.permissions().mode() & 0o777 != 0o700 {
        return Err(Error::StateDir("local_api.state_dir.mode"));
    }
    Ok(())
}

/// Exclusive, non-blocking lock held for the life of the server, so two
/// starts on one state directory cannot remove each other's socket.
pub(crate) fn lock_state_dir(dir: &Path) -> Result<File, Error> {
    let failed = Error::StateDir("local_api.state_dir.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(LOCK_FILE))
        .map_err(|_| failed.clone())?;
    let meta = file.metadata().map_err(|_| failed.clone())?;
    if !meta.is_file() || meta.uid() != euid() || meta.permissions().mode() & 0o077 != 0 {
        return Err(failed);
    }
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(file),
        Err(rustix::io::Errno::WOULDBLOCK) => Err(Error::StateDir("local_api.state_dir.locked")),
        Err(_) => Err(failed),
    }
}

fn valid_token(bytes: &[u8]) -> bool {
    (MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&bytes.len())
        && bytes.iter().all(|byte| (33..=126).contains(byte))
}

pub(crate) fn load_or_create_token(dir: &Path) -> Result<Vec<u8>, Error> {
    let path = dir.join(TOKEN_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => match create_token(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(Error::Token("local_api.token.create")),
        },
        Err(_) => return Err(Error::Token("local_api.token.metadata")),
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|_| Error::Token("local_api.token.open"))?;
    let meta = file
        .metadata()
        .map_err(|_| Error::Token("local_api.token.metadata"))?;
    if !meta.is_file() {
        return Err(Error::Token("local_api.token.not_file"));
    }
    if meta.uid() != euid() {
        return Err(Error::Token("local_api.token.owner"));
    }
    if meta.permissions().mode() & 0o777 != 0o600 {
        return Err(Error::Token("local_api.token.mode"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_TOKEN_BYTES as u64 + 2)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Token("local_api.token.read"))?;
    while bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if !valid_token(&bytes) {
        return Err(Error::Token("local_api.token.invalid"));
    }
    Ok(bytes)
}

/// Writes the complete token to a private temporary file, then publishes it
/// with `hard_link`, which fails instead of replacing an existing token. A
/// crash or a concurrent start can therefore never expose an empty token.
fn create_token(path: &Path) -> std::io::Result<()> {
    let mut random = [0u8; 40];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let hex = |bytes: &[u8]| {
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(text, "{byte:02x}");
        }
        text
    };
    let mut text = hex(&random[..32]);
    text.push('\n');
    let temporary = path.with_file_name(format!(".token-{}", hex(&random[32..])));
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        // The creation mode is reduced by the umask; make the final mode explicit.
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::hard_link(&temporary, path)
    })();
    let _ = fs::remove_file(&temporary);
    written
}

/// Removes the socket on drop, only while it is still the inode we bound.
pub(crate) struct SocketGuard {
    path: PathBuf,
    identity: (u64, u64),
}

impl SocketGuard {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.path) {
            if meta.file_type().is_socket() && (meta.dev(), meta.ino()) == self.identity {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

pub(crate) fn bind_socket(dir: &Path) -> Result<(UnixListener, SocketGuard), Error> {
    let path = dir.join(SOCKET_FILE);
    if path.as_os_str().len() > MAX_SOCKET_PATH_BYTES {
        return Err(Error::Socket("local_api.socket.path_too_long"));
    }
    match fs::symlink_metadata(&path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(Error::Socket("local_api.socket.occupied"));
            }
            if meta.uid() != euid() {
                return Err(Error::Socket("local_api.socket.owner"));
            }
            match UnixStream::connect(&path) {
                Ok(_) => return Err(Error::Socket("local_api.socket.in_use")),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(&path).map_err(|_| Error::Socket("local_api.socket.stale"))?;
                }
                Err(_) => return Err(Error::Socket("local_api.socket.probe")),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error::Socket("local_api.socket.metadata")),
    }
    let listener = UnixListener::bind(&path).map_err(|_| Error::Socket("local_api.socket.bind"))?;
    let meta =
        fs::symlink_metadata(&path).map_err(|_| Error::Socket("local_api.socket.metadata"))?;
    let guard = SocketGuard {
        path: path.clone(),
        identity: (meta.dev(), meta.ino()),
    };
    // The 0700 directory keeps other users out while the mode is tightened.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|_| Error::Socket("local_api.socket.mode"))?;
    let meta =
        fs::symlink_metadata(&path).map_err(|_| Error::Socket("local_api.socket.metadata"))?;
    if !meta.file_type().is_socket() || meta.permissions().mode() & 0o777 != 0o600 {
        return Err(Error::Socket("local_api.socket.mode"));
    }
    listener
        .set_nonblocking(true)
        .map_err(|_| Error::Socket("local_api.socket.nonblocking"))?;
    Ok((listener, guard))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("mode");
        dir
    }

    #[test]
    fn a_missing_state_directory_is_created_private() {
        let root = private_dir();
        let fresh = root.path().join("fresh");
        prepare_state_dir(&fresh).expect("created");
        assert_eq!(
            fs::metadata(&fresh).expect("metadata").permissions().mode() & 0o777,
            0o700
        );
        prepare_state_dir(&fresh).expect("reusable");
    }

    #[test]
    fn a_token_is_generated_once_then_reloaded() {
        let dir = private_dir();
        let first = load_or_create_token(dir.path()).expect("created");
        assert_eq!(first.len(), 64);
        assert!(first.iter().all(u8::is_ascii_hexdigit));
        let path = dir.path().join(TOKEN_FILE);
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(load_or_create_token(dir.path()).expect("reloaded"), first);
        let other = private_dir();
        assert_ne!(load_or_create_token(other.path()).expect("second"), first);
    }

    #[test]
    fn concurrent_first_starts_agree_on_one_complete_token() {
        let dir = private_dir();
        let tokens: Vec<_> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| load_or_create_token(dir.path())))
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().expect("join").expect("token"))
                .collect()
        });
        assert!(
            tokens
                .iter()
                .all(|token| token == &tokens[0] && token.len() == 64)
        );
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .expect("dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(leftovers, [std::ffi::OsString::from(TOKEN_FILE)]);
    }

    #[test]
    fn the_state_directory_lock_admits_one_holder_at_a_time() {
        let dir = private_dir();
        let first = lock_state_dir(dir.path()).expect("first holder");
        assert_eq!(
            lock_state_dir(dir.path()).err(),
            Some(Error::StateDir("local_api.state_dir.locked"))
        );
        drop(first);
        drop(lock_state_dir(dir.path()).expect("released with the holder"));
    }

    #[test]
    fn a_symlinked_lock_file_is_refused() {
        let dir = private_dir();
        let target = dir.path().join("elsewhere");
        fs::write(&target, b"").expect("target");
        std::os::unix::fs::symlink(&target, dir.path().join(LOCK_FILE)).expect("symlink");
        assert_eq!(
            lock_state_dir(dir.path()).err(),
            Some(Error::StateDir("local_api.state_dir.lock"))
        );
    }

    #[test]
    fn foreign_or_weak_tokens_are_refused() {
        let dir = private_dir();
        let path = dir.path().join(TOKEN_FILE);
        fs::write(&path, "a".repeat(64)).expect("token");
        for mode in [0o644, 0o640, 0o660, 0o400] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("mode");
            assert_eq!(
                load_or_create_token(dir.path()),
                Err(Error::Token("local_api.token.mode")),
                "{mode:o}"
            );
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        for weak in [
            "",
            "short",
            "has space in it ................................",
        ] {
            fs::write(&path, weak).expect("token");
            assert_eq!(
                load_or_create_token(dir.path()),
                Err(Error::Token("local_api.token.invalid")),
                "{weak:?}"
            );
        }
    }
}
