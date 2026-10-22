#![cfg(any(target_os = "macos", target_os = "linux"))]
#![forbid(unsafe_code)]

use nix::{
    errno::Errno,
    fcntl::{FcntlArg, fcntl},
};
use rusqlite::Connection;
use std::{
    fs,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    },
    path::Path,
    process::Command,
};

const PROBE_PATH: &str = "AGENT_ROUTER_TEST_SQLITE_LOCK_PATH";
const LOCKED: i32 = 72;
const AVAILABLE: i32 = 73;

// SQLite's Unix VFS holds this main-database range for a shared lock, also in WAL mode.
// The probe runs in another process: POSIX record locks are process-scoped.
#[test]
fn sqlite_lock_probe_child() {
    let Some(path) = std::env::var_os(PROBE_PATH) else {
        return;
    };
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let lock = nix::libc::flock {
        l_type: nix::libc::F_WRLCK as _,
        l_whence: nix::libc::SEEK_SET as _,
        l_start: 0x4000_0002,
        l_len: 510,
        l_pid: 0,
    };
    let code = match fcntl(file.as_raw_fd(), FcntlArg::F_SETLK(&lock)) {
        Ok(_) => AVAILABLE,
        Err(Errno::EACCES | Errno::EAGAIN) => LOCKED,
        Err(error) => panic!("lock probe failed: {error}"),
    };
    std::process::exit(code);
}

fn shared_lock_held(path: &Path) -> bool {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "sqlite_lock_probe_child", "--nocapture"])
        .env(PROBE_PATH, path)
        .output()
        .unwrap();
    match output.status.code() {
        Some(LOCKED) => true,
        Some(AVAILABLE) => false,
        _ => panic!(
            "lock probe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
    }
}

fn open_reader(path: &Path) -> Connection {
    let db = Connection::open(path).unwrap();
    db.execute_batch("BEGIN").unwrap();
    let _: u64 = db
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
        .unwrap();
    assert!(!db.is_autocommit());
    db
}

#[test]
fn opening_owner_preserves_an_existing_connections_main_database_lock() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("store");
    drop(open_owner(&root));
    let path = root.join(DATABASE);
    let reader = open_reader(&path);
    assert!(
        shared_lock_held(&path),
        "read transaction must hold the initial shared lock"
    );

    // Controls: SQLite's own FD management and metadata-only checks preserve it.
    drop(open_reader(&path));
    assert!(
        shared_lock_held(&path),
        "closing a managed SQLite reader must preserve the lock"
    );
    let _ = fs::symlink_metadata(&path).unwrap();
    assert!(shared_lock_held(&path));

    let owner = open_owner(&root);
    assert!(
        !reader.is_autocommit(),
        "original transaction must remain open"
    );
    assert!(
        shared_lock_held(&path),
        "opening the owner must not close an auxiliary database FD and discard another connection's POSIX lock"
    );
    drop(owner);
    assert!(
        shared_lock_held(&path),
        "the original reader still owns its lock"
    );
    reader.execute_batch("ROLLBACK").unwrap();
    drop(reader);
    assert!(
        !shared_lock_held(&path),
        "the probe must observe release after all SQLite connections close"
    );
}

#[test]
fn new_database_is_private_and_existing_contents_survive_reopening() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("store");
    drop(open_owner(&root));
    let path = root.join(DATABASE);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE test_preserved(value INTEGER); INSERT INTO test_preserved VALUES(37);",
    )
    .unwrap();
    drop(db);
    let _owner = open_owner(&root);
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("SELECT value FROM test_preserved", [], |row| row
            .get::<_, u64>(0))
            .unwrap(),
        37
    );
}

#[test]
fn database_symlinks_nonregular_files_and_public_modes_are_refused() {
    for case in ["symlink", "directory", "fifo", "public"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().join("store");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join(DATABASE);
        let outside = temp.path().join("outside");
        match case {
            "symlink" => {
                fs::write(&outside, b"private sentinel").unwrap();
                symlink(&outside, &path).unwrap();
            }
            "directory" => fs::create_dir(&path).unwrap(),
            "fifo" => nix::unistd::mkfifo(
                &path,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )
            .unwrap(),
            "public" => {
                fs::write(&path, b"public sentinel").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(owner_refused(&root), "{case} database must be refused");
        if case == "symlink" {
            assert_eq!(fs::read(&outside).unwrap(), b"private sentinel");
        }
        if case == "public" {
            assert_eq!(fs::read(&path).unwrap(), b"public sentinel");
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }
    }
}

const DATABASE: &str = "coordinator.sqlite3";
fn runtime(root: &Path) -> std::sync::Arc<router_runtime::Runtime> {
    std::sync::Arc::new(
        router_runtime::Runtime::open(
            &root.with_file_name("runtime"),
            router_runtime::RuntimeLimits::default(),
        )
        .unwrap(),
    )
}
fn open_owner(root: &Path) -> router_coordinator::Coordinator {
    router_coordinator::Coordinator::open(root, runtime(root)).unwrap()
}
fn owner_refused(root: &Path) -> bool {
    router_coordinator::Coordinator::open(root, runtime(root)).is_err()
}
