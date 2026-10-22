#![cfg(unix)]

use router_local_api::{
    Error, HandlerError, Limits, RouteHandler, RouteInput, SOCKET_FILE, Server, TOKEN_FILE,
};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use tempfile::TempDir;

/// Echoes the three documents so tests can see exactly what was delivered.
struct Echo(Arc<AtomicUsize>);

impl RouteHandler for Echo {
    fn route(&self, input: RouteInput<'_>) -> Result<Vec<u8>, HandlerError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let mut out = Vec::new();
        out.extend_from_slice(input.request);
        out.push(b'|');
        out.extend_from_slice(input.catalog);
        out.push(b'|');
        out.extend_from_slice(input.host_snapshot.unwrap_or(b"-"));
        Ok(out)
    }
}

struct Running {
    dir: TempDir,
    socket: PathBuf,
    token: String,
    calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<(), Error>>>,
}

impl Running {
    fn start(limits: Limits) -> Self {
        let dir = private_tempdir();
        let calls = Arc::new(AtomicUsize::new(0));
        let server = Server::bind(dir.path(), limits, Echo(calls.clone())).expect("bind");
        let socket = server.socket_path().to_owned();
        let token = fs::read_to_string(dir.path().join(TOKEN_FILE))
            .expect("token")
            .trim()
            .to_owned();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = thread::spawn(move || server.serve(&flag));
        Self {
            dir,
            socket,
            token,
            calls,
            stop,
            thread: Some(thread),
        }
    }

    fn connect(&self) -> UnixStream {
        let stream = UnixStream::connect(&self.socket).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        stream
    }

    fn send(&self, raw: &[u8]) -> Reply {
        let mut stream = self.connect();
        stream.write_all(raw).expect("write");
        read_reply(&mut stream)
    }

    fn get(&self, path: &str, auth: Option<&str>) -> Reply {
        self.send(&raw("GET", path, auth, None, &[]))
    }

    fn post(&self, body: &str) -> Reply {
        let auth = format!("Bearer {}", self.token);
        self.send(&raw(
            "POST",
            "/v1/route",
            Some(&auth),
            Some(body.len()),
            body.as_bytes(),
        ))
    }

    fn stop(&mut self) -> Result<(), Error> {
        self.stop.store(true, Ordering::Release);
        self.thread.take().expect("thread").join().expect("join")
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Reply {
    status: u16,
    body: String,
}

fn raw(
    method: &str,
    path: &str,
    auth: Option<&str>,
    length: Option<usize>,
    body: &[u8],
) -> Vec<u8> {
    let mut text = format!("{method} {path} HTTP/1.1\r\nHost: local\r\n");
    if let Some(auth) = auth {
        text.push_str(&format!("Authorization: {auth}\r\n"));
    }
    if let Some(length) = length {
        text.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {length}\r\n"
        ));
    }
    text.push_str("\r\n");
    let mut bytes = text.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn read_reply(stream: &mut UnixStream) -> Reply {
    let mut bytes = Vec::new();
    let _ = stream.read_to_end(&mut bytes);
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    Reply {
        status,
        body: body.to_owned(),
    }
}

/// `tempfile` creates 0755 directories here; the server requires 0700.
fn private_tempdir() -> TempDir {
    let dir = tempfile::Builder::new()
        .prefix("rla")
        .tempdir()
        .expect("tempdir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    dir
}

const GOOD: &str = r#"{"request":{"r":1},"catalog":{"c":2},"host_snapshot":{"h":3}}"#;

#[test]
fn a_bound_socket_serves_authenticated_calls_only() {
    let server = Running::start(Limits::default());
    assert_eq!(server.get("/v1/health", None).status, 401);
    let health = server.get("/v1/health", Some(&format!("Bearer {}", server.token)));
    assert_eq!(health.status, 200);
    let route = server.post(GOOD);
    assert_eq!(route.status, 200);
    assert_eq!(route.body, r#"{"r":1}|{"c":2}|{"h":3}"#);
    assert_eq!(server.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn concurrent_connections_are_capped() {
    let limits = Limits {
        max_connections: 2,
        request_deadline: Duration::from_secs(3),
        ..Limits::default()
    };
    let server = Running::start(limits);
    let _idle_a = server.connect();
    let _idle_b = server.connect();
    thread::sleep(Duration::from_millis(200));
    let mut third = server.connect();
    let reply = read_reply(&mut third);
    assert_eq!(reply.status, 503);
    assert!(reply.body.contains("local_api.busy"));
    drop((_idle_a, _idle_b));
    thread::sleep(Duration::from_millis(300));
    let auth = format!("Bearer {}", server.token);
    assert_eq!(server.get("/v1/health", Some(&auth)).status, 200);
}

#[test]
fn state_files_are_private() {
    let server = Running::start(Limits::default());
    let mode = |path: &Path| fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode(&server.socket), 0o600);
    assert_eq!(mode(&server.dir.path().join(TOKEN_FILE)), 0o600);
    assert_eq!(mode(server.dir.path()), 0o700);
}

#[test]
fn shutdown_removes_the_socket() {
    let mut server = Running::start(Limits::default());
    assert!(server.socket.exists());
    assert_eq!(server.stop(), Ok(()));
    assert!(server.dir.path().exists());
    assert!(!server.socket.exists());
    assert!(UnixStream::connect(&server.socket).is_err());
}

#[test]
fn stale_sockets_are_replaced_and_a_second_start_is_refused() {
    let dir = private_tempdir();
    let socket = dir.path().join(SOCKET_FILE);
    // A socket file left by a killed process: bound, then abandoned.
    drop(std::os::unix::net::UnixListener::bind(&socket).expect("stale"));
    assert!(socket.exists());
    let first =
        Server::bind(dir.path(), Limits::default(), Echo(Arc::default())).expect("replaces stale");
    // The state directory lock refuses a concurrent start before it can touch
    // the first server's socket.
    let second = Server::bind(dir.path(), Limits::default(), Echo(Arc::default()));
    assert_eq!(
        second.err(),
        Some(Error::StateDir("local_api.state_dir.locked"))
    );
    assert!(
        socket.exists(),
        "the refused start must leave the live socket alone"
    );
    drop(first);
    assert!(!socket.exists());
    // The lock died with the server: the directory is usable again.
    drop(Server::bind(dir.path(), Limits::default(), Echo(Arc::default())).expect("restart"));
}

#[test]
fn a_socket_with_a_live_listener_is_never_replaced() {
    let dir = private_tempdir();
    let live = std::os::unix::net::UnixListener::bind(dir.path().join(SOCKET_FILE)).expect("live");
    let error = Server::bind(dir.path(), Limits::default(), Echo(Arc::default())).err();
    assert_eq!(error, Some(Error::Socket("local_api.socket.in_use")));
    drop(live);
}

#[test]
fn a_replaced_socket_is_not_removed_by_the_old_server() {
    let mut server = Running::start(Limits::default());
    let socket = server.socket.clone();
    // Someone else takes over the path with a different socket inode.
    fs::remove_file(&socket).expect("remove");
    let usurper = std::os::unix::net::UnixListener::bind(&socket).expect("usurper");
    assert_eq!(server.stop(), Ok(()));
    assert!(
        socket.exists(),
        "the guard must only remove the inode it bound"
    );
    drop(usurper);
}

#[test]
fn unsafe_state_locations_are_refused() {
    let limits = Limits::default();
    let bind = |path: &Path| Server::bind(path, limits, Echo(Arc::default())).err();
    let root = private_tempdir();

    let real = root.path().join("real");
    fs::create_dir(&real).expect("dir");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).expect("mode");
    let link = root.path().join("link");
    symlink(&real, &link).expect("symlink");
    assert_eq!(
        bind(&link),
        Some(Error::StateDir("local_api.state_dir.symlink"))
    );

    let open = root.path().join("open");
    fs::create_dir(&open).expect("dir");
    for mode in [0o755, 0o750, 0o770, 0o777, 0o500] {
        fs::set_permissions(&open, fs::Permissions::from_mode(mode)).expect("mode");
        assert_eq!(
            bind(&open),
            Some(Error::StateDir("local_api.state_dir.mode")),
            "{mode:o}"
        );
    }

    let file = root.path().join("file");
    fs::write(&file, b"x").expect("file");
    assert_eq!(
        bind(&file),
        Some(Error::StateDir("local_api.state_dir.not_directory"))
    );
    assert_eq!(
        bind(Path::new("relative/state")),
        Some(Error::StateDir("local_api.state_dir.relative"))
    );
}

#[test]
fn unsafe_token_and_socket_entries_are_refused() {
    let limits = Limits::default();
    let bind = |path: &Path| Server::bind(path, limits, Echo(Arc::default())).err();

    let dir = private_tempdir();
    let target = dir.path().join("elsewhere");
    fs::write(&target, "a".repeat(64)).expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("mode");
    symlink(&target, dir.path().join(TOKEN_FILE)).expect("symlink");
    assert_eq!(bind(dir.path()), Some(Error::Token("local_api.token.open")));

    let dir = private_tempdir();
    let token = dir.path().join(TOKEN_FILE);
    fs::write(&token, "a".repeat(64)).expect("token");
    fs::set_permissions(&token, fs::Permissions::from_mode(0o640)).expect("mode");
    assert_eq!(bind(dir.path()), Some(Error::Token("local_api.token.mode")));
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).expect("mode");
    fs::write(&token, "short").expect("token");
    assert_eq!(
        bind(dir.path()),
        Some(Error::Token("local_api.token.invalid"))
    );

    let dir = private_tempdir();
    symlink("/nonexistent", dir.path().join(SOCKET_FILE)).expect("symlink");
    assert_eq!(
        bind(dir.path()),
        Some(Error::Socket("local_api.socket.occupied"))
    );
    let dir = private_tempdir();
    fs::write(dir.path().join(SOCKET_FILE), b"x").expect("file");
    assert_eq!(
        bind(dir.path()),
        Some(Error::Socket("local_api.socket.occupied"))
    );
}

#[test]
fn invalid_limits_are_refused() {
    let dir = private_tempdir();
    for limits in [
        Limits {
            max_connections: 0,
            ..Limits::default()
        },
        Limits {
            max_body_bytes: 0,
            ..Limits::default()
        },
        Limits {
            request_deadline: Duration::ZERO,
            ..Limits::default()
        },
        Limits {
            request_deadline: Duration::from_secs(3600),
            ..Limits::default()
        },
    ] {
        let error = Server::bind(dir.path(), limits, Echo(Arc::default())).err();
        assert_eq!(error, Some(Error::Limits));
    }
}
