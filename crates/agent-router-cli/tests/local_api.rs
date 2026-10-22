#![cfg(all(feature = "local-api", unix))]

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_agent-router");

fn root(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

struct Service {
    child: Child,
    socket: PathBuf,
    token: String,
    _dir: tempfile::TempDir,
}

impl Service {
    fn start() -> Self {
        Self::start_with(&[])
    }

    fn start_with(extra: &[&str]) -> Self {
        let dir = tempfile::Builder::new()
            .prefix("ar")
            .tempdir()
            .expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("mode");
        let mut child = Command::new(BIN)
            .arg("serve")
            .arg("--state-dir")
            .arg(dir.path())
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().expect("stdout"))
            .read_line(&mut line)
            .expect("listening line");
        let announcement: serde_json::Value = serde_json::from_str(&line).unwrap_or_else(|_| {
            let mut stderr = String::new();
            let _ = child
                .stderr
                .as_mut()
                .expect("stderr")
                .read_to_string(&mut stderr);
            panic!("no listening line: {line:?} {stderr:?}")
        });
        let socket = PathBuf::from(announcement["socket"].as_str().expect("socket"));
        let token = fs::read_to_string(dir.path().join("token"))
            .expect("token")
            .trim()
            .to_owned();
        Self {
            child,
            socket,
            token,
            _dir: dir,
        }
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: &[u8],
    ) -> (u16, Vec<u8>) {
        let mut stream = UnixStream::connect(&self.socket).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let mut head = format!("{method} {path} HTTP/1.1\r\nHost: local\r\n");
        if let Some(token) = token {
            head.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ));
        stream.write_all(head.as_bytes()).expect("write head");
        stream.write_all(body).expect("write body");
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).expect("read");
        let split = reply
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("head end");
        let status = std::str::from_utf8(&reply[..split])
            .expect("head")
            .split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("status");
        (status, reply[split + 4..].to_vec())
    }

    fn route(&self, body: &[u8]) -> (u16, Vec<u8>) {
        self.request("POST", "/v1/route", Some(&self.token), body)
    }

    fn terminate(&mut self) -> std::process::ExitStatus {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("kill");
        assert!(status.success());
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().expect("wait") {
                return status;
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "no exit after SIGTERM"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const CATALOG: &str = "assets/catalogs/codex-core-v1.json";

/// The envelope embeds the fixture bytes unchanged.
fn envelope(request: &str, catalog: &str) -> Vec<u8> {
    let mut body = b"{\"request\":".to_vec();
    body.extend(fs::read(root(request)).expect("request"));
    body.extend_from_slice(b",\"catalog\":");
    body.extend(fs::read(root(catalog)).expect("catalog"));
    body.push(b'}');
    body
}

fn cli_route(request: &str) -> (Option<i32>, Vec<u8>) {
    let output = Command::new(BIN)
        .args(["route", "--request"])
        .arg(root(request))
        .arg("--catalog")
        .arg(root(CATALOG))
        .arg("--json")
        .output()
        .expect("route");
    (output.status.code(), output.stdout)
}

#[test]
fn route_output_is_byte_identical_to_the_cli_for_selected_and_no_route() {
    let service = Service::start();
    for (request, exit_code, marker) in [
        (
            "tests/fixtures/requests/codex-implementation.json",
            0,
            "\"selected\"",
        ),
        (
            "tests/fixtures/requests/no-compatible-plan.json",
            3,
            "\"no_route\"",
        ),
    ] {
        let (code, expected) = cli_route(request);
        assert_eq!(code, Some(exit_code), "{request}");
        assert!(String::from_utf8_lossy(&expected).contains(marker));
        let (status, body) = service.route(&envelope(request, CATALOG));
        assert_eq!(status, 200, "{request}");
        assert_eq!(body, expected, "{request}");
    }
}

#[test]
fn only_the_three_route_only_endpoints_exist() {
    let service = Service::start();
    let token = Some(service.token.as_str());
    assert_eq!(service.request("GET", "/v1/health", token, b"").0, 200);
    let (status, caps) = service.request("GET", "/v1/capabilities", token, b"");
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&caps).contains("route-only"));
    for path in [
        "/v1/execute",
        "/v1/feedback",
        "/v1/outcome",
        "/v1/grant",
        "/v1/activate",
        "/v1/catalog",
    ] {
        assert_eq!(service.request("POST", path, token, b"{}").0, 404, "{path}");
    }
    assert_eq!(service.request("GET", "/v1/route", token, b"").0, 405);
}

#[test]
fn token_and_path_bearing_bodies_are_refused() {
    let service = Service::start();
    let body = envelope("tests/fixtures/requests/codex-implementation.json", CATALOG);
    let wrong = "0".repeat(service.token.len());
    for token in [None, Some(wrong.as_str())] {
        let (status, reply) = service.request("POST", "/v1/route", token, &body);
        assert_eq!(status, 401);
        assert!(!String::from_utf8_lossy(&reply).contains(&service.token));
    }
    let with_path = br#"{"request_path":"/etc/passwd","catalog_path":"/etc/passwd"}"#;
    assert_eq!(service.route(with_path).0, 400);
    let mut duplicate = body.clone();
    duplicate.truncate(duplicate.len() - 1);
    duplicate.extend_from_slice(b",\"catalog\":{}}");
    assert_eq!(service.route(&duplicate).0, 400);
    let (status, reply) = service.route(br#"{"request":{},"catalog":{}}"#);
    assert_eq!(status, 400);
    assert!(String::from_utf8_lossy(&reply).contains("request.json.invalid"));
}

#[test]
fn sigterm_stops_the_service_and_removes_the_socket() {
    let mut service = Service::start();
    assert!(service.socket.exists());
    let status = service.terminate();
    assert!(status.success(), "{status:?}");
    assert!(!service.socket.exists());
}

#[test]
fn a_second_signal_forces_exit_while_a_connection_holds_the_shutdown() {
    let mut service = Service::start_with(&["--request-deadline-ms", "30000"]);
    // An idle connection keeps the graceful stop waiting for its deadline.
    let _idle = UnixStream::connect(&service.socket).expect("connect");
    std::thread::sleep(Duration::from_millis(200));
    let signal = |service: &Service| {
        let status = Command::new("kill")
            .args(["-TERM", &service.child.id().to_string()])
            .status()
            .expect("kill");
        assert!(status.success());
    };
    signal(&service);
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        service.child.try_wait().expect("wait").is_none(),
        "first signal stops gracefully"
    );
    signal(&service);
    let started = Instant::now();
    let status = loop {
        if let Some(status) = service.child.try_wait().expect("wait") {
            break status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "second signal did not force exit"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(130));
}

#[test]
fn a_second_server_on_the_same_state_dir_is_refused() {
    let service = Service::start();
    let state_dir = service.socket.parent().expect("state dir");
    let output = Command::new(BIN)
        .arg("serve")
        .arg("--state-dir")
        .arg(state_dir)
        .output()
        .expect("second serve");
    // Contention class: retrying succeeds once the first server stops.
    assert_eq!(output.status.code(), Some(5));
    assert!(String::from_utf8_lossy(&output.stderr).contains("local_api.state_dir.locked"));
    assert!(output.stdout.is_empty());
    assert!(service.socket.exists(), "the first server keeps its socket");
    assert_eq!(
        service
            .request("GET", "/v1/health", Some(&service.token), b"")
            .0,
        200
    );
}

#[test]
fn a_relative_state_dir_is_refused_without_serving() {
    let output = Command::new(BIN)
        .args(["serve", "--state-dir", "relative"])
        .output()
        .expect("serve");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("local_api.state_dir.relative"));
    assert!(output.stdout.is_empty());
}

#[test]
fn help_lists_serve_when_the_feature_is_enabled() {
    let output = Command::new(BIN).arg("--help").output().expect("help");
    assert!(String::from_utf8_lossy(&output.stdout).contains("serve"));
}
