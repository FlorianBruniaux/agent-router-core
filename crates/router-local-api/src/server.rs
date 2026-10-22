use crate::{
    error::Error,
    http::{self, Failure, Head, MAX_HEADER_BYTES},
    json,
    state::{self, SocketGuard},
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{ErrorKind, Read, Write},
    net::Shutdown,
    os::unix::net::{UnixListener, UnixStream},
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

/// Time allowed to write a response once the request is settled.
const RESPONSE_BUDGET: Duration = Duration::from_secs(2);
/// Time spent discarding unread request bytes before closing.
const DRAIN_BUDGET: Duration = Duration::from_millis(200);
const ACCEPT_POLL: Duration = Duration::from_millis(10);
const MAX_ACCEPT_BACKOFF: Duration = Duration::from_millis(500);

/// The three inline documents of `POST /v1/route`, exactly as sent.
pub struct RouteInput<'a> {
    pub request: &'a [u8],
    pub catalog: &'a [u8],
    pub host_snapshot: Option<&'a [u8]>,
}

/// A rejected route call. `code` is a stable identifier, never input content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlerError {
    pub status: u16,
    pub code: &'static str,
}

/// The only capability the server hands to its embedder.
pub trait RouteHandler: Send + Sync {
    /// Returns the exact response body bytes for a successful route call.
    fn route(&self, input: RouteInput<'_>) -> Result<Vec<u8>, HandlerError>;
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Largest accepted `Content-Length`.
    pub max_body_bytes: usize,
    /// Simultaneous connections being served; further ones get 503.
    pub max_connections: usize,
    /// Whole-request budget, from accept to the last body byte.
    pub request_deadline: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 9 * 1024 * 1024,
            max_connections: 16,
            request_deadline: Duration::from_secs(10),
        }
    }
}

impl Limits {
    fn validate(&self) -> Result<(), Error> {
        if (1..=64 * 1024 * 1024).contains(&self.max_body_bytes)
            && (1..=256).contains(&self.max_connections)
            && !self.request_deadline.is_zero()
            && self.request_deadline <= Duration::from_secs(60)
        {
            Ok(())
        } else {
            Err(Error::Limits)
        }
    }
}

pub struct Server<H> {
    listener: UnixListener,
    guard: SocketGuard,
    _lock: File,
    token_digest: [u8; 32],
    limits: Limits,
    handler: Arc<H>,
}

impl<H: RouteHandler> Server<H> {
    /// Prepares the private state directory, takes its lock, loads the token
    /// and binds the socket. A second server on the same directory is refused.
    pub fn bind(state_dir: &Path, limits: Limits, handler: H) -> Result<Self, Error> {
        limits.validate()?;
        state::prepare_state_dir(state_dir)?;
        let lock = state::lock_state_dir(state_dir)?;
        let token = state::load_or_create_token(state_dir)?;
        let (listener, guard) = state::bind_socket(state_dir)?;
        Ok(Self {
            listener,
            guard,
            _lock: lock,
            token_digest: Sha256::digest(&token).into(),
            limits,
            handler: Arc::new(handler),
        })
    }

    pub fn socket_path(&self) -> &Path {
        self.guard.path()
    }

    /// Serves until `shutdown` is set, then waits for in-flight connections and
    /// removes the socket. Reading a request is bounded by the request deadline,
    /// then the response write by a fixed 2 s budget and the drain by a fixed
    /// 200 ms, none of which a slow peer can extend. `RouteHandler::route` runs
    /// between the read and the write, synchronously and outside those bounds:
    /// the server does not interrupt it, so a slot is held for as long as the
    /// handler runs.
    pub fn serve(self, shutdown: &AtomicBool) -> Result<(), Error> {
        let context = Context {
            token_digest: self.token_digest,
            limits: self.limits,
            handler: &self.handler,
        };
        let result = accept_loop(&self.listener, &context, shutdown);
        drop(self.guard);
        result
    }
}

trait Acceptor {
    fn accept(&self) -> std::io::Result<UnixStream>;
}

impl Acceptor for UnixListener {
    fn accept(&self) -> std::io::Result<UnixStream> {
        UnixListener::accept(self).map(|(stream, _)| stream)
    }
}

/// One connection slot, released on every exit path including a panic.
struct Slot<'a>(&'a AtomicUsize);

impl<'a> Slot<'a> {
    fn acquire(active: &'a AtomicUsize, max: usize) -> Option<Self> {
        if active.fetch_add(1, Ordering::AcqRel) >= max {
            active.fetch_sub(1, Ordering::AcqRel);
            None
        } else {
            Some(Self(active))
        }
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Resource exhaustion and aborted handshakes are transient: the server keeps
/// running and retries instead of dying under load.
fn transient_accept_error(error: &std::io::Error) -> bool {
    error.kind() == ErrorKind::ConnectionAborted
        || error.raw_os_error().is_some_and(|code| {
            [
                libc::EMFILE,
                libc::ENFILE,
                libc::ECONNABORTED,
                libc::ENOBUFS,
                libc::ENOMEM,
            ]
            .contains(&code)
        })
}

fn accept_loop<H: RouteHandler, A: Acceptor>(
    acceptor: &A,
    context: &Context<'_, H>,
    shutdown: &AtomicBool,
) -> Result<(), Error> {
    let active = AtomicUsize::new(0);
    let mut failure = None;
    let mut backoff = ACCEPT_POLL;
    thread::scope(|scope| {
        while !shutdown.load(Ordering::Acquire) {
            match acceptor.accept() {
                Ok(stream) => {
                    backoff = ACCEPT_POLL;
                    // BSD-derived systems hand out non-blocking sockets.
                    if stream.set_nonblocking(false).is_err() {
                        continue;
                    }
                    let Some(slot) = Slot::acquire(&active, context.limits.max_connections) else {
                        reject_busy(stream);
                        continue;
                    };
                    let fallback = stream.try_clone().ok();
                    let spawned = thread::Builder::new()
                        .name("local-api-connection".into())
                        .spawn_scoped(scope, move || {
                            let _slot = slot;
                            // A panic must neither leak the slot nor unwind the scope.
                            let _ = catch_unwind(AssertUnwindSafe(|| context.connection(stream)));
                        });
                    if spawned.is_err() {
                        // The closure, and with it the slot, is already dropped.
                        if let Some(stream) = fallback {
                            reject_busy(stream);
                        }
                        thread::sleep(backoff);
                        backoff = (backoff * 2).min(MAX_ACCEPT_BACKOFF);
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) if transient_accept_error(&error) => {
                    thread::sleep(backoff);
                    backoff = (backoff * 2).min(MAX_ACCEPT_BACKOFF);
                }
                Err(_) => {
                    failure = Some(Error::Io);
                    break;
                }
            }
        }
    });
    failure.map_or(Ok(()), Err)
}

struct Context<'a, H> {
    token_digest: [u8; 32],
    limits: Limits,
    handler: &'a Arc<H>,
}

impl<H: RouteHandler> Context<'_, H> {
    fn connection(&self, mut stream: UnixStream) {
        let deadline = Instant::now() + self.limits.request_deadline;
        let (status, body, extra) = match self.exchange(&mut stream, deadline) {
            Ok(body) => (200, body, None),
            Err(failure) => (
                failure.status,
                error_body(failure.code),
                extra_header(failure.status),
            ),
        };
        let _ = write_response(&mut stream, status, &body, extra);
        drain_and_close(stream);
    }

    fn exchange(&self, stream: &mut UnixStream, deadline: Instant) -> Result<Vec<u8>, Failure> {
        let (head, rest) = http::read_head(stream, deadline)?;
        // Authenticate before revealing anything about routes or methods.
        self.authenticate(&head)?;
        let post = match (head.method.as_str(), head.target.as_str()) {
            ("GET", "/v1/health") => false,
            ("GET", "/v1/capabilities") => false,
            ("POST", "/v1/route") => true,
            (_, "/v1/health" | "/v1/capabilities" | "/v1/route") => {
                return Err(Failure::new(405, "http.method"));
            }
            _ => return Err(Failure::new(404, "http.not_found")),
        };
        if !post {
            if head.content_length.unwrap_or(0) != 0 || !rest.is_empty() {
                return Err(Failure::new(400, "http.unexpected_body"));
            }
            return if head.target == "/v1/health" {
                Ok(b"{\"schema_version\":1,\"status\":\"ok\"}\n".to_vec())
            } else {
                self.capabilities()
            };
        }
        let length = head
            .content_length
            .ok_or(Failure::new(411, "http.length_required"))?;
        if length > self.limits.max_body_bytes {
            return Err(Failure::new(413, "http.body_too_large"));
        }
        if !head.content_type_json {
            return Err(Failure::new(415, "http.content_type"));
        }
        let body = http::read_body(stream, rest, length, deadline)?;
        let envelope = json::parse_envelope(&body).map_err(|code| Failure::new(400, code))?;
        let routed = catch_unwind(AssertUnwindSafe(|| {
            self.handler.route(RouteInput {
                request: envelope.request,
                catalog: envelope.catalog,
                host_snapshot: envelope.host_snapshot,
            })
        }));
        match routed {
            Ok(result) => result.map_err(|error| Failure::new(error.status, error.code)),
            Err(_) => Err(Failure::new(500, "local_api.handler_panic")),
        }
    }

    fn authenticate(&self, head: &Head) -> Result<(), Failure> {
        let denied = Failure::new(401, "auth.required");
        let value = head.authorization.as_deref().ok_or(denied)?;
        let (scheme, token) = value
            .iter()
            .position(|&byte| byte == b' ')
            .map(|at| (&value[..at], &value[at + 1..]))
            .ok_or(denied)?;
        // Hash both sides so the comparison time does not depend on length.
        let presented: [u8; 32] = Sha256::digest(token).into();
        let token_matches = bool::from(presented.ct_eq(&self.token_digest));
        if scheme.eq_ignore_ascii_case(b"bearer") && token_matches {
            Ok(())
        } else {
            Err(denied)
        }
    }

    fn capabilities(&self) -> Result<Vec<u8>, Failure> {
        let mut body = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "api_version": "v1",
            "authority": "route-only",
            "transport": "unix",
            "endpoints": ["GET /v1/health", "GET /v1/capabilities", "POST /v1/route"],
            "limits": {
                "max_body_bytes": self.limits.max_body_bytes,
                "max_header_bytes": MAX_HEADER_BYTES,
                "max_connections": self.limits.max_connections,
                "request_deadline_ms": self.limits.request_deadline.as_millis() as u64,
            },
        }))
        .map_err(|_| Failure::new(500, "local_api.internal"))?;
        body.push(b'\n');
        Ok(body)
    }
}

/// `schema_version` first, as documented; `json!` would sort the keys.
fn error_body(code: &str) -> Vec<u8> {
    let code = serde_json::to_string(code).unwrap_or_else(|_| "\"local_api.internal\"".into());
    format!("{{\"schema_version\":1,\"error\":{code}}}\n").into_bytes()
}

fn extra_header(status: u16) -> Option<&'static str> {
    match status {
        401 => Some("WWW-Authenticate: Bearer\r\n"),
        405 => Some("Allow: GET, POST\r\n"),
        _ => None,
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        417 => "Expectation Failed",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ if status >= 500 => "Internal Server Error",
        _ => "Bad Request",
    }
}

/// Writes all of `bytes` before `deadline`; the budget covers the whole write,
/// so a peer that reads one byte at a time cannot extend it. The socket is
/// polled in non-blocking mode because a send timeout is not honoured for every
/// socket type on every platform, while this bound must hold.
fn write_all_by(stream: &mut UnixStream, bytes: &[u8], deadline: Instant) -> std::io::Result<()> {
    stream.set_nonblocking(true)?;
    let result = write_polled(stream, bytes, deadline);
    let _ = stream.set_nonblocking(false);
    result
}

fn write_polled(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(ErrorKind::TimedOut.into());
        }
        match stream.write(bytes) {
            Ok(0) => return Err(ErrorKind::WriteZero.into()),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_response(
    stream: &mut UnixStream,
    status: u16,
    body: &[u8],
    extra: Option<&str>,
) -> std::io::Result<()> {
    let deadline = Instant::now() + RESPONSE_BUDGET;
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n{}\r\n",
        reason(status),
        body.len(),
        extra.unwrap_or("")
    );
    write_all_by(stream, head.as_bytes(), deadline)?;
    write_all_by(stream, body, deadline)
}

/// Runs on the accept thread, so it gets the drain budget, not the full one.
fn reject_busy(mut stream: UnixStream) {
    let body = error_body("local_api.busy");
    let head = format!(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let deadline = Instant::now() + DRAIN_BUDGET;
    let _ = write_all_by(&mut stream, head.as_bytes(), deadline)
        .and_then(|()| write_all_by(&mut stream, &body, deadline));
    let _ = stream.shutdown(Shutdown::Both);
}

/// Closing with unread request bytes can reset the connection before the
/// client reads the response. Discard for a fixed, global 200 ms at most.
fn drain_and_close(mut stream: UnixStream) {
    let _ = stream.shutdown(Shutdown::Write);
    let deadline = Instant::now() + DRAIN_BUDGET;
    let mut sink = [0u8; 4096];
    let mut drained = 0usize;
    while drained < 256 * 1024 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
            break;
        }
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(read) => drained += read,
        }
    }
}

#[cfg(test)]
mod tests {
    //! Protocol tests over `socketpair`, so they exercise the same connection
    //! code as a bound socket without needing to bind one.
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};

    #[test]
    fn error_body_keeps_the_documented_field_order() {
        assert_eq!(
            error_body("local_api.unauthorized"),
            b"{\"schema_version\":1,\"error\":\"local_api.unauthorized\"}\n".to_vec()
        );
    }

    struct Echo(AtomicUsize);

    impl RouteHandler for Echo {
        fn route(&self, input: RouteInput<'_>) -> Result<Vec<u8>, HandlerError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            assert_ne!(
                input.request, br#""boom""#,
                "handler failure injected by a test"
            );
            let mut out = input.request.to_vec();
            out.push(b'|');
            out.extend_from_slice(input.catalog);
            out.push(b'|');
            out.extend_from_slice(input.host_snapshot.unwrap_or(b"-"));
            Ok(out)
        }
    }

    struct Reply {
        status: u16,
        head: String,
        body: String,
    }

    struct Harness {
        token: String,
        limits: Limits,
        handler: Arc<Echo>,
    }

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";
    const GOOD: &str = r#"{"request":{"r":1},"catalog":{"c":2},"host_snapshot":{"h":3}}"#;

    impl Harness {
        fn new(limits: Limits) -> Self {
            Self {
                token: TOKEN.to_owned(),
                limits,
                handler: Arc::new(Echo(AtomicUsize::new(0))),
            }
        }

        fn calls(&self) -> usize {
            self.handler.0.load(Ordering::SeqCst)
        }

        fn context(&self) -> Context<'_, Echo> {
            Context {
                token_digest: Sha256::digest(self.token.as_bytes()).into(),
                limits: self.limits,
                handler: &self.handler,
            }
        }

        /// Runs `client` against one served connection.
        fn with_client<T: Send>(&self, client: impl FnOnce(&mut UnixStream) -> T + Send) -> T {
            let (mut near, far) = UnixStream::pair().expect("pair");
            near.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            let context = self.context();
            thread::scope(|scope| {
                scope.spawn(|| context.connection(far));
                client(&mut near)
            })
        }

        fn send(&self, raw: &[u8]) -> Reply {
            self.with_client(|stream| {
                // The server may answer and close before reading everything.
                let _ = stream.write_all(raw);
                read_reply(stream)
            })
        }

        fn get(&self, path: &str, auth: Option<&str>) -> Reply {
            self.send(&raw("GET", path, auth, None, b""))
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

        fn bearer(&self) -> String {
            format!("Bearer {}", self.token)
        }
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
        Reply {
            status: head
                .split(' ')
                .nth(1)
                .and_then(|code| code.parse().ok())
                .unwrap_or(0),
            head: head.to_owned(),
            body: body.to_owned(),
        }
    }

    #[test]
    fn authenticated_calls_reach_the_handler_with_untouched_documents() {
        let harness = Harness::new(Limits::default());
        let auth = harness.bearer();
        let health = harness.get("/v1/health", Some(&auth));
        assert_eq!(health.status, 200);
        assert_eq!(health.body, "{\"schema_version\":1,\"status\":\"ok\"}\n");
        let caps = harness.get("/v1/capabilities", Some(&auth.replace("Bearer", "bearer")));
        assert_eq!(caps.status, 200);
        assert!(
            caps.body.contains("\"authority\":\"route-only\""),
            "{}",
            caps.body
        );
        assert!(caps.head.contains("Content-Type: application/json"));
        let route = harness.post(GOOD);
        assert_eq!(route.status, 200);
        assert_eq!(route.body, r#"{"r":1}|{"c":2}|{"h":3}"#);
        assert_eq!(
            harness.post(r#"{"catalog":{},"request":{}}"#).body,
            "{}|{}|-"
        );
    }

    #[test]
    fn missing_or_wrong_token_is_401_and_never_echoed() {
        let harness = Harness::new(Limits::default());
        let wrong = "x".repeat(TOKEN.len());
        for auth in [
            None,
            Some(format!("Bearer {wrong}")),
            Some("Bearer ".to_owned()),
            Some(format!("Basic {TOKEN}")),
            Some(TOKEN.to_owned()),
            Some(format!("Bearer {TOKEN}x")),
            Some(format!("Bearer {}", &TOKEN[1..])),
        ] {
            let reply = harness.get("/v1/health", auth.as_deref());
            assert_eq!(reply.status, 401, "{auth:?}");
            assert!(reply.head.contains("WWW-Authenticate: Bearer"));
            assert!(!reply.head.contains(TOKEN) && !reply.body.contains(TOKEN));
            assert!(!reply.body.contains(&wrong));
        }
        // Unauthenticated callers learn nothing about routes or methods.
        assert_eq!(harness.get("/nope", None).status, 401);
        assert_eq!(
            harness
                .send(&raw("DELETE", "/v1/route", None, None, b""))
                .status,
            401
        );
        let post = raw("POST", "/v1/route", None, Some(GOOD.len()), GOOD.as_bytes());
        assert_eq!(harness.send(&post).status, 401);
        assert_eq!(harness.calls(), 0);
    }

    #[test]
    fn unknown_paths_and_methods_are_404_and_405() {
        let harness = Harness::new(Limits::default());
        let auth = harness.bearer();
        assert_eq!(harness.get("/v1/execute", Some(&auth)).status, 404);
        assert_eq!(harness.get("/v1/health?x=1", Some(&auth)).status, 404);
        assert_eq!(harness.get("/v1/route", Some(&auth)).status, 405);
        for method in ["PUT", "DELETE", "PATCH"] {
            let reply = harness.send(&raw(method, "/v1/route", Some(&auth), Some(2), b"{}"));
            assert_eq!(reply.status, 405, "{method}");
        }
        assert_eq!(
            harness
                .send(&raw("POST", "/v1/health", Some(&auth), Some(2), b"{}"))
                .status,
            405
        );
        assert_eq!(harness.calls(), 0);
    }

    #[test]
    fn oversized_bodies_are_413_before_the_body_is_read() {
        let harness = Harness::new(Limits {
            max_body_bytes: 64,
            ..Limits::default()
        });
        let auth = harness.bearer();
        assert_eq!(
            harness
                .send(&raw("POST", "/v1/route", Some(&auth), Some(65), b""))
                .status,
            413
        );
        let fits = format!(r#"{{"request":{{}},"catalog":{{}}{}}}"#, " ".repeat(20));
        assert!(fits.len() <= 64);
        assert_eq!(harness.post(&fits).status, 200);
        assert_eq!(harness.calls(), 1);
    }

    #[test]
    fn headers_beyond_16_kib_are_431() {
        let harness = Harness::new(Limits::default());
        let auth = harness.bearer();
        let big = format!(
            "GET /v1/health HTTP/1.1\r\nAuthorization: {auth}\r\nX-Pad: {}\r\n\r\n",
            "a".repeat(MAX_HEADER_BYTES)
        );
        assert_eq!(harness.send(big.as_bytes()).status, 431);
        // A head that never terminates is bounded too.
        let open = format!(
            "GET /v1/health HTTP/1.1\r\nX-Pad: {}",
            "a".repeat(20 * 1024)
        );
        assert_eq!(harness.send(open.as_bytes()).status, 431);
        let pad = "a".repeat(MAX_HEADER_BYTES - 200);
        let fits =
            format!("GET /v1/health HTTP/1.1\r\nAuthorization: {auth}\r\nX-Pad: {pad}\r\n\r\n");
        assert!(fits.len() < MAX_HEADER_BYTES);
        assert_eq!(harness.send(fits.as_bytes()).status, 200);
    }

    #[test]
    fn transfer_encoding_and_chunked_bodies_are_refused() {
        let harness = Harness::new(Limits::default());
        let auth = harness.bearer();
        let post = |extra: &str, body: &str| {
            format!(
                "POST /v1/route HTTP/1.1\r\nAuthorization: {auth}\r\nContent-Type: application/json\r\n{extra}\r\n{body}"
            )
        };
        for request in [
            post("Transfer-Encoding: chunked\r\n", "2\r\n{}\r\n0\r\n\r\n"),
            post("Content-Length: 2\r\nTransfer-Encoding: identity\r\n", "{}"),
            post("Content-Length: 2\r\nContent-Length: 2\r\n", "{}"),
        ] {
            assert_eq!(harness.send(request.as_bytes()).status, 400, "{request}");
        }
        assert_eq!(harness.calls(), 0);
    }

    #[test]
    fn pipelined_bytes_after_the_body_are_refused() {
        let harness = Harness::new(Limits::default());
        let body = r#"{"request":{},"catalog":{}}"#;
        let mut request = raw(
            "POST",
            "/v1/route",
            Some(&harness.bearer()),
            Some(body.len()),
            body.as_bytes(),
        );
        request.extend_from_slice(b"GET /v1/health HTTP/1.1\r\n\r\n");
        let reply = harness.send(&request);
        assert_eq!(reply.status, 400);
        assert!(reply.body.contains("http.pipelined"), "{}", reply.body);
        assert_eq!(harness.calls(), 0);
    }

    #[test]
    fn body_framing_and_content_type_are_enforced() {
        let harness = Harness::new(Limits::default());
        let auth = harness.bearer();
        let no_length = format!("POST /v1/route HTTP/1.1\r\nAuthorization: {auth}\r\n\r\n");
        assert_eq!(harness.send(no_length.as_bytes()).status, 411);
        let text = format!(
            "POST /v1/route HTTP/1.1\r\nAuthorization: {auth}\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{{}}"
        );
        assert_eq!(harness.send(text.as_bytes()).status, 415);
        assert_eq!(
            harness
                .send(&raw("GET", "/v1/health", Some(&auth), Some(2), b"{}"))
                .status,
            400
        );
        // Fewer body bytes than declared: the client hangs up early.
        let short = harness.with_client(|stream| {
            let _ = stream.write_all(&raw("POST", "/v1/route", Some(&auth), Some(50), b"{}"));
            let _ = stream.shutdown(Shutdown::Write);
            read_reply(stream)
        });
        assert_eq!(short.status, 400);
        assert_eq!(harness.calls(), 0);
    }

    #[test]
    fn unknown_fields_duplicate_keys_and_malformed_json_never_reach_the_handler() {
        let harness = Harness::new(Limits::default());
        for body in [
            r#"{"request":{},"catalog":{},"path":"/etc/passwd"}"#,
            r#"{"request":{},"request":{},"catalog":{}}"#,
            r#"{"request":{"a":1,"a":2},"catalog":{}}"#,
            r#"{"request":{},"catalog":{"a":{"b":1,"b":2}}}"#,
            r#"{"request":{}}"#,
            r#"[{"request":{},"catalog":{}}]"#,
            r#"{"request":{},"catalog":{}} trailing"#,
            "",
        ] {
            assert_eq!(harness.post(body).status, 400, "{body}");
        }
        assert_eq!(harness.calls(), 0);
    }

    #[test]
    fn a_slow_client_is_cut_at_the_deadline() {
        let harness = Harness::new(Limits {
            request_deadline: Duration::from_millis(400),
            ..Limits::default()
        });
        let started = Instant::now();
        // Trickle bytes: each write is fast, the request as a whole is not.
        let status = harness.with_client(|stream| {
            stream
                .write_all(b"GET /v1/health HTTP/1.1\r\n")
                .expect("write");
            for _ in 0..40 {
                thread::sleep(Duration::from_millis(50));
                if stream.write_all(b"X: y\r\n").is_err() {
                    break;
                }
            }
            read_reply(stream).status
        });
        assert_eq!(status, 408);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
        // A silent client is cut too.
        let silent = harness.with_client(read_reply);
        assert_eq!(silent.status, 408);
        // The next connection is served normally.
        let auth = harness.bearer();
        assert_eq!(harness.get("/v1/health", Some(&auth)).status, 200);
    }

    /// Accepts from a queue, so the accept loop runs without binding a socket
    /// and accept errors can be injected.
    struct Queue(Mutex<VecDeque<std::io::Result<UnixStream>>>);

    impl Queue {
        fn new() -> Self {
            Self(Mutex::new(VecDeque::new()))
        }

        fn connect(&self) -> UnixStream {
            let (near, far) = UnixStream::pair().expect("pair");
            near.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            self.0.lock().expect("queue").push_back(Ok(far));
            near
        }

        fn fail(&self, code: i32) {
            let error = std::io::Error::from_raw_os_error(code);
            self.0.lock().expect("queue").push_back(Err(error));
        }

        fn pending(&self) -> usize {
            self.0.lock().expect("queue").len()
        }
    }

    impl Acceptor for Queue {
        fn accept(&self) -> std::io::Result<UnixStream> {
            let next = self.0.lock().expect("queue").pop_front();
            next.unwrap_or_else(|| Err(ErrorKind::WouldBlock.into()))
        }
    }

    /// Runs the accept loop while `client` talks to it, then shuts it down.
    fn with_loop<T: Send>(
        harness: &Harness,
        queue: &Queue,
        client: impl FnOnce() -> T + Send,
    ) -> (T, Result<(), Error>) {
        let shutdown = AtomicBool::new(false);
        let context = harness.context();
        thread::scope(|scope| {
            let serving = scope.spawn(|| accept_loop(queue, &context, &shutdown));
            let out = catch_unwind(AssertUnwindSafe(client));
            shutdown.store(true, Ordering::Release);
            let served = serving.join();
            match out {
                Ok(out) => (out, served.expect("loop must not panic")),
                Err(panic) => std::panic::resume_unwind(panic),
            }
        })
    }

    fn health(harness: &Harness, stream: &mut UnixStream) -> Reply {
        stream
            .write_all(&raw(
                "GET",
                "/v1/health",
                Some(&harness.bearer()),
                None,
                b"",
            ))
            .expect("write");
        read_reply(stream)
    }

    /// A finished connection frees its slot when its thread notices the close,
    /// a moment after the client read the reply; only a leak keeps answering 503.
    fn health_when_free(harness: &Harness, queue: &Queue) -> u16 {
        let started = Instant::now();
        loop {
            let status = health(harness, &mut queue.connect()).status;
            if status != 503 || started.elapsed() > Duration::from_secs(2) {
                return status;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_panicking_client_stops_the_loop_and_preserves_its_panic() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let harness = Harness::new(Limits::default());
            let queue = Queue::new();
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                with_loop::<()>(&harness, &queue, || {
                    panic!("client failure injected by a test");
                })
            }));
            let _ = sender.send(outcome);
        });
        // Do not join before the timeout: the old helper strands its scoped
        // server thread when the client panics, so joining would hang this test.
        let outcome = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("client panic must not strand the accept loop");
        worker.join().expect("test worker must not panic");
        let panic = outcome.expect_err("client panic must propagate");
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"client failure injected by a test")
        );
    }

    #[test]
    fn the_accept_loop_serves_connections_and_stops_on_shutdown() {
        let harness = Harness::new(Limits::default());
        let queue = Queue::new();
        let (statuses, result) = with_loop(&harness, &queue, || {
            (0..3)
                .map(|_| health(&harness, &mut queue.connect()).status)
                .collect::<Vec<_>>()
        });
        assert_eq!(statuses, [200, 200, 200]);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn transient_accept_errors_are_retried_and_others_stop_the_server() {
        let harness = Harness::new(Limits::default());
        let queue = Queue::new();
        for code in [
            libc::EMFILE,
            libc::ENFILE,
            libc::ECONNABORTED,
            libc::ENOBUFS,
            libc::ENOMEM,
        ] {
            queue.fail(code);
        }
        let (status, result) = with_loop(&harness, &queue, || {
            health(&harness, &mut queue.connect()).status
        });
        assert_eq!(status, 200, "served after five transient errors");
        assert_eq!(result, Ok(()));

        queue.fail(libc::EINVAL);
        let shutdown = AtomicBool::new(false);
        let result = accept_loop(&queue, &harness.context(), &shutdown);
        assert_eq!(
            result,
            Err(Error::Io),
            "a non-transient error must not be swallowed"
        );
        assert!(!shutdown.load(Ordering::Acquire));
    }

    #[test]
    fn a_panicking_handler_answers_500_and_costs_no_slot() {
        let harness = Harness::new(Limits {
            max_connections: 1,
            ..Limits::default()
        });
        let queue = Queue::new();
        let auth = harness.bearer();
        let boom = r#"{"request":"boom","catalog":{}}"#;
        let (statuses, result) = with_loop(&harness, &queue, || {
            let mut statuses = Vec::new();
            for _ in 0..3 {
                let mut stream = queue.connect();
                let request = raw(
                    "POST",
                    "/v1/route",
                    Some(&auth),
                    Some(boom.len()),
                    boom.as_bytes(),
                );
                stream.write_all(&request).expect("write");
                let reply = read_reply(&mut stream);
                assert!(
                    reply.body.contains("local_api.handler_panic"),
                    "{}",
                    reply.body
                );
                statuses.push(reply.status);
                // With one slot, a leaked slot would turn this into a 503.
                statuses.push(health_when_free(&harness, &queue));
            }
            statuses
        });
        assert_eq!(statuses, [500, 200, 500, 200, 500, 200]);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn a_slot_is_released_when_its_owner_panics() {
        let active = AtomicUsize::new(0);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let _slot = Slot::acquire(&active, 1).expect("free slot");
            assert!(Slot::acquire(&active, 1).is_none(), "cap reached");
            panic!("owner failure injected by a test");
        }));
        assert!(outcome.is_err());
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(Slot::acquire(&active, 1).is_some());
    }

    #[test]
    fn the_connection_cap_answers_503_and_frees_slots_at_the_deadline() {
        let harness = Harness::new(Limits {
            max_connections: 1,
            request_deadline: Duration::from_millis(500),
            ..Limits::default()
        });
        let queue = Queue::new();
        let (statuses, result) = with_loop(&harness, &queue, || {
            let mut idle = queue.connect();
            thread::sleep(Duration::from_millis(100));
            let busy = read_reply(&mut queue.connect());
            assert!(busy.body.contains("local_api.busy"));
            let timed_out = read_reply(&mut idle);
            let after = health_when_free(&harness, &queue);
            [busy.status, timed_out.status, after]
        });
        assert_eq!(statuses, [503, 408, 200]);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn shutdown_completes_an_in_flight_connection_within_its_deadline() {
        let harness = Harness::new(Limits {
            request_deadline: Duration::from_millis(400),
            ..Limits::default()
        });
        let queue = Queue::new();
        let started = Instant::now();
        let (reply, result) = with_loop(&harness, &queue, || {
            let idle = queue.connect();
            thread::sleep(Duration::from_millis(100));
            // The loop has accepted `idle`; shutdown is requested right after.
            idle.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            idle
        });
        // `with_loop` returned: the loop joined its in-flight connection.
        assert!(
            started.elapsed() < Duration::from_millis(2500),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(result, Ok(()));
        let mut idle = reply;
        assert_eq!(
            read_reply(&mut idle).status,
            408,
            "in-flight request was answered, not dropped"
        );
        // Nothing is accepted once shutdown was requested.
        let late = queue.connect();
        assert_eq!(queue.pending(), 1);
        drop(late);
    }

    #[test]
    fn a_trickling_peer_cannot_hold_a_slot_past_the_deadline() {
        let harness = Harness::new(Limits {
            request_deadline: Duration::from_millis(400),
            ..Limits::default()
        });
        let (mut near, far) = UnixStream::pair().expect("pair");
        let context = harness.context();
        let (served, peer_gave_up) = thread::scope(|scope| {
            let connection = scope.spawn(|| {
                let started = Instant::now();
                context.connection(far);
                started.elapsed()
            });
            // One byte every 90 ms, for far longer than any server budget. The
            // same trickle continues while the server drains after answering.
            let started = Instant::now();
            let _ = near.write_all(b"GET /v1/health HTTP/1.1\r\n");
            while started.elapsed() < Duration::from_secs(4) {
                thread::sleep(Duration::from_millis(90));
                if near.write_all(b"x").is_err() {
                    break;
                }
            }
            (connection.join().expect("join"), started.elapsed())
        });
        // deadline 400 ms + drain 200 ms, plus scheduling slack.
        assert!(
            served < Duration::from_millis(1300),
            "slot held for {served:?}"
        );
        assert!(
            peer_gave_up < Duration::from_secs(2),
            "the server closed on the peer: {peer_gave_up:?}"
        );
    }

    #[test]
    fn a_peer_that_reads_slowly_cannot_stall_a_response_write() {
        let (mut far, near) = UnixStream::pair().expect("pair");
        let stop = AtomicBool::new(false);
        thread::scope(|scope| {
            scope.spawn(|| {
                // One byte every 90 ms: each syscall makes progress.
                let mut near = near;
                let mut byte = [0u8; 1];
                while !stop.load(Ordering::Acquire)
                    && near.read(&mut byte).is_ok_and(|read| read == 1)
                {
                    thread::sleep(Duration::from_millis(90));
                }
            });
            let started = Instant::now();
            let payload = vec![0u8; 8 * 1024 * 1024];
            let result = write_all_by(&mut far, &payload, started + Duration::from_millis(300));
            let elapsed = started.elapsed();
            stop.store(true, Ordering::Release);
            assert!(result.is_err());
            assert!(elapsed < Duration::from_millis(900), "{elapsed:?}");
        });
    }
}
