//! Private parent-owned subscription channel. No credentials or network egress.
use super::*;
use crate::Cancellation;
use serde_json::{Value, json};
use std::net::{Shutdown, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionControllerBinding {
    pub assignment_id: String,
    pub configuration_sha256: String,
    pub account_sha256: String,
    pub controller_sha256: String,
    pub channel_instance_sha256: String,
    pub nonce: String,
}
#[derive(Default, Clone, serde::Serialize)]
pub(crate) struct SubscriptionObservation {
    pub(crate) known_prefix_tokens: u64,
    pub(crate) equivalent_microcredits: u64,
    pub(crate) verified_responses: u64,
    pub(crate) usage_unknown: bool,
}
pub struct OwnedSubscriptionController {
    binding: SubscriptionControllerBinding,
    io: Mutex<UnixStream>,
    active: Mutex<Option<Value>>,
    started: Mutex<Option<Instant>>,
    stopping: AtomicBool,
    cancelled: Mutex<Option<Cancellation>>,
    terminal_count: Mutex<u64>,
    observation: Mutex<SubscriptionObservation>,
}
pub struct SubscriptionControllerPeer(UnixStream);
impl SubscriptionControllerPeer {
    pub fn into_transport(self) -> UnixStream {
        self.0
    }
}
impl OwnedSubscriptionController {
    pub fn pair(
        assignment_id: &str,
        configuration_sha256: &str,
        account_sha256: &str,
        controller_sha256: &str,
    ) -> Result<(Self, SubscriptionControllerPeer)> {
        let parts: Vec<_> = assignment_id.split('-').collect();
        if parts.len() != 4
            || !matches!(parts[0], "t02" | "t05" | "t08")
            || !matches!(parts[1], "Lm" | "Lx" | "Am" | "Ax")
            || parts[2] != "r1"
            || !matches!(parts[3], "H0" | "H1")
            || [configuration_sha256, account_sha256, controller_sha256]
                .iter()
                .any(|v| !is_digest(v))
        {
            return Err(RuntimeError::Invalid("subscription binding"));
        }
        let mut nonce = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        let nonce = hex::encode(nonce);
        let binding = SubscriptionControllerBinding {
            assignment_id: assignment_id.into(),
            configuration_sha256: configuration_sha256.into(),
            account_sha256: account_sha256.into(),
            controller_sha256: controller_sha256.into(),
            channel_instance_sha256: crate::digest("subscription-private-pair-v1", &nonce)?,
            nonce,
        };
        let (io, peer) = UnixStream::pair()?;
        Ok((
            Self {
                binding,
                io: Mutex::new(io),
                active: Mutex::new(None),
                started: Mutex::new(None),
                stopping: AtomicBool::new(false),
                cancelled: Mutex::new(None),
                terminal_count: Mutex::new(0),
                observation: Mutex::new(SubscriptionObservation::default()),
            },
            SubscriptionControllerPeer(peer),
        ))
    }
    pub(super) fn ready(&self, run_id: &str, approval_digest: &str) -> Result<()> {
        if run_id.is_empty() || run_id.len() > 96 || !is_digest(approval_digest) {
            return Err(RuntimeError::Invalid("controller run identity"));
        }
        let mut active = self.active.lock().map_err(|_| RuntimeError::Approval)?;
        if active.is_some() {
            return Err(RuntimeError::Approval);
        }
        let mut binding = serde_json::to_value(&self.binding)?;
        binding["run_id"] = run_id.into();
        binding["approval_digest"] = approval_digest.into();
        binding["attempt"] = 1.into();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut io = self.io.lock().map_err(|_| RuntimeError::Approval)?;
        send_json(
            &mut io,
            &json!({"schema_version":1,"kind":"runtime_ready","binding":binding}),
            deadline,
            &self.stopping,
        )?;
        let ack = read_json(&mut io, deadline, &self.stopping)?;
        if ack != json!({"schema_version":1,"kind":"controller_ready","binding":binding}) {
            return Err(RuntimeError::Integrity("controller ready binding"));
        }
        *active = Some(binding);
        *self.started.lock().map_err(|_| RuntimeError::Approval)? = Some(Instant::now());
        Ok(())
    }
    pub(crate) fn observation(&self) -> Result<SubscriptionObservation> {
        self.observation
            .lock()
            .map(|o| o.clone())
            .map_err(|_| RuntimeError::Integrity("subscription observation poisoned"))
    }
    pub fn binding(&self) -> &SubscriptionControllerBinding {
        &self.binding
    }
}
#[cfg(test)]
#[path = "subscription_controller_tests.rs"]
mod tests;

impl OwnedSubscriptionController {
    pub(super) fn check(&self, account: &str, controller: &str, run: &PreparedRun) -> Result<()> {
        let arm = self
            .binding
            .assignment_id
            .split('-')
            .nth(1)
            .ok_or(RuntimeError::Approval)?;
        let expected_model = if arm.starts_with('L') {
            "gpt-6-luna"
        } else {
            "gpt-6-astra"
        };
        let expected_effort = if arm.ends_with('m') {
            router_types::EffortLevel::Medium
        } else {
            router_types::EffortLevel::Xhigh
        };
        if self.binding.account_sha256 != account
            || self.binding.controller_sha256 != controller
            || run.requested_model.as_str() != expected_model
            || run.requested_effort != expected_effort
            || run.timeout_ms > 60000
            || self.stopping.load(Ordering::SeqCst)
        {
            return Err(RuntimeError::Integrity("subscription channel profile"));
        }
        Ok(())
    }
    pub(super) fn start(
        self: &Arc<Self>,
        listener: TcpListener,
        cancel: Cancellation,
    ) -> Result<SubscriptionServer> {
        listener.set_nonblocking(true)?;
        *self.cancelled.lock().map_err(|_| RuntimeError::Approval)? = Some(cancel.clone());
        let session = self.clone();
        let thread = std::thread::spawn(move || {
            while !session.stopping.load(Ordering::SeqCst) && !cancel.is_cancelled() {
                match listener.accept() {
                    Ok((socket, _)) => {
                        if session.serve(socket).is_err() {
                            if let Ok(mut observation) = session.observation.lock() {
                                observation.usage_unknown = true;
                            }
                            cancel.cancel();
                            // Preserve the duplex channel for an authenticated cleanup
                            // terminal; no subsequent worker request is accepted.
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => {
                        cancel.cancel();
                        break;
                    }
                }
            }
        });
        Ok(SubscriptionServer {
            owner: self.clone(),
            thread: Some(thread),
        })
    }
    fn deadline(&self) -> Result<Instant> {
        self.started
            .lock()
            .map_err(|_| RuntimeError::Approval)?
            .map(|s| s + Duration::from_secs(60))
            .ok_or(RuntimeError::Approval)
    }
    fn serve(&self, mut socket: TcpStream) -> Result<()> {
        socket.set_read_timeout(Some(Duration::from_millis(50)))?;
        socket.set_write_timeout(Some(Duration::from_millis(50)))?;
        let request_deadline = Instant::now() + Duration::from_secs(3);
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            let mut b = [0];
            if let Err(error) =
                read_exact_bound(&mut socket, &mut b, request_deadline, &self.stopping)
            {
                if headers.is_empty() && matches!(error, RuntimeError::Integrity("controller EOF"))
                {
                    return Ok(());
                }
                return Err(error);
            }
            headers.push(b[0]);
            if headers.len() > 16384 {
                return Err(RuntimeError::Limit);
            }
        }
        let headers =
            std::str::from_utf8(&headers).map_err(|_| RuntimeError::Invalid("broker HTTP"))?;
        let mut lines = headers.split("\r\n");
        let first = lines.next().ok_or(RuntimeError::Scope)?;
        if first == "GET /__router_probe__ HTTP/1.0" {
            write_bound(
                &mut socket,
                b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok",
                request_deadline,
                &self.stopping,
            )?;
            return Ok(());
        }
        if !matches!(
            first,
            "POST /v1/responses HTTP/1.1" | "POST /responses HTTP/1.1"
        ) {
            return Err(RuntimeError::Scope);
        }
        let mut length = None;
        for line in lines.filter(|s| !s.is_empty()) {
            let (key, value) = line.split_once(':').ok_or(RuntimeError::Scope)?;
            match key.to_ascii_lowercase().as_str() {
                "authorization" | "chatgpt-account-id" | "transfer-encoding" => {
                    return Err(RuntimeError::Sandbox);
                }
                "content-length" => {
                    if length.is_some() {
                        return Err(RuntimeError::Invalid("duplicate content length"));
                    }
                    length = Some(
                        value
                            .trim()
                            .parse::<usize>()
                            .map_err(|_| RuntimeError::Limit)?,
                    );
                }
                _ => {}
            }
        }
        let length = length
            .filter(|v| (1..=262144).contains(v))
            .ok_or(RuntimeError::Limit)?;
        let binding = self
            .active
            .lock()
            .map_err(|_| RuntimeError::Approval)?
            .clone()
            .ok_or(RuntimeError::Approval)?;
        let deadline = self.deadline()?;
        let mut body = vec![0; length];
        read_exact_bound(&mut socket, &mut body, deadline, &self.stopping)?;
        let body = router_adapter_api::strict_json_limited(&body, 262144)
            .map_err(|_| RuntimeError::Invalid("broker JSON"))?;
        let arm = self
            .binding
            .assignment_id
            .split('-')
            .nth(1)
            .ok_or(RuntimeError::Approval)?;
        if body["model"]
            != if arm.starts_with('L') {
                "gpt-6-luna"
            } else {
                "gpt-6-astra"
            }
            || body["reasoning"]["effort"]
                != if arm.ends_with('m') {
                    "medium"
                } else {
                    "xhigh"
                }
            || body["stream"] != true
            || body["store"] != false
        {
            return Err(RuntimeError::Approval);
        }
        let mut count = self
            .terminal_count
            .lock()
            .map_err(|_| RuntimeError::Approval)?;
        let id = *count + 1;
        if id > 64 {
            return Err(RuntimeError::Limit);
        }
        let request_hash = content_digest(&serde_json::to_vec(&body)?);
        let mut io = self.io.lock().map_err(|_| RuntimeError::Approval)?;
        send_json(
            &mut io,
            &json!({"schema_version":1,"id":id,"body":body}),
            deadline,
            &self.stopping,
        )?;
        write_bound(
            &mut socket,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
            deadline,
            &self.stopping,
        )?;
        let mut total = 0usize;
        loop {
            let frame = read_json(&mut io, deadline, &self.stopping)?;
            if frame["kind"] == "controller_stop" && frame["binding"] == binding {
                return Err(RuntimeError::Cancelled);
            }
            if frame["schema_version"] != 1 || frame["id"] != id {
                return Err(RuntimeError::Integrity("controller frame identity"));
            }
            match frame["kind"].as_str() {
                Some("chunk") => {
                    if frame.as_object().is_none_or(|v| v.len() != 4) {
                        return Err(RuntimeError::Scope);
                    }
                    let data = decode_chunk(frame["data"].as_str().ok_or(RuntimeError::Scope)?)?;
                    total = total.checked_add(data.len()).ok_or(RuntimeError::Limit)?;
                    if total > 8 * 1024 * 1024 {
                        return Err(RuntimeError::Limit);
                    }
                    write_bound(&mut socket, &data, deadline, &self.stopping)?;
                }
                Some("terminal") => {
                    let known = !(total == 0
                        || frame["complete"] != true
                        || frame["request_body_sha256"] != request_hash
                        || frame["observed_response_model"] != body["model"]
                        || frame["usage"]["total_tokens"].as_u64().is_none()
                        || frame["cumulative_usage"]["total_tokens"].as_u64().is_none()
                        || frame["cumulative_equivalent_microcredits"]
                            .as_u64()
                            .is_none());
                    let barrier = read_json(&mut io, deadline, &self.stopping)?;
                    if barrier["schema_version"] != 1
                        || barrier["kind"] != "controller_request_finished"
                        || barrier["binding"] != binding
                        || barrier["id"] != id
                    {
                        return Err(RuntimeError::Approval);
                    }
                    *count = id;
                    let persisted_known = known
                        && matches!(
                            barrier["reason"].as_str(),
                            None | Some(
                                "observed_campaign_budget"
                                    | "observed_token_limit"
                                    | "response_count_limit"
                            )
                        );
                    {
                        let mut observation = self
                            .observation
                            .lock()
                            .map_err(|_| RuntimeError::Approval)?;
                        if persisted_known {
                            let tokens = frame["cumulative_usage"]["total_tokens"]
                                .as_u64()
                                .ok_or(RuntimeError::Approval)?;
                            let cost = frame["cumulative_equivalent_microcredits"]
                                .as_u64()
                                .ok_or(RuntimeError::Approval)?;
                            if tokens < observation.known_prefix_tokens
                                || cost < observation.equivalent_microcredits
                            {
                                return Err(RuntimeError::Integrity(
                                    "subscription cumulative regression",
                                ));
                            }
                            observation.known_prefix_tokens = tokens;
                            observation.equivalent_microcredits = cost;
                            observation.verified_responses += 1;
                        } else {
                            observation.usage_unknown = true;
                        }
                    }
                    if !persisted_known
                        || barrier["continue"] != true
                        || frame["stop_reason"] != Value::Null
                        || frame["cumulative_usage"]["total_tokens"]
                            .as_u64()
                            .unwrap_or(u64::MAX)
                            >= 6000
                        || id >= 64
                    {
                        if let Some(cancel) = self
                            .cancelled
                            .lock()
                            .map_err(|_| RuntimeError::Approval)?
                            .as_ref()
                        {
                            cancel.cancel();
                        }
                    }
                    socket.shutdown(Shutdown::Write)?;
                    return Ok(());
                }
                _ => return Err(RuntimeError::Integrity("controller frame kind")),
            }
        }
    }
    pub(super) fn cleanup(&self, proof_sha256: &str, native_status: &str) -> Result<()> {
        if !is_digest(proof_sha256)
            || !matches!(native_status, "completed" | "failed" | "interrupted")
        {
            return Err(RuntimeError::Approval);
        }
        let binding = self
            .active
            .lock()
            .map_err(|_| RuntimeError::Approval)?
            .clone()
            .ok_or(RuntimeError::Approval)?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut io = self.io.lock().map_err(|_| RuntimeError::Approval)?;
        // The worker and broker are stopped now. The stopping flag must not abort
        // the bounded cleanup handshake itself.
        let finalizing = AtomicBool::new(false);
        send_json(
            &mut io,
            &json!({"schema_version":1,"kind":"runtime_cleanup","binding":binding,
            "cleanup":"namespace_terminated","native_status":native_status,"proof_sha256":proof_sha256}),
            deadline,
            &finalizing,
        )?;
        let ack = read_json(&mut io, deadline, &finalizing)?;
        if ack["schema_version"] != 1
            || ack["kind"] != "controller_finished"
            || ack["binding"] != binding
            || ack["execution_authorized"] != false
        {
            return Err(RuntimeError::Integrity("controller final ACK"));
        }
        Ok(())
    }
}
pub(super) struct SubscriptionServer {
    owner: Arc<OwnedSubscriptionController>,
    thread: Option<JoinHandle<()>>,
}
impl SubscriptionServer {
    pub(super) fn stop(&mut self) -> Result<()> {
        self.owner.stopping.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| RuntimeError::Integrity("controller server panic"))?;
        }
        Ok(())
    }
}
impl Drop for SubscriptionServer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn retry_io(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )
}
fn read_exact_bound<R: Read>(
    reader: &mut R,
    mut bytes: &mut [u8],
    deadline: Instant,
    stop: &AtomicBool,
) -> Result<()> {
    while !bytes.is_empty() {
        if stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return Err(RuntimeError::Limit);
        }
        match reader.read(bytes) {
            Ok(0) => return Err(RuntimeError::Integrity("controller EOF")),
            Ok(n) => {
                bytes = &mut bytes[n..];
            }
            Err(e) if retry_io(&e) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn write_bound<W: Write>(
    writer: &mut W,
    mut bytes: &[u8],
    deadline: Instant,
    stop: &AtomicBool,
) -> Result<()> {
    while !bytes.is_empty() {
        if stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return Err(RuntimeError::Limit);
        }
        match writer.write(bytes) {
            Ok(0) => return Err(RuntimeError::Integrity("controller closed write")),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if retry_io(&e) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn send_json(
    io: &mut UnixStream,
    value: &Value,
    deadline: Instant,
    stop: &AtomicBool,
) -> Result<()> {
    io.set_write_timeout(Some(Duration::from_millis(50)))?;
    let mut bytes = serde_json::to_vec(value)?;
    if bytes.len() >= 300000 {
        return Err(RuntimeError::Limit);
    }
    bytes.push(b'\n');
    write_bound(io, &bytes, deadline, stop)
}
fn read_json(io: &mut UnixStream, deadline: Instant, stop: &AtomicBool) -> Result<Value> {
    io.set_read_timeout(Some(Duration::from_millis(50)))?;
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        read_exact_bound(io, &mut byte, deadline, stop)?;
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
        if bytes.len() >= 300000 {
            return Err(RuntimeError::Limit);
        }
    }
    router_adapter_api::strict_json_limited(&bytes, 300000)
        .map_err(|_| RuntimeError::Invalid("controller JSON"))
}
fn decode_chunk(text: &str) -> Result<Vec<u8>> {
    if text.is_empty() || text.len() > 87384 || text.len() % 4 != 0 {
        return Err(RuntimeError::Limit);
    }
    fn digit(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a' + 26) as u32),
            b'0'..=b'9' => Some((b - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let len = text.len();
    for (index, c) in text.as_bytes().chunks_exact(4).enumerate() {
        let a = digit(c[0]).ok_or(RuntimeError::Scope)?;
        let b = digit(c[1]).ok_or(RuntimeError::Scope)?;
        out.push(((a << 2) | (b >> 4)) as u8);
        if c[2] == b'=' {
            if c[3] != b'=' || b & 15 != 0 || (index + 1) * 4 != len {
                return Err(RuntimeError::Scope);
            }
            continue;
        }
        let d = digit(c[2]).ok_or(RuntimeError::Scope)?;
        out.push(((b << 4) | (d >> 2)) as u8);
        if c[3] == b'=' {
            if d & 3 != 0 || (index + 1) * 4 != len {
                return Err(RuntimeError::Scope);
            }
            continue;
        }
        out.push(((d << 6) | digit(c[3]).ok_or(RuntimeError::Scope)?) as u8);
    }
    if out.len() > 65536 {
        return Err(RuntimeError::Limit);
    }
    Ok(out)
}

impl FiniteClientReview {
    /// Attaches a freshly created, non-serializable parent channel. This only
    /// changes the review definition; the combined Runtime approval and the
    /// durable controller ACK are still required before native dispatch.
    pub fn with_subscription_controller(
        mut self,
        controller: OwnedSubscriptionController,
    ) -> Result<Self> {
        self.check_files()?;
        if self.owned_subscription.is_some()
            || self.owned_tools.is_none()
            || self.owned_namespace.is_none()
        {
            return Err(RuntimeError::Sandbox);
        }
        let subscription = self
            .owned_state
            .as_ref()
            .and_then(|s| s.startup.subscription.as_ref())
            .ok_or(RuntimeError::Approval)?;
        controller.check(
            &subscription.account_sha256,
            &subscription.controller_sha256,
            &self.run,
        )?;
        self.approval = crate::digest(
            "finite-subscription-controller-review-v1",
            &(&self.approval, controller.binding()),
        )?;
        self.owned_subscription = Some(Arc::new(controller));
        Ok(self)
    }
    pub(super) fn provider_identity(&self) -> Result<&'static str> {
        match (
            self.owned_state
                .as_ref()
                .and_then(|s| s.startup.subscription.as_ref()),
            self.owned_subscription.as_ref(),
        ) {
            (Some(profile), Some(controller)) => {
                controller.check(
                    &profile.account_sha256,
                    &profile.controller_sha256,
                    &self.run,
                )?;
                Ok("codex_subscription_relay")
            }
            (None, None) => Ok("local_fixture"),
            _ => Err(RuntimeError::Invalid(
                "subscription controller admission unqualified",
            )),
        }
    }
}
