//! Bounded synthetic HTTP peer shared by protocol and application tests.
#![allow(dead_code)]
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
pub const ARTIFACT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub fn capabilities() -> Value {
    json!({"schema_version":1,"protocol_version":1,"backend_artifact_sha256":ARTIFACT,"operations":["rank","outcome","feedback"],"max_request_bytes":32768,"max_response_bytes":65536,"max_candidates":20,"idempotent_telemetry":true})
}
pub fn json_response(body: &Value) -> Vec<u8> {
    response(serde_json::to_vec(body).unwrap())
}
pub fn response(body: Vec<u8>) -> Vec<u8> {
    let mut wire = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    wire.extend(body);
    wire
}
pub enum Reply {
    Json(Value),
    Raw(Vec<u8>),
    Ack,
    Rank,
    Close,
}
pub struct Step {
    pub delay: Duration,
    pub reply: Reply,
}
impl Step {
    pub fn json(v: Value) -> Self {
        Self {
            delay: Duration::ZERO,
            reply: Reply::Json(v),
        }
    }
}
pub struct Server {
    pub address: SocketAddr,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    handle: Option<JoinHandle<()>>,
}
impl Server {
    pub fn start(steps: Vec<Step>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captures = requests.clone();
        let handle = thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(4);
            for step in steps {
                let mut socket = loop {
                    match listener.accept() {
                        Ok((s, _)) => break s,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < end, "client did not send expected request");
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(e) => panic!("{e}"),
                    }
                };
                // macOS may inherit O_NONBLOCK from the listener. Reading the
                // accepted socket must use its bounded blocking timeout.
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut b = [0; 1024];
                    let n = socket.read(&mut b).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&b[..n]);
                    assert!(bytes.len() < 65536);
                    if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let text = std::str::from_utf8(&bytes[..i]).unwrap();
                        let n: usize = text
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: "))
                            .unwrap()
                            .parse()
                            .unwrap();
                        if bytes.len() == i + 4 + n {
                            break;
                        }
                    }
                }
                captures.lock().unwrap().push(bytes.clone());
                thread::sleep(step.delay);
                let response = match step.reply {
                    Reply::Json(v) => json_response(&v),
                    Reply::Raw(v) => v,
                    Reply::Close => continue,
                    Reply::Rank => {
                        let p = body(&bytes);
                        json_response(
                            &json!({"schema_version":1,"protocol_version":1,"backend_artifact_sha256":ARTIFACT,"proposal":{"schema_version":1,"artifact_digest":p["request"]["artifact_digest"],"candidate_id":"c01","confidence_micros":900000,"probabilities_micros":{}}}),
                        )
                    }
                    Reply::Ack => {
                        let p = body(&bytes);
                        let operation = if bytes.starts_with(b"POST /v1/outcome ") {
                            "outcome"
                        } else {
                            "feedback"
                        };
                        json_response(
                            &json!({"schema_version":1,"protocol_version":1,"backend_artifact_sha256":ARTIFACT,"operation":operation,"message_sha256":p["message_sha256"],"status":"accepted"}),
                        )
                    }
                };
                let _ = socket.write_all(&response);
            }
        });
        Self {
            address,
            requests,
            handle: Some(handle),
        }
    }
    pub fn finish(mut self) -> Vec<Vec<u8>> {
        self.handle.take().unwrap().join().unwrap();
        self.requests.lock().unwrap().clone()
    }
}
pub fn body(bytes: &[u8]) -> Value {
    let i = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    serde_json::from_slice(&bytes[i + 4..]).unwrap()
}
