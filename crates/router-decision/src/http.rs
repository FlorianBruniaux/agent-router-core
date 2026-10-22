//! Closed, bounded HTTP/1 transport shared by explicit loopback clients.
use crate::{BackendError, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Result};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};
const MAX_HEADER_BYTES: usize = 16 * 1024;
#[derive(Clone, Copy)]
pub(crate) enum Endpoint {
    Legacy,
    Capabilities,
    Rank,
    Outcome,
    Feedback,
}
impl Endpoint {
    fn path(self) -> &'static str {
        match self {
            Self::Legacy => "/v1/systemone",
            Self::Capabilities => "/v1/capabilities",
            Self::Rank => "/v1/rank",
            Self::Outcome => "/v1/outcome",
            Self::Feedback => "/v1/feedback",
        }
    }
}
pub(crate) struct HttpFailure {
    pub error: BackendError,
    pub emitted: bool,
}
pub(crate) struct LoopbackHttp {
    endpoint: SocketAddr,
    bearer: Option<String>,
}
impl std::fmt::Debug for LoopbackHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopbackHttp")
            .field("endpoint", &self.endpoint)
            .field("authentication_configured", &self.bearer.is_some())
            .finish()
    }
}
impl LoopbackHttp {
    pub(crate) fn new(endpoint: SocketAddr, bearer: Option<String>) -> Result<Self> {
        if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
            return Err(BackendError::Endpoint);
        }
        if bearer.as_ref().is_some_and(|v| {
            v.is_empty() || v.len() > 4096 || !v.bytes().all(|b| (33..=126).contains(&b))
        }) {
            return Err(BackendError::Invalid);
        }
        Ok(Self { endpoint, bearer })
    }
    pub(crate) fn exchange(
        &self,
        endpoint: Endpoint,
        body: &[u8],
        deadline: Instant,
    ) -> std::result::Result<Vec<u8>, HttpFailure> {
        let mut emitted = false;
        let result = (|| {
            if body.len() > MAX_REQUEST_BYTES {
                return Err(BackendError::Limit);
            }
            let mut stream = TcpStream::connect_timeout(&self.endpoint, remaining(deadline)?)
                .map_err(io_error)?;
            let method = if matches!(endpoint, Endpoint::Capabilities) {
                "GET"
            } else {
                "POST"
            };
            let mut headers = format!(
                "{method} {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nContent-Length: {}\r\nConnection: close\r\n",
                endpoint.path(),
                self.endpoint,
                body.len()
            );
            if let Some(bearer) = &self.bearer {
                headers.push_str(&format!("Authorization: Bearer {bearer}\r\n"));
            }
            headers.push_str("\r\n");
            write_all_deadline(&mut stream, headers.as_bytes(), deadline, &mut emitted)?;
            write_all_deadline(&mut stream, body, deadline, &mut emitted)?;
            read_response(&mut stream, deadline)
        })();
        result.map_err(|error| HttpFailure { error, emitted })
    }
}
fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(BackendError::Timeout)
}
fn io_error(error: std::io::Error) -> BackendError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => BackendError::Timeout,
        _ => BackendError::Transport,
    }
}
fn write_all_deadline(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: Instant,
    emitted: &mut bool,
) -> Result<()> {
    while !bytes.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(io_error)?;
        let written = stream.write(bytes).map_err(io_error)?;
        if written == 0 {
            return Err(BackendError::Transport);
        }
        *emitted = true;
        bytes = &bytes[written..];
    }
    Ok(())
}

fn read_response(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>> {
    let mut received = Vec::new();
    let mut expected = None;
    loop {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(io_error)?;
        let mut buffer = [0u8; 4096];
        let length = stream.read(&mut buffer).map_err(io_error)?;
        if length == 0 {
            return Err(BackendError::Transport);
        }
        received.extend_from_slice(&buffer[..length]);
        if received.len() > MAX_HEADER_BYTES + MAX_RESPONSE_BYTES {
            return Err(BackendError::Limit);
        }
        if expected.is_none() {
            if let Some(header_end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
                if header_end > MAX_HEADER_BYTES {
                    return Err(BackendError::Limit);
                }
                expected = Some((header_end + 4, response_length(&received[..header_end])?));
            } else if received.len() > MAX_HEADER_BYTES {
                return Err(BackendError::Limit);
            }
        }
        if let Some((offset, size)) = expected {
            if received.len() > offset + size {
                return Err(BackendError::Schema);
            }
            if received.len() == offset + size {
                return Ok(received.split_off(offset));
            }
        }
    }
}
fn response_length(header: &[u8]) -> Result<usize> {
    let header = std::str::from_utf8(header).map_err(|_| BackendError::Schema)?;
    let mut lines = header.split("\r\n");
    let status = lines.next().ok_or(BackendError::Schema)?;
    let mut status_fields = status.split_whitespace();
    if !matches!(status_fields.next(), Some("HTTP/1.0" | "HTTP/1.1"))
        || status_fields.next() != Some("200")
    {
        return Err(BackendError::Transport);
    }
    let mut length = None;
    let mut content_type = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(BackendError::Schema)?;
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                if length.is_some() {
                    return Err(BackendError::Schema);
                }
                // Digits only: `usize::from_str` also accepts a leading `+`.
                let digits = value.trim();
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(BackendError::Schema);
                }
                let parsed: usize = digits.parse().map_err(|_| BackendError::Schema)?;
                if parsed > MAX_RESPONSE_BYTES {
                    return Err(BackendError::Limit);
                }
                length = Some(parsed);
            }
            "content-type" => {
                if content_type
                    || !value
                        .split(';')
                        .next()
                        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
                {
                    return Err(BackendError::Schema);
                }
                content_type = true;
            }
            "transfer-encoding" | "content-encoding" => return Err(BackendError::Schema),
            _ => {}
        }
    }
    if !content_type {
        return Err(BackendError::Schema);
    }
    length.ok_or(BackendError::Schema)
}
