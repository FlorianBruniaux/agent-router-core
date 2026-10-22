//! Closed HTTP/1.1 request framing: one request per connection, identity
//! bodies with an explicit `Content-Length`, no chunking, no pipelining.

use std::{
    io::{ErrorKind, Read},
    os::unix::net::UnixStream,
    time::Instant,
};

pub(crate) const MAX_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Failure {
    pub status: u16,
    pub code: &'static str,
}

impl Failure {
    pub(crate) const fn new(status: u16, code: &'static str) -> Self {
        Self { status, code }
    }
}

pub(crate) struct Head {
    pub method: String,
    pub target: String,
    pub content_length: Option<usize>,
    pub content_type_json: bool,
    pub authorization: Option<Vec<u8>>,
}

/// Reads until the blank line ending the head. Returns the parsed head and any
/// body bytes already received.
pub(crate) fn read_head(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<(Head, Vec<u8>), Failure> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(end) = find_terminator(&buffer) {
            if end + 4 > MAX_HEADER_BYTES {
                return Err(Failure::new(431, "http.headers_too_large"));
            }
            let rest = buffer.split_off(end + 4);
            buffer.truncate(end);
            return Ok((parse_head(&buffer)?, rest));
        }
        if buffer.len() >= MAX_HEADER_BYTES {
            return Err(Failure::new(431, "http.headers_too_large"));
        }
        let read = read_some(stream, &mut chunk, deadline)?;
        if read == 0 {
            return Err(Failure::new(400, "http.incomplete"));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

pub(crate) fn read_body(
    stream: &mut UnixStream,
    mut body: Vec<u8>,
    length: usize,
    deadline: Instant,
) -> Result<Vec<u8>, Failure> {
    if body.len() > length {
        return Err(Failure::new(400, "http.pipelined"));
    }
    let mut chunk = [0u8; 8192];
    while body.len() < length {
        let want = (length - body.len()).min(chunk.len());
        let read = read_some(stream, &mut chunk[..want], deadline)?;
        if read == 0 {
            return Err(Failure::new(400, "http.incomplete"));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(body)
}

/// One read bounded by the whole-request deadline, so a slow sender cannot
/// extend its own budget by trickling bytes.
fn read_some(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<usize, Failure> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Failure::new(408, "http.timeout"));
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| Failure::new(500, "local_api.io"))?;
        match stream.read(buffer) {
            Ok(read) => return Ok(read),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(Failure::new(408, "http.timeout"));
            }
            Err(_) => return Err(Failure::new(400, "http.incomplete")),
        }
    }
}

fn find_terminator(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn parse_head(bytes: &[u8]) -> Result<Head, Failure> {
    let malformed = || Failure::new(400, "http.malformed");
    if bytes.iter().any(|&byte| {
        byte == 0x7f || (byte < 0x20 && !matches!(byte, b'\r' | b'\n' | b'\t')) || byte >= 0x80
    }) {
        return Err(malformed());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| malformed())?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or_else(malformed)?;
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(malformed());
    };
    if !is_token(method) || !target.starts_with('/') || target.contains('#') {
        return Err(malformed());
    }
    if version != "HTTP/1.1" {
        return Err(if version.starts_with("HTTP/") {
            Failure::new(505, "http.version")
        } else {
            malformed()
        });
    }
    let mut head = Head {
        method: method.to_owned(),
        target: target.to_owned(),
        content_length: None,
        content_type_json: false,
        authorization: None,
    };
    for line in lines {
        // A bare CR or LF would let a proxy and this parser disagree on framing.
        if line.contains(['\r', '\n']) || line.starts_with([' ', '\t']) {
            return Err(malformed());
        }
        let (name, value) = line.split_once(':').ok_or_else(malformed)?;
        if !is_token(name) {
            return Err(malformed());
        }
        let value = value.trim_matches([' ', '\t']);
        match name.to_ascii_lowercase().as_str() {
            "transfer-encoding" => return Err(Failure::new(400, "http.transfer_encoding")),
            "content-encoding" => return Err(Failure::new(415, "http.content_encoding")),
            "expect" => return Err(Failure::new(417, "http.expect")),
            "content-length" => {
                if head.content_length.is_some()
                    || value.is_empty()
                    || value.len() > 18
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(Failure::new(400, "http.content_length"));
                }
                head.content_length = Some(
                    value
                        .parse()
                        .map_err(|_| Failure::new(400, "http.content_length"))?,
                );
            }
            "content-type" => {
                let media = value.split(';').next().unwrap_or("").trim();
                head.content_type_json = media.eq_ignore_ascii_case("application/json");
            }
            "authorization" => {
                if head.authorization.is_some() {
                    return Err(Failure::new(400, "http.authorization"));
                }
                head.authorization = Some(value.as_bytes().to_vec());
            }
            _ => {}
        }
    }
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Head, Failure> {
        parse_head(text.as_bytes())
    }

    #[test]
    fn parses_a_minimal_head() {
        let head = parse("POST /v1/route HTTP/1.1\r\nContent-Length: 4\r\nAuthorization: Bearer x\r\nContent-Type: application/json; charset=utf-8").expect("head");
        assert_eq!(head.method, "POST");
        assert_eq!(head.target, "/v1/route");
        assert_eq!(head.content_length, Some(4));
        assert!(head.content_type_json);
        assert_eq!(head.authorization.as_deref(), Some(&b"Bearer x"[..]));
    }

    #[test]
    fn rejects_ambiguous_framing() {
        for (text, code) in [
            (
                "POST / HTTP/1.1\r\nTransfer-Encoding: chunked",
                "http.transfer_encoding",
            ),
            (
                "POST / HTTP/1.1\r\ntransfer-encoding: identity",
                "http.transfer_encoding",
            ),
            (
                "POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1",
                "http.content_length",
            ),
            (
                "POST / HTTP/1.1\r\nContent-Length: +1",
                "http.content_length",
            ),
            (
                "POST / HTTP/1.1\r\nContent-Length: 1, 1",
                "http.content_length",
            ),
            ("POST / HTTP/1.1\r\nContent-Length: ", "http.content_length"),
            (
                "POST / HTTP/1.1\r\nAuthorization: a\r\nAuthorization: b",
                "http.authorization",
            ),
            ("POST / HTTP/1.0", "http.version"),
            ("POST / HTTP/1.1\r\nExpect: 100-continue", "http.expect"),
            (
                "POST / HTTP/1.1\r\nContent-Encoding: gzip",
                "http.content_encoding",
            ),
        ] {
            assert_eq!(parse(text).err().expect(text).code, code, "{text}");
        }
        for version in ["HTTP/1.0", "HTTP/2", "HTTP/1.2"] {
            let failure = parse(&format!("GET / {version}")).err().expect(version);
            assert_eq!(
                (failure.status, failure.code),
                (505, "http.version"),
                "{version}"
            );
        }
        assert_eq!(parse("GET / SPDY/3").err().expect("spdy").status, 400);
    }

    #[test]
    fn rejects_malformed_lines() {
        for text in [
            "POST /",
            "POST  / HTTP/1.1",
            "POST x HTTP/1.1",
            "POST / HTTP/1.1\r\nNo-Colon",
            "POST / HTTP/1.1\r\nBad Name: x",
            "POST / HTTP/1.1\r\nName : x",
            "POST / HTTP/1.1\r\nA: b\r\n folded",
            "POST / HTTP/1.1\r\nA: b\nContent-Length: 0",
            "POST / HTTP/1.1\r\nA: \u{e9}",
            "POST / HTTP/1.1\r\nA: \0",
        ] {
            assert_eq!(parse(text).err().expect(text).status, 400, "{text:?}");
        }
    }
}
