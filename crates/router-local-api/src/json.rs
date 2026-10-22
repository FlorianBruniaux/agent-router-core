//! Strict envelope splitter. `serde_json::Value` keeps the last of two equal
//! keys, so duplicates must be rejected before any typed parse. The scanner
//! checks every object of the body and hands back the byte range of each
//! top-level member untouched, so typed parsers see exactly what was sent.

use std::collections::HashSet;

const MAX_DEPTH: usize = 64;
/// Total object members in one body. Each connection keeps a key set per open
/// object, so this bounds memory independently of the body size limit.
const MAX_KEYS: usize = 100_000;

pub(crate) struct Envelope<'a> {
    pub request: &'a [u8],
    pub catalog: &'a [u8],
    pub host_snapshot: Option<&'a [u8]>,
}

type Range = (usize, usize);

pub(crate) fn parse_envelope(body: &[u8]) -> Result<Envelope<'_>, &'static str> {
    let text = std::str::from_utf8(body).map_err(|_| "json.invalid")?;
    let mut scanner = Scanner {
        text,
        bytes: body,
        at: 0,
        keys: 0,
    };
    scanner.whitespace();
    if scanner.peek() != Some(b'{') {
        return Err("json.envelope.not_object");
    }
    let members = scanner.object(1)?;
    scanner.whitespace();
    if scanner.at != body.len() {
        return Err("json.invalid");
    }
    let (mut request, mut catalog, mut snapshot) = (None, None, None);
    for (key, (start, end)) in members {
        let slot = match key.as_str() {
            "request" => &mut request,
            "catalog" => &mut catalog,
            "host_snapshot" => &mut snapshot,
            _ => return Err("json.envelope.unknown_field"),
        };
        *slot = Some(&body[start..end]);
    }
    Ok(Envelope {
        request: request.ok_or("json.envelope.missing_field")?,
        catalog: catalog.ok_or("json.envelope.missing_field")?,
        host_snapshot: snapshot,
    })
}

struct Scanner<'a> {
    text: &'a str,
    bytes: &'a [u8],
    at: usize,
    keys: usize,
}

impl Scanner<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), &'static str> {
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else {
            Err("json.invalid")
        }
    }

    fn value(&mut self, depth: usize) -> Result<Range, &'static str> {
        if depth > MAX_DEPTH {
            return Err("json.too_deep");
        }
        self.whitespace();
        let start = self.at;
        match self.peek().ok_or("json.invalid")? {
            b'{' => {
                self.object(depth + 1)?;
            }
            b'[' => self.array(depth + 1)?,
            b'"' => {
                self.string()?;
            }
            b't' => self.literal(b"true")?,
            b'f' => self.literal(b"false")?,
            b'n' => self.literal(b"null")?,
            b'-' | b'0'..=b'9' => self.number()?,
            _ => return Err("json.invalid"),
        }
        Ok((start, self.at))
    }

    fn object(&mut self, depth: usize) -> Result<Vec<(String, Range)>, &'static str> {
        if depth > MAX_DEPTH {
            return Err("json.too_deep");
        }
        self.expect(b'{')?;
        let mut members = Vec::new();
        let mut seen = HashSet::new();
        self.whitespace();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(members);
        }
        loop {
            self.whitespace();
            let (start, end) = self.string()?;
            let key: String =
                serde_json::from_str(&self.text[start..end]).map_err(|_| "json.invalid")?;
            self.whitespace();
            self.expect(b':')?;
            let range = self.value(depth)?;
            self.keys += 1;
            if self.keys > MAX_KEYS {
                return Err("json.too_many_keys");
            }
            if !seen.insert(key.clone()) {
                return Err("json.duplicate_key");
            }
            if depth == 1 {
                members.push((key, range));
            }
            self.whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(members);
                }
                _ => return Err("json.invalid"),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<(), &'static str> {
        if depth > MAX_DEPTH {
            return Err("json.too_deep");
        }
        self.expect(b'[')?;
        self.whitespace();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(());
        }
        loop {
            self.value(depth)?;
            self.whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(());
                }
                _ => return Err("json.invalid"),
            }
        }
    }

    fn string(&mut self) -> Result<Range, &'static str> {
        let start = self.at;
        self.expect(b'"')?;
        loop {
            match self.peek().ok_or("json.invalid")? {
                b'"' => {
                    self.at += 1;
                    return Ok((start, self.at));
                }
                b'\\' => {
                    self.at += 1;
                    match self.peek().ok_or("json.invalid")? {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => self.at += 1,
                        b'u' => {
                            self.at += 1;
                            for _ in 0..4 {
                                if !self.peek().is_some_and(|byte| byte.is_ascii_hexdigit()) {
                                    return Err("json.invalid");
                                }
                                self.at += 1;
                            }
                        }
                        _ => return Err("json.invalid"),
                    }
                }
                0..=0x1f => return Err("json.invalid"),
                _ => self.at += 1,
            }
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), &'static str> {
        if self.bytes[self.at..].starts_with(word) {
            self.at += word.len();
            Ok(())
        } else {
            Err("json.invalid")
        }
    }

    fn digits(&mut self) -> Result<(), &'static str> {
        let start = self.at;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.at += 1;
        }
        if self.at == start {
            Err("json.invalid")
        } else {
            Ok(())
        }
    }

    fn number(&mut self) -> Result<(), &'static str> {
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => self.digits()?,
            _ => return Err("json.invalid"),
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            self.digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            self.digits()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(body: &str) -> &'static str {
        parse_envelope(body.as_bytes()).err().expect("rejected")
    }

    #[test]
    fn splits_members_without_rewriting_them() {
        let body =
            r#" {"request": {"a":[1,2.5e3,"x\u00e9"]} ,"catalog":{}, "host_snapshot":{"k":null}} "#;
        let envelope = parse_envelope(body.as_bytes()).expect("valid");
        assert_eq!(envelope.request, br#"{"a":[1,2.5e3,"x\u00e9"]}"#);
        assert_eq!(envelope.catalog, b"{}");
        assert_eq!(envelope.host_snapshot, Some(&br#"{"k":null}"#[..]));
    }

    #[test]
    fn snapshot_is_optional_but_request_and_catalog_are_required() {
        assert!(parse_envelope(br#"{"request":{},"catalog":{}}"#).is_ok());
        assert_eq!(code(r#"{"request":{}}"#), "json.envelope.missing_field");
        assert_eq!(code(r#"{"catalog":{}}"#), "json.envelope.missing_field");
    }

    #[test]
    fn rejects_duplicate_keys_at_any_depth_and_through_escapes() {
        assert_eq!(
            code(r#"{"request":{},"request":{},"catalog":{}}"#),
            "json.duplicate_key"
        );
        assert_eq!(
            code(r#"{"request":{"a":1,"a":2},"catalog":{}}"#),
            "json.duplicate_key"
        );
        assert_eq!(
            code(r#"{"request":{"a":1,"\u0061":2},"catalog":{}}"#),
            "json.duplicate_key"
        );
        assert_eq!(
            code(r#"{"request":[{"a":1,"a":1}],"catalog":{}}"#),
            "json.duplicate_key"
        );
    }

    #[test]
    fn rejects_unknown_top_level_fields_and_non_objects() {
        assert_eq!(
            code(r#"{"request":{},"catalog":{},"path":"/etc/passwd"}"#),
            "json.envelope.unknown_field"
        );
        assert_eq!(code("[]"), "json.envelope.not_object");
        assert_eq!(code(""), "json.envelope.not_object");
    }

    #[test]
    fn rejects_malformed_and_trailing_input() {
        for body in [
            r#"{"request":{},"catalog":{}} x"#,
            r#"{"request":{},"catalog":{},}"#,
            r#"{"request":01,"catalog":{}}"#,
            r#"{"request":tru,"catalog":{}}"#,
            "{\"request\":\"a\nb\",\"catalog\":{}}",
            r#"{"request":"\x","catalog":{}}"#,
            r#"{"request":{},"catalog":{}"#,
        ] {
            assert_eq!(code(body), "json.invalid", "{body}");
        }
        assert!(parse_envelope(&[b'{', 0xff, b'}']).is_err());
    }

    #[test]
    fn bounds_the_total_number_of_keys() {
        let object = |count: usize| {
            let members: Vec<_> = (0..count).map(|index| format!("\"k{index}\":0")).collect();
            format!("{{\"request\":{{{}}},\"catalog\":{{}}}}", members.join(","))
        };
        assert!(parse_envelope(object(MAX_KEYS - 2).as_bytes()).is_ok());
        assert_eq!(code(&object(MAX_KEYS)), "json.too_many_keys");
        // Keys spread over many small objects count too.
        let many = format!("[{}]", vec![r#"{"a":1}"#; MAX_KEYS + 1].join(","));
        let body = format!("{{\"request\":{many},\"catalog\":{{}}}}");
        assert_eq!(code(&body), "json.too_many_keys");
    }

    #[test]
    fn bounds_nesting() {
        let deep = format!(
            r#"{{"request":{}0{},"catalog":{{}}}}"#,
            "[".repeat(200),
            "]".repeat(200)
        );
        assert_eq!(code(&deep), "json.too_deep");
    }
}
