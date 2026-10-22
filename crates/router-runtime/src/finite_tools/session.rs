//! One policy and budget owner across MCP connections.
use super::{ExecSandbox, FilePolicy, FiniteToolError, Limits};
use std::{
    io::{BufReader, Read, Write},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};
pub struct ToolSession {
    policy: FilePolicy,
    sandbox: ExecSandbox,
    failed: bool,
    sequence: u32,
    connections: u32,
    deadline: Instant,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl ToolSession {
    pub fn open(
        sandbox: ExecSandbox,
        preimage: Option<String>,
        limits: Limits,
    ) -> Result<Self, FiniteToolError> {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(limits.max_session_ms))
            .ok_or(FiniteToolError::Execution)?;
        let policy = FilePolicy::open(
            &sandbox.root,
            &sandbox.scratch,
            sandbox.public.clone(),
            &sandbox.output,
            preimage,
            limits,
        )?;
        Ok(Self {
            policy,
            sandbox,
            failed: false,
            sequence: 0,
            connections: 0,
            deadline,
            stop: Default::default(),
        })
    }
    /// Only sockets with the session's absolute I/O deadline are accepted.
    pub fn serve(&mut self, stream: UnixStream) -> Result<(), FiniteToolError> {
        let input = BufReader::new(DeadlineStream {
            stream: stream.try_clone().map_err(|_| FiniteToolError::Execution)?,
            deadline: self.deadline,
        });
        let output = DeadlineStream {
            stream,
            deadline: self.deadline,
        };
        if self.halted() || self.connections >= 8 || Instant::now() >= self.deadline {
            self.failed = true;
            return Err(FiniteToolError::Refused("session.halted"));
        }
        self.connections += 1;
        // A dedicated thread allows use by both sync and Tokio callers without
        // nesting a blocking runtime. It owns no outer namespace authority.
        let result = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| FiniteToolError::Execution)?;
                    super::serve_mcp(input, output, |name, args| {
                        let value = self
                            .policy
                            .dispatch(name, &args, &mut |argv, timeout, cap| {
                                self.sequence += 1;
                                runtime
                                    .block_on(self.sandbox.execute(
                                        argv,
                                        timeout,
                                        cap,
                                        self.sequence,
                                    ))
                                    .map_err(|_| FiniteToolError::Execution)
                            });
                        if self.policy.halted() {
                            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                        value
                    })
                })
                .join()
                .map_err(|_| FiniteToolError::Execution)
        })
        .and_then(|result| result);
        if result.is_err() {
            self.failed = true;
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        result
    }
    pub fn stop_signal(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.stop.clone()
    }
    pub fn terminal(
        &self,
        binding: &str,
        complete: bool,
    ) -> Result<super::ToolTerminal, FiniteToolError> {
        if !router_adapter_api::is_digest(binding) {
            return Err(FiniteToolError::Refused("terminal.binding"));
        }
        let output = self.policy.terminal_output()?;
        Ok(super::ToolTerminal {
            schema_version: 1,
            binding: binding.into(),
            complete: complete && !self.halted() && output.is_some(),
            halted: self.halted(),
            output,
            journal: self.journal().to_vec(),
        })
    }
    pub fn halted(&self) -> bool {
        self.failed || self.policy.halted()
    }
    /// Unauthenticated telemetry, never runtime cleanup or capability evidence.
    pub fn journal(&self) -> &[super::JournalEntry] {
        self.policy.journal()
    }
}
struct DeadlineStream {
    stream: UnixStream,
    deadline: Instant,
}
impl DeadlineStream {
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "MCP session deadline")
            })
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_adapter_api::content_digest;
    use serde_json::json;
    use std::fs;
    fn replay(session: &mut ToolSession, bytes: Vec<u8>) -> Result<(), FiniteToolError> {
        let (mut caller, server) = UnixStream::pair().unwrap();
        caller.write_all(&bytes).unwrap();
        caller.shutdown(std::net::Shutdown::Write).unwrap();
        session.serve(server)
    }
    #[test]
    fn connections_share_owned_creation_and_a_protocol_failure_stops_later_effects() {
        let root = tempfile::tempdir().unwrap();
        let candidate = root.path().join("candidate");
        let scratch = root.path().join("scratch");
        let control = root.path().join("control");
        for path in [&candidate, &scratch, &control] {
            fs::create_dir(path).unwrap();
        }
        fs::write(candidate.join("input.txt"), b"public").unwrap();
        let pin = router_types::FiniteClientFile {
            path: "/not-invoked".into(),
            sha256: "a".repeat(64),
        };
        let sandbox = ExecSandbox {
            namespace: pin.clone(),
            helper: pin.clone(),
            guard: pin.clone(),
            compiler: pin,
            root: candidate.clone(),
            scratch,
            control,
            public: std::collections::BTreeMap::from([(
                "input.txt".into(),
                content_digest(b"public"),
            )]),
            output: "review.json".into(),
        };
        let limits = Limits {
            max_calls: 8,
            max_file_bytes: 32768,
            max_output_bytes: 8192,
            max_total_output_bytes: 32768,
            max_exec_ms: 20000,
            max_total_exec_ms: 60000,
            max_session_ms: 90000,
            max_scratch_entries: 64,
            max_scratch_bytes: 16777216,
        };
        let mut session = ToolSession::open(sandbox, None, limits).unwrap();
        fn frames(content: &str, create: bool) -> Vec<u8> {
            let frames = [
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"owner-test","version":"1"}}}),
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"review.json","content":content,"create_new":create}}}),
            ];
            frames
                .iter()
                .flat_map(|v| {
                    let mut b = serde_json::to_vec(v).unwrap();
                    b.push(b'\n');
                    b
                })
                .collect()
        }
        assert!(!session.terminal(&"a".repeat(64), true).unwrap().complete);
        assert!(session.terminal("invalid", true).is_err());
        let stop = session.stop_signal();
        replay(&mut session, frames("first", true)).unwrap();
        assert_eq!(fs::read(candidate.join("review.json")).unwrap(), b"first");
        replay(&mut session, frames("second", false)).unwrap();
        assert_eq!(fs::read(candidate.join("review.json")).unwrap(), b"second");
        let terminal = session.terminal(&"a".repeat(64), true).unwrap();
        assert!(terminal.complete && !terminal.halted);
        assert_eq!(terminal.output.unwrap().sha256, content_digest(b"second"));
        assert!(!stop.load(std::sync::atomic::Ordering::SeqCst));
        assert!(replay(&mut session, b"{bad}\n".to_vec()).is_err());
        assert!(stop.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!session.terminal(&"a".repeat(64), true).unwrap().complete);
        assert!(replay(&mut session, frames("forbidden", false)).is_err());
        assert_eq!(fs::read(candidate.join("review.json")).unwrap(), b"second");
    }
    #[test]
    fn incomplete_client_input_cannot_hold_the_session_past_its_deadline() {
        use std::{io::Write, os::unix::net::UnixStream, time::Duration};
        let root = tempfile::tempdir().unwrap();
        let candidate = root.path().join("candidate");
        let scratch = root.path().join("scratch");
        let control = root.path().join("control");
        for p in [&candidate, &scratch, &control] {
            fs::create_dir(p).unwrap();
        }
        fs::write(candidate.join("input.txt"), b"public").unwrap();
        let pin = router_types::FiniteClientFile {
            path: "/not-invoked".into(),
            sha256: "a".repeat(64),
        };
        let sandbox = ExecSandbox {
            namespace: pin.clone(),
            helper: pin.clone(),
            guard: pin.clone(),
            compiler: pin,
            root: candidate,
            scratch,
            control,
            public: std::collections::BTreeMap::from([(
                "input.txt".into(),
                content_digest(b"public"),
            )]),
            output: "review.json".into(),
        };
        let mut session = ToolSession::open(
            sandbox,
            None,
            Limits {
                max_calls: 8,
                max_file_bytes: 32768,
                max_output_bytes: 8192,
                max_total_output_bytes: 32768,
                max_exec_ms: 20000,
                max_total_exec_ms: 60000,
                max_session_ms: 30,
                max_scratch_entries: 64,
                max_scratch_bytes: 16777216,
            },
        )
        .unwrap();
        let (mut caller, server) = UnixStream::pair().unwrap();
        caller.write_all(b"{").unwrap();
        let worker = std::thread::spawn(move || session.serve(server));
        std::thread::sleep(Duration::from_millis(200));
        let stopped = worker.is_finished();
        let _ = caller.shutdown(std::net::Shutdown::Both);
        let outcome = worker.join().unwrap();
        assert!(stopped, "owner blocked beyond its session deadline");
        assert!(outcome.is_err());
    }

    #[test]
    fn response_backpressure_cannot_hold_the_session_past_its_deadline() {
        let (server, _caller) = UnixStream::pair().unwrap();
        let mut stream = DeadlineStream {
            stream: server,
            deadline: Instant::now() + Duration::from_millis(30),
        };
        let started = Instant::now();
        assert!(stream.write_all(&vec![b'x'; 1024 * 1024]).is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
    }
}
