//! Finite MCP workers backed by the runtime process supervisor.
//! Native owner bootstrap remains worker data, never Runtime dispatch authority
//! or a capability proof. Runtime admission stays disabled until qualification.
mod exec;
#[cfg(all(test, target_os = "linux"))]
mod linux_tests;
mod mcp_stdio;
mod owner;
pub use owner::{ToolOwnerBoot, ToolOwnerProbe, run_owner};
mod policy;
mod session;
mod transport;
pub use exec::ExecSandbox;
pub use session::ToolSession;
pub use transport::bridge_stdio;

pub use policy::{JournalEntry, Limits, ToolResult};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolOutput {
    pub relative: String,
    pub sha256: String,
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
    pub bytes: u64,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolTerminal {
    pub schema_version: u32,
    pub binding: String,
    pub complete: bool,
    pub halted: bool,
    pub output: Option<ToolOutput>,
    pub journal: Vec<JournalEntry>,
}
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::{BufRead, Write},
    path::Path,
};

#[derive(Debug, thiserror::Error)]
pub enum FiniteToolError {
    #[error("local tool callback refused")]
    Execution,
    #[error("local tool protocol or policy refused: {0}")]
    Refused(&'static str),
}

/// A caller-scoped file policy, deliberately disconnected from Runtime.
/// The callback must provide its own approved isolation and stopped-descendant
/// proof. This type checks results and effects; it cannot stop that callback.
pub struct FilePolicy {
    inner: policy::Engine,
}
impl FilePolicy {
    pub fn open(
        root: &Path,
        scratch: &Path,
        public: BTreeMap<String, String>,
        output: &str,
        preimage: Option<String>,
        limits: Limits,
    ) -> Result<Self, FiniteToolError> {
        policy::Engine::open(root, scratch, public, output, preimage, limits)
            .map(|inner| Self { inner })
            .map_err(FiniteToolError::Refused)
    }
    pub fn dispatch(
        &mut self,
        name: &str,
        args: &Value,
        execute: &mut impl FnMut(&[String], u64, usize) -> Result<ToolResult, FiniteToolError>,
    ) -> Result<Value, FiniteToolError> {
        self.inner
            .dispatch(name, args, &mut |argv, timeout, output| {
                execute(argv, timeout, output).map_err(|_| "policy.exec")
            })
            .map_err(FiniteToolError::Refused)
    }
    pub fn terminal_output(&self) -> Result<Option<ToolOutput>, FiniteToolError> {
        self.inner
            .terminal_output()
            .map_err(FiniteToolError::Refused)
    }
    /// Binds retained preparation identities; this digest is not authority.
    pub fn preparation_binding(&self) -> Result<String, FiniteToolError> {
        self.inner
            .preparation_binding()
            .map_err(FiniteToolError::Refused)
    }
    /// Validates a terminal output against retained preparation identities.
    /// The caller must separately own the terminal channel and exact stopped
    /// namespace proof. This check grants no cleanup or execution authority.
    pub fn verify_terminal_output(&self, output: &ToolOutput) -> Result<(), FiniteToolError> {
        self.inner
            .verify_terminal_output(output)
            .map_err(FiniteToolError::Refused)
    }
    pub fn halted(&self) -> bool {
        self.inner.halted()
    }
    /// Redacted policy telemetry only. Not an authenticated runtime journal.
    pub fn journal(&self) -> &[JournalEntry] {
        self.inner.journal()
    }
}

/// Pure bounded JSONL codec. The dispatcher, not protocol data, owns effects.
/// Invalid framing or schema closes the stream without dispatching the request.
pub fn serve_mcp(
    reader: impl BufRead,
    writer: impl Write,
    mut dispatch: impl FnMut(&str, Value) -> Result<Value, FiniteToolError>,
) -> Result<(), FiniteToolError> {
    mcp_stdio::serve(reader, writer, |name, args| {
        dispatch(name, args).map_err(|_| "mcp.dispatch_refused")
    })
    .map_err(FiniteToolError::Refused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_adapter_api::content_digest;
    use serde_json::json;
    use std::{fs, io::Cursor};
    #[test]
    fn terminal_output_requires_the_retained_inode_and_unchanged_public_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("candidate");
        let scratch = temp.path().join("scratch");
        let writer_scratch = temp.path().join("writer-scratch");
        for p in [&root, &scratch, &writer_scratch] {
            fs::create_dir(p).unwrap();
        }
        fs::write(root.join("output.rs"), b"before").unwrap();
        fs::write(root.join("input.txt"), b"public").unwrap();
        let public = BTreeMap::from([
            ("output.rs".into(), content_digest(b"before")),
            ("input.txt".into(), content_digest(b"public")),
        ]);
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
        let observer = FilePolicy::open(
            &root,
            &scratch,
            public.clone(),
            "output.rs",
            Some(content_digest(b"before")),
            limits.clone(),
        )
        .unwrap();
        let mut writer = FilePolicy::open(
            &root,
            &writer_scratch,
            public,
            "output.rs",
            Some(content_digest(b"before")),
            limits,
        )
        .unwrap();
        writer
            .dispatch(
                "write_file",
                &json!({"path":"output.rs","content":"after"}),
                &mut |_, _, _| unreachable!(),
            )
            .unwrap();
        let observed = writer.terminal_output().unwrap().unwrap();
        observer.verify_terminal_output(&observed).unwrap();
        let mut forged = observed.clone();
        forged.sha256 = content_digest(b"before");
        assert!(observer.verify_terminal_output(&forged).is_err());
        forged = observed.clone();
        forged.relative = "input.txt".into();
        assert!(observer.verify_terminal_output(&forged).is_err());
        fs::write(root.join("input.txt"), b"changed").unwrap();
        assert!(observer.verify_terminal_output(&observed).is_err());
        fs::write(root.join("input.txt"), b"public").unwrap();
        observer.verify_terminal_output(&observed).unwrap();
        fs::remove_file(root.join("output.rs")).unwrap();
        fs::write(root.join("output.rs"), b"after").unwrap();
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(root.join("output.rs")).unwrap();
        forged = observed;
        forged.device = meta.dev();
        forged.inode = meta.ino();
        forged.mode = meta.mode();
        assert!(observer.verify_terminal_output(&forged).is_err());
    }
    #[test]
    fn mcp_and_file_policy_feed_real_file_effects_back_to_the_dispatcher() {
        let root = tempfile::tempdir().unwrap();
        let candidate = root.path().join("candidate");
        let scratch = root.path().join("scratch");
        fs::create_dir(&candidate).unwrap();
        fs::create_dir(&scratch).unwrap();
        fs::write(candidate.join("output.rs"), "before").unwrap();
        fs::write(
            candidate.join("feedback.py"),
            "authored feedback callback fixture",
        )
        .unwrap();
        let public = BTreeMap::from([
            ("output.rs".into(), content_digest(b"before")),
            (
                "feedback.py".into(),
                content_digest(b"authored feedback callback fixture"),
            ),
        ]);
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
        let mut policy = FilePolicy::open(
            &candidate,
            &scratch,
            public,
            "output.rs",
            Some(content_digest(b"before")),
            limits,
        )
        .unwrap();
        let frames = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec","arguments":{"argv":["python3","-B","feedback.py"]}}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"output.rs","content":"after"}}}),
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"exec","arguments":{"argv":["python3","-B","feedback.py"]}}}),
        ];
        let mut input = Vec::new();
        for frame in frames {
            serde_json::to_writer(&mut input, &frame).unwrap();
            input.push(b'\n');
        }
        let mut output = Vec::new();
        let mut executed = 0;
        // This injected check observes actual file bytes; no process/model runs.
        let mut feedback = |argv: &[String], timeout: u64, cap: usize| {
            assert_eq!(argv, ["python3", "-B", "feedback.py"]);
            assert!(timeout > 0 && timeout <= 20000);
            assert!(cap <= 8192);
            executed += 1;
            let green = fs::read(candidate.join("output.rs")).unwrap() == b"after";
            Ok(ToolResult {
                stdout: if green { "GREEN" } else { "RED" }.into(),
                stderr: String::new(),
                exit_code: if green { 0 } else { 1 },
                termination: "exited".into(),
                truncated: false,
                elapsed_ms: 0,
            })
        };
        serve_mcp(Cursor::new(input), &mut output, |name, args| {
            policy.dispatch(name, &args, &mut feedback)
        })
        .unwrap();
        let replies = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str::<Value>(s).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(executed, 2);
        let terminal = policy
            .terminal_output()
            .unwrap()
            .expect("owned output missing");
        assert_eq!(terminal.relative, "output.rs");
        assert_eq!(terminal.sha256, content_digest(b"after"));
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            terminal.inode,
            fs::metadata(candidate.join("output.rs")).unwrap().ino()
        );
        assert_eq!(replies.len(), 4);
        let red: Value =
            serde_json::from_str(replies[1]["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        let green: Value =
            serde_json::from_str(replies[3]["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(red["exit_code"], 1);
        assert_eq!(red["stdout"], "RED");
        assert_eq!(green["exit_code"], 0);
        assert_eq!(green["stdout"], "GREEN");
        assert_eq!(replies[1]["result"]["isError"], false);
        assert_eq!(fs::read(candidate.join("output.rs")).unwrap(), b"after");
        assert_eq!(policy.journal().len(), 3);
        assert!(!policy.halted());
    }
}
