//! Opt-in kernel qualification. Authored MCP caller only; no native/model process.
use super::*;
use router_adapter_api::content_digest;
use router_types::FiniteClientFile;
use serde_json::json;
use std::{
    fs,
    io::Cursor,
    os::unix::{
        fs::{DirBuilderExt, PermissionsExt},
        net::UnixStream,
    },
    path::PathBuf,
};
fn mkdir(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn limits() -> Limits {
    Limits {
        max_calls: 8,
        max_file_bytes: 32768,
        max_output_bytes: 8192,
        max_total_output_bytes: 32768,
        max_exec_ms: 20000,
        max_total_exec_ms: 60000,
        max_session_ms: 90000,
        max_scratch_entries: 64,
        max_scratch_bytes: 16777216,
    }
}
fn setup(
    name: &str,
    files: &[(&str, &[u8])],
    output: &str,
    new: bool,
) -> (ToolSession, PathBuf, PathBuf) {
    setup_limits(name, files, output, new, limits())
}
fn setup_limits(
    name: &str,
    files: &[(&str, &[u8])],
    output: &str,
    new: bool,
    limits: Limits,
) -> (ToolSession, PathBuf, PathBuf) {
    let root = PathBuf::from(std::env::var("AR_MCP_ROOT").unwrap()).join(name);
    mkdir(&root);
    let candidate = root.join("candidate");
    let control = root.join("control");
    mkdir(&candidate);
    mkdir(&control);
    let scratch = PathBuf::from(std::env::var("AR_MCP_SCRATCH").unwrap()).join(name);
    mkdir(&scratch);
    let mut public = BTreeMap::new();
    for (name, bytes) in files {
        fs::write(candidate.join(name), bytes).unwrap();
        public.insert((*name).into(), content_digest(bytes));
    }
    let programs = PathBuf::from(std::env::var("AR_MCP_PROGRAMS").unwrap());
    let pin = |name: &str| {
        let path = programs.join(name);
        FiniteClientFile {
            path: path.to_str().unwrap().into(),
            sha256: content_digest(&fs::read(path).unwrap()),
        }
    };
    let sandbox = ExecSandbox {
        namespace: pin("namespace"),
        helper: pin("helper"),
        guard: pin("guard"),
        compiler: pin("compiler/rustc"),
        root: candidate.clone(),
        scratch: scratch.clone(),
        control,
        public,
        output: output.into(),
    };
    let preimage = if new {
        None
    } else {
        Some(content_digest(&fs::read(candidate.join(output)).unwrap()))
    };
    (
        ToolSession::open(sandbox, preimage, limits).unwrap(),
        candidate,
        scratch,
    )
}
fn exchange(
    session: &mut ToolSession,
    calls: &[(&str, serde_json::Value)],
) -> Vec<serde_json::Value> {
    let mut frames = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"authored-no-model-caller","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    ];
    for (i, (name, args)) in calls.iter().enumerate() {
        frames.push(json!({"jsonrpc":"2.0","id":i+2,"method":"tools/call","params":{"name":name,"arguments":args,"_meta":{"callId":format!("authored-{i}"),"threadId":"authored-context","sessionId":"authored-session"}}}));
    }
    let bytes: Vec<_> = frames
        .iter()
        .flat_map(|v| {
            let mut b = serde_json::to_vec(v).unwrap();
            b.push(b'\n');
            b
        })
        .collect();
    let (client, server) = UnixStream::pair().unwrap();
    let mut output = Vec::new();
    std::thread::scope(|scope| {
        let serving = scope.spawn(|| session.serve(server));
        transport::relay(Cursor::new(bytes), &mut output, client).unwrap();
        serving.join().unwrap().unwrap();
    });
    output
        .split(|b| *b == b'\n')
        .filter(|s| !s.is_empty())
        .map(|s| serde_json::from_slice(s).unwrap())
        .collect()
}
fn result(value: &serde_json::Value) -> serde_json::Value {
    assert_eq!(value["result"]["isError"], false, "{value}");
    serde_json::from_str(value["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}
#[test]
#[ignore = "requires the explicit Linux lab and 16 MiB scratch mount"]
fn linux_mcp_feedback_red_write_green() {
    let feedback =
        include_bytes!("../../../../docs/bench/linux-finite-tools-guard-2026-10-16/feedback.py");
    assert_eq!(
        content_digest(feedback),
        "8a62ffb5eb9c59318bd9b274d0234f11def6eeb2dafb99e5163e305f3c8fd0ca"
    );
    let (mut session,candidate,_)=setup("red-green",&[("lib.rs",b"pub fn answer()->u32{41}\n"),("feedback-tests.rs",b"#[path=\"lib.rs\"] mod code; #[test] fn useful_check(){assert_eq!(code::answer(),42);}\n"),("feedback.py",feedback)],"lib.rs",false);
    let replies = exchange(
        &mut session,
        &[
            ("exec", json!({"argv":["python3","-B","feedback.py"]})),
            (
                "write_file",
                json!({"path":"lib.rs","content":"pub fn answer()->u32{42}\n"}),
            ),
            ("exec", json!({"argv":["python3","-B","feedback.py"]})),
        ],
    );
    eprintln!("FEEDBACK_REPLY {replies:#?}");
    let red = result(&replies[1]);
    let green = result(&replies[3]);
    assert_eq!(red["exit_code"], 1);
    assert!(
        red["stdout"]
            .as_str()
            .unwrap()
            .contains("test result: FAILED")
    );
    assert_eq!(green["exit_code"], 0);
    assert!(green["stdout"].as_str().unwrap().contains("1 passed"));
    assert_eq!(
        fs::read(candidate.join("lib.rs")).unwrap(),
        b"pub fn answer()->u32{42}\n"
    );
    assert!(!session.halted());
    assert_eq!(session.journal().len(), 3);
    println!(
        "RED_WRITE_GREEN {}",
        json!({"red":red,"green":green,"journal":session.journal()})
    );
}
#[test]
#[ignore = "requires the explicit Linux lab and 16 MiB scratch mount"]
fn linux_mcp_scratch_survives_compile_then_run() {
    let (mut session, _, scratch) = setup(
        "persistent",
        &[("output.rs", b"original")],
        "output.rs",
        false,
    );
    let replies = exchange(
        &mut session,
        &[
            (
                "write_file",
                json!({"path":".scratch/own-check.rs","content":"fn main(){println!(\"ACTUAL_COMPILED_CHECK\");}","create_new":true}),
            ),
            (
                "exec",
                json!({"argv":["rustc","--edition=2021",".scratch/own-check.rs","-o",".scratch/own-check"]}),
            ),
            ("exec", json!({"argv":[".scratch/own-check"]})),
        ],
    );
    eprintln!("SCRATCH_REPLY {replies:#?}");
    assert_eq!(result(&replies[2])["exit_code"], 0);
    let run = result(&replies[3]);
    assert_eq!(run["exit_code"], 0);
    assert_eq!(run["stdout"], "ACTUAL_COMPILED_CHECK\n");
    assert!(
        fs::metadata(scratch.join("own-check"))
            .unwrap()
            .permissions()
            .mode()
            & 0o100
            != 0
    );
    println!("PERSISTENT_SCRATCH {run}");
}
#[test]
#[ignore = "requires the explicit Linux lab and 16 MiB scratch mount"]
fn linux_mcp_tool_cannot_access_private_files_network_or_public_writes() {
    let (mut session, candidate, _) = setup(
        "privacy",
        &[("output.rs", b"original"), ("statement.txt", b"PUBLIC")],
        "output.rs",
        false,
    );
    let compiler_private =
        PathBuf::from(std::env::var("AR_MCP_PROGRAMS").unwrap()).join("compiler/sibling-private");
    fs::write(&compiler_private, b"unapproved-compiler-sibling").unwrap();
    let private = candidate.parent().unwrap().join("private-controller");
    fs::write(&private, b"unmounted-private-canary").unwrap();
    let script = format!(
        r#"import errno,mmap,os,resource,socket
assert resource.getrlimit(resource.RLIMIT_AS)==(8589934592,8589934592)
assert open('statement.txt').read()=='PUBLIC'
for path in [{private:?}, '/work', '/router-tools', '/unavailable/config.toml','/usr/local/bin/sibling-private']:
 try: open(path).read()
 except OSError as e: assert e.errno==errno.ENOENT
 else: raise AssertionError(path)
for action in [lambda:open('statement.txt','w'),lambda:os.chmod('statement.txt',0o600),lambda:socket.socket(socket.AF_INET,socket.SOCK_STREAM),lambda:socket.socket(socket.AF_UNIX,socket.SOCK_STREAM),lambda:socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET),lambda:socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)]:
 try: action()
 except OSError as e: assert e.errno in (errno.EPERM,errno.EACCES,errno.EROFS)
 else: raise AssertionError('effect allowed')
with mmap.mmap(-1,16777216,prot=0): pass
try: mmap.mmap(-1,9663676416,prot=0)
except OSError as e: assert e.errno==errno.ENOMEM
else: raise AssertionError('memory limit')
print('ACTUAL_PRIVATE_NETWORK_WRITE_MEMORY_REFUSALS')
"#
    );
    let replies = exchange(
        &mut session,
        &[("exec", json!({"argv":["python3","-c",script]}))],
    );
    eprintln!("PRIVACY_REPLY {replies:#?}");
    let observed = result(&replies[1]);
    assert_eq!(observed["exit_code"], 0);
    assert_eq!(
        observed["stdout"],
        "ACTUAL_PRIVATE_NETWORK_WRITE_MEMORY_REFUSALS\n"
    );
    assert_eq!(
        fs::read(candidate.join("statement.txt")).unwrap(),
        b"PUBLIC"
    );
    assert_eq!(fs::read(private).unwrap(), b"unmounted-private-canary");
    println!("PRIVACY {observed}");
}
#[test]
#[ignore = "requires the explicit Linux lab and 16 MiB scratch mount"]
fn linux_mcp_timeout_stops_detached_writer_before_sticky_refusal() {
    let (mut session, candidate, scratch) =
        setup("timeout", &[("output.rs", b"original")], "output.rs", false);
    let script = "import os,time\nf=os.open('.scratch/heartbeat',os.O_CREAT|os.O_WRONLY,0o600)\np=os.fork()\nif p==0:\n os.setsid()\n while True:\n  os.write(f,b'x');time.sleep(0.01)\nwhile True: time.sleep(0.01)\n";
    let replies = exchange(
        &mut session,
        &[
            (
                "exec",
                json!({"argv":["python3","-c",script],"timeout_ms":800}),
            ),
            (
                "write_file",
                json!({"path":"output.rs","content":"must refuse"}),
            ),
        ],
    );
    eprintln!("TIMEOUT_REPLY {replies:#?}");
    assert_eq!(replies[1]["result"]["isError"], true);
    assert_eq!(replies[2]["result"]["isError"], true);
    let before = fs::metadata(scratch.join("heartbeat")).unwrap().len();
    assert!(before > 1);
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(
        fs::metadata(scratch.join("heartbeat")).unwrap().len(),
        before
    );
    assert_eq!(fs::read(candidate.join("output.rs")).unwrap(), b"original");
    assert!(session.halted());
    println!(
        "TIMEOUT_STOPPED_DETACHED {}",
        json!({"heartbeat_bytes":before,"journal":session.journal()})
    );
}

#[test]
#[ignore = "requires the explicit Linux lab and fixed bridge program"]
fn linux_mcp_fixed_cli_bridge_reaches_owned_session_without_a_model() {
    use std::{
        os::unix::net::UnixListener,
        time::{Duration, Instant},
    };
    let (mut session, candidate, _) = setup(
        "cli-bridge",
        &[("input.txt", b"public")],
        "review.json",
        true,
    );
    let socket = Path::new("/router-tools/rpc.sock");
    let listener = UnixListener::bind(socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let serving = std::thread::spawn(move || {
        let started = Instant::now();
        loop {
            match listener.accept() {
                Ok((stream, _)) => return session.serve(stream),
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && started.elapsed() < Duration::from_secs(3) =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err(FiniteToolError::Execution),
            }
        }
    });
    let frames = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"authored-cli-caller","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"review.json","content":"{\"findings\":[]}","create_new":true},"_meta":{"callId":"authored-cli","threadId":"context","sessionId":"session"}}}),
    ];
    let input = frames
        .iter()
        .flat_map(|v| {
            let mut b = serde_json::to_vec(v).unwrap();
            b.push(b'\n');
            b
        })
        .collect();
    let client = PathBuf::from(std::env::var("AR_MCP_CLIENT").unwrap());
    let mut command = tokio::process::Command::new(client);
    command
        .arg("--mcp-tools")
        .env_clear()
        .env("PATH", "/usr/bin:/bin");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let captured = runtime
        .block_on(crate::process::capture(
            command,
            input,
            5000,
            65536,
            100,
            &crate::Cancellation::default(),
        ))
        .unwrap();
    serving.join().unwrap().unwrap();
    fs::remove_file(socket).unwrap();
    assert_eq!(
        captured.outcome.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&captured.stderr)
    );
    assert!(!captured.output_incomplete && !captured.output_limited);
    assert_eq!(
        fs::read(candidate.join("review.json")).unwrap(),
        b"{\"findings\":[]}"
    );
    let replies: Vec<serde_json::Value> = captured
        .stdout
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(|b| serde_json::from_slice(b).unwrap())
        .collect();
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[1]["result"]["isError"], false);
    println!(
        "FIXED_CLI_NO_MODEL {}",
        json!({"exit_code":captured.outcome.exit_code,"replies":replies.len(),"output_created":true})
    );
}

#[test]
#[ignore = "requires the explicit Linux lab and 16 MiB scratch mount"]
fn linux_session_deadline_stops_a_longer_exec_and_its_detached_writer() {
    let mut budget = limits();
    budget.max_session_ms = 500;
    let (mut session, candidate, scratch) = setup_limits(
        "session-deadline",
        &[("output.rs", b"original")],
        "output.rs",
        false,
        budget,
    );
    let script = "import os,time\nf=os.open('.scratch/heartbeat',os.O_CREAT|os.O_WRONLY,0o600)\np=os.fork()\nif p==0:\n os.setsid()\n while True:\n  os.write(f,b'x');time.sleep(0.01)\nwhile True: time.sleep(0.01)\n";
    let frames = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"session-deadline","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec","arguments":{"argv":["python3","-c",script],"timeout_ms":3000}}}),
    ];
    let bytes: Vec<_> = frames
        .iter()
        .flat_map(|v| {
            let mut b = serde_json::to_vec(v).unwrap();
            b.push(b'\n');
            b
        })
        .collect();
    let (client, server) = UnixStream::pair().unwrap();
    let started = std::time::Instant::now();
    std::thread::scope(|scope| {
        let serving = scope.spawn(|| session.serve(server));
        let _ = transport::relay(Cursor::new(bytes), &mut Vec::new(), client);
        assert!(serving.join().unwrap().is_err());
    });
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "exec exceeded the absolute session deadline: {:?}",
        started.elapsed()
    );
    assert!(session.halted());
    let before = fs::metadata(scratch.join("heartbeat")).unwrap().len();
    assert!(before > 1);
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(
        fs::metadata(scratch.join("heartbeat")).unwrap().len(),
        before
    );
    assert_eq!(fs::read(candidate.join("output.rs")).unwrap(), b"original");
}
