//! Opt-in real SDK protocol qualification against authored local Responses.
//! This is component evidence, never a Runtime approval or Tools capability.
use super::FiniteCodexState;
use crate::finite_tools::{ExecSandbox, Limits, ToolOwnerBoot, ToolTerminal};
use crate::{Cancellation, ResourceLimits, finite_client::OwnedBroker, leases::LeaseStorage};
use router_adapter_api::content_digest;
use router_types::{
    FiniteClientFile, PreparedInput, PreparedRun, ProcessCleanupEvidence, TransportTermination,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
fn mkdir(p: &Path) {
    fs::DirBuilder::new().mode(0o700).create(p).unwrap();
}
fn pin(p: &Path) -> FiniteClientFile {
    FiniteClientFile {
        path: p.to_str().unwrap().into(),
        sha256: content_digest(&fs::read(p).unwrap()),
    }
}
struct ScriptChild(std::process::Child);
impl Drop for ScriptChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
pub(super) fn broker(
    listener: TcpListener,
    inputs: PathBuf,
    script: PathBuf,
    adapter: PathBuf,
    evidence: PathBuf,
    count: usize,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let driver = r#"import json,sys
sys.path.insert(0,sys.argv[1]);sys.path.insert(0,sys.argv[3])
from native_tool_responses import ToolScript
v=json.load(open(sys.argv[2]));s=ToolScript(v['steps'],model=v['model'],effort=v['effort'],marker=v['marker'])
for line in sys.stdin:
 r=s.respond(json.loads(line));print(json.dumps({'sse':r.decode(),'catalog_digest':s.observed_native_catalogs[-1],'tool_results':s.observed_tool_results}),flush=True)
"#;
        let mut child = ScriptChild(
            Command::new("/usr/bin/python3")
                .args(["-B", "-u", "-c", driver])
                .arg(inputs)
                .arg(script)
                .arg(adapter)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("PYTHONNOUSERSITE", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let mut input = child.0.stdin.take().unwrap();
        let mut output = BufReader::new(child.0.stdout.take().unwrap());
        listener.set_nonblocking(true).unwrap();
        // Source hashing and two fresh OS probes precede the first authored
        // request. Their preparation time is not the worker's turn deadline.
        let mut deadline = Instant::now() + Duration::from_secs(300);
        let mut requests = Vec::new();
        while requests.len() < count {
            assert!(Instant::now() < deadline, "native local request deadline");
            let (mut socket, _) = match listener.accept() {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => panic!("accept {e}"),
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut first = String::new();
            if reader.read_line(&mut first).unwrap() == 0 {
                // The fresh OS canary proves a TCP connection without sending
                // a provider request. It is not an authored response or call.
                continue;
            }
            let mut length = 0usize;
            let mut headers = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                headers += line.len();
                assert!(headers <= 16384 && !line.is_empty());
                if line == "\r\n" {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                assert!(!lower.starts_with("authorization:"));
                if let Some(n) = lower.strip_prefix("content-length:") {
                    length = n.trim().parse().unwrap();
                }
            }
            if first == "GET /__router_probe__ HTTP/1.0\r\n" {
                assert_eq!(length, 0);
                socket
                    .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .unwrap();
                continue;
            }
            assert!(first.starts_with("POST /v1/responses "));
            if requests.is_empty() {
                deadline = Instant::now() + Duration::from_secs(70);
            }
            assert!((1..=262144).contains(&length));
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let request = router_adapter_api::strict_json_limited(&body, 262144).unwrap();
            fs::write(
                evidence.join(format!("request-{}.json", requests.len())),
                &body,
            )
            .unwrap();
            writeln!(input, "{}", serde_json::to_string(&request).unwrap()).unwrap();
            input.flush().unwrap();
            let mut reply = String::new();
            output.read_line(&mut reply).unwrap();
            let response: Value = serde_json::from_str(&reply).unwrap();
            assert_eq!(
                response["catalog_digest"],
                "f83cb0cae17d9b72a5bd2637f6db80fc2f5f6ef5eeeb61d5dd8bc6a869c7de85"
            );
            assert_eq!(response["tool_results"], requests.len());
            let response = response["sse"].as_str().unwrap();
            requests.push(content_digest(&body));
            write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",response.len()).unwrap();
            socket.write_all(response.as_bytes()).unwrap();
        }
        fs::write(evidence.join("broker.json"),serde_json::to_vec_pretty(&json!({"requests":requests,"auth_header_present":false,"model_calls_started":0,"authored_only":true,"observed_tool_results":count-1,"native_catalog_sha256":"f83cb0cae17d9b72a5bd2637f6db80fc2f5f6ef5eeeb61d5dd8bc6a869c7de85","discovery_wrappers_advertised":3,"discovery_wrappers_called":0})).unwrap()).unwrap();
    })
}
#[tokio::test]
#[ignore = "requires pinned native SDK, isolated loopback Linux ARM64, fixed 8GiB and public authored packets"]
async fn native_sdk_returns_actual_mcp_results_for_six_public_packets() {
    let root = PathBuf::from(std::env::var("AR_MCP_NATIVE_ROOT").unwrap());
    mkdir(&root);
    let inputs = PathBuf::from(std::env::var("AR_MCP_NATIVE_INPUTS").unwrap());
    let adapter = PathBuf::from(std::env::var("AR_MCP_NATIVE_ADAPTER").unwrap());
    assert_eq!(
        content_digest(&fs::read(adapter.join("native_tool_responses.py")).unwrap()),
        "6e2268fca17bb2bf0f241cf959fe229cf50c19ea7f44b85b67de359c24b80ffe"
    );
    assert_eq!(
        content_digest(&fs::read(adapter.join("expected-native-catalog.json")).unwrap()),
        "9550e472a5b090c76b35bc1db5e2e5a30d6d6d3cc41b38da826acb790713182f"
    );
    let manifest_bytes = fs::read(inputs.join("manifest.json")).unwrap();
    assert_eq!(
        content_digest(&manifest_bytes),
        "5f72c2221b5feb350ea05410f5496ee31bd924658130bf6ae394699cb0cfdf1b"
    );
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    for row in manifest["files"].as_array().unwrap() {
        let bytes = fs::read(inputs.join(row["path"].as_str().unwrap())).unwrap();
        assert_eq!(content_digest(&bytes), row["sha256"]);
        assert_eq!(bytes.len() as u64, row["bytes"].as_u64().unwrap());
    }
    let programs = PathBuf::from(std::env::var("AR_MCP_PROGRAMS").unwrap());
    assert_eq!(
        pin(&programs.join("native")).sha256,
        "113aa5d5952a6fd3950a88323219747d0c91978ebee948509a540c8a460e59a3"
    );
    for packet in manifest["packets"].as_array().unwrap() {
        let id = packet["assignment_id"].as_str().unwrap();
        let case = root.join(id);
        mkdir(&case);
        let candidate = case.join("candidate");
        mkdir(&candidate);
        let store = case.join("state");
        mkdir(&store);
        let evidence = case.join("evidence");
        mkdir(&evidence);
        let mut public = BTreeMap::new();
        for entry in fs::read_dir(inputs.join(packet["candidate"].as_str().unwrap())).unwrap() {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            let name = entry.file_name().into_string().unwrap();
            let bytes = fs::read(entry.path()).unwrap();
            fs::write(candidate.join(&name), &bytes).unwrap();
            fs::set_permissions(candidate.join(&name), fs::Permissions::from_mode(0o600)).unwrap();
            public.insert(name, content_digest(&bytes));
        }
        let output = packet["output_file"].as_str().unwrap().to_string();
        let preimage = packet["input_preimage_sha256"].as_str().map(str::to_owned);
        assert_eq!(preimage.is_none(), !candidate.join(&output).exists());
        let listener = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        rustix::net::sockopt::set_socket_reuseaddr(&listener, false).unwrap();
        rustix::net::sockopt::set_socket_reuseport(&listener, false).unwrap();
        let port = listener.local_addr().unwrap().port();
        let owned = OwnedBroker::from_isolated_listener(listener.try_clone().unwrap()).unwrap();
        let run=PreparedRun{schema_version:1,receipt_id:"a".repeat(64),source_state:"b".repeat(40),scope:vec![output.clone()],authorization_digest:"c".repeat(64),snapshot_hash:"d".repeat(64),host:router_types::HarnessId::parse("codex").unwrap(),requested_model:router_types::ModelId::parse("gpt-6-luna").unwrap(),requested_effort:router_types::EffortLevel::Medium,program:"finite-client".into(),argv:vec!["--worker".into()],cwd:candidate.to_str().unwrap().into(),stdin:PreparedInput::new(b"R2-LOCAL-TOOLS-V1\nComplete the synthetic task using only approved local tools. This is authored qualification, not a model trial.\n".to_vec()),mode:router_types::ExecutionMode::Execute,target:router_types::ExecutionTarget::ExternalWorker,sandbox:router_types::ExecutionSandbox::WorkspaceWrite,timeout_ms:60000,max_output_bytes:65536,degradations:vec![],missing_runtime_evidence:vec![],parent_model_changed:false};
        let mut state = owned.prepare_codex_tools_state(&store, &run).unwrap();
        let home_path = state.path().to_owned();
        let home = home_path.as_path();
        let configuration = state.configuration();
        let context = json!({"native":programs.join("native"),"native_sha256":pin(&programs.join("native")).sha256,"native_version":"0.159.2-linux-arm64-musl","home":home,"cwd":candidate,"configuration_sha256":configuration.sha256,"model":"gpt-6-luna","effort":"medium","stdin_sha256":content_digest(run.stdin.as_bytes()),"max_output_bytes":65536,"replacement":null});
        let binding = content_digest(id.as_bytes());
        let sandbox = ExecSandbox {
            namespace: pin(&programs.join("namespace")),
            helper: pin(&programs.join("helper")),
            guard: pin(&programs.join("guard")),
            compiler: pin(&programs.join("compiler/rustc")),
            root: candidate.clone(),
            scratch: "/router-tools/scratch".into(),
            control: "/router-tools/control".into(),
            public: public.clone(),
            output: output.clone(),
        };
        let boot = ToolOwnerBoot {
            sandbox,
            limits: Limits {
                max_calls: 8,
                max_file_bytes: 32768,
                max_output_bytes: 8192,
                max_total_output_bytes: 32768,
                max_exec_ms: 20000,
                max_total_exec_ms: 60000,
                max_session_ms: 60000,
                max_scratch_entries: 64,
                max_scratch_bytes: 16777216,
            },
            preimage,
            binding: binding.clone(),
            client: pin(&programs.join("client")),
            home: home.to_str().unwrap().into(),
            broker_port: port,
            reads: ["client", "native", "helper", "guard", "namespace"]
                .map(|name| programs.join(name).to_str().unwrap().to_owned())
                .to_vec(),
            context: context.to_string(),
            probe: None,
        };
        let boot_path = case.join("boot.json");
        fs::write(&boot_path, serde_json::to_vec(&boot).unwrap()).unwrap();
        fs::set_permissions(&boot_path, fs::Permissions::from_mode(0o400)).unwrap();
        let terminal = case.join("terminal.json");
        fs::write(&terminal, []).unwrap();
        fs::set_permissions(&terminal, fs::Permissions::from_mode(0o600)).unwrap();
        let script_path = inputs.join(packet["broker_script"].as_str().unwrap());
        let script: Value = serde_json::from_slice(&fs::read(&script_path).unwrap()).unwrap();
        let calls = script["steps"].as_array().unwrap().len();
        let server = broker(
            listener,
            inputs.clone(),
            script_path,
            adapter.clone(),
            evidence.clone(),
            calls + 1,
        );
        let leases_root = case.join("leases");
        mkdir(&leases_root);
        let leases = LeaseStorage::open(&leases_root).unwrap();
        let (mut record, lease) = leases.create("native", 1).unwrap();
        record.require_namespace(true);
        let mut command = tokio::process::Command::new(programs.join("helper"));
        command
            .args(ResourceLimits::default().args().unwrap())
            .arg("--supervise-v1")
            .arg(programs.join("namespace"))
            .args([
                "--die-with-parent",
                "--new-session",
                "--unshare-all",
                "--share-net",
                "--cap-drop",
                "ALL",
                "--tmpfs",
                "/",
                "--ro-bind",
                "/usr",
                "/usr",
                "--symlink",
                "usr/bin",
                "/bin",
                "--symlink",
                "usr/lib",
                "/lib",
                "--symlink",
                "usr/lib64",
                "/lib64",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--size",
                "134217728",
                "--tmpfs",
                "/tmp",
            ])
            .arg("--ro-bind")
            .arg(&programs)
            .arg(&programs)
            .arg("--ro-bind")
            .arg(home)
            .arg(home)
            .arg("--bind")
            .arg(home.join("tmp"))
            .arg(home.join("tmp"))
            .arg("--bind")
            .arg(&candidate)
            .arg(&candidate)
            .args([
                "--size",
                "1048576",
                "--tmpfs",
                "/router-tools",
                "--chmod",
                "700",
                "/router-tools",
                "--size",
                "16777216",
                "--tmpfs",
                "/router-tools/scratch",
                "--chmod",
                "700",
                "/router-tools/scratch",
            ])
            .arg("--ro-bind")
            .arg(&boot_path)
            .arg("/router-tools/boot.json")
            .arg("--bind")
            .arg(&terminal)
            .arg("/router-tools/terminal.json")
            .arg("--ro-bind")
            .arg(programs.join("client"))
            .arg("/finite-client")
            .args(["--remount-ro", "/", "--chdir"])
            .arg(&candidate)
            .arg("--")
            .arg(programs.join("client"))
            .arg("--tools-owner")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("ROUTER_RUNTIME_SUPERVISION", "framed-v1")
            .env("ROUTER_RUNTIME_CONTAINMENT", "pid-namespace-v1")
            .env("ROUTER_RUNTIME_LEASE", &lease);
        state.state.arm_cleanup(Some(&lease), true).unwrap();
        let captured = crate::process::capture(
            command,
            run.stdin.as_bytes().to_vec(),
            65000,
            65536,
            100,
            &Cancellation::default(),
        )
        .await;
        let proof = leases.cleanup_proof("native", 1, &record).unwrap();
        assert_eq!(proof.evidence, ProcessCleanupEvidence::NamespaceTerminated);
        let FiniteCodexState { state, .. } = state;
        state.cleanup_with_proof(&proof).unwrap();
        assert!(!home.exists());
        let captured = captured.unwrap();
        fs::write(evidence.join("stdout.jsonl"), &captured.stdout).unwrap();
        fs::write(evidence.join("stderr.txt"), &captured.stderr).unwrap();
        fs::write(evidence.join("transport.json"),serde_json::to_vec_pretty(&json!({"exit_code":captured.outcome.exit_code,"termination":captured.outcome.termination,"truncated":captured.output_limited,"incomplete":captured.output_incomplete,"cleanup":proof.evidence,"memory_bytes":8589934592u64,"models_started":0,"runtime_tools_admission":false})).unwrap()).unwrap();
        assert_eq!(
            captured.outcome.exit_code,
            Some(0),
            "{id}: {}",
            String::from_utf8_lossy(&captured.stderr)
        );
        assert_eq!(captured.outcome.termination, TransportTermination::Exited);
        assert!(!captured.output_limited && !captured.output_incomplete);
        server.join().unwrap();
        let observed: ToolTerminal = serde_json::from_slice(&fs::read(&terminal).unwrap()).unwrap();
        assert_eq!(observed.binding, binding);
        assert!(observed.complete && !observed.halted);
        assert_eq!(observed.journal.len(), calls);
        let actual = observed.output.as_ref().unwrap();
        assert_eq!(actual.relative, output);
        assert_eq!(
            actual.sha256,
            content_digest(&fs::read(candidate.join(&output)).unwrap())
        );
        for (name, hash) in public {
            if name != output {
                assert_eq!(
                    content_digest(&fs::read(candidate.join(name)).unwrap()),
                    hash
                );
            }
        }
        fs::write(
            evidence.join("terminal.json"),
            serde_json::to_vec_pretty(&observed).unwrap(),
        )
        .unwrap();
        println!(
            "native MCP authored packet {id}: {calls} real tool results returned, exact namespace stopped; no Runtime authority or model"
        );
    }
}
