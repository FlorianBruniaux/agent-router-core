//! Fixed trusted controller, called only inside the reviewed outer namespace.
//! These worker bytes cannot construct a Runtime approval or live Tools proof.
use super::{ExecSandbox, Limits, ToolSession, ToolTerminal};
use router_types::FiniteClientFile;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        net::{UnixListener, UnixStream},
    },
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolOwnerBoot {
    pub sandbox: ExecSandbox,
    pub limits: Limits,
    pub preimage: Option<String>,
    pub binding: String,
    pub client: FiniteClientFile,
    pub home: String,
    pub broker_port: u16,
    pub reads: Vec<String>,
    pub context: String,
    pub probe: Option<ToolOwnerProbe>,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolOwnerProbe {
    pub denied_port: u16,
    pub hidden: String,
    pub control: String,
    pub nonce: String,
}

/// No model call is made by constructing this data. Production dispatch must
/// retain the opaque review and fresh OS evidence outside this worker process.
pub fn run_owner(boot: ToolOwnerBoot) -> Result<i32, super::FiniteToolError> {
    run_owner_inner(boot).map_err(super::FiniteToolError::Refused)
}
fn run_owner_inner(boot: ToolOwnerBoot) -> Result<i32, &'static str> {
    if !cfg!(target_os = "linux")
        || boot.context.len() > 8192
        || !router_adapter_api::is_digest(&boot.binding)
        || boot.broker_port == 0
        || !(5..=8).contains(&boot.reads.len())
        || boot
            .reads
            .iter()
            .any(|p| !std::path::Path::new(p).is_absolute() || p == "/" || p.len() > 4096)
        || boot.sandbox.scratch != std::path::Path::new("/router-tools/scratch")
        || boot.sandbox.control != std::path::Path::new("/router-tools/control")
    {
        return Err("owner.boot");
    }
    let _client_pin =
        crate::finite_client::retain_tool_program(&boot.client).map_err(|_| "owner.client")?;
    let _guard_pin = crate::finite_client::retain_tool_program(&boot.sandbox.guard)
        .map_err(|_| "owner.guard")?;
    let mut prompt = Vec::new();
    std::io::stdin()
        .take(32769)
        .read_to_end(&mut prompt)
        .map_err(|_| "owner.stdin")?;
    if prompt.len() > 32768 {
        return Err("owner.stdin_bound");
    }
    let context = router_adapter_api::strict_json_limited(boot.context.as_bytes(), 8192)
        .map_err(|_| "owner.context")?;
    if context["cwd"].as_str() != boot.sandbox.root.to_str()
        || context["home"] != boot.home
        || !context["replacement"].is_null()
        || context["stdin_sha256"] != router_adapter_api::content_digest(&prompt)
        || context["native_sha256"]
            != "113aa5d5952a6fd3950a88323219747d0c91978ebee948509a540c8a460e59a3"
    {
        return Err("owner.context_binding");
    }
    let mut terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open("/router-tools/terminal.json")
        .map_err(|_| "owner.terminal")?;
    let metadata = terminal.metadata().map_err(|_| "owner.terminal")?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() != 0
    {
        return Err("owner.terminal_identity");
    }
    std::fs::create_dir("/router-tools/control").map_err(|_| "owner.control")?;
    let mut session = ToolSession::open(
        boot.sandbox.clone(),
        boot.preimage.clone(),
        boot.limits.clone(),
    )
    .map_err(|_| "owner.policy")?;
    let failed = session.stop_signal();
    let stop = Arc::new(AtomicBool::new(false));
    let current = Arc::new(Mutex::new(None::<UnixStream>));
    let listener = UnixListener::bind("/router-tools/rpc.sock").map_err(|_| "owner.listen")?;
    listener.set_nonblocking(true).map_err(|_| "owner.listen")?;
    let (thread_stop, thread_failed, thread_current) =
        (stop.clone(), failed.clone(), current.clone());
    let binding = boot.binding.clone();
    let deadline = Duration::from_millis(boot.limits.max_session_ms);
    let server = std::thread::spawn(move || {
        let started = Instant::now();
        let mut sessions = 0;
        let result = (|| -> Result<(), &'static str> {
            while !thread_stop.load(Ordering::SeqCst) {
                if started.elapsed() >= deadline {
                    return Err("owner.deadline");
                }
                let stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => return Err("owner.accept"),
                };
                sessions += 1;
                if sessions > 8 {
                    return Err("owner.connections");
                }
                *thread_current.lock().map_err(|_| "owner.lock")? =
                    Some(stream.try_clone().map_err(|_| "owner.clone")?);
                session.serve(stream).map_err(|_| "owner.protocol")?;
                *thread_current.lock().map_err(|_| "owner.lock")? = None;
                if session.halted() {
                    return Err("owner.halted");
                }
            }
            if sessions == 0 {
                return Err("owner.no_session");
            }
            Ok(())
        })();
        if result.is_err() {
            thread_failed.store(true, Ordering::SeqCst);
        }
        let observed = session
            .terminal(&binding, result.is_ok())
            .unwrap_or_else(|_| ToolTerminal {
                schema_version: 1,
                binding,
                complete: false,
                halted: true,
                output: None,
                journal: session.journal().to_vec(),
            });
        observed
    });
    let mut command = Command::new(&boot.sandbox.guard.path);
    command
        .arg("--restrict-tools-v1")
        .arg(boot.broker_port.to_string())
        .arg(&boot.home)
        .arg(context["cwd"].as_str().ok_or("owner.cwd")?)
        .arg("0")
        .arg(boot.reads.len().to_string())
        .args(&boot.reads);
    if let Some(probe) = &boot.probe {
        command
            .arg("--probe-v1")
            .arg(probe.denied_port.to_string())
            .arg(&probe.hidden)
            .arg(&probe.control)
            .arg(&probe.nonce);
    }
    command
        .arg("--")
        .arg(&boot.client.path)
        .arg(if boot.probe.is_some() {
            "--tools-probe-peer"
        } else {
            "--worker"
        })
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &boot.home)
        .env("CODEX_HOME", &boot.home)
        .env("TMPDIR", format!("{}/tmp", boot.home))
        .env("CODEX_SQLITE_HOME", format!("{}/tmp", boot.home))
        .env("ROUTER_FINITE_CONTEXT", &boot.context)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(probe) = &boot.probe {
        let (read, hash) = boot
            .sandbox
            .public
            .iter()
            .find(|(name, _)| *name != &boot.sandbox.output)
            .ok_or("owner.probe_public")?;
        command
            .env("ROUTER_FINITE_PROBE_NONCE", &probe.nonce)
            .env("ROUTER_FINITE_PROBE_OUTPUT", &boot.sandbox.output)
            .env("ROUTER_FINITE_PROBE_READ", read)
            .env("ROUTER_FINITE_PROBE_READ_SHA256", hash)
            .env(
                "ROUTER_FINITE_PROBE_CREATE",
                boot.preimage.is_none().to_string(),
            )
            .env(
                "ROUTER_FINITE_PROBE_EXEC_MS",
                boot.limits.max_exec_ms.min(5000).to_string(),
            );
    }
    let child = command.spawn();
    let result = (|| -> Result<i32, &'static str> {
        let mut child = child.map_err(|_| "owner.native_spawn")?;
        if child
            .stdin
            .take()
            .ok_or("owner.native_stdin")?
            .write_all(&prompt)
            .is_err()
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err("owner.native_input");
        }
        loop {
            if failed.load(Ordering::SeqCst) {
                let _ = child.kill();
            }
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status.code().unwrap_or(125)),
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("owner.native_wait");
                }
            }
        }
    })();
    stop.store(true, Ordering::SeqCst);
    if let Some(stream) = current.lock().map_err(|_| "owner.lock")?.as_ref() {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
    let mut observed = server.join().map_err(|_| "owner.server")?;
    observed.complete &=
        result.as_ref().is_ok_and(|code| *code == 0) && !failed.load(Ordering::SeqCst);
    let bytes = serde_json::to_vec(&observed).map_err(|_| "owner.terminal_encode")?;
    if bytes.len() > 16384 {
        return Err("owner.terminal_bound");
    }
    terminal.set_len(0).map_err(|_| "owner.terminal_write")?;
    terminal
        .write_all(&bytes)
        .and_then(|()| terminal.sync_all())
        .map_err(|_| "owner.terminal_write")?;
    if !observed.complete {
        return Err("owner.incomplete");
    }
    result
}
