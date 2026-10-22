//! Parent death is observed through stdin EOF, never through a reusable PID.
//! The worker receives a different stdin pipe and cannot inherit the life pipe.
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{FlockOperation, flock},
    process::{
        Pid, Signal, WaitId, WaitIdOptions, kill_process_group, test_kill_process_group, waitid,
    },
};
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        process::{CommandExt, ExitStatusExt},
    },
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const PENDING: &[u8] = b"router-runtime-lease-v1:pending\n";
const ACTIVE: &[u8] = b"router-runtime-lease-v1:active\n";
const MAX_INPUT: u64 = 16 * 1024 * 1024;

pub(crate) fn supervise(
    limits: Vec<OsString>,
    arguments: Vec<OsString>,
) -> Result<i32, &'static str> {
    if arguments.is_empty() || arguments.len() > 257 || !Path::new(&arguments[0]).is_absolute() {
        return Err("arguments");
    }
    if std::env::var_os("ROUTER_RUNTIME_SUPERVISION").as_deref() != Some("framed-v1".as_ref()) {
        return Err("supervision_protocol");
    }
    let namespace = cfg!(target_os = "linux")
        && std::env::var_os("ROUTER_RUNTIME_CONTAINMENT").as_deref()
            == Some("pid-namespace-v1".as_ref());
    let mut lease = open_lease()?;
    // Acquiring the lease precedes both the liveness check and worker creation.
    // Recovery invalidates pending while holding this same exclusive lock.
    let input = std::io::stdin();
    let mut reader = input.lock();
    let mut header = [0_u8; 32];
    reader
        .read_exact(&mut header)
        .map_err(|_| "supervision_frame")?;
    if &header[..8] != b"ARLIFE01" {
        return Err("supervision_frame");
    }
    let length = u64::from_be_bytes(header[8..16].try_into().map_err(|_| "supervision_frame")?);
    let timeout = u64::from_be_bytes(header[16..24].try_into().map_err(|_| "supervision_frame")?);
    let grace = u64::from_be_bytes(header[24..32].try_into().map_err(|_| "supervision_frame")?);
    if length > MAX_INPUT || !(1..=86_400_000).contains(&timeout) || grace > 5_000 {
        return Err("supervision_bounds");
    }
    let mut payload = vec![0; length as usize];
    reader
        .read_exact(&mut payload)
        .map_err(|_| "supervision_frame")?;
    // Drop StdinLock before poll: the input is unbuffered Read through StdinLock;
    // no extra application bytes are accepted after the exact framed payload.
    drop(reader);
    if parent_lost(&input, 0)? {
        return Err("parent_lost_before_spawn");
    }
    lease.seek(SeekFrom::Start(0)).map_err(|_| "lease_write")?;
    lease.set_len(0).map_err(|_| "lease_write")?;
    lease.write_all(ACTIVE).map_err(|_| "lease_write")?;
    lease.sync_all().map_err(|_| "lease_write")?;
    let mut command = Command::new(std::env::current_exe().map_err(|_| "helper_path")?);
    command
        .args(limits)
        .arg("--")
        .args(&arguments)
        .stdin(Stdio::piped())
        .process_group(0)
        .env_remove("ROUTER_RUNTIME_SUPERVISION")
        .env_remove("ROUTER_RUNTIME_LEASE")
        .env_remove("ROUTER_RUNTIME_CONTAINMENT");
    let mut child = command.spawn().map_err(|_| "worker_spawn")?;
    let pid =
        Pid::from_raw(i32::try_from(child.id()).map_err(|_| "worker_pid")?).ok_or("worker_pid")?;
    let mut worker_input = child.stdin.take().ok_or("worker_stdin")?;
    let writer = std::thread::Builder::new()
        .name("worker-stdin".into())
        .spawn(move || {
            let _ = worker_input.write_all(&payload);
        });
    let start = Instant::now();
    let result = if writer.is_err() {
        Err("worker_stdin")
    } else {
        loop {
            // NOWAIT keeps the child identity reserved until after our final signal;
            // no signal is sent after wait()/reaping, including on the normal path.
            match waitid(
                WaitId::Pid(pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            ) {
                Ok(Some(_)) => break Ok(()),
                Ok(None) => {}
                Err(_) => break Err("worker_wait"),
            }
            if start.elapsed() >= Duration::from_millis(timeout) {
                break Err("worker_timeout");
            }
            match parent_lost(&input, 10) {
                Ok(true) => break Err("parent_lost"),
                Ok(false) => {}
                Err(code) => break Err(code),
            }
        }
    };
    let _ = kill_process_group(pid, Signal::TERM);
    if grace > 0 {
        std::thread::sleep(Duration::from_millis(grace));
    }
    let _ = kill_process_group(pid, Signal::KILL);
    // Reap only after the last group signal. A reused group ID is never signalled.
    // Observing ESRCH below establishes group termination, not absence of detached
    // descendants. The native sandbox capability distinguishes a PID namespace.
    let cleanup_start = Instant::now();
    loop {
        if waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        )
        .map_err(|_| "worker_wait")?
        .is_some()
        {
            break;
        }
        if cleanup_start.elapsed() >= Duration::from_secs(2) {
            return Err("cleanup_unconfirmed");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let status = child.wait().map_err(|_| "worker_wait")?;
    if let Ok(writer) = writer {
        if writer.is_finished() {
            let _ = writer.join();
        }
    }
    loop {
        match test_kill_process_group(pid) {
            Err(rustix::io::Errno::SRCH) => break,
            Ok(()) | Err(rustix::io::Errno::PERM) => {}
            Err(_) => return Err("cleanup_unconfirmed"),
        }
        if cleanup_start.elapsed() >= Duration::from_secs(2) {
            return Err("cleanup_unconfirmed");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    lease.seek(SeekFrom::Start(0)).map_err(|_| "lease_write")?;
    lease.set_len(0).map_err(|_| "lease_write")?;
    lease
        .write_all(if namespace {
            b"router-runtime-lease-v1:namespace-clean\n"
        } else {
            b"router-runtime-lease-v1:group-clean\n"
        })
        .map_err(|_| "lease_write")?;
    lease.sync_all().map_err(|_| "lease_write")?;
    drop(lease);
    match result {
        Ok(()) => Ok(status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))),
        Err("worker_timeout") => Ok(124),
        Err("parent_lost") => Ok(125),
        Err(code) => Err(code),
    }
}

fn open_lease() -> Result<File, &'static str> {
    let path = std::env::var_os("ROUTER_RUNTIME_LEASE").ok_or("lease_required")?;
    let path = Path::new(&path);
    if !path.is_absolute() || std::fs::canonicalize(path).map_err(|_| "lease_path")? != path {
        return Err("lease_path");
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(
            i32::try_from(
                rustix::fs::OFlags::NOFOLLOW.bits() | rustix::fs::OFlags::NONBLOCK.bits(),
            )
            .map_err(|_| "lease_flags")?,
        )
        .open(path)
        .map_err(|_| "lease_open")?;
    let metadata = file.metadata().map_err(|_| "lease_metadata")?;
    if !metadata.is_file()
        || metadata.len() != PENDING.len() as u64
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err("lease_metadata");
    }
    flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|_| "lease_busy")?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(128)
        .read_to_end(&mut bytes)
        .map_err(|_| "lease_read")?;
    if bytes != PENDING {
        return Err("lease_state");
    }
    Ok(file)
}

fn parent_lost(input: &std::io::Stdin, timeout_ms: i64) -> Result<bool, &'static str> {
    let mut descriptors = [PollFd::new(
        input,
        PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
    )];
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: timeout_ms * 1_000_000,
    };
    match poll(&mut descriptors, Some(&timeout)) {
        Ok(0) => Ok(false),
        // EOF or unexpected extra protocol bytes both terminate the worker.
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::INTR) => Ok(false),
        Err(_) => Err("parent_poll"),
    }
}
