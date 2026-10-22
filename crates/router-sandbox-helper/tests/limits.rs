use std::{process::Command, time::Instant};
fn helper() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_router-sandbox-helper"));
    c.args([
        "--cpu-seconds",
        "1",
        "--address-space-bytes",
        if cfg!(target_os = "macos") {
            "none"
        } else {
            "1073741824"
        },
        "--max-open-files",
        "32",
        "--max-processes",
        "256",
        "--max-file-bytes",
        "1024",
    ]);
    c
}
#[test]
fn probe_and_invalid_arguments_fail_closed() {
    // Capture stdout like the runtime does: an inherited file stdout past the
    // 1024-byte file-size limit would kill the probe with SIGXFSZ.
    let probe = helper().arg("--probe").output().unwrap();
    assert!(probe.status.success());
    assert!(
        probe
            .stdout
            .starts_with(b"router-sandbox-helper-v1:limits-applied:")
    );
    let invalid = Command::new(env!("CARGO_BIN_EXE_router-sandbox-helper"))
        .arg("--probe")
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert_eq!(invalid.stderr, b"sandbox-helper.arguments\n");
}

#[test]
fn requested_memory_is_enforced_or_rejected_without_a_silent_downgrade() {
    let output = Command::new(env!("CARGO_BIN_EXE_router-sandbox-helper"))
        .args([
            "--cpu-seconds",
            "1",
            "--address-space-bytes",
            "1073741824",
            "--max-open-files",
            "32",
            "--max-processes",
            "256",
            "--max-file-bytes",
            "1024",
            "--probe",
        ])
        .output()
        .unwrap();
    if cfg!(target_os = "linux") || output.status.success() {
        assert!(output.status.success());
        assert_eq!(
            output.stdout,
            b"router-sandbox-helper-v1:limits-applied:address-space=enforced\n"
        );
    } else {
        assert_eq!(output.stderr, b"sandbox-helper.setrlimit.address_space\n");
    }
}
#[cfg(target_os = "linux")]
#[test]
fn allocation_worker() {
    if std::env::var_os("ROUTER_ALLOCATION_FIXTURE").is_none() {
        return;
    }
    let mut bytes = Vec::<u8>::new();
    if bytes.try_reserve_exact(256 * 1024 * 1024).is_err() {
        std::process::exit(42);
    }
    bytes.resize(256 * 1024 * 1024, 1);
    std::hint::black_box(bytes);
}
#[cfg(target_os = "linux")]
#[test]
fn address_space_limit_rejects_a_real_allocation() {
    let exe = std::env::current_exe().unwrap();
    let control = Command::new(&exe)
        .args(["--exact", "allocation_worker"])
        .env("ROUTER_ALLOCATION_FIXTURE", "1")
        .output()
        .unwrap();
    assert!(control.status.success());
    let output = Command::new(env!("CARGO_BIN_EXE_router-sandbox-helper"))
        .args([
            "--cpu-seconds",
            "10",
            "--address-space-bytes",
            "67108864",
            "--max-open-files",
            "64",
            "--max-processes",
            "4096",
            "--max-file-bytes",
            "1024",
            "--",
        ])
        .arg(exe)
        .args(["--exact", "allocation_worker"])
        .env("ROUTER_ALLOCATION_FIXTURE", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(42));
}
#[test]
fn descriptor_limit_is_applied_in_child_not_parent() {
    let before = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    let output = helper()
        .args(["--", "/bin/sh", "-c", "ulimit -n"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "32");
    assert_eq!(
        before,
        rustix::process::getrlimit(rustix::process::Resource::Nofile)
    );
}
#[test]
fn cpu_bound_process_is_terminated() {
    let start = Instant::now();
    let output = helper()
        .args(["--", "/bin/sh", "-c", "while :; do :; done"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(start.elapsed().as_secs() < 10);
}
#[test]
fn file_size_bound_stops_real_write() {
    let temp = tempfile::tempdir().unwrap();
    let output = helper()
        .args([
            "--",
            "/bin/sh",
            "-c",
            "exec /bin/dd if=/dev/zero of=large.bin bs=2048 count=2",
        ])
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        std::fs::metadata(temp.path().join("large.bin"))
            .unwrap()
            .len()
            <= 1024
    );
}
#[test]
fn address_space_and_process_limits_are_observed_not_claimed_as_rss_or_job_limits() {
    let output = helper()
        .args(["--", "/bin/bash", "-c", "ulimit -v; ulimit -u"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<_> = text.lines().collect();
    if cfg!(target_os = "linux") {
        assert_eq!(lines[0], "1048576");
    }
    assert_eq!(lines[1], "256");
}
