//! Fixed public fixture evaluator; never a generic verifier command or receipt importer.
use super::{Result, mkdir, save};
use router_adapter_api::content_digest;
use router_runtime::FiniteClientVerifier;
use router_types::{VerificationOutcome, VerificationRecord};
use serde_json::Value;
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const VERIFIER: &[u8] =
    include_bytes!("../../../../docs/bench/native-useful-score-2026-10-21/verify.py");
const CASES: &[u8] =
    include_bytes!("../../../../docs/bench/native-useful-score-2026-10-21/required-cases.rs");
const BASELINE: &[u8] =
    include_bytes!("../../../../docs/bench/native-useful-score-2026-10-21/acceptance.json");
const SOLUTION: &[u8] = include_bytes!(
    "../../../../docs/bench/linux-finite-dispatch-2026-10-16/inputs/t02/controller/control-output.json"
);

pub(super) fn check_scope(assignment: &str) -> Result<()> {
    if assignment != "t02-Lm-r1-H1" {
        return Err("public score assignment only".into());
    }
    Ok(())
}

// This parser is private to the fixed child invocation below. There is no
// user-supplied receipt entrance and no objective/acceptance inference.
fn validate_receipt(
    raw: &[u8],
    report: &[u8],
    candidate: &[u8],
    patch: &[u8],
) -> Result<VerificationRecord> {
    let receipt = router_adapter_api::strict_json_limited(raw, 32768)?;
    let mut expected: Value = serde_json::from_slice(BASELINE)?;
    expected["runtime_report_sha256"] = content_digest(report).into();
    for label in ["source", "candidate"] {
        let hash = receipt["outcomes"][label]["stdout_sha256"]
            .as_str()
            .ok_or("case output digest")?;
        if !router_adapter_api::is_digest(hash) {
            return Err("case output digest".into());
        }
        expected["outcomes"][label]["stdout_sha256"] = hash.into();
    }
    if receipt != expected
        || receipt["candidate_sha256"] != content_digest(candidate)
        || receipt["artifact_sha256"] != content_digest(patch)
        || receipt["verifier_sha256"] != content_digest(VERIFIER)
        || receipt["required_cases_sha256"] != content_digest(CASES)
    {
        return Err("public score receipt binding".into());
    }
    Ok(VerificationRecord {
        verifier: "fixed-public-score-v1".into(),
        evidence_sha256: content_digest(raw),
        artifact_sha256: Some(content_digest(patch)),
        validation: VerificationOutcome::Passed,
        objective: VerificationOutcome::Unknown,
    })
}
pub(super) fn read_private(path: &Path, bound: u64) -> Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o077 != 0
        || m.len() > bound
    {
        return Err("private evaluation file".into());
    }
    let mut bytes = Vec::new();
    f.take(bound + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != m.len() {
        return Err("changed evaluation file".into());
    }
    Ok(bytes)
}
pub(super) fn run_bounded(mut command: Command, deadline: Duration) -> Result<()> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    // Only async-signal-safe libc calls before exec. All staged outputs are private.
    unsafe {
        command.pre_exec(|| {
            nix::libc::umask(0o077);
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let pid = rustix::process::Pid::from_child(&child);
    let group = nix::unistd::Pid::from_raw(pid.as_raw_pid());
    let until = Instant::now() + deadline;
    let status = loop {
        // Keep the parent waitable until its group has been killed. Reaping
        // first would allow its PID/group ID to be reused by another process.
        use rustix::process::{WaitId, WaitIdOptions as W, waitid};
        match waitid(WaitId::Pid(pid), W::EXITED | W::NOHANG | W::NOWAIT) {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(10)),
            _ => break Err("public score child deadline or wait failure"),
        }
    };
    let cleanup = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
    let reaped = child.wait()?;
    if !matches!(cleanup, Ok(()) | Err(nix::errno::Errno::ESRCH)) {
        return Err("public score group cleanup".into());
    }
    if status?.exit_status() != Some(0) || !reaped.success() {
        return Err("public score child failed".into());
    }
    Ok(())
}

pub(super) fn evaluate(
    root: &Path,
    report: &[u8],
    verifier: &FiniteClientVerifier<'_>,
) -> Result<Value> {
    let patch = verifier.artifact()?;
    let candidate = read_private(&root.join("submission/lib.rs"), 32768)?;
    let packet = super::recipe::packets()?
        .assignments
        .into_iter()
        .find(|p| p.assignment_id == "t02-Lm-r1-H1")
        .ok_or("public score packet")?;
    let capsule = tempfile::Builder::new()
        .prefix("public-score-")
        .tempdir_in(root)?;
    let base = capsule.path();
    for directory in [
        "docs",
        "docs/bench",
        "docs/bench/native-useful-score-2026-10-21",
        "docs/bench/linux-finite-dispatch-2026-10-16",
        "docs/bench/linux-finite-dispatch-2026-10-16/inputs",
        "docs/bench/linux-finite-dispatch-2026-10-16/inputs/t02",
        "docs/bench/linux-finite-dispatch-2026-10-16/inputs/t02/controller",
        "crates",
        "crates/router-runtime",
        "crates/router-runtime/examples",
        "crates/router-runtime/examples/campaign",
        "input",
    ] {
        mkdir(&base.join(directory))?;
    }
    let script = base.join("docs/bench/native-useful-score-2026-10-21/verify.py");
    save(&script, VERIFIER)?;
    save(
        &base.join("docs/bench/native-useful-score-2026-10-21/required-cases.rs"),
        CASES,
    )?;
    save(
        &base.join(
            "docs/bench/linux-finite-dispatch-2026-10-16/inputs/t02/controller/control-output.json",
        ),
        SOLUTION,
    )?;
    save(
        &base.join("crates/router-runtime/examples/campaign/packets.json"),
        include_bytes!("packets.json"),
    )?;
    for (name, bytes) in [
        ("source-lib.rs", packet.files["lib.rs"].as_bytes()),
        ("lib.rs", &candidate),
        ("change.patch", &patch),
        ("runtime-result.json", report),
    ] {
        save(&base.join("input").join(name), bytes)?;
    }
    let receipt_path = base.join("receipt.json");
    let mut command = Command::new("/usr/bin/python3");
    command
        .args(["-I", "-B"])
        .arg(script)
        .arg("--input")
        .arg(base.join("input"))
        .arg("--output")
        .arg(&receipt_path)
        .env_clear()
        .env("PATH", "/usr/local/cargo/bin:/usr/bin:/bin")
        .env("HOME", base)
        .env("TMPDIR", base)
        .current_dir(base);
    run_bounded(command, Duration::from_secs(120))?;
    let raw = read_private(&receipt_path, 32768)?;
    let record = validate_receipt(&raw, report, &candidate, &patch)?;
    // Retain the exact evidence before the atomic attestation. A failed write
    // cannot leave an attestation whose evidence was never preserved.
    save(&root.join("public-score-receipt.json"), &raw)?;
    let summary = verifier.record(record.clone())?;
    Ok(
        serde_json::json!({"schema_version":1,"scope":"fixed-public-score-v1","verification":record,"summary":summary,"human_acceptance":null,"source_publication":false,"model_calls_started":0}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_adapter_api::content_digest;
    use router_types::VerificationOutcome;
    #[test]
    fn public_score_scope_refuses_other_assignments_before_launch() {
        assert!(check_scope("t02-Lm-r1-H1").is_ok());
        for id in ["t02-Lx-r1-H0", "t05-Lm-r1-H0", "", "../t02-Lm-r1-H1"] {
            assert!(check_scope(id).is_err());
        }
    }
    #[test]
    fn public_score_attestation_binds_actual_report_patch_and_all_required_cases() {
        let mut receipt: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../docs/bench/native-useful-score-2026-10-21/acceptance.json"
        ))
        .unwrap();
        let patch =
            include_bytes!("../../../../docs/bench/native-useful-score-2026-10-21/change.patch");
        let candidate = include_bytes!(
            "../../../../docs/bench/native-useful-score-2026-10-21/submission/lib.rs"
        );
        let report = b"current private report";
        receipt["runtime_report_sha256"] = content_digest(report).into();
        let raw = serde_json::to_vec(&receipt).unwrap();
        let record = validate_receipt(&raw, report, candidate, patch).unwrap();
        assert_eq!(record.validation, VerificationOutcome::Passed);
        assert_eq!(record.objective, VerificationOutcome::Unknown);
        assert_eq!(record.evidence_sha256, content_digest(&raw));
        assert_eq!(record.artifact_sha256, Some(content_digest(patch)));
        assert!(validate_receipt(&raw, b"stale report", candidate, patch).is_err());
        assert!(validate_receipt(&raw, report, b"changed candidate", patch).is_err());
        assert!(validate_receipt(&raw, report, candidate, b"changed patch").is_err());
        for pointer in [
            "/packet_sha256",
            "/frozen_campaign_acceptance_sha256",
            "/source_sha256",
            "/verifier_sha256",
            "/required_cases_sha256",
            "/outcomes/candidate/cases/empty",
            "/outcomes/source/exit_code",
            "/human_acceptance",
            "/source_publication",
            "/model_calls_started",
            "/memory_bytes",
            "/swap_bytes",
            "/git_mode",
            "/result_tree",
        ] {
            let mut bad = receipt.clone();
            *bad.pointer_mut(pointer).unwrap() = serde_json::json!("invalid");
            assert!(
                validate_receipt(&serde_json::to_vec(&bad).unwrap(), report, candidate, patch)
                    .is_err(),
                "{pointer}"
            );
        }
        receipt["outcomes"]["candidate"]["cases"]
            .as_object_mut()
            .unwrap()
            .remove("wide_sums");
        assert!(
            validate_receipt(
                &serde_json::to_vec(&receipt).unwrap(),
                report,
                candidate,
                patch
            )
            .is_err()
        );
    }
    #[test]
    fn public_score_reaps_group_before_returning_a_successful_parent() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("late-write");
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args([
                "-c",
                "(sleep 0.2; printf escaped > \"$1\") & exit 0",
                "fixture",
            ])
            .arg(&marker);
        run_bounded(command, std::time::Duration::from_secs(2)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(400));
        assert!(!marker.exists(), "child must not outlive evaluator return");
    }
    #[test]
    fn public_score_private_inputs_refuse_symlinks_links_and_oversize() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("input");
        super::save(&path, b"private bytes").unwrap();
        assert_eq!(read_private(&path, 32).unwrap(), b"private bytes");
        assert!(read_private(&path, 4).is_err());
        let link = temp.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_private(&link, 32).is_err());
        std::fs::hard_link(&path, temp.path().join("hard-link")).unwrap();
        assert!(read_private(&path, 32).is_err());
        std::fs::remove_file(temp.path().join("hard-link")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(&path, 32).is_err());
    }
    #[test]
    fn public_score_process_failure_and_timeout_do_not_return_evidence() {
        let mut fail = std::process::Command::new("/bin/sh");
        fail.args(["-c", "exit 7"]);
        assert!(run_bounded(fail, std::time::Duration::from_secs(2)).is_err());
        let mut hang = std::process::Command::new("/bin/sleep");
        hang.arg("5");
        let start = std::time::Instant::now();
        assert!(run_bounded(hang, std::time::Duration::from_millis(50)).is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }
}
