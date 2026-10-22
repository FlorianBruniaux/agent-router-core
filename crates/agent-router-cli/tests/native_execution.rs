//! Native OS sandbox canaries with a synthetic Claude protocol and v3 assets.
//! No live provider authentication, model or external service is claimed.
#![cfg(all(feature = "claude", any(target_os = "macos", target_os = "linux")))]

#[path = "support/native_fixture.rs"]
mod native_fixture;
use native_fixture::*;
use router_adapter_api::content_digest;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Stdio,
    thread,
    time::{Duration, Instant},
};

#[test]
#[ignore = "requires native OS sandbox, a built helper and local CLI; no live model"]
fn native_cli_review_run_feedback_verify_and_private_outputs() {
    let body = format!(
        "printf isolated > src/result.txt\nprintf '%s' {}\nprintf 'synthetic-private-stderr\\n' >&2",
        shell_quote(STREAM)
    );
    let fixture = Fixture::new(&body, 3_000);
    let digest = fixture.review();
    let output = checked(fixture.run().args(["--approve", &digest]), 0);
    let completion = &output["completion"];
    assert_eq!(completion["run"]["state"], "verifying");
    assert_eq!(completion["transport"]["termination"], "exited");
    assert_eq!(completion["transport"]["exit_code"], 0);
    assert_eq!(completion["validation"], "unknown");
    assert_eq!(completion["objective"], "unknown");
    assert_eq!(
        completion["memory_enforcement"],
        if cfg!(target_os = "linux") {
            "enforced"
        } else {
            "not_requested"
        }
    );
    assert_eq!(completion["runtime_evidence"]["transport_success"], true);
    assert_eq!(completion["runtime_evidence"]["executed_models"], json!([]));
    assert!(
        completion["runtime_evidence"]["missing_evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "model.runtime_unknown")
    );
    assert_eq!(output["feedback"]["recorded"], true);
    assert_eq!(fixture.status()["run"]["state"], "verifying");
    assert!(!fixture.repo.join("src/result.txt").exists());
    assert!(!fixture.repo.join("outside.txt").exists());
    let worktree = Path::new(completion["run"]["worktree"].as_str().unwrap());
    assert_eq!(
        fs::read(worktree.join("src/result.txt")).unwrap(),
        b"isolated"
    );
    assert!(!worktree.join("outside.txt").exists());
    let artifacts = checked(&mut fixture.artifacts("outputs"), 0);
    let record = &artifacts["outputs"][0];
    assert_eq!(record["state"], "retained");
    assert_eq!(record["truncated"], false);
    for (stream, expected) in [
        ("stdout", STREAM.as_bytes()),
        ("stderr", b"synthetic-private-stderr\n".as_slice()),
    ] {
        let path = Path::new(record[stream]["path"].as_str().unwrap());
        assert_eq!(fs::read(path).unwrap(), expected);
        assert_eq!(record[stream]["sha256"], content_digest(expected));
        assert_eq!(record[stream]["bytes"], expected.len());
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    let feedback = fixture.exported_feedback();
    assert_eq!(feedback["events"].as_array().unwrap().len(), 1);
    let event = &feedback["events"][0]["input"];
    assert_eq!(event["origin"], "automated");
    assert_eq!(event["transport"], "passed");
    assert_eq!(event["validation"], "unknown");
    assert_eq!(event["objective"], "unknown");
    assert_eq!(event["context"]["harness"], "claude-code");
    let events = checked(
        command()
            .args(["events", "--store"])
            .arg(&fixture.store)
            .args(["--run-id", RUN_ID, "--json"]),
        0,
    );
    for preview in [&output, &feedback, &events, &artifacts] {
        let text = preview.to_string();
        for secret in [
            PROMPT,
            "synthetic-private-output",
            "synthetic-private-result",
            "synthetic-private-stderr",
        ] {
            assert!(!text.contains(secret));
        }
    }
    // Independent test assertions above, not the fake host's verified=true,
    // supply this explicit verification evidence.
    let evidence = fixture.root.join("verification.json");
    write(
        &evidence,
        &json!({"verifier":"native-cli-test","evidence_sha256":content_digest(b"isolated path, exact stream bytes and private mode assertions passed"),"artifact_sha256":completion["run"]["artifact_sha256"],"validation":"passed","objective":"passed"}),
    );
    let verified = checked(
        command()
            .args(["verify", "--definition"])
            .arg(fixture.root.join("definition.json"))
            .arg("--store")
            .arg(&fixture.store)
            .arg("--evidence")
            .arg(evidence)
            .arg("--json"),
        0,
    );
    assert_eq!(verified["run"]["state"], "verified");
    assert_eq!(
        fixture.exported_feedback()["events"][0]["input"]["objective"],
        "unknown"
    );
    let purged = checked(
        fixture.artifacts("purge-outputs").args(["--attempt", "1"]),
        0,
    );
    assert_eq!(purged["purged"]["state"], "purged");
    for stream in ["stdout", "stderr"] {
        assert!(!Path::new(record[stream]["path"].as_str().unwrap()).exists());
    }
    assert_eq!(
        checked(&mut fixture.artifacts("outputs"), 0)["outputs"][0]["state"],
        "purged"
    );
}

// Shell builtins keep the signal handler runnable immediately. Waiting on a
// separate sleep process can defer the handler past the runtime's grace period.
const TERM_ZERO: &str =
    "trap 'printf term-handled; exit 0' TERM\nprintf ready > src/ready\nwhile :; do :; done";
fn assert_interrupted(output: &Value, state: &str, termination: &str) {
    let completion = &output["completion"];
    assert_eq!(completion["run"]["state"], state);
    assert_eq!(completion["transport"]["termination"], termination);
    assert_eq!(completion["validation"], "unknown");
    assert_eq!(completion["objective"], "unknown");
    // The worker's TERM handler exits zero, proven by its exact output below.
    // Closing the runtime lifetime pipe also stops the watchdog, whose native
    // exit is 125. The runtime's interruption cause remains authoritative.
    #[cfg(target_os = "macos")]
    {
        assert_eq!(
            completion["transport"]["exit_code"],
            125,
            "transport {:?}; stdout {:?}; stderr {:?}; ready {:?}",
            completion["transport"],
            fs::read_to_string(
                completion["output_artifacts"]["stdout"]["path"]
                    .as_str()
                    .unwrap()
            ),
            fs::read_to_string(
                completion["output_artifacts"]["stderr"]["path"]
                    .as_str()
                    .unwrap()
            ),
            fs::read_to_string(
                Path::new(completion["run"]["worktree"].as_str().unwrap()).join("src/ready")
            )
        );
        assert_eq!(
            fs::read(
                completion["output_artifacts"]["stdout"]["path"]
                    .as_str()
                    .unwrap()
            )
            .unwrap(),
            b"term-handled"
        );
    }
}

#[test]
#[ignore = "requires native OS sandbox and built helper; zero-exit TERM handler regression"]
fn native_cli_timeout_with_zero_exit_handler_is_failure() {
    let fixture = Fixture::new(TERM_ZERO, 1_500);
    let digest = fixture.review();
    let output = checked(fixture.run().args(["--approve", &digest]), 3);
    assert_interrupted(&output, "timed_out", "timed_out");
    let feedback = fixture.exported_feedback();
    assert_eq!(feedback["events"][0]["input"]["transport"], "failed");
    assert_eq!(feedback["events"][0]["input"]["failure"], "timeout");
}

#[test]
#[ignore = "requires native OS sandbox and built helper; second-process cancellation regression"]
fn native_cli_cancel_with_zero_exit_handler_is_failure() {
    let fixture = Fixture::new(TERM_ZERO, 5_000);
    let digest = fixture.review();
    let mut child = fixture
        .run()
        .args(["--approve", &digest])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("worker finished before cancellation: {status}");
        }
        let status = fixture.status();
        if status["run"]["state"] == "running"
            && status["run"]["worktree"]
                .as_str()
                .is_some_and(|path| Path::new(path).join("src/ready").is_file())
        {
            break;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("native fake worker never reached readiness");
        }
        thread::sleep(Duration::from_millis(10));
    }
    checked(
        command()
            .args(["cancel", "--store"])
            .arg(&fixture.store)
            .args(["--run-id", RUN_ID, "--json"]),
        0,
    );
    let output = parsed(child.wait_with_output().unwrap(), 3);
    assert_interrupted(&output, "cancelled", "cancelled");
    assert_eq!(fixture.status()["run"]["state"], "cancelled");
    let feedback = fixture.exported_feedback();
    assert_eq!(feedback["events"][0]["input"]["transport"], "failed");
    assert_eq!(feedback["events"][0]["input"]["failure"], "cancelled");
}

#[test]
#[ignore = "requires native OS sandbox and built helper; no live model"]
fn native_host_state_is_private_writable_and_removed_after_completion() {
    let body = format!(
        r#"[ -d "$CLAUDE_CONFIG_DIR" ] || exit 61
printf state > "$CLAUDE_CONFIG_DIR/probe"
[ "$(cat "$CLAUDE_CONFIG_DIR/probe")" = state ] || exit 62
if cat "$CLAUDE_CONFIG_DIR/../approval.key" >/dev/null 2>&1; then exit 63; fi
if cat "$CLAUDE_CONFIG_DIR/../runtime.sqlite3" >/dev/null 2>&1; then exit 64; fi
printf '%s' "$CLAUDE_CONFIG_DIR" > src/host-state-path
printf '%s' {}
"#,
        shell_quote(STREAM)
    );
    let fixture = Fixture::new(&body, 3_000);
    let digest = fixture.review();
    let output = checked(fixture.run().args(["--approve", &digest]), 0);
    assert_eq!(output["completion"]["transport"]["exit_code"], 0);
    let worktree = Path::new(output["completion"]["run"]["worktree"].as_str().unwrap());
    let state = fs::read_to_string(worktree.join("src/host-state-path")).unwrap();
    assert!(Path::new(&state).starts_with(&fixture.store));
    assert!(!Path::new(&state).exists());
}

#[test]
#[ignore = "requires native OS sandbox and built helper; no live model"]
fn native_host_state_cleanup_failure_is_terminal_and_reported() {
    let body = format!(
        "mkdir \"$CLAUDE_CONFIG_DIR/locked\"\nprintf private > \"$CLAUDE_CONFIG_DIR/locked/data\"\nchmod 000 \"$CLAUDE_CONFIG_DIR/locked\"\nprintf '%s' {}",
        shell_quote(STREAM)
    );
    let fixture = Fixture::new(&body, 3_000);
    let digest = fixture.review();
    let output = fixture.run().args(["--approve", &digest]).output().unwrap();
    let status = fixture.status();
    let states: Vec<_> = fs::read_dir(&fixture.store)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .as_encoded_bytes()
                .starts_with(b"host-state-")
        })
        .collect();
    // Restore synthetic fixture permissions so even a RED test leaves no orphan.
    for state in &states {
        fs::set_permissions(state.join("locked"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(state).unwrap();
    }
    assert_eq!(states.len(), 1);
    assert_eq!(output.status.code(), Some(6));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"],
        "runtime.cleanup.unknown"
    );
    assert_eq!(status["run"]["state"], "failed");
}
