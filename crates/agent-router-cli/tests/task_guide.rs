//! Guided task input supplies explicit parent facts, never runtime permissions.
use assert_cmd::Command;
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Seek},
    path::{Path, PathBuf},
    process::{Command as StdCommand, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const OBJECTIVE: &str = "Inspect the Rust contract";
fn command() -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("agent-router"));
    command.timeout(Duration::from_secs(10));
    command
}
fn task() -> Value {
    let request: Value = serde_json::from_str(include_str!(
        "../../../fixtures/examples/phase-request.json"
    ))
    .unwrap();
    let mut task = request["task"].clone();
    task["allowed_mutations"] = json!([]);
    task
}
fn write(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn input_file(dir: &Path, input: &Value) -> PathBuf {
    let path = dir.join("source-task.json");
    write(&path, input);
    path
}
fn parsed(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "expected one JSON result: {error}; status={:?}; stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}
fn answers() -> &'static str {
    "explore\nlow\npublic\n{\"max_cost_microusd\":10000,\"max_elapsed_ms\":1000,\"max_tokens\":1000}\n[]\n[\"cite an enforcing symbol\"]\n[\"src\"]\n"
}
fn has_question(report: &Value, code: &str) -> bool {
    report["questions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|question| question["code"] == code)
}
fn assert_incomplete(report: &Value, status: &str) {
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["status"], status);
    assert!(report["output_directory"].is_null());
    assert!(report["result"]["normalization"]["task"].is_null());
}

#[test]
fn text_alone_returns_only_kind_clarification_without_invented_input() {
    let output = command()
        .args(["task-guide", "--text", OBJECTIVE, "--json"])
        .assert()
        .code(3)
        .get_output()
        .clone();
    let report = parsed(&output);
    assert_incomplete(&report, "needs_clarification");
    assert_eq!(report["objective"], OBJECTIVE);
    assert!(report["input"].is_null());
    assert!(report["risk_context"].is_null());
    assert!(report["result"].is_null());
    let questions = report["questions"].as_array().unwrap();
    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0]["code"], "task.kind.unknown");
}

#[test]
fn complete_structured_task_reuses_the_normalizer_without_interaction() {
    let dir = tempfile::tempdir().unwrap();
    let input = task();
    let path = input_file(dir.path(), &input);
    let output = command()
        .args(["task-guide", "--task"])
        .arg(&path)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parsed(&output);
    assert_eq!(report["status"], "complete");
    assert_eq!(report["input"], input);
    assert!(report["questions"].as_array().unwrap().is_empty());
    assert!(report["output_directory"].is_null());
    let old = command()
        .args(["normalize", "--task"])
        .arg(path)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(report["result"], parsed(&old));
}

#[test]
fn explicit_interactive_answers_export_a_task_that_normalize_and_plan_accept() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("generated");
    let output = command()
        .args([
            "task-guide",
            "--text",
            OBJECTIVE,
            "--interactive",
            "--output-directory",
        ])
        .arg(&out)
        .arg("--json")
        .write_stdin(answers())
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parsed(&output);
    assert_eq!(report["status"], "complete");
    assert_eq!(report["input"]["kind"], "explore");
    assert_eq!(report["input"]["risk"], "low");
    assert_eq!(report["input"]["allowed_mutations"], json!([]));
    assert_eq!(report["input"]["scope"], json!(["src"]));
    assert_eq!(
        report["result"]["normalization"]["task"]["deliverables"],
        json!([OBJECTIVE])
    );
    assert!(
        !report["result"]["normalization"]["assumptions"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let saved: Value = serde_json::from_slice(&fs::read(out.join("input.json")).unwrap()).unwrap();
    assert_eq!(saved, report["input"]);
    let normalization: Value =
        serde_json::from_slice(&fs::read(out.join("normalization.json")).unwrap()).unwrap();
    assert_eq!(normalization, report["result"]);
    assert!(!out.join("risk-context.json").exists());
    let normalized = command()
        .args(["normalize", "--task"])
        .arg(out.join("input.json"))
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(parsed(&normalized), report["result"]);
    let planned = command()
        .args(["plan", "--task"])
        .arg(out.join("input.json"))
        .args(["--preset", "direct-safe", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(
        parsed(&planned)["plan"]["task"],
        report["result"]["normalization"]["task"]
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in ["input.json", "normalization.json"] {
            assert_eq!(
                fs::metadata(out.join(name)).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

#[test]
fn raw_text_file_and_inline_text_have_identical_structured_results() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("objective.txt");
    fs::write(&path, OBJECTIVE).unwrap();
    let inline = command()
        .args(["task-guide", "--text", OBJECTIVE, "--json"])
        .assert()
        .code(3)
        .get_output()
        .clone();
    let from_file = command()
        .args(["task-guide", "--text-file"])
        .arg(&path)
        .arg("--json")
        .assert()
        .code(3)
        .get_output()
        .clone();
    assert_eq!(parsed(&inline), parsed(&from_file));
    let human = command()
        .args(["task-guide", "--text-file"])
        .arg(path)
        .assert()
        .code(3)
        .get_output()
        .clone();
    assert!(!human.stdout.is_empty());
    assert!(serde_json::from_slice::<Value>(&human.stdout).is_err());
}

#[test]
fn explicit_risk_context_preserves_original_risk_but_exports_the_higher_floor() {
    let dir = tempfile::tempdir().unwrap();
    let mut input = task();
    input["objective"] = json!("Migrate the local database");
    input["kind"] = json!("migration");
    input["allowed_mutations"] = json!(["workspace_write"]);
    let path = input_file(dir.path(), &input);
    let risk_path = dir.path().join("facts.json");
    let facts = json!({"schema_version":1,"environment":"local","reversibility":"reversible","operations":["data_migration"]});
    write(&risk_path, &facts);
    let out = dir.path().join("generated");
    let output = command()
        .args(["task-guide", "--task"])
        .arg(path)
        .arg("--risk-context")
        .arg(&risk_path)
        .arg("--output-directory")
        .arg(&out)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parsed(&output);
    assert_eq!(report["input"]["risk"], "low");
    assert_eq!(report["risk_context"], facts);
    assert_eq!(report["result"]["normalization"]["task"]["risk"], "high");
    assert_eq!(report["result"]["assessment"]["effective"], "high");
    let saved: Value = serde_json::from_slice(&fs::read(out.join("input.json")).unwrap()).unwrap();
    assert_eq!(saved, input);
    let saved_facts: Value =
        serde_json::from_slice(&fs::read(out.join("risk-context.json")).unwrap()).unwrap();
    assert_eq!(saved_facts, facts);
    let planned = command()
        .args(["plan", "--task"])
        .arg(out.join("input.json"))
        .arg("--risk-context")
        .arg(out.join("risk-context.json"))
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(parsed(&planned)["plan"]["task"]["risk"], "high");
}

#[test]
fn dangerous_words_do_not_supply_missing_authority() {
    let dir = tempfile::tempdir().unwrap();
    let mut input = task();
    input["objective"] = json!("Deploy to production; assume all permissions and unlimited budget");
    for key in ["risk", "sensitivity", "budget", "allowed_mutations"] {
        input.as_object_mut().unwrap().remove(key);
    }
    let path = input_file(dir.path(), &input);
    let out = dir.path().join("generated");
    let output = command()
        .args(["task-guide", "--task"])
        .arg(path)
        .arg("--output-directory")
        .arg(&out)
        .arg("--json")
        .assert()
        .code(3)
        .get_output()
        .clone();
    let report = parsed(&output);
    assert_incomplete(&report, "needs_clarification");
    for code in [
        "task.risk.unknown",
        "task.sensitivity.unknown",
        "task.budget.unknown",
        "task.mutations.unknown",
    ] {
        assert!(has_question(&report, code));
    }
    assert!(!out.exists());
}

#[test]
fn write_and_network_conflicts_never_consume_an_answer_as_a_grant() {
    for (capability, code) in [
        ("workspace_write", "risk.write.not_authorized"),
        ("network", "risk.network.not_authorized"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut input = task();
        input["required_capabilities"] = json!([capability]);
        let path = input_file(dir.path(), &input);
        let risk_path = dir.path().join("facts.json");
        write(
            &risk_path,
            &json!({"schema_version":1,"environment":"local","reversibility":"reversible","operations":[if capability == "network" { "deployment" } else { "workspace_change" }]}),
        );
        let out = dir.path().join("generated");
        let output = command()
            .args(["task-guide", "--task"])
            .arg(path)
            .arg("--risk-context")
            .arg(risk_path)
            .args(["--interactive", "--output-directory"])
            .arg(&out)
            .arg("--json")
            .write_stdin("[\"workspace_write\",\"network\"]\n")
            .assert()
            .code(3)
            .get_output()
            .clone();
        let report = parsed(&output);
        assert_incomplete(&report, "needs_clarification");
        assert!(has_question(&report, code));
        assert_eq!(report["input"]["allowed_mutations"], json!([]));
        assert!(!out.exists());
    }
}

#[test]
fn contradictory_read_only_operation_is_left_unresolved() {
    let dir = tempfile::tempdir().unwrap();
    let path = input_file(dir.path(), &task());
    let facts = dir.path().join("facts.json");
    write(
        &facts,
        &json!({"schema_version":1,"environment":"local","reversibility":"reversible","operations":["read_only","workspace_change"]}),
    );
    let output = command()
        .args(["task-guide", "--task"])
        .arg(path)
        .arg("--risk-context")
        .arg(facts)
        .args(["--interactive", "--json"])
        .write_stdin("[\"workspace_write\"]\n")
        .assert()
        .code(3)
        .get_output()
        .clone();
    let report = parsed(&output);
    assert_incomplete(&report, "needs_clarification");
    assert!(has_question(&report, "risk.context.conflict"));
    assert_eq!(report["input"]["allowed_mutations"], json!([]));
}

#[test]
fn blank_unknown_eof_and_cancel_never_publish_a_task() {
    for (response, status) in [
        ("\n", "needs_clarification"),
        ("unknown\n", "needs_clarification"),
        ("", "needs_clarification"),
        ("cancel\n", "cancelled"),
        ("explore\nlow\n", "needs_clarification"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("generated");
        let output = command()
            .args([
                "task-guide",
                "--text",
                OBJECTIVE,
                "--interactive",
                "--output-directory",
            ])
            .arg(&out)
            .arg("--json")
            .write_stdin(response)
            .assert()
            .code(3)
            .get_output()
            .clone();
        assert_incomplete(&parsed(&output), status);
        assert!(!out.exists());
    }
}

#[test]
fn malformed_enum_list_duplicate_budget_or_budget_overflow_is_a_stable_error() {
    let responses = [
        "Explore\n",
        "invented_kind\n",
        "explore\nlow\npublic\nnot-json\n",
        "explore\nlow\npublic\n{\"max_cost_microusd\":1,\"max_elapsed_ms\":1,\"max_tokens\":1,\"max_tokens\":2}\n",
        "explore\nlow\npublic\n{\"max_cost_microusd\":18446744073709551616,\"max_elapsed_ms\":1,\"max_tokens\":1}\n",
        "explore\nlow\npublic\n{\"max_cost_microusd\":1,\"max_elapsed_ms\":1,\"max_tokens\":1}\nworkspace_write\n",
    ];
    for response in responses {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("generated");
        let output = command()
            .args([
                "task-guide",
                "--text",
                OBJECTIVE,
                "--interactive",
                "--output-directory",
            ])
            .arg(&out)
            .arg("--json")
            .write_stdin(response)
            .assert()
            .code(2)
            .get_output()
            .clone();
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("task_guide.answer.invalid"));
        assert!(!out.exists());
    }
}

#[test]
fn zero_time_or_tokens_and_unsafe_scope_do_not_become_valid_tasks() {
    for (field, replacement) in [
        ("scope", json!(["../escape"])),
        ("scope", json!(["/absolute"])),
        ("scope", json!(["src/*"])),
        (
            "budget",
            json!({"max_cost_microusd":0,"max_elapsed_ms":0,"max_tokens":1}),
        ),
        (
            "budget",
            json!({"max_cost_microusd":0,"max_elapsed_ms":1,"max_tokens":0}),
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut input = task();
        input[field] = replacement;
        let path = input_file(dir.path(), &input);
        let out = dir.path().join("generated");
        let output = command()
            .args(["task-guide", "--task"])
            .arg(path)
            .arg("--output-directory")
            .arg(&out)
            .arg("--json")
            .assert()
            .code(2)
            .get_output()
            .clone();
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            "{\"schema_version\":1,\"error\":\"workflow.invalid\"}\n"
        );
        assert!(!out.exists());
    }
}

#[test]
fn strict_task_and_risk_context_json_reject_unknown_and_duplicate_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("task.json");
    let good = serde_json::to_string(&task()).unwrap();
    let bad = [
        good.replacen('{', "{\"extra\":true,", 1),
        good.replace("\"risk\":\"low\"", "\"risk\":\"low\",\"risk\":\"high\""),
    ];
    for bytes in bad {
        fs::write(&path, bytes).unwrap();
        let output = command()
            .args(["task-guide", "--task"])
            .arg(&path)
            .arg("--json")
            .assert()
            .code(2)
            .get_output()
            .clone();
        assert!(output.stdout.is_empty());
    }
    write(&path, &task());
    let context = dir.path().join("facts.json");
    for bytes in [
        r#"{"schema_version":1,"environment":"local","reversibility":"reversible","operations":["read_only"],"extra":true}"#,
        r#"{"schema_version":1,"environment":"local","environment":"production","reversibility":"reversible","operations":["read_only"]}"#,
    ] {
        fs::write(&context, bytes).unwrap();
        let output = command()
            .args(["task-guide", "--task"])
            .arg(&path)
            .arg("--risk-context")
            .arg(&context)
            .arg("--json")
            .assert()
            .code(2)
            .get_output()
            .clone();
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn input_choice_is_exclusive_and_required() {
    let dir = tempfile::tempdir().unwrap();
    let path = input_file(dir.path(), &task());
    command().args(["task-guide", "--json"]).assert().code(2);
    command()
        .args(["task-guide", "--text", OBJECTIVE, "--task"])
        .arg(&path)
        .assert()
        .code(2);
    command()
        .args(["task-guide", "--text", OBJECTIVE, "--text-file"])
        .arg(&path)
        .assert()
        .code(2);
    command()
        .args(["task-guide", "--task"])
        .arg(&path)
        .arg("--text-file")
        .arg(path)
        .assert()
        .code(2);
}

#[test]
fn oversized_inputs_and_non_utf8_text_refuse_without_output() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("text.txt");
    for bytes in [vec![b'x'; 16 * 1024 + 1], vec![0xff, 0xfe]] {
        fs::write(&path, bytes).unwrap();
        let output = command()
            .args(["task-guide", "--text-file"])
            .arg(&path)
            .arg("--json")
            .assert()
            .code(2)
            .get_output()
            .clone();
        assert!(output.stdout.is_empty());
    }
    fs::write(&path, vec![b' '; 1024 * 1024 + 1]).unwrap();
    command()
        .args(["task-guide", "--task"])
        .arg(&path)
        .arg("--json")
        .assert()
        .code(2);
    let out = dir.path().join("generated");
    let output = command()
        .args([
            "task-guide",
            "--text",
            OBJECTIVE,
            "--interactive",
            "--output-directory",
        ])
        .arg(&out)
        .arg("--json")
        .write_stdin(format!("{}\n", "x".repeat(64 * 1024 + 1)))
        .assert()
        .code(2)
        .get_output()
        .clone();
    assert!(output.stdout.is_empty());
    assert!(!out.exists());
}

#[test]
fn existing_output_directory_is_never_changed() {
    let dir = tempfile::tempdir().unwrap();
    let path = input_file(dir.path(), &task());
    let out = dir.path().join("existing");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("input.json"), b"sentinel").unwrap();
    let output = command()
        .args(["task-guide", "--task"])
        .arg(path)
        .arg("--output-directory")
        .arg(&out)
        .arg("--json")
        .assert()
        .code(2)
        .get_output()
        .clone();
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read(out.join("input.json")).unwrap(), b"sentinel");
    assert!(!out.join("normalization.json").exists());
    assert_eq!(fs::read_dir(&out).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn output_symlink_does_not_overwrite_its_target() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let path = input_file(dir.path(), &task());
    let target = dir.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("sentinel"), b"unchanged").unwrap();
    let link = dir.path().join("link");
    symlink(&target, &link).unwrap();
    let output = command()
        .args(["task-guide", "--task"])
        .arg(path)
        .arg("--output-directory")
        .arg(&link)
        .arg("--json")
        .assert()
        .code(2)
        .get_output()
        .clone();
    assert!(output.stdout.is_empty());
    assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
    assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"unchanged");
    assert_eq!(fs::read_dir(target).unwrap().count(), 1);
}

fn output_with_stdin_held_open(args: &[&str]) -> Output {
    // Waiting before draining pipes can block the child on stdout, even when
    // it never reads stdin. Private files keep output capture out of that path.
    let mut stdout = tempfile::tempfile().unwrap();
    let mut stderr = tempfile::tempfile().unwrap();
    let mut child = StdCommand::new(assert_cmd::cargo::cargo_bin!("agent-router"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(stdout.try_clone().unwrap())
        .stderr(stderr.try_clone().unwrap())
        .spawn()
        .unwrap();
    // Keep the sole stdin writer alive through child exit. Child::wait must
    // not close it and accidentally satisfy a regression that waits for EOF.
    let input = child.stdin.take().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let timed_out = loop {
        if child.try_wait().unwrap().is_some() {
            break false;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break true;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let status = child.wait().unwrap();
    let mut output = Output {
        status,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    stdout.rewind().unwrap();
    stderr.rewind().unwrap();
    stdout.read_to_end(&mut output.stdout).unwrap();
    stderr.read_to_end(&mut output.stderr).unwrap();
    drop(input);
    assert!(
        !timed_out,
        "CLI did not exit with stdin held open: status={:?}; stdout_bytes={}; stderr={}",
        output.status.code(),
        output.stdout.len(),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

#[test]
fn noninteractive_text_does_not_wait_for_or_consume_stdin() {
    let output = output_with_stdin_held_open(&["task-guide", "--text", OBJECTIVE, "--json"]);
    assert_eq!(output.status.code(), Some(3));
    assert_incomplete(&parsed(&output), "needs_clarification");
}

#[test]
fn already_complete_task_never_waits_for_stdin_even_with_interactive_flag() {
    let dir = tempfile::tempdir().unwrap();
    let path = input_file(dir.path(), &task());
    let output = output_with_stdin_held_open(&[
        "task-guide",
        "--task",
        path.to_str().unwrap(),
        "--interactive",
        "--json",
    ]);
    assert!(output.status.success());
    assert_eq!(parsed(&output)["status"], "complete");
}

#[test]
fn complete_interactive_task_emits_large_report_with_stdin_held_open() {
    let dir = tempfile::tempdir().unwrap();
    let mut input = task();
    input["acceptance"] = json!(vec!["x".repeat(8192); 16]);
    let path = input_file(dir.path(), &input);
    let output = output_with_stdin_held_open(&[
        "task-guide",
        "--task",
        path.to_str().unwrap(),
        "--interactive",
        "--json",
    ]);
    assert!(output.status.success());
    assert!(
        output.stderr.is_empty(),
        "complete task must not ask a question"
    );
    assert!(output.stdout.len() > 256 * 1024);
    let report = parsed(&output);
    assert_eq!(report["status"], "complete");
    assert_eq!(report["input"], input);
}

#[test]
fn dialogue_accepts_completion_on_turn_32_but_refuses_a_33rd_answer() {
    let dir = tempfile::tempdir().unwrap();
    let mut input = task();
    input["acceptance"] = json!([]);
    let path = input_file(dir.path(), &input);
    for (empty_answers, code) in [(31, 0), (32, 2)] {
        let out = dir.path().join(format!("turns-{empty_answers}"));
        let response = format!(
            "{}[\"An enforcing symbol is identified\"]\n",
            "[]\n".repeat(empty_answers)
        );
        let output = command()
            .args(["task-guide", "--task"])
            .arg(&path)
            .args(["--interactive", "--json", "--output-directory"])
            .arg(&out)
            .write_stdin(response)
            .assert()
            .code(code)
            .get_output()
            .clone();
        let prompts = String::from_utf8_lossy(&output.stderr)
            .matches("Enter unknown")
            .count();
        assert_eq!(prompts, 32);
        if code == 0 {
            let report = parsed(&output);
            assert_eq!(report["status"], "complete");
            assert_eq!(
                report["input"]["acceptance"],
                json!(["An enforcing symbol is identified"])
            );
            assert!(out.join("normalization.json").is_file());
        } else {
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("task_guide.dialogue.limit"));
            assert!(!out.exists());
        }
    }
}

#[test]
fn dialogue_counts_whitespace_and_line_endings_toward_the_exact_byte_budget() {
    let dir = tempfile::tempdir().unwrap();
    let mut input = task();
    input["acceptance"] = json!([]);
    let path = input_file(dir.path(), &input);
    let padded = format!("[]{}\n", " ".repeat(64 * 1024 - 3));
    assert_eq!(padded.len(), 64 * 1024);
    for (suffix, code) in [("", 3), ("\n", 2)] {
        let out = dir.path().join(format!("bytes-{code}"));
        let response = format!("{}{suffix}", padded.repeat(16));
        assert_eq!(response.len(), 1024 * 1024 + suffix.len());
        let output = command()
            .args(["task-guide", "--task"])
            .arg(&path)
            .args(["--interactive", "--json", "--output-directory"])
            .arg(&out)
            .write_stdin(response)
            .assert()
            .code(code)
            .get_output()
            .clone();
        if code == 3 {
            let report = parsed(&output);
            assert_incomplete(&report, "needs_clarification");
            assert!(has_question(&report, "task.acceptance.missing"));
        } else {
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("task_guide.dialogue.limit"));
        }
        assert!(!out.exists());
    }
}

#[test]
fn interactive_risk_facts_keep_the_declared_risk_and_raise_the_effective_floor() {
    let dir = tempfile::tempdir().unwrap();
    let mut input = task();
    input["kind"] = json!("migration");
    input["risk"] = json!("low");
    input["allowed_mutations"] = json!(["workspace_write"]);
    let path = input_file(dir.path(), &input);
    let out = dir.path().join("risk-export");
    let output = command()
        .args(["task-guide", "--task"])
        .arg(&path)
        .args(["--interactive", "--json", "--output-directory"])
        .arg(&out)
        .write_stdin("production\n[\"data_migration\"]\nirreversible\n")
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parsed(&output);
    assert_eq!(report["input"], input);
    assert_eq!(
        report["result"]["normalization"]["task"]["risk"],
        "critical"
    );
    assert_eq!(
        report["risk_context"],
        json!({"schema_version":1,"environment":"production","reversibility":"irreversible","operations":["data_migration"]})
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(out.join("risk-context.json")).unwrap()).unwrap(),
        report["risk_context"]
    );
    let normalized = command()
        .args(["normalize", "--task"])
        .arg(out.join("input.json"))
        .arg("--risk-context")
        .arg(out.join("risk-context.json"))
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(parsed(&normalized), report["result"]);
}

#[test]
fn unsafe_terminal_text_is_preserved_in_json_and_escaped_in_the_human_projection() {
    let objective = "Inspect \u{1b}]52;c;fixture\u{7}\n\u{202e}contract";
    let json = command()
        .args(["task-guide", "--text", objective, "--json"])
        .assert()
        .code(3)
        .get_output()
        .clone();
    assert_eq!(parsed(&json)["objective"], objective);
    let human = command()
        .args(["task-guide", "--text", objective])
        .assert()
        .code(3)
        .get_output()
        .clone();
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(!text.contains('\u{1b}'));
    assert!(!text.contains('\u{7}'));
    assert!(!text.contains('\u{202e}'));
    assert!(text.contains("\\u{1b}"));
    assert!(text.contains("\\n"));
    let interactive = command()
        .args(["task-guide", "--text", objective, "--interactive", "--json"])
        .write_stdin("cancel\n")
        .assert()
        .code(3)
        .get_output()
        .clone();
    assert!(!interactive.stderr.contains(&0x1b));
    assert!(!interactive.stderr.contains(&7));
    assert_eq!(parsed(&interactive)["status"], "cancelled");
}

#[test]
fn invalid_utf8_answer_is_rejected_without_echo_or_publication() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("invalid-answer");
    let output = command()
        .args([
            "task-guide",
            "--text",
            OBJECTIVE,
            "--interactive",
            "--json",
            "--output-directory",
        ])
        .arg(&out)
        .write_stdin(vec![0xff, 0x1b, b'\n'])
        .assert()
        .code(2)
        .get_output()
        .clone();
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.contains(&0xff));
    assert!(!output.stderr.contains(&0x1b));
    assert!(String::from_utf8_lossy(&output.stderr).contains("task_guide.answer.invalid"));
    assert!(!out.exists());
}

#[test]
fn concurrent_exports_never_mix_or_replace_documents() {
    use std::sync::{Arc, Barrier};
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("same-destination");
    let barrier = Arc::new(Barrier::new(3));
    let handles: Vec<_> = (0..2)
        .map(|number| {
            let mut input = task();
            input["objective"] = json!(format!("Inspect contract {number}"));
            let path = dir.path().join(format!("source-{number}.json"));
            write(&path, &input);
            let out = out.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let output = command()
                    .args(["task-guide", "--task"])
                    .arg(path)
                    .args(["--json", "--output-directory"])
                    .arg(out)
                    .output()
                    .unwrap();
                (input, output)
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    let successes: Vec<_> = results
        .iter()
        .filter(|(_, output)| output.status.success())
        .collect();
    assert_eq!(successes.len(), 1);
    let (winner, output) = successes[0];
    assert_eq!(parsed(output)["input"], *winner);
    let saved: Value = serde_json::from_slice(&fs::read(out.join("input.json")).unwrap()).unwrap();
    assert_eq!(&saved, winner);
    let normalization: Value =
        serde_json::from_slice(&fs::read(out.join("normalization.json")).unwrap()).unwrap();
    assert_eq!(normalization, parsed(output)["result"]);
    assert_eq!(fs::read_dir(&out).unwrap().count(), 2);
    let (_, loser) = results
        .iter()
        .find(|(_, output)| !output.status.success())
        .unwrap();
    assert_eq!(loser.status.code(), Some(2));
    assert!(loser.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn interrupted_file_publication_retains_only_a_private_partial_directory() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let mut input = task();
    input["objective"] = json!("x".repeat(8000));
    let path = input_file(dir.path(), &input);
    let out = dir.path().join("interrupted");
    // This changes only the child process limits. Its first output document
    // exceeds the limit before any hard link can publish a complete document.
    let output = Command::new("/bin/sh")
        .timeout(Duration::from_secs(10))
        .args([
            "-c",
            "ulimit -c 0; ulimit -f 1; exec \"$@\"",
            "task-guide-test",
        ])
        .arg(assert_cmd::cargo::cargo_bin!("agent-router"))
        .args(["task-guide", "--task"])
        .arg(&path)
        .args(["--json", "--output-directory"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(out.is_dir());
    assert_eq!(
        fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(!out.join("normalization.json").exists());
    assert!(!out.join("input.json").exists());
    let pending = out.join(".input.json.pending");
    let metadata = fs::symlink_metadata(&pending).unwrap();
    assert!(metadata.is_file());
    assert!(metadata.len() > 0 && metadata.len() < 8000);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let before = fs::read(&pending).unwrap();
    command()
        .args(["task-guide", "--task"])
        .arg(path)
        .args(["--json", "--output-directory"])
        .arg(&out)
        .assert()
        .code(2);
    assert_eq!(fs::read(pending).unwrap(), before);
    assert!(!out.join("normalization.json").exists());
}

#[cfg(unix)]
#[test]
fn a_parent_directory_writable_by_other_users_is_refused_before_export() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = input_file(dir.path(), &task());
    let parent = dir.path().join("shared-parent");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
    let out = parent.join("output");
    command()
        .args(["task-guide", "--task"])
        .arg(path)
        .args(["--json", "--output-directory"])
        .arg(&out)
        .assert()
        .code(2);
    assert!(!out.exists());
}

#[test]
fn semantically_invalid_answers_fail_immediately_with_the_answer_error_code() {
    let dir = tempfile::tempdir().unwrap();
    let cases = [
        "explore\nlow\npublic\n{\"max_cost_microusd\":1,\"max_elapsed_ms\":0,\"max_tokens\":1}\n"
            .to_owned(),
        "explore\nlow\npublic\n{\"max_cost_microusd\":1,\"max_elapsed_ms\":1,\"max_tokens\":0}\n"
            .to_owned(),
        answers().replace("[\"src\"]", "[\"../escape\"]"),
        answers().replace("[\"cite an enforcing symbol\"]", "[\" \"]"),
    ];
    for (number, response) in cases.iter().enumerate() {
        let out = dir.path().join(format!("invalid-semantic-{number}"));
        let output = command()
            .args([
                "task-guide",
                "--text",
                OBJECTIVE,
                "--interactive",
                "--json",
                "--output-directory",
            ])
            .arg(&out)
            .write_stdin(response.clone())
            .assert()
            .code(2)
            .get_output()
            .clone();
        assert!(output.stdout.is_empty(), "case {number}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("task_guide.answer.invalid"),
            "case {number}"
        );
        assert!(!out.exists());
    }
}
