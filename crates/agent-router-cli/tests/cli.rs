use std::{fs, path::PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn workspace_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("CLI crate is nested beneath the workspace root")
        .join(path)
}

fn command() -> Command {
    Command::cargo_bin("agent-router").expect("agent-router binary exists")
}

fn route_args(request: PathBuf, catalog: PathBuf) -> Vec<String> {
    vec![
        "route".into(),
        "--request".into(),
        request.display().to_string(),
        "--catalog".into(),
        catalog.display().to_string(),
        "--json".into(),
    ]
}

fn catalog_path() -> PathBuf {
    workspace_path("assets/catalogs/codex-core-v1.json")
}

fn implementation_request() -> PathBuf {
    workspace_path("tests/fixtures/requests/codex-implementation.json")
}

fn no_route_request() -> PathBuf {
    workspace_path("tests/fixtures/requests/no-compatible-plan.json")
}

#[test]
fn help_is_rendered_by_clap_on_stdout_with_success() {
    let mut command = command();
    command
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: agent-router"))
        .stdout(predicate::str::contains("route"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn route_help_is_rendered_by_clap_on_stdout_with_success() {
    let mut command = command();
    command
        .args(["route", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: agent-router route"))
        .stdout(predicate::str::contains("--catalog <CATALOG>"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn version_is_rendered_by_clap_on_stdout_with_success() {
    let mut command = command();
    command
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("agent-router 0.0.1"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn invalid_command_keeps_the_stable_first_error_line() {
    let output = command().arg("not-a-command").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr.lines().next(),
        Some("error: cli.invalid"),
        "{stderr}"
    );
}

#[test]
fn route_emits_versioned_json_without_mutating_home() {
    let temp_home = TempDir::new().unwrap();
    let mut command = command();
    command
        .env("HOME", temp_home.path())
        .args(route_args(implementation_request(), catalog_path()))
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema_version\": \"1\""))
        .stderr(predicate::str::is_empty());

    assert_eq!(fs::read_dir(temp_home.path()).unwrap().count(), 0);
}

#[test]
fn malformed_request_returns_code_two_and_keeps_its_body_off_stderr() {
    let temporary = TempDir::new().unwrap();
    let request = temporary.path().join("request.json");
    let secret = "DO_NOT_LEAK_REQUEST_BODY";
    fs::write(
        &request,
        format!("{{\"task\":{{\"objective\":\"{secret}\"}}}}"),
    )
    .unwrap();

    let mut command = command();
    command
        .args(route_args(request, catalog_path()))
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "{\"schema_version\":1,\"error\":\"request.json.invalid\"}\n",
        ))
        .stderr(predicate::str::contains(secret).not());
}

#[test]
fn invalid_embedded_skill_candidates_return_request_invalid() {
    let cases = [
        ("negative", -1, "valid-source", 1),
        ("above-max", 1_000_001, "valid-source", 1),
        ("i64-max", i64::MAX, "valid-source", 1),
        ("empty-source", 500_000, "", 1),
        ("too-many", 500_000, "valid-source", 257),
    ];

    for (name, score, source, count) in cases {
        let temporary = TempDir::new().unwrap();
        let request = temporary.path().join(format!("{name}.json"));
        write_request_candidates(&request, score, source, count);

        let mut command = command();
        command
            .args(route_args(request, catalog_path()))
            .assert()
            .code(2)
            .stdout(predicate::str::is_empty())
            .stderr("{\"schema_version\":1,\"error\":\"request.invalid\"}\n");
    }
}

#[test]
fn combined_routing_work_limit_returns_request_invalid() {
    let temporary = TempDir::new().unwrap();
    let request = temporary.path().join("work-limit-request.json");
    let catalog = temporary.path().join("work-limit-catalog.json");
    write_work_limit_fixture(&request, &catalog, 32, 256);

    command()
        .args(route_args(request, catalog))
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr("{\"schema_version\":1,\"error\":\"request.invalid\"}\n");
}

#[test]
fn oversized_request_is_rejected_before_json_parsing() {
    let temporary = TempDir::new().unwrap();
    let request = temporary.path().join("oversized-request.json");
    fs::write(&request, vec![b' '; 1024 * 1024 + 1]).unwrap();

    command()
        .args(route_args(request, catalog_path()))
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr("{\"schema_version\":1,\"error\":\"request.too_large\"}\n");
}

#[test]
fn oversized_catalog_is_rejected_before_json_parsing() {
    let temporary = TempDir::new().unwrap();
    let catalog = temporary.path().join("oversized-catalog.json");
    fs::write(&catalog, vec![b' '; 4 * 1024 * 1024 + 1]).unwrap();

    command()
        .args(route_args(implementation_request(), catalog))
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr("{\"schema_version\":1,\"error\":\"catalog.too_large\"}\n");
}

#[test]
fn oversized_decision_is_rejected_before_json_parsing() {
    let temporary = TempDir::new().unwrap();
    let decision = temporary.path().join("oversized-decision.json");
    fs::write(&decision, vec![b' '; 8 * 1024 * 1024 + 1]).unwrap();

    command()
        .args(["explain", "--decision", decision.to_str().unwrap()])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr("error: decision.too_large\n");
}

#[test]
fn invalid_catalog_returns_code_two_and_a_single_concise_error_line() {
    let mut command = command();
    command
        .args(route_args(
            implementation_request(),
            workspace_path("tests/fixtures/catalogs/invalid-alias.json"),
        ))
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr("{\"schema_version\":1,\"error\":\"catalog.invalid\"}\n");
}

#[test]
fn no_route_has_a_distinct_exit_code_and_still_emits_json() {
    let mut command = command();
    command
        .args(route_args(no_route_request(), catalog_path()))
        .assert()
        .code(3)
        .stdout(predicate::str::contains("\"no_route\""))
        .stderr(predicate::str::is_empty());
}

#[test]
fn route_stdout_is_byte_exactly_the_pinned_implementation_decision() {
    let golden = fs::read(workspace_path(
        "tests/fixtures/decisions/codex-implementation.json",
    ))
    .expect("pinned implementation decision exists");

    let output = command()
        .args(route_args(implementation_request(), catalog_path()))
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(output.stderr, b"");
    assert_eq!(output.stdout, golden);
}

#[test]
fn explain_selected_prints_the_plan_without_request_or_skill_contents() {
    let temporary = TempDir::new().unwrap();
    let decision = temporary.path().join("selected.json");
    let output = command()
        .args(route_args(implementation_request(), catalog_path()))
        .output()
        .unwrap();
    assert!(output.status.success());
    fs::write(&decision, output.stdout).unwrap();

    let mut command = command();
    command
        .args(["explain", "--decision", decision.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Preset: plan-execute-verify"))
        .stdout(predicate::str::contains(
            "Plan: gpt-5.6-sol/high -> gpt-5.6-terra/medium -> gpt-5.6-terra/high",
        ))
        .stdout(predicate::str::contains("Implement a bounded parser change").not())
        .stdout(predicate::str::contains("red-green-refactor").not())
        .stderr(predicate::str::is_empty());
}

#[test]
fn explain_no_route_prints_each_exclusion_without_the_request_body() {
    let temporary = TempDir::new().unwrap();
    let decision = temporary.path().join("no-route.json");
    let output = command()
        .args(route_args(no_route_request(), catalog_path()))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    fs::write(&decision, output.stdout).unwrap();

    let mut command = command();
    command
        .args(["explain", "--decision", decision.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("No route"))
        .stdout(predicate::str::contains("Stage: plan"))
        .stdout(predicate::str::contains("Model: gpt-5.6-terra"))
        .stdout(predicate::str::contains("Code: model.stage.unsupported"))
        .stdout(predicate::str::contains("Evidence:"))
        .stdout(predicate::str::contains("Implement without an available planning model").not())
        .stderr(predicate::str::is_empty());
}

#[test]
fn explain_refuses_a_decision_with_an_unsupported_schema_version() {
    let temporary = TempDir::new().unwrap();
    let decision = temporary.path().join("unsupported.json");
    let output = command()
        .args(route_args(implementation_request(), catalog_path()))
        .output()
        .unwrap();
    assert!(output.status.success());
    let mut value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], "1");
    for version in ["2", "", "01", " 1"] {
        value["schema_version"] = version.into();
        fs::write(&decision, serde_json::to_vec(&value).unwrap()).unwrap();
        command()
            .args(["explain", "--decision", decision.to_str().unwrap()])
            .assert()
            .code(2)
            .stdout(predicate::str::is_empty())
            .stderr("error: decision.schema.unsupported\n");
    }
}

fn write_request_candidates(path: &std::path::Path, score: i64, source: &str, count: usize) {
    let mut request: serde_json::Value =
        serde_json::from_slice(&fs::read(implementation_request()).unwrap()).unwrap();
    let candidate = serde_json::json!({
        "skill": "tdd",
        "source": source,
        "score_micros": score
    });
    request["skill_candidates"] =
        serde_json::Value::Array((0..count).map(|_| candidate.clone()).collect());
    fs::write(path, serde_json::to_vec(&request).unwrap()).unwrap();
}

fn write_work_limit_fixture(
    request_path: &std::path::Path,
    catalog_path: &std::path::Path,
    model_count: usize,
    skill_count: usize,
) {
    let model_ids = (0..model_count)
        .map(|index| format!("provider-work-{index:02}"))
        .collect::<Vec<_>>();
    let skill_ids = (0..skill_count)
        .map(|index| format!("work-skill-{index:03}"))
        .collect::<Vec<_>>();
    let models = model_ids
        .iter()
        .map(|id| {
            serde_json::json!({
                "id": id,
                "stages": ["plan", "execute", "verify"],
                "efforts": ["medium", "high"],
                "capabilities": ["tools"],
                "quality_micros": 800000,
                "cost_micros": 0,
                "latency_micros": 0,
                "source": "work-limit-fixture"
            })
        })
        .collect::<Vec<_>>();
    let skills = skill_ids
        .iter()
        .map(|id| {
            serde_json::json!({
                "id": id,
                "description": "work limit fixture",
                "task_kinds": ["implement"],
                "required_capabilities": ["tools"],
                "trust": "builtin"
            })
        })
        .collect::<Vec<_>>();
    let supported_efforts = model_ids
        .iter()
        .map(|id| (id.clone(), serde_json::json!(["medium", "high"])))
        .collect::<serde_json::Map<_, _>>();
    let skill_candidates = skill_ids
        .iter()
        .map(|id| {
            serde_json::json!({
                "skill": id,
                "source": "work-limit-fixture",
                "score_micros": 1000000
            })
        })
        .collect::<Vec<_>>();

    let catalog = serde_json::json!({
        "schema_version": 1,
        "version": "work-limit-v1",
        "models": models,
        "skills": skills
    });
    let request = serde_json::json!({
        "task": {
            "objective": "reject excessive combined routing work",
            "kind": "implement",
            "risk": "medium",
            "required_capabilities": ["tools"],
            "acceptance": ["work budget is authoritative"]
        },
        "host": {
            "id": "work-limit-host",
            "harness": "codex",
            "supported_models": model_ids,
            "supported_efforts": supported_efforts,
            "capabilities": ["tools"]
        },
        "skill_candidates": skill_candidates,
        "capability_knowledge": {}
    });
    fs::write(catalog_path, serde_json::to_vec(&catalog).unwrap()).unwrap();
    fs::write(request_path, serde_json::to_vec(&request).unwrap()).unwrap();
}

#[test]
fn explain_escapes_terminal_controls_and_bidi_marks_in_untrusted_decision_fields() {
    let temporary = TempDir::new().unwrap();
    let decision = temporary.path().join("no-route.json");
    let output = command()
        .args(route_args(no_route_request(), catalog_path()))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let mut value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    value["decision_id"] = "id\u{1b}[2Jx".into();
    let exclusion = &mut value["decision"]["no_route"]["exclusions"][0];
    exclusion["code"] = "c\nfake: line\u{202e}".into();
    exclusion["evidence"] = "e\u{200f}v\u{61c}i\u{200e}d".into();
    fs::write(&decision, serde_json::to_vec(&value).unwrap()).unwrap();

    let output = command()
        .args(["explain", "--decision", decision.to_str().unwrap()])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    for raw in ['\u{1b}', '\u{202e}', '\u{200f}', '\u{61c}', '\u{200e}'] {
        assert!(!text.contains(raw), "{raw:?} leaked in {text:?}");
    }
    assert!(text.contains("id\\u{1b}[2Jx"), "{text}");
    assert!(text.contains("c\\nfake: line\\u{202e}"), "{text}");
    assert!(text.contains("e\\u{200f}v\\u{61c}i\\u{200e}d"), "{text}");
    assert!(!text.lines().any(|line| line.starts_with("fake:")));
}

#[cfg(unix)]
#[test]
fn a_broken_stdout_pipe_fails_without_panicking_or_reporting_success() {
    use std::process::{Command as Std, Stdio};
    let bin = assert_cmd::cargo::cargo_bin("agent-router");
    let args = route_args(implementation_request(), catalog_path());

    // A closed stdout (`>&-`) is not testable here: the Rust runtime reopens fds
    // 0-2 on /dev/null at startup, so the descriptor is valid and writes succeed.
    // A pipe whose reader already exited: the write end stays open here, so a
    // write fails with EPIPE. The reader's exit does not by itself prove that no
    // read end is left open: a concurrent test's fork can hold a copy until its
    // exec, and then the CLI's write would succeed. Probe the pipe until it
    // reports EPIPE. No reader can reappear afterwards, so the broken pipe is
    // established before the CLI runs, and a pipe that never breaks fails the
    // test instead of passing vacuously.
    let mut reader = Std::new("true").stdin(Stdio::piped()).spawn().unwrap();
    let mut broken = reader.stdin.take().unwrap();
    reader.wait().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match std::io::Write::write_all(&mut broken, b"\n") {
            Ok(()) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the pipe kept a reader for 10 s"
                );
                std::thread::yield_now();
            }
            Err(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
                break;
            }
        }
    }
    let output = Std::new(&bin)
        .args(&args)
        .stdout(Stdio::from(broken))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(4), "{stderr}");
    assert!(stderr.contains("route.internal"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

fn stderr_text(output: &std::process::Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

#[test]
fn usage_errors_keep_the_stable_first_line_then_name_the_problem_and_the_help_command() {
    let cases: [(&[&str], &str, &str); 5] = [
        (&["not-a-command"], "not-a-command", "agent-router --help"),
        (
            &["route", "--bogus-option"],
            "--bogus-option",
            "agent-router route --help",
        ),
        (
            &["route", "--catalog", "catalog.json"],
            "--request",
            "agent-router route --help",
        ),
        (
            &["catalog", "show", "--catalog", "c.json"],
            "--id",
            "agent-router catalog show --help",
        ),
        (&["catalog"], "subcommand", "agent-router catalog --help"),
    ];
    for (args, named, help) in cases {
        let output = command().args(args).output().unwrap();
        let stderr = stderr_text(&output);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert_eq!(
            stderr.lines().next(),
            Some("error: cli.invalid"),
            "{args:?}: {stderr}"
        );
        assert!(stderr.contains(named), "{args:?}: {stderr}");
        assert!(
            stderr.ends_with(&format!("Run '{help}' for usage.\n")),
            "{args:?}: {stderr}"
        );
        // Only the first line carries the stable `error:` prefix scripts match.
        assert_eq!(
            stderr.lines().filter(|l| l.starts_with("error:")).count(),
            1,
            "{args:?}: {stderr}"
        );
    }
}

#[test]
fn a_quoted_argument_with_a_newline_cannot_forge_an_error_line() {
    let output = command()
        .args([
            "route",
            "--bogus\nerror: forged\nUsage: agent-router doctor",
        ])
        .output()
        .unwrap();
    let stderr = stderr_text(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert_eq!(
        stderr.lines().next(),
        Some("error: cli.invalid"),
        "{stderr}"
    );
    assert_eq!(
        stderr.lines().filter(|l| l.starts_with("error:")).count(),
        1,
        "{stderr}"
    );
    assert!(
        stderr.ends_with("Run 'agent-router route --help' for usage.\n"),
        "{stderr}"
    );
}

#[test]
fn a_bare_invocation_is_a_usage_error_with_a_pointer_to_help() {
    let output = command().output().unwrap();
    let stderr = stderr_text(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(output.stdout.is_empty());
    assert_eq!(stderr.lines().next(), Some("error: cli.invalid"));
    assert!(
        stderr.ends_with("Run 'agent-router --help' for usage.\n"),
        "{stderr}"
    );
    // The short form never dumps the whole command list.
    assert!(stderr.lines().count() <= 6, "{stderr}");
}

#[test]
fn with_json_every_error_is_one_json_line_on_stderr_and_stdout_stays_empty() {
    let temporary = TempDir::new().unwrap();
    let request = temporary.path().join("request.json");
    let secret = "DO_NOT_LEAK_REQUEST_BODY";
    fs::write(
        &request,
        format!("{{\"task\":{{\"objective\":\"{secret}\"}}}}"),
    )
    .unwrap();
    let product = command()
        .args(route_args(request, catalog_path()))
        .output()
        .unwrap();
    // A clap failure is detected from the raw `--json` argument.
    let usage = command()
        .args(["route", "--json", "--bogus-option"])
        .output()
        .unwrap();
    let missing = command()
        .args(["catalog", "list", "--json"])
        .output()
        .unwrap();
    for (output, code) in [
        (product, "request.json.invalid"),
        (usage, "cli.invalid"),
        (missing, "cli.invalid"),
    ] {
        let stderr = stderr_text(&output);
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        assert!(output.stdout.is_empty(), "{stderr}");
        assert_eq!(stderr.lines().count(), 1, "{stderr}");
        let value: serde_json::Value = serde_json::from_str(&stderr).expect("stderr is JSON");
        assert_eq!(
            value,
            serde_json::json!({"schema_version": 1, "error": code}),
            "{stderr}"
        );
        assert!(!stderr.contains(secret));
    }
}

#[test]
fn an_argument_after_the_separator_does_not_switch_errors_to_json() {
    let output = command()
        .args(["not-a-command", "--", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        stderr_text(&output).lines().next(),
        Some("error: cli.invalid")
    );
}

#[test]
fn top_level_help_describes_every_subcommand() {
    let output = command().arg("--help").output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    let commands: Vec<&str> = help
        .lines()
        .skip_while(|line| *line != "Commands:")
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .collect();
    assert!(commands.len() >= 30, "{help}");
    for line in commands {
        assert!(
            line.split_whitespace().count() >= 2,
            "subcommand without description: {line:?}"
        );
    }
}

#[test]
fn every_nested_subcommand_has_a_description() {
    // Walks the whole command tree through `--help`, at every depth.
    let subcommands = |path: &[String]| -> Vec<(String, String)> {
        let mut args = path.to_vec();
        args.push("--help".into());
        let output = command().args(&args).output().unwrap();
        assert!(output.status.success(), "{path:?}");
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .skip_while(|line| *line != "Commands:")
            .skip(1)
            .take_while(|line| !line.trim().is_empty())
            .map(|line| {
                let name = line.split_whitespace().next().unwrap_or_default();
                (name.to_owned(), line.to_owned())
            })
            .filter(|(name, _)| name != "help")
            .collect()
    };
    let mut pending = vec![Vec::<String>::new()];
    let mut visited = 0;
    while let Some(path) = pending.pop() {
        for (name, line) in subcommands(&path) {
            assert!(
                line.split_whitespace().count() >= 2,
                "{path:?}: subcommand without description: {line:?}"
            );
            let mut child = path.clone();
            child.push(name);
            pending.push(child);
            visited += 1;
        }
    }
    assert!(visited >= 80, "only {visited} subcommands visited");
}

#[test]
fn common_options_and_examples_are_documented_in_help() {
    let help = |args: &[&str]| {
        let output = command().args(args).output().unwrap();
        assert!(output.status.success(), "{args:?}");
        String::from_utf8(output.stdout).unwrap()
    };
    let route = help(&["route", "--help"]);
    assert!(
        route.contains("Required: route prints only JSON"),
        "{route}"
    );
    let run = help(&["run", "--help"]);
    assert!(run.contains("Without --approve"), "{run}");
    assert!(run.contains("Unix seconds") || run.contains("--store <STORE>"));
    for command in ["route", "explain", "plan", "run", "doctor"] {
        let text = help(&[command, "--help"]);
        assert!(text.contains("Example:"), "{command}: {text}");
        assert!(
            text.contains(&format!("agent-router {command} ")),
            "{command}"
        );
    }
    for (command, option, word) in [
        ("plan", "--json", "JSON"),
        ("doctor", "--now", "Unix seconds"),
        ("status", "--store", "store"),
        ("run", "--approve", "digest"),
        ("run", "--sandbox", "sandbox"),
    ] {
        let text = help(&[command, "--help"]);
        let line = text
            .lines()
            .skip_while(|line| !line.trim_start().starts_with(option))
            .take(3)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(line.contains(word), "{command} {option}: {line:?}");
    }
}

#[test]
fn catalog_commands_render_a_human_view_without_json() {
    // `structured_output` forces JSON for every catalog subcommand before
    // `catalogs::run`, so no catalog path can report `cli.json.required`.
    let catalog = catalog_path();
    let catalog = catalog.to_str().unwrap();
    for args in [
        vec!["catalog", "validate", "--catalog", catalog],
        vec!["catalog", "list", "--catalog", catalog],
        vec![
            "catalog",
            "show",
            "--catalog",
            catalog,
            "--id",
            "gpt-5.6-terra",
        ],
    ] {
        let output = command().args(&args).output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            stderr_text_of(&output.stderr)
        );
        assert!(stdout.starts_with("Catalog\n"), "{args:?}: {stdout}");
        assert!(output.stderr.is_empty(), "{args:?}");
    }
}

fn stderr_text_of(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr).into_owned()
}
