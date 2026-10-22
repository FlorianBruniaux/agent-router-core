//! `completions <shell>`: the script names every top-level subcommand of `--help`.
use assert_cmd::Command;

fn command() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("agent-router"))
}
fn stdout(args: &[&str]) -> String {
    let out = command()
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(out).unwrap()
}

/// The names under `Commands:` in `--help`, the last section before `Options:`.
fn top_level_subcommands() -> Vec<String> {
    let help = stdout(&["--help"]);
    let names: Vec<String> = help
        .lines()
        .skip_while(|line| *line != "Commands:")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .map(|line| line.split_whitespace().next().unwrap().to_owned())
        .collect();
    assert!(names.len() > 30, "parsed {names:?} from\n{help}");
    assert!(names.contains(&"route".to_owned()), "{names:?}");
    names
}

/// Whether the script registers `name` as a top-level subcommand, matched on
/// the shell's own registration syntax and not on a bare substring.
fn registers(shell: &str, script: &str, name: &str) -> bool {
    match shell {
        // The dispatch arm of the root command.
        "bash" => script
            .lines()
            .any(|line| line.trim() == format!("agent__router,{name})")),
        // The entry of the root command list.
        "zsh" => script
            .lines()
            .any(|line| line.starts_with(&format!("'{name}:"))),
        "fish" => script.lines().any(|line| {
            line.starts_with("complete -c agent-router -n \"__fish_agent_router_needs_command\"")
                && line.contains(&format!(" -a \"{name}\" "))
        }),
        _ => unreachable!(),
    }
}

#[test]
fn every_script_registers_every_top_level_subcommand() {
    let names = top_level_subcommands();
    assert!(names.contains(&"completions".to_owned()));
    for shell in ["bash", "zsh", "fish"] {
        let script = stdout(&["completions", shell]);
        for name in &names {
            assert!(registers(shell, &script, name), "{shell} lacks {name}");
        }
    }
}

#[test]
fn the_anchored_check_fails_when_a_subcommand_is_removed() {
    for shell in ["bash", "zsh", "fish"] {
        let script = stdout(&["completions", shell]);
        // `plan` is also a substring of `generate-plan`, so a bare `contains` would pass.
        assert!(registers(shell, &script, "plan"), "{shell}");
        let without: String = script
            .lines()
            .filter(|line| !match shell {
                "bash" => line.trim() == "agent__router,plan)",
                "zsh" => line.starts_with("'plan:"),
                _ => line.contains("__fish_agent_router_needs_command\" -f -a \"plan\" "),
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!registers(shell, &without, "plan"), "{shell}");
        assert!(registers(shell, &without, "generate-plan"), "{shell}");
    }
}

#[test]
fn scripts_carry_the_flags_of_a_subcommand() {
    assert!(stdout(&["completions", "fish"]).contains("using_subcommand version\" -l json"));
    assert!(stdout(&["completions", "zsh"]).contains("'--json[Print the complete versioned JSON"));
    assert!(stdout(&["completions", "bash"]).contains("--json"));
}

#[test]
fn scripts_are_byte_identical_and_shell_specific() {
    for shell in ["bash", "zsh", "fish"] {
        assert_eq!(
            stdout(&["completions", shell]),
            stdout(&["completions", shell])
        );
    }
    assert!(stdout(&["completions", "bash"]).contains("complete -F"));
    assert!(stdout(&["completions", "zsh"]).starts_with("#compdef agent-router"));
    assert!(stdout(&["completions", "fish"]).contains("complete -c agent-router"));
}

#[test]
fn an_unsupported_shell_is_a_usage_error() {
    command()
        .args(["completions", "powershell"])
        .assert()
        .code(2)
        .stderr(predicates::str::starts_with("error: cli.invalid\n"));
    command()
        .arg("completions")
        .assert()
        .code(2)
        .stderr(predicates::str::starts_with("error: cli.invalid\n"));
}
