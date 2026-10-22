//! `version --json`: the build facts and the contract versions, tied to `schema --list`.
use assert_cmd::Command;
use serde_json::Value;

fn command() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("agent-router"))
}
fn run(args: &[&str]) -> Vec<u8> {
    command()
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone()
}

#[test]
fn version_json_parses_and_lists_the_contracts_of_schema_list() {
    let bytes = run(&["version", "--json"]);
    assert_eq!(bytes, run(&["version", "--json"]));
    let info: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(info["schema_version"], 1);
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
    assert!(info["target"].as_str().unwrap().contains('-'), "{info}");

    let listing: Value = serde_json::from_slice(&run(&["schema", "--list"])).unwrap();
    let contracts = info["contracts"].as_object().unwrap();
    for entry in listing["schemas"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let listed = contracts
            .get(name)
            .unwrap_or_else(|| panic!("{name} missing from version --json"));
        assert_eq!(
            listed["schema_versions"], entry["schema_versions"],
            "{name}"
        );
        assert_eq!(listed["command"], entry["command"], "{name}");
    }
    assert_eq!(
        contracts.len(),
        listing["schemas"].as_array().unwrap().len()
    );
}

#[test]
fn version_json_reports_the_enabled_features() {
    let info: Value = serde_json::from_slice(&run(&["version", "--json"])).unwrap();
    let features: Vec<&str> = info["features"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert_eq!(features.contains(&"codex"), cfg!(feature = "codex"));
    assert_eq!(features.contains(&"claude"), cfg!(feature = "claude"));
    assert_eq!(features.contains(&"local-api"), cfg!(feature = "local-api"));
    let mut sorted = features.clone();
    sorted.sort_unstable();
    assert_eq!(features, sorted);
}

#[test]
fn the_human_flag_is_unchanged_and_the_command_has_a_human_view() {
    let flag = String::from_utf8(run(&["--version"])).unwrap();
    assert_eq!(
        flag,
        format!("agent-router {}\n", env!("CARGO_PKG_VERSION"))
    );
    let human = String::from_utf8(run(&["version"])).unwrap();
    assert!(human.contains("Target:"), "{human}");
    assert!(!human.trim_start().starts_with('{'), "{human}");
}
