#![cfg(feature = "codex")]

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

fn cli() -> Command {
    Command::cargo_bin("agent-router").unwrap()
}
fn root(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}
fn cache() -> Value {
    json!({"fetched_at":"1970-01-01T00:00:00Z","client_version":"0.153.4","models":[
        {"slug":"gpt-5.6-luna","supported_reasoning_levels":[{"effort":"low"},{"effort":"medium"},{"effort":"high"}]},
        {"slug":"gpt-5.6-sol","supported_reasoning_levels":[{"effort":"high"},{"effort":"xhigh"},{"effort":"max"}]},
        {"slug":"gpt-5.6-terra","supported_reasoning_levels":[{"effort":"medium"},{"effort":"high"},{"effort":"xhigh"}]}
    ]})
}
fn inspect(source: &Path, now: &str) -> Command {
    let mut command = cli();
    command
        .args(["inspect", "--host", "codex", "--model-cache"])
        .arg(source)
        .args(["--now", now, "--json"]);
    command
}
fn route(request: &Path, snapshot: &Path) -> Command {
    let mut command = cli();
    command
        .arg("route")
        .arg("--request")
        .arg(request)
        .arg("--catalog")
        .arg(root("assets/catalogs/codex-core-v1.json"))
        .arg("--host-snapshot")
        .arg(snapshot)
        .args(["--now", "10", "--json"]);
    command
}

#[test]
fn inspect_is_repeatable_read_only_and_does_not_promote_cache_to_runtime() {
    let dir = TempDir::new().unwrap();
    let source = dir.path().join("cache.json");
    let original = serde_json::to_vec(&cache()).unwrap();
    fs::write(&source, &original).unwrap();
    let first = inspect(&source, "10")
        .env("HOME", dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let second = inspect(&source, "10")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(first, second);
    assert_eq!(fs::read(&source).unwrap(), original);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    let observation: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(observation["capabilities"].as_object().unwrap().len(), 5);
    for evidence in observation["capabilities"].as_object().unwrap().values() {
        assert_eq!(evidence["support"], "unknown");
    }
    assert!(
        observation["host"]["capabilities"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        !String::from_utf8(first)
            .unwrap()
            .contains(&dir.path().display().to_string())
    );
}

#[test]
fn auto_requires_a_host_marker_and_explicit_version_mismatch_is_rejected() {
    cli()
        .env_remove("CODEX_THREAD_ID")
        .args(["inspect", "--host", "auto", "--json"])
        .assert()
        .code(2)
        .stderr("{\"schema_version\":1,\"error\":\"host.unknown\"}\n");
    let dir = TempDir::new().unwrap();
    let source = dir.path().join("cache.json");
    fs::write(&source, serde_json::to_vec(&cache()).unwrap()).unwrap();
    inspect(&source, "10")
        .args(["--observed-version", "0.154.0"])
        .assert()
        .code(2)
        .stderr("{\"schema_version\":1,\"error\":\"probe.version.mismatch\"}\n");
    inspect(&source, "86401")
        .assert()
        .code(2)
        .stderr("{\"schema_version\":1,\"error\":\"snapshot.source.stale\"}\n");
}

#[test]
fn explicit_snapshot_replaces_claimed_support_even_for_low_risk() {
    let dir = TempDir::new().unwrap();
    let source = dir.path().join("cache.json");
    let snapshot = dir.path().join("snapshot.json");
    fs::write(&source, serde_json::to_vec(&cache()).unwrap()).unwrap();
    let bytes = inspect(&source, "10")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    fs::write(&snapshot, &bytes).unwrap();
    let mut request: Value = serde_json::from_slice(
        &fs::read(root("tests/fixtures/requests/codex-implementation.json")).unwrap(),
    )
    .unwrap();
    request["task"]["risk"] = json!("low");
    request["capability_knowledge"] = json!({"tools":"supported","subagents":"supported","workspace_write":"supported","network":"supported","vision":"supported"});
    let request_path = dir.path().join("request.json");
    fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();
    let output = route(&request_path, &snapshot)
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();
    let decision: Value = serde_json::from_slice(&output).unwrap();
    assert!(decision["decision"].get("no_route").is_some());
    assert_eq!(
        decision["host_snapshot_hash"],
        serde_json::from_slice::<Value>(&bytes).unwrap()["snapshot_hash"]
    );
    assert!(String::from_utf8(output).unwrap().contains("unknown"));
}

#[test]
fn corrupted_snapshot_fails_before_routing_and_provenance_changes_identity() {
    let dir = TempDir::new().unwrap();
    let source = dir.path().join("cache.json");
    let snapshot = dir.path().join("snapshot.json");
    let request = root("tests/fixtures/requests/codex-implementation.json");
    let mut ids = vec![];
    for version in ["0.153.4", "0.154.0"] {
        let mut input = cache();
        input["client_version"] = json!(version);
        fs::write(&source, serde_json::to_vec(&input).unwrap()).unwrap();
        fs::write(
            &snapshot,
            inspect(&source, "10")
                .assert()
                .success()
                .get_output()
                .stdout
                .clone(),
        )
        .unwrap();
        let decision: Value = serde_json::from_slice(
            &route(&request, &snapshot)
                .assert()
                .code(3)
                .get_output()
                .stdout,
        )
        .unwrap();
        ids.push(decision["decision_id"].clone());
    }
    assert_ne!(ids[0], ids[1]);
    let mut tampered: Value = serde_json::from_slice(&fs::read(&snapshot).unwrap()).unwrap();
    tampered["host"]["id"] = json!("tampered");
    fs::write(&snapshot, serde_json::to_vec(&tampered).unwrap()).unwrap();
    route(&request, &snapshot)
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr("{\"schema_version\":1,\"error\":\"snapshot.hash.invalid\"}\n");
}

#[cfg(unix)]
#[test]
fn snapshot_special_files_and_symlinks_fail_without_waiting() {
    use std::os::unix::fs::symlink;
    use std::time::Duration;
    let dir = TempDir::new().unwrap();
    let fifo = dir.path().join("snapshot.pipe");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let request = root("tests/fixtures/requests/codex-implementation.json");
    route(&request, &fifo)
        .timeout(Duration::from_secs(2))
        .assert()
        .code(2)
        .stderr("{\"schema_version\":1,\"error\":\"snapshot.read\"}\n");
    route(&request, Path::new("/dev/zero"))
        .timeout(Duration::from_secs(2))
        .assert()
        .code(2)
        .stderr("{\"schema_version\":1,\"error\":\"snapshot.read\"}\n");
    let target = dir.path().join("snapshot.json");
    fs::write(&target, "{}").unwrap();
    let link = dir.path().join("link.json");
    symlink(&target, &link).unwrap();
    route(&request, &link)
        .assert()
        .code(2)
        .stderr("{\"schema_version\":1,\"error\":\"snapshot.read\"}\n");
}
