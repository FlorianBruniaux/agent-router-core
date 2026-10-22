use assert_cmd::Command;
use router_runtime::{Runtime, RuntimeLimits};
use serde_json::Value;
#[test]
fn runtime_doctor_json_and_human_outputs_share_status_without_creating_storage() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("runtime");
    let runtime = Runtime::open(&root, RuntimeLimits::default()).unwrap();
    let output = Command::cargo_bin("agent-router")
        .unwrap()
        .args(["doctor", "--runtime-root"])
        .arg(&root)
        .args(["--now", "100", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["owner_lock"], "busy");
    assert_eq!(report["observed_at_unix_seconds"], 100);
    assert_eq!(report["process_liveness"], "unknown");
    let human = Command::cargo_bin("agent-router")
        .unwrap()
        .args(["doctor", "--runtime-root"])
        .arg(&root)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(String::from_utf8_lossy(&human).contains("Diagnostics"));
    drop(runtime);
    let missing = root.join("missing");
    Command::cargo_bin("agent-router")
        .unwrap()
        .args(["doctor", "--runtime-root"])
        .arg(&missing)
        .arg("--json")
        .assert()
        .code(2);
    assert!(!missing.exists());
}
#[test]
fn runtime_doctor_rejects_ambiguous_modes() {
    for args in [
        vec!["doctor", "--json"],
        vec![
            "doctor",
            "--runtime-root",
            "/missing",
            "--request",
            "/missing",
            "--json",
        ],
        vec!["doctor", "--runtime-root", "/missing", "--deep", "--json"],
    ] {
        Command::cargo_bin("agent-router")
            .unwrap()
            .args(args)
            .assert()
            .code(2);
    }
}

#[test]
fn missing_owner_is_warning_and_is_never_created() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("runtime");
    drop(Runtime::open(&root, RuntimeLimits::default()).unwrap());
    let lock = root.join("runtime.lock");
    std::fs::remove_file(&lock).unwrap();
    let output = Command::cargo_bin("agent-router")
        .unwrap()
        .args(["doctor", "--runtime-root"])
        .arg(&root)
        .arg("--json")
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["owner_lock"], "missing");
    assert_eq!(report["overall"], "warning");
    assert!(!lock.exists());
}

#[test]
fn database_over_the_inspection_cap_is_a_partial_unknown_report_with_exit_3() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("runtime");
    drop(Runtime::open(&root, RuntimeLimits::default()).unwrap());
    rusqlite::Connection::open(root.join("runtime.sqlite3"))
        .unwrap()
        .execute_batch("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<100) INSERT INTO runs SELECT 'big'||i,'p','n',zeroblob(60000) FROM n;")
        .unwrap();
    let output = Command::cargo_bin("agent-router")
        .unwrap()
        .args(["doctor", "--runtime-root"])
        .arg(&root)
        .arg("--json")
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["overall"], "unknown");
    assert_eq!(
        report["partial_reason"],
        "database_exceeds_inspection_limit"
    );
    assert_eq!(report["database"], Value::Null);
}
