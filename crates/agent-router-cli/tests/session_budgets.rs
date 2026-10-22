#![cfg(all(feature = "claude", any(target_os = "macos", target_os = "linux")))]
#[path = "support/admission_fixture.rs"]
mod admission_fixture;
#[path = "support/native_fixture.rs"]
mod native_fixture;
use native_fixture::*;
use router_types::*;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
fn read(p: &Path) -> Value {
    serde_json::from_slice(&fs::read(p).unwrap()).unwrap()
}
fn amount(cost: u64, tokens: u64) -> BudgetAmount {
    BudgetAmount {
        cost_microusd: cost,
        tokens,
    }
}
fn bind(registry: &Path, roots: &[(&Path, &Path, &str)]) -> (String, String) {
    let (_, hash) = admission_fixture::bind_with_capacity(registry, roots, 2);
    let policy = SessionBudgetPolicy {
        schema_version: 1,
        sessions: BTreeMap::from([(
            "session".into(),
            SessionBudgetRule {
                initial_limit: amount(150, 10000),
                parent_ceiling: amount(300, 20000),
                warning_basis_points: vec![5000, 9000],
            },
        )]),
        runtime_sessions: roots
            .iter()
            .map(|(_, _, id)| ((*id).into(), "session".into()))
            .collect(),
    };
    let path = registry.parent().unwrap().join("budget-policy.json");
    write(&path, &policy);
    let report = checked(
        command()
            .args(["admission", "budget", "init", "--registry"])
            .arg(registry)
            .args(["--expected-policy-sha256", &hash, "--policy"])
            .arg(&path)
            .arg("--json"),
        0,
    );
    assert_eq!(report["executed"], false);
    let budget_hash = report["policy_sha256"].as_str().unwrap().to_owned();
    for (root, _, _) in roots {
        let path = root.join("definition.json");
        let mut d = read(&path);
        d["admission"]["session_budget"] = json!(SessionBudgetConfig {
            schema_version: 1,
            expected_policy_sha256: budget_hash.clone(),
            session_id: "session".into(),
            approved_limit: amount(150, 10000),
            attempt_allocation: amount(100, 4500)
        });
        write(&path, &d);
    }
    (hash, budget_hash)
}
fn budget_command(op: &str, registry: &Path, h: &str, b: &str) -> Command {
    let mut c = command();
    c.args(["admission", "budget", op, "--registry"])
        .arg(registry)
        .args([
            "--expected-policy-sha256",
            h,
            "--expected-budget-policy-sha256",
            b,
            "--session",
            "session",
            "--json",
        ]);
    c
}
#[track_caller]
fn rejected(c: &mut Command, code: &str) {
    rejected_with(c, code, 2);
}
fn rejected_with(c: &mut Command, code: &str, status: i32) {
    let o = c.output().unwrap();
    assert_eq!(
        o.status.code(),
        Some(status),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(
        String::from_utf8_lossy(&o.stderr).contains(code),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}
#[test]
fn limit_review_requires_exact_current_ledger_and_never_launches() {
    let f = Fixture::metadata("exit 99", 3000);
    let registry = f.root.join("registry");
    let (h, b) = bind(&registry, &[(&f.root, &f.store, "fixture")]);
    let digest = f.review();
    let path = f.root.join("new-limit.json");
    write(&path, &amount(200, 15000));
    let review = checked(
        budget_command("limit", &registry, &h, &b)
            .arg("--new-limit")
            .arg(&path),
        0,
    );
    assert_eq!(review["executed"], false);
    assert!(review["applied"].is_null());
    let status = checked(&mut budget_command("status", &registry, &h, &b), 0);
    assert_eq!(status["limit"]["cost_microusd"], 150);
    assert!(status["observed_tokens"].is_null());
    let approval = review["preview"]["approval_digest"].as_str().unwrap();
    let head = review["preview"]["current"]["ledger_head"]
        .as_str()
        .unwrap();
    rejected(
        budget_command("limit", &registry, &h, &b)
            .arg("--new-limit")
            .arg(&path)
            .args(["--approve", &"f".repeat(64), "--expected-head", head]),
        "session_budget.authority.required_or_changed",
    );
    let applied = checked(
        budget_command("limit", &registry, &h, &b)
            .arg("--new-limit")
            .arg(&path)
            .args(["--approve", approval, "--expected-head", head]),
        0,
    );
    assert_eq!(applied["applied"]["limit"]["cost_microusd"], 200);
    rejected(
        budget_command("limit", &registry, &h, &b)
            .arg("--new-limit")
            .arg(&path)
            .args(["--approve", approval, "--expected-head", head]),
        "session_budget.review.stale",
    );
    assert_eq!(f.review(), digest);
    let path = f.root.join("definition.json");
    let mut d = read(&path);
    d["admission"]["session_budget"]["approved_limit"]["cost_microusd"] = json!(200);
    write(&path, &d);
    // A definition changed after review is an altered file: integrity class.
    rejected_with(&mut f.run(), "runtime.integrity", 7);
    assert!(!f.store.join("worktrees").exists());
}
#[test]
fn authority_cannot_be_omitted_or_reassigned() {
    for variant in 0..3 {
        let f = Fixture::metadata("exit 99", 3000);
        let registry = f.root.join("registry");
        bind(&registry, &[(&f.root, &f.store, "fixture")]);
        let path = f.root.join("definition.json");
        let mut d = read(&path);
        match variant {
            0 => {
                d["admission"]
                    .as_object_mut()
                    .unwrap()
                    .remove("session_budget");
            }
            1 => d["admission"]["session_budget"]["session_id"] = json!("invented"),
            _ => d["admission"]["session_budget"]["expected_policy_sha256"] = json!("f".repeat(64)),
        };
        write(&path, &d);
        rejected(&mut f.run(), "session_budget.authority.required_or_changed");
        assert!(!f.store.join("worktrees").exists());
    }
}
#[test]
fn strict_policy_parser_refuses_duplicate_unknown_and_oversized_input() {
    let f = Fixture::metadata("exit 99", 3000);
    let proof_store_entries = fs::read_dir(&f.store).unwrap().count();
    let path = f.root.join("invalid-policy.json");
    for bytes in [
        b"{\"schema_version\":1,\"schema_version\":1}".to_vec(),
        b"{\"schema_version\":1,\"sessions\":{},\"runtime_sessions\":{},\"grant\":true}".to_vec(),
        vec![b' '; 131073],
    ] {
        fs::write(&path, bytes).unwrap();
        let o = command()
            .args(["admission", "budget", "policy-hash", "--policy"])
            .arg(&path)
            .arg("--json")
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2));
    }
    assert_eq!(fs::read_dir(&f.store).unwrap().count(), proof_store_entries);
    assert!(!f.store.join("worktrees").exists());
}
struct Child(Option<std::process::Child>);
impl Child {
    fn output(mut self) -> std::process::Output {
        let until = Instant::now() + Duration::from_secs(20);
        while self.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(20));
        }
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
#[test]
#[ignore = "requires native sandbox and built helper; synthetic provider only"]
fn native_concurrent_roots_commit_once_and_ignore_claimed_zero_usage() {
    let temp = tempfile::tempdir().unwrap();
    let barrier = fs::canonicalize(temp.path()).unwrap();
    let mut a = Fixture::new(
        &format!(
            "while [ ! -f {} ]; do /bin/sleep 0.02; done\nprintf '%s' {}",
            shell_quote(barrier.join("release").to_str().unwrap()),
            shell_quote(&STREAM.replace("synthetic-private-output", "cost=0 tokens=0"))
        ),
        10000,
    );
    let b = Fixture::new("printf 'cost=0 tokens=0'", 10000);
    let mut sandbox = read(&a.root.join("sandbox.json"));
    sandbox["read_roots"] = json!([barrier]);
    write(&a.root.join("sandbox.json"), &sandbox);
    a.rebind_after_config_change();
    let registry = a.root.join("registry");
    let (h, bh) = bind(
        &registry,
        &[(&a.root, &a.store, "one"), (&b.root, &b.store, "two")],
    );
    let da = a.review();
    let db = b.review();
    let mut first = Child(Some(
        a.run()
            .args(["--approve", &da])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    let until = Instant::now() + Duration::from_secs(8);
    loop {
        let status = checked(&mut budget_command("status", &registry, &h, &bh), 0);
        if status["committed_allocation"]["cost_microusd"] == 100 {
            break;
        }
        assert!(
            Instant::now() < until,
            "budget={status}; run={:?}; events={:?}",
            router_runtime::observe(&a.store, RUN_ID),
            router_runtime::observe_events(&a.store, RUN_ID)
        );
        if first.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            panic!("first child exited: {:?}", first.output())
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let admission = router_runtime::AdmissionStore::open(&registry, &h).unwrap();
    let capacity_before = admission.status().unwrap();
    assert_eq!(capacity_before.granted, 1);
    let budget_before = checked(&mut budget_command("status", &registry, &h, &bh), 0);
    assert_eq!(budget_before["reserved_allocation"], json!(amount(0, 0)));
    assert_eq!(
        budget_before["committed_allocation"],
        json!(amount(100, 4500))
    );
    let doctor = checked(
        command()
            .args(["doctor", "--runtime-root"])
            .arg(&a.store)
            .arg("--json"),
        0,
    );
    assert_eq!(doctor["overall"], "pass");
    assert_eq!(doctor["storage_schema_version"], 9);
    assert_eq!(doctor["schema_layout"], "recognized_read_layout");
    assert_eq!(
        doctor["database"]["integrity"],
        "database_integrity_validated"
    );
    assert_eq!(doctor["journal_integrity"], "pass");
    assert_eq!(doctor["owner_lock"], "busy");
    for field in [
        "journal_authenticity",
        "process_liveness",
        "cleanup_authority",
        "shared_admission_accounting",
    ] {
        assert_eq!(doctor[field], "unknown", "{field}");
    }
    assert_eq!(admission.status().unwrap(), capacity_before);
    assert_eq!(
        checked(&mut budget_command("status", &registry, &h, &bh), 0),
        budget_before,
    );
    rejected(
        b.run().args(["--approve", &db]),
        "session_budget.cost.exhausted",
    );
    assert!(!b.store.join("worktrees").exists());
    fs::write(barrier.join("release"), b"release").unwrap();
    let done = parsed(first.output(), 0);
    assert_eq!(done["completion"]["run"]["state"], "verifying");
    let status = checked(&mut budget_command("status", &registry, &h, &bh), 0);
    assert_eq!(status["reserved_allocation"], json!(amount(0, 0)));
    assert_eq!(status["committed_allocation"], json!(amount(100, 4500)));
    assert!(status["observed_tokens"].is_null());
    assert!(status["observed_cost_microusd"].is_null());
    rejected(
        b.run().args(["--approve", &db]),
        "session_budget.cost.exhausted",
    );
}

#[test]
#[ignore = "requires native sandbox, built helper and local SIGKILL; synthetic provider only"]
fn native_sigkill_retains_host_cleanup_authority_and_committed_allocation() {
    let f = Fixture::new(
        "trap '' TERM; while :; do printf x >> src/heartbeat; /bin/sleep 0.02; done",
        10000,
    );
    let registry = f.root.join("registry");
    let (h, b) = bind(&registry, &[(&f.root, &f.store, "fixture")]);
    let digest = f.review();
    let mut child = Child(Some(
        f.run()
            .args(["--approve", &digest])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    let until = Instant::now() + Duration::from_secs(8);
    let heartbeat = loop {
        if let Ok(run) = router_runtime::observe(&f.store, RUN_ID) {
            if let Some(path) = run.worktree {
                let path = std::path::PathBuf::from(path).join("src/heartbeat");
                if fs::metadata(&path).is_ok_and(|m| m.len() > 0) {
                    break path;
                }
            }
        }
        assert!(Instant::now() < until, "worker never emitted heartbeat");
        assert!(child.0.as_mut().unwrap().try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(20));
    };
    child.0.as_mut().unwrap().kill().unwrap();
    let output = child.output();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(output.status.signal(), Some(9));
    let config: AdmissionConfig =
        serde_json::from_value(read(&f.root.join("definition.json"))["admission"].clone()).unwrap();
    let db = rusqlite::Connection::open(f.store.join("runtime.sqlite3")).unwrap();
    let record: String = db
        .query_row(
            "SELECT record FROM attempt_leases WHERE run_id=?1 AND attempt=1",
            [RUN_ID],
            |row| row.get(0),
        )
        .unwrap();
    let record: Value = serde_json::from_str(&record).unwrap();
    assert_eq!(record["host_state_pending"], true);
    let lease = f
        .store
        .join("leases")
        .join(record["name"].as_str().unwrap());
    drop(db);
    // A stopped namespace excludes writers. It cannot stand in for the lost
    // HostState owner or discharge its unfinished filesystem obligation.
    let until = Instant::now() + Duration::from_secs(8);
    loop {
        let marker = fs::read(&lease).unwrap();
        if marker == b"router-runtime-lease-v1:namespace-clean\n"
            || marker == b"router-runtime-lease-v1:group-clean\n"
        {
            break;
        }
        assert!(
            Instant::now() < until,
            "helper did not publish its stop marker"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    for _ in 0..2 {
        let runtime = router_runtime::Runtime::open_with_admission(
            &f.store,
            router_runtime::RuntimeLimits::default(),
            &config,
        )
        .unwrap();
        assert_eq!(
            runtime.cleanup_evidence(RUN_ID).unwrap(),
            ProcessCleanupEvidence::Unknown
        );
        let store = router_runtime::AdmissionStore::open(&registry, &h).unwrap();
        let state = store.session_budget_status("session", &b).unwrap();
        assert_eq!(state.committed_allocation, amount(100, 4500));
        assert_eq!(state.observed_tokens, None);
        assert_eq!(
            store.status().unwrap().granted,
            1,
            "unfinished host cleanup retains capacity across restart"
        );
        assert!(
            fs::read_dir(&f.store).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .as_encoded_bytes()
                    .starts_with(b"host-state-")
            }),
            "the exposed home must remain available for reconciliation"
        );
        drop(runtime);
    }
    let bytes = fs::metadata(&heartbeat).unwrap().len();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(fs::metadata(&heartbeat).unwrap().len(), bytes);
    let status = checked(&mut budget_command("status", &registry, &h, &b), 0);
    assert_eq!(status["committed_allocation"], json!(amount(100, 4500)));
    assert_eq!(status["reserved_allocation"], json!(amount(0, 0)));
}
