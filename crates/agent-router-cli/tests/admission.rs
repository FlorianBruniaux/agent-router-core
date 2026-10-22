#![cfg(all(feature = "claude", any(target_os = "macos", target_os = "linux")))]
#[path = "support/admission_fixture.rs"]
mod admission_fixture;
#[path = "support/native_fixture.rs"]
mod native_fixture;
use native_fixture::*;
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};
fn read(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn rejected(mut command: std::process::Command, code: &str) {
    let o = command.output().unwrap();
    assert_eq!(
        o.status.code(),
        Some(2),
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
fn pinned_shared_review_reopens_and_rejects_legacy_or_another_registry() {
    let fixture = Fixture::metadata("exit 99", 3000);
    let registry = fixture.root.join("admission");
    let (policy, hash) =
        admission_fixture::bind(&registry, &[(&fixture.root, &fixture.store, "fixture")]);
    let digest = fixture.review();
    assert_eq!(fixture.review(), digest);
    let report = checked(
        command()
            .args(["admission", "status", "--registry"])
            .arg(&registry)
            .args(["--expected-policy-sha256", &hash, "--json"]),
        0,
    );
    assert_eq!(report["waiting"], 0);
    assert_eq!(report["granted"], 0);
    let path = fixture.root.join("definition.json");
    let original = read(&path);
    let mut changed = original.clone();
    changed.as_object_mut().unwrap().remove("admission");
    write(&path, &changed);
    rejected(fixture.run(), "runtime.approval.required_or_changed");
    let other = fixture.root.join("other-registry");
    drop(router_runtime::AdmissionStore::create(&other, &policy).unwrap());
    changed = original;
    changed["admission"]["registry"] = json!(other);
    write(&path, &changed);
    rejected(fixture.run(), "runtime.approval.required_or_changed");
    assert!(!fixture.store.join("worktrees").exists());
}
#[test]
fn unknown_provider_mapping_and_wrong_external_pin_do_not_launch() {
    let fixture = Fixture::metadata("exit 99", 3000);
    let registry = fixture.root.join("admission");
    let (_policy, _) =
        admission_fixture::bind(&registry, &[(&fixture.root, &fixture.store, "fixture")]);
    let path = fixture.root.join("definition.json");
    let mut changed = read(&path);
    changed["admission"]["expected_policy_sha256"] = json!("f".repeat(64));
    write(&path, &changed);
    rejected(fixture.run(), "runtime.approval.required_or_changed");
    assert!(!fixture.store.join("worktrees").exists());
    let other = Fixture::metadata("exit 99", 3000);
    let bad = other.root.join("registry");
    assert!(other.store.is_dir(), "fixture provisions its proof store");
    let mut policy = router_types::AdmissionPolicy {
        schema_version: 1,
        global_limit: 1,
        runtimes: std::collections::BTreeMap::from([(
            "fixture".into(),
            router_types::AdmissionRuntimePolicy {
                root_sha256: router_runtime::admission_runtime_root_hash(&other.store).unwrap(),
                limit: 1,
            },
        )]),
        providers: std::collections::BTreeMap::from([("invented".into(), 1)]),
        agents: std::collections::BTreeMap::from([("fixture".into(), 1)]),
        agent_mappings: vec![],
    };
    let plan = read(&other.root.join("plan.json"));
    policy
        .agent_mappings
        .push(router_types::AdmissionAgentMapping {
            runtime_id: "fixture".into(),
            plan_owner: plan["nodes"][0]["owner"].as_str().unwrap().into(),
            candidate_agent: None,
            quota_id: "fixture".into(),
        });
    let hash = router_runtime::admission_policy_hash(&policy).unwrap();
    drop(router_runtime::AdmissionStore::create(&bad, &policy).unwrap());
    let mut d = read(&other.root.join("definition.json"));
    d["admission"] = json!({"schema_version":1,"registry":bad,"expected_policy_sha256":hash,"runtime_id":"fixture"});
    write(&other.root.join("definition.json"), &d);
    rejected(other.run(), "runtime.invalid");
    assert!(!other.store.join("worktrees").exists());
}
#[test]
#[ignore = "requires native sandbox and built helper; synthetic provider only"]
fn native_two_processes_share_provider_capacity_through_git_finalization() {
    native_pair(NativeCase::Complete);
}
#[test]
#[ignore = "requires native sandbox and built helper; synthetic provider only"]
fn native_source_change_while_queued_is_rechecked_before_preparation() {
    native_pair(NativeCase::SourceChanged);
}
struct ChildGuard(Option<std::process::Child>);
impl ChildGuard {
    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.0.as_mut().unwrap().try_wait()
    }
    fn output(mut self) -> std::process::Output {
        let until = Instant::now() + Duration::from_secs(20);
        while self.try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < until,
                "native CLI did not terminate within its test bound"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
#[derive(PartialEq)]
enum NativeCase {
    Complete,
    SourceChanged,
    Cancelled,
}
#[test]
#[ignore = "requires native sandbox and built helper; synthetic provider only"]
fn native_cancel_queued_releases_waiting_ticket_before_other_work_finishes() {
    native_pair(NativeCase::Cancelled);
}
fn native_pair(case: NativeCase) {
    let barrier_temp = tempfile::tempdir().unwrap();
    let barrier = fs::canonicalize(barrier_temp.path()).unwrap();
    let mut a = Fixture::new(
        &format!(
            "while [ ! -f {} ]; do /bin/sleep 0.02; done\nprintf first > src/result.txt\nprintf '%s' {}",
            shell_quote(barrier.join("release").to_str().unwrap()),
            shell_quote(STREAM)
        ),
        10_000,
    );
    let b = Fixture::new(
        &format!(
            "printf second > src/result.txt\nprintf '%s' {}",
            shell_quote(STREAM)
        ),
        10_000,
    );
    let mut config = read(&a.root.join("sandbox.json"));
    config["read_roots"] = json!([barrier]);
    write(&a.root.join("sandbox.json"), &config);
    a.rebind_after_config_change();
    let registry = a.root.join("registry");
    let (_, hash) = admission_fixture::bind(
        &registry,
        &[(&a.root, &a.store, "one"), (&b.root, &b.store, "two")],
    );
    let da = a.review();
    let db = b.review();
    let mut first = ChildGuard(Some(
        a.run()
            .args(["--approve", &da])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    let until = Instant::now() + Duration::from_secs(8);
    while a.status()["run"]["state"] != "running" {
        assert!(Instant::now() < until, "first process never started");
        assert!(first.try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut second = ChildGuard(Some(
        b.run()
            .args(["--approve", &db])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    let until = Instant::now() + Duration::from_secs(8);
    loop {
        let events = router_runtime::observe_events(&b.store, RUN_ID).unwrap();
        if events
            .iter()
            .any(|e| e.kind == "admission.queued" && e.detail.contains("provider_capacity"))
        {
            break;
        }
        assert!(
            Instant::now() < until,
            "second process never entered shared provider queue"
        );
        assert!(second.try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !b.store.join("worktrees").exists(),
        "queue grants no preparation side effects"
    );
    let shared = router_runtime::AdmissionStore::open(&registry, &hash).unwrap();
    assert_eq!(shared.status().unwrap().granted, 1);
    if case == NativeCase::SourceChanged {
        fs::write(b.repo.join("src/base.txt"), b"changed while queued").unwrap();
    }
    let second = if case == NativeCase::Cancelled {
        router_runtime::request_cancel(&b.store, RUN_ID).unwrap();
        let output = second.output();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("runtime.cancelled"));
        assert_eq!(
            shared.status().unwrap().waiting,
            0,
            "cancelled waiter must close its reservation intent without another owner poll"
        );
        assert_eq!(shared.status().unwrap().granted, 1);
        assert_eq!(b.status()["run"]["attempts"], 0);
        None
    } else {
        Some(second)
    };
    fs::write(barrier.join("release"), b"release").unwrap();
    let first = parsed(first.output(), 0);
    if let Some(second) = second {
        let second = second.output();
        if case == NativeCase::SourceChanged {
            assert_eq!(second.status.code(), Some(2));
            assert!(
                String::from_utf8_lossy(&second.stderr).contains("runtime.source.changed_or_dirty"),
                "{}",
                String::from_utf8_lossy(&second.stderr)
            );
            assert_eq!(b.status()["run"]["attempts"], 0);
            assert!(!b.store.join("worktrees").exists());
        } else {
            let second = parsed(second, 0);
            assert_eq!(second["completion"]["run"]["state"], "verifying");
            assert_eq!(second["completion"]["objective"], "unknown");
        }
    }
    assert_eq!(first["completion"]["run"]["state"], "verifying");
    assert_eq!(shared.status().unwrap().granted, 0);
    assert_eq!(shared.status().unwrap().released, 2);
    assert_eq!(first["completion"]["objective"], "unknown");
    let first_events = router_runtime::observe_events(&a.store, RUN_ID).unwrap();
    assert!(
        first_events.iter().any(|e| e.kind == "admission.intent.v1"
            && e.detail.contains("\"captures\":")
            && !e.detail.contains("\"captures\":0")),
        "writer finalization Git must be journaled under this admission"
    );
}
