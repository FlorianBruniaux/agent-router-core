use super::*;
use std::collections::BTreeMap;

pub(super) fn policy() -> AdmissionPolicy {
    AdmissionPolicy {
        schema_version: 1,
        global_limit: 2,
        runtimes: [("one", "a"), ("two", "b")]
            .into_iter()
            .map(|(k, v)| {
                (
                    k.into(),
                    AdmissionRuntimePolicy {
                        root_sha256: v.repeat(64),
                        limit: 2,
                    },
                )
            })
            .collect(),
        providers: BTreeMap::from([("provider".into(), 1), ("other".into(), 2)]),
        agents: BTreeMap::from([("worker".into(), 2)]),
        agent_mappings: vec![AdmissionAgentMapping {
            runtime_id: "one".into(),
            plan_owner: "worker".into(),
            candidate_agent: None,
            quota_id: "worker".into(),
        }],
    }
}
pub(super) fn fixture() -> (tempfile::TempDir, AdmissionStore) {
    let temp = tempfile::tempdir().unwrap();
    let store = AdmissionStore::create(&temp.path().join("registry"), &policy()).unwrap();
    (temp, store)
}
pub(super) fn ticket(
    s: &AdmissionStore,
    owner: &str,
    run: &str,
    group: &str,
    provider: &str,
) -> Ticket {
    let mut t = Ticket {
        session_budget: None,
        id: String::new(),
        binding: s.binding(owner).unwrap(),
        run_id: run.into(),
        definition_hash: "a".repeat(64),
        approval_digest: "b".repeat(64),
        workflow: None,
        admission_sequence: 1,
        cycle: 1,
        attempt: 1,
        group: digest("test", &group).unwrap(),
        provider: provider.into(),
        agent: "worker".into(),
        runtime_limit: 2,
        provider_limit: 2,
        agent_limit: 2,
        workflow_limit: 2,
    };
    t.seal().unwrap();
    t
}
fn release(s: &AdmissionStore, t: &Ticket) {
    s.release(&ReleaseProof::checked(t.clone(), None)).unwrap();
}
#[test]
fn capacity_vector_is_atomic_and_provider_identity_crosses_runtime_owners() {
    let (_temp, s) = fixture();
    let _one = s.owner("one").unwrap();
    let _two = s.owner("two").unwrap();
    let a = ticket(&s, "one", "a", "A", "provider");
    let b = ticket(&s, "two", "b", "B", "provider");
    let c = ticket(&s, "two", "c", "C", "other");
    let _waiters = [&a, &b, &c].map(|t| s.waiter(t).unwrap());
    for t in [&a, &b, &c] {
        s.enqueue(t).unwrap();
    }
    assert!(s.poll(&a).unwrap().is_empty());
    assert_eq!(
        s.poll(&b).unwrap(),
        vec![AdmissionQueueReason::ProviderCapacity]
    );
    assert!(
        s.poll(&c).unwrap().is_empty(),
        "blocked provider must not reserve the remaining global slot"
    );
    assert_eq!(s.status().unwrap().granted, 2);
    release(&s, &a);
    assert!(s.poll(&b).unwrap().is_empty());
}
#[test]
fn round_robin_gives_small_workflow_a_turn_before_backlogged_large_workflow() {
    let (_temp, s) = fixture();
    let _one = s.owner("one").unwrap();
    let _two = s.owner("two").unwrap();
    let a = ticket(&s, "one", "a", "large", "provider");
    let b = ticket(&s, "one", "b", "large", "provider");
    let small = ticket(&s, "two", "small", "small", "provider");
    let _waiters = [&a, &b, &small].map(|t| s.waiter(t).unwrap());
    for t in [&a, &b, &small] {
        s.enqueue(t).unwrap();
    }
    assert!(s.poll(&a).unwrap().is_empty());
    release(&s, &a);
    assert_eq!(s.poll(&b).unwrap(), vec![AdmissionQueueReason::FairTurn]);
    assert!(s.poll(&small).unwrap().is_empty());
    release(&s, &small);
    assert!(s.poll(&b).unwrap().is_empty());
}
#[test]
fn stale_waiter_can_be_removed_but_granted_ticket_survives_owner_loss_and_reopen() {
    let (temp, s) = fixture();
    let one = s.owner("one").unwrap();
    let _two = s.owner("two").unwrap();
    let a = ticket(&s, "one", "a", "A", "provider");
    let stale = ticket(&s, "one", "stale", "A", "other");
    let b = ticket(&s, "two", "b", "B", "provider");
    let _waiters = [&a, &stale, &b].map(|t| s.waiter(t).unwrap());
    for t in [&a, &stale, &b] {
        s.enqueue(t).unwrap();
    }
    assert!(s.poll(&a).unwrap().is_empty());
    drop(one);
    assert_eq!(
        s.poll(&b).unwrap(),
        vec![AdmissionQueueReason::ProviderCapacity]
    );
    assert_eq!(s.status().unwrap().released, 1);
    assert_eq!(s.status().unwrap().granted, 1);
    let reopened = AdmissionStore::open(&temp.path().join("registry"), s.policy_hash()).unwrap();
    assert_eq!(reopened.status().unwrap().granted, 1);
    release(&reopened, &a);
    assert!(s.poll(&b).unwrap().is_empty());
}
#[test]
fn pins_identity_changes_duplicate_owners_and_private_modes_are_refused() {
    let (temp, s) = fixture();
    let owner = s.owner("one").unwrap();
    assert!(matches!(s.owner("one"), Err(RuntimeError::Locked)));
    assert!(matches!(
        AdmissionStore::open(&temp.path().join("registry"), &"f".repeat(64)),
        Err(RuntimeError::Approval)
    ));
    let mut t = ticket(&s, "one", "a", "A", "invented-provider");
    assert!(matches!(s.enqueue(&t), Err(RuntimeError::Approval)));
    t.provider = "provider".into();
    t.seal().unwrap();
    s.enqueue(&t).unwrap();
    t.approval_digest = "c".repeat(64);
    assert!(matches!(
        s.poll(&t),
        Err(RuntimeError::Integrity("admission ticket"))
    ));
    drop(owner);
    let _new_owner = s.owner("one").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        temp.path().join("registry/admission.sqlite3"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(matches!(
        s.status(),
        Err(RuntimeError::Invalid("admission private file"))
    ));
}
#[test]
fn registry_symlinks_and_auxiliary_symlinks_are_refused() {
    let (temp, s) = fixture();
    std::os::unix::fs::symlink(temp.path().join("registry"), temp.path().join("alias")).unwrap();
    assert!(matches!(
        AdmissionStore::open(&temp.path().join("alias"), s.policy_hash()),
        Err(RuntimeError::Io(e))
            if [Some(nix::libc::ELOOP), Some(nix::libc::ENOTDIR)].contains(&e.raw_os_error())
    ));
    drop(s);
    let wal = temp.path().join("registry/admission.sqlite3-wal");
    if wal.exists() {
        std::fs::remove_file(&wal).unwrap();
    }
    std::os::unix::fs::symlink(temp.path().join("outside"), wal).unwrap();
    assert!(matches!(
        AdmissionStore::open(
            &temp.path().join("registry"),
            &admission_policy_hash(&policy()).unwrap()
        ),
        Err(RuntimeError::Invalid("admission private file"))
    ));
}
#[test]
fn subprocess_holder() {
    let Ok(path) = std::env::var("AR_ADMISSION_TEST_ROOT") else {
        return;
    };
    let s =
        AdmissionStore::open(Path::new(&path), &admission_policy_hash(&policy()).unwrap()).unwrap();
    let _owner = s.owner("one").unwrap();
    let t = ticket(&s, "one", "child", "A", "provider");
    let _waiter = s.waiter(&t).unwrap();
    s.enqueue(&t).unwrap();
    assert!(s.poll(&t).unwrap().is_empty());
    // Abrupt exit skips all destructors. Neither OS owner death nor elapsed time
    // may turn this granted ticket into a release proof.
    std::process::exit(0);
}
#[test]
fn process_crash_does_not_reclaim_an_active_provider_reservation() {
    let (temp, s) = fixture();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "admission::tests::subprocess_holder",
            "--nocapture",
        ])
        .env("AR_ADMISSION_TEST_ROOT", temp.path().join("registry"))
        .status()
        .unwrap();
    assert!(status.success());
    let _owner = s.owner("two").unwrap();
    let t = ticket(&s, "two", "parent", "B", "provider");
    let _waiter = s.waiter(&t).unwrap();
    s.enqueue(&t).unwrap();
    assert_eq!(
        s.poll(&t).unwrap(),
        vec![AdmissionQueueReason::ProviderCapacity]
    );
    assert_eq!(s.status().unwrap().granted, 1);
}
#[test]
fn dropping_a_waiter_does_not_stall_a_live_runtime_or_release_a_granted_ticket() {
    let (_temp, s) = fixture();
    let _owner = s.owner("one").unwrap();
    let a = ticket(&s, "one", "aborted", "first", "other");
    let b = ticket(&s, "one", "next", "second", "other");
    let waiter = s.waiter(&a).unwrap();
    let _next = s.waiter(&b).unwrap();
    s.enqueue(&a).unwrap();
    s.enqueue(&b).unwrap();
    assert_eq!(s.poll(&b).unwrap(), vec![AdmissionQueueReason::FairTurn]);
    drop(waiter);
    assert!(s.poll(&b).unwrap().is_empty());
    assert_eq!(s.status().unwrap().released, 1);
    drop(_next);
    assert_eq!(s.status().unwrap().granted, 1);
}
#[test]
fn active_stricter_workflow_limit_cannot_be_enlarged_by_another_phase() {
    let (_temp, s) = fixture();
    let _owner = s.owner("one").unwrap();
    let mut a = ticket(&s, "one", "a", "same", "other");
    a.workflow_limit = 1;
    a.seal().unwrap();
    let b = ticket(&s, "one", "b", "same", "other");
    let _waiters = [&a, &b].map(|t| s.waiter(t).unwrap());
    s.enqueue(&a).unwrap();
    s.enqueue(&b).unwrap();
    assert!(s.poll(&a).unwrap().is_empty());
    assert_eq!(
        s.poll(&b).unwrap(),
        vec![AdmissionQueueReason::WorkflowCapacity]
    );
    release(&s, &a);
    assert!(s.poll(&b).unwrap().is_empty());
}
#[test]
fn subprocess_contender() {
    let Ok(path) = std::env::var("AR_ADMISSION_CONTEND_ROOT") else {
        return;
    };
    let id = std::env::var("AR_ADMISSION_CONTEND_ID").unwrap();
    let root = Path::new(&path);
    let s = AdmissionStore::open(root, &admission_policy_hash(&policy()).unwrap()).unwrap();
    let _owner = s.owner(&id).unwrap();
    let t = ticket(&s, &id, &id, &id, "provider");
    let _waiter = s.waiter(&t).unwrap();
    s.enqueue(&t).unwrap();
    std::fs::write(root.join(format!("ready-{id}")), b"ready").unwrap();
    let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        assert!(std::time::Instant::now() < until);
        if root.join("stop").exists() {
            break;
        }
        if !root.join("start").exists() {
            std::thread::sleep(std::time::Duration::from_millis(5));
            continue;
        }
        let reasons = s.poll(&t).unwrap();
        std::fs::write(
            root.join(format!("result-{id}")),
            serde_json::to_vec(&reasons).unwrap(),
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    release(&s, &t);
}
#[test]
fn competing_processes_never_grant_the_same_provider_slot_twice() {
    let (temp, s) = fixture();
    let root = temp.path().join("registry");
    let mut children = Vec::new();
    for id in ["one", "two"] {
        children.push(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "admission::tests::subprocess_contender",
                    "--nocapture",
                ])
                .env("AR_ADMISSION_CONTEND_ROOT", &root)
                .env("AR_ADMISSION_CONTEND_ID", id)
                .spawn()
                .unwrap(),
        );
    }
    let until = std::time::Instant::now() + std::time::Duration::from_secs(8);
    while !root.join("ready-one").exists() || !root.join("ready-two").exists() {
        assert!(std::time::Instant::now() < until);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    std::fs::write(root.join("start"), b"start").unwrap();
    loop {
        let one = std::fs::read_to_string(root.join("result-one")).unwrap_or_default();
        let two = std::fs::read_to_string(root.join("result-two")).unwrap_or_default();
        if (one == "[]" && (two == "[]" || two.contains("provider_capacity")))
            || (two == "[]" && one.contains("provider_capacity"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < until,
            "contenders did not report a provider decision"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let granted = s.status().unwrap().granted;
    std::fs::write(root.join("stop"), b"stop").unwrap();
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
    assert_eq!(
        granted, 1,
        "same provider must have one reservation across distinct processes"
    );
    assert_eq!(s.status().unwrap().granted, 0);
}
#[test]
fn lifetime_ticket_count_is_not_capped_because_settled_rows_are_pruned() {
    let (_temp, s) = fixture();
    s.lock()
        .unwrap()
        .pragma_update(None, "synchronous", "OFF")
        .unwrap();
    let _one = s.owner("one").unwrap();
    for i in 0..(MAX_TICKETS as usize + 100) {
        let t = ticket(&s, "one", &format!("run-{i}"), &format!("g{i}"), "other");
        let _w = s.waiter(&t).unwrap();
        s.enqueue(&t).unwrap();
        assert!(s.poll(&t).unwrap().is_empty());
        release(&s, &t);
    }
    let status = s.status().unwrap();
    assert_eq!((status.waiting, status.granted), (0, 0));
    // Pruned at enqueue, so the newest release is on top of the retained window.
    assert_eq!(status.released, MAX_RETAINED_RELEASED + 1);
}
#[test]
fn poll_with_nothing_to_change_does_not_take_the_write_lock() {
    let (temp, s) = fixture();
    let _one = s.owner("one").unwrap();
    let _two = s.owner("two").unwrap();
    let a = ticket(&s, "one", "a", "A", "provider");
    let b = ticket(&s, "two", "b", "B", "provider");
    let _waiters = [&a, &b].map(|t| s.waiter(t).unwrap());
    for t in [&a, &b] {
        s.enqueue(t).unwrap();
    }
    let other =
        rusqlite::Connection::open(temp.path().join("registry").join("admission.sqlite3")).unwrap();
    // A grant needs the write lock, held here by another connection.
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(matches!(
        s.poll(&a),
        Err(RuntimeError::Storage(rusqlite::Error::SqliteFailure(f, _)))
            if f.code == rusqlite::ErrorCode::DatabaseBusy
    ));
    other.execute_batch("COMMIT").unwrap();
    assert!(s.poll(&a).unwrap().is_empty());
    // Nothing to grant or release for b: polling proceeds while the lock is held.
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    for _ in 0..3 {
        assert_eq!(
            s.poll(&b).unwrap(),
            vec![AdmissionQueueReason::ProviderCapacity]
        );
    }
    other.execute_batch("COMMIT").unwrap();
}
#[test]
fn policy_change_is_detected_without_reserializing_the_policy() {
    let (temp, s) = fixture();
    let _one = s.owner("one").unwrap();
    let a = ticket(&s, "one", "a", "A", "provider");
    let _waiter = s.waiter(&a).unwrap();
    s.enqueue(&a).unwrap();
    let other =
        rusqlite::Connection::open(temp.path().join("registry").join("admission.sqlite3")).unwrap();
    let mut changed = policy();
    changed.global_limit = 3;
    other
        .execute(
            "UPDATE config SET json=?1",
            [serde_json::to_string(&changed).unwrap()],
        )
        .unwrap();
    assert!(matches!(s.poll(&a), Err(RuntimeError::Approval)));
    // Same policy, different bytes: still not the pinned row.
    other
        .execute(
            "UPDATE config SET json=?1",
            [format!("{} ", serde_json::to_string(&policy()).unwrap())],
        )
        .unwrap();
    assert!(matches!(s.poll(&a), Err(RuntimeError::Approval)));
    other
        .execute(
            "UPDATE config SET json=?1",
            [serde_json::to_string(&policy()).unwrap()],
        )
        .unwrap();
    assert!(s.poll(&a).unwrap().is_empty());
}
