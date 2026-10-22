use super::tests::{fixture, ticket};
use super::*;
use std::collections::BTreeMap;
fn amount(n: u64) -> BudgetAmount {
    BudgetAmount {
        cost_microusd: n,
        tokens: n,
    }
}
fn policy() -> SessionBudgetPolicy {
    SessionBudgetPolicy {
        schema_version: 1,
        sessions: BTreeMap::from([(
            "session".into(),
            SessionBudgetRule {
                initial_limit: amount(100),
                parent_ceiling: amount(200),
                warning_basis_points: vec![5000, 9000],
            },
        )]),
        runtime_sessions: BTreeMap::from([
            ("one".into(), "session".into()),
            ("two".into(), "session".into()),
        ]),
    }
}
fn setup() -> (tempfile::TempDir, AdmissionStore, String) {
    let (t, mut s) = fixture();
    let h = s.initialize_session_budgets(&policy()).unwrap();
    (t, s, h)
}
fn request(s: &AdmissionStore, owner: &str, id: &str, n: u64) -> Ticket {
    let mut t = ticket(s, owner, id, id, "other");
    t.session_budget = Some(SessionBudgetConfig {
        schema_version: 1,
        expected_policy_sha256: session_budget_policy_hash(&policy()).unwrap(),
        session_id: "session".into(),
        approved_limit: amount(100),
        attempt_allocation: amount(n),
    });
    t.seal().unwrap();
    t
}
fn status(s: &AdmissionStore, h: &str) -> SessionBudgetStatus {
    s.session_budget_status("session", h).unwrap()
}
#[test]
fn vector_reservation_is_atomic_across_owners() {
    let (_t, s, h) = setup();
    let _owners = [s.owner("one").unwrap(), s.owner("two").unwrap()];
    let a = request(&s, "one", "a", 60);
    let b = request(&s, "two", "b", 60);
    let _w = [s.waiter(&a).unwrap(), s.waiter(&b).unwrap()];
    s.enqueue(&a).unwrap();
    s.enqueue(&b).unwrap();
    assert!(s.poll(&a).unwrap().is_empty());
    assert_eq!(
        s.poll(&b).unwrap(),
        vec![
            AdmissionQueueReason::SessionCostBudget,
            AdmissionQueueReason::SessionTokenBudget
        ]
    );
    assert_eq!(s.status().unwrap().granted, 1);
    assert_eq!(status(&s, &h).reserved_allocation, amount(60));
}
#[test]
fn committed_allocation_survives_cleanup_and_reopen_without_observed_usage() {
    let (temp, s, h) = setup();
    let _o = s.owner("one").unwrap();
    let a = request(&s, "one", "a", 60);
    let _w = s.waiter(&a).unwrap();
    s.enqueue(&a).unwrap();
    assert!(s.poll(&a).unwrap().is_empty());
    drop(s.commit_budget(&a).unwrap());
    assert!(matches!(
        s.commit_budget(&a),
        Err(RuntimeError::Budget(BudgetError::Authority))
    ));
    s.release(&ReleaseProof::checked(a.clone(), None)).unwrap();
    s.release(&ReleaseProof::checked(a, None)).unwrap();
    let before = status(&s, &h);
    assert_eq!(before.reserved_allocation, amount(0));
    assert_eq!(before.committed_allocation, amount(60));
    assert_eq!(before.observed_cost_microusd, None);
    assert_eq!(before.observed_tokens, None);
    drop(s);
    let s = AdmissionStore::open(
        &temp.path().join("registry"),
        &admission_policy_hash(&tests::policy()).unwrap(),
    )
    .unwrap();
    assert_eq!(status(&s, &h), before);
}
#[test]
fn only_unarmed_proof_refunds_reservation() {
    let (_t, s, h) = setup();
    let _o = s.owner("one").unwrap();
    for (id, armed) in [("cancel", false), ("crash_armed", true)] {
        let t = request(&s, "one", id, 40);
        let _w = s.waiter(&t).unwrap();
        s.enqueue(&t).unwrap();
        assert!(s.poll(&t).unwrap().is_empty());
        let mut p = ReleaseProof::checked(t, None);
        p.budget_armed = armed;
        s.release(&p).unwrap();
    }
    assert_eq!(status(&s, &h).reserved_allocation, amount(0));
    assert_eq!(status(&s, &h).committed_allocation, amount(40));
}
#[test]
fn exact_review_rejects_stale_state_replay_wrong_digest_and_parent_override() {
    let (_t, s, h) = setup();
    let _o = s.owner("one").unwrap();
    let old = s.review_session_limit("session", &h, amount(160)).unwrap();
    let t = request(&s, "one", "a", 40);
    let _w = s.waiter(&t).unwrap();
    s.enqueue(&t).unwrap();
    s.poll(&t).unwrap();
    assert!(matches!(
        s.approve_session_limit(&old, old.approval_digest()),
        Err(RuntimeError::Budget(BudgetError::Stale))
    ));
    assert!(matches!(
        s.review_session_limit("session", &h, amount(201)),
        Err(RuntimeError::Budget(BudgetError::Policy))
    ));
    let r = s.review_session_limit("session", &h, amount(160)).unwrap();
    assert!(matches!(
        s.approve_session_limit(&r, &"f".repeat(64)),
        Err(RuntimeError::Budget(BudgetError::Authority))
    ));
    s.approve_session_limit(&r, r.approval_digest()).unwrap();
    assert!(matches!(
        s.approve_session_limit(&r, r.approval_digest()),
        Err(RuntimeError::Budget(BudgetError::Stale))
    ));
}
#[test]
fn increased_current_limit_never_enlarges_old_definition_authority() {
    let (_t, s, h) = setup();
    let _owners = [s.owner("one").unwrap(), s.owner("two").unwrap()];
    let a = request(&s, "one", "a", 60);
    let _w = s.waiter(&a).unwrap();
    s.enqueue(&a).unwrap();
    s.poll(&a).unwrap();
    drop(s.commit_budget(&a).unwrap());
    s.release(&ReleaseProof::checked(a, None)).unwrap();
    let r = s.review_session_limit("session", &h, amount(160)).unwrap();
    s.approve_session_limit(&r, r.approval_digest()).unwrap();
    let b = request(&s, "two", "old", 60);
    let _w = s.waiter(&b).unwrap();
    s.enqueue(&b).unwrap();
    assert!(
        s.poll(&b)
            .unwrap()
            .contains(&AdmissionQueueReason::SessionCostBudget)
    );
    let mut c = request(&s, "two", "fresh", 60);
    c.session_budget.as_mut().unwrap().approved_limit = amount(160);
    c.seal().unwrap();
    let _w = s.waiter(&c).unwrap();
    s.enqueue(&c).unwrap();
    assert!(s.poll(&c).unwrap().is_empty());
}
#[test]
fn dispatch_lock_excludes_limit_change_and_reduction_keeps_encumbered_amount() {
    let (_t, s, h) = setup();
    let _o = s.owner("one").unwrap();
    let a = request(&s, "one", "a", 60);
    let _w = s.waiter(&a).unwrap();
    s.enqueue(&a).unwrap();
    s.poll(&a).unwrap();
    let guard = s.commit_budget(&a).unwrap();
    let r = s.review_session_limit("session", &h, amount(20)).unwrap();
    assert!(matches!(
        s.approve_session_limit(&r, r.approval_digest()),
        Err(RuntimeError::Locked)
    ));
    drop(guard);
    s.approve_session_limit(&r, r.approval_digest()).unwrap();
    s.release(&ReleaseProof::checked(a, None)).unwrap();
    assert_eq!(status(&s, &h).committed_allocation, amount(60));
    let b = request(&s, "one", "b", 1);
    let _w = s.waiter(&b).unwrap();
    s.enqueue(&b).unwrap();
    assert!(!s.poll(&b).unwrap().is_empty());
}
#[test]
fn reduced_limit_after_reservation_refuses_dispatch() {
    let (_t, s, h) = setup();
    let _o = s.owner("one").unwrap();
    let a = request(&s, "one", "a", 60);
    let _w = s.waiter(&a).unwrap();
    s.enqueue(&a).unwrap();
    s.poll(&a).unwrap();
    let r = s.review_session_limit("session", &h, amount(20)).unwrap();
    s.approve_session_limit(&r, r.approval_digest()).unwrap();
    assert!(matches!(
        s.commit_budget(&a),
        Err(RuntimeError::Budget(BudgetError::Cost))
    ));
    assert_eq!(status(&s, &h).reserved_allocation, amount(60));
}
#[test]
fn warnings_are_deduplicated_per_revision_and_observation_remains_unknown() {
    let (_t, s, h) = setup();
    let _o = s.owner("one").unwrap();
    let a = request(&s, "one", "a", 60);
    let _w = s.waiter(&a).unwrap();
    s.enqueue(&a).unwrap();
    s.poll(&a).unwrap();
    let before = status(&s, &h).warnings;
    assert_eq!(before.len(), 2);
    drop(s.commit_budget(&a).unwrap());
    s.release(&ReleaseProof::checked(a, None)).unwrap();
    assert_eq!(status(&s, &h).warnings, before);
    assert_eq!(status(&s, &h).observed_tokens, None);
}
#[test]
fn initialization_refuses_live_owner_history_and_missing_assignment() {
    let (_t, mut s) = fixture();
    let owner = s.owner("one").unwrap();
    assert!(matches!(
        s.initialize_session_budgets(&policy()),
        Err(RuntimeError::Locked)
    ));
    drop(owner);
    let a = ticket(&s, "one", "a", "a", "other");
    s.enqueue(&a).unwrap();
    assert!(matches!(
        s.initialize_session_budgets(&policy()),
        Err(RuntimeError::Budget(BudgetError::Authority))
    ));
    let (_t, mut s) = fixture();
    let mut p = policy();
    p.runtime_sessions.remove("two");
    assert!(matches!(
        s.initialize_session_budgets(&p),
        Err(RuntimeError::Budget(BudgetError::Policy))
    ));
    assert!(s.budget_policy.is_none());
}
#[test]
fn unknown_session_absent_authority_and_stale_cached_domain_are_refused() {
    let (temp, mut s) = fixture();
    let stale = AdmissionStore::open(&temp.path().join("registry"), s.policy_hash()).unwrap();
    s.initialize_session_budgets(&policy()).unwrap();
    assert!(matches!(
        stale.status(),
        Err(RuntimeError::Budget(BudgetError::Authority))
    ));
    assert!(matches!(
        s.validate_budget_config("one", None),
        Err(RuntimeError::Budget(BudgetError::Authority))
    ));
    let mut t = request(&s, "one", "a", 1);
    t.session_budget.as_mut().unwrap().session_id = "invented".into();
    t.seal().unwrap();
    assert!(matches!(
        s.enqueue(&t),
        Err(RuntimeError::Budget(BudgetError::Authority))
    ));
    let mut t = request(&s, "one", "b", 1);
    t.session_budget.as_mut().unwrap().expected_policy_sha256 = "f".repeat(64);
    t.seal().unwrap();
    assert!(matches!(
        s.enqueue(&t),
        Err(RuntimeError::Budget(BudgetError::Authority))
    ));
}
#[test]
fn projection_and_reservation_tampering_are_refused() {
    let (_t, s, h) = setup();
    let db = s.lock().unwrap();
    db.execute("UPDATE budget_sessions SET json=replace(json,'\"limit_revision\":1','\"limit_revision\":2')",[]).unwrap();
    drop(db);
    assert!(matches!(
        status_result(&s, &h),
        Err(RuntimeError::Integrity(_))
    ));
}
fn status_result(s: &AdmissionStore, h: &str) -> Result<SessionBudgetStatus> {
    s.session_budget_status("session", h)
}
#[test]
fn token_dimension_and_numeric_bounds_are_independent() {
    let (_t, s, h) = setup();
    let _o = s.owner("one").unwrap();
    let mut t = request(&s, "one", "a", 1);
    t.session_budget.as_mut().unwrap().attempt_allocation.tokens = 101;
    t.session_budget.as_mut().unwrap().approved_limit.tokens = 200;
    t.seal().unwrap();
    let _w = s.waiter(&t).unwrap();
    s.enqueue(&t).unwrap();
    assert_eq!(
        s.poll(&t).unwrap(),
        vec![AdmissionQueueReason::SessionTokenBudget]
    );
    assert_eq!(status(&s, &h).reserved_allocation, amount(0));
    let mut p = policy();
    p.sessions.get_mut("session").unwrap().parent_ceiling.tokens = u64::MAX;
    assert!(matches!(
        session_budget_policy_hash(&p),
        Err(RuntimeError::Budget(BudgetError::Policy))
    ));
    p = policy();
    p.sessions.get_mut("session").unwrap().warning_basis_points = vec![5000, 5000];
    assert!(matches!(
        session_budget_policy_hash(&p),
        Err(RuntimeError::Budget(BudgetError::Policy))
    ));
}
#[test]
fn budget_subprocess_helper() {
    if let Ok(root) = std::env::var("AR_BUDGET_OBSERVER_ROOT") {
        let root = std::path::PathBuf::from(root);
        let store = AdmissionStore::open(
            &root.join("registry"),
            &admission_policy_hash(&tests::policy()).unwrap(),
        )
        .unwrap();
        let state = status(&store, &session_budget_policy_hash(&policy()).unwrap());
        std::fs::write(
            root.join("observation.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        return;
    }

    let Ok(root) = std::env::var("AR_BUDGET_TEST_ROOT") else {
        return;
    };
    let owner = std::env::var("AR_BUDGET_TEST_OWNER").unwrap();
    let root = std::path::PathBuf::from(root);
    let s = AdmissionStore::open(
        &root.join("registry"),
        &admission_policy_hash(&tests::policy()).unwrap(),
    )
    .unwrap();
    let _o = s.owner(&owner).unwrap();
    let t = request(&s, &owner, &owner, 60);
    let _w = s.waiter(&t).unwrap();
    s.enqueue(&t).unwrap();
    std::fs::write(root.join(format!("ready-{owner}")), b"ready").unwrap();
    wait_file(&root.join("go"));
    let reasons = s.poll(&t).unwrap();
    // Publish atomically: the parent treats existence as "result ready".
    let staging = root.join(format!("result-{owner}.staging"));
    std::fs::write(&staging, serde_json::to_vec(&reasons).unwrap()).unwrap();
    std::fs::rename(staging, root.join(format!("result-{owner}"))).unwrap();
    wait_file(&root.join("finish"));
    std::process::exit(0);
}
fn wait_file(path: &std::path::Path) {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !path.exists() {
        assert!(std::time::Instant::now() < end, "barrier not reached");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}
#[test]
fn competing_processes_never_overbook_and_owner_loss_does_not_reset_allocations() {
    let (temp, s, h) = setup();
    let root = temp.path();
    let mut children: Vec<_> = ["one", "two"]
        .into_iter()
        .map(|owner| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "admission::budget_tests::budget_subprocess_helper",
                    "--nocapture",
                ])
                .env("AR_BUDGET_TEST_ROOT", root)
                .env("AR_BUDGET_TEST_OWNER", owner)
                .spawn()
                .unwrap()
        })
        .collect();
    wait_file(&root.join("ready-one"));
    wait_file(&root.join("ready-two"));
    std::fs::write(root.join("go"), b"go").unwrap();
    wait_file(&root.join("result-one"));
    wait_file(&root.join("result-two"));
    let results: Vec<Vec<AdmissionQueueReason>> = ["one", "two"]
        .into_iter()
        .map(|id| {
            serde_json::from_slice(&std::fs::read(root.join(format!("result-{id}"))).unwrap())
                .unwrap()
        })
        .collect();
    std::fs::write(root.join("finish"), b"finish").unwrap();
    for c in &mut children {
        assert!(c.wait().unwrap().success());
    }
    assert_eq!(results.iter().filter(|r| r.is_empty()).count(), 1);
    assert_eq!(status(&s, &h).reserved_allocation, amount(60));
    assert_eq!(s.status().unwrap().granted, 1);
    drop(s);
    let s = AdmissionStore::open(
        &root.join("registry"),
        &admission_policy_hash(&tests::policy()).unwrap(),
    )
    .unwrap();
    assert_eq!(status(&s, &h).reserved_allocation, amount(60));
}

#[test]
fn closing_independent_observer_never_unlinks_a_live_writers_wal() {
    let (temp, s, h) = setup();
    let observe = || {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "admission::budget_tests::budget_subprocess_helper",
                "--nocapture",
            ])
            .env("AR_BUDGET_OBSERVER_ROOT", temp.path())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        serde_json::from_slice::<SessionBudgetStatus>(
            &std::fs::read(temp.path().join("observation.json")).unwrap(),
        )
        .unwrap()
    };
    assert_eq!(observe().committed_allocation, amount(0));
    let _owner = s.owner("one").unwrap();
    let t = request(&s, "one", "a", 60);
    let _w = s.waiter(&t).unwrap();
    s.enqueue(&t).unwrap();
    assert!(s.poll(&t).unwrap().is_empty());
    drop(s.commit_budget(&t).unwrap());
    assert_eq!(status(&s, &h).committed_allocation, amount(60));
    assert_eq!(
        observe().committed_allocation,
        amount(60),
        "an observer must see the committed allocation from the still-live owner"
    );
}
#[test]
fn budget_arithmetic_refuses_overflow_and_underflow_in_each_dimension() {
    use super::budget::{add, sub};
    let limit = i64::MAX as u64;
    let both = |cost_microusd, tokens| BudgetAmount {
        cost_microusd,
        tokens,
    };
    assert_eq!(add(amount(1), amount(2)).unwrap(), amount(3));
    assert_eq!(sub(amount(3), amount(2)).unwrap(), amount(1));
    // u64 wraparound and the i64 storage ceiling are both refused, per dimension.
    for (a, b) in [
        (both(u64::MAX, 0), both(1, 0)),
        (both(0, u64::MAX), both(0, 1)),
        (both(limit, 0), both(1, 0)),
        (both(0, limit), both(0, 1)),
    ] {
        assert!(matches!(add(a, b), Err(RuntimeError::Limit)));
    }
    assert_eq!(add(both(limit - 1, 0), both(1, 0)).unwrap(), both(limit, 0));
    for (a, b) in [(both(0, 5), both(1, 0)), (both(5, 0), both(0, 1))] {
        assert!(matches!(
            sub(a, b),
            Err(RuntimeError::Budget(BudgetError::Unknown))
        ));
    }
}
#[test]
fn pruning_settled_tickets_keeps_committed_accounting_and_replayed_release() {
    let (_t, mut s, h) = setup();
    s.retain_released = 2;
    let _o = s.owner("one").unwrap();
    let mut first = None;
    for i in 0..10 {
        let t = request(&s, "one", &format!("r{i}"), 5);
        let _w = s.waiter(&t).unwrap();
        s.enqueue(&t).unwrap();
        assert!(s.poll(&t).unwrap().is_empty());
        // Every other cycle dispatches (committed), the rest never spawn (refunded).
        if i % 2 == 0 {
            drop(s.commit_budget(&t).unwrap());
        }
        let mut proof = ReleaseProof::checked(t.clone(), None);
        proof.budget_armed = i % 2 == 0;
        s.release(&proof).unwrap();
        first.get_or_insert(t);
        let status = status(&s, &h);
        assert_eq!(status.committed_allocation, amount(5 * (i as u64 / 2 + 1)));
        assert_eq!(status.reserved_allocation, amount(0));
    }
    assert_eq!(s.status().unwrap().released, 3);
    // The oldest ticket is pruned; replaying its armed release is a no-op.
    let first = first.unwrap();
    let mut proof = ReleaseProof::checked(first, None);
    proof.budget_armed = true;
    s.release(&proof).unwrap();
    assert_eq!(status(&s, &h).committed_allocation, amount(25));
    // Reopening re-verifies counters against reservations plus folded rows.
    let reopened =
        AdmissionStore::open(_t.path().join("registry").as_path(), s.policy_hash()).unwrap();
    assert_eq!(
        reopened
            .session_budget_status("session", &h)
            .unwrap()
            .committed_allocation,
        amount(25)
    );
}
#[test]
fn version_two_registry_migrates_to_three_and_future_versions_are_refused() {
    let (t, s, h) = setup();
    let root = t.path().join("registry");
    let version = |s: &AdmissionStore| {
        s.db.lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
            .unwrap()
    };
    assert_eq!(version(&s), 3);
    let pin = s.policy_hash().to_owned();
    let v3 = AdmissionStore::open(&root, &pin).unwrap();
    assert_eq!(
        v3.session_budget_status("session", &h).unwrap().limit,
        amount(100)
    );
    drop(v3);
    let db = rusqlite::Connection::open(root.join("admission.sqlite3")).unwrap();
    db.execute_batch("DROP TABLE budget_folded; DROP TABLE budget_pruned; PRAGMA user_version=2;")
        .unwrap();
    let migrated = AdmissionStore::open(&root, &pin).unwrap();
    assert_eq!(version(&migrated), 3);
    assert!(
        db.query_row("SELECT count(*) FROM budget_folded", [], |r| r
            .get::<_, u32>(0))
            .is_ok()
    );
    assert_eq!(
        migrated.session_budget_status("session", &h).unwrap().limit,
        amount(100)
    );
    drop(migrated);
    db.execute_batch("PRAGMA user_version=4;").unwrap();
    assert!(matches!(
        AdmissionStore::open(&root, &pin),
        Err(RuntimeError::Integrity("admission schema"))
    ));
}
#[test]
fn concurrent_opens_of_a_version_two_registry_both_migrate() {
    let (t, s, _h) = setup();
    let root = t.path().join("registry");
    let pin = s.policy_hash().to_owned();
    drop(s);
    let db = rusqlite::Connection::open(root.join("admission.sqlite3")).unwrap();
    db.execute_batch("DROP TABLE budget_folded; DROP TABLE budget_pruned; PRAGMA user_version=2;")
        .unwrap();
    drop(db);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let opens: Vec<_> = (0..2)
        .map(|_| {
            let (root, pin, barrier) = (root.clone(), pin.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                AdmissionStore::open(&root, &pin).map(|_| ())
            })
        })
        .collect();
    for open in opens {
        open.join().unwrap().unwrap();
    }
}
#[test]
fn armed_release_without_reservation_stays_unknown_unless_the_ticket_was_pruned() {
    let (_t, mut s, h) = setup();
    s.retain_released = 1;
    let _o = s.owner("one").unwrap();
    for i in 0..4 {
        let t = request(&s, "one", &format!("r{i}"), 5);
        let _w = s.waiter(&t).unwrap();
        s.enqueue(&t).unwrap();
        assert!(s.poll(&t).unwrap().is_empty());
        drop(s.commit_budget(&t).unwrap());
        let mut proof = ReleaseProof::checked(t, None);
        proof.budget_armed = true;
        s.release(&proof).unwrap();
    }
    let armed = |t: Ticket| {
        let mut proof = ReleaseProof::checked(t, None);
        proof.budget_armed = true;
        proof
    };
    // Live ticket that never received a reservation.
    let live = request(&s, "one", "live", 5);
    let _w = s.waiter(&live).unwrap();
    s.enqueue(&live).unwrap();
    assert!(matches!(
        s.release(&armed(live)),
        Err(RuntimeError::Budget(BudgetError::Unknown))
    ));
    // Never registered ticket, in a session that does have folded rows.
    let ghost = request(&s, "one", "ghost", 5);
    assert!(matches!(
        s.release(&armed(ghost)),
        Err(RuntimeError::Budget(BudgetError::Unknown))
    ));
    assert_eq!(status(&s, &h).committed_allocation, amount(20));
}
#[test]
fn budget_policy_row_mutated_after_open_is_refused_at_the_next_lock() {
    let (t, s, _) = setup();
    s.status().unwrap();
    let other =
        rusqlite::Connection::open(t.path().join("registry").join("admission.sqlite3")).unwrap();
    let mut changed = policy();
    changed.sessions.get_mut("session").unwrap().initial_limit = amount(1);
    other
        .execute(
            "UPDATE budget_policy SET json=?1",
            [serde_json::to_string(&changed).unwrap()],
        )
        .unwrap();
    assert!(matches!(
        s.status(),
        Err(RuntimeError::Budget(BudgetError::Authority))
    ));
}
