//! Runtime half of the cross-database admission protocol. An intent is durable
//! before enqueue; only this module can construct a release proof.
use super::*;
use crate::admission::{ReleaseProof, Ticket};
use router_types::AdmissionBinding;
use serde::{Deserialize, Serialize};
fn is_false(value: &bool) -> bool {
    !*value
}
const EVENT: &str = "admission.intent.v1";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    ticket: Ticket,
    released: bool,
    git_open: bool,
    captures: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    budget_armed: bool,
}

pub(crate) struct Finalization<'a> {
    store: &'a Store,
    run_id: String,
}
impl Store {
    pub(crate) fn bind_admission(&self, binding: Option<&AdmissionBinding>) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT binding FROM admission_binding WHERE id=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let expected = binding.map(serde_json::to_string).transpose()?;
        if let Some(existing) = existing {
            if Some(&existing) != expected.as_ref() {
                return Err(RuntimeError::Approval);
            }
        } else if let Some(expected) = expected {
            if tx.prepare("SELECT 1 FROM runs LIMIT 1")?.exists([])? {
                return Err(RuntimeError::Invalid(
                    "legacy admission migration requires a new runtime",
                ));
            }
            tx.execute("INSERT INTO admission_binding VALUES(1,?1)", [expected])?;
        }
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn start_admission(&self, mut ticket: Ticket) -> Result<Ticket> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let run = load_opt(&tx, &ticket.run_id)?.ok_or(RuntimeError::NotFound)?;
        if run.state != RunState::Queued
            || run.definition_hash != ticket.definition_hash
            || run.approval_digest != ticket.approval_digest
            || run.workflow != ticket.workflow
        {
            return Err(RuntimeError::Approval);
        }
        let previous = load(&tx, &run)?;
        if previous.as_ref().is_some_and(|i| !i.released) {
            return Err(RuntimeError::Locked);
        }
        ticket.admission_sequence = previous.map_or(1, |i| i.ticket.admission_sequence + 1);
        if ticket.admission_sequence > 4096 {
            return Err(RuntimeError::Limit);
        }
        ticket.cycle = preparation::next_sequence(&tx, &run)?;
        ticket.attempt = run.attempts.checked_add(1).ok_or(RuntimeError::Limit)?;
        ticket.seal()?;
        let intent = Intent {
            ticket: ticket.clone(),
            released: false,
            git_open: false,
            captures: 0,
            budget_armed: false,
        };
        persist(&tx, &run, &intent)?;
        tx.commit()?;
        Ok(ticket)
    }
    pub(crate) fn admission_tickets(&self) -> Result<Vec<Ticket>> {
        let db = self.lock()?;
        let mut q = db.prepare(
            "SELECT summary FROM runs WHERE run_id IN(SELECT run_id FROM admission_intents)",
        )?;
        let values = q
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut tickets = Vec::new();
        for value in values {
            let run = serde_json::from_str(&value)?;
            let i = load(&db, &run)?.ok_or(RuntimeError::CleanupUnknown)?;
            if !i.released {
                tickets.push(i.ticket);
            }
        }
        Ok(tickets)
    }
    pub(crate) fn admission_release_proof(&self, ticket: &Ticket) -> Result<ReleaseProof> {
        let db = self.lock()?;
        let run = load_opt(&db, &ticket.run_id)?.ok_or(RuntimeError::NotFound)?;
        let intent = load(&db, &run)?.ok_or(RuntimeError::CleanupUnknown)?;
        if intent.ticket != *ticket || intent.git_open || intent.released {
            return Err(RuntimeError::CleanupUnknown);
        }
        if !preparation::safe_admission_cycle(&db, &run, ticket.cycle, ticket.attempt)? {
            return Err(RuntimeError::CleanupUnknown);
        }
        let lock = if run.attempts == ticket.attempt {
            // A live lease may become provable after Store::recover marked this
            // run blocked. Keep shared capacity until that proof is persisted
            // and the durable cleanup projection agrees with the release.
            if cleanup_evidence(&db, &run.run_id)? == router_types::ProcessCleanupEvidence::Unknown
            {
                return Err(RuntimeError::CleanupUnknown);
            }
            let record: Option<String> = db
                .query_row(
                    "SELECT record FROM attempt_leases WHERE run_id=?1 AND attempt=?2",
                    params![run.run_id, ticket.attempt],
                    |r| r.get(0),
                )
                .optional()?;
            let record: LeaseRecord =
                serde_json::from_str(&record.ok_or(RuntimeError::CleanupUnknown)?)?;
            Some(
                self.leases
                    .cleanup_proof(&run.run_id, ticket.attempt, &record)?,
            )
        } else if run.attempts.checked_add(1) == Some(ticket.attempt) {
            None
        } else {
            return Err(RuntimeError::CleanupUnknown);
        };
        let mut proof = ReleaseProof::checked(ticket.clone(), lock);
        proof.budget_armed = intent.budget_armed;
        Ok(proof)
    }
    pub(crate) fn arm_session_budget(&self, id: &str) -> Result<Ticket> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let run = load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
        let mut intent = load(&tx, &run)?.ok_or(crate::admission::BudgetError::Unknown)?;
        if run.state != RunState::Running
            || run.attempts != intent.ticket.attempt
            || intent.released
            || intent.budget_armed
            || intent.ticket.session_budget.is_none()
        {
            return Err(crate::admission::BudgetError::Authority.into());
        }
        intent.budget_armed = true;
        persist(&tx, &run, &intent)?;
        tx.commit()?;
        Ok(intent.ticket)
    }
    /// Undoes `arm_session_budget` after the registry refused the dispatch, so
    /// the release refunds the reservation instead of committing it for a run
    /// that never spawned. Safe when the registry did commit: release then reads
    /// the committed reservation state, not this flag.
    pub(crate) fn disarm_session_budget(&self, id: &str) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let run = load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
        let mut intent = load(&tx, &run)?.ok_or(crate::admission::BudgetError::Unknown)?;
        if intent.released || !intent.budget_armed {
            return Ok(());
        }
        intent.budget_armed = false;
        persist(&tx, &run, &intent)?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn admission_released(&self, ticket: &Ticket) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let run = load_opt(&tx, &ticket.run_id)?.ok_or(RuntimeError::NotFound)?;
        let mut intent = load(&tx, &run)?.ok_or(RuntimeError::CleanupUnknown)?;
        if intent.ticket != *ticket || intent.git_open {
            return Err(RuntimeError::CleanupUnknown);
        }
        intent.released = true;
        persist(&tx, &run, &intent)?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn finalization(&self, id: &str) -> Finalization<'_> {
        Finalization {
            store: self,
            run_id: id.into(),
        }
    }
}
impl crate::workspace::CaptureObserver for Finalization<'_> {
    fn before_capture(&self) -> Result<()> {
        self.update(true)
    }
    fn after_capture(&self) -> Result<()> {
        self.update(false)
    }
}
impl Finalization<'_> {
    fn update(&self, opening: bool) -> Result<()> {
        let mut db = self.store.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let run = load_opt(&tx, &self.run_id)?.ok_or(RuntimeError::NotFound)?;
        if let Some(mut intent) = load(&tx, &run)? {
            if intent.released
                || intent.git_open == opening
                || intent.ticket.attempt != run.attempts
                || intent.captures >= 1024
            {
                return Err(RuntimeError::CleanupUnknown);
            }
            intent.git_open = opening;
            if opening {
                intent.captures += 1;
            }
            persist(&tx, &run, &intent)?;
        }
        tx.commit()?;
        Ok(())
    }
}
fn persist(tx: &Transaction<'_>, run: &RunSummary, intent: &Intent) -> Result<()> {
    let json = serde_json::to_string(intent)?;
    tx.execute("INSERT INTO admission_intents VALUES(?1,?2) ON CONFLICT(run_id) DO UPDATE SET record=excluded.record",params![run.run_id,json])?;
    append(tx, run, EVENT, &json)
}
fn load(db: &Connection, run: &RunSummary) -> Result<Option<Intent>> {
    let value: Option<String> = db
        .query_row(
            "SELECT record FROM admission_intents WHERE run_id=?1",
            [&run.run_id],
            |r| r.get(0),
        )
        .optional()?;
    let event: Option<String> = db
        .query_row(
            "SELECT detail FROM events WHERE run_id=?1 AND kind=?2 ORDER BY sequence DESC LIMIT 1",
            params![run.run_id, EVENT],
            |r| r.get(0),
        )
        .optional()?;
    if value != event {
        return Err(RuntimeError::CleanupUnknown);
    }
    let Some(value) = value else {
        return Ok(None);
    };
    if value.len() > 16384 {
        return Err(RuntimeError::Limit);
    }
    let i: Intent = serde_json::from_str(&value)?;
    if i.ticket.run_id != run.run_id
        || i.ticket.definition_hash != run.definition_hash
        || (!i.released && i.ticket.approval_digest != run.approval_digest)
        || i.ticket.workflow != run.workflow
        || i.captures > 1024
    {
        return Err(RuntimeError::CleanupUnknown);
    }
    Ok(Some(i))
}
pub(super) fn require_released(db: &Connection, run: &RunSummary) -> Result<()> {
    if load(db, run)?.is_some_and(|i| !i.released) {
        return Err(RuntimeError::Locked);
    }
    Ok(())
}
pub(super) fn finalization_safe(db: &Connection, run: &RunSummary) -> Result<bool> {
    Ok(load(db, run)?.is_none_or(|i| !i.git_open))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::CaptureObserver;
    pub(super) fn setup() -> (tempfile::TempDir, Store, Ticket) {
        setup_with_budget(None)
    }
    fn setup_with_budget(
        budget: Option<router_types::SessionBudgetConfig>,
    ) -> (tempfile::TempDir, Store, Ticket) {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("runtime")).unwrap();
        let mut run = super::super::tests::summary("admission-run");
        run.definition_hash = "a".repeat(64);
        run.approval_digest = "b".repeat(64);
        store.register(&run).unwrap();
        store
            .transition(
                &run.run_id,
                router_types::RunState::AwaitingApproval,
                "",
                None,
            )
            .unwrap();
        store
            .transition(&run.run_id, router_types::RunState::Queued, "", None)
            .unwrap();
        let ticket = Ticket {
            session_budget: budget,
            id: String::new(),
            binding: AdmissionBinding {
                session_budget: None,
                schema_version: 1,
                registry_sha256: "c".repeat(64),
                policy_sha256: "d".repeat(64),
                runtime_id: "one".into(),
            },
            run_id: run.run_id,
            definition_hash: run.definition_hash,
            approval_digest: run.approval_digest,
            workflow: None,
            admission_sequence: 0,
            cycle: 0,
            attempt: 0,
            group: "e".repeat(64),
            provider: "provider".into(),
            agent: "agent".into(),
            runtime_limit: 1,
            provider_limit: 1,
            agent_limit: 1,
            workflow_limit: 1,
        };
        let t = store.start_admission(ticket).unwrap();
        (temp, store, t)
    }
    #[test]
    fn dispatch_arming_survives_reopen_and_projection_cannot_forge_a_refund() {
        let config = router_types::SessionBudgetConfig {
            schema_version: 1,
            expected_policy_sha256: "f".repeat(64),
            session_id: "session".into(),
            approved_limit: router_types::BudgetAmount {
                cost_microusd: 100,
                tokens: 100,
            },
            attempt_allocation: router_types::BudgetAmount {
                cost_microusd: 60,
                tokens: 60,
            },
        };
        let (temp, store, t) = setup_with_budget(Some(config));
        assert!(store.arm_session_budget(&t.run_id).is_err());
        let prep = store.begin_preparation(&t.run_id).unwrap();
        prep.no_child_yet().unwrap();
        prep.complete().unwrap();
        drop(prep);
        let lease = store.attempt(&t.run_id, 2, true).unwrap().unwrap();
        let held = nix::fcntl::Flock::lock(
            std::fs::File::open(lease).unwrap(),
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        )
        .unwrap();
        store
            .transition(&t.run_id, RunState::Running, "test", None)
            .unwrap();
        assert_eq!(store.arm_session_budget(&t.run_id).unwrap(), t);
        assert!(store.arm_session_budget(&t.run_id).is_err());
        assert!(store.admission_release_proof(&t).is_err());
        drop(held);
        store.confirm_attempt_cleanup(&t.run_id).unwrap();
        drop(store);
        let store = Store::open(&temp.path().join("runtime")).unwrap();
        assert!(store.admission_release_proof(&t).unwrap().budget_armed);
        {
            let db = store.lock().unwrap();
            let json: String = db
                .query_row(
                    "SELECT record FROM admission_intents WHERE run_id=?1",
                    [&t.run_id],
                    |r| r.get(0),
                )
                .unwrap();
            let mut intent: Intent = serde_json::from_str(&json).unwrap();
            intent.budget_armed = false;
            db.execute(
                "UPDATE admission_intents SET record=?1 WHERE run_id=?2",
                params![serde_json::to_string(&intent).unwrap(), t.run_id],
            )
            .unwrap();
        }
        assert!(store.admission_release_proof(&t).is_err());
    }
    #[test]
    fn intent_before_enqueue_has_no_child_but_is_not_reusable_concurrently() {
        let (_temp, store, t) = setup();
        assert!(store.start_admission(t.clone()).is_err());
        assert!(store.admission_release_proof(&t).is_ok());
        let mut forged = t.clone();
        forged.approval_digest = "f".repeat(64);
        assert!(store.admission_release_proof(&forged).is_err());
        store.admission_released(&t).unwrap();
        assert!(store.admission_release_proof(&t).is_err());
    }
    #[test]
    fn open_preparation_window_survives_restart_without_release() {
        let (temp, store, t) = setup();
        let prep = store.begin_preparation(&t.run_id).unwrap();
        prep.no_child_yet().unwrap();
        prep.before_capture().unwrap();
        assert!(store.admission_release_proof(&t).is_err());
        drop(prep);
        drop(store);
        let store = Store::open(&temp.path().join("runtime")).unwrap();
        assert!(store.admission_release_proof(&t).is_err());
        assert!(store.require_cleanup_complete().is_err());
    }
    #[test]
    fn admission_release_waits_for_durable_cleanup_after_lease_unlock() {
        let (temp, store, ticket) = setup();
        let prep = store.begin_preparation(&ticket.run_id).unwrap();
        prep.no_child_yet().unwrap();
        prep.complete().unwrap();
        drop(prep);
        let lease = store.attempt(&ticket.run_id, 2, true).unwrap().unwrap();
        std::fs::write(&lease, b"router-runtime-lease-v1:group-clean\n").unwrap();
        let held = nix::fcntl::Flock::lock(
            std::fs::File::open(&lease).unwrap(),
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        )
        .unwrap();
        store
            .transition(&ticket.run_id, RunState::Running, "test", None)
            .unwrap();
        drop(store);

        // The first reopen observes a held lease and durably blocks cleanup.
        let store = Store::open(&temp.path().join("runtime")).unwrap();
        assert_eq!(
            store.cleanup_evidence(&ticket.run_id).unwrap(),
            router_types::ProcessCleanupEvidence::Unknown
        );
        drop(held);
        // The lease can now be proved live, but that proof has not been
        // reconciled into the runtime journal. Capacity must stay reserved.
        assert!(matches!(
            store.admission_release_proof(&ticket),
            Err(RuntimeError::CleanupUnknown)
        ));
        assert_eq!(
            store.cleanup_evidence(&ticket.run_id).unwrap(),
            router_types::ProcessCleanupEvidence::Unknown
        );
        drop(store);

        let store = Store::open(&temp.path().join("runtime")).unwrap();
        assert_eq!(
            store.cleanup_evidence(&ticket.run_id).unwrap(),
            router_types::ProcessCleanupEvidence::GroupTerminated
        );
        assert!(store.admission_release_proof(&ticket).is_ok());
    }
    #[test]
    fn model_cleanup_is_not_proof_of_finalization_git_cleanup() {
        let (temp, store, t) = setup();
        let prep = store.begin_preparation(&t.run_id).unwrap();
        prep.no_child_yet().unwrap();
        prep.complete().unwrap();
        drop(prep);
        store.attempt(&t.run_id, 2, true).unwrap();
        store.confirm_attempt_cleanup(&t.run_id).unwrap();
        assert!(store.admission_release_proof(&t).is_ok());
        store.finalization(&t.run_id).before_capture().unwrap();
        assert!(store.admission_release_proof(&t).is_err());
        drop(store);
        let store = Store::open(&temp.path().join("runtime")).unwrap();
        assert!(store.admission_release_proof(&t).is_err());
        assert!(store.require_cleanup_complete().is_err());
    }
    #[test]
    fn completed_finalization_and_distinct_preparation_cycles_release_exactly_once() {
        let (_temp, store, t) = setup();
        let prep = store.begin_preparation(&t.run_id).unwrap();
        prep.no_child_yet().unwrap();
        prep.complete().unwrap();
        drop(prep);
        store.attempt(&t.run_id, 2, true).unwrap();
        store.confirm_attempt_cleanup(&t.run_id).unwrap();
        let finish = store.finalization(&t.run_id);
        finish.before_capture().unwrap();
        finish.after_capture().unwrap();
        assert!(store.admission_release_proof(&t).is_ok());
        store.admission_released(&t).unwrap();
        assert!(store.admission_release_proof(&t).is_err());
    }
    #[test]
    fn version_eight_migrates_without_granting_legacy_admission() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        let store = Store::open(&root).unwrap();
        store
            .register(&super::super::tests::summary("legacy"))
            .unwrap();
        drop(store);
        let db = Connection::open(root.join("runtime.sqlite3")).unwrap();
        db.execute_batch(
            "DROP TABLE admission_binding;DROP TABLE admission_intents;PRAGMA user_version=8;",
        )
        .unwrap();
        drop(db);
        let store = Store::open(&root).unwrap();
        let binding = AdmissionBinding {
            session_budget: None,
            schema_version: 1,
            registry_sha256: "a".repeat(64),
            policy_sha256: "b".repeat(64),
            runtime_id: "one".into(),
        };
        assert!(store.bind_admission(Some(&binding)).is_err());
        drop(store);
        let store = Store::open(&root).unwrap();
        assert!(store.bind_admission(None).is_ok());
    }
}
#[cfg(test)]
mod recovery_regressions {
    use super::*;
    #[test]
    fn release_before_preparation_allocates_a_new_admission_identity_on_resume() {
        let (_temp, store, t) = super::tests::setup();
        store.admission_released(&t).unwrap();
        let next = store.start_admission(t.clone()).unwrap();
        assert_ne!(next.id, t.id);
        assert_eq!(next.cycle, t.cycle);
        assert_eq!(next.attempt, t.attempt);
        assert_eq!(next.admission_sequence, t.admission_sequence + 1);
    }
    #[test]
    fn released_intent_survives_retry_approval_change_but_active_intent_does_not() {
        let (_temp, store, t) = super::tests::setup();
        store.admission_released(&t).unwrap();
        {
            let mut db = store.lock().unwrap();
            let tx = db.transaction().unwrap();
            let mut run = load_opt(&tx, &t.run_id).unwrap().unwrap();
            run.approval_digest = "f".repeat(64);
            save(&tx, &run).unwrap();
            tx.commit().unwrap();
        }
        assert!(store.admission_tickets().unwrap().is_empty());
        let mut retry = t;
        retry.approval_digest = "f".repeat(64);
        let retry = store.start_admission(retry).unwrap();
        assert!(store.admission_release_proof(&retry).is_ok());
        {
            let mut db = store.lock().unwrap();
            let tx = db.transaction().unwrap();
            let mut run = load_opt(&tx, &retry.run_id).unwrap().unwrap();
            run.approval_digest = "e".repeat(64);
            save(&tx, &run).unwrap();
            tx.commit().unwrap();
        }
        assert!(store.admission_tickets().is_err());
        assert!(store.admission_release_proof(&retry).is_err());
    }
}
