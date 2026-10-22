//! Preparation evidence is independent from model-attempt and escalation evidence.
use super::*;
use crate::leases::CleanupProof;
use router_types::{ProcessCleanupEvidence, WorkflowRunBinding};
use serde::{Deserialize, Serialize};

const EVENT: &str = "preparation.cycle.v1";
const MAX_CYCLES: u32 = 1024;
const MAX_PROBES: usize = 8;
const MAX_CAPTURES: u32 = 1024;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    Untracked,
    LeaseOnly,
    Complete,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    id: String,
    record: LeaseRecord,
    evidence: Option<ProcessCleanupEvidence>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cycle {
    schema_version: u8,
    sequence: u32,
    run_id: String,
    definition_hash: String,
    workflow: Option<WorkflowRunBinding>,
    next_attempt: u32,
    stage: Stage,
    captures: u32,
    probes: Vec<Probe>,
}

/// Only Store can create a live cycle. Neither its identity nor its leases come
/// from caller JSON. No model attempt is consumed by this handle.
pub(crate) struct Preparation<'a> {
    store: &'a Store,
    run_id: String,
    sequence: u32,
}

impl Store {
    pub(crate) fn begin_preparation(&self, id: &str) -> Result<Preparation<'_>> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut run = load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
        if run.state == RunState::Cancelled {
            return Err(RuntimeError::Cancelled);
        }
        if run.state != RunState::Queued {
            return Err(RuntimeError::Transition);
        }
        if cleanup_blocked(&tx, None)? {
            return Err(RuntimeError::CleanupUnknown);
        }
        let previous = cycle(&tx, &run)?;
        if !terminal_safe(&tx, &run)? {
            return Err(RuntimeError::CleanupUnknown);
        }
        let sequence = previous.map_or(1, |c| c.sequence + 1);
        if sequence > MAX_CYCLES {
            return Err(RuntimeError::Limit);
        }
        let record = Cycle {
            schema_version: 1,
            sequence,
            run_id: id.into(),
            definition_hash: run.definition_hash.clone(),
            workflow: run.workflow.clone(),
            next_attempt: run.attempts.checked_add(1).ok_or(RuntimeError::Limit)?,
            stage: Stage::Untracked,
            captures: 0,
            probes: Vec::new(),
        };
        run.state = RunState::Preparing;
        run.failure = None;
        save(&tx, &run)?;
        append(&tx, &run, "transition", "capacity_acquired")?;
        persist(&tx, &run, &record)?;
        tx.commit()?;
        Ok(Preparation {
            store: self,
            run_id: id.into(),
            sequence,
        })
    }
}

impl Preparation<'_> {
    fn update<T>(
        &self,
        f: impl FnOnce(&Transaction<'_>, &RunSummary, &mut Cycle) -> Result<T>,
    ) -> Result<T> {
        let mut db = self.store.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let run = load_opt(&tx, &self.run_id)?.ok_or(RuntimeError::NotFound)?;
        let mut record = cycle(&tx, &run)?.ok_or(RuntimeError::CleanupUnknown)?;
        if run.state != RunState::Preparing
            || record.sequence != self.sequence
            || record.next_attempt != run.attempts.checked_add(1).ok_or(RuntimeError::Limit)?
        {
            return Err(RuntimeError::Integrity("preparation cycle changed"));
        }
        let value = f(&tx, &run, &mut record)?;
        persist(&tx, &run, &record)?;
        tx.commit()?;
        Ok(value)
    }

    /// Executed synchronously by the owning task before any preparation I/O.
    /// Recovery never infers this transition from the absence of child rows.
    pub(crate) fn no_child_yet(&self) -> Result<()> {
        self.update(|_, _, c| {
            if c.stage != Stage::Untracked || c.captures != 0 || !c.probes.is_empty() {
                return Err(RuntimeError::Integrity("preparation already started"));
            }
            c.stage = Stage::LeaseOnly;
            Ok(())
        })
    }

    #[cfg(test)]
    pub(crate) fn register_probe(&self) -> Result<(String, PathBuf)> {
        self.register_probe_with_host_state(false)
    }
    pub(crate) fn register_probe_with_host_state(
        &self,
        host_state: bool,
    ) -> Result<(String, PathBuf)> {
        self.update(|_, _, c| {
            if c.stage != Stage::LeaseOnly || !settled(c) || c.probes.len() >= MAX_PROBES {
                return Err(RuntimeError::CleanupUnknown);
            }
            let id = digest(
                "runtime-preparation-probe-v1",
                &(&c.run_id, c.sequence, c.probes.len()),
            )?;
            let (mut record, path) = self.store.leases.create(&id, 0)?;
            record.require_namespace(host_state);
            c.probes.push(Probe {
                id: id.clone(),
                record,
                evidence: None,
            });
            Ok((id, path))
        })
    }

    #[cfg(test)]
    pub(crate) fn resolve_probe(&self, id: &str) -> Result<ProcessCleanupEvidence> {
        self.resolve_probe_and_state(id, None)
    }
    pub(crate) fn resolve_probe_and_state(
        &self,
        id: &str,
        state: Option<crate::HostState>,
    ) -> Result<ProcessCleanupEvidence> {
        self.resolve_probe_and_state_locked(id, state)
            .map(|proof| proof.evidence)
    }
    pub(crate) fn resolve_probe_and_state_locked(
        &self,
        id: &str,
        state: Option<crate::HostState>,
    ) -> Result<CleanupProof> {
        self.resolve_probe_and_state_observed(id, state, |_| Ok(()))
    }
    pub(crate) fn resolve_probe_and_state_observed(
        &self,
        id: &str,
        state: Option<crate::HostState>,
        observe: impl FnOnce(&CleanupProof) -> Result<()>,
    ) -> Result<CleanupProof> {
        // Return the opaque lock from the transaction closure: it must outlive
        // both the resolved projection and its append-only event commit.
        let proof = self.update(|tx, run, c| {
            let probe = c
                .probes
                .iter_mut()
                .find(|p| p.id == id)
                .ok_or(RuntimeError::Integrity("unregistered preparation probe"))?;
            let proof = self
                .store
                .leases
                .cleanup_proof(id, 0, &probe.record)
                .and_then(|proof| {
                    if probe.record.needs_host_cleanup() && state.is_none() {
                        return Err(RuntimeError::CleanupUnknown);
                    }
                    observe(&proof)?;
                    if let Some(state) = state {
                        state.cleanup_with_proof(&proof)?;
                        probe.record.host_state_cleaned();
                    }
                    Ok(proof)
                });
            match proof {
                Ok(proof) => {
                    probe.evidence = Some(proof.evidence);
                    Ok(Some(proof))
                }
                Err(_) => {
                    tx.execute(
                        "INSERT OR IGNORE INTO cleanup_blocks VALUES(?1)",
                        [&run.run_id],
                    )?;
                    append(tx, run, "preparation.cleanup_unknown", "authority_retained")?;
                    Ok(None)
                }
            }
        })?;
        proof.ok_or(RuntimeError::CleanupUnknown)
    }

    pub(crate) fn complete(&self) -> Result<()> {
        self.update(|_, _, c| {
            if !settled(c) {
                return Err(RuntimeError::CleanupUnknown);
            }
            c.stage = Stage::Complete;
            Ok(())
        })
    }
}

impl crate::workspace::CaptureObserver for Preparation<'_> {
    fn before_capture(&self) -> Result<()> {
        self.update(|_, _, c| {
            if c.stage != Stage::LeaseOnly || !settled(c) || c.captures >= MAX_CAPTURES {
                return Err(RuntimeError::CleanupUnknown);
            }
            c.captures += 1;
            c.stage = Stage::Untracked;
            Ok(())
        })
    }
    fn after_capture(&self) -> Result<()> {
        self.update(|tx, run, c| {
            if c.stage != Stage::Untracked || c.captures == 0 {
                return Err(RuntimeError::Integrity("no open Git capture"));
            }
            c.stage = Stage::LeaseOnly;
            append(tx, run, "preparation.git_returned", &c.captures.to_string())?;
            Ok(())
        })
    }
}

fn persist(tx: &Transaction<'_>, run: &RunSummary, c: &Cycle) -> Result<()> {
    let json = serde_json::to_string(c)?;
    tx.execute("INSERT INTO preparation_cycles(run_id,sequence,record) VALUES(?1,?2,?3) ON CONFLICT(run_id,sequence) DO UPDATE SET record=excluded.record",
        params![run.run_id, c.sequence, json])?;
    append(tx, run, EVENT, &json)
}

fn cycle(db: &Connection, run: &RunSummary) -> Result<Option<Cycle>> {
    let value: Option<(u32, String)> = db.query_row(
        "SELECT sequence,record FROM preparation_cycles WHERE run_id=?1 ORDER BY sequence DESC LIMIT 1",
        [&run.run_id], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
    let anchor: Option<String> = db
        .query_row(
            "SELECT detail FROM events WHERE run_id=?1 AND kind=?2 ORDER BY sequence DESC LIMIT 1",
            params![run.run_id, EVENT],
            |r| r.get(0),
        )
        .optional()?;
    match (value, anchor) {
        (None, None) => Ok(None),
        (Some((sequence, value)), Some(anchor)) if value == anchor && value.len() <= 16_384 => {
            let c: Cycle =
                serde_json::from_str(&value).map_err(|_| RuntimeError::CleanupUnknown)?;
            if c.schema_version != 1
                || c.sequence != sequence
                || sequence == 0
                || sequence > MAX_CYCLES
                || c.run_id != run.run_id
                || c.definition_hash != run.definition_hash
                || c.workflow != run.workflow
                || c.probes.len() > MAX_PROBES
                || c.captures > MAX_CAPTURES
                || c.next_attempt == 0
                || !(c.next_attempt == run.attempts
                    || Some(c.next_attempt) == run.attempts.checked_add(1))
            {
                return Err(RuntimeError::CleanupUnknown);
            }
            for (index, p) in c.probes.iter().enumerate() {
                if p.id
                    != digest(
                        "runtime-preparation-probe-v1",
                        &(&c.run_id, c.sequence, index),
                    )?
                    || p.evidence.is_some_and(|e| !safe_evidence(e))
                {
                    return Err(RuntimeError::CleanupUnknown);
                }
            }
            Ok(Some(c))
        }
        _ => Err(RuntimeError::CleanupUnknown),
    }
}

fn safe_evidence(e: ProcessCleanupEvidence) -> bool {
    matches!(
        e,
        ProcessCleanupEvidence::NotStarted
            | ProcessCleanupEvidence::GroupTerminated
            | ProcessCleanupEvidence::NamespaceTerminated
    )
}
fn settled(c: &Cycle) -> bool {
    c.stage != Stage::Untracked
        && c.probes
            .iter()
            .all(|p| p.evidence.is_some_and(safe_evidence))
}

/// Used by terminal transitions, with no inference from terminal state itself.
pub(super) fn terminal_safe(db: &Connection, run: &RunSummary) -> Result<bool> {
    match cycle(db, run) {
        Ok(Some(c)) => Ok(settled(&c)),
        Ok(None) => {
            // A run that never entered Preparing needs no preparation proof.
            Ok(!db
                .prepare("SELECT 1 FROM events WHERE run_id=?1 AND state=?2 LIMIT 1")?
                .exists(params![
                    run.run_id,
                    serde_json::to_string(&RunState::Preparing)?
                ])?)
        }
        Err(RuntimeError::CleanupUnknown) => Ok(false),
        Err(e) => Err(e),
    }
}

pub(super) fn require_complete(db: &Connection, run: &RunSummary) -> Result<()> {
    match cycle(db, run)? {
        Some(c)
            if c.stage == Stage::Complete
                && settled(&c)
                && Some(c.next_attempt) == run.attempts.checked_add(1) =>
        {
            Ok(())
        }
        _ => Err(RuntimeError::CleanupUnknown),
    }
}

/// Reconcile probes while retaining every successful lease lock until the outer
/// recovery transaction commits. Open Git windows cannot be reconstructed.
pub(super) fn recover(
    store: &Store,
    tx: &Transaction<'_>,
    run: &RunSummary,
    locks: &mut Vec<CleanupProof>,
) -> Result<bool> {
    let mut c = match cycle(tx, run) {
        Ok(Some(c)) => c,
        Ok(None) | Err(RuntimeError::CleanupUnknown) => return Ok(false),
        Err(e) => return Err(e),
    };
    let mut changed = false;
    for probe in &mut c.probes {
        if probe.evidence.is_some() {
            continue;
        }
        if let Ok(proof) = store.leases.recovery_proof(&probe.id, 0, &probe.record) {
            probe.evidence = Some(proof.evidence);
            locks.push(proof);
            changed = true;
        }
    }
    if changed {
        persist(tx, run, &c)?;
    }
    Ok(settled(&c))
}

/// Absence of a model lease is safe only before this cycle's next attempt.
pub(super) fn no_model_started(db: &Connection, run: &RunSummary) -> Result<bool> {
    match cycle(db, run) {
        Ok(Some(c)) => Ok(Some(c.next_attempt) == run.attempts.checked_add(1)),
        Ok(None) | Err(RuntimeError::CleanupUnknown) => Ok(false),
        Err(e) => Err(e),
    }
}

/// A ticket pins the next preparation cycle, not merely the next model attempt.
pub(super) fn next_sequence(db: &Connection, run: &RunSummary) -> Result<u32> {
    let n = cycle(db, run)?.map_or(1, |c| c.sequence + 1);
    if n > MAX_CYCLES {
        return Err(RuntimeError::Limit);
    }
    Ok(n)
}
pub(super) fn safe_admission_cycle(
    db: &Connection,
    run: &RunSummary,
    sequence: u32,
    attempt: u32,
) -> Result<bool> {
    match cycle(db, run)? {
        Some(c) if c.sequence == sequence => Ok(c.next_attempt == attempt && settled(&c)),
        Some(c) if c.sequence.checked_add(1) == Some(sequence) => {
            Ok(run.attempts.checked_add(1) == Some(attempt) && settled(&c))
        }
        None => Ok(sequence == 1 && run.attempts == 0 && attempt == 1 && terminal_safe(db, run)?),
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::{self, CaptureObserver};

    fn queued(store: &Store, id: &str) {
        store.register(&super::super::tests::summary(id)).unwrap();
        store
            .transition(id, RunState::AwaitingApproval, "", None)
            .unwrap();
        store.transition(id, RunState::Queued, "", None).unwrap();
    }
    fn lease_only(store: &Store) -> Preparation<'_> {
        queued(store, "run");
        let prep = store.begin_preparation("run").unwrap();
        prep.no_child_yet().unwrap();
        prep
    }
    fn retained(store: &Store) {
        assert!(matches!(
            store.require_cleanup_complete(),
            Err(RuntimeError::CleanupUnknown)
        ));
        assert_eq!(
            store.cleanup_evidence("run").unwrap(),
            ProcessCleanupEvidence::Unknown
        );
    }

    #[test]
    fn registered_probes_reconcile_only_exact_private_unlocked_leases() {
        for status in [
            "pending",
            "group-clean",
            "namespace-clean",
            "active",
            "corrupt",
            "absent",
            "replaced",
            "symlink",
            "held",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("runtime");
            let store = Store::open(&root).unwrap();
            let prep = lease_only(&store);
            let (_, path) = prep.register_probe().unwrap();
            let moved = path.with_extension("original");
            let mut held = None;
            match status {
                "absent" => fs::remove_file(&path).unwrap(),
                "replaced" => {
                    fs::rename(&path, &moved).unwrap();
                    fs::write(&path, b"router-runtime-lease-v1:group-clean\n").unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                }
                "symlink" => {
                    fs::rename(&path, &moved).unwrap();
                    std::os::unix::fs::symlink(&moved, &path).unwrap();
                }
                "held" => {
                    held = Some(
                        Flock::lock(File::open(&path).unwrap(), FlockArg::LockExclusiveNonblock)
                            .unwrap(),
                    )
                }
                s => fs::write(&path, format!("router-runtime-lease-v1:{s}\n")).unwrap(),
            }
            drop(prep);
            drop(store);
            let store = Store::open(&root).unwrap();
            let safe = matches!(status, "pending" | "group-clean" | "namespace-clean");
            assert_eq!(store.require_cleanup_complete().is_ok(), safe, "{status}");
            assert_eq!(store.get("run").unwrap().attempts, 0);
            assert!(store.escalation_history("run").unwrap().attempts.is_empty());
            if status == "pending" {
                assert_eq!(
                    fs::read(&path).unwrap(),
                    b"router-runtime-lease-v1:recovered\n"
                );
            }
            let count = store.events().unwrap().len();
            drop(store);
            let store = Store::open(&root).unwrap();
            assert_eq!(store.require_cleanup_complete().is_ok(), safe);
            assert_eq!(
                store.events().unwrap().len(),
                count,
                "reconciliation must be idempotent"
            );
            drop(held);
        }
    }

    #[test]
    fn confirmed_probe_host_cleanup_survives_restart() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap().join("runtime");
        let store = Store::open(&root).unwrap();
        let prep = lease_only(&store);
        let (id, path) = prep.register_probe_with_host_state(true).unwrap();
        let mut state =
            crate::HostState::create(&root, "codex", &std::collections::BTreeMap::new())
                .unwrap()
                .unwrap();
        let home = state.path().to_owned();
        state.arm_cleanup(Some(&path), true).unwrap();
        fs::write(&path, b"router-runtime-lease-v1:namespace-clean\n").unwrap();
        assert_eq!(
            prep.resolve_probe_and_state(&id, Some(state)).unwrap(),
            ProcessCleanupEvidence::NamespaceTerminated
        );
        assert!(!home.exists());
        prep.complete().unwrap();
        store
            .transition("run", RunState::Cancelled, "fixture-complete", None)
            .unwrap();
        drop(prep);
        drop(store);
        Store::open(&root)
            .unwrap()
            .require_cleanup_complete()
            .unwrap();
    }

    #[test]
    fn group_only_probe_cannot_settle_exposed_host_state() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap().join("runtime");
        let store = Store::open(&root).unwrap();
        let prep = lease_only(&store);
        let (id, path) = prep.register_probe_with_host_state(true).unwrap();
        let mut state =
            crate::HostState::create(&root, "codex", &std::collections::BTreeMap::new())
                .unwrap()
                .unwrap();
        let home = state.path().to_owned();
        state.arm_cleanup(Some(&path), false).unwrap();
        fs::write(&path, b"router-runtime-lease-v1:group-clean\n").unwrap();
        assert!(matches!(
            prep.resolve_probe_and_state(&id, Some(state)),
            Err(RuntimeError::CleanupUnknown)
        ));
        assert!(home.exists());
        assert!(prep.complete().is_err());
        retained(&store);
        drop(prep);
        drop(store);
        let store = Store::open(&root).unwrap();
        retained(&store);
    }

    #[test]
    fn refused_probe_home_cleanup_survives_restart() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap().join("runtime");
        let store = Store::open(&root).unwrap();
        let prep = lease_only(&store);
        let (id, path) = prep.register_probe_with_host_state(true).unwrap();
        let mut state =
            crate::HostState::create(&root, "codex", &std::collections::BTreeMap::new())
                .unwrap()
                .unwrap();
        let home = state.path().to_owned();
        state.arm_cleanup(Some(&path), false).unwrap();
        fs::rename(&home, root.join("moved-home")).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
        fs::write(home.join("foreign"), b"keep").unwrap();
        assert!(matches!(
            prep.resolve_probe_and_state(&id, Some(state)),
            Err(RuntimeError::CleanupUnknown)
        ));
        assert!(home.exists());
        assert!(prep.complete().is_err());
        retained(&store);
        drop(prep);
        drop(store);
        let store = Store::open(&root).unwrap();
        retained(&store);
    }

    #[test]
    fn failed_locked_observation_cannot_discharge_host_cleanup_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap().join("runtime");
        let store = Store::open(&root).unwrap();
        let prep = lease_only(&store);
        let (id, path) = prep.register_probe_with_host_state(true).unwrap();
        let mut state = crate::HostState::create(&root, "codex", &Default::default())
            .unwrap()
            .unwrap();
        let home = state.path().to_owned();
        state.arm_cleanup(Some(&path), true).unwrap();
        fs::write(&path, b"router-runtime-lease-v1:namespace-clean\n").unwrap();
        let mut observed = false;
        assert!(matches!(
            prep.resolve_probe_and_state_observed(&id, Some(state), |proof| {
                observed = true;
                assert_eq!(proof.evidence, ProcessCleanupEvidence::NamespaceTerminated);
                assert!(
                    Flock::lock(File::open(&path).unwrap(), FlockArg::LockExclusiveNonblock)
                        .is_err()
                );
                assert!(home.exists(), "observation must precede disposal");
                Err(RuntimeError::Integrity("retained bundle changed"))
            }),
            Err(RuntimeError::CleanupUnknown)
        ));
        assert!(observed);
        assert!(home.exists());
        retained(&store);
        drop(prep);
        drop(store);
        let store = Store::open(&root).unwrap();
        retained(&store);
        assert_eq!(store.get("run").unwrap().attempts, 0);
    }

    #[test]
    fn no_marker_and_open_git_window_never_inherit_probe_cleanup() {
        for open_git in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("runtime");
            let store = Store::open(&root).unwrap();
            queued(&store, "run");
            let prep = store.begin_preparation("run").unwrap();
            if open_git {
                prep.no_child_yet().unwrap();
                let (id, _) = prep.register_probe().unwrap();
                assert_eq!(
                    prep.resolve_probe(&id).unwrap(),
                    ProcessCleanupEvidence::NotStarted
                );
                prep.before_capture().unwrap();
            }
            drop(prep);
            drop(store);
            let store = Store::open(&root).unwrap();
            retained(&store);
            assert_eq!(store.get("run").unwrap().attempts, 0);
        }
    }

    #[test]
    fn terminal_cancel_keeps_unknown_and_reconciles_late_exact_proof() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        let store = Store::open(&root).unwrap();
        let prep = lease_only(&store);
        queued(&store, "next");
        store
            .writer_lock("run", "/fixture", &["src".into()])
            .unwrap();
        let (id, path) = prep.register_probe().unwrap();
        fs::write(&path, b"router-runtime-lease-v1:active\n").unwrap();
        assert!(matches!(
            prep.resolve_probe(&id),
            Err(RuntimeError::CleanupUnknown)
        ));
        store
            .transition("run", RunState::Cancelled, "cancelled", None)
            .unwrap();
        retained(&store);
        assert!(matches!(
            store.writer_lock("next", "/fixture", &["src".into()]),
            Err(RuntimeError::Scope)
        ));
        drop(prep);
        drop(store);
        let store = Store::open(&root).unwrap();
        retained(&store);
        assert_eq!(store.get("run").unwrap().state, RunState::Cancelled);
        drop(store);
        fs::write(&path, b"router-runtime-lease-v1:group-clean\n").unwrap();
        let store = Store::open(&root).unwrap();
        store.require_cleanup_complete().unwrap();
        store
            .writer_lock("next", "/fixture", &["src".into()])
            .unwrap();
        assert_eq!(store.get("run").unwrap().state, RunState::Cancelled);
        assert_eq!(store.get("run").unwrap().attempts, 0);
    }

    #[test]
    fn clean_content_cannot_release_authority_before_the_helper_unlocks() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        let store = Store::open(&root).unwrap();
        let prep = lease_only(&store);
        let (_, path) = prep.register_probe().unwrap();
        let held =
            Flock::lock(File::open(&path).unwrap(), FlockArg::LockExclusiveNonblock).unwrap();
        // Publication and unlock are distinct operations in the helper.
        fs::write(&path, b"router-runtime-lease-v1:group-clean\n").unwrap();
        drop(prep);
        drop(store);
        let store = Store::open(&root).unwrap();
        retained(&store);
        drop(store);
        drop(held);
        let store = Store::open(&root).unwrap();
        store.require_cleanup_complete().unwrap();
        assert_eq!(store.get("run").unwrap().attempts, 0);
    }

    #[test]
    fn restored_probe_inode_reconciles_after_a_missing_path() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        let store = Store::open(&root).unwrap();
        let prep = lease_only(&store);
        let (_, path) = prep.register_probe().unwrap();
        let moved = root.join("moved");
        fs::rename(&path, &moved).unwrap();
        drop(prep);
        drop(store);
        let store = Store::open(&root).unwrap();
        retained(&store);
        drop(store);
        fs::write(&moved, b"router-runtime-lease-v1:group-clean\n").unwrap();
        fs::rename(&moved, &path).unwrap();
        let store = Store::open(&root).unwrap();
        store.require_cleanup_complete().unwrap();
        assert_eq!(store.get("run").unwrap().attempts, 0);
    }

    #[test]
    fn previous_model_cleanup_does_not_cover_the_next_preparation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        let store = Store::open(&root).unwrap();
        let prep = lease_only(&store);
        prep.complete().unwrap();
        store.attempt("run", 3, true).unwrap();
        store.confirm_attempt_cleanup("run").unwrap();
        store
            .transition("run", RunState::Running, "", None)
            .unwrap();
        store.finish_attempt("run", "failed").unwrap();
        store
            .transition("run", RunState::Failed, "", Some(RunFailure::Crash))
            .unwrap();
        store.retry_expecting("run", 3, None).unwrap();
        store.transition("run", RunState::Queued, "", None).unwrap();
        let prep2 = store.begin_preparation("run").unwrap();
        prep2.no_child_yet().unwrap();
        let (_, path) = prep2.register_probe().unwrap();
        fs::write(&path, b"router-runtime-lease-v1:active\n").unwrap();
        assert_eq!(prep2.sequence, 2);
        assert!(
            prep.before_capture().is_err(),
            "old handle cannot mutate new cycle"
        );
        drop(prep2);
        drop(prep);
        drop(store);
        let store = Store::open(&root).unwrap();
        retained(&store);
        assert_eq!(store.get("run").unwrap().attempts, 1);
    }

    #[test]
    fn safe_preparation_never_covers_an_active_main_attempt() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        let store = Store::open(&root).unwrap();
        let prep = lease_only(&store);
        prep.complete().unwrap();
        let path = store.attempt("run", 2, true).unwrap().unwrap();
        fs::write(&path, b"router-runtime-lease-v1:active\n").unwrap();
        drop(prep);
        drop(store);
        let store = Store::open(&root).unwrap();
        retained(&store);
    }

    #[test]
    fn projection_and_definition_tampering_cannot_be_cleanup_authority() {
        for mutation in ["record", "missing", "definition"] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("runtime");
            let store = Store::open(&root).unwrap();
            let prep = lease_only(&store);
            prep.complete().unwrap();
            let db = store.lock().unwrap();
            match mutation {
                "record" => {
                    db.execute("UPDATE preparation_cycles SET record=replace(record,'complete','lease_only')", []).unwrap();
                }
                "missing" => {
                    db.execute("DELETE FROM preparation_cycles", []).unwrap();
                }
                _ => {
                    let mut run = load_opt(&db, "run").unwrap().unwrap();
                    run.definition_hash = "d".repeat(64);
                    db.execute(
                        "UPDATE runs SET summary=?1",
                        [serde_json::to_string(&run).unwrap()],
                    )
                    .unwrap();
                }
            }
            drop(db);
            drop(prep);
            drop(store);
            let store = Store::open(&root).unwrap();
            retained(&store);
        }
    }

    #[test]
    fn recovery_holds_probe_lock_until_commit_and_rolls_back_failed_commit() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        let store = Store::open(&root).unwrap();
        let prep = lease_only(&store);
        let (_, path) = prep.register_probe().unwrap();
        let mut db = store.lock().unwrap();
        let tx = db.transaction().unwrap();
        let run = load_opt(&tx, "run").unwrap().unwrap();
        let mut locks = Vec::new();
        assert!(recover(&store, &tx, &run, &mut locks).unwrap());
        assert!(Flock::lock(File::open(&path).unwrap(), FlockArg::LockExclusiveNonblock).is_err());
        tx.rollback().unwrap();
        drop(locks);
        assert!(
            cycle(&db, &run).unwrap().unwrap().probes[0]
                .evidence
                .is_none()
        );
        drop(db);
        drop(prep);
        drop(store);
        let store = Store::open(&root).unwrap();
        store.require_cleanup_complete().unwrap();
        assert_eq!(store.get("run").unwrap().attempts, 0);
    }

    #[test]
    fn preparation_sequence_is_independent_of_attempts_and_starts_atomically() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        let store = Store::open(&root).unwrap();
        queued(&store, "run");
        store.lock().unwrap().execute_batch("CREATE TRIGGER fail_start BEFORE INSERT ON preparation_cycles BEGIN SELECT RAISE(ABORT,'test start failure'); END;").unwrap();
        let count = store.events().unwrap().len();
        assert!(store.begin_preparation("run").is_err());
        assert_eq!(store.get("run").unwrap().state, RunState::Queued);
        assert_eq!(store.events().unwrap().len(), count);
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_start")
            .unwrap();
        let first = store.begin_preparation("run").unwrap();
        first.no_child_yet().unwrap();
        drop(first);
        drop(store);
        let store = Store::open(&root).unwrap();
        store.require_cleanup_complete().unwrap();
        store.retry_expecting("run", 2, None).unwrap();
        store.transition("run", RunState::Queued, "", None).unwrap();
        let second = store.begin_preparation("run").unwrap();
        second.no_child_yet().unwrap();
        let run = store.get("run").unwrap();
        let c = cycle(&store.lock().unwrap(), &run).unwrap().unwrap();
        assert_eq!(c.sequence, 2);
        assert_eq!(c.next_attempt, 1);
        assert_eq!(run.attempts, 0);
        assert!(store.escalation_history("run").unwrap().attempts.is_empty());
    }

    #[test]
    fn unresolved_probe_prevents_completion_and_main_attempt_reservation() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("runtime")).unwrap();
        let prep = lease_only(&store);
        prep.register_probe().unwrap();
        assert!(matches!(prep.complete(), Err(RuntimeError::CleanupUnknown)));
        assert!(matches!(
            store.attempt("run", 2, true),
            Err(RuntimeError::CleanupUnknown)
        ));
        assert_eq!(store.get("run").unwrap().attempts, 0);
    }

    #[test]
    fn schema_seven_running_with_clean_model_lease_is_not_backfilled() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        let store = Store::open(&root).unwrap();
        queued(&store, "run");
        store
            .transition("run", RunState::Preparing, "legacy", None)
            .unwrap();
        let (record, path) = store.leases.create("run", 1).unwrap();
        fs::write(path, b"router-runtime-lease-v1:group-clean\n").unwrap();
        {
            let mut db = store.lock().unwrap();
            let tx = db.transaction().unwrap();
            let mut run = load_opt(&tx, "run").unwrap().unwrap();
            run.attempts = 1;
            save(&tx, &run).unwrap();
            tx.execute("INSERT INTO run_attempts VALUES('run',1,'started')", [])
                .unwrap();
            tx.execute(
                "INSERT INTO attempt_leases(run_id,attempt,record) VALUES('run',1,?1)",
                [serde_json::to_string(&record).unwrap()],
            )
            .unwrap();
            append(&tx, &run, "attempt.started", "").unwrap();
            tx.commit().unwrap();
        }
        store
            .transition("run", RunState::Running, "legacy", None)
            .unwrap();
        drop(store);
        let db = Connection::open(root.join("runtime.sqlite3")).unwrap();
        db.execute_batch("DROP TABLE admission_intents; DROP TABLE admission_binding; DROP TABLE preparation_cycles; PRAGMA user_version=7;")
            .unwrap();
        drop(db);
        let store = Store::open(&root).unwrap();
        retained(&store);
        let db = store.lock().unwrap();
        assert_eq!(
            db.pragma_query_value::<u32, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            9
        );
        assert_eq!(
            db.query_row::<u32, _, _>("SELECT count(*) FROM preparation_cycles", [], |r| r.get(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row::<u32, _, _>("SELECT resolved FROM attempt_leases", [], |r| r.get(0))
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn git_wrappers_observe_config_and_operations_and_close_before_business_errors() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let status = std::process::Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .arg(&repo)
            .status()
            .unwrap();
        assert!(status.success());
        let store = Store::open(&temp.path().join("runtime")).unwrap();
        let prep = lease_only(&store);
        let result =
            workspace::source_state_observed(&fs::canonicalize(&repo).unwrap(), Some(&prep)).await;
        assert!(
            matches!(result, Err(RuntimeError::Process)),
            "empty repository has no HEAD"
        );
        let run = store.get("run").unwrap();
        let c = cycle(&store.lock().unwrap(), &run).unwrap().unwrap();
        assert_eq!(
            c.captures, 6,
            "three Git calls each include the preliminary config capture"
        );
        assert!(settled(&c));
        fs::write(repo.join("dirty"), "not committed").unwrap();
        assert!(matches!(
            workspace::source_state_observed(&fs::canonicalize(&repo).unwrap(), Some(&prep)).await,
            Err(RuntimeError::SourceChanged)
        ));
        store
            .transition(
                "run",
                RunState::Blocked,
                "source_changed",
                Some(RunFailure::Policy),
            )
            .unwrap();
        store.require_cleanup_complete().unwrap();
    }

    #[tokio::test]
    async fn failed_observer_commit_prevents_even_the_preliminary_git_capture() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("runtime")).unwrap();
        let prep = lease_only(&store);
        store.lock().unwrap().execute_batch("CREATE TRIGGER fail_preparation BEFORE UPDATE ON preparation_cycles BEGIN SELECT RAISE(ABORT,'test journal failure'); END;").unwrap();
        let result = workspace::git_observed(temp.path(), &["init"], vec![], Some(&prep)).await;
        assert!(matches!(result, Err(RuntimeError::Storage(_))));
        assert!(!temp.path().join(".git").exists());
        let db = store.lock().unwrap();
        let run = load_opt(&db, "run").unwrap().unwrap();
        assert_eq!(cycle(&db, &run).unwrap().unwrap().captures, 0);
    }
}
