use super::*;
use router_types::AttemptEvidence;
use serde::Serialize;

#[derive(Clone, Serialize)]
pub(crate) struct EscalationHistory {
    pub runs: Vec<RunSummary>,
    pub attempts: Vec<(String, u32, String)>,
    pub events: Vec<RuntimeEvent>,
    pub ledger_hash: String,
}
impl Store {
    /// One transaction records the terminal transport and its per-attempt facts.
    /// Old attempts are deliberately never reconstructed from a latest summary.
    pub(crate) fn observed_attempt(
        &self,
        mut evidence: AttemptEvidence,
        timing: crate::timing::CaptureTiming,
    ) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut run = load_opt(&tx, &evidence.identity.run_id)?.ok_or(RuntimeError::NotFound)?;
        if run.state != RunState::Running
            || !run.state.permits(evidence.state)
            || run.attempts != evidence.identity.attempt
            || run.definition_hash != evidence.definition_hash
            || run.receipt_id != evidence.authorization_id
            || run.workflow != evidence.workflow
        {
            return Err(RuntimeError::Integrity("attempt identity"));
        }
        evidence.started_event_hash = tx.query_row(
            "SELECT event_hash FROM events WHERE run_id=?1 AND kind='attempt.started' ORDER BY sequence DESC LIMIT 1",
            [&run.run_id], |r| r.get(0))?;
        let changed = tx.execute("UPDATE run_attempts SET status='observed' WHERE run_id=?1 AND attempt=?2 AND status='started'",
            params![run.run_id, run.attempts])?;
        if changed != 1 {
            return Err(RuntimeError::Integrity("attempt already finished"));
        }
        append(&tx, &run, "attempt.finished", "observed")?;
        evidence.finished_event_hash = last_hash(&tx)?;
        run.state = evidence.state;
        run.failure = evidence.failure;
        save(&tx, &run)?;
        append(&tx, &run, "transition", "transport_observed")?;
        evidence.transition_event_hash = last_hash(&tx)?;
        evidence.cleanup = cleanup_evidence(&tx, &run.run_id)?;
        append(
            &tx,
            &run,
            "attempt.evidence.v1",
            &serde_json::to_string(&evidence)?,
        )?;
        let timing = crate::timing::AttemptTimingRecord::new(run.attempts, last_hash(&tx)?, timing);
        if !timing.valid(evidence.transport.elapsed_ms) {
            return Err(RuntimeError::Integrity("attempt timing"));
        }
        append(
            &tx,
            &run,
            "attempt.timing.v1",
            &serde_json::to_string(&timing)?,
        )?;
        if run.state.terminal() && !cleanup_blocked(&tx, Some(&run.run_id))? {
            tx.execute("DELETE FROM writer_locks WHERE run_id=?1", [&run.run_id])?;
        }
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn escalation_history(&self, id: &str) -> Result<EscalationHistory> {
        let mut db = self.lock()?;
        let tx = self.verified_transaction(&mut db, rusqlite::TransactionBehavior::Deferred)?;
        let snapshot = history(&tx, id, &self.root, &self.verified()?.anchors)?;
        tx.commit()?;
        Ok(snapshot)
    }
    /// Compare and append under the same SQLite write lock. The caller's opaque
    /// preview cannot approve an accounting claim against a changed history.
    pub(crate) fn escalation_event(
        &self,
        id: &str,
        ledger: &str,
        kind: &str,
        detail: &str,
    ) -> Result<()> {
        let mut db = self.lock()?;
        let tx = self.verified_transaction(&mut db, rusqlite::TransactionBehavior::Immediate)?;
        let previous = history(&tx, id, &self.root, &self.verified()?.anchors)?;
        if previous.ledger_hash != ledger {
            return Err(RuntimeError::Approval);
        }
        if previous
            .events
            .iter()
            .any(|e| e.kind == "escalation.claim.v1")
        {
            if kind == "escalation.claim.v1"
                && previous
                    .events
                    .iter()
                    .any(|e| e.kind == kind && e.detail == detail)
            {
                return Ok(());
            }
            return Err(RuntimeError::Approval);
        }
        let run = load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
        append(&tx, &run, kind, detail)?;
        tx.commit()?;
        Ok(())
    }
}
fn last_hash(db: &Connection) -> Result<String> {
    Ok(db.query_row(
        "SELECT event_hash FROM events ORDER BY sequence DESC LIMIT 1",
        [],
        |r| r.get(0),
    )?)
}
/// Callers verify the event chain in the same transaction first and pass the
/// owner's verified anchors.
fn history(
    db: &Connection,
    id: &str,
    root: &Path,
    anchors: &std::collections::BTreeMap<String, PlanAuthorityAnchor>,
) -> Result<EscalationHistory> {
    let source = load_opt(db, id)?.ok_or(RuntimeError::NotFound)?;
    if let Some(binding) = &source.workflow {
        verify_instance_authority(db, &binding.instance_id, anchors.get(&binding.instance_id))?;
    }
    let runs = if let Some(binding) = &source.workflow {
        let mut q = db.prepare("SELECT r.summary FROM runs r JOIN workflow_node_runs n ON r.run_id=n.run_id WHERE n.instance_id=?1 AND n.node_id=?2 AND n.generation<=?3 ORDER BY n.generation LIMIT 7")?;
        q.query_map(
            params![binding.instance_id, source.node_id, binding.generation],
            |r| r.get::<_, String>(0),
        )?
        .map(|r| Ok(serde_json::from_str(&r?)?))
        .collect::<Result<Vec<RunSummary>>>()?
    } else {
        vec![source]
    };
    if runs.len() > 6 {
        return Err(RuntimeError::Limit);
    }
    let mut attempts = Vec::new();
    for run in &runs {
        let mut q = db.prepare(
            "SELECT attempt,status FROM run_attempts WHERE run_id=?1 ORDER BY attempt LIMIT 6",
        )?;
        for value in q.query_map([&run.run_id], |r| {
            Ok((r.get::<_, u32>(0)?, r.get::<_, String>(1)?))
        })? {
            let (attempt, status) = value?;
            attempts.push((run.run_id.clone(), attempt, status));
        }
    }
    if attempts.len() > 5 {
        return Err(RuntimeError::Limit);
    }
    let events = read_events(db)?
        .into_iter()
        .filter(|e| runs.iter().any(|r| r.run_id == e.run_id))
        .collect::<Vec<_>>();
    if events.len() > 2048 {
        return Err(RuntimeError::Limit);
    }
    // Claims reserve authority but do not change source accounting. All other
    // changes, including approvals, retries, cancellation and cleanup, do.
    let ledger_events = events
        .iter()
        .filter(|e| e.kind != "escalation.claim.v1")
        .collect::<Vec<_>>();
    let ledger_hash = digest(
        "runtime-escalation-ledger-v1",
        &(root, &runs, &attempts, ledger_events),
    )?;
    Ok(EscalationHistory {
        runs,
        attempts,
        events,
        ledger_hash,
    })
}
