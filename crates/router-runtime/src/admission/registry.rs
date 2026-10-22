use super::*;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::sync::Mutex;

pub struct AdmissionStore {
    pub(super) db: Mutex<Connection>,
    pub(super) files: files::Files,
    pub(super) policy: AdmissionPolicy,
    pub(super) policy_hash: String,
    pub(super) registry_hash: String,
    pub(super) budget_policy: Option<SessionBudgetPolicy>,
    /// Digests of the persisted JSON pinned at load, so a poll compares the
    /// stored row without deserializing and reserializing the policy.
    pub(super) config_fp: String,
    pub(super) budget_fp: Option<String>,
    pub(super) retain_released: u32,
}
enum Outcome {
    /// The ticket already holds its grant: nothing to decide or write.
    Granted,
    Queued(Vec<AdmissionQueueReason>),
    Grant,
}
struct Evaluation {
    /// Waiting rows whose owner lock is gone, to be released under the write lock.
    dead: Vec<String>,
    outcome: Outcome,
}
impl Evaluation {
    fn reasons(self) -> Vec<AdmissionQueueReason> {
        match self.outcome {
            Outcome::Queued(reasons) => reasons,
            Outcome::Granted | Outcome::Grant => Vec::new(),
        }
    }
}
pub(super) fn fingerprint(json: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(json.as_bytes()))
}
impl AdmissionStore {
    /// Explicitly initializes an empty private registry; never imports legacy runs.
    pub fn create(root: &Path, policy: &AdmissionPolicy) -> Result<Self> {
        let hash = admission_policy_hash(policy)?;
        Self::load(root, &hash, Some(policy))
    }
    pub fn open(root: &Path, expected_policy_sha256: &str) -> Result<Self> {
        Self::load(root, expected_policy_sha256, None)
    }
    fn load(root: &Path, expected: &str, create: Option<&AdmissionPolicy>) -> Result<Self> {
        if !router_adapter_api::is_digest(expected) {
            return Err(RuntimeError::Invalid("admission policy pin"));
        }
        let files = files::Files::open(root, create.is_some())?;
        let mut db = Connection::open(files.path.join("admission.sqlite3"))?;
        db.busy_timeout(std::time::Duration::from_millis(250))?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        if let Some(policy) = create {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch("CREATE TABLE config(id INTEGER PRIMARY KEY CHECK(id=1),json TEXT NOT NULL); CREATE TABLE groups(id TEXT PRIMARY KEY,turn INTEGER NOT NULL); CREATE TABLE tickets(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,owner TEXT NOT NULL,group_id TEXT NOT NULL REFERENCES groups(id),state TEXT NOT NULL CHECK(state IN ('waiting','granted','released')),record TEXT NOT NULL); CREATE TABLE clock(id INTEGER PRIMARY KEY CHECK(id=1),tick INTEGER NOT NULL); INSERT INTO clock VALUES(1,0); PRAGMA user_version=1;")?;
            tx.execute(
                "INSERT INTO config VALUES(1,?1)",
                [serde_json::to_string(policy)?],
            )?;
            tx.commit()?;
        }
        let version: u32 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if ![1, 2, 3].contains(&version) {
            return Err(RuntimeError::Integrity("admission schema"));
        }
        if version == 2 {
            // v3 adds the per-session total of pruned committed reservations.
            // Another opener may migrate first: re-read under the write lock.
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let current: u32 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
            if current == 2 {
                tx.execute_batch(budget_store::CREATE_FOLDED)?;
                tx.execute_batch("PRAGMA user_version=3;")?;
            } else if current != 3 {
                return Err(RuntimeError::Integrity("admission schema"));
            }
            tx.commit()?;
        }
        let json: String = db.query_row(
            "SELECT substr(json,1,131073) FROM config WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        if json.len() > 128 * 1024 {
            return Err(RuntimeError::Limit);
        }
        let policy: AdmissionPolicy = serde_json::from_str(&json)?;
        let policy_hash = admission_policy_hash(&policy)?;
        if policy_hash != expected || json != serde_json::to_string(&policy)? {
            return Err(RuntimeError::Approval);
        }
        let budget_json = budget::read_policy_json(&db)?;
        let budget_policy = budget_json
            .as_deref()
            .map(budget::parse_policy)
            .transpose()?;
        let budget_fp = budget_json.as_deref().map(fingerprint);
        if budget_policy
            .as_ref()
            .is_some_and(|p| p.runtime_sessions.keys().ne(policy.runtimes.keys()))
        {
            return Err(BudgetError::Policy.into());
        }
        let registry_hash = files.binding_hash()?;
        files.check()?;
        Ok(Self {
            db: Mutex::new(db),
            files,
            policy,
            policy_hash,
            registry_hash,
            budget_policy,
            config_fp: fingerprint(&json),
            budget_fp,
            retain_released: MAX_RETAINED_RELEASED,
        })
    }
    pub fn policy(&self) -> &AdmissionPolicy {
        &self.policy
    }
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }
    pub(crate) fn binding(&self, runtime_id: &str) -> Result<AdmissionBinding> {
        if !self.policy.runtimes.contains_key(runtime_id) {
            return Err(RuntimeError::Invalid("admission unknown runtime"));
        }
        Ok(AdmissionBinding {
            session_budget: self.budget_binding(runtime_id)?,
            schema_version: 1,
            registry_sha256: self.registry_hash.clone(),
            policy_sha256: self.policy_hash.clone(),
            runtime_id: runtime_id.into(),
        })
    }
    pub(super) fn owner(&self, id: &str) -> Result<files::Owner> {
        self.files.check()?;
        self.files.owner(id)
    }
    pub(super) fn waiter(&self, ticket: &Ticket) -> Result<files::Owner> {
        self.files.owner(&format!("ticket:{}", ticket.id))
    }
    pub(super) fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.files.check()?;
        let db = self
            .db
            .lock()
            .map_err(|_| RuntimeError::Integrity("admission lock"))?;
        let json: String = db.query_row(
            "SELECT substr(json,1,131073) FROM config WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        if fingerprint(&json) != self.config_fp {
            return Err(RuntimeError::Approval);
        }
        if budget::read_policy_json(&db)?.as_deref().map(fingerprint) != self.budget_fp {
            return Err(BudgetError::Authority.into());
        }
        Ok(db)
    }
    pub(super) fn validate_ticket(&self, ticket: &Ticket) -> Result<()> {
        ticket.verify()?;
        self.validate_budget_config(&ticket.binding.runtime_id, ticket.session_budget.as_ref())?;
        if ticket.binding != self.binding(&ticket.binding.runtime_id)?
            || !self.policy.providers.contains_key(&ticket.provider)
            || !self.policy.agents.contains_key(&ticket.agent)
        {
            return Err(RuntimeError::Approval);
        }
        Ok(())
    }
    pub(crate) fn enqueue(&self, ticket: &Ticket) -> Result<()> {
        self.validate_ticket(ticket)?;
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT record FROM tickets WHERE id=?1",
                [&ticket.id],
                |r| r.get(0),
            )
            .optional()?;
        let record = serde_json::to_string(ticket)?;
        if let Some(existing) = existing {
            if existing != record {
                return Err(RuntimeError::Integrity("admission ticket changed"));
            }
            return Ok(());
        }
        budget_store::prune_settled(&tx, self.retain_released, self.budget_policy.is_some())?;
        let live: u32 = tx.query_row(
            "SELECT count(*) FROM tickets WHERE state!='released'",
            [],
            |r| r.get(0),
        )?;
        if live >= MAX_TICKETS {
            return Err(RuntimeError::Limit);
        }
        let tick: i64 = tx.query_row("SELECT tick FROM clock WHERE id=1", [], |r| r.get(0))?;
        tx.execute(
            "INSERT OR IGNORE INTO groups VALUES(?1,?2)",
            params![ticket.group, tick],
        )?;
        tx.execute(
            "INSERT INTO tickets(id,owner,group_id,state,record) VALUES(?1,?2,?3,'waiting',?4)",
            params![ticket.id, ticket.binding.runtime_id, ticket.group, record],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Entire capacity vector is reserved in one immediate transaction. Only the
    /// polling owner can grant its own ticket; abandoned waiters cannot block it.
    /// A first deferred read decides whether anything must be granted or released;
    /// only then is the write lock taken, and the decision is made again inside
    /// it. A poll with nothing to change never holds the write lock.
    pub(crate) fn poll(&self, ticket: &Ticket) -> Result<Vec<AdmissionQueueReason>> {
        self.validate_ticket(ticket)?;
        let mut db = self.lock()?;
        {
            let tx = db.transaction_with_behavior(TransactionBehavior::Deferred)?;
            let seen = self.evaluate(&tx, ticket)?;
            if seen.dead.is_empty() && !matches!(seen.outcome, Outcome::Grant) {
                return Ok(seen.reasons());
            }
        }
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = self.evaluate(&tx, ticket)?;
        for id in &now.dead {
            tx.execute(
                "UPDATE tickets SET state='released' WHERE id=?1 AND state='waiting'",
                [id],
            )?;
        }
        if matches!(now.outcome, Outcome::Grant) {
            if let Some(policy) = &self.budget_policy {
                budget_store::reserve(&tx, ticket, policy, &self.registry_hash)?;
            }
            tx.execute(
                "UPDATE tickets SET state='granted' WHERE id=?1 AND state='waiting'",
                [&ticket.id],
            )?;
            tx.execute("UPDATE clock SET tick=tick+1 WHERE id=1", [])?;
            tx.execute(
                "UPDATE groups SET turn=(SELECT tick FROM clock WHERE id=1) WHERE id=?1",
                [&ticket.group],
            )?;
        }
        if matches!(now.outcome, Outcome::Granted) {
            // Nothing was decided: earlier releases in this pass are dropped.
            return Ok(vec![]);
        }
        tx.commit()?;
        Ok(now.reasons())
    }
    /// Read-only decision over the live rows. Writes are returned, not applied.
    fn evaluate(&self, tx: &Connection, ticket: &Ticket) -> Result<Evaluation> {
        let live: u32 = tx.query_row(
            "SELECT count(*) FROM tickets WHERE state!='released'",
            [],
            |r| r.get(0),
        )?;
        if live > MAX_TICKETS
            || tx
                .prepare("SELECT 1 FROM tickets WHERE length(record)>16384 LIMIT 1")?
                .exists([])?
        {
            return Err(RuntimeError::Limit);
        }
        let rows = {
            let mut q=tx.prepare("SELECT t.id,t.state,t.record FROM tickets t JOIN groups g ON g.id=t.group_id WHERE state!='released' ORDER BY g.turn,t.sequence")?;
            q.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        if rows.len() > MAX_TICKETS as usize {
            return Err(RuntimeError::Limit);
        }
        let mut granted = Vec::new();
        let mut waiting = Vec::new();
        let mut dead = Vec::new();
        let mut found = false;
        for (id, state, json) in rows {
            if json.len() > 16384 {
                return Err(RuntimeError::Limit);
            }
            let item: Ticket = serde_json::from_str(&json)?;
            self.validate_ticket(&item)?;
            if id != item.id {
                return Err(RuntimeError::Integrity("admission row identity"));
            }
            if id == ticket.id {
                found = true;
                if item != *ticket {
                    return Err(RuntimeError::Approval);
                }
                if state == "granted" {
                    return Ok(Evaluation {
                        dead: Vec::new(),
                        outcome: Outcome::Granted,
                    });
                }
            }
            if state == "granted" {
                granted.push(item);
            } else if self.files.owner_alive(&item.binding.runtime_id)?
                && self.files.owner_alive(&format!("ticket:{}", item.id))?
            {
                waiting.push(item);
            } else {
                dead.push(id);
            }
        }
        if !found || !waiting.iter().any(|t| t.id == ticket.id) {
            return Err(RuntimeError::Cancelled);
        }
        if granted.len() > self.policy.global_limit as usize {
            return Err(RuntimeError::Integrity("admission overcapacity"));
        }
        let states = self.budget_states(tx)?;
        let reasons = self.reasons(ticket, &granted, &states);
        if !reasons.is_empty() {
            return Ok(Evaluation {
                dead,
                outcome: Outcome::Queued(reasons),
            });
        }
        let mut groups = BTreeSet::new();
        let outcome = if waiting
            .iter()
            .filter(|t| groups.insert(&t.group))
            .find(|t| self.reasons(t, &granted, &states).is_empty())
            .map(|t| &t.id)
            != Some(&ticket.id)
        {
            Outcome::Queued(vec![AdmissionQueueReason::FairTurn])
        } else {
            Outcome::Grant
        };
        Ok(Evaluation { dead, outcome })
    }
    fn reasons(
        &self,
        t: &Ticket,
        active: &[Ticket],
        states: &std::collections::BTreeMap<String, SessionBudgetStatus>,
    ) -> Vec<AdmissionQueueReason> {
        let count = |f: &dyn Fn(&Ticket) -> bool| active.iter().filter(|v| f(v)).count() as u32;
        let mut out = Vec::new();
        if active.len() as u32 >= self.policy.global_limit {
            out.push(AdmissionQueueReason::GlobalCapacity);
        }
        let same_runtime = |x: &Ticket| x.binding.runtime_id == t.binding.runtime_id;
        let minimum =
            |predicate: &dyn Fn(&Ticket) -> bool, field: fn(&Ticket) -> u32, requested: u32| {
                active
                    .iter()
                    .filter(|v| predicate(v))
                    .map(field)
                    .fold(requested, u32::min)
            };
        if count(&same_runtime)
            >= minimum(&same_runtime, |x| x.runtime_limit, t.runtime_limit)
                .min(self.policy.runtimes[&t.binding.runtime_id].limit)
        {
            out.push(AdmissionQueueReason::RuntimeCapacity);
        }
        if count(&|x| x.provider == t.provider) >= self.policy.providers[&t.provider]
            || count(&|x| same_runtime(x) && x.provider == t.provider)
                >= minimum(
                    &|x| same_runtime(x) && x.provider == t.provider,
                    |x| x.provider_limit,
                    t.provider_limit,
                )
        {
            out.push(AdmissionQueueReason::ProviderCapacity);
        }
        if count(&|x| x.agent == t.agent) >= self.policy.agents[&t.agent]
            || count(&|x| same_runtime(x) && x.agent == t.agent)
                >= minimum(
                    &|x| same_runtime(x) && x.agent == t.agent,
                    |x| x.agent_limit,
                    t.agent_limit,
                )
        {
            out.push(AdmissionQueueReason::AgentCapacity);
        }
        if count(&|x| x.group == t.group)
            >= minimum(
                &|x| x.group == t.group,
                |x| x.workflow_limit,
                t.workflow_limit,
            )
        {
            out.push(AdmissionQueueReason::WorkflowCapacity);
        }
        out.extend(budget::reasons(t, states));
        out
    }
    pub(crate) fn release(&self, proof: &ReleaseProof) -> Result<()> {
        let ticket = &proof.ticket;
        self.validate_ticket(ticket)?;
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let json: Option<String> = tx
            .query_row(
                "SELECT record FROM tickets WHERE id=?1",
                [&ticket.id],
                |r| r.get(0),
            )
            .optional()?;
        let expected = serde_json::to_string(ticket)?;
        if json.as_deref().is_some_and(|j| j != expected) {
            return Err(RuntimeError::Integrity("admission release identity"));
        }
        if let Some(policy) = &self.budget_policy {
            budget_store::release(&tx, proof, policy, &self.registry_hash)?;
        }
        // Missing means the runtime intent committed before registry enqueue.
        tx.execute(
            "UPDATE tickets SET state='released' WHERE id=?1",
            [&ticket.id],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn status(&self) -> Result<AdmissionStatus> {
        let db = self.lock()?;
        let count = |s: &str| {
            db.query_row("SELECT count(*) FROM tickets WHERE state=?1", [s], |r| {
                r.get(0)
            })
        };
        Ok(AdmissionStatus {
            schema_version: 1,
            policy_sha256: self.policy_hash.clone(),
            waiting: count("waiting")?,
            granted: count("granted")?,
            released: count("released")?,
            max_tickets: MAX_TICKETS,
        })
    }
}
