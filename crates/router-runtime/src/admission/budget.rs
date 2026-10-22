//! Conservative allocations, never provider usage measurements.
use super::*;
use rusqlite::{Connection, TransactionBehavior};
use std::collections::BTreeMap;
#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error("session_budget.policy.invalid")]
    Policy,
    #[error("session_budget.authority.required_or_changed")]
    Authority,
    #[error("session_budget.cost.exhausted")]
    Cost,
    #[error("session_budget.tokens.exhausted")]
    Tokens,
    #[error("session_budget.review.stale")]
    Stale,
    #[error("session_budget.accounting.unknown")]
    Unknown,
}
pub struct ReviewedSessionLimit {
    preview: SessionLimitPreview,
}
impl ReviewedSessionLimit {
    pub fn preview(&self) -> &SessionLimitPreview {
        &self.preview
    }
    pub fn approval_digest(&self) -> &str {
        &self.preview.approval_digest
    }
}
/// Held from the final check through spawn, never constructible from a DTO.
pub(crate) struct BudgetDispatchGuard {
    _guard: files::Owner,
}
pub(super) fn within(a: BudgetAmount, b: BudgetAmount) -> bool {
    a.cost_microusd <= b.cost_microusd && a.tokens <= b.tokens
}
pub(super) fn valid_amount(a: BudgetAmount) -> bool {
    a.cost_microusd <= i64::MAX as u64 && a.tokens <= i64::MAX as u64
}
pub(super) fn add(a: BudgetAmount, b: BudgetAmount) -> Result<BudgetAmount> {
    let value = BudgetAmount {
        cost_microusd: a
            .cost_microusd
            .checked_add(b.cost_microusd)
            .ok_or(RuntimeError::Limit)?,
        tokens: a.tokens.checked_add(b.tokens).ok_or(RuntimeError::Limit)?,
    };
    if !valid_amount(value) {
        return Err(RuntimeError::Limit);
    }
    Ok(value)
}
pub(super) fn sub(a: BudgetAmount, b: BudgetAmount) -> Result<BudgetAmount> {
    Ok(BudgetAmount {
        cost_microusd: a
            .cost_microusd
            .checked_sub(b.cost_microusd)
            .ok_or(BudgetError::Unknown)?,
        tokens: a.tokens.checked_sub(b.tokens).ok_or(BudgetError::Unknown)?,
    })
}
pub fn session_budget_policy_hash(p: &SessionBudgetPolicy) -> Result<String> {
    if p.schema_version != 1
        || p.sessions.is_empty()
        || p.sessions.len() > MAX_IDENTITIES
        || p.runtime_sessions.is_empty()
        || p.runtime_sessions.len() > MAX_IDENTITIES
    {
        return Err(BudgetError::Policy.into());
    }
    for (id, r) in &p.sessions {
        if !valid_id(id)
            || !valid_amount(r.parent_ceiling)
            || !within(r.initial_limit, r.parent_ceiling)
            || r.warning_basis_points.len() > 8
            || r.warning_basis_points.iter().any(|n| *n == 0 || *n > 10000)
            || r.warning_basis_points.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(BudgetError::Policy.into());
        }
    }
    if p.runtime_sessions
        .iter()
        .any(|(id, s)| !valid_id(id) || !p.sessions.contains_key(s))
    {
        return Err(BudgetError::Policy.into());
    }
    digest("session-budget-policy-v1", p)
}
pub(super) fn read_policy(db: &Connection) -> Result<Option<SessionBudgetPolicy>> {
    read_policy_json(db)?
        .as_deref()
        .map(parse_policy)
        .transpose()
}
/// Raw persisted policy JSON, bounded; `None` for a registry without budgets.
pub(super) fn read_policy_json(db: &Connection) -> Result<Option<String>> {
    let version: u32 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version == 1 {
        return Ok(None);
    }
    if !(2..=3).contains(&version) {
        return Err(RuntimeError::Integrity("admission schema"));
    }
    let json: String = db.query_row(
        "SELECT substr(json,1,131073) FROM budget_policy WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    if json.len() > 128 * 1024 {
        return Err(RuntimeError::Limit);
    }
    Ok(Some(json))
}
pub(super) fn parse_policy(json: &str) -> Result<SessionBudgetPolicy> {
    let policy = serde_json::from_str(json)?;
    session_budget_policy_hash(&policy)?;
    if json != serde_json::to_string(&policy)? {
        return Err(BudgetError::Policy.into());
    }
    Ok(policy)
}
impl AdmissionStore {
    /// Initializes only an empty domain with no live runtime owner. No zero backfill.
    pub fn initialize_session_budgets(&mut self, policy: &SessionBudgetPolicy) -> Result<String> {
        let hash = session_budget_policy_hash(policy)?;
        if policy
            .runtime_sessions
            .keys()
            .ne(self.policy.runtimes.keys())
        {
            return Err(BudgetError::Policy.into());
        }
        let _owners: Vec<_> = self
            .policy
            .runtimes
            .keys()
            .map(|id| self.files.owner(id))
            .collect::<Result<_>>()?;
        let _exclusive = self.files.budget_guard(false)?;
        let canonical = serde_json::to_string(policy)?;
        {
            let mut db = self.lock()?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if read_policy(&tx)?.is_some()
                || tx.prepare("SELECT 1 FROM tickets LIMIT 1")?.exists([])?
            {
                return Err(BudgetError::Authority.into());
            }
            tx.execute_batch("CREATE TABLE budget_policy(id INTEGER PRIMARY KEY CHECK(id=1),json TEXT NOT NULL);CREATE TABLE budget_sessions(id TEXT PRIMARY KEY,json TEXT NOT NULL);CREATE TABLE budget_reservations(ticket TEXT PRIMARY KEY REFERENCES tickets(id),session TEXT NOT NULL REFERENCES budget_sessions(id),state TEXT NOT NULL CHECK(state IN ('reserved','committed','released')),amount TEXT NOT NULL);CREATE TABLE budget_events(sequence INTEGER PRIMARY KEY,session TEXT NOT NULL,kind TEXT NOT NULL,ticket TEXT,previous_hash TEXT NOT NULL,state TEXT NOT NULL,event_hash TEXT NOT NULL);PRAGMA user_version=2;")?;
            tx.execute_batch(budget_store::CREATE_FOLDED)?;
            tx.execute_batch("PRAGMA user_version=3;")?;
            tx.execute("INSERT INTO budget_policy VALUES(1,?1)", [&canonical])?;
            for (id, r) in &policy.sessions {
                let state = SessionBudgetStatus {
                    schema_version: 1,
                    binding: SessionBudgetBinding {
                        policy_sha256: hash.clone(),
                        session_id: id.clone(),
                    },
                    registry_sha256: self.registry_hash.clone(),
                    limit: r.initial_limit,
                    parent_ceiling: r.parent_ceiling,
                    limit_revision: 1,
                    reserved_allocation: BudgetAmount::default(),
                    committed_allocation: BudgetAmount::default(),
                    observed_cost_microusd: None,
                    observed_tokens: None,
                    warnings: vec![],
                    ledger_head: String::new(),
                };
                budget_store::persist(&tx, state, "created", None, r)?;
            }
            tx.commit()?;
        }
        self.budget_policy = Some(policy.clone());
        self.budget_fp = Some(registry::fingerprint(&canonical));
        Ok(hash)
    }
    pub(super) fn budget_binding(&self, runtime: &str) -> Result<Option<SessionBudgetBinding>> {
        self.budget_policy
            .as_ref()
            .map(|p| {
                Ok(SessionBudgetBinding {
                    policy_sha256: session_budget_policy_hash(p)?,
                    session_id: p
                        .runtime_sessions
                        .get(runtime)
                        .ok_or(BudgetError::Authority)?
                        .clone(),
                })
            })
            .transpose()
    }
    pub(super) fn validate_budget_config(
        &self,
        runtime: &str,
        config: Option<&SessionBudgetConfig>,
    ) -> Result<()> {
        match (self.budget_binding(runtime)?, config) {
            (None, None) => Ok(()),
            (Some(b), Some(c))
                if c.schema_version == 1
                    && c.expected_policy_sha256 == b.policy_sha256
                    && c.session_id == b.session_id =>
            {
                let r = &self
                    .budget_policy
                    .as_ref()
                    .ok_or(BudgetError::Authority)?
                    .sessions[&c.session_id];
                if !valid_amount(c.attempt_allocation)
                    || !within(c.approved_limit, r.parent_ceiling)
                    || !within(c.attempt_allocation, c.approved_limit)
                {
                    return Err(BudgetError::Policy.into());
                }
                Ok(())
            }
            _ => Err(BudgetError::Authority.into()),
        }
    }
    pub fn session_budget_status(
        &self,
        session: &str,
        expected: &str,
    ) -> Result<SessionBudgetStatus> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let p = self.budget_policy.as_ref().ok_or(BudgetError::Authority)?;
        if session_budget_policy_hash(p)? != expected {
            return Err(BudgetError::Authority.into());
        }
        let result = budget_store::load(&tx, p, &self.registry_hash)?
            .remove(session)
            .ok_or(BudgetError::Authority)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn review_session_limit(
        &self,
        session: &str,
        expected: &str,
        new_limit: BudgetAmount,
    ) -> Result<ReviewedSessionLimit> {
        let current = self.session_budget_status(session, expected)?;
        if !within(new_limit, current.parent_ceiling) {
            return Err(BudgetError::Policy.into());
        }
        let mut preview = SessionLimitPreview {
            schema_version: 1,
            current,
            new_limit,
            approval_digest: String::new(),
        };
        preview.approval_digest = digest("session-limit-approval-v1", &preview)?;
        Ok(ReviewedSessionLimit { preview })
    }
    pub fn approve_session_limit(
        &self,
        reviewed: &ReviewedSessionLimit,
        approval: &str,
    ) -> Result<SessionBudgetStatus> {
        let preview = &reviewed.preview;
        if approval != preview.approval_digest
            || preview.current.registry_sha256 != self.registry_hash
        {
            return Err(BudgetError::Authority.into());
        }
        let _exclusive = self.files.budget_guard(false)?;
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let p = self.budget_policy.as_ref().ok_or(BudgetError::Authority)?;
        let id = &preview.current.binding.session_id;
        let mut state = budget_store::load(&tx, p, &self.registry_hash)?
            .remove(id)
            .ok_or(BudgetError::Authority)?;
        if state != preview.current {
            return Err(BudgetError::Stale.into());
        }
        if !within(preview.new_limit, state.parent_ceiling) || state.limit_revision >= 1024 {
            return Err(BudgetError::Policy.into());
        }
        state.limit = preview.new_limit;
        state.limit_revision += 1;
        state.warnings.clear();
        let state = budget_store::persist(&tx, state, "limit_changed", None, &p.sessions[id])?;
        tx.commit()?;
        Ok(state)
    }
    pub(crate) fn commit_budget(&self, ticket: &Ticket) -> Result<Option<BudgetDispatchGuard>> {
        if ticket.session_budget.is_none() {
            return Ok(None);
        }
        self.validate_ticket(ticket)?;
        let guard = self.files.budget_guard(true)?;
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let p = self.budget_policy.as_ref().ok_or(BudgetError::Authority)?;
        budget_store::commit(&tx, ticket, p, &self.registry_hash, true)?;
        tx.commit()?;
        Ok(Some(BudgetDispatchGuard { _guard: guard }))
    }
    pub(super) fn budget_states(
        &self,
        db: &Connection,
    ) -> Result<BTreeMap<String, SessionBudgetStatus>> {
        match &self.budget_policy {
            Some(p) => budget_store::load(db, p, &self.registry_hash),
            None => Ok(BTreeMap::new()),
        }
    }
}
pub(super) fn reasons(
    t: &Ticket,
    states: &BTreeMap<String, SessionBudgetStatus>,
) -> Vec<AdmissionQueueReason> {
    let Some(c) = &t.session_budget else {
        return vec![];
    };
    let Some(s) = states.get(&c.session_id) else {
        return vec![
            AdmissionQueueReason::SessionCostBudget,
            AdmissionQueueReason::SessionTokenBudget,
        ];
    };
    let mut out = vec![];
    let cost = u128::from(s.committed_allocation.cost_microusd)
        + u128::from(s.reserved_allocation.cost_microusd)
        + u128::from(c.attempt_allocation.cost_microusd);
    let tokens = u128::from(s.committed_allocation.tokens)
        + u128::from(s.reserved_allocation.tokens)
        + u128::from(c.attempt_allocation.tokens);
    if cost > u128::from(s.limit.cost_microusd.min(c.approved_limit.cost_microusd)) {
        out.push(AdmissionQueueReason::SessionCostBudget)
    }
    if tokens > u128::from(s.limit.tokens.min(c.approved_limit.tokens)) {
        out.push(AdmissionQueueReason::SessionTokenBudget)
    }
    out
}
