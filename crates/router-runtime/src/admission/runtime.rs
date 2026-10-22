use super::*;
use crate::{Cancellation, PendingRun, RuntimeLimits, store::Store};

pub(crate) struct SharedAdmission {
    registry: AdmissionStore,
    binding: AdmissionBinding,
    budget: Option<SessionBudgetConfig>,
    _owner: files::Owner,
}
impl SharedAdmission {
    pub fn open(config: &AdmissionConfig, root: &Path) -> Result<Self> {
        if config.schema_version != 1 {
            return Err(RuntimeError::Invalid("admission configuration"));
        }
        let registry = AdmissionStore::open(&config.registry, &config.expected_policy_sha256)?;
        registry.validate_budget_config(&config.runtime_id, config.session_budget.as_ref())?;
        let binding = registry.binding(&config.runtime_id)?;
        if registry.policy().runtimes[&config.runtime_id].root_sha256
            != admission_runtime_root_hash(root)?
        {
            return Err(RuntimeError::Approval);
        }
        let owner = registry.owner(&config.runtime_id)?;
        Ok(Self {
            registry,
            binding,
            budget: config.session_budget.clone(),
            _owner: owner,
        })
    }
    pub fn binding(&self) -> &AdmissionBinding {
        &self.binding
    }
    pub fn budget_config(&self) -> Option<&SessionBudgetConfig> {
        self.budget.as_ref()
    }
    pub fn validate(&self, pending: &PendingRun) -> Result<(String, String)> {
        if let Some(c) = &self.budget {
            let a = c.attempt_allocation;
            let candidate = &pending.decision.selection().candidate;
            let r = &pending.context.request().restrictions;
            if a.cost_microusd
                > pending
                    .node
                    .budget
                    .max_cost_microusd
                    .min(r.max_cost_microusd.unwrap_or(u64::MAX))
                || a.tokens
                    > pending
                        .node
                        .budget
                        .max_tokens
                        .min(r.max_tokens.unwrap_or(u64::MAX))
                || a.cost_microusd < candidate.estimated_cost_microusd
                || a.tokens < candidate.estimated_tokens
            {
                return Err(BudgetError::Policy.into());
            }
        }
        self.validate_request_bound(
            &pending.context,
            &pending.request,
            &pending.node.owner,
            pending.finite_client_binding.as_deref(),
            pending.finite_client_provider.as_deref(),
        )
    }
    pub fn validate_request(
        &self,
        context: &router_policy::ValidatedPhaseContext,
        request: &ExecutionRequest,
        owner: &str,
    ) -> Result<(String, String)> {
        self.validate_request_bound(context, request, owner, None, None)
    }
    pub fn validate_request_bound(
        &self,
        context: &router_policy::ValidatedPhaseContext,
        request: &ExecutionRequest,
        owner: &str,
        finite_binding: Option<&str>,
        finite_provider: Option<&str>,
    ) -> Result<(String, String)> {
        let provider = provider_identity(
            context
                .asset_requirements(&request.candidate_id)
                .map(|a| a.provider.as_str()),
            finite_binding,
            finite_provider,
        )?;
        if !self.registry.policy().providers.contains_key(&provider) {
            return Err(RuntimeError::Invalid("admission unknown provider"));
        }
        let candidate_agent = request.agent.as_deref();
        let mapping = self
            .registry
            .policy()
            .agent_mappings
            .iter()
            .find(|m| {
                m.runtime_id == self.binding.runtime_id
                    && m.plan_owner == owner
                    && m.candidate_agent.as_deref() == candidate_agent
            })
            .ok_or(RuntimeError::Invalid("admission unknown logical agent"))?;
        Ok((provider, mapping.quota_id.clone()))
    }
    pub fn start(
        &self,
        store: &Store,
        pending: &PendingRun,
        limits: &RuntimeLimits,
    ) -> Result<Ticket> {
        let (provider, agent) = self.validate(pending)?;
        let group = group_key(
            &self.binding.runtime_id,
            pending.run.workflow.as_ref(),
            &pending.run.run_id,
        )?;
        let t = Ticket {
            session_budget: self.budget.clone(),
            id: String::new(),
            binding: self.binding.clone(),
            run_id: pending.run.run_id.clone(),
            definition_hash: pending.run.definition_hash.clone(),
            approval_digest: pending.run.approval_digest.clone(),
            workflow: pending.run.workflow.clone(),
            admission_sequence: 0,
            cycle: 0,
            attempt: 0,
            group,
            provider,
            agent,
            runtime_limit: limits.global_concurrency as u32,
            provider_limit: limits.provider_concurrency as u32,
            agent_limit: limits.agent_concurrency as u32,
            workflow_limit: pending.plan.max_width.min(
                pending
                    .context
                    .request()
                    .restrictions
                    .max_concurrency
                    .unwrap_or(32),
            ) as u32,
        };
        store.start_admission(t)
    }
    pub async fn wait(&self, store: &Store, ticket: &Ticket, cancel: &Cancellation) -> Result<()> {
        let _waiter = self.registry.waiter(ticket)?;
        let mut busy = BusyRetry::default();
        loop {
            match self.registry.enqueue(ticket) {
                Err(error) if busy.retry(&error)? => {
                    tokio::time::sleep(BUSY_PAUSE).await;
                }
                other => break other?,
            }
        }
        let mut previous = Vec::new();
        let mut pause = POLL_MIN;
        loop {
            if cancel.is_cancelled() || store.cancel_requested(&ticket.run_id)? {
                return Err(RuntimeError::Cancelled);
            }
            let reasons = match self.registry.poll(ticket) {
                Ok(reasons) => {
                    busy = BusyRetry::default();
                    reasons
                }
                Err(error) if busy.retry(&error)? => {
                    tokio::time::sleep(BUSY_PAUSE).await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if reasons.is_empty() {
                return Ok(());
            }
            let changed = reasons != previous;
            pause = poll_pause(pause, changed);
            if changed {
                store.event(
                    &ticket.run_id,
                    "admission.queued",
                    &serde_json::to_string(&reasons)?,
                )?;
                previous = reasons.clone();
            }
            if reasons.contains(&AdmissionQueueReason::SessionCostBudget) {
                return Err(BudgetError::Cost.into());
            }
            if reasons.contains(&AdmissionQueueReason::SessionTokenBudget) {
                return Err(BudgetError::Tokens.into());
            }
            tokio::time::sleep(pause).await;
        }
    }
    pub fn commit_budget(&self, store: &Store, id: &str) -> Result<Option<BudgetDispatchGuard>> {
        if self.budget.is_none() {
            return Ok(None);
        }
        let ticket = store.arm_session_budget(id)?;
        // Armed first so a crash between the two commits is recovered as a
        // dispatch. A refusal is definite: the run never spawns, so disarm and
        // let the release refund. If disarming fails the run stays armed, which
        // over-charges rather than under-charges, and the refusal still surfaces.
        match self.registry.commit_budget(&ticket) {
            Ok(guard) => Ok(guard),
            Err(error) => {
                let _ = store.disarm_session_budget(id);
                Err(error)
            }
        }
    }
    pub fn release(&self, store: &Store, ticket: &Ticket) -> Result<()> {
        let proof = store.admission_release_proof(ticket)?;
        // Model cleanup flock survives both journal commits. No Drop release.
        self.registry.release(&proof)?;
        store.admission_released(ticket)
    }
    pub fn recover(&self, store: &Store) -> Result<()> {
        for ticket in store.admission_tickets()? {
            if ticket.binding != self.binding {
                return Err(RuntimeError::Approval);
            }
            match self.release(store, &ticket) {
                Ok(()) => {}
                Err(RuntimeError::CleanupUnknown) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// A registry writer held by another runtime is contention, not a failure of
/// this queued run. Retry inside the wait; after this long of consecutive
/// contention the wait fails with `RuntimeError::Limit`, so a wedged registry
/// still ends the run instead of hanging it.
const BUSY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
/// Queue poll spacing: starts at `POLL_MIN`, doubles while the queue state is
/// unchanged up to `POLL_MAX`, and returns to `POLL_MIN` when the reasons change.
const POLL_MIN: std::time::Duration = std::time::Duration::from_millis(20);
const POLL_MAX: std::time::Duration = std::time::Duration::from_millis(100);
fn poll_pause(pause: std::time::Duration, changed: bool) -> std::time::Duration {
    if changed {
        POLL_MIN
    } else {
        (pause * 2).min(POLL_MAX)
    }
}
const BUSY_PAUSE: std::time::Duration = std::time::Duration::from_millis(20);
#[derive(Default)]
struct BusyRetry(Option<std::time::Instant>);
impl BusyRetry {
    /// `Ok(true)` when `error` is busy contention still inside the deadline,
    /// `Ok(false)` for any other error, and `Limit` once the deadline has
    /// passed.
    fn retry(&mut self, error: &RuntimeError) -> Result<bool> {
        let busy = matches!(
            error,
            RuntimeError::Storage(rusqlite::Error::SqliteFailure(failure, _))
                if matches!(
                    failure.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                )
        );
        if !busy {
            return Ok(false);
        }
        let since = *self.0.get_or_insert_with(std::time::Instant::now);
        if since.elapsed() > BUSY_DEADLINE {
            return Err(RuntimeError::Limit);
        }
        Ok(true)
    }
}

fn group_key(
    runtime_id: &str,
    workflow: Option<&WorkflowRunBinding>,
    run_id: &str,
) -> Result<String> {
    match workflow {
        Some(w) => digest(
            "admission-workflow-v1",
            &(&w.instance_id, &w.contract_sha256),
        ),
        None => digest("admission-standalone-v1", &(runtime_id, run_id)),
    }
}
#[cfg(test)]
mod group_tests {
    use super::*;
    #[test]
    fn workflow_capacity_is_shared_across_runtime_roots_and_generations() {
        let mut workflow = WorkflowRunBinding {
            instance_id: "same-instance".into(),
            contract_sha256: "a".repeat(64),
            generation: 0,
        };
        let one = group_key("one", Some(&workflow), "run-a").unwrap();
        workflow.generation = 1;
        assert_eq!(one, group_key("two", Some(&workflow), "run-b").unwrap());
        assert_ne!(
            group_key("one", None, "run").unwrap(),
            group_key("two", None, "run").unwrap()
        );
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::tests::{fixture, ticket};
    use crate::store::tests::summary;
    use router_types::{BudgetAmount, RunState, SessionBudgetPolicy, SessionBudgetRule};
    use std::collections::BTreeMap;

    fn amount(n: u64) -> BudgetAmount {
        BudgetAmount {
            cost_microusd: n,
            tokens: n,
        }
    }
    struct Fixture {
        temp: tempfile::TempDir,
        admission: SharedAdmission,
        store: Store,
        ticket: Ticket,
        policy_hash: String,
    }
    fn setup() -> Fixture {
        let (temp, mut registry) = fixture();
        let policy = SessionBudgetPolicy {
            schema_version: 1,
            sessions: BTreeMap::from([(
                "session".into(),
                SessionBudgetRule {
                    initial_limit: amount(100),
                    parent_ceiling: amount(200),
                    warning_basis_points: vec![],
                },
            )]),
            runtime_sessions: BTreeMap::from([
                ("one".into(), "session".into()),
                ("two".into(), "session".into()),
            ]),
        };
        let policy_hash = registry.initialize_session_budgets(&policy).unwrap();
        let config = SessionBudgetConfig {
            schema_version: 1,
            expected_policy_sha256: session_budget_policy_hash(&policy).unwrap(),
            session_id: "session".into(),
            approved_limit: amount(100),
            attempt_allocation: amount(60),
        };
        let store = Store::open(&temp.path().join("runtime")).unwrap();
        store.register(&summary("run")).unwrap();
        for state in [RunState::AwaitingApproval, RunState::Queued] {
            store.transition("run", state, "", None).unwrap();
        }
        let mut pending = ticket(&registry, "one", "run", "group", "other");
        pending.session_budget = Some(config.clone());
        pending.seal().unwrap();
        let ticket = store.start_admission(pending).unwrap();
        let admission = SharedAdmission {
            binding: registry.binding("one").unwrap(),
            budget: Some(config),
            _owner: registry.owner("one").unwrap(),
            registry,
        };
        Fixture {
            temp,
            admission,
            store,
            ticket,
            policy_hash,
        }
    }
    fn running(f: &Fixture) {
        let prep = f.store.begin_preparation("run").unwrap();
        prep.no_child_yet().unwrap();
        prep.complete().unwrap();
        drop(prep);
        f.store.attempt("run", 2, true).unwrap();
        f.store
            .transition("run", RunState::Running, "test", None)
            .unwrap();
    }

    #[tokio::test]
    async fn refused_budget_dispatch_is_refunded_by_the_release() {
        let f = setup();
        f.admission
            .wait(&f.store, &f.ticket, &Cancellation::default())
            .await
            .unwrap();
        running(&f);
        // Lowering the limit after the grant makes the registry refuse the commit.
        let review = f
            .admission
            .registry
            .review_session_limit("session", &f.policy_hash, amount(20))
            .unwrap();
        f.admission
            .registry
            .approve_session_limit(&review, review.approval_digest())
            .unwrap();
        assert!(matches!(
            f.admission.commit_budget(&f.store, "run"),
            Err(RuntimeError::Budget(BudgetError::Cost))
        ));
        f.store.confirm_attempt_cleanup("run").unwrap();
        f.admission.release(&f.store, &f.ticket).unwrap();
        let status = f
            .admission
            .registry
            .session_budget_status("session", &f.policy_hash)
            .unwrap();
        assert_eq!(status.committed_allocation, amount(0));
        assert_eq!(status.reserved_allocation, amount(0));
    }
    #[test]
    fn budget_commit_still_charges_when_dispatch_is_accepted() {
        let f = setup();
        f.admission.registry.enqueue(&f.ticket).unwrap();
        let _waiter = f.admission.registry.waiter(&f.ticket).unwrap();
        assert!(f.admission.registry.poll(&f.ticket).unwrap().is_empty());
        running(&f);
        drop(f.admission.commit_budget(&f.store, "run").unwrap());
        f.store.confirm_attempt_cleanup("run").unwrap();
        f.admission.release(&f.store, &f.ticket).unwrap();
        let status = f
            .admission
            .registry
            .session_budget_status("session", &f.policy_hash)
            .unwrap();
        assert_eq!(status.committed_allocation, amount(60));
    }
    #[tokio::test]
    async fn wait_retries_registry_busy_instead_of_failing_the_queued_run() {
        let f = setup();
        let registry_db = f.temp.path().join("registry").join("admission.sqlite3");
        let (locked, ready) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let db = rusqlite::Connection::open(registry_db).unwrap();
            db.execute_batch("BEGIN IMMEDIATE").unwrap();
            locked.send(()).unwrap();
            // Longer than the registry's own 250 ms busy timeout.
            std::thread::sleep(std::time::Duration::from_millis(700));
            db.execute_batch("COMMIT").unwrap();
        });
        ready.recv().unwrap();
        f.admission
            .wait(&f.store, &f.ticket, &Cancellation::default())
            .await
            .unwrap();
        holder.join().unwrap();
    }
    #[test]
    fn poll_pause_doubles_to_a_bound_and_resets_when_reasons_change() {
        let ms = |d: std::time::Duration| d.as_millis();
        let mut pause = poll_pause(POLL_MIN, true);
        let mut seen = vec![ms(pause)];
        for _ in 0..4 {
            pause = poll_pause(pause, false);
            seen.push(ms(pause));
        }
        assert_eq!(seen, [20, 40, 80, 100, 100]);
        assert_eq!(ms(poll_pause(pause, true)), 20);
        assert_eq!(ms(poll_pause(poll_pause(pause, true), false)), 40);
    }
    #[test]
    fn busy_retry_is_bounded_and_ignores_other_errors() {
        let busy = RuntimeError::Storage(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            None,
        ));
        let mut retry = BusyRetry::default();
        assert!(retry.retry(&busy).unwrap());
        assert!(!retry.retry(&RuntimeError::Locked).unwrap());
        let mut expired = BusyRetry(Some(
            std::time::Instant::now() - BUSY_DEADLINE - std::time::Duration::from_secs(1),
        ));
        assert!(matches!(expired.retry(&busy), Err(RuntimeError::Limit)));
    }
}

#[cfg(test)]
mod finite_provider_tests {
    use super::*;
    #[test]
    fn subscription_uses_separate_quota_and_refuses_fixture_or_unbound_profile() {
        let binding = "a".repeat(64);
        assert_eq!(
            provider_identity(
                Some("codex_subscription_relay"),
                Some(&binding),
                Some("codex_subscription_relay")
            )
            .unwrap(),
            "codex_subscription_relay"
        );
        assert!(
            provider_identity(
                Some("local_fixture"),
                Some(&binding),
                Some("codex_subscription_relay")
            )
            .is_err()
        );
        assert!(provider_identity(Some("codex_subscription_relay"), Some(&binding), None).is_err());
        assert!(provider_identity(None, None, Some("codex_subscription_relay")).is_err());
    }
    #[test]
    fn local_fixture_provider_needs_a_finite_binding_and_cannot_mask_a_remote_provider() {
        let binding = "a".repeat(64);
        assert!(provider_identity(None, None, None).is_err());
        assert!(provider_identity(None, Some("receipt-is-not-a-binding"), None).is_err());
        assert_eq!(
            provider_identity(None, Some(&binding), None).unwrap(),
            "local_fixture"
        );
        assert_eq!(
            provider_identity(Some("local_fixture"), Some(&binding), None).unwrap(),
            "local_fixture"
        );
        assert!(provider_identity(Some("remote"), Some(&binding), None).is_err());
        assert_eq!(
            provider_identity(Some("remote"), None, None).unwrap(),
            "remote"
        );
    }
}

// The private finite entrance supplies both binding and provider identity. A
// remote subscription can never silently select authored fixture admission.
fn provider_identity(
    asset_provider: Option<&str>,
    finite_binding: Option<&str>,
    finite_provider: Option<&str>,
) -> Result<String> {
    if let Some(binding) = finite_binding {
        let provider = finite_provider.unwrap_or("local_fixture");
        if !router_adapter_api::is_digest(binding)
            || !matches!(provider, "local_fixture" | "codex_subscription_relay")
            || asset_provider.is_some_and(|declared| declared != provider)
        {
            return Err(RuntimeError::Invalid("finite provider binding"));
        }
        return Ok(provider.into());
    }
    if finite_provider.is_some() {
        return Err(RuntimeError::Approval);
    }
    asset_provider
        .map(str::to_owned)
        .ok_or(RuntimeError::Invalid("admission unknown provider"))
}
