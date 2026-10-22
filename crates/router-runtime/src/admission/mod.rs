//! One explicitly pinned shared concurrency domain. No time-based reclamation.
mod budget;
mod budget_store;
#[cfg(test)]
mod budget_tests;
pub(crate) use budget::BudgetDispatchGuard;
pub use budget::{BudgetError, ReviewedSessionLimit, session_budget_policy_hash};
mod files;
mod registry;
mod runtime;
#[cfg(test)]
mod tests;

use crate::{Result, RuntimeError, digest};
pub use registry::AdmissionStore;
use router_types::*;
pub(crate) use runtime::SharedAdmission;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

/// Bounds LIVE (waiting or granted) tickets, not lifetime rows: settled rows are
/// pruned past `MAX_RETAINED_RELEASED` inside the enqueue transaction. See
/// docs/adr/0017-bounded-retention-and-publish-durability.md.
const MAX_TICKETS: u32 = 4096;
/// Most recent released tickets kept for status and idempotent reconciliation.
const MAX_RETAINED_RELEASED: u32 = 512;
const MAX_IDENTITIES: usize = 128;
const MAX_CAPACITY: u32 = 32;

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 160
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:@/".contains(&b))
}
fn capacity(n: u32) -> bool {
    (1..=MAX_CAPACITY).contains(&n)
}
fn validate(policy: &AdmissionPolicy) -> Result<()> {
    if policy.schema_version != 1
        || !capacity(policy.global_limit)
        || policy.runtimes.is_empty()
        || policy.providers.is_empty()
        || policy.agents.is_empty()
        || [
            policy.runtimes.len(),
            policy.providers.len(),
            policy.agents.len(),
            policy.agent_mappings.len(),
        ]
        .into_iter()
        .any(|n| n > MAX_IDENTITIES)
    {
        return Err(RuntimeError::Invalid("admission policy bounds"));
    }
    for (id, runtime) in &policy.runtimes {
        if !valid_id(id)
            || !router_adapter_api::is_digest(&runtime.root_sha256)
            || !capacity(runtime.limit)
        {
            return Err(RuntimeError::Invalid("admission runtime"));
        }
    }
    for (id, n) in policy.providers.iter().chain(policy.agents.iter()) {
        if !valid_id(id) || !capacity(*n) {
            return Err(RuntimeError::Invalid("admission identity"));
        }
    }
    let mut seen = BTreeSet::new();
    for rule in &policy.agent_mappings {
        if !policy.runtimes.contains_key(&rule.runtime_id)
            || !valid_id(&rule.plan_owner)
            || rule.candidate_agent.as_ref().is_some_and(|s| !valid_id(s))
            || !policy.agents.contains_key(&rule.quota_id)
            || !seen.insert((&rule.runtime_id, &rule.plan_owner, &rule.candidate_agent))
        {
            return Err(RuntimeError::Invalid("admission agent mapping"));
        }
    }
    Ok(())
}

pub fn admission_policy_hash(policy: &AdmissionPolicy) -> Result<String> {
    validate(policy)?;
    digest("runtime-admission-policy-v1", policy)
}
pub fn admission_runtime_root_hash(root: &Path) -> Result<String> {
    digest("runtime-admission-root-v1", &std::fs::canonicalize(root)?)
}

/// Private ticket inputs come from the owned runtime journal, not a caller DTO.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ticket {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_budget: Option<SessionBudgetConfig>,
    pub id: String,
    pub binding: AdmissionBinding,
    pub run_id: String,
    pub definition_hash: String,
    pub approval_digest: String,
    pub workflow: Option<WorkflowRunBinding>,
    pub admission_sequence: u32,
    pub cycle: u32,
    pub attempt: u32,
    pub group: String,
    pub provider: String,
    pub agent: String,
    pub runtime_limit: u32,
    pub provider_limit: u32,
    pub agent_limit: u32,
    pub workflow_limit: u32,
}
impl Ticket {
    pub fn seal(&mut self) -> Result<()> {
        self.id.clear();
        self.id = digest("runtime-admission-ticket-v1", self)?;
        Ok(())
    }
    fn verify(&self) -> Result<()> {
        let mut copy = self.clone();
        copy.seal()?;
        if &copy != self
            || !(1..=MAX_TICKETS).contains(&self.admission_sequence)
            || self.cycle == 0
            || self.cycle > 1024
            || !(1..=5).contains(&self.attempt)
            || !router_adapter_api::is_digest(&self.definition_hash)
            || !router_adapter_api::is_digest(&self.approval_digest)
            || !router_adapter_api::is_digest(&self.group)
            || [
                self.runtime_limit,
                self.provider_limit,
                self.agent_limit,
                self.workflow_limit,
            ]
            .into_iter()
            .any(|n| !capacity(n))
        {
            return Err(RuntimeError::Integrity("admission ticket"));
        }
        Ok(())
    }
}

/// Created only after the owned runtime has verified this exact activity cycle.
/// Keeping construction in Store prevents forged public cleanup DTOs being used.
pub(crate) struct ReleaseProof {
    pub(crate) budget_armed: bool,
    pub(super) ticket: Ticket,
    _model_lock: Option<crate::leases::CleanupProof>,
}
impl ReleaseProof {
    pub(crate) fn checked(ticket: Ticket, model_lock: Option<crate::leases::CleanupProof>) -> Self {
        Self {
            ticket,
            _model_lock: model_lock,
            budget_armed: false,
        }
    }
}
