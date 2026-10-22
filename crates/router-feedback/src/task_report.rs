//! Reconcile persisted runtime attempts with optional feedback observations.
//! Runtime inventory and feedback are independently captured snapshots, so a
//! feedback run ahead of its inventory is refused rather than truncated.
use crate::{FeedbackError, FeedbackReport, Result, RunVerdict};
use router_types::{FeedbackRuntimeInventory, RunState};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskOccurrenceReport {
    pub occurrence_sha256: String,
    pub run_keys_sha256: Vec<String>,
    pub escalations: u64,
    pub status: &'static str,
    pub expected_attempts: u64,
    pub feedback_attempts: u64,
    pub missing_feedback_attempts: u64,
    pub priced_attempts: u64,
    pub known_subtotal_microusd: Option<u64>,
    pub total_microusd: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskMeasurementReport {
    pub schema_version: u32,
    pub source: &'static str,
    pub journal_sha256: String,
    pub occurrences: Vec<TaskOccurrenceReport>,
    pub expected_attempts: u64,
    pub feedback_attempts: u64,
    pub missing_feedback_attempts: u64,
    pub priced_attempts: u64,
    pub accepted_occurrences: u64,
    /// Feedback runs outside this runtime inventory, including external sessions.
    /// They remain in the ordinary run report and are not joined by task text.
    pub unmatched_feedback_runs: u64,
    pub known_subtotal_microusd: Option<u64>,
    pub total_microusd: Option<u64>,
    pub per_accepted_microusd: Option<u64>,
    pub interpretation: &'static str,
}

pub(crate) fn measure(
    report: &FeedbackReport,
    inventory: &FeedbackRuntimeInventory,
    events: &[router_types::FeedbackEvent],
    pricing: Option<crate::FeedbackPricing<'_>>,
) -> Result<TaskMeasurementReport> {
    if inventory.schema_version != 1 || inventory.runs.len() > crate::MAX_EVENTS {
        return Err(FeedbackError::Invalid("runtime inventory"));
    }
    let feedback: BTreeMap<_, _> = report
        .runs
        .iter()
        .filter_map(|run| run.run_key_sha256.as_deref().map(|key| (key, run)))
        .collect();
    let mut keys = BTreeSet::new();
    let mut grouped = BTreeMap::new();
    for run in &inventory.runs {
        if !keys.insert(run.run_key_sha256.as_str()) {
            return Err(FeedbackError::Integrity("duplicate runtime run"));
        }
        keys.extend(run.feedback_run_keys_sha256.iter().map(String::as_str));
        grouped
            .entry(run.occurrence_sha256.as_str())
            .or_insert_with(Vec::new)
            .push(run);
    }
    let mut occurrences = Vec::new();
    for (occurrence, runs) in grouped {
        let mut row = TaskOccurrenceReport {
            occurrence_sha256: occurrence.into(),
            run_keys_sha256: Vec::new(),
            escalations: 0,
            status: "unknown",
            expected_attempts: 0,
            feedback_attempts: 0,
            missing_feedback_attempts: 0,
            priced_attempts: 0,
            known_subtotal_microusd: None,
            total_microusd: None,
        };
        let mut subtotal = 0u64;
        let mut known = false;
        let mut complete = true;
        let mut accepted = false;
        let mut cancelled = false;
        let mut terminal = true;
        let mut failed = false;
        let mut verified_without_acceptance = false;
        for runtime in runs {
            row.run_keys_sha256.push(runtime.run_key_sha256.clone());
            row.escalations += u64::from(runtime.predecessor_run_key_sha256.is_some());
            row.expected_attempts += u64::from(runtime.attempts);
            cancelled |= runtime.state == RunState::Cancelled;
            terminal &= runtime.state.terminal();
            verified_without_acceptance |= runtime.state == RunState::Verified;
            failed |= matches!(
                runtime.state,
                RunState::Failed
                    | RunState::VerificationFailed
                    | RunState::TimedOut
                    | RunState::Blocked
            );
            let aliases: BTreeSet<_> = runtime
                .feedback_run_keys_sha256
                .iter()
                .map(String::as_str)
                .collect();
            let mut attempts = crate::report::RunAttempts::default();
            for event in events.iter().filter(|event| {
                event.input.origin == router_types::FeedbackOrigin::Automated
                    && event
                        .input
                        .run_key_sha256
                        .as_deref()
                        .is_some_and(|key| aliases.contains(key))
            }) {
                attempts.observe(event);
            }
            let cost = attempts.measurement_cost(pricing);
            if cost.expected_attempts > u64::from(runtime.attempts) {
                return Err(FeedbackError::Integrity(
                    "feedback ahead of runtime inventory",
                ));
            }
            row.feedback_attempts += cost.observed_attempts;
            row.priced_attempts += cost.priced_attempts;
            accepted |= aliases
                .iter()
                .filter_map(|key| feedback.get(key))
                .any(|run| run.verdict == RunVerdict::Accepted);
            complete &= cost.total_microusd.is_some()
                && cost.expected_attempts == u64::from(runtime.attempts);
            if let Some(amount) = cost.known_subtotal_microusd {
                subtotal = subtotal.checked_add(amount).ok_or(FeedbackError::Limit)?;
                known = true;
            }
        }
        row.run_keys_sha256.sort();
        row.status = if accepted {
            "accepted"
        } else if !terminal || verified_without_acceptance {
            "unknown"
        } else if cancelled {
            "abandoned"
        } else if failed {
            "failed"
        } else {
            "unknown"
        };
        row.missing_feedback_attempts = row.expected_attempts - row.feedback_attempts;
        row.known_subtotal_microusd = known.then_some(subtotal);
        row.total_microusd = (complete && row.expected_attempts > 0).then_some(subtotal);
        occurrences.push(row);
    }
    let mut result = TaskMeasurementReport {
        schema_version: 1,
        source: "runtime_journal",
        journal_sha256: inventory.journal_sha256.clone(),
        expected_attempts: 0,
        feedback_attempts: 0,
        missing_feedback_attempts: 0,
        priced_attempts: 0,
        accepted_occurrences: 0,
        unmatched_feedback_runs: report
            .runs
            .iter()
            .filter(|run| {
                run.run_key_sha256
                    .as_deref()
                    .is_none_or(|key| !keys.contains(key))
            })
            .count() as u64,
        known_subtotal_microusd: None,
        total_microusd: None,
        per_accepted_microusd: None,
        interpretation: "runtime_inventory_scope_only; journal_consistency_is_not_host_usage_or_external_session_authentication",
        occurrences,
    };
    let mut subtotal = 0u64;
    let mut known = false;
    let mut complete = !result.occurrences.is_empty();
    for row in &result.occurrences {
        result.expected_attempts += row.expected_attempts;
        result.feedback_attempts += row.feedback_attempts;
        result.missing_feedback_attempts += row.missing_feedback_attempts;
        result.priced_attempts += row.priced_attempts;
        result.accepted_occurrences += u64::from(row.status == "accepted");
        complete &= row.total_microusd.is_some();
        if let Some(amount) = row.known_subtotal_microusd {
            subtotal = subtotal.checked_add(amount).ok_or(FeedbackError::Limit)?;
            known = true;
        }
    }
    result.known_subtotal_microusd = known.then_some(subtotal);
    result.total_microusd = complete.then_some(subtotal);
    if complete && result.accepted_occurrences > 0 {
        result.per_accepted_microusd = Some(
            ((u128::from(subtotal) + u128::from(result.accepted_occurrences) / 2)
                / u128::from(result.accepted_occurrences)) as u64,
        );
    }
    Ok(result)
}
