//! Explicit opt-in runtime feedback. No prompt or raw output crosses this boundary.
use crate::CliError;
use router_adapter_api::content_digest;
use router_feedback::{FeedbackError, FeedbackStore};
use router_policy::ValidatedPhaseContext;
use router_types::*;
use std::path::Path;

pub(crate) fn consent(path: Option<&Path>) -> Result<Option<FeedbackConsent>, CliError> {
    path.map(|path| {
        if !path.join("feedback.sqlite3").is_file() {
            return Err(CliError::Product("feedback.store.unavailable"));
        }
        FeedbackStore::open(path)
            .and_then(|store| store.consent())
            .map_err(|_| CliError::Product("feedback.store.invalid"))
    })
    .transpose()
}

pub(crate) fn record(
    path: Option<&Path>,
    consent: Option<&FeedbackConsent>,
    selection: &router_execution_decision::ExecutionDecision,
    context: &ValidatedPhaseContext,
    completion: &RunCompletion,
    started_at: Option<u64>,
) -> serde_json::Value {
    let (Some(path), Some(consent)) = (path, consent) else {
        return serde_json::json!({"recorded":false,"reason":"not_requested"});
    };
    if !consent.preferences.collection_enabled {
        return serde_json::json!({"recorded":false,"reason":"collection_disabled"});
    }
    let result = (|| {
        let now = crate::inspect::current_time(None).map_err(|_| ())?;
        let receipt = selection.baseline();
        if receipt.context_hash != context.context_hash()
            || completion.run.receipt_id != selection.authorization_id()
        {
            return Err(());
        }
        let selected = &selection.selection().candidate;
        let route = route_facts(receipt, selection.selection());
        // One at most: escalation sources are limited to deterministic or
        // activated runs (`escalation.rs` `source_in`), so a chain stops at 1.
        let escalations = u32::from(selection.origin() == ExecutionDecisionOrigin::Escalated);
        let mut input = feedback_input(
            context,
            completion,
            receipt,
            selected,
            route,
            escalations,
            now,
        )?;
        input.started_at_unix_seconds = started_at.filter(|started| *started <= now);
        input.run_key_sha256 = Some(run_key(&completion.run)?);
        input.binding.receipt_hash = selection.authorization_id().into();
        if let Some(binding) = selection.binding() {
            input.binding.provenance_sha256 = digest(&(completion, receipt, binding))?;
        }
        let store = FeedbackStore::open(path).map_err(|_| ())?;
        if store.consent().map_err(|_| ())? != *consent {
            return Err(());
        }
        store.record(input, now).map_err(|_| ())
    })();
    match result {
        Ok(event) => serde_json::json!({"recorded":true,"event_hash":event.event_hash}),
        // Transport completion remains observable even if consent changed or
        // persistence failed. Never encourage a replay of the native operation.
        Err(()) => {
            serde_json::json!({"recorded":false,"reason":"consent_changed_or_storage_error"})
        }
    }
}

/// Stable across state changes: `run_hash` covers `state` and `attempts`, so a
/// later verification or integration cannot recompute it. The writer and the
/// late-fact paths both key the run through this one function.
pub(crate) fn run_key(run: &RunSummary) -> Result<String, ()> {
    digest(&(&run.run_id, &run.definition_hash, &run.approval_digest))
}

/// Records one late fact for a run, or says why not. Nothing here can fail the
/// command that already succeeded: a failure is only reported in the value.
pub(crate) fn record_fact(
    path: Option<&Path>,
    run: &RunSummary,
    kind: FeedbackFactKind,
) -> serde_json::Value {
    record_fact_at(path, run, kind, None)
}

/// A verification fact only once the runtime left `Verifying`: it can replace an
/// inconclusive record, and a stored fact is never rewritten. `resulting` is the
/// summary `record_verification` returned; `identity` gives the run key.
pub(crate) fn record_verification_fact(
    path: Option<&Path>,
    identity: &RunSummary,
    record: &VerificationRecord,
    resulting: &RunSummary,
) -> serde_json::Value {
    verification_fact_at(path, identity, record, resulting, None)
}
/// For a coordinated run, whose verification `service` applies from a queue and
/// does not report per run. `was_concluded` is read before the service pass, so
/// only a run this pass moved to `Verified` or `VerificationFailed` gets a fact,
/// once, from the record the runtime stored. The configuration is read only for
/// such a run. `None`: nothing to report.
pub(crate) fn service_verification_fact(
    was_concluded: bool,
    now: &RunSummary,
    stored: impl FnOnce() -> Result<Option<VerificationRecord>, ()>,
    feedback_store: impl FnOnce() -> Result<Option<std::path::PathBuf>, ()>,
) -> Option<serde_json::Value> {
    let concluded = matches!(now.state, RunState::Verified | RunState::VerificationFailed);
    if was_concluded || !concluded {
        return None;
    }
    let Ok(Some(record)) = stored() else {
        return Some(
            serde_json::json!({"recorded":false,"reason":"verification_record_unavailable"}),
        );
    };
    Some(match feedback_store() {
        Ok(path) => record_verification_fact(path.as_deref(), now, &record, now),
        Err(()) => {
            serde_json::json!({"recorded":false,"reason":"consent_changed_or_storage_error"})
        }
    })
}
fn verification_fact_at(
    path: Option<&Path>,
    identity: &RunSummary,
    record: &VerificationRecord,
    resulting: &RunSummary,
    now: Option<u64>,
) -> serde_json::Value {
    if path.is_none() {
        return serde_json::json!({"recorded":false,"reason":"not_requested"});
    }
    if !matches!(
        resulting.state,
        RunState::Verified | RunState::VerificationFailed
    ) {
        return serde_json::json!({"recorded":false,"reason":"inconclusive"});
    }
    match verification_fact(record) {
        Ok(kind) => record_fact_at(path, identity, kind, now),
        Err(()) => {
            serde_json::json!({"recorded":false,"reason":"consent_changed_or_storage_error"})
        }
    }
}

/// `now` overrides the clock, for tests. The store treats a repeat as idempotent
/// only when `observed_at` matches too; here an existing fact with the same
/// content but another `observed_at` is reported as `already_recorded`, and a
/// different content stays a refusal.
fn record_fact_at(
    path: Option<&Path>,
    run: &RunSummary,
    kind: FeedbackFactKind,
    now: Option<u64>,
) -> serde_json::Value {
    let Some(path) = path else {
        return serde_json::json!({"recorded":false,"reason":"not_requested"});
    };
    if matches!(
        &kind,
        FeedbackFactKind::Verification {
            validation: VerificationOutcome::Unknown,
            objective: VerificationOutcome::Unknown,
            ..
        }
    ) {
        return serde_json::json!({"recorded":false,"reason":"inconclusive"});
    }
    enum Written {
        Recorded(FeedbackFactEvent),
        Disabled,
        Already,
    }
    let result = (|| {
        if !path.join("feedback.sqlite3").is_file() {
            return Err(false);
        }
        let store = FeedbackStore::open(path).map_err(|_| false)?;
        if !store
            .consent()
            .map_err(|_| false)?
            .preferences
            .collection_enabled
        {
            return Ok(Written::Disabled);
        }
        let now = crate::inspect::current_time(now).map_err(|_| false)?;
        let fact = FeedbackFact {
            schema_version: 1,
            run_key_sha256: run_key(run).map_err(|()| false)?,
            observed_at_unix_seconds: now,
            kind,
        };
        let already = store
            .facts(now)
            .map_err(|_| false)?
            .iter()
            .any(|e| e.fact.run_key_sha256 == fact.run_key_sha256 && e.fact.kind == fact.kind);
        if already {
            return Ok(Written::Already);
        }
        store
            .record_fact(fact, now)
            .map(Written::Recorded)
            .map_err(|error| {
                matches!(
                    error,
                    FeedbackError::Invalid("fact binding" | "verification fact")
                )
            })
    })();
    match result {
        Ok(Written::Recorded(event)) => {
            serde_json::json!({"recorded":true,"fact_hash":event.fact_hash})
        }
        Ok(Written::Disabled) => {
            serde_json::json!({"recorded":false,"reason":"collection_disabled"})
        }
        Ok(Written::Already) => serde_json::json!({"recorded":false,"reason":"already_recorded"}),
        // The fact breaks the contract, for example a passed objective with a
        // failed validation. It is not a storage or consent problem.
        Err(true) => serde_json::json!({"recorded":false,"reason":"invalid_fact"}),
        Err(false) => {
            serde_json::json!({"recorded":false,"reason":"consent_changed_or_storage_error"})
        }
    }
}

/// The evidence digest covers the whole stored record, verifier included.
fn verification_fact(record: &VerificationRecord) -> Result<FeedbackFactKind, ()> {
    Ok(FeedbackFactKind::Verification {
        validation: record.validation,
        objective: record.objective,
        evidence_sha256: digest(record)?,
    })
}

fn digest(value: &impl serde::Serialize) -> Result<String, ()> {
    serde_json::to_vec(value)
        .map(|bytes| content_digest(&bytes))
        .map_err(|_| ())
}
fn feedback_failure(failure: Option<RunFailure>, state: RunState) -> Option<FeedbackFailure> {
    match failure {
        Some(RunFailure::Authentication) => Some(FeedbackFailure::Authentication),
        Some(RunFailure::RateLimit) => Some(FeedbackFailure::RateLimit),
        Some(RunFailure::Timeout) => Some(FeedbackFailure::Timeout),
        Some(RunFailure::Crash) => Some(FeedbackFailure::Crash),
        Some(RunFailure::Network) => Some(FeedbackFailure::Network),
        Some(RunFailure::Policy) => Some(FeedbackFailure::Policy),
        Some(RunFailure::Verification) => Some(FeedbackFailure::Validation),
        // An unclassified outcome says nothing about the candidate model.
        Some(RunFailure::Unclassified) => Some(FeedbackFailure::Unknown),
        Some(_) => Some(FeedbackFailure::Unknown),
        None if state == RunState::Cancelled => Some(FeedbackFailure::Cancelled),
        None => None,
    }
}
/// Rank and margin come from the receipt's own ordering: the selected
/// candidate first, then its alternatives. Nothing here is recomputed.
fn route_facts(receipt: &PhaseReceipt, executed: &PhaseSelection) -> FeedbackRoute {
    let ranked: Vec<&PhaseSelection> = receipt
        .selected
        .iter()
        .chain(&receipt.alternatives)
        .collect();
    let position = ranked
        .iter()
        .position(|s| s.candidate.id == executed.candidate.id);
    let count = |others: usize| u32::try_from(others).unwrap_or(u32::MAX);
    FeedbackRoute {
        candidate_id: executed.candidate.id.clone(),
        rank: position.map(|i| count(i + 1)),
        margin_micros: position.and_then(|i| {
            let next = ranked.get(i + 1)?;
            ranked[i]
                .score
                .utility_micros
                .checked_sub(next.score.utility_micros)
        }),
        alternatives: count(ranked.len().saturating_sub(usize::from(position.is_some()))),
        abstention: receipt.abstention,
    }
}
/// Host-declared usage is a report input only, never an admission input.
fn measurements(completion: &RunCompletion, escalations: u32) -> FeedbackMeasurements {
    let usage = completion
        .runtime_evidence
        .as_ref()
        .and_then(|evidence| evidence.host_usage);
    FeedbackMeasurements {
        cost_microusd: None,
        latency_ms: Some(completion.transport.elapsed_ms),
        tokens: usage.as_ref().and_then(HostUsage::total_tokens),
        attempts: completion.run.attempts,
        escalations,
        usage,
        usage_scope: Some(FeedbackUsageScope::PerAttempt),
    }
}
fn feedback_input(
    context: &ValidatedPhaseContext,
    completion: &RunCompletion,
    receipt: &PhaseReceipt,
    selected: &PhaseCandidate,
    route: FeedbackRoute,
    escalations: u32,
    now: u64,
) -> Result<FeedbackInput, ()> {
    let failure = feedback_failure(completion.run.failure, completion.run.state);
    Ok(FeedbackInput {
        schema_version: 1,
        observed_at_unix_seconds: now,
        started_at_unix_seconds: None,
        run_key_sha256: None,
        binding: FeedbackBinding {
            task_hash: digest(&context.request().task)?,
            run_hash: digest(&completion.run)?,
            receipt_hash: receipt.receipt_id.clone(),
            policy_hash: receipt.policy_hash.clone(),
            catalog_hash: receipt.catalog_hash.clone(),
            snapshot_hash: receipt.snapshot_hash.clone(),
            producer_version: env!("CARGO_PKG_VERSION").into(),
            provenance_sha256: digest(completion)?,
        },
        context: FeedbackContext {
            task_kind: context.request().task.kind,
            risk: context.request().task.risk,
            model: selected.model.clone(),
            effort: selected.effort,
            harness: context.snapshot().host.harness.clone(),
            transport: "subprocess-jsonl".into(),
            agent: selected.agent.clone(),
            skills: selected.skills.iter().map(ToString::to_string).collect(),
            plan: completion.run.plan_id.clone(),
            propensity_micros: None,
            route: Some(route),
        },
        origin: FeedbackOrigin::Automated,
        transport: if completion.transport.exit_code == Some(0)
            && completion.transport.termination == TransportTermination::Exited
            && completion.run.failure.is_none()
        {
            VerificationOutcome::Passed
        } else {
            VerificationOutcome::Failed
        },
        // A successful process says nothing about validation or the objective.
        validation: VerificationOutcome::Unknown,
        objective: VerificationOutcome::Unknown,
        verification_evidence_sha256: None,
        human: None,
        failure,
        measurements: measurements(completion, escalations),
        comment_sha256: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn selection(id: &str, utility_micros: i64) -> PhaseSelection {
        PhaseSelection {
            candidate: PhaseCandidate {
                id: id.into(),
                model: ModelId::parse("fixture-model").unwrap(),
                effort: EffortLevel::Medium,
                agent: None,
                skills: BTreeSet::new(),
                tools: BTreeSet::new(),
                tool_policy: PhaseToolPolicy::Restricted,
                sandbox: PhaseSandbox::ReadOnly,
                verification: PhaseVerification::Required,
                required_capabilities: BTreeSet::new(),
                required_mutations: BTreeSet::new(),
                estimated_cost_microusd: 1,
                estimated_tokens: 1,
                estimated_elapsed_ms: 1,
                relevance_micros: 0,
            },
            score: PhaseScore {
                quality_micros: 0,
                relevance_micros: 0,
                cost_penalty_micros: 0,
                latency_penalty_micros: 0,
                utility_micros,
            },
            assets: Vec::new(),
            reasons: Vec::new(),
        }
    }
    fn receipt(
        selected: Option<PhaseSelection>,
        alternatives: Vec<PhaseSelection>,
    ) -> PhaseReceipt {
        PhaseReceipt {
            capability_evidence: Default::default(),
            schema_version: 2,
            receipt_id: "r".into(),
            phase: StageKind::Execute,
            context_hash: String::new(),
            snapshot_hash: String::new(),
            catalog_hash: String::new(),
            policy_hash: String::new(),
            pool_hash: String::new(),
            registry_hash: String::new(),
            abstention: selected.is_none().then_some(PhaseAbstention::Ambiguous),
            selected,
            alternatives,
            exclusions: Vec::new(),
            unavailable: BTreeSet::new(),
        }
    }

    #[test]
    fn route_facts_match_the_receipt_ranking() {
        let receipt = receipt(
            Some(selection("a", 900_000)),
            vec![selection("b", 700_000), selection("c", 650_000)],
        );
        let top = route_facts(&receipt, &selection("a", 900_000));
        assert_eq!(
            (
                top.rank,
                top.margin_micros,
                top.alternatives,
                top.abstention
            ),
            (Some(1), Some(200_000), 2, None)
        );
        let last = route_facts(&receipt, &selection("c", 650_000));
        assert_eq!(
            (last.rank, last.margin_micros, last.alternatives),
            (Some(3), None, 2)
        );
    }

    #[test]
    fn a_preferred_model_ranked_first_gives_a_negative_margin() {
        let receipt = receipt(
            Some(selection("preferred", 500_000)),
            vec![selection("better", 700_000)],
        );
        let facts = route_facts(&receipt, &selection("preferred", 500_000));
        assert_eq!((facts.rank, facts.margin_micros), (Some(1), Some(-200_000)));
    }

    #[test]
    fn route_facts_of_an_overridden_abstention_are_counted_and_unranked_is_unknown() {
        let receipt = receipt(None, vec![selection("b", 700_000), selection("c", 690_000)]);
        let facts = route_facts(&receipt, &selection("b", 700_000));
        assert_eq!(
            (facts.rank, facts.margin_micros, facts.abstention),
            (Some(1), Some(10_000), Some(PhaseAbstention::Ambiguous))
        );
        let outside = route_facts(&receipt, &selection("z", 1));
        assert_eq!(
            (outside.rank, outside.margin_micros, outside.alternatives),
            (None, None, 2)
        );
    }

    fn completion(host_usage: Option<HostUsage>) -> RunCompletion {
        RunCompletion {
            run: RunSummary {
                run_id: "run".into(),
                definition_hash: "d".into(),
                approval_digest: "a".into(),
                receipt_id: "r".into(),
                plan_id: "p".into(),
                node_id: "n".into(),
                state: RunState::Verifying,
                attempts: 1,
                failure: None,
                worktree: None,
                artifact_sha256: None,
                output_retention: Default::default(),
                workflow: None,
                artifact_contract_sha256: None,
            },
            transport: TransportOutcome {
                termination: TransportTermination::Exited,
                exit_code: Some(0),
                elapsed_ms: 5,
            },
            stdout_sha256: String::new(),
            stderr_sha256: String::new(),
            stdout_bytes: 0,
            stderr_bytes: 0,
            validation: VerificationOutcome::Unknown,
            objective: VerificationOutcome::Unknown,
            memory_enforcement: MemoryEnforcement::NotRequested,
            runtime_evidence: Some(RuntimeEvidence {
                schema_version: 1,
                transport: TransportOutcome {
                    termination: TransportTermination::Exited,
                    exit_code: Some(0),
                    elapsed_ms: 5,
                },
                transport_success: true,
                stream_complete: true,
                validation: VerificationOutcome::Unknown,
                objective: VerificationOutcome::Unknown,
                executed_models: vec![],
                executed_effort: None,
                events: vec![],
                missing_evidence: vec![],
                host_usage,
            }),
            output_artifacts: None,
        }
    }

    #[test]
    fn host_usage_becomes_total_tokens_and_absence_stays_unknown() {
        let usage = HostUsage {
            input_tokens: UsageField::host_reported(100),
            cached_input_tokens: UsageField::host_reported(40),
            cache_write_input_tokens: UsageField::UNKNOWN,
            output_tokens: UsageField::host_reported(20),
            reasoning_output_tokens: UsageField::host_reported(5),
        };
        let m = measurements(&completion(Some(usage)), 0);
        assert_eq!(m.tokens, Some(120));
        // The split is stored with its provenance, not only the total.
        assert_eq!(m.usage, Some(usage));
        for absent in [
            None,
            Some(HostUsage {
                output_tokens: UsageField::UNKNOWN,
                ..usage
            }),
        ] {
            let m = measurements(&completion(absent), 0);
            assert_eq!(m.tokens, None);
            assert_eq!(m.usage, absent);
        }
    }

    #[test]
    fn completion_attempt_measurements_survive_store_and_report() {
        let (_temp, path) = store(true);
        let store = FeedbackStore::open(&path).unwrap();
        let usage = HostUsage {
            input_tokens: UsageField::host_reported(10),
            cached_input_tokens: UsageField::host_reported(0),
            cache_write_input_tokens: UsageField::UNKNOWN,
            output_tokens: UsageField::host_reported(2),
            reasoning_output_tokens: UsageField::UNKNOWN,
        };
        for (ordinal, state) in [
            (1, RunState::Failed),
            (2, RunState::Verifying),
            (2, RunState::Verified),
        ] {
            let mut completion = completion(Some(usage));
            completion.run.attempts = ordinal;
            completion.run.state = state;
            let mut input: FeedbackInput = serde_json::from_str(include_str!(
                "../../../tests/fixtures/feedback/automated-unknown-v1.json"
            ))
            .unwrap();
            input.observed_at_unix_seconds = 1_100;
            input.run_key_sha256 = Some(run_key(&completion.run).unwrap());
            input.binding.run_hash = digest(&completion.run).unwrap();
            input.measurements = measurements(&completion, 0);
            let stored = store.record(input, 1_100).unwrap();
            assert_eq!(
                serde_json::to_value(stored).unwrap()["input"]["measurements"]["usage_scope"],
                "per_attempt"
            );
        }
        let pricing = router_eval::PricingTable {
            schema_version: 1,
            version: "fixture".into(),
            source: "synthetic".into(),
            observed_at_unix_seconds: 1_000,
            models: [(
                ModelId::parse("fixture-model").unwrap(),
                router_eval::TokenPrice {
                    input_microusd_per_million: 1_000_000,
                    cached_input_microusd_per_million: 1_000_000,
                    output_microusd_per_million: 1_000_000,
                },
            )]
            .into(),
        };
        let report = store.report(Some(&pricing), 1_200).unwrap();
        let summary = store.summary(Some(&pricing), 1_200).unwrap();
        assert_eq!((report.runs.len(), report.superseded_events), (1, 2));
        assert_eq!(summary.cost.total_microusd, Some(24));
        assert_eq!(summary.cost.per_accepted_microusd, None);
    }

    #[test]
    fn unclassified_failure_is_unknown_feedback_never_a_model_fault() {
        assert!(matches!(
            feedback_failure(Some(RunFailure::Unclassified), RunState::Failed),
            Some(FeedbackFailure::Unknown)
        ));
        assert!(matches!(
            feedback_failure(Some(RunFailure::Verification), RunState::VerificationFailed),
            Some(FeedbackFailure::Validation)
        ));
    }
    fn run(state: RunState, attempts: u32) -> RunSummary {
        RunSummary {
            run_id: "run-1".into(),
            definition_hash: "d".repeat(64),
            approval_digest: "a".repeat(64),
            receipt_id: "receipt".into(),
            plan_id: "plan".into(),
            node_id: "node".into(),
            state,
            attempts,
            failure: None,
            worktree: None,
            artifact_sha256: None,
            output_retention: OutputRetentionPolicy::default(),
            workflow: None,
            artifact_contract_sha256: None,
        }
    }

    #[test]
    fn run_key_ignores_state_and_attempts_but_run_hash_does_not() {
        let at_completion = run(RunState::Verifying, 1);
        let later = run(RunState::Verified, 2);
        assert_eq!(run_key(&at_completion), run_key(&later));
        assert_ne!(digest(&at_completion), digest(&later));
        let mut other = run(RunState::Verifying, 1);
        other.approval_digest = "b".repeat(64);
        assert_ne!(run_key(&at_completion), run_key(&other));
        other = run(RunState::Verifying, 1);
        other.run_id = "run-2".into();
        assert_ne!(run_key(&at_completion), run_key(&other));
        other = run(RunState::Verifying, 1);
        other.definition_hash = "e".repeat(64);
        assert_ne!(run_key(&at_completion), run_key(&other));
    }

    fn now_secs() -> u64 {
        crate::inspect::current_time(None).ok().unwrap()
    }
    const CONFIGURED: u64 = 1_000;
    const FACT_TIME: Option<u64> = Some(1_500);
    fn store(collection_enabled: bool) -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("feedback");
        let store = FeedbackStore::open(&path).unwrap();
        store
            .configure(
                FeedbackPreferences {
                    collection_enabled,
                    ..FeedbackPreferences::default()
                },
                CONFIGURED,
            )
            .unwrap();
        (temp, path)
    }
    fn applied() -> FeedbackFactKind {
        FeedbackFactKind::Integration {
            outcome: IntegrationOutcome::Applied,
        }
    }

    #[test]
    fn late_fact_is_recorded_under_the_writer_run_key() {
        let (_temp, path) = store(true);
        let value = record_fact_at(
            Some(&path),
            &run(RunState::Verified, 2),
            applied(),
            FACT_TIME,
        );
        assert_eq!(value["recorded"], true);
        let facts = FeedbackStore::open(&path).unwrap().facts(1_500).unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(
            facts[0].fact.run_key_sha256,
            run_key(&run(RunState::Verifying, 1)).unwrap()
        );
        assert_eq!(value["fact_hash"], facts[0].fact_hash);
        // A repeat, at any time, is reported as already recorded, not rewritten.
        let again = record_fact_at(
            Some(&path),
            &run(RunState::Verified, 2),
            applied(),
            FACT_TIME,
        );
        assert_eq!(again["reason"], "already_recorded");
        let later = record_fact_at(
            Some(&path),
            &run(RunState::Verified, 2),
            applied(),
            Some(1_501),
        );
        assert_eq!(later["reason"], "already_recorded");
    }

    #[test]
    fn late_fact_reports_why_it_was_not_recorded() {
        let reason = |value: serde_json::Value| {
            assert_eq!(value["recorded"], false);
            value["reason"].as_str().unwrap().to_owned()
        };
        let summary = run(RunState::Verified, 1);
        assert_eq!(
            reason(record_fact_at(None, &summary, applied(), FACT_TIME)),
            "not_requested"
        );
        let (_temp, disabled) = store(false);
        assert_eq!(
            reason(record_fact_at(
                Some(&disabled),
                &summary,
                applied(),
                FACT_TIME
            )),
            "collection_disabled"
        );
        let missing = disabled.join("absent");
        assert_eq!(
            reason(record_fact_at(
                Some(&missing),
                &summary,
                applied(),
                FACT_TIME
            )),
            "consent_changed_or_storage_error"
        );
        assert!(!missing.exists());
        let (_temp, enabled) = store(true);
        let inconclusive = FeedbackFactKind::Verification {
            validation: VerificationOutcome::Unknown,
            objective: VerificationOutcome::Unknown,
            evidence_sha256: "9".repeat(64),
        };
        assert_eq!(
            reason(record_fact_at(
                Some(&enabled),
                &summary,
                inconclusive,
                FACT_TIME
            )),
            "inconclusive"
        );
        // A conflicting outcome is a storage refusal, never a command failure.
        record_fact_at(Some(&enabled), &summary, applied(), FACT_TIME);
        let conflict = FeedbackFactKind::Integration {
            outcome: IntegrationOutcome::Discarded,
        };
        assert_eq!(
            reason(record_fact_at(
                Some(&enabled),
                &summary,
                conflict,
                FACT_TIME
            )),
            "consent_changed_or_storage_error"
        );
    }

    #[test]
    fn verification_fact_carries_the_stored_outcomes_and_a_record_digest() {
        let record = VerificationRecord {
            verifier: "checker".into(),
            evidence_sha256: "1".repeat(64),
            artifact_sha256: None,
            validation: VerificationOutcome::Passed,
            objective: VerificationOutcome::Failed,
        };
        let FeedbackFactKind::Verification {
            validation,
            objective,
            evidence_sha256,
        } = verification_fact(&record).unwrap()
        else {
            panic!("verification fact");
        };
        assert_eq!(
            (validation, objective),
            (VerificationOutcome::Passed, VerificationOutcome::Failed)
        );
        assert_eq!(evidence_sha256, digest(&record).unwrap());
    }

    fn record(
        validation: VerificationOutcome,
        objective: VerificationOutcome,
    ) -> VerificationRecord {
        VerificationRecord {
            verifier: "checker".into(),
            evidence_sha256: "1".repeat(64),
            artifact_sha256: None,
            validation,
            objective,
        }
    }

    #[test]
    fn a_verification_fact_waits_for_a_conclusive_runtime_state() {
        use VerificationOutcome::{Failed, Passed, Unknown};
        let (_temp, path) = store(true);
        let identity = run(RunState::Verifying, 1);
        // The runtime keeps the run in `Verifying` and may replace this record.
        let first = verification_fact_at(
            Some(&path),
            &identity,
            &record(Passed, Unknown),
            &run(RunState::Verifying, 1),
            FACT_TIME,
        );
        assert_eq!(first["reason"], "inconclusive");
        let stored = || FeedbackStore::open(&path).unwrap().facts(1_500).unwrap();
        assert!(stored().is_empty());
        let second = verification_fact_at(
            Some(&path),
            &identity,
            &record(Passed, Passed),
            &run(RunState::Verified, 1),
            FACT_TIME,
        );
        assert_eq!(second["recorded"], true);
        let facts = stored();
        assert_eq!(facts.len(), 1);
        assert!(matches!(
            facts[0].fact.kind,
            FeedbackFactKind::Verification {
                validation: Passed,
                objective: Passed,
                ..
            }
        ));
        // A failure is conclusive too.
        let (_temp, path) = store(true);
        let failed = verification_fact_at(
            Some(&path),
            &identity,
            &record(Failed, Unknown),
            &run(RunState::VerificationFailed, 1),
            FACT_TIME,
        );
        assert_eq!(failed["recorded"], true);
    }

    #[test]
    fn a_contract_violating_verification_is_invalid_not_a_storage_error() {
        use VerificationOutcome::{Failed, Passed};
        let (_temp, path) = store(true);
        // Conclusive for the runtime (a failed validation), refused by the contract.
        let value = verification_fact_at(
            Some(&path),
            &run(RunState::Verifying, 1),
            &record(Failed, Passed),
            &run(RunState::VerificationFailed, 1),
            FACT_TIME,
        );
        assert_eq!(value["recorded"], false);
        assert_eq!(value["reason"], "invalid_fact");
        assert!(
            FeedbackStore::open(&path)
                .unwrap()
                .facts(1_500)
                .unwrap()
                .is_empty()
        );
    }

    /// Service pass over one run: `stored` record, and the configuration path.
    fn service(
        path: Option<&std::path::Path>,
        was_concluded: bool,
        state: RunState,
        stored: Result<Option<VerificationRecord>, ()>,
    ) -> Option<serde_json::Value> {
        service_verification_fact(
            was_concluded,
            &run(state, 1),
            || stored,
            || Ok(path.map(std::path::Path::to_path_buf)),
        )
    }

    #[test]
    fn service_records_a_fact_only_for_a_run_it_concluded() {
        use VerificationOutcome::{Passed, Unknown};
        let (_temp, path) = store(true);
        let stored = record(Passed, Passed);
        let verifying = run(RunState::Verifying, 1);
        let facts = || {
            FeedbackStore::open(&path)
                .unwrap()
                .facts(now_secs())
                .unwrap()
        };
        // Still verifying (an inconclusive record), or concluded before the pass.
        let inconclusive = Ok(Some(record(Passed, Unknown)));
        assert!(service(Some(&path), false, RunState::Verifying, inconclusive).is_none());
        let done = Ok(Some(stored.clone()));
        assert!(service(Some(&path), true, RunState::Verified, done).is_none());
        assert!(facts().is_empty());
        let reported = service(
            Some(&path),
            false,
            RunState::Verified,
            Ok(Some(stored.clone())),
        )
        .unwrap();
        assert_eq!(reported["recorded"], true);
        let facts = facts();
        assert_eq!(facts.len(), 1);
        // Same key as the automated event written at completion, while `Verifying`.
        assert_eq!(facts[0].fact.run_key_sha256, run_key(&verifying).unwrap());
        assert_eq!(facts[0].fact.kind.name(), "verification");
        // Collection off: nothing recorded, and the service keeps going.
        let (_temp, off) = store(false);
        let value = service(
            Some(&off),
            false,
            RunState::Verified,
            Ok(Some(stored.clone())),
        )
        .unwrap();
        assert_eq!(value["reason"], "collection_disabled");
        assert!(
            FeedbackStore::open(&off)
                .unwrap()
                .facts(now_secs())
                .unwrap()
                .is_empty()
        );
        let none = service(None, false, RunState::Verified, Ok(Some(stored))).unwrap();
        assert_eq!(none["reason"], "not_requested");
    }

    #[test]
    fn service_reports_an_unreadable_record_and_reads_the_config_only_when_needed() {
        use VerificationOutcome::Passed;
        let read = std::cell::Cell::new(0);
        let pass = |was, state, stored| {
            service_verification_fact(
                was,
                &run(state, 1),
                || stored,
                || {
                    read.set(read.get() + 1);
                    Ok(None)
                },
            )
        };
        assert!(pass(false, RunState::Verifying, Ok(None)).is_none());
        assert!(pass(true, RunState::Verified, Ok(None)).is_none());
        assert_eq!(read.get(), 0);
        for stored in [Err(()), Ok(None)] {
            let value = pass(false, RunState::Verified, stored).unwrap();
            assert_eq!(value["reason"], "verification_record_unavailable");
        }
        assert_eq!(read.get(), 0);
        let value = pass(false, RunState::Verified, Ok(Some(record(Passed, Passed)))).unwrap();
        assert_eq!(value["reason"], "not_requested");
        assert_eq!(read.get(), 1);
    }

    #[test]
    fn a_second_pass_reports_already_recorded_and_a_different_fact_stays_refused() {
        use VerificationOutcome::Passed;
        let (_temp, path) = store(true);
        let summary = run(RunState::Verified, 1);
        let first = record_fact_at(Some(&path), &summary, applied(), Some(1_500));
        assert_eq!(first["recorded"], true);
        let later = record_fact_at(Some(&path), &summary, applied(), Some(1_501));
        assert_eq!(later["recorded"], false);
        assert_eq!(later["reason"], "already_recorded");
        let facts = FeedbackStore::open(&path).unwrap().facts(1_501).unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].fact.observed_at_unix_seconds, 1_500);
        let other = FeedbackFactKind::Integration {
            outcome: IntegrationOutcome::Discarded,
        };
        let conflict = record_fact_at(Some(&path), &summary, other, Some(1_502));
        assert_eq!(conflict["reason"], "consent_changed_or_storage_error");
        // Content differing inside one kind is a conflict too.
        let verified = |validation| verification_fact(&record(validation, Passed)).ok().unwrap();
        let a = record_fact_at(Some(&path), &summary, verified(Passed), Some(1_503));
        assert_eq!(a["recorded"], true);
        let b = record_fact_at(Some(&path), &summary, verified(Passed), Some(1_504));
        assert_eq!(b["reason"], "already_recorded");
    }
    #[test]
    fn qualified_pricing_preserves_completion_usage_and_exposes_missing_cache_cost() {
        let (_temp, path) = store(true);
        let store = FeedbackStore::open(&path).unwrap();
        let usage = HostUsage {
            input_tokens: UsageField::host_reported(100),
            cached_input_tokens: UsageField::host_reported(20),
            cache_write_input_tokens: UsageField::host_reported(30),
            output_tokens: UsageField::host_reported(40),
            reasoning_output_tokens: UsageField::host_reported(10),
        };
        let completion = completion(Some(usage));
        let mut input: FeedbackInput = serde_json::from_str(include_str!(
            "../../../tests/fixtures/feedback/automated-unknown-v1.json"
        ))
        .unwrap();
        input.observed_at_unix_seconds = 1100;
        input.run_key_sha256 = Some(run_key(&completion.run).unwrap());
        input.measurements = measurements(&completion, 0);
        store.record(input, 1100).unwrap();
        let mut pricing:router_eval::QualifiedPricingTable=serde_json::from_value(serde_json::json!({"schema_version":2,"version":"fixture-v2","source":"synthetic","observed_at_unix_seconds":1000,"models":{"fixture-model":{
            "input_microusd_per_million":1000000,"cache_read_microusd_per_million":500000,"cache_write_microusd_per_million":2000000,"cache_write_scope":"all_reported_writes","output_microusd_per_million":3000000,"reasoning":{"mode":"separate","microusd_per_million":4000000}
        }}})).unwrap();
        let events = store.events(1200).unwrap();
        let (report, summary) = store
            .report_and_summary_with_pricing(
                Some(router_feedback::FeedbackPricing::Qualified(&pricing)),
                None,
                1200,
            )
            .unwrap();
        assert_eq!(report.runs[0].usage, Some(usage));
        assert_eq!(summary.cost.total_microusd, Some(250));
        pricing
            .models
            .get_mut(&ModelId::parse("fixture-model").unwrap())
            .unwrap()
            .cache_write_microusd_per_million = None;
        let (_, summary) = store
            .report_and_summary_with_pricing(
                Some(router_feedback::FeedbackPricing::Qualified(&pricing)),
                None,
                1200,
            )
            .unwrap();
        assert_eq!(summary.cost.known_subtotal_microusd, Some(190));
        assert_eq!(summary.cost.total_microusd, None);
        assert_eq!(events, store.events(1200).unwrap());
    }
}
