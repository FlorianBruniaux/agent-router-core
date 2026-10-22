use crate::{
    CliError, Outcome, command::EvalCommand, inspect, phases::read_json, product::json_output,
    read_bounded,
};
use router_adapter_api::SnapshotValidation;
use router_eval::{
    CandidateCorpus, EvalError, PairedTrace, ReplayRecord, compare_shadow,
    replay_deterministic_with_verifier,
};
use router_feedback::{
    AttemptCorrelationInput, SuppliedAttempt, SuppliedAttemptEvidence, SuppliedPhysical,
    SuppliedRequested, SuppliedRuntime,
};
use serde::{Deserialize, Deserializer, de::DeserializeOwned};
use std::{path::Path, process::ExitCode};

const ATTEMPT_CORRELATION_INVALID: CliError = CliError::Product("eval.attempt_correlation.invalid");

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

macro_rules! strict_string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Eq, PartialEq)]
        enum $name {
            $($variant),+
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                match String::deserialize(deserializer)?.as_str() {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(serde::de::Error::custom("invalid enum value")),
                }
            }
        }
    };
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationV2 {
    schema_version: u32,
    snapshot_sha256: String,
    identity: ObservationIdentity,
    horizon: ObservationHorizon,
    known: ObservationKnown,
    unknown: ObservationUnknowns,
    completeness: ObservationCompleteness,
    attempts: Vec<ObservationAttempt>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationTiming {
    ordinal: u32,
    attempt_key_sha256: String,
    #[serde(deserialize_with = "required_nullable")]
    timing_event_sha256: Option<String>,
    scope: String,
    clock: String,
    start_boundary: String,
    end_boundary: String,
    precision: String,
    measurement: ObservationMeasurement,
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum ObservationMeasurement {
    Known {
        #[serde(rename = "duration_ms")]
        _duration_ms: u64,
    },
    Unknown {
        reason: ObservationTimingUnknown,
    },
}

strict_string_enum!(ObservationTimingUnknown {
    MissingRecord => "missing_record",
    ClockRegression => "clock_regression",
    DurationOverflow => "duration_overflow",
});

fn observation_document(bytes: &[u8]) -> Result<ObservationV2, CliError> {
    // Decode duplicate keys and the byte bound before removing the v3-only field.
    let mut value: serde_json::Value = strict_document(bytes)?;
    let timings: Option<Vec<ObservationTiming>> = match value["schema_version"].as_u64() {
        Some(2) => None,
        Some(3) => Some(
            serde_json::from_value(
                value
                    .as_object_mut()
                    .and_then(|object| object.remove("timings"))
                    .ok_or(ATTEMPT_CORRELATION_INVALID)?,
            )
            .map_err(|_| ATTEMPT_CORRELATION_INVALID)?,
        ),
        _ => return Err(ATTEMPT_CORRELATION_INVALID),
    };
    let observation: ObservationV2 =
        serde_json::from_value(value).map_err(|_| ATTEMPT_CORRELATION_INVALID)?;
    if let Some(timings) = timings {
        validate_observation_timings(&observation, &timings)?;
    }
    Ok(observation)
}

fn validate_observation_timings(
    observation: &ObservationV2,
    timings: &[ObservationTiming],
) -> Result<(), CliError> {
    if timings.len() != observation.attempts.len()
        || timings.len() > 5
        || observation.known.events.len() > 4096
    {
        return Err(ATTEMPT_CORRELATION_INVALID);
    }
    let mut ordinals = std::collections::BTreeSet::new();
    let mut event_hashes = std::collections::BTreeSet::new();
    for timing in timings {
        let attempt = observation
            .attempts
            .iter()
            .find(|attempt| attempt.ordinal == timing.ordinal)
            .ok_or(ATTEMPT_CORRELATION_INVALID)?;
        if !ordinals.insert(timing.ordinal)
            || timing.attempt_key_sha256 != attempt.attempt_key_sha256
            || timing.scope != "supervisor_capture"
            || timing.clock != "monotonic_same_invocation"
            || timing.start_boundary != "before_dispatch_validation"
            || timing.end_boundary != "after_reap_and_both_output_drains"
            || timing.precision != "milliseconds_truncated"
        {
            return Err(ATTEMPT_CORRELATION_INVALID);
        }
        let missing = matches!(
            timing.measurement,
            ObservationMeasurement::Unknown {
                reason: ObservationTimingUnknown::MissingRecord
            }
        );
        if missing != timing.timing_event_sha256.is_none() {
            return Err(ATTEMPT_CORRELATION_INVALID);
        }
        if let Some(hash) = &timing.timing_event_sha256 {
            digest(hash)?;
            if attempt.evidence != ObservationEvidence::DurableAttempt || !event_hashes.insert(hash)
            {
                return Err(ATTEMPT_CORRELATION_INVALID);
            }
            let evidence_hash = attempt
                .sources
                .attempt_evidence_sha256
                .as_ref()
                .ok_or(ATTEMPT_CORRELATION_INVALID)?;
            let mut timing_events = observation
                .known
                .events
                .iter()
                .filter(|e| &e.event_sha256 == hash);
            let mut evidence_events = observation
                .known
                .events
                .iter()
                .filter(|e| &e.event_sha256 == evidence_hash);
            let timing_event = timing_events.next().ok_or(ATTEMPT_CORRELATION_INVALID)?;
            let evidence_event = evidence_events.next().ok_or(ATTEMPT_CORRELATION_INVALID)?;
            if timing_events.next().is_some()
                || evidence_events.next().is_some()
                || evidence_event.sequence.checked_add(1) != Some(timing_event.sequence)
                || evidence_event.state != timing_event.state
            {
                return Err(ATTEMPT_CORRELATION_INVALID);
            }
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationIdentity {
    run_key_sha256: String,
    definition_sha256: String,
    receipt_id_sha256: String,
    plan_id_sha256: String,
    node_id_sha256: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationHorizon {
    sequence: u64,
    #[serde(deserialize_with = "required_nullable")]
    event_sha256: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationKnown {
    state: ObservationState,
    attempts: u32,
    #[serde(deserialize_with = "required_nullable")]
    failure: Option<ObservationFailure>,
    cleanup: ObservationCleanup,
    events: Vec<ObservationEvent>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationEvent {
    sequence: u64,
    state: ObservationState,
    event_sha256: String,
}

strict_string_enum!(ObservationState {
    Planned => "planned",
    AwaitingApproval => "awaiting_approval",
    Queued => "queued",
    Preparing => "preparing",
    Running => "running",
    SucceededTransport => "succeeded_transport",
    Verifying => "verifying",
    Verified => "verified",
    Failed => "failed",
    VerificationFailed => "verification_failed",
    TimedOut => "timed_out",
    Cancelled => "cancelled",
    Blocked => "blocked",
});

strict_string_enum!(ObservationFailure {
    Authentication => "authentication",
    RateLimit => "rate_limit",
    Timeout => "timeout",
    Crash => "crash",
    Network => "network",
    Policy => "policy",
    Verification => "verification",
    Interrupted => "interrupted",
    OutputLimit => "output_limit",
    Spawn => "spawn",
    Unclassified => "unclassified",
});

strict_string_enum!(ObservationCleanup {
    Unknown => "unknown",
    NotStarted => "not_started",
    GroupTerminated => "group_terminated",
    NamespaceTerminated => "namespace_terminated",
});

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationUnknowns {
    requested_model: Unknown,
    requested_effort: Unknown,
    observed_model: Unknown,
    observed_effort: Unknown,
    transport: Unknown,
    validation: Unknown,
    objective: Unknown,
    duration: Unknown,
    journal_authenticity: Unknown,
    process_liveness: Unknown,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationCompleteness {
    journal: Complete,
    external_observations: Unknown,
    detail: Redacted,
}

strict_string_enum!(Unknown { Unknown => "unknown" });
strict_string_enum!(Complete { Complete => "complete" });
strict_string_enum!(Redacted { Redacted => "redacted" });

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationAttempt {
    ordinal: u32,
    attempt_key_sha256: String,
    evidence: ObservationEvidence,
    #[serde(deserialize_with = "required_nullable")]
    requested: Option<ObservationRequested>,
    #[serde(deserialize_with = "required_nullable")]
    transport: Option<ObservationTransport>,
    sources: ObservationSources,
    capture: ObservationCapture,
    protocol: Unknown,
    native: ObservationNative,
}

strict_string_enum!(ObservationEvidence {
    Unknown => "unknown",
    DurableAttempt => "durable_attempt",
});

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationRequested {
    model: String,
    effort: ObservationEffort,
}

strict_string_enum!(ObservationEffort {
    None => "none",
    Minimal => "minimal",
    Low => "low",
    Medium => "medium",
    High => "high",
    Xhigh => "xhigh",
    Max => "max",
    Ultra => "ultra",
});

impl From<ObservationEffort> for router_types::EffortLevel {
    fn from(value: ObservationEffort) -> Self {
        match value {
            ObservationEffort::None => Self::None,
            ObservationEffort::Minimal => Self::Minimal,
            ObservationEffort::Low => Self::Low,
            ObservationEffort::Medium => Self::Medium,
            ObservationEffort::High => Self::High,
            ObservationEffort::Xhigh => Self::Xhigh,
            ObservationEffort::Max => Self::Max,
            ObservationEffort::Ultra => Self::Ultra,
        }
    }
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationTransport {
    termination: ObservationTermination,
    #[serde(deserialize_with = "required_nullable")]
    exit_code: Option<i32>,
}

strict_string_enum!(ObservationTermination {
    Exited => "exited",
    TimedOut => "timed_out",
    Cancelled => "cancelled",
    Killed => "killed",
    SpawnFailed => "spawn_failed",
});

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationSources {
    started_event_sha256: String,
    #[serde(deserialize_with = "required_nullable")]
    attempt_evidence_sha256: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    finished_event_sha256: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    transition_event_sha256: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    output_incomplete_event_sha256: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    protocol_event_sha256: Option<String>,
}

strict_string_enum!(ObservationCapture {
    Unknown => "unknown",
    Incomplete => "incomplete",
    OutputLimit => "output_limit",
    OutputLimitIncomplete => "output_limit_incomplete",
});

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationNative {
    observed_model: Unknown,
    observed_effort: Unknown,
    thread_id: Unknown,
    turn_id: Unknown,
    usage: Unknown,
    notification_delivery: Unknown,
    lost_notifications: Unknown,
    duration: Unknown,
    validation: Unknown,
    objective: Unknown,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PhysicalEnvelope {
    schema_version: u32,
    physical: Vec<SuppliedPhysical>,
}

fn attempt_bytes(path: &Path) -> Result<Vec<u8>, CliError> {
    read_bounded(
        path,
        router_feedback::MAX_ATTEMPT_CORRELATION_BYTES,
        ATTEMPT_CORRELATION_INVALID,
        ATTEMPT_CORRELATION_INVALID,
    )
}

fn strict_document<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CliError> {
    let value = router_adapter_api::strict_json_limited(
        bytes,
        router_feedback::MAX_ATTEMPT_CORRELATION_BYTES,
    )
    .map_err(|_| ATTEMPT_CORRELATION_INVALID)?;
    serde_json::from_value(value).map_err(|_| ATTEMPT_CORRELATION_INVALID)
}

fn digest(value: &str) -> Result<(), CliError> {
    router_adapter_api::is_digest(value)
        .then_some(())
        .ok_or(ATTEMPT_CORRELATION_INVALID)
}

fn project_observation(
    observation: ObservationV2,
    authority_sha256: String,
    physical: PhysicalEnvelope,
) -> Result<AttemptCorrelationInput, CliError> {
    if !matches!(observation.schema_version, 2 | 3)
        || physical.schema_version != 1
        || observation.horizon.sequence > 100_000
        || observation.known.attempts as usize != observation.attempts.len()
        || observation.attempts.len() > 5
        || observation.known.events.is_empty()
        || observation.known.events.len() > 4096
    {
        return Err(ATTEMPT_CORRELATION_INVALID);
    }
    digest(&observation.snapshot_sha256)?;
    for value in [
        &observation.identity.run_key_sha256,
        &observation.identity.definition_sha256,
        &observation.identity.receipt_id_sha256,
        &observation.identity.plan_id_sha256,
        &observation.identity.node_id_sha256,
    ] {
        digest(value)?;
    }
    if let Some(value) = &observation.horizon.event_sha256 {
        digest(value)?;
    }
    for event in &observation.known.events {
        if event.sequence == 0 || event.sequence > 100_000 {
            return Err(ATTEMPT_CORRELATION_INVALID);
        }
        digest(&event.event_sha256)?;
    }

    let mut attempts = Vec::with_capacity(observation.attempts.len());
    for attempt in observation.attempts {
        if !(1..=5).contains(&attempt.ordinal) {
            return Err(ATTEMPT_CORRELATION_INVALID);
        }
        digest(&attempt.attempt_key_sha256)?;
        digest(&attempt.sources.started_event_sha256)?;
        if attempt.sources.protocol_event_sha256.is_some() {
            return Err(ATTEMPT_CORRELATION_INVALID);
        }
        let optional_sources = [
            &attempt.sources.attempt_evidence_sha256,
            &attempt.sources.finished_event_sha256,
            &attempt.sources.transition_event_sha256,
            &attempt.sources.output_incomplete_event_sha256,
        ];
        for value in optional_sources.into_iter().flatten() {
            digest(value)?;
        }
        let complete_sources = attempt.sources.attempt_evidence_sha256.is_some()
            && attempt.sources.finished_event_sha256.is_some()
            && attempt.sources.transition_event_sha256.is_some();
        let incomplete_capture = matches!(
            attempt.capture,
            ObservationCapture::Incomplete | ObservationCapture::OutputLimitIncomplete
        );
        if incomplete_capture != attempt.sources.output_incomplete_event_sha256.is_some() {
            return Err(ATTEMPT_CORRELATION_INVALID);
        }
        match attempt.evidence {
            ObservationEvidence::Unknown
                if attempt.requested.is_none()
                    && attempt.transport.is_none()
                    && !complete_sources
                    && attempt.sources.attempt_evidence_sha256.is_none()
                    && attempt.sources.finished_event_sha256.is_none()
                    && attempt.sources.transition_event_sha256.is_none()
                    && attempt.sources.output_incomplete_event_sha256.is_none()
                    && attempt.capture == ObservationCapture::Unknown => {}
            ObservationEvidence::DurableAttempt
                if attempt.requested.is_some()
                    && attempt.transport.is_some()
                    && complete_sources => {}
            _ => return Err(ATTEMPT_CORRELATION_INVALID),
        }
        attempts.push(SuppliedAttempt {
            ordinal: attempt.ordinal,
            attempt_key_sha256: attempt.attempt_key_sha256,
            evidence: match attempt.evidence {
                ObservationEvidence::Unknown => SuppliedAttemptEvidence::Unknown,
                ObservationEvidence::DurableAttempt => SuppliedAttemptEvidence::DurableAttempt,
            },
            requested: attempt.requested.map(|requested| SuppliedRequested {
                model: requested.model,
                effort: requested.effort.into(),
            }),
        });
    }
    Ok(AttemptCorrelationInput {
        schema_version: 1,
        runtime: SuppliedRuntime {
            authority_sha256,
            snapshot_sha256: observation.snapshot_sha256,
            run_key_sha256: observation.identity.run_key_sha256,
            definition_sha256: observation.identity.definition_sha256,
            attempts,
        },
        physical: physical.physical,
    })
}

fn error(error: EvalError) -> CliError {
    CliError::Product(match error {
        EvalError::Invalid(_) => "eval.invalid",
        EvalError::Limit(_) => "eval.limit",
        EvalError::Integrity => "eval.integrity",
        EvalError::UnknownModel => "eval.model.unknown",
        EvalError::UnknownPricing => "eval.pricing.unknown",
        EvalError::CostOverflow => "eval.pricing.overflow",
        EvalError::UnknownPolicy => "eval.policy.unknown",
        EvalError::Snapshot(_) => "eval.snapshot.invalid",
        EvalError::Catalog => "eval.catalog.invalid",
        EvalError::Backend => "eval.backend.failed",
    })
}
fn bytes(path: &Path) -> Result<Vec<u8>, CliError> {
    read_bounded(
        path,
        router_eval::MAX_REPLAY_BYTES,
        CliError::RequestRead,
        CliError::RequestTooLarge,
    )
}
fn validation(now: Option<u64>, max_age_seconds: u64) -> Result<SnapshotValidation, CliError> {
    Ok(SnapshotValidation {
        now_unix_seconds: inspect::current_time(now)?,
        max_age_seconds,
    })
}
pub(crate) fn replay(
    path: &Path,
    policy: &str,
    store: Option<&Path>,
    now: Option<u64>,
    max_age: u64,
    json: bool,
) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    let record = ReplayRecord::from_json(&bytes(path)?).map_err(error)?;
    let verifier = store
        .map(|store| crate::capability_proofs::historical_replay(store, &record))
        .transpose()?;
    let trace = replay_deterministic_with_verifier(
        &record,
        policy,
        validation(now, max_age)?,
        verifier.as_deref(),
    )
    .map_err(error)?;
    json_output(&trace, ExitCode::SUCCESS)
}
pub(crate) fn run(command: EvalCommand) -> Result<Outcome, CliError> {
    match command {
        EvalCommand::EvaluatorQualification { input, json } => {
            if !json {
                return Err(CliError::JsonOutputRequired);
            }
            let raw = read_bounded(
                &input,
                router_eval::MAX_EVALUATOR_QUALIFICATION_BYTES,
                CliError::RequestRead,
                CliError::RequestTooLarge,
            )?;
            let report = router_eval::evaluator_qualification_report(&raw)
                .map_err(|_| CliError::Product("eval.evaluator_qualification.invalid"))?;
            json_output(&report, ExitCode::SUCCESS)
        }
        EvalCommand::SuppliedUsagePricing {
            input,
            portable,
            json,
        } => {
            if !json {
                return Err(CliError::JsonOutputRequired);
            }
            let raw = read_bounded(
                &input,
                router_feedback::MAX_SUPPLIED_USAGE_PRICING_BYTES,
                CliError::RequestRead,
                CliError::RequestTooLarge,
            )?;
            let report = router_feedback::supplied_usage_pricing_report(&raw)
                .map_err(|_| CliError::Product("eval.supplied_usage_pricing.invalid"))?;
            if portable {
                json_output(&report.portable_pricing, ExitCode::SUCCESS)
            } else {
                json_output(&report, ExitCode::SUCCESS)
            }
        }
        EvalCommand::AttemptCorrelation {
            input,
            observation,
            physical,
            runtime_authority_sha256,
            json,
        } => {
            if !json {
                return Err(CliError::JsonOutputRequired);
            }
            let report = match (input, observation, physical, runtime_authority_sha256) {
                (Some(input), None, None, None) => {
                    router_feedback::attempt_correlation_report(&attempt_bytes(&input)?)
                        .map_err(|_| ATTEMPT_CORRELATION_INVALID)?
                }
                (None, Some(observation), Some(physical), Some(authority)) => {
                    let observation = observation_document(&attempt_bytes(&observation)?)?;
                    let physical = strict_document(&attempt_bytes(&physical)?)?;
                    let input = project_observation(observation, authority, physical)?;
                    router_feedback::calculate_attempt_correlation(&input)
                        .map_err(|_| ATTEMPT_CORRELATION_INVALID)?
                }
                _ => return Err(ATTEMPT_CORRELATION_INVALID),
            };
            json_output(&report, ExitCode::SUCCESS)
        }
        EvalCommand::AcceptedChanges { input, json } => {
            if !json {
                return Err(CliError::JsonOutputRequired);
            }
            let raw = read_bounded(
                &input,
                router_feedback::MAX_ACCEPTED_CHANGES_BYTES,
                CliError::RequestRead,
                CliError::RequestTooLarge,
            )?;
            let report = router_feedback::accepted_changes_report(&raw)
                .map_err(|_| CliError::Product("eval.accepted_changes.invalid"))?;
            json_output(&report, ExitCode::SUCCESS)
        }
        EvalCommand::Tradeoffs {
            cohort,
            records,
            json,
        } => {
            if !json {
                return Err(CliError::JsonOutputRequired);
            }
            if records.is_empty() || records.len() > router_eval::MAX_EVALUATION_CASES {
                return Err(CliError::Product("eval.limit"));
            }
            let raw = read_bounded(
                &cohort,
                router_eval::MAX_METRICS_COHORT_BYTES,
                CliError::RequestRead,
                CliError::RequestTooLarge,
            )?;
            let cohort = router_eval::TradeoffCohort::from_json(&raw).map_err(error)?;
            let mut total = 0usize;
            let mut inputs = Vec::new();
            for path in records {
                let raw = bytes(&path)?;
                total = total
                    .checked_add(raw.len())
                    .ok_or(CliError::Product("eval.limit"))?;
                if total > router_eval::MAX_METRICS_RECORD_BYTES {
                    return Err(CliError::Product("eval.limit"));
                }
                inputs.push(ReplayRecord::from_json(&raw).map_err(error)?);
            }
            json_output(
                &router_eval::evaluate_tradeoffs(&cohort, &inputs).map_err(error)?,
                ExitCode::SUCCESS,
            )
        }
        EvalCommand::Metrics {
            cohort,
            records,
            json,
        } => {
            if !json {
                return Err(CliError::JsonOutputRequired);
            }
            if records.is_empty() || records.len() > router_eval::MAX_EVALUATION_CASES {
                return Err(CliError::Product("eval.limit"));
            }
            let input = read_bounded(
                &cohort,
                router_eval::MAX_METRICS_COHORT_BYTES,
                CliError::RequestRead,
                CliError::RequestTooLarge,
            )?;
            let cohort = router_eval::MetricsCohort::from_json(&input).map_err(error)?;
            let mut total = 0usize;
            let mut inputs = Vec::new();
            for path in records {
                let raw = bytes(&path)?;
                total = total
                    .checked_add(raw.len())
                    .ok_or(CliError::Product("eval.limit"))?;
                if total > router_eval::MAX_METRICS_RECORD_BYTES {
                    return Err(CliError::Product("eval.limit"));
                }
                inputs.push(ReplayRecord::from_json(&raw).map_err(error)?);
            }
            json_output(
                &router_eval::evaluate_metrics(&cohort, &inputs).map_err(error)?,
                ExitCode::SUCCESS,
            )
        }
        EvalCommand::Seal { input, json } => {
            if !json {
                return Err(CliError::JsonOutputRequired);
            }
            let input = read_json(&input, router_eval::MAX_REPLAY_BYTES)?;
            json_output(
                &ReplayRecord::seal(input).map_err(error)?,
                ExitCode::SUCCESS,
            )
        }
        EvalCommand::Corpus { corpus, json } => {
            if !json {
                return Err(CliError::JsonOutputRequired);
            }
            let corpus = CandidateCorpus::from_json(&bytes(&corpus)?).map_err(error)?;
            json_output(
                &serde_json::json!({"schema_version":1,"valid":true,"content_hash":corpus.content_hash().map_err(error)?,"corpus":corpus}),
                ExitCode::SUCCESS,
            )
        }
        EvalCommand::Compare {
            store,
            records,
            baseline,
            candidate,
            criteria,
            now,
            snapshot_max_age_seconds,
            json,
        } => {
            if !json {
                return Err(CliError::JsonOutputRequired);
            }
            if records.len() > router_eval::MAX_EVALUATION_CASES {
                return Err(CliError::Product("eval.limit"));
            }
            let validation = validation(now, snapshot_max_age_seconds)?;
            let criteria = criteria
                .as_ref()
                .map(|path| read_json(path, 64 * 1024))
                .transpose()?;
            let mut pairs = Vec::new();
            for path in records {
                let record = ReplayRecord::from_json(&bytes(&path)?).map_err(error)?;
                let verifier = store
                    .as_deref()
                    .map(|store| crate::capability_proofs::historical_replay(store, &record))
                    .transpose()?;
                pairs.push(PairedTrace {
                    baseline: replay_deterministic_with_verifier(
                        &record,
                        &baseline,
                        validation,
                        verifier.as_deref(),
                    )
                    .map_err(error)?,
                    semantic: replay_deterministic_with_verifier(
                        &record,
                        &candidate,
                        validation,
                        verifier.as_deref(),
                    )
                    .map_err(error)?,
                });
            }
            let report = compare_shadow(&pairs, criteria.as_ref()).map_err(error)?;
            let code = if report.promotion_blockers.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(3)
            };
            json_output(&report, code)
        }
    }
}
