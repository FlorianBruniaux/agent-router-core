//! Export of a real run as a sealed replay record. The label comes only from a
//! recorded late fact or a human verdict, never from transport success alone.
use crate::{CliError, Outcome, execution, product::json_output};
use router_eval::{
    CaseLabel, DatasetSplit, ObservedOutcome, RecordedPhase, ReplayInput, ReplayRecord, TokenUsage,
    VerificationOutcomes,
};
use router_feedback::FeedbackStore;
use router_types::{
    FeedbackEvent, FeedbackFactEvent, FeedbackFactKind, FeedbackOrigin, IntegrationOutcome,
    VerificationOutcome,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

pub(crate) struct ExportArgs {
    pub definition: PathBuf,
    pub runtime_store: PathBuf,
    pub pricing: PathBuf,
    pub case_id: String,
    pub family_id: String,
    pub split: String,
    pub output: Option<PathBuf>,
}

/// What the recorded facts say about the executed candidate.
#[derive(Debug, Eq, PartialEq)]
struct Verdict {
    human_validated: bool,
    reviewer: Option<String>,
    evidence_sha256: Option<String>,
    basis: &'static str,
}

fn outcome(value: VerificationOutcome) -> ObservedOutcome {
    match value {
        VerificationOutcome::Passed => ObservedOutcome::Passed,
        VerificationOutcome::Failed => ObservedOutcome::Failed,
        VerificationOutcome::Unknown => ObservedOutcome::Unknown,
    }
}

/// `CaseLabel` can only say "these candidates are expected" or "abstain"
/// (`expect_abstention` is true exactly when the expected set is empty). A
/// rejected candidate is neither, so a negative signal refuses the export.
fn judge(
    verification: Option<(VerificationOutcome, VerificationOutcome, &str)>,
    integration: Option<IntegrationOutcome>,
    human: Option<&FeedbackEvent>,
) -> Result<Verdict, CliError> {
    let human_verdict = human.and_then(|event| event.input.human.as_ref());
    let human_outcome = human_verdict.map(|verdict| verdict.success);
    let (validation, objective) = verification.map_or(
        (VerificationOutcome::Unknown, VerificationOutcome::Unknown),
        |(validation, objective, _)| (validation, objective),
    );
    if integration == Some(IntegrationOutcome::Discarded)
        || validation == VerificationOutcome::Failed
        || objective == VerificationOutcome::Failed
        || human_outcome == Some(VerificationOutcome::Failed)
    {
        return Err(CliError::Product("feedback.replay.rejected"));
    }
    let human_passed = human_outcome == Some(VerificationOutcome::Passed);
    let integrated = integration == Some(IntegrationOutcome::Applied)
        && objective == VerificationOutcome::Passed;
    if !human_passed && !integrated {
        return Err(CliError::Product("feedback.replay.unlabeled"));
    }
    let evidence_sha256 = verification
        .map(|(_, _, digest)| digest.to_owned())
        .or_else(|| human.and_then(|event| event.input.verification_evidence_sha256.clone()));
    Ok(Verdict {
        human_validated: human_passed,
        reviewer: human_verdict
            .filter(|_| human_passed)
            .map(|verdict| verdict.reviewer_sha256.clone()),
        evidence_sha256,
        basis: match (human_passed, integrated) {
            (true, true) => "human_and_integration",
            (true, false) => "human",
            _ => "integration",
        },
    })
}

fn one<'a, T>(mut items: impl Iterator<Item = &'a T>) -> Result<Option<&'a T>, CliError> {
    let first = items.next();
    if items.next().is_some() {
        return Err(CliError::Product("feedback.replay.ambiguous"));
    }
    Ok(first)
}

/// Names of the request fields that carry text written by a person.
fn free_text_fields(request: &router_types::PhaseRouteRequest) -> Vec<&'static str> {
    let task = &request.task;
    let mut fields = vec!["task.objective"];
    for (name, present) in [
        ("task.deliverables", !task.deliverables.is_empty()),
        ("task.constraints", !task.constraints.is_empty()),
        ("task.scope", !task.scope.is_empty()),
        ("task.dependencies", !task.dependencies.is_empty()),
        ("task.acceptance", !task.acceptance.is_empty()),
    ] {
        if present {
            fields.push(name);
        }
    }
    fields
}

/// A partial file must never look like a sealed record: write a private
/// temporary file next to the target, sync it, then link it into place. The
/// link fails if the target exists, so nothing is overwritten.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::os::unix::fs::OpenOptionsExt;
    let name = path.file_name().ok_or(CliError::Product(
        "feedback.replay.output_exists_or_unavailable",
    ))?;
    let mut temporary_name = std::ffi::OsString::from(".");
    temporary_name.push(name);
    temporary_name.push(format!(".tmp-{}", std::process::id()));
    let temporary = path.with_file_name(temporary_name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|_| CliError::Product("feedback.replay.output_exists_or_unavailable"))?;
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| CliError::Product("feedback.replay.output_write"));
    let result = written.and_then(|()| {
        std::fs::hard_link(&temporary, path)
            .map_err(|_| CliError::Product("feedback.replay.output_exists_or_unavailable"))
    });
    let _ = std::fs::remove_file(&temporary);
    result
}

pub(crate) fn export(
    store: &FeedbackStore,
    now: u64,
    args: ExportArgs,
) -> Result<Outcome, CliError> {
    let split: DatasetSplit = serde_json::from_value(serde_json::Value::String(args.split))
        .map_err(|_| CliError::InvalidCommand)?;
    let pricing = match crate::feedback::read_report_pricing(&args.pricing)? {
        crate::feedback::ReportPricing::Legacy(pricing) => pricing,
        crate::feedback::ReportPricing::Qualified(_) => {
            return Err(CliError::Product(
                "feedback.replay.qualified_pricing_unsupported",
            ));
        }
    };
    let source = execution::replay_source(&args.definition, &args.runtime_store)?;
    let key = crate::execution_feedback::run_key(&source.run).map_err(|()| CliError::Internal)?;
    let feedback_error = |_| CliError::Product("feedback.storage_database");
    let events = store.events(now).map_err(feedback_error)?;
    let facts = store.facts(now).map_err(feedback_error)?;
    // `run_hash` covers state and attempts, so one run can hold several
    // automated events. Like `feedback report`, take the latest for the key.
    let runs: Vec<&FeedbackEvent> = events
        .iter()
        .filter(|event| {
            event.input.origin == FeedbackOrigin::Automated
                && event.input.run_key_sha256.as_deref() == Some(&key)
        })
        .collect();
    let automated = runs.iter().max_by_key(|event| event.sequence).copied();
    // A human verdict shares the frozen run identity of one of those events.
    let verdicts: Vec<&FeedbackEvent> = events
        .iter()
        .filter(|event| {
            event.input.origin == FeedbackOrigin::Human
                && (event.input.run_key_sha256.as_deref() == Some(&key)
                    || runs
                        .iter()
                        .any(|auto| auto.input.binding.run_hash == event.input.binding.run_hash))
        })
        .collect();
    let success = |event: &&FeedbackEvent| event.input.human.as_ref().map(|h| h.success);
    if verdicts
        .iter()
        .any(|event| success(event) != success(&verdicts[0]))
    {
        return Err(CliError::Product("feedback.replay.ambiguous"));
    }
    let human = verdicts.iter().max_by_key(|event| event.sequence).copied();
    let mine = |fact: &&FeedbackFactEvent| fact.fact.run_key_sha256 == key;
    let verification = one(facts
        .iter()
        .filter(mine)
        .filter(|fact| matches!(fact.fact.kind, FeedbackFactKind::Verification { .. })))?;
    let integration = one(facts
        .iter()
        .filter(mine)
        .filter(|fact| matches!(fact.fact.kind, FeedbackFactKind::Integration { .. })))?;
    let verification = verification.and_then(|fact| match &fact.fact.kind {
        FeedbackFactKind::Verification {
            validation,
            objective,
            evidence_sha256,
        } => Some((*validation, *objective, evidence_sha256.as_str())),
        FeedbackFactKind::Integration { .. } => None,
    });
    let integration = integration.and_then(|fact| match &fact.fact.kind {
        FeedbackFactKind::Integration { outcome } => Some(*outcome),
        FeedbackFactKind::Verification { .. } => None,
    });
    let verdict = judge(verification, integration, human)?;
    if !source
        .request
        .candidates
        .iter()
        .any(|candidate| candidate.id == source.executed_candidate)
    {
        return Err(CliError::Product(
            "feedback.replay.candidate_outside_request",
        ));
    }
    let outcomes = VerificationOutcomes {
        transport: automated.map_or(ObservedOutcome::Unknown, |event| {
            outcome(event.input.transport)
        }),
        command_validation: outcome(verification.map_or(VerificationOutcome::Unknown, |v| v.0)),
        functional: outcome(verification.map_or(VerificationOutcome::Unknown, |v| v.1)),
    };
    let elapsed_ms = automated.and_then(|event| event.input.measurements.latency_ms);
    let fields = free_text_fields(&source.request);
    let policy_id = source.policy.version.clone();
    // The usage split lives in the automated event, not in the runtime store.
    // `TokenUsage.input_tokens` is the total input, cache included: `price_usage`
    // subtracts the cached part itself. Any undeclared count leaves the usage
    // empty, UNKNOWN, never a row of zeros.
    let usage: Vec<TokenUsage> = automated
        .and_then(|event| event.input.measurements.usage.as_ref())
        .and_then(|host| {
            Some(TokenUsage {
                model: source
                    .request
                    .candidates
                    .iter()
                    .find(|candidate| candidate.id == source.executed_candidate)?
                    .model
                    .clone(),
                input_tokens: host.input_tokens.reported()?,
                cached_input_tokens: host.cached_input_tokens.reported()?,
                output_tokens: host.output_tokens.reported()?,
            })
        })
        .into_iter()
        .collect();
    let usage_status = if usage.is_empty() {
        "unknown"
    } else {
        "host_reported"
    };
    let observation = RecordedPhase {
        usage,
        elapsed_ms,
        fallback_reasons: Vec::new(),
        outcomes,
    };
    let record = ReplayRecord::seal(ReplayInput {
        schema_version: 1,
        case_id: args.case_id,
        family_id: args.family_id,
        split,
        out_of_domain: false,
        request: source.request,
        snapshot: source.snapshot,
        catalog: source.catalog,
        policies: BTreeMap::from([(policy_id.clone(), source.policy)]),
        pricing,
        observations: BTreeMap::from([(policy_id.clone(), observation)]),
        label: Some(CaseLabel {
            human_validated: verdict.human_validated,
            independent: false,
            reviewer_id: verdict.reviewer,
            evidence_sha256: verdict.evidence_sha256,
            expected_candidate_ids: BTreeSet::from([source.executed_candidate.clone()]),
            expect_abstention: false,
        }),
    })
    .map_err(|_| CliError::Product("feedback.replay.invalid"))?;
    let mut report = serde_json::json!({
        "schema_version": 1,
        "input_hash": record.input_hash(),
        "policy_id": policy_id,
        "executed_candidate_id": source.executed_candidate,
        "label": {"basis": verdict.basis, "human_validated": verdict.human_validated, "independent": false},
        "observations": {"usage": usage_status, "elapsed_ms": elapsed_ms},
        "replay_context": if source.uses_assets { "without_asset_authority" } else { "complete" },
        "request_free_text_fields": fields,
    });
    match &args.output {
        Some(path) => {
            let bytes = record.canonical_json().map_err(|_| CliError::Internal)?;
            write_private(path, &bytes)?;
            report["output"] = serde_json::json!(path);
        }
        None => report["record"] = serde_json::to_value(&record).map_err(|_| CliError::Internal)?,
    }
    json_output(&report, ExitCode::SUCCESS)
}
