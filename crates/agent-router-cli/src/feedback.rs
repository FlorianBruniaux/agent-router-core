use crate::{
    CliError, Outcome,
    command::{FeedbackCommand, PolicyCommand},
    inspect,
    phases::read_json,
    product::json_output,
    read_bounded,
};
use router_feedback::{FeedbackError, FeedbackStore};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::ExitCode,
};

fn error(error: FeedbackError) -> CliError {
    CliError::Product(match error {
        FeedbackError::Invalid(_) => "feedback.invalid",
        FeedbackError::Integrity(_) => "feedback.integrity",
        FeedbackError::Consent => "feedback.consent_required",
        FeedbackError::LearningDisabled => "feedback.learning_disabled",
        FeedbackError::Limit => "feedback.limit",
        FeedbackError::Locked => "feedback.storage_locked",
        FeedbackError::NotFound => "feedback.not_found",
        FeedbackError::Gate(_) => "feedback.policy.gate",
        FeedbackError::Signature => "feedback.policy.signature",
        FeedbackError::Io(_) => "feedback.storage_io",
        FeedbackError::Database(e)
            if crate::execution::corruption(e.sqlite_error().map(|f| f.extended_code)) =>
        {
            "feedback.storage_corrupt"
        }
        FeedbackError::Database(_) => "feedback.storage_database",
        FeedbackError::Json(_) => "feedback.serialization",
        FeedbackError::Evaluation(_) => "feedback.evaluation",
    })
}
pub(crate) enum ReportPricing {
    Legacy(router_eval::PricingTable),
    Qualified(router_eval::QualifiedPricingTable),
}
impl ReportPricing {
    fn borrowed(&self) -> router_feedback::FeedbackPricing<'_> {
        match self {
            Self::Legacy(p) => router_feedback::FeedbackPricing::Legacy(p),
            Self::Qualified(p) => router_feedback::FeedbackPricing::Qualified(p),
        }
    }
}
pub(crate) fn read_report_pricing(path: &Path) -> Result<ReportPricing, CliError> {
    let value: serde_json::Value = read_json(path, 64 * 1024)?;
    match value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
    {
        Some(1) => serde_json::from_value(value)
            .map(ReportPricing::Legacy)
            .map_err(|_| CliError::RequestJsonInvalid),
        Some(2) => serde_json::from_value(value)
            .map(ReportPricing::Qualified)
            .map_err(|_| CliError::RequestJsonInvalid),
        _ => Err(CliError::RequestJsonInvalid),
    }
}
fn read_pricing(path: Option<PathBuf>) -> Result<Option<ReportPricing>, CliError> {
    path.as_deref().map(read_report_pricing).transpose()
}

pub(crate) fn feedback(
    path: &Path,
    now: Option<u64>,
    json: bool,
    command: FeedbackCommand,
) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    let now = inspect::current_time(now)?;
    let store = FeedbackStore::open(path).map_err(error)?;
    match command {
        FeedbackCommand::Consent => {
            json_output(&store.consent().map_err(error)?, ExitCode::SUCCESS)
        }
        FeedbackCommand::Configure { preferences } => json_output(
            &store
                .configure(read_json(&preferences, 4096)?, now)
                .map_err(error)?,
            ExitCode::SUCCESS,
        ),
        FeedbackCommand::Record { input } => {
            let bytes = read_bounded(
                &input,
                router_feedback::MAX_INPUT_BYTES,
                CliError::RequestRead,
                CliError::RequestTooLarge,
            )?;
            let input = router_feedback::parse_feedback(&bytes).map_err(error)?;
            json_output(&store.record(input, now).map_err(error)?, ExitCode::SUCCESS)
        }
        FeedbackCommand::Export => {
            json_output(&store.export(now).map_err(error)?, ExitCode::SUCCESS)
        }
        FeedbackCommand::Statistics => {
            json_output(&store.statistics(now).map_err(error)?, ExitCode::SUCCESS)
        }
        FeedbackCommand::Purge { expired_only } => {
            let count = if expired_only {
                store.purge_expired(now)
            } else {
                store.purge_all(now)
            }
            .map_err(error)?;
            json_output(
                &serde_json::json!({"schema_version":1,"purged_events":count,"expired_only":expired_only}),
                ExitCode::SUCCESS,
            )
        }
        FeedbackCommand::ReplayExport {
            definition,
            runtime_store,
            pricing,
            case_id,
            family_id,
            split,
            output,
        } => crate::replay_export::export(
            &store,
            now,
            crate::replay_export::ExportArgs {
                definition,
                runtime_store,
                pricing,
                case_id,
                family_id,
                split,
                output,
            },
        ),
        FeedbackCommand::Drift { rules } => json_output(
            &store.drift(&read_json(&rules, 4096)?, now).map_err(error)?,
            ExitCode::SUCCESS,
        ),
        FeedbackCommand::Report {
            pricing,
            runtime_store,
        } => {
            let pricing = read_pricing(pricing)?;
            let inventory = runtime_store
                .as_deref()
                .map(router_runtime::measurement_inventory)
                .transpose()
                .map_err(crate::execution::error)?;
            let (report, _summary) = store
                .report_and_summary_with_pricing(
                    pricing.as_ref().map(ReportPricing::borrowed),
                    inventory.as_ref(),
                    now,
                )
                .map_err(error)?;
            json_output(&report, ExitCode::SUCCESS)
        }
        FeedbackCommand::Summary {
            pricing,
            runtime_store,
        } => {
            let pricing = read_pricing(pricing)?;
            let inventory = runtime_store
                .as_deref()
                .map(router_runtime::measurement_inventory)
                .transpose()
                .map_err(crate::execution::error)?;
            let (_report, summary) = store
                .report_and_summary_with_pricing(
                    pricing.as_ref().map(ReportPricing::borrowed),
                    inventory.as_ref(),
                    now,
                )
                .map_err(error)?;
            json_output(&summary, ExitCode::SUCCESS)
        }
    }
}
pub(crate) fn policy(
    path: &Path,
    now: Option<u64>,
    json: bool,
    command: PolicyCommand,
) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    let now = inspect::current_time(now)?;
    if let PolicyCommand::SigningPayload { approval } = &command {
        let approval = read_json(approval, 16 * 1024)?;
        let bytes = router_feedback::approval_message(&approval).map_err(error)?;
        // A byte array avoids any text encoding ambiguity for external signers.
        return json_output(
            &serde_json::json!({"schema_version":1,"message_bytes":bytes}),
            ExitCode::SUCCESS,
        );
    }
    let store = FeedbackStore::open(path).map_err(error)?;
    match command {
        PolicyCommand::Baseline { policy } => json_output(
            &store
                .register_baseline(read_json(&policy, 64 * 1024)?, now)
                .map_err(error)?,
            ExitCode::SUCCESS,
        ),
        PolicyCommand::Propose { policy, rules } => json_output(
            &store
                .propose_policy(
                    read_json(&policy, 64 * 1024)?,
                    read_json(&rules, 4096)?,
                    now,
                )
                .map_err(error)?,
            ExitCode::SUCCESS,
        ),
        PolicyCommand::List => json_output(
            &serde_json::json!({"schema_version":1,"policies":store.policies().map_err(error)?}),
            ExitCode::SUCCESS,
        ),
        PolicyCommand::Active => json_output(
            &serde_json::json!({"schema_version":1,"active":store.active_policy().map_err(error)?}),
            ExitCode::SUCCESS,
        ),
        PolicyCommand::Show { id } => {
            json_output(&store.policy(&id).map_err(error)?, ExitCode::SUCCESS)
        }
        PolicyCommand::Digest { id } => json_output(
            &serde_json::json!({"schema_version":1,"artifact_id":id,"gate_hash":store.promotion_digest(&id).map_err(error)?}),
            ExitCode::SUCCESS,
        ),
        PolicyCommand::Evaluate {
            id,
            records,
            baseline,
            candidate,
            criteria,
            snapshot_max_age_seconds,
        } => {
            if records.len() > router_eval::MAX_EVALUATION_CASES {
                return Err(CliError::RequestTooLarge);
            }
            let mut pairs = Vec::new();
            let validation = router_adapter_api::SnapshotValidation {
                now_unix_seconds: now,
                max_age_seconds: snapshot_max_age_seconds,
            };
            for path in records {
                let bytes = read_bounded(
                    &path,
                    router_eval::MAX_REPLAY_BYTES,
                    CliError::RequestRead,
                    CliError::RequestTooLarge,
                )?;
                let record = router_eval::ReplayRecord::from_json(&bytes)
                    .map_err(|_| CliError::Product("eval.invalid"))?;
                pairs.push(router_eval::PairedTrace {
                    baseline: router_eval::replay_deterministic(&record, &baseline, validation)
                        .map_err(|_| CliError::Product("eval.invalid"))?,
                    semantic: router_eval::replay_deterministic(&record, &candidate, validation)
                        .map_err(|_| CliError::Product("eval.invalid"))?,
                });
            }
            let report = store
                .evaluate_proposal(&id, &pairs, &read_json(&criteria, 64 * 1024)?, now)
                .map_err(error)?;
            let code = if report.semantic_enabled {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(3)
            };
            json_output(&report, code)
        }
        PolicyCommand::Trial { id, evidence } => json_output(
            &store
                .record_trial(&id, read_json(&evidence, 16 * 1024)?, now)
                .map_err(error)?,
            ExitCode::SUCCESS,
        ),
        PolicyCommand::Apply {
            approval,
            trusted_keys,
        } => {
            let keys: BTreeSet<String> = read_json(&trusted_keys, 16 * 1024)?;
            // A bad key set is invalid input, not a signature that stopped matching.
            if keys.is_empty() || keys.len() > 32 {
                return Err(CliError::Product("feedback.invalid"));
            }
            json_output(
                &store
                    .apply_signed_action(&read_json(&approval, 16 * 1024)?, &keys, now)
                    .map_err(error)?,
                ExitCode::SUCCESS,
            )
        }
        PolicyCommand::SigningPayload { .. } => Err(CliError::Internal),
    }
}
