use crate::{CliError, Outcome, execution, human, product::json_output};
use router_runtime::RunObservation;
use serde::Serialize;
use std::{path::Path, process::ExitCode};

const HUMAN_EVENT_LIMIT: usize = 20;

pub(crate) fn run(
    store: &Path,
    id: &str,
    schema_version: u32,
    json: bool,
) -> Result<Outcome, CliError> {
    if !(1..=3).contains(&schema_version) {
        return Err(CliError::InvalidCommand);
    }
    if schema_version == 3 {
        let report = router_runtime::observe_run_v3(store, id).map_err(execution::error)?;
        if json {
            return json_output(&report, ExitCode::SUCCESS);
        }
        let mut output = render_v2(&report.observation)?;
        for timing in &report.timings {
            let value = match timing.measurement {
                router_runtime::CaptureTiming::Known { duration_ms } => format!("{duration_ms} ms"),
                router_runtime::CaptureTiming::Unknown { reason } => {
                    format!("unknown ({})", label(&reason)?)
                }
            };
            output.push_str(&format!("Attempt {} local supervisor capture: {} (monotonic; includes dispatch checks, reap and both output drains)\n", timing.ordinal, value));
        }
        return Ok(Outcome {
            output,
            exit_code: ExitCode::SUCCESS,
        });
    }
    if schema_version == 2 {
        let report = router_runtime::observe_run_v2(store, id).map_err(execution::error)?;
        if json {
            return json_output(&report, ExitCode::SUCCESS);
        }
        return Ok(Outcome {
            output: render_v2(&report)?,
            exit_code: ExitCode::SUCCESS,
        });
    }
    let report = router_runtime::observe_run(store, id).map_err(execution::error)?;
    if json {
        return json_output(&report, ExitCode::SUCCESS);
    }
    Ok(Outcome {
        output: render(&report)?,
        exit_code: ExitCode::SUCCESS,
    })
}

fn label(value: &impl Serialize) -> Result<String, CliError> {
    let value = serde_json::to_value(value).map_err(|_| CliError::Internal)?;
    Ok(match value {
        serde_json::Value::String(text) => human::escaped(&text),
        other => other.to_string(),
    })
}

fn render(report: &RunObservation) -> Result<String, CliError> {
    let mut output = format!(
        "Run observation\nSnapshot: {}\nRun key: {}\nState: {} | Attempts: {}\nJournal: {} through global sequence {} | Details: {}\nExternal observations: {}\nModel requested/observed: {}/{} | Effort requested/observed: {}/{}\nTransport: {} | Validation: {} | Objective: {}\nDuration: {}\nProcess liveness: {} | Journal authenticity: {}\nRecorded cleanup: {}\n",
        report.snapshot_sha256,
        report.identity.run_key_sha256,
        label(&report.known.state)?,
        report.known.attempts,
        label(&report.completeness.journal)?,
        report.horizon.sequence,
        label(&report.completeness.detail)?,
        label(&report.completeness.external_observations)?,
        label(&report.unknown.requested_model)?,
        label(&report.unknown.observed_model)?,
        label(&report.unknown.requested_effort)?,
        label(&report.unknown.observed_effort)?,
        label(&report.unknown.transport)?,
        label(&report.unknown.validation)?,
        label(&report.unknown.objective)?,
        label(&report.unknown.duration)?,
        label(&report.unknown.process_liveness)?,
        label(&report.unknown.journal_authenticity)?,
        label(&report.known.cleanup)?,
    );
    if let Some(failure) = &report.known.failure {
        output.push_str(&format!("Recorded failure: {}\n", label(failure)?));
    }
    let omitted = report.known.events.len().saturating_sub(HUMAN_EVENT_LIMIT);
    output.push_str(&format!(
        "Run events: showing {} of {} (sequence, recorded state)\n",
        report.known.events.len() - omitted,
        report.known.events.len(),
    ));
    for event in &report.known.events[omitted..] {
        output.push_str(&format!("  {}: {}\n", event.sequence, label(&event.state)?));
    }
    if omitted > 0 {
        output.push_str(&format!(
            "{} earlier event references omitted from this view; use --json for the full bounded snapshot.\n",
            omitted,
        ));
    }
    Ok(output)
}

fn render_v2(report: &router_runtime::RunObservationV2) -> Result<String, CliError> {
    let mut output = render(&report.summary)?;
    output.push_str("Aggregate fields remain unknown; per-attempt durable evidence follows.\n");
    for attempt in &report.attempts {
        let (model, effort) = match &attempt.requested {
            Some(requested) => (label(&requested.model)?, label(&requested.effort)?),
            None => ("unknown".into(), "unknown".into()),
        };
        let (termination, exit_code) = match &attempt.transport {
            Some(transport) => (
                label(&transport.termination)?,
                transport
                    .exit_code
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "unknown".into()),
            ),
            None => ("unknown".into(), "unknown".into()),
        };
        output.push_str(&format!("Attempt {}\nRequested model: {} | Requested effort: {}\nSupervisor termination: {} | Exit code: {}\nEvidence: {} | Capture: {} | Protocol: {}\n", attempt.ordinal, model, effort, termination, exit_code, label(&attempt.evidence)?, label(&attempt.capture)?, label(&attempt.protocol)?));
    }
    Ok(output)
}
