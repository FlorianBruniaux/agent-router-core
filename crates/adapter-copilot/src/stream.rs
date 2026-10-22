use router_adapter_api::{
    AdapterError, MAX_TRANSPORT_BYTES, MAX_TRANSPORT_EVENTS, is_final_segment, safe_identifier,
    strict_json,
};
use router_types::{
    RuntimeEvidence, TransportEvent, TransportEventKind, TransportOutcome, TransportTermination,
    VerificationOutcome,
};

pub(crate) fn decode(
    bytes: &[u8],
    outcome: TransportOutcome,
    max_bytes: usize,
) -> Result<RuntimeEvidence, AdapterError> {
    parse(bytes, outcome, max_bytes, false).map(|(evidence, _)| evidence)
}

pub(crate) fn final_text(
    bytes: &[u8],
    outcome: TransportOutcome,
    max_bytes: usize,
) -> Result<Option<String>, AdapterError> {
    parse(bytes, outcome, max_bytes, true).map(|(_, text)| text)
}

fn parse(
    bytes: &[u8],
    outcome: TransportOutcome,
    max_bytes: usize,
    collect_text: bool,
) -> Result<(RuntimeEvidence, Option<String>), AdapterError> {
    if max_bytes == 0 || max_bytes > MAX_TRANSPORT_BYTES || bytes.len() > max_bytes {
        return Err(AdapterError::OutputLimit);
    }
    if outcome.termination == TransportTermination::Exited && outcome.exit_code.is_none() {
        return Err(AdapterError::Invalid("transport status"));
    }
    let mut events = Vec::new();
    let mut session: Option<String> = None;
    let mut terminal = false;
    let mut truncated = false;
    let mut final_message = None;
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        if events.len() >= MAX_TRANSPORT_EVENTS || line.len() > 256 * 1024 {
            return Err(AdapterError::OutputLimit);
        }
        let value = match strict_json(line) {
            Ok(value) => value,
            Err(_)
                if outcome.termination != TransportTermination::Exited
                    && !bytes.ends_with(b"\n")
                    && is_final_segment(bytes, line) =>
            {
                truncated = true;
                break;
            }
            Err(_) => return Err(AdapterError::Protocol),
        };
        let kind = value
            .get("type")
            .and_then(|v| v.as_str())
            .filter(|v| safe_identifier(v))
            .ok_or(AdapterError::Protocol)?;
        let known = matches!(
            kind,
            "session.start"
                | "session.idle"
                | "session.error"
                | "assistant.turn_start"
                | "assistant.turn_end"
                | "assistant.message"
                | "assistant.message_delta"
                | "assistant.usage"
                | "tool.execution_start"
                | "tool.execution_complete"
        );
        if known
            && (!value.get("data").is_some_and(|v| v.is_object())
                || !value
                    .get("id")
                    .and_then(|v| v.as_str())
                    .is_some_and(safe_identifier)
                || !value
                    .get("timestamp")
                    .and_then(|v| v.as_str())
                    .is_some_and(|v| !v.is_empty() && v.len() <= 64)
                || !value
                    .get("parentId")
                    .is_some_and(|v| v.is_null() || v.as_str().is_some_and(safe_identifier)))
        {
            return Err(AdapterError::Protocol);
        }
        // Subagent and sampling usage is never attributed to the main worker.
        let root = router_adapter_api::copilot_root_event(&value);
        let event = match kind {
            "session.start" if root => {
                if let Some(id) = value.pointer("/data/sessionId") {
                    let id = id
                        .as_str()
                        .filter(|v| safe_identifier(v))
                        .ok_or(AdapterError::Protocol)?;
                    if session.as_ref().is_some_and(|s| s != id) {
                        return Err(AdapterError::Protocol);
                    }
                    session.get_or_insert_with(|| id.to_owned());
                }
                TransportEventKind::SessionStarted
            }
            "assistant.turn_start" if root => {
                terminal = false;
                final_message = None;
                TransportEventKind::TurnStarted
            }
            "assistant.message" | "assistant.message_delta" if root => {
                // A message arriving after result starts unclosed work; the old
                // result cannot authorize a later body as a completed output.
                terminal = false;
                if collect_text && kind == "assistant.message" {
                    final_message = Some(
                        value
                            .pointer("/data/content")
                            .and_then(|v| v.as_str())
                            .ok_or(AdapterError::Protocol)?
                            .to_owned(),
                    );
                }
                TransportEventKind::AssistantMessage
            }
            "session.error" if root => TransportEventKind::HostError,
            "tool.execution_start" | "tool.execution_complete" => TransportEventKind::ToolActivity,
            "result" if root => {
                let id = value
                    .get("sessionId")
                    .and_then(|v| v.as_str())
                    .filter(|v| safe_identifier(v))
                    .ok_or(AdapterError::Protocol)?;
                let exit_code = value
                    .get("exitCode")
                    .and_then(|v| v.as_i64())
                    .and_then(|v| i32::try_from(v).ok())
                    .ok_or(AdapterError::Protocol)?;
                if session.as_ref().is_some_and(|s| s != id)
                    || !value
                        .get("timestamp")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty() && s.len() <= 64)
                    || !value.get("usage").is_some_and(|v| v.is_object())
                    || (outcome.termination == TransportTermination::Exited
                        && outcome.exit_code != Some(exit_code))
                {
                    return Err(AdapterError::Protocol);
                }
                session.get_or_insert_with(|| id.to_owned());
                terminal = true;
                if exit_code == 0 {
                    TransportEventKind::TurnCompleted
                } else {
                    TransportEventKind::HostError
                }
            }
            // CLI JSONL filters SDK session.idle and assistant.usage. SDK-shaped
            // data does not establish a compatible live CLI or executed model.
            _ => TransportEventKind::Ignored,
        };
        events.push(TransportEvent {
            sequence: events.len(),
            kind: event,
        });
    }
    let mut missing = vec![
        "validation.not_run".into(),
        "objective.not_verified".into(),
        "model.runtime_unknown".into(),
        "effort.runtime_unknown".into(),
    ];
    if !terminal || truncated {
        missing.push("stream.incomplete".into());
    }
    let evidence = RuntimeEvidence {
        schema_version: 1,
        transport_success: outcome.termination == TransportTermination::Exited
            && outcome.exit_code == Some(0),
        transport: outcome,
        stream_complete: terminal && !truncated,
        validation: VerificationOutcome::Unknown,
        objective: VerificationOutcome::Unknown,
        executed_models: vec![],
        executed_effort: None,
        events,
        missing_evidence: missing,
        // Token usage is not decoded for this host.
        host_usage: None,
    };
    let text = if collect_text
        && evidence.transport_success
        && evidence.stream_complete
        && !evidence
            .events
            .iter()
            .any(|e| e.kind == TransportEventKind::HostError)
    {
        final_message.filter(|s| !s.is_empty())
    } else {
        None
    };
    Ok((evidence, text))
}
