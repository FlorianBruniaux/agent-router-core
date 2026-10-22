use router_adapter_api::{
    AdapterError, MAX_TRANSPORT_BYTES, MAX_TRANSPORT_EVENTS, is_final_segment, safe_identifier,
    strict_json,
};
use router_types::{
    RuntimeEvidence, TransportEvent, TransportEventKind, TransportOutcome, TransportTermination,
    VerificationOutcome,
};
use std::collections::BTreeMap;

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
    let mut message_texts: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut finished_message = None;
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
        let id = value
            .get("sessionID")
            .and_then(|v| v.as_str())
            .filter(|v| safe_identifier(v))
            .ok_or(AdapterError::Protocol)?;
        if value.get("timestamp").and_then(|v| v.as_u64()).is_none()
            || session.as_ref().is_some_and(|s| s != id)
        {
            return Err(AdapterError::Protocol);
        }
        session.get_or_insert_with(|| id.to_owned());
        let expected = match kind {
            "step_start" => Some("step-start"),
            "step_finish" => Some("step-finish"),
            "text" => Some("text"),
            "reasoning" => Some("reasoning"),
            "tool_use" => Some("tool"),
            _ => None,
        };
        if let Some(expected) = expected {
            if value.pointer("/part/type").and_then(|v| v.as_str()) != Some(expected)
                || value.pointer("/part/sessionID").and_then(|v| v.as_str()) != Some(id)
            {
                return Err(AdapterError::Protocol);
            }
        }
        let event = match kind {
            "step_start" => {
                terminal = false;
                finished_message = None;
                TransportEventKind::TurnStarted
            }
            "step_finish" => {
                let reason = value
                    .pointer("/part/reason")
                    .and_then(|v| v.as_str())
                    .ok_or(AdapterError::Protocol)?;
                terminal = reason == "stop";
                if collect_text && terminal {
                    finished_message = Some(part_id(&value, "messageID")?.to_owned());
                }
                TransportEventKind::TurnCompleted
            }
            "text" | "reasoning" => {
                if value
                    .pointer("/part/text")
                    .and_then(|v| v.as_str())
                    .is_none()
                    || value
                        .pointer("/part/time/end")
                        .and_then(|v| v.as_u64())
                        .is_none()
                {
                    return Err(AdapterError::Protocol);
                }
                // Content after a terminal step_finish starts unclosed work; the
                // earlier finish cannot authorize the stream or a final text.
                terminal = false;
                finished_message = None;
                if collect_text && kind == "text" {
                    let message_id = part_id(&value, "messageID")?;
                    let text_id = part_id(&value, "id")?;
                    let text = value
                        .pointer("/part/text")
                        .and_then(|v| v.as_str())
                        .ok_or(AdapterError::Protocol)?;
                    let parts = message_texts.entry(message_id.to_owned()).or_default();
                    if let Some((_, old)) = parts.iter_mut().find(|(id, _)| id == text_id) {
                        *old = text.to_owned();
                    } else {
                        parts.push((text_id.to_owned(), text.to_owned()));
                    }
                }
                TransportEventKind::AssistantMessage
            }
            "tool_use" => {
                if !matches!(
                    value.pointer("/part/state/status").and_then(|v| v.as_str()),
                    Some("completed" | "error")
                ) {
                    return Err(AdapterError::Protocol);
                }
                TransportEventKind::ToolActivity
            }
            "error" => {
                if value
                    .pointer("/error/name")
                    .and_then(|v| v.as_str())
                    .is_none()
                {
                    return Err(AdapterError::Protocol);
                }
                terminal = true;
                TransportEventKind::HostError
            }
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
        // run-v1 prints modelID only in non-JSON output. Text/config fields must
        // not be promoted to evidence of a completed model call.
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
        finished_message
            .and_then(|id| message_texts.remove(&id))
            .map(|parts| {
                parts
                    .into_iter()
                    .map(|(_, text)| text)
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .filter(|s| !s.is_empty())
    } else {
        None
    };
    Ok((evidence, text))
}

fn part_id<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str, AdapterError> {
    value
        .get("part")
        .and_then(|v| v.get(key))
        .and_then(|v| v.as_str())
        .filter(|v| safe_identifier(v))
        .ok_or(AdapterError::Protocol)
}
