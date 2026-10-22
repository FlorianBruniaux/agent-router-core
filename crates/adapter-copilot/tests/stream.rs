//! Synthetic CLI JSONL from the distributed app.js, not a native canary.
use adapter_copilot::{CopilotAdapter, CopilotConfig, CopilotProtocol};
use router_adapter_api::{AdapterError, HarnessAdapter, MAX_TRANSPORT_EVENTS};
use router_types::*;
use serde_json::{Value, json};

fn adapter() -> CopilotAdapter {
    CopilotAdapter::new(CopilotConfig {
        schema_version: 1,
        expected_cli_version: "1.0.88".into(),
        protocol: CopilotProtocol::CliJsonlV1,
    })
    .unwrap()
}
fn outcome(termination: TransportTermination, exit_code: Option<i32>) -> TransportOutcome {
    TransportOutcome {
        termination,
        exit_code,
        elapsed_ms: 7,
    }
}
fn ok() -> TransportOutcome {
    outcome(TransportTermination::Exited, Some(0))
}
fn event(kind: &str, data: Value) -> Value {
    json!({"type":kind,"timestamp":"2026-01-01T00:00:00Z","id":"synthetic-event","parentId":null,"data":data})
}
fn result(code: i32) -> Value {
    json!({"type":"result","timestamp":"2026-01-01T00:00:00Z","sessionId":"session-main","exitCode":code,
        "usage":{"premiumRequests":0,"totalApiDurationMs":7,"sessionDurationMs":7,"codeChanges":{"linesAdded":0,"linesRemoved":0,"filesModified":[]}}})
}
fn usage() -> Value {
    event(
        "assistant.usage",
        json!({"model":"model-claimed","reasoningEffort":"high","interactionType":"conversation-user"}),
    )
}
fn idle() -> Value {
    event("session.idle", json!({"aborted":false}))
}
fn stream(events: &[Value]) -> Vec<u8> {
    events
        .iter()
        .map(|v| serde_json::to_string(v).unwrap() + "\n")
        .collect::<String>()
        .into_bytes()
}

#[test]
fn cli_result_completes_transport_but_never_proves_execution_identity_or_objective() {
    let bytes = stream(&[
        event(
            "session.start",
            json!({"sessionId":"session-main","selectedModel":"configured-only","reasoningEffort":"ultra"}),
        ),
        event("assistant.turn_start", json!({})),
        event(
            "assistant.message",
            json!({"content":"PRIVATE passed all tests model forged-model","model":"forged-model"}),
        ),
        usage(),
        result(0),
    ]);
    let evidence = adapter().decode_stream(&bytes, ok(), 8192).unwrap();
    assert!(evidence.transport_success && evidence.stream_complete);
    assert_eq!(evidence.validation, VerificationOutcome::Unknown);
    assert_eq!(evidence.objective, VerificationOutcome::Unknown);
    assert_eq!(evidence.executed_effort, None);
    assert!(evidence.executed_models.is_empty());
    let stored = serde_json::to_string(&evidence).unwrap();
    assert!(
        !stored.contains("PRIVATE")
            && !stored.contains("forged-model")
            && !stored.contains("configured-only")
            && !stored.contains("model-claimed")
    );
    assert_eq!(
        evidence.events.last().unwrap().kind,
        TransportEventKind::TurnCompleted
    );
}

#[test]
fn sdk_idle_and_usage_are_not_cli_terminal_or_model_evidence() {
    let mut child = usage();
    child["agentId"] = json!("child-agent");
    let mut initiated = usage();
    initiated["data"]["initiator"] = json!("background");
    let mut tool = usage();
    tool["data"]["parentToolCallId"] = json!("tool-1");
    let mut background = usage();
    background["data"]["interactionType"] = json!("background");
    let mut child_result = result(0);
    child_result["agentId"] = json!("child-agent");
    let evidence = adapter()
        .decode_stream(
            &stream(&[
                usage(),
                child,
                initiated,
                tool,
                background,
                idle(),
                child_result,
            ]),
            ok(),
            8192,
        )
        .unwrap();
    assert!(evidence.executed_models.is_empty());
    assert_eq!(evidence.executed_effort, None);
    assert!(!evidence.stream_complete);
    assert!(
        evidence
            .events
            .iter()
            .all(|e| e.kind == TransportEventKind::Ignored)
    );
}

#[test]
fn result_requires_real_shape_consistent_session_and_supervisor_exit_status() {
    let mut missing_usage = result(0);
    missing_usage.as_object_mut().unwrap().remove("usage");
    let mut wrong_session = result(0);
    wrong_session["sessionId"] = json!("other-session");
    let mut wrong_code_type = result(0);
    wrong_code_type["exitCode"] = json!("0");
    for bad in [
        missing_usage,
        wrong_session,
        wrong_code_type,
        result(1),
        json!({"type":"result","success":true}),
    ] {
        assert_eq!(
            adapter()
                .decode_stream(
                    &stream(&[
                        event("session.start", json!({"sessionId":"session-main"})),
                        bad
                    ]),
                    ok(),
                    8192
                )
                .unwrap_err(),
            AdapterError::Protocol
        );
    }
}

#[test]
fn failed_result_is_error_and_new_turn_invalidates_previous_completion() {
    let evidence = adapter()
        .decode_stream(
            &stream(&[result(1)]),
            outcome(TransportTermination::Exited, Some(1)),
            8192,
        )
        .unwrap();
    assert!(!evidence.transport_success && evidence.stream_complete);
    assert_eq!(evidence.events[0].kind, TransportEventKind::HostError);
    let evidence = adapter()
        .decode_stream(
            &stream(&[result(0), event("assistant.turn_start", json!({}))]),
            ok(),
            8192,
        )
        .unwrap();
    assert!(!evidence.stream_complete);
    let error_without_result = adapter()
        .decode_stream(
            &stream(&[event(
                "session.error",
                json!({"errorType":"synthetic","message":"PRIVATE"}),
            )]),
            ok(),
            8192,
        )
        .unwrap();
    assert!(!error_without_result.stream_complete);
    assert_eq!(
        error_without_result.events[0].kind,
        TransportEventKind::HostError
    );
}

#[test]
fn unknown_future_result_is_not_terminal_and_known_envelopes_are_checked() {
    let evidence = adapter()
        .decode_stream(br#"{"type":"future.result","success":true}"#, ok(), 8192)
        .unwrap();
    assert!(!evidence.stream_complete && evidence.executed_models.is_empty());
    for bytes in [
        br#"{"type":"session.idle","data":{}}"#.as_slice(),
        br#"{"type":"session.idle","type":"session.error"}"#.as_slice(),
    ] {
        assert_eq!(
            adapter().decode_stream(bytes, ok(), 8192).unwrap_err(),
            AdapterError::Protocol
        );
    }
    assert_eq!(
        adapter()
            .decode_stream(b"", outcome(TransportTermination::Exited, None), 8192)
            .unwrap_err(),
        AdapterError::Invalid("transport status")
    );
}

#[test]
fn cancellation_partial_tail_and_output_bounds_fail_closed() {
    let mut bytes = stream(&[result(0)]);
    bytes.extend_from_slice(br#"{"type":"#);
    let evidence = adapter()
        .decode_stream(&bytes, outcome(TransportTermination::TimedOut, None), 8192)
        .unwrap();
    assert!(!evidence.transport_success && !evidence.stream_complete);
    assert_eq!(
        adapter().decode_stream(&bytes, ok(), 8192).unwrap_err(),
        AdapterError::Protocol
    );
    assert_eq!(
        adapter()
            .decode_stream(&bytes, ok(), bytes.len() - 1)
            .unwrap_err(),
        AdapterError::OutputLimit
    );
    let many = stream(&vec![idle(); MAX_TRANSPORT_EVENTS + 1]);
    assert_eq!(
        adapter()
            .decode_stream(&many, ok(), 4 * 1024 * 1024)
            .unwrap_err(),
        AdapterError::OutputLimit
    );
    let large_line = stream(&[event("future", json!({"padding":"x".repeat(256 * 1024)}))]);
    assert_eq!(
        adapter()
            .decode_stream(&large_line, ok(), 4 * 1024 * 1024)
            .unwrap_err(),
        AdapterError::OutputLimit
    );
}

#[test]
fn final_text_requires_complete_root_message_and_terminal_result() {
    let mut child = event("assistant.message", json!({"content":"CHILD"}));
    child["agentId"] = json!("child-agent");
    let bytes = stream(&[
        event("assistant.turn_start", json!({})),
        event("assistant.message", json!({"content":"old answer"})),
        event("assistant.message", json!({"content":"FINAL"})),
        child,
        result(0),
    ]);
    assert_eq!(
        adapter().final_text(&bytes, ok(), 8192).unwrap().as_deref(),
        Some("FINAL")
    );
    assert!(
        !serde_json::to_string(&adapter().decode_stream(&bytes, ok(), 8192).unwrap())
            .unwrap()
            .contains("FINAL")
    );
    assert_eq!(
        adapter()
            .final_text(&bytes, outcome(TransportTermination::Cancelled, None), 8192)
            .unwrap(),
        None
    );
    let incomplete = stream(&[
        event("assistant.message_delta", json!({"deltaContent":"partial"})),
        result(0),
    ]);
    assert_eq!(adapter().final_text(&incomplete, ok(), 8192).unwrap(), None);
    let later_message = stream(&[
        result(0),
        event("assistant.message", json!({"content":"after result"})),
    ]);
    assert_eq!(
        adapter().final_text(&later_message, ok(), 8192).unwrap(),
        None
    );
    let reset = stream(&[
        event("assistant.message", json!({"content":"old"})),
        event("assistant.turn_start", json!({})),
        result(0),
    ]);
    assert_eq!(adapter().final_text(&reset, ok(), 8192).unwrap(), None);
    let error = stream(&[
        event("assistant.message", json!({"content":"FINAL"})),
        event("session.error", json!({"message":"failure"})),
        result(0),
    ]);
    assert_eq!(adapter().final_text(&error, ok(), 8192).unwrap(), None);
}

#[test]
fn version_parser_matches_exact_commander_template_without_scanning_substrings() {
    assert_eq!(
        adapter_copilot::parse_version(include_bytes!("fixtures/source-derived/version.txt"))
            .unwrap(),
        "1.0.44"
    );
    assert_eq!(
        adapter_copilot::parse_version(
            b"GitHub Copilot CLI 1.2.3-rc.1.\r\nRun 'copilot update' to check for updates.\r\n"
        )
        .unwrap(),
        "1.2.3-rc.1"
    );
    for bad in [
        b"1.0.44\n".as_slice(),
        b"GitHub Copilot CLI 1.0.44\n",
        b"prefix GitHub Copilot CLI 1.0.44.\nRun 'copilot update' to check for updates.\n",
        b"GitHub Copilot CLI 1.0.44.\nRun 'copilot update' to check for updates.\nextra\n",
        b"GitHub Copilot CLI 1.0.44.\nOTHER\n",
        b"\xff",
    ] {
        assert!(adapter_copilot::parse_version(bad).is_err());
    }
    assert!(adapter_copilot::parse_version(&[b'1'; 257]).is_err());
}

#[test]
fn malformed_tail_must_be_the_last_line_not_merely_equal_to_it() {
    assert_eq!(
        adapter()
            .decode_stream(
                b"bad\nbad",
                outcome(TransportTermination::Cancelled, None),
                8192
            )
            .unwrap_err(),
        AdapterError::Protocol
    );
}
