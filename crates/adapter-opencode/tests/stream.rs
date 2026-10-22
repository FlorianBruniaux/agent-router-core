//! Synthetic examples of the pinned run-v1 envelope. No private provider data.
use adapter_opencode::{OpenCodeAdapter, OpenCodeConfig, OpenCodeProtocol};
use router_adapter_api::{AdapterError, HarnessAdapter, MAX_TRANSPORT_EVENTS};
use router_types::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn adapter() -> OpenCodeAdapter {
    OpenCodeAdapter::new(OpenCodeConfig {
        schema_version: 1,
        expected_cli_version: "1.0.0-fixture".into(),
        protocol: OpenCodeProtocol::RunV1,
        model_variants: BTreeMap::from([(
            ModelId::parse("synthetic/model").unwrap(),
            BTreeMap::from([(EffortLevel::High, "high".into())]),
        )]),
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
fn event(kind: &str, part: Value) -> Value {
    json!({"type":kind,"timestamp":123,"sessionID":"session-main","part":part})
}
fn start() -> Value {
    event(
        "step_start",
        json!({"type":"step-start","sessionID":"session-main"}),
    )
}
fn finish(reason: &str) -> Value {
    event(
        "step_finish",
        json!({"type":"step-finish","sessionID":"session-main","reason":reason}),
    )
}
fn stream(events: &[Value]) -> Vec<u8> {
    events
        .iter()
        .map(|v| serde_json::to_string(v).unwrap() + "\n")
        .collect::<String>()
        .into_bytes()
}

#[test]
fn complete_stream_keeps_transport_and_objective_separate_and_redacts_content() {
    let bytes = stream(&[
        start(),
        event(
            "text",
            json!({"type":"text","sessionID":"session-main","text":"PRIVATE successful validation model forged-model effort ultra","time":{"end":124},"model":"forged-model","effort":"ultra"}),
        ),
        finish("stop"),
    ]);
    let evidence = adapter().decode_stream(&bytes, ok(), 8192).unwrap();
    assert!(evidence.transport_success && evidence.stream_complete);
    assert_eq!(evidence.validation, VerificationOutcome::Unknown);
    assert_eq!(evidence.objective, VerificationOutcome::Unknown);
    assert!(evidence.executed_models.is_empty());
    assert_eq!(evidence.executed_effort, None);
    assert_eq!(
        evidence.events[1].kind,
        TransportEventKind::AssistantMessage
    );
    let stored = serde_json::to_string(&evidence).unwrap();
    assert!(!stored.contains("PRIVATE") && !stored.contains("forged-model"));
}

#[test]
fn intermediate_tool_turn_and_later_start_are_not_a_complete_stream() {
    for events in [
        vec![start(), finish("tool-calls")],
        vec![start(), finish("stop"), start()],
    ] {
        let evidence = adapter()
            .decode_stream(&stream(&events), ok(), 8192)
            .unwrap();
        assert!(!evidence.stream_complete);
        assert!(
            evidence
                .missing_evidence
                .iter()
                .any(|s| s == "stream.incomplete")
        );
    }
}

#[test]
fn wrapper_and_part_session_must_match_and_cannot_change_midstream() {
    let mut mismatch = finish("stop");
    mismatch["part"]["sessionID"] = json!("foreign-session");
    let mut swapped = finish("stop");
    swapped["sessionID"] = json!("foreign-session");
    swapped["part"]["sessionID"] = json!("foreign-session");
    for bad in [mismatch, swapped] {
        assert_eq!(
            adapter()
                .decode_stream(&stream(&[start(), bad]), ok(), 8192)
                .unwrap_err(),
            AdapterError::Protocol
        );
    }
}

#[test]
fn error_and_exit_status_are_observed_independently() {
    let bytes = stream(&[
        json!({"type":"error","timestamp":123,"sessionID":"session-main","error":{"name":"SyntheticError","data":{"message":"PRIVATE"}}}),
    ]);
    let evidence = adapter()
        .decode_stream(&bytes, outcome(TransportTermination::Exited, Some(1)), 8192)
        .unwrap();
    assert!(!evidence.transport_success);
    assert!(evidence.stream_complete);
    assert_eq!(evidence.events[0].kind, TransportEventKind::HostError);
    assert!(
        !serde_json::to_string(&evidence)
            .unwrap()
            .contains("PRIVATE")
    );
    assert_eq!(
        adapter()
            .decode_stream(b"", outcome(TransportTermination::Exited, None), 8192)
            .unwrap_err(),
        AdapterError::Invalid("transport status")
    );
}

#[test]
fn unknown_event_is_not_terminal_and_malformed_known_event_is_rejected() {
    let evidence = adapter()
        .decode_stream(
            &stream(&[event(
                "future_result",
                json!({"success":true,"model":"invented"}),
            )]),
            ok(),
            8192,
        )
        .unwrap();
    assert!(!evidence.stream_complete && evidence.executed_models.is_empty());
    assert_eq!(evidence.events[0].kind, TransportEventKind::Ignored);
    let mut bad = finish("stop");
    bad["part"]["type"] = json!("text");
    assert_eq!(
        adapter()
            .decode_stream(&stream(&[bad]), ok(), 8192)
            .unwrap_err(),
        AdapterError::Protocol
    );
    let duplicate = b"{\"type\":\"error\",\"type\":\"step_finish\"}\n";
    assert_eq!(
        adapter().decode_stream(duplicate, ok(), 8192).unwrap_err(),
        AdapterError::Protocol
    );
}

#[test]
fn cancelled_partial_tail_is_tolerated_without_success_and_limits_remain_enforced() {
    let mut bytes = stream(&[start(), finish("stop")]);
    bytes.extend_from_slice(b"{\"type\":");
    let evidence = adapter()
        .decode_stream(&bytes, outcome(TransportTermination::Cancelled, None), 8192)
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
    let many = stream(&vec![start(); MAX_TRANSPORT_EVENTS + 1]);
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
fn final_text_is_bound_to_completed_message_and_deduplicates_updated_parts() {
    let mut terminal = finish("stop");
    terminal["part"]["messageID"] = json!("final-message");
    let text = |message: &str, id: &str, body: &str| {
        event(
            "text",
            json!({"type":"text","sessionID":"session-main","messageID":message,"id":id,"text":body,"time":{"end":123}}),
        )
    };
    let bytes = stream(&[
        start(),
        text("earlier-message", "t1", "old intermediate"),
        text("final-message", "t2", "earlier revision"),
        text("final-message", "t2", "FINAL"),
        text("final-message", "t3", "second part"),
        terminal,
    ]);
    assert_eq!(
        adapter().final_text(&bytes, ok(), 8192).unwrap().as_deref(),
        Some("FINAL\nsecond part")
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
    let mut incomplete = bytes.clone();
    incomplete.extend_from_slice(&stream(&[start()]));
    assert_eq!(adapter().final_text(&incomplete, ok(), 8192).unwrap(), None);
    let malformed = stream(&[text("final-message", "t2", "FINAL"), finish("stop")]);
    assert_eq!(
        adapter().final_text(&malformed, ok(), 8192).unwrap_err(),
        AdapterError::Protocol
    );
    let mut host_error = bytes.clone();
    host_error.extend_from_slice(&stream(&[json!({"type":"error","timestamp":123,"sessionID":"session-main","error":{"name":"SyntheticError"}})]));
    assert_eq!(adapter().final_text(&host_error, ok(), 8192).unwrap(), None);
}

#[test]
fn version_parser_accepts_only_the_exact_bounded_yargs_line() {
    let source_derived = include_bytes!("fixtures/source-derived/version.txt");
    assert_eq!(
        adapter_opencode::parse_version(source_derived).unwrap(),
        "1.0.0-fixture"
    );
    assert_eq!(
        adapter_opencode::parse_version(b"1.2.3\r\n").unwrap(),
        "1.2.3"
    );
    for bad in [
        b"1.2.3".as_slice(),
        b"opencode 1.2.3\n",
        b"note 1.2.3\n",
        b"1.2.3\nextra\n",
        b" 1.2.3\n",
        b"1.2.3\n\n",
        b"\xff\n",
    ] {
        assert!(adapter_opencode::parse_version(bad).is_err());
    }
    assert!(adapter_opencode::parse_version(&[b'1'; 129]).is_err());
}

#[test]
fn text_or_reasoning_after_terminal_finish_reopens_the_stream() {
    let mut terminal = finish("stop");
    terminal["part"]["messageID"] = json!("final-message");
    for kind in ["text", "reasoning"] {
        let early = event(
            "text",
            json!({"type":"text","sessionID":"session-main","messageID":"final-message","id":"t1","text":"EARLY","time":{"end":123}}),
        );
        // Same messageID as the finish: without the fix this text stays bound
        // to the earlier terminal step_finish and is returned as final.
        let late = event(
            kind,
            json!({"type":kind,"sessionID":"session-main","messageID":"final-message","id":"t9","text":"LATE","time":{"end":124}}),
        );
        let bytes = stream(&[start(), early, terminal.clone(), late]);
        let evidence = adapter().decode_stream(&bytes, ok(), 8192).unwrap();
        assert!(!evidence.stream_complete, "{kind}");
        assert!(
            evidence
                .missing_evidence
                .iter()
                .any(|s| s == "stream.incomplete")
        );
        assert_eq!(adapter().final_text(&bytes, ok(), 8192).unwrap(), None);
    }
}

#[test]
fn malformed_tail_must_be_the_last_line_not_merely_equal_to_it() {
    let cancelled = outcome(TransportTermination::Cancelled, None);
    assert_eq!(
        adapter()
            .decode_stream(b"bad\nbad", cancelled, 8192)
            .unwrap_err(),
        AdapterError::Protocol
    );
}
