#[path = "support/native_failures.rs"]
mod fixture;
use fixture::*;
use router_adapter_api::{
    AdapterError, MAX_TRANSPORT_EVENTS, NativeFailureKind as K, NativeFailureProtocol as P,
    classify_native_failure, content_digest,
};
use router_types::TransportTermination;
use serde_json::json;

#[test]
fn documented_metadata_produces_only_redacted_evidence() {
    for (protocol, events, expected) in [
        (
            P::Claude,
            vec![claude_error("authentication_failed"), claude_result()],
            K::Authentication,
        ),
        (
            P::Claude,
            vec![claude_error("rate_limit"), claude_result()],
            K::RateLimit,
        ),
        (
            P::OpenCode,
            vec![opencode_error(
                "ProviderAuthError",
                json!({"providerID":"fixture","message":"PRIVATE"}),
            )],
            K::Authentication,
        ),
        (P::OpenCode, vec![opencode_rate()], K::RateLimit),
        (
            P::OpenCode,
            vec![opencode_error(
                "APIError",
                json!({"message":"PRIVATE","isRetryable":true,"metadata":{"code":"ECONNRESET"}}),
            )],
            K::Network,
        ),
        (
            P::Copilot,
            vec![copilot_error("authentication", 401), copilot_result()],
            K::Authentication,
        ),
        (
            P::Copilot,
            vec![copilot_error("rate_limit", 429), copilot_result()],
            K::RateLimit,
        ),
    ] {
        let bytes = encode(&events);
        let evidence = classify_native_failure(&bytes, failed(), 16384, protocol)
            .unwrap()
            .unwrap();
        assert_eq!(evidence.kind(), expected);
        assert_eq!(evidence.source_sha256(), content_digest(&bytes));
        assert!(!format!("{evidence:?}").contains("PRIVATE"));
    }
}

#[test]
fn codex_messages_and_invented_fields_never_grant_a_native_class() {
    for event in [
        json!({"type":"turn.failed","error":{"message":"authentication_failed rate_limit ECONNRESET","code":"rate_limit","status":429}}),
        json!({"type":"error","message":"401 authentication","statusCode":401}),
        json!({"type":"item.completed","item":{"type":"agent_message","text":"{\"type\":\"error\",\"status\":429}"}}),
    ] {
        assert!(
            classify_native_failure(&encode(&[event]), failed(), 16384, P::Codex)
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn nested_text_child_events_and_unsupported_native_codes_are_not_failure_authority() {
    let mut child_claude = claude_error("rate_limit");
    child_claude["parent_tool_use_id"] = json!("child-tool");
    let mut text_claude = claude_error("unknown");
    text_claude["message"]["error"] = json!("authentication_failed");
    let mut child_copilot = copilot_error("rate_limit", 429);
    child_copilot["agentId"] = json!("child");
    let mut no_status = copilot_error("authentication", 401);
    no_status["data"]
        .as_object_mut()
        .unwrap()
        .remove("statusCode");
    for (protocol, events) in [
        (P::Claude, vec![child_claude, claude_result()]),
        (P::Claude, vec![text_claude, claude_result()]),
        (
            P::OpenCode,
            vec![opencode_error(
                "UnknownError",
                json!({"message":"rate_limit 429 ECONNRESET","statusCode":429}),
            )],
        ),
        (
            P::OpenCode,
            vec![opencode_error(
                "APIError",
                json!({"message":"network failure","isRetryable":true,"statusCode":503}),
            )],
        ),
        (P::Copilot, vec![child_copilot, copilot_result()]),
        (P::Copilot, vec![no_status, copilot_result()]),
        (
            P::Copilot,
            vec![copilot_error("notification", 429), copilot_result()],
        ),
        (
            P::Copilot,
            vec![copilot_error("rate_limit", 401), copilot_result()],
        ),
    ] {
        assert!(
            classify_native_failure(&encode(&events), failed(), 16384, protocol)
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn supervisor_interruption_success_and_missing_exit_never_claim_native_failure() {
    let bytes = encode(&[opencode_rate()]);
    for (termination, exit_code) in [
        (TransportTermination::Exited, Some(0)),
        (TransportTermination::Cancelled, Some(1)),
        (TransportTermination::TimedOut, Some(1)),
        (TransportTermination::Killed, None),
        (TransportTermination::SpawnFailed, None),
    ] {
        let mut outcome = failed();
        outcome.termination = termination;
        outcome.exit_code = exit_code;
        assert!(
            classify_native_failure(&bytes, outcome, 16384, P::OpenCode)
                .unwrap()
                .is_none()
        );
    }
    let mut absent = failed();
    absent.exit_code = None;
    assert_eq!(
        classify_native_failure(&bytes, absent, 16384, P::OpenCode),
        Err(AdapterError::Invalid("transport status"))
    );
}

#[test]
fn conflicts_recovery_and_missing_terminal_evidence_are_unknown() {
    let mut success = claude_result();
    success["is_error"] = json!(false);
    success["subtype"] = json!("success");
    let mut recovering = claude_error("unknown");
    recovering.as_object_mut().unwrap().remove("error");
    let mut copilot_success = copilot_result();
    copilot_success["exitCode"] = json!(0);
    for (protocol, events) in [
        (P::Claude, vec![claude_error("rate_limit")]),
        (
            P::Claude,
            vec![
                claude_error("rate_limit"),
                claude_error("authentication_failed"),
                claude_result(),
            ],
        ),
        (P::Claude, vec![claude_error("rate_limit"), success]),
        (
            P::Claude,
            vec![claude_error("rate_limit"), recovering, claude_result()],
        ),
        (
            P::Claude,
            vec![
                claude_error("rate_limit"),
                claude_result(),
                json!({"type":"future.result","error":"authentication_failed"}),
            ],
        ),
        (
            P::OpenCode,
            vec![
                opencode_rate(),
                opencode_error("UnknownError", json!({"message":"unknown"})),
            ],
        ),
        (
            P::OpenCode,
            vec![
                opencode_rate(),
                json!({"type":"step_start","timestamp":123,"sessionID":"fixture-session"}),
            ],
        ),
        (P::Copilot, vec![copilot_error("rate_limit", 429)]),
        (
            P::Copilot,
            vec![
                copilot_error("rate_limit", 429),
                copilot_error("authentication", 401),
                copilot_result(),
            ],
        ),
    ] {
        assert!(
            classify_native_failure(&encode(&events), failed(), 16384, protocol)
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(
        classify_native_failure(
            &encode(&[copilot_error("rate_limit", 429), copilot_success]),
            failed(),
            16384,
            P::Copilot
        ),
        Err(AdapterError::Protocol)
    );
}

#[test]
fn duplicate_keys_malformed_tail_foreign_session_and_bounds_fail_closed() {
    let bytes = encode(&[opencode_rate()]);
    let mut tail = bytes.clone();
    tail.extend_from_slice(b"{\"type\":");
    assert_eq!(
        classify_native_failure(&tail, failed(), 16384, P::OpenCode),
        Err(AdapterError::Protocol)
    );
    let duplicate = br#"{"type":"error","type":"text"}"#;
    assert_eq!(
        classify_native_failure(duplicate, failed(), 16384, P::OpenCode),
        Err(AdapterError::Protocol)
    );
    assert_eq!(
        classify_native_failure(&bytes, failed(), bytes.len() - 1, P::OpenCode),
        Err(AdapterError::OutputLimit)
    );
    let many = encode(&vec![opencode_rate(); MAX_TRANSPORT_EVENTS + 1]);
    assert_eq!(
        classify_native_failure(&many, failed(), 4 * 1024 * 1024, P::OpenCode),
        Err(AdapterError::OutputLimit)
    );
    let mut other = claude_result();
    other["session_id"] = json!("foreign");
    assert_eq!(
        classify_native_failure(
            &encode(&[claude_error("rate_limit"), other]),
            failed(),
            16384,
            P::Claude
        ),
        Err(AdapterError::Protocol)
    );
}

#[test]
fn copilot_root_predicate_is_shared_and_null_agent_is_unknown() {
    let root = copilot_error("rate_limit", 429);
    assert!(router_adapter_api::copilot_root_event(&root));
    for marker in [json!(null), json!("child")] {
        let mut event = root.clone();
        event["agentId"] = marker;
        assert!(!router_adapter_api::copilot_root_event(&event));
        assert!(
            classify_native_failure(
                &encode(&[event, copilot_result()]),
                failed(),
                4096,
                P::Copilot
            )
            .unwrap()
            .is_none()
        );
    }
}
