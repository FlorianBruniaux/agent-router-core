#[path = "../../router-adapter-api/tests/support/native_failures.rs"]
mod fixture;
use fixture::*;
use router_adapter_api::{HarnessAdapter, NativeFailureKind};
use serde_json::json;

fn opencode() -> adapter_opencode::OpenCodeAdapter {
    adapter_opencode::OpenCodeAdapter::from_json(br#"{"schema_version":1,"expected_cli_version":"1.0.0-fixture","protocol":"run_v1","model_variants":{"synthetic/model":{"medium":"medium"}}}"#).unwrap()
}
fn copilot() -> adapter_copilot::CopilotAdapter {
    adapter_copilot::CopilotAdapter::from_json(
        br#"{"schema_version":1,"expected_cli_version":"1.0.44","protocol":"cli_jsonl_v1"}"#,
    )
    .unwrap()
}

#[test]
fn opencode_adapter_uses_native_status_and_connection_code_only() {
    for (events, expected) in [
        (vec![opencode_rate()], NativeFailureKind::RateLimit),
        (
            vec![opencode_error(
                "ProviderAuthError",
                json!({"providerID":"synthetic","message":"PRIVATE"}),
            )],
            NativeFailureKind::Authentication,
        ),
        (
            vec![opencode_error(
                "APIError",
                json!({"message":"PRIVATE","isRetryable":true,"metadata":{"code":"ECONNRESET"}}),
            )],
            NativeFailureKind::Network,
        ),
    ] {
        assert_eq!(
            opencode()
                .classify_failure(&encode(&events), failed(), 4096)
                .unwrap()
                .unwrap()
                .kind(),
            expected
        );
    }
    assert!(
        opencode()
            .classify_failure(
                &encode(&[opencode_error(
                    "UnknownError",
                    json!({"message":"429 authentication ECONNRESET"})
                )]),
                failed(),
                4096
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn copilot_adapter_requires_terminal_result_and_matching_native_status() {
    for (class, status, expected) in [
        ("authentication", 401, NativeFailureKind::Authentication),
        ("rate_limit", 429, NativeFailureKind::RateLimit),
    ] {
        assert_eq!(
            copilot()
                .classify_failure(
                    &encode(&[copilot_error(class, status), copilot_result()]),
                    failed(),
                    4096
                )
                .unwrap()
                .unwrap()
                .kind(),
            expected
        );
    }
    let mut missing_usage = copilot_result();
    missing_usage.as_object_mut().unwrap().remove("usage");
    assert!(
        copilot()
            .classify_failure(
                &encode(&[copilot_error("rate_limit", 429), missing_usage]),
                failed(),
                4096
            )
            .is_err()
    );
    assert!(
        copilot()
            .classify_failure(&encode(&[copilot_error("rate_limit", 429)]), failed(), 4096)
            .unwrap()
            .is_none()
    );
}

#[test]
fn later_answer_delta_cannot_inherit_a_stale_authentication_failure() {
    let delta = json!({"type":"assistant.message_delta","timestamp":"2026-01-01T00:00:01Z",
        "id":"delta-1","parentId":"error-1","data":{"deltaContent":"PRIVATE recovery text"}});
    assert!(
        copilot()
            .classify_failure(
                &encode(&[
                    copilot_error("authentication", 401),
                    delta,
                    copilot_result()
                ]),
                failed(),
                4096
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn later_unknown_root_event_cannot_inherit_a_stale_rate_failure() {
    let event = json!({"type":"future.terminal_error","timestamp":"2026-01-01T00:00:01Z",
        "id":"unknown-1","parentId":"error-1","data":{}});
    assert!(
        copilot()
            .classify_failure(
                &encode(&[copilot_error("rate_limit", 429), event, copilot_result()]),
                failed(),
                4096
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn ignored_root_markers_cannot_classify_or_complete_a_native_failure() {
    let adapter = copilot();
    for child_marker in [json!(null), json!("child-agent")] {
        let mut terminal = copilot_result();
        terminal["agentId"] = child_marker.clone();
        let bytes = encode(&[copilot_error("rate_limit", 429), terminal]);
        assert!(
            !adapter
                .decode_stream(&bytes, failed(), 4096)
                .unwrap()
                .stream_complete
        );
        assert!(
            adapter
                .classify_failure(&bytes, failed(), 4096)
                .unwrap()
                .is_none()
        );
        // A complete root result cannot turn an ignored error event into proof.
        let mut error = copilot_error("rate_limit", 429);
        error["agentId"] = child_marker;
        let bytes = encode(&[error, copilot_result()]);
        assert!(
            adapter
                .decode_stream(&bytes, failed(), 4096)
                .unwrap()
                .stream_complete
        );
        assert!(
            adapter
                .classify_failure(&bytes, failed(), 4096)
                .unwrap()
                .is_none()
        );
    }
}
