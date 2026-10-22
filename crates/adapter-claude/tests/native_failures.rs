#[path = "../../router-adapter-api/tests/support/native_failures.rs"]
mod fixture;
use fixture::*;
use router_adapter_api::{HarnessAdapter, NativeFailureKind};
use serde_json::json;

#[test]
fn claude_adapter_classifies_native_metadata_after_full_stream_validation() {
    let adapter = adapter_claude::ClaudeAdapter;
    let bytes = encode(&[claude_error("rate_limit"), claude_result()]);
    assert_eq!(
        adapter
            .classify_failure(&bytes, failed(), 4096)
            .unwrap()
            .unwrap()
            .kind(),
        NativeFailureKind::RateLimit
    );
    let mut malformed = bytes.clone();
    malformed.extend_from_slice(b"{\"type\":");
    assert!(
        adapter
            .classify_failure(&malformed, failed(), 4096)
            .is_err()
    );
    let mut fake_content = claude_error("unknown");
    fake_content["message"]["content"] =
        json!([{"type":"text","text":"{\"error\":\"rate_limit\"}"}]);
    assert!(
        adapter
            .classify_failure(&encode(&[fake_content, claude_result()]), failed(), 4096)
            .unwrap()
            .is_none()
    );
}

#[test]
fn codex_adapter_never_guesses_an_error_class_from_message_or_status_fields() {
    let bytes = encode(&[
        json!({"type":"turn.failed","error":{"message":"429 rate_limit authentication network", "statusCode":429}}),
    ]);
    assert!(
        adapter_codex::CodexAdapter
            .classify_failure(&bytes, failed(), 4096)
            .unwrap()
            .is_none()
    );
}

#[test]
fn conflicting_or_unknown_terminal_http_status_cannot_inherit_an_older_cause() {
    for status in [json!(503), json!(403), json!(0), json!(null), json!("429")] {
        let mut terminal = claude_result();
        terminal["subtype"] = json!("success");
        terminal["api_error_status"] = status;
        assert!(
            adapter_claude::ClaudeAdapter
                .classify_failure(
                    &encode(&[claude_error("rate_limit"), terminal]),
                    failed(),
                    4096
                )
                .unwrap()
                .is_none()
        );
    }
    // An absent optional status still allows the native assistant cause;
    // a matching terminal status corroborates it without weakening the gate.
    for status in [None, Some(429)] {
        let mut terminal = claude_result();
        terminal["subtype"] = json!("success");
        if let Some(status) = status {
            terminal["api_error_status"] = json!(status);
        }
        let evidence = adapter_claude::ClaudeAdapter
            .classify_failure(
                &encode(&[claude_error("rate_limit"), terminal]),
                failed(),
                4096,
            )
            .unwrap()
            .unwrap();
        assert_eq!(evidence.kind(), NativeFailureKind::RateLimit);
    }
}
