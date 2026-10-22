//! Source-derived synthetic native envelopes, never provider observations.
#![allow(dead_code)]
use router_types::{TransportOutcome, TransportTermination};
use serde_json::{Value, json};

pub fn failed() -> TransportOutcome {
    TransportOutcome {
        termination: TransportTermination::Exited,
        exit_code: Some(1),
        elapsed_ms: 1,
    }
}
pub fn encode(events: &[Value]) -> Vec<u8> {
    events
        .iter()
        .map(|v| serde_json::to_string(v).unwrap() + "\n")
        .collect::<String>()
        .into_bytes()
}
pub fn claude_error(class: &str) -> Value {
    json!({"type":"assistant","error":class,"session_id":"fixture-session","uuid":"message-1",
        "parent_tool_use_id":null,"message":{"type":"message","role":"assistant",
        "content":[{"type":"text","text":"PRIVATE do not classify this rate_limit authentication_failed ECONNRESET"}]}})
}
pub fn claude_result() -> Value {
    json!({"type":"result","subtype":"error_during_execution","is_error":true,"session_id":"fixture-session","errors":["PRIVATE"],"uuid":"result-1"})
}
pub fn opencode_error(name: &str, data: Value) -> Value {
    json!({"type":"error","timestamp":123,"sessionID":"fixture-session","error":{"name":name,"data":data}})
}
pub fn opencode_rate() -> Value {
    opencode_error(
        "APIError",
        json!({"message":"PRIVATE authentication network","statusCode":429,"isRetryable":true}),
    )
}
pub fn copilot_error(class: &str, status: u16) -> Value {
    json!({"type":"session.error","timestamp":"2026-01-01T00:00:00Z","id":"error-1","parentId":null,
        "data":{"errorType":class,"statusCode":status,"message":"PRIVATE rate_limit authentication network"}})
}
pub fn copilot_result() -> Value {
    json!({"type":"result","timestamp":"2026-01-01T00:00:00Z","sessionId":"fixture-session","exitCode":1,
        "usage":{"premiumRequests":0,"totalApiDurationMs":1,"sessionDurationMs":1,"codeChanges":{"linesAdded":0,"linesRemoved":0,"filesModified":[]}}})
}
