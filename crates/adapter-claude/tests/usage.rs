//! Host-declared usage decoding. Behavior is asserted on the serialized
//! evidence so the tests hold independently of the Rust type.
//!
//! Sources, read by the orchestrator on 2026-09-30 (not by this crate):
//! - Codex: https://learn.chatgpt.com/docs/non-interactive-mode shows
//!   `{"type":"turn.completed","usage":{"input_tokens":24763,"cached_input_tokens":24448,"output_tokens":122,"reasoning_output_tokens":0}}`.
//!   `codex-usage-documented.jsonl` reuses that line verbatim inside a
//!   synthetic session scaffold.
//! - Claude: https://code.claude.com/docs/en/agent-sdk/typescript, type
//!   `SDKResultMessage`, carries `usage`, `total_cost_usd` and `modelUsage`.
//!   The counts inside `usage` follow the API shape (`input_tokens`,
//!   `output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`);
//!   the page did not list the fields of `NonNullableUsage`. The values in
//!   `claude-usage-documented-shape.jsonl` are invented.
use adapter_claude::ClaudeAdapter;
use adapter_codex::CodexAdapter;
use router_adapter_api::HarnessAdapter;
use router_types::{TransportOutcome, TransportTermination};
use serde_json::{Value, json};

const CODEX: &str = include_str!("fixtures/codex-usage-documented.jsonl");
const CLAUDE: &str = include_str!("fixtures/claude-usage-documented-shape.jsonl");

fn hr(tokens: u64) -> Value {
    json!({"tokens":tokens,"provenance":"host_reported"})
}

fn unknown() -> Value {
    json!({"tokens":null,"provenance":"unknown"})
}

fn decode(adapter: &dyn HarnessAdapter, stream: &str) -> Value {
    let outcome = TransportOutcome {
        termination: TransportTermination::Exited,
        exit_code: Some(0),
        elapsed_ms: 1,
    };
    let evidence = adapter
        .decode_stream(stream.as_bytes(), outcome, 65536)
        .unwrap();
    serde_json::to_value(evidence).unwrap()
}

fn lines(stream: &str) -> Vec<Value> {
    stream
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn join(events: &[Value]) -> String {
    events.iter().map(|e| e.to_string() + "\n").collect()
}

fn codex_with_usage(usage: Value) -> String {
    let mut events = lines(CODEX);
    events[3]["usage"] = usage;
    join(&events)
}

fn claude_with_usage(usage: Value) -> String {
    let mut events = lines(CLAUDE);
    events[2]["usage"] = usage;
    join(&events)
}

#[test]
fn codex_usage_is_normalized_as_declared_with_no_cache_write() {
    let evidence = decode(&CodexAdapter, CODEX);
    assert_eq!(
        evidence["host_usage"],
        json!({"input_tokens":hr(24763),"cached_input_tokens":hr(24448),"cache_write_input_tokens":unknown(),"output_tokens":hr(122),"reasoning_output_tokens":hr(0)})
    );
}

#[test]
fn claude_usage_is_normalized_so_input_includes_cache_reads_and_writes() {
    let evidence = decode(&ClaudeAdapter, CLAUDE);
    assert_eq!(
        evidence["host_usage"],
        json!({"input_tokens":hr(5030),"cached_input_tokens":hr(4000),"cache_write_input_tokens":hr(30),"output_tokens":hr(200),"reasoning_output_tokens":unknown()})
    );
}

#[test]
fn streams_without_usage_have_no_usage_never_zero() {
    for (adapter, stream) in [
        (
            &CodexAdapter as &dyn HarnessAdapter,
            include_str!("fixtures/codex.jsonl"),
        ),
        (
            &ClaudeAdapter as &dyn HarnessAdapter,
            include_str!("fixtures/claude.jsonl"),
        ),
    ] {
        // The pre-existing adversarial Codex fixture declares 1 and 1; strip it.
        let stream = stream.replace(r#","usage":{"input_tokens":1,"output_tokens":1}"#, "");
        let evidence = decode(adapter, &stream);
        assert!(evidence.get("host_usage").is_none());
    }
}

#[test]
fn more_than_one_codex_turn_gives_no_usage_because_cumulative_or_per_turn_is_unproven() {
    let mut events = lines(CODEX);
    assert!(
        decode(&CodexAdapter, &join(&events))
            .get("host_usage")
            .is_some()
    );
    events.push(json!({"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":3}}));
    let evidence = decode(&CodexAdapter, &join(&events));
    assert!(evidence.get("host_usage").is_none());
    assert_eq!(evidence["stream_complete"], true);
}

#[test]
fn unusable_counts_are_unknown_not_clamped_or_fatal() {
    for bad in [
        json!(-1),
        json!(1.5),
        json!("7"),
        json!(1_000_000_000_001u64),
        json!(null),
    ] {
        let evidence = decode(
            &CodexAdapter,
            &codex_with_usage(json!({"input_tokens":bad,"output_tokens":4})),
        );
        assert_eq!(evidence["host_usage"]["input_tokens"], unknown(), "{bad}");
        assert_eq!(evidence["host_usage"]["output_tokens"], hr(4));
        let evidence = decode(
            &ClaudeAdapter,
            &claude_with_usage(
                json!({"input_tokens":bad,"output_tokens":4,"cache_read_input_tokens":bad}),
            ),
        );
        assert_eq!(evidence["host_usage"]["input_tokens"], unknown(), "{bad}");
        assert_eq!(
            evidence["host_usage"]["cached_input_tokens"],
            unknown(),
            "{bad}"
        );
        assert_eq!(evidence["host_usage"]["output_tokens"], hr(4));
        // A valid input next to an unusable cache count would understate. A
        // null cache count is just absent, so it is excluded here.
        if !bad.is_null() {
            let evidence = decode(
                &ClaudeAdapter,
                &claude_with_usage(
                    json!({"input_tokens":9,"output_tokens":4,"cache_read_input_tokens":bad}),
                ),
            );
            assert_eq!(evidence["host_usage"]["input_tokens"], unknown(), "{bad}");
        }
    }
    // Both counts unusable: no usage at all, and the run still decodes.
    let evidence = decode(&CodexAdapter, &codex_with_usage(json!({"input_tokens":-1})));
    assert!(evidence.get("host_usage").is_none());
    assert_eq!(evidence["transport_success"], true);
}

#[test]
fn claude_subagent_usage_is_not_attributed_to_the_root_worker() {
    // Only a subagent result declares usage. A root result with usage must be
    // the source, so this stream has none.
    let mut events = lines(CLAUDE);
    events[2]["parent_tool_use_id"] = json!("toolu_sub");
    let evidence = decode(&ClaudeAdapter, &join(&events));
    assert!(evidence.get("host_usage").is_none());
}

#[test]
fn two_claude_root_results_are_ambiguous_and_give_no_usage() {
    let mut events = lines(CLAUDE);
    events.push(events[2].clone());
    let evidence = decode(&ClaudeAdapter, &join(&events));
    assert!(evidence.get("host_usage").is_none());
}

#[test]
fn decoded_evidence_carries_no_assistant_text_cost_or_per_model_usage() {
    for (adapter, stream) in [
        (&CodexAdapter as &dyn HarnessAdapter, CODEX),
        (&ClaudeAdapter as &dyn HarnessAdapter, CLAUDE),
    ] {
        let encoded = decode(adapter, stream).to_string();
        for leaked in [
            "secret-assistant-text",
            "secret-provider-output",
            "total_cost_usd",
            "9999",
        ] {
            assert!(!encoded.contains(leaked), "{leaked}");
        }
    }
}

fn typed(evidence: &Value) -> router_types::HostUsage {
    serde_json::from_value(evidence["host_usage"].clone()).unwrap()
}

#[test]
fn codex_cached_input_is_never_counted_twice_in_the_total() {
    let usage = typed(&decode(&CodexAdapter, CODEX));
    // 24448 cached tokens are already inside the 24763 input tokens.
    assert_eq!(usage.total_tokens(), Some(24763 + 122));
    assert_ne!(usage.total_tokens(), Some(24763 + 24448 + 122));
}

#[test]
fn claude_total_counts_cache_once_through_the_normalized_input() {
    let usage = typed(&decode(&ClaudeAdapter, CLAUDE));
    // input 1000 + write 30 + read 4000, then output 200; no cache added again.
    assert_eq!(usage.total_tokens(), Some(5030 + 200));
}

#[test]
fn nonzero_reasoning_stays_a_subset_of_output_and_is_never_added() {
    let stream = codex_with_usage(json!({
        "input_tokens":100,"cached_input_tokens":40,"output_tokens":20,"reasoning_output_tokens":5
    }));
    let evidence = decode(&CodexAdapter, &stream);
    assert_eq!(evidence["host_usage"]["output_tokens"], hr(20));
    assert_eq!(evidence["host_usage"]["reasoning_output_tokens"], hr(5));
    let usage = typed(&evidence);
    assert_eq!(usage.total_tokens(), Some(120));
    assert_ne!(usage.total_tokens(), Some(125));
}

fn decode_with(adapter: &dyn HarnessAdapter, stream: &str, outcome: TransportOutcome) -> Value {
    let evidence = adapter
        .decode_stream(stream.as_bytes(), outcome, 65536)
        .unwrap();
    serde_json::to_value(evidence).unwrap()
}

#[test]
fn incomplete_or_failed_streams_report_no_usage() {
    let exited = |code| TransportOutcome {
        termination: TransportTermination::Exited,
        exit_code: Some(code),
        elapsed_ms: 1,
    };
    // Sanity: the same turn is reported when complete.
    assert!(
        decode_with(&CodexAdapter, CODEX, exited(0))
            .get("host_usage")
            .is_some()
    );
    // Truncated: cut before turn.completed.
    let truncated: String = CODEX.lines().take(3).collect::<Vec<_>>().join("\n") + "\n";
    let evidence = decode_with(&CodexAdapter, &truncated, exited(0));
    assert!(evidence.get("host_usage").is_none());
    // Timeout after a complete turn, non-zero exit after a complete turn.
    let timed_out = TransportOutcome {
        termination: TransportTermination::TimedOut,
        exit_code: None,
        elapsed_ms: 1,
    };
    assert!(
        decode_with(&CodexAdapter, CODEX, timed_out)
            .get("host_usage")
            .is_none()
    );
    assert!(
        decode_with(&CodexAdapter, CODEX, exited(1))
            .get("host_usage")
            .is_none()
    );
    // A turn.failed after turn.completed is a host error.
    let mut events = lines(CODEX);
    events.push(json!({"type":"turn.failed","error":{"message":"x"}}));
    let evidence = decode_with(&CodexAdapter, &join(&events), exited(0));
    assert!(evidence.get("host_usage").is_none());
    // Claude: an is_error result.
    let mut events = lines(CLAUDE);
    events[2]["is_error"] = json!(true);
    let evidence = decode_with(&ClaudeAdapter, &join(&events), exited(0));
    assert!(evidence.get("host_usage").is_none());
}

#[test]
fn only_the_root_result_counts_when_a_subagent_result_is_mixed_in() {
    let mut events = lines(CLAUDE);
    let mut sub = events[2].clone();
    sub["parent_tool_use_id"] = json!("toolu_sub");
    sub["usage"] = json!({"input_tokens":7777,"output_tokens":8888});
    events.insert(2, sub);
    let evidence = decode(&ClaudeAdapter, &join(&events));
    assert_eq!(evidence["host_usage"]["input_tokens"], hr(5030));
    assert_eq!(evidence["host_usage"]["output_tokens"], hr(200));
    assert!(!evidence.to_string().contains("7777"));
}

#[test]
fn usage_field_refuses_inconsistent_pairs_and_totals_need_host_reported() {
    use router_types::{HostUsage, UsageField, UsageProvenance};
    for bad in [
        json!({"tokens":5,"provenance":"unknown"}),
        json!({"tokens":null,"provenance":"host_reported"}),
        json!({"tokens":1_000_000_000_001u64,"provenance":"host_reported"}),
        json!({"tokens":5,"provenance":"host_reported","extra":1}),
    ] {
        assert!(
            serde_json::from_value::<UsageField>(bad.clone()).is_err(),
            "{bad}"
        );
    }
    assert_eq!(
        serde_json::from_value::<UsageField>(hr(5)).unwrap(),
        UsageField::host_reported(5)
    );
    assert_eq!(
        serde_json::from_value::<UsageField>(unknown()).unwrap(),
        UsageField::UNKNOWN
    );
    // A hand-built inconsistent field cannot yield a total.
    let forged = UsageField {
        tokens: Some(5),
        provenance: UsageProvenance::Unknown,
    };
    let usage = HostUsage {
        input_tokens: forged,
        cached_input_tokens: UsageField::UNKNOWN,
        cache_write_input_tokens: UsageField::UNKNOWN,
        output_tokens: UsageField::host_reported(1),
        reasoning_output_tokens: UsageField::UNKNOWN,
    };
    assert_eq!(usage.total_tokens(), None);
}
