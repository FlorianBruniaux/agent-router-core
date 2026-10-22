//! Request scope canonicality and native stream attribution.
#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use std::collections::{BTreeMap, BTreeSet};

use router_adapter_api::*;
use router_types::*;

fn gate(scope: Vec<String>) -> Result<(), AdapterError> {
    let model = ModelId::parse("test-exact-model-v1").unwrap();
    let capabilities = ALL_CAPABILITIES.into_iter().collect::<BTreeSet<_>>();
    let observation = HostObservation {
        attestations: None,
        schema_version: 1,
        host: HostSnapshot {
            id: "synthetic-conformance".into(),
            harness: HarnessId::parse("codex").unwrap(),
            supported_models: BTreeSet::from([model.clone()]),
            supported_efforts: BTreeMap::from([(
                model.clone(),
                BTreeSet::from([EffortLevel::High]),
            )]),
            capabilities: capabilities.clone(),
        },
        capabilities: capabilities
            .into_iter()
            .map(|capability| {
                (
                    capability,
                    CapabilityEvidence {
                        support: CapabilitySupport::Supported,
                        source_ids: BTreeSet::from(["synthetic-runtime".into()]),
                    },
                )
            })
            .collect(),
        evidence: vec![EvidenceSource {
            id: "synthetic-runtime".into(),
            kind: EvidenceKind::HostRuntime,
            observed_version: Some("test-version".into()),
            observed_at_unix_seconds: 100,
            content_sha256: "b".repeat(64),
        }],
        observed_at_unix_seconds: 100,
        snapshot_hash: String::new(),
    }
    .seal()
    .unwrap();
    let snapshot = fixture_proofs::from_observation(
        observation,
        SnapshotValidation {
            now_unix_seconds: 100,
            max_age_seconds: 10,
        },
    )
    .unwrap();
    let request = ExecutionRequest {
        schema_version: 1,
        receipt_id: "a".repeat(64),
        candidate_id: "candidate-1".into(),
        phase: StageKind::Execute,
        host: HarnessId::parse("codex").unwrap(),
        model,
        effort: EffortLevel::High,
        workspace: "/private/tmp/adapter-fixture".into(),
        source_state: "c".repeat(40),
        scope,
        sandbox: ExecutionSandbox::ReadOnly,
        required_capabilities: BTreeSet::new(),
        tools: ToolSelection::HostPolicy,
        agent: None,
        skills: vec![],
        prompt: "prompt".into(),
        mode: ExecutionMode::DryRun,
        target: ExecutionTarget::ExternalWorker,
        allow_degradation: false,
        timeout_ms: 1000,
        max_output_bytes: 8192,
    };
    let restrictions = EffectiveRestrictions {
        schema_version: 1,
        sources: vec!["test".into()],
        allowed_models: None,
        allowed_capabilities: None,
        allowed_mutations: Some(BTreeSet::new()),
        max_cost_microusd: None,
        max_tokens: None,
        max_concurrency: None,
        preferred_model: None,
        policy_hash: "d".repeat(64),
    };
    authorize_execution(request, &snapshot, &restrictions, None).map(|_| ())
}

#[test]
fn scope_entries_must_be_canonical_so_duplicates_cannot_hide() {
    gate(vec!["src".into(), "src/a".into()]).unwrap();
    for scope in [
        vec!["src".into(), "src/".into()],
        vec!["src".into(), "src/./".into()],
        vec!["src/./a".into()],
        vec!["src//a".into()],
        vec!["src/".into()],
    ] {
        assert_eq!(gate(scope).unwrap_err(), AdapterError::Invalid("scope"));
    }
}

fn outcome(code: Option<i32>, termination: TransportTermination) -> TransportOutcome {
    TransportOutcome {
        termination,
        exit_code: code,
        elapsed_ms: 1,
    }
}

#[test]
fn claude_subagent_model_is_not_attributed_to_the_root_worker() {
    let bytes = b"{\"type\":\"assistant\",\"parent_tool_use_id\":\"toolu_1\",\"message\":{\"role\":\"assistant\",\"type\":\"message\",\"model\":\"subagent-model\"}}\n{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\"type\":\"message\",\"model\":\"root-model\"}}\n";
    let evidence = decode_transport(
        bytes,
        outcome(Some(0), TransportTermination::Exited),
        8192,
        StreamDialect::Claude,
    )
    .unwrap();
    let models: Vec<_> = evidence
        .executed_models
        .iter()
        .map(|m| m.model.as_str())
        .collect();
    assert_eq!(models, ["root-model"]);
}

#[test]
fn malformed_tail_must_be_the_last_line_not_merely_equal_to_it() {
    let bytes = b"bad\nbad";
    for dialect in [StreamDialect::Codex, StreamDialect::Claude] {
        assert_eq!(
            decode_transport(
                bytes,
                outcome(None, TransportTermination::Cancelled),
                8192,
                dialect,
            )
            .unwrap_err(),
            AdapterError::Protocol
        );
        let evidence = decode_transport(
            b"{\"type\":\"ignored\"}\n{\"type\":",
            outcome(None, TransportTermination::Cancelled),
            8192,
            dialect,
        )
        .unwrap();
        assert!(!evidence.stream_complete);
    }
}

#[test]
fn codex_cache_write_is_reported_only_when_declared() {
    use serde_json::{Value, json};

    for (declared, expected) in [
        (None, UsageField::UNKNOWN),
        (Some(Value::Null), UsageField::UNKNOWN),
        (Some(json!(0)), UsageField::host_reported(0)),
        (Some(json!(17)), UsageField::host_reported(17)),
    ] {
        let mut usage = json!({
            "input_tokens": 100,
            "cached_input_tokens": 20,
            "output_tokens": 30,
            "reasoning_output_tokens": 5
        });
        if let Some(value) = declared {
            usage["cache_write_input_tokens"] = value;
        }
        let event = json!({"type": "turn.completed", "usage": usage});
        let stream = format!("{event}\n");
        let evidence = decode_transport(
            stream.as_bytes(),
            outcome(Some(0), TransportTermination::Exited),
            8192,
            StreamDialect::Codex,
        )
        .unwrap();
        let actual = evidence.host_usage.unwrap();
        assert_eq!(actual.input_tokens, UsageField::host_reported(100));
        assert_eq!(actual.cached_input_tokens, UsageField::host_reported(20));
        assert_eq!(actual.cache_write_input_tokens, expected);
        assert_eq!(actual.output_tokens, UsageField::host_reported(30));
        assert_eq!(actual.reasoning_output_tokens, UsageField::host_reported(5));
    }
}
