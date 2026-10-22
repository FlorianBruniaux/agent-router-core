//! Both host implementations run the same admission and supervision fixtures.
#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use std::collections::{BTreeMap, BTreeSet};

use adapter_claude::{ClaudeAdapter, ClaudeStreamProbe};
use adapter_codex::CodexAdapter;
use router_adapter_api::*;
use router_types::*;

fn hosts() -> Vec<Box<dyn HarnessAdapter>> {
    vec![Box::new(CodexAdapter), Box::new(ClaudeAdapter)]
}

fn fixture(
    host: &str,
) -> (
    ExecutionRequest,
    ValidatedHostObservation,
    EffectiveRestrictions,
) {
    let model = ModelId::parse("test-exact-model-v1").unwrap();
    let capabilities = ALL_CAPABILITIES.into_iter().collect::<BTreeSet<_>>();
    let observation = HostObservation {
        attestations: None,
        schema_version: 1,
        host: HostSnapshot {
            id: "synthetic-conformance".into(),
            harness: HarnessId::parse(host).unwrap(),
            supported_models: BTreeSet::from([model.clone()]),
            supported_efforts: BTreeMap::from([(
                model.clone(),
                BTreeSet::from([EffortLevel::High, EffortLevel::Ultra]),
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
        host: HarnessId::parse(host).unwrap(),
        model,
        effort: EffortLevel::High,
        workspace: "/private/tmp/adapter-fixture".into(),
        source_state: "c".repeat(40),
        scope: vec!["src".into()],
        sandbox: ExecutionSandbox::ReadOnly,
        required_capabilities: BTreeSet::new(),
        tools: ToolSelection::HostPolicy,
        agent: None,
        skills: vec![],
        prompt: "PRIVATE_PROMPT $(not-a-command)".into(),
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
    (request, snapshot, restrictions)
}

#[test]
fn shared_dry_run_shadow_preserve_model_effort_and_redact_prompt() {
    for adapter in hosts() {
        for mode in [ExecutionMode::DryRun, ExecutionMode::Shadow] {
            let (mut request, snapshot, restrictions) = fixture(adapter.host());
            request.mode = mode;
            let validated =
                authorize_execution(request.clone(), &snapshot, &restrictions, None).unwrap();
            let prepared = adapter.prepare(&validated).unwrap();
            assert_eq!(prepared.requested_model, request.model);
            assert_eq!(prepared.requested_effort, request.effort);
            assert_eq!(prepared.mode, mode);
            assert_eq!(prepared.source_state, request.source_state);
            assert_eq!(prepared.scope, request.scope);
            assert!(!prepared.parent_model_changed);
            assert!(prepared.degradations.is_empty());
            assert_eq!(prepared.stdin.as_bytes(), request.prompt.as_bytes());
            let preview = serde_json::to_string(&prepared).unwrap();
            assert!(!preview.contains("PRIVATE_PROMPT"));
            assert!(!format!("{prepared:?} {validated:?}").contains("PRIVATE_PROMPT"));
            if adapter.host() == "codex" {
                assert!(
                    prepared
                        .argv
                        .windows(2)
                        .any(|args| args == ["--config", "model_reasoning_effort=\"high\""])
                );
                assert!(
                    prepared
                        .argv
                        .windows(2)
                        .any(|args| args == ["--sandbox", "read-only"])
                );
                assert_eq!(prepared.argv.last().map(String::as_str), Some("-"));
            } else {
                assert!(
                    prepared
                        .argv
                        .windows(2)
                        .any(|args| args == ["--effort", "high"])
                );
                assert!(
                    prepared
                        .argv
                        .windows(2)
                        .any(|args| args == ["--permission-mode", "plan"])
                );
            }
            assert!(
                prepared
                    .argv
                    .iter()
                    .any(|arg| arg == request.model.as_str())
            );
            assert!(prepared.argv.iter().all(|arg| !arg.contains("dangerously")
                && !arg.contains("bypass")
                && !arg.contains("allowedTools")
                && !arg.contains("PRIVATE_PROMPT")));
        }
    }
}

#[test]
fn shared_execute_approval_binds_receipt_source_scope_model_and_prompt() {
    for adapter in hosts() {
        let (mut request, snapshot, restrictions) = fixture(adapter.host());
        request.mode = ExecutionMode::Execute;
        assert_eq!(
            authorize_execution(request.clone(), &snapshot, &restrictions, None).unwrap_err(),
            AdapterError::ApprovalRequired
        );
        let approval = execution_authorization_digest(&request, &snapshot, &restrictions).unwrap();
        let validated =
            authorize_execution(request.clone(), &snapshot, &restrictions, Some(&approval))
                .unwrap();
        assert_eq!(
            adapter.prepare(&validated).unwrap().authorization_digest,
            approval
        );
        for altered in [
            ExecutionRequest {
                source_state: "f".repeat(40),
                ..request.clone()
            },
            ExecutionRequest {
                receipt_id: "f".repeat(64),
                ..request.clone()
            },
            ExecutionRequest {
                scope: vec!["other".into()],
                ..request.clone()
            },
            ExecutionRequest {
                prompt: "altered".into(),
                ..request.clone()
            },
            ExecutionRequest {
                effort: EffortLevel::Ultra,
                ..request.clone()
            },
        ] {
            assert_eq!(
                authorize_execution(altered, &snapshot, &restrictions, Some(&approval))
                    .unwrap_err(),
                AdapterError::ApprovalRequired
            );
        }
    }
}

#[test]
fn shared_gate_rejects_unknown_model_effort_permissions_paths_and_parent() {
    for adapter in hosts() {
        let (request, snapshot, restrictions) = fixture(adapter.host());
        for (altered, expected) in [
            (
                ExecutionRequest {
                    model: ModelId::parse("unobserved-model").unwrap(),
                    ..request.clone()
                },
                AdapterError::ModelUnsupported,
            ),
            (
                ExecutionRequest {
                    effort: EffortLevel::Low,
                    ..request.clone()
                },
                AdapterError::EffortUnsupported,
            ),
            (
                ExecutionRequest {
                    sandbox: ExecutionSandbox::WorkspaceWrite,
                    ..request.clone()
                },
                AdapterError::PermissionDenied,
            ),
            (
                ExecutionRequest {
                    scope: vec!["../escape".into()],
                    ..request.clone()
                },
                AdapterError::Invalid("scope"),
            ),
            (
                ExecutionRequest {
                    target: ExecutionTarget::ParentConversation,
                    ..request.clone()
                },
                AdapterError::Unsupported("parent-model-change"),
            ),
            (
                ExecutionRequest {
                    model: ModelId::parse("--config=bad").unwrap(),
                    ..request.clone()
                },
                AdapterError::Invalid("identity"),
            ),
        ] {
            assert_eq!(
                authorize_execution(altered, &snapshot, &restrictions, None).unwrap_err(),
                expected
            );
        }
        let mut restricted = restrictions.clone();
        restricted.allowed_capabilities = Some(BTreeSet::new());
        assert_eq!(
            authorize_execution(request, &snapshot, &restricted, None).unwrap_err(),
            AdapterError::CapabilityDenied
        );
    }
}

#[test]
fn shared_unknown_capability_is_not_permission_and_snapshot_cannot_be_stale() {
    for adapter in hosts() {
        let (request, snapshot, restrictions) = fixture(adapter.host());
        let mut observation = snapshot.observation().clone();
        observation
            .capabilities
            .get_mut(&Capability::Tools)
            .unwrap()
            .support = CapabilitySupport::Unknown;
        observation.host.capabilities.remove(&Capability::Tools);
        let observation = observation.seal().unwrap();
        assert!(matches!(
            fixture_proofs::from_observation(
                observation.clone(),
                SnapshotValidation {
                    now_unix_seconds: 111,
                    max_age_seconds: 10
                }
            ),
            Err(SnapshotError::Stale)
        ));
        let unknown = fixture_proofs::from_observation(
            observation,
            SnapshotValidation {
                now_unix_seconds: 100,
                max_age_seconds: 10,
            },
        )
        .unwrap();
        assert_eq!(
            authorize_execution(request, &unknown, &restrictions, None).unwrap_err(),
            AdapterError::CapabilityDenied
        );
    }
}

#[test]
fn shared_agent_and_subagent_downgrades_are_explicit_and_opt_in() {
    for adapter in hosts() {
        let (mut request, snapshot, restrictions) = fixture(adapter.host());
        request.agent = Some("reviewer".into());
        request.target = ExecutionTarget::NativeSubagent;
        let validated =
            authorize_execution(request.clone(), &snapshot, &restrictions, None).unwrap();
        assert!(matches!(
            adapter.prepare(&validated),
            Err(AdapterError::Unsupported(_))
        ));
        request.allow_degradation = true;
        let validated = authorize_execution(request, &snapshot, &restrictions, None).unwrap();
        let prepared = adapter.prepare(&validated).unwrap();
        assert_eq!(
            prepared
                .degradations
                .iter()
                .map(|d| d.code.as_str())
                .collect::<Vec<_>>(),
            ["target.external_worker", "agent.prompt_role"]
        );
        assert_eq!(prepared.target, ExecutionTarget::ExternalWorker);
        assert!(!prepared.parent_model_changed);
    }
}

#[test]
fn shared_instruction_skills_are_hashed_and_never_executables_or_grants() {
    for adapter in hosts() {
        let (mut request, snapshot, restrictions) = fixture(adapter.host());
        request.skills.push(ExecutionSkill {
            id: SkillId::parse("review").unwrap(),
            content_sha256: content_digest(b"PRIVATE_SKILL"),
            kind: ExecutionSkillKind::Instruction,
            trust: SkillTrust::TrustedLocal,
            body: "PRIVATE_SKILL".into(),
        });
        let validated =
            authorize_execution(request.clone(), &snapshot, &restrictions, None).unwrap();
        let prepared = adapter.prepare(&validated).unwrap();
        assert!(String::from_utf8_lossy(prepared.stdin.as_bytes()).contains("PRIVATE_SKILL"));
        assert!(!format!("{prepared:?}").contains("PRIVATE_SKILL"));
        request.skills[0].body.push('x');
        assert_eq!(
            authorize_execution(request.clone(), &snapshot, &restrictions, None).unwrap_err(),
            AdapterError::Invalid("skill")
        );
        request.skills[0].kind = ExecutionSkillKind::Executable;
        assert_eq!(
            authorize_execution(request.clone(), &snapshot, &restrictions, None).unwrap_err(),
            AdapterError::Unsupported("executable-skill")
        );
        request.skills[0].kind = ExecutionSkillKind::Instruction;
        request.skills[0].trust = SkillTrust::Untrusted;
        assert_eq!(
            authorize_execution(request, &snapshot, &restrictions, None).unwrap_err(),
            AdapterError::PermissionDenied
        );
    }
}

#[test]
fn native_tool_selection_never_silently_broadens() {
    for tools in [
        ToolSelection::Disabled,
        ToolSelection::AllowList(vec!["Read".into(), "Grep".into()]),
    ] {
        let (mut request, snapshot, restrictions) = fixture("codex");
        request.tools = tools.clone();
        let validated = authorize_execution(request, &snapshot, &restrictions, None).unwrap();
        assert_eq!(
            CodexAdapter.prepare(&validated).unwrap_err(),
            AdapterError::Unsupported("tool-selection")
        );
        let (mut request, snapshot, restrictions) = fixture("claude-code");
        request.tools = tools;
        let validated = authorize_execution(request, &snapshot, &restrictions, None).unwrap();
        let prepared = ClaudeAdapter.prepare(&validated).unwrap();
        assert!(prepared.argv.windows(2).any(|args| args[0] == "--tools"));
        assert!(
            prepared
                .argv
                .windows(2)
                .any(|args| args == ["--permission-mode", "plan"])
        );
        assert!(
            prepared
                .argv
                .windows(2)
                .any(|args| args == ["--permission-prompts", "none"])
        );
    }
    let (mut request, snapshot, restrictions) = fixture("claude-code");
    request.effort = EffortLevel::Ultra;
    let validated = authorize_execution(request, &snapshot, &restrictions, None).unwrap();
    assert_eq!(
        ClaudeAdapter.prepare(&validated).unwrap_err(),
        AdapterError::Unsupported("effort-native-flag")
    );
}

#[test]
fn shared_explicit_write_permission_retains_native_controls() {
    for adapter in hosts() {
        let (mut request, snapshot, mut restrictions) = fixture(adapter.host());
        request.sandbox = ExecutionSandbox::WorkspaceWrite;
        restrictions.allowed_mutations = Some(BTreeSet::from([Mutation::WorkspaceWrite]));
        let validated = authorize_execution(request, &snapshot, &restrictions, None).unwrap();
        let prepared = adapter.prepare(&validated).unwrap();
        let expected = if adapter.host() == "codex" {
            ["--sandbox", "workspace-write"]
        } else {
            ["--permission-mode", "manual"]
        };
        assert!(prepared.argv.windows(2).any(|args| args == expected));
        assert_eq!(prepared.sandbox, ExecutionSandbox::WorkspaceWrite);
    }
    let (request, snapshot, restrictions) = fixture("codex");
    let validated = authorize_execution(request, &snapshot, &restrictions, None).unwrap();
    assert_eq!(
        ClaudeAdapter.prepare(&validated).unwrap_err(),
        AdapterError::HostMismatch
    );
}

fn outcome(termination: TransportTermination, code: Option<i32>) -> TransportOutcome {
    TransportOutcome {
        termination,
        exit_code: code,
        elapsed_ms: 17,
    }
}

#[test]
fn shared_streams_never_promote_assistant_claims_to_verification() {
    for (adapter, stream) in [
        (
            &CodexAdapter as &dyn HarnessAdapter,
            include_bytes!("fixtures/codex.jsonl").as_slice(),
        ),
        (
            &ClaudeAdapter as &dyn HarnessAdapter,
            include_bytes!("fixtures/claude.jsonl").as_slice(),
        ),
    ] {
        let evidence = adapter
            .decode_stream(stream, outcome(TransportTermination::Exited, Some(0)), 8192)
            .unwrap();
        assert!(evidence.transport_success);
        assert!(evidence.stream_complete);
        assert_eq!(evidence.validation, VerificationOutcome::Unknown);
        assert_eq!(evidence.objective, VerificationOutcome::Unknown);
        assert_eq!(evidence.executed_effort, None);
        let encoded = serde_json::to_string(&evidence).unwrap();
        assert!(!encoded.contains("forged-model"));
        assert!(!encoded.contains("secret-provider-output"));
        if adapter.host() == "codex" {
            assert!(evidence.executed_models.is_empty());
        } else {
            assert_eq!(
                evidence.executed_models[0].model.as_str(),
                "claude-test-model"
            );
        }
        let failed = adapter
            .decode_stream(stream, outcome(TransportTermination::Exited, Some(1)), 8192)
            .unwrap();
        assert!(!failed.transport_success);
    }
}

#[test]
fn shared_timeout_truncation_malformed_and_bounds_are_explicit() {
    for adapter in hosts() {
        for termination in [
            TransportTermination::TimedOut,
            TransportTermination::Cancelled,
            TransportTermination::Killed,
            TransportTermination::SpawnFailed,
        ] {
            let evidence = adapter
                .decode_stream(
                    b"{\"type\":\"ignored\"}\n{\"type\":",
                    outcome(termination, None),
                    8192,
                )
                .unwrap();
            assert!(!evidence.transport_success);
            assert!(!evidence.stream_complete);
            assert!(
                evidence
                    .missing_evidence
                    .contains(&"stream.truncated".into())
            );
        }
        assert_eq!(
            adapter
                .decode_stream(b"{}", outcome(TransportTermination::Exited, Some(0)), 8192)
                .unwrap_err(),
            AdapterError::Protocol
        );
        assert_eq!(
            adapter
                .decode_stream(
                    b"{\"type\":\"one\",\"type\":\"two\"}\n",
                    outcome(TransportTermination::Exited, Some(0)),
                    8192
                )
                .unwrap_err(),
            AdapterError::Protocol
        );
        assert_eq!(
            adapter
                .decode_stream(b"secret", outcome(TransportTermination::Exited, Some(0)), 1)
                .unwrap_err(),
            AdapterError::OutputLimit
        );
        let empty = adapter
            .decode_stream(b"", outcome(TransportTermination::Exited, Some(0)), 8192)
            .unwrap();
        assert!(empty.transport_success);
        assert!(!empty.stream_complete);
        assert_eq!(empty.objective, VerificationOutcome::Unknown);
    }
}

#[test]
fn passive_claude_probe_is_bounded_redacted_and_does_not_infer_effort_or_capabilities() {
    let bytes = include_bytes!("fixtures/claude.jsonl");
    let observation = ClaudeStreamProbe::from_native_stream(bytes)
        .probe(100)
        .unwrap();
    assert_eq!(observation.host.harness.as_str(), "claude-code");
    assert_eq!(
        observation
            .host
            .supported_models
            .iter()
            .next()
            .unwrap()
            .as_str(),
        "claude-test-model"
    );
    assert!(observation.host.supported_efforts.is_empty());
    assert!(observation.host.capabilities.is_empty());
    assert!(
        observation
            .capabilities
            .values()
            .all(|value| value.support == CapabilitySupport::Unknown)
    );
    let json = serde_json::to_string(&observation).unwrap();
    assert!(!json.contains("secret-provider-output"));
    assert!(!json.contains("forged-model"));
    assert_eq!(
        observation.evidence[0].kind,
        EvidenceKind::ClaudeNativeStream
    );
    assert_eq!(
        observation.evidence[0].content_sha256,
        content_digest(bytes)
    );
    assert!(
        ClaudeStreamProbe::from_native_stream(b"")
            .probe(100)
            .is_err()
    );
    assert!(
        ClaudeStreamProbe::from_native_stream(b"{bad}")
            .probe(100)
            .is_err()
    );
    assert!(
        ClaudeStreamProbe::from_native_stream(&vec![b' '; MAX_TRANSPORT_BYTES + 1])
            .probe(100)
            .is_err()
    );
    assert!(matches!(
        ClaudeStreamProbe::from_native_stream(b"{\"type\":\"system\",\"subtype\":\"init\",\"model\":\"invented\",\"claude_code_version\":\"1\"}\n")
            .probe(100)
            .unwrap_err(),
        ProbeError::InvalidCache("model not observed")
    ));
}

#[test]
fn probe_ignores_subagent_models_and_caps_observed_models() {
    let init = "{\"type\":\"system\",\"subtype\":\"init\",\"model\":\"claude-test-model\",\"claude_code_version\":\"1\"}\n";
    let assistant = |model: &str, sub: bool| {
        let parent = if sub {
            ",\"parent_tool_use_id\":\"toolu_1\""
        } else {
            ""
        };
        format!(
            "{{\"type\":\"assistant\"{parent},\"message\":{{\"role\":\"assistant\",\"type\":\"message\",\"model\":\"{model}\"}}}}\n"
        )
    };
    let stream = format!(
        "{init}{}{}",
        assistant("claude-test-model", false),
        assistant("subagent-model", true)
    );
    let observation = ClaudeStreamProbe::from_native_stream(stream.as_bytes())
        .probe(100)
        .unwrap();
    let models: Vec<_> = observation
        .host
        .supported_models
        .iter()
        .map(|m| m.as_str().to_owned())
        .collect();
    assert_eq!(models, ["claude-test-model"]);

    let mut many = format!("{init}{}", assistant("claude-test-model", false));
    for i in 0..MAX_SNAPSHOT_MODELS {
        many.push_str(&assistant(&format!("extra-model-{i}"), false));
    }
    assert!(matches!(
        ClaudeStreamProbe::from_native_stream(many.as_bytes())
            .probe(100)
            .unwrap_err(),
        ProbeError::InvalidCache("model bounds")
    ));
}

#[test]
fn probe_lists_only_the_dated_assistant_model_when_init_names_an_alias() {
    let init = "{\"type\":\"system\",\"subtype\":\"init\",\"model\":\"claude-haiku-4-5\",\"claude_code_version\":\"2.1.285\"}\n";
    let assistant = "{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\"type\":\"message\",\"model\":\"claude-haiku-4-5-20251001\"}}\n";
    let observation =
        ClaudeStreamProbe::from_native_stream(format!("{init}{assistant}").as_bytes())
            .probe(100)
            .unwrap();
    let models: Vec<_> = observation
        .host
        .supported_models
        .iter()
        .map(|m| m.as_str().to_owned())
        .collect();
    assert_eq!(models, ["claude-haiku-4-5-20251001"]);
    // Without a root assistant message nothing is observed.
    assert!(matches!(
        ClaudeStreamProbe::from_native_stream(init.as_bytes())
            .probe(100)
            .unwrap_err(),
        ProbeError::InvalidCache("model not observed")
    ));
}

#[test]
fn probe_fails_when_only_a_subagent_names_a_model() {
    let stream = "{\"type\":\"system\",\"subtype\":\"init\",\"model\":\"claude-haiku-4-5\",\"claude_code_version\":\"2.1.285\"}\n{\"type\":\"assistant\",\"parent_tool_use_id\":\"toolu_1\",\"message\":{\"role\":\"assistant\",\"type\":\"message\",\"model\":\"claude-haiku-4-5-20251001\"}}\n";
    assert!(matches!(
        ClaudeStreamProbe::from_native_stream(stream.as_bytes())
            .probe(100)
            .unwrap_err(),
        ProbeError::InvalidCache("model not observed")
    ));
}
