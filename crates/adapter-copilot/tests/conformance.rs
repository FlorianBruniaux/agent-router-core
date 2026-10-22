//! Synthetic admission fixtures, not claims about installed provider runtimes.
#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use adapter_copilot::{CopilotAdapter, CopilotConfig, CopilotProtocol};
use adapter_opencode::{OpenCodeAdapter, OpenCodeConfig, OpenCodeProtocol};
use router_adapter_api::*;
use router_types::*;
use std::collections::{BTreeMap, BTreeSet};

fn opencode() -> OpenCodeAdapter {
    OpenCodeAdapter::new(OpenCodeConfig {
        schema_version: 1,
        expected_cli_version: "1.0.0-fixture".into(),
        protocol: OpenCodeProtocol::RunV1,
        model_variants: BTreeMap::from([(
            ModelId::parse("synthetic/model-v1").unwrap(),
            BTreeMap::from([(EffortLevel::High, "provider-high".into())]),
        )]),
    })
    .unwrap()
}

fn copilot() -> CopilotAdapter {
    CopilotAdapter::new(CopilotConfig {
        schema_version: 1,
        expected_cli_version: "1.0.0-fixture".into(),
        protocol: CopilotProtocol::CliJsonlV1,
    })
    .unwrap()
}

fn hosts() -> Vec<Box<dyn HarnessAdapter>> {
    vec![Box::new(opencode()), Box::new(copilot())]
}

fn fixture(
    host: &str,
) -> (
    ExecutionRequest,
    ValidatedHostObservation,
    EffectiveRestrictions,
) {
    let model = ModelId::parse("synthetic/model-v1").unwrap();
    let capabilities: BTreeSet<_> = ALL_CAPABILITIES.into_iter().collect();
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
            observed_version: Some("synthetic-version".into()),
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
        sources: vec!["synthetic".into()],
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
fn preparation_preserves_exact_worker_request_and_keeps_prompt_out_of_argv_preview() {
    for adapter in hosts() {
        for mode in [ExecutionMode::DryRun, ExecutionMode::Shadow] {
            let (mut request, snapshot, restrictions) = fixture(adapter.host());
            request.mode = mode;
            let validated =
                authorize_execution(request.clone(), &snapshot, &restrictions, None).unwrap();
            let run = adapter.prepare(&validated).unwrap();
            assert_eq!(run.program, adapter.host());
            assert_eq!(run.requested_model, request.model);
            assert_eq!(run.requested_effort, request.effort);
            assert_eq!(run.mode, mode);
            assert_eq!(run.source_state, request.source_state);
            assert_eq!(run.scope, request.scope);
            assert_eq!(run.sandbox, request.sandbox);
            assert_eq!(run.stdin.as_bytes(), request.prompt.as_bytes());
            assert!(!run.parent_model_changed);
            assert!(run.degradations.is_empty());
            assert!(!format!("{run:?} {validated:?}").contains("PRIVATE_PROMPT"));
            assert!(
                !serde_json::to_string(&run)
                    .unwrap()
                    .contains("PRIVATE_PROMPT")
            );
            for arg in &run.argv {
                assert!(
                    !arg.contains("PRIVATE_PROMPT")
                        && !arg.contains("dangerously")
                        && !arg.contains("yolo")
                        && !arg.starts_with("--allow-")
                        && arg != "--auto"
                        && arg != "-p"
                );
            }
            assert!(
                run.argv
                    .windows(2)
                    .any(|a| a == ["--model", "synthetic/model-v1"])
            );
            if adapter.host() == "opencode" {
                assert!(
                    run.argv
                        .windows(2)
                        .any(|a| a == ["--variant", "provider-high"])
                );
                assert!(run.argv.windows(2).any(|a| a == ["--format", "json"]));
            } else {
                assert!(run.argv.windows(2).any(|a| a == ["--effort", "high"]));
                assert!(run.argv.windows(2).any(|a| a == ["--mode", "plan"]));
                assert!(run.argv.iter().any(|a| a == "--no-remote-export"));
                assert!(run.argv.iter().any(|a| a == "--no-custom-instructions"));
            }
            assert!(
                run.missing_runtime_evidence
                    .iter()
                    .any(|s| s.contains("fresh_binary_bound_probe"))
            );
            assert!(
                run.missing_runtime_evidence
                    .iter()
                    .any(|s| s.contains("supervisor_confinement"))
            );
        }
    }
}

#[test]
fn execute_approval_is_exact_and_cannot_reconfigure_parent() {
    for adapter in hosts() {
        let (mut request, snapshot, restrictions) = fixture(adapter.host());
        request.mode = ExecutionMode::Execute;
        assert_eq!(
            authorize_execution(request.clone(), &snapshot, &restrictions, None).unwrap_err(),
            AdapterError::ApprovalRequired
        );
        let digest = execution_authorization_digest(&request, &snapshot, &restrictions).unwrap();
        let validated =
            authorize_execution(request.clone(), &snapshot, &restrictions, Some(&digest)).unwrap();
        assert_eq!(
            adapter.prepare(&validated).unwrap().authorization_digest,
            digest
        );
        request.prompt.push('x');
        assert_eq!(
            authorize_execution(request.clone(), &snapshot, &restrictions, Some(&digest))
                .unwrap_err(),
            AdapterError::ApprovalRequired
        );
        request.target = ExecutionTarget::ParentConversation;
        assert_eq!(
            authorize_execution(request, &snapshot, &restrictions, Some(&digest)).unwrap_err(),
            AdapterError::Unsupported("parent-model-change")
        );
    }
}

#[test]
fn unknown_capability_and_unapproved_writes_never_become_available_from_configuration() {
    for adapter in hosts() {
        let (mut request, snapshot, restrictions) = fixture(adapter.host());
        let mut observation = snapshot.observation().clone();
        observation
            .capabilities
            .get_mut(&Capability::Tools)
            .unwrap()
            .support = CapabilitySupport::Unknown;
        observation.host.capabilities.remove(&Capability::Tools);
        let unknown = fixture_proofs::from_observation(
            observation.seal().unwrap(),
            SnapshotValidation {
                now_unix_seconds: 100,
                max_age_seconds: 10,
            },
        )
        .unwrap();
        assert_eq!(
            authorize_execution(request.clone(), &unknown, &restrictions, None).unwrap_err(),
            AdapterError::CapabilityDenied
        );
        request.sandbox = ExecutionSandbox::WorkspaceWrite;
        assert_eq!(
            authorize_execution(request, &snapshot, &restrictions, None).unwrap_err(),
            AdapterError::PermissionDenied
        );
    }
}

#[test]
fn tool_restrictions_fail_closed_even_when_worker_degradation_is_allowed() {
    for adapter in hosts() {
        for selection in [
            ToolSelection::Disabled,
            ToolSelection::AllowList(vec!["unobserved_mcp_tool".into()]),
        ] {
            let (mut request, snapshot, restrictions) = fixture(adapter.host());
            request.tools = selection;
            request.allow_degradation = true;
            let validated = authorize_execution(request, &snapshot, &restrictions, None).unwrap();
            assert!(matches!(
                adapter.prepare(&validated),
                Err(AdapterError::Unsupported(_))
            ));
        }
    }
    let (mut request, snapshot, restrictions) = fixture("copilot");
    request.tools = ToolSelection::AllowList(vec!["view".into(), "grep".into()]);
    let validated = authorize_execution(request, &snapshot, &restrictions, None).unwrap();
    let run = copilot().prepare(&validated).unwrap();
    assert!(
        run.argv
            .windows(2)
            .any(|a| a == ["--available-tools", "view,grep"])
    );
    assert!(run.argv.iter().all(|a| !a.starts_with("--allow-")));
}

#[test]
fn missing_effort_mapping_and_host_mismatch_are_errors() {
    for adapter in hosts() {
        let (mut request, snapshot, restrictions) = fixture(adapter.host());
        request.effort = EffortLevel::Ultra;
        let validated = authorize_execution(request, &snapshot, &restrictions, None).unwrap();
        assert_eq!(
            adapter.prepare(&validated).unwrap_err(),
            AdapterError::EffortUnsupported
        );
    }
    let (request, snapshot, restrictions) = fixture("copilot");
    let validated = authorize_execution(request, &snapshot, &restrictions, None).unwrap();
    assert_eq!(
        opencode().prepare(&validated).unwrap_err(),
        AdapterError::HostMismatch
    );
}

#[test]
fn native_agents_require_explicit_degradation_but_skills_stay_hashed_instructions() {
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
        request.skills.push(ExecutionSkill {
            id: SkillId::parse("review").unwrap(),
            content_sha256: content_digest(b"PRIVATE_SKILL"),
            kind: ExecutionSkillKind::Instruction,
            trust: SkillTrust::TrustedLocal,
            body: "PRIVATE_SKILL".into(),
        });
        let validated =
            authorize_execution(request.clone(), &snapshot, &restrictions, None).unwrap();
        let run = adapter.prepare(&validated).unwrap();
        assert_eq!(run.target, ExecutionTarget::ExternalWorker);
        assert_eq!(
            run.degradations
                .iter()
                .map(|v| v.code.as_str())
                .collect::<Vec<_>>(),
            ["target.external_worker", "agent.prompt_role"]
        );
        assert!(String::from_utf8_lossy(run.stdin.as_bytes()).contains("PRIVATE_SKILL"));
        assert!(!format!("{run:?}").contains("PRIVATE_SKILL"));
        request.skills[0].body.push('x');
        assert_eq!(
            authorize_execution(request, &snapshot, &restrictions, None).unwrap_err(),
            AdapterError::Invalid("skill")
        );
    }
}

#[test]
fn version_and_dialect_configuration_is_strict_canonical_and_external_to_host_proof() {
    let original = opencode();
    let encoded = serde_json::to_vec(original.config()).unwrap();
    assert_eq!(
        OpenCodeAdapter::from_json(&encoded)
            .unwrap()
            .config_hash()
            .unwrap(),
        original.config_hash().unwrap()
    );
    let mut changed = original.config().clone();
    changed.expected_cli_version = "2.0.0".into();
    assert_ne!(
        OpenCodeAdapter::new(changed)
            .unwrap()
            .config_hash()
            .unwrap(),
        original.config_hash().unwrap()
    );
    let mut changed = original.config().clone();
    changed
        .model_variants
        .values_mut()
        .next()
        .unwrap()
        .insert(EffortLevel::High, "different-variant".into());
    assert_ne!(
        OpenCodeAdapter::new(changed)
            .unwrap()
            .config_hash()
            .unwrap(),
        original.config_hash().unwrap()
    );
    for bad in [
        r#"{"schema_version":1,"schema_version":1}"#,
        r#"{"schema_version":1,"expected_cli_version":"1","protocol":"run_v2","model_variants":{}}"#,
    ] {
        assert!(OpenCodeAdapter::from_json(bad.as_bytes()).is_err());
    }
    assert!(OpenCodeAdapter::from_json(&vec![b' '; 64 * 1024 + 1]).is_err());
    let original = copilot();
    assert_eq!(
        CopilotAdapter::from_json(&serde_json::to_vec(original.config()).unwrap())
            .unwrap()
            .config_hash()
            .unwrap(),
        original.config_hash().unwrap()
    );
    let mut changed = original.config().clone();
    changed.expected_cli_version = "1.0.1".into();
    assert_ne!(
        CopilotAdapter::new(changed).unwrap().config_hash().unwrap(),
        original.config_hash().unwrap()
    );
    for bad in [
        r#"{"schema_version":1,"schema_version":1}"#,
        r#"{"schema_version":1,"expected_cli_version":"1","protocol":"cli_jsonl_v1","unknown":true}"#,
    ] {
        assert!(CopilotAdapter::from_json(bad.as_bytes()).is_err());
    }
    assert!(CopilotAdapter::from_json(&vec![b' '; 4097]).is_err());
}

#[cfg(unix)]
#[test]
fn synthetic_child_receives_literal_stdin_without_shell_expansion() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    for adapter in hosts() {
        let (request, snapshot, restrictions) = fixture(adapter.host());
        let validated = authorize_execution(request, &snapshot, &restrictions, None).unwrap();
        let run = adapter.prepare(&validated).unwrap();
        // A bounded stdin transport check with a local OS utility, not a provider invocation.
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(run.stdin.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, run.stdin.as_bytes());
        assert!(String::from_utf8_lossy(&output.stdout).contains("$(not-a-command)"));
    }
}

#[test]
fn explicitly_allowed_writes_preserve_supervisor_scope_without_permission_flags() {
    for adapter in hosts() {
        let (mut request, snapshot, mut restrictions) = fixture(adapter.host());
        request.sandbox = ExecutionSandbox::WorkspaceWrite;
        restrictions.allowed_mutations = Some(BTreeSet::from([Mutation::WorkspaceWrite]));
        let validated =
            authorize_execution(request.clone(), &snapshot, &restrictions, None).unwrap();
        let run = adapter.prepare(&validated).unwrap();
        assert_eq!(run.sandbox, ExecutionSandbox::WorkspaceWrite);
        assert_eq!(run.scope, request.scope);
        assert_eq!(run.cwd, request.workspace);
        assert!(
            !run.argv.iter().any(|arg| arg == "--mode"
                || arg.starts_with("--allow-")
                || arg.contains("bypass"))
        );
    }
}

#[test]
fn unsafe_configuration_identifiers_are_rejected_before_preparation() {
    for bad_version in ["", "latest", "1.2.3 --yolo", "1.2.3\n", "--version"] {
        let mut config = opencode().config().clone();
        config.expected_cli_version = bad_version.into();
        assert!(OpenCodeAdapter::new(config).is_err());
        let mut config = copilot().config().clone();
        config.expected_cli_version = bad_version.into();
        assert!(CopilotAdapter::new(config).is_err());
    }
    for bad_variant in ["", "--auto", "high --yolo", "high\n"] {
        let mut config = opencode().config().clone();
        config
            .model_variants
            .values_mut()
            .next()
            .unwrap()
            .insert(EffortLevel::High, bad_variant.into());
        assert!(OpenCodeAdapter::new(config).is_err());
    }
    for bad_model in [
        "unqualified",
        "provider/auto",
        "provider/default",
        "provider/model/nested",
    ] {
        let mut config = opencode().config().clone();
        config.model_variants = BTreeMap::from([(
            ModelId::parse(bad_model).unwrap(),
            BTreeMap::from([(EffortLevel::High, "high".into())]),
        )]);
        assert!(OpenCodeAdapter::new(config).is_err());
    }
}

#[test]
fn exact_version_pin_is_checked_through_the_runtime_trait() {
    let oc = opencode();
    let cp = copilot();
    let cases: [(&dyn HarnessAdapter, &[u8], &[u8]); 2] = [
        (&oc, b"1.0.0-fixture\n", b"1.0.1-fixture\n"),
        (
            &cp,
            b"GitHub Copilot CLI 1.0.0-fixture.\nRun 'copilot update' to check for updates.\n",
            b"GitHub Copilot CLI 1.0.1-fixture.\nRun 'copilot update' to check for updates.\n",
        ),
    ];
    for (adapter, exact, changed) in cases {
        assert!(adapter.requires_native_version());
        adapter.validate_native_version(exact).unwrap();
        assert!(adapter.validate_native_version(changed).is_err());
        assert!(
            adapter
                .validate_native_version(b"arbitrary text 1.0.0-fixture\n")
                .is_err()
        );
    }
}
