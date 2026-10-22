use router_doctor::{AuditInput, DoctorError, build_audit_bundle, verify_audit_bundle};
use router_types::*;
use serde_json::{Value, json};

#[test]
fn bundle_omits_raw_content_and_preserves_deterministic_metadata() {
    let bytes = br#"{"schema_version":1,"prompt":"PRIVATE_PROMPT","api_key":"PRIVATE_KEY","path":"/private/home/user","custom":{"anything":"SECRET"}}"#;
    let inputs = [
        AuditInput {
            kind: AuditArtifactKind::EffectiveConfig,
            bytes,
        },
        AuditInput {
            kind: AuditArtifactKind::Events,
            bytes: br#"[{"output":"PRIVATE_LOG"}]"#,
        },
    ];
    let bundle = build_audit_bundle(&inputs).unwrap();
    let output = serde_json::to_string(&bundle).unwrap();
    for forbidden in [
        "PRIVATE_PROMPT",
        "PRIVATE_KEY",
        "PRIVATE_LOG",
        "/private/home/user",
        "SECRET",
    ] {
        assert!(!output.contains(forbidden));
    }
    assert!(bundle.records[0].metadata.contained_secret_pattern);
    assert_eq!(bundle.records[0].metadata.schema_version, Some(1));
    assert!(!bundle.raw_content_included);
    assert!(!bundle.signature_verified);
    assert!(!format!("{:?}", inputs[0]).contains("PRIVATE_KEY"));
    verify_audit_bundle(&bundle, Some(&bundle.root_hash)).unwrap();
    assert_eq!(bundle, build_audit_bundle(&inputs).unwrap());
}

fn build(kind: AuditArtifactKind, value: Value) -> AuditBundle {
    build_audit_bundle(&[AuditInput {
        kind,
        bytes: &serde_json::to_vec(&value).unwrap(),
    }])
    .unwrap()
}

fn data(bundle: &AuditBundle) -> &AuditProjectionData {
    let projection = bundle.records[0].projection.as_ref().unwrap();
    assert_eq!(projection.provenance, AuditProvenance::UnverifiedInput);
    &projection.data
}

fn reference(raw: &str) -> String {
    let mut bytes = b"agent-router:audit-reference:v2\0".to_vec();
    bytes.extend(raw.as_bytes());
    router_adapter_api::content_digest(&bytes)
}

fn examples() -> Vec<(AuditArtifactKind, Value)> {
    vec![
        (
            AuditArtifactKind::EffectiveConfig,
            json!({"schema_version":1,"sources":["organization-private","task-private"],
                "allowed_models":["private-model"],"allowed_capabilities":["tools"],
                "allowed_mutations":[],"preferred_model":"private-model",
                "max_cost_microusd":5000,"max_tokens":12000,"max_elapsed_ms":60000,
                "max_concurrency":2,"policy_hash":"policy-private"}),
        ),
        (
            AuditArtifactKind::Decision,
            json!({"schema_version":2,"receipt_id":"private-receipt","phase":"execute",
                "context_hash":"private-context","catalog_hash":"private-catalog",
                "policy_hash":"policy-private","snapshot_hash":"private-snapshot",
                "pool_hash":"private-pool","registry_hash":"private-registry",
                "selected":{"candidate":{"id":"private-candidate","model":"private-model",
                    "effort":"high","sandbox":"read_only","verification":"independent",
                    "required_capabilities":["tools"],"required_mutations":[],
                    "estimated_cost_microusd":4000,"estimated_tokens":8000,"estimated_elapsed_ms":50000},
                    "score":{"utility_micros":3000000},"assets":[{"id":"private-agent"}],
                    "reasons":["private-reason"]},"alternatives":[{}],"exclusions":[{},{}],
                "unavailable":[],"abstention":null}),
        ),
        (
            AuditArtifactKind::Events,
            json!({"run":{"run_id":"private-run","state":"timed_out","attempts":2,
                    "failure":"timeout","receipt_id":"private-receipt","plan_id":"private-plan",
                    "node_id":"private-node","definition_hash":"private-definition",
                    "approval_digest":"private-approval","artifact_sha256":"private-artifact",
                    "worktree":"/private/worktree"},
                "sequence":4,"kind":"transition","event_hash":"private-event",
                "recorded_at_unix_seconds":1790000000,
                "transport":{"termination":"timed_out","exit_code":null,"elapsed_ms":2000},
                "stdout_bytes":100,"stderr_bytes":50,"stdout_sha256":"private-stdout-digest",
                "stderr_sha256":"private-stderr-digest","validation":"unknown","objective":"unknown",
                "requested_model":"private-model","requested_effort":"high"}),
        ),
        (
            AuditArtifactKind::Evidence,
            json!({"schema_version":1,"runtime_evidence":{
                "transport":{"termination":"exited","exit_code":0,"elapsed_ms":400},
                "transport_success":true,"stream_complete":true,"validation":"passed","objective":"failed",
                "executed_models":[{"model":"private-model","source":"native-init",
                    "source_sha256":"private-native-evidence"}],"executed_effort":"high",
                "events":[{"kind":"session_started"},{"kind":"turn_completed"}],
                "missing_evidence":["private-evidence-explanation"]},"evidence_sha256":"private-evidence"}),
        ),
        (
            AuditArtifactKind::Versions,
            json!({"policy_version":"1.2.3","backend":"laya-local","backend_version":"4.5.6",
                "producer_version":"0.1","provenance_sha256":"private-provenance"}),
        ),
        (
            AuditArtifactKind::Catalog,
            json!({"version":"3.2","models":[{"id":"private-model"}],
                "skills":[{},{}],"assets":[],"catalog_content_sha256":"private-catalog"}),
        ),
    ]
}

#[test]
fn projections_preserve_decisions_restrictions_and_runtime_outcomes() {
    let bundles: Vec<_> = examples()
        .into_iter()
        .map(|(kind, v)| build(kind, v))
        .collect();
    for bundle in &bundles {
        assert_eq!(bundle.schema_version, 2);
        verify_audit_bundle(bundle, Some(&bundle.root_hash)).unwrap();
        let json = serde_json::to_vec(bundle).unwrap();
        assert_eq!(
            *bundle,
            serde_json::from_slice::<AuditBundle>(&json).unwrap()
        );
    }
    let AuditProjectionData::EffectiveConfig(config) = data(&bundles[0]) else {
        panic!()
    };
    assert_eq!(config.source_sha256.len(), 2);
    assert_eq!(config.allowed_capabilities, Some(vec![Capability::Tools]));
    assert_eq!(config.allowed_mutations, Some(vec![]));
    assert_eq!(
        config.preferred_model_sha256,
        Some(reference("private-model"))
    );
    assert_eq!(
        config.allowed_model_sha256,
        Some(vec![reference("private-model")])
    );
    assert_eq!(config.budget.max_tokens, Some(12000));
    assert_eq!(config.budget.max_concurrency, Some(2));
    let AuditProjectionData::Decision(decision) = data(&bundles[1]) else {
        panic!()
    };
    assert_eq!(decision.verdict, AuditDecisionVerdict::Selected);
    assert_eq!(decision.phase, Some(StageKind::Execute));
    assert_eq!(decision.model_sha256, config.preferred_model_sha256);
    assert_eq!(decision.effort, Some(EffortLevel::High));
    assert_eq!(decision.sandbox, Some(PhaseSandbox::ReadOnly));
    assert_eq!(decision.verification, Some(PhaseVerification::Independent));
    assert_eq!(decision.utility_micros, Some(3000000));
    assert_eq!(decision.estimated_tokens, Some(8000));
    assert_eq!(decision.asset_count, Some(1));
    assert_eq!(decision.alternatives, Some(1));
    assert_eq!(decision.exclusions, Some(2));
    assert_eq!(
        decision.references.policy_sha256,
        config.references.policy_sha256
    );
    let AuditProjectionData::Events(events) = data(&bundles[2]) else {
        panic!()
    };
    assert_eq!(events.total_entries, 1);
    let event = &events.entries[0];
    assert_eq!(event.run_sha256, Some(reference("private-run")));
    assert_eq!(event.kind, Some(AuditEventKind::Transition));
    assert_eq!(event.state, Some(AuditRunState::TimedOut));
    assert_eq!(event.failure, Some(AuditFailure::Timeout));
    assert_eq!(event.attempts, Some(2));
    assert_eq!(event.termination, Some(TransportTermination::TimedOut));
    assert_eq!(event.recorded_at_unix_seconds, Some(1790000000));
    assert_eq!(event.stdout_bytes, Some(100));
    assert_eq!(
        event.stdout_sha256,
        Some(reference("private-stdout-digest"))
    );
    assert_eq!(
        event.references.receipt_sha256,
        decision.references.receipt_sha256
    );
    assert_eq!(
        event.references.approval_sha256,
        Some(reference("private-approval"))
    );
    let AuditProjectionData::Evidence(evidence) = data(&bundles[3]) else {
        panic!()
    };
    assert_eq!(evidence.transport_success, Some(true));
    assert_eq!(evidence.termination, Some(TransportTermination::Exited));
    assert_eq!(evidence.exit_code, Some(0));
    assert_eq!(evidence.validation, Some(VerificationOutcome::Passed));
    assert_eq!(evidence.objective, Some(VerificationOutcome::Failed));
    assert_eq!(evidence.observed_effort, Some(EffortLevel::High));
    assert_eq!(evidence.model_sha256, vec![reference("private-model")]);
    assert_eq!(
        evidence.model_source_sha256,
        vec![reference("private-native-evidence")]
    );
    assert_eq!(evidence.event_count, Some(2));
    let AuditProjectionData::Versions(versions) = data(&bundles[4]) else {
        panic!()
    };
    assert_eq!(versions.backend, AuditBackendKind::Laya);
    assert_eq!(
        (
            versions.policy.major,
            versions.policy.minor,
            versions.policy.patch
        ),
        (Some(1), Some(2), Some(3))
    );
    assert_eq!(
        versions.backend_version.identity_sha256,
        Some(reference("4.5.6"))
    );
    let AuditProjectionData::Catalog(catalog) = data(&bundles[5]) else {
        panic!()
    };
    assert_eq!(catalog.model_count, Some(1));
    assert_eq!(catalog.skill_count, Some(2));
    assert_eq!(catalog.asset_count, Some(0));
    assert_eq!(
        catalog.references.catalog_sha256,
        decision.references.catalog_sha256
    );
}

#[test]
fn abstention_and_unknown_remain_distinct_from_selection() {
    let abstained = build(
        AuditArtifactKind::Decision,
        json!({"receipt":{
        "phase":"verify","selected":null,"abstention":"no_eligible_candidate"}}),
    );
    let AuditProjectionData::Decision(decision) = data(&abstained) else {
        panic!()
    };
    assert_eq!(decision.verdict, AuditDecisionVerdict::Abstained);
    assert_eq!(
        decision.abstention,
        Some(PhaseAbstention::NoEligibleCandidate)
    );
    let unknown = build(
        AuditArtifactKind::Decision,
        json!({"selected":null,"abstention":"PRIVATE_REASON"}),
    );
    let AuditProjectionData::Decision(decision) = data(&unknown) else {
        panic!()
    };
    assert_eq!(decision.verdict, AuditDecisionVerdict::Unknown);
    assert!(decision.abstention.is_none());
}

#[test]
fn raw_and_indirect_canaries_are_removed_from_every_input_string_field() {
    fn poison(value: &mut Value, canary: &str) {
        match value {
            Value::String(text) => *text = canary.into(),
            Value::Array(items) => items.iter_mut().for_each(|v| poison(v, canary)),
            Value::Object(fields) => {
                fields.values_mut().for_each(|v| poison(v, canary));
                fields.insert(canary.into(), json!({"secret":canary,"api_key":canary}));
            }
            _ => {}
        }
    }
    for canary in [
        "CANARY_PRIVATE_PROMPT_PATH_TOKEN",
        "a9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba98",
    ] {
        for (kind, mut input) in examples() {
            poison(&mut input, canary);
            let input_bytes = serde_json::to_vec(&input).unwrap();
            let transient = AuditInput {
                kind,
                bytes: &input_bytes,
            };
            let bundle = build_audit_bundle(&[transient]).unwrap();
            verify_audit_bundle(&bundle, Some(&bundle.root_hash)).unwrap();
            for output in [
                serde_json::to_string(&bundle).unwrap(),
                format!("{bundle:?}"),
            ] {
                assert!(!output.contains(canary), "{kind:?} leaked {canary}");
                assert!(!output.contains("api_key"));
            }
            assert!(!bundle.signature_verified);
            assert_eq!(
                bundle.records[0].projection.as_ref().unwrap().provenance,
                AuditProvenance::UnverifiedInput
            );
        }
    }
}

#[test]
fn declared_hashes_and_versions_are_correlation_keys_not_reflected_proofs() {
    let digest = "c9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba98";
    let bundle = build(
        AuditArtifactKind::Versions,
        json!({
        "policy_version":"secret-release-token","backend":"PRIVATE_BACKEND",
        "backend_version":"1.2.3-secret","producer_version":"12345.2",
        "evidence_sha256":digest,"signature_verified":true,"authenticated":true,
        "provenance":"verified_native","authority":{"token":"PRIVATE_AUTHORITY"}}),
    );
    let AuditProjectionData::Versions(versions) = data(&bundle) else {
        panic!()
    };
    assert_eq!(versions.backend, AuditBackendKind::Unknown);
    assert!(versions.policy.major.is_none());
    assert!(versions.backend_version.major.is_none());
    assert!(versions.producer.major.is_none());
    assert_eq!(versions.references.evidence_sha256, Some(reference(digest)));
    let output = serde_json::to_string(&bundle).unwrap();
    for canary in [
        digest,
        "secret-release-token",
        "1.2.3-secret",
        "PRIVATE_BACKEND",
        "PRIVATE_AUTHORITY",
        "verified_native",
    ] {
        assert!(!output.contains(canary));
    }
    assert!(!bundle.signature_verified);
}

#[test]
fn malformed_or_out_of_range_fields_become_unknown_without_extra_text() {
    let bundle = build(
        AuditArtifactKind::EffectiveConfig,
        json!({
        "allowed_models":vec!["x"; 65],"allowed_capabilities":["tools","PRIVATE_TOKEN"],
        "allowed_mutations":[{"api_key":"PRIVATE_TOKEN"}],"sources":[false],
        "max_tokens":1000000000001_u64,"max_cost_microusd":-1,"max_elapsed_ms":1.5,
        "max_concurrency":1000000000000_u64,"preferred_model":"x".repeat(16385)}),
    );
    let AuditProjectionData::EffectiveConfig(config) = data(&bundle) else {
        panic!()
    };
    assert!(config.allowed_model_sha256.is_none());
    assert!(config.allowed_capabilities.is_none());
    assert!(config.allowed_mutations.is_none());
    assert!(config.source_sha256.is_empty());
    assert!(config.budget.max_tokens.is_none());
    assert!(config.budget.max_cost_microusd.is_none());
    assert!(config.budget.max_elapsed_ms.is_none());
    assert!(config.preferred_model_sha256.is_none());
    assert_eq!(config.budget.max_concurrency, Some(1000000000000));
    verify_audit_bundle(&bundle, None).unwrap();
    let bundle = build(
        AuditArtifactKind::Events,
        json!({
        "events":vec![json!({"kind":"session_started","sequence":u64::MAX,
            "recorded_at_unix_seconds":-1,"elapsed_ms":u64::MAX,"exit_code":i64::MAX});65]}),
    );
    let AuditProjectionData::Events(events) = data(&bundle) else {
        panic!()
    };
    assert_eq!(
        (
            events.total_entries,
            events.omitted_entries,
            events.entries.len()
        ),
        (65, 1, 64)
    );
    assert_eq!(
        events.entries[0].transport_kind,
        Some(TransportEventKind::SessionStarted)
    );
    assert!(events.entries[0].kind.is_none());
    assert!(events.entries[0].sequence.is_none());
    assert!(events.entries[0].recorded_at_unix_seconds.is_none());
    assert!(events.entries[0].elapsed_ms.is_none());
    assert!(events.entries[0].exit_code.is_none());
    verify_audit_bundle(&bundle, None).unwrap();
}

#[test]
fn v2_chain_binds_projection_and_rejects_unsupported_provenance() {
    let bundle = build(AuditArtifactKind::EffectiveConfig, examples().remove(0).1);
    let mut changed = bundle.clone();
    let AuditProjectionData::EffectiveConfig(config) =
        &mut changed.records[0].projection.as_mut().unwrap().data
    else {
        panic!()
    };
    config.budget.max_tokens = Some(1);
    assert_eq!(
        verify_audit_bundle(&changed, None),
        Err(DoctorError::Integrity)
    );
    let AuditProjectionData::EffectiveConfig(config) =
        &mut changed.records[0].projection.as_mut().unwrap().data
    else {
        panic!()
    };
    config.allowed_model_sha256 = Some(vec!["PRIVATE_TOKEN".into()]);
    assert_eq!(
        verify_audit_bundle(&changed, None),
        Err(DoctorError::Integrity)
    );
    let mut changed = bundle.clone();
    changed.records[0].kind = AuditArtifactKind::Catalog;
    assert_eq!(
        verify_audit_bundle(&changed, None),
        Err(DoctorError::Integrity)
    );
    let mut changed = bundle.clone();
    changed.records[0].projection = None;
    assert_eq!(
        verify_audit_bundle(&changed, None),
        Err(DoctorError::Integrity)
    );
    let mut json = serde_json::to_value(&bundle).unwrap();
    json["records"][0]["projection"]["provenance"] = json!("authenticated");
    assert!(serde_json::from_value::<AuditBundle>(json).is_err());
    let mut json = serde_json::to_value(&bundle).unwrap();
    json["records"][0]["projection"]["data"]["fields"]["api_key"] = json!("PRIVATE_TOKEN");
    assert!(serde_json::from_value::<AuditBundle>(json).is_err());
}

#[test]
fn projection_numeric_and_entry_limits_are_verified_on_deserialized_bundles() {
    let bundle = build(AuditArtifactKind::Events, json!([{"sequence":1}]));
    let mut value = serde_json::to_value(&bundle).unwrap();
    value["records"][0]["projection"]["data"]["fields"]["entries"][0]["sequence"] =
        json!(1000000000001_u64);
    let changed: AuditBundle = serde_json::from_value(value).unwrap();
    assert_eq!(verify_audit_bundle(&changed, None), Err(DoctorError::Limit));
    let mut value = serde_json::to_value(&bundle).unwrap();
    let fields = &mut value["records"][0]["projection"]["data"]["fields"];
    fields["entries"] = json!(vec![fields["entries"][0].clone(); 65]);
    fields["total_entries"] = json!(65);
    let changed: AuditBundle = serde_json::from_value(value).unwrap();
    assert_eq!(verify_audit_bundle(&changed, None), Err(DoctorError::Limit));
    let mut value = serde_json::to_value(&bundle).unwrap();
    value["records"][0]["projection"]["data"]["fields"]["omitted_entries"] = json!(1);
    let changed: AuditBundle = serde_json::from_value(value).unwrap();
    assert_eq!(
        verify_audit_bundle(&changed, None),
        Err(DoctorError::Integrity)
    );
}

#[test]
fn fixed_v1_fixture_verifies_without_projection_and_cannot_accept_one() {
    // Frozen v1 bytes and digest, independent of the v2 builder.
    let fixture = json!({"schema_version":1,"records":[{
        "sequence":1,"kind":"catalog",
        "content_sha256":"a9d5f6d002d956b8af5787a05e0ca000d45c03977ffa54ee8fbed719fed5fd23",
        "byte_count":20,"metadata":{"schema_version":1,"top_level_entries":1,"contained_secret_pattern":false},
        "previous_hash":"0000000000000000000000000000000000000000000000000000000000000000",
        "record_hash":"bf237715d47345b41516b4ff38ffc1d8817b685f238dd14c61071a919ec6f138"}],
        "root_hash":"bf237715d47345b41516b4ff38ffc1d8817b685f238dd14c61071a919ec6f138",
        "raw_content_included":false,"signature_verified":false});
    let bundle: AuditBundle = serde_json::from_value(fixture.clone()).unwrap();
    verify_audit_bundle(&bundle, Some(&bundle.root_hash)).unwrap();
    assert_eq!(serde_json::to_value(&bundle).unwrap(), fixture);
    let mut changed = bundle.clone();
    changed.records[0].projection = build(AuditArtifactKind::Catalog, json!({}))
        .records
        .remove(0)
        .projection;
    assert_eq!(
        verify_audit_bundle(&changed, None),
        Err(DoctorError::Integrity)
    );
    let mut changed = bundle;
    changed.schema_version = 2;
    assert_eq!(
        verify_audit_bundle(&changed, None),
        Err(DoctorError::Integrity)
    );
    let mut changed = build(AuditArtifactKind::Catalog, json!({}));
    changed.schema_version = 1;
    changed.records[0].projection = None;
    assert_eq!(
        verify_audit_bundle(&changed, None),
        Err(DoctorError::Integrity)
    );
}

#[test]
fn maximum_record_count_and_projected_event_lists_remain_bounded() {
    let event = examples().remove(2).1;
    let bytes = serde_json::to_vec(&vec![event; 64]).unwrap();
    let inputs: Vec<_> = (0..router_doctor::MAX_ARTIFACTS)
        .map(|_| AuditInput {
            kind: AuditArtifactKind::Events,
            bytes: &bytes,
        })
        .collect();
    assert!(bytes.len() * inputs.len() < router_doctor::MAX_TOTAL_BYTES);
    let bundle = build_audit_bundle(&inputs).unwrap();
    verify_audit_bundle(&bundle, Some(&bundle.root_hash)).unwrap();
    let encoded = serde_json::to_vec(&bundle).unwrap();
    assert!(encoded.len() <= 32 * 1024 * 1024);
    eprintln!(
        "audit bounded export: input_bytes={}, output_bytes={}",
        bytes.len() * inputs.len(),
        encoded.len()
    );
}

#[test]
fn anchored_chain_detects_edit_reorder_truncation_and_replacement() {
    let bundle = build_audit_bundle(&[
        AuditInput {
            kind: AuditArtifactKind::Catalog,
            bytes: br#"{"schema_version":1}"#,
        },
        AuditInput {
            kind: AuditArtifactKind::Decision,
            bytes: b"{}",
        },
    ])
    .unwrap();
    let mut changed = bundle.clone();
    changed.records[0].byte_count += 1;
    assert_eq!(
        verify_audit_bundle(&changed, None),
        Err(DoctorError::Integrity)
    );
    let mut changed = bundle.clone();
    changed.records.swap(0, 1);
    assert_eq!(
        verify_audit_bundle(&changed, None),
        Err(DoctorError::Integrity)
    );
    let mut changed = bundle.clone();
    changed.records.pop();
    changed.root_hash = changed.records[0].record_hash.clone();
    verify_audit_bundle(&changed, None).unwrap();
    assert_eq!(
        verify_audit_bundle(&changed, Some(&bundle.root_hash)),
        Err(DoctorError::Integrity)
    );
    let other = build_audit_bundle(&[AuditInput {
        kind: AuditArtifactKind::Evidence,
        bytes: b"{}",
    }])
    .unwrap();
    assert_eq!(
        verify_audit_bundle(&other, Some(&bundle.root_hash)),
        Err(DoctorError::Integrity)
    );
    let mut changed = bundle;
    changed.signature_verified = true;
    assert_eq!(
        verify_audit_bundle(&changed, None),
        Err(DoctorError::Integrity)
    );
}

#[test]
fn malformed_duplicate_secret_content_cannot_enter_audit_fields() {
    for bytes in [b"bad".as_slice(), b"{\"a\":1,\"a\":2}", b"42"] {
        assert_eq!(
            build_audit_bundle(&[AuditInput {
                kind: AuditArtifactKind::Evidence,
                bytes
            }])
            .unwrap_err(),
            DoctorError::Schema
        );
    }
}
