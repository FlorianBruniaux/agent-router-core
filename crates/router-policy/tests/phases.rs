#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use std::collections::BTreeSet;

use router_adapter_api::{
    ALL_CAPABILITIES, CapabilityEvidence, EvidenceKind, EvidenceSource, HostObservation,
    SnapshotValidation, ValidatedHostObservation,
};
use router_catalog::Catalog;
use router_policy::{MAX_PHASE_CANDIDATES, PhaseRouteError, PhaseRouter};
use router_types::*;
use router_workflow::merge_restrictions;
use serde_json::{Value, json};

fn model(id: &str) -> ModelId {
    ModelId::parse(id).unwrap()
}

fn catalog_json() -> Value {
    json!({"schema_version":1,"version":"same-version","models":[
        {"id":"fixture-best","stages":["plan","execute","verify"],"efforts":["medium","high"],"capabilities":["tools","subagents","vision","network","workspace_write"],"quality_micros":900000,"cost_micros":100,"latency_micros":100,"source":"synthetic"},
        {"id":"fixture-second","stages":["plan","execute","verify"],"efforts":["medium","high"],"capabilities":["tools","subagents","vision","network","workspace_write"],"quality_micros":700000,"cost_micros":50,"latency_micros":50,"source":"synthetic"}
    ],"skills":[
        {"id":"trusted-skill","description":"bounded tests","task_kinds":["explore","implement"],"required_capabilities":[],"trust":"trusted_local"},
        {"id":"untrusted-skill","description":"untrusted metadata","task_kinds":["explore"],"required_capabilities":[],"trust":"untrusted"},
        {"id":"blocked-skill","description":"blocked metadata","task_kinds":["explore"],"required_capabilities":[],"trust":"blocked"}
    ]})
}

fn catalog(value: Value) -> Catalog {
    Catalog::from_json(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn observation() -> HostObservation {
    let models = [model("fixture-best"), model("fixture-second")];
    HostObservation {
        attestations: None,
        schema_version: 1,
        host: HostSnapshot {
            id: "synthetic-host".into(),
            harness: HarnessId::parse("codex").unwrap(),
            supported_models: models.iter().cloned().collect(),
            supported_efforts: models
                .into_iter()
                .map(|id| (id, BTreeSet::from([EffortLevel::Medium, EffortLevel::High])))
                .collect(),
            capabilities: ALL_CAPABILITIES.into_iter().collect(),
        },
        capabilities: ALL_CAPABILITIES
            .into_iter()
            .map(|cap| {
                (
                    cap,
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
            observed_version: Some("fixture-v1".into()),
            observed_at_unix_seconds: 100,
            content_sha256: "a".repeat(64),
        }],
        observed_at_unix_seconds: 100,
        snapshot_hash: String::new(),
    }
}

fn snapshot(observation: HostObservation) -> ValidatedHostObservation {
    fixture_proofs::from_observation(
        observation.seal().unwrap(),
        SnapshotValidation {
            now_unix_seconds: 100,
            max_age_seconds: 10,
        },
    )
    .unwrap()
}

fn restrictions() -> EffectiveRestrictions {
    merge_restrictions(&[RestrictionLayer {
        name: "fixture-authority".into(),
        allowed_models: None,
        allowed_capabilities: Some(ALL_CAPABILITIES.into_iter().collect()),
        allowed_mutations: Some(BTreeSet::from([
            Mutation::WorkspaceWrite,
            Mutation::Network,
            Mutation::ExecuteSkills,
            Mutation::Integrate,
        ])),
        max_cost_microusd: Some(10000),
        max_tokens: Some(1000),
        max_concurrency: Some(2),
        preferred_model: None,
    }])
    .unwrap()
}

fn candidate(id: &str, model_id: &str) -> PhaseCandidate {
    PhaseCandidate {
        tool_policy: router_types::PhaseToolPolicy::Restricted,
        id: id.into(),
        model: model(model_id),
        effort: EffortLevel::Medium,
        agent: None,
        skills: BTreeSet::new(),
        tools: BTreeSet::new(),
        sandbox: PhaseSandbox::ReadOnly,
        verification: PhaseVerification::Required,
        required_capabilities: BTreeSet::new(),
        required_mutations: BTreeSet::new(),
        estimated_cost_microusd: 100,
        estimated_tokens: 100,
        estimated_elapsed_ms: 100,
        relevance_micros: 0,
    }
}

fn registered(kind: PhaseAssetKind, id: &str) -> PhaseRegisteredAsset {
    PhaseRegisteredAsset {
        kind,
        id: id.into(),
        content_sha256: "b".repeat(64),
        trust: SkillTrust::TrustedLocal,
        license: "MIT".into(),
        permission: CapabilitySupport::Supported,
        required_capabilities: BTreeSet::new(),
        required_mutations: BTreeSet::new(),
        allowed_sandboxes: BTreeSet::from([PhaseSandbox::ReadOnly, PhaseSandbox::WorkspaceWrite]),
        maximum_sensitivity: DataSensitivity::Secret,
    }
}

fn request() -> PhaseRouteRequest {
    PhaseRouteRequest {
        schema_version: 2,
        task: NormalizedTask {
            objective: "Inspect the Rust contract".into(),
            kind: TaskKind::Explore,
            deliverables: vec!["contract report".into()],
            constraints: vec![],
            scope: vec!["src".into()],
            risk: RiskLevel::Low,
            sensitivity: DataSensitivity::Public,
            budget: TaskBudget {
                max_cost_microusd: 10000,
                max_elapsed_ms: 1000,
                max_tokens: 1000,
            },
            allowed_mutations: BTreeSet::from([
                Mutation::WorkspaceWrite,
                Mutation::Network,
                Mutation::ExecuteSkills,
                Mutation::Integrate,
            ]),
            dependencies: vec![],
            acceptance: vec!["cite an enforcing symbol".into()],
            required_capabilities: BTreeSet::new(),
        },
        phase: StageKind::Plan,
        restrictions: restrictions(),
        permissions: [
            PhasePermission::ModelInference,
            PhasePermission::WorkspaceRead,
            PhasePermission::WorkspaceWrite,
            PhasePermission::Network,
            PhasePermission::ExecuteSkills,
            PhasePermission::Delegate,
            PhasePermission::Integrate,
        ]
        .into_iter()
        .map(|permission| (permission, CapabilitySupport::Supported))
        .collect(),
        registry: PhaseAssetRegistry::default(),
        candidates: vec![
            candidate("primary", "fixture-best"),
            candidate("secondary", "fixture-second"),
        ],
        previous_model: None,
    }
}

fn route(request: PhaseRouteRequest) -> PhaseReceipt {
    let router = PhaseRouter::stable_v2();
    router
        .route(
            &router
                .context(request, &snapshot(observation()), &catalog(catalog_json()))
                .unwrap(),
        )
        .unwrap()
}

fn prefer(request: &mut PhaseRouteRequest, preferred: &str) {
    use sha2::{Digest, Sha256};
    request.restrictions.preferred_model = Some(model(preferred));
    request.restrictions.policy_hash.clear();
    request.restrictions.policy_hash = hex::encode(Sha256::digest(
        serde_json::to_vec(&request.restrictions).unwrap(),
    ));
}

#[test]
fn native_host_tools_require_explicit_permission_and_cannot_hide_an_allowlist() {
    let mut input = request();
    input.candidates.truncate(1);
    input.candidates[0].tool_policy = PhaseToolPolicy::NativeHost;
    let denied = route(input.clone());
    assert!(denied.selected.is_none());
    assert!(
        denied
            .exclusions
            .iter()
            .any(|e| e.code == "permission.unknown_or_denied")
    );
    input.permissions.insert(
        PhasePermission::NativeHostTools,
        CapabilitySupport::Supported,
    );
    let accepted = route(input.clone());
    assert_eq!(
        accepted.selected.as_ref().unwrap().candidate.tool_policy,
        PhaseToolPolicy::NativeHost
    );
    input.candidates[0].tools.insert("shell".into());
    let conflict = route(input);
    assert!(conflict.selected.is_none());
    assert!(
        conflict
            .exclusions
            .iter()
            .any(|e| e.code == "tools.policy.conflict")
    );
}

#[test]
fn restricted_default_preserves_the_original_candidate_wire_bytes() {
    let value = serde_json::to_value(candidate("test", "fixture-primary")).unwrap();
    assert!(value.get("tool_policy").is_none());
    let decoded: PhaseCandidate = serde_json::from_value(value).unwrap();
    assert_eq!(decoded.tool_policy, PhaseToolPolicy::Restricted);
}

#[test]
fn preferred_model_precedes_score_and_preserves_constrained_fallback() {
    let mut request = request();
    prefer(&mut request, "fixture-second");
    let router = PhaseRouter::stable_v2();
    let context = router
        .context(request, &snapshot(observation()), &catalog(catalog_json()))
        .unwrap();
    let receipt = router.route(&context).unwrap();
    let selection = receipt.selected.as_ref().unwrap();
    assert_eq!(selection.candidate.id, "secondary");
    assert!(selection.score.utility_micros < receipt.alternatives[0].score.utility_micros);
    router.validate_selection(&context, selection).unwrap();
    let fallback = router
        .fallback(&context, &BTreeSet::from(["secondary".into()]))
        .unwrap();
    assert_eq!(fallback.selected.unwrap().candidate.id, "primary");
}

#[test]
fn preferred_model_never_regrants_permissions_or_suppresses_ambiguity_within_that_model() {
    let mut denied = request();
    prefer(&mut denied, "fixture-second");
    denied.candidates[1].sandbox = PhaseSandbox::WorkspaceWrite;
    denied.permissions.insert(
        PhasePermission::WorkspaceWrite,
        CapabilitySupport::Unsupported,
    );
    let receipt = route(denied);
    assert_eq!(receipt.selected.unwrap().candidate.id, "primary");
    assert!(
        receipt
            .exclusions
            .iter()
            .any(|e| e.candidate_id == "secondary" && e.code == "permission.unknown_or_denied")
    );

    let mut ambiguous = request();
    prefer(&mut ambiguous, "fixture-second");
    let mut duplicate = ambiguous.candidates[1].clone();
    duplicate.id = "another-preferred".into();
    ambiguous.candidates.push(duplicate);
    assert_eq!(
        route(ambiguous).abstention,
        Some(PhaseAbstention::Ambiguous)
    );
}

#[test]
fn preferred_model_cannot_bypass_the_minimum_utility_threshold() {
    let mut request = request();
    prefer(&mut request, "fixture-second");
    let router = PhaseRouter::new(PhasePolicy {
        minimum_utility_micros: 80_000_000,
        ..PhasePolicy::default()
    })
    .unwrap();
    let context = router
        .context(request, &snapshot(observation()), &catalog(catalog_json()))
        .unwrap();
    let receipt = router.route(&context).unwrap();
    assert_eq!(receipt.abstention, Some(PhaseAbstention::BelowThreshold));
    assert!(receipt.selected.is_none());
}

#[test]
fn deterministic_receipt_binds_each_phase_and_complete_selection() {
    let router = PhaseRouter::stable_v2();
    let context = router
        .context(
            request(),
            &snapshot(observation()),
            &catalog(catalog_json()),
        )
        .unwrap();
    let first = router.route(&context).unwrap();
    assert_eq!(first.schema_version, 2);
    assert_eq!(first.selected.as_ref().unwrap().candidate.id, "primary");
    assert_eq!(first.alternatives[0].candidate.id, "secondary");
    assert_eq!(first.selected.as_ref().unwrap().assets[0].kind, "model");
    assert!(first.exclusions.is_empty());
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&router.route(&context).unwrap()).unwrap()
    );
    let mut execution = request();
    execution.phase = StageKind::Execute;
    assert_ne!(first.receipt_id, route(execution).receipt_id);
    let mut verification = request();
    verification.phase = StageKind::Verify;
    assert_ne!(first.receipt_id, route(verification).receipt_id);
}

#[test]
fn advertised_pool_is_immutable_and_substitution_is_rejected() {
    let router = PhaseRouter::stable_v2();
    let mut input = request();
    let context = router
        .context(
            input.clone(),
            &snapshot(observation()),
            &catalog(catalog_json()),
        )
        .unwrap();
    let selected = router.route(&context).unwrap().selected.unwrap();
    router.validate_selection(&context, &selected).unwrap();
    input.candidates[0].estimated_cost_microusd = 9999;
    assert_eq!(router.route(&context).unwrap().selected.unwrap(), selected);
    let mut altered = selected.clone();
    altered.candidate.model = model("fixture-second");
    assert!(matches!(
        router.validate_selection(&context, &altered),
        Err(PhaseRouteError::OutsidePool)
    ));
    let mut altered = selected;
    altered.score.utility_micros += 1;
    assert!(matches!(
        router.validate_selection(&context, &altered),
        Err(PhaseRouteError::Ineligible)
    ));
    assert!(matches!(
        router.fallback(&context, &BTreeSet::from(["unadvertised".into()])),
        Err(PhaseRouteError::OutsidePool)
    ));
}

#[test]
fn every_risk_rejects_unknown_required_permissions_and_capabilities() {
    for risk in [
        RiskLevel::Low,
        RiskLevel::Medium,
        RiskLevel::High,
        RiskLevel::Critical,
    ] {
        let mut input = request();
        input.task.risk = risk;
        for candidate in &mut input.candidates {
            candidate.verification = PhaseVerification::Independent;
        }
        input.permissions.remove(&PhasePermission::ModelInference);
        let receipt = route(input.clone());
        assert_eq!(
            receipt.abstention,
            Some(PhaseAbstention::NoEligibleCandidate)
        );
        assert!(
            receipt
                .exclusions
                .iter()
                .any(|e| e.code == "permission.unknown_or_denied")
        );
        input.permissions.insert(
            PhasePermission::ModelInference,
            CapabilitySupport::Supported,
        );
        for capability in ALL_CAPABILITIES {
            let mut input = input.clone();
            input.task.required_capabilities.insert(capability);
            let mut raw = observation();
            raw.host.capabilities.remove(&capability);
            raw.capabilities.get_mut(&capability).unwrap().support = CapabilitySupport::Unknown;
            let router = PhaseRouter::stable_v2();
            let result = router
                .route(
                    &router
                        .context(input, &snapshot(raw), &catalog(catalog_json()))
                        .unwrap(),
                )
                .unwrap();
            assert!(
                result.selected.is_none(),
                "risk={risk:?} capability={capability:?}"
            );
            assert!(
                result
                    .exclusions
                    .iter()
                    .any(|e| e.code == "capability.unknown_or_unsupported")
            );
        }
    }
}

#[test]
fn unavailable_or_forbidden_models_and_efforts_are_excluded_before_scoring() {
    let mut input = request();
    input.candidates[0].model = model("missing-model");
    input.candidates[0].relevance_micros = 1_000_000;
    let result = route(input);
    assert_eq!(result.selected.unwrap().candidate.id, "secondary");
    assert!(
        result
            .exclusions
            .iter()
            .any(|e| e.code == "model.catalog.missing")
    );
    let mut input = request();
    input.candidates[0].effort = EffortLevel::Ultra;
    assert_eq!(route(input).selected.unwrap().candidate.id, "secondary");
}

#[test]
fn asset_trust_registry_permissions_and_required_capabilities_are_authoritative() {
    for id in ["untrusted-skill", "blocked-skill"] {
        let mut input = request();
        input.candidates[0]
            .skills
            .insert(SkillId::parse(id).unwrap());
        input.candidates[0].relevance_micros = 1_000_000;
        let result = route(input);
        assert_eq!(result.selected.unwrap().candidate.id, "secondary");
        assert!(
            result
                .exclusions
                .iter()
                .any(|e| e.code == "skill.trust.forbidden")
        );
    }
    let mut input = request();
    input.candidates[0].agent = Some("role".into());
    let result = route(input.clone());
    assert_eq!(result.selected.unwrap().candidate.id, "secondary");
    input
        .registry
        .assets
        .push(registered(PhaseAssetKind::Agent, "role"));
    let result = route(input.clone());
    assert_eq!(result.selected.unwrap().candidate.id, "primary");
    input.registry.assets[0].permission = CapabilitySupport::Unknown;
    assert_eq!(
        route(input.clone()).selected.unwrap().candidate.id,
        "secondary"
    );
    input.registry.assets[0].permission = CapabilitySupport::Supported;
    input.registry.assets[0].trust = SkillTrust::Untrusted;
    assert_eq!(route(input).selected.unwrap().candidate.id, "secondary");
}

#[test]
fn tools_skills_sandbox_and_verification_are_in_the_selected_receipt() {
    let mut input = request();
    input.registry.assets = vec![
        registered(PhaseAssetKind::Agent, "role"),
        registered(PhaseAssetKind::Tool, "cargo"),
    ];
    input.candidates[0].agent = Some("role".into());
    input.candidates[0].tools.insert("cargo".into());
    input.candidates[0]
        .skills
        .insert(SkillId::parse("trusted-skill").unwrap());
    let result = route(input);
    let selected = result.selected.unwrap();
    assert_eq!(selected.assets.len(), 4);
    assert!(
        selected
            .assets
            .iter()
            .all(|asset| asset.content_sha256.len() == 64)
    );
    assert_eq!(selected.candidate.sandbox, PhaseSandbox::ReadOnly);
    assert_eq!(selected.candidate.verification, PhaseVerification::Required);
    assert!(
        selected
            .assets
            .iter()
            .any(|asset| asset.id == "cargo" && asset.authority == "declared_phase_registry")
    );
}

#[test]
fn capability_cannot_smuggle_write_through_a_read_only_sandbox() {
    let mut input = request();
    input.candidates[0]
        .required_capabilities
        .insert(Capability::WorkspaceWrite);
    let result = route(input);
    assert_eq!(result.selected.unwrap().candidate.id, "secondary");
    assert!(
        result
            .exclusions
            .iter()
            .any(|e| e.code == "sandbox.write.forbidden")
    );
    let mut input = request();
    input.candidates[0].sandbox = PhaseSandbox::WorkspaceWrite;
    input
        .task
        .allowed_mutations
        .remove(&Mutation::WorkspaceWrite);
    assert_eq!(route(input).selected.unwrap().candidate.id, "secondary");
}

#[test]
fn budgets_and_independence_are_hard_constraints() {
    let mut input = request();
    input.candidates[0].estimated_cost_microusd = 10001;
    assert_eq!(route(input).selected.unwrap().candidate.id, "secondary");
    let mut input = request();
    input.phase = StageKind::Verify;
    input.task.risk = RiskLevel::High;
    for candidate in &mut input.candidates {
        candidate.verification = PhaseVerification::Independent;
    }
    assert_eq!(
        route(input.clone()).abstention,
        Some(PhaseAbstention::NoEligibleCandidate)
    );
    input.previous_model = Some(model("fixture-best"));
    assert_eq!(route(input).selected.unwrap().candidate.id, "secondary");
}

#[test]
fn fallback_and_abstention_are_deterministic_and_bounded() {
    let router = PhaseRouter::stable_v2();
    let context = router
        .context(
            request(),
            &snapshot(observation()),
            &catalog(catalog_json()),
        )
        .unwrap();
    let fallback = router
        .fallback(&context, &BTreeSet::from(["primary".into()]))
        .unwrap();
    assert_eq!(fallback.selected.unwrap().candidate.id, "secondary");
    let none = router
        .fallback(
            &context,
            &BTreeSet::from(["primary".into(), "secondary".into()]),
        )
        .unwrap();
    assert_eq!(none.abstention, Some(PhaseAbstention::AllUnavailable));
    let mut input = request();
    input.candidates.clear();
    assert_eq!(route(input).abstention, Some(PhaseAbstention::EmptyPool));
    let mut input = request();
    input.candidates[1].model = model("fixture-best");
    assert_eq!(route(input).abstention, Some(PhaseAbstention::Ambiguous));
    let policy = PhasePolicy {
        minimum_utility_micros: i64::MAX,
        ..PhasePolicy::default()
    };
    let router = PhaseRouter::new(policy).unwrap();
    let context = router
        .context(
            request(),
            &snapshot(observation()),
            &catalog(catalog_json()),
        )
        .unwrap();
    assert_eq!(
        router.route(&context).unwrap().abstention,
        Some(PhaseAbstention::BelowThreshold)
    );
}

#[test]
fn full_content_changes_receipt_even_when_versions_are_identical() {
    let router = PhaseRouter::stable_v2();
    let original = route(request());
    let mut value = catalog_json();
    value["models"][0]["quality_micros"] = json!(899999);
    let changed = router
        .route(
            &router
                .context(request(), &snapshot(observation()), &catalog(value))
                .unwrap(),
        )
        .unwrap();
    assert_ne!(original.catalog_hash, changed.catalog_hash);
    assert_ne!(original.receipt_id, changed.receipt_id);
    let mut policy = PhasePolicy::default();
    policy.quality_weight += 1;
    let other_router = PhaseRouter::new(policy).unwrap();
    let changed = other_router
        .route(
            &other_router
                .context(
                    request(),
                    &snapshot(observation()),
                    &catalog(catalog_json()),
                )
                .unwrap(),
        )
        .unwrap();
    assert_ne!(original.policy_hash, changed.policy_hash);
    assert_ne!(original.receipt_id, changed.receipt_id);
    let mut input = request();
    input.candidates[0].estimated_tokens += 1;
    let changed = route(input);
    assert_ne!(original.pool_hash, changed.pool_hash);
    assert_ne!(original.receipt_id, changed.receipt_id);
    let mut raw = observation();
    raw.evidence[0].content_sha256 = "c".repeat(64);
    let changed = router
        .route(
            &router
                .context(request(), &snapshot(raw), &catalog(catalog_json()))
                .unwrap(),
        )
        .unwrap();
    assert_ne!(original.snapshot_hash, changed.snapshot_hash);
    assert_ne!(original.receipt_id, changed.receipt_id);
    let mut input = request();
    input.task.objective = "Inspect another explicit scope".into();
    assert_ne!(original.receipt_id, route(input).receipt_id);
    let mut input = request();
    input
        .registry
        .assets
        .push(registered(PhaseAssetKind::Agent, "role"));
    let registry_original = route(input.clone());
    input.registry.assets[0].content_sha256 = "d".repeat(64);
    assert_ne!(registry_original.registry_hash, route(input).registry_hash);
}

#[test]
fn receipt_proof_accepts_exact_fallback_and_rejects_tampering_or_abstention() {
    let router = PhaseRouter::stable_v2();
    let context = router
        .context(
            request(),
            &snapshot(observation()),
            &catalog(catalog_json()),
        )
        .unwrap();
    let original = router.route(&context).unwrap();
    let proof = router.validate_receipt(&context, &original).unwrap();
    assert_eq!(proof.selection().candidate.id, "primary");
    let fallback = router
        .fallback(&context, &BTreeSet::from(["primary".into()]))
        .unwrap();
    let proof = router.validate_receipt(&context, &fallback).unwrap();
    assert_eq!(proof.selection().candidate.id, "secondary");
    assert_eq!(proof.context_hash(), context.context_hash());
    assert_eq!(proof.receipt(), &fallback);
    let mut forged = fallback.clone();
    forged.unavailable.clear();
    assert!(matches!(
        router.validate_receipt(&context, &forged),
        Err(PhaseRouteError::ReceiptMismatch)
    ));
    let mut forged = fallback.clone();
    forged.selected.as_mut().unwrap().candidate.model = model("fixture-best");
    assert!(matches!(
        router.validate_receipt(&context, &forged),
        Err(PhaseRouteError::ReceiptMismatch)
    ));
    let mut changed = request();
    changed.task.objective.push_str(" changed");
    let changed = router
        .context(changed, &snapshot(observation()), &catalog(catalog_json()))
        .unwrap();
    assert!(matches!(
        router.validate_receipt(&changed, &fallback),
        Err(PhaseRouteError::ReceiptMismatch)
    ));
    let abstained = router
        .fallback(
            &context,
            &BTreeSet::from(["primary".into(), "secondary".into()]),
        )
        .unwrap();
    assert!(matches!(
        router.validate_receipt(&context, &abstained),
        Err(PhaseRouteError::Ineligible)
    ));
}

#[test]
fn canonical_pool_order_is_irrelevant_but_policy_context_cannot_be_swapped() {
    let mut input = request();
    input.candidates.reverse();
    assert_eq!(route(input), route(request()));
    let router = PhaseRouter::stable_v2();
    let context = router
        .context(
            request(),
            &snapshot(observation()),
            &catalog(catalog_json()),
        )
        .unwrap();
    let mut policy = PhasePolicy::default();
    policy.cost_weight += 1;
    assert!(matches!(
        PhaseRouter::new(policy).unwrap().route(&context),
        Err(PhaseRouteError::PolicyMismatch)
    ));
}

#[test]
fn forged_normalization_restrictions_and_oversized_pools_are_rejected() {
    let router = PhaseRouter::stable_v2();
    let snapshot = snapshot(observation());
    let catalog = catalog(catalog_json());
    let mut input = request();
    input.task.scope = vec!["../outside".into()];
    assert!(router.context(input, &snapshot, &catalog).is_err());
    let mut input = request();
    input.restrictions.max_tokens = Some(999999);
    assert!(router.context(input, &snapshot, &catalog).is_err());
    let mut input = request();
    input.candidates = vec![candidate("a", "fixture-best"); MAX_PHASE_CANDIDATES + 1];
    assert!(matches!(
        router.context(input, &snapshot, &catalog),
        Err(PhaseRouteError::Limit(_))
    ));
    let mut input = request();
    input.candidates[1].id = "primary".into();
    assert!(router.context(input, &snapshot, &catalog).is_err());
}

#[test]
fn versioned_cli_example_fixture_has_valid_integrity_and_replays() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/examples");
    let read = |name| std::fs::read(root.join(name)).unwrap();
    let request: PhaseRouteRequest = serde_json::from_slice(&read("phase-request.json")).unwrap();
    let policy: PhasePolicy = serde_json::from_slice(&read("phase-policy.json")).unwrap();
    let snapshot = fixture_proofs::from_json(
        &read("phase-snapshot.json"),
        SnapshotValidation {
            now_unix_seconds: 100,
            max_age_seconds: 10,
        },
    )
    .unwrap();
    let catalog = Catalog::from_json(&read("phase-catalog.json")).unwrap();
    let router = PhaseRouter::new(policy).unwrap();
    let context = router.context(request, &snapshot, &catalog).unwrap();
    let receipt = router.route(&context).unwrap();
    assert_eq!(receipt.selected.as_ref().unwrap().candidate.id, "primary");
    router
        .validate_selection(&context, receipt.selected.as_ref().unwrap())
        .unwrap();
    assert_eq!(receipt, router.route(&context).unwrap());
}
