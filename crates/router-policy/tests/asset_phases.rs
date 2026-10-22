#[path = "support/asset_fixture.rs"]
mod asset_fixture;
#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;

use router_adapter_api::{
    HostObservation, SnapshotValidation, ValidatedHostObservation, content_digest,
};
use router_asset_contracts::{
    ValidatedAvailability, ValidatedContracts, seal_availability, seal_contracts,
};
use router_catalog::Catalog;
use router_policy::{
    PhaseAssetInputs, PhaseExecutionScope, PhaseRouteError, PhaseRouter, ValidatedPhaseContext,
    asset_authority_scope_digest,
};
use router_types::*;
use std::collections::BTreeMap;

const BODY: &str = "Inspect the source and report evidence.";
struct Fixture {
    request: PhaseRouteRequest,
    snapshot: ValidatedHostObservation,
    catalog: Catalog,
    inputs: PhaseAssetInputs,
}
impl Fixture {
    fn new() -> Self {
        let mut request: PhaseRouteRequest = serde_json::from_slice(include_bytes!(
            "../../../fixtures/examples/phase-request.json"
        ))
        .unwrap();
        for candidate in &mut request.candidates {
            candidate.estimated_tokens = 900;
            candidate
                .skills
                .insert(SkillId::parse("trusted-skill").unwrap());
        }
        let observation: HostObservation = serde_json::from_slice(include_bytes!(
            "../../../fixtures/examples/phase-snapshot.json"
        ))
        .unwrap();
        let snapshot = fixture_proofs::from_observation(
            observation,
            SnapshotValidation {
                now_unix_seconds: 100,
                max_age_seconds: 100,
            },
        )
        .unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../fixtures/examples/phase-catalog.json"
        ))
        .unwrap();
        value["skills"] = serde_json::json!([{"id":"trusted-skill","description":"fixture","task_kinds":["explore"],"required_capabilities":[],"trust":"trusted_local"}]);
        let catalog = Catalog::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
        let inputs = asset_fixture::inputs(
            &request,
            &snapshot,
            &catalog,
            PhaseExecutionScope {
                workspace: "/fixture/workspace".into(),
                source_state: "a".repeat(40),
                scope: vec!["src".into()],
            },
            &BTreeMap::from([(SkillId::parse("trusted-skill").unwrap(), BODY.into())]),
            512,
        );
        Self {
            request,
            snapshot,
            catalog,
            inputs,
        }
    }
    fn context(&self) -> Result<ValidatedPhaseContext, PhaseRouteError> {
        PhaseRouter::stable_v2().context_with_assets(
            self.request.clone(),
            &self.snapshot,
            &self.catalog,
            self.inputs.clone(),
            100,
        )
    }
    fn bind_availability(&mut self, mutator: impl FnOnce(&mut AssetAvailabilityDocument)) {
        let mut doc = self.inputs.availability.document().clone();
        mutator(&mut doc);
        let doc = seal_availability(doc, &self.snapshot).unwrap();
        self.inputs.availability = ValidatedAvailability::from_json(
            &serde_json::to_vec(&doc).unwrap(),
            &self.snapshot,
            &doc.content_hash,
            100,
        )
        .unwrap();
    }
    fn bind_contracts(&mut self, mutator: impl FnOnce(&mut AssetContractsDocument)) {
        let mut doc = self.inputs.contracts.document().clone();
        mutator(&mut doc);
        let doc = seal_contracts(doc, &self.catalog).unwrap();
        self.inputs.contracts = ValidatedContracts::from_json(
            &serde_json::to_vec(&doc).unwrap(),
            &self.catalog,
            &doc.content_hash,
        )
        .unwrap();
    }
    fn refresh_scope(&mut self) {
        let scope =
            asset_authority_scope_digest(&self.request, &self.inputs.execution_scope).unwrap();
        for request in self.inputs.requests.values_mut() {
            request.authority_scope_digest = scope.clone();
        }
    }
    fn execution(&self, context: &ValidatedPhaseContext) -> ExecutionRequest {
        let router = PhaseRouter::stable_v2();
        let receipt = router.route(context).unwrap();
        let selected = receipt.selected.as_ref().unwrap();
        let candidate = &selected.candidate;
        ExecutionRequest {
            schema_version: 1,
            receipt_id: receipt.receipt_id.clone(),
            candidate_id: candidate.id.clone(),
            phase: receipt.phase,
            host: self.snapshot.host().harness.clone(),
            model: candidate.model.clone(),
            effort: candidate.effort,
            workspace: self.inputs.execution_scope.workspace.clone(),
            source_state: self.inputs.execution_scope.source_state.clone(),
            scope: self.inputs.execution_scope.scope.clone(),
            sandbox: ExecutionSandbox::ReadOnly,
            required_capabilities: router.execution_capabilities(context, selected).unwrap(),
            tools: ToolSelection::Disabled,
            agent: None,
            skills: vec![ExecutionSkill {
                id: SkillId::parse("trusted-skill").unwrap(),
                body: BODY.into(),
                content_sha256: content_digest(BODY.as_bytes()),
                kind: ExecutionSkillKind::Instruction,
                trust: SkillTrust::TrustedLocal,
            }],
            prompt: "Review this scope.".into(),
            mode: ExecutionMode::Execute,
            target: ExecutionTarget::ExternalWorker,
            allow_degradation: false,
            timeout_ms: 500,
            max_output_bytes: 4096,
        }
    }
}

#[test]
fn v3_receipt_binds_all_documents_and_preserves_v2_validation() {
    let mut fixture = Fixture::new();
    let router = PhaseRouter::stable_v2();
    let context = fixture.context().unwrap();
    let receipt = router.route(&context).unwrap();
    assert_eq!(receipt.schema_version, 3);
    router.validate_receipt(&context, &receipt).unwrap();
    let legacy = router
        .context(fixture.request.clone(), &fixture.snapshot, &fixture.catalog)
        .unwrap();
    assert_eq!(router.route(&legacy).unwrap().schema_version, 2);
    assert!(router.validate_receipt(&legacy, &receipt).is_err());
    assert_ne!(context.context_hash(), legacy.context_hash());
    assert_eq!(
        receipt
            .selected
            .as_ref()
            .unwrap()
            .assets
            .iter()
            .find(|a| a.kind == "skill")
            .unwrap()
            .content_sha256,
        content_digest(BODY.as_bytes())
    );
    let old = context.context_hash().to_owned();
    fixture.inputs.policy.maximum_output_tokens = 127;
    assert_ne!(fixture.context().unwrap().context_hash(), old);
    fixture.inputs.policy.maximum_output_tokens = 128;
    fixture.inputs.approved_review_digests.clear();
    assert_ne!(fixture.context().unwrap().context_hash(), old);
}

#[test]
fn asset_auth_exclusion_precedes_score_and_best_candidate_can_fall_back() {
    let mut fixture = Fixture::new();
    fixture.bind_availability(|doc| {
        doc.bindings
            .iter_mut()
            .find(|b| b.model.as_str() == "fixture-best")
            .unwrap()
            .authentication = AssetAuthStatus::Unavailable
    });
    let receipt = PhaseRouter::stable_v2()
        .route(&fixture.context().unwrap())
        .unwrap();
    assert_eq!(receipt.selected.unwrap().candidate.id, "secondary");
    assert!(
        receipt
            .exclusions
            .iter()
            .any(|e| e.candidate_id == "primary" && e.code == "asset_gate.auth.unavailable")
    );
}

#[test]
fn candidate_mapping_and_review_scope_cannot_be_rehashed_into_new_authority() {
    let fixture = Fixture::new();
    for mutation in 0..7 {
        let mut changed = fixture.inputs.clone();
        let item = changed.requests.get_mut("primary").unwrap();
        match mutation {
            0 => item.model = ModelId::parse("fixture-second").unwrap(),
            1 => item.effort = EffortLevel::High,
            2 => item.skills.clear(),
            3 => item.authority_scope_digest = "c".repeat(64),
            4 => changed.execution_scope.workspace = "/different/repository".into(),
            5 => changed.execution_scope.source_state = "b".repeat(40),
            _ => changed.execution_scope.scope = vec!["src/child".into()],
        }
        assert!(
            PhaseRouter::stable_v2()
                .context_with_assets(
                    fixture.request.clone(),
                    &fixture.snapshot,
                    &fixture.catalog,
                    changed,
                    100
                )
                .is_err(),
            "mutation {mutation}"
        );
    }
    let mut changed = fixture.inputs.clone();
    changed.requests.remove("secondary");
    assert!(
        PhaseRouter::stable_v2()
            .context_with_assets(
                fixture.request,
                &fixture.snapshot,
                &fixture.catalog,
                changed,
                100
            )
            .is_err()
    );
}

#[test]
fn manifest_cannot_add_undeclared_effects_or_regrant_denied_phase_permissions() {
    let mut fixture = Fixture::new();
    fixture.bind_contracts(|doc| {
        doc.skills[0]
            .required_capabilities
            .insert(Capability::Network);
        doc.skills[0].required_mutations.insert(Mutation::Network);
    });
    assert!(
        PhaseRouter::stable_v2()
            .route(&fixture.context().unwrap())
            .unwrap()
            .selected
            .is_none()
    );
    for extension in fixture.inputs.requests.values_mut() {
        extension.required_capabilities.insert(Capability::Network);
        extension.required_mutations.insert(Mutation::Network);
    }
    fixture
        .request
        .permissions
        .insert(PhasePermission::Network, CapabilitySupport::Unknown);
    fixture.refresh_scope();
    let receipt = PhaseRouter::stable_v2()
        .route(&fixture.context().unwrap())
        .unwrap();
    assert!(receipt.selected.is_none());
    assert!(
        receipt
            .exclusions
            .iter()
            .all(|e| e.code == "asset_gate.capability.unknown_or_denied")
    );
}

#[test]
fn reservations_include_output_overhead_and_obey_phase_budget() {
    let mut fixture = Fixture::new();
    fixture.request.candidates[0].estimated_tokens = 689;
    fixture.refresh_scope();
    let receipt = PhaseRouter::stable_v2()
        .route(&fixture.context().unwrap())
        .unwrap();
    assert_eq!(receipt.selected.unwrap().candidate.id, "secondary");
    assert!(
        receipt
            .exclusions
            .iter()
            .any(|e| e.code == "asset_gate.context.exceeded")
    );
}

#[test]
fn final_gate_binds_true_bytes_rechecks_ttl_and_forbids_cross_repository_replay() {
    let fixture = Fixture::new();
    let router = PhaseRouter::stable_v2();
    let context = fixture.context().unwrap();
    let request = fixture.execution(&context);
    let bytes = b"Approved prompt with separately approved dependency result.";
    let gated = router
        .validate_execution_assets(&context, &request, bytes, 100)
        .unwrap()
        .unwrap();
    gated.verify_prompt(bytes).unwrap();
    assert!(gated.verify_prompt(b"changed").is_err());
    assert!(
        router
            .validate_execution_assets(&context, &request, &vec![b'x'; 513], 100)
            .is_err()
    );
    assert!(
        router
            .validate_execution_assets(&context, &request, bytes, 161)
            .is_err()
    );
    for mutation in 0..8 {
        let mut changed = request.clone();
        match mutation {
            0 => changed.workspace = "/other".into(),
            1 => changed.source_state = "c".repeat(40),
            2 => changed.scope = vec!["src/child".into()],
            3 => changed.skills[0].body.push('!'),
            4 => changed.skills[0].kind = ExecutionSkillKind::Executable,
            5 => changed.skills.clear(),
            6 => changed.tools = ToolSelection::HostPolicy,
            _ => {
                changed.required_capabilities.insert(Capability::Network);
            }
        };
        assert!(
            router
                .validate_execution_assets(&context, &changed, bytes, 100)
                .is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn approvals_reconstructed_for_another_policy_or_scope_cannot_authorize_bodies() {
    let mut fixture = Fixture::new();
    fixture.inputs.policy.maximum_evidence_age_seconds = 59;
    let context = fixture.context().unwrap();
    let request = fixture.execution(&context);
    assert!(
        PhaseRouter::stable_v2()
            .validate_execution_assets(&context, &request, b"prompt", 100)
            .is_err()
    );
    let mut fixture = Fixture::new();
    fixture.inputs.execution_scope.workspace = "/new-repository".into();
    fixture.refresh_scope();
    let context = fixture.context().unwrap();
    let request = fixture.execution(&context);
    assert!(
        PhaseRouter::stable_v2()
            .validate_execution_assets(&context, &request, b"prompt", 100)
            .is_err()
    );
}

#[test]
fn model_audio_or_format_availability_does_not_invent_adapter_input_support() {
    let mut fixture = Fixture::new();
    for request in fixture.inputs.requests.values_mut() {
        request.required_features.insert(AssetFeature::AudioInput);
    }
    let context = fixture.context().unwrap();
    let request = fixture.execution(&context);
    assert!(matches!(
        PhaseRouter::stable_v2().validate_execution_assets(&context, &request, b"prompt", 100),
        Err(PhaseRouteError::Invalid(
            "asset feature has no execution representation"
        ))
    ));
}

#[test]
fn exact_scope_rejects_duplicates_escape_and_missing_source_before_review() {
    let fixture = Fixture::new();
    for scope in [
        vec![],
        vec!["src".into(), "src".into()],
        vec!["../src".into()],
        vec!["outside".into()],
    ] {
        let mut changed = fixture.inputs.execution_scope.clone();
        changed.scope = scope;
        assert!(asset_authority_scope_digest(&fixture.request, &changed).is_err());
    }
    let mut changed = fixture.inputs.execution_scope.clone();
    changed.source_state = "UNKNOWN".into();
    assert!(asset_authority_scope_digest(&fixture.request, &changed).is_err());
}

#[test]
fn historical_context_explicitly_reports_absent_asset_gate() {
    let fixture = Fixture::new();
    let router = PhaseRouter::stable_v2();
    let context = router
        .context(fixture.request.clone(), &fixture.snapshot, &fixture.catalog)
        .unwrap();
    assert!(!context.has_asset_contracts());
    assert!(
        router
            .validate_execution_assets(&context, &fixture.execution(&context), b"historical", 100)
            .unwrap()
            .is_none()
    );
}
