//! Synthetic signed roots and local evidence, never production authorization.
#[path = "support/signed_fixture.rs"]
mod signed_fixture;
use router_catalog::{CatalogAssetKind as Kind, SignedAssetPayload, TrustedCatalogPublishers};
use router_policy::{GenerationError, GenerationNode, PlanGenerationInput, generate_plans};
use router_retrieval::{Bm25Index, MetadataEnvelopeV3};
use router_types::*;
use signed_fixture::Fixture;
use std::collections::BTreeSet;

fn selected(context: &router_policy::ValidatedPhaseContext, f: &Fixture) -> String {
    let receipt = f.router.route(context).unwrap();
    f.router
        .validate_receipt(context, &receipt)
        .unwrap()
        .selection()
        .candidate
        .id
        .clone()
}
#[test]
fn signed_projection_routes_without_loading_any_asset_body() {
    let mut f = Fixture::new();
    f.select_optional_assets();
    f.activate(100);
    let context = f.context(100).unwrap();
    assert_eq!(selected(&context, &f), "primary");
    let receipt = f.router.route(&context).unwrap();
    assert_eq!(receipt.schema_version, 5);
    assert!(!receipt.capability_evidence.is_empty());
    let proof = f.router.validate_receipt(&context, &receipt).unwrap();
    let kinds: BTreeSet<_> = proof
        .selection()
        .assets
        .iter()
        .filter(|asset| asset.authority == "signed_catalog_store_v1")
        .map(|asset| asset.kind.as_str())
        .collect();
    assert_eq!(
        kinds,
        BTreeSet::from([
            "agent", "host", "model", "preset", "prompt", "skill", "tool"
        ])
    );
    assert!(context.has_signed_catalog());
    assert_eq!(context.signed_prompt_id("primary"), Some("fixture-prompt"));
    assert_eq!(
        context.signed_plan().unwrap().preset,
        WorkflowPreset::PlanExecuteVerify
    );
    // The signed body references have no filesystem roots and do not exist.
    assert!(!f.temp.path().join("agents/fixture.md").exists());
}
#[test]
fn better_candidate_is_excluded_before_scoring_by_signed_mutation_ceiling() {
    let mut f = Fixture::new();
    f.request.candidates[0]
        .required_mutations
        .insert(Mutation::Network);
    f.entry(Kind::Model, "fixture-best")
        .restrictions
        .allowed_mutations
        .clear();
    f.activate(100);
    let context = f.context(100).unwrap();
    assert_eq!(selected(&context, &f), "secondary");
    assert!(
        f.router
            .route(&context)
            .unwrap()
            .exclusions
            .iter()
            .any(|row| row.candidate_id == "primary")
    );
    let wire = serde_json::to_string(&f.router.route(&context).unwrap()).unwrap();
    assert!(wire.contains("signed.mutation.forbidden"));
}
#[test]
fn every_selected_family_preserves_mutation_sandbox_and_sensitivity_ceilings() {
    for (kind, id) in [
        (Kind::Model, "fixture-best"),
        (Kind::Agent, "fixture-agent"),
        (Kind::Skill, "fixture-skill"),
        (Kind::Tool, "fixture-tool"),
        (Kind::Prompt, "fixture-prompt"),
        (Kind::Host, "fixture-host"),
    ] {
        let mut f = Fixture::new();
        f.select_optional_assets();
        f.request.candidates[0]
            .required_mutations
            .insert(Mutation::Network);
        f.entry(kind, id).restrictions.allowed_mutations.clear();
        f.activate(100);
        let context = f.context(100).unwrap();
        assert!(
            f.router
                .route(&context)
                .unwrap()
                .exclusions
                .iter()
                .any(|row| row.candidate_id == "primary"),
            "{kind:?}"
        );
        assert_eq!(selected(&context, &f), "secondary");
    }
    let mut f = Fixture::new();
    f.entry(Kind::Preset, "fixture-preset")
        .restrictions
        .allowed_mutations
        .clear();
    f.activate(100);
    assert!(f.context(100).is_err()); // Preset would silently narrow the task.
    for sensitivity in [false, true] {
        let mut f = Fixture::new();
        if sensitivity {
            f.request.task.sensitivity = DataSensitivity::Internal;
        } else {
            f.request.candidates[0].sandbox = PhaseSandbox::WorkspaceWrite;
            f.entry(Kind::Model, "fixture-best")
                .restrictions
                .allowed_sandboxes = BTreeSet::from([PhaseSandbox::ReadOnly]);
        }
        f.activate(100);
        match f.context(100) {
            Ok(context) => assert!(
                f.router
                    .route(&context)
                    .unwrap()
                    .exclusions
                    .iter()
                    .any(|row| row.candidate_id == "primary")
            ),
            Err(_) => assert!(sensitivity),
        }
    }
}
#[test]
fn signed_requirements_still_need_observed_capability_and_parent_permission() {
    for unknown_capability in [false, true] {
        let mut f = Fixture::new();
        f.entry(Kind::Model, "fixture-best")
            .requirements
            .mutations
            .insert(Mutation::Network);
        if unknown_capability {
            f.observation
                .capabilities
                .get_mut(&Capability::Network)
                .unwrap()
                .support = CapabilitySupport::Unknown;
            f.observation
                .capabilities
                .get_mut(&Capability::Network)
                .unwrap()
                .source_ids
                .clear();
            f.observation.host.capabilities.remove(&Capability::Network);
        } else {
            f.request
                .permissions
                .insert(PhasePermission::Network, CapabilitySupport::Unknown);
        }
        f.activate(100);
        let context = f.context(100).unwrap();
        assert_eq!(selected(&context, &f), "secondary");
        assert!(
            f.router
                .route(&context)
                .unwrap()
                .exclusions
                .iter()
                .any(|row| row.candidate_id == "primary")
        );
    }
}
#[test]
fn exact_native_host_model_prompt_and_parent_registry_are_required() {
    for case in 0..6 {
        let mut f = Fixture::new();
        match case {
            0 => f.observation.evidence[0].observed_version = None,
            1 => f.observation.evidence[0].observed_version = Some("other-version".into()),
            2 => {
                if let SignedAssetPayload::Host(host) =
                    &mut f.entry(Kind::Host, "fixture-host").payload
                {
                    host.compatible_models
                        .remove(&ModelId::parse("fixture-best").unwrap());
                }
            }
            3 => {
                if let SignedAssetPayload::Prompt(prompt) =
                    &mut f.entry(Kind::Prompt, "fixture-prompt").payload
                {
                    prompt
                        .compatible_models
                        .remove(&ModelId::parse("fixture-best").unwrap());
                }
            }
            4 => {
                f.select_optional_assets();
                f.request.registry.assets[0].content_sha256 = "f".repeat(64);
            }
            5 => {
                f.request.candidates[0].tool_policy = PhaseToolPolicy::NativeHost;
                f.request.permissions.insert(
                    PhasePermission::NativeHostTools,
                    CapabilitySupport::Supported,
                );
            }
            _ => unreachable!(),
        }
        f.activate(100);
        if case <= 1 {
            assert!(f.context(100).is_err());
        } else {
            let context = f.context(100).unwrap();
            assert!(
                f.router
                    .route(&context)
                    .unwrap()
                    .exclusions
                    .iter()
                    .any(|row| row.candidate_id == "primary"),
                "case {case}"
            );
            assert_eq!(selected(&context, &f), "secondary");
        }
    }
}
#[test]
fn rehashed_metadata_and_invalid_scope_never_become_signed_authority() {
    let mut f = Fixture::new();
    let head = f.activate(100);
    let guard = f
        .store
        .acquire_current(&head.head_hash, &f.roots, 100)
        .unwrap();
    let envelope = guard
        .catalog()
        .retrieval(&guard.access(&f.roots, 100).unwrap())
        .unwrap();
    drop(guard);
    let mut metadata = envelope.metadata;
    metadata.assets[0].description = "Forged metadata with a fresh matching local hash".into();
    let index = Bm25Index::build_v3(
        MetadataEnvelopeV3::new(metadata, envelope.signals, &envelope.catalog_content_sha256)
            .unwrap(),
    )
    .unwrap();
    assert!(f.context_with_index(&index, 100).is_err());
    for scope in [
        vec!["../outside".into()],
        vec!["different".into()],
        vec!["src".into(), "src".into()],
    ] {
        f.inputs.execution_scope.scope = scope;
        assert!(f.context(100).is_err());
    }
}
#[test]
fn rollback_aba_roots_and_fallback_bind_the_full_current_authority() {
    let mut f = Fixture::new();
    let a = f.activate(100);
    let first = f.context(100).unwrap();
    let receipt = f.router.route(&first).unwrap();
    f.manifest.version = "B".into();
    f.activate(101);
    f.manifest.version = "fixtures-v1".into();
    let again = f.activate(102);
    let last = f.context(102).unwrap();
    assert_eq!(a.binding_hash, again.binding_hash);
    assert_ne!(first.context_hash(), last.context_hash());
    assert_ne!(first.pool_hash(), last.pool_hash());
    assert_ne!(f.router.route(&last).unwrap(), receipt);
    assert!(f.router.validate_receipt(&last, &receipt).is_err());
    let fallback = f
        .router
        .fallback(&last, &BTreeSet::from(["primary".into()]))
        .unwrap();
    assert_eq!(fallback.schema_version, 4);
    assert_eq!(fallback.context_hash, last.context_hash());
    assert_eq!(
        f.router
            .validate_receipt(&last, &fallback)
            .unwrap()
            .selection()
            .candidate
            .id,
        "secondary"
    );
    let mut grant = signed_fixture::grant();
    grant.trust_ceiling = SkillTrust::TrustedLocal;
    f.roots = TrustedCatalogPublishers::new([grant]).unwrap();
    assert!(
        f.store
            .acquire_current(&again.head_hash, &f.roots, 103)
            .is_err()
    );
    f.activate(103);
    let changed = f.context(103).unwrap();
    assert_ne!(
        last.signed_catalog_authority_hash(),
        changed.signed_catalog_authority_hash()
    );
    assert_ne!(last.context_hash(), changed.context_hash());
}
#[test]
fn signed_receipt_cannot_be_reinterpreted_as_legacy_and_generation_refuses_external_plan() {
    let f = Fixture::new();
    let head = f.activate(100);
    let context = f.context(100).unwrap();
    let receipt = f.router.route(&context).unwrap();
    let guard = f
        .store
        .acquire_current(&head.head_hash, &f.roots, 100)
        .unwrap();
    let catalog = guard
        .catalog()
        .catalog(&guard.access(&f.roots, 100).unwrap())
        .unwrap();
    let legacy = f
        .router
        .context(f.request.clone(), &f.snapshot(), &catalog)
        .unwrap();
    assert!(!legacy.has_signed_catalog());
    assert!(f.router.validate_receipt(&legacy, &receipt).is_err());
    let external = router_workflow::build_plan(
        &f.request.task,
        WorkflowPreset::DirectSafe,
        router_workflow::PlanLimits::default(),
    )
    .unwrap();
    assert_ne!(external.plan_id, context.signed_plan().unwrap().plan_id);
    let contract = WorkflowExecutionContract {
        schema_version: 1,
        instance_id: "untrusted-external".into(),
        plan_id: external.plan_id.clone(),
        workspace: "/synthetic/workspace".into(),
        source_state: "a".repeat(40),
        nodes: Default::default(),
        contract_sha256: String::new(),
    };
    let nodes = [GenerationNode::from_context("execute", &f.router, &context)];
    let policy = PlanGenerationPolicy::default();
    let input = PlanGenerationInput {
        plan: &external,
        execution: &contract,
        nodes: &nodes,
        compatibility: &[],
        policy: &policy,
        now_unix_seconds: 100,
    };
    assert!(matches!(
        generate_plans(&input),
        Err(GenerationError::Invalid(
            "signed catalog plan generation unavailable"
        ))
    ));
}

#[path = "support/asset_fixture.rs"]
mod asset_fixture;
#[test]
fn extended_features_cannot_bypass_signed_model_capability_ceiling() {
    let mut f = Fixture::new();
    f.request
        .candidates
        .iter_mut()
        .for_each(|candidate| candidate.estimated_tokens = 900);
    let entry = f.entry(Kind::Model, "fixture-best");
    entry.capabilities.remove(&Capability::Vision);
    if let SignedAssetPayload::Model(model) = &mut entry.payload {
        model.capabilities.remove(&Capability::Vision);
    }
    let head = f.activate(100);
    let guard = f
        .store
        .acquire_current(&head.head_hash, &f.roots, 100)
        .unwrap();
    let access = guard.access(&f.roots, 100).unwrap();
    let catalog = guard.catalog().catalog(&access).unwrap();
    let index = f.index(100);
    let mut assets = asset_fixture::inputs(
        &f.request,
        &f.snapshot(),
        &catalog,
        f.inputs.execution_scope.clone(),
        &Default::default(),
        512,
    );
    let primary = assets.requests.get_mut("primary").unwrap();
    primary.required_features.insert(AssetFeature::ImageInput);
    primary.required_capabilities.insert(Capability::Vision);
    let context = f
        .router
        .context_with_signed_catalog(
            f.request.clone(),
            &f.snapshot(),
            &guard,
            &f.roots,
            f.inputs.clone(),
            Some(assets),
            &index,
            100,
        )
        .unwrap();
    assert_eq!(selected(&context, &f), "secondary");
    assert!(
        f.router
            .route(&context)
            .unwrap()
            .exclusions
            .iter()
            .any(|row| matches!(
                row.code.as_str(),
                "signed.model.capability" | "asset_gate.capability.unknown_or_denied"
            )),
        "{:?}",
        f.router.route(&context).unwrap().exclusions
    );
}
#[test]
fn extended_skill_body_and_late_mutations_remain_bound_to_signed_assets() {
    for case in 0..3 {
        let mut f = Fixture::new();
        let mut grant = signed_fixture::grant();
        grant.trust_ceiling = SkillTrust::TrustedLocal;
        f.roots = TrustedCatalogPublishers::new([grant]).unwrap();
        f.request
            .candidates
            .iter_mut()
            .for_each(|candidate| candidate.estimated_tokens = 900);
        f.request.candidates[0]
            .skills
            .insert(SkillId::parse("fixture-skill").unwrap());
        if case == 2 {
            f.entry(Kind::Model, "fixture-best")
                .restrictions
                .allowed_mutations
                .clear();
        }
        let head = f.activate(100);
        let guard = f
            .store
            .acquire_current(&head.head_hash, &f.roots, 100)
            .unwrap();
        let catalog = guard
            .catalog()
            .catalog(&guard.access(&f.roots, 100).unwrap())
            .unwrap();
        let body = if case == 1 {
            "different instructions locally approved"
        } else {
            "inspect parser body"
        };
        let bodies = std::collections::BTreeMap::from([(
            SkillId::parse("fixture-skill").unwrap(),
            body.into(),
        )]);
        let mut assets = asset_fixture::inputs(
            &f.request,
            &f.snapshot(),
            &catalog,
            f.inputs.execution_scope.clone(),
            &bodies,
            512,
        );
        let mut contracts = assets.contracts.document().clone();
        let entry = f
            .manifest
            .assets
            .iter()
            .find(|entry| entry.id == "fixture-skill")
            .unwrap();
        contracts.skills[0].version = entry.version.clone();
        contracts.skills[0].provenance = entry.provenance.clone();
        contracts.skills[0].license_expression = entry.license_expression.clone();
        if case == 2 {
            contracts.skills[0]
                .required_mutations
                .insert(Mutation::Network);
        }
        let doc = router_asset_contracts::seal_contracts(contracts, &catalog).unwrap();
        assets.contracts = router_asset_contracts::ValidatedContracts::from_json(
            &serde_json::to_vec(&doc).unwrap(),
            &catalog,
            &doc.content_hash,
        )
        .unwrap();
        if case == 2 {
            let primary = assets.requests.get_mut("primary").unwrap();
            primary.required_mutations.insert(Mutation::Network);
            primary.required_capabilities.insert(Capability::Network);
        }
        let context = f
            .router
            .context_with_signed_catalog(
                f.request.clone(),
                &f.snapshot(),
                &guard,
                &f.roots,
                f.inputs.clone(),
                Some(assets),
                &f.index(100),
                100,
            )
            .unwrap();
        if case == 0 {
            assert_eq!(selected(&context, &f), "primary");
        } else {
            assert_eq!(selected(&context, &f), "secondary");
            let code = if case == 1 {
                "signed.skill.contract_changed"
            } else {
                "signed.mutation.forbidden"
            };
            assert!(
                f.router
                    .route(&context)
                    .unwrap()
                    .exclusions
                    .iter()
                    .any(|row| row.code == code),
                "case {case}"
            );
        }
    }
}
#[test]
fn prompt_pool_tools_context_budget_and_conflicting_versions_fail_closed() {
    for case in 0..7 {
        let mut f = Fixture::new();
        match case {
            0 => {
                f.inputs.prompt_ids.remove("primary");
            }
            1 => {
                f.inputs
                    .prompt_ids
                    .insert("primary".into(), "absent".into());
            }
            2 => {
                let entry = f.entry(Kind::Model, "fixture-best");
                entry.requirements.tools.insert("fixture-tool".into());
                entry.signals.as_mut().unwrap().required_tools = router_retrieval::Signal::Unknown;
            }
            3 => {
                f.entry(Kind::Model, "fixture-best").context_cost_estimate = 101;
            }
            4 => {
                if let SignedAssetPayload::Preset(preset) =
                    &mut f.entry(Kind::Preset, "fixture-preset").payload
                {
                    preset.maximum_budget.max_tokens = 500;
                }
            }
            5 => {
                let mut evidence = f.observation.evidence[0].clone();
                evidence.id = "conflicting-native-version".into();
                evidence.observed_version = Some("other-version".into());
                f.observation.evidence.push(evidence);
            }
            6 => {
                f.select_optional_assets();
                f.request.registry.assets[0].permission = CapabilitySupport::Unknown;
            }
            _ => unreachable!(),
        }
        f.activate(100);
        if [0, 4, 5].contains(&case) {
            assert!(f.context(100).is_err(), "case {case}");
        } else {
            let context = f.context(100).unwrap();
            assert_eq!(selected(&context, &f), "secondary", "case {case}");
        }
    }
}
