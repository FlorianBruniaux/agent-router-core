//! Synthetic publishers and keys only; no production roots or human approval.
#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use ed25519_dalek::{Signer, SigningKey};
use router_adapter_api::{HostObservation, SnapshotValidation, content_digest};
use router_catalog::*;
use router_retrieval::{Bm25Index, ContextSearchQuery, SearchQuery, SignalProvenance};
use router_types::*;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[13; 32])
}
fn host() -> AssetHostBinding {
    AssetHostBinding {
        harness: HarnessId::parse("codex").unwrap(),
        version: "1.2.3".into(),
    }
}
fn provenance() -> SignalProvenance {
    SignalProvenance {
        source_id: "synthetic-signed-fixture".into(),
        source_version: "1".into(),
        source_sha256: "a".repeat(64),
        observed_at_unix_seconds: 100,
    }
}
fn grant() -> CatalogPublisherGrant {
    CatalogPublisherGrant {
        key_id: "fixture-publisher".into(),
        public_key: signer().verifying_key().to_bytes(),
        catalog_ids: BTreeSet::from(["fixture-catalog".into()]),
        allowed_kinds: BTreeSet::from([
            CatalogAssetKind::Model,
            CatalogAssetKind::Agent,
            CatalogAssetKind::Skill,
            CatalogAssetKind::Prompt,
            CatalogAssetKind::Tool,
            CatalogAssetKind::Host,
            CatalogAssetKind::Preset,
        ]),
        allowed_licenses: BTreeSet::from(["MIT".into()]),
        trust_ceiling: SkillTrust::VerifiedThirdParty,
    }
}
fn roots() -> TrustedCatalogPublishers {
    TrustedCatalogPublishers::new([grant()]).unwrap()
}
fn all_mutations() -> BTreeSet<Mutation> {
    BTreeSet::from([
        Mutation::WorkspaceWrite,
        Mutation::Network,
        Mutation::ExecuteSkills,
        Mutation::Integrate,
    ])
}
fn entry(
    id: &str,
    kind: &str,
    definition: Value,
    body: Option<(&str, &[u8])>,
) -> SignedCatalogEntry {
    let searchable = kind != "host" && kind != "preset";
    let capabilities = if kind == "model" || kind == "host" {
        json!(["tools"])
    } else {
        json!([])
    };
    serde_json::from_value(json!({
        "schema_version":1,"id":id,"version":"1","provenance":{"source":"https://example.test/synthetic-catalog","revision":"fixture-revision","source_sha256":"a".repeat(64)},
        "license_expression":"MIT","authors":["Synthetic fixture publisher"],"valid_from_unix_seconds":100,"valid_until_unix_seconds":1000,"declared_trust":"builtin",
        "capabilities":capabilities,"requirements":{"capabilities":[],"mutations":[],"tools":[],"compatible_hosts":[host()]},
        "restrictions":{"allowed_mutations":if matches!(kind,"agent"|"tool") { all_mutations() } else { BTreeSet::new() },"allowed_sandboxes":["read_only"],"maximum_sensitivity":"public"},
        "context_cost_estimate":32,"deprecated_by":null,"payload_sha256":"","payload":{"kind":kind,"definition":definition},
        "search":if searchable {json!({"kind":kind,"id":id,"trust":"builtin","description":"inspect parser","body":body.map(|(path,bytes)|json!({"path":path,"sha256":content_digest(bytes)}))})} else {Value::Null},
        "signals":if searchable {json!({"asset":{"kind":kind,"id":id},"languages":{"status":"observed","value":["rust"],"provenance":provenance()},"required_tools":{"status":"observed","value":[],"provenance":provenance()},"history":{"status":"unknown"}})} else {Value::Null}
    })).unwrap()
}
fn fixture() -> (SignedCatalogManifest, Vec<u8>) {
    let prompt = router_workflow::seal_prompt(PromptTemplate {
        schema_version: 1,
        id: "fixture-prompt".into(),
        version: "1".into(),
        template: "Inspect ${topic}".into(),
        variables: BTreeMap::from([("topic".into(), PromptVariableType::Text)]),
        compatible_hosts: BTreeSet::from(["codex".into()]),
        compatible_models: BTreeSet::from([ModelId::parse("fixture-model-v1").unwrap()]),
        max_rendered_bytes: 1024,
        output_contract: "Plain text findings".into(),
        content_sha256: String::new(),
    })
    .unwrap();
    let prompt_bytes = serde_json::to_vec(&prompt).unwrap();
    let model = json!({"id":"fixture-model-v1","stages":["plan","execute","verify"],"efforts":["medium","high"],"capabilities":["tools"],"quality_micros":800000,"cost_micros":100,"latency_micros":100,"source":"https://example.test/synthetic-catalog"});
    let skill = json!({"id":"fixture-skill","description":"inspect parser","task_kinds":["explore"],"required_capabilities":[],"trust":"builtin"});
    let registered = |id: &str, kind: &str| json!({"id":id,"kind":kind,"content_sha256":content_digest(b"inspect parser body"),"trust":"builtin","license":"MIT","permission":"unknown","required_capabilities":[],"required_mutations":[],"allowed_sandboxes":["read_only"],"maximum_sensitivity":"public"});
    let prompt_definition = json!({"variables":prompt.variables,"compatible_hosts":prompt.compatible_hosts,"compatible_models":prompt.compatible_models,"max_rendered_bytes":prompt.max_rendered_bytes,"output_contract":prompt.output_contract});
    let assets = vec![
        entry("fixture-model-v1", "model", model, None),
        entry(
            "fixture-agent",
            "agent",
            registered("fixture-agent", "agent"),
            Some(("agents/fixture.md", b"inspect parser body")),
        ),
        entry(
            "fixture-skill",
            "skill",
            skill,
            Some(("skills/fixture.md", b"inspect parser body")),
        ),
        entry(
            "fixture-prompt",
            "prompt",
            prompt_definition,
            Some(("prompts/fixture.json", &prompt_bytes)),
        ),
        entry(
            "fixture-tool",
            "tool",
            registered("fixture-tool", "tool"),
            None,
        ),
        entry(
            "fixture-host",
            "host",
            json!({"harness":"codex","versions":["1.2.3"],"declared_capabilities":["tools"],"compatible_models":["fixture-model-v1"]}),
            None,
        ),
        entry(
            "fixture-preset",
            "preset",
            json!({"preset":"direct-safe","max_width":2,"max_depth":4,"max_nodes":8,"reserve_cost_microusd":1,"reserve_tokens":1,"reserve_elapsed_ms":1,"maximum_budget":{"max_cost_microusd":1000,"max_tokens":500,"max_elapsed_ms":500},"allowed_capabilities":["tools"],"minimum_risk":"medium"}),
            None,
        ),
    ];
    (
        seal_signed_manifest(SignedCatalogManifest {
            schema_version: 1,
            id: "fixture-catalog".into(),
            version: "fixtures-v1".into(),
            valid_from_unix_seconds: 100,
            valid_until_unix_seconds: 1000,
            assets,
            content_sha256: String::new(),
        })
        .unwrap(),
        prompt_bytes,
    )
}
fn signed(manifest: SignedCatalogManifest) -> SignedCatalogDocument {
    let manifest = seal_signed_manifest(manifest).unwrap();
    let signature =
        signer().sign(&catalog_signing_message("fixture-publisher", &manifest).unwrap());
    SignedCatalogDocument {
        schema_version: 3,
        manifest,
        signature: CatalogPublisherSignature {
            key_id: "fixture-publisher".into(),
            signature_hex: hex::encode(signature.to_bytes()),
        },
    }
}
fn verified(
    document: &SignedCatalogDocument,
    roots: &TrustedCatalogPublishers,
) -> ValidatedSignedCatalog {
    match ValidatedSignedCatalog::from_json(&document.canonical_json().unwrap(), roots, 110)
        .unwrap()
    {
        CatalogVerification::Verified(value) => value,
        _ => panic!("fixture should be verified"),
    }
}
fn access<'a>(
    catalog: &'a ValidatedSignedCatalog,
    roots: &'a TrustedCatalogPublishers,
    now: u64,
) -> CatalogAccess<'a> {
    CatalogAccess {
        publishers: roots,
        now_unix_seconds: now,
        expected_binding_hash: catalog.binding_hash(),
    }
}
fn task() -> NormalizedTask {
    serde_json::from_value(
        serde_json::from_str::<Value>(include_str!(
            "../../../fixtures/examples/phase-request.json"
        ))
        .unwrap()["task"]
            .clone(),
    )
    .unwrap()
}

#[test]
fn all_seven_families_feed_real_catalog_retrieval_registry_and_plan_without_reading_bodies() {
    let (manifest, prompt_bytes) = fixture();
    let roots = roots();
    let validated = verified(&signed(manifest), &roots);
    let access = access(&validated, &roots, 110);
    let catalog = validated.catalog(&access).unwrap();
    assert_eq!(catalog.models().count(), 1);
    assert_eq!(catalog.skills().count(), 1);
    assert_eq!(
        catalog
            .skill(&SkillId::parse("fixture-skill").unwrap())
            .unwrap()
            .trust,
        SkillTrust::VerifiedThirdParty
    );
    let metadata = validated.retrieval(&access).unwrap();
    assert_eq!(metadata.metadata.assets.len(), 5);
    assert_eq!(
        metadata.catalog_content_sha256,
        catalog.content_hash().unwrap()
    );
    let index = Bm25Index::build_v3(metadata).unwrap();
    let mut query = ContextSearchQuery::new(SearchQuery::new("parser"), provenance(), 110);
    query.languages = vec!["rust".into()];
    for result in index
        .search_families(&query, &catalog.content_hash().unwrap())
        .unwrap()
    {
        assert!(result.selected.is_some());
    }
    let registry = validated
        .phase_registry(&access, &host(), &BTreeMap::new())
        .unwrap();
    assert_eq!(registry.assets.len(), 2);
    assert!(
        registry
            .assets
            .iter()
            .all(|a| a.permission == CapabilitySupport::Unknown)
    );
    let permissions = BTreeMap::from([(
        SignedAssetKey {
            kind: CatalogAssetKind::Agent,
            id: "fixture-agent".into(),
        },
        CapabilitySupport::Supported,
    )]);
    assert_eq!(
        validated
            .phase_registry(&access, &host(), &permissions)
            .unwrap()
            .assets[0]
            .permission,
        CapabilitySupport::Supported
    );
    assert_eq!(
        validated.host("fixture-host", &access).unwrap().versions,
        BTreeSet::from(["1.2.3".into()])
    );
    let source = task();
    let plan = validated
        .build_plan("fixture-preset", &source, &host(), &access)
        .unwrap();
    router_workflow::validate_plan(plan.plan()).unwrap();
    assert!(plan.plan().task.allowed_mutations.is_empty());
    assert_eq!(plan.plan().task.risk, RiskLevel::Medium);
    assert_eq!(plan.plan().task.budget.max_tokens, 500);
    assert_eq!(plan.catalog_hash(), catalog.content_hash().unwrap());
    assert_eq!(plan.content_hash().len(), 64);
    let prompt = validated
        .validate_prompt("fixture-prompt", &prompt_bytes, &access)
        .unwrap();
    assert_eq!(
        router_workflow::render_prompt(
            &prompt,
            "codex",
            &ModelId::parse("fixture-model-v1").unwrap(),
            &BTreeMap::from([("topic".into(), PromptValue::Text("Rust".into()))])
        )
        .unwrap(),
        "Inspect Rust"
    );
    let config = validated.generation_config(&access).unwrap();
    assert_eq!(config.registry.assets.len(), 4);
    let mut observation: HostObservation = serde_json::from_str(include_str!(
        "../../../fixtures/examples/phase-snapshot.json"
    ))
    .unwrap();
    let model = ModelId::parse("fixture-model-v1").unwrap();
    observation.host.supported_models = BTreeSet::from([model.clone()]);
    observation.host.supported_efforts = BTreeMap::from([(
        model,
        BTreeSet::from([EffortLevel::Medium, EffortLevel::High]),
    )]);
    let snapshot = fixture_proofs::from_observation(
        observation.seal().unwrap(),
        SnapshotValidation {
            now_unix_seconds: 110,
            max_age_seconds: 100,
        },
    )
    .unwrap();
    assert_eq!(
        GeneratedCatalog::generate(&snapshot, &catalog, &config)
            .unwrap()
            .catalog()
            .models()
            .count(),
        1
    );
}
#[test]
fn unknown_key_quarantines_and_a_reissued_hash_cannot_forge_the_publisher() {
    let (manifest, _) = fixture();
    let document = signed(manifest);
    let empty = TrustedCatalogPublishers::new([]).unwrap();
    let CatalogVerification::Quarantined(value) = document.verify(&empty, 110).unwrap() else {
        panic!("unknown key")
    };
    assert_eq!(value.trust, SkillTrust::Untrusted);
    assert_eq!(value.asset_count, 7);
    let mut forged = document.clone();
    forged.manifest.assets[0].authors.push("attacker".into());
    forged.manifest = seal_signed_manifest(forged.manifest).unwrap();
    assert!(matches!(
        forged.verify(&roots(), 110),
        Err(SignedCatalogError::Signature)
    ));
    let mut forged = document;
    forged.signature.signature_hex = "0".repeat(128);
    assert!(matches!(
        forged.verify(&roots(), 110),
        Err(SignedCatalogError::Signature)
    ));
}
#[test]
fn all_active_projections_recheck_time_roots_and_external_expected_binding() {
    let (manifest, body) = fixture();
    let roots = roots();
    let document = signed(manifest);
    let value = verified(&document, &roots);
    for now in [99, 1000, u64::MAX] {
        assert!(matches!(
            document.verify(&roots, now),
            Err(SignedCatalogError::Expired)
        ));
    }
    for now in [100, 999] {
        assert!(matches!(
            document.verify(&roots, now).unwrap(),
            CatalogVerification::Verified(_)
        ));
    }
    let expired = access(&value, &roots, 1000);
    assert!(value.catalog(&expired).is_err());
    assert!(value.retrieval(&expired).is_err());
    assert!(value.generation_config(&expired).is_err());
    assert!(
        value
            .phase_registry(&expired, &host(), &BTreeMap::new())
            .is_err()
    );
    assert!(value.host("fixture-host", &expired).is_err());
    assert!(value.preset("fixture-preset", &expired).is_err());
    assert!(
        value
            .validate_prompt("fixture-prompt", &body, &expired)
            .is_err()
    );
    assert!(
        value
            .build_plan("fixture-preset", &task(), &host(), &expired)
            .is_err()
    );
    let empty = TrustedCatalogPublishers::new([]).unwrap();
    assert!(matches!(
        value.catalog(&access(&value, &empty, 110)),
        Err(SignedCatalogError::Authority)
    ));
    let wrong = CatalogAccess {
        publishers: &roots,
        now_unix_seconds: 110,
        expected_binding_hash: &"0".repeat(64),
    };
    let key = SignedAssetKey {
        kind: CatalogAssetKind::Prompt,
        id: "fixture-prompt".into(),
    };
    assert!(matches!(
        value.load_selected_body(&key, std::path::Path::new("/nonexistent"), &wrong),
        Err(SignedCatalogError::Stale)
    ));
}
#[test]
fn current_grant_scope_license_key_bytes_and_trust_ceiling_are_bound() {
    let (manifest, _) = fixture();
    let document = signed(manifest);
    let original = roots();
    let value = verified(&document, &original);
    for change in 0..4 {
        let mut grant = grant();
        match change {
            0 => grant.allowed_licenses = BTreeSet::from(["Apache-2.0".into()]),
            1 => grant.allowed_kinds = BTreeSet::from([CatalogAssetKind::Skill]),
            2 => grant.catalog_ids = BTreeSet::from(["other".into()]),
            _ => grant.public_key = SigningKey::from_bytes(&[14; 32]).verifying_key().to_bytes(),
        };
        let changed = TrustedCatalogPublishers::new([grant]).unwrap();
        assert!(document.verify(&changed, 110).is_err());
        assert!(value.catalog(&access(&value, &changed, 110)).is_err());
    }
    let mut broader = grant();
    broader.trust_ceiling = SkillTrust::TrustedLocal;
    let changed = TrustedCatalogPublishers::new([broader]).unwrap();
    let refreshed = verified(&document, &changed);
    assert_ne!(refreshed.binding_hash(), value.binding_hash());
    assert_ne!(
        refreshed
            .catalog(&access(&refreshed, &changed, 110))
            .unwrap()
            .content_hash()
            .unwrap(),
        value
            .catalog(&access(&value, &original, 110))
            .unwrap()
            .content_hash()
            .unwrap()
    );
    let mut weak = grant();
    weak.public_key = [0; 32];
    assert!(TrustedCatalogPublishers::new([weak]).is_err());
    assert!(TrustedCatalogPublishers::new([grant(), grant()]).is_err());
}
#[test]
fn removal_and_metadata_replacement_same_version_invalidate_catalog_index_and_plan_binding() {
    let (manifest, _) = fixture();
    let roots = roots();
    let first = verified(&signed(manifest.clone()), &roots);
    let original = access(&first, &roots, 110);
    let catalog = first.catalog(&original).unwrap();
    let index = Bm25Index::build_v3(first.retrieval(&original).unwrap()).unwrap();
    let plan = first
        .build_plan("fixture-preset", &task(), &host(), &original)
        .unwrap();
    for change in 0..3 {
        let mut next = manifest.clone();
        match change {
            0 => next
                .assets
                .retain(|a| a.payload.kind() != CatalogAssetKind::Tool),
            1 => next
                .assets
                .iter_mut()
                .find(|e| e.payload.kind() == CatalogAssetKind::Host)
                .unwrap()
                .authors
                .push("Second declared author".into()),
            _ => next
                .assets
                .iter_mut()
                .find(|e| e.payload.kind() == CatalogAssetKind::Skill)
                .unwrap()
                .search
                .as_mut()
                .unwrap()
                .description
                .push_str(" updated"),
        };
        let updated = verified(&signed(next), &roots);
        let current = access(&updated, &roots, 110);
        let next_catalog = updated.catalog(&current).unwrap();
        assert_ne!(
            catalog.content_hash().unwrap(),
            next_catalog.content_hash().unwrap()
        );
        assert!(
            index
                .validate_catalog_hash(&next_catalog.content_hash().unwrap())
                .is_err()
        );
        assert_ne!(
            index.index_hash(),
            Bm25Index::build_v3(updated.retrieval(&current).unwrap())
                .unwrap()
                .index_hash()
        );
        assert_ne!(
            plan.content_hash(),
            updated
                .build_plan("fixture-preset", &task(), &host(), &current)
                .unwrap()
                .content_hash()
        );
        assert!(matches!(
            first.catalog(&current),
            Err(SignedCatalogError::Stale)
        ));
    }
}
#[test]
fn canonical_order_is_stable_and_nested_unknown_fields_duplicates_and_bad_digests_fail() {
    let (manifest, _) = fixture();
    let original = signed(manifest.clone());
    let mut reordered = manifest;
    reordered.assets.reverse();
    assert_eq!(
        original.canonical_json().unwrap(),
        signed(reordered).canonical_json().unwrap()
    );
    let mut value = serde_json::to_value(&original).unwrap();
    value["manifest"]["assets"][0]["payload"]["definition"]["silent_permission"] = true.into();
    assert!(SignedCatalogDocument::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = serde_json::to_value(&original).unwrap();
    value["manifest"]["assets"][0]["payload_sha256"] = "f".repeat(64).into();
    assert!(SignedCatalogDocument::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    let text = String::from_utf8(original.canonical_json().unwrap()).unwrap();
    let duplicated = text.replacen(
        "\"schema_version\":3",
        "\"schema_version\":3,\"schema_version\":3",
        1,
    );
    assert!(SignedCatalogDocument::from_json(duplicated.as_bytes()).is_err());
    assert!(matches!(
        SignedCatalogDocument::from_json(&vec![b' '; MAX_SIGNED_CATALOG_BYTES + 1]),
        Err(SignedCatalogError::Limit)
    ));
}
#[test]
fn sealed_catalog_between_snapshot_and_catalog_bounds_parses() {
    // The JSON parser's default bound is 4 MiB; the catalog bound is 8 MiB.
    // Whitespace padding keeps the document semantically identical to the
    // sealed one, so only the size path differs from the small fixtures.
    let (manifest, _) = fixture();
    let sealed = signed(manifest);
    let canonical = sealed.canonical_json().unwrap();
    let mut padded = Vec::with_capacity(canonical.len() + 5 * 1024 * 1024 + 1);
    padded.push(canonical[0]);
    padded.resize(padded.len() + 5 * 1024 * 1024, b' ');
    padded.extend_from_slice(&canonical[1..]);
    assert!(padded.len() > 4 * 1024 * 1024 && padded.len() <= MAX_SIGNED_CATALOG_BYTES);
    let parsed = SignedCatalogDocument::from_json(&padded).unwrap();
    assert_eq!(parsed.canonical_json().unwrap(), canonical);
}
#[test]
fn unsafe_paths_publisher_permissions_expiry_and_cross_family_deprecation_are_refused() {
    for path in ["../escape", "/private/secret", "x/../file", "x\\file"] {
        let (mut manifest, _) = fixture();
        manifest
            .assets
            .iter_mut()
            .find(|e| e.payload.kind() == CatalogAssetKind::Skill)
            .unwrap()
            .search
            .as_mut()
            .unwrap()
            .body
            .as_mut()
            .unwrap()
            .path = path.into();
        assert!(seal_signed_manifest(manifest).is_err());
    }
    for change in 0..4 {
        let (mut manifest, _) = fixture();
        let entry = manifest
            .assets
            .iter_mut()
            .find(|e| e.payload.kind() == CatalogAssetKind::Agent)
            .unwrap();
        match change {
            0 => {
                let SignedAssetPayload::Agent(value) = &mut entry.payload else {
                    panic!()
                };
                value.permission = CapabilitySupport::Supported;
            }
            1 => entry.valid_until_unix_seconds = 1001,
            2 => {
                entry.deprecated_by = Some(SignedAssetKey {
                    kind: CatalogAssetKind::Skill,
                    id: "fixture-skill".into(),
                })
            }
            _ => entry.provenance.source = "https://user:secret@example.test/repo".into(),
        };
        assert!(seal_signed_manifest(manifest).is_err());
    }
}
#[test]
fn selected_body_and_prompt_require_exact_bytes_and_cannot_expand_parent_mutations() {
    let (manifest, body) = fixture();
    let roots = roots();
    let value = verified(&signed(manifest), &roots);
    let access = access(&value, &roots, 110);
    assert!(
        value
            .validate_prompt("fixture-prompt", b"changed", &access)
            .is_err()
    );
    assert!(
        value
            .validate_prompt(
                "fixture-prompt",
                &vec![b'x'; router_retrieval::MAX_BODY_BYTES + 1],
                &access
            )
            .is_err()
    );
    assert!(
        value
            .validate_prompt("fixture-agent", &body, &access)
            .is_err()
    );
    let mut task = task();
    task.kind = TaskKind::Implement;
    task.allowed_mutations.insert(Mutation::WorkspaceWrite);
    assert!(
        value
            .build_plan("fixture-preset", &task, &host(), &access)
            .is_err()
    );
    let mut other_host = host();
    other_host.version = "2".into();
    assert!(
        value
            .build_plan("fixture-preset", &task, &other_host, &access)
            .is_err()
    );
}

#[test]
fn deprecation_is_explicit_and_never_resolves_or_promotes_an_old_asset_silently() {
    let (mut manifest, _) = fixture();
    let mut replacement = manifest
        .assets
        .iter()
        .find(|e| e.payload.kind() == CatalogAssetKind::Tool)
        .unwrap()
        .clone();
    replacement.id = "replacement-tool".into();
    replacement.search.as_mut().unwrap().id = replacement.id.clone();
    replacement.signals.as_mut().unwrap().asset.id = replacement.id.clone();
    let SignedAssetPayload::Tool(tool) = &mut replacement.payload else {
        panic!()
    };
    tool.id = replacement.id.clone();
    let previous = manifest
        .assets
        .iter_mut()
        .find(|e| e.payload.kind() == CatalogAssetKind::Tool)
        .unwrap();
    previous.deprecated_by = Some(replacement.key());
    manifest.assets.push(replacement);
    let roots = roots();
    let value = verified(&signed(manifest.clone()), &roots);
    let access = access(&value, &roots, 110);
    let metadata = value.retrieval(&access).unwrap();
    assert_eq!(
        metadata
            .metadata
            .assets
            .iter()
            .find(|a| a.id == "fixture-tool")
            .unwrap()
            .trust,
        SkillTrust::Blocked
    );
    let config = value.generation_config(&access).unwrap();
    assert!(
        !config
            .registry
            .assets
            .iter()
            .any(|a| a.id == "fixture-tool")
    );
    assert!(
        config
            .registry
            .assets
            .iter()
            .any(|a| a.id == "replacement-tool")
    );
    let registry = value
        .phase_registry(&access, &host(), &BTreeMap::new())
        .unwrap();
    for entry in config
        .registry
        .assets
        .iter()
        .filter(|a| matches!(a.kind, AssetKind::Agent | AssetKind::Tool))
    {
        assert_eq!(
            entry.content_sha256,
            registry
                .assets
                .iter()
                .find(|asset| asset.id == entry.id)
                .unwrap()
                .content_sha256
        );
    }
    manifest
        .assets
        .iter_mut()
        .find(|e| e.id == "replacement-tool")
        .unwrap()
        .deprecated_by = Some(SignedAssetKey {
        kind: CatalogAssetKind::Tool,
        id: "fixture-tool".into(),
    });
    assert!(seal_signed_manifest(manifest).is_err());
}

#[test]
fn host_and_model_references_are_validated_without_creating_availability() {
    let (mut manifest, _) = fixture();
    manifest
        .assets
        .retain(|entry| entry.payload.kind() != CatalogAssetKind::Host);
    assert!(seal_signed_manifest(manifest).is_err());
    let (mut manifest, _) = fixture();
    let SignedAssetPayload::Prompt(value) = &mut manifest
        .assets
        .iter_mut()
        .find(|e| e.payload.kind() == CatalogAssetKind::Prompt)
        .unwrap()
        .payload
    else {
        panic!()
    };
    value
        .compatible_models
        .insert(ModelId::parse("invented-model").unwrap());
    assert!(seal_signed_manifest(manifest).is_err());
}

#[test]
fn prompt_host_reference_must_resolve_to_a_pinned_harness_not_an_asset_id() {
    for invalid_host in ["invented-host", "fixture-host", "fixture-tool"] {
        let (mut manifest, _) = fixture();
        let prompt = manifest
            .assets
            .iter_mut()
            .find(|entry| entry.id == "fixture-prompt")
            .unwrap();
        assert_eq!(
            prompt.requirements.compatible_hosts,
            BTreeSet::from([host()])
        );
        let SignedAssetPayload::Prompt(definition) = &mut prompt.payload else {
            panic!()
        };
        definition.compatible_hosts = BTreeSet::from([invalid_host.into()]);
        assert!(
            matches!(
                seal_signed_manifest(manifest),
                Err(SignedCatalogError::Invalid)
            ),
            "unresolved harness accepted: {invalid_host}"
        );
    }
}

#[test]
fn prompt_payload_cannot_expand_its_signed_host_requirements() {
    let (mut manifest, _) = fixture();
    manifest.assets.push(entry("second-host-asset", "host", json!({"harness":"claude-code","versions":["1.2.3"],"declared_capabilities":["tools"],"compatible_models":["fixture-model-v1"]}), None));
    let prompt = manifest
        .assets
        .iter_mut()
        .find(|entry| entry.id == "fixture-prompt")
        .unwrap();
    let SignedAssetPayload::Prompt(definition) = &mut prompt.payload else {
        panic!()
    };
    definition.compatible_hosts.insert("claude-code".into());
    assert!(
        matches!(
            seal_signed_manifest(manifest),
            Err(SignedCatalogError::Invalid)
        ),
        "a declared host still requires an exact signed host/version pin"
    );
}

#[test]
fn prompt_may_narrow_pinned_harnesses_without_changing_any_version_or_restriction() {
    let (mut manifest, body) = fixture();
    manifest.assets.push(entry("second-host-asset", "host", json!({"harness":"claude-code","versions":["1.2.3"],"declared_capabilities":["tools"],"compatible_models":["fixture-model-v1"]}), None));
    let SignedAssetPayload::Host(definition) = &mut manifest
        .assets
        .iter_mut()
        .find(|entry| entry.id == "fixture-host")
        .unwrap()
        .payload
    else {
        panic!()
    };
    definition.versions.insert("1.2.4".into());
    let prompt = manifest
        .assets
        .iter_mut()
        .find(|entry| entry.id == "fixture-prompt")
        .unwrap();
    prompt.requirements.compatible_hosts.extend([
        AssetHostBinding {
            harness: HarnessId::parse("codex").unwrap(),
            version: "1.2.4".into(),
        },
        AssetHostBinding {
            harness: HarnessId::parse("claude-code").unwrap(),
            version: "1.2.3".into(),
        },
    ]);
    let requirements = prompt.requirements.clone();
    let restrictions = prompt.restrictions.clone();
    let sealed = seal_signed_manifest(manifest).unwrap();
    let prompt = sealed
        .assets
        .iter()
        .find(|entry| entry.id == "fixture-prompt")
        .unwrap();
    assert_eq!(prompt.requirements, requirements);
    assert_eq!(prompt.restrictions, restrictions);
    let SignedAssetPayload::Prompt(definition) = &prompt.payload else {
        panic!()
    };
    assert_eq!(
        definition.compatible_hosts,
        BTreeSet::from(["codex".into()])
    );
    let publishers = roots();
    let catalog = verified(&signed(sealed), &publishers);
    let template = catalog
        .validate_prompt("fixture-prompt", &body, &access(&catalog, &publishers, 110))
        .unwrap();
    assert_eq!(template.compatible_hosts, BTreeSet::from(["codex".into()]));
    assert!(
        router_workflow::render_prompt(
            &template,
            "claude-code",
            &ModelId::parse("fixture-model-v1").unwrap(),
            &BTreeMap::from([("topic".into(), PromptValue::Text("Rust".into()))])
        )
        .is_err()
    );
}

#[test]
fn prompt_harness_match_cannot_replace_a_missing_exact_version_pin() {
    let (mut manifest, _) = fixture();
    manifest
        .assets
        .iter_mut()
        .find(|entry| entry.id == "fixture-prompt")
        .unwrap()
        .requirements
        .compatible_hosts = BTreeSet::from([AssetHostBinding {
        harness: HarnessId::parse("codex").unwrap(),
        version: "9.9.9".into(),
    }]);
    assert!(matches!(
        seal_signed_manifest(manifest),
        Err(SignedCatalogError::Invalid)
    ));
}

#[test]
fn a_valid_body_hash_does_not_override_the_signed_prompt_contract() {
    let (mut manifest, original) = fixture();
    let mut changed: PromptTemplate = serde_json::from_slice(&original).unwrap();
    changed.max_rendered_bytes = 2048;
    changed = router_workflow::seal_prompt(changed).unwrap();
    let bytes = serde_json::to_vec(&changed).unwrap();
    manifest
        .assets
        .iter_mut()
        .find(|e| e.payload.kind() == CatalogAssetKind::Prompt)
        .unwrap()
        .search
        .as_mut()
        .unwrap()
        .body
        .as_mut()
        .unwrap()
        .sha256 = content_digest(&bytes);
    let roots = roots();
    let value = verified(&signed(manifest), &roots);
    assert!(
        value
            .validate_prompt("fixture-prompt", &bytes, &access(&value, &roots, 110))
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn selected_body_loader_is_read_only_bounded_and_rejects_links_and_replacements() {
    use std::{
        fs,
        os::unix::fs::symlink,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Root(PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let mut owned = None;
    for _ in 0..32 {
        let path = std::env::temp_dir().join(format!(
            "agent-router-signed-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                owned = Some(Root(path));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("fixture directory: {error}"),
        }
    }
    let root = owned.unwrap();
    fs::create_dir(root.0.join("prompts")).unwrap();
    let (manifest, bytes) = fixture();
    let roots = roots();
    let value = verified(&signed(manifest), &roots);
    let access = access(&value, &roots, 110);
    let path = root.0.join("prompts/fixture.json");
    fs::write(&path, &bytes).unwrap();
    let key = SignedAssetKey {
        kind: CatalogAssetKind::Prompt,
        id: "fixture-prompt".into(),
    };
    assert_eq!(
        value.load_selected_body(&key, &root.0, &access).unwrap(),
        bytes
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    fs::write(&path, b"changed").unwrap();
    assert!(value.load_selected_body(&key, &root.0, &access).is_err());
    fs::write(&path, vec![b'x'; router_retrieval::MAX_BODY_BYTES + 1]).unwrap();
    assert!(value.load_selected_body(&key, &root.0, &access).is_err());
    fs::remove_file(&path).unwrap();
    let target = root.0.join("target.json");
    fs::write(&target, &bytes).unwrap();
    symlink(&target, &path).unwrap();
    assert!(value.load_selected_body(&key, &root.0, &access).is_err());
    assert_eq!(fs::read(target).unwrap(), bytes);
}

#[test]
fn recomputed_index_hash_with_matching_catalog_hash_does_not_forge_signed_metadata() {
    let (manifest, _) = fixture();
    let roots = roots();
    let value = verified(&signed(manifest), &roots);
    let access = access(&value, &roots, 110);
    let metadata = value.retrieval(&access).unwrap();
    let index = Bm25Index::build_v3(metadata.clone()).unwrap();
    value.validate_retrieval(&index, &access).unwrap();
    let mut changed = metadata;
    changed.metadata.assets[0].description = "attacker ranking".into();
    let changed = router_retrieval::MetadataEnvelopeV3::new(
        changed.metadata,
        changed.signals,
        &changed.catalog_content_sha256,
    )
    .unwrap();
    let forged = Bm25Index::build_v3(changed).unwrap();
    assert_eq!(forged.catalog_hash(), index.catalog_hash());
    assert!(matches!(
        value.validate_retrieval(&forged, &access),
        Err(SignedCatalogError::Integrity)
    ));
}

#[test]
fn projections_never_drop_host_tool_or_sandbox_restrictions() {
    let (mut manifest, _) = fixture();
    let SignedAssetPayload::Host(definition) = &mut manifest
        .assets
        .iter_mut()
        .find(|entry| entry.payload.kind() == CatalogAssetKind::Host)
        .unwrap()
        .payload
    else {
        panic!()
    };
    definition.versions.insert("2".into());
    let roots = roots();
    let value = verified(&signed(manifest.clone()), &roots);
    let current = access(&value, &roots, 110);
    let mut other = host();
    other.version = "2".into();
    let permissions = BTreeMap::from([(
        SignedAssetKey {
            kind: CatalogAssetKind::Agent,
            id: "fixture-agent".into(),
        },
        CapabilitySupport::Supported,
    )]);
    assert!(
        value
            .phase_registry(&current, &other, &permissions)
            .unwrap()
            .assets
            .is_empty()
    );
    other.version = "not-declared".into();
    assert!(
        value
            .phase_registry(&current, &other, &permissions)
            .is_err()
    );

    let agent = manifest
        .assets
        .iter_mut()
        .find(|entry| entry.payload.kind() == CatalogAssetKind::Agent)
        .unwrap();
    agent.requirements.tools.insert("cargo".into());
    agent.signals.as_mut().unwrap().required_tools = router_retrieval::Signal::Observed {
        value: vec!["cargo".into()],
        provenance: provenance(),
    };
    let value = verified(&signed(manifest), &roots);
    assert!(matches!(
        value.phase_registry(&access(&value, &roots, 110), &host(), &permissions),
        Err(SignedCatalogError::Projection)
    ));

    let (mut manifest, _) = fixture();
    manifest
        .assets
        .iter_mut()
        .find(|entry| entry.payload.kind() == CatalogAssetKind::Preset)
        .unwrap()
        .restrictions
        .allowed_sandboxes = BTreeSet::from([PhaseSandbox::WorkspaceWrite]);
    let value = verified(&signed(manifest), &roots);
    assert!(matches!(
        value.build_plan(
            "fixture-preset",
            &task(),
            &host(),
            &access(&value, &roots, 110)
        ),
        Err(SignedCatalogError::Authority)
    ));
}

#[test]
fn duplicate_structured_set_members_and_signature_key_id_substitution_are_refused() {
    let (manifest, _) = fixture();
    let document = signed(manifest);
    let mut value = serde_json::to_value(&document).unwrap();
    let duplicate = value["manifest"]["assets"][0]["requirements"]["compatible_hosts"][0].clone();
    value["manifest"]["assets"][0]["requirements"]["compatible_hosts"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(SignedCatalogDocument::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut switched = document;
    switched.signature.key_id = "different-key-id".into();
    let mut grant = grant();
    grant.key_id = switched.signature.key_id.clone();
    let publishers = TrustedCatalogPublishers::new([grant]).unwrap();
    assert!(matches!(
        switched.verify(&publishers, 110),
        Err(SignedCatalogError::Signature)
    ));
}

#[test]
fn operational_registry_refuses_unrepresentable_mutation_ceilings_even_with_parent_permission() {
    let roots = roots();
    let permissions = BTreeMap::from([
        (
            SignedAssetKey {
                kind: CatalogAssetKind::Agent,
                id: "fixture-agent".into(),
            },
            CapabilitySupport::Supported,
        ),
        (
            SignedAssetKey {
                kind: CatalogAssetKind::Tool,
                id: "fixture-tool".into(),
            },
            CapabilitySupport::Supported,
        ),
    ]);
    for kind in [CatalogAssetKind::Agent, CatalogAssetKind::Tool] {
        for removed in all_mutations() {
            let (mut manifest, _) = fixture();
            manifest
                .assets
                .iter_mut()
                .find(|entry| entry.payload.kind() == kind)
                .unwrap()
                .restrictions
                .allowed_mutations
                .remove(&removed);
            let value = verified(&signed(manifest), &roots);
            assert!(
                matches!(
                    value.phase_registry(&access(&value, &roots, 110), &host(), &permissions),
                    Err(SignedCatalogError::Projection)
                ),
                "{kind:?}: omitted mutation ceiling {removed:?} must refuse the projection"
            );
        }
    }
    let (manifest, _) = fixture();
    let value = verified(&signed(manifest), &roots);
    let registry = value
        .phase_registry(&access(&value, &roots, 110), &host(), &permissions)
        .unwrap();
    assert_eq!(registry.assets.len(), 2);
    for asset in registry.assets {
        assert_eq!(asset.permission, CapabilitySupport::Supported);
        assert!(asset.required_mutations.is_empty());
        assert_eq!(
            asset.allowed_sandboxes,
            BTreeSet::from([PhaseSandbox::ReadOnly])
        );
        assert_eq!(asset.maximum_sensitivity, DataSensitivity::Public);
    }
}

fn seal_with_source(source: &str) -> bool {
    let (mut manifest, _) = fixture();
    let entry = manifest
        .assets
        .iter_mut()
        .find(|e| e.payload.kind() == CatalogAssetKind::Agent)
        .unwrap();
    entry.provenance.source = source.into();
    seal_signed_manifest(manifest).is_ok()
}
#[test]
fn provenance_source_accepts_only_public_locators_and_refuses_local_paths() {
    for accepted in [
        "https://host/path",
        "https://host:8443/path",
        "https://example.test/synthetic-catalog",
        "https://host",
        "https://host/",
        "https://host/x/",
        "https://Example.COM:65535/a/b_c~d.e-f",
        "https://h.example:1/x",
        "https://172.32.0.1/x",
        "https://8.8.8.8/x",
        "https://example.com./x",
        "fixture-registry",
        "builtin_policy.v1",
    ] {
        assert!(seal_with_source(accepted), "should accept {accepted}");
    }
    for refused in [
        "/etc/passwd",
        "../../srv/me/pack",
        "./pack",
        "..",
        ".",
        "Users/me/pack",
        "owner/repo",
        "file:///etc",
        "FILE:///etc",
        "File:///etc",
        "HTTP://host/path",
        "http://host/path",
        "HTTPS://host/path",
        "https:///x",
        "https://host/../x",
        "https://host/./x",
        "https://../x",
        "C:\\Data\\me",
        "C:/Data/me",
        "c:/x",
        "scheme:id",
        "~/pack",
        "https://user:secret@host/x",
        "https://host/x?q=1",
        "https://host/x#f",
        "https://host with space/x",
        "https://host/%2e%2e/x",
        "https://host/a b",
        "https://host/caf\u{e9}",
        "https://host/a\u{202e}b",
        "https://h\u{e9}st/x",
        "https://host//x",
        "https://host/x//y",
        "https://host//",
        "https://:",
        "https://:8443/x",
        "https://a:b:c",
        "https://...",
        "https://host:/x",
        "https://host:0/x",
        "https://host:65536/x",
        "https://host:123456/x",
        "https://host:+80/x",
        "https://localhost/x",
        "https://LOCALHOST:8443/x",
        "https://app.localhost/x",
        "https://printer.local/x",
        "https://127.0.0.1/x",
        "https://127.255.255.254/x",
        "https://0.0.0.0/x",
        "https://10.0.0.1/x",
        "https://172.16.0.1/x",
        "https://172.31.255.255/x",
        "https://192.168.1.1/x",
        "https://169.254.169.254/latest",
        "https://100.64.0.1/x",
        "https://2130706433/x",
        "https://0x7f.1/x",
        "https://127.1/x",
        "https://017700000001/x",
        "...",
        "-",
        "_x",
        "x.",
        ".x",
        "",
    ] {
        assert!(!seal_with_source(refused), "should refuse {refused:?}");
    }
}
