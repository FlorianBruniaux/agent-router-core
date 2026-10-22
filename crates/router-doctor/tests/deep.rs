#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use router_adapter_api::content_digest;
use router_catalog::Catalog;
use router_doctor::{DoctorError, diagnose_deep};
use router_retrieval::{
    AssetKind, AssetMetadata, BodyReference, MetadataDocument, MetadataEnvelope,
};
use router_types::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

const CATALOG: &[u8] = include_bytes!("../../router-catalog/tests/fixtures/generated-prior.json");

fn artifact(path: &str, kind: DoctorArtifactKind) -> DoctorArtifact {
    DoctorArtifact {
        id: path.into(),
        relative_path: path.into(),
        kind,
        expected_sha256: None,
        require_private: false,
    }
}
fn request(root: &Path, artifacts: Vec<DoctorArtifact>) -> DeepDoctorRequest {
    DeepDoctorRequest {
        schema_version: 1,
        base: DoctorRequest {
            schema_version: 1,
            root: root.canonicalize().unwrap().to_str().unwrap().into(),
            artifacts,
            max_snapshot_age_seconds: 100,
        },
        schemas: vec![],
        retrieval_bindings: vec![],
    }
}
fn has(report: &DeepDoctorReport, code: DeepDoctorCode) -> bool {
    report.checks.iter().any(|check| check.code == code)
}
fn assert_pass(report: &DeepDoctorReport, code: DeepDoctorCode) {
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.code == code && check.configuration == DiagnosticState::Pass)
    );
    assert!(
        report
            .checks
            .iter()
            .all(|check| check.runtime == DiagnosticState::Unknown)
    );
    assert_eq!(
        (
            report.base.network_requests,
            report.base.processes_launched,
            report.base.files_modified
        ),
        (0, 0, 0)
    );
}
fn schema_request(
    root: &Path,
    schema: DoctorSchema,
    value: &impl serde::Serialize,
) -> DeepDoctorRequest {
    fs::write(root.join("config.json"), serde_json::to_vec(value).unwrap()).unwrap();
    let mut request = request(
        root,
        vec![artifact(
            "config.json",
            DoctorArtifactKind::JsonConfiguration,
        )],
    );
    request.schemas.push(DoctorSchemaBinding {
        artifact_id: "config.json".into(),
        schema,
    });
    request
}

#[test]
fn component_validator_replaces_only_generic_schema_and_preserves_legacy_contract() {
    let temp = tempfile::tempdir().unwrap();
    let policy = PhasePolicy::default();
    let mut input = schema_request(temp.path(), DoctorSchema::PhasePolicy, &policy);
    let report = diagnose_deep(&input, 110).unwrap();
    assert_pass(&report, DeepDoctorCode::ComponentValidated);
    assert_ne!(report.overall, DiagnosticState::Fail);
    let output = serde_json::to_string(&report).unwrap();
    assert!(!output.contains("config.json"));
    assert!(!output.contains(&input.base.root));
    input.base.artifacts[0].expected_sha256 = Some("1".repeat(64));
    let report = diagnose_deep(&input, 110).unwrap();
    assert_eq!(report.overall, DiagnosticState::Fail);
    assert!(!has(&report, DeepDoctorCode::ComponentValidated));
}

#[test]
fn generic_configuration_remains_unknown_without_component_schema() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("config.json"),
        br#"{"schema_version":1,"anything":"not semantic proof"}"#,
    )
    .unwrap();
    let input = request(
        temp.path(),
        vec![artifact(
            "config.json",
            DoctorArtifactKind::JsonConfiguration,
        )],
    );
    let report = diagnose_deep(&input, 110).unwrap();
    assert!(has(&report, DeepDoctorCode::ComponentSchemaRequired));
    assert_eq!(report.overall, DiagnosticState::Unknown);
}

#[test]
fn typed_validation_rejects_unknown_duplicate_fields_and_invalid_policy_values() {
    let temp = tempfile::tempdir().unwrap();
    let input = schema_request(
        temp.path(),
        DoctorSchema::PhasePolicy,
        &PhasePolicy::default(),
    );
    let original = fs::read(temp.path().join("config.json")).unwrap();
    let mut unknown: serde_json::Value = serde_json::from_slice(&original).unwrap();
    unknown["unrecognized_permission"] = true.into();
    let mut invalid = unknown.clone();
    invalid
        .as_object_mut()
        .unwrap()
        .remove("unrecognized_permission");
    invalid["schema_version"] = 999.into();
    for bytes in [
        serde_json::to_vec(&unknown).unwrap(),
        serde_json::to_vec(&invalid).unwrap(),
        br#"{"schema_version":2,"schema_version":2}"#.to_vec(),
    ] {
        fs::write(temp.path().join("config.json"), bytes).unwrap();
        let report = diagnose_deep(&input, 110).unwrap();
        assert!(has(&report, DeepDoctorCode::SchemaInvalid));
        assert_eq!(report.overall, DiagnosticState::Fail);
    }
}

#[test]
fn prompt_seal_and_typed_variable_declarations_are_checked_without_render_or_execution() {
    let temp = tempfile::tempdir().unwrap();
    let prompt = router_workflow::seal_prompt(PromptTemplate {
        schema_version: 1,
        id: "private-prompt-id".into(),
        version: "1".into(),
        template: "SECRET_PROMPT ${task}".into(),
        variables: BTreeMap::from([("task".into(), PromptVariableType::Text)]),
        compatible_hosts: BTreeSet::from(["fixture-host".into()]),
        compatible_models: BTreeSet::from([ModelId::parse("fixture-model").unwrap()]),
        max_rendered_bytes: 1024,
        output_contract: "text".into(),
        content_sha256: String::new(),
    })
    .unwrap();
    let input = schema_request(temp.path(), DoctorSchema::PromptTemplate, &prompt);
    let report = diagnose_deep(&input, 110).unwrap();
    assert_pass(&report, DeepDoctorCode::ComponentValidated);
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("SECRET_PROMPT") && !json.contains("private-prompt-id"));
    let mut changed = prompt;
    changed.template.push_str(" changed");
    fs::write(
        temp.path().join("config.json"),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    assert!(has(
        &diagnose_deep(&input, 110).unwrap(),
        DeepDoctorCode::InputChanged
    ));
}

fn metadata(catalog: &Catalog) -> MetadataDocument {
    MetadataDocument {
        schema_version: "1".into(),
        catalog_version: catalog.version().into(),
        assets: vec![AssetMetadata {
            id: "fixture-skill".into(),
            kind: AssetKind::Skill,
            trust: SkillTrust::Builtin,
            task_kinds: vec![TaskKind::Implement],
            triggers: vec![],
            description: "fixture instructions".into(),
            examples: vec![],
            tags: vec![],
            paths: vec![],
            anti_triggers: vec![],
            body: Some(BodyReference {
                path: "skill.txt".into(),
                sha256: content_digest(b"BODY_SECRET_CANARY"),
            }),
        }],
    }
}
fn linked_request(root: &Path) -> (DeepDoctorRequest, Catalog, MetadataDocument) {
    let catalog = Catalog::from_json(CATALOG).unwrap();
    let metadata = metadata(&catalog);
    fs::write(root.join("catalog.json"), CATALOG).unwrap();
    fs::write(
        root.join("index.json"),
        MetadataEnvelope::new(metadata.clone(), &catalog.content_hash().unwrap())
            .unwrap()
            .canonical_json()
            .unwrap(),
    )
    .unwrap();
    fs::create_dir(root.join("bodies")).unwrap();
    fs::write(root.join("bodies/skill.txt"), b"BODY_SECRET_CANARY").unwrap();
    let mut input = request(
        root,
        vec![
            artifact("catalog.json", DoctorArtifactKind::Catalog),
            artifact("index.json", DoctorArtifactKind::RetrievalIndex),
        ],
    );
    input.retrieval_bindings.push(DoctorRetrievalBinding {
        index_artifact_id: "index.json".into(),
        catalog_artifact_id: "catalog.json".into(),
        body_root: Some("bodies".into()),
    });
    (input, catalog, metadata)
}

#[test]
fn catalog_index_body_binding_is_verified_read_only_and_redacted() {
    let temp = tempfile::tempdir().unwrap();
    let (input, _, _) = linked_request(temp.path());
    let report = diagnose_deep(&input, 110).unwrap();
    assert_pass(&report, DeepDoctorCode::CatalogBindingValidated);
    assert_pass(&report, DeepDoctorCode::AssetBodyValidated);
    assert_eq!(report.examined_body_count, 1);
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("BODY_SECRET_CANARY")
    );
    assert_eq!(
        fs::read(temp.path().join("bodies/skill.txt")).unwrap(),
        b"BODY_SECRET_CANARY"
    );
    fs::write(temp.path().join("bodies/skill.txt"), b"tampered").unwrap();
    let report = diagnose_deep(&input, 110).unwrap();
    assert!(has(&report, DeepDoctorCode::AssetBodyMismatch));
    assert_eq!(report.overall, DiagnosticState::Fail);
}

#[test]
fn stale_catalog_hash_is_rejected_before_body_io_even_when_version_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let (input, _, _) = linked_request(temp.path());
    let mut changed: serde_json::Value = serde_json::from_slice(CATALOG).unwrap();
    changed["models"][0]["cost_micros"] = 200000.into();
    fs::write(
        temp.path().join("catalog.json"),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    fs::remove_file(temp.path().join("bodies/skill.txt")).unwrap();
    let report = diagnose_deep(&input, 110).unwrap();
    assert!(has(&report, DeepDoctorCode::CatalogBindingMismatch));
    assert_eq!(report.examined_body_count, 0);
    assert!(!has(&report, DeepDoctorCode::InputUnavailable));
}

#[test]
fn legacy_unbound_index_and_missing_component_binding_never_pass_deep_binding() {
    let temp = tempfile::tempdir().unwrap();
    let (mut input, _, metadata) = linked_request(temp.path());
    fs::write(
        temp.path().join("index.json"),
        serde_json::to_vec(&metadata).unwrap(),
    )
    .unwrap();
    assert!(has(
        &diagnose_deep(&input, 110).unwrap(),
        DeepDoctorCode::CatalogBindingRequired
    ));
    input.retrieval_bindings.clear();
    assert!(has(
        &diagnose_deep(&input, 110).unwrap(),
        DeepDoctorCode::CatalogBindingRequired
    ));
}

#[test]
fn metadata_cannot_upgrade_catalog_trust_or_introduce_unknown_skills() {
    let temp = tempfile::tempdir().unwrap();
    let (input, catalog, metadata) = linked_request(temp.path());
    for (id, trust, expected) in [
        (
            "fixture-skill",
            SkillTrust::TrustedLocal,
            DeepDoctorCode::AssetBodyUntrusted,
        ),
        (
            "unknown",
            SkillTrust::Builtin,
            DeepDoctorCode::CatalogBindingMismatch,
        ),
    ] {
        let mut changed = metadata.clone();
        changed.assets[0].id = id.into();
        changed.assets[0].trust = trust;
        fs::write(
            temp.path().join("index.json"),
            MetadataEnvelope::new(changed, &catalog.content_hash().unwrap())
                .unwrap()
                .canonical_json()
                .unwrap(),
        )
        .unwrap();
        let report = diagnose_deep(&input, 110).unwrap();
        assert!(has(&report, expected));
        assert_eq!(report.examined_body_count, 0);
    }
}

#[test]
fn deep_binding_validates_references_before_reads_and_never_reads_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let mut input = request(
        temp.path(),
        vec![artifact("credential.json", DoctorArtifactKind::AuthMarker)],
    );
    input.schemas.push(DoctorSchemaBinding {
        artifact_id: "credential.json".into(),
        schema: DoctorSchema::PhasePolicy,
    });
    assert_eq!(diagnose_deep(&input, 110), Err(DoctorError::Invalid));
    assert!(!temp.path().join("credential.json").exists());
}

#[cfg(unix)]
#[test]
fn body_symlinks_and_parent_traversal_are_rejected() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let (mut input, _, _) = linked_request(temp.path());
    fs::remove_file(temp.path().join("bodies/skill.txt")).unwrap();
    symlink(
        temp.path().join("catalog.json"),
        temp.path().join("bodies/skill.txt"),
    )
    .unwrap();
    let report = diagnose_deep(&input, 110).unwrap();
    assert!(has(&report, DeepDoctorCode::PathRejected));
    assert!(!has(&report, DeepDoctorCode::InputUnavailable));
    assert_eq!(report.examined_body_count, 0);
    input.retrieval_bindings[0].body_root = Some("../escape".into());
    assert_eq!(diagnose_deep(&input, 110), Err(DoctorError::Invalid));
}

fn database_request(root: &Path) -> DeepDoctorRequest {
    request(
        root,
        vec![artifact("runtime.db", DoctorArtifactKind::Database)],
    )
}
fn create_database(root: &Path, invalid_fk: bool) {
    let connection = rusqlite::Connection::open(root.join("runtime.db")).unwrap();
    connection.execute_batch("CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(parent_id INTEGER REFERENCES parent(id)); PRAGMA user_version = 42;").unwrap();
    if invalid_fk {
        connection
            .execute_batch("PRAGMA foreign_keys = OFF; INSERT INTO child VALUES(100);")
            .unwrap();
    }
}

#[test]
fn database_missing_or_header_only_is_not_integrity_proof_and_never_created() {
    let temp = tempfile::tempdir().unwrap();
    let input = database_request(temp.path());
    let report = diagnose_deep(&input, 110).unwrap();
    assert_eq!(report.overall, DiagnosticState::Fail);
    assert_eq!(report.database_queries, 0);
    assert!(!temp.path().join("runtime.db").exists());
    fs::write(temp.path().join("runtime.db"), b"SQLite format 3\0").unwrap();
    assert!(has(
        &diagnose_deep(&input, 110).unwrap(),
        DeepDoctorCode::DatabaseSnapshotRequired
    ));
}

#[test]
fn pathname_database_integrity_requires_an_owned_connection_without_migration() {
    for invalid_fk in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        create_database(temp.path(), invalid_fk);
        let before = fs::read(temp.path().join("runtime.db")).unwrap();
        let report = diagnose_deep(&database_request(temp.path()), 110).unwrap();
        assert!(has(&report, DeepDoctorCode::DatabaseSnapshotRequired));
        assert_eq!(report.database_queries, 0);
        assert!(
            report
                .checks
                .iter()
                .all(|check| check.content_sha256.is_none())
        );
        assert_eq!(before, fs::read(temp.path().join("runtime.db")).unwrap());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
        assert_eq!(
            (report.base.files_modified, report.base.processes_launched),
            (0, 0)
        );
        assert!(
            report
                .checks
                .iter()
                .all(|check| check.runtime == DiagnosticState::Unknown)
        );
    }
}

#[test]
fn wal_and_journal_require_consistent_export_without_opening_sqlite() {
    let temp = tempfile::tempdir().unwrap();
    create_database(temp.path(), false);
    let path = temp.path().join("runtime.db");
    let original = fs::read(&path).unwrap();
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = temp.path().join(format!("runtime.db{suffix}"));
        fs::write(&sidecar, b"PRIVATE_JOURNAL").unwrap();
        let report = diagnose_deep(&database_request(temp.path()), 110).unwrap();
        assert!(has(&report, DeepDoctorCode::DatabaseSnapshotRequired));
        assert_eq!(report.database_queries, 0);
        assert_eq!(fs::read(&sidecar).unwrap(), b"PRIVATE_JOURNAL");
        fs::remove_file(sidecar).unwrap();
    }
    let mut wal_header = original.clone();
    wal_header[18] = 2;
    wal_header[19] = 2;
    fs::write(&path, wal_header).unwrap();
    let report = diagnose_deep(&database_request(temp.path()), 110).unwrap();
    assert!(has(&report, DeepDoctorCode::DatabaseSnapshotRequired));
    assert_eq!(report.database_queries, 0);
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
}

#[test]
fn bounded_body_reads_and_missing_body_are_explicit_failures() {
    let temp = tempfile::tempdir().unwrap();
    let (input, catalog, mut metadata) = linked_request(temp.path());
    fs::write(
        temp.path().join("bodies/skill.txt"),
        vec![b'x'; router_retrieval::MAX_BODY_BYTES + 1],
    )
    .unwrap();
    assert!(has(
        &diagnose_deep(&input, 110).unwrap(),
        DeepDoctorCode::InputLimit
    ));
    metadata.assets[0].body = None;
    fs::write(
        temp.path().join("index.json"),
        MetadataEnvelope::new(metadata, &catalog.content_hash().unwrap())
            .unwrap()
            .canonical_json()
            .unwrap(),
    )
    .unwrap();
    assert!(has(
        &diagnose_deep(&input, 110).unwrap(),
        DeepDoctorCode::AssetBodyUnavailable
    ));
}

#[test]
fn normalized_task_plan_restrictions_and_configuration_use_their_semantic_validators() {
    let temp = tempfile::tempdir().unwrap();
    let fixture: PhaseRouteRequest = serde_json::from_slice(include_bytes!(
        "../../../fixtures/examples/phase-request.json"
    ))
    .unwrap();
    let plan = router_workflow::build_plan(
        &fixture.task,
        WorkflowPreset::DirectSafe,
        router_workflow::PlanLimits::default(),
    )
    .unwrap();
    let layers = ConfigurationLayers {
        schema_version: 1,
        defaults: RestrictionLayer {
            name: "synthetic".into(),
            allowed_models: None,
            allowed_capabilities: None,
            allowed_mutations: None,
            max_cost_microusd: Some(100),
            max_tokens: Some(100),
            max_concurrency: Some(1),
            preferred_model: None,
        },
        active_offline_policy: None,
        preset: None,
        project: None,
        organization: None,
        task: None,
    };
    for (schema, value) in [
        (
            DoctorSchema::NormalizedTask,
            serde_json::to_value(&fixture.task).unwrap(),
        ),
        (
            DoctorSchema::WorkflowPlan,
            serde_json::to_value(plan).unwrap(),
        ),
        (
            DoctorSchema::EffectiveRestrictions,
            serde_json::to_value(&fixture.restrictions).unwrap(),
        ),
        (
            DoctorSchema::ConfigurationLayers,
            serde_json::to_value(layers).unwrap(),
        ),
    ] {
        let input = schema_request(temp.path(), schema, &value);
        assert_pass(
            &diagnose_deep(&input, 110).unwrap(),
            DeepDoctorCode::ComponentValidated,
        );
        let input = schema_request(
            temp.path(),
            schema,
            &serde_json::json!({"schema_version":1}),
        );
        assert!(has(
            &diagnose_deep(&input, 110).unwrap(),
            DeepDoctorCode::SchemaInvalid
        ));
    }
    let mut unknown = serde_json::to_value(&fixture.restrictions).unwrap();
    unknown["ignored_permission"] = true.into();
    let input = schema_request(temp.path(), DoctorSchema::EffectiveRestrictions, &unknown);
    assert!(has(
        &diagnose_deep(&input, 110).unwrap(),
        DeepDoctorCode::SchemaInvalid
    ));
}

#[test]
fn generated_catalog_registry_hash_must_match_body_metadata_not_only_projection() {
    use router_adapter_api::{HostObservation, SnapshotValidation};
    use router_catalog::{AssetRegistry, GeneratedCatalog, GenerationConfig, RegistryAsset};
    let temp = tempfile::tempdir().unwrap();
    let (input, prior, mut metadata) = linked_request(temp.path());
    let mut observation: HostObservation = serde_json::from_slice(include_bytes!(
        "../../../fixtures/examples/phase-snapshot.json"
    ))
    .unwrap();
    let model = ModelId::parse("fixture-model-v1").unwrap();
    observation.host.supported_models = BTreeSet::from([model.clone()]);
    observation.host.supported_efforts = BTreeMap::from([(
        model,
        BTreeSet::from([EffortLevel::Medium, EffortLevel::High]),
    )]);
    observation.host.capabilities.clear();
    for evidence in observation.capabilities.values_mut() {
        evidence.support = router_types::CapabilitySupport::Unknown;
    }
    let snapshot = fixture_proofs::from_observation(
        observation.seal().unwrap(),
        SnapshotValidation {
            now_unix_seconds: 110,
            max_age_seconds: 100,
        },
    )
    .unwrap();
    let config = GenerationConfig {
        aliases: vec![],
        registry: AssetRegistry {
            schema_version: 1,
            version: "1".into(),
            assets: vec![RegistryAsset {
                kind: router_catalog::AssetKind::Skill,
                id: "fixture-skill".into(),
                version: "1".into(),
                source: "fixture".into(),
                content_sha256: content_digest(b"BODY_SECRET_CANARY"),
                required_capabilities: BTreeSet::new(),
                deprecated_by: None,
            }],
        },
    };
    let generated = GeneratedCatalog::generate(&snapshot, &prior, &config).unwrap();
    fs::write(
        temp.path().join("catalog.json"),
        generated.canonical_json().unwrap(),
    )
    .unwrap();
    metadata.catalog_version = generated.catalog().version().into();
    let hash = generated.catalog().content_hash().unwrap();
    fs::write(
        temp.path().join("index.json"),
        MetadataEnvelope::new(metadata.clone(), &hash)
            .unwrap()
            .canonical_json()
            .unwrap(),
    )
    .unwrap();
    assert_pass(
        &diagnose_deep(&input, 110).unwrap(),
        DeepDoctorCode::AssetBodyValidated,
    );
    metadata.assets[0].body.as_mut().unwrap().sha256 = content_digest(b"replacement");
    fs::write(temp.path().join("bodies/skill.txt"), b"replacement").unwrap();
    fs::write(
        temp.path().join("index.json"),
        MetadataEnvelope::new(metadata, &hash)
            .unwrap()
            .canonical_json()
            .unwrap(),
    )
    .unwrap();
    let report = diagnose_deep(&input, 110).unwrap();
    assert!(has(&report, DeepDoctorCode::AssetBodyMismatch));
    assert_eq!(report.examined_body_count, 0);
}

#[test]
fn v3_signal_metadata_keeps_catalog_and_body_gates_without_runtime_claims() {
    use router_retrieval::{AssetSignals, MetadataEnvelopeV3, Signal};
    let temp = tempfile::tempdir().unwrap();
    let (input, catalog, metadata) = linked_request(temp.path());
    let signals = metadata
        .assets
        .iter()
        .map(|asset| AssetSignals {
            asset: asset.key(),
            languages: Signal::Unknown,
            required_tools: Signal::Unknown,
            history: Signal::Unknown,
        })
        .collect();
    let envelope =
        MetadataEnvelopeV3::new(metadata, signals, &catalog.content_hash().unwrap()).unwrap();
    fs::write(
        temp.path().join("index.json"),
        envelope.canonical_json().unwrap(),
    )
    .unwrap();
    let report = diagnose_deep(&input, 110).unwrap();
    assert_pass(&report, DeepDoctorCode::CatalogBindingValidated);
    assert_pass(&report, DeepDoctorCode::AssetBodyValidated);
    assert_eq!(report.examined_body_count, 1);
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("BODY_SECRET_CANARY")
    );

    let mut corrupt = serde_json::to_value(&envelope).unwrap();
    corrupt["signals"][0]["asset"]["id"] = "invented-asset".into();
    fs::write(
        temp.path().join("index.json"),
        serde_json::to_vec(&corrupt).unwrap(),
    )
    .unwrap();
    let report = diagnose_deep(&input, 110).unwrap();
    assert_eq!(report.overall, DiagnosticState::Fail);
    assert_eq!(report.examined_body_count, 0);
    assert!(!has(&report, DeepDoctorCode::CatalogBindingValidated));

    let mut mismatch = envelope;
    mismatch.catalog_content_sha256 = "c".repeat(64);
    fs::write(
        temp.path().join("index.json"),
        mismatch.canonical_json().unwrap(),
    )
    .unwrap();
    fs::remove_file(temp.path().join("bodies/skill.txt")).unwrap();
    let report = diagnose_deep(&input, 110).unwrap();
    assert!(has(&report, DeepDoctorCode::CatalogBindingMismatch));
    assert_eq!(report.examined_body_count, 0);
    assert!(!has(&report, DeepDoctorCode::InputUnavailable));
}
