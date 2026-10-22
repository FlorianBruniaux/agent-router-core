use std::collections::BTreeSet;

use router_catalog::Catalog;
use router_types::{
    Capability, EffortLevel, ModelId, ModelSpec, SkillId, SkillSpec, SkillTrust, StageKind,
    TaskKind,
};

#[test]
fn rejects_bare_model_alias_in_catalog() {
    let bytes = include_bytes!("../../../tests/fixtures/catalogs/invalid-alias.json");
    let error = Catalog::from_json(bytes).unwrap_err();
    assert_eq!(error.code(), "catalog.model.non_canonical_id");
}

#[test]
fn rejects_duplicate_model_ids() {
    let bytes = include_bytes!("../../../tests/fixtures/catalogs/duplicate-model.json");
    let error = Catalog::from_json(bytes).unwrap_err();
    assert_eq!(error.code(), "catalog.model.duplicate_id");
}

#[test]
fn loads_exact_codex_models() {
    let bytes = include_bytes!("../../../assets/catalogs/codex-core-v1.json");
    let catalog = Catalog::from_json(bytes).unwrap();
    let sol_id = ModelId::parse("gpt-5.6-sol").unwrap();
    let terra_id = ModelId::parse("gpt-5.6-terra").unwrap();
    let luna_id = ModelId::parse("gpt-5.6-luna").unwrap();

    assert_eq!(
        catalog.model(&sol_id),
        Some(&ModelSpec {
            id: sol_id.clone(),
            stages: BTreeSet::from([StageKind::Plan, StageKind::Execute, StageKind::Verify]),
            efforts: BTreeSet::from([EffortLevel::High, EffortLevel::Xhigh, EffortLevel::Max]),
            capabilities: BTreeSet::from([Capability::Tools, Capability::Subagents]),
            quality_micros: 950_000,
            cost_micros: 900_000,
            latency_micros: 900_000,
            source: "builtin-policy-prior".into(),
        })
    );
    assert_eq!(
        catalog.model(&terra_id),
        Some(&ModelSpec {
            id: terra_id.clone(),
            stages: BTreeSet::from([StageKind::Execute, StageKind::Verify]),
            efforts: BTreeSet::from([EffortLevel::Medium, EffortLevel::High, EffortLevel::Xhigh]),
            capabilities: BTreeSet::from([Capability::Tools, Capability::Subagents]),
            quality_micros: 820_000,
            cost_micros: 550_000,
            latency_micros: 550_000,
            source: "builtin-policy-prior".into(),
        })
    );
    assert_eq!(
        catalog.model(&luna_id),
        Some(&ModelSpec {
            id: luna_id.clone(),
            stages: BTreeSet::from([StageKind::Execute]),
            efforts: BTreeSet::from([EffortLevel::Low, EffortLevel::Medium, EffortLevel::High]),
            capabilities: BTreeSet::from([Capability::Tools]),
            quality_micros: 650_000,
            cost_micros: 200_000,
            latency_micros: 200_000,
            source: "builtin-policy-prior".into(),
        })
    );
}

#[test]
fn iterates_models_in_deterministic_id_order() {
    let catalog = Catalog::from_json(include_bytes!(
        "../../../assets/catalogs/codex-core-v1.json"
    ))
    .unwrap();

    assert_eq!(
        catalog
            .models()
            .map(|(model_id, _)| model_id.as_str())
            .collect::<Vec<_>>(),
        vec!["gpt-5.6-luna", "gpt-5.6-sol", "gpt-5.6-terra"]
    );
}

#[test]
fn exposes_catalog_version_and_builtin_skill_metadata() {
    let bytes = include_bytes!("../../../assets/catalogs/codex-core-v1.json");
    let catalog = Catalog::from_json(bytes).unwrap();

    assert_eq!(catalog.version(), "codex-core-v1");
    let tdd_id = SkillId::parse("tdd").unwrap();
    let critique_plan_id = SkillId::parse("critique-plan").unwrap();
    let security_guardian_id = SkillId::parse("security-guardian").unwrap();

    assert_eq!(
        catalog.skill(&tdd_id),
        Some(&SkillSpec {
            id: tdd_id.clone(),
            description: "Guides a red-green-refactor implementation cycle.".into(),
            task_kinds: BTreeSet::from([TaskKind::Implement]),
            required_capabilities: BTreeSet::from([Capability::Tools]),
            trust: SkillTrust::Builtin,
        })
    );
    assert_eq!(
        catalog.skill(&critique_plan_id),
        Some(&SkillSpec {
            id: critique_plan_id.clone(),
            description: "Challenges implementation plans for omissions and unsafe assumptions."
                .into(),
            task_kinds: BTreeSet::from([
                TaskKind::Architecture,
                TaskKind::Migration,
                TaskKind::Security,
            ]),
            required_capabilities: BTreeSet::new(),
            trust: SkillTrust::Builtin,
        })
    );
    assert_eq!(
        catalog.skill(&security_guardian_id),
        Some(&SkillSpec {
            id: security_guardian_id.clone(),
            description: "Reviews changes for security boundaries and unsafe behavior.".into(),
            task_kinds: BTreeSet::from([TaskKind::Security, TaskKind::Review]),
            required_capabilities: BTreeSet::from([Capability::Tools]),
            trust: SkillTrust::Builtin,
        })
    );
}

#[test]
fn rejects_invalid_catalog_semantics_with_specific_codes() {
    for (field, value, expected_code, expected_path) in [
        (
            "schema_version",
            "2",
            "catalog.schema.unsupported_version",
            "schema_version",
        ),
        ("version", "\"\"", "catalog.version.empty", "version"),
        (
            "models[0].id",
            "\"\"",
            "catalog.model.invalid_id",
            "models[0].id",
        ),
        (
            "models[0].stages",
            "[]",
            "catalog.model.empty_stages",
            "models[0].stages",
        ),
        (
            "models[0].efforts",
            "[]",
            "catalog.model.empty_efforts",
            "models[0].efforts",
        ),
        (
            "models[0].quality_micros",
            "1000001",
            "catalog.model.quality_out_of_range",
            "models[0].quality_micros",
        ),
        (
            "models[0].cost_micros",
            "-1",
            "catalog.model.negative_cost",
            "models[0].cost_micros",
        ),
        (
            "models[0].latency_micros",
            "-1",
            "catalog.model.negative_latency",
            "models[0].latency_micros",
        ),
        (
            "skills[0].trust",
            "\"unknown\"",
            "catalog.skill.invalid_trust",
            "skills[0].trust",
        ),
        (
            "skills[0].id",
            "\"\"",
            "catalog.skill.invalid_id",
            "skills[0].id",
        ),
        (
            "models[0].stages",
            "[\"deploy\"]",
            "catalog.model.invalid_stage",
            "models[0].stages[0]",
        ),
        (
            "models[0].efforts",
            "[\"turbo\"]",
            "catalog.model.invalid_effort",
            "models[0].efforts[0]",
        ),
        (
            "models[0].capabilities",
            "[\"teleport\"]",
            "catalog.model.invalid_capability",
            "models[0].capabilities[0]",
        ),
        (
            "skills[0].task_kinds",
            "[\"deploy\"]",
            "catalog.skill.invalid_task_kind",
            "skills[0].task_kinds[0]",
        ),
        (
            "skills[0].required_capabilities",
            "[\"teleport\"]",
            "catalog.skill.invalid_capability",
            "skills[0].required_capabilities[0]",
        ),
    ] {
        let bytes = invalid_catalog(field, value);
        let error = Catalog::from_json(bytes.as_bytes()).unwrap_err();
        assert_eq!(error.code(), expected_code, "field {field}");
        assert_eq!(error.path, expected_path, "field {field}");
    }
}

fn invalid_catalog(field: &str, value: &str) -> String {
    let catalog = std::str::from_utf8(include_bytes!(
        "../../../assets/catalogs/codex-core-v1.json"
    ))
    .unwrap();
    let mut parsed: serde_json::Value = serde_json::from_str(catalog).unwrap();
    let replacement: serde_json::Value = serde_json::from_str(value).unwrap();

    match field {
        "schema_version" | "version" => parsed[field] = replacement,
        "models[0].id"
        | "models[0].stages"
        | "models[0].efforts"
        | "models[0].quality_micros"
        | "models[0].cost_micros"
        | "models[0].latency_micros"
        | "models[0].capabilities" => {
            let field = field.rsplit('.').next().unwrap();
            parsed["models"][0][field] = replacement;
        }
        "skills[0].trust"
        | "skills[0].id"
        | "skills[0].task_kinds"
        | "skills[0].required_capabilities" => {
            let field = field.rsplit('.').next().unwrap();
            parsed["skills"][0][field] = replacement;
        }
        _ => unreachable!("test only supplies supported catalog paths"),
    }

    serde_json::to_string(&parsed).unwrap()
}

#[test]
fn rejects_duplicate_skill_ids() {
    let bytes = include_bytes!("../../../assets/catalogs/codex-core-v1.json");
    let mut catalog: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let duplicate = catalog["skills"][0].clone();
    catalog["skills"].as_array_mut().unwrap().push(duplicate);

    let bytes = serde_json::to_vec(&catalog).unwrap();
    let error = Catalog::from_json(&bytes).unwrap_err();
    assert_eq!(error.code(), "catalog.skill.duplicate_id");
}

#[test]
fn rejects_empty_model_catalogs_with_a_structured_error() {
    let bytes = generated_catalog(0, 0);

    let error = Catalog::from_json(&bytes).unwrap_err();
    assert_eq!(error.code(), "catalog.models.empty");
    assert_eq!(error.path, "models");
}

#[test]
fn enforces_model_catalog_cardinality_boundaries() {
    assert!(Catalog::from_json(&generated_catalog(64, 0)).is_ok());

    let error = Catalog::from_json(&generated_catalog(65, 0)).unwrap_err();
    assert_eq!(error.code(), "catalog.models.too_many");
    assert_eq!(error.path, "models");
}

#[test]
fn enforces_skill_catalog_cardinality_boundaries() {
    assert!(Catalog::from_json(&generated_catalog(1, 256)).is_ok());

    let error = Catalog::from_json(&generated_catalog(1, 257)).unwrap_err();
    assert_eq!(error.code(), "catalog.skills.too_many");
    assert_eq!(error.path, "skills");
}

fn generated_catalog(model_count: usize, skill_count: usize) -> Vec<u8> {
    let models = (0..model_count)
        .map(|index| {
            serde_json::json!({
                "id": format!("model-{index}"),
                "stages": ["execute"],
                "efforts": ["low"],
                "capabilities": ["tools"],
                "quality_micros": 1,
                "cost_micros": 0,
                "latency_micros": 0,
                "source": "test-policy-prior"
            })
        })
        .collect::<Vec<_>>();
    let skills = (0..skill_count)
        .map(|index| {
            serde_json::json!({
                "id": format!("skill-{index}"),
                "description": "Generated boundary-test skill.",
                "task_kinds": ["implement"],
                "required_capabilities": [],
                "trust": "builtin"
            })
        })
        .collect::<Vec<_>>();

    serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "version": "generated-boundary-test-v1",
        "models": models,
        "skills": skills
    }))
    .unwrap()
}

fn catalog_with(pointer: &str, value: serde_json::Value) -> Vec<u8> {
    let mut parsed: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../assets/catalogs/codex-core-v1.json"
    ))
    .unwrap();
    *parsed.pointer_mut(pointer).expect("fixture pointer") = value;
    serde_json::to_vec(&parsed).unwrap()
}

#[test]
fn rejects_unsafe_labels_and_text_like_the_signed_path() {
    let long = "x".repeat(129);
    let long_source = "x".repeat(513);
    let long_description = "x".repeat(8193);
    for (pointer, value, code) in [
        (
            "/version",
            serde_json::json!("v1\u{202e}2"),
            "catalog.version.invalid",
        ),
        (
            "/version",
            serde_json::json!("v1\u{0007}"),
            "catalog.version.invalid",
        ),
        (
            "/version",
            serde_json::json!(long),
            "catalog.version.invalid",
        ),
        (
            "/models/0/source",
            serde_json::json!("a\nb"),
            "catalog.model.invalid_source",
        ),
        (
            "/models/0/source",
            serde_json::json!("a\u{2066}b"),
            "catalog.model.invalid_source",
        ),
        (
            "/models/0/source",
            serde_json::json!("  "),
            "catalog.model.invalid_source",
        ),
        (
            "/models/0/source",
            serde_json::json!(long_source),
            "catalog.model.invalid_source",
        ),
        (
            "/models/0/id",
            serde_json::json!("gpt 5\u{202e}"),
            "catalog.model.invalid_id",
        ),
        (
            "/models/0/id",
            serde_json::json!("x".repeat(129)),
            "catalog.model.invalid_id",
        ),
        (
            "/skills/0/id",
            serde_json::json!("skill\u{0}id"),
            "catalog.skill.invalid_id",
        ),
        (
            "/skills/0/id",
            serde_json::json!("skill id"),
            "catalog.skill.invalid_id",
        ),
        (
            "/skills/0/description",
            serde_json::json!("a\u{202e}b"),
            "catalog.skill.invalid_description",
        ),
        (
            "/skills/0/description",
            serde_json::json!("a\u{1b}[31m"),
            "catalog.skill.invalid_description",
        ),
        (
            "/skills/0/description",
            serde_json::json!(long_description),
            "catalog.skill.invalid_description",
        ),
    ] {
        let error = Catalog::from_json(&catalog_with(pointer, value)).unwrap_err();
        assert_eq!(error.code(), code, "pointer {pointer}");
    }
}

#[test]
fn rejects_unknown_keys_at_catalog_model_and_skill_level() {
    for pointer in ["", "/models/0", "/skills/0"] {
        let mut parsed: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../assets/catalogs/codex-core-v1.json"
        ))
        .unwrap();
        parsed.pointer_mut(pointer).unwrap()["unexpected_key"] = serde_json::json!(1);
        let error = Catalog::from_json(&serde_json::to_vec(&parsed).unwrap()).unwrap_err();
        assert!(
            error.to_string().contains("unexpected_key"),
            "pointer {pointer:?}: {error}"
        );
    }
}
