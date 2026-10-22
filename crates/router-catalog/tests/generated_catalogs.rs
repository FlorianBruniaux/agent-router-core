#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use std::collections::{BTreeMap, BTreeSet};

use router_adapter_api::{
    CapabilityEvidence, EvidenceKind, EvidenceSource, HostObservation, SnapshotValidation,
    ValidatedHostObservation,
};
use router_catalog::{
    AssetAlias, AssetAvailability, AssetKind, AssetRegistry, Catalog, GeneratedCatalog,
    GenerationConfig, RegistryAsset,
};
use router_types::{Capability, CapabilitySupport, EffortLevel, HarnessId, HostSnapshot, ModelId};

const PRIOR: &[u8] = include_bytes!("fixtures/generated-prior.json");

fn validation() -> SnapshotValidation {
    SnapshotValidation {
        now_unix_seconds: 110,
        max_age_seconds: 60,
    }
}

fn observation(runtime: bool) -> HostObservation {
    let id = ModelId::parse("fixture-model-v1").unwrap();
    let mut document = HostObservation {
        attestations: None,
        schema_version: 1,
        host: HostSnapshot {
            id: "fixture-host".into(),
            harness: HarnessId::parse("codex").unwrap(),
            supported_models: BTreeSet::from([id.clone()]),
            supported_efforts: BTreeMap::from([(
                id,
                BTreeSet::from([EffortLevel::Medium, EffortLevel::High]),
            )]),
            capabilities: BTreeSet::new(),
        },
        capabilities: BTreeMap::new(),
        evidence: vec![EvidenceSource {
            id: "fixture-source".into(),
            kind: if runtime {
                EvidenceKind::HostRuntime
            } else {
                EvidenceKind::CodexModelCache
            },
            observed_version: Some("0.1.0".into()),
            observed_at_unix_seconds: 100,
            content_sha256: "1".repeat(64),
        }],
        observed_at_unix_seconds: 100,
        snapshot_hash: String::new(),
    };
    if runtime {
        document.host.capabilities.insert(Capability::Tools);
        document.capabilities.insert(
            Capability::Tools,
            CapabilityEvidence {
                support: CapabilitySupport::Supported,
                source_ids: BTreeSet::from(["fixture-source".into()]),
            },
        );
    }
    document
}

fn snapshot(runtime: bool) -> ValidatedHostObservation {
    fixture_proofs::from_observation(observation(runtime).seal().unwrap(), validation()).unwrap()
}

fn registry_asset(kind: AssetKind, id: &str) -> RegistryAsset {
    RegistryAsset {
        kind,
        id: id.into(),
        version: "v1".into(),
        source: "fixture-registry".into(),
        content_sha256: "a".repeat(64),
        required_capabilities: BTreeSet::new(),
        deprecated_by: None,
    }
}

fn full_config() -> GenerationConfig {
    GenerationConfig {
        aliases: vec![AssetAlias {
            kind: AssetKind::Model,
            alias: "short".into(),
            target: "fixture-model-v1".into(),
        }],
        registry: AssetRegistry {
            schema_version: 1,
            version: "registry-v1".into(),
            assets: vec![
                registry_asset(AssetKind::Agent, "fixture-agent"),
                registry_asset(AssetKind::Skill, "fixture-skill"),
                registry_asset(AssetKind::Prompt, "fixture-prompt"),
                registry_asset(AssetKind::Tool, "fixture-tool"),
            ],
        },
    }
}

#[test]
fn legacy_canonical_hash_covers_content_even_when_version_is_unchanged() {
    let original = Catalog::from_json(PRIOR).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(PRIOR).unwrap();
    value["models"][0]["cost_micros"] = 100_001.into();
    let modified = Catalog::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(original.version(), modified.version());
    assert_ne!(
        original.content_hash().unwrap(),
        modified.content_hash().unwrap()
    );
    let round_trip = Catalog::from_json(&original.canonical_json().unwrap()).unwrap();
    assert_eq!(
        original.content_hash().unwrap(),
        round_trip.content_hash().unwrap()
    );
}

#[test]
fn generated_hash_is_deterministic_and_scores_remain_policy_priors() {
    let prior = Catalog::from_json(PRIOR).unwrap();
    let first = GeneratedCatalog::generate(&snapshot(false), &prior, &full_config()).unwrap();
    let second = GeneratedCatalog::generate(&snapshot(false), &prior, &full_config()).unwrap();
    assert_eq!(
        first.canonical_json().unwrap(),
        second.canonical_json().unwrap()
    );
    let id = ModelId::parse("fixture-model-v1").unwrap();
    let model = first.catalog().model(&id).unwrap();
    assert_eq!(model.quality_micros, 800_000);
    assert_eq!(model.cost_micros, 100_000);
    assert_eq!(model.latency_micros, 200_000);
    assert!(model.capabilities.is_empty());
    let bytes = first.canonical_json().unwrap();
    let decoded = GeneratedCatalog::from_json(&bytes, validation()).unwrap();
    assert_eq!(decoded.content_hash(), first.content_hash());
    assert_eq!(decoded.assets().len(), 5);
    for asset in decoded.assets() {
        assert_eq!(asset.provenance.snapshot_hash, snapshot(false).hash());
        assert_eq!(
            asset.provenance.policy_catalog_hash,
            prior.content_hash().unwrap()
        );
        assert_eq!(
            asset.provenance.host_versions["fixture-source"].as_deref(),
            Some("0.1.0")
        );
        assert_eq!(
            asset.provenance.availability,
            if asset.kind == AssetKind::Model {
                AssetAvailability::HostSnapshot
            } else {
                AssetAvailability::ExplicitRegistry
            }
        );
    }
}

#[test]
fn exact_registered_identifiers_and_input_aliases_are_resolved() {
    let generated = GeneratedCatalog::generate(
        &snapshot(false),
        &Catalog::from_json(PRIOR).unwrap(),
        &full_config(),
    )
    .unwrap();
    assert_eq!(
        generated.resolve(AssetKind::Model, "short").unwrap(),
        "fixture-model-v1"
    );
    assert_eq!(
        generated
            .resolve(AssetKind::Agent, "fixture-agent")
            .unwrap(),
        "fixture-agent"
    );
    for kind in [
        AssetKind::Agent,
        AssetKind::Skill,
        AssetKind::Prompt,
        AssetKind::Tool,
        AssetKind::Model,
    ] {
        assert_eq!(
            generated
                .resolve(kind, "not-registered")
                .unwrap_err()
                .code(),
            "catalog.asset.unknown"
        );
    }
    assert!(!generated.assets().iter().any(|asset| asset.id == "short"));
}

#[test]
fn registry_and_alias_order_do_not_change_hash() {
    let prior = Catalog::from_json(PRIOR).unwrap();
    let mut config = full_config();
    config.aliases.push(AssetAlias {
        kind: AssetKind::Agent,
        alias: "agent".into(),
        target: "fixture-agent".into(),
    });
    let before = GeneratedCatalog::generate(&snapshot(false), &prior, &config).unwrap();
    config.aliases.reverse();
    config.registry.assets.reverse();
    assert_eq!(
        before.content_hash(),
        GeneratedCatalog::generate(&snapshot(false), &prior, &config)
            .unwrap()
            .content_hash()
    );
}

#[test]
fn registry_content_changes_catalog_version_and_complete_hash() {
    let prior = Catalog::from_json(PRIOR).unwrap();
    let mut config = full_config();
    let before = GeneratedCatalog::generate(&snapshot(false), &prior, &config).unwrap();
    config.registry.assets[0].content_sha256 = "b".repeat(64);
    let after = GeneratedCatalog::generate(&snapshot(false), &prior, &config).unwrap();
    assert_ne!(before.content_hash(), after.content_hash());
    assert_ne!(before.catalog().version(), after.catalog().version());
}

#[test]
fn explicit_capability_requirements_fail_closed_and_cannot_hide_skill_drift() {
    let prior = Catalog::from_json(PRIOR).unwrap();
    let config =
        GenerationConfig::from_json(include_bytes!("fixtures/capability-drift.json")).unwrap();
    assert_eq!(
        GeneratedCatalog::generate(&snapshot(false), &prior, &config)
            .unwrap_err()
            .code(),
        "catalog.capability.unknown"
    );
    assert_eq!(
        GeneratedCatalog::generate(&snapshot(true), &prior, &config)
            .unwrap_err()
            .code(),
        "catalog.skill.capability.drift"
    );
    let mut config = full_config();
    config.registry.assets[0]
        .required_capabilities
        .insert(Capability::Tools);
    assert!(GeneratedCatalog::generate(&snapshot(true), &prior, &config).is_ok());
}

#[test]
fn conflicting_aliases_unknown_targets_and_deprecation_are_errors() {
    let prior = Catalog::from_json(PRIOR).unwrap();
    for (fixture, expected) in [
        (
            &include_bytes!("fixtures/conflicting-aliases.json")[..],
            "catalog.alias.conflict",
        ),
        (
            &include_bytes!("fixtures/deprecated-model.json")[..],
            "catalog.asset.deprecated",
        ),
    ] {
        let config = GenerationConfig::from_json(fixture).unwrap();
        assert_eq!(
            GeneratedCatalog::generate(&snapshot(false), &prior, &config)
                .unwrap_err()
                .code(),
            expected
        );
    }
    let mut config = full_config();
    config.aliases[0].target = "unknown".into();
    assert_eq!(
        GeneratedCatalog::generate(&snapshot(false), &prior, &config)
            .unwrap_err()
            .code(),
        "catalog.alias.target.unknown"
    );
    config.aliases[0].target = "fixture-model-v1".into();
    config.aliases[0].alias = "fixture-model-v1".into();
    assert_eq!(
        GeneratedCatalog::generate(&snapshot(false), &prior, &config)
            .unwrap_err()
            .code(),
        "catalog.alias.conflict"
    );
}

#[test]
fn unobserved_models_unsupported_efforts_and_unknown_skills_are_rejected() {
    let prior = Catalog::from_json(PRIOR).unwrap();
    let mut host = observation(false);
    let id = ModelId::parse("unknown-model-v1").unwrap();
    host.host.supported_models.insert(id.clone());
    host.host
        .supported_efforts
        .insert(id, BTreeSet::from([EffortLevel::High]));
    let host = fixture_proofs::from_observation(host.seal().unwrap(), validation()).unwrap();
    assert_eq!(
        GeneratedCatalog::generate(&host, &prior, &GenerationConfig::default())
            .unwrap_err()
            .code(),
        "catalog.model.unknown"
    );
    let mut host = observation(false);
    host.host
        .supported_efforts
        .values_mut()
        .next()
        .unwrap()
        .insert(EffortLevel::Ultra);
    let host = fixture_proofs::from_observation(host.seal().unwrap(), validation()).unwrap();
    assert_eq!(
        GeneratedCatalog::generate(&host, &prior, &GenerationConfig::default())
            .unwrap_err()
            .code(),
        "catalog.effort.unsupported"
    );
    let mut config = full_config();
    config
        .registry
        .assets
        .push(registry_asset(AssetKind::Skill, "unknown-skill"));
    assert_eq!(
        GeneratedCatalog::generate(&snapshot(false), &prior, &config)
            .unwrap_err()
            .code(),
        "catalog.skill.unknown"
    );
}

#[test]
fn forged_output_provenance_stale_snapshots_and_unknown_capabilities_fail() {
    let generated = GeneratedCatalog::generate(
        &snapshot(false),
        &Catalog::from_json(PRIOR).unwrap(),
        &full_config(),
    )
    .unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&generated.canonical_json().unwrap()).unwrap();
    value["catalog"]["models"][0]["quality_micros"] = 999_999.into();
    assert_eq!(
        GeneratedCatalog::from_json(&serde_json::to_vec(&value).unwrap(), validation())
            .unwrap_err()
            .code(),
        "catalog.generated.hash.invalid"
    );
    assert_eq!(
        GeneratedCatalog::from_json(
            &generated.canonical_json().unwrap(),
            SnapshotValidation {
                now_unix_seconds: 161,
                max_age_seconds: 60
            }
        )
        .unwrap_err()
        .code(),
        "snapshot.stale"
    );
    let mut config = serde_json::to_value(full_config()).unwrap();
    config["registry"]["assets"][0]["required_capabilities"] =
        serde_json::json!(["invented_capability"]);
    assert_eq!(
        GenerationConfig::from_json(&serde_json::to_vec(&config).unwrap())
            .unwrap_err()
            .code(),
        "catalog.registry.json.invalid"
    );
}

#[test]
fn unregistered_skills_are_not_silently_imported_from_policy() {
    let prior = Catalog::from_json(PRIOR).unwrap();
    let generated =
        GeneratedCatalog::generate(&snapshot(false), &prior, &GenerationConfig::default()).unwrap();
    assert_eq!(prior.skills().count(), 1);
    assert_eq!(generated.catalog().skills().count(), 0);
    assert!(
        generated
            .resolve(AssetKind::Skill, "fixture-skill")
            .is_err()
    );
}

#[test]
fn recomputing_the_envelope_hash_cannot_hide_output_input_disagreement() {
    use sha2::{Digest, Sha256};
    let generated = GeneratedCatalog::generate(
        &snapshot(false),
        &Catalog::from_json(PRIOR).unwrap(),
        &full_config(),
    )
    .unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&generated.canonical_json().unwrap()).unwrap();
    value["assets"][0]["provenance"]["policy_catalog_hash"] = "f".repeat(64).into();
    value.as_object_mut().unwrap().remove("content_hash");
    let mut hasher = Sha256::new();
    hasher.update(b"agent-router:generated-catalog:v2\0");
    hasher.update(serde_json::to_vec(&value).unwrap());
    value["content_hash"] = hex::encode(hasher.finalize()).into();
    assert_eq!(
        GeneratedCatalog::from_json(&serde_json::to_vec(&value).unwrap(), validation())
            .unwrap_err()
            .code(),
        "catalog.generated.provenance.invalid"
    );
}

#[test]
fn duplicate_registry_assets_and_excessive_work_fail_before_generation() {
    let prior = Catalog::from_json(PRIOR).unwrap();
    let mut config = full_config();
    config
        .registry
        .assets
        .push(config.registry.assets[0].clone());
    assert_eq!(
        GeneratedCatalog::generate(&snapshot(false), &prior, &config)
            .unwrap_err()
            .code(),
        "catalog.registry.asset.duplicate"
    );
    config.registry.assets = vec![registry_asset(AssetKind::Agent, "agent"); 513];
    assert_eq!(
        GeneratedCatalog::generate(&snapshot(false), &prior, &config)
            .unwrap_err()
            .code(),
        "catalog.registry.too_many"
    );
    let mut config = full_config();
    config.aliases = vec![config.aliases[0].clone(); 513];
    assert_eq!(
        GeneratedCatalog::generate(&snapshot(false), &prior, &config)
            .unwrap_err()
            .code(),
        "catalog.alias.too_many"
    );
}

#[test]
fn registry_source_must_not_be_a_local_absolute_path() {
    let prior = Catalog::from_json(PRIOR).unwrap();
    for source in [
        "/etc/registry",
        "\\\\server\\share",
        "C:\\registry",
        "c:/registry",
        "~/registry",
        "file:///tmp/registry",
        "FILE:registry",
        "../registry",
        "a/../registry",
    ] {
        let mut config = full_config();
        config.registry.assets[0].source = source.into();
        assert_eq!(
            GeneratedCatalog::generate(&snapshot(false), &prior, &config)
                .unwrap_err()
                .code(),
            "catalog.registry.asset.invalid",
            "source {source}"
        );
    }
    let mut config = full_config();
    config.registry.assets[0].source = "https://example.com/registry".into();
    assert!(GeneratedCatalog::generate(&snapshot(false), &prior, &config).is_ok());
}
