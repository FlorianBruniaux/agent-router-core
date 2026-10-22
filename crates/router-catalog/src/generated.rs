use std::collections::{BTreeMap, BTreeSet};

use router_adapter_api::{
    HostObservation, SnapshotValidation, ValidatedHostObservation, strict_json,
};
use router_types::{Capability, CapabilitySupport, ModelId, SkillId};
use serde::{Deserialize, Serialize};

use crate::{Catalog, CatalogError, content_hash};

const GENERATED_SCHEMA_VERSION: u32 = 2;
const MAX_GENERATED_BYTES: usize = 4 * 1024 * 1024;
const MAX_REGISTRY_ASSETS: usize = 512;
const MAX_ALIASES: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Model,
    Agent,
    Skill,
    Prompt,
    Tool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetAlias {
    pub kind: AssetKind,
    pub alias: String,
    pub target: String,
}

/// Explicit asset metadata, never a claim that the host discovered or loaded it.
/// The content hash identifies a separately maintained definition. This registry
/// does not load that definition or elevate its permissions or trust.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryAsset {
    pub kind: AssetKind,
    pub id: String,
    pub version: String,
    pub source: String,
    pub content_sha256: String,
    pub required_capabilities: BTreeSet<Capability>,
    pub deprecated_by: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetRegistry {
    pub schema_version: u32,
    pub version: String,
    pub assets: Vec<RegistryAsset>,
}

impl Default for AssetRegistry {
    fn default() -> Self {
        Self {
            schema_version: 1,
            version: "empty-v1".into(),
            assets: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationConfig {
    pub aliases: Vec<AssetAlias>,
    pub registry: AssetRegistry,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetAvailability {
    HostSnapshot,
    ExplicitRegistry,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetProvenance {
    pub availability: AssetAvailability,
    pub snapshot_hash: String,
    pub snapshot_schema_version: u32,
    pub source_ids: BTreeSet<String>,
    pub host_versions: BTreeMap<String, Option<String>>,
    pub observed_at_unix_seconds: u64,
    pub policy_catalog_version: String,
    pub policy_catalog_hash: String,
    pub registry_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedAsset {
    pub kind: AssetKind,
    pub id: String,
    pub schema_version: u32,
    pub version: String,
    pub source: String,
    pub content_sha256: String,
    pub provenance: AssetProvenance,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GeneratedDocument {
    schema_version: u32,
    snapshot: HostObservation,
    policy_prior: serde_json::Value,
    config: GenerationConfig,
    catalog: serde_json::Value,
    assets: Vec<GeneratedAsset>,
    content_hash: String,
}

#[derive(Clone, Debug)]
pub struct GeneratedCatalog {
    document: GeneratedDocument,
    catalog: Catalog,
}

impl GenerationConfig {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CatalogError> {
        let value = strict_json(bytes)
            .map_err(|_| error("catalog.registry.json.invalid", "invalid registry input"))?;
        reject_duplicate_strings(&value)?;
        serde_json::from_value(value)
            .map_err(|_| error("catalog.registry.json.invalid", "invalid registry schema"))
    }
}

impl GeneratedCatalog {
    pub fn generate(
        snapshot: &ValidatedHostObservation,
        prior: &Catalog,
        config: &GenerationConfig,
    ) -> Result<Self, CatalogError> {
        if config.registry.assets.len() > MAX_REGISTRY_ASSETS {
            return Err(error(
                "catalog.registry.too_many",
                "registry asset limit exceeded",
            ));
        }
        if config.aliases.len() > MAX_ALIASES {
            return Err(error("catalog.alias.too_many", "alias limit exceeded"));
        }
        let mut config = config.clone();
        normalize_config(&mut config);
        validate_registry(&config.registry, snapshot, prior)?;
        let policy_hash = prior.content_hash()?;
        let registry_hash =
            hash_serializable(b"agent-router:asset-registry:v1\0", &config.registry)?;
        let mut models = BTreeMap::new();
        let mut skills = BTreeMap::new();
        let mut assets = Vec::new();
        let knowledge = snapshot.capabilities();
        let provenance = |availability, registered| AssetProvenance {
            availability,
            snapshot_hash: snapshot.hash().into(),
            snapshot_schema_version: snapshot.observation().schema_version,
            source_ids: snapshot
                .observation()
                .evidence
                .iter()
                .map(|source| source.id.clone())
                .collect(),
            host_versions: snapshot
                .observation()
                .evidence
                .iter()
                .map(|source| (source.id.clone(), source.observed_version.clone()))
                .collect(),
            observed_at_unix_seconds: snapshot.observation().observed_at_unix_seconds,
            policy_catalog_version: prior.version().into(),
            policy_catalog_hash: policy_hash.clone(),
            registry_hash: if registered {
                Some(registry_hash.clone())
            } else {
                None
            },
        };
        for id in &snapshot.host().supported_models {
            let policy = prior.model(id).ok_or_else(|| {
                error(
                    "catalog.model.unknown",
                    "observed model has no policy prior",
                )
            })?;
            let efforts = snapshot.host().supported_efforts.get(id).ok_or_else(|| {
                error(
                    "catalog.effort.unknown",
                    "observed model has no effort evidence",
                )
            })?;
            if efforts.is_empty() {
                return Err(error(
                    "catalog.effort.unknown",
                    "observed model has no established effort",
                ));
            }
            if !efforts.is_subset(&policy.efforts) {
                return Err(error(
                    "catalog.effort.unsupported",
                    "observed effort is absent from policy prior",
                ));
            }
            if !valid_source(&policy.source) {
                return Err(error(
                    "catalog.source.invalid",
                    "model prior source is missing or invalid",
                ));
            }
            let mut model = policy.clone();
            model.efforts = efforts.clone();
            // UNKNOWN host evidence must never add a model capability to an
            // admissible generated catalog, even when a policy prior lists it.
            model.capabilities.retain(|capability| {
                knowledge.get(capability) == Some(&CapabilitySupport::Supported)
            });
            assets.push(GeneratedAsset {
                kind: AssetKind::Model,
                id: id.to_string(),
                schema_version: 1,
                version: prior.version().into(),
                source: policy.source.clone(),
                content_sha256: hash_serializable(b"agent-router:model-asset:v1\0", &model)?,
                provenance: provenance(
                    AssetAvailability::HostSnapshot,
                    config
                        .registry
                        .assets
                        .iter()
                        .any(|asset| asset.kind == AssetKind::Model && asset.id == id.as_str()),
                ),
            });
            models.insert(id.clone(), model);
        }
        if models.is_empty() {
            return Err(error("catalog.models.empty", "no observed models"));
        }
        for asset in &config.registry.assets {
            if asset.kind == AssetKind::Model {
                continue;
            }
            if asset.kind == AssetKind::Skill {
                let id = SkillId::parse(&asset.id)
                    .map_err(|_| error("catalog.skill.invalid_id", "invalid skill id"))?;
                let skill = prior.skill(&id).ok_or_else(|| {
                    error(
                        "catalog.skill.unknown",
                        "registered skill has no policy prior",
                    )
                })?;
                skills.insert(id, skill.clone());
            }
            assets.push(GeneratedAsset {
                kind: asset.kind,
                id: asset.id.clone(),
                schema_version: config.registry.schema_version,
                version: asset.version.clone(),
                source: asset.source.clone(),
                content_sha256: asset.content_sha256.clone(),
                provenance: provenance(AssetAvailability::ExplicitRegistry, true),
            });
        }
        assets.sort_by(|left, right| (left.kind, &left.id).cmp(&(right.kind, &right.id)));
        validate_aliases(&config.aliases, &assets)?;
        let config_hash = hash_serializable(b"agent-router:generation-config:v1\0", &config)?;
        let catalog = Catalog {
            version: format!(
                "generated-{}-{}-{}",
                &snapshot.hash()[..16],
                &policy_hash[..16],
                &config_hash[..16]
            ),
            models,
            skills,
        };
        // The v1 parser remains the final structural and cardinality gate for
        // the policy projection consumed by the existing deterministic router.
        let catalog = Catalog::from_json(&catalog.canonical_json()?)?;
        let mut document = GeneratedDocument {
            schema_version: GENERATED_SCHEMA_VERSION,
            snapshot: snapshot.observation().clone(),
            policy_prior: serde_json::from_slice(&prior.canonical_json()?)
                .map_err(|_| error("catalog.serialize", "prior serialization"))?,
            config,
            catalog: serde_json::from_slice(&catalog.canonical_json()?)
                .map_err(|_| error("catalog.serialize", "catalog serialization"))?,
            assets,
            content_hash: String::new(),
        };
        document.content_hash = document_hash(&document)?;
        let generated = Self { document, catalog };
        generated.canonical_json()?;
        Ok(generated)
    }

    pub fn from_json(bytes: &[u8], validation: SnapshotValidation) -> Result<Self, CatalogError> {
        Self::from_json_with_verifier(bytes, validation, None)
    }
    pub fn from_json_with_verifier(
        bytes: &[u8],
        validation: SnapshotValidation,
        verifier: Option<&dyn router_adapter_api::CapabilityProofVerifier>,
    ) -> Result<Self, CatalogError> {
        if bytes.len() > MAX_GENERATED_BYTES {
            return Err(error(
                "catalog.generated.too_large",
                "generated catalog exceeds byte limit",
            ));
        }
        let value = strict_json(bytes)
            .map_err(|_| error("catalog.generated.json.invalid", "invalid generated JSON"))?;
        reject_duplicate_strings(&value)?;
        let snapshot_bytes = serde_json::to_vec(
            value
                .get("snapshot")
                .ok_or_else(|| error("catalog.generated.json.invalid", "snapshot is required"))?,
        )
        .map_err(|_| error("catalog.serialize", "snapshot serialization"))?;
        let snapshot = ValidatedHostObservation::from_json_with_verifier(
            &snapshot_bytes,
            validation,
            verifier,
        )
        .map_err(|source| error(source.code(), "invalid host snapshot"))?;
        let document: GeneratedDocument = serde_json::from_value(value)
            .map_err(|_| error("catalog.generated.json.invalid", "invalid generated schema"))?;
        if document.schema_version != GENERATED_SCHEMA_VERSION {
            return Err(error(
                "catalog.generated.schema.unsupported",
                "expected generated schema version 2",
            ));
        }
        if !valid_hash(&document.content_hash) || document_hash(&document)? != document.content_hash
        {
            return Err(error(
                "catalog.generated.hash.invalid",
                "generated catalog content changed",
            ));
        }
        let prior = Catalog::from_json(
            &serde_json::to_vec(&document.policy_prior)
                .map_err(|_| error("catalog.serialize", "prior serialization"))?,
        )?;
        let expected = Self::generate(&snapshot, &prior, &document.config)?;
        if expected.document != document {
            return Err(error(
                "catalog.generated.provenance.invalid",
                "generated assets do not match their inputs",
            ));
        }
        Ok(expected)
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, CatalogError> {
        let bytes = serde_json::to_vec(&self.document)
            .map_err(|_| error("catalog.serialize", "generated serialization"))?;
        if bytes.len() > MAX_GENERATED_BYTES {
            return Err(error(
                "catalog.generated.too_large",
                "generated catalog exceeds byte limit",
            ));
        }
        Ok(bytes)
    }

    pub fn content_hash(&self) -> &str {
        &self.document.content_hash
    }
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }
    pub fn assets(&self) -> &[GeneratedAsset] {
        &self.document.assets
    }
    pub fn snapshot(&self) -> &HostObservation {
        &self.document.snapshot
    }

    pub fn resolve(&self, kind: AssetKind, requested: &str) -> Result<&str, CatalogError> {
        if let Some(asset) = self
            .document
            .assets
            .iter()
            .find(|asset| asset.kind == kind && asset.id == requested)
        {
            return Ok(&asset.id);
        }
        if let Some(alias) = self
            .document
            .config
            .aliases
            .iter()
            .find(|alias| alias.kind == kind && alias.alias == requested)
        {
            return Ok(&alias.target);
        }
        Err(error(
            "catalog.asset.unknown",
            "asset is absent from the generated registry",
        ))
    }
}

fn validate_registry(
    registry: &AssetRegistry,
    snapshot: &ValidatedHostObservation,
    prior: &Catalog,
) -> Result<(), CatalogError> {
    if registry.schema_version != 1 || !valid_label(&registry.version) {
        return Err(error(
            "catalog.registry.schema.invalid",
            "registry requires schema 1 and a version",
        ));
    }
    if registry.assets.len() > MAX_REGISTRY_ASSETS {
        return Err(error(
            "catalog.registry.too_many",
            "registry asset limit exceeded",
        ));
    }
    let mut seen = BTreeSet::new();
    let knowledge = snapshot.capabilities();
    for asset in &registry.assets {
        if !valid_id(&asset.id)
            || !valid_label(&asset.version)
            || !valid_source(&asset.source)
            || !valid_hash(&asset.content_sha256)
        {
            return Err(error(
                "catalog.registry.asset.invalid",
                "registry requires canonical id, source, version and hash",
            ));
        }
        if !seen.insert((asset.kind, &asset.id)) {
            return Err(error(
                "catalog.registry.asset.duplicate",
                "duplicate registry asset",
            ));
        }
        if let Some(replacement) = &asset.deprecated_by {
            if !valid_id(replacement) || replacement == &asset.id {
                return Err(error(
                    "catalog.asset.deprecation.invalid",
                    "invalid replacement identifier",
                ));
            }
            return Err(error(
                "catalog.asset.deprecated",
                "deprecated assets cannot be generated; select their replacement explicitly",
            ));
        }
        for capability in &asset.required_capabilities {
            match knowledge.get(capability) {
                Some(CapabilitySupport::Supported) => {}
                Some(CapabilitySupport::Unsupported) => {
                    return Err(error(
                        "catalog.capability.unsupported",
                        "required registry capability is unsupported",
                    ));
                }
                _ => {
                    return Err(error(
                        "catalog.capability.unknown",
                        "required registry capability has unknown evidence",
                    ));
                }
            }
        }
        match asset.kind {
            AssetKind::Model => {
                let id = ModelId::parse(&asset.id).map_err(|_| {
                    error(
                        "catalog.model.invalid_id",
                        "model aliases are forbidden in registry ids",
                    )
                })?;
                if prior.model(&id).is_none() || !snapshot.host().supported_models.contains(&id) {
                    return Err(error(
                        "catalog.model.unknown",
                        "registered model is not observed with policy prior",
                    ));
                }
                if prior.model(&id).is_some_and(|model| {
                    !asset.required_capabilities.is_subset(&model.capabilities)
                }) {
                    return Err(error(
                        "catalog.model.capability.unsupported",
                        "registered model requires a capability absent from its policy prior",
                    ));
                }
            }
            AssetKind::Skill => {
                let id = SkillId::parse(&asset.id)
                    .map_err(|_| error("catalog.skill.invalid_id", "invalid skill id"))?;
                let skill = prior.skill(&id).ok_or_else(|| {
                    error(
                        "catalog.skill.unknown",
                        "registered skill has no policy prior",
                    )
                })?;
                if skill.required_capabilities != asset.required_capabilities {
                    return Err(error(
                        "catalog.skill.capability.drift",
                        "registry requirements differ from skill policy prior",
                    ));
                }
            }
            AssetKind::Agent | AssetKind::Prompt | AssetKind::Tool => {}
        }
    }
    Ok(())
}

fn validate_aliases(aliases: &[AssetAlias], assets: &[GeneratedAsset]) -> Result<(), CatalogError> {
    if aliases.len() > MAX_ALIASES {
        return Err(error("catalog.alias.too_many", "alias limit exceeded"));
    }
    let known: BTreeSet<_> = assets
        .iter()
        .map(|asset| (asset.kind, asset.id.as_str()))
        .collect();
    let mut seen = BTreeSet::new();
    for alias in aliases {
        if !valid_id(&alias.alias) || !valid_id(&alias.target) {
            return Err(error(
                "catalog.alias.invalid",
                "invalid alias or canonical target",
            ));
        }
        if !seen.insert((alias.kind, &alias.alias))
            || known.contains(&(alias.kind, alias.alias.as_str()))
        {
            return Err(error(
                "catalog.alias.conflict",
                "alias conflicts with another alias or canonical identifier",
            ));
        }
        if !known.contains(&(alias.kind, alias.target.as_str())) {
            return Err(error(
                "catalog.alias.target.unknown",
                "alias target is not a generated canonical asset",
            ));
        }
    }
    Ok(())
}

fn normalize_config(config: &mut GenerationConfig) {
    config
        .registry
        .assets
        .sort_by(|left, right| (left.kind, &left.id).cmp(&(right.kind, &right.id)));
    config.aliases.sort_by(|left, right| {
        (left.kind, &left.alias, &left.target).cmp(&(right.kind, &right.alias, &right.target))
    });
}

fn document_hash(document: &GeneratedDocument) -> Result<String, CatalogError> {
    let mut value = serde_json::to_value(document)
        .map_err(|_| error("catalog.serialize", "generated serialization"))?;
    value
        .as_object_mut()
        .ok_or_else(|| error("catalog.serialize", "generated object required"))?
        .remove("content_hash");
    hash_serializable(b"agent-router:generated-catalog:v2\0", &value)
}

fn hash_serializable<T: Serialize>(domain: &[u8], value: &T) -> Result<String, CatalogError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| error("catalog.serialize", "asset serialization"))?;
    Ok(content_hash(domain, &bytes))
}

fn valid_label(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
}
/// A provenance label that never names a local absolute path: no leading
/// separator, `~`, `file:` scheme or drive prefix, and no `..` component.
fn valid_source(value: &str) -> bool {
    let bytes = value.as_bytes();
    let drive = bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes.get(2).is_none_or(|b| matches!(b, b'/' | b'\\'));
    let local = drive
        || value.starts_with(['/', '\\', '~'])
        || value.to_ascii_lowercase().starts_with("file:")
        || value.split(['/', '\\']).any(|part| part == "..");
    valid_label(value) && !local
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn error(code: &str, message: &str) -> CatalogError {
    CatalogError::new(code, "$", message)
}

fn reject_duplicate_strings(value: &serde_json::Value) -> Result<(), CatalogError> {
    match value {
        serde_json::Value::Array(items) => {
            let mut seen = BTreeSet::new();
            for item in items {
                if let Some(text) = item.as_str() {
                    if !seen.insert(text) {
                        return Err(error("catalog.generated.duplicate", "duplicate set entry"));
                    }
                }
                reject_duplicate_strings(item)?;
            }
        }
        serde_json::Value::Object(fields) => {
            for child in fields.values() {
                reject_duplicate_strings(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}
