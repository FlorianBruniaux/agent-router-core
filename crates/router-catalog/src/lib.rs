#![forbid(unsafe_code)]

mod error;
mod generated;
mod signed;
mod validate;

use std::collections::BTreeMap;

use router_types::{ModelId, ModelSpec, SkillId, SkillSpec};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub use error::CatalogError;
pub use generated::{
    AssetAlias, AssetAvailability, AssetKind, AssetProvenance, AssetRegistry, GeneratedAsset,
    GeneratedCatalog, GenerationConfig, RegistryAsset,
};
pub use signed::*;

/// Bidirectional controls can reorder rendered text; they are not `is_control`.
pub fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Maximum number of model rows accepted by the MVP catalog parser.
pub const MAX_CATALOG_MODELS: usize = 64;
/// Maximum number of skill rows accepted by the MVP catalog parser.
pub const MAX_CATALOG_SKILLS: usize = 256;

#[derive(Clone, Debug)]
pub struct Catalog {
    version: String,
    models: BTreeMap<ModelId, ModelSpec>,
    skills: BTreeMap<SkillId, SkillSpec>,
}

impl Catalog {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CatalogError> {
        let raw = serde_json::from_slice(bytes)
            .map_err(|error| CatalogError::new("catalog.json.invalid", "$", error.to_string()))?;
        validate::validate(raw)
    }

    pub fn model(&self, id: &ModelId) -> Option<&ModelSpec> {
        self.models.get(id)
    }

    pub fn models(&self) -> impl Iterator<Item = (&ModelId, &ModelSpec)> {
        self.models.iter()
    }

    pub fn skill(&self, id: &SkillId) -> Option<&SkillSpec> {
        self.skills.get(id)
    }

    pub fn skills(&self) -> impl Iterator<Item = (&SkillId, &SkillSpec)> {
        self.skills.iter()
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    /// Stable v1 representation including all policy content, not just version.
    pub fn canonical_json(&self) -> Result<Vec<u8>, CatalogError> {
        #[derive(Serialize)]
        struct CanonicalCatalog<'a> {
            schema_version: u32,
            version: &'a str,
            models: Vec<&'a ModelSpec>,
            skills: Vec<&'a SkillSpec>,
        }
        serde_json::to_vec(&CanonicalCatalog {
            schema_version: 1,
            version: &self.version,
            models: self.models.values().collect(),
            skills: self.skills.values().collect(),
        })
        .map_err(|_| CatalogError::new("catalog.serialize", "$", "cannot serialize catalog"))
    }

    pub fn content_hash(&self) -> Result<String, CatalogError> {
        Ok(content_hash(
            b"agent-router:policy-catalog:v1\0",
            &self.canonical_json()?,
        ))
    }
}

fn content_hash(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
