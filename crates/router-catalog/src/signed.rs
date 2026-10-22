//! Authenticated publisher declarations, not runtime observations or execution grants.
//! Active projections require current external roots, clock and expected binding.
use crate::{AssetKind, AssetRegistry, Catalog, GenerationConfig, RegistryAsset};
use ed25519_dalek::{Signature, VerifyingKey};
use router_adapter_api::{content_digest, is_digest, strict_json, strict_json_limited};
use router_retrieval::{
    AssetMetadata, AssetSignals, Bm25Index, MetadataDocument, MetadataEnvelopeV3,
};
use router_types::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub const MAX_SIGNED_CATALOG_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SIGNED_ASSETS: usize = 512;
pub const MAX_SIGNED_VALIDITY_SECONDS: u64 = 366 * 86_400;

#[derive(Debug, thiserror::Error)]
pub enum SignedCatalogError {
    #[error("signed_catalog.invalid")]
    Invalid,
    #[error("signed_catalog.limit")]
    Limit,
    #[error("signed_catalog.integrity")]
    Integrity,
    #[error("signed_catalog.signature")]
    Signature,
    #[error("signed_catalog.authority")]
    Authority,
    #[error("signed_catalog.expired")]
    Expired,
    #[error("signed_catalog.stale")]
    Stale,
    #[error("signed_catalog.selection")]
    Selection,
    #[error("signed_catalog.projection")]
    Projection,
    #[error("signed_catalog.body")]
    Body,
}
type Result<T> = std::result::Result<T, SignedCatalogError>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogAssetKind {
    Model,
    Agent,
    Skill,
    Prompt,
    Tool,
    Host,
    Preset,
}
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAssetKey {
    pub kind: CatalogAssetKind,
    pub id: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAssetRequirements {
    pub capabilities: BTreeSet<Capability>,
    pub mutations: BTreeSet<Mutation>,
    pub tools: BTreeSet<String>,
    pub compatible_hosts: BTreeSet<AssetHostBinding>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAssetRestrictions {
    pub allowed_mutations: BTreeSet<Mutation>,
    pub allowed_sandboxes: BTreeSet<PhaseSandbox>,
    pub maximum_sensitivity: DataSensitivity,
}
/// Prompt bodies remain external; only a selected body can become a template.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPromptDefinition {
    pub variables: BTreeMap<String, PromptVariableType>,
    /// Harness IDs, not catalog asset IDs or host@version strings. This may
    /// narrow the entry's exact host/version requirements, never expand them.
    pub compatible_hosts: BTreeSet<String>,
    pub compatible_models: BTreeSet<ModelId>,
    pub max_rendered_bytes: usize,
    pub output_contract: String,
}
/// Declared compatibility only. This never constructs a HostObservation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHostDefinition {
    pub harness: HarnessId,
    pub versions: BTreeSet<String>,
    pub declared_capabilities: BTreeSet<Capability>,
    pub compatible_models: BTreeSet<ModelId>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPresetDefinition {
    pub preset: WorkflowPreset,
    pub max_width: usize,
    pub max_depth: usize,
    pub max_nodes: usize,
    pub reserve_cost_microusd: u64,
    pub reserve_tokens: u64,
    pub reserve_elapsed_ms: u64,
    pub maximum_budget: TaskBudget,
    pub allowed_capabilities: BTreeSet<Capability>,
    pub minimum_risk: RiskLevel,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "definition",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SignedAssetPayload {
    Model(ModelSpec),
    Agent(PhaseRegisteredAsset),
    Skill(SkillSpec),
    Prompt(SignedPromptDefinition),
    Tool(PhaseRegisteredAsset),
    Host(SignedHostDefinition),
    Preset(SignedPresetDefinition),
}
impl SignedAssetPayload {
    pub fn kind(&self) -> CatalogAssetKind {
        match self {
            Self::Model(_) => CatalogAssetKind::Model,
            Self::Agent(_) => CatalogAssetKind::Agent,
            Self::Skill(_) => CatalogAssetKind::Skill,
            Self::Prompt(_) => CatalogAssetKind::Prompt,
            Self::Tool(_) => CatalogAssetKind::Tool,
            Self::Host(_) => CatalogAssetKind::Host,
            Self::Preset(_) => CatalogAssetKind::Preset,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCatalogEntry {
    pub schema_version: u32,
    pub id: String,
    pub version: String,
    pub provenance: AssetSourceProvenance,
    /// Signed declaration, not a legal compatibility conclusion.
    pub license_expression: String,
    pub authors: Vec<String>,
    pub valid_from_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
    pub declared_trust: SkillTrust,
    pub capabilities: BTreeSet<Capability>,
    pub requirements: SignedAssetRequirements,
    pub restrictions: SignedAssetRestrictions,
    pub context_cost_estimate: u64,
    pub deprecated_by: Option<SignedAssetKey>,
    /// Canonical definition digest, distinct from the external body digest.
    pub payload_sha256: String,
    pub payload: SignedAssetPayload,
    pub search: Option<AssetMetadata>,
    pub signals: Option<AssetSignals>,
}
impl SignedCatalogEntry {
    pub fn key(&self) -> SignedAssetKey {
        SignedAssetKey {
            kind: self.payload.kind(),
            id: self.id.clone(),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCatalogManifest {
    pub schema_version: u32,
    pub id: String,
    pub version: String,
    pub valid_from_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
    pub assets: Vec<SignedCatalogEntry>,
    pub content_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogPublisherSignature {
    pub key_id: String,
    pub signature_hex: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCatalogDocument {
    pub schema_version: u32,
    pub manifest: SignedCatalogManifest,
    pub signature: CatalogPublisherSignature,
}
/// These grants must come from approved application configuration, never the
/// catalog itself. There is deliberately no Deserialize implementation.
#[derive(Clone, Debug)]
pub struct CatalogPublisherGrant {
    pub key_id: String,
    pub public_key: [u8; 32],
    pub catalog_ids: BTreeSet<String>,
    pub allowed_kinds: BTreeSet<CatalogAssetKind>,
    pub allowed_licenses: BTreeSet<String>,
    pub trust_ceiling: SkillTrust,
}
#[derive(Clone, Debug)]
pub struct TrustedCatalogPublishers {
    grants: BTreeMap<String, (CatalogPublisherGrant, VerifyingKey)>,
}
impl TrustedCatalogPublishers {
    pub fn new(grants: impl IntoIterator<Item = CatalogPublisherGrant>) -> Result<Self> {
        let mut output = BTreeMap::new();
        let mut physical = BTreeSet::new();
        for grant in grants {
            if output.len() >= 128
                || !label(&grant.key_id)
                || output.contains_key(&grant.key_id)
                || !physical.insert(grant.public_key)
                || grant.catalog_ids.is_empty()
                || grant.catalog_ids.len() > 128
                || grant.catalog_ids.iter().any(|v| !label(v))
                || grant.allowed_kinds.is_empty()
                || grant.allowed_licenses.is_empty()
                || grant.allowed_licenses.len() > 128
                || grant.allowed_licenses.iter().any(|v| !text(v, 256))
                || trust_rank(grant.trust_ceiling) <= 0
            {
                return Err(SignedCatalogError::Authority);
            }
            let key = VerifyingKey::from_bytes(&grant.public_key)
                .map_err(|_| SignedCatalogError::Signature)?;
            if key.is_weak() {
                return Err(SignedCatalogError::Signature);
            }
            output.insert(grant.key_id.clone(), (grant, key));
        }
        Ok(Self { grants: output })
    }
    pub fn fingerprint(&self) -> Result<String> {
        let values: Vec<_> = self
            .grants
            .values()
            .map(|(g, _)| {
                (
                    &g.key_id,
                    hex::encode(g.public_key),
                    &g.catalog_ids,
                    &g.allowed_kinds,
                    &g.allowed_licenses,
                    g.trust_ceiling,
                )
            })
            .collect();
        digest(b"agent-router:catalog-publishers:v1\0", &values)
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct QuarantinedCatalog {
    pub catalog_id: String,
    pub version: String,
    pub publisher_key_id: String,
    pub content_sha256: String,
    pub asset_count: usize,
    pub trust: SkillTrust,
    pub reason: &'static str,
}
#[derive(Clone, Debug)]
pub enum CatalogVerification {
    Verified(ValidatedSignedCatalog),
    Quarantined(QuarantinedCatalog),
}
/// Immutable authenticated content. It cannot be deserialized into authority.
#[derive(Clone, Debug)]
pub struct ValidatedSignedCatalog {
    document: SignedCatalogDocument,
    roots_hash: String,
    binding_hash: String,
    trust_ceiling: SkillTrust,
}
/// The expected binding belongs to the caller's current catalog selection. A
/// cache must not obtain this expected value from its own untrusted document.
pub struct CatalogAccess<'a> {
    pub publishers: &'a TrustedCatalogPublishers,
    pub now_unix_seconds: u64,
    pub expected_binding_hash: &'a str,
}
#[derive(Clone, Debug)]
pub struct SignedPlanProjection {
    plan: WorkflowPlan,
    catalog_hash: String,
    binding_hash: String,
    content_hash: String,
}
impl SignedPlanProjection {
    pub fn plan(&self) -> &WorkflowPlan {
        &self.plan
    }
    pub fn catalog_hash(&self) -> &str {
        &self.catalog_hash
    }
    pub fn catalog_binding_hash(&self) -> &str {
        &self.binding_hash
    }
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }
}

impl SignedCatalogDocument {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_SIGNED_CATALOG_BYTES {
            return Err(SignedCatalogError::Limit);
        }
        let value = strict_json_limited(bytes, MAX_SIGNED_CATALOG_BYTES)
            .map_err(|_| SignedCatalogError::Invalid)?;
        reject_duplicates(&value)?;
        let document: Self =
            serde_json::from_value(value.clone()).map_err(|_| SignedCatalogError::Invalid)?;
        reject_unknown(
            &value,
            &serde_json::to_value(&document).map_err(|_| SignedCatalogError::Invalid)?,
        )?;
        document.canonical()
    }
    fn canonical(&self) -> Result<Self> {
        if self.schema_version != 3
            || !label(&self.signature.key_id)
            || !hex_string(&self.signature.signature_hex, 128)
        {
            return Err(SignedCatalogError::Invalid);
        }
        let manifest = seal_signed_manifest(self.manifest.clone())?;
        if manifest != self.manifest {
            // Canonical ordering is harmless, but every recorded digest must
            // match the canonical payload; do not reseal changed content here.
            if manifest.content_sha256 != self.manifest.content_sha256
                || manifest.assets.iter().any(|e| {
                    self.manifest
                        .assets
                        .iter()
                        .find(|old| old.key() == e.key())
                        .is_none_or(|old| old.payload_sha256 != e.payload_sha256)
                })
            {
                return Err(SignedCatalogError::Integrity);
            }
        }
        let next = Self {
            schema_version: 3,
            manifest,
            signature: self.signature.clone(),
        };
        bounded_json(&next)?;
        Ok(next)
    }
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        bounded_json(&self.canonical()?)
    }
    pub fn verify(
        &self,
        publishers: &TrustedCatalogPublishers,
        now: u64,
    ) -> Result<CatalogVerification> {
        let document = self.canonical()?;
        validate_time(&document.manifest, now)?;
        let Some((grant, _)) = publishers.grants.get(&document.signature.key_id) else {
            return Ok(CatalogVerification::Quarantined(QuarantinedCatalog {
                catalog_id: document.manifest.id.clone(),
                version: document.manifest.version.clone(),
                publisher_key_id: document.signature.key_id.clone(),
                content_sha256: document.manifest.content_sha256.clone(),
                asset_count: document.manifest.assets.len(),
                trust: SkillTrust::Untrusted,
                reason: "publisher_key_not_approved",
            }));
        };
        verify_authority(&document, publishers)?;
        let roots_hash = publishers.fingerprint()?;
        let binding_hash = digest(
            b"agent-router:signed-catalog-binding:v1\0",
            &(&document, &roots_hash),
        )?;
        Ok(CatalogVerification::Verified(ValidatedSignedCatalog {
            document,
            roots_hash,
            binding_hash,
            trust_ceiling: grant.trust_ceiling,
        }))
    }
}
impl ValidatedSignedCatalog {
    pub fn from_json(
        bytes: &[u8],
        publishers: &TrustedCatalogPublishers,
        now: u64,
    ) -> Result<CatalogVerification> {
        SignedCatalogDocument::from_json(bytes)?.verify(publishers, now)
    }
    pub fn binding_hash(&self) -> &str {
        &self.binding_hash
    }
    pub fn content_hash(&self) -> &str {
        &self.document.manifest.content_sha256
    }
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        self.document.canonical_json()
    }
    pub fn validate_current(&self, access: &CatalogAccess<'_>) -> Result<()> {
        if access.expected_binding_hash != self.binding_hash {
            return Err(SignedCatalogError::Stale);
        }
        if access.publishers.fingerprint()? != self.roots_hash {
            return Err(SignedCatalogError::Authority);
        }
        validate_time(&self.document.manifest, access.now_unix_seconds)?;
        verify_authority(&self.document, access.publishers)
    }
    pub fn entries(&self, access: &CatalogAccess<'_>) -> Result<&[SignedCatalogEntry]> {
        self.validate_current(access)?;
        Ok(&self.document.manifest.assets)
    }
    fn trust(&self, entry: &SignedCatalogEntry) -> SkillTrust {
        if entry.deprecated_by.is_some() {
            SkillTrust::Blocked
        } else {
            clamp_trust(entry.declared_trust, self.trust_ceiling)
        }
    }
    fn selected(
        &self,
        key: &SignedAssetKey,
        access: &CatalogAccess<'_>,
    ) -> Result<&SignedCatalogEntry> {
        self.validate_current(access)?;
        self.document
            .manifest
            .assets
            .iter()
            .find(|e| e.key() == *key && trust_rank(self.trust(e)) > 0)
            .ok_or(SignedCatalogError::Selection)
    }
    /// Policy priors only. Native availability, permissions and advanced asset
    /// gates remain separate. Full catalog identity includes every asset/roots.
    pub fn catalog(&self, access: &CatalogAccess<'_>) -> Result<Catalog> {
        self.validate_current(access)?;
        let mut models = Vec::new();
        let mut skills = Vec::new();
        for entry in &self.document.manifest.assets {
            match &entry.payload {
                SignedAssetPayload::Model(value) if trust_rank(self.trust(entry)) > 0 => {
                    models.push(value.clone())
                }
                SignedAssetPayload::Skill(value) => {
                    let mut value = value.clone();
                    value.trust = self.trust(entry);
                    skills.push(value);
                }
                _ => {}
            }
        }
        let value = serde_json::json!({"schema_version":1,"version":format!("signed-v1:{}",self.binding_hash),"models":models,"skills":skills});
        Catalog::from_json(&bounded_json(&value)?).map_err(|_| SignedCatalogError::Projection)
    }
    pub fn retrieval(&self, access: &CatalogAccess<'_>) -> Result<MetadataEnvelopeV3> {
        let catalog = self.catalog(access)?;
        let mut assets = Vec::new();
        let mut signals = Vec::new();
        for entry in &self.document.manifest.assets {
            if let (Some(metadata), Some(signal)) = (&entry.search, &entry.signals) {
                let mut metadata = metadata.clone();
                metadata.trust = self.trust(entry);
                assets.push(metadata);
                signals.push(signal.clone());
            }
        }
        MetadataEnvelopeV3::new(
            MetadataDocument {
                schema_version: "1".into(),
                catalog_version: catalog.version().into(),
                assets,
            },
            signals,
            &catalog
                .content_hash()
                .map_err(|_| SignedCatalogError::Projection)?,
        )
        .map_err(|_| SignedCatalogError::Projection)
    }
    /// Availability/prior references only. This legacy DTO cannot carry the
    /// complete signed restrictions and is never signed execution authority.
    pub fn generation_config(&self, access: &CatalogAccess<'_>) -> Result<GenerationConfig> {
        self.validate_current(access)?;
        let mut assets = Vec::new();
        for entry in &self.document.manifest.assets {
            let kind = match entry.payload.kind() {
                CatalogAssetKind::Model => continue,
                CatalogAssetKind::Agent => AssetKind::Agent,
                CatalogAssetKind::Skill => AssetKind::Skill,
                CatalogAssetKind::Prompt => AssetKind::Prompt,
                CatalogAssetKind::Tool => AssetKind::Tool,
                _ => continue,
            };
            if trust_rank(self.trust(entry)) <= 0 {
                continue;
            }
            assets.push(RegistryAsset {
                kind,
                id: entry.id.clone(),
                version: entry.version.clone(),
                source: entry.provenance.source.clone(),
                content_sha256: match &entry.payload {
                    SignedAssetPayload::Agent(value) | SignedAssetPayload::Tool(value) => {
                        value.content_sha256.clone()
                    }
                    _ => entry
                        .search
                        .as_ref()
                        .and_then(|m| m.body.as_ref())
                        .map_or_else(|| entry.payload_sha256.clone(), |body| body.sha256.clone()),
                },
                required_capabilities: entry.requirements.capabilities.clone(),
                deprecated_by: None,
            });
        }
        Ok(GenerationConfig {
            aliases: vec![],
            registry: AssetRegistry {
                schema_version: 1,
                version: format!("signed-v1:{}", self.binding_hash),
                assets,
            },
        })
    }
    /// A matching catalog digest alone does not authenticate an index. Compare
    /// the complete derived metadata/signals against this signed declaration.
    pub fn validate_retrieval(&self, index: &Bm25Index, access: &CatalogAccess<'_>) -> Result<()> {
        let expected = Bm25Index::build_v3(self.retrieval(access)?)
            .map_err(|_| SignedCatalogError::Projection)?;
        if index.source_hash() != expected.source_hash()
            || index.index_hash() != expected.index_hash()
        {
            return Err(SignedCatalogError::Integrity);
        }
        Ok(())
    }
    /// Permission comes exclusively from the supplied parent map, never a publisher.
    /// Refuse mutation ceilings: the legacy registry can represent requirements,
    /// sandbox and sensitivity constraints, but no upper mutation bound.
    pub fn phase_registry(
        &self,
        access: &CatalogAccess<'_>,
        host: &AssetHostBinding,
        permissions: &BTreeMap<SignedAssetKey, CapabilitySupport>,
    ) -> Result<PhaseAssetRegistry> {
        self.validate_current(access)?;
        if !self.declared_host(host)
            || permissions.len() > MAX_SIGNED_ASSETS
            || permissions.keys().any(|key| {
                !self.document.manifest.assets.iter().any(|entry| {
                    entry.key() == *key
                        && matches!(key.kind, CatalogAssetKind::Agent | CatalogAssetKind::Tool)
                })
            })
        {
            return Err(SignedCatalogError::Authority);
        }
        let mut assets = Vec::new();
        for entry in &self.document.manifest.assets {
            if trust_rank(self.trust(entry)) <= 0
                || !entry.requirements.compatible_hosts.contains(host)
            {
                continue;
            }
            if let SignedAssetPayload::Agent(value) | SignedAssetPayload::Tool(value) =
                &entry.payload
            {
                if !entry.requirements.tools.is_empty()
                    || entry.restrictions.allowed_mutations
                        != BTreeSet::from([
                            Mutation::WorkspaceWrite,
                            Mutation::Network,
                            Mutation::ExecuteSkills,
                            Mutation::Integrate,
                        ])
                {
                    return Err(SignedCatalogError::Projection);
                }
                let mut value = value.clone();
                value.trust = self.trust(entry);
                value.permission = permissions
                    .get(&entry.key())
                    .copied()
                    .unwrap_or(CapabilitySupport::Unknown);
                assets.push(value);
            }
        }
        Ok(PhaseAssetRegistry {
            schema_version: 1,
            version: format!("signed-v1:{}", self.binding_hash),
            assets,
        })
    }
    fn declared_host(&self, host: &AssetHostBinding) -> bool {
        self.document.manifest.assets.iter().any(|entry| trust_rank(self.trust(entry)) > 0 && matches!(&entry.payload, SignedAssetPayload::Host(definition) if definition.harness == host.harness && definition.versions.contains(&host.version)))
    }
    pub fn host(&self, id: &str, access: &CatalogAccess<'_>) -> Result<&SignedHostDefinition> {
        match &self
            .selected(
                &SignedAssetKey {
                    kind: CatalogAssetKind::Host,
                    id: id.into(),
                },
                access,
            )?
            .payload
        {
            SignedAssetPayload::Host(value) => Ok(value),
            _ => Err(SignedCatalogError::Selection),
        }
    }
    pub fn preset(&self, id: &str, access: &CatalogAccess<'_>) -> Result<&SignedPresetDefinition> {
        match &self
            .selected(
                &SignedAssetKey {
                    kind: CatalogAssetKind::Preset,
                    id: id.into(),
                },
                access,
            )?
            .payload
        {
            SignedAssetPayload::Preset(value) => Ok(value),
            _ => Err(SignedCatalogError::Selection),
        }
    }
    pub fn build_plan(
        &self,
        id: &str,
        task: &NormalizedTask,
        host: &AssetHostBinding,
        access: &CatalogAccess<'_>,
    ) -> Result<SignedPlanProjection> {
        let entry = self.selected(
            &SignedAssetKey {
                kind: CatalogAssetKind::Preset,
                id: id.into(),
            },
            access,
        )?;
        let preset = self.preset(id, access)?;
        if !self.document.manifest.assets.iter().any(|entry| trust_rank(self.trust(entry)) > 0 && matches!(&entry.payload, SignedAssetPayload::Host(definition) if definition.harness == host.harness && definition.versions.contains(&host.version)))
            || !entry.requirements.compatible_hosts.contains(host)
            || !entry.requirements.tools.is_empty()
            || sensitivity(task.sensitivity) > sensitivity(entry.restrictions.maximum_sensitivity)
        {
            return Err(SignedCatalogError::Authority);
        }
        let mut task = task.clone();
        task.allowed_mutations = task
            .allowed_mutations
            .intersection(&entry.restrictions.allowed_mutations)
            .copied()
            .collect();
        task.required_capabilities
            .extend(&entry.requirements.capabilities);
        if !task
            .required_capabilities
            .is_subset(&preset.allowed_capabilities)
            || !entry
                .requirements
                .mutations
                .is_subset(&task.allowed_mutations)
            || (task.required_capabilities.contains(&Capability::Network)
                && !task.allowed_mutations.contains(&Mutation::Network))
            || (task
                .required_capabilities
                .contains(&Capability::WorkspaceWrite)
                && !task.allowed_mutations.contains(&Mutation::WorkspaceWrite))
        {
            return Err(SignedCatalogError::Authority);
        }
        task.risk = task.risk.max(preset.minimum_risk);
        task.budget.max_cost_microusd = task
            .budget
            .max_cost_microusd
            .min(preset.maximum_budget.max_cost_microusd);
        task.budget.max_tokens = task.budget.max_tokens.min(preset.maximum_budget.max_tokens);
        task.budget.max_elapsed_ms = task
            .budget
            .max_elapsed_ms
            .min(preset.maximum_budget.max_elapsed_ms);
        let plan = router_workflow::build_plan(
            &task,
            preset.preset,
            router_workflow::PlanLimits {
                max_depth: preset.max_depth,
                max_width: preset.max_width,
                max_nodes: preset.max_nodes,
                reserve_cost_microusd: preset.reserve_cost_microusd,
                reserve_tokens: preset.reserve_tokens,
                reserve_elapsed_ms: preset.reserve_elapsed_ms,
            },
        )
        .map_err(|_| SignedCatalogError::Projection)?;
        if plan.nodes.iter().any(|node| {
            !entry
                .restrictions
                .allowed_sandboxes
                .contains(&match node.mode {
                    NodeMode::ReadOnly => PhaseSandbox::ReadOnly,
                    NodeMode::IsolatedWrite => PhaseSandbox::WorkspaceWrite,
                })
        }) {
            return Err(SignedCatalogError::Authority);
        }
        let catalog_hash = self
            .catalog(access)?
            .content_hash()
            .map_err(|_| SignedCatalogError::Projection)?;
        let content_hash = digest(
            b"agent-router:signed-preset-plan:v1\0",
            &(&self.binding_hash, &entry.id, &entry.payload_sha256, &plan),
        )?;
        Ok(SignedPlanProjection {
            plan,
            catalog_hash,
            binding_hash: self.binding_hash.clone(),
            content_hash,
        })
    }
    pub fn validate_selected_body(
        &self,
        key: &SignedAssetKey,
        bytes: &[u8],
        access: &CatalogAccess<'_>,
    ) -> Result<()> {
        let entry = self.selected(key, access)?;
        if bytes.len() > router_retrieval::MAX_BODY_BYTES {
            return Err(SignedCatalogError::Limit);
        }
        let body = entry
            .search
            .as_ref()
            .and_then(|metadata| metadata.body.as_ref())
            .ok_or(SignedCatalogError::Body)?;
        if content_digest(bytes) != body.sha256 {
            return Err(SignedCatalogError::Body);
        }
        Ok(())
    }
    pub fn load_selected_body(
        &self,
        key: &SignedAssetKey,
        root: &Path,
        access: &CatalogAccess<'_>,
    ) -> Result<Vec<u8>> {
        self.selected(key, access)?;
        let metadata = self.retrieval(access)?;
        let hash = metadata.catalog_content_sha256.clone();
        let index = Bm25Index::build_v3(metadata).map_err(|_| SignedCatalogError::Projection)?;
        index
            .load_body_with_catalog(
                root,
                retrieval_kind(key.kind).ok_or(SignedCatalogError::Body)?,
                &key.id,
                &hash,
            )
            .map(|body| body.text.into_bytes())
            .map_err(|_| SignedCatalogError::Body)
    }
    pub fn validate_prompt(
        &self,
        id: &str,
        bytes: &[u8],
        access: &CatalogAccess<'_>,
    ) -> Result<PromptTemplate> {
        let key = SignedAssetKey {
            kind: CatalogAssetKind::Prompt,
            id: id.into(),
        };
        self.validate_selected_body(&key, bytes, access)?;
        let entry = self.selected(&key, access)?;
        let SignedAssetPayload::Prompt(definition) = &entry.payload else {
            return Err(SignedCatalogError::Selection);
        };
        let value = strict_json(bytes).map_err(|_| SignedCatalogError::Body)?;
        let template: PromptTemplate =
            serde_json::from_value(value).map_err(|_| SignedCatalogError::Body)?;
        if template.id != id
            || template.version != entry.version
            || template.variables != definition.variables
            || template.compatible_hosts != definition.compatible_hosts
            || template.compatible_models != definition.compatible_models
            || template.max_rendered_bytes != definition.max_rendered_bytes
            || template.output_contract != definition.output_contract
            || router_workflow::seal_prompt(template.clone())
                .map_err(|_| SignedCatalogError::Body)?
                != template
        {
            return Err(SignedCatalogError::Body);
        }
        Ok(template)
    }
}

/// Canonicalize and hash a candidate manifest. This never signs or trusts it.
pub fn seal_signed_manifest(mut manifest: SignedCatalogManifest) -> Result<SignedCatalogManifest> {
    if manifest.schema_version != 1
        || !label(&manifest.id)
        || !text(&manifest.version, 128)
        || manifest.assets.is_empty()
        || manifest.assets.len() > MAX_SIGNED_ASSETS
    {
        return Err(SignedCatalogError::Invalid);
    }
    interval(
        manifest.valid_from_unix_seconds,
        manifest.valid_until_unix_seconds,
    )?;
    manifest.assets.sort_by_key(SignedCatalogEntry::key);
    let mut keys = BTreeSet::new();
    let mut metadata = Vec::new();
    let mut signals = Vec::new();
    for entry in &mut manifest.assets {
        if !keys.insert(entry.key()) {
            return Err(SignedCatalogError::Invalid);
        }
        entry.authors.sort();
        if entry.schema_version != 1
            || !label(&entry.id)
            || !text(&entry.version, 128)
            || !public_source(&entry.provenance.source)
            || !label(&entry.provenance.revision)
            || !is_digest(&entry.provenance.source_sha256)
            || !text(&entry.license_expression, 256)
            || entry.authors.is_empty()
            || entry.authors.len() > 16
            || entry.authors.iter().any(|v| !text(v, 128))
            || entry.authors.windows(2).any(|p| p[0] == p[1])
            || entry.context_cost_estimate > 1_000_000
            || entry.requirements.tools.len() > 32
            || entry.requirements.tools.iter().any(|v| !label(v))
            || entry.requirements.compatible_hosts.len() > 32
            || entry
                .requirements
                .compatible_hosts
                .iter()
                .any(|h| !label(h.harness.as_str()) || !text(&h.version, 128))
            || entry.restrictions.allowed_sandboxes.is_empty()
            || !entry
                .requirements
                .mutations
                .is_subset(&entry.restrictions.allowed_mutations)
        {
            return Err(SignedCatalogError::Invalid);
        }
        interval(
            entry.valid_from_unix_seconds,
            entry.valid_until_unix_seconds,
        )?;
        if entry.valid_from_unix_seconds < manifest.valid_from_unix_seconds
            || entry.valid_until_unix_seconds > manifest.valid_until_unix_seconds
        {
            return Err(SignedCatalogError::Invalid);
        }
        validate_payload(entry)?;
        match (
            retrieval_kind(entry.payload.kind()),
            &entry.search,
            &entry.signals,
        ) {
            (Some(kind), Some(search), Some(signal))
                if search.kind == kind
                    && search.id == entry.id
                    && search.trust == entry.declared_trust
                    && signal.asset == search.key() =>
            {
                if let router_retrieval::Signal::Observed { value, .. } = &signal.required_tools {
                    if value.iter().collect::<BTreeSet<_>>()
                        != entry.requirements.tools.iter().collect::<BTreeSet<_>>()
                    {
                        return Err(SignedCatalogError::Invalid);
                    }
                }
                metadata.push(search.clone());
                signals.push(signal.clone());
            }
            (None, None, None) => {}
            _ => return Err(SignedCatalogError::Invalid),
        }
        entry.payload_sha256 = digest(b"agent-router:signed-asset-payload:v1\0", &entry.payload)?;
    }
    let mut edges = BTreeMap::new();
    for entry in &manifest.assets {
        if let Some(next) = &entry.deprecated_by {
            if next.kind != entry.payload.kind() || next == &entry.key() || !keys.contains(next) {
                return Err(SignedCatalogError::Invalid);
            }
        }
        edges.insert(entry.key(), entry.deprecated_by.clone());
    }
    deprecation_walk(&edges)?;
    let model_ids: BTreeSet<_> = manifest
        .assets
        .iter()
        .filter_map(|entry| match &entry.payload {
            SignedAssetPayload::Model(model) => Some(model.id.clone()),
            _ => None,
        })
        .collect();
    if model_ids.len() > crate::MAX_CATALOG_MODELS
        || manifest
            .assets
            .iter()
            .filter(|e| matches!(e.payload, SignedAssetPayload::Skill(_)))
            .count()
            > crate::MAX_CATALOG_SKILLS
    {
        return Err(SignedCatalogError::Limit);
    }
    for entry in &manifest.assets {
        for required in &entry.requirements.compatible_hosts {
            if !manifest.assets.iter().any(|host| matches!(&host.payload, SignedAssetPayload::Host(definition) if definition.harness == required.harness && definition.versions.contains(&required.version))) {
                return Err(SignedCatalogError::Invalid);
            }
        }
        if let SignedAssetPayload::Prompt(prompt) = &entry.payload {
            // Exact version pins above resolve against Host definitions. A
            // template's unversioned harness list is only a further restriction;
            // a matching Host asset elsewhere cannot grant an unpinned harness.
            if prompt.compatible_hosts.iter().any(|harness| {
                !entry
                    .requirements
                    .compatible_hosts
                    .iter()
                    .any(|required| required.harness.as_str() == harness)
            }) {
                return Err(SignedCatalogError::Invalid);
            }
        }
        // Models resolve by Model payload ID, never by a similarly named asset
        // of another kind. These declarations provide no runtime availability.
        let references = match &entry.payload {
            SignedAssetPayload::Host(value) => Some(&value.compatible_models),
            SignedAssetPayload::Prompt(value) => Some(&value.compatible_models),
            _ => None,
        };
        if references.is_some_and(|references| !references.is_subset(&model_ids)) {
            return Err(SignedCatalogError::Invalid);
        }
    }
    // Reuse exact retrieval validators/canonicalization, without reading bodies.
    let envelope = MetadataEnvelopeV3::new(
        MetadataDocument {
            schema_version: "1".into(),
            catalog_version: manifest.version.clone(),
            assets: metadata,
        },
        signals,
        &"0".repeat(64),
    )
    .map_err(|_| SignedCatalogError::Invalid)?;
    Bm25Index::build_v3(envelope.clone()).map_err(|_| SignedCatalogError::Limit)?;
    for entry in &mut manifest.assets {
        if let Some(kind) = retrieval_kind(entry.payload.kind()) {
            entry.search = envelope
                .metadata
                .assets
                .iter()
                .find(|m| m.kind == kind && m.id == entry.id)
                .cloned();
            entry.signals = envelope
                .signals
                .iter()
                .find(|s| s.asset.kind == kind && s.asset.id == entry.id)
                .cloned();
        }
    }
    manifest.content_sha256.clear();
    manifest.content_sha256 = digest(b"agent-router:signed-catalog-manifest:v1\0", &manifest)?;
    bounded_json(&manifest)?;
    Ok(manifest)
}
pub fn catalog_signing_message(key_id: &str, manifest: &SignedCatalogManifest) -> Result<Vec<u8>> {
    if !label(key_id) {
        return Err(SignedCatalogError::Invalid);
    }
    let canonical = seal_signed_manifest(manifest.clone())?;
    if canonical.content_sha256 != manifest.content_sha256 {
        return Err(SignedCatalogError::Integrity);
    }
    let mut message = b"agent-router:catalog-publisher-signature:v1\0".to_vec();
    message.extend(bounded_json(&(key_id, canonical))?);
    Ok(message)
}
fn verify_authority(
    document: &SignedCatalogDocument,
    publishers: &TrustedCatalogPublishers,
) -> Result<()> {
    let (grant, key) = publishers
        .grants
        .get(&document.signature.key_id)
        .ok_or(SignedCatalogError::Authority)?;
    if !grant.catalog_ids.contains(&document.manifest.id)
        || document.manifest.assets.iter().any(|e| {
            !grant.allowed_kinds.contains(&e.payload.kind())
                || !grant.allowed_licenses.contains(&e.license_expression)
        })
    {
        return Err(SignedCatalogError::Authority);
    }
    let signature = hex::decode(&document.signature.signature_hex)
        .map_err(|_| SignedCatalogError::Signature)?;
    let signature = Signature::from_slice(&signature).map_err(|_| SignedCatalogError::Signature)?;
    key.verify_strict(
        &catalog_signing_message(&document.signature.key_id, &document.manifest)?,
        &signature,
    )
    .map_err(|_| SignedCatalogError::Signature)
}
fn validate_time(manifest: &SignedCatalogManifest, now: u64) -> Result<()> {
    if now < manifest.valid_from_unix_seconds
        || now >= manifest.valid_until_unix_seconds
        || manifest
            .assets
            .iter()
            .any(|e| now < e.valid_from_unix_seconds || now >= e.valid_until_unix_seconds)
    {
        return Err(SignedCatalogError::Expired);
    }
    Ok(())
}
fn validate_payload(entry: &SignedCatalogEntry) -> Result<()> {
    let body = entry.search.as_ref().and_then(|m| m.body.as_ref());
    match &entry.payload {
        SignedAssetPayload::Model(model) => {
            if model.id.as_str() != entry.id
                || model.capabilities != entry.capabilities
                || model.source != entry.provenance.source
                || body.is_some()
            {
                return Err(SignedCatalogError::Invalid);
            }
            let value = serde_json::json!({"schema_version":1,"version":"signed-validation","models":[model],"skills":[]});
            Catalog::from_json(&bounded_json(&value)?).map_err(|_| SignedCatalogError::Invalid)?;
        }
        SignedAssetPayload::Skill(skill) => {
            if skill.id.as_str() != entry.id
                || skill.trust != entry.declared_trust
                || skill.required_capabilities != entry.requirements.capabilities
                || !text(&skill.description, 8192)
                || body.is_none()
            {
                return Err(SignedCatalogError::Invalid);
            }
        }
        SignedAssetPayload::Agent(value) | SignedAssetPayload::Tool(value) => {
            if value.id != entry.id
                || value.trust != entry.declared_trust
                || value.license != entry.license_expression
                || value.permission != CapabilitySupport::Unknown
                || value.required_capabilities != entry.requirements.capabilities
                || value.required_mutations != entry.requirements.mutations
                || value.allowed_sandboxes != entry.restrictions.allowed_sandboxes
                || value.maximum_sensitivity != entry.restrictions.maximum_sensitivity
                || !is_digest(&value.content_sha256)
                || (matches!(entry.payload, SignedAssetPayload::Agent(_))
                    && value.kind != PhaseAssetKind::Agent)
                || (matches!(entry.payload, SignedAssetPayload::Tool(_))
                    && value.kind != PhaseAssetKind::Tool)
                || body.is_some_and(|body| body.sha256 != value.content_sha256)
            {
                return Err(SignedCatalogError::Invalid);
            }
        }
        SignedAssetPayload::Prompt(value) => {
            if body.is_none()
                || value.variables.len() > 32
                || value.variables.keys().any(|v| {
                    v.is_empty()
                        || v.len() > 64
                        || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                })
                || value.compatible_hosts.is_empty()
                || value.compatible_hosts.len() > 32
                || value.compatible_hosts.iter().any(|v| !label(v))
                || value.compatible_models.is_empty()
                || value.compatible_models.len() > 64
                || value.compatible_models.iter().any(|id| !label(id.as_str()))
                || value.max_rendered_bytes == 0
                || value.max_rendered_bytes > router_retrieval::MAX_BODY_BYTES
                || !text(&value.output_contract, 8192)
            {
                return Err(SignedCatalogError::Invalid);
            }
        }
        SignedAssetPayload::Host(value) => {
            if !label(value.harness.as_str())
                || value.versions.is_empty()
                || value.versions.len() > 64
                || value.versions.iter().any(|v| !text(v, 128))
                || value.declared_capabilities != entry.capabilities
                || value.compatible_models.len() > 64
                || value.compatible_models.iter().any(|id| !label(id.as_str()))
            {
                return Err(SignedCatalogError::Invalid);
            }
        }
        SignedAssetPayload::Preset(value) => {
            if value.max_width == 0
                || value.max_width > 16
                || value.max_depth == 0
                || value.max_depth > 32
                || value.max_nodes == 0
                || value.max_nodes > 64
                || value.maximum_budget.max_tokens == 0
                || value.maximum_budget.max_elapsed_ms == 0
                || value.reserve_tokens == 0
                || value.reserve_elapsed_ms == 0
                || !entry
                    .requirements
                    .capabilities
                    .is_subset(&value.allowed_capabilities)
            {
                return Err(SignedCatalogError::Invalid);
            }
        }
    }
    Ok(())
}
fn retrieval_kind(kind: CatalogAssetKind) -> Option<router_retrieval::AssetKind> {
    use router_retrieval::AssetKind as R;
    match kind {
        CatalogAssetKind::Model => Some(R::Model),
        CatalogAssetKind::Agent => Some(R::Agent),
        CatalogAssetKind::Skill => Some(R::Skill),
        CatalogAssetKind::Prompt => Some(R::Prompt),
        CatalogAssetKind::Tool => Some(R::Tool),
        _ => None,
    }
}
fn interval(from: u64, until: u64) -> Result<()> {
    if from >= until || until - from > MAX_SIGNED_VALIDITY_SECONDS {
        Err(SignedCatalogError::Invalid)
    } else {
        Ok(())
    }
}
fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
}
fn text(value: &str, limit: usize) -> bool {
    !value.trim().is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}
/// Provenance locator accepted by the signed verifier: a public `https://` URL
/// or a bare identifier, never a local path, credential, loopback, private or
/// link-local host.
pub fn public_source(value: &str) -> bool {
    if !text(value, 512) || value.contains(['@', '?', '#', '\\']) {
        return false;
    }
    if let Some(rest) = value.strip_prefix("https://") {
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        return public_authority(authority) && public_path(path);
    }
    let bytes = value.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}
fn public_authority(value: &str) -> bool {
    let (host, port) = match value.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (value, None),
    };
    !host.is_empty()
        && !local_host(host)
        && host.bytes().any(|b| b != b'.')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        && port.is_none_or(|port| {
            (1..=5).contains(&port.len())
                && port.bytes().all(|b| b.is_ascii_digit())
                && port.parse::<u32>().is_ok_and(|p| (1..=65535).contains(&p))
        })
}
/// Loopback, private, link-local and otherwise non-public hosts. A host whose
/// last label looks numeric must be a strict decimal dotted quad, so the
/// integer and hexadecimal spellings of an address cannot bypass the ranges.
fn local_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    let name = lower.trim_end_matches('.');
    if name == "localhost" || name.ends_with(".localhost") || name.ends_with(".local") {
        return true;
    }
    let last = name.rsplit('.').next().unwrap_or("");
    if !last.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
        return false;
    }
    let octets: Vec<Option<u8>> = name
        .split('.')
        .map(|part| {
            (!part.is_empty()
                && part.len() <= 3
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0')))
            .then(|| part.parse().ok())
            .flatten()
        })
        .collect();
    let [Some(a), Some(b), Some(_), Some(_)] = octets[..] else {
        return true;
    };
    a == 0
        || a == 10
        || a == 127
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 100 && (64..=127).contains(&b))
        || a >= 224
}
/// Empty segments are refused except one trailing slash.
fn public_path(path: &str) -> bool {
    let mut segments: Vec<&str> = path.split('/').collect();
    if segments.len() > 1 && segments.last() == Some(&"") {
        segments.pop();
    }
    path.is_empty()
        || segments.iter().all(|s| {
            !s.is_empty()
                && *s != "."
                && *s != ".."
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
        })
}
fn hex_string(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn trust_rank(value: SkillTrust) -> i8 {
    match value {
        SkillTrust::Blocked => -1,
        SkillTrust::Untrusted => 0,
        SkillTrust::VerifiedThirdParty => 1,
        SkillTrust::TrustedLocal => 2,
        SkillTrust::Builtin => 3,
    }
}
fn clamp_trust(value: SkillTrust, ceiling: SkillTrust) -> SkillTrust {
    if trust_rank(value) > trust_rank(ceiling) {
        ceiling
    } else {
        value
    }
}
fn sensitivity(value: DataSensitivity) -> u8 {
    match value {
        DataSensitivity::Public => 0,
        DataSensitivity::Internal => 1,
        DataSensitivity::Secret => 2,
    }
}
fn bounded_json(value: &impl Serialize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| SignedCatalogError::Invalid)?;
    if bytes.len() > MAX_SIGNED_CATALOG_BYTES {
        Err(SignedCatalogError::Limit)
    } else {
        Ok(bytes)
    }
}
fn digest(domain: &[u8], value: &impl Serialize) -> Result<String> {
    Ok(crate::content_hash(domain, &bounded_json(value)?))
}
/// Rejects `deprecated_by` cycles. Every chain is walked once: a node already
/// proven acyclic ends the walk, so total work is linear in the entry count.
/// Returns the number of edge traversals so a test can bound the work.
fn deprecation_walk(edges: &BTreeMap<SignedAssetKey, Option<SignedAssetKey>>) -> Result<usize> {
    let mut acyclic: BTreeSet<&SignedAssetKey> = BTreeSet::new();
    let mut steps = 0;
    for start in edges.keys() {
        let mut path: BTreeSet<&SignedAssetKey> = BTreeSet::new();
        let mut cursor = Some(start);
        while let Some(key) = cursor {
            if acyclic.contains(key) {
                break;
            }
            if !path.insert(key) {
                return Err(SignedCatalogError::Invalid);
            }
            steps += 1;
            cursor = edges.get(key).and_then(Option::as_ref);
        }
        acyclic.extend(path);
    }
    Ok(steps)
}
fn reject_duplicates(value: &serde_json::Value) -> Result<()> {
    router_adapter_api::reject_duplicate_elements(value).map_err(|_| SignedCatalogError::Invalid)
}
fn reject_unknown(input: &serde_json::Value, typed: &serde_json::Value) -> Result<()> {
    match (input, typed) {
        (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
            for (key, value) in a {
                reject_unknown(value, b.get(key).ok_or(SignedCatalogError::Invalid)?)?;
            }
        }
        (serde_json::Value::Array(a), serde_json::Value::Array(b)) => {
            for (a, b) in a.iter().zip(b) {
                reject_unknown(a, b)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod duplicate_tests {
    use super::*;

    fn deep_chain(depth: usize, leaf_items: usize) -> serde_json::Value {
        let leaf: Vec<serde_json::Value> = (0..leaf_items)
            .map(|i| serde_json::Value::String(format!("{i:0>1000}")))
            .collect();
        let mut value = serde_json::Value::Array(leaf);
        for _ in 0..depth {
            value = serde_json::Value::Array(vec![value]);
        }
        value
    }

    #[test]
    fn duplicate_detection_is_linear_on_deep_single_element_chains() {
        // About 3.6 MB of leaf text under 120 single-element arrays. Serializing
        // every element at every level would cost roughly 430 MB of work.
        let value = deep_chain(120, 3_600);
        let started = std::time::Instant::now();
        assert!(reject_duplicates(&value).is_ok());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "duplicate detection took {:?}",
            started.elapsed()
        );
    }

    fn key(index: usize) -> SignedAssetKey {
        SignedAssetKey {
            kind: CatalogAssetKind::Skill,
            id: format!("skill-{index}"),
        }
    }

    #[test]
    fn deprecation_walk_is_linear_on_a_512_entry_chain() {
        let mut edges = BTreeMap::new();
        for index in 0..512 {
            edges.insert(key(index), (index + 1 < 512).then(|| key(index + 1)));
        }
        let steps = deprecation_walk(&edges).expect("acyclic chain");
        assert!(steps <= 512, "walked {steps} edges for 512 entries");
    }

    #[test]
    fn deprecation_walk_rejects_a_cycle_and_a_late_cycle() {
        let mut edges = BTreeMap::new();
        for index in 0..512 {
            edges.insert(key(index), Some(key((index + 1) % 512)));
        }
        assert!(matches!(
            deprecation_walk(&edges),
            Err(SignedCatalogError::Invalid)
        ));
        let mut tail = BTreeMap::new();
        tail.insert(key(0), Some(key(1)));
        tail.insert(key(1), Some(key(2)));
        tail.insert(key(2), Some(key(1)));
        assert!(matches!(
            deprecation_walk(&tail),
            Err(SignedCatalogError::Invalid)
        ));
    }

    #[test]
    fn duplicates_are_still_found_at_every_depth() {
        let repeated = serde_json::json!({"a": [[1], [1]]});
        assert!(matches!(
            reject_duplicates(&repeated),
            Err(SignedCatalogError::Invalid)
        ));
        let reordered = serde_json::json!({"a": [[1, 2], [2, 1]], "b": [{"x": 1}, {"x": 1.0}]});
        assert!(reject_duplicates(&reordered).is_ok());
        let objects = serde_json::json!([{"k": [1, {"z": 0}]}, {"k": [1, {"z": 0}]}]);
        assert!(matches!(
            reject_duplicates(&objects),
            Err(SignedCatalogError::Invalid)
        ));
    }
}
