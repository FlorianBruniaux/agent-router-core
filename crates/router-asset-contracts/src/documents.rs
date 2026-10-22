use crate::*;
use router_adapter_api::{ValidatedHostObservation, strict_json};
use router_catalog::Catalog;
use router_types::*;
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct ValidatedContracts {
    document: AssetContractsDocument,
    model_capabilities: BTreeMap<ModelId, BTreeSet<Capability>>,
}
impl ValidatedContracts {
    /// `expected_hash` must be pinned by the parent independently of `bytes`.
    /// Validation does not authenticate a source or grant execution authority.
    pub fn from_json(bytes: &[u8], catalog: &Catalog, expected_hash: &str) -> Result<Self> {
        let document: AssetContractsDocument = parse(bytes)?;
        let canonical = seal_contracts(document.clone(), catalog)?;
        valid_root(&document.content_hash, &canonical.content_hash)?;
        valid_root(expected_hash, &canonical.content_hash)?;
        let model_capabilities = catalog
            .models()
            .map(|(id, model)| (id.clone(), model.capabilities.clone()))
            .collect();
        Ok(Self {
            document: canonical,
            model_capabilities,
        })
    }
    pub fn hash(&self) -> &str {
        &self.document.content_hash
    }
    pub fn catalog_hash(&self) -> &str {
        &self.document.catalog_hash
    }
    pub fn document(&self) -> &AssetContractsDocument {
        &self.document
    }
    pub fn model(&self, id: &ModelId) -> Option<&ModelAssetContract> {
        self.document.models.iter().find(|v| &v.model == id)
    }
    pub fn skill(&self, id: &SkillId) -> Option<&SkillAssetManifest> {
        self.document.skills.iter().find(|v| &v.skill == id)
    }
    pub(crate) fn model_capabilities(&self, id: &ModelId) -> Option<&BTreeSet<Capability>> {
        self.model_capabilities.get(id)
    }
}

#[derive(Clone, Debug)]
pub struct ValidatedAvailability {
    document: AssetAvailabilityDocument,
    snapshot: ValidatedHostObservation,
}
impl ValidatedAvailability {
    pub fn from_json(
        bytes: &[u8],
        snapshot: &ValidatedHostObservation,
        expected_hash: &str,
        now: u64,
    ) -> Result<Self> {
        let document: AssetAvailabilityDocument = parse(bytes)?;
        let canonical = seal_availability(document.clone(), snapshot)?;
        valid_root(&document.content_hash, &canonical.content_hash)?;
        valid_root(expected_hash, &canonical.content_hash)?;
        let result = Self {
            document: canonical,
            snapshot: snapshot.clone(),
        };
        result.check_fresh(now, MAX_EVIDENCE_AGE_SECONDS)?;
        Ok(result)
    }
    pub fn hash(&self) -> &str {
        &self.document.content_hash
    }
    pub fn snapshot_hash(&self) -> &str {
        &self.document.snapshot_hash
    }
    pub fn document(&self) -> &AssetAvailabilityDocument {
        &self.document
    }
    pub fn snapshot(&self) -> &ValidatedHostObservation {
        &self.snapshot
    }
    pub fn binding(&self, request: &AssetGateRequest) -> Option<&ModelAssetAvailability> {
        self.document.bindings.iter().find(|v| {
            v.model == request.model && v.provider == request.provider && v.host == request.host
        })
    }
    pub(crate) fn check_fresh(&self, now: u64, max_age: u64) -> Result<()> {
        let fresh = |time| time <= now && now - time <= max_age;
        if now >= self.document.expires_at_unix_seconds
            || !fresh(self.document.observed_at_unix_seconds)
            || !fresh(self.snapshot.observation().observed_at_unix_seconds)
            || self
                .document
                .evidence
                .iter()
                .any(|e| !fresh(e.observed_at_unix_seconds))
            || self
                .snapshot
                .observation()
                .evidence
                .iter()
                .any(|e| !fresh(e.observed_at_unix_seconds))
        {
            return Err(excluded(GateCode::EvidenceStale));
        }
        Ok(())
    }
}

/// Producer operation only: recomputing this hash is not source authentication.
pub fn seal_contracts(
    mut document: AssetContractsDocument,
    catalog: &Catalog,
) -> Result<AssetContractsDocument> {
    require(
        document.schema_version == 1 && document.models.len() <= 64 && document.skills.len() <= 256,
    )?;
    if document.catalog_hash != catalog.content_hash().map_err(|_| ContractError::Binding)? {
        return Err(ContractError::Binding);
    }
    let mut models = BTreeSet::new();
    for model in &document.models {
        require(
            identifier(model.model.as_str())
                && identifier(&model.provider)
                && models.insert(&model.model)
                && model.compatible_hosts.len() <= 64
                && model.compatible_hosts.iter().all(valid_host)
                && model.maximum_context_tokens.is_none_or(positive),
        )?;
        provenance(&model.provenance)?;
        if catalog.model(&model.model).is_none() {
            return Err(ContractError::Binding);
        }
    }
    let mut skills = BTreeSet::new();
    for skill in &document.skills {
        require(
            identifier(skill.skill.as_str())
                && identifier(&skill.version)
                && skills.insert(&skill.skill)
                && valid_license(&skill.license_expression)
                && is_digest(&skill.body_sha256)
                && positive(skill.maximum_context_tokens)
                && skill.compatible_hosts.len() <= 64
                && skill.compatible_hosts.iter().all(valid_host)
                && skill.required_tools.len() <= 64
                && skill.required_tools.iter().all(|s| identifier(s))
                && [&skill.triggers, &skill.anti_triggers, &skill.examples]
                    .iter()
                    .all(|items| {
                        items.len() <= 64
                            && items.iter().all(|s| public_label(s, 1024))
                            && items.iter().collect::<BTreeSet<_>>().len() == items.len()
                    }),
        )?;
        provenance(&skill.provenance)?;
        let prior = catalog.skill(&skill.skill).ok_or(ContractError::Binding)?;
        if prior.trust != skill.trust
            || !prior
                .required_capabilities
                .is_subset(&skill.required_capabilities)
        {
            return Err(ContractError::Binding);
        }
    }
    document.models.sort_by(|a, b| a.model.cmp(&b.model));
    document.skills.sort_by(|a, b| a.skill.cmp(&b.skill));
    document.content_hash.clear();
    document.content_hash = digest("agent-router:asset-contracts:v1", &document)?;
    bounded(&document)?;
    Ok(document)
}

/// Producer operation only. Native evidence references must match the supplied
/// snapshot; approving the expected document root remains the parent's job.
pub fn seal_availability(
    mut document: AssetAvailabilityDocument,
    snapshot: &ValidatedHostObservation,
) -> Result<AssetAvailabilityDocument> {
    require(
        document.schema_version == 1
            && document.bindings.len() <= 64
            && document.evidence.len() <= 64
            && document.observed_at_unix_seconds <= 1_000_000_000_000
            && document.expires_at_unix_seconds > document.observed_at_unix_seconds
            && document.expires_at_unix_seconds - document.observed_at_unix_seconds
                <= MAX_EVIDENCE_AGE_SECONDS,
    )?;
    if document.snapshot_hash != snapshot.hash() {
        return Err(ContractError::Binding);
    }
    let mut evidence = BTreeMap::new();
    for item in &document.evidence {
        require(
            identifier(&item.id)
                && is_digest(&item.source_sha256)
                && evidence.insert(&item.id, item).is_none()
                && item.observed_at_unix_seconds <= document.observed_at_unix_seconds,
        )?;
        if matches!(
            item.kind,
            AssetEvidenceKind::NativeRuntime | AssetEvidenceKind::NativeStatus
        ) && !snapshot.observation().evidence.iter().any(|source| {
            source.kind != router_adapter_api::EvidenceKind::CodexModelCache
                && source.content_sha256 == item.source_sha256
                && source.observed_at_unix_seconds == item.observed_at_unix_seconds
        }) {
            return Err(ContractError::Binding);
        }
    }
    let mut bindings = BTreeSet::new();
    for binding in &document.bindings {
        require(
            identifier(binding.model.as_str())
                && identifier(&binding.provider)
                && valid_host(&binding.host)
                && bindings.insert((&binding.model, &binding.provider, &binding.host))
                && binding.maximum_context_tokens.is_none_or(positive)
                && binding
                    .host_overhead_tokens
                    .is_none_or(|v| v <= MAX_CONTEXT_TOKENS),
        )?;
        if binding.host.harness != snapshot.host().harness
            || !snapshot.host().supported_models.contains(&binding.model)
            || !snapshot
                .host()
                .supported_efforts
                .get(&binding.model)
                .is_some_and(|efforts| binding.efforts.is_subset(efforts))
            || !snapshot
                .observation()
                .evidence
                .iter()
                .any(|source| source.observed_version.as_ref() == Some(&binding.host.version))
        {
            return Err(ContractError::Binding);
        }
        let kinds = |ids: &BTreeSet<String>| -> Result<Vec<AssetEvidenceKind>> {
            require(ids.len() <= 64)?;
            ids.iter()
                .map(|id| {
                    evidence
                        .get(id)
                        .map(|e| e.kind)
                        .ok_or(ContractError::Binding)
                })
                .collect()
        };
        let auth = kinds(&binding.auth_evidence_ids)?;
        match binding.authentication {
            AssetAuthStatus::Authenticated => {
                require(auth.contains(&AssetEvidenceKind::NativeRuntime))?
            }
            AssetAuthStatus::NotRequired => {
                require(auth.contains(&AssetEvidenceKind::OperatorReview))?
            }
            AssetAuthStatus::Unknown | AssetAuthStatus::Unavailable => {}
        }
        let context = kinds(&binding.context_evidence_ids)?;
        if binding.maximum_context_tokens.is_some()
            || binding.host_overhead_tokens.is_some()
            || binding.token_accounting != AssetTokenAccounting::Unknown
        {
            require(!context.is_empty())?;
        }
        if binding.host_overhead_tokens.is_some() {
            require(context.contains(&AssetEvidenceKind::NativeRuntime))?;
        }
        for (feature, ids) in &binding.feature_evidence_ids {
            require(binding.features.contains_key(feature))?;
            kinds(ids)?;
        }
        for (feature, support) in &binding.features {
            if *support == CapabilitySupport::Supported {
                let refs = binding
                    .feature_evidence_ids
                    .get(feature)
                    .ok_or(ContractError::Binding)?;
                require(kinds(refs)?.contains(&AssetEvidenceKind::NativeRuntime))?;
            }
        }
    }
    document
        .bindings
        .sort_by(|a, b| (&a.model, &a.provider, &a.host).cmp(&(&b.model, &b.provider, &b.host)));
    document.evidence.sort_by(|a, b| a.id.cmp(&b.id));
    document.content_hash.clear();
    document.content_hash = digest("agent-router:asset-availability:v1", &document)?;
    bounded(&document)?;
    Ok(document)
}

pub(crate) fn valid_host(host: &AssetHostBinding) -> bool {
    identifier(host.harness.as_str()) && identifier(&host.version)
}
pub(crate) fn valid_license(text: &str) -> bool {
    if text.is_empty()
        || text.len() > 128
        || text.trim() != text
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-+.(): ".contains(&b))
    {
        return false;
    }
    let spaced = text.replace('(', " ( ").replace(')', " ) ");
    let tokens: Vec<_> = spaced.split_whitespace().collect();
    fn atom(tokens: &[&str], position: &mut usize, depth: usize) -> bool {
        if depth > 8 {
            return false;
        }
        match tokens.get(*position).copied() {
            Some("(") => {
                *position += 1;
                if !expression(tokens, position, depth + 1) || tokens.get(*position) != Some(&")") {
                    return false;
                }
                *position += 1;
                true
            }
            Some("AND" | "OR" | "WITH" | ")") | None => false,
            Some(_) => {
                *position += 1;
                if tokens.get(*position) == Some(&"WITH") {
                    *position += 1;
                    if matches!(
                        tokens.get(*position),
                        None | Some(&"AND" | &"OR" | &"WITH" | &"(" | &")")
                    ) {
                        return false;
                    }
                    *position += 1;
                }
                true
            }
        }
    }
    fn expression(tokens: &[&str], position: &mut usize, depth: usize) -> bool {
        if !atom(tokens, position, depth) {
            return false;
        }
        while matches!(tokens.get(*position), Some(&"AND" | &"OR")) {
            *position += 1;
            if !atom(tokens, position, depth) {
                return false;
            }
        }
        true
    }
    let mut position = 0;
    expression(&tokens, &mut position, 0) && position == tokens.len()
}
fn provenance(value: &AssetSourceProvenance) -> Result<()> {
    require(
        identifier(&value.source)
            && !value.source.starts_with('/')
            && !value.source.starts_with("file:")
            && !value.source.contains("..")
            && identifier(&value.revision)
            && is_digest(&value.source_sha256),
    )
}
fn bounded<T: serde::Serialize>(value: &T) -> Result<()> {
    if serde_json::to_vec(value)
        .map_err(|_| ContractError::Schema)?
        .len()
        > MAX_DOCUMENT_BYTES
    {
        return Err(ContractError::Limit);
    }
    Ok(())
}
fn distinct(value: &serde_json::Value) -> Result<()> {
    router_adapter_api::reject_duplicate_elements(value).map_err(|_| ContractError::Schema)
}
pub(crate) fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(ContractError::Limit);
    }
    let value = strict_json(bytes).map_err(|_| ContractError::Schema)?;
    distinct(&value)?;
    serde_json::from_value(value).map_err(|_| ContractError::Schema)
}

#[cfg(test)]
mod distinct_tests {
    use super::*;

    #[test]
    fn distinct_is_linear_on_deep_single_element_chains() {
        // About 3.6 MB of leaf text under 120 single-element arrays. Serializing
        // every element at every level would cost roughly 430 MB of work.
        let leaf: Vec<serde_json::Value> = (0..3_600)
            .map(|i| serde_json::Value::String(format!("{i:0>1000}")))
            .collect();
        let mut value = serde_json::Value::Array(leaf);
        for _ in 0..120 {
            value = serde_json::Value::Array(vec![value]);
        }
        let started = std::time::Instant::now();
        assert!(distinct(&value).is_ok());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "distinct took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn distinct_still_rejects_repeats_at_every_depth() {
        assert!(matches!(
            distinct(&serde_json::json!({"a": [[1], [1]]})),
            Err(ContractError::Schema)
        ));
        assert!(distinct(&serde_json::json!({"a": [[1, 2], [2, 1]]})).is_ok());
    }
}
