#![forbid(unsafe_code)]

mod attestations;
pub use attestations::*;

mod proofs;
pub use proofs::*;

mod execution;
pub use execution::*;
mod registry;
pub use registry::*;

use std::collections::{BTreeMap, BTreeSet};

use router_types::{Capability, CapabilitySupport, HostSnapshot};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_MAX_AGE_SECONDS: u64 = 86_400;
pub const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SNAPSHOT_MODELS: usize = 64;
pub const MAX_EVIDENCE_SOURCES: usize = 64;
pub const ALL_CAPABILITIES: [Capability; 5] = [
    Capability::Tools,
    Capability::Subagents,
    Capability::Vision,
    Capability::Network,
    Capability::WorkspaceWrite,
];

pub trait HostProbe {
    fn probe(&self, observed_at_unix_seconds: u64) -> Result<HostObservation, ProbeError>;
}

/// Evidence kinds describe provenance, not authentication. Callers must establish
/// the authority of an externally supplied document independently of its hash.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    CodexModelCache,
    ClaudeNativeStream,
    HostRuntime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSource {
    pub id: String,
    pub kind: EvidenceKind,
    pub observed_version: Option<String>,
    pub observed_at_unix_seconds: u64,
    pub content_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityEvidence {
    pub support: CapabilitySupport,
    pub source_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostObservation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestations: Option<CapabilityAttestationReferences>,
    pub schema_version: u32,
    pub host: HostSnapshot,
    pub capabilities: BTreeMap<Capability, CapabilityEvidence>,
    pub evidence: Vec<EvidenceSource>,
    pub observed_at_unix_seconds: u64,
    pub snapshot_hash: String,
}

#[derive(Clone, Copy, Debug)]
pub struct SnapshotValidation {
    pub now_unix_seconds: u64,
    pub max_age_seconds: u64,
}

#[derive(Clone, Debug)]
pub struct ValidatedHostObservation {
    observation: HostObservation,
    capability_proofs: Vec<VerifiedCapabilityProof>,
}

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error(transparent)]
    CapabilityProof(#[from] CapabilityProofError),
    #[error("snapshot.too_large")]
    TooLarge,
    #[error("snapshot.json.invalid")]
    InvalidJson,
    #[error("snapshot.schema.unsupported")]
    UnsupportedSchema,
    #[error("snapshot.invalid: {0}")]
    Invalid(&'static str),
    #[error("snapshot.hash.invalid")]
    InvalidHash,
    #[error("snapshot.stale")]
    Stale,
    #[error("snapshot.source.stale")]
    StaleSource,
    #[error("snapshot.timestamp.future")]
    FutureTimestamp,
}

impl SnapshotError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::CapabilityProof(error) => error.code(),
            Self::TooLarge => "snapshot.too_large",
            Self::InvalidJson => "snapshot.json.invalid",
            Self::UnsupportedSchema => "snapshot.schema.unsupported",
            Self::Invalid(_) => "snapshot.invalid",
            Self::InvalidHash => "snapshot.hash.invalid",
            Self::Stale => "snapshot.stale",
            Self::StaleSource => "snapshot.source.stale",
            Self::FutureTimestamp => "snapshot.timestamp.future",
        }
    }
}

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("probe.unavailable")]
    Unavailable,
    #[error("probe.read")]
    Read,
    #[error("probe.cache.too_large")]
    CacheTooLarge,
    #[error("probe.cache.invalid: {0}")]
    InvalidCache(&'static str),
    #[error("probe.version.mismatch")]
    VersionMismatch,
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
}

impl ProbeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unavailable => "probe.unavailable",
            Self::Read => "probe.read",
            Self::CacheTooLarge => "probe.cache.too_large",
            Self::InvalidCache(_) => "probe.cache.invalid",
            Self::VersionMismatch => "probe.version.mismatch",
            Self::Snapshot(error) => error.code(),
        }
    }
}

impl HostObservation {
    /// Producer operation. Missing capability evidence is explicitly UNKNOWN.
    /// This computes integrity only; it does not attest to the producer's claims.
    pub fn seal(mut self) -> Result<Self, SnapshotError> {
        self.normalize();
        self.validate_structure()?;
        self.snapshot_hash = self.compute_hash()?;
        if serde_json::to_vec(&self)
            .map_err(|_| SnapshotError::InvalidJson)?
            .len()
            > MAX_SNAPSHOT_BYTES
        {
            return Err(SnapshotError::TooLarge);
        }
        Ok(self)
    }

    fn normalize(&mut self) {
        for capability in ALL_CAPABILITIES {
            self.capabilities
                .entry(capability)
                .or_insert_with(|| CapabilityEvidence {
                    support: CapabilitySupport::Unknown,
                    source_ids: BTreeSet::new(),
                });
        }
        self.evidence.sort_by(|left, right| left.id.cmp(&right.id));
        if let Some(attestations) = &mut self.attestations {
            attestations.entries.sort_by_key(|entry| entry.capability);
        }
    }

    fn compute_hash(&self) -> Result<String, SnapshotError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            schema_version: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            attestations: &'a Option<CapabilityAttestationReferences>,
            host: &'a HostSnapshot,
            capabilities: &'a BTreeMap<Capability, CapabilityEvidence>,
            evidence: &'a [EvidenceSource],
            observed_at_unix_seconds: u64,
        }
        let bytes = serde_json::to_vec(&Payload {
            schema_version: self.schema_version,
            attestations: &self.attestations,
            host: &self.host,
            capabilities: &self.capabilities,
            evidence: &self.evidence,
            observed_at_unix_seconds: self.observed_at_unix_seconds,
        })
        .map_err(|_| SnapshotError::InvalidJson)?;
        let mut hasher = Sha256::new();
        hasher.update(if self.schema_version == 2 {
            b"agent-router:host-observation:v2\0"
        } else {
            b"agent-router:host-observation:v1\0"
        });
        hasher.update(bytes);
        Ok(hex::encode(hasher.finalize()))
    }

    fn validate_structure(&self) -> Result<(), SnapshotError> {
        if !matches!(self.schema_version, 1 | 2)
            || (self.schema_version == 1 && self.attestations.is_some())
            || (self.schema_version == 2 && self.attestations.is_none())
        {
            return Err(SnapshotError::UnsupportedSchema);
        }
        if let Some(attestations) = &self.attestations {
            attestations.validate()?;
            if attestations.entries.iter().any(|entry| {
                self.host.capabilities.contains(&entry.capability)
                    || self
                        .capabilities
                        .get(&entry.capability)
                        .is_none_or(|e| e.support != CapabilitySupport::Unknown)
            }) {
                return Err(SnapshotError::Invalid(
                    "attestation cannot promote capability support",
                ));
            }
        }
        if !valid_identifier(&self.host.id) || !valid_identifier(self.host.harness.as_str()) {
            return Err(SnapshotError::Invalid("host identity"));
        }
        if self.host.supported_models.len() > MAX_SNAPSHOT_MODELS
            || self.host.supported_efforts.len() > MAX_SNAPSHOT_MODELS
            || self.evidence.is_empty()
            || self.evidence.len() > MAX_EVIDENCE_SOURCES
        {
            return Err(SnapshotError::Invalid("collection bounds"));
        }
        for model in &self.host.supported_models {
            // A model may be observed while its supported efforts remain unknown.
            // Missing/empty efforts never authorize any effort at routing time.
            if !valid_identifier(model.as_str()) {
                return Err(SnapshotError::Invalid("model or effort"));
            }
        }
        if self
            .host
            .supported_efforts
            .keys()
            .any(|model| !self.host.supported_models.contains(model))
        {
            return Err(SnapshotError::Invalid("orphan model effort"));
        }
        let mut sources = BTreeMap::new();
        for source in &self.evidence {
            if !valid_identifier(&source.id)
                || !valid_hash(&source.content_sha256)
                || source.observed_version.as_ref().is_some_and(|value| {
                    value.is_empty()
                        || value.len() > 128
                        || !value.bytes().all(|byte| byte.is_ascii_graphic())
                })
                || sources.insert(&source.id, source).is_some()
            {
                return Err(SnapshotError::Invalid("evidence source"));
            }
            if source.observed_at_unix_seconds > self.observed_at_unix_seconds {
                return Err(SnapshotError::FutureTimestamp);
            }
        }
        for capability in ALL_CAPABILITIES {
            let evidence = self
                .capabilities
                .get(&capability)
                .ok_or(SnapshotError::Invalid("missing capability evidence"))?;
            if evidence.source_ids.len() > MAX_EVIDENCE_SOURCES {
                return Err(SnapshotError::Invalid("capability evidence bounds"));
            }
            let mut has_runtime_source = false;
            for id in &evidence.source_ids {
                let source = sources
                    .get(id)
                    .ok_or(SnapshotError::Invalid("unknown evidence source"))?;
                has_runtime_source |= source.kind == EvidenceKind::HostRuntime;
            }
            if evidence.support != CapabilitySupport::Unknown && !has_runtime_source {
                return Err(SnapshotError::Invalid(
                    "runtime support requires runtime evidence",
                ));
            }
            if self.host.capabilities.contains(&capability)
                != (evidence.support == CapabilitySupport::Supported)
            {
                return Err(SnapshotError::Invalid("contradictory capability evidence"));
            }
        }
        Ok(())
    }
}

impl ValidatedHostObservation {
    pub fn from_json(bytes: &[u8], validation: SnapshotValidation) -> Result<Self, SnapshotError> {
        Self::from_json_with_verifier(bytes, validation, None)
    }

    pub fn from_json_with_verifier(
        bytes: &[u8],
        validation: SnapshotValidation,
        verifier: Option<&dyn CapabilityProofVerifier>,
    ) -> Result<Self, SnapshotError> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(SnapshotError::TooLarge);
        }
        let value = strict_json(bytes)?;
        if let Some(host) = value.get("host").and_then(serde_json::Value::as_object) {
            let fields = [
                "id",
                "harness",
                "supported_models",
                "supported_efforts",
                "capabilities",
            ];
            if host.keys().any(|key| !fields.contains(&key.as_str())) {
                return Err(SnapshotError::InvalidJson);
            }
        }
        reject_duplicate_sets(&value)?;
        let observation = serde_json::from_value(value).map_err(|_| SnapshotError::InvalidJson)?;
        Self::from_observation_with_verifier(observation, validation, verifier)
    }

    pub fn from_observation(
        observation: HostObservation,
        validation: SnapshotValidation,
    ) -> Result<Self, SnapshotError> {
        Self::from_observation_with_verifier(observation, validation, None)
    }

    pub fn from_observation_with_verifier(
        mut observation: HostObservation,
        validation: SnapshotValidation,
        verifier: Option<&dyn CapabilityProofVerifier>,
    ) -> Result<Self, SnapshotError> {
        observation.normalize();
        observation.validate_structure()?;
        if !valid_hash(&observation.snapshot_hash)
            || observation.compute_hash()? != observation.snapshot_hash
        {
            return Err(SnapshotError::InvalidHash);
        }
        if observation.observed_at_unix_seconds > validation.now_unix_seconds {
            return Err(SnapshotError::FutureTimestamp);
        }
        if validation.now_unix_seconds - observation.observed_at_unix_seconds
            > validation.max_age_seconds
        {
            return Err(SnapshotError::Stale);
        }
        let mut capability_proofs = Vec::new();
        let mut authenticated_sources = BTreeSet::new();
        for (capability, evidence) in &observation.capabilities {
            if evidence.support == CapabilitySupport::Unknown {
                continue;
            }
            let verifier = verifier.ok_or(CapabilityProofError::Unauthenticated)?;
            // Failed canaries produce UNKNOWN, never an unsupported assertion.
            if evidence.support != CapabilitySupport::Supported {
                return Err(CapabilityProofError::Unauthenticated.into());
            }
            for source in observation.evidence.iter().filter(|source| {
                source.kind == EvidenceKind::HostRuntime && evidence.source_ids.contains(&source.id)
            }) {
                capability_proofs.push(verifier.verify(
                    source,
                    *capability,
                    &observation.host,
                    validation.now_unix_seconds,
                )?);
                authenticated_sources.insert(&source.id);
            }
        }
        if let Some(attestations) = &observation.attestations {
            for reference in &attestations.entries {
                capability_proofs.push(
                    verifier
                        .ok_or(CapabilityProofError::Unauthenticated)?
                        .verify_attestation(
                            reference,
                            &observation.host,
                            validation.now_unix_seconds,
                        )?,
                );
            }
        }
        for source in &observation.evidence {
            if !authenticated_sources.contains(&source.id)
                && validation.now_unix_seconds - source.observed_at_unix_seconds
                    > validation.max_age_seconds
            {
                return Err(SnapshotError::StaleSource);
            }
        }
        if serde_json::to_vec(&observation)
            .map_err(|_| SnapshotError::InvalidJson)?
            .len()
            > MAX_SNAPSHOT_BYTES
        {
            return Err(SnapshotError::TooLarge);
        }
        Ok(Self {
            observation,
            capability_proofs,
        })
    }

    /// Recheck freshness of already authenticated in-process evidence. This
    /// retains its original authority; it does not re-read store revocations.
    /// Executable consumers must additionally use their live store verifier.
    pub fn revalidate_at(&self, validation: SnapshotValidation) -> Result<Self, SnapshotError> {
        struct Retained<'a>(&'a [VerifiedCapabilityProof]);
        impl CapabilityProofVerifier for Retained<'_> {
            fn verify(
                &self,
                source: &EvidenceSource,
                capability: Capability,
                host: &HostSnapshot,
                now: u64,
            ) -> Result<VerifiedCapabilityProof, CapabilityProofError> {
                let proof = self
                    .0
                    .iter()
                    .find(|proof| {
                        proof.capability == capability
                            && proof.proof_id == source.id
                            && proof.proof_sha256 == source.content_sha256
                            && proof.observed_at_unix_seconds == source.observed_at_unix_seconds
                            && Some(proof.binding.observed_version.as_str())
                                == source.observed_version.as_deref()
                            && proof.binding.host_snapshot_id == host.id
                            && proof.binding.harness_id == host.harness.as_str()
                    })
                    .ok_or(CapabilityProofError::Unauthenticated)?;
                if now > proof.expires_at_unix_seconds {
                    return Err(CapabilityProofError::Expired);
                }
                Ok(proof.clone())
            }
            fn verify_attestation(
                &self,
                reference: &CapabilityAttestationReference,
                host: &HostSnapshot,
                now: u64,
            ) -> Result<VerifiedCapabilityProof, CapabilityProofError> {
                if reference.capability == Capability::Network {
                    return Err(CapabilityProofError::NetworkAdmissionRequired);
                }
                let proof = self
                    .0
                    .iter()
                    .find(|p| {
                        p.tier == CapabilityProofTier::Attested
                            && p.capability == reference.capability
                            && p.proof_id == reference.record_id
                            && p.proof_sha256 == reference.content_sha256
                            && p.observed_at_unix_seconds == reference.created_at_unix_seconds
                            && p.binding.host_snapshot_id == host.id
                            && p.binding.harness_id == host.harness.as_str()
                    })
                    .ok_or(CapabilityProofError::Unauthenticated)?;
                if now < proof.observed_at_unix_seconds {
                    return Err(CapabilityProofError::Future);
                }
                if now > proof.expires_at_unix_seconds {
                    return Err(CapabilityProofError::Expired);
                }
                Ok(proof.clone())
            }
        }
        Self::from_observation_with_verifier(
            self.observation.clone(),
            validation,
            Some(&Retained(&self.capability_proofs)),
        )
    }

    pub fn permits_capability(
        &self,
        capability: Capability,
        acceptance: &CapabilityAcceptance,
    ) -> bool {
        self.capabilities().get(&capability) == Some(&CapabilitySupport::Supported)
            || (acceptance.accepts(capability)
                && self.capability_proofs.iter().any(|proof| {
                    proof.capability == capability && proof.tier == CapabilityProofTier::Attested
                }))
    }

    pub fn capability_proofs(&self) -> &[VerifiedCapabilityProof] {
        &self.capability_proofs
    }

    pub fn host(&self) -> &HostSnapshot {
        &self.observation.host
    }

    /// Complete replacement for request evidence, never merge caller assertions.
    pub fn capabilities(&self) -> BTreeMap<Capability, CapabilitySupport> {
        self.observation
            .capabilities
            .iter()
            .map(|(capability, evidence)| (*capability, evidence.support))
            .collect()
    }

    pub fn hash(&self) -> &str {
        &self.observation.snapshot_hash
    }

    pub fn observation(&self) -> &HostObservation {
        &self.observation
    }
}

fn valid_identifier(value: &str) -> bool {
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

fn reject_duplicate_sets(value: &serde_json::Value) -> Result<(), SnapshotError> {
    match value {
        serde_json::Value::Array(items) => {
            // Arrays of strings in this schema represent sets. Reject before
            // serde's BTreeSet conversion can silently discard duplicates.
            let mut seen = BTreeSet::new();
            for item in items {
                if let Some(text) = item.as_str() {
                    if !seen.insert(text) {
                        return Err(SnapshotError::Invalid("duplicate set entry"));
                    }
                }
                reject_duplicate_sets(item)?;
            }
        }
        serde_json::Value::Object(fields) => {
            for child in fields.values() {
                reject_duplicate_sets(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Error from `reject_duplicate_elements`: an array holds a repeated element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateElement;

/// Rejects a repeated element inside any array. Each value is reduced once,
/// bottom-up, to a fixed-size structural digest, so the work stays linear in
/// the document size instead of re-serializing every subtree at every level.
pub fn reject_duplicate_elements(value: &serde_json::Value) -> Result<(), DuplicateElement> {
    structural_digest(value).map(|_| ())
}

fn structural_digest(value: &serde_json::Value) -> Result<[u8; 32], DuplicateElement> {
    fn frame(hasher: &mut Sha256, tag: u8, bytes: &[u8]) {
        hasher.update([tag]);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    let mut hasher = Sha256::new();
    match value {
        serde_json::Value::Null => hasher.update([0]),
        serde_json::Value::Bool(value) => hasher.update([1, u8::from(*value)]),
        serde_json::Value::Number(number) => frame(&mut hasher, 2, number.to_string().as_bytes()),
        serde_json::Value::String(text) => frame(&mut hasher, 3, text.as_bytes()),
        serde_json::Value::Array(values) => {
            let mut seen = BTreeSet::new();
            hasher.update([4]);
            hasher.update((values.len() as u64).to_be_bytes());
            for value in values {
                let child = structural_digest(value)?;
                if !seen.insert(child) {
                    return Err(DuplicateElement);
                }
                hasher.update(child);
            }
        }
        serde_json::Value::Object(values) => {
            let mut fields: Vec<_> = values.iter().collect();
            fields.sort_by(|a, b| a.0.cmp(b.0));
            hasher.update([5]);
            hasher.update((fields.len() as u64).to_be_bytes());
            for (key, value) in fields {
                frame(&mut hasher, 6, key.as_bytes());
                hasher.update(structural_digest(value)?);
            }
        }
    }
    Ok(hasher.finalize().into())
}

/// Strict JSON also rejects repeated object keys, including inside typed maps.
pub fn strict_json(bytes: &[u8]) -> Result<serde_json::Value, SnapshotError> {
    strict_json_limited(bytes, MAX_SNAPSHOT_BYTES)
}

/// Strict JSON with a caller-chosen byte bound. `strict_json` applies
/// `MAX_SNAPSHOT_BYTES`; callers whose documented bound is larger pass it here.
pub fn strict_json_limited(bytes: &[u8], limit: usize) -> Result<serde_json::Value, SnapshotError> {
    if bytes.len() > limit {
        return Err(SnapshotError::TooLarge);
    }
    use serde::de::{MapAccess, SeqAccess, Visitor};
    struct StrictValue(serde_json::Value);
    struct StrictVisitor;
    impl<'de> Visitor<'de> for StrictVisitor {
        type Value = StrictValue;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("JSON with unique object keys")
        }
        fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
            Ok(StrictValue(value.into()))
        }
        fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
            Ok(StrictValue(value.into()))
        }
        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
            Ok(StrictValue(value.into()))
        }
        fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
            serde_json::Number::from_f64(value)
                .map(|number| StrictValue(number.into()))
                .ok_or_else(|| E::custom("non-finite number"))
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            Ok(StrictValue(value.into()))
        }
        fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
            Ok(StrictValue(value.into()))
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(StrictValue(serde_json::Value::Null))
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut items = Vec::new();
            while let Some(StrictValue(value)) = seq.next_element()? {
                items.push(value);
            }
            Ok(StrictValue(items.into()))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut fields = serde_json::Map::new();
            while let Some((key, StrictValue(value))) = map.next_entry::<String, StrictValue>()? {
                if fields.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate object key"));
                }
            }
            Ok(StrictValue(fields.into()))
        }
    }
    impl<'de> Deserialize<'de> for StrictValue {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_any(StrictVisitor)
        }
    }
    serde_json::from_slice::<StrictValue>(bytes)
        .map(|value| value.0)
        .map_err(|_| SnapshotError::InvalidJson)
}

#[cfg(test)]
mod strict_json_limited_tests {
    use super::*;

    #[test]
    fn honors_the_caller_limit_in_both_directions() {
        let padded = format!("{{}}{}", " ".repeat(MAX_SNAPSHOT_BYTES));
        assert!(matches!(
            strict_json(padded.as_bytes()),
            Err(SnapshotError::TooLarge)
        ));
        assert!(strict_json_limited(padded.as_bytes(), MAX_SNAPSHOT_BYTES + 2).is_ok());
        assert!(matches!(
            strict_json_limited(b"{\"a\":1}", 6),
            Err(SnapshotError::TooLarge)
        ));
        assert!(strict_json_limited(b"{\"a\":1}", 7).is_ok());
    }

    #[test]
    fn still_rejects_duplicate_keys_under_a_larger_limit() {
        assert!(matches!(
            strict_json_limited(b"{\"a\":1,\"a\":2}", 1024),
            Err(SnapshotError::InvalidJson)
        ));
    }
}

#[cfg(test)]
mod attestation_schema_contract {
    use super::*;
    #[test]
    fn version_two_empty_attestation_field_keeps_all_capabilities_unknown() {
        let mut value: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/examples/phase-snapshot.json"
        ))
        .unwrap();
        value["schema_version"] = serde_json::json!(2);
        value["attestations"] = serde_json::json!({"schema_version":1,"entries":[]});
        value["host"]["capabilities"] = serde_json::json!([]);
        for evidence in value["capabilities"].as_object_mut().unwrap().values_mut() {
            evidence["support"] = serde_json::json!("unknown");
            evidence["source_ids"] = serde_json::json!([]);
        }
        let observation: HostObservation =
            serde_json::from_value(value).expect("schema-2 attestation envelope must decode");
        let validated = ValidatedHostObservation::from_observation(
            observation.seal().unwrap(),
            SnapshotValidation {
                now_unix_seconds: 110,
                max_age_seconds: 300,
            },
        )
        .unwrap();
        assert!(validated.host().capabilities.is_empty());
        assert!(
            validated
                .capabilities()
                .values()
                .all(|value| *value == CapabilitySupport::Unknown)
        );
    }
}
