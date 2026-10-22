//! Operator declarations authenticated as declarations, never canary effects.
use crate::{
    CapabilityProofBinding, CapabilityProofError, CapabilityProofTier, DEFAULT_MAX_AGE_SECONDS,
    MAX_CAPABILITY_PROOF_BYTES, VerifiedCapabilityProof, content_digest, valid_hash,
    valid_identifier,
};
use hmac::{Hmac, Mac};
use router_types::{Capability, HostSnapshot};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityAttestationBinding {
    pub harness_id: String,
    pub host_snapshot_id: String,
    pub binary_sha256: String,
    pub declared_version: String,
    pub adapter_id: String,
    pub argument_template_sha256: String,
    pub sandbox_helper_sha256: String,
    pub sandbox_wrapper_sha256: String,
    pub sandbox_profile_sha256: String,
    pub write_roots: BTreeSet<String>,
    pub network: bool,
    pub os: String,
}
impl CapabilityAttestationBinding {
    /// Internal comparison pins. The payload continues to name its version as
    /// declared; this conversion is not a claim of a version observation.
    pub fn execution_pins(&self) -> CapabilityProofBinding {
        CapabilityProofBinding {
            harness_id: self.harness_id.clone(),
            host_snapshot_id: self.host_snapshot_id.clone(),
            binary_sha256: self.binary_sha256.clone(),
            observed_version: self.declared_version.clone(),
            adapter_id: self.adapter_id.clone(),
            argument_template_sha256: self.argument_template_sha256.clone(),
            sandbox_helper_sha256: self.sandbox_helper_sha256.clone(),
            sandbox_wrapper_sha256: self.sandbox_wrapper_sha256.clone(),
            sandbox_profile_sha256: self.sandbox_profile_sha256.clone(),
            write_roots: self.write_roots.clone(),
            network: self.network,
            os: self.os.clone(),
        }
    }
    pub fn from_execution_pins(pins: CapabilityProofBinding) -> Self {
        Self {
            harness_id: pins.harness_id,
            host_snapshot_id: pins.host_snapshot_id,
            binary_sha256: pins.binary_sha256,
            declared_version: pins.observed_version,
            adapter_id: pins.adapter_id,
            argument_template_sha256: pins.argument_template_sha256,
            sandbox_helper_sha256: pins.sandbox_helper_sha256,
            sandbox_wrapper_sha256: pins.sandbox_wrapper_sha256,
            sandbox_profile_sha256: pins.sandbox_profile_sha256,
            write_roots: pins.write_roots,
            network: pins.network,
            os: pins.os,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapabilityAttestationAction {
    Grant {
        max_age_seconds: u64,
    },
    Revoke {
        record_id: String,
        content_sha256: String,
    },
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityAttestationRecord {
    pub schema_version: u32,
    pub record_id: String,
    pub sequence: u64,
    pub store_id: String,
    pub capability: Capability,
    pub binding: CapabilityAttestationBinding,
    /// A declared label, not authentication of a person or an account.
    pub operator_label: String,
    pub reason: String,
    pub created_at_unix_seconds: u64,
    pub action: CapabilityAttestationAction,
}
impl CapabilityAttestationRecord {
    pub fn validate(&self) -> Result<(), CapabilityProofError> {
        self.binding.execution_pins().digest()?;
        if self.schema_version != 2
            || self.sequence == 0
            || !valid_identifier(&self.record_id)
            || !valid_hash(&self.store_id)
            || !valid_identifier(&self.operator_label)
            || self.reason.trim().is_empty()
            || self.reason.len() > 2048
            || self.reason.chars().any(|c| {
                c.is_control() || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
            })
        {
            return Err(CapabilityProofError::Invalid);
        }
        match &self.action {
            CapabilityAttestationAction::Grant { max_age_seconds } => {
                if *max_age_seconds == 0
                    || *max_age_seconds > DEFAULT_MAX_AGE_SECONDS
                    || self
                        .created_at_unix_seconds
                        .checked_add(*max_age_seconds)
                        .is_none()
                {
                    return Err(CapabilityProofError::Invalid);
                }
            }
            CapabilityAttestationAction::Revoke {
                record_id,
                content_sha256,
            } => {
                if !valid_identifier(record_id)
                    || !valid_hash(content_sha256)
                    || *record_id == self.record_id
                {
                    return Err(CapabilityProofError::Invalid);
                }
            }
        }
        if self.bytes()?.len() > MAX_CAPABILITY_PROOF_BYTES {
            return Err(CapabilityProofError::Bounds);
        }
        Ok(())
    }
    fn bytes(&self) -> Result<Vec<u8>, CapabilityProofError> {
        serde_json::to_vec(self).map_err(|_| CapabilityProofError::Invalid)
    }
    pub fn expires_at(&self) -> Option<u64> {
        match self.action {
            CapabilityAttestationAction::Grant { max_age_seconds } => {
                self.created_at_unix_seconds.checked_add(max_age_seconds)
            }
            _ => None,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedCapabilityAttestation {
    pub record: CapabilityAttestationRecord,
    pub mac_sha256: String,
}
impl AuthenticatedCapabilityAttestation {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CapabilityProofError> {
        if bytes.len() > MAX_CAPABILITY_PROOF_BYTES + 256 {
            return Err(CapabilityProofError::Bounds);
        }
        let value = crate::strict_json(bytes).map_err(|_| CapabilityProofError::Invalid)?;
        let proof: Self =
            serde_json::from_value(value).map_err(|_| CapabilityProofError::Invalid)?;
        proof.record.validate()?;
        if !valid_hash(&proof.mac_sha256) {
            return Err(CapabilityProofError::Unauthenticated);
        }
        Ok(proof)
    }
    pub fn digest(&self) -> Result<String, CapabilityProofError> {
        serde_json::to_vec(self)
            .map(|bytes| content_digest(&bytes))
            .map_err(|_| CapabilityProofError::Invalid)
    }
    pub fn reference(&self) -> Result<CapabilityAttestationReference, CapabilityProofError> {
        Ok(CapabilityAttestationReference {
            record_id: self.record.record_id.clone(),
            content_sha256: self.digest()?,
            capability: self.record.capability,
            created_at_unix_seconds: self.record.created_at_unix_seconds,
        })
    }
}
pub struct CapabilityAttestationKey([u8; 32]);
impl CapabilityAttestationKey {
    pub fn derive(secret: &[u8; 32], store_id: &str) -> Result<Self, CapabilityProofError> {
        if !valid_hash(store_id) {
            return Err(CapabilityProofError::Invalid);
        }
        let prk = crate::proofs::hkdf_extract(store_id.as_bytes(), secret)?;
        let bytes =
            crate::proofs::hkdf_expand(&prk, b"agent-router/capability-attestation/v1", 32)?;
        Ok(Self(
            bytes
                .try_into()
                .map_err(|_| CapabilityProofError::Invalid)?,
        ))
    }
    /// Authentication of a declaration only. The issuer must enforce its own
    /// admission gate; a valid MAC does not authorize a network attestation.
    pub fn authenticate(
        &self,
        record: CapabilityAttestationRecord,
    ) -> Result<AuthenticatedCapabilityAttestation, CapabilityProofError> {
        record.validate()?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0).map_err(|_| CapabilityProofError::Invalid)?;
        mac.update(&record.bytes()?);
        Ok(AuthenticatedCapabilityAttestation {
            record,
            mac_sha256: hex::encode(mac.finalize().into_bytes()),
        })
    }
    pub fn verify(
        &self,
        proof: &AuthenticatedCapabilityAttestation,
    ) -> Result<(), CapabilityProofError> {
        proof.record.validate()?;
        let supplied =
            hex::decode(&proof.mac_sha256).map_err(|_| CapabilityProofError::Unauthenticated)?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0).map_err(|_| CapabilityProofError::Invalid)?;
        mac.update(&proof.record.bytes()?);
        mac.verify_slice(&supplied)
            .map_err(|_| CapabilityProofError::Unauthenticated)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityAttestationReference {
    pub record_id: String,
    pub content_sha256: String,
    pub capability: Capability,
    pub created_at_unix_seconds: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityAttestationReferences {
    pub schema_version: u32,
    pub entries: Vec<CapabilityAttestationReference>,
}
impl CapabilityAttestationReferences {
    pub fn validate(&self) -> Result<(), CapabilityProofError> {
        if self.schema_version != 1 || self.entries.len() > crate::ALL_CAPABILITIES.len() {
            return Err(CapabilityProofError::Bounds);
        }
        let mut capabilities = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for entry in &self.entries {
            if !valid_identifier(&entry.record_id)
                || !valid_hash(&entry.content_sha256)
                || !capabilities.insert(entry.capability)
                || !ids.insert(&entry.record_id)
            {
                return Err(CapabilityProofError::Invalid);
            }
        }
        Ok(())
    }
}
/// Validated policy opt-in. Existing execution entry points use proven_only().
/// Policy authenticity remains the caller's responsibility, as for restrictions.
#[derive(Clone, Debug)]
pub struct CapabilityAcceptance {
    policy_hash: Option<String>,
    accepted: BTreeSet<Capability>,
}
impl CapabilityAcceptance {
    pub fn proven_only() -> Self {
        Self {
            policy_hash: None,
            accepted: BTreeSet::new(),
        }
    }
    pub fn from_policy(
        policy: &router_types::PhasePolicy,
        policy_hash: &str,
    ) -> Result<Self, CapabilityProofError> {
        if !valid_hash(policy_hash)
            || !matches!(policy.schema_version, 2 | 3)
            || (policy.schema_version == 2 && !policy.accepted_attestations.is_empty())
        {
            return Err(CapabilityProofError::Invalid);
        }
        let mut hash = Sha256::new();
        hash.update(if policy.schema_version == 3 {
            b"phase-policy-v3\0"
        } else {
            b"phase-policy-v2\0"
        });
        hash.update(serde_json::to_vec(policy).map_err(|_| CapabilityProofError::Invalid)?);
        if hex::encode(hash.finalize()) != policy_hash {
            return Err(CapabilityProofError::BindingMismatch);
        }
        Ok(Self {
            policy_hash: Some(policy_hash.into()),
            accepted: policy.accepted_attestations.clone(),
        })
    }
    pub fn accepts(&self, capability: Capability) -> bool {
        capability != Capability::Network && self.accepted.contains(&capability)
    }
    pub fn policy_hash(&self) -> Option<&str> {
        self.policy_hash.as_deref()
    }
    pub fn accepted(&self) -> &BTreeSet<Capability> {
        &self.accepted
    }
}
pub(crate) fn verified_attestation(
    record: &AuthenticatedCapabilityAttestation,
    host: &HostSnapshot,
) -> Result<VerifiedCapabilityProof, CapabilityProofError> {
    if record.record.binding.host_snapshot_id != host.id
        || record.record.binding.harness_id != host.harness.as_str()
    {
        return Err(CapabilityProofError::BindingMismatch);
    }
    Ok(VerifiedCapabilityProof {
        sequence: record.record.sequence,
        proof_id: record.record.record_id.clone(),
        proof_sha256: record.digest()?,
        capability: record.record.capability,
        tier: CapabilityProofTier::Attested,
        observed_at_unix_seconds: record.record.created_at_unix_seconds,
        expires_at_unix_seconds: record
            .record
            .expires_at()
            .ok_or(CapabilityProofError::Revoked)?,
        binding: record.record.binding.execution_pins(),
    })
}
