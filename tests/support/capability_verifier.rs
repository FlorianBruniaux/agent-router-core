//! Synthetic verifier for unrelated policy/adapter test fixtures only.
//! Imported by tests/examples via an explicit path, never by production libraries.
#![allow(dead_code)]
use router_adapter_api::{
    CapabilityProofBinding, CapabilityProofError, CapabilityProofTier, CapabilityProofVerifier,
    EvidenceSource, HostObservation, SnapshotError, SnapshotValidation, ValidatedHostObservation,
    VerifiedCapabilityProof,
};
use router_types::{Capability, HostSnapshot};

pub struct FixtureVerifier;
impl CapabilityProofVerifier for FixtureVerifier {
    fn verify(
        &self,
        source: &EvidenceSource,
        capability: Capability,
        host: &HostSnapshot,
        _now: u64,
    ) -> Result<VerifiedCapabilityProof, CapabilityProofError> {
        Ok(VerifiedCapabilityProof {
            sequence: 1,
            proof_id: source.id.clone(),
            proof_sha256: source.content_sha256.clone(),
            capability,
            tier: CapabilityProofTier::Proven,
            observed_at_unix_seconds: source.observed_at_unix_seconds,
            expires_at_unix_seconds: source.observed_at_unix_seconds.saturating_add(86_400),
            binding: CapabilityProofBinding {
                harness_id: host.harness.to_string(),
                host_snapshot_id: host.id.clone(),
                binary_sha256: "a".repeat(64),
                observed_version: source
                    .observed_version
                    .clone()
                    .unwrap_or_else(|| "fixture-version".into()),
                adapter_id: host.harness.to_string(),
                argument_template_sha256: "b".repeat(64),
                sandbox_helper_sha256: "c".repeat(64),
                sandbox_wrapper_sha256: "d".repeat(64),
                sandbox_profile_sha256: "e".repeat(64),
                write_roots: Default::default(),
                network: capability == Capability::Network,
                os: "fixture-os".into(),
            },
        })
    }
}
pub fn from_observation(
    observation: HostObservation,
    validation: SnapshotValidation,
) -> Result<ValidatedHostObservation, SnapshotError> {
    ValidatedHostObservation::from_observation_with_verifier(
        observation,
        validation,
        Some(&FixtureVerifier),
    )
}
pub fn from_json(
    bytes: &[u8],
    validation: SnapshotValidation,
) -> Result<ValidatedHostObservation, SnapshotError> {
    ValidatedHostObservation::from_json_with_verifier(bytes, validation, Some(&FixtureVerifier))
}
