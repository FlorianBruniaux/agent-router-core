//! Offline join of supplied runtime attempt keys and supplied physical observations.
//! Digests bind content, not authenticity. Nothing here reads a store or a provider.
use crate::{FeedbackError, Result, hash, identifier, valid_hash};
use router_types::EffortLevel;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_ATTEMPT_CORRELATION_BYTES: usize = 4 * 1024 * 1024;
const MAX_ATTEMPTS: usize = 5;
const MAX_PHYSICAL: usize = 4096;
const MAX_MODEL_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SuppliedAttemptEvidence {
    Unknown,
    DurableAttempt,
}
/// Mirrors `requested` of `observe --schema-version 2 --json`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SuppliedRequested {
    pub model: String,
    pub effort: EffortLevel,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuppliedAttempt {
    pub ordinal: u32,
    pub attempt_key_sha256: String,
    pub evidence: SuppliedAttemptEvidence,
    pub requested: Option<SuppliedRequested>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuppliedRuntime {
    pub authority_sha256: String,
    pub snapshot_sha256: String,
    pub run_key_sha256: String,
    pub definition_sha256: String,
    pub attempts: Vec<SuppliedAttempt>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SuppliedPhysical {
    pub key: crate::PhysicalObservationKey,
    pub sequence: u64,
    pub evidence_sha256: String,
    pub external_request_id: Option<String>,
    pub declared_model: Option<String>,
    pub claimed_attempt_key_sha256: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptCorrelationInput {
    pub schema_version: u32,
    pub runtime: SuppliedRuntime,
    pub physical: Vec<SuppliedPhysical>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SelectionAgreement {
    Match,
    Mismatch,
    Unknown,
}
#[derive(Clone, Debug, Serialize)]
pub struct CorrelatedPhysical {
    pub key: crate::PhysicalObservationKey,
    pub sequence: u64,
    pub evidence_sha256: String,
    pub external_request_id: Option<String>,
    pub declared_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection_agreement: Option<SelectionAgreement>,
}
/// `Unknown` means no physical claim was supplied. It is never zero sends.
#[derive(Clone, Debug)]
pub enum PhysicalSends {
    Unknown,
    Linked(Vec<CorrelatedPhysical>),
}
impl Serialize for PhysicalSends {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Unknown => serializer.serialize_str("unknown"),
            Self::Linked(calls) => calls.serialize(serializer),
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct CorrelatedAttempt {
    pub ordinal: u32,
    pub attempt_key_sha256: String,
    pub evidence: SuppliedAttemptEvidence,
    pub requested: Option<SuppliedRequested>,
    pub physical_sends: PhysicalSends,
}
#[derive(Clone, Debug, Serialize)]
pub struct CorrelatedRuntime {
    pub authority_sha256: String,
    pub snapshot_sha256: String,
    pub run_key_sha256: String,
    pub definition_sha256: String,
}
#[derive(Debug, Serialize)]
pub struct AttemptCorrelationReport {
    pub schema_version: u32,
    pub input_sha256: String,
    pub report_sha256: String,
    pub evidence_trust: &'static str,
    pub runtime: CorrelatedRuntime,
    pub attempts: Vec<CorrelatedAttempt>,
    pub unattributed: Vec<CorrelatedPhysical>,
    pub supplied_physical_observation_count: usize,
    pub duplicate_observation_count: usize,
    /// Facts this report neither checks nor produces.
    pub unverified: &'static [&'static str],
}

const UNVERIFIED: &[&str] = &[
    "snapshot_sha256_not_reverified",
    "runtime_authority_not_verified",
    "physical_sends_per_attempt_unknown_without_inventory",
    "thread_turn_usage_duration_not_joined",
    "observed_tokens_and_cost_not_read",
    "feedback_join_run_key_ordinal_unchanged",
    "same_request_under_two_authorities_counts_as_two_observations",
    "sequence_is_a_supplied_total_order_unique_across_authorities",
    "claim_to_another_runs_attempt_detected_only_if_runtime_block_is_faithful",
    "input_is_a_projection_of_observe_v2_not_its_raw_output",
];

fn invalid<T>(reason: &'static str) -> Result<T> {
    Err(FeedbackError::Invalid(reason))
}
fn model_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_MODEL_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
}

/// Strict JSON is checked before decoding. Evidence is supplied and not authenticated.
pub fn attempt_correlation_report(bytes: &[u8]) -> Result<AttemptCorrelationReport> {
    if bytes.len() > MAX_ATTEMPT_CORRELATION_BYTES {
        return Err(FeedbackError::Limit);
    }
    let value = router_adapter_api::strict_json_limited(bytes, MAX_ATTEMPT_CORRELATION_BYTES)
        .map_err(|_| FeedbackError::Invalid("JSON"))?;
    let input: AttemptCorrelationInput = serde_json::from_value(value)?;
    calculate_attempt_correlation(&input)
}

pub fn calculate_attempt_correlation(
    input: &AttemptCorrelationInput,
) -> Result<AttemptCorrelationReport> {
    if input.schema_version != 1 {
        return invalid("attempt correlation version");
    }
    if input.runtime.attempts.len() > MAX_ATTEMPTS
        || input.physical.len() > MAX_PHYSICAL
        || serde_json::to_vec(input)?.len() > MAX_ATTEMPT_CORRELATION_BYTES
    {
        return Err(FeedbackError::Limit);
    }
    let runtime = &input.runtime;
    if ![
        &runtime.authority_sha256,
        &runtime.snapshot_sha256,
        &runtime.run_key_sha256,
        &runtime.definition_sha256,
    ]
    .into_iter()
    .all(|h| valid_hash(h))
    {
        return invalid("runtime digest");
    }
    let mut by_key = BTreeMap::new();
    let mut ordinals = BTreeSet::new();
    for attempt in &runtime.attempts {
        if !valid_hash(&attempt.attempt_key_sha256) {
            return invalid("attempt key digest");
        }
        if attempt
            .requested
            .as_ref()
            .is_some_and(|r| !model_token(&r.model))
        {
            return invalid("requested model token");
        }
        // The v2 producer sets evidence and requested together, and only together.
        if (attempt.evidence == SuppliedAttemptEvidence::DurableAttempt)
            != attempt.requested.is_some()
        {
            return invalid("attempt evidence and requested selection disagree");
        }
        if by_key
            .insert(attempt.attempt_key_sha256.as_str(), attempt)
            .is_some()
        {
            return invalid("duplicate attempt key");
        }
        if !ordinals.insert(attempt.ordinal) {
            return invalid("duplicate attempt ordinal");
        }
    }
    // BTreeSet iterates ascending, so equality with 1..=n rejects 0, gaps and > n.
    if !ordinals
        .iter()
        .copied()
        .eq(1..=runtime.attempts.len() as u32)
    {
        return invalid("attempt ordinals");
    }

    let mut calls = BTreeMap::new();
    let mut sequences = BTreeSet::new();
    let mut duplicates = 0usize;
    for call in &input.physical {
        if !valid_hash(&call.key.authority_sha256)
            || !valid_hash(&call.key.physical_sha256)
            || !valid_hash(&call.evidence_sha256)
            || call
                .claimed_attempt_key_sha256
                .as_deref()
                .is_some_and(|h| !valid_hash(h))
            || call
                .external_request_id
                .as_deref()
                .is_some_and(|id| !identifier(id))
            || call
                .declared_model
                .as_deref()
                .is_some_and(|m| !model_token(m))
            || call.sequence == 0
        {
            return invalid("physical observation");
        }
        if call.key.authority_sha256 == runtime.authority_sha256 {
            return invalid("physical key under runtime authority");
        }
        if let Some(existing) = calls.get(&call.key) {
            if *existing != call {
                return invalid("physical identity conflict");
            }
            duplicates += 1;
            continue;
        }
        if !sequences.insert(call.sequence) {
            return invalid("physical sequence");
        }
        if call
            .claimed_attempt_key_sha256
            .as_deref()
            .is_some_and(|claim| !by_key.contains_key(claim))
        {
            return invalid("claimed attempt absent from snapshot");
        }
        calls.insert(call.key.clone(), call);
    }

    let mut linked: BTreeMap<&str, Vec<CorrelatedPhysical>> = BTreeMap::new();
    let mut unattributed = Vec::new();
    for call in calls.values() {
        let mut out = CorrelatedPhysical {
            key: call.key.clone(),
            sequence: call.sequence,
            evidence_sha256: call.evidence_sha256.clone(),
            external_request_id: call.external_request_id.clone(),
            declared_model: call.declared_model.clone(),
            selection_agreement: None,
        };
        match call.claimed_attempt_key_sha256.as_deref() {
            None => unattributed.push(out),
            Some(claim) => {
                // Presence was checked above; fall back to unknown, never panic.
                let requested = by_key.get(claim).and_then(|a| a.requested.as_ref());
                out.selection_agreement = Some(match (requested, call.declared_model.as_deref()) {
                    (Some(r), Some(m)) if r.model == m => SelectionAgreement::Match,
                    (Some(_), Some(_)) => SelectionAgreement::Mismatch,
                    _ => SelectionAgreement::Unknown,
                });
                linked.entry(claim).or_default().push(out);
            }
        }
    }
    let mut attempts: Vec<_> = runtime
        .attempts
        .iter()
        .map(|a| CorrelatedAttempt {
            ordinal: a.ordinal,
            attempt_key_sha256: a.attempt_key_sha256.clone(),
            evidence: a.evidence,
            requested: a.requested.clone(),
            physical_sends: linked
                .remove(a.attempt_key_sha256.as_str())
                .map_or(PhysicalSends::Unknown, PhysicalSends::Linked),
        })
        .collect();
    attempts.sort_by_key(|a| a.ordinal);
    let mut report = AttemptCorrelationReport {
        schema_version: 1,
        input_sha256: hash("attempt-correlation/input/v1", input)?,
        report_sha256: String::new(),
        evidence_trust: "supplied_unverified",
        runtime: CorrelatedRuntime {
            authority_sha256: runtime.authority_sha256.clone(),
            snapshot_sha256: runtime.snapshot_sha256.clone(),
            run_key_sha256: runtime.run_key_sha256.clone(),
            definition_sha256: runtime.definition_sha256.clone(),
        },
        attempts,
        unattributed,
        supplied_physical_observation_count: calls.len(),
        duplicate_observation_count: duplicates,
        unverified: UNVERIFIED,
    };
    report.report_sha256 = hash("attempt-correlation/report/v1", &report)?;
    Ok(report)
}
