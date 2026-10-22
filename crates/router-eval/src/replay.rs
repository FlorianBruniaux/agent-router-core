use std::collections::{BTreeMap, BTreeSet};

use router_adapter_api::{
    HostObservation, SnapshotValidation, ValidatedHostObservation, strict_json,
};
use router_catalog::Catalog;
use router_policy::{PhaseRouter, ValidatedPhaseContext};
use router_types::{ModelId, PhasePolicy, PhaseReceipt, PhaseRouteRequest, StageKind};
use serde::{Deserialize, Serialize};

use crate::{EvalError, MAX_REPLAY_BYTES, Result, hash, text, valid_hash};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetSplit {
    Training,
    Validation,
    HeldOut,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedOutcome {
    Passed,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationOutcomes {
    pub transport: ObservedOutcome,
    pub command_validation: ObservedOutcome,
    pub functional: ObservedOutcome,
}
impl Default for VerificationOutcomes {
    fn default() -> Self {
        Self {
            transport: ObservedOutcome::Unknown,
            command_validation: ObservedOutcome::Unknown,
            functional: ObservedOutcome::Unknown,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenPrice {
    pub input_microusd_per_million: u64,
    pub cached_input_microusd_per_million: u64,
    pub output_microusd_per_million: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PricingTable {
    pub schema_version: u32,
    pub version: String,
    pub source: String,
    pub observed_at_unix_seconds: u64,
    pub models: BTreeMap<ModelId, TokenPrice>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenUsage {
    pub model: ModelId,
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedPhase {
    pub usage: Vec<TokenUsage>,
    pub elapsed_ms: Option<u64>,
    pub fallback_reasons: Vec<String>,
    pub outcomes: VerificationOutcomes,
}

/// A supplied review attestation, not authentication of a reviewer's identity.
/// Generated candidate corpora never contain a positive human attestation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseLabel {
    pub human_validated: bool,
    pub independent: bool,
    pub reviewer_id: Option<String>,
    pub evidence_sha256: Option<String>,
    pub expected_candidate_ids: BTreeSet<String>,
    pub expect_abstention: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayInput {
    pub schema_version: u32,
    pub case_id: String,
    pub family_id: String,
    pub split: DatasetSplit,
    pub out_of_domain: bool,
    pub request: PhaseRouteRequest,
    pub snapshot: HostObservation,
    pub catalog: serde_json::Value,
    pub policies: BTreeMap<String, PhasePolicy>,
    pub pricing: PricingTable,
    pub observations: BTreeMap<String, RecordedPhase>,
    pub label: Option<CaseLabel>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRecord {
    input: ReplayInput,
    input_hash: String,
}

pub struct ReplayContext<'a> {
    pub request: &'a PhaseRouteRequest,
    pub snapshot: &'a ValidatedHostObservation,
    pub catalog: &'a Catalog,
    pub policy: &'a PhasePolicy,
    pub phase_context: &'a ValidatedPhaseContext,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HardConstraintViolation {
    pub code: String,
    pub candidate_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityEvidenceVerification {
    Verified,
    Unverified,
}

/// Only the replay harness constructs this type. Persisted arbitrary JSON cannot
/// become a promotion input without replay and independent constraint auditing.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReplayTrace {
    pub(crate) capability_evidence: CapabilityEvidenceVerification,
    pub(crate) input_hash: String,
    pub(crate) case_id: String,
    pub(crate) family_id: String,
    pub(crate) split: DatasetSplit,
    pub(crate) label: Option<CaseLabel>,
    pub(crate) policy_id: String,
    pub(crate) policy_version: String,
    pub(crate) policy_hash: String,
    pub(crate) phase: StageKind,
    pub(crate) evaluated_at_unix_seconds: u64,
    pub(crate) receipt: PhaseReceipt,
    pub(crate) cost_microusd: u64,
    pub(crate) pricing_hash: String,
    pub(crate) usage: Vec<TokenUsage>,
    pub(crate) elapsed_ms: Option<u64>,
    pub(crate) fallback_reasons: Vec<String>,
    pub(crate) outcomes: VerificationOutcomes,
    pub(crate) hard_constraint_violations: Vec<HardConstraintViolation>,
    pub(crate) trace_hash: String,
}

impl ReplayRecord {
    pub fn seal(mut input: ReplayInput) -> Result<Self> {
        validate_input(&input)?;
        let catalog = Catalog::from_json(
            &serde_json::to_vec(&input.catalog).map_err(|_| EvalError::Catalog)?,
        )
        .map_err(|_| EvalError::Catalog)?;
        input.catalog =
            serde_json::from_slice(&catalog.canonical_json().map_err(|_| EvalError::Catalog)?)
                .map_err(|_| EvalError::Catalog)?;
        let input_hash = hash(b"agent-router:replay-input:v1\0", &input)?;
        let result = Self { input, input_hash };
        result.canonical_json()?;
        Ok(result)
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_REPLAY_BYTES {
            return Err(EvalError::Limit("replay bytes"));
        }
        let value = strict_json(bytes).map_err(|_| EvalError::Invalid("replay JSON"))?;
        let raw: Self =
            serde_json::from_value(value).map_err(|_| EvalError::Invalid("replay schema"))?;
        let expected = Self::seal(raw.input.clone())?;
        if raw != expected {
            return Err(EvalError::Integrity);
        }
        Ok(expected)
    }
    pub fn input(&self) -> &ReplayInput {
        &self.input
    }
    pub fn input_hash(&self) -> &str {
        &self.input_hash
    }
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        let bytes =
            serde_json::to_vec(self).map_err(|_| EvalError::Invalid("replay serialization"))?;
        if bytes.len() > MAX_REPLAY_BYTES {
            return Err(EvalError::Limit("replay bytes"));
        }
        Ok(bytes)
    }
}

impl ReplayTrace {
    pub fn capability_evidence(&self) -> CapabilityEvidenceVerification {
        self.capability_evidence
    }

    pub fn receipt(&self) -> &PhaseReceipt {
        &self.receipt
    }
    pub fn cost_microusd(&self) -> u64 {
        self.cost_microusd
    }
    pub fn outcomes(&self) -> &VerificationOutcomes {
        &self.outcomes
    }
    pub fn violations(&self) -> &[HardConstraintViolation] {
        &self.hard_constraint_violations
    }
    pub fn trace_hash(&self) -> &str {
        &self.trace_hash
    }
    pub fn input_hash(&self) -> &str {
        &self.input_hash
    }
}

/// Offline callbacks only. PhaseRouter independently re-evaluates all selected
/// candidates; backend-supplied safety assertions are never used.
pub fn run_replay<P>(
    record: &ReplayRecord,
    policy_id: &str,
    validation: SnapshotValidation,
    route: P,
) -> Result<ReplayTrace>
where
    P: FnOnce(&ReplayContext<'_>) -> Result<PhaseReceipt>,
{
    run_replay_with_verifier(record, policy_id, validation, None, route)
}

pub fn run_replay_with_verifier<P>(
    record: &ReplayRecord,
    policy_id: &str,
    validation: SnapshotValidation,
    verifier: Option<&dyn router_adapter_api::CapabilityProofVerifier>,
    route: P,
) -> Result<ReplayTrace>
where
    P: FnOnce(&ReplayContext<'_>) -> Result<PhaseReceipt>,
{
    validate_input(&record.input)?;
    if hash(b"agent-router:replay-input:v1\0", &record.input)? != record.input_hash {
        return Err(EvalError::Integrity);
    }
    let input = &record.input;
    let policy = input
        .policies
        .get(policy_id)
        .ok_or(EvalError::UnknownPolicy)?;
    let observation = input
        .observations
        .get(policy_id)
        .ok_or(EvalError::Invalid("missing policy observations"))?;
    let (snapshot, capability_evidence) =
        match ValidatedHostObservation::from_observation_with_verifier(
            input.snapshot.clone(),
            validation,
            verifier,
        ) {
            Ok(snapshot) => (snapshot, CapabilityEvidenceVerification::Verified),
            Err(error)
                if verifier.is_none() && error.code() == "capability.evidence.unauthenticated" =>
            {
                // The original hash and structure were checked before authenticity.
                // Offline exports retain the input hash but route only UNKNOWN claims.
                let mut unverified = input.snapshot.clone();
                unverified.schema_version = 1;
                unverified.attestations = None;
                unverified.host.capabilities.clear();
                for evidence in unverified.capabilities.values_mut() {
                    evidence.support = router_types::CapabilitySupport::Unknown;
                }
                (
                    ValidatedHostObservation::from_observation(unverified.seal()?, validation)?,
                    CapabilityEvidenceVerification::Unverified,
                )
            }
            Err(error) => return Err(error.into()),
        };
    if input.pricing.observed_at_unix_seconds > validation.now_unix_seconds {
        return Err(EvalError::Invalid("pricing timestamp in future"));
    }
    let catalog =
        Catalog::from_json(&serde_json::to_vec(&input.catalog).map_err(|_| EvalError::Catalog)?)
            .map_err(|_| EvalError::Catalog)?;
    for candidate in &input.request.candidates {
        if catalog.model(&candidate.model).is_none() {
            return Err(EvalError::UnknownModel);
        }
    }
    let router =
        PhaseRouter::new(policy.clone()).map_err(|_| EvalError::Invalid("phase policy"))?;
    let phase_context = router
        .context(input.request.clone(), &snapshot, &catalog)
        .map_err(|_| EvalError::Invalid("phase context"))?;
    let expected = router
        .route(&phase_context)
        .map_err(|_| EvalError::Backend)?;
    let context = ReplayContext {
        request: &input.request,
        snapshot: &snapshot,
        catalog: &catalog,
        policy,
        phase_context: &phase_context,
    };
    let receipt = route(&context)?;
    let mut receipt_preimage = receipt.clone();
    receipt_preimage.receipt_id.clear();
    let receipt_domain: &[u8] = if receipt.schema_version == 6 {
        b"phase-receipt-v6\0"
    } else if receipt.schema_version == 5 {
        b"phase-receipt-v5\0"
    } else {
        b"phase-receipt-v2\0"
    };
    if hash(receipt_domain, &receipt_preimage)? != receipt.receipt_id {
        return Err(EvalError::Integrity);
    }
    if receipt.phase != input.request.phase
        || receipt.snapshot_hash != snapshot.hash()
        || receipt.catalog_hash != phase_context.catalog_hash()
        || receipt.context_hash != phase_context.context_hash()
        || receipt.policy_hash != phase_context.policy_hash()
        || receipt.pool_hash != phase_context.pool_hash()
        || receipt.registry_hash != expected.registry_hash
        || !matches!(receipt.schema_version, 2 | 5 | 6)
        || receipt.capability_evidence != expected.capability_evidence
    {
        return Err(EvalError::Integrity);
    }
    if receipt.selected.is_some() == receipt.abstention.is_some() {
        return Err(EvalError::Invalid("receipt selection or abstention"));
    }
    let mut violations = Vec::new();
    if capability_evidence == CapabilityEvidenceVerification::Unverified {
        violations.push(HardConstraintViolation {
            code: "capability.evidence.unverified".into(),
            candidate_id: None,
        });
    }
    if receipt.alternatives.len() > 64 || receipt.unavailable.len() > 64 {
        return Err(EvalError::Limit("receipt alternatives"));
    }
    for selection in receipt.selected.iter().chain(receipt.alternatives.iter()) {
        if catalog.model(&selection.candidate.model).is_none() {
            return Err(EvalError::UnknownModel);
        }
        if router
            .validate_selection(&phase_context, selection)
            .is_err()
        {
            let specific: Vec<_> = expected
                .exclusions
                .iter()
                .filter(|exclusion| exclusion.candidate_id == selection.candidate.id)
                .collect();
            if specific.is_empty() {
                violations.push(HardConstraintViolation {
                    code: "phase.selection.invalid".into(),
                    candidate_id: Some(selection.candidate.id.clone()),
                });
            } else {
                violations.extend(
                    specific
                        .into_iter()
                        .map(|exclusion| HardConstraintViolation {
                            code: exclusion.code.clone(),
                            candidate_id: Some(selection.candidate.id.clone()),
                        }),
                );
            }
        }
        if receipt.unavailable.contains(&selection.candidate.id) {
            violations.push(HardConstraintViolation {
                code: "phase.selection.unavailable".into(),
                candidate_id: Some(selection.candidate.id.clone()),
            });
        }
    }
    if let Some(selected) = &receipt.selected {
        if !input.pricing.models.contains_key(&selected.candidate.model) {
            return Err(EvalError::UnknownPricing);
        }
        if !observation
            .usage
            .iter()
            .any(|usage| usage.model == selected.candidate.model)
        {
            return Err(EvalError::Invalid("selected model usage missing"));
        }
    }
    if violations.len() > 256
        || violations.iter().any(|violation| {
            !text(&violation.code) || violation.candidate_id.as_ref().is_some_and(|id| !text(id))
        })
    {
        return Err(EvalError::Invalid("constraint audit"));
    }
    let cost_microusd = price_usage(&input.pricing, &observation.usage, &catalog)?;
    let mut trace = ReplayTrace {
        capability_evidence,
        input_hash: record.input_hash.clone(),
        case_id: input.case_id.clone(),
        family_id: input.family_id.clone(),
        split: input.split,
        label: input.label.clone(),
        policy_id: policy_id.into(),
        policy_version: policy.version.clone(),
        policy_hash: phase_context.policy_hash().into(),
        phase: input.request.phase,
        evaluated_at_unix_seconds: validation.now_unix_seconds,
        receipt,
        cost_microusd,
        pricing_hash: hash(b"agent-router:pricing:v1\0", &input.pricing)?,
        usage: observation.usage.clone(),
        elapsed_ms: observation.elapsed_ms,
        fallback_reasons: observation.fallback_reasons.clone(),
        outcomes: observation.outcomes.clone(),
        hard_constraint_violations: violations,
        trace_hash: String::new(),
    };
    trace.trace_hash = hash(b"agent-router:replay-trace:v1\0", &trace)?;
    Ok(trace)
}

pub fn replay_deterministic(
    record: &ReplayRecord,
    policy_id: &str,
    validation: SnapshotValidation,
) -> Result<ReplayTrace> {
    run_replay(record, policy_id, validation, |context| {
        PhaseRouter::new(context.policy.clone())
            .map_err(|_| EvalError::Invalid("phase policy"))?
            .route(context.phase_context)
            .map_err(|_| EvalError::Backend)
    })
}

pub fn replay_deterministic_with_verifier(
    record: &ReplayRecord,
    policy_id: &str,
    validation: SnapshotValidation,
    verifier: Option<&dyn router_adapter_api::CapabilityProofVerifier>,
) -> Result<ReplayTrace> {
    run_replay_with_verifier(record, policy_id, validation, verifier, |context| {
        PhaseRouter::new(context.policy.clone())
            .map_err(|_| EvalError::Invalid("phase policy"))?
            .route(context.phase_context)
            .map_err(|_| EvalError::Backend)
    })
}

pub fn price_usage(pricing: &PricingTable, usage: &[TokenUsage], catalog: &Catalog) -> Result<u64> {
    validate_pricing(pricing)?;
    if usage.len() > 64 {
        return Err(EvalError::Limit("usage rows"));
    }
    let mut total = 0u64;
    for item in usage {
        if catalog.model(&item.model).is_none() {
            return Err(EvalError::UnknownModel);
        }
        let price = pricing
            .models
            .get(&item.model)
            .ok_or(EvalError::UnknownPricing)?;
        if item.cached_input_tokens > item.input_tokens {
            return Err(EvalError::Invalid("cached tokens exceed input tokens"));
        }
        let costs = [
            (
                item.input_tokens - item.cached_input_tokens,
                price.input_microusd_per_million,
            ),
            (
                item.cached_input_tokens,
                price.cached_input_microusd_per_million,
            ),
            (item.output_tokens, price.output_microusd_per_million),
        ];
        let numerator = costs.into_iter().try_fold(0u128, |sum, (tokens, rate)| {
            sum.checked_add(u128::from(tokens) * u128::from(rate))
                .ok_or(EvalError::CostOverflow)
        })?;
        let cost = numerator
            .checked_add(999_999)
            .ok_or(EvalError::CostOverflow)?
            / 1_000_000;
        total = total
            .checked_add(u64::try_from(cost).map_err(|_| EvalError::CostOverflow)?)
            .ok_or(EvalError::CostOverflow)?;
    }
    Ok(total)
}

fn validate_pricing(pricing: &PricingTable) -> Result<()> {
    if pricing.schema_version != 1
        || !text(&pricing.version)
        || !text(&pricing.source)
        || pricing.models.len() > 64
    {
        return Err(EvalError::Invalid("pricing provenance"));
    }
    Ok(())
}

fn validate_input(input: &ReplayInput) -> Result<()> {
    validate_pricing(&input.pricing)?;
    if input.schema_version != 1
        || !text(&input.case_id)
        || !text(&input.family_id)
        || input.request.candidates.len() > 256
        || input.policies.is_empty()
        || input.policies.len() > 8
        || input.observations.len() != input.policies.len()
        || input.pricing.schema_version != 1
        || !text(&input.pricing.version)
        || !text(&input.pricing.source)
        || input.pricing.models.len() > 64
    {
        return Err(EvalError::Invalid("replay context"));
    }
    for (id, policy) in &input.policies {
        if !text(id) || !text(&policy.version) || !input.observations.contains_key(id) {
            return Err(EvalError::Invalid("policy identity"));
        }
    }
    for observation in input.observations.values() {
        if observation.usage.len() > 64
            || observation.fallback_reasons.len() > 64
            || observation
                .fallback_reasons
                .iter()
                .any(|reason| !text(reason))
        {
            return Err(EvalError::Limit("recorded phase observations"));
        }
    }
    if let Some(label) = &input.label {
        if label.expected_candidate_ids.len() > 256
            || label.expected_candidate_ids.iter().any(|id| !text(id))
            || label.expect_abstention != label.expected_candidate_ids.is_empty()
            || label.expected_candidate_ids.iter().any(|id| {
                !input
                    .request
                    .candidates
                    .iter()
                    .any(|candidate| &candidate.id == id)
            })
            || label.reviewer_id.as_ref().is_some_and(|id| !text(id))
            || label
                .evidence_sha256
                .as_ref()
                .is_some_and(|digest| !valid_hash(digest))
        {
            return Err(EvalError::Invalid("case label"));
        }
    }
    Ok(())
}
