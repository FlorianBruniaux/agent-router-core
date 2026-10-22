#![forbid(unsafe_code)]

#[cfg(feature = "local-sidecar")]
mod http;
#[cfg(feature = "local-sidecar")]
mod sidecar;
#[cfg(feature = "local-sidecar")]
mod standard_sidecar;
#[cfg(feature = "local-sidecar")]
pub use sidecar::{JevSidecarBackend, LayaLocalBackend};
#[cfg(feature = "local-sidecar")]
pub use standard_sidecar::*;

use router_policy::{PhaseRouter, ValidatedPhaseContext};
use router_types::{
    BackendCandidate, BackendDataPolicy, BackendDecision, BackendFailurePolicy, BackendProposal,
    BackendRequest, PhaseReceipt, PhaseSelection,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

pub const MAX_BACKEND_CANDIDATES: usize = 20;
pub const MAX_REQUEST_BYTES: usize = 32 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("backend.protocol.incompatible")]
    Protocol,
    #[error("backend.delivery.unknown")]
    DeliveryUnknown,
    #[error("backend.invalid")]
    Invalid,
    #[error("backend.data_policy.denied")]
    DataPolicy,
    #[error("backend.timeout")]
    Timeout,
    #[error("backend.transport")]
    Transport,
    #[error("backend.schema")]
    Schema,
    #[error("backend.out_of_pool")]
    OutOfPool,
    #[error("backend.confidence.low")]
    LowConfidence,
    #[error("backend.abstained")]
    Abstained,
    #[error("backend.integrity")]
    Integrity,
    #[error("backend.endpoint.not_loopback")]
    Endpoint,
    #[error("backend.limit")]
    Limit,
}
impl BackendError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Protocol => "backend.protocol.incompatible",
            Self::DeliveryUnknown => "backend.delivery.unknown",
            Self::Invalid => "backend.invalid",
            Self::DataPolicy => "backend.data_policy.denied",
            Self::Timeout => "backend.timeout",
            Self::Transport => "backend.transport",
            Self::Schema => "backend.schema",
            Self::OutOfPool => "backend.out_of_pool",
            Self::LowConfidence => "backend.confidence.low",
            Self::Abstained => "backend.abstained",
            Self::Integrity => "backend.integrity",
            Self::Endpoint => "backend.endpoint.not_loopback",
            Self::Limit => "backend.limit",
        }
    }
}
pub type Result<T> = std::result::Result<T, BackendError>;

/// Implementations consume only a closed, redacted pool. An in-process custom
/// implementation is trusted Rust code and must honor the supplied deadline.
/// The shipped network adapters enforce a total wall-clock I/O deadline.
pub trait DecisionBackend {
    fn name(&self) -> &'static str;
    fn requires_data_policy(&self) -> bool {
        true
    }
    fn propose(&self, request: &BackendRequest, deadline: Instant) -> Result<BackendProposal>;
}

#[derive(Clone, Debug)]
pub struct BoundedDecisionContext {
    request: BackendRequest,
    baseline: PhaseReceipt,
    selections: BTreeMap<String, PhaseSelection>,
}
impl BoundedDecisionContext {
    pub fn from_phase(router: &PhaseRouter, context: &ValidatedPhaseContext) -> Result<Self> {
        let baseline = router.route(context).map_err(|_| BackendError::Invalid)?;
        let mut choices: Vec<_> = baseline
            .selected
            .iter()
            .chain(baseline.alternatives.iter())
            .cloned()
            .collect();
        choices.sort_by(|a, b| {
            b.score
                .utility_micros
                .cmp(&a.score.utility_micros)
                .then_with(|| a.candidate.id.cmp(&b.candidate.id))
        });
        choices.dedup_by(|a, b| a.candidate.id == b.candidate.id);
        choices.truncate(MAX_BACKEND_CANDIDATES);
        let mut selections = BTreeMap::new();
        let mut candidates = Vec::new();
        for (index, selection) in choices.into_iter().enumerate() {
            router
                .validate_selection(context, &selection)
                .map_err(|_| BackendError::Invalid)?;
            let id = format!("c{index:02}");
            candidates.push(BackendCandidate {
                id: id.clone(),
                utility_micros: selection.score.utility_micros,
                cost_microusd: selection.candidate.estimated_cost_microusd,
                tokens: selection.candidate.estimated_tokens,
                elapsed_ms: selection.candidate.estimated_elapsed_ms,
            });
            selections.insert(id, selection);
        }
        let task = &context.request().task;
        let request = BackendRequest {
            schema_version: 1,
            artifact_digest: context.context_hash().into(),
            kind: task.kind,
            risk: task.risk,
            phase: context.request().phase,
            candidates,
        };
        validate_request(&request)?;
        Ok(Self {
            request,
            baseline,
            selections,
        })
    }
    pub fn redacted_request(&self) -> &BackendRequest {
        &self.request
    }
    pub fn baseline(&self) -> &PhaseReceipt {
        &self.baseline
    }
    /// Digest of the alias to candidate and score table. Aliases are regenerated
    /// per context, so a redacted request alone does not identify what `c00` names.
    pub fn alias_digest(&self) -> Result<String> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"backend-alias-table-v1\0");
        for (id, selection) in &self.selections {
            let bytes = serde_json::to_vec(&(id, &selection.candidate, &selection.score))
                .map_err(|_| BackendError::Schema)?;
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    /// Resolve a structurally valid proposal into this context's already
    /// constrained selection. This read-only lookup is not activation authority.
    /// Explicit backend abstention returns None; low confidence remains an error.
    pub fn selection_for(
        &self,
        proposal: &BackendProposal,
        minimum_confidence: u32,
    ) -> Result<Option<&PhaseSelection>> {
        match validate_proposal(&self.request, proposal, minimum_confidence) {
            Ok(()) => {}
            Err(BackendError::Abstained) => return Ok(None),
            Err(error) => return Err(error),
        }
        let id = proposal
            .candidate_id
            .as_ref()
            .ok_or(BackendError::Abstained)?;
        self.selections
            .get(id)
            .map(Some)
            .ok_or(BackendError::OutOfPool)
    }
}

pub struct DeterministicBackend;
impl DecisionBackend for DeterministicBackend {
    fn name(&self) -> &'static str {
        "deterministic"
    }
    fn requires_data_policy(&self) -> bool {
        false
    }
    fn propose(&self, request: &BackendRequest, deadline: Instant) -> Result<BackendProposal> {
        validate_request(request)?;
        if Instant::now() >= deadline {
            return Err(BackendError::Timeout);
        }
        let mut ranked: Vec<_> = request.candidates.iter().collect();
        ranked.sort_by(|a, b| {
            b.utility_micros
                .cmp(&a.utility_micros)
                .then_with(|| a.id.cmp(&b.id))
        });
        let selected = ranked.first().filter(|first| {
            ranked
                .get(1)
                .is_none_or(|next| next.utility_micros != first.utility_micros)
        });
        let candidate_id = selected.map(|candidate| candidate.id.clone());
        Ok(BackendProposal {
            schema_version: 1,
            artifact_digest: request.artifact_digest.clone(),
            confidence_micros: if candidate_id.is_some() { 1_000_000 } else { 0 },
            candidate_id,
            probabilities_micros: BTreeMap::new(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BackendOptions {
    pub data_policy: BackendDataPolicy,
    pub failure_policy: BackendFailurePolicy,
    pub timeout: Duration,
    pub minimum_confidence_micros: u32,
}
impl Default for BackendOptions {
    fn default() -> Self {
        Self {
            data_policy: BackendDataPolicy::Deny,
            failure_policy: BackendFailurePolicy::DeterministicFallback,
            timeout: Duration::from_millis(500),
            minimum_confidence_micros: 800_000,
        }
    }
}

/// Semantic proposals remain shadow-only. This function cannot promote a policy
/// or replace a production receipt; promotion requires independent replay gates.
pub fn decide_shadow(
    context: &BoundedDecisionContext,
    backend: &(impl DecisionBackend + ?Sized),
    options: BackendOptions,
) -> Result<BackendDecision> {
    if options.timeout.is_zero()
        || options.timeout > Duration::from_secs(10)
        || options.minimum_confidence_micros > 1_000_000
    {
        return Err(BackendError::Invalid);
    }
    let mut outcome = BackendDecision {
        schema_version: 1,
        baseline_receipt_id: context.baseline.receipt_id.clone(),
        backend: backend.name().into(),
        active_candidate_id: context
            .baseline
            .selected
            .as_ref()
            .map(|choice| choice.candidate.id.clone()),
        shadow_candidate_id: None,
        confidence_micros: None,
        fallback_reason: None,
        semantic_execution_enabled: false,
    };
    let result = if options.data_policy == BackendDataPolicy::Deny && backend.requires_data_policy()
    {
        Err(BackendError::DataPolicy)
    } else {
        let deadline = Instant::now() + options.timeout;
        backend
            .propose(&context.request, deadline)
            .and_then(|proposal| {
                if Instant::now() >= deadline {
                    return Err(BackendError::Timeout);
                }
                validate_proposal(
                    &context.request,
                    &proposal,
                    options.minimum_confidence_micros,
                )?;
                Ok(proposal)
            })
    };
    match result {
        Ok(proposal) => {
            let id = proposal
                .candidate_id
                .as_ref()
                .ok_or(BackendError::Abstained)?;
            let choice = context.selections.get(id).ok_or(BackendError::OutOfPool)?;
            outcome.shadow_candidate_id = Some(choice.candidate.id.clone());
            outcome.confidence_micros = Some(proposal.confidence_micros);
        }
        Err(error) => {
            outcome.fallback_reason = Some(error.code().into());
            if options.failure_policy == BackendFailurePolicy::Abstain {
                outcome.active_candidate_id = None;
            }
        }
    }
    Ok(outcome)
}

pub fn validate_request(request: &BackendRequest) -> Result<()> {
    if request.schema_version != 1
        || !digest(&request.artifact_digest)
        || request.candidates.len() > MAX_BACKEND_CANDIDATES
    {
        return Err(BackendError::Invalid);
    }
    let mut ids = BTreeSet::new();
    for candidate in &request.candidates {
        if candidate.id.len() != 3
            || !candidate.id.starts_with('c')
            || !candidate.id.as_bytes()[1..].iter().all(u8::is_ascii_digit)
            || !ids.insert(&candidate.id)
        {
            return Err(BackendError::Invalid);
        }
    }
    if serde_json::to_vec(request)
        .map_err(|_| BackendError::Schema)?
        .len()
        > MAX_REQUEST_BYTES
    {
        return Err(BackendError::Limit);
    }
    Ok(())
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub fn validate_proposal(
    request: &BackendRequest,
    proposal: &BackendProposal,
    minimum_confidence: u32,
) -> Result<()> {
    validate_request(request)?;
    if proposal.schema_version != 1 || proposal.artifact_digest != request.artifact_digest {
        return Err(BackendError::Integrity);
    }
    if proposal.confidence_micros > 1_000_000
        || minimum_confidence > 1_000_000
        || proposal.probabilities_micros.len() > MAX_BACKEND_CANDIDATES
    {
        return Err(BackendError::Schema);
    }
    let pool: BTreeSet<_> = request
        .candidates
        .iter()
        .map(|candidate| candidate.id.as_str())
        .collect();
    if proposal
        .probabilities_micros
        .iter()
        .any(|(id, value)| !pool.contains(id.as_str()) || *value > 1_000_000)
    {
        return Err(BackendError::OutOfPool);
    }
    if !proposal.probabilities_micros.is_empty() {
        let sum: u64 = proposal
            .probabilities_micros
            .values()
            .map(|value| u64::from(*value))
            .sum();
        // The Jev-compatible Laya wire format rounds probabilities to four
        // decimal places, so permit at most one such unit per supplied entry.
        if sum.abs_diff(1_000_000) > 100 * proposal.probabilities_micros.len() as u64 {
            return Err(BackendError::Schema);
        }
    }
    let selected = proposal
        .candidate_id
        .as_deref()
        .ok_or(BackendError::Abstained)?;
    if !pool.contains(selected) {
        return Err(BackendError::OutOfPool);
    }
    if proposal.confidence_micros < minimum_confidence {
        return Err(BackendError::LowConfidence);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/support/capability_verifier.rs"]
mod fixture_proofs;

#[cfg(test)]
mod tests {
    use super::*;
    use router_adapter_api::SnapshotValidation;
    use router_catalog::Catalog;

    fn context() -> BoundedDecisionContext {
        let request = serde_json::from_str(include_str!(
            "../../../fixtures/examples/phase-request.json"
        ))
        .unwrap();
        let snapshot = crate::fixture_proofs::from_json(
            include_bytes!("../../../fixtures/examples/phase-snapshot.json"),
            SnapshotValidation {
                now_unix_seconds: 100,
                max_age_seconds: 60,
            },
        )
        .unwrap();
        let catalog = Catalog::from_json(include_bytes!(
            "../../../fixtures/examples/phase-catalog.json"
        ))
        .unwrap();
        let router = PhaseRouter::stable_v2();
        let phase = router.context(request, &snapshot, &catalog).unwrap();
        BoundedDecisionContext::from_phase(&router, &phase).unwrap()
    }

    // Through the public API the redacted request and the alias table move
    // together, because the artifact digest covers the whole phase request. The
    // alias digest is a second binding that must still notice a table that
    // differs behind an identical redacted request.
    #[test]
    fn alias_digest_changes_when_only_the_alias_table_changes() {
        let original = context();
        assert_eq!(
            original.alias_digest().unwrap(),
            context().alias_digest().unwrap()
        );
        let mut swapped = original.clone();
        let candidate = |context: &mut BoundedDecisionContext, id: &str| {
            context
                .selections
                .get_mut(id)
                .unwrap()
                .candidate
                .estimated_cost_microusd += 1;
        };
        candidate(&mut swapped, "c00");
        assert_eq!(swapped.redacted_request(), original.redacted_request());
        assert_ne!(
            swapped.alias_digest().unwrap(),
            original.alias_digest().unwrap()
        );

        // Same encoded length, so a length-only digest could not tell them apart.
        let mut rescored = original.clone();
        rescored
            .selections
            .get_mut("c00")
            .unwrap()
            .score
            .utility_micros += 1;
        assert_eq!(rescored.redacted_request(), original.redacted_request());
        assert_ne!(
            rescored.alias_digest().unwrap(),
            original.alias_digest().unwrap()
        );

        // Exchanging what two aliases name is also a different table.
        let mut exchanged = original.clone();
        let (first, second) = (
            exchanged.selections["c00"].clone(),
            exchanged.selections["c01"].clone(),
        );
        exchanged.selections.insert("c00".into(), second);
        exchanged.selections.insert("c01".into(), first);
        assert_eq!(exchanged.redacted_request(), original.redacted_request());
        assert_ne!(
            exchanged.alias_digest().unwrap(),
            original.alias_digest().unwrap()
        );
    }
}
