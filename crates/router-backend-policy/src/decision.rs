use crate::{crypto::fresh, *};
use router_decision::BoundedDecisionContext;
use router_policy::{PhaseRouter, ValidatedPhaseContext};
use router_types::{BackendDataPolicy, BackendFailurePolicy, PhaseReceipt, PhaseSelection};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveDecisionMode {
    Semantic,
    DeterministicFallback,
    Abstained,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveDecisionReason {
    Verified,
    Inactive,
    MissingProposal,
    InvalidProof,
    Expired,
    PolicyMismatch,
    DataPolicy,
    BackendAbstained,
}

/// Serializable audit projection, never itself an execution authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActiveDecisionEvidence {
    pub schema_version: u32,
    pub mode: ActiveDecisionMode,
    pub reason: ActiveDecisionReason,
    pub state_hash: String,
    pub context_hash: String,
    pub pool_hash: String,
    pub baseline_receipt_id: String,
    pub backend_artifact_hash: Option<String>,
    pub promotion_hash: Option<String>,
    pub proposal_sha256: Option<String>,
    pub selected_candidate_id: Option<String>,
    pub decided_at_unix_seconds: u64,
    pub proposal_expires_at_unix_seconds: Option<u64>,
    pub authority_roots_sha256: String,
    pub decision_hash: String,
}
/// Construction is private, fields are immutable, and JSON cannot deserialize
/// into this proof. Consumers must also check the current activation state.
#[derive(Clone, Debug)]
pub struct ActivatedBackendDecision {
    baseline: PhaseReceipt,
    selection: Option<PhaseSelection>,
    evidence: ActiveDecisionEvidence,
}
impl ActivatedBackendDecision {
    pub fn baseline(&self) -> &PhaseReceipt {
        &self.baseline
    }
    pub fn selection(&self) -> Option<&PhaseSelection> {
        self.selection.as_ref()
    }
    pub fn evidence(&self) -> &ActiveDecisionEvidence {
        &self.evidence
    }
    /// A rollback, stale context, age expiry or different exact selection fails
    /// before a consumer may prepare/dispatch this decision.
    pub fn validate_current(
        &self,
        state: &BackendActivationState,
        router: &PhaseRouter,
        context: &ValidatedPhaseContext,
        authorities: &TrustedAuthorities,
        now: u64,
    ) -> Result<()> {
        state.fresh_at(now)?;
        state.validate_authorities(authorities)?;
        if context.policy_hash() != state.baseline_policy_hash() {
            return Err(PromotionError::Context);
        }
        if self.evidence.authority_roots_sha256 != authorities.fingerprint()? {
            return Err(PromotionError::Authority);
        }
        if now < self.evidence.decided_at_unix_seconds
            || self.evidence.state_hash != state.state_hash()
            || self.evidence.context_hash != context.context_hash()
            || self.evidence.pool_hash != context.pool_hash()
            || router.route(context).map_err(|_| PromotionError::Context)? != self.baseline
        {
            return Err(PromotionError::State);
        }
        if let Some(selection) = &self.selection {
            router
                .validate_selection(context, selection)
                .map_err(|_| PromotionError::Context)?;
        }
        if self.evidence.mode == ActiveDecisionMode::Semantic {
            let active = state.active_promotion().ok_or(PromotionError::State)?;
            if active.expires_at_unix_seconds() <= now
                || self.evidence.promotion_hash.as_deref() != Some(active.promotion_hash())
                || self
                    .evidence
                    .proposal_expires_at_unix_seconds
                    .is_none_or(|expires| now >= expires)
                || now - self.evidence.decided_at_unix_seconds
                    > active.artifact().maximum_proposal_age_seconds
            {
                return Err(PromotionError::Freshness);
            }
        }
        Ok(())
    }
}

pub fn decide_active(
    state: &BackendActivationState,
    router: &PhaseRouter,
    context: &ValidatedPhaseContext,
    proposal: Option<&SignedBackendProposal>,
    authorities: &TrustedAuthorities,
    now: u64,
) -> Result<ActivatedBackendDecision> {
    state.fresh_at(now)?;
    state.validate_authorities(authorities)?;
    if context.policy_hash() != state.baseline_policy_hash() {
        return Err(PromotionError::Context);
    }
    let bounded =
        BoundedDecisionContext::from_phase(router, context).map_err(|_| PromotionError::Context)?;
    let baseline = bounded.baseline().clone();
    let mut evidence = ActiveDecisionEvidence {
        schema_version: 1,
        mode: ActiveDecisionMode::DeterministicFallback,
        reason: ActiveDecisionReason::Inactive,
        state_hash: state.state_hash().into(),
        context_hash: context.context_hash().into(),
        pool_hash: context.pool_hash().into(),
        baseline_receipt_id: baseline.receipt_id.clone(),
        backend_artifact_hash: None,
        promotion_hash: None,
        proposal_sha256: None,
        selected_candidate_id: None,
        decided_at_unix_seconds: now,
        proposal_expires_at_unix_seconds: None,
        authority_roots_sha256: authorities.fingerprint()?,
        decision_hash: String::new(),
    };
    let mut selection = baseline.selected.clone();
    if let Some(active) = state.active_promotion() {
        let artifact = active.artifact();
        evidence.backend_artifact_hash = Some(artifact.content_hash()?);
        evidence.promotion_hash = Some(active.promotion_hash().into());
        let result = if active.expires_at_unix_seconds() <= now {
            Err(ActiveDecisionReason::Expired)
        } else if context.policy_hash() != artifact.routing_policy_hash {
            Err(ActiveDecisionReason::PolicyMismatch)
        } else if artifact.data_policy == BackendDataPolicy::Deny {
            Err(ActiveDecisionReason::DataPolicy)
        } else if let Some(proposal) = proposal {
            verify_proposal(
                artifact,
                &bounded,
                proposal,
                &ProposalPurpose::Active(state.state_hash().into()),
                authorities,
                now,
            )
            .map_err(|_| ActiveDecisionReason::InvalidProof)
            .and_then(|selected| {
                let selected = selected.ok_or(ActiveDecisionReason::BackendAbstained)?;
                if selected.score.utility_micros < active.policy().minimum_utility_micros {
                    return Err(ActiveDecisionReason::InvalidProof);
                }
                router
                    .validate_selection(context, selected)
                    .map_err(|_| ActiveDecisionReason::InvalidProof)?;
                Ok(selected.clone())
            })
        } else {
            Err(ActiveDecisionReason::MissingProposal)
        };
        match result {
            Ok(selected) => {
                selection = Some(selected);
                evidence.mode = ActiveDecisionMode::Semantic;
                evidence.reason = ActiveDecisionReason::Verified;
                evidence.proposal_expires_at_unix_seconds =
                    proposal.map(|p| p.statement.expires_at_unix_seconds);
                evidence.proposal_sha256 = Some(digest(
                    "agent-router:signed-backend-proposal:v1\0",
                    &proposal,
                )?);
            }
            Err(reason) => {
                evidence.reason = reason;
                if artifact.failure_policy == BackendFailurePolicy::Abstain {
                    selection = None;
                    evidence.mode = ActiveDecisionMode::Abstained;
                }
            }
        }
    }
    evidence.selected_candidate_id = selection
        .as_ref()
        .map(|selected| selected.candidate.id.clone());
    evidence.decision_hash = digest("agent-router:active-backend-decision:v1\0", &evidence)?;
    Ok(ActivatedBackendDecision {
        baseline,
        selection,
        evidence,
    })
}

pub(crate) fn verify_proposal<'a>(
    artifact: &BackendArtifact,
    context: &'a BoundedDecisionContext,
    signed: &SignedBackendProposal,
    purpose: &ProposalPurpose,
    authorities: &TrustedAuthorities,
    now: u64,
) -> Result<Option<&'a PhaseSelection>> {
    if signed.key_id != artifact.backend_key_id {
        return Err(PromotionError::Authority);
    }
    authorities.verify(AuthorityRole::Backend, signed)?;
    let response = &signed.statement;
    if response.schema_version != 1
        || response.backend_artifact_hash != artifact.content_hash()?
        || &response.purpose != purpose
        || response.request_sha256 != backend_request_hash(context.redacted_request())?
    {
        return Err(PromotionError::Integrity);
    }
    fresh(
        response.issued_at_unix_seconds,
        response.expires_at_unix_seconds,
        artifact.maximum_proposal_age_seconds,
        now,
    )?;
    context
        .selection_for(&response.proposal, artifact.minimum_confidence_micros)
        .map_err(|_| PromotionError::Context)
}
