use std::collections::{BTreeMap, BTreeSet};

use router_adapter_api::{SnapshotValidation, strict_json};
use router_types::{PhaseAbstention, PhaseReceipt};
use serde::{Deserialize, Serialize};

use crate::{
    CandidateCase, EvalError, MAX_REPLAY_BYTES, ReplayRecord, ReplayTrace, Result, hash,
    run_replay_with_verifier, text,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedDecision {
    pub policy_id: String,
    pub candidate_id: Option<String>,
    pub abstention: Option<PhaseAbstention>,
    pub rationale: String,
    /// A generated fixture proposal, never an independent human judgment.
    pub human_validated: bool,
}

/// A replayable, frozen candidate for independent review. The expected receipts
/// are regression artifacts, not evidence of a correct human decision.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateReplay {
    schema_version: u32,
    case: CandidateCase,
    record: ReplayRecord,
    evaluated_at_unix_seconds: u64,
    snapshot_max_age_seconds: u64,
    fixture_provenance: String,
    proposed_decision: ProposedDecision,
    unavailable_candidates: BTreeMap<String, BTreeSet<String>>,
    expected_receipts: BTreeMap<String, PhaseReceipt>,
    expected_trace_hashes: BTreeMap<String, String>,
    content_hash: String,
}

impl CandidateReplay {
    pub fn seal(
        case: CandidateCase,
        record: ReplayRecord,
        validation: SnapshotValidation,
        proposal: ProposedDecision,
        unavailable_candidates: BTreeMap<String, BTreeSet<String>>,
    ) -> Result<Self> {
        Self::seal_with_verifier(
            case,
            record,
            validation,
            proposal,
            unavailable_candidates,
            None,
        )
    }
    pub fn seal_with_verifier(
        case: CandidateCase,
        record: ReplayRecord,
        validation: SnapshotValidation,
        proposal: ProposedDecision,
        unavailable_candidates: BTreeMap<String, BTreeSet<String>>,
        verifier: Option<&dyn router_adapter_api::CapabilityProofVerifier>,
    ) -> Result<Self> {
        let mut candidate = Self {
            schema_version: 1,
            case,
            record,
            evaluated_at_unix_seconds: validation.now_unix_seconds,
            snapshot_max_age_seconds: validation.max_age_seconds,
            fixture_provenance: "synthetic_context_prices_and_usage_not_runtime_measurements"
                .into(),
            proposed_decision: proposal,
            unavailable_candidates,
            expected_receipts: BTreeMap::new(),
            expected_trace_hashes: BTreeMap::new(),
            content_hash: String::new(),
        };
        candidate.validate_identity()?;
        for (id, trace) in candidate.replay_with_verifier(verifier)? {
            candidate
                .expected_trace_hashes
                .insert(id.clone(), trace.trace_hash().into());
            candidate
                .expected_receipts
                .insert(id, trace.receipt().clone());
        }
        let proposal = &candidate.proposed_decision;
        let receipt = candidate
            .expected_receipts
            .get(&proposal.policy_id)
            .ok_or(EvalError::UnknownPolicy)?;
        if receipt.selected.as_ref().map(|s| &s.candidate.id) != proposal.candidate_id.as_ref()
            || receipt.abstention != proposal.abstention
        {
            return Err(EvalError::Invalid(
                "proposed decision differs from fixture constraints",
            ));
        }
        candidate.content_hash = hash(b"agent-router:candidate-replay:v1\0", &candidate)?;
        candidate.canonical_json()?;
        Ok(candidate)
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        Self::from_json_with_verifier(bytes, None)
    }
    pub fn from_json_with_verifier(
        bytes: &[u8],
        verifier: Option<&dyn router_adapter_api::CapabilityProofVerifier>,
    ) -> Result<Self> {
        if bytes.len() > MAX_REPLAY_BYTES {
            return Err(EvalError::Limit("candidate replay bytes"));
        }
        let value = strict_json(bytes).map_err(|_| EvalError::Invalid("candidate replay JSON"))?;
        let parsed: Self = serde_json::from_value(value)
            .map_err(|_| EvalError::Invalid("candidate replay schema"))?;
        let record = ReplayRecord::from_json(&parsed.record.canonical_json()?)?;
        let expected = Self::seal_with_verifier(
            parsed.case.clone(),
            record,
            parsed.validation(),
            parsed.proposed_decision.clone(),
            parsed.unavailable_candidates.clone(),
            verifier,
        )?;
        if expected != parsed {
            return Err(EvalError::Integrity);
        }
        Ok(parsed)
    }
    pub fn replay(&self) -> Result<BTreeMap<String, ReplayTrace>> {
        self.replay_with_verifier(None)
    }
    pub fn replay_with_verifier(
        &self,
        verifier: Option<&dyn router_adapter_api::CapabilityProofVerifier>,
    ) -> Result<BTreeMap<String, ReplayTrace>> {
        self.validate_identity()?;
        self.record
            .input()
            .policies
            .keys()
            .map(|id| {
                let trace = run_replay_with_verifier(
                    &self.record,
                    id,
                    self.validation(),
                    verifier,
                    |context| {
                        let router = router_policy::PhaseRouter::new(context.policy.clone())
                            .map_err(|_| EvalError::Invalid("phase policy"))?;
                        if let Some(unavailable) = self.unavailable_candidates.get(id) {
                            router
                                .fallback(context.phase_context, unavailable)
                                .map_err(|_| EvalError::Backend)
                        } else {
                            router
                                .route(context.phase_context)
                                .map_err(|_| EvalError::Backend)
                        }
                    },
                )?;
                Ok((id.clone(), trace))
            })
            .collect()
    }
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| EvalError::Invalid("candidate replay serialization"))?;
        if bytes.len() > MAX_REPLAY_BYTES {
            return Err(EvalError::Limit("candidate replay bytes"));
        }
        Ok(bytes)
    }
    pub fn record(&self) -> &ReplayRecord {
        &self.record
    }
    pub fn case(&self) -> &CandidateCase {
        &self.case
    }
    pub fn proposed_decision(&self) -> &ProposedDecision {
        &self.proposed_decision
    }
    pub fn expected_receipts(&self) -> &BTreeMap<String, PhaseReceipt> {
        &self.expected_receipts
    }
    pub fn expected_trace_hashes(&self) -> &BTreeMap<String, String> {
        &self.expected_trace_hashes
    }
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }
    pub fn validation(&self) -> SnapshotValidation {
        SnapshotValidation {
            now_unix_seconds: self.evaluated_at_unix_seconds,
            max_age_seconds: self.snapshot_max_age_seconds,
        }
    }
    fn validate_identity(&self) -> Result<()> {
        let input = self.record.input();
        let case = &self.case;
        let proposal = &self.proposed_decision;
        if self.schema_version != 1
            || self.fixture_provenance
                != "synthetic_context_prices_and_usage_not_runtime_measurements"
            || case.human_validated
            || proposal.human_validated
            || !text(&proposal.rationale)
            || case.id != input.case_id
            || case.family_id != input.family_id
            || case.split != input.split
            || case.out_of_domain != input.out_of_domain
            || case.objective != input.request.task.objective
            || case.task_kind != input.request.task.kind
            || case.proposed_risk != input.request.task.risk
            || case.source_refs.is_empty()
            || case.source_refs.len() > 8
            || case.source_refs.iter().any(|s| !text(s))
            || !input.policies.contains_key(&proposal.policy_id)
            || self.unavailable_candidates.iter().any(|(id, ids)| {
                !input.policies.contains_key(id)
                    || ids.len() > 64
                    || ids
                        .iter()
                        .any(|id| !input.request.candidates.iter().any(|c| &c.id == id))
            })
            || proposal.candidate_id.is_some() == proposal.abstention.is_some()
        {
            return Err(EvalError::Invalid("candidate replay identity"));
        }
        let label = input
            .label
            .as_ref()
            .ok_or(EvalError::Invalid("candidate proposal label required"))?;
        if label.human_validated
            || label.independent
            || label.reviewer_id.is_some()
            || label.evidence_sha256.is_some()
            || label.expect_abstention != proposal.abstention.is_some()
            || label.expected_candidate_ids.iter().collect::<Vec<_>>()
                != proposal.candidate_id.iter().collect::<Vec<_>>()
        {
            return Err(EvalError::Invalid(
                "candidate label is not human validation",
            ));
        }
        Ok(())
    }
}
