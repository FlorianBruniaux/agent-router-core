use crate::*;
use router_adapter_api::SnapshotValidation;
use router_decision::BoundedDecisionContext;
use router_eval::{EvaluationMetrics, PairedTrace, PromotionMetric, ReplayRecord, ShadowReport};
use router_policy::PhaseRouter;
use router_types::{BackendFailurePolicy, PhaseAbstention, PhasePolicy, PhaseReceipt};
use std::collections::BTreeMap;

/// The signed aggregate criteria's regression limits also apply to every
/// held-out family. Minimum gains and sample counts remain aggregate gates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FamilyEvaluationReport {
    pub dataset_hash: String,
    pub baseline: EvaluationMetrics,
    pub semantic: EvaluationMetrics,
}

/// Not deserializable: obtaining it always reruns the constraint/replay gates.
#[derive(Clone, Debug)]
pub struct ValidatedBackendEvaluation {
    pub(crate) artifact: BackendArtifact,
    pub(crate) policy: PhasePolicy,
    pub(crate) report: ShadowReport,
    pub(crate) families: BTreeMap<String, FamilyEvaluationReport>,
    pub(crate) evaluation_hash: String,
    pub(crate) latest_evaluation: u64,
    pub(crate) expires_at: u64,
    pub(crate) authority_hash: String,
}
impl ValidatedBackendEvaluation {
    pub fn report(&self) -> &ShadowReport {
        &self.report
    }
    pub fn evaluation_hash(&self) -> &str {
        &self.evaluation_hash
    }
    pub fn family_reports(&self) -> &BTreeMap<String, FamilyEvaluationReport> {
        &self.families
    }
}

#[derive(Clone, Debug)]
pub struct ValidatedBackendPromotion {
    pub(crate) evaluation: ValidatedBackendEvaluation,
    pub(crate) promotion_hash: String,
    pub(crate) ready_at: u64,
}
impl ValidatedBackendPromotion {
    pub fn artifact(&self) -> &BackendArtifact {
        &self.evaluation.artifact
    }
    pub fn policy(&self) -> &PhasePolicy {
        &self.evaluation.policy
    }
    pub fn report(&self) -> &ShadowReport {
        &self.evaluation.report
    }
    pub fn promotion_hash(&self) -> &str {
        &self.promotion_hash
    }
    pub fn expires_at_unix_seconds(&self) -> u64 {
        self.evaluation.expires_at
    }
    pub fn authority_hash(&self) -> &str {
        &self.evaluation.authority_hash
    }
    pub fn family_reports(&self) -> &BTreeMap<String, FamilyEvaluationReport> {
        &self.evaluation.families
    }
}

/// Dataset registration uses the complete frozen replay inputs, including
/// supplied observations/labels, before this offline comparison is performed.
pub fn evaluation_dataset_hash(cases: &[BackendEvaluationCase]) -> Result<String> {
    if cases.is_empty() || cases.len() > MAX_CASES {
        return Err(PromotionError::Limit);
    }
    let mut identities: Vec<_> = cases
        .iter()
        .map(|case| {
            (
                case.record.input().case_id.as_str(),
                case.record.input_hash(),
            )
        })
        .collect();
    identities.sort();
    if identities.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(PromotionError::Invalid);
    }
    digest("agent-router:evaluation-dataset:v1\0", &identities)
}

/// Replays every record. Serialized success reports, raw receipt hashes and
/// unsigned `human_validated: true` flags cannot enter the positive path.
pub fn evaluate_backend(
    artifact: &BackendArtifact,
    criteria: &router_eval::PromotionCriteria,
    registration: &Signed<CriteriaStatement>,
    cases: &[BackendEvaluationCase],
    authorities: &TrustedAuthorities,
    now: u64,
) -> Result<ValidatedBackendEvaluation> {
    evaluate_backend_with_verifier(
        artifact,
        criteria,
        registration,
        cases,
        authorities,
        now,
        None,
    )
}
pub fn evaluate_backend_with_verifier(
    artifact: &BackendArtifact,
    criteria: &router_eval::PromotionCriteria,
    registration: &Signed<CriteriaStatement>,
    cases: &[BackendEvaluationCase],
    authorities: &TrustedAuthorities,
    now: u64,
    verifier: Option<&dyn router_adapter_api::CapabilityProofVerifier>,
) -> Result<ValidatedBackendEvaluation> {
    artifact.validate()?;
    let artifact_hash = artifact.content_hash()?;
    let criteria_digest = criteria_hash(criteria)?;
    if artifact.created_at_unix_seconds > criteria.registered_at_unix_seconds
        || criteria.policy_authors != artifact.authors
        || evaluation_dataset_hash(cases)? != criteria.dataset_hash
        || registration.statement.schema_version != 1
        || registration.statement.backend_artifact_hash != artifact_hash
        || registration.statement.criteria_sha256 != criteria_digest
        || registration.statement.registered_at_unix_seconds != criteria.registered_at_unix_seconds
    {
        return Err(PromotionError::Gate);
    }
    authorities.verify(AuthorityRole::GateOwner, registration)?;
    let mut total = 0usize;
    let mut pairs = Vec::with_capacity(cases.len());
    let mut family_pairs: BTreeMap<String, Vec<PairedTrace>> = BTreeMap::new();
    let mut proofs = BTreeMap::new();
    let mut policy = None;
    let mut latest = 0u64;
    let mut expiry = u64::MAX;
    for case in cases {
        let bytes = case
            .record
            .canonical_json()
            .map_err(|_| PromotionError::Integrity)?;
        total = total
            .checked_add(bytes.len())
            .ok_or(PromotionError::Limit)?;
        if total > MAX_DOCUMENT_BYTES {
            return Err(PromotionError::Limit);
        }
        let record = ReplayRecord::from_json(&bytes).map_err(|_| PromotionError::Integrity)?;
        let input = record.input();
        if !label(&case.baseline_policy_id)
            || !label(&case.semantic_policy_id)
            || case.baseline_policy_id == case.semantic_policy_id
            || case.evaluated_at_unix_seconds > now
            || case.evaluated_at_unix_seconds <= criteria.registered_at_unix_seconds
            || now - case.evaluated_at_unix_seconds > artifact.maximum_evidence_age_seconds
            || case.snapshot_max_age_seconds > 30 * 86_400
        {
            return Err(PromotionError::Freshness);
        }
        let baseline_policy = input
            .policies
            .get(&case.baseline_policy_id)
            .ok_or(PromotionError::Gate)?;
        let semantic_policy = input
            .policies
            .get(&case.semantic_policy_id)
            .ok_or(PromotionError::Gate)?;
        if baseline_policy != semantic_policy
            || digest("phase-policy-v2\0", baseline_policy)? != artifact.routing_policy_hash
            || policy
                .as_ref()
                .is_some_and(|previous| previous != baseline_policy)
        {
            return Err(PromotionError::Gate);
        }
        policy = Some(baseline_policy.clone());
        let human = input.label.as_ref().ok_or(PromotionError::Gate)?;
        if !human.human_validated
            || !human.independent
            || human.reviewer_id.as_deref() != Some(case.label.key_id.as_str())
            || artifact.authors.contains(&case.label.key_id)
            || case.label.statement.schema_version != 1
            || case.label.statement.replay_input_hash != record.input_hash()
            || case.label.statement.label_sha256 != label_hash(human)?
            || case.label.statement.reviewed_at_unix_seconds > case.evaluated_at_unix_seconds
        {
            return Err(PromotionError::Gate);
        }
        authorities.verify(AuthorityRole::HumanReviewer, &case.label)?;
        let validation = SnapshotValidation {
            now_unix_seconds: case.evaluated_at_unix_seconds,
            max_age_seconds: case.snapshot_max_age_seconds,
        };
        let baseline = router_eval::replay_deterministic_with_verifier(
            &record,
            &case.baseline_policy_id,
            validation,
            verifier,
        )
        .map_err(|_| PromotionError::Gate)?;
        let semantic = router_eval::run_replay_with_verifier(
            &record,
            &case.semantic_policy_id,
            validation,
            verifier,
            |context| {
                let router = PhaseRouter::new(context.policy.clone())
                    .map_err(|_| router_eval::EvalError::Backend)?;
                let bounded = BoundedDecisionContext::from_phase(&router, context.phase_context)
                    .map_err(|_| router_eval::EvalError::Backend)?;
                let selection = crate::decision::verify_proposal(
                    artifact,
                    &bounded,
                    &case.proposal,
                    &ProposalPurpose::Evaluation(record.input_hash().into()),
                    authorities,
                    case.evaluated_at_unix_seconds,
                )
                .map_err(|_| router_eval::EvalError::Backend)?;
                if selection.as_ref().is_some_and(|selected| {
                    selected.score.utility_micros < context.policy.minimum_utility_micros
                }) {
                    return Err(router_eval::EvalError::Backend);
                }
                evaluation_receipt(
                    bounded.baseline(),
                    selection.cloned(),
                    artifact.failure_policy,
                )
                .map_err(|_| router_eval::EvalError::Backend)
            },
        )
        .map_err(|_| PromotionError::Gate)?;
        proofs.insert(
            input.case_id.clone(),
            (
                baseline.trace_hash().to_owned(),
                semantic.trace_hash().to_owned(),
                digest(
                    "backend-case-evidence-v1\0",
                    &(case.label.clone(), case.proposal.clone()),
                )?,
            ),
        );
        latest = latest.max(case.evaluated_at_unix_seconds);
        expiry = expiry.min(
            case.evaluated_at_unix_seconds
                .checked_add(artifact.maximum_evidence_age_seconds)
                .ok_or(PromotionError::Freshness)?,
        );
        let pair = PairedTrace { baseline, semantic };
        family_pairs
            .entry(input.family_id.clone())
            .or_default()
            .push(pair.clone());
        pairs.push(pair);
    }
    let report =
        router_eval::compare_shadow(&pairs, Some(criteria)).map_err(|_| PromotionError::Gate)?;
    if !report.semantic_enabled || !report.promotion_blockers.is_empty() {
        return Err(PromotionError::Gate);
    }
    let mut families = BTreeMap::new();
    for (family, pairs) in family_pairs {
        // Compare with the original signed criteria so independent labels use
        // the same author exclusions. Dataset size, minimum gains and global
        // registration binding have already been checked above; a family is
        // not a separately registered promotion dataset.
        let cohort = router_eval::compare_shadow(&pairs, Some(criteria))
            .map_err(|_| PromotionError::Gate)?;
        for rule in &criteria.rules {
            let improvement = metric_improvement(rule.metric, &cohort.baseline, &cohort.semantic)
                .ok_or(PromotionError::Gate)?;
            if improvement < -i128::from(rule.maximum_regression_micros) {
                return Err(PromotionError::Gate);
            }
        }
        families.insert(
            family,
            FamilyEvaluationReport {
                dataset_hash: cohort.dataset_hash,
                baseline: cohort.baseline,
                semantic: cohort.semantic,
            },
        );
    }
    let authority_hash = authorities.fingerprint()?;
    let evaluation_hash = digest(
        "agent-router:verified-backend-evaluation:v1\0",
        &(
            &artifact_hash,
            &report,
            &families,
            registration,
            &proofs,
            &authority_hash,
        ),
    )?;
    Ok(ValidatedBackendEvaluation {
        artifact: artifact.clone(),
        policy: policy.ok_or(PromotionError::Gate)?,
        report,
        families,
        evaluation_hash,
        latest_evaluation: latest,
        expires_at: expiry,
        authority_hash,
    })
}

fn metric_improvement(
    metric: PromotionMetric,
    baseline: &EvaluationMetrics,
    semantic: &EvaluationMetrics,
) -> Option<i128> {
    match metric {
        PromotionMetric::RouteAccuracy => Some(
            i128::from(semantic.route_accuracy_micros?)
                - i128::from(baseline.route_accuracy_micros?),
        ),
        PromotionMetric::Abstention => {
            Some(i128::from(baseline.abstention_micros) - i128::from(semantic.abstention_micros))
        }
        PromotionMetric::Cost => Some(relative_reduction(
            baseline.total_cost_microusd,
            semantic.total_cost_microusd,
        )),
        PromotionMetric::Latency => Some(relative_reduction(
            baseline.total_elapsed_ms?,
            semantic.total_elapsed_ms?,
        )),
        PromotionMetric::FunctionalSuccess => {
            if baseline.functional.unknown > 0
                || semantic.functional.unknown > 0
                || baseline.cases == 0
                || semantic.cases == 0
            {
                return None;
            }
            Some(
                (semantic.functional.passed as i128 * 1_000_000 / semantic.cases as i128)
                    - (baseline.functional.passed as i128 * 1_000_000 / baseline.cases as i128),
            )
        }
    }
}

fn relative_reduction(baseline: u64, semantic: u64) -> i128 {
    if baseline == 0 {
        return if semantic == 0 { 0 } else { -1_000_001 };
    }
    (i128::from(baseline) - i128::from(semantic)) * 1_000_000 / i128::from(baseline)
}

pub fn evaluate_promotion(
    artifact: &BackendArtifact,
    evidence: &PromotionEvidence,
    authorities: &TrustedAuthorities,
    now: u64,
) -> Result<ValidatedBackendPromotion> {
    evaluate_promotion_with_verifier(artifact, evidence, authorities, now, None)
}
pub fn evaluate_promotion_with_verifier(
    artifact: &BackendArtifact,
    evidence: &PromotionEvidence,
    authorities: &TrustedAuthorities,
    now: u64,
    verifier: Option<&dyn router_adapter_api::CapabilityProofVerifier>,
) -> Result<ValidatedBackendPromotion> {
    if evidence.schema_version != 1 {
        return Err(PromotionError::Invalid);
    }
    let evaluation = evaluate_backend_with_verifier(
        artifact,
        &evidence.criteria,
        &evidence.criteria_registration,
        &evidence.cases,
        authorities,
        now,
        verifier,
    )?;
    let mut previous = evaluation.latest_evaluation;
    for (expected, signed) in [
        (TrialStage::Shadow, &evidence.shadow),
        (TrialStage::Canary, &evidence.canary),
    ] {
        authorities.verify(AuthorityRole::GateOwner, signed)?;
        let trial = &signed.statement;
        if trial.schema_version != 1
            || trial.stage != expected
            || trial.backend_artifact_hash != artifact.content_hash()?
            || trial.evaluation_sha256 != evaluation.evaluation_hash
            || !valid_hash(&trial.evidence_sha256)
            || !trial.accepted
            || trial.hard_constraint_violations != 0
            || trial.subgroup_regressions != 0
            || trial.cases == 0
            || trial.cases > MAX_CASES
            || trial.started_at_unix_seconds < previous
            || trial.completed_at_unix_seconds < trial.started_at_unix_seconds
            || trial.completed_at_unix_seconds > now
            || (expected == TrialStage::Shadow && trial.cases < artifact.minimum_shadow_cases)
            || (expected == TrialStage::Canary && trial.cases > artifact.maximum_canary_cases)
        {
            return Err(PromotionError::Gate);
        }
        previous = trial.completed_at_unix_seconds;
    }
    if evidence.shadow.statement.evidence_sha256 == evidence.canary.statement.evidence_sha256 {
        return Err(PromotionError::Gate);
    }
    let promotion_hash = digest(
        "agent-router:backend-promotion:v1\0",
        &(
            &evaluation.evaluation_hash,
            &evidence.shadow,
            &evidence.canary,
        ),
    )?;
    Ok(ValidatedBackendPromotion {
        evaluation,
        promotion_hash,
        ready_at: previous,
    })
}

// A v2 projection is used only by the existing offline audit harness. Production
// receives a separate opaque ActivatedBackendDecision, never a forged stable receipt.
fn evaluation_receipt(
    baseline: &PhaseReceipt,
    selection: Option<router_types::PhaseSelection>,
    failure: BackendFailurePolicy,
) -> Result<PhaseReceipt> {
    if selection.is_none() && failure == BackendFailurePolicy::DeterministicFallback {
        return Ok(baseline.clone());
    }
    let mut receipt = baseline.clone();
    receipt.alternatives = baseline
        .selected
        .iter()
        .chain(&baseline.alternatives)
        .filter(|candidate| {
            selection
                .as_ref()
                .is_none_or(|selected| selected.candidate.id != candidate.candidate.id)
        })
        .take(baseline.alternatives.len())
        .cloned()
        .collect();
    receipt.selected = selection;
    receipt.abstention = receipt
        .selected
        .is_none()
        .then_some(PhaseAbstention::Ambiguous);
    receipt.receipt_id.clear();
    receipt.receipt_id = digest(
        if receipt.schema_version == 6 {
            "phase-receipt-v6\0"
        } else if receipt.schema_version == 5 {
            "phase-receipt-v5\0"
        } else {
            "phase-receipt-v2\0"
        },
        &receipt,
    )?;
    Ok(receipt)
}
