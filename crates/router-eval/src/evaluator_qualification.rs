//! Bounded offline checks of supplied evaluator evidence. No authenticity or authority is granted.
use crate::{ObservedOutcome, hash, valid_hash};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_EVALUATOR_QUALIFICATION_BYTES: usize = 4 * 1024 * 1024;
const MAX_INSTANCES: usize = 256;
const MAX_ROWS: usize = 4096;
const MAX_EVALUATORS: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum EvaluatorQualificationError {
    #[error("eval.evaluator_qualification.invalid")]
    Invalid,
    #[error("eval.evaluator_qualification.limit")]
    Limit,
    #[error("eval.evaluator_qualification.integrity")]
    Integrity,
    #[error("eval.evaluator_qualification.cost_overflow")]
    CostOverflow,
}
type Result<T> = std::result::Result<T, EvaluatorQualificationError>;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskIntention {
    Design,
    Implementation,
    Validation,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorTaskContract {
    pub instance_id: String,
    pub intention: TaskIntention,
    pub source_sha256: String,
    pub input_sha256: String,
    pub criteria_sha256: String,
    pub required_case_ids: Vec<String>,
    pub candidate_authors: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorIdentity {
    pub evaluator_id: String,
    pub version: String,
    pub executable_sha256: String,
    pub configuration_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum QualificationWitnessKind {
    CorrectOutput,
    KnownDefect,
    InfrastructureFailure,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QualificationWitness {
    pub case_id: String,
    pub output_sha256: String,
    pub kind: QualificationWitnessKind,
    pub observed: ObservedOutcome,
    pub reviewer_id: String,
    pub oracle_evidence_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SuppliedEvaluatorQualification {
    pub evaluator: EvaluatorIdentity,
    pub corpus_sha256: String,
    pub applicable_criteria_sha256: Vec<String>,
    pub max_duration_ms: u64,
    pub max_output_bytes: u64,
    pub witnesses: Vec<QualificationWitness>,
    pub tuning_output_sha256: Vec<String>,
    /// Schema 2 requires the complete supplied set, including an explicit empty set.
    /// IDs and outputs are independent sets: one tuning case may have many outputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tuning_case_ids: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvaluatorExecution {
    Completed,
    InfrastructureFailure,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequiredCaseOutcome {
    pub case_id: String,
    pub outcome: ObservedOutcome,
    pub execution: EvaluatorExecution,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoredEvaluatorVerdict {
    pub verdict_id: String,
    pub instance_id: String,
    pub task_contract_sha256: String,
    pub cohort_sha256: String,
    pub evaluator: EvaluatorIdentity,
    pub revision_sha256: String,
    pub output_sha256: String,
    pub cases: Vec<RequiredCaseOutcome>,
    /// Names an earlier verdict on exactly the same stored output, never a new run.
    pub reevaluates: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorComparisonSelection {
    pub instance_id: String,
    pub reference_verdict_id: Option<String>,
    pub candidate_verdict_id: Option<String>,
    /// Supplied totals only. No cost is inferred from a verdict or reevaluation.
    pub reference_cost_microusd: Option<u64>,
    pub candidate_cost_microusd: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvaluatorPermittedDifference {
    Revision,
    Output,
    Cost,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorQualificationInput {
    pub schema_version: u32,
    pub cohort: Vec<EvaluatorTaskContract>,
    pub cohort_sha256: String,
    pub permitted_differences: Vec<EvaluatorPermittedDifference>,
    pub qualifications: Vec<SuppliedEvaluatorQualification>,
    pub verdicts: Vec<StoredEvaluatorVerdict>,
    pub comparisons: Vec<EvaluatorComparisonSelection>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvaluatorComparisonStatus {
    RequiredCasesSatisfied,
    RequiredCasesFailed,
    Regression,
    Inconclusive,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct EvaluatorQualificationSummary {
    pub evaluator: EvaluatorIdentity,
    pub corpus_sha256: String,
    pub structurally_consistent: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RequiredCaseComparison {
    pub case_id: String,
    pub reference: ObservedOutcome,
    pub candidate: ObservedOutcome,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct EvaluatorInstanceComparison {
    pub instance_id: String,
    pub task_contract_sha256: String,
    pub reference_verdict_id: Option<String>,
    pub candidate_verdict_id: Option<String>,
    pub status: EvaluatorComparisonStatus,
    pub blockers: Vec<String>,
    pub cases: Vec<RequiredCaseComparison>,
    pub regressed_case_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct EvaluatorQualificationReport {
    pub schema_version: u32,
    pub cohort_sha256: String,
    pub oracle_authenticity: &'static str,
    pub adoption_authorized: bool,
    pub qualifications: Vec<EvaluatorQualificationSummary>,
    pub comparisons: Vec<EvaluatorInstanceComparison>,
    pub verdict_history: Vec<StoredEvaluatorVerdict>,
    pub supplied_reference_cost_microusd: Option<u64>,
    pub supplied_candidate_cost_microusd: Option<u64>,
}

/// Order is part of each v1 seal. These hashes bind supplied contents, not origin.
pub fn evaluator_task_contract_sha256(task: &EvaluatorTaskContract) -> Result<String> {
    seal(b"agent-router:evaluator-task:v1\0", task)
}
pub fn evaluator_cohort_sha256(cohort: &[EvaluatorTaskContract]) -> Result<String> {
    seal(b"agent-router:evaluator-cohort:v1\0", &cohort)
}
pub fn evaluator_qualification_corpus_sha256(witnesses: &[QualificationWitness]) -> Result<String> {
    seal(b"agent-router:evaluator-corpus:v1\0", &witnesses)
}
fn seal<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    hash(domain, value).map_err(|_| EvaluatorQualificationError::Invalid)
}

/// Checks supplied records only. Never executes an evaluator, authenticates an
/// oracle, records a run, writes history or grants adoption authority.
pub fn evaluator_qualification_report(bytes: &[u8]) -> Result<EvaluatorQualificationReport> {
    if bytes.len() > MAX_EVALUATOR_QUALIFICATION_BYTES {
        return Err(EvaluatorQualificationError::Limit);
    }
    let value = router_adapter_api::strict_json_limited(bytes, MAX_EVALUATOR_QUALIFICATION_BYTES)
        .map_err(|_| EvaluatorQualificationError::Invalid)?;
    let input: EvaluatorQualificationInput =
        serde_json::from_value(value).map_err(|_| EvaluatorQualificationError::Invalid)?;
    validate(&input)?;
    let authors: BTreeSet<_> = input
        .cohort
        .iter()
        .flat_map(|task| &task.candidate_authors)
        .collect();
    let qualifications: Vec<_> = input
        .qualifications
        .iter()
        .map(|qualification| {
            let kinds: BTreeSet<_> = qualification.witnesses.iter().map(|w| w.kind).collect();
            let consistent = kinds.len() == 3
                && qualification.witnesses.iter().all(|w| {
                    let expected = match w.kind {
                        QualificationWitnessKind::CorrectOutput => ObservedOutcome::Passed,
                        QualificationWitnessKind::KnownDefect => ObservedOutcome::Failed,
                        QualificationWitnessKind::InfrastructureFailure => ObservedOutcome::Unknown,
                    };
                    w.observed == expected && !authors.contains(&w.reviewer_id)
                });
            EvaluatorQualificationSummary {
                evaluator: qualification.evaluator.clone(),
                corpus_sha256: qualification.corpus_sha256.clone(),
                structurally_consistent: consistent,
            }
        })
        .collect();
    let comparisons = input
        .cohort
        .iter()
        .map(|task| compare_task(&input, &qualifications, task))
        .collect::<Result<Vec<_>>>()?;
    Ok(EvaluatorQualificationReport {
        schema_version: input.schema_version,
        cohort_sha256: input.cohort_sha256.clone(),
        oracle_authenticity: "supplied_unverified",
        adoption_authorized: false,
        qualifications,
        comparisons,
        verdict_history: input.verdicts.clone(),
        supplied_reference_cost_microusd: total_cost(&input, false)?,
        supplied_candidate_cost_microusd: total_cost(&input, true)?,
    })
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn unique<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|value| seen.insert(value))
}
fn identity_valid(identity: &EvaluatorIdentity) -> bool {
    identifier(&identity.evaluator_id)
        && identifier(&identity.version)
        && valid_hash(&identity.executable_sha256)
        && valid_hash(&identity.configuration_sha256)
}
fn validate(input: &EvaluatorQualificationInput) -> Result<()> {
    use EvaluatorQualificationError::{Integrity, Invalid, Limit};
    if !matches!(input.schema_version, 1 | 2) || input.cohort.is_empty() {
        return Err(Invalid);
    }
    if input.cohort.len() > MAX_INSTANCES
        || input.qualifications.len() > MAX_EVALUATORS
        || input.verdicts.len() > MAX_ROWS
        || input.comparisons.len() > MAX_INSTANCES
    {
        return Err(Limit);
    }
    let rows = input
        .cohort
        .iter()
        .map(|t| t.required_case_ids.len() + t.candidate_authors.len())
        .sum::<usize>()
        + input
            .qualifications
            .iter()
            .map(|q| {
                q.witnesses.len()
                    + q.tuning_output_sha256.len()
                    + q.tuning_case_ids.as_ref().map_or(0, Vec::len)
                    + q.applicable_criteria_sha256.len()
            })
            .sum::<usize>()
        + input.verdicts.iter().map(|v| v.cases.len()).sum::<usize>();
    if rows > MAX_ROWS {
        return Err(Limit);
    }
    if !unique(input.cohort.iter().map(|t| t.instance_id.as_str()))
        || !unique(input.comparisons.iter().map(|s| s.instance_id.as_str()))
        || input
            .permitted_differences
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != input.permitted_differences.len()
    {
        return Err(Invalid);
    }
    for task in &input.cohort {
        if !identifier(&task.instance_id)
            || !valid_hash(&task.source_sha256)
            || !valid_hash(&task.input_sha256)
            || !valid_hash(&task.criteria_sha256)
            || task.required_case_ids.is_empty()
            || task.candidate_authors.is_empty()
            || task
                .required_case_ids
                .iter()
                .chain(&task.candidate_authors)
                .any(|id| !identifier(id))
            || !unique(task.required_case_ids.iter().map(String::as_str))
            || !unique(task.candidate_authors.iter().map(String::as_str))
        {
            return Err(Invalid);
        }
    }
    if evaluator_cohort_sha256(&input.cohort)? != input.cohort_sha256 {
        return Err(Integrity);
    }
    let mut evaluator_versions = BTreeSet::new();
    for q in &input.qualifications {
        let tuning_valid = match (input.schema_version, &q.tuning_case_ids) {
            (1, None) => true,
            (2, Some(ids)) => {
                ids.is_empty() == q.tuning_output_sha256.is_empty()
                    && ids.iter().all(|id| identifier(id))
                    && unique(ids.iter().map(String::as_str))
            }
            _ => false,
        };
        if !tuning_valid
            || !identity_valid(&q.evaluator)
            || !evaluator_versions.insert((&q.evaluator.evaluator_id, &q.evaluator.version))
            || q.max_duration_ms == 0
            || q.max_duration_ms > 3_600_000
            || q.max_output_bytes == 0
            || q.max_output_bytes > MAX_EVALUATOR_QUALIFICATION_BYTES as u64
            || q.applicable_criteria_sha256.is_empty()
            || q.applicable_criteria_sha256
                .iter()
                .chain(&q.tuning_output_sha256)
                .any(|h| !valid_hash(h))
            || !unique(q.applicable_criteria_sha256.iter().map(String::as_str))
            || !unique(q.tuning_output_sha256.iter().map(String::as_str))
            || !unique(q.witnesses.iter().map(|w| w.case_id.as_str()))
            || !unique(q.witnesses.iter().map(|w| w.output_sha256.as_str()))
            || q.witnesses.iter().any(|w| {
                !identifier(&w.case_id)
                    || !identifier(&w.reviewer_id)
                    || !valid_hash(&w.output_sha256)
                    || !valid_hash(&w.oracle_evidence_sha256)
            })
        {
            return Err(Invalid);
        }
        if evaluator_qualification_corpus_sha256(&q.witnesses)? != q.corpus_sha256 {
            return Err(Integrity);
        }
    }
    let mut history = BTreeMap::new();
    for verdict in &input.verdicts {
        if !identifier(&verdict.verdict_id)
            || !identifier(&verdict.instance_id)
            || !identity_valid(&verdict.evaluator)
            || [
                &verdict.task_contract_sha256,
                &verdict.cohort_sha256,
                &verdict.revision_sha256,
                &verdict.output_sha256,
            ]
            .iter()
            .any(|h| !valid_hash(h))
            || !unique(verdict.cases.iter().map(|c| c.case_id.as_str()))
            || verdict.cases.iter().any(|c| !identifier(&c.case_id))
            || history.contains_key(&verdict.verdict_id)
        {
            return Err(Invalid);
        }
        if let Some(previous) = &verdict.reevaluates {
            let old: &&StoredEvaluatorVerdict = history.get(previous).ok_or(Integrity)?;
            if old.instance_id != verdict.instance_id
                || old.task_contract_sha256 != verdict.task_contract_sha256
                || old.cohort_sha256 != verdict.cohort_sha256
                || old.revision_sha256 != verdict.revision_sha256
                || old.output_sha256 != verdict.output_sha256
            {
                return Err(Integrity);
            }
        }
        history.insert(&verdict.verdict_id, verdict);
    }
    for selection in &input.comparisons {
        if !input
            .cohort
            .iter()
            .any(|task| task.instance_id == selection.instance_id)
            || selection
                .reference_verdict_id
                .iter()
                .chain(&selection.candidate_verdict_id)
                .any(|id| !identifier(id))
        {
            return Err(Invalid);
        }
    }
    Ok(())
}

fn effective_outcome(verdict: Option<&StoredEvaluatorVerdict>, case_id: &str) -> ObservedOutcome {
    verdict
        .and_then(|v| v.cases.iter().find(|c| c.case_id == case_id))
        .filter(|c| c.execution == EvaluatorExecution::Completed)
        .map_or(ObservedOutcome::Unknown, |c| c.outcome)
}

fn compare_task(
    input: &EvaluatorQualificationInput,
    qualifications: &[EvaluatorQualificationSummary],
    task: &EvaluatorTaskContract,
) -> Result<EvaluatorInstanceComparison> {
    let selection = input
        .comparisons
        .iter()
        .find(|s| s.instance_id == task.instance_id);
    let find =
        |id: Option<&String>| id.and_then(|id| input.verdicts.iter().find(|v| v.verdict_id == *id));
    let reference = find(selection.and_then(|s| s.reference_verdict_id.as_ref()));
    let candidate = find(selection.and_then(|s| s.candidate_verdict_id.as_ref()));
    let task_digest = evaluator_task_contract_sha256(task)?;
    let mut blockers = BTreeSet::new();
    if reference.is_none() || candidate.is_none() {
        blockers.insert("missing_verdict");
    }
    if input
        .qualifications
        .iter()
        .any(|q| q.tuning_case_ids.is_none() && !q.tuning_output_sha256.is_empty())
    {
        blockers.insert("tuning_case_identity_unknown");
    }
    for verdict in reference.into_iter().chain(candidate) {
        if verdict.instance_id != task.instance_id
            || verdict.task_contract_sha256 != task_digest
            || verdict.cohort_sha256 != input.cohort_sha256
        {
            blockers.insert("binding_mismatch");
        }
        let qualification = input
            .qualifications
            .iter()
            .zip(qualifications)
            .find(|(q, _)| q.evaluator == verdict.evaluator);
        if !qualification.is_some_and(|(q, summary)| {
            summary.structurally_consistent
                && q.applicable_criteria_sha256.contains(&task.criteria_sha256)
        }) {
            blockers.insert("evaluator_unqualified_or_inapplicable");
        }
        if input.qualifications.iter().any(|q| {
            q.witnesses.iter().any(|w| {
                w.output_sha256 == verdict.output_sha256
                    || task.required_case_ids.contains(&w.case_id)
            }) || q.tuning_output_sha256.contains(&verdict.output_sha256)
                || q.tuning_case_ids
                    .as_ref()
                    .is_some_and(|ids| ids.iter().any(|id| task.required_case_ids.contains(id)))
        }) {
            blockers.insert("decision_corpus_overlap");
        }
        if verdict.cases.len() != task.required_case_ids.len()
            || verdict
                .cases
                .iter()
                .any(|case| !task.required_case_ids.contains(&case.case_id))
        {
            blockers.insert("required_case_set_mismatch");
        }
    }
    if let Some((reference, candidate)) = reference.zip(candidate) {
        if reference.evaluator != candidate.evaluator {
            blockers.insert("evaluator_changed");
        }
        for (different, permission) in [
            (
                reference.revision_sha256 != candidate.revision_sha256,
                EvaluatorPermittedDifference::Revision,
            ),
            (
                reference.output_sha256 != candidate.output_sha256,
                EvaluatorPermittedDifference::Output,
            ),
            (
                selection.is_some_and(|s| s.reference_cost_microusd != s.candidate_cost_microusd),
                EvaluatorPermittedDifference::Cost,
            ),
        ] {
            if different && !input.permitted_differences.contains(&permission) {
                blockers.insert("unpermitted_difference");
            }
        }
    }
    let cases: Vec<_> = task
        .required_case_ids
        .iter()
        .map(|id| RequiredCaseComparison {
            case_id: id.clone(),
            reference: effective_outcome(reference, id),
            candidate: effective_outcome(candidate, id),
        })
        .collect();
    if cases
        .iter()
        .any(|c| c.reference == ObservedOutcome::Unknown || c.candidate == ObservedOutcome::Unknown)
    {
        blockers.insert("required_case_unknown");
    }
    let regressed_case_ids: Vec<_> = cases
        .iter()
        .filter(|c| {
            c.reference == ObservedOutcome::Passed && c.candidate == ObservedOutcome::Failed
        })
        .map(|c| c.case_id.clone())
        .collect();
    let status = if !blockers.is_empty() {
        EvaluatorComparisonStatus::Inconclusive
    } else if !regressed_case_ids.is_empty() {
        EvaluatorComparisonStatus::Regression
    } else if cases.iter().any(|c| c.candidate != ObservedOutcome::Passed) {
        EvaluatorComparisonStatus::RequiredCasesFailed
    } else {
        EvaluatorComparisonStatus::RequiredCasesSatisfied
    };
    Ok(EvaluatorInstanceComparison {
        instance_id: task.instance_id.clone(),
        task_contract_sha256: task_digest,
        reference_verdict_id: selection.and_then(|s| s.reference_verdict_id.clone()),
        candidate_verdict_id: selection.and_then(|s| s.candidate_verdict_id.clone()),
        status,
        blockers: blockers.into_iter().map(str::to_owned).collect(),
        cases,
        regressed_case_ids,
    })
}

fn total_cost(input: &EvaluatorQualificationInput, candidate: bool) -> Result<Option<u64>> {
    let mut total = 0u64;
    let mut complete = input.comparisons.len() == input.cohort.len();
    for selection in &input.comparisons {
        let cost = if candidate {
            selection.candidate_cost_microusd
        } else {
            selection.reference_cost_microusd
        };
        if let Some(cost) = cost {
            total = total
                .checked_add(cost)
                .ok_or(EvaluatorQualificationError::CostOverflow)?;
        } else {
            complete = false;
        }
    }
    Ok(complete.then_some(total))
}
