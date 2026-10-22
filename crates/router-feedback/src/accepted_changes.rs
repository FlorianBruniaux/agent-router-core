//! Offline, supplied-evidence accounting. Digests bind content, not authenticity.
use crate::{FeedbackError, Result, hash, identifier, valid_hash};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_ACCEPTED_CHANGES_BYTES: usize = 4 * 1024 * 1024;
const MAX_ROWS: usize = 4096;
const MAX_ASSIGNMENTS: usize = 256;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcceptedAssignment {
    pub assignment_id: String,
    pub start_sequence: u64,
    pub task_start_sha256: String,
    pub source_sha256: String,
    pub criteria_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedCohort {
    pub complete: bool,
    pub assignments: Vec<AcceptedAssignment>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevisionBinding {
    pub assignment_id: String,
    pub source_sha256: String,
    pub criteria_sha256: String,
    pub candidate_sha256: String,
    pub revision_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedRevision {
    pub sequence: u64,
    pub binding: RevisionBinding,
    pub predecessor_sha256: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionSelection {
    pub assignment_id: String,
    pub revision_sha256: Option<String>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RevisionStatus {
    Accepted,
    Rejected,
    Pending,
    Unknown,
    Revoked,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SuppliedVerifierOutcome {
    Passed,
    Failed,
    Unknown,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionVerdict {
    pub sequence: u64,
    pub binding: RevisionBinding,
    pub status: RevisionStatus,
    pub verifier_outcome: SuppliedVerifierOutcome,
    pub verifier_sha256: Option<String>,
    pub reviewer_sha256: Option<String>,
    pub acceptance_sequence: Option<u64>,
    pub cost_frontier_sequence: Option<u64>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AcceptedCostKind {
    Model,
    Ci,
    Human,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCoverage {
    Complete,
    Partial,
    LastTurnOnly,
    Unknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SuppliedAgentOutcome {
    Exited,
    Failed,
    TimedOut,
    Cancelled,
    FailedBeforeSend,
    Unknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CohortAttribution {
    CohortOnce,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct PhysicalObservationKey {
    pub authority_sha256: String,
    pub physical_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcceptedWorkLink {
    pub assignment_id: String,
    pub source_sha256: String,
    pub criteria_sha256: String,
    pub candidate_sha256: Option<String>,
    pub revision_sha256: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcceptedCostObservation {
    pub key: PhysicalObservationKey,
    pub sequence: u64,
    pub cohort_sha256: String,
    pub kind: AcceptedCostKind,
    pub attribution: CohortAttribution,
    pub links: Vec<AcceptedWorkLink>,
    pub external_request_id: Option<String>,
    pub evidence_sha256: String,
    pub agent_outcome: SuppliedAgentOutcome,
    pub usage_coverage: EvidenceCoverage,
    pub pricing_coverage: EvidenceCoverage,
    pub cost_microusd: Option<u64>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedObservation {
    pub key: PhysicalObservationKey,
    pub sequence: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedCostInventory {
    pub kind: AcceptedCostKind,
    pub coverage: EvidenceCoverage,
    pub expected: Vec<ExpectedObservation>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedChangesInput {
    pub schema_version: u32,
    pub cohort: AcceptedCohort,
    pub cohort_sha256: String,
    pub analysis_sequence: u64,
    pub selections: Vec<RevisionSelection>,
    pub revisions: Vec<AcceptedRevision>,
    pub verdicts: Vec<RevisionVerdict>,
    pub inventories: Vec<AcceptedCostInventory>,
    pub observations: Vec<AcceptedCostObservation>,
}
#[derive(Clone, Debug, Serialize)]
pub struct AcceptedCostTotal {
    pub known_subtotal_microusd: u64,
    pub total_microusd: Option<u64>,
    pub observation_count: usize,
    pub missing_expected_count: usize,
    pub inventory_coverage: EvidenceCoverage,
}
#[derive(Clone, Debug, Serialize)]
pub struct AcceptedCosts {
    pub model: AcceptedCostTotal,
    pub ci: AcceptedCostTotal,
    pub human: AcceptedCostTotal,
}
#[derive(Debug, Serialize)]
pub struct AcceptedCostRatio {
    pub numerator_microusd: u64,
    pub denominator: usize,
}
#[derive(Debug, Serialize)]
pub struct AcceptedCostRatios {
    pub model: Option<AcceptedCostRatio>,
    pub ci: Option<AcceptedCostRatio>,
    pub human: Option<AcceptedCostRatio>,
}
#[derive(Debug, Serialize)]
pub struct SelectedRevisionVerdict {
    pub assignment_id: String,
    pub revision_sha256: Option<String>,
    pub status: RevisionStatus,
    pub verdict_sequence: Option<u64>,
}
#[derive(Debug, Serialize)]
pub struct HistoricalAcceptance {
    pub acceptance: RevisionVerdict,
    pub cohort_costs_at_frontier: AcceptedCosts,
    pub assignment_model_cost_at_frontier: AcceptedCostTotal,
}
#[derive(Debug, Serialize)]
pub struct AcceptedChangesReport {
    pub schema_version: u32,
    pub input_sha256: String,
    pub report_sha256: String,
    pub evidence_trust: &'static str,
    pub cohort_sha256: String,
    pub cohort: AcceptedCohort,
    pub analysis_sequence: u64,
    pub selected: Vec<SelectedRevisionVerdict>,
    pub selected_accepted_changes: usize,
    pub revision_history: Vec<AcceptedRevision>,
    pub verdict_history: Vec<RevisionVerdict>,
    pub acceptance_history: Vec<HistoricalAcceptance>,
    pub inventories: Vec<AcceptedCostInventory>,
    pub observations: Vec<AcceptedCostObservation>,
    pub off_cohort_observation_count: usize,
    pub cohort_costs: AcceptedCosts,
    pub cost_per_selected_accepted_change: AcceptedCostRatios,
}

fn invalid<T>(reason: &'static str) -> Result<T> {
    Err(FeedbackError::Invalid(reason))
}
fn check_key(key: &PhysicalObservationKey) -> bool {
    valid_hash(&key.authority_sha256) && valid_hash(&key.physical_sha256)
}
fn check_binding(binding: &RevisionBinding) -> bool {
    identifier(&binding.assignment_id)
        && [
            &binding.source_sha256,
            &binding.criteria_sha256,
            &binding.candidate_sha256,
            &binding.revision_sha256,
        ]
        .into_iter()
        .all(|v| valid_hash(v))
}
fn sequence(seen: &mut BTreeSet<u64>, value: u64, snapshot: u64) -> Result<()> {
    if value == 0 || value > snapshot || !seen.insert(value) {
        return invalid("evidence sequence");
    }
    Ok(())
}
fn revision<'a>(
    revisions: &BTreeMap<(&str, &str), &'a AcceptedRevision>,
    binding: &RevisionBinding,
) -> Result<&'a AcceptedRevision> {
    let Some(revision) = revisions.get(&(
        binding.assignment_id.as_str(),
        binding.revision_sha256.as_str(),
    )) else {
        return invalid("unknown revision");
    };
    if revision.binding != *binding {
        return invalid("revision binding conflict");
    }
    Ok(revision)
}

/// Strict JSON is checked before decoding. This function never opens a store,
/// invokes a provider, prices an allocation, or authenticates supplied evidence.
pub fn accepted_changes_report(bytes: &[u8]) -> Result<AcceptedChangesReport> {
    if bytes.len() > MAX_ACCEPTED_CHANGES_BYTES {
        return Err(FeedbackError::Limit);
    }
    let value =
        router_adapter_api::strict_json(bytes).map_err(|_| FeedbackError::Invalid("JSON"))?;
    let input: AcceptedChangesInput = serde_json::from_value(value)?;
    calculate_accepted_changes(&input)
}

/// Seal only assignment membership. Selections and later evidence are deliberately
/// outside this immutable cohort identity. List order is part of the v1 seal.
pub fn accepted_cohort_sha256(cohort: &AcceptedCohort) -> Result<String> {
    hash("accepted-changes/cohort/v1", cohort)
}

pub fn calculate_accepted_changes(input: &AcceptedChangesInput) -> Result<AcceptedChangesReport> {
    if input.schema_version != 1 || !input.cohort.complete || input.analysis_sequence == 0 {
        return invalid("accepted changes version or cohort");
    }
    if input.cohort.assignments.is_empty()
        || input.cohort.assignments.len() > MAX_ASSIGNMENTS
        || input.selections.len() != input.cohort.assignments.len()
        || input.revisions.len() > MAX_ROWS
        || input.verdicts.len() > MAX_ROWS
        || input.observations.len() > MAX_ROWS
        || input.inventories.len() > 3
        || input
            .inventories
            .iter()
            .any(|i| i.expected.len() > MAX_ROWS)
        || serde_json::to_vec(input)?.len() > MAX_ACCEPTED_CHANGES_BYTES
    {
        return Err(FeedbackError::Limit);
    }
    if accepted_cohort_sha256(&input.cohort)? != input.cohort_sha256 {
        return invalid("cohort seal");
    }
    let mut sequences = BTreeSet::new();
    let mut assignments = BTreeMap::new();
    for assignment in &input.cohort.assignments {
        if !identifier(&assignment.assignment_id)
            || [
                &assignment.task_start_sha256,
                &assignment.source_sha256,
                &assignment.criteria_sha256,
            ]
            .into_iter()
            .any(|v| !valid_hash(v))
            || assignments
                .insert(assignment.assignment_id.as_str(), assignment)
                .is_some()
        {
            return invalid("assignment");
        }
        sequence(
            &mut sequences,
            assignment.start_sequence,
            input.analysis_sequence,
        )?;
    }
    let mut revisions = BTreeMap::new();
    let mut previous = BTreeMap::new();
    let mut last_sequence = 0;
    for entry in &input.revisions {
        let b = &entry.binding;
        let Some(assignment) = assignments.get(b.assignment_id.as_str()) else {
            return invalid("revision assignment");
        };
        if !check_binding(b)
            || b.source_sha256 != assignment.source_sha256
            || b.criteria_sha256 != assignment.criteria_sha256
            || entry.sequence <= assignment.start_sequence
            || entry.sequence <= last_sequence
            || entry.predecessor_sha256.as_deref()
                != previous.get(b.assignment_id.as_str()).copied()
            || revisions
                .insert(
                    (b.assignment_id.as_str(), b.revision_sha256.as_str()),
                    entry,
                )
                .is_some()
        {
            return invalid("revision chain");
        }
        sequence(&mut sequences, entry.sequence, input.analysis_sequence)?;
        previous.insert(b.assignment_id.as_str(), b.revision_sha256.as_str());
        last_sequence = entry.sequence;
    }
    let mut verdicts_by_revision: BTreeMap<(&str, &str), &RevisionVerdict> = BTreeMap::new();
    let mut acceptances: BTreeMap<u64, &RevisionVerdict> = BTreeMap::new();
    let mut revoked = BTreeSet::new();
    last_sequence = 0;
    for verdict in &input.verdicts {
        let rev = revision(&revisions, &verdict.binding)?;
        if verdict.sequence <= rev.sequence
            || verdict.sequence <= last_sequence
            || [&verdict.verifier_sha256, &verdict.reviewer_sha256]
                .into_iter()
                .flatten()
                .any(|h| !valid_hash(h))
            || verdict.verifier_outcome != SuppliedVerifierOutcome::Unknown
                && verdict.verifier_sha256.is_none()
        {
            return invalid("verdict evidence");
        }
        sequence(&mut sequences, verdict.sequence, input.analysis_sequence)?;
        match verdict.status {
            RevisionStatus::Accepted => {
                if verdict.verifier_outcome != SuppliedVerifierOutcome::Passed
                    || verdict.verifier_sha256.is_none()
                    || verdict.reviewer_sha256.is_none()
                    || verdict.acceptance_sequence.is_some()
                    || !verdict
                        .cost_frontier_sequence
                        .is_some_and(|f| f >= rev.sequence && f <= verdict.sequence)
                {
                    return invalid("acceptance evidence");
                }
                acceptances.insert(verdict.sequence, verdict);
            }
            RevisionStatus::Revoked => {
                let Some(acceptance) = verdict
                    .acceptance_sequence
                    .and_then(|seq| acceptances.get(&seq))
                else {
                    return invalid("revocation target");
                };
                if acceptance.binding != verdict.binding
                    || !verdicts_by_revision
                        .get(&(
                            verdict.binding.assignment_id.as_str(),
                            verdict.binding.revision_sha256.as_str(),
                        ))
                        .is_some_and(|current| {
                            current.status == RevisionStatus::Accepted
                                && current.sequence == acceptance.sequence
                        })
                    || !revoked.insert(acceptance.sequence)
                    || verdict.cost_frontier_sequence.is_some()
                    || verdict.reviewer_sha256.is_none()
                {
                    return invalid("revocation binding");
                }
            }
            _ => {
                if verdict.acceptance_sequence.is_some() || verdict.cost_frontier_sequence.is_some()
                {
                    return invalid("non acceptance frontier");
                }
            }
        }
        verdicts_by_revision.insert(
            (
                verdict.binding.assignment_id.as_str(),
                verdict.binding.revision_sha256.as_str(),
            ),
            verdict,
        );
        last_sequence = verdict.sequence;
    }
    let mut selected = BTreeMap::new();
    for selection in &input.selections {
        if !assignments.contains_key(selection.assignment_id.as_str())
            || selected.contains_key(&selection.assignment_id)
        {
            return invalid("selection assignment");
        }
        if let Some(sha) = &selection.revision_sha256 {
            if !revisions.contains_key(&(selection.assignment_id.as_str(), sha.as_str())) {
                return invalid("selection revision");
            }
        } else if previous.contains_key(selection.assignment_id.as_str()) {
            return invalid("missing revision selection");
        }
        let verdict = selection.revision_sha256.as_ref().and_then(|sha| {
            verdicts_by_revision.get(&(selection.assignment_id.as_str(), sha.as_str()))
        });
        selected.insert(
            selection.assignment_id.clone(),
            SelectedRevisionVerdict {
                assignment_id: selection.assignment_id.clone(),
                revision_sha256: selection.revision_sha256.clone(),
                status: verdict.map_or(RevisionStatus::Unknown, |v| v.status),
                verdict_sequence: verdict.map(|v| v.sequence),
            },
        );
    }
    let mut observations = BTreeMap::new();
    for observation in &input.observations {
        if !check_key(&observation.key)
            || !valid_hash(&observation.cohort_sha256)
            || !valid_hash(&observation.evidence_sha256)
            || observation
                .external_request_id
                .as_ref()
                .is_some_and(|id| !identifier(id))
            || observation.links.is_empty()
            || observation.links.len() > MAX_ASSIGNMENTS
            || observation.kind != AcceptedCostKind::Ci && observation.links.len() != 1
        {
            return invalid("observation");
        }
        if let Some(existing) = observations.insert(observation.key.clone(), observation.clone()) {
            if existing != *observation {
                return invalid("physical identity conflict");
            }
            continue;
        }
        sequence(
            &mut sequences,
            observation.sequence,
            input.analysis_sequence,
        )?;
        let mut links = BTreeSet::new();
        for link in &observation.links {
            if !identifier(&link.assignment_id)
                || !valid_hash(&link.source_sha256)
                || !valid_hash(&link.criteria_sha256)
                || link.candidate_sha256.is_some() != link.revision_sha256.is_some()
                || [&link.candidate_sha256, &link.revision_sha256]
                    .into_iter()
                    .flatten()
                    .any(|h| !valid_hash(h))
                || !links.insert((&link.assignment_id, &link.revision_sha256))
            {
                return invalid("observation links");
            }
            if observation.cohort_sha256 == input.cohort_sha256 {
                let Some(assignment) = assignments.get(link.assignment_id.as_str()) else {
                    return invalid("work assignment");
                };
                if link.source_sha256 != assignment.source_sha256
                    || link.criteria_sha256 != assignment.criteria_sha256
                    || observation.sequence <= assignment.start_sequence
                {
                    return invalid("work assignment binding");
                }
                if let (Some(candidate), Some(sha)) =
                    (&link.candidate_sha256, &link.revision_sha256)
                {
                    let binding = RevisionBinding {
                        assignment_id: link.assignment_id.clone(),
                        source_sha256: link.source_sha256.clone(),
                        criteria_sha256: link.criteria_sha256.clone(),
                        candidate_sha256: candidate.clone(),
                        revision_sha256: sha.clone(),
                    };
                    if revision(&revisions, &binding)?.sequence > observation.sequence {
                        return invalid("observation before revision");
                    }
                }
            }
        }
    }
    let mut inventories = BTreeMap::new();
    let mut expected_keys = BTreeSet::new();
    let mut expected_sequences = BTreeSet::new();
    for inventory in &input.inventories {
        if inventories.insert(inventory.kind, inventory).is_some() {
            return invalid("duplicate inventory");
        }
        for expected in &inventory.expected {
            if !check_key(&expected.key)
                || expected.sequence == 0
                || expected.sequence > input.analysis_sequence
                || !expected_keys.insert(&expected.key)
                || !expected_sequences.insert(expected.sequence)
            {
                return invalid("inventory identity");
            }
            if let Some(observation) = observations.get(&expected.key) {
                if observation.kind != inventory.kind
                    || observation.sequence != expected.sequence
                    || observation.cohort_sha256 != input.cohort_sha256
                {
                    return invalid("inventory join");
                }
            } else if sequences.contains(&expected.sequence) {
                return invalid("inventory sequence conflict");
            }
        }
    }
    // Even a partial inventory must name every supplied in-cohort observation for
    // that category. Missing inventories retain subtotals but never a total.
    for observation in observations
        .values()
        .filter(|o| o.cohort_sha256 == input.cohort_sha256)
    {
        if inventories.contains_key(&observation.kind) && !expected_keys.contains(&observation.key)
        {
            return invalid("observation outside inventory");
        }
    }
    let costs = |frontier| costs_through(input, &observations, &inventories, frontier);
    let cohort_costs = costs(input.analysis_sequence)?;
    let acceptance_history = acceptances
        .values()
        .map(|acceptance| {
            // The acceptance branch above establishes this field; avoid panics even
            // if a future edit loosens that invariant.
            let frontier = acceptance
                .cost_frontier_sequence
                .ok_or(FeedbackError::Invalid("acceptance frontier"))?;
            Ok(HistoricalAcceptance {
                acceptance: (*acceptance).clone(),
                cohort_costs_at_frontier: costs(frontier)?,
                assignment_model_cost_at_frontier: cost_through(
                    input,
                    &observations,
                    &inventories,
                    frontier,
                    AcceptedCostKind::Model,
                    Some(&acceptance.binding.assignment_id),
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let selected: Vec<_> = selected.into_values().collect();
    let accepted = selected
        .iter()
        .filter(|s| s.status == RevisionStatus::Accepted)
        .count();
    let ratio = |cost: &AcceptedCostTotal| {
        cost.total_microusd
            .filter(|_| accepted != 0)
            .map(|numerator| AcceptedCostRatio {
                numerator_microusd: numerator,
                denominator: accepted,
            })
    };
    let cost_per_selected_accepted_change = AcceptedCostRatios {
        model: ratio(&cohort_costs.model),
        ci: ratio(&cohort_costs.ci),
        human: ratio(&cohort_costs.human),
    };
    let off_cohort_observation_count = observations
        .values()
        .filter(|o| o.cohort_sha256 != input.cohort_sha256)
        .count();
    let mut report = AcceptedChangesReport {
        schema_version: 1,
        input_sha256: hash("accepted-changes/input/v1", input)?,
        report_sha256: String::new(),
        evidence_trust: "supplied_unverified",
        cohort_sha256: input.cohort_sha256.clone(),
        cohort: input.cohort.clone(),
        analysis_sequence: input.analysis_sequence,
        selected,
        selected_accepted_changes: accepted,
        revision_history: input.revisions.clone(),
        verdict_history: input.verdicts.clone(),
        acceptance_history,
        inventories: inventories.into_values().cloned().collect(),
        observations: observations.into_values().collect(),
        off_cohort_observation_count,
        cohort_costs,
        cost_per_selected_accepted_change,
    };
    report.report_sha256 = hash("accepted-changes/report/v1", &report)?;
    Ok(report)
}

fn costs_through(
    input: &AcceptedChangesInput,
    observations: &BTreeMap<PhysicalObservationKey, AcceptedCostObservation>,
    inventories: &BTreeMap<AcceptedCostKind, &AcceptedCostInventory>,
    frontier: u64,
) -> Result<AcceptedCosts> {
    Ok(AcceptedCosts {
        model: cost_through(
            input,
            observations,
            inventories,
            frontier,
            AcceptedCostKind::Model,
            None,
        )?,
        ci: cost_through(
            input,
            observations,
            inventories,
            frontier,
            AcceptedCostKind::Ci,
            None,
        )?,
        human: cost_through(
            input,
            observations,
            inventories,
            frontier,
            AcceptedCostKind::Human,
            None,
        )?,
    })
}

fn cost_through(
    input: &AcceptedChangesInput,
    observations: &BTreeMap<PhysicalObservationKey, AcceptedCostObservation>,
    inventories: &BTreeMap<AcceptedCostKind, &AcceptedCostInventory>,
    frontier: u64,
    kind: AcceptedCostKind,
    assignment: Option<&str>,
) -> Result<AcceptedCostTotal> {
    let inventory = inventories.get(&kind);
    let coverage = inventory.map_or(EvidenceCoverage::Unknown, |i| i.coverage);
    // Expected identities do not claim assignment attribution. Any missing
    // identity conservatively prevents an assignment-specific complete total.
    let missing = inventory.map_or(0, |i| {
        i.expected
            .iter()
            .filter(|e| e.sequence <= frontier && !observations.contains_key(&e.key))
            .count()
    });
    let mut complete = coverage == EvidenceCoverage::Complete && missing == 0;
    let mut subtotal = 0u64;
    let mut count = 0;
    for observation in observations.values().filter(|o| {
        o.kind == kind
            && o.cohort_sha256 == input.cohort_sha256
            && o.sequence <= frontier
            && assignment.is_none_or(|id| o.links.iter().any(|link| link.assignment_id == id))
    }) {
        count += 1;
        if let Some(cost) = observation.cost_microusd {
            subtotal = subtotal
                .checked_add(cost)
                .ok_or(FeedbackError::Invalid("cost overflow"))?;
        }
        complete &= observation.cost_microusd.is_some()
            && observation.pricing_coverage == EvidenceCoverage::Complete
            && observation.usage_coverage == EvidenceCoverage::Complete;
    }
    Ok(AcceptedCostTotal {
        known_subtotal_microusd: subtotal,
        total_microusd: complete.then_some(subtotal),
        observation_count: count,
        missing_expected_count: missing,
        inventory_coverage: coverage,
    })
}
