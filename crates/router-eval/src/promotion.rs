use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    DatasetSplit, EvalError, MAX_EVALUATION_CASES, ObservedOutcome, ReplayTrace, Result, hash,
    text, valid_hash,
};

#[derive(Clone, Debug)]
pub struct PairedTrace {
    pub baseline: ReplayTrace,
    pub semantic: ReplayTrace,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionMetric {
    RouteAccuracy,
    Cost,
    Latency,
    Abstention,
    FunctionalSuccess,
}

/// Every metric, in a fixed order. The exhaustive `match` makes a new
/// `PromotionMetric` variant a compile error here, so the regression guard can
/// never silently skip it.
fn all_metrics() -> impl Iterator<Item = PromotionMetric> {
    fn next(metric: Option<PromotionMetric>) -> Option<PromotionMetric> {
        match metric {
            None => Some(PromotionMetric::RouteAccuracy),
            Some(PromotionMetric::RouteAccuracy) => Some(PromotionMetric::Cost),
            Some(PromotionMetric::Cost) => Some(PromotionMetric::Latency),
            Some(PromotionMetric::Latency) => Some(PromotionMetric::Abstention),
            Some(PromotionMetric::Abstention) => Some(PromotionMetric::FunctionalSuccess),
            Some(PromotionMetric::FunctionalSuccess) => None,
        }
    }
    std::iter::successors(next(None), |metric| next(Some(*metric)))
}

/// Metrics the criteria do not list, which regressed. An unmeasurable metric
/// (unknown outcomes, missing latency) shows no regression here.
fn unlisted_regressions(
    rules: &[MetricRule],
    baseline: &EvaluationMetrics,
    semantic: &EvaluationMetrics,
) -> Vec<PromotionMetric> {
    all_metrics()
        .filter(|metric| !rules.iter().any(|rule| rule.metric == *metric))
        .filter(|metric| improvement(*metric, baseline, semantic).is_some_and(|value| value < 0))
        .collect()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricRule {
    pub metric: PromotionMetric,
    pub minimum_improvement_micros: u32,
    pub maximum_regression_micros: u32,
}

/// Supplied, pre-registered criteria. This structure carries the registration
/// evidence hash; the harness does not invent thresholds or attest the evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionCriteria {
    pub schema_version: u32,
    pub dataset_hash: String,
    pub registered_at_unix_seconds: u64,
    pub registration_evidence_sha256: String,
    pub minimum_cases: usize,
    pub minimum_families: usize,
    pub policy_authors: BTreeSet<String>,
    pub training_families: BTreeSet<String>,
    pub rules: Vec<MetricRule>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct OutcomeCounts {
    pub passed: usize,
    pub failed: usize,
    pub unknown: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvaluationMetrics {
    pub cases: usize,
    pub route_accuracy_micros: Option<u32>,
    pub total_cost_microusd: u64,
    pub mean_elapsed_ms: Option<u64>,
    pub total_elapsed_ms: Option<u64>,
    pub p95_elapsed_ms: Option<u64>,
    pub abstention_micros: u32,
    pub hard_constraint_violations: usize,
    pub transport: OutcomeCounts,
    pub command_validation: OutcomeCounts,
    pub functional: OutcomeCounts,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ShadowReport {
    pub schema_version: u32,
    pub dataset_hash: String,
    pub criteria_hash: Option<String>,
    pub baseline: EvaluationMetrics,
    pub semantic: EvaluationMetrics,
    pub semantic_enabled: bool,
    pub promotion_blockers: Vec<String>,
}

pub fn dataset_hash(pairs: &[PairedTrace]) -> Result<String> {
    validate_pairs(pairs)?;
    let mut identities: Vec<_> = pairs
        .iter()
        .map(|pair| (&pair.baseline.case_id, &pair.baseline.input_hash))
        .collect();
    identities.sort();
    hash(b"agent-router:evaluation-dataset:v1\0", &identities)
}

pub fn compare_shadow(
    pairs: &[PairedTrace],
    criteria: Option<&PromotionCriteria>,
) -> Result<ShadowReport> {
    let dataset_hash = dataset_hash(pairs)?;
    let baseline = metrics(pairs.iter().map(|pair| &pair.baseline), criteria)?;
    let semantic = metrics(pairs.iter().map(|pair| &pair.semantic), criteria)?;
    let mut blockers = BTreeSet::new();
    if baseline.hard_constraint_violations > 0 || semantic.hard_constraint_violations > 0 {
        blockers.insert("promotion.hard_constraint_violation".into());
    }
    if pairs
        .iter()
        .any(|pair| pair.baseline.split != DatasetSplit::HeldOut)
    {
        blockers.insert("promotion.heldout_required".into());
    }
    if pairs
        .iter()
        .any(|pair| !independent_label(&pair.baseline, criteria))
    {
        blockers.insert("promotion.independent_human_labels_required".into());
    }
    let criteria_hash = if let Some(criteria) = criteria {
        validate_criteria(criteria)?;
        if criteria.dataset_hash != dataset_hash {
            blockers.insert("promotion.dataset_mismatch".into());
        }
        if pairs.len() < criteria.minimum_cases
            || pairs
                .iter()
                .map(|pair| &pair.baseline.family_id)
                .collect::<BTreeSet<_>>()
                .len()
                < criteria.minimum_families
        {
            blockers.insert("promotion.insufficient_heldout_cases".into());
        }
        if pairs.iter().any(|pair| {
            criteria
                .training_families
                .contains(&pair.baseline.family_id)
        }) {
            blockers.insert("promotion.family_leakage".into());
        }
        if pairs.iter().any(|pair| {
            criteria.registered_at_unix_seconds
                >= pair
                    .baseline
                    .evaluated_at_unix_seconds
                    .min(pair.semantic.evaluated_at_unix_seconds)
        }) {
            blockers.insert("promotion.criteria_not_preregistered".into());
        }
        let mut observed_gain = false;
        for rule in &criteria.rules {
            let Some(improvement) = improvement(rule.metric, &baseline, &semantic) else {
                blockers.insert(format!("promotion.metric_unknown.{:?}", rule.metric));
                continue;
            };
            if improvement < -i128::from(rule.maximum_regression_micros) {
                blockers.insert(format!("promotion.metric_regression.{:?}", rule.metric));
            }
            if rule.minimum_improvement_micros > 0 {
                if improvement < i128::from(rule.minimum_improvement_micros) {
                    blockers.insert(format!("promotion.insufficient_gain.{:?}", rule.metric));
                } else {
                    observed_gain = true;
                }
            }
        }
        // Every metric guards against regression. A metric the criteria do not
        // list gets no allowance; only an explicit rule's recorded
        // `maximum_regression_micros` can permit a regression.
        for metric in unlisted_regressions(&criteria.rules, &baseline, &semantic) {
            blockers.insert(format!("promotion.metric_regression.{metric:?}"));
        }
        if !observed_gain {
            blockers.insert("promotion.no_demonstrated_gain".into());
        }
        Some(hash(b"agent-router:promotion-criteria:v1\0", criteria)?)
    } else {
        blockers.insert("promotion.criteria_required".into());
        None
    };
    Ok(ShadowReport {
        schema_version: 1,
        dataset_hash,
        criteria_hash,
        baseline,
        semantic,
        semantic_enabled: blockers.is_empty(),
        promotion_blockers: blockers.into_iter().collect(),
    })
}

fn validate_pairs(pairs: &[PairedTrace]) -> Result<()> {
    if pairs.is_empty() || pairs.len() > MAX_EVALUATION_CASES {
        return Err(EvalError::Limit("comparison cases"));
    }
    let mut ids = BTreeSet::new();
    let first = &pairs[0];
    for pair in pairs {
        if pair.baseline.input_hash != pair.semantic.input_hash
            || pair.baseline.case_id != pair.semantic.case_id
            || pair.baseline.policy_id == pair.semantic.policy_id
            || !ids.insert(&pair.baseline.case_id)
            || pair.baseline.policy_id != first.baseline.policy_id
            || pair.semantic.policy_id != first.semantic.policy_id
            || pair.baseline.policy_hash != first.baseline.policy_hash
            || pair.semantic.policy_hash != first.semantic.policy_hash
        {
            return Err(EvalError::Invalid(
                "paired contexts or policy versions differ",
            ));
        }
    }
    Ok(())
}

fn validate_criteria(criteria: &PromotionCriteria) -> Result<()> {
    if criteria.schema_version != 1
        || !valid_hash(&criteria.dataset_hash)
        || !valid_hash(&criteria.registration_evidence_sha256)
        || criteria.minimum_cases == 0
        || criteria.minimum_cases > MAX_EVALUATION_CASES
        || criteria.minimum_families == 0
        || criteria.minimum_families > criteria.minimum_cases
        || criteria.rules.is_empty()
        || criteria.rules.len() > 5
        || criteria
            .rules
            .iter()
            .map(|rule| rule.metric)
            .collect::<BTreeSet<_>>()
            .len()
            != criteria.rules.len()
        || criteria.rules.iter().any(|rule| {
            rule.minimum_improvement_micros > 1_000_000
                || rule.maximum_regression_micros > 1_000_000
        })
        || !criteria
            .rules
            .iter()
            .any(|rule| rule.minimum_improvement_micros > 0)
        || !criteria.rules.iter().any(|rule| {
            rule.metric == PromotionMetric::RouteAccuracy && rule.maximum_regression_micros == 0
        })
        || criteria.policy_authors.is_empty()
        || criteria.policy_authors.len() > 64
        || criteria.policy_authors.iter().any(|id| !text(id))
        || criteria.training_families.len() > MAX_EVALUATION_CASES
        || criteria.training_families.iter().any(|id| !text(id))
    {
        return Err(EvalError::Invalid("promotion criteria"));
    }
    Ok(())
}

fn independent_label(trace: &ReplayTrace, criteria: Option<&PromotionCriteria>) -> bool {
    trace.label.as_ref().is_some_and(|label| {
        label.human_validated
            && label.independent
            && label.evidence_sha256.as_deref().is_some_and(valid_hash)
            && label.reviewer_id.as_ref().is_some_and(|id| {
                text(id) && criteria.is_some_and(|criteria| !criteria.policy_authors.contains(id))
            })
    })
}

fn metrics<'a>(
    traces: impl Iterator<Item = &'a ReplayTrace>,
    criteria: Option<&PromotionCriteria>,
) -> Result<EvaluationMetrics> {
    let mut result = EvaluationMetrics {
        cases: 0,
        route_accuracy_micros: None,
        total_cost_microusd: 0,
        mean_elapsed_ms: None,
        total_elapsed_ms: None,
        p95_elapsed_ms: None,
        abstention_micros: 0,
        hard_constraint_violations: 0,
        transport: OutcomeCounts::default(),
        command_validation: OutcomeCounts::default(),
        functional: OutcomeCounts::default(),
    };
    let (mut correct, mut labels, mut abstentions, mut latency, mut latency_count) =
        (0usize, 0usize, 0usize, 0u64, 0usize);
    let mut latency_samples = Vec::new();
    for trace in traces {
        result.cases += 1;
        result.total_cost_microusd = result
            .total_cost_microusd
            .checked_add(trace.cost_microusd)
            .ok_or(EvalError::CostOverflow)?;
        result.hard_constraint_violations += trace.hard_constraint_violations.len();
        if let Some(ms) = trace.elapsed_ms {
            latency = latency
                .checked_add(ms)
                .ok_or(EvalError::Limit("latency sum"))?;
            latency_count += 1;
            latency_samples.push(ms);
        }
        abstentions += usize::from(trace.receipt.selected.is_none());
        if let Some(label) = trace
            .label
            .as_ref()
            .filter(|_| independent_label(trace, criteria))
        {
            labels += 1;
            correct += usize::from(match &trace.receipt.selected {
                Some(selection) => label
                    .expected_candidate_ids
                    .contains(&selection.candidate.id),
                None => label.expect_abstention,
            });
        }
        count(&mut result.transport, trace.outcomes.transport);
        count(
            &mut result.command_validation,
            trace.outcomes.command_validation,
        );
        count(&mut result.functional, trace.outcomes.functional);
    }
    if result.cases == 0 {
        return Err(EvalError::Invalid("empty metrics"));
    }
    if labels == result.cases {
        result.route_accuracy_micros = Some(fraction(correct, labels));
    }
    if latency_count == result.cases {
        result.mean_elapsed_ms = Some(latency / result.cases as u64);
        result.total_elapsed_ms = Some(latency);
        latency_samples.sort_unstable();
        result.p95_elapsed_ms = Some(latency_samples[(result.cases * 95).div_ceil(100) - 1]);
    }
    result.abstention_micros = fraction(abstentions, result.cases);
    Ok(result)
}

fn count(counts: &mut OutcomeCounts, outcome: ObservedOutcome) {
    match outcome {
        ObservedOutcome::Passed => counts.passed += 1,
        ObservedOutcome::Failed => counts.failed += 1,
        ObservedOutcome::Unknown => counts.unknown += 1,
    }
}
fn fraction(numerator: usize, denominator: usize) -> u32 {
    (numerator * 1_000_000 / denominator) as u32
}
fn improvement(
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
            if baseline.functional.unknown > 0 || semantic.functional.unknown > 0 {
                return None;
            }
            Some(
                i128::from(fraction(semantic.functional.passed, semantic.cases))
                    - i128::from(fraction(baseline.functional.passed, baseline.cases)),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics() -> EvaluationMetrics {
        EvaluationMetrics {
            cases: 10,
            route_accuracy_micros: Some(800_000),
            total_cost_microusd: 1_000,
            mean_elapsed_ms: Some(10),
            total_elapsed_ms: Some(100),
            p95_elapsed_ms: Some(10),
            abstention_micros: 100_000,
            hard_constraint_violations: 0,
            transport: OutcomeCounts::default(),
            command_validation: OutcomeCounts::default(),
            functional: OutcomeCounts {
                passed: 9,
                failed: 1,
                unknown: 0,
            },
        }
    }

    #[test]
    fn all_metrics_lists_every_variant_once() {
        assert_eq!(all_metrics().count(), 5);
        assert_eq!(
            all_metrics().collect::<BTreeSet<_>>().len(),
            all_metrics().count()
        );
    }

    #[test]
    fn every_unlisted_metric_blocks_its_own_regression() {
        let baseline = metrics();
        assert!(unlisted_regressions(&[], &baseline, &baseline).is_empty());
        type Degrade = fn(&mut EvaluationMetrics);
        let worse: [(PromotionMetric, Degrade); 5] = [
            (PromotionMetric::RouteAccuracy, |m| {
                m.route_accuracy_micros = Some(700_000)
            }),
            (PromotionMetric::Cost, |m| m.total_cost_microusd = 1_001),
            (PromotionMetric::Latency, |m| m.total_elapsed_ms = Some(101)),
            (PromotionMetric::Abstention, |m| {
                m.abstention_micros = 200_000
            }),
            (PromotionMetric::FunctionalSuccess, |m| {
                m.functional.passed = 8;
                m.functional.failed = 2;
            }),
        ];
        for (metric, degrade) in worse {
            let mut semantic = baseline.clone();
            degrade(&mut semantic);
            assert_eq!(unlisted_regressions(&[], &baseline, &semantic), [metric]);
            // A listed metric is judged by its own rule, not by the guard.
            let rule = MetricRule {
                metric,
                minimum_improvement_micros: 0,
                maximum_regression_micros: 1_000_000,
            };
            assert!(unlisted_regressions(&[rule], &baseline, &semantic).is_empty());
        }
    }
}
