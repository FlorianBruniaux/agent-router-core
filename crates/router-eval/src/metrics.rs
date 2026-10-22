//! Descriptive metrics over an exhaustive cohort of supplied, sealed records.
//! Hashes bind content; they do not authenticate labels, consent or usage.
use std::collections::BTreeMap;

use router_adapter_api::{content_digest, strict_json};
use router_catalog::Catalog;
use serde::{Deserialize, Serialize};

use crate::{
    EvalError, MAX_EVALUATION_CASES, ObservedOutcome, OutcomeCounts, ReplayRecord, Result, hash,
    price_usage, text, valid_hash,
};

pub const MAX_METRICS_COHORT_BYTES: usize = 1024 * 1024;
pub const MAX_METRICS_RECORD_BYTES: usize = 16 * 1024 * 1024;
const SCALE: u64 = 1_000_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricsProvenance {
    Synthetic,
    Supplied,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsBudget {
    pub max_cost_microusd: u64,
    pub max_tokens: u64,
    pub max_elapsed_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsCase {
    pub case_id: String,
    pub input_hash: String,
    pub policy_id: String,
    /// SHA-256 of serde_json's serialized typed PhasePolicy, not a route receipt hash.
    pub policy_sha256: String,
    pub budget: MetricsBudget,
    pub predicted_success_micros: Option<u32>,
    pub usage_complete: bool,
    pub usage_evidence_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsCohort {
    pub schema_version: u32,
    pub analysis_authorized: bool,
    pub provenance: MetricsProvenance,
    pub cases: Vec<MetricsCase>,
}

impl MetricsCohort {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_METRICS_COHORT_BYTES {
            return Err(EvalError::Limit("metrics cohort bytes"));
        }
        let value = strict_json(bytes).map_err(|_| EvalError::Invalid("metrics JSON"))?;
        let cohort: Self =
            serde_json::from_value(value).map_err(|_| EvalError::Invalid("metrics schema"))?;
        cohort.canonical()?;
        Ok(cohort)
    }

    fn canonical(&self) -> Result<Self> {
        if self.schema_version != 1 || !self.analysis_authorized {
            return Err(EvalError::Invalid("metrics authorization or version"));
        }
        if self.cases.is_empty() || self.cases.len() > MAX_EVALUATION_CASES {
            return Err(EvalError::Limit("metrics cases"));
        }
        let mut canonical = self.clone();
        canonical.cases.sort_by(|a, b| a.case_id.cmp(&b.case_id));
        for (index, case) in canonical.cases.iter().enumerate() {
            if !text(&case.case_id)
                || !text(&case.policy_id)
                || !valid_hash(&case.input_hash)
                || !valid_hash(&case.policy_sha256)
                || case
                    .predicted_success_micros
                    .is_some_and(|p| u64::from(p) > SCALE)
                || case
                    .usage_evidence_sha256
                    .as_ref()
                    .is_some_and(|h| !valid_hash(h))
                || (case.usage_complete && case.usage_evidence_sha256.is_none())
                || (index > 0 && canonical.cases[index - 1].case_id == case.case_id)
            {
                return Err(EvalError::Invalid("metrics case"));
            }
        }
        if serde_json::to_vec(&canonical)
            .map_err(|_| EvalError::Invalid("metrics serialization"))?
            .len()
            > MAX_METRICS_COHORT_BYTES
        {
            return Err(EvalError::Limit("metrics cohort bytes"));
        }
        Ok(canonical)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExactRatio {
    pub numerator: u64,
    pub denominator: u64,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CalibrationBin {
    pub lower_micros: u32,
    pub upper_micros: u32,
    pub known_pairs: u64,
    pub predicted_sum_micros: u64,
    pub functional_successes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CalibrationMetrics {
    pub known_pairs: u64,
    pub missing_predictions: u64,
    pub missing_outcomes: u64,
    pub brier: Option<ExactRatio>,
    pub ece: Option<ExactRatio>,
    pub bins: Vec<CalibrationBin>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProductMetricsReport {
    pub schema_version: u32,
    pub cohort_hash: String,
    pub provenance: MetricsProvenance,
    pub cases: u64,
    pub functional: OutcomeCounts,
    pub success_at_budget: OutcomeCounts,
    pub success_at_budget_rate: Option<ExactRatio>,
    pub success_at_budget_lower: ExactRatio,
    pub success_at_budget_upper: ExactRatio,
    pub known_cost_cases: u64,
    pub known_cost_microusd: u64,
    pub cost_unknown_reasons: BTreeMap<String, u64>,
    pub known_latency_cases: u64,
    pub known_total_execution_ms: u64,
    pub cost_microusd_per_functional_success: Option<ExactRatio>,
    pub total_execution_ms_per_functional_success: Option<ExactRatio>,
    pub calibration: CalibrationMetrics,
}

fn add(total: &mut u64, amount: u64) -> Result<()> {
    *total = total
        .checked_add(amount)
        .ok_or(EvalError::Limit("metrics arithmetic"))?;
    Ok(())
}
fn count(counts: &mut OutcomeCounts, outcome: ObservedOutcome) {
    match outcome {
        ObservedOutcome::Passed => counts.passed += 1,
        ObservedOutcome::Failed => counts.failed += 1,
        ObservedOutcome::Unknown => counts.unknown += 1,
    }
}
fn ratio(numerator: u64, denominator: u64) -> ExactRatio {
    ExactRatio {
        numerator,
        denominator,
    }
}

pub fn evaluate_metrics(
    cohort: &MetricsCohort,
    records: &[ReplayRecord],
) -> Result<ProductMetricsReport> {
    let cohort = cohort.canonical()?;
    if records.len() != cohort.cases.len() {
        return Err(EvalError::Invalid("metrics record set"));
    }
    let mut by_id = BTreeMap::new();
    let mut bytes = 0usize;
    for record in records {
        let raw = record.canonical_json()?;
        bytes = bytes
            .checked_add(raw.len())
            .ok_or(EvalError::Limit("metrics records bytes"))?;
        if bytes > MAX_METRICS_RECORD_BYTES {
            return Err(EvalError::Limit("metrics records bytes"));
        }
        // Deserialize is available for legacy formats; do not assume callers used from_json.
        ReplayRecord::from_json(&raw)?;
        if by_id
            .insert(record.input().case_id.as_str(), record)
            .is_some()
        {
            return Err(EvalError::Invalid("metrics duplicate record"));
        }
    }
    let total = records.len() as u64;
    let mut report = ProductMetricsReport {
        schema_version: 1,
        cohort_hash: hash(b"agent-router:metrics-cohort:v1\0", &cohort)?,
        provenance: cohort.provenance.clone(),
        cases: total,
        functional: OutcomeCounts::default(),
        success_at_budget: OutcomeCounts::default(),
        success_at_budget_rate: None,
        success_at_budget_lower: ratio(0, total),
        success_at_budget_upper: ratio(0, total),
        known_cost_cases: 0,
        known_cost_microusd: 0,
        cost_unknown_reasons: BTreeMap::new(),
        known_latency_cases: 0,
        known_total_execution_ms: 0,
        cost_microusd_per_functional_success: None,
        total_execution_ms_per_functional_success: None,
        calibration: CalibrationMetrics {
            known_pairs: 0,
            missing_predictions: 0,
            missing_outcomes: 0,
            brier: None,
            ece: None,
            bins: (0..10)
                .map(|n| CalibrationBin {
                    lower_micros: n * 100_000,
                    upper_micros: (n + 1) * 100_000,
                    ..Default::default()
                })
                .collect(),
        },
    };
    let mut brier_sum = 0;
    for case in &cohort.cases {
        let record = by_id
            .get(case.case_id.as_str())
            .ok_or(EvalError::Integrity)?;
        let input = record.input();
        if record.input_hash() != case.input_hash {
            return Err(EvalError::Integrity);
        }
        let policy = input
            .policies
            .get(&case.policy_id)
            .ok_or(EvalError::UnknownPolicy)?;
        router_policy::PhaseRouter::new(policy.clone())
            .map_err(|_| EvalError::Invalid("metrics policy"))?;
        let serialized =
            serde_json::to_vec(policy).map_err(|_| EvalError::Invalid("metrics policy"))?;
        if content_digest(&serialized) != case.policy_sha256 {
            return Err(EvalError::Integrity);
        }
        let observation = input
            .observations
            .get(&case.policy_id)
            .ok_or(EvalError::Invalid("metrics observation"))?;
        let catalog = Catalog::from_json(
            &serde_json::to_vec(&input.catalog).map_err(|_| EvalError::Catalog)?,
        )
        .map_err(|_| EvalError::Catalog)?;
        let mut tokens = 0;
        for usage in &observation.usage {
            if catalog.model(&usage.model).is_none() {
                return Err(EvalError::UnknownModel);
            }
            if usage.cached_input_tokens > usage.input_tokens {
                return Err(EvalError::Invalid("cached tokens exceed input tokens"));
            }
            add(&mut tokens, usage.input_tokens)?;
            add(&mut tokens, usage.output_tokens)?;
        }
        let cost = if !case.usage_complete {
            *report
                .cost_unknown_reasons
                .entry("usage_incomplete".into())
                .or_default() += 1;
            None
        } else {
            match price_usage(&input.pricing, &observation.usage, &catalog) {
                Ok(cost) => Some(cost),
                Err(EvalError::UnknownPricing) => {
                    *report
                        .cost_unknown_reasons
                        .entry("pricing_missing".into())
                        .or_default() += 1;
                    None
                }
                Err(error) => return Err(error),
            }
        };
        if let Some(cost) = cost {
            add(&mut report.known_cost_microusd, cost)?;
            report.known_cost_cases += 1;
        }
        if let Some(elapsed) = observation.elapsed_ms {
            add(&mut report.known_total_execution_ms, elapsed)?;
            report.known_latency_cases += 1;
        }
        let outcome = observation.outcomes.functional;
        count(&mut report.functional, outcome);
        let exceeded = cost.is_some_and(|c| c > case.budget.max_cost_microusd)
            || tokens > case.budget.max_tokens
            || observation
                .elapsed_ms
                .is_some_and(|ms| ms > case.budget.max_elapsed_ms);
        let budget_outcome = if outcome == ObservedOutcome::Failed || exceeded {
            ObservedOutcome::Failed
        } else if outcome == ObservedOutcome::Passed
            && case.usage_complete
            && cost.is_some()
            && observation.elapsed_ms.is_some()
        {
            ObservedOutcome::Passed
        } else {
            ObservedOutcome::Unknown
        };
        count(&mut report.success_at_budget, budget_outcome);
        if case.predicted_success_micros.is_none() {
            report.calibration.missing_predictions += 1;
        }
        if outcome == ObservedOutcome::Unknown {
            report.calibration.missing_outcomes += 1;
        }
        if let Some(p) = case
            .predicted_success_micros
            .filter(|_| outcome != ObservedOutcome::Unknown)
        {
            let p = u64::from(p);
            let y = if outcome == ObservedOutcome::Passed {
                SCALE
            } else {
                0
            };
            let delta = p.abs_diff(y);
            add(
                &mut brier_sum,
                delta
                    .checked_mul(delta)
                    .ok_or(EvalError::Limit("metrics arithmetic"))?,
            )?;
            let bin = &mut report.calibration.bins[(p / 100_000).min(9) as usize];
            bin.known_pairs += 1;
            add(&mut bin.predicted_sum_micros, p)?;
            bin.functional_successes += u64::from(outcome == ObservedOutcome::Passed);
            report.calibration.known_pairs += 1;
        }
    }
    let successes = report.functional.passed as u64;
    if successes > 0 && report.functional.unknown == 0 {
        if report.known_cost_cases == total {
            report.cost_microusd_per_functional_success =
                Some(ratio(report.known_cost_microusd, successes));
        }
        if report.known_latency_cases == total {
            report.total_execution_ms_per_functional_success =
                Some(ratio(report.known_total_execution_ms, successes));
        }
    }
    let passed = report.success_at_budget.passed as u64;
    report.success_at_budget_lower = ratio(passed, total);
    report.success_at_budget_upper = ratio(passed + report.success_at_budget.unknown as u64, total);
    if report.success_at_budget.unknown == 0 {
        report.success_at_budget_rate = Some(ratio(passed, total));
    }
    if report.calibration.known_pairs == total {
        report.calibration.brier = Some(ratio(brier_sum, total * SCALE * SCALE));
        let mut deviation = 0;
        for bin in &report.calibration.bins {
            add(
                &mut deviation,
                bin.predicted_sum_micros
                    .abs_diff(bin.functional_successes * SCALE),
            )?;
        }
        report.calibration.ece = Some(ratio(deviation, total * SCALE));
    }
    Ok(report)
}
