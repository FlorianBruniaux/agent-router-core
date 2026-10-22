//! Descriptive regret and quality/cost frontier over fixed, exhaustive replays.
use std::collections::{BTreeMap, BTreeSet};

use router_adapter_api::content_digest;
use router_catalog::Catalog;
use serde::{Deserialize, Serialize};

use crate::{
    EvalError, MetricsBudget, MetricsCase, MetricsCohort, MetricsProvenance, ObservedOutcome,
    PricingTable, ProductMetricsReport, ReplayRecord, Result, TokenUsage, evaluate_metrics, hash,
    price_usage, text, valid_hash,
};

pub const MAX_TRADEOFF_CELLS: usize = 8_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TradeoffPolicy {
    pub policy_id: String,
    pub policy_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TradeoffCell {
    pub policy_id: String,
    pub usage_complete: bool,
    pub usage_evidence_sha256: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TradeoffCase {
    pub case_id: String,
    pub input_hash: String,
    pub budget: MetricsBudget,
    pub selected_policy_id: String,
    pub cells: Vec<TradeoffCell>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TradeoffCohort {
    pub schema_version: u32,
    pub analysis_authorized: bool,
    pub provenance: MetricsProvenance,
    pub policies: Vec<TradeoffPolicy>,
    pub cases: Vec<TradeoffCase>,
}

impl TradeoffCohort {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > crate::MAX_METRICS_COHORT_BYTES {
            return Err(EvalError::Limit("tradeoffs cohort bytes"));
        }
        let value = router_adapter_api::strict_json(bytes)
            .map_err(|_| EvalError::Invalid("tradeoffs JSON"))?;
        let value: Self =
            serde_json::from_value(value).map_err(|_| EvalError::Invalid("tradeoffs schema"))?;
        value.canonical()?;
        Ok(value)
    }
    fn canonical(&self) -> Result<Self> {
        if self.schema_version != 1 || !self.analysis_authorized {
            return Err(EvalError::Invalid("tradeoffs authorization or version"));
        }
        if !(2..=8).contains(&self.policies.len())
            || self.cases.is_empty()
            || self.cases.len() > crate::MAX_EVALUATION_CASES
        {
            return Err(EvalError::Limit("tradeoffs dimensions"));
        }
        let cells = self
            .cases
            .len()
            .checked_mul(self.policies.len())
            .ok_or(EvalError::Limit("tradeoffs cells"))?;
        if cells > MAX_TRADEOFF_CELLS {
            return Err(EvalError::Limit("tradeoffs cells"));
        }
        let mut out = self.clone();
        out.policies.sort_by(|a, b| a.policy_id.cmp(&b.policy_id));
        out.cases.sort_by(|a, b| a.case_id.cmp(&b.case_id));
        for (i, p) in out.policies.iter().enumerate() {
            if !text(&p.policy_id)
                || !valid_hash(&p.policy_sha256)
                || (i > 0 && out.policies[i - 1].policy_id == p.policy_id)
            {
                return Err(EvalError::Invalid("tradeoffs policy"));
            }
        }
        let policies: BTreeSet<_> = out.policies.iter().map(|p| p.policy_id.as_str()).collect();
        for i in 0..out.cases.len() {
            let previous_id = i.checked_sub(1).map(|j| out.cases[j].case_id.clone());
            let c = &mut out.cases[i];
            if !text(&c.case_id)
                || !valid_hash(&c.input_hash)
                || !policies.contains(c.selected_policy_id.as_str())
                || previous_id.as_ref().is_some_and(|id| id == &c.case_id)
            {
                return Err(EvalError::Invalid("tradeoffs case"));
            }
            c.cells.sort_by(|a, b| a.policy_id.cmp(&b.policy_id));
            if c.cells.len() != policies.len() {
                return Err(EvalError::Invalid("tradeoffs cell matrix"));
            }
            for (j, cell) in c.cells.iter().enumerate() {
                if !policies.contains(cell.policy_id.as_str())
                    || cell
                        .usage_evidence_sha256
                        .as_ref()
                        .is_some_and(|h| !valid_hash(h))
                    || (cell.usage_complete && cell.usage_evidence_sha256.is_none())
                    || (j > 0 && c.cells[j - 1].policy_id == cell.policy_id)
                {
                    return Err(EvalError::Invalid("tradeoffs cell"));
                }
            }
            if c.cells
                .iter()
                .map(|x| x.policy_id.as_str())
                .collect::<BTreeSet<_>>()
                != policies
            {
                return Err(EvalError::Invalid("tradeoffs cell matrix"));
            }
        }
        if serde_json::to_vec(&out)
            .map_err(|_| EvalError::Invalid("tradeoffs serialization"))?
            .len()
            > crate::MAX_METRICS_COHORT_BYTES
        {
            return Err(EvalError::Limit("tradeoffs cohort bytes"));
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyTradeoff {
    pub policy_id: String,
    pub functional: crate::OutcomeCounts,
    pub known_cost_microusd: u64,
    pub known_cost_cases: u64,
    pub cost_unknown_cases: u64,
    pub complete_point: bool,
    pub dominated_by: Vec<String>,
    pub selected_cases: u64,
    pub functional_regret_known_cases: u64,
    pub functional_regret_unknown_cases: u64,
    pub functional_regret_sum_micros: u64,
    pub cost_regret_known_cases: u64,
    pub cost_regret_unknown_cases: u64,
    pub cost_regret_not_applicable_cases: u64,
    pub cost_regret_sum_microusd: u64,
    pub metrics: ProductMetricsReport,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TradeoffReport {
    pub schema_version: u32,
    pub cohort_hash: String,
    pub provenance: MetricsProvenance,
    pub cases: u64,
    pub partial_frontier: bool,
    pub policies: Vec<PolicyTradeoff>,
    pub frontier: Vec<String>,
    pub incomplete: Vec<String>,
    pub incomparable: Vec<String>,
}

pub fn evaluate_tradeoffs(
    cohort: &TradeoffCohort,
    records: &[ReplayRecord],
) -> Result<TradeoffReport> {
    let cohort = cohort.canonical()?;
    if records.len() != cohort.cases.len() {
        return Err(EvalError::Invalid("tradeoffs record set"));
    }
    let by_record: BTreeMap<_, _> = records
        .iter()
        .map(|r| (r.input().case_id.as_str(), r))
        .collect();
    if by_record.len() != records.len() {
        return Err(EvalError::Invalid("tradeoffs duplicate record"));
    }
    let ids: BTreeSet<_> = cohort.cases.iter().map(|c| c.case_id.as_str()).collect();
    if by_record.keys().copied().collect::<BTreeSet<_>>() != ids {
        return Err(EvalError::Invalid("tradeoffs record set"));
    }
    let mut reports = BTreeMap::new();
    for policy in &cohort.policies {
        let mut metric_cases = Vec::new();
        for case in &cohort.cases {
            let record = by_record[case.case_id.as_str()];
            if record.input_hash() != case.input_hash {
                return Err(EvalError::Integrity);
            }
            let input = record.input();
            if input.policies.keys().collect::<BTreeSet<_>>()
                != cohort
                    .policies
                    .iter()
                    .map(|p| &p.policy_id)
                    .collect::<BTreeSet<_>>()
                || input.observations.keys().collect::<BTreeSet<_>>()
                    != cohort
                        .policies
                        .iter()
                        .map(|p| &p.policy_id)
                        .collect::<BTreeSet<_>>()
            {
                return Err(EvalError::Invalid("tradeoffs policy matrix"));
            }
            let pinned = cohort
                .policies
                .iter()
                .find(|p| p.policy_id == policy.policy_id)
                .ok_or(EvalError::UnknownPolicy)?;
            if content_digest(
                &serde_json::to_vec(&input.policies[&policy.policy_id])
                    .map_err(|_| EvalError::Invalid("tradeoffs policy"))?,
            ) != pinned.policy_sha256
            {
                return Err(EvalError::Integrity);
            }
            let cell = case
                .cells
                .iter()
                .find(|x| x.policy_id == policy.policy_id)
                .ok_or(EvalError::Integrity)?;
            metric_cases.push(MetricsCase {
                case_id: case.case_id.clone(),
                input_hash: case.input_hash.clone(),
                policy_id: policy.policy_id.clone(),
                policy_sha256: pinned.policy_sha256.clone(),
                budget: case.budget.clone(),
                predicted_success_micros: None,
                usage_complete: cell.usage_complete,
                usage_evidence_sha256: cell.usage_evidence_sha256.clone(),
            });
        }
        reports.insert(
            policy.policy_id.clone(),
            evaluate_metrics(
                &MetricsCohort {
                    schema_version: 1,
                    analysis_authorized: true,
                    provenance: cohort.provenance.clone(),
                    cases: metric_cases,
                },
                records,
            )?,
        );
    }
    let ids: Vec<_> = cohort
        .policies
        .iter()
        .map(|p| p.policy_id.clone())
        .collect();
    let mut dominated = BTreeMap::<String, Vec<String>>::new();
    for a in &ids {
        for b in &ids {
            if a == b {
                continue;
            }
            let x = &reports[a];
            let y = &reports[b];
            if x.functional.unknown == 0
                && y.functional.unknown == 0
                && x.known_cost_cases == cohort.cases.len() as u64
                && y.known_cost_cases == cohort.cases.len() as u64
            {
                let xs = x.functional.passed as u64;
                let ys = y.functional.passed as u64;
                if xs >= ys
                    && x.known_cost_microusd <= y.known_cost_microusd
                    && (xs > ys || x.known_cost_microusd < y.known_cost_microusd)
                {
                    dominated.entry(b.clone()).or_default().push(a.clone());
                }
            }
        }
    }
    let mut result = Vec::new();
    for policy in &ids {
        let m = &reports[policy];
        let mut regret_known = 0u64;
        let mut regret_unknown = 0u64;
        let mut regret_sum = 0u64;
        let mut cost_known = 0u64;
        let mut cost_unknown = 0u64;
        let mut cost_na = 0u64;
        let mut cost_sum = 0u64;
        for case in &cohort.cases {
            let record = by_record[case.case_id.as_str()];
            let chosen = record
                .input()
                .observations
                .get(&case.selected_policy_id)
                .ok_or(EvalError::Invalid("tradeoffs selected observation"))?;
            if policy != &case.selected_policy_id {
                continue;
            }
            if chosen.outcomes.functional == ObservedOutcome::Failed {
                cost_na += 1;
            }
            let outcomes: Vec<_> = ids
                .iter()
                .map(|id| {
                    record
                        .input()
                        .observations
                        .get(id)
                        .map(|o| o.outcomes.functional)
                })
                .collect();
            let best = if outcomes.contains(&Some(ObservedOutcome::Passed)) {
                Some(1_000_000)
            } else if outcomes.iter().all(|o| *o == Some(ObservedOutcome::Failed)) {
                Some(0)
            } else {
                None
            };
            match (best, chosen.outcomes.functional) {
                (Some(_), ObservedOutcome::Passed) => {
                    regret_known += 1;
                }
                (Some(best), ObservedOutcome::Failed) => {
                    regret_known += 1;
                    regret_sum = regret_sum
                        .checked_add(best)
                        .ok_or(EvalError::Limit("tradeoffs arithmetic"))?;
                }
                (_, ObservedOutcome::Unknown) => regret_unknown += 1,
                (None, _) => regret_unknown += 1,
            }
            if chosen.outcomes.functional != ObservedOutcome::Failed {
                if outcomes.contains(&Some(ObservedOutcome::Unknown))
                    || outcomes.iter().any(Option::is_none)
                {
                    cost_unknown += 1;
                } else {
                    let catalog = Catalog::from_json(
                        &serde_json::to_vec(&record.input().catalog)
                            .map_err(|_| EvalError::Catalog)?,
                    )
                    .map_err(|_| EvalError::Catalog)?;
                    let usage_complete = |id: &str| {
                        case.cells
                            .iter()
                            .find(|cell| cell.policy_id == id)
                            .is_some_and(|cell| cell.usage_complete)
                    };
                    let choice_cost = if usage_complete(&case.selected_policy_id) {
                        known_price(&record.input().pricing, &chosen.usage, &catalog)?
                    } else {
                        None
                    };
                    let successful: Vec<_> = ids
                        .iter()
                        .filter_map(|id| {
                            record
                                .input()
                                .observations
                                .get(id)
                                .filter(|o| o.outcomes.functional == ObservedOutcome::Passed)
                                .map(|o| (id, o))
                        })
                        .collect();
                    let costs = successful
                        .iter()
                        .map(|(id, obs)| {
                            if usage_complete(id) {
                                known_price(&record.input().pricing, &obs.usage, &catalog)
                            } else {
                                Ok(None)
                            }
                        })
                        .collect::<Result<Vec<_>>>()?;
                    if let (Some(actual), Some(best)) = (
                        choice_cost,
                        costs
                            .iter()
                            .copied()
                            .collect::<Option<Vec<_>>>()
                            .and_then(|values| values.into_iter().min()),
                    ) {
                        cost_known += 1;
                        let regret = actual.checked_sub(best).ok_or(EvalError::Integrity)?;
                        cost_sum = cost_sum
                            .checked_add(regret)
                            .ok_or(EvalError::Limit("tradeoffs arithmetic"))?;
                    } else {
                        cost_unknown += 1;
                    }
                }
            }
        }
        let incomplete = m.functional.unknown > 0 || m.known_cost_cases < cohort.cases.len() as u64;
        result.push(PolicyTradeoff {
            policy_id: policy.clone(),
            functional: m.functional.clone(),
            known_cost_microusd: m.known_cost_microusd,
            known_cost_cases: m.known_cost_cases,
            cost_unknown_cases: m.cases - m.known_cost_cases,
            complete_point: !incomplete,
            dominated_by: dominated.remove(policy).unwrap_or_default(),
            selected_cases: cohort
                .cases
                .iter()
                .filter(|case| case.selected_policy_id == *policy)
                .count() as u64,
            functional_regret_known_cases: regret_known,
            functional_regret_unknown_cases: regret_unknown,
            functional_regret_sum_micros: regret_sum,
            cost_regret_known_cases: cost_known,
            cost_regret_unknown_cases: cost_unknown,
            cost_regret_not_applicable_cases: cost_na,
            cost_regret_sum_microusd: cost_sum,
            metrics: m.clone(),
        });
    }
    let incomplete: Vec<_> = result
        .iter()
        .filter(|p| !p.complete_point)
        .map(|p| p.policy_id.clone())
        .collect();
    let frontier: Vec<_> = result
        .iter()
        .filter(|p| p.complete_point && p.dominated_by.is_empty())
        .map(|p| p.policy_id.clone())
        .collect();
    let incomparable = incomplete.clone();
    let hash = hash(b"agent-router:tradeoffs-cohort:v1\0", &cohort)?;
    Ok(TradeoffReport {
        schema_version: 1,
        cohort_hash: hash,
        provenance: cohort.provenance.clone(),
        cases: cohort.cases.len() as u64,
        partial_frontier: !incomplete.is_empty(),
        policies: result,
        frontier,
        incomplete,
        incomparable,
    })
}

/// Only a price genuinely absent from the table is unknown cost. An unknown
/// model, an overflow or a limit is an evaluation error, never silently unknown.
fn known_price(
    pricing: &PricingTable,
    usage: &[TokenUsage],
    catalog: &Catalog,
) -> Result<Option<u64>> {
    match price_usage(pricing, usage, catalog) {
        Ok(cost) => Ok(Some(cost)),
        Err(EvalError::UnknownPricing) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TokenPrice;
    use router_types::ModelId;

    fn catalog() -> Catalog {
        Catalog::from_json(include_bytes!(
            "../../../fixtures/examples/phase-catalog.json"
        ))
        .unwrap()
    }
    fn pricing(models: &[(&str, u64)]) -> PricingTable {
        PricingTable {
            schema_version: 1,
            version: "fixture".into(),
            source: "fixture".into(),
            observed_at_unix_seconds: 100,
            models: models
                .iter()
                .map(|(name, rate)| {
                    (
                        ModelId::parse(*name).unwrap(),
                        TokenPrice {
                            input_microusd_per_million: *rate,
                            cached_input_microusd_per_million: *rate,
                            output_microusd_per_million: *rate,
                        },
                    )
                })
                .collect(),
        }
    }
    fn usage(model: &str, input_tokens: u64) -> TokenUsage {
        TokenUsage {
            model: ModelId::parse(model).unwrap(),
            input_tokens,
            cached_input_tokens: 0,
            output_tokens: 0,
        }
    }

    #[test]
    fn only_a_missing_price_is_an_unknown_cost() {
        let catalog = catalog();
        let priced = pricing(&[("fixture-best", 1_000_000)]);
        assert!(matches!(
            known_price(&priced, &[usage("fixture-best", 7)], &catalog),
            Ok(Some(7))
        ));
        assert!(matches!(
            known_price(&pricing(&[]), &[usage("fixture-best", 7)], &catalog),
            Ok(None)
        ));
        assert!(matches!(
            known_price(&priced, &[usage("not-in-catalog", 7)], &catalog),
            Err(EvalError::UnknownModel)
        ));
        assert!(matches!(
            known_price(
                &pricing(&[("fixture-best", u64::MAX)]),
                &[usage("fixture-best", u64::MAX)],
                &catalog
            ),
            Err(EvalError::CostOverflow)
        ));
    }
}
