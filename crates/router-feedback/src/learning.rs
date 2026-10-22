use std::collections::BTreeMap;

use router_types::{FeedbackEvent, FeedbackOrigin, VerificationOutcome};
use serde::{Deserialize, Serialize};

use crate::{FeedbackError, Result, hash};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct OutcomeStatistics {
    pub passed: u64,
    pub failed: u64,
    pub unknown: u64,
}
impl OutcomeStatistics {
    fn observe(&mut self, value: VerificationOutcome) {
        match value {
            VerificationOutcome::Passed => self.passed += 1,
            VerificationOutcome::Failed => self.failed += 1,
            VerificationOutcome::Unknown => self.unknown += 1,
        }
    }
    pub fn verified_samples(&self) -> u64 {
        self.passed + self.failed
    }
}

/// Beta(1,1) prior plus explicit success/failure observations. UNKNOWN does not
/// update either parameter; this is descriptive association, not causal effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BetaCompetence {
    pub alpha: u64,
    pub beta: u64,
    pub unknown: u64,
}
impl Default for BetaCompetence {
    fn default() -> Self {
        Self {
            alpha: 1,
            beta: 1,
            unknown: 0,
        }
    }
}
impl BetaCompetence {
    fn observe(&mut self, value: VerificationOutcome) {
        match value {
            VerificationOutcome::Passed => self.alpha += 1,
            VerificationOutcome::Failed => self.beta += 1,
            VerificationOutcome::Unknown => self.unknown += 1,
        }
    }
}

/// Exact moments and empirical quantiles. Ratios remain rational to avoid
/// floating-point drift; divide by samples when presenting mean/variance.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct MeasurementStatistics {
    pub samples: u64,
    pub missing: u64,
    pub sum: u128,
    pub sum_squares: u128,
    pub min: Option<u64>,
    pub median: Option<u64>,
    pub p95: Option<u64>,
    pub max: Option<u64>,
}
fn measurement(values: impl Iterator<Item = Option<u64>>) -> MeasurementStatistics {
    let mut result = MeasurementStatistics::default();
    let mut known = Vec::new();
    for value in values {
        match value {
            None => result.missing += 1,
            Some(value) => {
                known.push(value);
                result.samples += 1;
                result.sum += u128::from(value);
                result.sum_squares += u128::from(value).pow(2);
            }
        }
    }
    known.sort_unstable();
    result.min = known.first().copied();
    result.max = known.last().copied();
    if !known.is_empty() {
        result.median = Some(known[(known.len() - 1) / 2]);
        result.p95 = Some(known[(known.len() * 95).div_ceil(100) - 1]);
    }
    result
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CompetenceStatistics {
    pub automated: BetaCompetence,
    pub human: BetaCompetence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PerformanceStatistics {
    pub model: String,
    pub effort: String,
    pub harness: String,
    pub cost_microusd: MeasurementStatistics,
    pub latency_ms: MeasurementStatistics,
    pub tokens: MeasurementStatistics,
    pub attempts: u64,
    pub escalations: u64,
}

/// Route facts of automated events. Skipped when empty so statistics of
/// pre-route stores keep their content hash.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RouteStatistics {
    pub recorded: usize,
    /// Executions that overrode an abstaining baseline receipt.
    pub abstained: usize,
}
impl RouteStatistics {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FeedbackStatistics {
    pub schema_version: u32,
    pub event_set_hash: String,
    pub events: usize,
    pub transport: OutcomeStatistics,
    pub validation: OutcomeStatistics,
    pub objective: OutcomeStatistics,
    pub human_success: OutcomeStatistics,
    pub human_quality: MeasurementStatistics,
    pub competence: BTreeMap<String, CompetenceStatistics>,
    pub performance: Vec<PerformanceStatistics>,
    pub transport_failures: BTreeMap<String, OutcomeStatistics>,
    pub failure_classes: BTreeMap<String, u64>,
    /// Human preference by discrete context/plan. It never changes live routing.
    pub plan_preference: BTreeMap<String, OutcomeStatistics>,
    pub known_propensities: usize,
    pub unknown_propensities: usize,
    #[serde(skip_serializing_if = "RouteStatistics::is_empty")]
    pub route: RouteStatistics,
    pub interpretation: String,
    pub content_hash: String,
}

pub(crate) fn statistics(events: &[FeedbackEvent]) -> Result<FeedbackStatistics> {
    let mut result = FeedbackStatistics {
        schema_version: 1,
        event_set_hash: event_set_hash(events)?,
        events: events.len(),
        transport: OutcomeStatistics::default(),
        validation: OutcomeStatistics::default(),
        objective: OutcomeStatistics::default(),
        human_success: OutcomeStatistics::default(),
        human_quality: measurement(
            events
                .iter()
                .filter_map(|e| e.input.human.as_ref())
                .map(|h| h.quality.map(u64::from)),
        ),
        competence: BTreeMap::new(),
        performance: vec![],
        transport_failures: BTreeMap::new(),
        failure_classes: BTreeMap::new(),
        plan_preference: BTreeMap::new(),
        known_propensities: 0,
        unknown_propensities: 0,
        route: RouteStatistics::default(),
        interpretation: "descriptive_associations_not_causal_or_verified_human_gain".into(),
        content_hash: String::new(),
    };
    let mut groups: BTreeMap<(String, String, String), Vec<&FeedbackEvent>> = BTreeMap::new();
    for event in events {
        let i = &event.input;
        let c = &i.context;
        if i.origin == FeedbackOrigin::Automated {
            result.transport.observe(i.transport);
            result.validation.observe(i.validation);
            result.objective.observe(i.objective);
            result
                .transport_failures
                .entry(c.transport.clone())
                .or_default()
                .observe(i.transport);
            if let Some(failure) = i.failure {
                *result
                    .failure_classes
                    .entry(format!("{failure:?}"))
                    .or_default() += 1;
            }
            groups
                .entry((
                    c.model.to_string(),
                    format!("{:?}", c.effort),
                    c.harness.to_string(),
                ))
                .or_default()
                .push(event);
            if c.propensity_micros.is_some() {
                result.known_propensities += 1;
            } else {
                result.unknown_propensities += 1;
            }
            if let Some(route) = &c.route {
                result.route.recorded += 1;
                result.route.abstained += usize::from(route.abstention.is_some());
            }
        }
        if let Some(human) = &i.human {
            result.human_success.observe(human.success);
            let key = serde_json::to_string(&(c.task_kind, c.risk, &c.plan))?;
            result
                .plan_preference
                .entry(key)
                .or_default()
                .observe(human.success);
        }
        if let Some(agent) = &c.agent {
            for skill in &c.skills {
                let key = serde_json::to_string(&(agent, skill))?;
                let entry = result.competence.entry(key).or_default();
                match i.origin {
                    FeedbackOrigin::Automated => entry.automated.observe(i.objective),
                    FeedbackOrigin::Human => {
                        if let Some(h) = &i.human {
                            entry.human.observe(h.success);
                        }
                    }
                }
            }
        }
    }
    for ((model, effort, harness), events) in groups {
        result.performance.push(PerformanceStatistics {
            model,
            effort,
            harness,
            cost_microusd: measurement(events.iter().map(|e| e.input.measurements.cost_microusd)),
            latency_ms: measurement(events.iter().map(|e| e.input.measurements.latency_ms)),
            tokens: measurement(events.iter().map(|e| e.input.measurements.tokens)),
            attempts: events
                .iter()
                .map(|e| u64::from(e.input.measurements.attempts))
                .sum(),
            escalations: events
                .iter()
                .map(|e| u64::from(e.input.measurements.escalations))
                .sum(),
        });
    }
    result.content_hash = hash("feedback-statistics-v1", &result)?;
    Ok(result)
}

pub(crate) fn event_set_hash(events: &[FeedbackEvent]) -> Result<String> {
    hash(
        "feedback-event-set-v1",
        &events.iter().map(|e| &e.event_hash).collect::<Vec<_>>(),
    )
}

/// Caller-supplied experimental rules, never a claim of a learned threshold.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LearningRules {
    pub schema_version: u32,
    pub minimum_verified_samples: u32,
    pub drift_window_seconds: u64,
    pub minimum_drift_micros: u32,
    pub maximum_weight_delta: u32,
    pub maximum_canary_cases: u32,
}
impl LearningRules {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.minimum_verified_samples == 0
            || self.minimum_verified_samples > 10_000
            || self.drift_window_seconds == 0
            || self.drift_window_seconds > crate::MAX_RETENTION_SECONDS / 2
            || self.minimum_drift_micros == 0
            || self.minimum_drift_micros > 1_000_000
            || self.maximum_weight_delta == 0
            || self.maximum_weight_delta > 1000
            || self.maximum_canary_cases == 0
            || self.maximum_canary_cases > 100
        {
            return Err(FeedbackError::Invalid("learning rules"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DriftFinding {
    pub policy_hash: String,
    pub previous: OutcomeStatistics,
    pub recent: OutcomeStatistics,
    pub quarantine_recommended: bool,
    pub reason: String,
}

pub(crate) fn drift(
    events: &[FeedbackEvent],
    rules: &LearningRules,
    now: u64,
) -> Result<Vec<DriftFinding>> {
    rules.validate()?;
    let recent_start = now.saturating_sub(rules.drift_window_seconds);
    let previous_start = recent_start.saturating_sub(rules.drift_window_seconds);
    let mut groups: BTreeMap<String, (OutcomeStatistics, OutcomeStatistics)> = BTreeMap::new();
    for event in events {
        let input = &event.input;
        if input.origin != FeedbackOrigin::Automated
            || input.observed_at_unix_seconds < previous_start
        {
            continue;
        }
        let (previous, recent) = groups.entry(input.binding.policy_hash.clone()).or_default();
        if input.observed_at_unix_seconds < recent_start {
            previous.observe(input.objective);
        } else {
            recent.observe(input.objective);
        }
    }
    Ok(groups
        .into_iter()
        .map(|(policy_hash, (previous, recent))| {
            let enough = previous.verified_samples() >= u64::from(rules.minimum_verified_samples)
                && recent.verified_samples() >= u64::from(rules.minimum_verified_samples);
            let decline = enough
                && (i128::from(previous.passed) * i128::from(recent.verified_samples())
                    - i128::from(recent.passed) * i128::from(previous.verified_samples()))
                    * 1_000_000
                    >= i128::from(rules.minimum_drift_micros)
                        * i128::from(previous.verified_samples())
                        * i128::from(recent.verified_samples());
            DriftFinding {
                policy_hash,
                previous,
                recent,
                quarantine_recommended: decline,
                reason: if !enough {
                    "insufficient_verified_samples"
                } else if decline {
                    "observed_success_decline_requires_review"
                } else {
                    "no_threshold_crossing"
                }
                .into(),
            }
        })
        .collect())
}
