//! `feedback report`: descriptive outcome measurement per model, effort and
//! task kind. Read-only and deterministic: every list is sorted and every
//! figure is an integer or fixed-precision micros. It shows associations, not
//! a gain attributable to the router (that needs the paired A/B protocol).
use std::collections::{BTreeMap, BTreeSet};

use router_eval::{PricingTable, TokenPrice};
use router_types::{
    FeedbackBinding, FeedbackEvent, FeedbackFact, FeedbackFactEvent, FeedbackFactKind,
    FeedbackFailure, FeedbackOrigin, FeedbackUsageScope, HostUsage, IntegrationOutcome,
    VerificationOutcome,
};
use serde::Serialize;

use crate::{
    FeedbackError, FeedbackStore, Result,
    beta::jeffreys_interval_micros,
    facts::read_facts,
    hash,
    learning::event_set_hash,
    store::{read_consent, scrub, snapshot_in, timestamp},
};

/// V1 remains byte-compatible; qualified rates require the explicit v2 contract.
#[derive(Clone, Copy)]
pub enum FeedbackPricing<'a> {
    Legacy(&'a PricingTable),
    Qualified(&'a router_eval::QualifiedPricingTable),
}
impl FeedbackPricing<'_> {
    fn citation(self) -> PricingCitation {
        match self {
            Self::Legacy(p) => PricingCitation {
                contract_version: None,
                version: p.version.clone(),
                source: p.source.clone(),
                observed_at_unix_seconds: p.observed_at_unix_seconds,
            },
            Self::Qualified(p) => PricingCitation {
                contract_version: Some(2),
                version: p.version.clone(),
                source: p.source.clone(),
                observed_at_unix_seconds: p.observed_at_unix_seconds,
            },
        }
    }
    fn valid(self) -> bool {
        match self {
            Self::Legacy(p) => valid_pricing(p),
            Self::Qualified(p) => p.validate().is_ok(),
        }
    }
    fn cost(self, model: &router_types::ModelId, usage: &HostUsage) -> (Option<u128>, bool) {
        match self {
            Self::Legacy(p) => {
                let cost = p.models.get(model).and_then(|price| run_cost(usage, price));
                (cost, cost.is_some())
            }
            Self::Qualified(p) => {
                let cost = router_eval::price_host_usage(p, model, usage).unwrap_or_default();
                (
                    cost.known_subtotal_microusd.map(u128::from),
                    cost.total_microusd.is_some(),
                )
            }
        }
    }
}

/// Percentile method: nearest rank on the sorted known values.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Percentiles {
    pub samples: u64,
    pub missing: u64,
    pub p50: Option<u64>,
    pub p90: Option<u64>,
}

fn percentiles(values: impl Iterator<Item = Option<u64>>) -> Percentiles {
    let mut known = Vec::new();
    let mut missing = 0;
    for value in values {
        match value {
            Some(v) => known.push(v),
            None => missing += 1,
        }
    }
    known.sort_unstable();
    let rank =
        |p: usize| (!known.is_empty()).then(|| known[(known.len() * p).div_ceil(100).max(1) - 1]);
    Percentiles {
        samples: known.len() as u64,
        missing,
        p50: rank(50),
        p90: rank(90),
    }
}

/// `numerator / denominator` in micros, rounded half up.
fn ratio_micros(numerator: u64, denominator: u64) -> Option<u64> {
    (denominator > 0).then(|| {
        ((u128::from(numerator) * 1_000_000 + u128::from(denominator) / 2)
            / u128::from(denominator)) as u64
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcceptedRate {
    pub accepted: u64,
    pub rejected: u64,
    pub point_micros: u64,
    pub lower_micros: u64,
    pub upper_micros: u64,
    pub level_micros: u32,
    pub prior: &'static str,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HumanCounts {
    pub passed: u64,
    pub failed: u64,
    pub unknown: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct IntegrationCounts {
    pub applied: u64,
    pub discarded: u64,
    /// Runs with no integration fact.
    pub unknown: u64,
    /// `applied / (applied + discarded)`; null without a decided run.
    pub rate_micros: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct GroupCost {
    /// Runs whose expected attempts all have unambiguous usage and a price.
    pub priced_runs: u64,
    /// Runs with missing, ambiguous or unpriced attempts.
    pub cost_unknown: u64,
    /// Priced runs with a declared cache write count above zero. Cache writes
    /// are priced at the input rate because the table has no write price.
    pub runs_with_cache_writes_priced_as_input: u64,
    /// Known charges even with incomplete coverage. Qualified pricing v2 also
    /// preserves priced token classes within an otherwise unpriced attempt.
    pub known_subtotal_microusd: Option<u64>,
    pub expected_attempts: u64,
    pub observed_attempts: u64,
    pub priced_attempts: u64,
    pub missing_attempts: u64,
    pub conflicting_attempts: u64,
    /// Legacy retry records whose usage has no explicit attempt scope.
    pub scope_unknown_runs: u64,
    /// Complete total only when every expected attempt is observed and priced.
    pub total_microusd: Option<u64>,
    /// Total over all runs divided by accepted tasks; null unless every run is priced.
    pub per_accepted_microusd: Option<u64>,
    pub reason: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GroupReport {
    pub model: String,
    pub effort: String,
    pub task_kind: String,
    pub runs: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub unknown: u64,
    /// Runs without a run key; they are counted in `unknown`.
    pub unlinked: u64,
    pub human: HumanCounts,
    pub accepted_rate: Option<AcceptedRate>,
    pub integration: IntegrationCounts,
    pub tokens: Percentiles,
    pub latency_ms: Percentiles,
    pub attempts: Percentiles,
    /// Accepted runs only: applied fact time minus run start, in seconds.
    pub time_to_acceptance_seconds: Percentiles,
    pub cost: GroupCost,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PricingCitation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_version: Option<u32>,
    pub version: String,
    pub source: String,
    pub observed_at_unix_seconds: u64,
}

/// No value of this type exists: the figure it types is always null.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Never {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NullFigure {
    pub value: Option<Never>,
    pub reason: &'static str,
}

/// Never a policy change. `suggestion` has no constructible value: report data
/// alone cannot express a sound weight delta (see docs/feedback.md).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Advisory {
    Disabled {
        advisory: Option<bool>,
        reason: &'static str,
    },
    Enabled {
        advisory: bool,
        suggestion: Option<Never>,
        reason: &'static str,
    },
}

/// Evidence retained in the feedback store, not a verified runtime receipt.
/// Hashes identify source records; this projection does not open the runtime
/// journal or authenticate native external captures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RunEvidence {
    pub source: &'static str,
    pub feedback_event_hash: String,
    pub verification_fact_hash: Option<String>,
    pub integration_fact_hash: Option<String>,
    pub runtime_evidence: VerificationOutcome,
    pub native_external_evidence: VerificationOutcome,
}

/// One retained automated run snapshot. Multiple runs may share a task hash;
/// Cost covers the observed attempts of this run, not separate escalated runs
/// or repeated tasks. Ordering follows event sequence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RunReport {
    pub binding: FeedbackBinding,
    pub run_key_sha256: Option<String>,
    pub observed_at_unix_seconds: u64,
    pub model: String,
    pub effort: String,
    pub task_kind: String,
    pub verdict: RunVerdict,
    /// Transport success is not objective success or acceptance.
    pub transport: VerificationOutcome,
    pub failure: Option<FeedbackFailure>,
    /// None means no usage was stored, never zero consumption.
    pub usage: Option<HostUsage>,
    pub cost: GroupCost,
    pub evidence: RunEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FeedbackReport {
    /// Optional reconciliation with an independently captured runtime inventory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_measurement: Option<crate::TaskMeasurementReport>,
    pub schema_version: u32,
    pub generated_at_unix_seconds: u64,
    pub event_set_hash: String,
    pub fact_set_hash: String,
    pub automated_events: u64,
    pub human_events: u64,
    pub facts: u64,
    /// Automated events without a run key: no late fact can refer to them.
    pub unlinked: u64,
    /// Facts whose run key matches no retained automated event.
    pub orphan_facts: u64,
    /// Automated events left out because a later event holds the same run key.
    /// `automated_events` and the groups count each run key once.
    pub superseded_events: u64,
    pub pricing: Option<PricingCitation>,
    pub groups: Vec<GroupReport>,
    /// At most MAX_EVENTS rows, using the same retained events as the groups.
    pub runs: Vec<RunReport>,
    pub catalog_estimate_ratio: NullFigure,
    pub advisory: Advisory,
    pub interpretation: &'static str,
    pub content_hash: String,
}

/// Counts of what the summary could not establish. Each is a count of runs or
/// records, never a value shown as zero for an unknown figure.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct UnknownCounts {
    /// Runs with neither an accepting nor a rejecting signal.
    pub verdict: u64,
    /// Runs without a run key: no late fact can refer to them.
    pub unlinked: u64,
    /// Runs without a computed cost (no table, no complete usage or model not priced).
    pub cost: u64,
    /// Accepted runs whose time to acceptance cannot be computed.
    pub time_to_acceptance: u64,
    /// Runs without an integration fact.
    pub integration: u64,
    /// Facts whose run key matches no retained automated event.
    pub orphan_facts: u64,
    /// Automated events left out because a later event holds the same run key.
    pub superseded_events: u64,
}

/// `feedback summary`: one global total over every group of the report, built
/// from the same run classification, so the totals equal the sum of the groups.
/// Percentiles and the rate are recomputed over the merged runs, never
/// averaged from group figures. Like the report it shows associations, not a
/// gain attributable to the router.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FeedbackSummary {
    /// Optional reconciliation with an independently captured runtime inventory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_measurement: Option<crate::TaskMeasurementReport>,
    pub schema_version: u32,
    pub generated_at_unix_seconds: u64,
    pub event_set_hash: String,
    pub fact_set_hash: String,
    /// `content_hash` of the report built from the same events and facts.
    pub report_content_hash: String,
    pub pricing: Option<PricingCitation>,
    pub runs: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub unknown: u64,
    pub human: HumanCounts,
    pub accepted_rate: Option<AcceptedRate>,
    pub cost: GroupCost,
    pub time_to_acceptance_seconds: Percentiles,
    pub unknown_counts: UnknownCounts,
    pub attribution: &'static str,
    pub attribution_note: &'static str,
    pub content_hash: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunVerdict {
    Accepted,
    Rejected,
    Unknown,
}

#[derive(Default)]
struct RunFacts<'a> {
    verification: Option<&'a FeedbackFact>,
    integration: Option<&'a FeedbackFact>,
    verification_hash: Option<&'a str>,
    integration_hash: Option<&'a str>,
}

impl RunFacts<'_> {
    fn integration_outcome(&self) -> Option<IntegrationOutcome> {
        match self.integration.map(|f| &f.kind) {
            Some(FeedbackFactKind::Integration { outcome }) => Some(*outcome),
            _ => None,
        }
    }
    fn objective(&self) -> Option<VerificationOutcome> {
        match self.verification.map(|f| &f.kind) {
            Some(FeedbackFactKind::Verification { objective, .. }) => Some(*objective),
            _ => None,
        }
    }
    /// A rejection signal wins over acceptance. Anything else is unknown,
    /// never a failure.
    fn verdict(&self) -> RunVerdict {
        let integration = self.integration_outcome();
        let objective = self.objective();
        if integration == Some(IntegrationOutcome::Discarded)
            || objective == Some(VerificationOutcome::Failed)
        {
            RunVerdict::Rejected
        } else if integration == Some(IntegrationOutcome::Applied)
            && objective == Some(VerificationOutcome::Passed)
        {
            RunVerdict::Accepted
        } else {
            RunVerdict::Unknown
        }
    }
}

fn label<T: Serialize>(value: &T) -> Result<String> {
    match serde_json::to_value(value)? {
        serde_json::Value::String(text) => Ok(text),
        _ => Err(FeedbackError::Integrity("label")),
    }
}

fn valid_pricing(pricing: &PricingTable) -> bool {
    let text = |v: &str| !v.trim().is_empty() && v.len() <= 512 && !v.chars().any(char::is_control);
    pricing.schema_version == 1
        && text(&pricing.version)
        && text(&pricing.source)
        && pricing.models.len() <= 64
}

/// Same formula as `router_eval::price_usage`: uncached input, cached input and
/// output, rounded up to a micro-dollar per attempt. Reasoning tokens are part of
/// output and cache writes part of input, so neither is priced twice; the table
/// has no cache write price, so writes are priced as input. A field the host
/// did not declare makes the run unknown, never zero.
fn run_cost(usage: &HostUsage, price: &TokenPrice) -> Option<u128> {
    let input = usage.input_tokens.reported()?;
    let cached = usage.cached_input_tokens.reported()?;
    let output = usage.output_tokens.reported()?;
    if cached > input {
        return None;
    }
    let numerator = u128::from(input - cached) * u128::from(price.input_microusd_per_million)
        + u128::from(cached) * u128::from(price.cached_input_microusd_per_million)
        + u128::from(output) * u128::from(price.output_microusd_per_million);
    Some(numerator.div_ceil(1_000_000))
}

/// One entry per observed ordinal, never allocated from the declared maximum.
/// The store bounds the event count; missing ordinals are counted by subtraction.
#[derive(Default)]
pub(crate) struct RunAttempts<'a> {
    expected: u32,
    marked: BTreeMap<u32, AttemptSnapshot<'a>>,
    legacy_first: Option<AttemptSnapshot<'a>>,
    unscoped_retry: bool,
    latest: Option<&'a FeedbackEvent>,
}

#[derive(Clone, Copy)]
struct AttemptSnapshot<'a> {
    event: &'a FeedbackEvent,
    conflict: bool,
}

impl<'a> AttemptSnapshot<'a> {
    fn observe(&mut self, event: &'a FeedbackEvent) {
        let prior = &self.event.input;
        let input = &event.input;
        self.conflict |= prior.measurements.usage != input.measurements.usage
            || prior.context.model != input.context.model;
        self.event = event;
    }
}

impl<'a> RunAttempts<'a> {
    pub(crate) fn observe(&mut self, event: &'a FeedbackEvent) {
        let input = &event.input;
        let ordinal = input.measurements.attempts;
        self.expected = self.expected.max(ordinal);
        self.latest = Some(event);
        if input.measurements.usage_scope != Some(FeedbackUsageScope::PerAttempt) {
            if ordinal == 1 {
                match &mut self.legacy_first {
                    Some(snapshot) => snapshot.observe(event),
                    None => {
                        self.legacy_first = Some(AttemptSnapshot {
                            event,
                            conflict: false,
                        })
                    }
                }
            } else {
                self.unscoped_retry = true;
            }
            return;
        }
        self.marked
            .entry(ordinal)
            .and_modify(|snapshot| snapshot.observe(event))
            .or_insert(AttemptSnapshot {
                event,
                conflict: false,
            });
    }

    pub(crate) fn measurement_cost(&self, pricing: Option<FeedbackPricing<'_>>) -> GroupCost {
        group_cost(pricing, &self.cost(pricing))
    }

    fn cost(&self, pricing: Option<FeedbackPricing<'_>>) -> Accumulator<'a> {
        let mut result = Accumulator {
            expected_attempts: u64::from(self.expected),
            ..Accumulator::default()
        };
        // A legacy ordinal one is unambiguous, including during upgrades.
        // Pure legacy single-attempt runs keep latest-snapshot compatibility.
        // Any unscoped retry prevents a complete total, even with marked data.
        let mut first = self.marked.get(&1).copied();
        if let Some(legacy) = self.legacy_first {
            if let Some(marked) = &mut first {
                marked.observe(legacy.event);
                marked.conflict |= legacy.conflict;
            } else {
                first = Some(legacy);
            }
        }
        if self.marked.is_empty() && self.expected == 1 {
            first = self.latest.map(|event| AttemptSnapshot {
                event,
                conflict: false,
            });
        }
        result.scope_unknown_runs = u64::from(self.unscoped_retry);
        let mut cache_write = false;
        for snapshot in self
            .marked
            .range(2..)
            .map(|(_, snapshot)| snapshot)
            .chain(first.iter())
        {
            result.observed_attempts += 1;
            if snapshot.conflict {
                result.conflicting_attempts += 1;
                continue;
            }
            let input = &snapshot.event.input;
            let cost = pricing
                .zip(input.measurements.usage.as_ref())
                .map(|(pricing, usage)| pricing.cost(&input.context.model, usage))
                .unwrap_or_default();
            if let Some(subtotal) = cost.0 {
                result.known_cost = true;
                result.cost_total += subtotal;
            }
            if cost.1 {
                result.priced_attempts += 1;
                cache_write |= matches!(pricing, Some(FeedbackPricing::Legacy(_)))
                    && input
                        .measurements
                        .usage
                        .as_ref()
                        .and_then(|u| u.cache_write_input_tokens.reported())
                        .is_some_and(|writes| writes > 0);
            }
        }
        result.cache_write_runs = u64::from(cache_write);
        result.missing_attempts = result.expected_attempts - result.observed_attempts;
        let complete = result.expected_attempts > 0
            && result.priced_attempts == result.expected_attempts
            && result.scope_unknown_runs == 0;
        result.priced = u64::from(complete);
        result.cost_unknown = u64::from(!complete);
        result
    }
}

#[derive(Default)]
struct Accumulator<'a> {
    events: Vec<&'a FeedbackEvent>,
    accepted: u64,
    rejected: u64,
    unknown: u64,
    unlinked: u64,
    human: HumanCounts,
    integration: IntegrationCounts,
    acceptance_seconds: Vec<Option<u64>>,
    priced: u64,
    cost_unknown: u64,
    cache_write_runs: u64,
    cost_total: u128,
    known_cost: bool,
    expected_attempts: u64,
    observed_attempts: u64,
    priced_attempts: u64,
    missing_attempts: u64,
    conflicting_attempts: u64,
    scope_unknown_runs: u64,
}

impl<'a> Accumulator<'a> {
    /// Adds another group's runs: counters are summed and the raw values are
    /// concatenated, so percentiles and rates come from the merged runs.
    fn absorb(&mut self, other: &Accumulator<'a>) {
        self.events.extend(other.events.iter().copied());
        self.accepted += other.accepted;
        self.rejected += other.rejected;
        self.unknown += other.unknown;
        self.unlinked += other.unlinked;
        self.human.passed += other.human.passed;
        self.human.failed += other.human.failed;
        self.human.unknown += other.human.unknown;
        self.integration.applied += other.integration.applied;
        self.integration.discarded += other.integration.discarded;
        self.integration.unknown += other.integration.unknown;
        self.acceptance_seconds
            .extend(other.acceptance_seconds.iter().copied());
        self.absorb_cost(other);
    }

    fn absorb_cost(&mut self, other: &Accumulator<'_>) {
        self.expected_attempts += other.expected_attempts;
        self.observed_attempts += other.observed_attempts;
        self.priced_attempts += other.priced_attempts;
        self.missing_attempts += other.missing_attempts;
        self.conflicting_attempts += other.conflicting_attempts;
        self.scope_unknown_runs += other.scope_unknown_runs;
        self.priced += other.priced;
        self.cost_unknown += other.cost_unknown;
        self.cache_write_runs += other.cache_write_runs;
        self.cost_total += other.cost_total;
        self.known_cost |= other.known_cost;
    }
}

fn accepted_rate(a: &Accumulator<'_>) -> Option<AcceptedRate> {
    let decided = a.accepted + a.rejected;
    let (lower, upper) = jeffreys_interval_micros(a.accepted, a.rejected);
    (decided > 0).then(|| AcceptedRate {
        accepted: a.accepted,
        rejected: a.rejected,
        point_micros: ratio_micros(a.accepted, decided).unwrap_or(0),
        lower_micros: lower,
        upper_micros: upper,
        level_micros: 950_000,
        prior: "jeffreys",
    })
}

/// The report and the summary, from one pass over the same classified runs.
fn build_report(
    events: &[FeedbackEvent],
    fact_events: &[FeedbackFactEvent],
    pricing: Option<FeedbackPricing<'_>>,
    learning_enabled: bool,
    now: u64,
) -> Result<(FeedbackReport, FeedbackSummary)> {
    if pricing.is_some_and(|p| !p.valid()) {
        return Err(FeedbackError::Invalid("pricing"));
    }
    let mut by_key: BTreeMap<&str, RunFacts<'_>> = BTreeMap::new();
    for event in fact_events {
        let entry = by_key.entry(&event.fact.run_key_sha256).or_default();
        match event.fact.kind {
            FeedbackFactKind::Verification { .. } => {
                entry.verification = Some(&event.fact);
                entry.verification_hash = Some(&event.fact_hash);
            }
            FeedbackFactKind::Integration { .. } => {
                entry.integration = Some(&event.fact);
                entry.integration_hash = Some(&event.fact_hash);
            }
        }
    }
    let mut groups: BTreeMap<(String, String, String), Accumulator<'_>> = BTreeMap::new();
    let mut automated_keys = BTreeSet::new();
    let (mut automated, mut human, mut unlinked) = (0u64, 0u64, 0u64);
    let none = RunFacts::default();
    // `run_hash` covers state and attempts, so one run can hold several
    // automated events. Late facts belong to the run, not to an event: count
    // each run key once, on its latest event.
    let mut latest: BTreeMap<&str, u64> = BTreeMap::new();
    let mut attempts: BTreeMap<&str, RunAttempts<'_>> = BTreeMap::new();
    for event in events {
        if let (FeedbackOrigin::Automated, Some(run_key)) =
            (event.input.origin, event.input.run_key_sha256.as_deref())
        {
            let entry = latest.entry(run_key).or_default();
            *entry = (*entry).max(event.sequence);
            attempts.entry(run_key).or_default().observe(event);
        }
    }
    let mut superseded = 0u64;
    let mut runs = Vec::new();
    for event in events {
        let i = &event.input;
        if i.origin == FeedbackOrigin::Automated
            && i.run_key_sha256
                .as_deref()
                .is_some_and(|run_key| latest.get(run_key) != Some(&event.sequence))
        {
            superseded += 1;
            continue;
        }
        let key = (
            i.context.model.to_string(),
            label(&i.context.effort)?,
            label(&i.context.task_kind)?,
        );
        let group = groups.entry(key).or_default();
        match i.origin {
            FeedbackOrigin::Human => {
                human += 1;
                match i.human.as_ref().map(|h| h.success) {
                    Some(VerificationOutcome::Passed) => group.human.passed += 1,
                    Some(VerificationOutcome::Failed) => group.human.failed += 1,
                    _ => group.human.unknown += 1,
                }
            }
            FeedbackOrigin::Automated => {
                automated += 1;
                group.events.push(event);
                let facts = match i.run_key_sha256.as_deref() {
                    Some(run_key) => {
                        automated_keys.insert(run_key);
                        by_key.get(run_key).unwrap_or(&none)
                    }
                    None => {
                        unlinked += 1;
                        group.unlinked += 1;
                        &none
                    }
                };
                let mut standalone = RunAttempts::default();
                let history = i
                    .run_key_sha256
                    .as_deref()
                    .and_then(|key| attempts.get(key))
                    .unwrap_or_else(|| {
                        standalone.observe(event);
                        &standalone
                    });
                let mut attempt_cost = history.cost(pricing);
                attempt_cost.accepted = u64::from(facts.verdict() == RunVerdict::Accepted);
                group.absorb_cost(&attempt_cost);
                runs.push(RunReport {
                    binding: i.binding.clone(),
                    run_key_sha256: i.run_key_sha256.clone(),
                    observed_at_unix_seconds: i.observed_at_unix_seconds,
                    model: i.context.model.to_string(),
                    effort: label(&i.context.effort)?,
                    task_kind: label(&i.context.task_kind)?,
                    verdict: facts.verdict(),
                    transport: i.transport,
                    failure: i.failure,
                    usage: i.measurements.usage,
                    cost: group_cost(pricing, &attempt_cost),
                    evidence: RunEvidence {
                        source: "feedback_store",
                        feedback_event_hash: event.event_hash.clone(),
                        verification_fact_hash: facts.verification_hash.map(str::to_owned),
                        integration_fact_hash: facts.integration_hash.map(str::to_owned),
                        runtime_evidence: VerificationOutcome::Unknown,
                        native_external_evidence: VerificationOutcome::Unknown,
                    },
                });
                match facts.verdict() {
                    RunVerdict::Accepted => {
                        group.accepted += 1;
                        let applied = facts.integration.map(|f| f.observed_at_unix_seconds);
                        group.acceptance_seconds.push(
                            i.started_at_unix_seconds
                                .zip(applied)
                                .and_then(|(start, end)| end.checked_sub(start)),
                        );
                    }
                    RunVerdict::Rejected => group.rejected += 1,
                    RunVerdict::Unknown => group.unknown += 1,
                }
                match facts.integration_outcome() {
                    Some(IntegrationOutcome::Applied) => group.integration.applied += 1,
                    Some(IntegrationOutcome::Discarded) => group.integration.discarded += 1,
                    None => group.integration.unknown += 1,
                }
            }
        }
    }
    let orphan_facts = fact_events
        .iter()
        .filter(|f| !automated_keys.contains(f.fact.run_key_sha256.as_str()))
        .count() as u64;
    let mut total = Accumulator::default();
    for group in groups.values() {
        total.absorb(group);
    }
    let event_set = event_set_hash(events)?;
    let fact_set = hash(
        "feedback-fact-set-v1",
        &fact_events.iter().map(|f| &f.fact_hash).collect::<Vec<_>>(),
    )?;
    let mut summary = FeedbackSummary {
        task_measurement: None,
        schema_version: 2,
        generated_at_unix_seconds: now,
        event_set_hash: event_set.clone(),
        fact_set_hash: fact_set.clone(),
        report_content_hash: String::new(),
        pricing: pricing.map(FeedbackPricing::citation),
        runs: total.events.len() as u64,
        accepted: total.accepted,
        rejected: total.rejected,
        unknown: total.unknown,
        human: total.human.clone(),
        accepted_rate: accepted_rate(&total),
        cost: group_cost(pricing, &total),
        time_to_acceptance_seconds: percentiles(total.acceptance_seconds.iter().copied()),
        unknown_counts: UnknownCounts {
            verdict: total.unknown,
            unlinked: total.unlinked,
            cost: total.cost_unknown,
            time_to_acceptance: total
                .acceptance_seconds
                .iter()
                .filter(|s| s.is_none())
                .count() as u64,
            integration: total.integration.unknown,
            orphan_facts,
            superseded_events: superseded,
        },
        attribution: "not_established",
        attribution_note: "descriptive associations only; a gain attributable to the router needs the paired A/B protocol",
        content_hash: String::new(),
    };
    let groups = groups
        .into_iter()
        .map(|((model, effort, task_kind), a)| {
            let mut integration = a.integration.clone();
            integration.rate_micros = ratio_micros(
                integration.applied,
                integration.applied + integration.discarded,
            );
            let cost = group_cost(pricing, &a);
            let rate = accepted_rate(&a);
            GroupReport {
                model,
                effort,
                task_kind,
                runs: a.events.len() as u64,
                accepted: a.accepted,
                rejected: a.rejected,
                unknown: a.unknown,
                unlinked: a.unlinked,
                human: a.human,
                accepted_rate: rate,
                integration,
                tokens: percentiles(a.events.iter().map(|e| e.input.measurements.tokens)),
                latency_ms: percentiles(a.events.iter().map(|e| e.input.measurements.latency_ms)),
                attempts: percentiles(
                    a.events
                        .iter()
                        .map(|e| Some(u64::from(e.input.measurements.attempts))),
                ),
                time_to_acceptance_seconds: percentiles(a.acceptance_seconds.into_iter()),
                cost,
            }
        })
        .collect();
    let mut report = FeedbackReport {
        task_measurement: None,
        schema_version: 3,
        generated_at_unix_seconds: now,
        event_set_hash: event_set,
        fact_set_hash: fact_set,
        automated_events: automated,
        human_events: human,
        facts: fact_events.len() as u64,
        unlinked,
        orphan_facts,
        superseded_events: superseded,
        pricing: pricing.map(FeedbackPricing::citation),
        groups,
        runs,
        catalog_estimate_ratio: NullFigure {
            value: None,
            reason: "no_catalog_estimate_stored_in_feedback",
        },
        advisory: if learning_enabled {
            Advisory::Enabled {
                advisory: true,
                suggestion: None,
                reason: "no_sound_weight_suggestion_from_report_data",
            }
        } else {
            Advisory::Disabled {
                advisory: None,
                reason: "learning_disabled",
            }
        },
        interpretation: "descriptive_associations_not_causal_or_router_gain",
        content_hash: String::new(),
    };
    report.content_hash = hash("feedback-report-v3", &report)?;
    summary.report_content_hash = report.content_hash.clone();
    summary.content_hash = hash("feedback-summary-v2", &summary)?;
    Ok((report, summary))
}

fn group_cost(pricing: Option<FeedbackPricing<'_>>, a: &Accumulator<'_>) -> GroupCost {
    let mut cost = GroupCost {
        expected_attempts: a.expected_attempts,
        observed_attempts: a.observed_attempts,
        priced_attempts: a.priced_attempts,
        missing_attempts: a.missing_attempts,
        conflicting_attempts: a.conflicting_attempts,
        scope_unknown_runs: a.scope_unknown_runs,
        priced_runs: a.priced,
        cost_unknown: a.cost_unknown,
        runs_with_cache_writes_priced_as_input: a.cache_write_runs,
        ..GroupCost::default()
    };
    if pricing.is_none() {
        cost.reason = Some("no_pricing_table");
        return cost;
    }
    if !a.known_cost {
        cost.reason = Some("no_priced_runs");
        return cost;
    }
    let Ok(total) = u64::try_from(a.cost_total) else {
        cost.reason = Some("cost_overflow");
        return cost;
    };
    cost.known_subtotal_microusd = Some(total);
    if a.cost_unknown > 0 {
        cost.reason = Some("cost_unknown_runs");
        return cost;
    }
    cost.total_microusd = Some(total);
    if a.accepted == 0 {
        cost.reason = Some("no_accepted_task");
    } else {
        // Round half up, like the other ratios.
        cost.per_accepted_microusd = Some(
            ((u128::from(total) + u128::from(a.accepted) / 2) / u128::from(a.accepted)) as u64,
        );
    }
    cost
}

impl FeedbackStore {
    /// Needs collection consent; a table is optional. Reads like the other
    /// readers: it may expire retained rows and advance the clock watermark,
    /// and writes nothing else. The advisory part needs learning consent.
    pub fn report(&self, pricing: Option<&PricingTable>, now: u64) -> Result<FeedbackReport> {
        self.report_and_summary(pricing, now)
            .map(|(report, _)| report)
    }

    /// The global total of `report`, from the same read and the same
    /// classification. Same consent and read effects as `report`.
    pub fn summary(&self, pricing: Option<&PricingTable>, now: u64) -> Result<FeedbackSummary> {
        self.report_and_summary(pricing, now)
            .map(|(_, summary)| summary)
    }

    /// Adds task occurrence accounting without rewriting stored events or changing
    /// the legacy report when no inventory was requested.
    pub fn report_and_summary_with_inventory(
        &self,
        pricing: Option<&PricingTable>,
        inventory: Option<&router_types::FeedbackRuntimeInventory>,
        now: u64,
    ) -> Result<(FeedbackReport, FeedbackSummary)> {
        self.report_and_summary_with_pricing(pricing.map(FeedbackPricing::Legacy), inventory, now)
    }

    pub fn report_and_summary_with_pricing(
        &self,
        pricing: Option<FeedbackPricing<'_>>,
        inventory: Option<&router_types::FeedbackRuntimeInventory>,
        now: u64,
    ) -> Result<(FeedbackReport, FeedbackSummary)> {
        let (mut report, mut summary, events) = self.report_snapshot(pricing, now)?;
        if let Some(inventory) = inventory {
            let measurement = crate::task_report::measure(&report, inventory, &events, pricing)?;
            report.schema_version = 4;
            summary.schema_version = 3;
            report.task_measurement = Some(measurement.clone());
            summary.task_measurement = Some(measurement);
            report.content_hash.clear();
            report.content_hash = hash("feedback-report-v4", &report)?;
            summary.report_content_hash = report.content_hash.clone();
            summary.content_hash.clear();
            summary.content_hash = hash("feedback-summary-v3", &summary)?;
        }
        if matches!(pricing, Some(FeedbackPricing::Qualified(_))) {
            report.schema_version = 5;
            summary.schema_version = 4;
            report.content_hash.clear();
            report.content_hash = hash("feedback-report-v5", &report)?;
            summary.report_content_hash = report.content_hash.clone();
            summary.content_hash.clear();
            summary.content_hash = hash("feedback-summary-v4", &summary)?;
        }
        Ok((report, summary))
    }

    /// Both views from one snapshot, so a test can compare them exactly.
    pub fn report_and_summary(
        &self,
        pricing: Option<&PricingTable>,
        now: u64,
    ) -> Result<(FeedbackReport, FeedbackSummary)> {
        self.report_snapshot(pricing.map(FeedbackPricing::Legacy), now)
            .map(|(report, summary, _)| (report, summary))
    }

    fn report_snapshot(
        &self,
        pricing: Option<FeedbackPricing<'_>>,
        now: u64,
    ) -> Result<(FeedbackReport, FeedbackSummary, Vec<FeedbackEvent>)> {
        timestamp(now)?;
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        if !read_consent(&tx)?.preferences.collection_enabled {
            return Err(FeedbackError::Consent);
        }
        let (events, consent, removed) = snapshot_in(&tx, now, false)?;
        let facts = read_facts(&tx)?;
        tx.commit()?;
        if removed > 0 {
            scrub(&db)?;
        }
        let (report, summary) = build_report(
            &events,
            &facts,
            pricing,
            consent.preferences.learning_enabled,
            now,
        )?;
        Ok((report, summary, events))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_use_the_nearest_rank_and_count_missing_values() {
        let ten = (1..=10).map(|v| Some(v * 10));
        let p = percentiles(ten.chain([None, None]));
        assert_eq!(
            p,
            Percentiles {
                samples: 10,
                missing: 2,
                p50: Some(50),
                p90: Some(90)
            }
        );
        let one = percentiles([Some(7)].into_iter());
        assert_eq!((one.p50, one.p90), (Some(7), Some(7)));
        // Order of arrival does not matter.
        let shuffled = percentiles([Some(30), Some(10), Some(20)].into_iter());
        assert_eq!((shuffled.p50, shuffled.p90), (Some(20), Some(30)));
        assert_eq!(percentiles([None].into_iter()).p50, None);
    }

    #[test]
    fn ratios_round_half_up_in_micros() {
        assert_eq!(ratio_micros(1, 3), Some(333_333));
        assert_eq!(ratio_micros(2, 3), Some(666_667));
        assert_eq!(ratio_micros(1, 0), None);
    }
}
