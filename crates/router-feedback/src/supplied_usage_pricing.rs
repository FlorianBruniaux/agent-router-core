//! Offline pricing of explicitly supplied per-physical usage. No producer is authenticated.
use crate::{
    AcceptedChangesInput, AcceptedChangesReport, AcceptedCostKind, EvidenceCoverage, FeedbackError,
    PhysicalObservationKey, Result, calculate_accepted_changes, hash, valid_usage,
};
use router_eval::{QualifiedPricingTable, QualifiedUsageCost, price_host_usage};
use router_types::{HostUsage, ModelId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_SUPPLIED_USAGE_PRICING_BYTES: usize = 4 * 1024 * 1024;
const MAX_ROWS: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SuppliedUsageScope {
    PerPhysicalCall,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SuppliedPhysicalUsage {
    pub key: PhysicalObservationKey,
    pub evidence_sha256: String,
    pub model: ModelId,
    pub usage: HostUsage,
    pub scope: SuppliedUsageScope,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuppliedUsagePricingInput {
    pub schema_version: u32,
    pub accounting: AcceptedChangesInput,
    pub pricing: QualifiedPricingTable,
    pub physical_usage: Vec<SuppliedPhysicalUsage>,
}

/// Allowlisted row: no supplied model names, IDs, provenance text or references.
#[derive(Debug, Serialize)]
pub struct PortablePhysicalUsagePrice {
    pub key: PhysicalObservationKey,
    pub evidence_sha256: String,
    pub usage_sha256: String,
    pub model_sha256: String,
    pub scope: SuppliedUsageScope,
    pub supplied_usage_coverage: EvidenceCoverage,
    pub supplied_pricing_coverage: EvidenceCoverage,
    pub cost: QualifiedUsageCost,
}

/// Only this projection is intended for portable export. Hashes are content
/// bindings, not authentication or proof that observations are additive.
#[derive(Debug, Serialize)]
pub struct PortableUsagePricingReport {
    pub schema_version: u32,
    pub input_sha256: String,
    pub accounting_input_sha256: String,
    pub priced_accounting_report_sha256: String,
    pub pricing_sha256: String,
    pub evidence_trust: &'static str,
    pub cost_basis: &'static str,
    pub physical_usage: Vec<PortablePhysicalUsagePrice>,
    pub duplicate_usage_count: usize,
    pub unverified: &'static [&'static str],
}

/// Local report: `accounting` retains the existing B1 contract and its supplied
/// text. Export `portable_pricing` alone when a portable allowlist is required.
#[derive(Debug, Serialize)]
pub struct SuppliedUsagePricingReport {
    pub schema_version: u32,
    pub input_sha256: String,
    pub evidence_trust: &'static str,
    pub accounting: AcceptedChangesReport,
    pub portable_pricing: PortableUsagePricingReport,
}

const UNVERIFIED: &[&str] = &[
    "producer_authenticity_not_verified",
    "model_and_physical_identity_not_verified",
    "supplied_coverage_and_inventory_not_upgraded",
    "cross_authority_overlap_not_reconciled",
    "same_external_request_id_not_a_deduplication_key",
    "estimated_cost_not_invoice",
    "partial_subtotals_not_accounting_totals",
];

fn invalid(reason: &'static str) -> FeedbackError {
    FeedbackError::Invalid(reason)
}

/// Reject duplicate JSON keys, unknown fields and oversized input. Errors never
/// echo supplied text, including serde's unknown-field or enum diagnostics.
pub fn supplied_usage_pricing_report(bytes: &[u8]) -> Result<SuppliedUsagePricingReport> {
    if bytes.len() > MAX_SUPPLIED_USAGE_PRICING_BYTES {
        return Err(FeedbackError::Limit);
    }
    let value = router_adapter_api::strict_json_limited(bytes, MAX_SUPPLIED_USAGE_PRICING_BYTES)
        .map_err(|_| invalid("supplied pricing JSON"))?;
    let input = serde_json::from_value(value).map_err(|_| invalid("supplied pricing schema"))?;
    calculate_supplied_usage_pricing(&input)
}

/// Reuse B1 validation before and after transformation. Only complete price
/// results fill previously unknown costs. No coverage or inventory is inferred.
pub fn calculate_supplied_usage_pricing(
    input: &SuppliedUsagePricingInput,
) -> Result<SuppliedUsagePricingReport> {
    if input.schema_version != 1 {
        return Err(invalid("supplied pricing version"));
    }
    if input.physical_usage.len() > MAX_ROWS
        || serde_json::to_vec(input)
            .map_err(|_| invalid("supplied pricing serialization"))?
            .len()
            > MAX_SUPPLIED_USAGE_PRICING_BYTES
    {
        return Err(FeedbackError::Limit);
    }
    // Validate the original duplicate observations, bindings and seals before
    // changing costs, so a transformation cannot erase an existing conflict.
    let original = calculate_accepted_changes(&input.accounting)
        .map_err(|_| invalid("supplied pricing accounting"))?;
    input
        .pricing
        .validate()
        .map_err(|_| invalid("supplied pricing table"))?;
    let valid_model = |model: &ModelId| {
        let name = model.as_str();
        !name.trim().is_empty() && name.len() <= 256 && !name.chars().any(char::is_control)
    };
    if input.pricing.models.keys().any(|m| !valid_model(m)) {
        return Err(invalid("supplied pricing model"));
    }
    let observations: BTreeMap<_, _> = original
        .observations
        .iter()
        .map(|observation| (&observation.key, observation))
        .collect();
    let mut unique = BTreeMap::new();
    for row in &input.physical_usage {
        if !valid_model(&row.model)
            || !valid_usage(&row.usage)
            || row
                .usage
                .input_tokens
                .reported()
                .zip(row.usage.output_tokens.reported())
                .is_some_and(|(input, output)| {
                    input
                        .checked_add(output)
                        .is_none_or(|total| total > HostUsage::MAX_TOKENS)
                })
        {
            return Err(invalid("supplied pricing usage"));
        }
        let observation = observations
            .get(&row.key)
            .ok_or_else(|| invalid("supplied pricing observation missing"))?;
        if observation.kind != AcceptedCostKind::Model
            || observation.evidence_sha256 != row.evidence_sha256
        {
            return Err(invalid("supplied pricing observation binding"));
        }
        if observation.cost_microusd.is_some() {
            return Err(invalid("supplied pricing cost already present"));
        }
        if let Some(previous) = unique.insert(&row.key, row) {
            if previous != row {
                return Err(invalid("supplied pricing duplicate conflict"));
            }
        }
    }
    let mut costs = BTreeMap::new();
    let mut portable_rows = Vec::with_capacity(unique.len());
    for (key, row) in &unique {
        let cost = price_host_usage(&input.pricing, &row.model, &row.usage)
            .map_err(|_| invalid("supplied pricing cost overflow or invalid table"))?;
        let observation = observations
            .get(key)
            .ok_or_else(|| invalid("supplied pricing observation missing"))?;
        costs.insert(*key, cost.total_microusd);
        portable_rows.push(PortablePhysicalUsagePrice {
            key: row.key.clone(),
            evidence_sha256: row.evidence_sha256.clone(),
            usage_sha256: hash("supplied-usage-pricing/usage/v1", row)?,
            model_sha256: hash("supplied-usage-pricing/model/v1", &row.model)?,
            scope: row.scope,
            supplied_usage_coverage: observation.usage_coverage,
            supplied_pricing_coverage: observation.pricing_coverage,
            cost,
        });
    }
    let mut priced = input.accounting.clone();
    for observation in &mut priced.observations {
        if let Some(cost) = costs.get(&observation.key) {
            observation.cost_microusd = *cost;
        }
    }
    let accounting = calculate_accepted_changes(&priced)
        .map_err(|_| invalid("supplied pricing priced accounting"))?;
    let input_sha256 = hash("supplied-usage-pricing/input/v1", input)?;
    let portable_pricing = PortableUsagePricingReport {
        schema_version: 1,
        input_sha256: input_sha256.clone(),
        accounting_input_sha256: original.input_sha256,
        priced_accounting_report_sha256: accounting.report_sha256.clone(),
        pricing_sha256: hash("supplied-usage-pricing/pricing/v1", &input.pricing)?,
        evidence_trust: "supplied_unverified",
        cost_basis: "estimated_not_invoice",
        physical_usage: portable_rows,
        duplicate_usage_count: input.physical_usage.len() - unique.len(),
        unverified: UNVERIFIED,
    };
    Ok(SuppliedUsagePricingReport {
        schema_version: 1,
        input_sha256,
        evidence_trust: "supplied_unverified",
        accounting,
        portable_pricing,
    })
}
