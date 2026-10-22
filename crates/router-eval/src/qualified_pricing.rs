//! Explicit rate semantics for normalized HostUsage. V1 replay pricing stays
//! unchanged: this v2 contract is only consumed where all token classes survive.
use crate::{EvalError, Result};
use router_types::{HostUsage, ModelId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedPricingTable {
    pub schema_version: u32,
    pub version: String,
    pub source: String,
    pub observed_at_unix_seconds: u64,
    pub models: BTreeMap<ModelId, QualifiedTokenPrice>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedTokenPrice {
    pub input_microusd_per_million: Option<u64>,
    pub cache_read_microusd_per_million: Option<u64>,
    pub cache_write_microusd_per_million: Option<u64>,
    /// A uniform rate for every reported write. A TTL-specific quote cannot be
    /// applied to HostUsage, which carries no TTL classification.
    pub cache_write_scope: Option<CacheWritePriceScope>,
    pub output_microusd_per_million: Option<u64>,
    pub reasoning: Option<ReasoningPrice>,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheWritePriceScope {
    AllReportedWrites,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReasoningPrice {
    IncludedInOutput,
    Separate { microusd_per_million: Option<u64> },
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct QualifiedUsageCost {
    pub known_subtotal_microusd: Option<u64>,
    pub total_microusd: Option<u64>,
}
impl QualifiedPricingTable {
    pub fn validate(&self) -> Result<()> {
        let text = |value: &str| {
            !value.trim().is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
        };
        if self.schema_version != 2
            || !text(&self.version)
            || !text(&self.source)
            || self.models.len() > 64
        {
            return Err(EvalError::Invalid("qualified pricing provenance"));
        }
        Ok(())
    }
}
/// Ceiling after summing disjoint known classes, once per attempt. A subtotal
/// is never promoted to a total if even one class lacks counts, scope or price.
pub fn price_host_usage(
    table: &QualifiedPricingTable,
    model: &ModelId,
    usage: &HostUsage,
) -> Result<QualifiedUsageCost> {
    table.validate()?;
    let Some(price) = table.models.get(model) else {
        return Ok(QualifiedUsageCost::default());
    };
    let bounded = |field: router_types::UsageField| {
        field
            .reported()
            .filter(|count| *count <= HostUsage::MAX_TOKENS)
    };
    let input = bounded(usage.input_tokens);
    let read = bounded(usage.cached_input_tokens);
    let write = bounded(usage.cache_write_input_tokens);
    let output = bounded(usage.output_tokens);
    let reasoning = bounded(usage.reasoning_output_tokens);
    let input_valid = input
        .zip(read.zip(write))
        .is_none_or(|(input, (read, write))| {
            read.checked_add(write)
                .is_some_and(|cached| cached <= input)
        });
    let mut numerator = 0u128;
    let mut known = false;
    let mut complete = true;
    let mut charge = |count: Option<u64>, rate: Option<u64>| -> Result<()> {
        if let Some((count, rate)) = count.zip(rate) {
            numerator = numerator
                .checked_add(u128::from(count) * u128::from(rate))
                .ok_or(EvalError::CostOverflow)?;
            known = true;
        } else {
            complete = false;
        }
        Ok(())
    };
    if input_valid {
        let ordinary = input
            .zip(read.zip(write))
            .and_then(|(input, (read, write))| input.checked_sub(read)?.checked_sub(write));
        charge(ordinary, price.input_microusd_per_million)?;
        charge(read, price.cache_read_microusd_per_million)?;
        charge(
            write,
            price
                .cache_write_scope
                .and(price.cache_write_microusd_per_million),
        )?;
    } else {
        charge(None, None)?;
    }
    match price.reasoning {
        Some(ReasoningPrice::IncludedInOutput) => {
            charge(output, price.output_microusd_per_million)?
        }
        Some(ReasoningPrice::Separate {
            microusd_per_million,
        }) => {
            if output
                .zip(reasoning)
                .is_none_or(|(total, reasoning)| reasoning <= total)
            {
                charge(
                    output
                        .zip(reasoning)
                        .map(|(total, reasoning)| total - reasoning),
                    price.output_microusd_per_million,
                )?;
                charge(reasoning, microusd_per_million)?;
            } else {
                charge(None, None)?;
            }
        }
        None => charge(None, None)?,
    }
    let amount =
        u64::try_from(numerator.div_ceil(1_000_000)).map_err(|_| EvalError::CostOverflow)?;
    Ok(QualifiedUsageCost {
        known_subtotal_microusd: known.then_some(amount),
        total_microusd: complete.then_some(amount),
    })
}
