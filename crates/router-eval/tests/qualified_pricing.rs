use router_eval::{QualifiedPricingTable, price_host_usage};
use router_types::{HostUsage, ModelId, UsageField};
use serde_json::json;
fn table() -> QualifiedPricingTable {
    serde_json::from_value(json!({"schema_version":2,"version":"fixture-v2","source":"synthetic","observed_at_unix_seconds":90,"models":{"fixture":{
        "input_microusd_per_million":1000000,"cache_read_microusd_per_million":500000,
        "cache_write_microusd_per_million":2000000,"cache_write_scope":"all_reported_writes",
        "output_microusd_per_million":3000000,"reasoning":{"mode":"separate","microusd_per_million":4000000}
    }}})).unwrap()
}
fn usage() -> HostUsage {
    HostUsage {
        input_tokens: UsageField::host_reported(100),
        cached_input_tokens: UsageField::host_reported(20),
        cache_write_input_tokens: UsageField::host_reported(30),
        output_tokens: UsageField::host_reported(40),
        reasoning_output_tokens: UsageField::host_reported(10),
    }
}
#[test]
fn disjoint_categories_cost_250_and_missing_fields_keep_only_known_charges() {
    let model = ModelId::parse("fixture").unwrap();
    for (field, want) in [
        ("none", 250),
        ("write_count", 140),
        ("write_rate", 190),
        ("write_scope", 190),
        ("reasoning_count", 120),
        ("reasoning_scope", 120),
        ("output_count", 160),
    ] {
        let mut rates = table();
        let mut usage = usage();
        let price = rates.models.get_mut(&model).unwrap();
        match field {
            "write_count" => usage.cache_write_input_tokens = UsageField::UNKNOWN,
            "write_rate" => price.cache_write_microusd_per_million = None,
            "write_scope" => price.cache_write_scope = None,
            "reasoning_count" => usage.reasoning_output_tokens = UsageField::UNKNOWN,
            "reasoning_scope" => price.reasoning = None,
            "output_count" => usage.output_tokens = UsageField::UNKNOWN,
            _ => {}
        }
        let cost = price_host_usage(&rates, &model, &usage).unwrap();
        assert_eq!(cost.known_subtotal_microusd, Some(want), "{field}");
        assert_eq!(
            cost.total_microusd,
            if field == "none" { Some(250) } else { None },
            "{field}"
        );
    }
}
#[test]
fn included_reasoning_uses_output_once_even_when_breakdown_unknown() {
    let model = ModelId::parse("fixture").unwrap();
    let mut rates = table();
    let mut usage = usage();
    rates.models.get_mut(&model).unwrap().reasoning =
        Some(router_eval::ReasoningPrice::IncludedInOutput);
    usage.reasoning_output_tokens = UsageField::UNKNOWN;
    assert_eq!(
        price_host_usage(&rates, &model, &usage)
            .unwrap()
            .total_microusd,
        Some(240)
    );
}
#[test]
fn missing_model_or_overlapping_cache_counts_never_claim_complete_price() {
    let rates = table();
    let mut usage = usage();
    let unknown = price_host_usage(&rates, &ModelId::parse("absent").unwrap(), &usage).unwrap();
    assert_eq!(unknown.total_microusd, None);
    assert_eq!(unknown.known_subtotal_microusd, None);
    usage.cache_write_input_tokens = UsageField::host_reported(90);
    let invalid = price_host_usage(&rates, &ModelId::parse("fixture").unwrap(), &usage).unwrap();
    assert_eq!(invalid.total_microusd, None);
    assert_eq!(invalid.known_subtotal_microusd, Some(130));
}
