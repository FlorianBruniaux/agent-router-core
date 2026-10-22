use router_feedback::supplied_usage_pricing_report;
use serde_json::{Value, json};

// Synthetic supplied evidence; never an invoice or live producer export.
fn fixture() -> Value {
    let mut accounting: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/evaluation/accepted-changes-v1.json"
    ))
    .unwrap();
    accounting["selections"][0]["revision_sha256"] =
        accounting["revisions"][0]["binding"]["revision_sha256"].clone();
    let field = |tokens| json!({"tokens":tokens,"provenance":"host_reported"});
    let usage = json!({"input_tokens":field(100),"cached_input_tokens":field(20),
        "cache_write_input_tokens":field(10),"output_tokens":field(50),"reasoning_output_tokens":field(5)});
    let mut physical = Vec::new();
    for observation in accounting["observations"].as_array_mut().unwrap() {
        if observation["kind"] == "model" {
            observation["cost_microusd"] = Value::Null;
            physical.push(
                json!({"key":observation["key"],"evidence_sha256":observation["evidence_sha256"],
                "model":"test-model","scope":"per_physical_call","usage":usage}),
            );
        }
    }
    json!({"schema_version":1,"accounting":accounting,"physical_usage":physical,
        "pricing":{"schema_version":2,"version":"fixture-v1","source":"synthetic",
        "observed_at_unix_seconds":1,"models":{"test-model":{
        "input_microusd_per_million":1000000,"cache_read_microusd_per_million":1000000,
        "cache_write_microusd_per_million":1000000,"cache_write_scope":"all_reported_writes",
        "output_microusd_per_million":1000000,"reasoning":{"mode":"included_in_output"}}}}})
}
fn report(v: &Value) -> Value {
    serde_json::to_value(supplied_usage_pricing_report(&serde_json::to_vec(v).unwrap()).unwrap())
        .unwrap()
}
fn refuses(v: &Value) {
    assert!(supplied_usage_pricing_report(&serde_json::to_vec(v).unwrap()).is_err());
}

#[test]
fn includes_failed_retried_and_timed_out_physical_calls_once() {
    let mut v = fixture();
    let duplicate = v["physical_usage"][0].clone();
    v["physical_usage"].as_array_mut().unwrap().push(duplicate);
    let duplicate = v["accounting"]["observations"][0].clone();
    v["accounting"]["observations"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    let r = report(&v);
    assert_eq!(
        r["accounting"]["cohort_costs"]["model"]["total_microusd"],
        450
    );
    assert_eq!(
        r["accounting"]["cost_per_selected_accepted_change"]["model"],
        json!({"numerator_microusd":450,"denominator":1})
    );
    assert_eq!(
        r["portable_pricing"]["physical_usage"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(r["portable_pricing"]["duplicate_usage_count"], 1);
    assert_eq!(r["evidence_trust"], "supplied_unverified");
    assert_eq!(r["portable_pricing"]["cost_basis"], "estimated_not_invoice");
}

#[test]
fn partial_cost_never_enters_accounting_as_a_total() {
    for field in [
        "cache_write_scope",
        "cache_read_microusd_per_million",
        "reasoning",
    ] {
        let mut v = fixture();
        v["pricing"]["models"]["test-model"][field] = Value::Null;
        let r = report(&v);
        assert_eq!(
            r["accounting"]["cohort_costs"]["model"]["total_microusd"],
            Value::Null
        );
        assert_eq!(
            r["accounting"]["cohort_costs"]["model"]["known_subtotal_microusd"],
            0
        );
        assert!(
            r["portable_pricing"]["physical_usage"][0]["cost"]["known_subtotal_microusd"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(
            r["portable_pricing"]["physical_usage"][0]["cost"]["total_microusd"],
            Value::Null
        );
    }
}

#[test]
fn preserves_incomplete_coverage_and_inventory() {
    for (field, value) in [
        ("usage_coverage", "last_turn_only"),
        ("pricing_coverage", "partial"),
    ] {
        let mut v = fixture();
        v["accounting"]["observations"][0][field] = json!(value);
        let r = report(&v);
        let observed = r["accounting"]["observations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["key"] == v["accounting"]["observations"][0]["key"])
            .unwrap();
        assert_eq!(observed[field], value);
        assert_eq!(
            r["accounting"]["cohort_costs"]["model"]["total_microusd"],
            Value::Null
        );
    }
    let mut v = fixture();
    v["accounting"]["inventories"][0]["coverage"] = json!("partial");
    assert_eq!(
        report(&v)["accounting"]["cohort_costs"]["model"]["total_microusd"],
        Value::Null
    );
    let mut v = fixture();
    v["physical_usage"].as_array_mut().unwrap().pop();
    assert_eq!(
        report(&v)["accounting"]["cohort_costs"]["model"]["total_microusd"],
        Value::Null
    );
}

#[test]
fn refuses_conflicting_duplicates_substitution_nonmodel_and_replacement() {
    for field in ["model", "evidence_sha256", "usage"] {
        let mut v = fixture();
        let mut other = v["physical_usage"][0].clone();
        other[field] = match field {
            "model" => json!("different"),
            "evidence_sha256" => json!("f".repeat(64)),
            _ => v["physical_usage"][1]["usage"].clone(),
        };
        if field == "usage" {
            other[field]["input_tokens"]["tokens"] = json!(101);
        }
        v["physical_usage"].as_array_mut().unwrap().push(other);
        refuses(&v);
    }
    let mut v = fixture();
    v["physical_usage"][0]["evidence_sha256"] = json!("f".repeat(64));
    refuses(&v);
    let mut v = fixture();
    v["physical_usage"][0]["key"]["physical_sha256"] = json!("f".repeat(64));
    refuses(&v);
    let mut v = fixture();
    v["physical_usage"][0]["key"] = v["accounting"]["observations"][2]["key"].clone();
    refuses(&v);
    let mut v = fixture();
    v["accounting"]["observations"][0]["cost_microusd"] = json!(150);
    refuses(&v);
    // Raw conflicting accounting must be rejected before pricing could erase the difference.
    let mut v = fixture();
    let mut other = v["accounting"]["observations"][0].clone();
    other["cost_microusd"] = json!(1);
    v["accounting"]["observations"]
        .as_array_mut()
        .unwrap()
        .push(other);
    refuses(&v);
}

#[test]
fn refuses_missing_cumulative_and_session_usage_scope() {
    for scope in [
        Value::Null,
        json!("cumulative"),
        json!("session"),
        json!("last_turn"),
    ] {
        let mut v = fixture();
        v["physical_usage"][0]["scope"] = scope;
        refuses(&v);
    }
    let mut v = fixture();
    v["physical_usage"][0]
        .as_object_mut()
        .unwrap()
        .remove("scope");
    refuses(&v);
}

#[test]
fn refuses_invalid_token_subsets_provenance_and_overflow() {
    for (field, count) in [
        ("cached_input_tokens", 101),
        ("cache_write_input_tokens", 81),
        ("reasoning_output_tokens", 51),
        ("input_tokens", u64::MAX),
    ] {
        let mut v = fixture();
        v["physical_usage"][0]["usage"][field]["tokens"] = json!(count);
        refuses(&v);
    }
    let mut v = fixture();
    v["physical_usage"][0]["usage"]["input_tokens"]["provenance"] = json!("unknown");
    refuses(&v);
    let mut v = fixture();
    v["physical_usage"][0]["usage"]["input_tokens"]["tokens"] = json!(1_000_000_000_000u64);
    refuses(&v);
    let mut v = fixture();
    v["physical_usage"][0]["usage"]["input_tokens"]["tokens"] = json!(999_999_999_950u64);
    v["pricing"]["models"]["test-model"]["input_microusd_per_million"] = json!(u64::MAX);
    refuses(&v);
}

#[test]
fn absent_model_rates_and_unknown_usage_remain_unknown() {
    let mut v = fixture();
    v["pricing"]["models"] = json!({});
    let r = report(&v);
    assert_eq!(
        r["portable_pricing"]["physical_usage"][0]["cost"]["known_subtotal_microusd"],
        Value::Null
    );
    let mut v = fixture();
    v["physical_usage"][0]["usage"]["input_tokens"] = json!({"tokens":null,"provenance":"unknown"});
    assert_eq!(
        report(&v)["accounting"]["cohort_costs"]["model"]["total_microusd"],
        Value::Null
    );
}

#[test]
fn same_physical_id_and_external_id_under_different_authority_stays_distinct() {
    let mut v = fixture();
    let mut row = v["accounting"]["observations"][0].clone();
    row["sequence"] = json!(15);
    row["key"]["authority_sha256"] = json!("e".repeat(64));
    let mut usage = v["physical_usage"][0].clone();
    usage["key"] = row["key"].clone();
    v["physical_usage"].as_array_mut().unwrap().push(usage);
    v["accounting"]["inventories"][0]["expected"]
        .as_array_mut()
        .unwrap()
        .push(json!({"key":row["key"],"sequence":15}));
    v["accounting"]["observations"]
        .as_array_mut()
        .unwrap()
        .push(row);
    assert_eq!(
        report(&v)["accounting"]["cohort_costs"]["model"]["total_microusd"],
        600
    );
}

#[test]
fn portable_projection_omits_all_supplied_free_text_and_retains_source_digests() {
    let sentinel = "SECRET_SENTINEL";
    let mut v = fixture();
    let rate = v["pricing"]["models"]["test-model"].clone();
    v["pricing"]["models"] = json!({sentinel:rate});
    v["pricing"]["source"] = json!(sentinel);
    v["pricing"]["version"] = json!(sentinel);
    for row in v["physical_usage"].as_array_mut().unwrap() {
        row["model"] = json!(sentinel);
    }
    // Assignment IDs appear in several nested local accounting records.
    fn poison_ids(value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    if key == "assignment_id" || key == "external_request_id" {
                        *value = json!(format!(
                            "SECRET_SENTINEL_{}",
                            value.as_str().unwrap_or("id")
                        ));
                    } else {
                        poison_ids(value);
                    }
                }
            }
            Value::Array(rows) => {
                for row in rows {
                    poison_ids(row);
                }
            }
            _ => {}
        }
    }
    poison_ids(&mut v["accounting"]);
    let cohort = serde_json::from_value(v["accounting"]["cohort"].clone()).unwrap();
    let digest = router_feedback::accepted_cohort_sha256(&cohort).unwrap();
    v["accounting"]["cohort_sha256"] = json!(digest);
    for row in v["accounting"]["observations"].as_array_mut().unwrap() {
        row["cohort_sha256"] = json!(digest);
    }
    let r = report(&v);
    let portable = &r["portable_pricing"];
    assert!(!serde_json::to_string(portable).unwrap().contains(sentinel));
    assert_eq!(
        portable["physical_usage"][0]["evidence_sha256"],
        v["physical_usage"][0]["evidence_sha256"]
    );
    for field in ["input_sha256", "accounting_input_sha256", "pricing_sha256"] {
        assert_eq!(portable[field].as_str().unwrap().len(), 64);
    }
    assert!(
        serde_json::to_string(&r["accounting"])
            .unwrap()
            .contains(sentinel)
    );
}

#[test]
fn strict_parser_refuses_duplicate_keys_unknown_fields_and_bounds_without_echo() {
    let v = fixture();
    let bytes = serde_json::to_vec(&v).unwrap();
    let mut duplicate = b"{\"schema_version\":1,".to_vec();
    duplicate.extend_from_slice(&bytes[1..]);
    assert!(supplied_usage_pricing_report(&duplicate).is_err());
    for pointer in [
        "",
        "/physical_usage/0",
        "/physical_usage/0/usage",
        "/pricing",
        "/accounting",
    ] {
        let mut v = fixture();
        v.pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("SECRET_SENTINEL".into(), json!("SECRET_SENTINEL"));
        let error = supplied_usage_pricing_report(&serde_json::to_vec(&v).unwrap()).unwrap_err();
        assert!(!error.to_string().contains("SECRET_SENTINEL"));
    }
    let mut v = fixture();
    v["physical_usage"] = json!(vec![v["physical_usage"][0].clone(); 4097]);
    refuses(&v);
    assert!(supplied_usage_pricing_report(&vec![b' '; 4 * 1024 * 1024 + 1]).is_err());
}

#[test]
fn fixture_contract_matches_the_public_example() {
    let example: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/evaluation/supplied-usage-pricing/complete.json"
    ))
    .unwrap();
    assert_eq!(example, fixture());
    assert_eq!(report(&example), report(&example));
}

#[test]
fn every_supplied_text_leaf_is_omitted_or_safely_rejected() {
    fn paths(value: &Value, path: String, out: &mut Vec<String>) {
        match value {
            Value::String(_) => out.push(path),
            Value::Array(rows) => {
                for (i, row) in rows.iter().enumerate() {
                    paths(row, format!("{path}/{i}"), out);
                }
            }
            Value::Object(map) => {
                for (key, row) in map {
                    paths(row, format!("{path}/{key}"), out);
                }
            }
            _ => {}
        }
    }
    let mut leaves = Vec::new();
    paths(&fixture(), String::new(), &mut leaves);
    assert!(leaves.len() > 50);
    for path in leaves {
        let mut v = fixture();
        *v.pointer_mut(&path).unwrap() = json!("SECRET_SENTINEL");
        match supplied_usage_pricing_report(&serde_json::to_vec(&v).unwrap()) {
            Ok(result) => assert!(
                !serde_json::to_string(&result.portable_pricing)
                    .unwrap()
                    .contains("SECRET_SENTINEL"),
                "{path}"
            ),
            Err(error) => assert!(!error.to_string().contains("SECRET_SENTINEL"), "{path}"),
        }
    }
}

#[test]
fn typed_entrypoint_also_refuses_inconsistent_usage() {
    let mut input: router_feedback::SuppliedUsagePricingInput =
        serde_json::from_value(fixture()).unwrap();
    input.physical_usage[0].usage.input_tokens.tokens = Some(u64::MAX);
    assert!(router_feedback::calculate_supplied_usage_pricing(&input).is_err());
    input.physical_usage[0].usage.input_tokens = router_types::UsageField {
        tokens: Some(100),
        provenance: router_types::UsageProvenance::Unknown,
    };
    assert!(router_feedback::calculate_supplied_usage_pricing(&input).is_err());
}
