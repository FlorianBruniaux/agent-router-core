use router_feedback::attempt_correlation_report;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

// Synthetic supplied evidence only. No store, provider or model is involved.
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/evaluation/attempt-correlation-v1.json"
    ))
    .unwrap()
}
fn digest(label: &str) -> String {
    hex::encode(Sha256::digest(label.as_bytes()))
}
fn run(v: &Value) -> router_feedback::Result<Value> {
    attempt_correlation_report(&serde_json::to_vec(v).unwrap())
        .map(|r| serde_json::to_value(r).unwrap())
}
fn report(v: &Value) -> Value {
    run(v).unwrap()
}
fn refuses(v: &Value, reason: &str) {
    let err = run(v).expect_err("input must be refused").to_string();
    assert!(err.contains(reason), "expected `{reason}`, got `{err}`");
}

#[test]
fn positive_control_links_dedups_and_leaves_unknown() {
    let r = report(&fixture());
    assert_eq!(r["evidence_trust"], "supplied_unverified");
    let first = &r["attempts"][0]["physical_sends"];
    assert_eq!(first.as_array().unwrap().len(), 2);
    // Calls are ordered by physical key, so compare the agreement set.
    let mut agreements: Vec<_> = first
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["selection_agreement"].as_str().unwrap())
        .collect();
    agreements.sort();
    assert_eq!(agreements, ["match", "mismatch"]);
    assert_eq!(r["attempts"][1]["physical_sends"], "unknown");
    assert_eq!(r["unattributed"].as_array().unwrap().len(), 1);
    assert_eq!(r["supplied_physical_observation_count"], 3);
    assert_eq!(r["duplicate_observation_count"], 1);
    assert!(
        r["unverified"]
            .as_array()
            .unwrap()
            .contains(&json!("snapshot_sha256_not_reverified"))
    );
}

#[test]
fn same_physical_key_with_any_differing_field_is_a_conflict() {
    // physical[1] repeats physical[0]; changing any one field must conflict.
    let changes: [(&str, Value); 5] = [
        (
            "claimed_attempt_key_sha256",
            fixture()["runtime"]["attempts"][1]["attempt_key_sha256"].clone(),
        ),
        ("evidence_sha256", json!(digest("other-evidence"))),
        ("sequence", json!(99)),
        ("declared_model", json!("model-z")),
        ("external_request_id", json!("req-other")),
    ];
    for (field, value) in changes {
        let mut v = fixture();
        v["physical"][1][field] = value;
        refuses(&v, "physical identity conflict");
    }
}

#[test]
fn claim_for_absent_attempt_key_is_a_substitution() {
    let mut v = fixture();
    v["physical"][3]["claimed_attempt_key_sha256"] = json!(digest("not-in-snapshot"));
    refuses(&v, "claimed attempt absent from snapshot");
}

#[test]
fn duplicate_attempt_key_is_refused() {
    let mut v = fixture();
    v["runtime"]["attempts"][1]["attempt_key_sha256"] =
        v["runtime"]["attempts"][0]["attempt_key_sha256"].clone();
    refuses(&v, "duplicate attempt key");
}

#[test]
fn bad_attempt_ordinals_are_refused() {
    for (ordinals, reason) in [
        ([0, 2], "attempt ordinals"),
        ([1, 6], "attempt ordinals"),
        ([1, 3], "attempt ordinals"),
        ([1, 1], "duplicate attempt ordinal"),
    ] {
        let mut v = fixture();
        v["runtime"]["attempts"][0]["ordinal"] = json!(ordinals[0]);
        v["runtime"]["attempts"][1]["ordinal"] = json!(ordinals[1]);
        refuses(&v, reason);
    }
}

#[test]
fn physical_key_under_runtime_authority_is_refused() {
    let mut v = fixture();
    v["physical"][3]["key"]["authority_sha256"] = v["runtime"]["authority_sha256"].clone();
    refuses(&v, "physical key under runtime authority");
}

#[test]
fn unknown_evidence_with_requested_selection_is_refused() {
    let mut v = fixture();
    v["runtime"]["attempts"][1]["requested"] = json!({"model": "model-a", "effort": "high"});
    refuses(&v, "attempt evidence and requested selection disagree");
}

#[test]
fn malformed_input_is_refused_without_partial_report() {
    let mut v = fixture();
    v["extra"] = json!(1);
    assert!(run(&v).is_err());

    let mut v = fixture();
    v["physical"][0]["extra"] = json!(1);
    assert!(run(&v).is_err());

    let mut v = fixture();
    v["runtime"]["snapshot_sha256"] = json!("ABC");
    refuses(&v, "runtime digest");

    let mut v = fixture();
    v["physical"][2]["evidence_sha256"] = json!("zz");
    refuses(&v, "physical observation");

    let mut v = fixture();
    v["physical"][2]["sequence"] = json!(0);
    refuses(&v, "physical observation");

    let mut v = fixture();
    v["physical"][3]["sequence"] = v["physical"][0]["sequence"].clone();
    refuses(&v, "physical sequence");

    let mut v = fixture();
    v["schema_version"] = json!(2);
    refuses(&v, "attempt correlation version");

    // A valid document with one repeated key: only strict JSON can refuse it.
    let text = serde_json::to_string(&fixture()).unwrap();
    let dup = text.replacen("{", "{\"schema_version\":1,", 1);
    assert!(attempt_correlation_report(text.as_bytes()).is_ok());
    assert!(attempt_correlation_report(dup.as_bytes()).is_err());

    let huge = vec![b' '; 4 * 1024 * 1024 + 1];
    let err = attempt_correlation_report(&huge).unwrap_err().to_string();
    assert!(err.contains("feedback.limit"), "{err}");
}

#[test]
fn shared_external_request_id_never_merges_calls() {
    let v = fixture();
    assert_eq!(
        v["physical"][0]["external_request_id"],
        v["physical"][2]["external_request_id"]
    );
    assert_ne!(v["physical"][0]["key"], v["physical"][2]["key"]);
    let r = report(&v);
    let calls = r["attempts"][0]["physical_sends"].as_array().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0]["external_request_id"],
        calls[1]["external_request_id"]
    );
}

#[test]
fn attempt_without_claim_is_unknown_never_zero_or_failed() {
    let mut v = fixture();
    v["physical"] = json!([]);
    let r = report(&v);
    for attempt in r["attempts"].as_array().unwrap() {
        assert_eq!(attempt["physical_sends"], "unknown");
    }
    let text = serde_json::to_string(&r).unwrap();
    assert!(!text.contains("failed_before_send"));
    assert_eq!(r["supplied_physical_observation_count"], 0);
}

#[test]
fn output_is_byte_identical_and_order_insensitive_for_calls() {
    let bytes = serde_json::to_vec(&fixture()).unwrap();
    let a = serde_json::to_vec(&attempt_correlation_report(&bytes).unwrap()).unwrap();
    let b = serde_json::to_vec(&attempt_correlation_report(&bytes).unwrap()).unwrap();
    assert_eq!(a, b);
    let mut v = fixture();
    v["physical"].as_array_mut().unwrap().reverse();
    v["runtime"]["attempts"].as_array_mut().unwrap().reverse();
    let c = serde_json::to_vec(&report(&v)).unwrap();
    let d: Value = serde_json::from_slice(&a).unwrap();
    let c: Value = serde_json::from_slice(&c).unwrap();
    assert_eq!(d["attempts"], c["attempts"]);
    assert_eq!(d["unattributed"], c["unattributed"]);
}

#[test]
fn durable_attempt_without_requested_is_refused() {
    let mut v = fixture();
    v["runtime"]["attempts"][0]["requested"] = Value::Null;
    refuses(&v, "attempt evidence and requested selection disagree");
}

#[test]
fn attempt_bound_is_enforced_on_contiguous_attempts() {
    let mut v = fixture();
    let attempts: Vec<Value> = (1..=6)
        .map(|n| {
            json!({"ordinal": n, "attempt_key_sha256": digest(&format!("attempt-{n}")),
                   "evidence": "unknown", "requested": null})
        })
        .collect();
    v["runtime"]["attempts"] = json!(attempts);
    v["physical"] = json!([]);
    let err = run(&v).unwrap_err().to_string();
    assert!(err.contains("feedback.limit"), "{err}");
}

#[test]
fn physical_bound_is_enforced_on_valid_distinct_observations() {
    let mut v = fixture();
    let physical: Vec<Value> = (1..=4097u64)
        .map(|n| {
            json!({"key": {"authority_sha256": digest("external-authority"),
                           "physical_sha256": digest(&format!("phys-{n}"))},
                   "sequence": n, "evidence_sha256": digest(&format!("ev-{n}")),
                   "external_request_id": null, "declared_model": null,
                   "claimed_attempt_key_sha256": null})
        })
        .collect();
    v["physical"] = json!(physical);
    let bytes = serde_json::to_vec(&v).unwrap();
    assert!(bytes.len() < 4 * 1024 * 1024);
    let err = attempt_correlation_report(&bytes).unwrap_err().to_string();
    assert!(err.contains("feedback.limit"), "{err}");
    // Without the surplus row the same shape is accepted.
    v["physical"].as_array_mut().unwrap().pop();
    assert!(run(&v).is_ok());
}

#[test]
fn missing_requested_or_declared_model_gives_unknown_agreement() {
    let mut v = fixture();
    let ext = v["physical"][0]["key"]["authority_sha256"].clone();
    let k2 = v["runtime"]["attempts"][1]["attempt_key_sha256"].clone();
    let k1 = v["runtime"]["attempts"][0]["attempt_key_sha256"].clone();
    let mut extra = |name: &str, seq: u64, claim: Value, model: Value| {
        v["physical"].as_array_mut().unwrap().push(json!({
            "key": {"authority_sha256": ext, "physical_sha256": digest(name)},
            "sequence": seq, "evidence_sha256": digest(name),
            "external_request_id": null, "declared_model": model,
            "claimed_attempt_key_sha256": claim}));
    };
    extra("claim-to-unknown-attempt", 10, k2, json!("model-a"));
    extra("claim-without-declared-model", 11, k1, Value::Null);
    let r = report(&v);
    let unknown_attempt = r["attempts"][1]["physical_sends"].as_array().unwrap();
    assert_eq!(unknown_attempt[0]["selection_agreement"], "unknown");
    let undeclared = r["attempts"][0]["physical_sends"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["declared_model"].is_null())
        .unwrap();
    assert_eq!(undeclared["selection_agreement"], "unknown");
}
