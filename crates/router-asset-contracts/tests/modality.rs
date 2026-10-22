use router_adapter_api::content_digest;
use router_asset_contracts::*;
use serde_json::{Value, json};

fn contract(modality: &str, types: &[&str], max: u64, bytes: &[u8]) -> InputContract {
    parse_input_contract(
        &serde_json::to_vec(&json!({"schema_version":1,"modality":modality,
            "allowed_media_types":types,"max_bytes":max,"sha256":content_digest(bytes)}))
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn each_modality_accepts_matching_bytes() {
    for (modality, kind, media) in [
        (Modality::Image, "image", "image/png"),
        (Modality::Audio, "audio", "audio/wav"),
        (Modality::File, "file", "application/pdf"),
    ] {
        let bytes = format!("payload-{kind}").into_bytes();
        let c = contract(kind, &[media], 1024, &bytes);
        let ok = c.validate_bytes(media, &bytes).unwrap();
        assert_eq!(ok.modality(), modality);
        assert_eq!(ok.media_type(), media);
        assert_eq!(ok.bytes(), bytes.len() as u64);
        assert_eq!(ok.sha256(), content_digest(&bytes));
    }
}

#[test]
fn noncanonical_or_unlisted_media_type_is_refused() {
    let bytes = b"png-bytes";
    let c = contract("image", &["image/png"], 1024, bytes);
    for media in [
        "image/jpeg",
        "Image/PNG",
        "image/png; charset=utf-8",
        "image/png ",
        "image/svg+xml",
        "",
    ] {
        assert_eq!(
            c.validate_bytes(media, bytes).unwrap_err(),
            ContractError::Binding,
            "{media}"
        );
    }
}

#[test]
fn contract_rejects_svg_wrong_family_wildcards_and_noncanonical_entries() {
    let d = content_digest(b"x");
    for (modality, types) in [
        ("image", vec!["image/svg+xml"]),
        ("image", vec!["audio/wav"]),
        ("audio", vec!["image/png"]),
        ("file", vec!["image/png"]),
        ("image", vec!["image/*"]),
        ("image", vec!["Image/png"]),
        ("image", vec!["image/png; q=1"]),
        ("image", vec!["image/png", "image/png"]),
        ("image", vec![]),
    ] {
        let doc = json!({"schema_version":1,"modality":modality,
            "allowed_media_types":types,"max_bytes":10,"sha256":d});
        assert_eq!(
            parse_input_contract(&serde_json::to_vec(&doc).unwrap()).unwrap_err(),
            ContractError::Schema,
            "{modality} {types:?}"
        );
    }
}

#[test]
fn oversize_is_refused_before_hashing_and_bounds_are_enforced() {
    let bytes = b"0123456789";
    let c = contract("audio", &["audio/wav"], 9, bytes);
    assert_eq!(
        c.validate_bytes("audio/wav", bytes).unwrap_err(),
        ContractError::Limit
    );
    let exact = contract("audio", &["audio/wav"], 10, bytes);
    assert!(exact.validate_bytes("audio/wav", bytes).is_ok());
    let d = content_digest(bytes);
    for max in [0u64, MAX_MODALITY_BYTES + 1] {
        let doc = json!({"schema_version":1,"modality":"audio","allowed_media_types":["audio/wav"],
            "max_bytes":max,"sha256":d});
        assert!(parse_input_contract(&serde_json::to_vec(&doc).unwrap()).is_err());
    }
}

#[test]
fn wrong_digest_and_empty_input_are_refused() {
    let c = contract("image", &["image/png"], 1024, b"expected");
    assert_eq!(
        c.validate_bytes("image/png", b"tampered").unwrap_err(),
        ContractError::Integrity
    );
    assert_eq!(
        c.validate_bytes("image/png", b"").unwrap_err(),
        ContractError::Schema
    );
    let doc = json!({"schema_version":1,"modality":"image","allowed_media_types":["image/png"],
        "max_bytes":10,"sha256":content_digest(b"x").to_uppercase()});
    assert!(parse_input_contract(&serde_json::to_vec(&doc).unwrap()).is_err());
}

#[test]
fn unknown_field_and_version_are_refused() {
    let d = content_digest(b"x");
    let base = json!({"schema_version":1,"modality":"image","allowed_media_types":["image/png"],
        "max_bytes":10,"sha256":d});
    let mut extra = base.clone();
    extra["extra"] = json!(true);
    assert_eq!(
        parse_input_contract(&serde_json::to_vec(&extra).unwrap()).unwrap_err(),
        ContractError::Schema
    );
    let mut v2 = base;
    v2["schema_version"] = json!(2);
    assert!(parse_input_contract(&serde_json::to_vec(&v2).unwrap()).is_err());
    let out = json!({"schema_version":1,"schema_sha256":d,"max_bytes":10,"extra":1});
    assert!(parse_json_output_contract(&serde_json::to_vec(&out).unwrap()).is_err());
}

fn output_contract(schema: &str, max: u64) -> JsonOutputContract {
    parse_json_output_contract(
        &serde_json::to_vec(&json!({"schema_version":1,"schema_sha256":schema,"max_bytes":max}))
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn json_output_is_bound_to_schema_and_own_digest() {
    let schema = content_digest(b"schema");
    let c = output_contract(&schema, 64);
    let out = br#"{"ok":true}"#;
    let ok = c
        .validate_output(&schema, &content_digest(out), out)
        .unwrap();
    assert_eq!(ok.sha256(), content_digest(out));
    assert_eq!(ok.schema_sha256(), schema);

    let tampered = br#"{"ok":false}"#;
    assert_eq!(
        c.validate_output(&schema, &content_digest(out), tampered)
            .unwrap_err(),
        ContractError::Integrity
    );
    assert_eq!(
        c.validate_output(&content_digest(b"other"), &content_digest(out), out)
            .unwrap_err(),
        ContractError::Binding
    );
    assert_eq!(
        c.validate_output(&schema, "not-a-digest", out).unwrap_err(),
        ContractError::Schema
    );
}

#[test]
fn json_output_must_be_object_within_bound() {
    let schema = content_digest(b"schema");
    let c = output_contract(&schema, 16);
    for bad in [&b"[1]"[..], b"not json", b"\"s\"", b"{\"a\":"] {
        assert_eq!(
            c.validate_output(&schema, &content_digest(bad), bad)
                .unwrap_err(),
            ContractError::Schema
        );
    }
    let big = br#"{"key":"0123456789"}"#;
    assert_eq!(
        c.validate_output(&schema, &content_digest(big), big)
            .unwrap_err(),
        ContractError::Limit
    );
}

fn input_doc(modality: &str, types: Value, max: Value, sha: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"schema_version":1,"modality":modality,
        "allowed_media_types":types,"max_bytes":max,"sha256":sha}))
    .unwrap()
}

#[test]
fn checks_run_in_the_documented_order() {
    let c = contract("image", &["image/png"], 4, b"good");
    // wrong digest and oversize: size wins.
    assert_eq!(
        c.validate_bytes("image/png", b"toolarge").unwrap_err(),
        ContractError::Limit
    );
    // wrong digest and unlisted media type: media type wins.
    assert_eq!(
        c.validate_bytes("image/gif", b"evil").unwrap_err(),
        ContractError::Binding
    );
    // unlisted media type and empty: media type wins; empty and wrong digest: empty wins.
    assert_eq!(
        c.validate_bytes("image/gif", b"").unwrap_err(),
        ContractError::Binding
    );
    assert_eq!(
        c.validate_bytes("image/png", b"").unwrap_err(),
        ContractError::Schema
    );
    let out = output_contract(&content_digest(b"schema"), 4);
    let schema = content_digest(b"schema");
    // wrong schema and wrong digest: schema binding wins.
    assert_eq!(
        out.validate_output(&content_digest(b"x"), &content_digest(b"y"), b"{}")
            .unwrap_err(),
        ContractError::Binding
    );
    // unlisted media type and oversize (bytes and digest otherwise fine): media type wins.
    assert_eq!(
        c.validate_bytes("image/gif", b"toolarge").unwrap_err(),
        ContractError::Binding
    );
    let bad = content_digest(b"y");
    let form = "not-a-digest";
    let other = content_digest(b"other");
    let big = br#"{"a":1}"#;
    // wrong schema beats malformed claimed digest, oversize and wrong digest.
    for (claimed, output) in [
        (form, &b"{}"[..]),
        (bad.as_str(), &b"{}"[..]),
        (bad.as_str(), &big[..]),
    ] {
        assert_eq!(
            out.validate_output(&other, claimed, output).unwrap_err(),
            ContractError::Binding
        );
    }
    // malformed claimed digest beats oversize (Limit) and digest mismatch (Integrity).
    assert_eq!(
        out.validate_output(&schema, form, big).unwrap_err(),
        ContractError::Schema
    );
    assert_eq!(
        out.validate_output(&schema, form, b"{}").unwrap_err(),
        ContractError::Schema
    );
    // digest beats JSON shape: a non-object with a wrong (well-formed) digest is Integrity.
    assert_eq!(
        out.validate_output(&schema, &bad, b"[1]").unwrap_err(),
        ContractError::Integrity
    );
    // matching digest on a non-object falls through to the shape check.
    assert_eq!(
        out.validate_output(&schema, &content_digest(b"[1]"), b"[1]")
            .unwrap_err(),
        ContractError::Schema
    );
    // wrong digest and oversize: size wins.
    assert_eq!(
        out.validate_output(&schema, &content_digest(b"y"), br#"{"a":1}"#)
            .unwrap_err(),
        ContractError::Limit
    );
}

#[test]
fn duplicate_keys_are_refused_in_contracts_and_output() {
    let d = content_digest(b"x");
    let dup_input = format!(
        r#"{{"schema_version":1,"modality":"image","allowed_media_types":["image/png"],"max_bytes":10,"max_bytes":11,"sha256":"{d}"}}"#
    );
    assert_eq!(
        parse_input_contract(dup_input.as_bytes()).unwrap_err(),
        ContractError::Schema
    );
    let dup_output =
        format!(r#"{{"schema_version":1,"schema_sha256":"{d}","max_bytes":10,"max_bytes":11}}"#);
    assert_eq!(
        parse_json_output_contract(dup_output.as_bytes()).unwrap_err(),
        ContractError::Schema
    );
    let c = output_contract(&d, 64);
    let out = br#"{"a":1,"a":2}"#;
    assert_eq!(
        c.validate_output(&d, &content_digest(out), out)
            .unwrap_err(),
        ContractError::Schema
    );
}

#[test]
fn input_contract_bounds_are_enforced() {
    let d = content_digest(b"x");
    let png = json!(["image/png"]);
    // schema_version
    for v in [0, 2] {
        let doc = serde_json::to_vec(&json!({"schema_version":v,"modality":"image",
            "allowed_media_types":png,"max_bytes":10,"sha256":d}))
        .unwrap();
        assert!(parse_input_contract(&doc).is_err());
    }
    // MAX_MEDIA_TYPES: 16 accepted, 17 refused.
    let many = |n: usize| -> Value {
        (0..n)
            .map(|i| format!("image/t{i}"))
            .collect::<Vec<_>>()
            .into()
    };
    assert!(
        parse_input_contract(&input_doc(
            "image",
            many(MAX_MEDIA_TYPES),
            json!(10),
            json!(d)
        ))
        .is_ok()
    );
    assert!(
        parse_input_contract(&input_doc(
            "image",
            many(MAX_MEDIA_TYPES + 1),
            json!(10),
            json!(d)
        ))
        .is_err()
    );
    // MAX_MEDIA_TYPE_LEN: total length 127 accepted, 128 refused.
    let long = |n: usize| format!("image/{}", "a".repeat(n - "image/".len()));
    assert!(
        parse_input_contract(&input_doc(
            "image",
            json!([long(MAX_MEDIA_TYPE_LEN)]),
            json!(10),
            json!(d)
        ))
        .is_ok()
    );
    assert!(
        parse_input_contract(&input_doc(
            "image",
            json!([long(MAX_MEDIA_TYPE_LEN + 1)]),
            json!(10),
            json!(d)
        ))
        .is_err()
    );
    // malformed shapes
    for bad in ["image/", "image/a/b", "image", "/png", "image/ png"] {
        assert!(
            parse_input_contract(&input_doc("image", json!([bad]), json!(10), json!(d))).is_err(),
            "{bad}"
        );
    }
    // max_bytes upper bound is inclusive.
    assert!(
        parse_input_contract(&input_doc(
            "image",
            png.clone(),
            json!(MAX_MODALITY_BYTES),
            json!(d)
        ))
        .is_ok()
    );
    // uppercase digest
    assert!(
        parse_input_contract(&input_doc("image", png, json!(10), json!(d.to_uppercase()))).is_err()
    );
    // document size bound
    let mut big = input_doc("image", json!(["image/png"]), json!(10), json!(d));
    big.resize(4 * 1024 * 1024 + 1, b' ');
    assert_eq!(
        parse_input_contract(&big).unwrap_err(),
        ContractError::Limit
    );
}

#[test]
fn file_family_is_an_explicit_allow_list() {
    for media in FILE_MEDIA_TYPES {
        let bytes = media.as_bytes();
        let c = contract("file", &[media], 1024, bytes);
        assert!(c.validate_bytes(media, bytes).is_ok(), "{media}");
    }
    let d = content_digest(b"x");
    for media in [
        "text/html",
        "application/xhtml+xml",
        "application/xml",
        "application/javascript",
        "application/x-msdownload",
        "image/svg+xml",
        "audio/wav",
    ] {
        assert_eq!(
            parse_input_contract(&input_doc("file", json!([media]), json!(10), json!(d)))
                .unwrap_err(),
            ContractError::Schema,
            "{media}"
        );
    }
}

#[test]
fn output_contract_bounds_are_enforced() {
    let d = content_digest(b"schema");
    let doc = |v: u64, max: u64, sha: &str| {
        serde_json::to_vec(&json!({"schema_version":v,"schema_sha256":sha,"max_bytes":max}))
            .unwrap()
    };
    assert!(parse_json_output_contract(&doc(1, MAX_JSON_OUTPUT_BYTES, &d)).is_ok());
    for bad in [
        doc(1, 0, &d),
        doc(1, MAX_JSON_OUTPUT_BYTES + 1, &d),
        doc(0, 10, &d),
        doc(2, 10, &d),
        doc(1, 10, &d.to_uppercase()),
        doc(1, 10, "short"),
    ] {
        assert_eq!(
            parse_json_output_contract(&bad).unwrap_err(),
            ContractError::Schema
        );
    }
    let mut big = doc(1, 10, &d);
    big.resize(4 * 1024 * 1024 + 1, b' ');
    assert_eq!(
        parse_json_output_contract(&big).unwrap_err(),
        ContractError::Limit
    );
}
