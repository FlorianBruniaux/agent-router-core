use router_validation::*;
use sha2::{Digest, Sha256};

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn contract(json: &str) -> ValidatedContract {
    parse_contract(json.as_bytes()).expect("valid contract")
}

fn view(changed: &[&str], files: &[(&str, &[u8])]) -> ValidationView {
    ValidationView {
        changed_paths: changed.iter().map(|p| (*p).to_owned()).collect(),
        files: files
            .iter()
            .map(|(p, c)| ((*p).to_owned(), c.to_vec()))
            .collect(),
    }
}

fn single(assertion: &str, v: &ValidationView) -> AssertionResult {
    let json = format!(r#"{{"version":1,"scope":["src"],"assertions":[{assertion}]}}"#);
    let report = evaluate(&contract(&json), v).unwrap();
    assert_eq!(report.objective, Objective::Unknown);
    report.results[0].clone()
}

fn code(assertion: &str, v: &ValidationView) -> Option<FailureCode> {
    single(assertion, v).code
}

#[test]
fn scope_pass_and_fail() {
    let a = r#"{"kind":"changed_paths_within_scope"}"#;
    assert_eq!(
        code(a, &view(&["src/a.rs", "src/x/b.rs", "src"], &[])),
        None
    );
    let r = single(a, &view(&["src/a.rs", "docs/z.md"], &[]));
    assert_eq!(r.code, Some(FailureCode::OutOfScope));
    assert_eq!(r.path.as_deref(), Some("docs/z.md"));
}

#[test]
fn scope_is_component_bounded() {
    let a = r#"{"kind":"changed_paths_within_scope"}"#;
    assert_eq!(
        code(a, &view(&["srcx/a.rs"], &[])),
        Some(FailureCode::OutOfScope)
    );
}

#[test]
fn presence_and_absence() {
    let v = view(&[], &[("a", b"x")]);
    assert_eq!(code(r#"{"kind":"path_present","path":"a"}"#, &v), None);
    assert_eq!(
        code(r#"{"kind":"path_present","path":"b"}"#, &v),
        Some(FailureCode::PathMissing)
    );
    assert_eq!(code(r#"{"kind":"path_absent","path":"b"}"#, &v), None);
    assert_eq!(
        code(r#"{"kind":"path_absent","path":"a"}"#, &v),
        Some(FailureCode::PathPresent)
    );
}

#[test]
fn sha256_assertion() {
    let v = view(&[], &[("a", b"hello")]);
    let ok = format!(
        r#"{{"kind":"sha256","path":"a","sha256":"{}"}}"#,
        sha(b"hello")
    );
    let bad = format!(
        r#"{{"kind":"sha256","path":"a","sha256":"{}"}}"#,
        sha(b"other")
    );
    let missing = format!(
        r#"{{"kind":"sha256","path":"b","sha256":"{}"}}"#,
        sha(b"hello")
    );
    assert_eq!(code(&ok, &v), None);
    assert_eq!(code(&bad, &v), Some(FailureCode::DigestMismatch));
    assert_eq!(code(&missing, &v), Some(FailureCode::PathMissing));
}

#[test]
fn json_pointer_assertion() {
    let v = view(
        &[],
        &[
            ("c.json", br#"{"a":{"b":[1,2]},"s":"x"}"#),
            ("bad.json", b"{nope"),
        ],
    );
    let eq = |p: &str, val: &str, f: &str| {
        format!(r#"{{"kind":"json_pointer_equals","path":"{f}","pointer":"{p}","value":{val}}}"#)
    };
    assert_eq!(code(&eq("/a/b/1", "2", "c.json"), &v), None);
    assert_eq!(
        code(&eq("", r#"{"a":{"b":[1,2]},"s":"x"}"#, "c.json"), &v),
        None
    );
    assert_eq!(
        code(&eq("/a/b/1", "3", "c.json"), &v),
        Some(FailureCode::PointerMismatch)
    );
    assert_eq!(
        code(&eq("/zz", "1", "c.json"), &v),
        Some(FailureCode::PointerMissing)
    );
    assert_eq!(
        code(&eq("/a", "1", "bad.json"), &v),
        Some(FailureCode::InvalidJson)
    );
    assert_eq!(
        code(&eq("/a", "1", "gone.json"), &v),
        Some(FailureCode::PathMissing)
    );
}

#[test]
fn json_too_deep_in_view() {
    let deep = format!(
        "{}1{}",
        "[".repeat(MAX_JSON_DEPTH + 1),
        "]".repeat(MAX_JSON_DEPTH + 1)
    );
    let v = view(&[], &[("d.json", deep.as_bytes())]);
    let a = r#"{"kind":"json_pointer_equals","path":"d.json","pointer":"","value":1}"#;
    assert_eq!(code(a, &v), Some(FailureCode::JsonTooDeep));
}

#[test]
fn brackets_inside_strings_do_not_count_as_depth() {
    let body = format!(r#"{{"s":"{}"}}"#, "[".repeat(200));
    let v = view(&[], &[("s.json", body.as_bytes())]);
    let a = r#"{"kind":"json_pointer_equals","path":"s.json","pointer":"/s","value":"x"}"#;
    assert_eq!(code(a, &v), Some(FailureCode::PointerMismatch));
}

#[test]
fn max_size_boundary() {
    let v = view(&[], &[("a", b"12345")]);
    assert_eq!(
        code(r#"{"kind":"max_size","path":"a","max_bytes":5}"#, &v),
        None
    );
    assert_eq!(
        code(r#"{"kind":"max_size","path":"a","max_bytes":4}"#, &v),
        Some(FailureCode::SizeExceeded)
    );
    assert_eq!(
        code(r#"{"kind":"max_size","path":"b","max_bytes":4}"#, &v),
        Some(FailureCode::PathMissing)
    );
}

#[test]
fn any_failure_fails_validation_and_objective_stays_unknown() {
    let c = contract(
        r#"{"version":1,"assertions":[{"kind":"path_present","path":"a"},{"kind":"path_present","path":"b"}]}"#,
    );
    let r = evaluate(&c, &view(&[], &[("a", b"")])).unwrap();
    assert_eq!(r.validation, Outcome::Failed);
    assert_eq!(r.objective, Objective::Unknown);
    let r = evaluate(&c, &view(&[], &[("a", b""), ("b", b"")])).unwrap();
    assert_eq!(r.validation, Outcome::Passed);
    assert_eq!(r.objective, Objective::Unknown);
    let text = String::from_utf8(r.to_canonical_bytes()).unwrap();
    assert!(text.contains(r#""objective":"unknown""#));
}

#[test]
fn contract_rejections() {
    let bad = |json: &str| parse_contract(json.as_bytes()).unwrap_err();
    assert!(matches!(
        bad(r#"{"version":1,"assertions":[],"x":1}"#),
        ValidationError::InvalidContract(_)
    ));
    assert!(matches!(
        bad(r#"{"version":1,"assertions":[{"kind":"path_present","path":"a","extra":1}]}"#),
        ValidationError::InvalidContract(_)
    ));
    assert!(matches!(
        bad(r#"{"version":1,"assertions":[{"kind":"run_command","path":"a"}]}"#),
        ValidationError::InvalidContract(_)
    ));
    assert_eq!(
        bad(r#"{"version":2,"assertions":[{"kind":"changed_paths_within_scope"}]}"#),
        ValidationError::UnsupportedVersion(2)
    );
    assert_eq!(
        bad(r#"{"version":1,"assertions":[]}"#),
        ValidationError::NoAssertions
    );
    assert_eq!(
        bad(r#"{"version":1,"assertions":[{"kind":"changed_paths_within_scope"}]}"#),
        ValidationError::ScopeRequired
    );
    for path in ["", "/abs", "a/../b", "a//b", "./a", "a/", "a\\b"] {
        let json = format!(
            r#"{{"version":1,"assertions":[{{"kind":"path_present","path":{}}}]}}"#,
            serde_json::to_string(path).unwrap()
        );
        assert!(
            matches!(bad(&json), ValidationError::InvalidPath(_)),
            "{path}"
        );
    }
    assert_eq!(
        bad(r#"{"version":1,"assertions":[{"kind":"sha256","path":"a","sha256":"ABC"}]}"#),
        ValidationError::InvalidDigest(0)
    );
    assert_eq!(
        bad(
            r#"{"version":1,"assertions":[{"kind":"json_pointer_equals","path":"a","pointer":"x","value":1}]}"#
        ),
        ValidationError::InvalidPointer(0)
    );
}

#[test]
fn contract_bounds() {
    let many = format!(
        r#"{{"version":1,"assertions":[{}]}}"#,
        vec![r#"{"kind":"path_present","path":"a"}"#; MAX_ASSERTIONS + 1].join(",")
    );
    assert_eq!(
        parse_contract(many.as_bytes()).unwrap_err(),
        ValidationError::TooManyAssertions
    );
    let big = vec![b' '; MAX_CONTRACT_BYTES + 1];
    assert_eq!(
        parse_contract(&big).unwrap_err(),
        ValidationError::ContractTooLarge
    );
    let deep = format!(
        r#"{{"version":1,"assertions":[{{"kind":"json_pointer_equals","path":"a","pointer":"","value":{}1{}}}]}}"#,
        "[".repeat(MAX_JSON_DEPTH),
        "]".repeat(MAX_JSON_DEPTH)
    );
    assert_eq!(
        parse_contract(deep.as_bytes()).unwrap_err(),
        ValidationError::ContractTooDeep
    );
    assert_eq!(
        parse_contract(
            br#"{"version":1,"assertions":[{"kind":"max_size","path":"a","max_bytes":4194305}]}"#
        )
        .unwrap_err(),
        ValidationError::SizeBoundTooLarge(0)
    );
}

#[test]
fn view_rejections() {
    let c = contract(r#"{"version":1,"assertions":[{"kind":"path_present","path":"a"}]}"#);
    assert!(matches!(
        evaluate(&c, &view(&["../x"], &[])).unwrap_err(),
        ValidationError::InvalidPath(_)
    ));
    let mut v = view(&[], &[]);
    v.files
        .insert("big".into(), vec![0; MAX_FILE_BYTES as usize + 1]);
    assert!(matches!(
        evaluate(&c, &v).unwrap_err(),
        ValidationError::ViewFileTooLarge(_)
    ));
    let mut v = view(&[], &[]);
    v.changed_paths = (0..=MAX_CHANGED_PATHS).map(|i| format!("p{i}")).collect();
    assert_eq!(evaluate(&c, &v).unwrap_err(), ValidationError::ViewTooLarge);
}

#[test]
fn report_is_byte_stable_and_order_independent() {
    let json = r#"{"version":1,"scope":["src"],"assertions":[{"kind":"changed_paths_within_scope"},{"kind":"path_present","path":"src/a"}]}"#;
    let c = contract(json);
    let a = evaluate(
        &c,
        &view(&["src/a", "src/b"], &[("src/a", b"1"), ("src/b", b"2")]),
    )
    .unwrap();
    let b = evaluate(
        &c,
        &view(
            &["src/b", "src/a", "src/a"],
            &[("src/b", b"2"), ("src/a", b"1")],
        ),
    )
    .unwrap();
    assert_eq!(a.to_canonical_bytes(), b.to_canonical_bytes());
    assert_eq!(a.contract_sha256, sha(json.as_bytes()));
    assert!(a.digest_is_consistent());
    assert_eq!(a.evidence_sha256.len(), 64);
}

#[test]
fn digest_covers_verdict_and_view() {
    let c = contract(r#"{"version":1,"assertions":[{"kind":"path_present","path":"a"}]}"#);
    let pass = evaluate(&c, &view(&[], &[("a", b"1")])).unwrap();
    let other = evaluate(&c, &view(&[], &[("a", b"2")])).unwrap();
    assert_ne!(pass.evidence_sha256, other.evidence_sha256);
    let mut tampered = pass.clone();
    tampered.validation = Outcome::Failed;
    assert!(!tampered.digest_is_consistent());
    let mut tampered = pass.clone();
    tampered.results[0].outcome = Outcome::Failed;
    assert!(!tampered.digest_is_consistent());
}

#[test]
fn report_rejects_unknown_objective_value() {
    let c = contract(r#"{"version":1,"assertions":[{"kind":"path_present","path":"a"}]}"#);
    let r = evaluate(&c, &view(&[], &[("a", b"")])).unwrap();
    let text = String::from_utf8(r.to_canonical_bytes())
        .unwrap()
        .replace("\"unknown\"", "\"met\"");
    assert!(serde_json::from_str::<ValidationReport>(&text).is_err());
}

fn assertions_json(n: usize) -> String {
    format!(
        r#"{{"version":1,"assertions":[{}]}}"#,
        vec![r#"{"kind":"path_present","path":"a"}"#; n].join(",")
    )
}

#[test]
fn assertion_and_scope_counts_at_the_limit() {
    assert!(parse_contract(assertions_json(MAX_ASSERTIONS).as_bytes()).is_ok());
    let scope = |n: usize| {
        let entries: Vec<String> = (0..n).map(|i| format!("\"s{i}\"")).collect();
        format!(
            r#"{{"version":1,"scope":[{}],"assertions":[{{"kind":"changed_paths_within_scope"}}]}}"#,
            entries.join(",")
        )
    };
    assert!(parse_contract(scope(MAX_SCOPE_ENTRIES).as_bytes()).is_ok());
    assert_eq!(
        parse_contract(scope(MAX_SCOPE_ENTRIES + 1).as_bytes()).unwrap_err(),
        ValidationError::TooManyScopeEntries
    );
}

#[test]
fn scope_entries_are_path_checked() {
    for entry in ["..", "a/../b", "/abs", "a\\u0000b", "."] {
        let json = format!(
            r#"{{"version":1,"scope":["{entry}"],"assertions":[{{"kind":"changed_paths_within_scope"}}]}}"#
        );
        assert!(
            matches!(
                parse_contract(json.as_bytes()),
                Err(ValidationError::InvalidPath(_))
            ),
            "{entry}"
        );
    }
}

#[test]
fn nul_and_dot_paths_are_rejected() {
    for path in ["a\\u0000b", ".", "..", "a/."] {
        let json =
            format!(r#"{{"version":1,"assertions":[{{"kind":"path_present","path":"{path}"}}]}}"#);
        assert!(
            matches!(
                parse_contract(json.as_bytes()),
                Err(ValidationError::InvalidPath(_))
            ),
            "{path}"
        );
    }
    let long = "a".repeat(MAX_PATH_BYTES + 1);
    let json =
        format!(r#"{{"version":1,"assertions":[{{"kind":"path_present","path":"{long}"}}]}}"#);
    assert!(matches!(
        parse_contract(json.as_bytes()),
        Err(ValidationError::InvalidPath(_))
    ));
    let ok = "a".repeat(MAX_PATH_BYTES);
    let json = format!(r#"{{"version":1,"assertions":[{{"kind":"path_present","path":"{ok}"}}]}}"#);
    assert!(parse_contract(json.as_bytes()).is_ok());
}

#[test]
fn uppercase_hex_digest_of_correct_length_is_rejected() {
    let upper = sha(b"x").to_uppercase();
    assert_eq!(upper.len(), 64);
    let json = format!(
        r#"{{"version":1,"assertions":[{{"kind":"sha256","path":"a","sha256":"{upper}"}}]}}"#
    );
    assert_eq!(
        parse_contract(json.as_bytes()).unwrap_err(),
        ValidationError::InvalidDigest(0)
    );
    let non_hex = "g".repeat(64);
    let json = format!(
        r#"{{"version":1,"assertions":[{{"kind":"sha256","path":"a","sha256":"{non_hex}"}}]}}"#
    );
    assert_eq!(
        parse_contract(json.as_bytes()).unwrap_err(),
        ValidationError::InvalidDigest(0)
    );
}

#[test]
fn pointer_length_boundary() {
    let pointer = |n: usize| {
        let p = format!("/{}", "a".repeat(n - 1));
        format!(
            r#"{{"version":1,"assertions":[{{"kind":"json_pointer_equals","path":"a","pointer":"{p}","value":1}}]}}"#
        )
    };
    assert!(parse_contract(pointer(MAX_POINTER_BYTES).as_bytes()).is_ok());
    assert_eq!(
        parse_contract(pointer(MAX_POINTER_BYTES + 1).as_bytes()).unwrap_err(),
        ValidationError::InvalidPointer(0)
    );
}

#[test]
fn contract_depth_boundary() {
    // root object, assertions array and assertion object take 3 levels.
    let with_depth = |arrays: usize| {
        format!(
            r#"{{"version":1,"assertions":[{{"kind":"json_pointer_equals","path":"a","pointer":"","value":{}1{}}}]}}"#,
            "[".repeat(arrays),
            "]".repeat(arrays)
        )
    };
    assert!(parse_contract(with_depth(MAX_JSON_DEPTH - 3).as_bytes()).is_ok());
    assert_eq!(
        parse_contract(with_depth(MAX_JSON_DEPTH - 2).as_bytes()).unwrap_err(),
        ValidationError::ContractTooDeep
    );
}

#[test]
fn view_json_depth_boundary() {
    let nested = |n: usize| format!("{}1{}", "[".repeat(n), "]".repeat(n));
    let a = r#"{"kind":"json_pointer_equals","path":"d.json","pointer":"","value":1}"#;
    let ok = nested(MAX_JSON_DEPTH);
    let deep = nested(MAX_JSON_DEPTH + 1);
    assert_eq!(
        code(a, &view(&[], &[("d.json", ok.as_bytes())])),
        Some(FailureCode::PointerMismatch)
    );
    assert_eq!(
        code(a, &view(&[], &[("d.json", deep.as_bytes())])),
        Some(FailureCode::JsonTooDeep)
    );
}

#[test]
fn escaped_quote_in_string_keeps_string_state() {
    // The escaped quote must not end the string: the 40 brackets that follow are
    // still inside it, so depth stays 1 and the pointer lookup runs.
    let body = format!(r#"{{"s":"a\"{}"}}"#, "[".repeat(40));
    let a = r#"{"kind":"json_pointer_equals","path":"s.json","pointer":"/s","value":"x"}"#;
    assert_eq!(
        code(a, &view(&[], &[("s.json", body.as_bytes())])),
        Some(FailureCode::PointerMismatch)
    );
}

#[test]
fn view_file_count_boundary() {
    let c = contract(r#"{"version":1,"assertions":[{"kind":"path_present","path":"f0"}]}"#);
    let mut v = view(&[], &[]);
    for i in 0..MAX_VIEW_FILES {
        v.files.insert(format!("f{i}"), Vec::new());
    }
    assert!(evaluate(&c, &v).is_ok());
    v.files.insert("extra".into(), Vec::new());
    assert_eq!(evaluate(&c, &v).unwrap_err(), ValidationError::ViewTooLarge);
}

#[test]
fn changed_paths_alone_change_view_and_evidence_digests() {
    let c = contract(
        r#"{"version":1,"scope":["src"],"assertions":[{"kind":"path_present","path":"a"}]}"#,
    );
    let one = evaluate(&c, &view(&["src/a"], &[("a", b"1")])).unwrap();
    let two = evaluate(&c, &view(&["src/b"], &[("a", b"1")])).unwrap();
    assert_eq!(one.results, two.results);
    assert_ne!(one.view_sha256, two.view_sha256);
    assert_ne!(one.evidence_sha256, two.evidence_sha256);
}

#[test]
fn evidence_digest_covers_every_body_field() {
    let c = contract(r#"{"version":1,"assertions":[{"kind":"path_present","path":"a"}]}"#);
    let r = evaluate(&c, &view(&[], &[("a", b"1")])).unwrap();
    let body = format!(
        r#"{{"schema":"{}","contract_sha256":"{}","view_sha256":"{}","validation":"passed","objective":"unknown","results":{}}}"#,
        r.schema,
        r.contract_sha256,
        r.view_sha256,
        serde_json::to_string(&r.results).unwrap()
    );
    assert_eq!(r.evidence_sha256, sha(body.as_bytes()));
    for tamper in [
        |r: &mut ValidationReport| r.contract_sha256 = sha(b"other"),
        |r: &mut ValidationReport| r.view_sha256 = sha(b"other"),
        |r: &mut ValidationReport| r.schema = "other".into(),
    ] {
        let mut t = r.clone();
        tamper(&mut t);
        assert!(!t.digest_is_consistent());
    }
}

#[test]
fn unit_assertion_rejects_extra_fields_and_keeps_its_shape() {
    let ok =
        r#"{"version":1,"scope":["src"],"assertions":[{"kind":"changed_paths_within_scope"}]}"#;
    let parsed = parse_contract(ok.as_bytes()).expect("bare unit assertion");
    assert_eq!(
        serde_json::to_string(&parsed.contract().assertions[0]).unwrap(),
        r#"{"kind":"changed_paths_within_scope"}"#
    );
    let extra = r#"{"version":1,"scope":["src"],"assertions":[{"kind":"changed_paths_within_scope","path":"src"}]}"#;
    match parse_contract(extra.as_bytes()) {
        Err(ValidationError::InvalidContract(message)) => {
            assert!(message.contains("unknown field"), "{message}");
        }
        other => panic!("expected InvalidContract, got {other:?}"),
    }
}

#[test]
fn duplicate_keys_inside_expected_value_are_rejected() {
    let json = r#"{"version":1,"assertions":[{"kind":"json_pointer_equals","path":"a.json","pointer":"","value":{"k":1,"k":2}}]}"#;
    match parse_contract(json.as_bytes()) {
        Err(ValidationError::InvalidContract(message)) => {
            assert!(message.contains("duplicate object key"), "{message}");
        }
        other => panic!("expected InvalidContract, got {other:?}"),
    }
}
