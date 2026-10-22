use std::path::PathBuf;

use router_adapter_api::{
    AdapterDescriptor, AdapterRegistry, MAX_DESCRIPTOR_BYTES, MAX_DESCRIPTORS, RESERVED_NAMES,
    RegistryError, normalize_name,
};
use router_types::CapabilitySupport;
use serde_json::{Value, json};

/// Real codex descriptor as JSON, with `f` applied, serialized back to bytes.
fn variant(f: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value: Value = serde_json::from_str(&real("codex")).unwrap();
    f(&mut value);
    serde_json::to_vec(&value).unwrap()
}

/// A valid descriptor for an arbitrary host/crate pair (entry point bound).
fn doc(host: &str, krate: &str) -> Vec<u8> {
    variant(|v| {
        v["host"] = json!(host);
        v["crate"] = json!(krate);
        v["entry_point"] = json!(format!("{}::Adapter", krate.replace('-', "_")));
    })
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn real(name: &str) -> String {
    std::fs::read_to_string(root().join("integrations").join(name).join("adapter.json")).unwrap()
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/registry")
            .join(name),
    )
    .unwrap()
}

/// Replaces `from` with `to` in the real codex descriptor; the replacement
/// must hit, so a mutation cannot silently be a no-op.
fn mutated(from: &str, to: &str) -> Vec<u8> {
    let text = real("codex");
    assert!(text.contains(from), "mutation target missing: {from}");
    text.replacen(from, to, 1).into_bytes()
}

fn parse(bytes: &[u8]) -> Result<AdapterDescriptor, RegistryError> {
    AdapterDescriptor::parse(bytes)
}

#[test]
fn both_real_descriptors_pass_and_form_a_registry() {
    let dirs: Vec<_> = std::fs::read_dir(root().join("integrations"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.join("adapter.json").is_file())
        .collect();
    // Tripwire on purpose: adding a third descriptor must update this test.
    assert_eq!(dirs.len(), 2, "expected exactly the two known descriptors");
    let documents: Vec<Vec<u8>> = dirs
        .iter()
        .map(|dir| std::fs::read(dir.join("adapter.json")).unwrap())
        .collect();
    let refs: Vec<&[u8]> = documents.iter().map(Vec::as_slice).collect();
    let registry = AdapterRegistry::from_documents(&refs).unwrap();
    assert_eq!(registry.len(), 2);
    let codex = registry.get("codex").unwrap();
    assert_eq!(codex.crate_name(), "adapter-codex");
    assert_eq!(codex.entry_point(), "adapter_codex::CodexAdapter");
    assert!(registry.get("claude-code").is_some());
}

#[test]
fn capabilities_are_unknown_by_default() {
    for name in ["codex", "claude-code"] {
        let descriptor = parse(real(name).as_bytes()).unwrap();
        // Tripwire on purpose: a new Capability variant must be reviewed here.
        assert_eq!(descriptor.capabilities().len(), 5);
        assert!(
            descriptor
                .capabilities()
                .values()
                .all(|support| *support == CapabilitySupport::Unknown)
        );
    }
}

#[test]
fn restating_unknown_is_accepted_but_claiming_support_is_refused() {
    let unknown = mutated(
        "\"requires\"",
        "\"capabilities\": {\"tools\": \"unknown\"},\n  \"requires\"",
    );
    assert!(parse(&unknown).is_ok());
    let claimed = mutated(
        "\"requires\"",
        "\"capabilities\": {\"tools\": \"supported\"},\n  \"requires\"",
    );
    assert_eq!(parse(&claimed), Err(RegistryError::CapabilityClaimed));
}

#[test]
fn unknown_field_is_refused() {
    let bytes = mutated("\"requires\"", "\"signature\": \"abc\",\n  \"requires\"");
    assert_eq!(parse(&bytes), Err(RegistryError::InvalidJson));
}

#[test]
fn activation_must_be_none() {
    for value in ["not_installed", "auto", "None", ""] {
        let bytes = mutated(
            "\"activation\": \"none\"",
            &format!("\"activation\": \"{value}\""),
        );
        assert_eq!(
            parse(&bytes),
            Err(RegistryError::ActivationNotNone),
            "{value}"
        );
    }
}

#[test]
fn every_reserved_name_is_refused_as_host_and_as_crate() {
    for name in RESERVED_NAMES {
        assert_eq!(
            parse(&doc(name, "adapter-codex")),
            Err(RegistryError::ReservedName),
            "host {name}"
        );
        assert_eq!(
            parse(&doc("codex", name)),
            Err(RegistryError::ReservedName),
            "crate {name}"
        );
    }
}

#[test]
fn reserved_names_and_prefixes_cannot_be_bypassed_with_underscore() {
    for name in [
        "router_types",
        "router-types",
        "router_core",
        "agent_router_cli",
        "agent-router-cli",
        "agent-router-x",
        "router-x",
        "router_x",
        "agent_router",
        "agent_routerx",
    ] {
        assert_eq!(
            parse(&doc("codex", name)),
            Err(RegistryError::ReservedName),
            "crate {name}"
        );
        assert_eq!(
            parse(&doc(name, "adapter-codex")),
            Err(RegistryError::ReservedName),
            "host {name}"
        );
    }
    // Underscore variants of reserved plain names are not reserved words here
    // unless they normalize to one.
    assert!(parse(&doc("my-router", "adapter-my-router")).is_ok());
}

#[test]
fn hyphen_and_underscore_forms_conflict() {
    let a = doc("codex", "adapter-codex");
    let same_crate = doc("other", "adapter_codex");
    assert_eq!(
        AdapterRegistry::from_documents(&[&a, &same_crate]),
        Err(RegistryError::Conflict("crate"))
    );
    let a = doc("claude-code", "adapter-a");
    let same_host = doc("claude_code", "adapter-b");
    assert_eq!(
        AdapterRegistry::from_documents(&[&a, &same_host]),
        Err(RegistryError::Conflict("host"))
    );
    let exact = doc("codex", "adapter-codex");
    assert_eq!(
        AdapterRegistry::from_documents(&[&exact, &exact]),
        Err(RegistryError::Conflict("host"))
    );
    let registry = AdapterRegistry::from_documents(&[&a]).unwrap();
    assert!(registry.get("claude_code").is_some());
    assert!(registry.get("claude-code").is_some());
}

#[test]
fn entry_point_must_belong_to_the_declared_crate() {
    // host=codex, crate=adapter-claude, foreign entry point.
    let bytes = variant(|v| {
        v["crate"] = json!("adapter-claude");
        v["entry_point"] = json!("std::process::Command");
    });
    assert_eq!(
        parse(&bytes),
        Err(RegistryError::Invalid("entry_point crate mismatch"))
    );
    // Well-formed entry point of another adapter crate.
    let bytes = variant(|v| v["crate"] = json!("adapter-claude"));
    assert_eq!(
        parse(&bytes),
        Err(RegistryError::Invalid("entry_point crate mismatch"))
    );
    // The underscore spelling of the crate is the accepted binding.
    assert!(parse(&doc("codex", "adapter_codex")).is_ok());
}

#[test]
fn native_plugin_manifest_true_is_refused() {
    let bytes = variant(|v| v["native_plugin_manifest"] = json!(true));
    assert_eq!(
        parse(&bytes),
        Err(RegistryError::Invalid("native_plugin_manifest"))
    );
}

#[test]
fn requires_cannot_drop_the_minimum_gates_but_may_add() {
    let empty = variant(|v| v["requires"] = json!([]));
    assert_eq!(
        parse(&empty),
        Err(RegistryError::Invalid("requires minimum"))
    );
    for missing in [
        "validated-phase-receipt",
        "bound-authorization",
        "supervised-sandbox",
    ] {
        let bytes = variant(|v| {
            let list: Vec<Value> = v["requires"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|item| item.as_str() != Some(missing))
                .cloned()
                .collect();
            v["requires"] = Value::Array(list);
        });
        assert_eq!(
            parse(&bytes),
            Err(RegistryError::Invalid("requires minimum")),
            "{missing}"
        );
    }
    let extra = variant(|v| {
        v["requires"]
            .as_array_mut()
            .unwrap()
            .push(json!("extra-gate"))
    });
    assert!(parse(&extra).is_ok());
}

#[test]
fn requires_is_bounded_at_sixteen() {
    let with = |extras: usize| {
        variant(|v| {
            let list = v["requires"].as_array_mut().unwrap();
            for n in 0..extras {
                list.push(json!(format!("gate-{n}")));
            }
        })
    };
    assert!(parse(&with(13)).is_ok(), "3 + 13 = 16");
    assert_eq!(parse(&with(14)), Err(RegistryError::Invalid("requires")));
}

#[test]
fn unsupported_capability_claim_is_refused() {
    let bytes = variant(|v| v["capabilities"] = json!({"network": "unsupported"}));
    assert_eq!(parse(&bytes), Err(RegistryError::CapabilityClaimed));
}

#[test]
fn invalid_names_are_refused() {
    let long = format!("a{}", "b".repeat(64)); // 65 bytes
    for bad in [
        "Codex",
        "cödex",
        "1codex",
        "",
        "co dex",
        "co.dex",
        long.as_str(),
    ] {
        let bytes = variant(|v| v["host"] = json!(bad));
        assert_eq!(
            parse(&bytes),
            Err(RegistryError::Invalid("host")),
            "{bad:?}"
        );
        let bytes = variant(|v| v["crate"] = json!(bad));
        assert_eq!(
            parse(&bytes),
            Err(RegistryError::Invalid("crate")),
            "{bad:?}"
        );
    }
    let sixty_four = format!("a{}", "b".repeat(63));
    assert!(parse(&doc(&sixty_four, "adapter-codex")).is_ok());
}

#[test]
fn iteration_is_ordered_by_normalized_host() {
    let docs = [
        doc("zeta", "adapter-z"),
        doc("alpha", "adapter-a"),
        doc("mid_h", "adapter-m"),
    ];
    let refs: Vec<&[u8]> = docs.iter().map(Vec::as_slice).collect();
    let registry = AdapterRegistry::from_documents(&refs).unwrap();
    let hosts: Vec<&str> = registry.iter().map(|d| d.host()).collect();
    assert_eq!(hosts, ["alpha", "mid_h", "zeta"]);
    assert_eq!(normalize_name("a-b_c"), "a_b_c");
}

#[test]
fn error_codes_and_display_agree() {
    let cases = [
        (RegistryError::TooLarge, "descriptor.too_large"),
        (
            RegistryError::TooManyDescriptors,
            "descriptor.set.too_large",
        ),
        (RegistryError::InvalidJson, "descriptor.json.invalid"),
        (
            RegistryError::ActivationNotNone,
            "descriptor.activation.not_none",
        ),
        (RegistryError::ReservedName, "descriptor.name.reserved"),
        (
            RegistryError::CapabilityClaimed,
            "descriptor.capability.claimed",
        ),
    ];
    for (error, code) in cases {
        assert_eq!(error.code(), code);
        assert_eq!(error.to_string(), code);
    }
    let invalid = RegistryError::Invalid("x");
    assert_eq!(invalid.code(), "descriptor.invalid");
    assert_eq!(invalid.to_string(), "descriptor.invalid: x");
    let conflict = RegistryError::Conflict("host");
    assert_eq!(conflict.code(), "descriptor.conflict");
    assert_eq!(conflict.to_string(), "descriptor.conflict: host");
}

#[test]
fn size_bounds_are_exact() {
    let mut exact = real("codex").into_bytes();
    exact.resize(MAX_DESCRIPTOR_BYTES, b' ');
    assert_eq!(exact.len(), 16384);
    assert!(parse(&exact).is_ok());
    exact.push(b' ');
    assert_eq!(parse(&exact), Err(RegistryError::TooLarge));

    let docs: Vec<Vec<u8>> = (0..=MAX_DESCRIPTORS)
        .map(|n| {
            doc(
                &format!("host{}", letters(n)),
                &format!("adapter-h{}", letters(n)),
            )
        })
        .collect();
    let refs: Vec<&[u8]> = docs.iter().map(Vec::as_slice).collect();
    assert_eq!(MAX_DESCRIPTORS, 32);
    assert!(AdapterRegistry::from_documents(&refs[..32]).is_ok());
    assert_eq!(
        AdapterRegistry::from_documents(&refs[..33]),
        Err(RegistryError::TooManyDescriptors)
    );
}

/// Digit-free suffix, since names must not depend on digits for uniqueness.
fn letters(mut n: usize) -> String {
    let mut out = String::new();
    loop {
        out.push((b'a' + (n % 26) as u8) as char);
        n /= 26;
        if n == 0 {
            return out;
        }
    }
}

#[test]
fn entry_point_is_text_and_never_a_path() {
    // Documented rule: a Rust-style `a::B` path of identifiers. Absolute
    // paths, `..`, separators and bare names are refused, never resolved.
    for bad in [
        "/usr/bin/evil",
        "C:\\\\evil",
        "../adapter_codex::CodexAdapter",
        "adapter_codex::../CodexAdapter",
        "::adapter_codex::CodexAdapter",
        "adapter_codex",
        "adapter_codex::",
        "adapter codex::X",
    ] {
        let bytes = mutated("adapter_codex::CodexAdapter", bad);
        assert_eq!(
            parse(&bytes),
            Err(RegistryError::Invalid("entry_point")),
            "{bad}"
        );
    }
}

#[test]
fn duplicate_json_keys_and_duplicate_entries_are_refused() {
    assert_eq!(
        parse(&fixture("duplicate-key.json")),
        Err(RegistryError::InvalidJson)
    );
    let modes = mutated(
        "[\"dry_run\", \"shadow\", \"execute\"]",
        "[\"shadow\", \"shadow\"]",
    );
    assert_eq!(parse(&modes), Err(RegistryError::Invalid("modes")));
    let requires = mutated("\"validated-phase-receipt\"", "\"bound-authorization\"");
    assert_eq!(parse(&requires), Err(RegistryError::Invalid("requires")));
}

#[test]
fn wrong_identity_fields_are_refused() {
    assert_eq!(
        parse(&mutated("\"schema_version\": 1", "\"schema_version\": 2")),
        Err(RegistryError::Invalid("schema_version"))
    );
    assert_eq!(
        parse(&mutated(
            "\"contract\": \"HarnessAdapter\"",
            "\"contract\": \"Other\""
        )),
        Err(RegistryError::Invalid("contract"))
    );
    assert_eq!(
        parse(&mutated(
            "\"target\": \"external_worker\"",
            "\"target\": \"native\""
        )),
        Err(RegistryError::InvalidJson)
    );
    assert_eq!(parse(b"[]"), Err(RegistryError::InvalidJson));
    assert_eq!(parse(b""), Err(RegistryError::InvalidJson));
}
