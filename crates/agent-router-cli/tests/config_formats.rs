use assert_cmd::Command;
use serde_json::{Value, json};
use std::{fmt::Write, fs, path::Path, process::Output};

const TOML: &str = r#"schema_version = 1
[defaults]
name = "base"
allowed_models = ["fixture-model-b", "fixture-model-a"]
allowed_capabilities = ["tools", "network"]
allowed_mutations = ["network", "workspace_write"]
max_cost_microusd = 100
max_tokens = 1000
max_concurrency = 4
[organization]
name = "org"
allowed_models = ["fixture-model-a"]
allowed_mutations = []
max_cost_microusd = 60
[task]
name = "task"
allowed_models = ["fixture-model-a", "fixture-model-b"]
allowed_mutations = ["network"]
max_tokens = 250
preferred_model = "fixture-model-a"
"#;
const YAML: &str = r#"# Explicit local layers. No implicit configuration discovery.
schema_version: 1
defaults:
  name: base
  allowed_models: [fixture-model-a, fixture-model-b]
  allowed_capabilities: [network, tools]
  allowed_mutations: [workspace_write, network]
  max_cost_microusd: 100
  max_tokens: 1000
  max_concurrency: 4
organization:
  name: org
  allowed_models: [fixture-model-a]
  allowed_mutations: []
  max_cost_microusd: 60
task:
  name: task
  allowed_models: [fixture-model-b, fixture-model-a]
  allowed_mutations: [network]
  max_tokens: 250
  preferred_model: fixture-model-a
"#;
fn fixture() -> Value {
    json!({
        "schema_version":1,
        "defaults":{"name":"base","allowed_models":["fixture-model-a","fixture-model-b"],"allowed_capabilities":["tools","network"],"allowed_mutations":["network","workspace_write"],"max_cost_microusd":100,"max_tokens":1000,"max_concurrency":4},
        "organization":{"name":"org","allowed_models":["fixture-model-a"],"allowed_mutations":[],"max_cost_microusd":60},
        "task":{"name":"task","allowed_models":["fixture-model-a","fixture-model-b"],"allowed_mutations":["network"],"max_tokens":250,"preferred_model":"fixture-model-a"}
    })
}
fn command(path: &Path, structured: bool) -> Output {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("agent-router"));
    command.args(["config", "--layers"]).arg(path);
    if structured {
        command.arg("--json");
    }
    command.output().unwrap()
}
fn run(extension: &str, bytes: impl AsRef<[u8]>) -> Output {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join(format!("private-sentinel.{extension}"));
    fs::write(&path, bytes.as_ref()).unwrap();
    let output = command(&path, true);
    assert_eq!(
        fs::read(path).unwrap(),
        bytes.as_ref(),
        "configuration is read-only"
    );
    output
}
fn rejected(extension: &str, bytes: impl AsRef<[u8]>, code: &str) {
    let output = run(extension, bytes);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{extension}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains(code), "{extension}: {error}");
    assert!(!error.contains("private-sentinel"));
    assert!(!error.contains("secret-value"));
    assert!(!error.contains("/tmp/"));
}

#[test]
fn all_formats_have_identical_output_and_never_regrant_a_restriction() {
    let json = serde_json::to_vec(&fixture()).unwrap();
    let expected = run("json", json);
    assert!(expected.status.success());
    for (extension, body) in [("toml", TOML), ("yaml", YAML), ("yml", YAML)] {
        let output = run(extension, body);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, expected.stdout);
    }
    let output: Value = serde_json::from_slice(&expected.stdout).unwrap();
    assert_eq!(output["allowed_mutations"], json!([]));
    assert_eq!(output["allowed_models"], json!(["fixture-model-a"]));
    assert_eq!(output["max_cost_microusd"], 60);
    assert_eq!(output["max_tokens"], 250);
    assert_eq!(output["max_concurrency"], 4);
    assert_eq!(
        output["sources"],
        json!(["defaults:base", "organization:org", "task:task"])
    );
}

#[test]
fn human_configuration_uses_the_same_result_for_every_format() {
    let temp = tempfile::tempdir().unwrap();
    let bodies = [
        ("json", serde_json::to_string(&fixture()).unwrap()),
        ("toml", TOML.into()),
        ("yaml", YAML.into()),
    ];
    let mut expected = None;
    for (extension, text) in bodies {
        let path = temp.path().join(format!("config.{extension}"));
        fs::write(&path, text).unwrap();
        let output = command(&path, false);
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.starts_with("Effective configuration\n"));
        if let Some(previous) = &expected {
            assert_eq!(previous, &text);
        }
        expected = Some(text);
    }
}

#[test]
fn duplicate_fields_tables_and_set_members_are_never_silently_collapsed() {
    for text in [
        r#"{"schema_version":1,"schema_version":1,"defaults":{"name":"base"}}"#,
        r#"{"schema_version":1,"defaults":{"name":"base","name":"base"}}"#,
        r#"{"schema_version":1,"defaults":{"name":"base","allowed_mutations":["network","network"]}}"#,
    ] {
        rejected("json", text, "configuration.invalid");
    }
    for text in [
        "schema_version=1\nschema_version=1\n[defaults]\nname='base'",
        "schema_version=1\n[defaults]\nname='base'\nname='base'",
        "schema_version=1\n[defaults]\nname='base'\n[defaults]\nmax_tokens=1",
        "schema_version=1\n[defaults]\nname='base'\nallowed_mutations=['network','network']",
    ] {
        rejected("toml", text, "configuration.invalid");
    }
    for text in [
        "schema_version: 1\nschema_version: 1\ndefaults: {name: base}",
        "schema_version: 1\ndefaults: {name: base, name: base}",
        "schema_version: 1\ndefaults: {name: base, allowed_mutations: [network, network]}",
    ] {
        rejected("yaml", text, "configuration.invalid");
    }
}

#[test]
fn unknown_fields_and_wrong_types_are_refused_with_redacted_errors() {
    for text in [
        r#"{"schema_version":1,"defaults":{"name":"base"},"secret-value":true}"#,
        r#"{"schema_version":1,"defaults":{"name":"base","secret-value":true}}"#,
        r#"{"schema_version":"1","defaults":{"name":"base"}}"#,
    ] {
        rejected("json", text, "configuration.invalid");
    }
    for text in [
        "schema_version=1\nsecret-value=true\n[defaults]\nname='base'",
        "schema_version=1\n[defaults]\nname='base'\nsecret-value=true",
        "schema_version='1'\n[defaults]\nname='base'",
        "schema_version=1\n[defaults]\nname=2026-09-27",
    ] {
        rejected("toml", text, "configuration.invalid");
    }
    for text in [
        "schema_version: 1\nsecret-value: true\ndefaults: {name: base}",
        "schema_version: 1\ndefaults: {name: base, secret-value: true}",
        "schema_version: '1'\ndefaults: {name: base}",
        "schema_version: 1\ndefaults: {name: base, max_tokens: 1.0}",
        "schema_version: 1\ndefaults: {name: base, max_tokens: -1}",
    ] {
        rejected("yaml", text, "configuration.invalid");
    }
}

#[test]
fn yaml_rejects_tags_anchors_aliases_merges_directives_and_multiple_documents() {
    for text in [
        "schema_version: 1\ndefaults: &base {name: base}",
        "schema_version: 1\ndefaults: *base",
        "schema_version: 1\ndefaults: !!map {name: base}",
        "schema_version: 1\ndefaults: !include /private/secret-value",
        "schema_version: 1\ndefaults: !env secret-value",
        "schema_version: 1\ndefaults: {name: base, <<: {max_tokens: 1}}",
        "%YAML 1.2\n---\nschema_version: 1\ndefaults: {name: base}",
        "%TAG !x! tag:example.test,2026:\n---\nschema_version: 1\ndefaults: {name: base}",
        "schema_version: 1\ndefaults: {name: base}\n---\nschema_version: 1\ndefaults: {name: second}",
        "schema_version: 1\ndefaults: {name: base}\n...\n---\n",
        "schema_version: 1\ndefaults: {name: base}\n...\nsecret-value",
        "&loop [*loop]",
        "? [schema_version]\n: 1\ndefaults: {name: base}",
    ] {
        rejected("yaml", text, "configuration.invalid");
    }
    let output = run(
        "yaml",
        "---\nschema_version: 1\ndefaults: {name: base}\n...\n",
    );
    assert!(output.status.success());
}

#[test]
fn quoted_control_symbols_are_data_and_environment_is_never_expanded() {
    let temp = tempfile::tempdir().unwrap();
    let name = "${ROUTER_CONFIG_SECRET} !include &anchor *alias";
    let bodies = [
        (
            "json",
            json!({"schema_version":1,"defaults":{"name":name}}).to_string(),
        ),
        (
            "toml",
            format!("schema_version=1\n[defaults]\nname='{name}'"),
        ),
        (
            "yaml",
            format!("schema_version: 1\ndefaults:\n  name: '{name}'"),
        ),
    ];
    for (extension, text) in bodies {
        let path = temp.path().join(format!("config.{extension}"));
        fs::write(&path, text).unwrap();
        let output = Command::new(assert_cmd::cargo::cargo_bin!("agent-router"))
            .args(["config", "--layers"])
            .arg(path)
            .arg("--json")
            .env("ROUTER_CONFIG_SECRET", "secret-value-must-not-be-read")
            .output()
            .unwrap();
        assert!(output.status.success());
        let decoded: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decoded["sources"][0], format!("defaults:{name}"));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("secret-value-must-not-be-read"));
    }
}

#[test]
fn local_file_extension_is_required_and_never_sniffed_or_fetched() {
    rejected(
        "txt",
        serde_json::to_vec(&fixture()).unwrap(),
        "configuration.format",
    );
    rejected(
        "JSON",
        serde_json::to_vec(&fixture()).unwrap(),
        "configuration.format",
    );
    rejected("toml", YAML, "configuration.invalid");
    rejected("json", TOML, "configuration.invalid");
    let missing = command(
        Path::new("https://example.test/private-sentinel.yaml"),
        true,
    );
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("configuration.read"));
    assert!(!String::from_utf8_lossy(&missing.stderr).contains("example.test"));
}

#[test]
fn input_bytes_tree_work_and_scalar_lengths_are_bounded() {
    for extension in ["json", "toml", "yaml"] {
        rejected(extension, vec![b' '; 256 * 1024 + 1], "configuration.limit");
        rejected(extension, [0xff, 0xfe], "configuration.invalid");
    }
    let too_long = "s".repeat(8193);
    rejected(
        "json",
        json!({"schema_version":1,"defaults":{"name":too_long}}).to_string(),
        "configuration.limit",
    );
    rejected(
        "toml",
        format!("schema_version=1\n[defaults]\nname='{too_long}'"),
        "configuration.limit",
    );
    rejected(
        "yaml",
        format!("schema_version: 1\ndefaults: {{name: '{too_long}'}}"),
        "configuration.limit",
    );
    let arrays = format!("{}0{}", "[".repeat(40), "]".repeat(40));
    rejected("yaml", &arrays, "configuration.limit");
    rejected(
        "toml",
        format!("schema_version=1\ndefaults={arrays}"),
        "configuration.limit",
    );
    let many = (0..5000)
        .map(|i| format!("'item{i}'"))
        .collect::<Vec<_>>()
        .join(",");
    rejected("yaml", format!("[{many}]"), "configuration.limit");
    rejected(
        "toml",
        format!("schema_version=1\ndefaults=[{many}]"),
        "configuration.limit",
    );
    rejected("json", json!({"schema_version":1,"defaults":{"name":"base","allowed_models":(0..5000).map(|i|format!("item{i}")).collect::<Vec<_>>()}}).to_string(), "configuration.limit");
}

#[test]
fn invalid_budget_and_forbidden_preference_remain_workflow_failures() {
    let mut value = fixture();
    value["task"]["preferred_model"] = json!("fixture-model-b");
    rejected("json", value.to_string(), "workflow.authority");
    rejected(
        "toml",
        TOML.replace(
            "preferred_model = \"fixture-model-a\"",
            "preferred_model = \"fixture-model-b\"",
        ),
        "workflow.authority",
    );
    rejected(
        "yaml",
        YAML.replace(
            "preferred_model: fixture-model-a",
            "preferred_model: fixture-model-b",
        ),
        "workflow.authority",
    );
    for extension in ["json", "toml", "yaml"] {
        let text = match extension {
            "json" => r#"{"schema_version":1,"defaults":{"name":"base","max_concurrency":0}}"#,
            "toml" => "schema_version=1\n[defaults]\nname='base'\nmax_concurrency=0",
            _ => "schema_version: 1\ndefaults: {name: base, max_concurrency: 0}",
        };
        rejected(extension, text, "workflow.limit");
    }
}

#[cfg(unix)]
#[test]
fn symlinks_and_non_regular_inputs_are_refused_without_following_them() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("private-sentinel-source.yaml");
    let link = temp.path().join("private-sentinel-link.yaml");
    fs::write(&source, YAML).unwrap();
    std::os::unix::fs::symlink(&source, &link).unwrap();
    for path in [&link, temp.path()] {
        let output = command(path, true);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-sentinel"));
    }
    assert_eq!(fs::read_to_string(source).unwrap(), YAML);
}

#[test]
fn decoded_keys_and_members_cannot_hide_duplicates_with_escaping() {
    for (extension, text) in [
        (
            "json",
            r#"{"schema_version":1,"defaults":{"name":"base","na\u006de":"second"}}"#,
        ),
        (
            "json",
            r#"{"schema_version":1,"defaults":{"name":"base","allowed_models":["fixture-a","fixture-\u0061"]}}"#,
        ),
        (
            "toml",
            "schema_version=1\n[defaults]\nname='base'\n\"na\\u006de\"='second'",
        ),
        (
            "toml",
            "schema_version=1\n[defaults]\nname='base'\nallowed_models=['fixture-a',\"fixture-\\u0061\"]",
        ),
        (
            "yaml",
            "schema_version: 1\ndefaults: {name: base, \"na\\u006de\": second}",
        ),
        (
            "yaml",
            "schema_version: 1\ndefaults: {name: base, allowed_models: [fixture-a, \"fixture-\\u0061\"]}",
        ),
    ] {
        rejected(extension, text, "configuration.invalid");
    }
}

#[test]
fn byte_limit_is_inclusive_and_measured_before_parsing() {
    for (extension, text) in [
        ("json", serde_json::to_string(&fixture()).unwrap()),
        ("toml", TOML.into()),
        ("yaml", YAML.into()),
    ] {
        let expected = run(extension, &text);
        let mut bytes = text.into_bytes();
        bytes.resize(256 * 1024, b' ');
        let at_limit = run(extension, &bytes);
        assert!(at_limit.status.success());
        assert_eq!(expected.stdout, at_limit.stdout);
        bytes.push(b' ');
        rejected(extension, bytes, "configuration.limit");
    }
}

#[test]
fn depth_node_and_utf8_scalar_limits_cover_mappings_as_well_as_arrays() {
    let deep_json = format!("{}null{}", "{\"nested\":".repeat(18), "}".repeat(18));
    rejected("json", deep_json, "configuration.limit");
    let deep_yaml = format!("{}null{}", "{nested: ".repeat(18), "}".repeat(18));
    rejected("yaml", deep_yaml, "configuration.limit");
    let deep_toml = format!("nested = {}0{}", "{ nested = ".repeat(18), "}".repeat(18));
    rejected("toml", deep_toml, "configuration.limit");
    let fields: Vec<_> = (0..4096).map(|i| (format!("field{i}"), json!(0))).collect();
    let json_fields = fields.iter().cloned().collect::<serde_json::Map<_, _>>();
    rejected(
        "json",
        Value::Object(json_fields).to_string(),
        "configuration.limit",
    );
    let mut yaml = String::new();
    let mut toml = String::new();
    for (key, _) in &fields {
        writeln!(&mut yaml, "{key}: 0").unwrap();
        writeln!(&mut toml, "{key}=0").unwrap();
    }
    rejected("yaml", yaml, "configuration.limit");
    rejected("toml", toml, "configuration.limit");
    let unicode = "é".repeat(4097);
    rejected(
        "json",
        json!({"schema_version":1,"defaults":{"name":unicode}}).to_string(),
        "configuration.limit",
    );
    rejected(
        "toml",
        format!("schema_version=1\n[defaults]\nname='{unicode}'"),
        "configuration.limit",
    );
    rejected(
        "yaml",
        format!("schema_version: 1\ndefaults: {{name: '{unicode}'}}"),
        "configuration.limit",
    );
}

#[test]
fn numbers_do_not_round_or_coerce_float_and_string_budgets() {
    let expected = run(
        "json",
        r#"{"schema_version":1,"defaults":{"name":"base","max_tokens":9223372036854775807}}"#,
    );
    assert!(expected.status.success());
    for (extension, text) in [
        (
            "toml",
            "schema_version=1\n[defaults]\nname='base'\nmax_tokens=9223372036854775807",
        ),
        (
            "yaml",
            "schema_version: 1\ndefaults: {name: base, max_tokens: 9223372036854775807}",
        ),
    ] {
        let output = run(extension, text);
        assert!(output.status.success());
        assert_eq!(output.stdout, expected.stdout);
    }
    for number in ["18446744073709551616", "1e309", "1.5", "'100'"] {
        rejected(
            "yaml",
            format!("schema_version: 1\ndefaults: {{name: base, max_tokens: {number}}}"),
            "configuration.invalid",
        );
        rejected(
            "toml",
            format!("schema_version=1\n[defaults]\nname='base'\nmax_tokens={number}"),
            "configuration.invalid",
        );
    }
    for number in ["1e309", "1.5", "\"100\""] {
        rejected(
            "json",
            format!(
                "{{\"schema_version\":1,\"defaults\":{{\"name\":\"base\",\"max_tokens\":{number}}}}}"
            ),
            "configuration.invalid",
        );
    }
    let upper = run(
        "json",
        r#"{"schema_version":1,"defaults":{"name":"base","max_tokens":18446744073709551615}}"#,
    );
    let yaml_upper = run(
        "yaml",
        "schema_version: 1\ndefaults: {name: base, max_tokens: 18446744073709551615}",
    );
    assert!(upper.status.success() && yaml_upper.status.success());
    assert_eq!(upper.stdout, yaml_upper.stdout);
    let value: Value = serde_json::from_slice(&upper.stdout).unwrap();
    assert_eq!(value["max_tokens"].as_u64(), Some(u64::MAX));
    rejected(
        "toml",
        "schema_version=1\n[defaults]\nname='base'\nmax_tokens=9223372036854775808",
        "configuration.invalid",
    );
    rejected(
        "json",
        r#"{"schema_version":1,"defaults":{"name":"base","max_tokens":18446744073709551616}}"#,
        "configuration.invalid",
    );
}

#[test]
fn yaml_reserved_directives_block_tags_and_alias_bombs_are_rejected() {
    for text in [
        "%RESERVED secret-value\n---\nschema_version: 1\ndefaults: {name: base}",
        "schema_version: 1\ndefaults:\n  name: !<tag:example.test,2026:secret-value> base",
        "schema_version: 1\ndefaults: {name: base, '<<': {max_tokens: 1}}",
        "a: &a [secret-value, secret-value]\nb: &b [*a, *a, *a]\nc: [*b, *b, *b]",
        "schema_version: 1\ndefaults: &base\n  name: base\nproject: *base",
        "---\nschema_version: 1\ndefaults: {name: base}\n---\n# empty second document",
        "---\n# empty first document\n---\nschema_version: 1\ndefaults: {name: base}",
    ] {
        rejected("yaml", text, "configuration.invalid");
    }
}

#[cfg(unix)]
#[test]
fn a_fifo_with_a_valid_extension_is_rejected_without_waiting_for_a_writer() {
    let temp = tempfile::tempdir().unwrap();
    let fifo = temp.path().join("private-sentinel.yaml");
    assert!(
        std::process::Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    Command::new(assert_cmd::cargo::cargo_bin!("agent-router"))
        .args(["config", "--layers"])
        .arg(&fifo)
        .arg("--json")
        .timeout(std::time::Duration::from_secs(5))
        .assert()
        .code(2)
        .stdout("")
        .stderr("{\"schema_version\":1,\"error\":\"configuration.read\"}\n");
}
