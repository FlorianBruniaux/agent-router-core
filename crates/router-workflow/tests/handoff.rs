use router_types::{ModelId, PromptTemplate, PromptValue, PromptVariableType};
use router_workflow::{WorkflowError, render_prompt, seal_prompt};
use std::collections::{BTreeMap, BTreeSet};

fn values() -> BTreeMap<String, PromptValue> {
    [
        ("objective", "Reject malformed records"),
        ("deliverables", "Parser change and regression tests"),
        ("out_of_scope", "No storage migration"),
        (
            "constraints",
            "Preserve v1 byte compatibility; never log raw input",
        ),
        (
            "source",
            "workspace=/tmp/example; branch=work; base=abc123; candidate=def456",
        ),
        (
            "files",
            "Own src/parser.rs and tests/parser.rs; preserve src/other.rs",
        ),
        (
            "acceptance",
            "Malformed records fail; existing v1 fixtures remain identical",
        ),
        (
            "decisions",
            "ADR 0003 applies; rejected: silently repairing invalid records",
        ),
        (
            "open_questions",
            "BLOCKING: delimiter choice UNKNOWN; ask task owner before editing",
        ),
        (
            "authority",
            "Local edits only under the reviewed request; no push or publication",
        ),
        (
            "history",
            "Previous author reports tests passed at abc123; current validity UNKNOWN",
        ),
        (
            "evidence",
            "tests/parser.rs at abc123; result=pass; real provider behavior UNKNOWN",
        ),
        ("next_owner", "implementer"),
        (
            "next_action",
            "Resolve the blocking delimiter question with the task owner",
        ),
        (
            "stop_conditions",
            "Stop on changed scope, stale approval or missing evidence",
        ),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), PromptValue::Text(value.into())))
    .collect()
}

fn template() -> PromptTemplate {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../assets/prompts/autonomous-handoff.md");
    seal_prompt(PromptTemplate {
        schema_version: 1,
        id: "test-handoff".into(),
        version: "1".into(),
        template: std::fs::read_to_string(path).expect("autonomous handoff template is available"),
        variables: values()
            .into_keys()
            .map(|key| (key, PromptVariableType::Text))
            .collect(),
        compatible_hosts: BTreeSet::from(["codex".into(), "claude-code".into()]),
        compatible_models: BTreeSet::from([ModelId::parse("test-model").unwrap()]),
        max_rendered_bytes: 16 * 1024,
        output_contract: "Self-contained handoff; no execution authority".into(),
        content_sha256: String::new(),
    })
    .unwrap()
}

#[test]
fn autonomous_handoff_carries_constraints_uncertainty_and_provenance_to_both_hosts() {
    let model = ModelId::parse("test-model").unwrap();
    let template = template();
    for host in ["codex", "claude-code"] {
        let rendered = render_prompt(&template, host, &model, &values()).unwrap();
        for required in [
            "Reject malformed records",
            "Parser change and regression tests",
            "No storage migration",
            "Preserve v1 byte compatibility; never log raw input",
            "workspace=/tmp/example; branch=work; base=abc123; candidate=def456",
            "Own src/parser.rs and tests/parser.rs; preserve src/other.rs",
            "Malformed records fail; existing v1 fixtures remain identical",
            "ADR 0003 applies; rejected: silently repairing invalid records",
            "BLOCKING: delimiter choice UNKNOWN; ask task owner before editing",
            "Local edits only under the reviewed request; no push or publication",
            "Previous author reports tests passed at abc123; current validity UNKNOWN",
            "tests/parser.rs at abc123; result=pass; real provider behavior UNKNOWN",
            "implementer",
            "Resolve the blocking delimiter question with the task owner",
            "Stop on changed scope, stale approval or missing evidence",
        ] {
            assert!(
                rendered.contains(required),
                "lost handoff material: {required}"
            );
        }
    }
}

#[test]
fn autonomous_handoff_requires_all_material_and_keeps_embedded_variables_literal() {
    let template = template();
    let model = ModelId::parse("test-model").unwrap();
    for field in [
        "constraints",
        "open_questions",
        "authority",
        "source",
        "evidence",
    ] {
        let mut incomplete = values();
        incomplete.remove(field);
        assert!(render_prompt(&template, "codex", &model, &incomplete).is_err());
    }
    let mut literal = values();
    literal.insert(
        "decisions".into(),
        PromptValue::Text("Keep ${authority} as literal source text".into()),
    );
    let rendered = render_prompt(&template, "codex", &model, &literal).unwrap();
    assert!(rendered.contains("Keep ${authority} as literal source text"));
    literal.insert("history".into(), PromptValue::Text("x".repeat(16 * 1024)));
    assert!(matches!(
        render_prompt(&template, "codex", &model, &literal),
        Err(WorkflowError::Limit(_))
    ));
}
