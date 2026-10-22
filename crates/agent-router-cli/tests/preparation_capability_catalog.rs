//! Preparation must preserve authenticated embedded-snapshot authority when
//! exporting a generated catalog. No native host is launched by this fixture.
#[path = "support/native_fixture.rs"]
mod native_fixture;
use native_fixture::{Fixture, asset_inputs, checked, command, write, write_asset_authority};
use router_catalog::{Catalog, GeneratedCatalog, GenerationConfig};
use router_types::*;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn prepare_output_preserves_authenticated_generated_catalog() {
    let f = Fixture::metadata("printf executed > src/provider-must-not-run", 500);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let snapshot = f.validated_snapshot(now);
    let prior = Catalog::from_json(&fs::read(f.root.join("catalog.json")).unwrap()).unwrap();
    let generated =
        GeneratedCatalog::generate(&snapshot, &prior, &GenerationConfig::default()).unwrap();
    let catalog_hash = generated.catalog().content_hash().unwrap();
    fs::write(
        f.root.join("catalog.json"),
        generated.canonical_json().unwrap(),
    )
    .unwrap();
    // The indexer consumes the same generated catalog's normalized content.
    // Its own command has no capability proof store argument.
    fs::write(
        f.root.join("index-catalog.json"),
        generated.catalog().canonical_json().unwrap(),
    )
    .unwrap();
    let request: PhaseRouteRequest =
        serde_json::from_slice(&fs::read(f.root.join("context.json")).unwrap()).unwrap();
    let execution: ExecutionRequest =
        serde_json::from_slice(&fs::read(f.root.join("request.json")).unwrap()).unwrap();
    let assets = asset_inputs(
        &request,
        &snapshot,
        generated.catalog(),
        &f.repo,
        &execution.source_state,
        now,
    );
    write_asset_authority(&f.root, &assets);
    let template = router_workflow::seal_prompt(PromptTemplate {
        schema_version: 1,
        id: "authenticated-template".into(),
        version: "v1".into(),
        template: "Report ${subject}".into(),
        variables: BTreeMap::from([("subject".into(), PromptVariableType::Text)]),
        compatible_hosts: BTreeSet::from(["claude-code".into()]),
        compatible_models: BTreeSet::from([execution.model.clone()]),
        max_rendered_bytes: 4096,
        output_contract: "Evidence".into(),
        content_sha256: String::new(),
    })
    .unwrap();
    write(&f.root.join("prompt.json"), &template);
    let metadata = router_retrieval::MetadataDocument {
        schema_version: "1".into(),
        catalog_version: "fixture".into(),
        assets: vec![router_retrieval::AssetMetadata {
            id: template.id.clone(),
            kind: router_retrieval::AssetKind::Prompt,
            trust: SkillTrust::TrustedLocal,
            task_kinds: vec![],
            triggers: vec![],
            description: "Report".into(),
            examples: vec![],
            tags: vec![],
            paths: vec![],
            anti_triggers: vec![],
            body: Some(router_retrieval::BodyReference {
                path: "prompt.json".into(),
                sha256: router_adapter_api::content_digest(
                    &fs::read(f.root.join("prompt.json")).unwrap(),
                ),
            }),
        }],
    };
    write(&f.root.join("metadata.json"), &metadata);
    let index = checked(
        command()
            .args(["index", "--metadata"])
            .arg(f.root.join("metadata.json"))
            .arg("--catalog")
            .arg(f.root.join("index-catalog.json"))
            .arg("--json"),
        0,
    );
    write(&f.root.join("index.json"), &index);
    write(
        &f.root.join("variables.json"),
        &BTreeMap::from([("subject", PromptValue::Text("private fixture input".into()))]),
    );
    write(
        &f.root.join("options.json"),
        &json!({"schema_version":1,"workspace":execution.workspace,
        "source_state":execution.source_state,"target":"external_worker","allow_degradation":false,
        "timeout_ms":500,"max_output_bytes":16384,"max_input_bytes":65536,"now_unix_seconds":0,"max_snapshot_age_seconds":300}),
    );
    write(
        &f.root.join("prepare.json"),
        &json!({"schema_version":1,"run_id":"prepared-generated-proof",
        "context":"context.json","host_snapshot":"snapshot.json","catalog":"catalog.json",
        "capability_store":"store","execution_config":"sandbox.json","asset_authority":"asset-authority.json",
        "plan":"plan.json","node_id":"execute","metadata":"index.json","body_root":".",
        "template":"prompt.json","variables":"variables.json","options":"options.json"}),
    );
    let preview = checked(
        command()
            .args(["prepare", "--manifest"])
            .arg(f.root.join("prepare.json"))
            .arg("--json"),
        0,
    );
    assert_eq!(preview["executed"], false);
    let directory = f.root.join("prepared");
    let exported = checked(
        command()
            .args(["prepare", "--manifest"])
            .arg(f.root.join("prepare.json"))
            .arg("--output-directory")
            .arg(&directory)
            .arg("--json"),
        0,
    );
    assert_eq!(preview["written"], false);
    assert_eq!(exported["written"], true);
    assert_eq!(exported["executed"], false);
    assert_eq!(exported["approved"], false);
    assert_eq!(
        preview["preview"]["preparation_hash"],
        preview["preparation_hash"]
    );
    assert_eq!(
        exported["preview"]["preparation_hash"],
        exported["preparation_hash"]
    );
    let mut preview_without_hash = preview["preview"].clone();
    preview_without_hash
        .as_object_mut()
        .unwrap()
        .remove("preparation_hash");
    let mut exported_preview_without_hash = exported["preview"].clone();
    exported_preview_without_hash
        .as_object_mut()
        .unwrap()
        .remove("preparation_hash");
    assert_eq!(exported_preview_without_hash, preview_without_hash);
    let persisted_preview: Value =
        serde_json::from_slice(&fs::read(directory.join("preview.json")).unwrap()).unwrap();
    assert_eq!(persisted_preview, exported["preview"]);
    let catalog = Catalog::from_json(&fs::read(directory.join("catalog.json")).unwrap()).unwrap();
    assert_eq!(catalog.content_hash().unwrap(), catalog_hash);
    let receipt: PhaseReceipt =
        serde_json::from_slice(&fs::read(directory.join("receipt.json")).unwrap()).unwrap();
    assert_eq!(receipt.schema_version, 5);
    assert_eq!(receipt.catalog_hash, catalog_hash);
    assert!(
        receipt
            .capability_evidence
            .contains_key(&Capability::WorkspaceWrite)
    );
    let bundled_snapshot: Value =
        serde_json::from_slice(&fs::read(directory.join("snapshot.json")).unwrap()).unwrap();
    assert_eq!(bundled_snapshot["snapshot_hash"], snapshot.hash());
    assert!(!f.repo.join("src/provider-must-not-run").exists());
    assert!(!f.store.join("worktrees").exists());
}
