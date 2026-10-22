//! Synthetic offline contexts and provenance; no human outcome or runtime proof.
use assert_cmd::Command;
use router_retrieval::*;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn command() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("agent-router"))
}
fn catalog_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/examples/phase-catalog.json")
}
fn provenance() -> SignalProvenance {
    SignalProvenance {
        source_id: "synthetic-cli".into(),
        source_version: "1".into(),
        source_sha256: "a".repeat(64),
        observed_at_unix_seconds: 100,
    }
}
fn write(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn output(assertion: assert_cmd::assert::Assert) -> Value {
    serde_json::from_slice(&assertion.get_output().stdout).unwrap()
}
fn fixture(root: &Path) -> (MetadataEnvelopeV3, ContextSearchQuery) {
    let catalog = router_catalog::Catalog::from_json(&fs::read(catalog_path()).unwrap()).unwrap();
    let assets: Vec<AssetMetadata> = ["fixture-best", "fixture-second"].into_iter().map(|id|
        serde_json::from_value(json!({"kind":"model","id":id,"trust":"trusted_local","description":"database migration"})).unwrap()
    ).collect();
    let signals: Vec<_> = assets
        .iter()
        .enumerate()
        .map(|(i, asset)| AssetSignals {
            asset: asset.key(),
            languages: Signal::Observed {
                value: vec![if i == 0 { "python" } else { "rust" }.into()],
                provenance: provenance(),
            },
            required_tools: Signal::Observed {
                value: vec![],
                provenance: provenance(),
            },
            history: Signal::Unknown,
        })
        .collect();
    let metadata = MetadataDocument {
        schema_version: "1".into(),
        catalog_version: catalog.version().into(),
        assets,
    };
    write(&root.join("metadata.json"), &metadata);
    write(&root.join("signals.json"), &signals);
    let envelope =
        MetadataEnvelopeV3::new(metadata, signals, &catalog.content_hash().unwrap()).unwrap();
    write(&root.join("index.json"), &envelope);
    let mut query = ContextSearchQuery::new(SearchQuery::new("database"), provenance(), 110);
    query.query.kind = Some(AssetKind::Model);
    query.languages = vec!["rust".into()];
    write(&root.join("query.json"), &query);
    (envelope, query)
}
fn search(root: &Path) -> Command {
    let mut cmd = command();
    cmd.args(["search", "--metadata"])
        .arg(root.join("index.json"))
        .arg("--catalog")
        .arg(catalog_path())
        .arg("--context-query")
        .arg(root.join("query.json"))
        .args(["--now", "110", "--json"]);
    cmd
}
fn refresh(root: &Path, old: &str) -> Command {
    let mut cmd = command();
    cmd.args(["refresh", "--metadata"])
        .arg(root.join("index.json"))
        .arg("--successor")
        .arg(root.join("successor.json"))
        .args(["--expected-source-hash", old])
        .arg("--catalog")
        .arg(catalog_path())
        .args(["--now", "110", "--json"]);
    cmd
}
#[test]
fn index_without_signals_keeps_v2_and_with_signals_builds_v3() {
    let temp = tempfile::tempdir().unwrap();
    fixture(temp.path());
    for version in ["2", "3"] {
        let mut cmd = command();
        cmd.args(["index", "--metadata"])
            .arg(temp.path().join("metadata.json"))
            .arg("--catalog")
            .arg(catalog_path())
            .args(["--json", "--now", "110"]);
        if version == "3" {
            cmd.arg("--signals").arg(temp.path().join("signals.json"));
        }
        let result = output(cmd.assert().success());
        assert_eq!(result["schema_version"], version);
        let index = Bm25Index::from_json(&serde_json::to_vec(&result).unwrap()).unwrap();
        assert!(index.catalog_hash().is_some());
    }
}
#[test]
fn contextual_model_search_uses_languages_and_refuses_legacy_bypass() {
    let temp = tempfile::tempdir().unwrap();
    fixture(temp.path());
    let result = output(search(temp.path()).assert().success());
    assert_eq!(result["selected"]["id"], "fixture-second");
    assert_eq!(result["selected"]["kind"], "model");
    assert_eq!(result["semantic_status"], "disabled");
    command()
        .args(["search", "--metadata"])
        .arg(temp.path().join("index.json"))
        .arg("--catalog")
        .arg(catalog_path())
        .args(["--query", "database", "--kind", "model", "--json"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("retrieval.context.required"));
    search(temp.path())
        .args(["--query", "override"])
        .assert()
        .code(2);
    search(temp.path()).args(["--top-k", "1"]).assert().code(2);
    search(temp.path())
        .args(["--kind", "skill"])
        .assert()
        .code(2);
}
#[test]
fn unknown_required_tools_abstain_and_expired_query_clock_is_not_trusted() {
    let temp = tempfile::tempdir().unwrap();
    let (mut envelope, _) = fixture(temp.path());
    for signal in &mut envelope.signals {
        signal.required_tools = Signal::Unknown;
    }
    envelope = MetadataEnvelopeV3::new(
        envelope.metadata,
        envelope.signals,
        &envelope.catalog_content_sha256,
    )
    .unwrap();
    write(&temp.path().join("index.json"), &envelope);
    let result = output(search(temp.path()).assert().code(3));
    assert!(result["selected"].is_null());
    assert_eq!(result["excluded_count"], 2);
    assert_eq!(result["exclusions"][0]["reason"], "required_tools_unknown");
    command()
        .args(["search", "--metadata"])
        .arg(temp.path().join("index.json"))
        .arg("--catalog")
        .arg(catalog_path())
        .arg("--context-query")
        .arg(temp.path().join("query.json"))
        .arg("--json")
        .assert()
        .code(2)
        .stderr(predicates::str::contains("retrieval.invalid"));
}
#[test]
fn malformed_context_missing_catalog_and_implicit_ranking_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let (_, query) = fixture(temp.path());
    let mut value = serde_json::to_value(query).unwrap();
    value["grant_tool_authority"] = true.into();
    write(&temp.path().join("query.json"), &value);
    search(temp.path()).assert().code(2);
    command()
        .args(["search", "--metadata"])
        .arg(temp.path().join("index.json"))
        .arg("--context-query")
        .arg(temp.path().join("query.json"))
        .arg("--json")
        .assert()
        .code(2);
    command()
        .args(["search", "--metadata"])
        .arg(temp.path().join("index.json"))
        .args(["--query", "database", "--semantic-ranking"])
        .arg(temp.path().join("missing.json"))
        .arg("--json")
        .assert()
        .code(2);
}
#[test]
fn semantic_rankings_require_explicit_policy_and_build_feature() {
    let temp = tempfile::tempdir().unwrap();
    let (envelope, mut query) = fixture(temp.path());
    query.semantic_policy = SemanticPolicy::Required;
    query.languages.clear();
    write(&temp.path().join("query.json"), &query);
    let index = Bm25Index::build_v3(envelope).unwrap();
    let ranking = SemanticRanking {
        schema_version: 1,
        index_hash: index.index_hash().into(),
        query_hash: query.content_hash().unwrap(),
        provenance: provenance(),
        hits: vec![RankedHit {
            asset: AssetKey {
                kind: AssetKind::Model,
                id: "fixture-second".into(),
            },
            score_micros: 900000,
        }],
    };
    write(&temp.path().join("ranking.json"), &ranking);
    let mut cmd = search(temp.path());
    cmd.arg("--semantic-ranking")
        .arg(temp.path().join("ranking.json"));
    if cfg!(feature = "semantic-retrieval") {
        let result = output(cmd.assert().success());
        assert_eq!(result["semantic_status"], "applied");
        assert_eq!(result["selected"]["id"], "fixture-second");
        let mut invalid = ranking.clone();
        invalid.query_hash = "b".repeat(64);
        write(&temp.path().join("ranking.json"), &invalid);
        search(temp.path())
            .arg("--semantic-ranking")
            .arg(temp.path().join("ranking.json"))
            .assert()
            .code(2)
            .stderr(predicates::str::contains("retrieval.semantic.invalid"));
    } else {
        cmd.assert()
            .code(2)
            .stderr(predicates::str::contains("retrieval.semantic.unavailable"));
    }
    query.semantic_policy = SemanticPolicy::LexicalFallback;
    query.languages = vec!["rust".into()];
    write(&temp.path().join("query.json"), &query);
    let result = output(search(temp.path()).assert().success());
    assert_eq!(result["semantic_status"], "unavailable_fallback");
    assert_eq!(result["selected"]["id"], "fixture-second");
    query.semantic_policy = SemanticPolicy::Disabled;
    write(&temp.path().join("query.json"), &query);
    search(temp.path())
        .arg("--semantic-ranking")
        .arg(temp.path().join("ranking.json"))
        .assert()
        .code(2)
        .stderr(predicates::str::contains("retrieval.semantic.invalid"));
}
#[test]
fn refresh_is_checked_equivalent_to_rebuild_and_atomically_publishes_without_overwrite() {
    let temp = tempfile::tempdir().unwrap();
    let (envelope, query) = fixture(temp.path());
    let index = Bm25Index::build_v3(envelope.clone()).unwrap();
    let before = fs::read(temp.path().join("index.json")).unwrap();
    let mut next = envelope;
    next.metadata.assets[0].description = "database rust concurrent migration".into();
    next =
        MetadataEnvelopeV3::new(next.metadata, next.signals, &next.catalog_content_sha256).unwrap();
    write(&temp.path().join("successor.json"), &next);
    let destination = temp.path().join("next-index.json");
    let result = output(
        refresh(temp.path(), index.source_hash())
            .arg("--output")
            .arg(&destination)
            .assert()
            .success(),
    );
    assert_eq!(result["update"]["updated"], 1);
    assert_eq!(result["update"]["retokenized_assets"], 1);
    let persisted = Bm25Index::from_json(&fs::read(&destination).unwrap()).unwrap();
    let rebuilt = Bm25Index::build_v3(next).unwrap();
    assert_eq!(persisted.index_hash(), rebuilt.index_hash());
    assert_eq!(
        persisted
            .search_contextual(&query, persisted.catalog_hash().unwrap())
            .unwrap(),
        rebuilt
            .search_contextual(&query, rebuilt.catalog_hash().unwrap())
            .unwrap()
    );
    assert_eq!(fs::read(temp.path().join("index.json")).unwrap(), before);
    fs::write(&destination, "sentinel").unwrap();
    refresh(temp.path(), index.source_hash())
        .arg("--output")
        .arg(&destination)
        .assert()
        .code(2)
        .stderr(predicates::str::contains("retrieval.output"));
    assert_eq!(fs::read(&destination).unwrap(), b"sentinel");
    assert!(fs::read_dir(temp.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp")
    }));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
#[test]
fn refresh_stale_hash_and_wrong_catalog_never_publish_anything() {
    let temp = tempfile::tempdir().unwrap();
    let (mut next, _) = fixture(temp.path());
    let index = Bm25Index::build_v3(next.clone()).unwrap();
    write(&temp.path().join("successor.json"), &next);
    let destination = temp.path().join("next-index.json");
    refresh(temp.path(), &"0".repeat(64))
        .arg("--output")
        .arg(&destination)
        .assert()
        .code(2)
        .stderr(predicates::str::contains("retrieval.stale"));
    assert!(!destination.exists());
    next.catalog_content_sha256 = "b".repeat(64);
    write(&temp.path().join("successor.json"), &next);
    refresh(temp.path(), index.source_hash())
        .arg("--output")
        .arg(&destination)
        .assert()
        .code(2)
        .stderr(predicates::str::contains("retrieval.catalog.mismatch"));
    assert!(!destination.exists());
}
#[cfg(unix)]
#[test]
fn refresh_refuses_symlink_destination_without_modifying_target() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let (next, _) = fixture(temp.path());
    let index = Bm25Index::build_v3(next.clone()).unwrap();
    write(&temp.path().join("successor.json"), &next);
    let target = temp.path().join("target");
    fs::write(&target, "sentinel").unwrap();
    let destination = temp.path().join("link");
    symlink(&target, &destination).unwrap();
    refresh(temp.path(), index.source_hash())
        .arg("--output")
        .arg(&destination)
        .assert()
        .code(2);
    assert_eq!(fs::read(target).unwrap(), b"sentinel");
}
