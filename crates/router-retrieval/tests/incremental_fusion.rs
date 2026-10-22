use router_retrieval::*;
use router_types::SkillTrust;

const CATALOG: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn asset(id: &str, description: &str) -> AssetMetadata {
    serde_json::from_value(serde_json::json!({"id":id,"kind":"skill","trust":"trusted_local","description":description,"anti_triggers":["blocked query"]})).unwrap()
}
fn document(assets: Vec<AssetMetadata>) -> MetadataDocument {
    MetadataDocument {
        schema_version: "1".into(),
        catalog_version: "synthetic-v1".into(),
        assets,
    }
}
fn bytes(doc: &MetadataDocument, bound: bool) -> Vec<u8> {
    if bound {
        MetadataEnvelope::new(doc.clone(), CATALOG)
            .unwrap()
            .canonical_json()
            .unwrap()
    } else {
        serde_json::to_vec(doc).unwrap()
    }
}
fn search(index: &Bm25Index, query: &SearchQuery, bound: bool) -> SearchResult {
    if bound {
        index.search_with_catalog(query, CATALOG).unwrap()
    } else {
        index.search(query).unwrap()
    }
}
#[test]
fn insert_modify_remove_and_trust_changes_match_full_rebuild_exactly() {
    for bound in [false, true] {
        let mut doc = document(vec![
            asset("a", "rust parser"),
            asset("b", "javascript parser"),
            asset("c", "rust concurrency"),
        ]);
        let mut index = Bm25Index::from_json(&bytes(&doc, bound)).unwrap();
        for change in 0..6 {
            match change {
                0 => doc.assets.push(asset("d", "rust parser parser tests")),
                1 => doc.assets[0].description = "new rust parser input".into(),
                2 => {
                    doc.assets.remove(1);
                }
                3 => doc.assets[0].trust = SkillTrust::Untrusted,
                4 => doc.assets[0].trust = SkillTrust::Blocked,
                _ => doc.assets.clear(),
            }
            let next = bytes(&doc, bound);
            let old = index.source_hash().to_owned();
            let report = index.refresh_from_json(&next, &old).unwrap();
            let rebuild = Bm25Index::from_json(&next).unwrap();
            assert_eq!(index.source_hash(), rebuild.source_hash());
            assert_eq!(index.index_hash(), rebuild.index_hash());
            assert_eq!(report.index_hash, index.index_hash());
            for text in [
                "rust parser",
                "javascript",
                "blocked query",
                "\"rust parser\"",
                "unknown",
                "",
            ] {
                for top_k in [1, 5] {
                    let mut query = SearchQuery::new(text);
                    query.top_k = top_k;
                    assert_eq!(
                        search(&index, &query, bound),
                        search(&rebuild, &query, bound),
                        "change {change}, {text}"
                    );
                }
            }
            assert_eq!(
                report.retokenized_assets,
                if change == 2 || change == 4 || change == 5 {
                    0
                } else {
                    1
                }
            );
        }
    }
}
#[test]
fn canonical_noop_retains_postings_and_invalid_update_is_atomic() {
    let mut doc = document(vec![asset("a", "needle"), asset("b", "needle")]);
    let mut index = Bm25Index::build_bound(doc.clone(), CATALOG).unwrap();
    let original = index.source_hash().to_owned();
    let result = index
        .search_with_catalog(&SearchQuery::new("needle"), CATALOG)
        .unwrap();
    doc.assets.reverse();
    let report = index
        .refresh_from_json(&bytes(&doc, true), &original)
        .unwrap();
    assert_eq!(
        (
            report.inserted,
            report.updated,
            report.removed,
            report.retokenized_assets
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(index.source_hash(), original);
    doc.assets[0].description = "changed".into();
    assert!(matches!(
        index.refresh_from_json(&bytes(&doc, true), &"0".repeat(64)),
        Err(RetrievalError::Stale)
    ));
    assert!(index.refresh_from_json(b"{malformed", &original).is_err());
    assert!(
        index
            .refresh_from_json(&bytes(&doc, false), &original)
            .is_err()
    );
    assert_eq!(
        index
            .search_with_catalog(&SearchQuery::new("needle"), CATALOG)
            .unwrap(),
        result
    );
}
#[test]
fn content_catalog_and_body_references_change_hash_without_body_io() {
    let mut doc = document(vec![asset("a", "needle")]);
    let mut index = Bm25Index::build_bound(doc.clone(), CATALOG).unwrap();
    let old = index.source_hash().to_owned();
    doc.assets[0].body = Some(BodyReference {
        path: "missing/body.md".into(),
        sha256: "b".repeat(64),
    });
    let changed = MetadataEnvelope::new(doc, "c".repeat(64).as_str()).unwrap();
    let report = index
        .refresh_from_json(&changed.canonical_json().unwrap(), &old)
        .unwrap();
    assert_eq!(report.updated, 1);
    assert_ne!(old, index.source_hash());
    assert!(matches!(
        index.search_with_catalog(&SearchQuery::new("needle"), CATALOG),
        Err(RetrievalError::CatalogMismatch)
    ));
    assert_eq!(
        index
            .search_with_catalog(&SearchQuery::new("needle"), &"c".repeat(64))
            .unwrap()
            .selected
            .unwrap()
            .id,
        "a"
    );
}
fn hit(id: &str, kind: AssetKind, score: u64) -> RankedHit {
    RankedHit {
        asset: AssetKey {
            kind,
            id: id.into(),
        },
        score_micros: score,
    }
}
fn source(id: &str, hits: Vec<RankedHit>) -> RankedSource {
    RankedSource {
        id: id.into(),
        weight_micros: 1_000_000,
        hits,
    }
}
#[test]
fn rrf_is_deterministic_deduplicated_and_preserves_each_source_score() {
    let a = hit("a", AssetKind::Skill, 20);
    let b = hit("b", AssetKind::Skill, 900);
    let lexical = source("bm25", vec![a.clone(), a.clone(), b.clone()]);
    let semantic = source("semantic", vec![b.clone(), a.clone(), b.clone()]);
    let config = RrfConfig::default();
    let forward = fuse_rankings(&[lexical.clone(), semantic.clone()], config).unwrap();
    assert_eq!(
        forward,
        fuse_rankings(&[semantic, lexical], config).unwrap()
    );
    assert_eq!(forward.len(), 2);
    assert_eq!(forward[0].asset.id, "a");
    assert_eq!(
        forward[0].rrf_score_nanos,
        1_000_000_000 / 61 + 1_000_000_000 / 62
    );
    assert_eq!(forward[0].rrf_score_nanos, forward[1].rrf_score_nanos);
    assert_eq!(forward[1].sources[0].rank, 2);
    assert_eq!(forward[1].sources[0].source_score_micros, 900);
    assert_eq!(forward[1].sources.len(), 2);
}
#[test]
fn rrf_weights_change_order_and_equal_ids_in_different_families_are_distinct() {
    let a = hit("a", AssetKind::Skill, 1);
    let b = hit("b", AssetKind::Skill, 1);
    let mut first = source("first", vec![a.clone(), b.clone()]);
    let mut second = source("second", vec![b.clone(), a]);
    first.weight_micros = 500_000;
    assert_eq!(
        fuse_rankings(&[first.clone(), second.clone()], RrfConfig::default()).unwrap()[0].asset,
        b.asset
    );
    second.weight_micros = 100_000;
    assert_eq!(
        fuse_rankings(&[first, second], RrfConfig::default()).unwrap()[0]
            .asset
            .id,
        "a"
    );
    assert_eq!(
        fuse_rankings(
            &[source(
                "one",
                vec![hit("a", AssetKind::Skill, 1), hit("a", AssetKind::Model, 1)]
            )],
            RrfConfig::default()
        )
        .unwrap()
        .len(),
        2
    );
}
#[test]
fn fusion_rejects_duplicate_sources_invalid_weights_and_unbounded_inputs() {
    let one = source("one", vec![hit("a", AssetKind::Skill, 1)]);
    assert!(fuse_rankings(&[one.clone(), one.clone()], RrfConfig::default()).is_err());
    let mut invalid = one.clone();
    invalid.weight_micros = 1_000_001;
    assert!(fuse_rankings(&[invalid], RrfConfig::default()).is_err());
    let mut invalid = one.clone();
    invalid.hits = vec![hit("a", AssetKind::Skill, 1); MAX_RANKED_HITS + 1];
    assert!(fuse_rankings(&[invalid], RrfConfig::default()).is_err());
    for config in [
        RrfConfig { k: 0, top_k: 5 },
        RrfConfig { k: 60, top_k: 0 },
        RrfConfig {
            k: 60,
            top_k: MAX_RESULTS + 1,
        },
    ] {
        assert!(fuse_rankings(std::slice::from_ref(&one), config).is_err());
    }
}
#[test]
fn term_limit_during_incremental_insertion_never_publishes_partial_postings() {
    let original = document(vec![asset("keep", "needle")]);
    let mut index = Bm25Index::build(original.clone()).unwrap();
    let before = index.search(&SearchQuery::new("needle")).unwrap();
    let expected = index.source_hash().to_owned();
    let mut successor = original;
    for i in 0..200 {
        let mut entry = asset(&format!("bulk-{i:03}"), &"x ".repeat(MAX_FIELD_BYTES / 2));
        entry.triggers = vec!["x ".repeat(MAX_FIELD_BYTES / 2)];
        entry.examples = vec!["x ".repeat(MAX_FIELD_BYTES / 2)];
        successor.assets.push(entry);
    }
    assert!(matches!(
        index.refresh_from_json(&bytes(&successor, false), &expected),
        Err(RetrievalError::Limit("index terms"))
    ));
    assert_eq!(index.source_hash(), expected);
    assert_eq!(index.len(), 1);
    assert_eq!(index.search(&SearchQuery::new("needle")).unwrap(), before);
    assert_eq!(
        index.search(&SearchQuery::new("x")).unwrap().abstention,
        Some(Abstention::NoMatches)
    );
}

#[test]
fn persistence_round_trip_keeps_source_schema_and_exact_index_hashes() {
    let metadata = document(vec![asset("b", "rust"), asset("a", "python")]);
    let signals = metadata
        .assets
        .iter()
        .map(|asset| AssetSignals {
            asset: asset.key(),
            languages: Signal::Unknown,
            required_tools: Signal::Unknown,
            history: Signal::Unknown,
        })
        .collect();
    for index in [
        Bm25Index::build(metadata.clone()).unwrap(),
        Bm25Index::build_bound(metadata.clone(), CATALOG).unwrap(),
        Bm25Index::build_v3(MetadataEnvelopeV3::new(metadata, signals, CATALOG).unwrap()).unwrap(),
    ] {
        let persisted = index.canonical_source_json().unwrap();
        let reopened = Bm25Index::from_json(&persisted).unwrap();
        assert_eq!(index.source_hash(), reopened.source_hash());
        assert_eq!(index.index_hash(), reopened.index_hash());
        assert_eq!(persisted, reopened.canonical_source_json().unwrap());
    }
}
