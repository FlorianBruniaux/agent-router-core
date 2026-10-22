use router_retrieval::*;
use router_types::{SkillTrust, TaskKind};
use std::fs;

fn asset(id: &str, description: &str) -> AssetMetadata {
    AssetMetadata {
        id: id.into(),
        kind: AssetKind::Skill,
        trust: SkillTrust::TrustedLocal,
        task_kinds: vec![],
        triggers: vec![],
        description: description.into(),
        examples: vec![],
        tags: vec![],
        paths: vec![],
        anti_triggers: vec![],
        body: None,
    }
}

fn document(assets: Vec<AssetMetadata>) -> MetadataDocument {
    MetadataDocument {
        schema_version: "1".into(),
        catalog_version: "fixture-v1".into(),
        assets,
    }
}

fn index(assets: Vec<AssetMetadata>) -> Bm25Index {
    Bm25Index::build(document(assets)).unwrap()
}

#[test]
fn positive_score_has_additive_field_and_term_evidence() {
    let mut entry = asset("rust-tests", "regression fixtures");
    entry.triggers = vec!["regression".into()];
    entry.examples = vec!["a regression parser".into()];
    let index = index(vec![entry]);
    let query = SearchQuery::new("regression");
    let result = index.search(&query).unwrap();
    assert_eq!(result.abstention, None);
    assert_eq!(result.selected.as_ref().unwrap().id, "rust-tests");
    let candidate = &result.candidates[0];
    assert_eq!(
        candidate.fields.iter().map(|f| f.score_micros).sum::<u64>(),
        candidate.bm25_micros
    );
    assert_eq!(
        candidate
            .evidence
            .iter()
            .map(|f| f.contribution_micros)
            .sum::<u64>(),
        candidate.bm25_micros
    );
    assert!(
        candidate
            .evidence
            .iter()
            .any(|e| e.field == Field::Triggers && e.boost_millis == 5000)
    );
    assert!(candidate.route_utility_micros > 0 && candidate.route_utility_micros < 1_000_000);
    let serialized = serde_json::to_vec(&result).unwrap();
    for _ in 0..8 {
        assert_eq!(
            serialized,
            serde_json::to_vec(&index.search(&query).unwrap()).unwrap()
        );
    }
}

#[test]
fn each_metadata_field_is_searchable_with_its_declared_boost() {
    let mut entry = asset("identifierword", "descriptionword");
    entry.task_kinds = vec![TaskKind::Security];
    entry.triggers = vec!["triggerword".into()];
    entry.examples = vec!["exampleword".into()];
    entry.tags = vec!["tagword".into()];
    entry.paths = vec!["src/pathword.rs".into()];
    let index = index(vec![entry]);
    for (query, field, boost) in [
        ("identifierword", Field::Identifier, 8000),
        ("security", Field::TaskKinds, 6000),
        ("triggerword", Field::Triggers, 5000),
        ("descriptionword", Field::Description, 3000),
        ("exampleword", Field::Examples, 2500),
        ("tagword", Field::Tags, 2000),
        ("src/pathword.rs", Field::Paths, 2000),
    ] {
        let result = index.search(&SearchQuery::new(query)).unwrap();
        assert!(
            result.candidates[0]
                .evidence
                .iter()
                .any(|e| e.field == field && e.boost_millis == boost)
        );
    }
}

#[test]
fn boosts_and_term_frequency_saturation_affect_ranking() {
    let mut trigger = asset("a", "");
    trigger.triggers = vec!["needle".into()];
    let description = asset("b", "needle");
    let index = index(vec![description, trigger]);
    let result = index.search(&SearchQuery::new("needle")).unwrap();
    assert_eq!(result.candidates[0].asset.id, "a");
    assert!(result.candidates[0].bm25_micros > result.candidates[1].bm25_micros);
    let one = self::index(vec![asset("a", "needle")])
        .search(&SearchQuery::new("needle"))
        .unwrap();
    let repeated = self::index(vec![asset("a", &"needle ".repeat(100))])
        .search(&SearchQuery::new("needle"))
        .unwrap();
    assert!(repeated.candidates[0].bm25_micros < one.candidates[0].bm25_micros * 3);
}

#[test]
fn untrusted_corpus_does_not_change_trusted_scores_or_displace_top_k() {
    let trusted_asset = asset("trusted", "parser regression fixtures");
    let baseline = index(vec![trusted_asset.clone()]);
    let mut assets = vec![trusted_asset];
    for i in 0..100 {
        let mut untrusted = asset(
            &format!("untrusted-{i}"),
            "parser regression fixtures parser regression fixtures",
        );
        untrusted.triggers = vec!["parser regression fixtures".into()];
        untrusted.trust = SkillTrust::Untrusted;
        assets.push(untrusted);
    }
    let polluted = index(assets);
    let mut query = SearchQuery::new("parser regression");
    query.top_k = 1;
    let before = baseline.search(&query).unwrap();
    let after = polluted.search(&query).unwrap();
    assert_eq!(before.candidates, after.candidates);
    assert_eq!(before.abstention, after.abstention);
    assert_eq!(before.selected, after.selected);
    assert_eq!(
        polluted.skill_candidates(&query).unwrap()[0].skill.as_str(),
        "trusted"
    );
    query.top_k = 50;
    let result = polluted.search(&query).unwrap();
    assert!(
        result
            .candidates
            .iter()
            .filter(|c| c.trust == SkillTrust::Untrusted)
            .all(|c| c.route_utility_micros == 0)
    );
}

#[test]
fn blocked_assets_are_excluded_and_untrusted_only_abstains() {
    let mut blocked = asset("blocked", "PRIVATE_SENTINEL needle");
    blocked.trust = SkillTrust::Blocked;
    let mut untrusted = asset("untrusted", "needle");
    untrusted.trust = SkillTrust::Untrusted;
    let index = index(vec![blocked, untrusted]);
    let query = SearchQuery::new("needle");
    let result = index.search(&query).unwrap();
    assert_eq!(result.abstention, Some(Abstention::UntrustedOnly));
    assert_eq!(result.candidates.len(), 1);
    assert_eq!(result.candidates[0].route_utility_micros, 0);
    assert_eq!(result.exclusions[0].reason, ExclusionReason::Blocked);
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains("PRIVATE_SENTINEL")
    );
    assert!(index.skill_candidates(&query).unwrap().is_empty());
}

#[test]
fn empty_no_match_weak_and_ambiguous_are_distinct() {
    let index = index(vec![
        asset("a", "ownership review"),
        asset("b", "ownership review"),
    ]);
    assert_eq!(
        index.search(&SearchQuery::new(" ")).unwrap().abstention,
        Some(Abstention::EmptyQuery)
    );
    assert_eq!(
        index
            .search(&SearchQuery::new("galaxy"))
            .unwrap()
            .abstention,
        Some(Abstention::NoMatches)
    );
    let mut query = SearchQuery::new("ownership");
    query.top_k = 1;
    assert_eq!(
        index.search(&query).unwrap().abstention,
        Some(Abstention::Ambiguous)
    );
    assert!(index.skill_candidates(&query).unwrap().is_empty());
    let result = index
        .search(&SearchQuery::new(
            "ownership foo bar baz qux galaxy ocean lemon orange plum",
        ))
        .unwrap();
    assert_eq!(result.abstention, Some(Abstention::WeakMatch));
    assert!(result.selected.is_none());
}

#[test]
fn anti_triggers_use_contiguous_whole_words() {
    let mut entry = asset("release", "release stylesheet style deployment");
    entry.anti_triggers = vec!["production deploy".into(), "style".into()];
    let index = index(vec![entry]);
    assert_eq!(
        index
            .search(&SearchQuery::new("release production deploy"))
            .unwrap()
            .abstention,
        Some(Abstention::NoMatches)
    );
    assert_eq!(
        index
            .search(&SearchQuery::new("release style"))
            .unwrap()
            .exclusions[0]
            .reason,
        ExclusionReason::AntiTrigger
    );
    assert_eq!(
        index
            .search(&SearchQuery::new("stylesheet"))
            .unwrap()
            .abstention,
        None
    );
    assert_eq!(
        index
            .search(&SearchQuery::new("release deploy production"))
            .unwrap()
            .abstention,
        None
    );
}

#[test]
fn quoted_phrases_paths_and_symbols_are_retained() {
    let mut exact = asset("exact", "transaction isolation C++ foo::bar");
    exact.paths = vec!["src/router.rs".into()];
    let index = index(vec![
        exact,
        asset("split", "transaction unrelated isolation"),
    ]);
    let result = index
        .search(&SearchQuery::new("\"transaction isolation\""))
        .unwrap();
    assert_eq!(result.candidates.len(), 1);
    assert_eq!(
        result.candidates[0].phrase_evidence[0].phrase,
        "transaction isolation"
    );
    for term in ["C++", "foo::bar", "src/router.rs"] {
        let result = index.search(&SearchQuery::new(term)).unwrap();
        assert!(
            result.candidates[0]
                .evidence
                .iter()
                .any(|e| e.term == term.to_lowercase())
        );
    }
}

#[test]
fn kinds_are_separate_and_canonical_hashes_ignore_order() {
    let skill = asset("same", "rust");
    let mut tool = skill.clone();
    tool.kind = AssetKind::Tool;
    let mut other = asset("other", "network");
    other.tags = vec!["z".into(), "a".into()];
    let a = index(vec![skill.clone(), other.clone(), tool.clone()]);
    other.tags.reverse();
    let b = index(vec![tool, other, skill]);
    assert_eq!(a.source_hash(), b.source_hash());
    assert_eq!(a.index_hash(), b.index_hash());
    let mut query = SearchQuery::new("rust");
    query.kind = Some(AssetKind::Tool);
    let result = a.search(&query).unwrap();
    assert_eq!(result.candidates.len(), 1);
    assert_eq!(result.candidates[0].asset.kind, AssetKind::Tool);
    let single = index(vec![asset("same", "rust"), asset("other", "network")]);
    query.kind = Some(AssetKind::Skill);
    assert_eq!(
        a.search(&query).unwrap().candidates[0].bm25_micros,
        single.search(&query).unwrap().candidates[0].bm25_micros
    );
}

#[test]
fn index_invalidation_tracks_catalog_trust_metadata_and_body_hash() {
    let mut doc = document(vec![asset("a", "rust")]);
    let index = Bm25Index::build(doc.clone()).unwrap();
    assert!(
        index
            .is_current(&serde_json::to_vec_pretty(&doc).unwrap())
            .unwrap()
    );
    doc.catalog_version = "fixture-v2".into();
    assert!(
        !index
            .is_current(&serde_json::to_vec(&doc).unwrap())
            .unwrap()
    );
    assert!(matches!(
        index.search_current(
            &serde_json::to_vec(&doc).unwrap(),
            &SearchQuery::new("rust")
        ),
        Err(RetrievalError::Stale)
    ));
    doc.catalog_version = "fixture-v1".into();
    doc.assets[0].trust = SkillTrust::Untrusted;
    assert!(
        !index
            .is_current(&serde_json::to_vec(&doc).unwrap())
            .unwrap()
    );
    doc.assets[0].trust = SkillTrust::TrustedLocal;
    doc.assets[0].body = Some(BodyReference {
        path: "missing.md".into(),
        sha256: "a".repeat(64),
    });
    assert!(
        !index
            .is_current(&serde_json::to_vec(&doc).unwrap())
            .unwrap()
    );
}

#[test]
fn malformed_unknown_oversized_duplicate_and_query_limits_fail_closed() {
    assert!(Bm25Index::from_json(b"not json").is_err());
    assert!(
        Bm25Index::from_json(
            br#"{"schema_version":"1","catalog_version":"v1","assets":[],"permissions":"allow"}"#
        )
        .is_err()
    );
    assert!(Bm25Index::build(document(vec![asset("same", "a"), asset("same", "b")])).is_err());
    assert!(Bm25Index::build(document(vec![asset("BAD ID", "a")])).is_err());
    assert!(
        Bm25Index::build(document(vec![asset("a", &"x".repeat(MAX_FIELD_BYTES + 1))])).is_err()
    );
    let index = index(vec![]);
    assert!(
        index
            .search(&SearchQuery::new("x".repeat(MAX_QUERY_BYTES + 1)))
            .is_err()
    );
    assert!(
        index
            .search(&SearchQuery::new(
                (0..65)
                    .map(|i| format!("term{i}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ))
            .is_err()
    );
    let mut query = SearchQuery::new("rust");
    query.top_k = MAX_RESULTS + 1;
    assert!(index.search(&query).is_err());
    query.top_k = 0;
    assert!(index.search(&query).is_err());
    query.top_k = 1;
    query.policy.minimum_coverage_micros = 1_000_001;
    assert!(index.search(&query).is_err());
}

#[test]
fn asset_count_list_count_and_index_work_limits_are_enforced() {
    assert!(matches!(
        Bm25Index::build(document(vec![asset("a", "rust"); MAX_ASSETS + 1])),
        Err(RetrievalError::Limit("asset count"))
    ));
    let mut entry = asset("a", "rust");
    entry.triggers = vec!["rust".into(); MAX_LIST_ITEMS + 1];
    assert!(matches!(
        Bm25Index::build(document(vec![entry])),
        Err(RetrievalError::Limit("metadata list items"))
    ));
    let entries = (0..501)
        .map(|i| asset(&format!("asset-{i}"), &"a ".repeat(4000)))
        .collect();
    assert!(matches!(
        Bm25Index::build(document(entries)),
        Err(RetrievalError::Limit("index terms"))
    ));
}

#[test]
fn exclusions_are_bounded_without_losing_total_count() {
    let assets = (0..60)
        .map(|i| {
            let mut entry = asset(&format!("asset-{i}"), "needle");
            entry.trust = SkillTrust::Blocked;
            entry
        })
        .collect();
    let result = index(assets).search(&SearchQuery::new("needle")).unwrap();
    assert_eq!(result.excluded_count, 60);
    assert_eq!(result.exclusions.len(), MAX_RESULTS);
    assert!(result.candidates.is_empty());
}

#[test]
fn build_and_search_never_load_bodies_and_selected_load_checks_hash() {
    use sha2::{Digest, Sha256};
    let text = "secret-body-term not indexed";
    let mut entry = asset("a", "rust metadata");
    entry.body = Some(BodyReference {
        path: "skill.md".into(),
        sha256: hex::encode(Sha256::digest(text.as_bytes())),
    });
    let index = index(vec![entry]);
    let root = tempfile::tempdir().unwrap();
    assert!(index.load_body(root.path(), AssetKind::Skill, "a").is_err());
    fs::write(root.path().join("skill.md"), text).unwrap();
    assert_eq!(
        index
            .search(&SearchQuery::new("secret-body-term"))
            .unwrap()
            .abstention,
        Some(Abstention::NoMatches)
    );
    assert_eq!(
        index
            .load_body(root.path(), AssetKind::Skill, "a")
            .unwrap()
            .text,
        text
    );
    fs::write(root.path().join("skill.md"), "changed bytes").unwrap();
    assert!(matches!(
        index.load_body(root.path(), AssetKind::Skill, "a"),
        Err(RetrievalError::BodyHashMismatch)
    ));
    fs::write(root.path().join("skill.md"), "x".repeat(MAX_BODY_BYTES + 1)).unwrap();
    assert!(matches!(
        index.load_body(root.path(), AssetKind::Skill, "a"),
        Err(RetrievalError::Limit(_))
    ));
}

#[test]
fn body_paths_and_untrusted_selections_are_refused() {
    for path in [
        "../private",
        "/etc/passwd",
        "a/../private",
        "a\\private",
        "a//b",
        "./a",
    ] {
        let mut entry = asset("a", "rust");
        entry.body = Some(BodyReference {
            path: path.into(),
            sha256: "a".repeat(64),
        });
        assert!(Bm25Index::build(document(vec![entry])).is_err(), "{path}");
    }
    for trust in [SkillTrust::Untrusted, SkillTrust::Blocked] {
        let mut entry = asset("a", "rust");
        entry.trust = trust;
        entry.body = Some(BodyReference {
            path: "not-read.md".into(),
            sha256: "a".repeat(64),
        });
        let index = index(vec![entry]);
        assert!(matches!(
            index.load_body(std::path::Path::new("missing-root"), AssetKind::Skill, "a"),
            Err(RetrievalError::Selection)
        ));
    }
}

#[cfg(unix)]
#[test]
fn symlink_body_and_ancestor_are_refused() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("file.md"), "private").unwrap();
    symlink(outside.path(), root.path().join("linked")).unwrap();
    symlink(outside.path().join("file.md"), root.path().join("file.md")).unwrap();
    for path in ["linked/file.md", "file.md"] {
        let mut entry = asset("a", "rust");
        entry.body = Some(BodyReference {
            path: path.into(),
            sha256: "a".repeat(64),
        });
        assert!(matches!(
            index(vec![entry]).load_body(root.path(), AssetKind::Skill, "a"),
            Err(RetrievalError::UnsafePath)
        ));
    }
}

#[derive(serde::Deserialize)]
struct Corpus {
    provenance: String,
    assets: Vec<AssetMetadata>,
    cases: Vec<Case>,
}
#[derive(serde::Deserialize)]
struct Case {
    label: String,
    query: String,
    kind: Option<AssetKind>,
    selected: Option<String>,
    abstention: Option<Abstention>,
}

#[test]
fn synthetic_labeled_corpus_covers_positive_negative_ambiguous_and_empty() {
    let corpus: Corpus = serde_json::from_slice(include_bytes!("fixtures/corpus.json")).unwrap();
    assert_eq!(
        corpus.provenance,
        "synthetic engineering fixtures; human validation NOT_DONE"
    );
    let index = index(corpus.assets);
    for case in corpus.cases {
        let mut query = SearchQuery::new(case.query);
        query.kind = case.kind;
        let result = index.search(&query).unwrap();
        assert_eq!(
            result.selected.map(|key| key.id),
            case.selected,
            "{}",
            case.label
        );
        assert_eq!(result.abstention, case.abstention, "{}", case.label);
    }
}

#[test]
fn quoted_technical_terms_preserve_language_identity() {
    let only_wrong_language = index(vec![asset("csharp", "C# library development")]);
    let result = only_wrong_language
        .search(&SearchQuery::new("\"C++\""))
        .unwrap();
    assert!(result.selected.is_none());
    assert!(result.candidates.is_empty());
    let both = index(vec![
        asset("csharp", "C# library development"),
        asset("cplusplus", "C++ library development"),
    ]);
    let result = both.search(&SearchQuery::new("\"C++\"")).unwrap();
    assert_eq!(result.selected.unwrap().id, "cplusplus");
    assert_eq!(result.candidates.len(), 1);
    assert_eq!(result.candidates[0].phrase_evidence[0].phrase, "c++");
}

#[test]
fn repeated_quoted_phrases_collapse_and_distinct_phrases_are_capped() {
    let index = index(vec![asset("rust-tests", "x regression fixtures")]);
    let single = index.search(&SearchQuery::new("\"x\"")).unwrap();
    let repeated = "\"x\" ".repeat(60);
    let flooded = index.search(&SearchQuery::new(&repeated)).unwrap();
    assert_eq!(flooded, single);
    assert_eq!(flooded.candidates[0].phrase_evidence.len(), 1);

    let phrases = |n: usize| {
        (0..n)
            .map(|i| format!("\"p{i}\""))
            .collect::<Vec<_>>()
            .join(" ")
    };
    assert!(
        index
            .search(&SearchQuery::new(phrases(MAX_QUERY_PHRASES)))
            .is_ok()
    );
    assert!(matches!(
        index.search(&SearchQuery::new(phrases(MAX_QUERY_PHRASES + 1))),
        Err(RetrievalError::Limit("query phrases"))
    ));
}

#[test]
fn index_hash_is_pinned_to_the_scoring_parameters() {
    let index = index(vec![asset("rust-tests", "regression fixtures")]);
    let result = index.search(&SearchQuery::new("regression")).unwrap();
    // Recorded before the parameters were derived from constants: the value
    // must not move unless a scoring parameter is deliberately changed.
    assert_eq!(
        result.index_hash,
        "c13a41bf68bbeb2c800aa6a3f218996b373d3dffe4a73540e4b163793a750b22"
    );
}
