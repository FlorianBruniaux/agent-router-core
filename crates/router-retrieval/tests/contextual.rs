//! Synthetic metadata and attested counts only. No real human evaluation claim.
use router_retrieval::*;
use router_types::{CapabilitySupport, SkillTrust, TaskKind};

const CATALOG: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn provenance() -> SignalProvenance {
    SignalProvenance {
        source_id: "synthetic-fixture".into(),
        source_version: "1".into(),
        source_sha256: "b".repeat(64),
        observed_at_unix_seconds: 100,
    }
}
fn observed<T>(value: T) -> Signal<T> {
    Signal::Observed {
        value,
        provenance: provenance(),
    }
}
fn asset(id: &str, kind: AssetKind) -> AssetMetadata {
    serde_json::from_value(serde_json::json!({"id":id,"kind":kind,"trust":"trusted_local","description":"database migration"})).unwrap()
}
fn signals(asset: &AssetMetadata) -> AssetSignals {
    AssetSignals {
        asset: asset.key(),
        languages: Signal::Unknown,
        required_tools: observed(vec![]),
        history: Signal::Unknown,
    }
}
fn envelope(assets: Vec<AssetMetadata>, signals: Vec<AssetSignals>) -> MetadataEnvelopeV3 {
    MetadataEnvelopeV3::new(
        MetadataDocument {
            schema_version: "1".into(),
            catalog_version: "fixtures-v1".into(),
            assets,
        },
        signals,
        CATALOG,
    )
    .unwrap()
}
fn query() -> ContextSearchQuery {
    ContextSearchQuery::new(SearchQuery::new("database"), provenance(), 110)
}
fn pair() -> (Vec<AssetMetadata>, Vec<AssetSignals>) {
    let assets = vec![asset("a", AssetKind::Model), asset("b", AssetKind::Model)];
    let signals = assets.iter().map(signals).collect();
    (assets, signals)
}
fn history(successes: u32, transport: u32) -> Signal<SuccessHistory> {
    observed(SuccessHistory {
        task_kind: TaskKind::Implement,
        language: Some("rust".into()),
        attempts: 10,
        verified_successes: successes,
        transport_successes: transport,
    })
}
#[test]
fn all_five_families_search_separately_without_loading_bodies() {
    let mut assets = Vec::new();
    for kind in [
        AssetKind::Agent,
        AssetKind::Skill,
        AssetKind::Prompt,
        AssetKind::Tool,
        AssetKind::Model,
    ] {
        let mut entry = asset("same-id", kind);
        if kind != AssetKind::Model {
            entry.body = Some(BodyReference {
                path: "nonexistent/secret.md".into(),
                sha256: "f".repeat(64),
            });
        }
        assets.push(entry);
    }
    let signals = assets.iter().map(signals).collect();
    let index = Bm25Index::build_v3(envelope(assets, signals)).unwrap();
    let results = index.search_families(&query(), CATALOG).unwrap();
    assert_eq!(results.len(), 5);
    for result in &results {
        assert_eq!(result.selected.as_ref().unwrap().id, "same-id");
        assert_eq!(result.candidates.len(), 1);
    }
    assert_eq!(results[4].selected.as_ref().unwrap().kind, AssetKind::Model);
    assert!(matches!(
        index.search_with_catalog(&query().query, CATALOG),
        Err(RetrievalError::ContextRequired)
    ));
    assert!(matches!(
        index.search_contextual(&query(), &"c".repeat(64)),
        Err(RetrievalError::CatalogMismatch)
    ));
    assert!(matches!(
        index.load_body_with_catalog(
            std::path::Path::new("/missing"),
            AssetKind::Model,
            "same-id",
            CATALOG
        ),
        Err(RetrievalError::Selection)
    ));
}
#[test]
fn language_tool_and_verified_history_each_change_ranking_with_evidence() {
    for case in 0..3 {
        let (assets, mut signals) = pair();
        let baseline = Bm25Index::build_v3(envelope(assets.clone(), signals.clone())).unwrap();
        assert_eq!(
            baseline
                .search_contextual(&query(), CATALOG)
                .unwrap()
                .candidates[0]
                .fusion
                .asset
                .id,
            "a"
        );
        let mut query = query();
        match case {
            0 => {
                signals[1].languages = observed(vec!["rust".into()]);
                query.languages = vec!["rust".into()];
            }
            1 => {
                signals[1].required_tools = observed(vec!["cargo".into()]);
                query.required_tools = vec!["cargo".into()];
                query.available_tools.push(ToolObservation {
                    tool: "cargo".into(),
                    support: CapabilitySupport::Supported,
                    provenance: provenance(),
                });
            }
            _ => {
                signals[1].history = history(9, 10);
                query.task_kind = Some(TaskKind::Implement);
                query.languages = vec!["rust".into()];
            }
        }
        let index = Bm25Index::build_v3(envelope(assets, signals)).unwrap();
        let result = index.search_contextual(&query, CATALOG).unwrap();
        assert_eq!(result.selected.as_ref().unwrap().id, "b", "case {case}");
        let winner = &result.candidates[0];
        assert_eq!(winner.fusion.sources.len(), 2);
        assert!(
            winner
                .signals
                .iter()
                .any(|e| e.score_micros > 0 && e.provenance.as_ref() == Some(&provenance()))
        );
        assert_eq!(
            winner
                .fusion
                .sources
                .iter()
                .map(|s| s.contribution_nanos)
                .sum::<u64>(),
            winner.fusion.rrf_score_nanos
        );
    }
}
#[test]
fn c_plus_plus_and_c_sharp_remain_distinct_language_signals() {
    let (assets, mut signals) = pair();
    signals[0].languages = observed(vec!["c#".into()]);
    signals[1].languages = observed(vec!["c++".into()]);
    let index = Bm25Index::build_v3(envelope(assets, signals)).unwrap();
    let mut query = query();
    query.query.text = "database c++".into();
    query.query.policy.minimum_coverage_micros = 0;
    assert_eq!(
        index
            .search_contextual(&query, CATALOG)
            .unwrap()
            .selected
            .unwrap()
            .id,
        "b"
    );
}
#[test]
fn unknown_unsupported_missing_and_stale_tools_never_become_permissions() {
    for case in 0..5 {
        let (assets, mut signals) = pair();
        signals[0].required_tools = observed(vec!["cargo".into()]);
        let mut query = query();
        if case != 0 {
            query.available_tools.push(ToolObservation {
                tool: "cargo".into(),
                support: if case == 1 {
                    CapabilitySupport::Unsupported
                } else {
                    CapabilitySupport::Unknown
                },
                provenance: provenance(),
            });
        }
        if case == 3 {
            query.available_tools[0].support = CapabilitySupport::Supported;
            query.available_tools[0].provenance.observed_at_unix_seconds = 111;
        }
        if case == 4 {
            signals[0].required_tools = Signal::Unknown;
        }
        let result = Bm25Index::build_v3(envelope(assets, signals))
            .unwrap()
            .search_contextual(&query, CATALOG)
            .unwrap();
        assert_eq!(result.selected.unwrap().id, "b");
        assert_eq!(result.excluded_count, 1);
        assert_eq!(result.exclusions[0].asset.id, "a");
        assert_eq!(
            result.exclusions[0].reason,
            match case {
                1 => ContextExclusionReason::ToolUnsupported,
                4 => ContextExclusionReason::RequiredToolsUnknown,
                _ => ContextExclusionReason::ToolUnknown,
            }
        );
    }
}
#[test]
fn stale_requirements_exclude_but_stale_soft_evidence_remains_unknown() {
    let (assets, mut signals) = pair();
    signals[0].languages = Signal::Observed {
        value: vec!["rust".into()],
        provenance: SignalProvenance {
            observed_at_unix_seconds: 0,
            ..provenance()
        },
    };
    signals[0].history = history(10, 10);
    if let Signal::Observed { provenance, .. } = &mut signals[0].history {
        provenance.observed_at_unix_seconds = 111;
    }
    if let Signal::Observed { provenance, .. } = &mut signals[1].required_tools {
        provenance.observed_at_unix_seconds = 0;
    }
    let index = Bm25Index::build_v3(envelope(assets, signals)).unwrap();
    let mut query = query();
    query.max_signal_age_seconds = 10;
    query.languages = vec!["rust".into()];
    query.task_kind = Some(TaskKind::Implement);
    let result = index.search_contextual(&query, CATALOG).unwrap();
    assert_eq!(result.selected.unwrap().id, "a");
    assert_eq!(
        result.exclusions[0].reason,
        ContextExclusionReason::RequiredToolsStale
    );
    for signal in [
        &result.candidates[0].signals[0],
        &result.candidates[0].signals[2],
    ] {
        assert_eq!(signal.status, SignalStatus::Stale);
        assert_eq!(signal.score_micros, 0);
    }
}
#[test]
fn transport_success_low_sample_count_and_wrong_task_do_not_boost_verified_history() {
    for case in 0..3 {
        let (assets, mut signals) = pair();
        signals[1].history = history(0, 10);
        if let Signal::Observed { value, .. } = &mut signals[1].history {
            if case == 1 {
                value.attempts = 1;
                value.verified_successes = 1;
                value.transport_successes = 1;
            }
            if case == 2 {
                value.verified_successes = 10;
                value.task_kind = TaskKind::Review;
            }
        }
        let mut query = query();
        query.task_kind = Some(TaskKind::Implement);
        query.languages = vec!["rust".into()];
        let result = Bm25Index::build_v3(envelope(assets, signals))
            .unwrap()
            .search_contextual(&query, CATALOG)
            .unwrap();
        assert_eq!(result.candidates[0].fusion.asset.id, "a");
        assert_eq!(result.candidates[1].signals[2].score_micros, 0);
        assert_eq!(result.abstention, Some(Abstention::Ambiguous));
    }
}
#[test]
fn untrusted_signals_cannot_displace_trusted_matches_and_exclusions_are_stable() {
    let (mut assets, mut signals) = pair();
    assets[0].trust = SkillTrust::Untrusted;
    signals[0].languages = observed(vec!["rust".into()]);
    signals[0].history = history(10, 10);
    let mut query = query();
    query.languages = vec!["rust".into()];
    query.task_kind = Some(TaskKind::Implement);
    let result = Bm25Index::build_v3(envelope(assets, signals))
        .unwrap()
        .search_contextual(&query, CATALOG)
        .unwrap();
    assert_eq!(result.selected.unwrap().id, "b");
    assert_eq!(
        result.exclusions[0].reason,
        ContextExclusionReason::Untrusted
    );
}
#[test]
fn canonical_envelope_binds_signals_provenance_and_rejects_bad_counts_unknown_fields_and_duplicates()
 {
    let (assets, mut signals) = pair();
    signals[0].languages = observed(vec!["rust".into(), "python".into()]);
    let doc = envelope(assets.clone(), signals.clone());
    signals.reverse();
    let mut reversed = assets;
    reversed.reverse();
    assert_eq!(
        doc.canonical_json().unwrap(),
        envelope(reversed, signals).canonical_json().unwrap()
    );
    let mut changed = doc.clone();
    if let Signal::Observed { provenance, .. } = &mut changed.signals[0].languages {
        provenance.source_version = "2".into();
    }
    assert!(matches!(
        Bm25Index::build_v3(changed),
        Err(RetrievalError::Stale)
    ));
    let mut bad = doc.clone();
    bad.signals[0].history = history(11, 10);
    assert!(MetadataEnvelopeV3::new(bad.metadata, bad.signals, CATALOG).is_err());
    let mut bad = doc.clone();
    bad.signals[0].history = history(1, MAX_HISTORY_SAMPLES + 1);
    assert!(MetadataEnvelopeV3::new(bad.metadata, bad.signals, CATALOG).is_err());
    let mut bad = doc.clone();
    bad.signals[1].asset = bad.signals[0].asset.clone();
    assert!(MetadataEnvelopeV3::new(bad.metadata, bad.signals, CATALOG).is_err());
    let json = String::from_utf8(doc.canonical_json().unwrap()).unwrap();
    assert!(
        Bm25Index::from_json(
            json.replacen(
                "\"schema_version\":\"3\"",
                "\"schema_version\":\"3\",\"schema_version\":\"3\"",
                1
            )
            .as_bytes()
        )
        .is_err()
    );
    assert!(
        Bm25Index::from_json(
            json.replacen("\"signals\":", "\"unknown\":1,\"signals\":", 1)
                .as_bytes()
        )
        .is_err()
    );
}
#[test]
fn query_and_signal_bounds_are_explicit_and_rejected_before_ranking() {
    let (assets, signals) = pair();
    let index = Bm25Index::build_v3(envelope(assets.clone(), signals.clone())).unwrap();
    for case in 0..5 {
        let mut query = query();
        match case {
            0 => query.languages = vec!["rust".into(); MAX_LIST_ITEMS + 1],
            1 => query.provenance.observed_at_unix_seconds = 111,
            2 => query.max_signal_age_seconds = MAX_SIGNAL_AGE_SECONDS + 1,
            3 => query.minimum_history_samples = 0,
            _ => query.rrf_k = 0,
        };
        assert!(index.search_contextual(&query, CATALOG).is_err());
    }
    let mut signals = signals;
    signals[0].languages = observed(vec!["rust".into(); MAX_LIST_ITEMS + 1]);
    assert!(
        MetadataEnvelopeV3::new(
            MetadataDocument {
                schema_version: "1".into(),
                catalog_version: "1".into(),
                assets
            },
            signals,
            CATALOG
        )
        .is_err()
    );
}
fn semantic(
    index: &Bm25Index,
    query: &ContextSearchQuery,
    hits: Vec<RankedHit>,
) -> SemanticRanking {
    SemanticRanking {
        schema_version: 1,
        index_hash: index.index_hash().into(),
        query_hash: query.content_hash().unwrap(),
        provenance: provenance(),
        hits,
    }
}
#[test]
fn optional_semantic_source_is_off_by_default_with_explicit_errors_or_fallback() {
    let (assets, signals) = pair();
    let index = Bm25Index::build_v3(envelope(assets, signals)).unwrap();
    let mut query = query();
    let rank = semantic(&index, &query, vec![]);
    assert!(matches!(
        index.search_contextual_with_semantic(&query, CATALOG, Some(&rank)),
        Err(RetrievalError::SemanticInvalid)
    ));
    query.semantic_policy = SemanticPolicy::Required;
    assert!(matches!(
        index.search_contextual(&query, CATALOG),
        Err(RetrievalError::SemanticUnavailable)
    ));
    query.semantic_policy = SemanticPolicy::LexicalFallback;
    assert_eq!(
        index
            .search_contextual(&query, CATALOG)
            .unwrap()
            .semantic_status,
        SemanticStatus::UnavailableFallback
    );
    #[cfg(not(feature = "semantic-ranking"))]
    {
        let rank = semantic(&index, &query, vec![]);
        assert_eq!(
            index
                .search_contextual_with_semantic(&query, CATALOG, Some(&rank))
                .unwrap()
                .semantic_status,
            SemanticStatus::UnavailableFallback
        );
    }
}
#[cfg(feature = "semantic-ranking")]
#[test]
fn explicit_semantic_ranking_is_bound_filtered_and_never_revives_ineligible_assets() {
    let (mut assets, mut signals) = pair();
    assets.push(asset("blocked", AssetKind::Model));
    signals.push(signals::for_asset(&assets[2]));
    assets[2].trust = SkillTrust::Blocked;
    signals[0].required_tools = observed(vec!["unknown-tool".into()]);
    let index = Bm25Index::build_v3(envelope(assets, signals)).unwrap();
    let mut query = query();
    query.semantic_policy = SemanticPolicy::Required;
    let hits = ["blocked", "a", "b", "b"]
        .into_iter()
        .map(|id| RankedHit {
            asset: AssetKey {
                kind: AssetKind::Model,
                id: id.into(),
            },
            score_micros: 1,
        })
        .collect();
    let mut rank = semantic(&index, &query, hits);
    let result = index
        .search_contextual_with_semantic(&query, CATALOG, Some(&rank))
        .unwrap();
    assert_eq!(result.selected.unwrap().id, "b");
    assert_eq!(result.candidates.len(), 1);
    assert_eq!(result.excluded_count, 2);
    assert_eq!(
        result.candidates[0]
            .fusion
            .sources
            .iter()
            .filter(|s| s.source == "semantic")
            .count(),
        1
    );
    rank.index_hash = "c".repeat(64);
    assert!(matches!(
        index.search_contextual_with_semantic(&query, CATALOG, Some(&rank)),
        Err(RetrievalError::SemanticInvalid)
    ));
    query.semantic_policy = SemanticPolicy::LexicalFallback;
    assert_eq!(
        index
            .search_contextual_with_semantic(&query, CATALOG, Some(&rank))
            .unwrap()
            .semantic_status,
        SemanticStatus::InvalidFallback
    );
}
#[cfg(feature = "semantic-ranking")]
mod signals {
    use super::*;
    pub fn for_asset(asset: &AssetMetadata) -> AssetSignals {
        super::signals(asset)
    }
}
#[test]
fn signal_only_update_is_atomic_hash_bound_and_does_not_retokenize_metadata() {
    let (assets, mut values) = pair();
    let before = envelope(assets.clone(), values.clone());
    let mut index = Bm25Index::build_v3(before.clone()).unwrap();
    let old = index.source_hash().to_owned();
    values[1].languages = observed(vec!["rust".into()]);
    let next = envelope(assets, values);
    let report = index
        .refresh_from_json(&next.canonical_json().unwrap(), &old)
        .unwrap();
    assert_eq!(report.retokenized_assets, 0);
    assert_eq!(report.updated, 1);
    assert_ne!(index.source_hash(), old);
    let rebuilt = Bm25Index::build_v3(next).unwrap();
    let mut query = query();
    query.languages = vec!["rust".into()];
    assert_eq!(
        index.search_contextual(&query, CATALOG).unwrap(),
        rebuilt.search_contextual(&query, CATALOG).unwrap()
    );
    assert_eq!(
        index
            .search_contextual(&query, CATALOG)
            .unwrap()
            .selected
            .unwrap()
            .id,
        "b"
    );
    assert!(!index.is_current(&before.canonical_json().unwrap()).unwrap());
    assert!(matches!(
        index.search_contextual_current_with_catalog(
            &before.canonical_json().unwrap(),
            &query,
            CATALOG
        ),
        Err(RetrievalError::Stale)
    ));
    query.weights.languages = 0;
    assert_eq!(
        index.search_contextual(&query, CATALOG).unwrap().abstention,
        Some(Abstention::Ambiguous)
    );
}
#[cfg(feature = "semantic-ranking")]
#[test]
fn semantic_only_matches_still_obey_phrase_and_anti_trigger_exclusions() {
    let (mut assets, values) = pair();
    assets[0].anti_triggers = vec!["never enable".into()];
    let index = Bm25Index::build_v3(envelope(assets, values)).unwrap();
    let mut query = query();
    query.query.text = "\"missing phrase\"".into();
    query.semantic_policy = SemanticPolicy::Required;
    let hits = vec![RankedHit {
        asset: AssetKey {
            kind: AssetKind::Model,
            id: "a".into(),
        },
        score_micros: 1_000_000,
    }];
    let rank = semantic(&index, &query, hits.clone());
    let result = index
        .search_contextual_with_semantic(&query, CATALOG, Some(&rank))
        .unwrap();
    assert!(result.candidates.is_empty());
    assert_eq!(result.excluded_count, 2);
    assert!(
        result
            .exclusions
            .iter()
            .all(|e| e.reason == ContextExclusionReason::RequiredPhraseMissing)
    );
    query.query.text = "never enable".into();
    let rank = semantic(&index, &query, hits);
    let result = index
        .search_contextual_with_semantic(&query, CATALOG, Some(&rank))
        .unwrap();
    assert!(result.candidates.is_empty());
    assert_eq!(
        result.exclusions[0].reason,
        ContextExclusionReason::AntiTrigger
    );
}
#[test]
fn lexical_confidence_is_not_replaced_with_compressed_rrf_rank_distances() {
    let (mut assets, values) = pair();
    assets[0].triggers = vec!["database database database".into()];
    let base = Bm25Index::build_bound(
        MetadataDocument {
            schema_version: "1".into(),
            catalog_version: "1".into(),
            assets: assets.clone(),
        },
        CATALOG,
    )
    .unwrap();
    let query = query();
    let expected = base.search_with_catalog(&query.query, CATALOG).unwrap();
    assert_eq!(expected.selected.as_ref().unwrap().id, "a");
    let result = Bm25Index::build_v3(envelope(assets, values))
        .unwrap()
        .search_contextual(&query, CATALOG)
        .unwrap();
    assert_eq!(result.selected, expected.selected);
    assert_eq!(result.abstention, expected.abstention);
}
#[test]
fn quoted_language_and_tool_fields_match_only_fresh_metadata() {
    let (assets, mut values) = pair();
    values[1].languages = observed(vec!["c++".into()]);
    values[1].required_tools = observed(vec!["cargo".into()]);
    let index = Bm25Index::build_v3(envelope(assets, values)).unwrap();
    let mut query = query();
    query.available_tools = vec![ToolObservation {
        tool: "cargo".into(),
        support: CapabilitySupport::Supported,
        provenance: provenance(),
    }];
    for text in ["\"c++\"", "\"cargo\""] {
        query.query.text = text.into();
        let result = index.search_contextual(&query, CATALOG).unwrap();
        assert_eq!(result.selected.unwrap().id, "b");
        assert_eq!(result.exclusions[0].asset.id, "a");
        assert!(result.candidates[0].lexical.is_none());
    }
}
