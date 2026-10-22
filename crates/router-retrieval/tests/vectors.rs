#![cfg(feature = "semantic-ranking")]
use router_retrieval::*;

const CATALOG: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn provenance() -> SignalProvenance {
    SignalProvenance {
        source_id: "synthetic-fixture".into(),
        source_version: "1".into(),
        source_sha256: "b".repeat(64),
        observed_at_unix_seconds: 100,
    }
}
fn asset(id: &str) -> AssetMetadata {
    serde_json::from_value(serde_json::json!({"id":id,"kind":"model","trust":"trusted_local","description":"database migration"})).unwrap()
}
fn key(id: &str) -> AssetKey {
    AssetKey {
        kind: AssetKind::Model,
        id: id.into(),
    }
}
fn index(ids: &[&str]) -> Bm25Index {
    let assets: Vec<_> = ids.iter().map(|id| asset(id)).collect();
    let signals = assets
        .iter()
        .map(|a| AssetSignals {
            asset: a.key(),
            languages: Signal::Unknown,
            required_tools: Signal::Observed {
                value: vec![],
                provenance: provenance(),
            },
            history: Signal::Unknown,
        })
        .collect();
    Bm25Index::build_v3(
        MetadataEnvelopeV3::new(
            MetadataDocument {
                schema_version: "1".into(),
                catalog_version: "fixtures-v1".into(),
                assets,
            },
            signals,
            CATALOG,
        )
        .unwrap(),
    )
    .unwrap()
}
fn query() -> ContextSearchQuery {
    let mut q = ContextSearchQuery::new(SearchQuery::new("database"), provenance(), 110);
    q.semantic_policy = SemanticPolicy::Required;
    q
}
fn set(index: &Bm25Index, vectors: Vec<(&str, Vec<i32>)>) -> AssetVectorSet {
    AssetVectorSet {
        schema_version: 1,
        index_hash: index.index_hash().into(),
        dimension: vectors.first().map_or(2, |v| v.1.len()),
        vectors: vectors
            .into_iter()
            .map(|(id, components)| AssetVector {
                asset: key(id),
                components,
            })
            .collect(),
    }
}
fn qvec(q: &ContextSearchQuery, components: Vec<i32>) -> QueryVector {
    QueryVector {
        schema_version: 1,
        query_hash: q.content_hash().unwrap(),
        components,
    }
}
fn rank(
    index: &Bm25Index,
    q: &ContextSearchQuery,
    s: &AssetVectorSet,
    v: &QueryVector,
) -> Result<SemanticRanking> {
    rank_semantic(index, q, s, v, provenance())
}
fn hits(r: &SemanticRanking) -> Vec<(&str, u64)> {
    r.hits
        .iter()
        .map(|h| (h.asset.id.as_str(), h.score_micros))
        .collect()
}

#[test]
fn exact_cosines_are_ranked_with_integer_floor() {
    let i = index(&["a", "b", "c", "d"]);
    let q = query();
    let s = set(
        &i,
        vec![
            ("a", vec![3, 4]),
            ("b", vec![1, 0]),
            ("c", vec![0, 5]),
            ("d", vec![-1, 0]),
        ],
    );
    let r = rank(&i, &q, &s, &qvec(&q, vec![1, 0])).unwrap();
    // cos(a)=0.6 exactly, cos(b)=1, cos(c)=0 and cos(d)=-1 are omitted.
    assert_eq!(hits(&r), vec![("b", 1_000_000), ("a", 600_000)]);
    assert_eq!(r.index_hash, i.index_hash());
    assert_eq!(r.query_hash, q.content_hash().unwrap());
}

#[test]
fn refuses_foreign_index_query_dimension_unknown_id_and_duplicates() {
    let i = index(&["a", "b"]);
    let q = query();
    let good = set(&i, vec![("a", vec![1, 1]), ("b", vec![1, 2])]);
    let v = qvec(&q, vec![1, 1]);
    assert!(rank(&i, &q, &good, &v).is_ok());

    let mut s = good.clone();
    s.index_hash = index(&["a", "b", "z"]).index_hash().into();
    assert!(rank(&i, &q, &s, &v).is_err());

    let mut other = query();
    other.query = SearchQuery::new("different");
    assert!(rank(&i, &q, &good, &qvec(&other, vec![1, 1])).is_err());

    assert!(rank(&i, &q, &good, &qvec(&q, vec![1, 1, 1])).is_err());
    let mut s = good.clone();
    s.vectors[1].components = vec![1];
    assert!(rank(&i, &q, &s, &v).is_err());
    let mut s = good.clone();
    s.dimension = 3;
    assert!(rank(&i, &q, &s, &v).is_err());

    let s = set(&i, vec![("a", vec![1, 1]), ("ghost", vec![1, 2])]);
    assert!(rank(&i, &q, &s, &v).is_err());
    let s = set(&i, vec![("a", vec![1, 1]), ("a", vec![1, 2])]);
    assert!(rank(&i, &q, &s, &v).is_err());
    let mut s = good.clone();
    s.schema_version = 2;
    assert!(rank(&i, &q, &s, &v).is_err());
    let mut bad = v.clone();
    bad.schema_version = 2;
    assert!(rank(&i, &q, &good, &bad).is_err());
}

#[test]
fn zero_vectors_and_dimension_bounds_are_refused() {
    let i = index(&["a"]);
    let q = query();
    let s = set(&i, vec![("a", vec![0, 0])]);
    assert!(rank(&i, &q, &s, &qvec(&q, vec![1, 1])).is_err());
    let s = set(&i, vec![("a", vec![1, 1])]);
    assert!(rank(&i, &q, &s, &qvec(&q, vec![0, 0])).is_err());
    let mut empty = s.clone();
    empty.dimension = 0;
    empty.vectors[0].components.clear();
    assert!(rank(&i, &q, &empty, &qvec(&q, vec![])).is_err());
    let big = MAX_VECTOR_DIMENSION + 1;
    let s = set(&i, vec![("a", vec![1; big])]);
    assert!(rank(&i, &q, &s, &qvec(&q, vec![1; big])).is_err());
}

#[test]
fn maximum_dimension_and_values_cannot_overflow() {
    let i = index(&["a", "b", "c"]);
    let q = query();
    let m = MAX_VECTOR_COMPONENT;
    let n = MAX_VECTOR_DIMENSION;
    let s = set(
        &i,
        vec![("a", vec![m; n]), ("b", vec![-m; n]), ("c", vec![m; n])],
    );
    let r = rank(&i, &q, &s, &qvec(&q, vec![m; n])).unwrap();
    assert_eq!(hits(&r), vec![("a", 1_000_000), ("c", 1_000_000)]);
    let mut over = s.clone();
    over.vectors[0].components[0] = m + 1;
    assert!(rank(&i, &q, &over, &qvec(&q, vec![m; n])).is_err());
    let mut under = s.clone();
    under.vectors[0].components[0] = -m - 1;
    assert!(rank(&i, &q, &under, &qvec(&q, vec![m; n])).is_err());
    assert!(rank(&i, &q, &s, &qvec(&q, vec![i32::MIN; n])).is_err());
    assert!(rank(&i, &q, &s, &qvec(&q, vec![i32::MAX; n])).is_err());
}

#[test]
fn ties_use_canonical_asset_order_regardless_of_input_order() {
    let i = index(&["a", "b", "c"]);
    let q = query();
    let v = qvec(&q, vec![1, 0]);
    let forward = set(
        &i,
        vec![("a", vec![2, 0]), ("b", vec![5, 0]), ("c", vec![1, 0])],
    );
    let mut reversed = forward.clone();
    reversed.vectors.reverse();
    let r1 = rank(&i, &q, &forward, &v).unwrap();
    let r2 = rank(&i, &q, &reversed, &v).unwrap();
    assert_eq!(r1, r2);
    assert_eq!(
        hits(&r1),
        vec![("a", 1_000_000), ("b", 1_000_000), ("c", 1_000_000)]
    );
}

#[test]
fn ranking_is_capped_at_200_hits() {
    let ids: Vec<String> = (0..250).map(|n| format!("m{n:03}")).collect();
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let i = index(&refs);
    let q = query();
    let s = set(&i, refs.iter().map(|id| (*id, vec![1, 1])).collect());
    let r = rank(&i, &q, &s, &qvec(&q, vec![1, 1])).unwrap();
    assert_eq!(r.hits.len(), MAX_RANKED_HITS);
    assert_eq!(r.hits[0].asset.id, "m000");
    assert_eq!(r.hits[199].asset.id, "m199");
}

#[test]
fn matches_an_equivalent_hand_supplied_ranking_through_search() {
    let i = index(&["a", "b", "c"]);
    let q = query();
    let s = set(
        &i,
        vec![("a", vec![1, 1]), ("b", vec![1, 0]), ("c", vec![0, 1])],
    );
    let computed = rank(&i, &q, &s, &qvec(&q, vec![3, 1])).unwrap();
    // cos(b)=3/sqrt(10)=0.948683..., cos(a)=4/sqrt(20)=0.894427..., cos(c)=1/sqrt(10)=0.316227...
    let manual = SemanticRanking {
        schema_version: 1,
        index_hash: i.index_hash().into(),
        query_hash: q.content_hash().unwrap(),
        provenance: provenance(),
        hits: vec![
            RankedHit {
                asset: key("b"),
                score_micros: 948_683,
            },
            RankedHit {
                asset: key("a"),
                score_micros: 894_427,
            },
            RankedHit {
                asset: key("c"),
                score_micros: 316_227,
            },
        ],
    };
    assert_eq!(computed, manual);
    let by_hand = i
        .search_contextual_with_semantic(&q, CATALOG, Some(&manual))
        .unwrap();
    let by_code = i
        .search_contextual_with_semantic(&q, CATALOG, Some(&computed))
        .unwrap();
    assert_eq!(by_hand, by_code);
    assert_eq!(by_code.semantic_status, SemanticStatus::Applied);
}

#[test]
fn result_is_revalidated_by_search_and_kind_filter_is_applied() {
    let i = index(&["a"]);
    let mut q = query();
    let s = set(&i, vec![("a", vec![1, 1])]);
    let v = qvec(&q, vec![1, 1]);
    // Future-dated provenance is rejected by the existing search validation.
    let stale = SignalProvenance {
        observed_at_unix_seconds: 200,
        ..provenance()
    };
    let r = rank_semantic(&i, &q, &s, &v, stale).unwrap();
    assert!(matches!(
        i.search_contextual_with_semantic(&q, CATALOG, Some(&r)),
        Err(RetrievalError::SemanticInvalid)
    ));
    // A query restricted to another kind yields no hits rather than an invalid list.
    q.query.kind = Some(AssetKind::Skill);
    let v = qvec(&q, vec![1, 1]);
    let r = rank(&i, &q, &s, &v).unwrap();
    assert!(r.hits.is_empty());
}

#[test]
fn more_than_max_assets_vectors_is_a_limit_error() {
    let i = index(&["a"]);
    let q = query();
    let mut s = set(&i, vec![("a", vec![1])]);
    let template = s.vectors[0].clone();
    s.vectors = vec![template; MAX_ASSETS + 1];
    let v = qvec(&q, vec![1]);
    assert!(matches!(
        rank(&i, &q, &s, &v),
        Err(RetrievalError::Limit("asset vectors"))
    ));
    s.vectors.truncate(1);
    assert!(rank(&i, &q, &s, &v).is_ok());
}

#[test]
fn matching_requested_kind_keeps_the_hit() {
    let i = index(&["a"]);
    let mut q = query();
    q.query.kind = Some(AssetKind::Model);
    let s = set(&i, vec![("a", vec![1, 1])]);
    let r = rank(&i, &q, &s, &qvec(&q, vec![1, 1])).unwrap();
    assert_eq!(hits(&r), vec![("a", 1_000_000)]);
}
