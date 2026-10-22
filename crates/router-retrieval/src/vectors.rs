//! Deterministic integer cosine ranking over caller-supplied fixed-point vectors.
//! No embedding model, provider, I/O or floating point is involved.
use crate::{
    AssetKey, Bm25Index, ContextSearchQuery, MAX_ASSETS, MAX_RANKED_HITS, RankedHit, Result,
    RetrievalError, SemanticRanking, SignalProvenance,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const VECTOR_SCHEMA_VERSION: u32 = 1;
pub const MAX_VECTOR_DIMENSION: usize = 1024;
/// Components are fixed-point integers in `-MAX_VECTOR_COMPONENT..=MAX_VECTOR_COMPONENT`.
/// With dimension 1024 a dot product is below 2^40, its square below 2^80 and the
/// scaled numerator below 2^120, so every intermediate fits in `u128`.
pub const MAX_VECTOR_COMPONENT: i32 = 32_767;
const MICROS: u128 = 1_000_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetVector {
    pub asset: AssetKey,
    pub components: Vec<i32>,
}

/// Asset vectors bound to one exact index hash.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetVectorSet {
    pub schema_version: u32,
    pub index_hash: String,
    pub dimension: usize,
    pub vectors: Vec<AssetVector>,
}

/// Query vector bound to the canonical `ContextSearchQuery::content_hash`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryVector {
    pub schema_version: u32,
    pub query_hash: String,
    pub components: Vec<i32>,
}

fn invalid<T>() -> Result<T> {
    Err(RetrievalError::SemanticInvalid)
}

/// Squared norm after dimension and component bounds checks; zero vectors are refused.
fn norm_squared(components: &[i32], dimension: usize) -> Result<u128> {
    if components.len() != dimension {
        return invalid();
    }
    let mut sum = 0_u128;
    for c in components {
        if c.unsigned_abs() > MAX_VECTOR_COMPONENT.unsigned_abs() {
            return invalid();
        }
        sum += u128::from(c.unsigned_abs()) * u128::from(c.unsigned_abs());
    }
    if sum == 0 {
        return invalid();
    }
    Ok(sum)
}

fn dot(a: &[i32], b: &[i32]) -> i128 {
    a.iter()
        .zip(b)
        .map(|(x, y)| i128::from(*x) * i128::from(*y))
        .sum()
}

/// The `Limit("vector arithmetic")` errors are defensive and unreachable: the bounds
/// enforced before this call keep every intermediate below 2^120.
///
/// `floor(cosine * 1_000_000)` for positive cosines, otherwise zero. Exact integer
/// arithmetic: `isqrt(floor(dot^2 * 10^12 / (|a|^2 * |b|^2)))`.
fn cosine_micros(dot: i128, norm_a: u128, norm_b: u128) -> Result<u64> {
    if dot <= 0 {
        return Ok(0);
    }
    let dot = dot.unsigned_abs();
    let numerator = dot
        .checked_mul(dot)
        .and_then(|v| v.checked_mul(MICROS * MICROS))
        .ok_or(RetrievalError::Limit("vector arithmetic"))?;
    let denominator = norm_a
        .checked_mul(norm_b)
        .ok_or(RetrievalError::Limit("vector arithmetic"))?;
    u64::try_from((numerator / denominator).isqrt())
        .map_err(|_| RetrievalError::Limit("vector arithmetic"))
}

/// Rank the supplied asset vectors against the query vector.
///
/// The result is an ordinary `SemanticRanking`; `search_contextual_with_semantic`
/// still applies its own validation (including provenance shape and freshness) and
/// eligibility checks. Assets with a non-positive cosine are omitted, ties break by
/// canonical `AssetKey` order and at most `MAX_RANKED_HITS` hits are kept.
pub fn rank_semantic(
    index: &Bm25Index,
    query: &ContextSearchQuery,
    assets: &AssetVectorSet,
    query_vector: &QueryVector,
    provenance: SignalProvenance,
) -> Result<SemanticRanking> {
    if assets.schema_version != VECTOR_SCHEMA_VERSION
        || query_vector.schema_version != VECTOR_SCHEMA_VERSION
        || assets.index_hash != index.index_hash()
        || query_vector.query_hash != query.content_hash()?
        || assets.dimension == 0
        || assets.dimension > MAX_VECTOR_DIMENSION
    {
        return invalid();
    }
    if assets.vectors.len() > MAX_ASSETS {
        return Err(RetrievalError::Limit("asset vectors"));
    }
    let query_norm = norm_squared(&query_vector.components, assets.dimension)?;
    let mut seen = BTreeSet::new();
    let mut hits = Vec::new();
    for item in &assets.vectors {
        if index.asset(item.asset.kind, &item.asset.id).is_none() || !seen.insert(&item.asset) {
            return invalid();
        }
        let norm = norm_squared(&item.components, assets.dimension)?;
        if query.query.kind.is_some_and(|kind| kind != item.asset.kind) {
            continue;
        }
        let score = cosine_micros(
            dot(&item.components, &query_vector.components),
            norm,
            query_norm,
        )?;
        if score > 0 {
            hits.push(RankedHit {
                asset: item.asset.clone(),
                score_micros: score,
            });
        }
    }
    hits.sort_by(|a, b| {
        b.score_micros
            .cmp(&a.score_micros)
            .then_with(|| a.asset.cmp(&b.asset))
    });
    hits.truncate(MAX_RANKED_HITS);
    Ok(SemanticRanking {
        schema_version: 1,
        index_hash: index.index_hash().into(),
        query_hash: query_vector.query_hash.clone(),
        provenance,
        hits,
    })
}
