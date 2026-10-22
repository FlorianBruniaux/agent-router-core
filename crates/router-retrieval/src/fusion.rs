use crate::{AssetKey, MAX_RESULTS, Result, RetrievalError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_RETRIEVERS: usize = 5;
pub const MAX_RANKED_HITS: usize = 200;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RrfConfig {
    pub k: u32,
    pub top_k: usize,
}
impl Default for RrfConfig {
    fn default() -> Self {
        Self { k: 60, top_k: 5 }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RankedHit {
    pub asset: AssetKey,
    /// Source-specific score, retained for explanation. RRF uses only rank.
    pub score_micros: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RankedSource {
    pub id: String,
    pub weight_micros: u32,
    pub hits: Vec<RankedHit>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RankContribution {
    pub source: String,
    pub rank: usize,
    pub source_score_micros: u64,
    pub contribution_nanos: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FusedCandidate {
    pub asset: AssetKey,
    pub rrf_score_nanos: u64,
    pub sources: Vec<RankContribution>,
}
/// Pure rank fusion, not eligibility or authority. Duplicate canonical keys in
/// a source count once at their first position; ties use AssetKey ordering.
/// Contributions are floor(weight_micros * 1000 / (k + one_based_unique_rank)).
pub fn fuse_rankings(sources: &[RankedSource], config: RrfConfig) -> Result<Vec<FusedCandidate>> {
    if config.k == 0
        || config.k > 10_000
        || config.top_k == 0
        || config.top_k > MAX_RESULTS
        || sources.len() > MAX_RETRIEVERS
    {
        return Err(RetrievalError::Limit("RRF configuration"));
    }
    let mut ids = BTreeSet::new();
    let mut candidates: BTreeMap<AssetKey, FusedCandidate> = BTreeMap::new();
    for source in sources {
        if !valid_identifier(&source.id)
            || !ids.insert(&source.id)
            || source.weight_micros == 0
            || source.weight_micros > 1_000_000
        {
            return Err(RetrievalError::Invalid("RRF source identity or weight"));
        }
        if source.hits.len() > MAX_RANKED_HITS {
            return Err(RetrievalError::Limit("RRF source hits"));
        }
        let mut seen = BTreeSet::new();
        for hit in &source.hits {
            if !valid_identifier(&hit.asset.id) || hit.asset.id.contains(['+', '#']) {
                return Err(RetrievalError::Invalid("canonical ranked identifier"));
            }
            if !seen.insert(&hit.asset) {
                continue;
            }
            let rank = seen.len();
            let contribution =
                u64::from(source.weight_micros) * 1000 / (u64::from(config.k) + rank as u64);
            let candidate = candidates
                .entry(hit.asset.clone())
                .or_insert_with(|| FusedCandidate {
                    asset: hit.asset.clone(),
                    rrf_score_nanos: 0,
                    sources: vec![],
                });
            candidate.rrf_score_nanos += contribution;
            candidate.sources.push(RankContribution {
                source: source.id.clone(),
                rank,
                source_score_micros: hit.score_micros,
                contribution_nanos: contribution,
            });
        }
    }
    let mut candidates: Vec<_> = candidates.into_values().collect();
    for candidate in &mut candidates {
        candidate.sources.sort_by(|a, b| a.source.cmp(&b.source));
    }
    candidates.sort_by(|a, b| {
        b.rrf_score_nanos
            .cmp(&a.rrf_score_nanos)
            .then_with(|| a.asset.cmp(&b.asset))
    });
    candidates.truncate(config.top_k);
    Ok(candidates)
}
pub(crate) fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"-_.:/+#".contains(&c))
}
