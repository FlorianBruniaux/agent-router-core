//! Provider separation between a producing node and its review node.
//!
//! The provider string comes from the asset contracts document
//! (`AssetGateRequest::provider`). It is a declaration checked against the
//! availability evidence, not an authenticated identity: two labels that
//! differ may still reach the same backend, and this module cannot detect it.
use crate::ValidatedPhaseContext;
use router_types::GenerationEdgeCompatibility;
use std::collections::{BTreeMap, BTreeSet};

use crate::generator::MAX_GENERATION_EDGE_PAIRS;

/// Verdict for one producer/reviewer candidate pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairSeparation {
    Distinct,
    SameProvider,
    /// At least one side has no declared provider (no assets, or empty label).
    UnknownProvider,
}

/// Verdict for the edge that `compatibility` describes, not for the raw
/// producers x reviewers product. Read it together with `pairs`, which keeps the
/// per-pair verdicts of the full product.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewSeparationVerdict {
    /// At least one pair of the base compatibility has distinct providers and
    /// survives in `compatibility`.
    Distinct,
    /// The base pairs have no distinct pair, and at least one is same-provider.
    SameProvider,
    /// The base pairs have no distinct pair and no known same-provider pair
    /// (unknown provider, or pairs outside the candidate maps).
    UnknownProvider,
    /// No producer or no reviewer candidate exists.
    ReviewerUnavailable,
    /// The base compatibility is UNKNOWN (`None`), so the result is UNKNOWN too
    /// and asserts no usable pair, whatever `pairs` says.
    CompatibilityUnknown,
    /// The base compatibility is a known empty set: no pair to restrict.
    NoDeclaredPair,
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReviewSeparationError {
    #[error("review separation pair limit exceeded")]
    PairLimit,
}

/// Candidate id to declared provider. `None` is UNKNOWN.
pub type CandidateProviders = BTreeMap<String, Option<String>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewSeparation {
    pub verdict: ReviewSeparationVerdict,
    pub pairs: BTreeMap<(String, String), PairSeparation>,
    pub compatibility: GenerationEdgeCompatibility,
}

/// Declared providers for every eligible candidate of a validated context, the
/// same set the generator joins over. An ineligible candidate is absent. An
/// eligible candidate without asset requirements, or with an empty provider,
/// maps to `None`.
pub fn candidate_providers(context: &ValidatedPhaseContext) -> CandidateProviders {
    context
        .request()
        .candidates
        .iter()
        .filter(|c| context.eligible_selection(&c.id).is_some())
        .map(|c| {
            let provider = context
                .asset_requirements(&c.id)
                .map(|r| r.provider.clone())
                .filter(|p| !p.trim().is_empty());
            (c.id.clone(), provider)
        })
        .collect()
}

fn declared(provider: &Option<String>) -> Option<&str> {
    provider.as_deref().map(str::trim).filter(|p| !p.is_empty())
}

fn separation(producer: &Option<String>, reviewer: &Option<String>) -> PairSeparation {
    match (declared(producer), declared(reviewer)) {
        (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => PairSeparation::SameProvider,
        (Some(_), Some(_)) => PairSeparation::Distinct,
        _ => PairSeparation::UnknownProvider,
    }
}

/// Restrict an edge to producer/reviewer pairs with distinct declared providers.
///
/// `base` is the compatibility already declared for the edge. The result only
/// removes pairs from it: a `None` base stays UNKNOWN and no pair is ever added.
/// With no producer or no reviewer the result is an explicit empty set.
pub fn distinct_provider_pairs(
    source: &str,
    target: &str,
    producers: &CandidateProviders,
    reviewers: &CandidateProviders,
    base: Option<&BTreeSet<(String, String)>>,
) -> Result<ReviewSeparation, ReviewSeparationError> {
    if producers
        .len()
        .checked_mul(reviewers.len())
        .is_none_or(|n| n > MAX_GENERATION_EDGE_PAIRS)
    {
        return Err(ReviewSeparationError::PairLimit);
    }
    let mut pairs = BTreeMap::new();
    for (p, pp) in producers {
        for (r, rp) in reviewers {
            pairs.insert((p.clone(), r.clone()), separation(pp, rp));
        }
    }
    let verdict = match base {
        _ if pairs.is_empty() => ReviewSeparationVerdict::ReviewerUnavailable,
        None => ReviewSeparationVerdict::CompatibilityUnknown,
        Some(base) if base.is_empty() => ReviewSeparationVerdict::NoDeclaredPair,
        Some(base) => {
            let of = |pair: &(String, String)| {
                pairs
                    .get(pair)
                    .copied()
                    .unwrap_or(PairSeparation::UnknownProvider)
            };
            if base.iter().any(|p| of(p) == PairSeparation::Distinct) {
                ReviewSeparationVerdict::Distinct
            } else if base.iter().any(|p| of(p) == PairSeparation::SameProvider) {
                ReviewSeparationVerdict::SameProvider
            } else {
                ReviewSeparationVerdict::UnknownProvider
            }
        }
    };
    let allowed_pairs = base.map(|base| {
        base.iter()
            .filter(|pair| pairs.get(*pair) == Some(&PairSeparation::Distinct))
            .cloned()
            .collect()
    });
    Ok(ReviewSeparation {
        verdict,
        pairs,
        compatibility: GenerationEdgeCompatibility {
            source: source.into(),
            target: target.into(),
            allowed_pairs,
        },
    })
}
