use router_catalog::Catalog;
use router_types::{DecisionEnvelope, Exclusion, RouteDecision, RouteRequest};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{preset::build_candidates, score::rank_plans};

pub const MAX_ROUTE_SKILL_CANDIDATES: usize = 256;
pub(crate) const MAX_PLAN_WORK_UNITS: usize = 1_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyConfig {
    schema_version: String,
    policy_version: String,
}

impl PolicyConfig {
    pub fn stable_v1() -> Self {
        Self {
            schema_version: "1".into(),
            policy_version: "stable-v1".into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Router {
    config: PolicyConfig,
}

impl Router {
    pub const MAX_PLAN_WORK_UNITS: usize = crate::route::MAX_PLAN_WORK_UNITS;

    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    pub fn stable_v1() -> Self {
        Self::new(PolicyConfig::stable_v1())
    }

    pub fn route(
        &self,
        request: &RouteRequest,
        catalog: &Catalog,
    ) -> Result<DecisionEnvelope, RouteError> {
        self.route_internal(request, catalog, None)
    }

    /// Bind an externally validated snapshot to the decision identity. The hash
    /// provides integrity and provenance, not authorization or runtime evidence.
    pub fn route_with_snapshot_hash(
        &self,
        request: &RouteRequest,
        catalog: &Catalog,
        snapshot_hash: &str,
    ) -> Result<DecisionEnvelope, RouteError> {
        if snapshot_hash.len() != 64
            || !snapshot_hash
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(RouteError::InvalidRequest {
                code: "snapshot.hash.invalid",
                path: "host_snapshot_hash".into(),
                message: "expected a lowercase SHA-256 digest",
            });
        }
        self.route_internal(request, catalog, Some(snapshot_hash))
    }

    fn route_internal(
        &self,
        request: &RouteRequest,
        catalog: &Catalog,
        snapshot_hash: Option<&str>,
    ) -> Result<DecisionEnvelope, RouteError> {
        validate_request(request)?;
        let canonical_request = match snapshot_hash {
            Some(hash) => serde_json::to_vec(&("host-observation-v1", request, hash)),
            None => serde_json::to_vec(request),
        }
        .map_err(RouteError::SerializeRequest)?;
        let decision_id = decision_id(
            &self.config.schema_version,
            &canonical_request,
            catalog.version(),
            &self.config.policy_version,
        );
        let mut build = build_candidates(request, catalog);
        let mut ranked = rank_plans(
            &build.stages,
            request.task.kind,
            request.task.risk,
            &mut build.exclusions,
        )?;
        normalize_exclusions(&mut build.exclusions);
        build.missing_evidence.sort();
        build.missing_evidence.dedup();

        let decision = if ranked.is_empty() {
            RouteDecision::NoRoute {
                exclusions: build.exclusions,
                missing_evidence: build.missing_evidence,
            }
        } else {
            let selected = ranked.remove(0).plan;
            let alternatives = ranked
                .into_iter()
                .take(2)
                .map(|ranked| ranked.plan)
                .collect();
            RouteDecision::Selected {
                plan: selected,
                alternatives,
                exclusions: build.exclusions,
                missing_evidence: build.missing_evidence,
            }
        };

        Ok(DecisionEnvelope {
            schema_version: self.config.schema_version.clone(),
            decision_id,
            host_snapshot_hash: snapshot_hash.map(str::to_owned),
            catalog_version: catalog.version().into(),
            policy_version: self.config.policy_version.clone(),
            decision,
        })
    }
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("{code} at {path}: {message}")]
    InvalidRequest {
        code: &'static str,
        path: String,
        message: &'static str,
    },
    #[error("route.request.serialize: {0}")]
    SerializeRequest(serde_json::Error),
    #[error("route.arithmetic.out_of_range: {component} is outside the supported range")]
    ArithmeticOutOfRange { component: &'static str },
    #[error("route.resource.work_limit_exceeded: actual={actual:?} max={max}")]
    WorkLimitExceeded { actual: Option<usize>, max: usize },
}

impl RouteError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest { code, .. } => code,
            Self::SerializeRequest(_) => "route.request.serialize",
            Self::ArithmeticOutOfRange { .. } => "route.arithmetic.out_of_range",
            Self::WorkLimitExceeded { .. } => "route.resource.work_limit_exceeded",
        }
    }

    pub fn component(&self) -> Option<&'static str> {
        match self {
            Self::SerializeRequest(_) => None,
            Self::InvalidRequest { .. } => None,
            Self::ArithmeticOutOfRange { component } => Some(component),
            Self::WorkLimitExceeded { .. } => None,
        }
    }

    pub fn path(&self) -> Option<&str> {
        match self {
            Self::InvalidRequest { path, .. } => Some(path),
            Self::SerializeRequest(_)
            | Self::ArithmeticOutOfRange { .. }
            | Self::WorkLimitExceeded { .. } => None,
        }
    }

    pub fn is_invalid_request(&self) -> bool {
        matches!(
            self,
            Self::InvalidRequest { .. } | Self::WorkLimitExceeded { .. }
        )
    }

    pub fn work_limit(&self) -> Option<(Option<usize>, usize)> {
        match self {
            Self::WorkLimitExceeded { actual, max } => Some((*actual, *max)),
            Self::InvalidRequest { .. }
            | Self::SerializeRequest(_)
            | Self::ArithmeticOutOfRange { .. } => None,
        }
    }
}

fn validate_request(request: &RouteRequest) -> Result<(), RouteError> {
    if request.skill_candidates.len() > MAX_ROUTE_SKILL_CANDIDATES {
        return Err(RouteError::InvalidRequest {
            code: "request.skill_candidates.too_many",
            path: "skill_candidates".into(),
            message: "request must contain at most 256 skill candidates",
        });
    }
    for (index, candidate) in request.skill_candidates.iter().enumerate() {
        if candidate.source.is_empty() {
            return Err(RouteError::InvalidRequest {
                code: "request.skill_candidate.source.empty",
                path: format!("skill_candidates[{index}].source"),
                message: "skill candidate source must not be empty",
            });
        }
        if !(0..=1_000_000).contains(&candidate.score_micros) {
            return Err(RouteError::InvalidRequest {
                code: "request.skill_candidate.score_out_of_range",
                path: format!("skill_candidates[{index}].score_micros"),
                message: "skill candidate score must be between 0 and 1_000_000",
            });
        }
    }
    Ok(())
}

fn decision_id(
    schema_version: &str,
    canonical_request: &[u8],
    catalog_version: &str,
    policy_version: &str,
) -> String {
    let mut hasher = Sha256::new();
    for component in [
        schema_version.as_bytes(),
        canonical_request,
        catalog_version.as_bytes(),
        policy_version.as_bytes(),
    ] {
        hasher.update((component.len() as u64).to_be_bytes());
        hasher.update(component);
    }
    hex::encode(hasher.finalize())
}

fn normalize_exclusions(exclusions: &mut Vec<Exclusion>) {
    exclusions.sort_by(|left, right| {
        left.stage
            .cmp(&right.stage)
            .then_with(|| left.model.cmp(&right.model))
            .then_with(|| left.code.cmp(&right.code))
            .then_with(|| left.evidence.cmp(&right.evidence))
    });
    exclusions.dedup_by(|left, right| {
        left.stage == right.stage
            && left.model == right.model
            && left.code == right.code
            && left.evidence == right.evidence
    });
}

#[cfg(test)]
mod tests {
    use super::decision_id;

    #[test]
    fn decision_id_components_are_length_prefixed() {
        let left = decision_id("ab", b"c", "d", "e");
        let right = decision_id("a", b"bc", "d", "e");
        assert_ne!(left, right);
    }
}
