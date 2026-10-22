#![forbid(unsafe_code)]

mod asset_phases;
mod constraint;
mod generator;
mod phases;
mod preset;
mod retrieval;
mod review_separation;
mod route;
mod score;
mod signed_phases;

pub use asset_phases::{PhaseAssetInputs, PhaseExecutionScope, asset_authority_scope_digest};
pub use constraint::{
    CapabilitiesSatisfied, CapabilityKnowledge, Constraint, ConstraintEngine, ConstraintVerdict,
    EffortSupported, EligibilityContext, ModelAvailable, StageSupported, Support, is_eligible,
};
pub use generator::{
    GenerationError, GenerationNode, MAX_GENERATION_BYTES, MAX_GENERATION_EDGE_PAIRS,
    MAX_GENERATION_NODES, MAX_GENERATION_ROWS, MAX_GENERATION_WORK, PlanGenerationInput,
    ValidatedGeneratedPlan, generate_plans, validate_generated_plan,
};
pub use phases::{
    MAX_PHASE_ASSETS, MAX_PHASE_CANDIDATES, MAX_PHASE_REQUEST_BYTES, PhaseRouteError, PhaseRouter,
    ValidatedPhaseContext, ValidatedPhaseReceipt,
};
pub use retrieval::{
    RetrievalError, SkillRetriever, StaticSkillRetriever, parse_candidate_document,
};
pub use review_separation::{
    CandidateProviders, PairSeparation, ReviewSeparation, ReviewSeparationError,
    ReviewSeparationVerdict, candidate_providers, distinct_provider_pairs,
};
pub use route::{PolicyConfig, RouteError, Router};
pub use signed_phases::SignedPhaseInputs;
