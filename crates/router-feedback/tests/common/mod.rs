#[path = "../../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)]
mod fixture_proofs;
// Synthetic replay evidence only. No actual human labels or prices.
use std::collections::{BTreeMap, BTreeSet};

use router_adapter_api::{EvidenceKind, EvidenceSource, HostObservation, SnapshotValidation};
use router_eval::*;
use router_policy::PhaseRouter;
use router_types::*;
use router_workflow::merge_restrictions;
use serde_json::json;

fn model(id: &str) -> ModelId {
    ModelId::parse(id).unwrap()
}
fn validation() -> SnapshotValidation {
    SnapshotValidation {
        now_unix_seconds: 110,
        max_age_seconds: 60,
    }
}
fn candidate(id: &str, model_id: &str) -> PhaseCandidate {
    PhaseCandidate {
        tool_policy: router_types::PhaseToolPolicy::Restricted,
        id: id.into(),
        model: model(model_id),
        effort: EffortLevel::Medium,
        agent: None,
        skills: BTreeSet::new(),
        tools: BTreeSet::new(),
        sandbox: PhaseSandbox::ReadOnly,
        verification: PhaseVerification::Required,
        required_capabilities: BTreeSet::new(),
        required_mutations: BTreeSet::new(),
        estimated_cost_microusd: 100,
        estimated_tokens: 100,
        estimated_elapsed_ms: 100,
        relevance_micros: 0,
    }
}
pub fn input() -> ReplayInput {
    let catalog = json!({"schema_version":1,"version":"synthetic-prior","models":[
        {"id":"fixture-best","stages":["plan","execute","verify"],"efforts":["medium"],"capabilities":[],"quality_micros":900000,"cost_micros":100,"latency_micros":100,"source":"synthetic-test"},
        {"id":"fixture-second","stages":["plan","execute","verify"],"efforts":["medium"],"capabilities":[],"quality_micros":700000,"cost_micros":50,"latency_micros":50,"source":"synthetic-test"}],"skills":[]});
    let models = [model("fixture-best"), model("fixture-second")];
    let snapshot = HostObservation {
        attestations: None,
        schema_version: 1,
        host: HostSnapshot {
            id: "fixture-host".into(),
            harness: HarnessId::parse("codex").unwrap(),
            supported_models: models.iter().cloned().collect(),
            supported_efforts: models
                .into_iter()
                .map(|id| (id, BTreeSet::from([EffortLevel::Medium])))
                .collect(),
            capabilities: BTreeSet::new(),
        },
        capabilities: BTreeMap::new(),
        evidence: vec![EvidenceSource {
            id: "fixture-cache".into(),
            kind: EvidenceKind::CodexModelCache,
            observed_version: Some("fixture-v1".into()),
            observed_at_unix_seconds: 100,
            content_sha256: "a".repeat(64),
        }],
        observed_at_unix_seconds: 100,
        snapshot_hash: String::new(),
    }
    .seal()
    .unwrap();
    let restrictions = merge_restrictions(&[RestrictionLayer {
        name: "fixture-authority".into(),
        allowed_models: None,
        allowed_capabilities: None,
        allowed_mutations: Some(BTreeSet::new()),
        max_cost_microusd: Some(10000),
        max_tokens: Some(1000),
        max_concurrency: Some(1),
        preferred_model: None,
    }])
    .unwrap();
    let request = PhaseRouteRequest {
        schema_version: 2,
        task: NormalizedTask {
            objective: "Inspect the deterministic Rust contract".into(),
            kind: TaskKind::Explore,
            deliverables: vec!["contract report".into()],
            constraints: vec![],
            scope: vec!["src".into()],
            risk: RiskLevel::Low,
            sensitivity: DataSensitivity::Public,
            budget: TaskBudget {
                max_cost_microusd: 10000,
                max_elapsed_ms: 1000,
                max_tokens: 1000,
            },
            allowed_mutations: BTreeSet::new(),
            dependencies: vec![],
            acceptance: vec!["Cite an enforcing symbol".into()],
            required_capabilities: BTreeSet::new(),
        },
        phase: StageKind::Plan,
        restrictions,
        permissions: BTreeMap::from([
            (
                PhasePermission::ModelInference,
                CapabilitySupport::Supported,
            ),
            (PhasePermission::WorkspaceRead, CapabilitySupport::Supported),
        ]),
        registry: PhaseAssetRegistry::default(),
        candidates: vec![
            candidate("primary", "fixture-best"),
            candidate("secondary", "fixture-second"),
        ],
        previous_model: None,
    };
    let phase = |id: &str| RecordedPhase {
        usage: vec![TokenUsage {
            model: model(id),
            input_tokens: 100,
            cached_input_tokens: 0,
            output_tokens: 0,
        }],
        elapsed_ms: Some(10),
        fallback_reasons: vec![],
        outcomes: VerificationOutcomes::default(),
    };
    ReplayInput {
        schema_version: 1,
        case_id: "case-1".into(),
        family_id: "family-1".into(),
        split: DatasetSplit::HeldOut,
        out_of_domain: false,
        request,
        snapshot,
        catalog,
        policies: BTreeMap::from([
            (
                "baseline".into(),
                PhasePolicy {
                    version: "baseline-v1".into(),
                    ..PhasePolicy::default()
                },
            ),
            (
                "semantic".into(),
                PhasePolicy {
                    version: "recorded-shadow-v1".into(),
                    ..PhasePolicy::default()
                },
            ),
        ]),
        pricing: PricingTable {
            schema_version: 1,
            version: "synthetic-price-v1".into(),
            source: "synthetic-test-only-not-market-prices".into(),
            observed_at_unix_seconds: 100,
            models: BTreeMap::from([
                (
                    model("fixture-best"),
                    TokenPrice {
                        input_microusd_per_million: 2_000_000,
                        cached_input_microusd_per_million: 1_000_000,
                        output_microusd_per_million: 4_000_000,
                    },
                ),
                (
                    model("fixture-second"),
                    TokenPrice {
                        input_microusd_per_million: 1_000_000,
                        cached_input_microusd_per_million: 500_000,
                        output_microusd_per_million: 2_000_000,
                    },
                ),
            ]),
        },
        observations: BTreeMap::from([
            ("baseline".into(), phase("fixture-best")),
            ("semantic".into(), phase("fixture-second")),
        ]),
        label: None,
    }
}

fn shadow(record: &ReplayRecord) -> ReplayTrace {
    run_replay(record, "semantic", validation(), |context| {
        PhaseRouter::new(context.policy.clone())
            .unwrap()
            .fallback(context.phase_context, &BTreeSet::from(["primary".into()]))
            .map_err(|_| EvalError::Backend)
    })
    .unwrap()
}

pub fn pair(mut input: ReplayInput) -> PairedTrace {
    // Synthetic test attestations exercise the gate. They are never exported to
    // the project candidate corpus and represent no actual human review.
    input.label.get_or_insert(CaseLabel {
        human_validated: true,
        independent: true,
        reviewer_id: Some("synthetic-reviewer".into()),
        evidence_sha256: Some("b".repeat(64)),
        expected_candidate_ids: BTreeSet::from(["primary".into(), "secondary".into()]),
        expect_abstention: false,
    });
    let record = ReplayRecord::seal(input).unwrap();
    PairedTrace {
        baseline: replay_deterministic(&record, "baseline", validation()).unwrap(),
        semantic: shadow(&record),
    }
}

pub fn criteria(pairs: &[PairedTrace]) -> PromotionCriteria {
    PromotionCriteria {
        schema_version: 1,
        dataset_hash: dataset_hash(pairs).unwrap(),
        registered_at_unix_seconds: 99,
        registration_evidence_sha256: "c".repeat(64),
        minimum_cases: 1,
        minimum_families: 1,
        policy_authors: BTreeSet::from(["synthetic-policy-author".into()]),
        training_families: BTreeSet::new(),
        rules: vec![
            MetricRule {
                metric: PromotionMetric::RouteAccuracy,
                minimum_improvement_micros: 0,
                maximum_regression_micros: 0,
            },
            MetricRule {
                metric: PromotionMetric::Cost,
                minimum_improvement_micros: 100_000,
                maximum_regression_micros: 0,
            },
        ],
    }
}

// Explicit authentication for this synthetic replay corpus only.
fn replay_deterministic(
    record: &ReplayRecord,
    policy: &str,
    validation: SnapshotValidation,
) -> router_eval::Result<ReplayTrace> {
    router_eval::replay_deterministic_with_verifier(
        record,
        policy,
        validation,
        Some(&fixture_proofs::FixtureVerifier),
    )
}
fn run_replay<P>(
    record: &ReplayRecord,
    policy: &str,
    validation: SnapshotValidation,
    route: P,
) -> router_eval::Result<ReplayTrace>
where
    P: FnOnce(&ReplayContext<'_>) -> router_eval::Result<PhaseReceipt>,
{
    router_eval::run_replay_with_verifier(
        record,
        policy,
        validation,
        Some(&fixture_proofs::FixtureVerifier),
        route,
    )
}
