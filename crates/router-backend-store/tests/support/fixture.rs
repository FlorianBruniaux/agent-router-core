#[path = "../../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
// All reviewers, labels, keys and model observations here are synthetic.
// Positive tests exercise proof mechanics, never authorize a production backend.
use ed25519_dalek::{Signer, SigningKey};
use router_adapter_api::{HostObservation, SnapshotValidation};
use router_backend_policy::*;
use router_catalog::Catalog;
use router_decision::BoundedDecisionContext;
use router_eval::*;
use router_policy::{PhaseRouter, ValidatedPhaseContext};
use router_types::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

struct Keys {
    backend: SigningKey,
    reviewer: SigningKey,
    gate: SigningKey,
    approver: SigningKey,
}
impl Keys {
    fn new() -> Self {
        Self {
            backend: SigningKey::from_bytes(&[1; 32]),
            reviewer: SigningKey::from_bytes(&[2; 32]),
            gate: SigningKey::from_bytes(&[3; 32]),
            approver: SigningKey::from_bytes(&[4; 32]),
        }
    }
    fn authorities(&self) -> TrustedAuthorities {
        TrustedAuthorities::new([
            (
                AuthorityRole::Backend,
                "backend".into(),
                self.backend.verifying_key().to_bytes(),
            ),
            (
                AuthorityRole::HumanReviewer,
                "reviewer".into(),
                self.reviewer.verifying_key().to_bytes(),
            ),
            (
                AuthorityRole::GateOwner,
                "gate".into(),
                self.gate.verifying_key().to_bytes(),
            ),
            (
                AuthorityRole::Approver,
                "approver".into(),
                self.approver.verifying_key().to_bytes(),
            ),
        ])
        .unwrap()
    }
    fn sign<T: Serialize>(&self, role: AuthorityRole, statement: T) -> Signed<T> {
        let (id, key) = match role {
            AuthorityRole::Backend => ("backend", &self.backend),
            AuthorityRole::HumanReviewer => ("reviewer", &self.reviewer),
            AuthorityRole::GateOwner => ("gate", &self.gate),
            AuthorityRole::Approver => ("approver", &self.approver),
        };
        let signature = key.sign(&signing_message(role, id, &statement).unwrap());
        Signed {
            statement,
            key_id: id.into(),
            signature_hex: hex::encode(signature.to_bytes()),
        }
    }
}
struct Fixture {
    keys: Keys,
    artifact: BackendArtifact,
    evidence: PromotionEvidence,
    router: PhaseRouter,
    context: ValidatedPhaseContext,
}
impl Fixture {
    fn resign_evaluation(&self, evidence: &mut PromotionEvidence) {
        for case in &mut evidence.cases {
            case.proposal = proposal(
                &self.keys,
                &self.artifact,
                &self.router,
                &self.context,
                ProposalPurpose::Evaluation(case.record.input_hash().into()),
                110,
                150,
                Some("c01"),
            );
            case.label = self.keys.sign(
                AuthorityRole::HumanReviewer,
                HumanLabelStatement {
                    schema_version: 1,
                    replay_input_hash: case.record.input_hash().into(),
                    label_sha256: label_hash(case.record.input().label.as_ref().unwrap()).unwrap(),
                    reviewed_at_unix_seconds: 105,
                },
            );
        }
        evidence.criteria.dataset_hash = evaluation_dataset_hash(&evidence.cases).unwrap();
        evidence.criteria_registration = self.keys.sign(
            AuthorityRole::GateOwner,
            CriteriaStatement {
                schema_version: 1,
                backend_artifact_hash: self.artifact.content_hash().unwrap(),
                criteria_sha256: criteria_hash(&evidence.criteria).unwrap(),
                registered_at_unix_seconds: evidence.criteria.registered_at_unix_seconds,
            },
        );
    }
    fn new() -> Self {
        Self::with_failure(BackendFailurePolicy::DeterministicFallback)
    }
    fn with_failure(failure_policy: BackendFailurePolicy) -> Self {
        Self::build(failure_policy, "test-v1")
    }
    /// Same trust roots, a distinct artifact (hence a distinct promotion hash).
    fn with_version(version: &str) -> Self {
        Self::build(BackendFailurePolicy::DeterministicFallback, version)
    }
    fn build(failure_policy: BackendFailurePolicy, version: &str) -> Self {
        let keys = Keys::new();
        let authorities = keys.authorities();
        let request: PhaseRouteRequest = serde_json::from_slice(include_bytes!(
            "../../../../fixtures/examples/phase-request.json"
        ))
        .unwrap();
        let snapshot: HostObservation = serde_json::from_slice(include_bytes!(
            "../../../../fixtures/examples/phase-snapshot.json"
        ))
        .unwrap();
        let validated = fixture_proofs::from_observation(
            snapshot.clone(),
            SnapshotValidation {
                now_unix_seconds: 110,
                max_age_seconds: 300,
            },
        )
        .unwrap();
        let catalog_value: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../fixtures/examples/phase-catalog.json"
        ))
        .unwrap();
        let catalog = Catalog::from_json(&serde_json::to_vec(&catalog_value).unwrap()).unwrap();
        let router = PhaseRouter::stable_v2();
        let context = router
            .context(request.clone(), &validated, &catalog)
            .unwrap();
        let artifact = BackendArtifact {
            schema_version: 1,
            backend_id: "synthetic-semantic".into(),
            version: version.into(),
            artifact_sha256: "a".repeat(64),
            implementation_sha256: "b".repeat(64),
            protocol_sha256: protocol_hash(),
            backend_key_id: "backend".into(),
            authors: BTreeSet::from(["synthetic-author".into()]),
            routing_policy_hash: context.policy_hash().into(),
            created_at_unix_seconds: 90,
            minimum_confidence_micros: 900000,
            failure_policy,
            data_policy: BackendDataPolicy::RedactedMetadataToLoopback,
            maximum_proposal_age_seconds: 60,
            maximum_evidence_age_seconds: 1000,
            minimum_shadow_cases: 2,
            maximum_canary_cases: 1,
        };
        let model = |id: &str| ModelId::parse(id).unwrap();
        let phase = |id: &str| RecordedPhase {
            usage: vec![TokenUsage {
                model: model(id),
                input_tokens: 100,
                cached_input_tokens: 0,
                output_tokens: 0,
            }],
            elapsed_ms: Some(10),
            fallback_reasons: vec![],
            outcomes: VerificationOutcomes {
                transport: ObservedOutcome::Passed,
                command_validation: ObservedOutcome::Unknown,
                functional: ObservedOutcome::Unknown,
            },
        };
        let pricing = PricingTable {
            schema_version: 1,
            version: "synthetic-price".into(),
            source: "synthetic-test-only".into(),
            observed_at_unix_seconds: 100,
            models: BTreeMap::from([
                (
                    model("fixture-best"),
                    TokenPrice {
                        input_microusd_per_million: 2000000,
                        cached_input_microusd_per_million: 1000000,
                        output_microusd_per_million: 4000000,
                    },
                ),
                (
                    model("fixture-second"),
                    TokenPrice {
                        input_microusd_per_million: 1000000,
                        cached_input_microusd_per_million: 500000,
                        output_microusd_per_million: 2000000,
                    },
                ),
            ]),
        };
        let cases = (0..2)
            .map(|i| {
                let input = ReplayInput {
                    schema_version: 1,
                    case_id: format!("synthetic-case-{i}"),
                    family_id: format!("synthetic-family-{i}"),
                    split: DatasetSplit::HeldOut,
                    out_of_domain: false,
                    request: request.clone(),
                    snapshot: snapshot.clone(),
                    catalog: catalog_value.clone(),
                    policies: BTreeMap::from([
                        ("baseline".into(), PhasePolicy::default()),
                        ("semantic".into(), PhasePolicy::default()),
                    ]),
                    pricing: pricing.clone(),
                    observations: BTreeMap::from([
                        ("baseline".into(), phase("fixture-best")),
                        ("semantic".into(), phase("fixture-second")),
                    ]),
                    label: Some(CaseLabel {
                        human_validated: true,
                        independent: true,
                        reviewer_id: Some("reviewer".into()),
                        evidence_sha256: Some("c".repeat(64)),
                        expected_candidate_ids: BTreeSet::from([
                            "primary".into(),
                            "secondary".into(),
                        ]),
                        expect_abstention: false,
                    }),
                };
                let record = ReplayRecord::seal(input).unwrap();
                let proposal = proposal(
                    &keys,
                    &artifact,
                    &router,
                    &context,
                    ProposalPurpose::Evaluation(record.input_hash().into()),
                    110,
                    150,
                    Some("c01"),
                );
                let label = keys.sign(
                    AuthorityRole::HumanReviewer,
                    HumanLabelStatement {
                        schema_version: 1,
                        replay_input_hash: record.input_hash().into(),
                        label_sha256: label_hash(record.input().label.as_ref().unwrap()).unwrap(),
                        reviewed_at_unix_seconds: 105,
                    },
                );
                BackendEvaluationCase {
                    record,
                    baseline_policy_id: "baseline".into(),
                    semantic_policy_id: "semantic".into(),
                    evaluated_at_unix_seconds: 110,
                    snapshot_max_age_seconds: 300,
                    proposal,
                    label,
                }
            })
            .collect::<Vec<_>>();
        let criteria = PromotionCriteria {
            schema_version: 1,
            dataset_hash: evaluation_dataset_hash(&cases).unwrap(),
            registered_at_unix_seconds: 99,
            registration_evidence_sha256: "d".repeat(64),
            minimum_cases: 2,
            minimum_families: 2,
            policy_authors: artifact.authors.clone(),
            training_families: BTreeSet::new(),
            rules: vec![
                MetricRule {
                    metric: PromotionMetric::RouteAccuracy,
                    minimum_improvement_micros: 0,
                    maximum_regression_micros: 0,
                },
                MetricRule {
                    metric: PromotionMetric::Cost,
                    minimum_improvement_micros: 100000,
                    maximum_regression_micros: 0,
                },
            ],
        };
        let registration = keys.sign(
            AuthorityRole::GateOwner,
            CriteriaStatement {
                schema_version: 1,
                backend_artifact_hash: artifact.content_hash().unwrap(),
                criteria_sha256: criteria_hash(&criteria).unwrap(),
                registered_at_unix_seconds: 99,
            },
        );
        let evaluation = evaluate_backend_with_verifier(
            &artifact,
            &criteria,
            &registration,
            &cases,
            &authorities,
            120,
         Some(&fixture_proofs::FixtureVerifier))
        .unwrap();
        let trial = |stage, start, end, hash, cases| {
            keys.sign(
                AuthorityRole::GateOwner,
                TrialStatement {
                    schema_version: 1,
                    stage,
                    backend_artifact_hash: artifact.content_hash().unwrap(),
                    evaluation_sha256: evaluation.evaluation_hash().into(),
                    evidence_sha256: hash,
                    cases,
                    hard_constraint_violations: 0,
                    subgroup_regressions: 0,
                    accepted: true,
                    started_at_unix_seconds: start,
                    completed_at_unix_seconds: end,
                },
            )
        };
        let shadow = trial(TrialStage::Shadow, 111, 112, "e".repeat(64), 2);
        let canary = trial(TrialStage::Canary, 113, 114, "f".repeat(64), 1);
        let evidence = PromotionEvidence {
            schema_version: 1,
            criteria,
            criteria_registration: registration,
            cases,
            shadow,
            canary,
        };
        Self {
            keys,
            artifact,
            evidence,
            router,
            context,
        }
    }
    fn promotion(&self) -> ValidatedBackendPromotion {
        evaluate_promotion_with_verifier(
            &self.artifact,
            &self.evidence,
            &self.keys.authorities(),
            120,
         Some(&fixture_proofs::FixtureVerifier))
        .unwrap()
    }
    fn approval(
        &self,
        state: &BackendActivationState,
        action: ActivationAction,
        target: &str,
        now: u64,
        nonce: &str,
    ) -> Signed<ActivationApproval> {
        self.approval_with_nonce(state, action, target, now, nonce.repeat(64))
    }
    fn approval_with_nonce(
        &self,
        state: &BackendActivationState,
        action: ActivationAction,
        target: &str,
        now: u64,
        nonce_sha256: String,
    ) -> Signed<ActivationApproval> {
        self.keys.sign(
            AuthorityRole::Approver,
            ActivationApproval {
                schema_version: 1,
                action,
                expected_state_hash: state.state_hash().into(),
                target_hash: target.into(),
                issued_at_unix_seconds: now,
                expires_at_unix_seconds: now + 100,
                nonce_sha256,
            },
        )
    }
    fn active(&self) -> BackendActivationState {
        let promotion = self.promotion();
        let mut state =
            BackendActivationState::new(self.context.policy_hash(), &"9".repeat(64)).unwrap();
        let approval = self.approval(
            &state,
            ActivationAction::Activate,
            promotion.promotion_hash(),
            120,
            "1",
        );
        state
            .apply(&approval, Some(&promotion), &self.keys.authorities(), 120)
            .unwrap();
        state
    }
}
#[allow(clippy::too_many_arguments)]
fn proposal(
    keys: &Keys,
    artifact: &BackendArtifact,
    router: &PhaseRouter,
    context: &ValidatedPhaseContext,
    purpose: ProposalPurpose,
    issued: u64,
    expires: u64,
    candidate: Option<&str>,
) -> SignedBackendProposal {
    let bounded = BoundedDecisionContext::from_phase(router, context).unwrap();
    let request = bounded.redacted_request();
    keys.sign(
        AuthorityRole::Backend,
        BackendResponse {
            schema_version: 1,
            backend_artifact_hash: artifact.content_hash().unwrap(),
            request_sha256: backend_request_hash(request).unwrap(),
            purpose,
            proposal: BackendProposal {
                schema_version: 1,
                artifact_digest: request.artifact_digest.clone(),
                candidate_id: candidate.map(str::to_owned),
                confidence_micros: 1000000,
                probabilities_micros: request
                    .candidates
                    .iter()
                    .map(|c| {
                        (
                            c.id.clone(),
                            if Some(c.id.as_str()) == candidate {
                                1000000
                            } else {
                                0
                            },
                        )
                    })
                    .collect(),
            },
            issued_at_unix_seconds: issued,
            expires_at_unix_seconds: expires,
        },
    )
}
