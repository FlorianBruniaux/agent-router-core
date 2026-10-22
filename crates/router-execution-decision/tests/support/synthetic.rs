//! All reviewers, labels, keys and model observations here are synthetic.
//! Positive tests exercise proof mechanics, never authorize a production backend.
#![allow(dead_code)]
#[path = "../../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use ed25519_dalek::{Signer, SigningKey};
use router_adapter_api::{HostObservation, SnapshotValidation};
use router_backend_policy::*;
use router_catalog::Catalog;
use router_decision::BoundedDecisionContext;
use router_eval::*;
use router_policy::{PhaseRouter, ValidatedPhaseContext};
use router_types::*;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
};

pub struct Keys {
    pub backend: SigningKey,
    pub reviewer: SigningKey,
    pub gate: SigningKey,
    pub approver: SigningKey,
}
impl Keys {
    pub fn new() -> Self {
        Self {
            backend: SigningKey::from_bytes(&[1; 32]),
            reviewer: SigningKey::from_bytes(&[2; 32]),
            gate: SigningKey::from_bytes(&[3; 32]),
            approver: SigningKey::from_bytes(&[4; 32]),
        }
    }
    pub fn authorities(&self) -> TrustedAuthorities {
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
    pub fn sign<T: Serialize>(&self, role: AuthorityRole, statement: T) -> Signed<T> {
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
            signature_hex: signature.to_bytes().iter().fold(
                String::with_capacity(128),
                |mut output, byte| {
                    write!(&mut output, "{byte:02x}").unwrap();
                    output
                },
            ),
        }
    }
}
pub struct Fixture {
    pub epoch: u64,
    pub keys: Keys,
    pub artifact: BackendArtifact,
    pub evidence: PromotionEvidence,
    pub router: PhaseRouter,
    pub context: ValidatedPhaseContext,
}
impl Fixture {
    pub fn new() -> Self {
        Self::new_at(0)
    }
    pub fn new_at(epoch: u64) -> Self {
        Self::with_failure(epoch, BackendFailurePolicy::DeterministicFallback)
    }
    pub fn with_failure(epoch: u64, failure_policy: BackendFailurePolicy) -> Self {
        let keys = Keys::new();
        let authorities = keys.authorities();
        let request: PhaseRouteRequest = serde_json::from_slice(include_bytes!(
            "../../../../fixtures/examples/phase-request.json"
        ))
        .unwrap();
        let mut snapshot: HostObservation = serde_json::from_slice(include_bytes!(
            "../../../../fixtures/examples/phase-snapshot.json"
        ))
        .unwrap();
        snapshot.observed_at_unix_seconds += epoch;
        for e in &mut snapshot.evidence {
            e.observed_at_unix_seconds += epoch;
        }
        let snapshot = snapshot.seal().unwrap();
        let validated = fixture_proofs::from_observation(
            snapshot.clone(),
            SnapshotValidation {
                now_unix_seconds: epoch + 110,
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
            version: "test-v1".into(),
            artifact_sha256: "a".repeat(64),
            implementation_sha256: "b".repeat(64),
            protocol_sha256: protocol_hash(),
            backend_key_id: "backend".into(),
            authors: BTreeSet::from(["synthetic-author".into()]),
            routing_policy_hash: context.policy_hash().into(),
            created_at_unix_seconds: epoch + 90,
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
            observed_at_unix_seconds: epoch + 100,
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
                    epoch + 110,
                    epoch + 150,
                    Some("c01"),
                );
                let label = keys.sign(
                    AuthorityRole::HumanReviewer,
                    HumanLabelStatement {
                        schema_version: 1,
                        replay_input_hash: record.input_hash().into(),
                        label_sha256: label_hash(record.input().label.as_ref().unwrap()).unwrap(),
                        reviewed_at_unix_seconds: epoch + 105,
                    },
                );
                BackendEvaluationCase {
                    record,
                    baseline_policy_id: "baseline".into(),
                    semantic_policy_id: "semantic".into(),
                    evaluated_at_unix_seconds: epoch + 110,
                    snapshot_max_age_seconds: 300,
                    proposal,
                    label,
                }
            })
            .collect::<Vec<_>>();
        let criteria = PromotionCriteria {
            schema_version: 1,
            dataset_hash: evaluation_dataset_hash(&cases).unwrap(),
            registered_at_unix_seconds: epoch + 99,
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
                registered_at_unix_seconds: epoch + 99,
            },
        );
        let evaluation = evaluate_backend_with_verifier(
            &artifact,
            &criteria,
            &registration,
            &cases,
            &authorities,
            epoch + 120,
            Some(&fixture_proofs::FixtureVerifier),
        )
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
        let shadow = trial(
            TrialStage::Shadow,
            epoch + 111,
            epoch + 112,
            "e".repeat(64),
            2,
        );
        let canary = trial(
            TrialStage::Canary,
            epoch + 113,
            epoch + 114,
            "f".repeat(64),
            1,
        );
        let evidence = PromotionEvidence {
            schema_version: 1,
            criteria,
            criteria_registration: registration,
            cases,
            shadow,
            canary,
        };
        Self {
            epoch,
            keys,
            artifact,
            evidence,
            router,
            context,
        }
    }
    pub fn promotion(&self) -> ValidatedBackendPromotion {
        let epoch = self.epoch;
        evaluate_promotion_with_verifier(
            &self.artifact,
            &self.evidence,
            &self.keys.authorities(),
            epoch + 120,
            Some(&fixture_proofs::FixtureVerifier),
        )
        .unwrap()
    }
    pub fn approval(
        &self,
        state: &BackendActivationState,
        action: ActivationAction,
        target: &str,
        now: u64,
        nonce: &str,
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
                nonce_sha256: nonce.repeat(64),
            },
        )
    }
    pub fn active(&self) -> BackendActivationState {
        let epoch = self.epoch;
        let promotion = self.promotion();
        let mut state =
            BackendActivationState::new(self.context.policy_hash(), &"9".repeat(64)).unwrap();
        let approval = self.approval(
            &state,
            ActivationAction::Activate,
            promotion.promotion_hash(),
            epoch + 120,
            "1",
        );
        state
            .apply(
                &approval,
                Some(&promotion),
                &self.keys.authorities(),
                epoch + 120,
            )
            .unwrap();
        state
    }
}
#[allow(clippy::too_many_arguments)]
pub fn proposal(
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

/// Test-only authority. Rust exclusive borrowing replaces persistent-store
/// locking in these deterministic unit fixtures; production uses an OS lock.
pub struct TestAuthority {
    pub state: BackendActivationState,
    pub roots: TrustedAuthorities,
    pub guards: std::sync::atomic::AtomicUsize,
}
impl TestAuthority {
    pub fn new(state: BackendActivationState, roots: TrustedAuthorities) -> Self {
        Self {
            state,
            roots,
            guards: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}
struct TestGuard<'a>(&'a TestAuthority);
impl router_execution_decision::ActivationGuard for TestGuard<'_> {
    fn state(&self) -> &BackendActivationState {
        &self.0.state
    }
    fn authorities(&self) -> &TrustedAuthorities {
        &self.0.roots
    }
}
impl Drop for TestGuard<'_> {
    fn drop(&mut self) {
        self.0
            .guards
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
impl router_execution_decision::ActivationAuthority for TestAuthority {
    fn acquire(
        &self,
    ) -> router_execution_decision::Result<Box<dyn router_execution_decision::ActivationGuard + '_>>
    {
        self.guards
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Box::new(TestGuard(self)))
    }
}
pub fn decision(
    fixture: &Fixture,
    router: &PhaseRouter,
    context: &ValidatedPhaseContext,
    authority: &TestAuthority,
    now: u64,
    expires: u64,
) -> router_execution_decision::ExecutionDecision {
    use router_execution_decision::{ActivationAuthority, ExecutionDecision};
    let signed = proposal(
        &fixture.keys,
        &fixture.artifact,
        router,
        context,
        ProposalPurpose::Active(authority.state.state_hash().into()),
        now,
        expires,
        Some("c01"),
    );
    let proof = decide_active(
        &authority.state,
        router,
        context,
        Some(&signed),
        &authority.roots,
        now,
    )
    .unwrap();
    assert_eq!(proof.evidence().mode, ActiveDecisionMode::Semantic);
    ExecutionDecision::activated(router, context, &proof, &*authority.acquire().unwrap(), now)
        .unwrap()
}
