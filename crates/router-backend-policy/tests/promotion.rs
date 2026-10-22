//! All reviewers, labels, keys and model observations here are synthetic.
//! Positive tests exercise proof mechanics, never authorize a production backend.
#[path = "../../../tests/support/capability_verifier.rs"]
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
        let keys = Keys::new();
        let authorities = keys.authorities();
        let request: PhaseRouteRequest = serde_json::from_slice(include_bytes!(
            "../../../fixtures/examples/phase-request.json"
        ))
        .unwrap();
        let snapshot: HostObservation = serde_json::from_slice(include_bytes!(
            "../../../fixtures/examples/phase-snapshot.json"
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
            "../../../fixtures/examples/phase-catalog.json"
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
            Some(&fixture_proofs::FixtureVerifier),
        )
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

#[test]
fn signed_heldout_gain_promotes_exact_secondary_without_forging_baseline() {
    let fixture = Fixture::new();
    let authorities = fixture.keys.authorities();
    let promotion = fixture.promotion();
    assert!(promotion.report().semantic_enabled);
    assert_eq!(promotion.report().baseline.total_cost_microusd, 400);
    assert_eq!(promotion.report().semantic.total_cost_microusd, 200);
    let state = fixture.active();
    let signed = proposal(
        &fixture.keys,
        &fixture.artifact,
        &fixture.router,
        &fixture.context,
        ProposalPurpose::Active(state.state_hash().into()),
        120,
        125,
        Some("c01"),
    );
    let decision = decide_active(
        &state,
        &fixture.router,
        &fixture.context,
        Some(&signed),
        &authorities,
        124,
    )
    .unwrap();
    assert_eq!(decision.evidence().mode, ActiveDecisionMode::Semantic);
    assert_eq!(decision.selection().unwrap().candidate.id, "secondary");
    assert_eq!(
        decision.baseline(),
        &fixture.router.route(&fixture.context).unwrap()
    );
    assert_eq!(
        decision.baseline().selected.as_ref().unwrap().candidate.id,
        "primary"
    );
    decision
        .validate_current(&state, &fixture.router, &fixture.context, &authorities, 124)
        .unwrap();
    assert!(matches!(
        decision.validate_current(&state, &fixture.router, &fixture.context, &authorities, 125),
        Err(PromotionError::Freshness)
    ));
    assert!(matches!(
        decision.validate_current(&state, &fixture.router, &fixture.context, &authorities, 121),
        Err(PromotionError::State)
    ));
}

#[test]
fn invalid_signature_wrong_pool_context_purpose_and_expiry_fall_back_without_permissions() {
    let fixture = Fixture::new();
    let authorities = fixture.keys.authorities();
    let state = fixture.active();
    for mutation in 0..6 {
        let mut signed = proposal(
            &fixture.keys,
            &fixture.artifact,
            &fixture.router,
            &fixture.context,
            ProposalPurpose::Active(state.state_hash().into()),
            120,
            125,
            Some("c01"),
        );
        match mutation {
            0 => signed.signature_hex = "0".repeat(128),
            1 => signed.statement.proposal.candidate_id = Some("injected".into()),
            2 => signed.statement.request_sha256 = "0".repeat(64),
            3 => signed.statement.purpose = ProposalPurpose::Evaluation("a".repeat(64)),
            4 => signed.statement.expires_at_unix_seconds = 121,
            _ => signed.statement.proposal.confidence_micros = 1,
        }
        if mutation != 0 {
            signed = fixture.keys.sign(AuthorityRole::Backend, signed.statement);
        }
        let decision = decide_active(
            &state,
            &fixture.router,
            &fixture.context,
            Some(&signed),
            &authorities,
            122,
        )
        .unwrap();
        assert_eq!(
            decision.evidence().mode,
            ActiveDecisionMode::DeterministicFallback,
            "mutation {mutation}"
        );
        assert_eq!(decision.selection(), decision.baseline().selected.as_ref());
    }
    let absent = decide_active(
        &state,
        &fixture.router,
        &fixture.context,
        None,
        &authorities,
        122,
    )
    .unwrap();
    assert_eq!(
        absent.evidence().reason,
        ActiveDecisionReason::MissingProposal
    );
    let abstain = Fixture::with_failure(BackendFailurePolicy::Abstain);
    let state = abstain.active();
    let result = decide_active(
        &state,
        &abstain.router,
        &abstain.context,
        None,
        &abstain.keys.authorities(),
        122,
    )
    .unwrap();
    assert_eq!(result.evidence().mode, ActiveDecisionMode::Abstained);
    assert!(result.selection().is_none());
}

#[test]
fn signed_rollback_revokes_decisions_and_history_requires_independent_head() {
    let fixture = Fixture::new();
    let authorities = fixture.keys.authorities();
    let promotion = fixture.promotion();
    let mut state = fixture.active();
    let signed = proposal(
        &fixture.keys,
        &fixture.artifact,
        &fixture.router,
        &fixture.context,
        ProposalPurpose::Active(state.state_hash().into()),
        120,
        150,
        Some("c01"),
    );
    let decision = decide_active(
        &state,
        &fixture.router,
        &fixture.context,
        Some(&signed),
        &authorities,
        122,
    )
    .unwrap();
    let rollback = fixture.approval(
        &state,
        ActivationAction::Rollback,
        fixture.context.policy_hash(),
        123,
        "2",
    );
    state.apply(&rollback, None, &authorities, 123).unwrap();
    assert!(state.active_promotion().is_none());
    assert!(
        decision
            .validate_current(&state, &fixture.router, &fixture.context, &authorities, 124)
            .is_err()
    );
    assert!(state.apply(&rollback, None, &authorities, 124).is_err());
    let promotions = BTreeMap::from([(promotion.promotion_hash().into(), promotion)]);
    let restored = BackendActivationState::restore(
        fixture.context.policy_hash(),
        &"9".repeat(64),
        state.events(),
        &promotions,
        &authorities,
        state.state_hash(),
        124,
    )
    .unwrap();
    assert_eq!(restored.state_hash(), state.state_hash());
    assert!(
        BackendActivationState::restore(
            fixture.context.policy_hash(),
            &"9".repeat(64),
            &state.events()[..1],
            &promotions,
            &authorities,
            state.state_hash(),
            124
        )
        .is_err()
    );
    assert!(
        BackendActivationState::restore(
            fixture.context.policy_hash(),
            &"8".repeat(64),
            state.events(),
            &promotions,
            &authorities,
            state.state_hash(),
            124
        )
        .is_err()
    );
    let fallback = decide_active(
        &restored,
        &fixture.router,
        &fixture.context,
        None,
        &authorities,
        124,
    )
    .unwrap();
    assert_eq!(fallback.evidence().reason, ActiveDecisionReason::Inactive);
}

#[test]
fn proofs_cannot_cross_changed_external_trust_roots() {
    let fixture = Fixture::new();
    let promotion = fixture.promotion();
    let mut changed = Keys::new();
    changed.reviewer = SigningKey::from_bytes(&[9; 32]);
    let roots = changed.authorities();
    let mut state =
        BackendActivationState::new(fixture.context.policy_hash(), &"9".repeat(64)).unwrap();
    let approval = fixture.approval(
        &state,
        ActivationAction::Activate,
        promotion.promotion_hash(),
        120,
        "1",
    );
    assert!(matches!(
        state.apply(&approval, Some(&promotion), &roots, 120),
        Err(PromotionError::Authority)
    ));
    let state = fixture.active();
    let signed = proposal(
        &fixture.keys,
        &fixture.artifact,
        &fixture.router,
        &fixture.context,
        ProposalPurpose::Active(state.state_hash().into()),
        120,
        150,
        Some("c01"),
    );
    let proof = decide_active(
        &state,
        &fixture.router,
        &fixture.context,
        Some(&signed),
        &fixture.keys.authorities(),
        122,
    )
    .unwrap();
    assert!(matches!(
        proof.validate_current(&state, &fixture.router, &fixture.context, &roots, 123),
        Err(PromotionError::Authority)
    ));
    assert!(matches!(
        decide_active(
            &state,
            &fixture.router,
            &fixture.context,
            Some(&signed),
            &roots,
            123
        ),
        Err(PromotionError::Authority)
    ));
}

#[test]
fn fabricated_reports_unsigned_labels_and_late_or_leaked_criteria_do_not_promote() {
    let fixture = Fixture::new();
    for mutation in 0..7 {
        let mut evidence = fixture.evidence.clone();
        match mutation {
            0 => evidence.cases[0].label.signature_hex = "0".repeat(128),
            1 => {
                evidence
                    .criteria
                    .training_families
                    .insert("synthetic-family-0".into());
            }
            2 => evidence.criteria.registered_at_unix_seconds = 110,
            3 => evidence.criteria.minimum_families = 3,
            4 => evidence.canary.statement.accepted = false,
            5 => {
                evidence.canary.statement.evidence_sha256 =
                    evidence.shadow.statement.evidence_sha256.clone()
            }
            _ => evidence.shadow.statement.hard_constraint_violations = 1,
        };
        if (1..=3).contains(&mutation) {
            evidence.criteria_registration = fixture.keys.sign(
                AuthorityRole::GateOwner,
                CriteriaStatement {
                    schema_version: 1,
                    backend_artifact_hash: fixture.artifact.content_hash().unwrap(),
                    criteria_sha256: criteria_hash(&evidence.criteria).unwrap(),
                    registered_at_unix_seconds: evidence.criteria.registered_at_unix_seconds,
                },
            );
        }
        if mutation >= 4 {
            evidence.shadow = fixture
                .keys
                .sign(AuthorityRole::GateOwner, evidence.shadow.statement);
            evidence.canary = fixture
                .keys
                .sign(AuthorityRole::GateOwner, evidence.canary.statement);
        }
        assert!(
            evaluate_promotion_with_verifier(
                &fixture.artifact,
                &evidence,
                &fixture.keys.authorities(),
                120,
                Some(&fixture_proofs::FixtureVerifier)
            )
            .is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn duplicate_role_keys_and_expired_activation_are_rejected() {
    let fixture = Fixture::new();
    let key = fixture.keys.backend.verifying_key().to_bytes();
    assert!(
        TrustedAuthorities::new([
            (AuthorityRole::Backend, "backend".into(), key),
            (AuthorityRole::HumanReviewer, "reviewer".into(), key)
        ])
        .is_err()
    );
    let promotion = fixture.promotion();
    let mut state =
        BackendActivationState::new(fixture.context.policy_hash(), &"9".repeat(64)).unwrap();
    let approval = fixture.approval(
        &state,
        ActivationAction::Activate,
        promotion.promotion_hash(),
        120,
        "1",
    );
    assert!(matches!(
        state.apply(
            &approval,
            Some(&promotion),
            &fixture.keys.authorities(),
            220
        ),
        Err(PromotionError::Freshness)
    ));
    assert!(state.events().is_empty());
    assert!(state.active_promotion().is_none());
}

#[test]
fn valid_resignatures_do_not_bypass_heldout_labels_diversity_or_unknown_outcomes() {
    let fixture = Fixture::new();
    for mutation in 0..5 {
        let mut evidence = fixture.evidence.clone();
        let mut input = evidence.cases[0].record.input().clone();
        match mutation {
            0 => input.split = DatasetSplit::Training,
            1 => input.label.as_mut().unwrap().human_validated = false,
            2 => input.label.as_mut().unwrap().independent = false,
            3 => input.family_id = evidence.cases[1].record.input().family_id.clone(),
            _ => evidence.criteria.rules.push(MetricRule {
                metric: PromotionMetric::FunctionalSuccess,
                minimum_improvement_micros: 1,
                maximum_regression_micros: 0,
            }),
        }
        evidence.cases[0].record = ReplayRecord::seal(input).unwrap();
        fixture.resign_evaluation(&mut evidence);
        assert!(
            matches!(
                evaluate_backend_with_verifier(
                    &fixture.artifact,
                    &evidence.criteria,
                    &evidence.criteria_registration,
                    &evidence.cases,
                    &fixture.keys.authorities(),
                    120,
                    Some(&fixture_proofs::FixtureVerifier)
                ),
                Err(PromotionError::Gate)
            ),
            "mutation {mutation}"
        );
    }
}

#[test]
fn role_reassignment_unknown_json_fields_and_duplicate_keys_never_create_authority() {
    let fixture = Fixture::new();
    let promotion = fixture.promotion();
    let mut state =
        BackendActivationState::new(fixture.context.policy_hash(), &"9".repeat(64)).unwrap();
    let approval = fixture.approval(
        &state,
        ActivationAction::Activate,
        promotion.promotion_hash(),
        120,
        "1",
    );
    let wrong = fixture
        .keys
        .sign(AuthorityRole::GateOwner, approval.statement.clone());
    assert!(matches!(
        state.apply(&wrong, Some(&promotion), &fixture.keys.authorities(), 120),
        Err(PromotionError::Authority)
    ));
    let mut value = serde_json::to_value(&approval).unwrap();
    value["trusted"] = serde_json::json!(true);
    assert!(
        parse_document::<Signed<ActivationApproval>>(&serde_json::to_vec(&value).unwrap()).is_err()
    );
    let text =
        serde_json::to_string(&approval)
            .unwrap()
            .replacen('{', "{\"key_id\":\"approver\",", 1);
    assert!(parse_document::<Signed<ActivationApproval>>(text.as_bytes()).is_err());
    let mut future = approval.statement;
    future.issued_at_unix_seconds = 121;
    let future = fixture.keys.sign(AuthorityRole::Approver, future);
    assert!(matches!(
        state.apply(&future, Some(&promotion), &fixture.keys.authorities(), 120),
        Err(PromotionError::Freshness)
    ));
}

#[test]
fn documents_between_snapshot_and_policy_bounds_parse_and_larger_are_limited() {
    // The JSON parser's default bound is 4 MiB; the policy bound is 16 MiB.
    let fixture = Fixture::new();
    let state =
        BackendActivationState::new(fixture.context.policy_hash(), &"9".repeat(64)).unwrap();
    let promotion = fixture.promotion();
    let approval = fixture.approval(
        &state,
        ActivationAction::Activate,
        promotion.promotion_hash(),
        120,
        "1",
    );
    let compact = serde_json::to_vec(&approval).unwrap();
    let mut padded = vec![compact[0]];
    padded.resize(1 + 5 * 1024 * 1024, b' ');
    padded.extend_from_slice(&compact[1..]);
    let parsed = parse_document::<Signed<ActivationApproval>>(&padded).unwrap();
    assert_eq!(serde_json::to_vec(&parsed).unwrap(), compact);
    assert!(matches!(
        parse_document::<Signed<ActivationApproval>>(&vec![b' '; MAX_DOCUMENT_BYTES + 1]),
        Err(PromotionError::Limit)
    ));
}
#[test]
fn baseline_policy_is_pinned_before_inactive_active_and_rollback_fallback() {
    let fixture = Fixture::new();
    let roots = fixture.keys.authorities();
    let input = fixture.evidence.cases[0].record.input();
    let policy = PhasePolicy {
        version: "unapproved-replacement-policy".into(),
        minimum_utility_micros: 1_000_000_000,
        ..PhasePolicy::default()
    };
    let other_router = PhaseRouter::new(policy).unwrap();
    let snapshot = fixture_proofs::from_observation(
        input.snapshot.clone(),
        SnapshotValidation {
            now_unix_seconds: 122,
            max_age_seconds: 300,
        },
    )
    .unwrap();
    let catalog = Catalog::from_json(&serde_json::to_vec(&input.catalog).unwrap()).unwrap();
    let other_context = other_router
        .context(input.request.clone(), &snapshot, &catalog)
        .unwrap();
    assert!(
        fixture
            .router
            .route(&fixture.context)
            .unwrap()
            .selected
            .is_some()
    );
    assert!(
        other_router
            .route(&other_context)
            .unwrap()
            .selected
            .is_none()
    );
    let inactive =
        BackendActivationState::new(fixture.context.policy_hash(), &"9".repeat(64)).unwrap();
    let active = fixture.active();
    let mut rolled_back = fixture.active();
    let rollback = fixture.approval(
        &rolled_back,
        ActivationAction::Rollback,
        fixture.context.policy_hash(),
        123,
        "2",
    );
    rolled_back.apply(&rollback, None, &roots, 123).unwrap();
    for state in [inactive, active, rolled_back] {
        let valid =
            decide_active(&state, &fixture.router, &fixture.context, None, &roots, 124).unwrap();
        valid
            .validate_current(&state, &fixture.router, &fixture.context, &roots, 124)
            .unwrap();
        assert!(matches!(
            decide_active(&state, &other_router, &other_context, None, &roots, 124),
            Err(PromotionError::Context)
        ));
        assert!(matches!(
            valid.validate_current(&state, &other_router, &other_context, &roots, 124),
            Err(PromotionError::Context)
        ));
    }
    let wrong_pin = BackendActivationState::new(&"0".repeat(64), &"9".repeat(64)).unwrap();
    assert!(matches!(
        decide_active(
            &wrong_pin,
            &fixture.router,
            &fixture.context,
            None,
            &roots,
            124
        ),
        Err(PromotionError::Context)
    ));
}

#[test]
fn aggregate_gain_cannot_hide_a_complete_heldout_family_regression() {
    let fixture = Fixture::new();
    let mut evidence = fixture.evidence.clone();
    for (index, expected) in ["secondary", "primary"].into_iter().enumerate() {
        let mut input = evidence.cases[index].record.input().clone();
        input.label.as_mut().unwrap().expected_candidate_ids = BTreeSet::from([expected.into()]);
        evidence.cases[index].record = ReplayRecord::seal(input).unwrap();
    }
    fixture.resign_evaluation(&mut evidence);
    // Aggregate accuracy stays 50%, cost improves 50%, but family 1 loses
    // its only correct selection. Every document has a valid external signature.
    assert!(matches!(
        evaluate_backend_with_verifier(
            &fixture.artifact,
            &evidence.criteria,
            &evidence.criteria_registration,
            &evidence.cases,
            &fixture.keys.authorities(),
            120,
            Some(&fixture_proofs::FixtureVerifier)
        ),
        Err(PromotionError::Gate)
    ));
    assert!(matches!(
        evaluate_promotion_with_verifier(
            &fixture.artifact,
            &evidence,
            &fixture.keys.authorities(),
            120,
            Some(&fixture_proofs::FixtureVerifier)
        ),
        Err(PromotionError::Gate)
    ));
}

#[test]
fn stable_family_needs_no_individual_gain_and_reports_are_bound() {
    let fixture = Fixture::new();
    let model = |name: &str| ModelId::parse(name).unwrap();
    let mut evidence = fixture.evidence.clone();
    let mut input = evidence.cases[1].record.input().clone();
    let baseline_price = input
        .pricing
        .models
        .get(&model("fixture-best"))
        .unwrap()
        .clone();
    input
        .pricing
        .models
        .insert(model("fixture-second"), baseline_price);
    evidence.cases[1].record = ReplayRecord::seal(input).unwrap();
    fixture.resign_evaluation(&mut evidence);
    let evaluation = evaluate_backend_with_verifier(
        &fixture.artifact,
        &evidence.criteria,
        &evidence.criteria_registration,
        &evidence.cases,
        &fixture.keys.authorities(),
        120,
        Some(&fixture_proofs::FixtureVerifier),
    )
    .unwrap();
    assert_eq!(evaluation.family_reports().len(), 2);
    let stable = &evaluation.family_reports()["synthetic-family-1"];
    assert_eq!(
        stable.baseline.total_cost_microusd,
        stable.semantic.total_cost_microusd
    );
    assert_eq!(
        stable.baseline.route_accuracy_micros,
        stable.semantic.route_accuracy_micros
    );
    assert!(
        evaluation.report().semantic.total_cost_microusd
            < evaluation.report().baseline.total_cost_microusd
    );
    assert_ne!(
        evaluation.evaluation_hash(),
        fixture.evidence.shadow.statement.evaluation_sha256
    );
    for trial in [&mut evidence.shadow, &mut evidence.canary] {
        trial.statement.evaluation_sha256 = evaluation.evaluation_hash().into();
        *trial = fixture
            .keys
            .sign(AuthorityRole::GateOwner, trial.statement.clone());
    }
    let promotion = evaluate_promotion_with_verifier(
        &fixture.artifact,
        &evidence,
        &fixture.keys.authorities(),
        120,
        Some(&fixture_proofs::FixtureVerifier),
    )
    .unwrap();
    assert_eq!(promotion.family_reports(), evaluation.family_reports());
}
