#![allow(dead_code)]
use router_types::*;
use std::collections::BTreeSet;
pub fn preferences() -> FeedbackPreferences {
    FeedbackPreferences {
        schema_version: 1,
        collection_enabled: true,
        learning_enabled: true,
        retention_seconds: 60,
    }
}
pub fn input(now: u64, human: bool) -> FeedbackInput {
    FeedbackInput {
        schema_version: 1,
        observed_at_unix_seconds: now,
        started_at_unix_seconds: None,
        run_key_sha256: None,
        binding: FeedbackBinding {
            task_hash: "a".repeat(64),
            run_hash: "b".repeat(64),
            receipt_hash: "c".repeat(64),
            policy_hash: "d".repeat(64),
            catalog_hash: "e".repeat(64),
            snapshot_hash: "f".repeat(64),
            producer_version: "private-producer-canary".into(),
            provenance_sha256: "1".repeat(64),
        },
        context: FeedbackContext {
            task_kind: TaskKind::Explore,
            risk: RiskLevel::Low,
            model: ModelId::parse("private-model-canary").unwrap(),
            effort: EffortLevel::Medium,
            harness: HarnessId::parse("private-harness-canary").unwrap(),
            transport: "private-transport-canary".into(),
            agent: Some("private-agent-canary".into()),
            skills: BTreeSet::from(["private-skill-canary".into()]),
            plan: "private-plan-canary".into(),
            propensity_micros: None,
            route: None,
        },
        origin: if human {
            FeedbackOrigin::Human
        } else {
            FeedbackOrigin::Automated
        },
        transport: VerificationOutcome::Passed,
        validation: VerificationOutcome::Unknown,
        objective: VerificationOutcome::Unknown,
        verification_evidence_sha256: None,
        human: human.then(|| HumanVerdict {
            success: VerificationOutcome::Unknown,
            quality: Some(75),
            perceived_cost: PerceivedCost::Acceptable,
            correction_required: None,
            reviewer_sha256: "2".repeat(64),
        }),
        failure: None,
        measurements: FeedbackMeasurements {
            usage_scope: None,
            cost_microusd: None,
            latency_ms: Some(50),
            tokens: None,
            attempts: 1,
            escalations: 0,
            usage: None,
        },
        comment_sha256: Some("3".repeat(64)),
    }
}
