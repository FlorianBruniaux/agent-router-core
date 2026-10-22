#[path = "../../../tests/support/capability_verifier.rs"]
mod fixture_proofs;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use router_eval::*;
use router_types::PhaseAbstention;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/evaluation")
}
fn bundles() -> Vec<CandidateReplay> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root().join("replay-manifest-v1.json")).unwrap()).unwrap();
    manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let bundle = CandidateReplay::from_json_with_verifier(
                &fs::read(root().join(entry["path"].as_str().unwrap())).unwrap(),
                Some(&fixture_proofs::FixtureVerifier),
            )
            .unwrap();
            assert_eq!(
                bundle.content_hash(),
                entry["content_hash"].as_str().unwrap()
            );
            assert_eq!(
                bundle.record().input_hash(),
                entry["input_hash"].as_str().unwrap()
            );
            bundle
        })
        .collect()
}

#[test]
fn all_one_hundred_contexts_replay_to_frozen_receipts_without_claiming_human_labels() {
    let bundles = bundles();
    assert_eq!(bundles.len(), 100);
    let mut ids = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    let mut families = BTreeMap::new();
    let mut selected = BTreeSet::new();
    let mut abstentions = BTreeSet::new();
    let mut phases = BTreeSet::new();
    let mut ood = 0;
    for bundle in &bundles {
        assert!(ids.insert(bundle.case().id.clone()));
        assert!(hashes.insert(bundle.record().input_hash().to_owned()));
        assert!(!bundle.case().human_validated);
        assert!(!bundle.proposed_decision().human_validated);
        let label = bundle.record().input().label.as_ref().unwrap();
        assert!(!label.human_validated);
        assert!(!label.independent);
        assert!(label.reviewer_id.is_none());
        assert!(label.evidence_sha256.is_none());
        if let Some(old) = families.insert(bundle.case().family_id.clone(), bundle.case().split) {
            assert_eq!(old, bundle.case().split);
        }
        for (policy_id, trace) in bundle
            .replay_with_verifier(Some(&fixture_proofs::FixtureVerifier))
            .unwrap()
        {
            assert!(trace.violations().is_empty());
            assert_eq!(trace.receipt(), &bundle.expected_receipts()[&policy_id]);
            assert_eq!(
                trace.trace_hash(),
                bundle.expected_trace_hashes()[&policy_id]
            );
            assert_eq!(trace.outcomes(), &VerificationOutcomes::default());
            phases.insert(format!("{:?}", trace.receipt().phase));
            if let Some(selection) = &trace.receipt().selected {
                selected.insert(selection.candidate.id.clone());
            }
            if let Some(abstention) = &trace.receipt().abstention {
                abstentions.insert(format!("{abstention:?}"));
            }
        }
        if bundle.case().out_of_domain {
            ood += 1;
            assert_eq!(
                bundle.proposed_decision().abstention,
                Some(PhaseAbstention::EmptyPool)
            );
        }
    }
    assert_eq!(families.len(), 20);
    assert_eq!(ood, 20);
    assert_eq!(
        selected,
        BTreeSet::from(["primary".into(), "secondary".into(), "economy".into()])
    );
    assert_eq!(
        abstentions,
        BTreeSet::from([
            "EmptyPool".into(),
            "NoEligibleCandidate".into(),
            "Ambiguous".into(),
            "AllUnavailable".into()
        ])
    );
    assert_eq!(phases.len(), 3);
}

#[test]
fn heldout_candidate_fixtures_cannot_promote_even_when_supplied_thresholds_are_zero() {
    let heldout: Vec<_> = bundles()
        .into_iter()
        .filter(|bundle| bundle.case().split == DatasetSplit::HeldOut)
        .collect();
    let pairs: Vec<_> = heldout
        .iter()
        .map(|bundle| {
            let mut traces = bundle
                .replay_with_verifier(Some(&fixture_proofs::FixtureVerifier))
                .unwrap();
            PairedTrace {
                baseline: traces.remove("baseline").unwrap(),
                semantic: traces.remove("shadow_candidate").unwrap(),
            }
        })
        .collect();
    let criteria = PromotionCriteria {
        schema_version: 1,
        dataset_hash: dataset_hash(&pairs).unwrap(),
        registered_at_unix_seconds: 1_700_000_000,
        registration_evidence_sha256: "f".repeat(64),
        minimum_cases: 20,
        minimum_families: 4,
        policy_authors: BTreeSet::from(["fixture-generator".into()]),
        training_families: BTreeSet::new(),
        rules: vec![
            MetricRule {
                metric: PromotionMetric::RouteAccuracy,
                minimum_improvement_micros: 0,
                maximum_regression_micros: 0,
            },
            MetricRule {
                metric: PromotionMetric::Cost,
                minimum_improvement_micros: 1,
                maximum_regression_micros: 0,
            },
        ],
    };
    let report = compare_shadow(&pairs, Some(&criteria)).unwrap();
    assert!(!report.semantic_enabled);
    assert!(
        report
            .promotion_blockers
            .iter()
            .any(|b| b == "promotion.independent_human_labels_required")
    );
    assert!(report.baseline.route_accuracy_micros.is_none());
}

#[test]
fn bundle_tampering_rehash_and_false_human_claims_are_rejected() {
    let bundle = bundles().remove(0);
    let original = serde_json::to_value(&bundle).unwrap();
    for index in 0..5 {
        let mut value = original.clone();
        match index {
            0 => value["case"]["human_validated"] = true.into(),
            1 => value["proposed_decision"]["human_validated"] = true.into(),
            2 => {
                value["expected_receipts"]["baseline"]["selected"]["candidate"]["model"] =
                    "fixture-gamma".into()
            }
            3 => {
                value["record"]["input"]["request"]["task"]["objective"] =
                    "Changed after review".into()
            }
            _ => value["expected_trace_hashes"]["baseline"] = "0".repeat(64).into(),
        }
        value["content_hash"] = "".into();
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"agent-router:candidate-replay:v1\0");
        let raw: CandidateReplay = serde_json::from_value(value.clone()).unwrap();
        hash.update(raw.canonical_json().unwrap());
        value["content_hash"] = hex::encode(hash.finalize()).into();
        assert!(
            CandidateReplay::from_json_with_verifier(
                &serde_json::to_vec(&value).unwrap(),
                Some(&fixture_proofs::FixtureVerifier)
            )
            .is_err(),
            "tamper {index}"
        );
    }
}

#[test]
fn human_review_worksheet_is_complete_and_hash_bound_without_prefilled_attestations() {
    let worksheet: serde_json::Value =
        serde_json::from_slice(&fs::read(root().join("human-review-worksheet-v1.json")).unwrap())
            .unwrap();
    let rows = worksheet["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 100);
    let bundles = bundles();
    for (row, bundle) in rows.iter().zip(bundles) {
        assert_eq!(row["case_id"], bundle.case().id);
        assert_eq!(row["input_hash"], bundle.record().input_hash());
        assert_eq!(row["human_validated"], false);
        assert_eq!(row["independent"], false);
        for field in [
            "reviewer_id",
            "evidence_sha256",
            "reviewed_expected_candidate_ids",
            "reviewed_expect_abstention",
        ] {
            assert!(row[field].is_null());
        }
    }
}
