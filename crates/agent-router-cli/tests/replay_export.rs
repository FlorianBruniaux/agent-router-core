//! `feedback replay-export` on a review-only run: the runtime store holds the run,
//! the feedback store holds hand-recorded events and facts keyed by its run key.
//! No host process runs and no live model or provider is involved.
#![cfg(all(feature = "claude", any(target_os = "macos", target_os = "linux")))]
#[path = "support/native_fixture.rs"]
mod native_fixture;
use native_fixture::*;
use router_adapter_api::{SnapshotValidation, content_digest};
use router_eval::{
    CapabilityEvidenceVerification, ObservedOutcome, ReplayRecord, replay_deterministic,
    replay_deterministic_with_verifier,
};
use router_feedback::{FeedbackStore, parse_feedback};
use router_runtime::{CapabilityProofStore, StoredCapabilityProofVerifier};
use router_types::{
    FeedbackFact, FeedbackFactKind, FeedbackInput, FeedbackOrigin, HostUsage, HumanVerdict,
    IntegrationOutcome, PerceivedCost, UsageField, VerificationOutcome,
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const EVIDENCE: &str = "9999999999999999999999999999999999999999999999999999999999999999";
const REVIEWER: &str = "7777777777777777777777777777777777777777777777777777777777777777";

struct Case {
    f: Fixture,
    key: String,
    pricing: PathBuf,
    model: String,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
impl Case {
    fn new() -> Self {
        let f = Fixture::metadata("exit 0", 3000);
        f.review();
        let run = f.status()["run"].clone();
        let key = content_digest(
            &serde_json::to_vec(&(
                &run["run_id"],
                &run["definition_hash"],
                &run["approval_digest"],
            ))
            .unwrap(),
        );
        let context: Value =
            serde_json::from_slice(&fs::read(f.root.join("context.json")).unwrap()).unwrap();
        let model = context["candidates"][0]["model"]
            .as_str()
            .unwrap()
            .to_owned();
        let pricing = f.root.join("pricing.json");
        write(
            &pricing,
            &json!({"schema_version":1,"version":"test-v1","source":"synthetic",
            "observed_at_unix_seconds":now() - 10,
            "models":{&model:{"input_microusd_per_million":1000,"cached_input_microusd_per_million":100,"output_microusd_per_million":5000}}}),
        );
        Self {
            f,
            key,
            pricing,
            model,
        }
    }
    fn store(&self) -> FeedbackStore {
        FeedbackStore::open(&self.f.feedback).unwrap()
    }
    fn automated_with(&self, usage: HostUsage) {
        let mut input = self.input(FeedbackOrigin::Automated);
        input.measurements.usage = Some(usage);
        self.store().record(input, now()).unwrap();
    }
    /// An automated event of the same run at another state: another `run_hash`.
    fn automated_at(&self, run_hash: char, latency_ms: u64, usage: HostUsage) {
        let mut input = self.input(FeedbackOrigin::Automated);
        input.binding.run_hash = run_hash.to_string().repeat(64);
        input.measurements.latency_ms = Some(latency_ms);
        input.measurements.usage = Some(usage);
        self.store().record(input, now()).unwrap();
    }
    /// A human verdict on the frozen identity `run_hash`.
    fn human_on(&self, run_hash: char, success: VerificationOutcome) {
        let mut input = self.input(FeedbackOrigin::Human);
        input.binding.run_hash = run_hash.to_string().repeat(64);
        input.human = Some(HumanVerdict {
            success,
            quality: Some(90),
            perceived_cost: PerceivedCost::Acceptable,
            correction_required: Some(false),
            reviewer_sha256: REVIEWER.into(),
        });
        self.store().record(input, now()).unwrap();
    }
    fn input(&self, origin: FeedbackOrigin) -> FeedbackInput {
        let mut input = parse_feedback(include_bytes!(
            "../../../tests/fixtures/feedback/automated-unknown-v1.json"
        ))
        .unwrap();
        input.observed_at_unix_seconds = now();
        input.origin = origin;
        if origin == FeedbackOrigin::Automated {
            input.run_key_sha256 = Some(self.key.clone());
            input.transport = VerificationOutcome::Passed;
            input.measurements.latency_ms = Some(1234);
        }
        input
    }
    fn automated(&self) {
        self.store()
            .record(self.input(FeedbackOrigin::Automated), now())
            .unwrap();
    }
    fn human(&self, success: VerificationOutcome) {
        let mut input = self.input(FeedbackOrigin::Human);
        input.human = Some(HumanVerdict {
            success,
            quality: Some(90),
            perceived_cost: PerceivedCost::Acceptable,
            correction_required: Some(false),
            reviewer_sha256: REVIEWER.into(),
        });
        self.store().record(input, now()).unwrap();
    }
    fn fact(&self, kind: FeedbackFactKind) {
        self.store()
            .record_fact(
                FeedbackFact {
                    schema_version: 1,
                    run_key_sha256: self.key.clone(),
                    observed_at_unix_seconds: now(),
                    kind,
                },
                now(),
            )
            .unwrap();
    }
    fn verified(&self, validation: VerificationOutcome, objective: VerificationOutcome) {
        self.fact(FeedbackFactKind::Verification {
            validation,
            objective,
            evidence_sha256: EVIDENCE.into(),
        });
    }
    fn integrated(&self, outcome: IntegrationOutcome) {
        self.fact(FeedbackFactKind::Integration { outcome });
    }
    fn export(&self) -> Command {
        let mut cmd = command();
        cmd.args(["feedback", "--store"])
            .arg(&self.f.feedback)
            .args(["replay-export", "--definition"])
            .arg(self.f.root.join("definition.json"))
            .arg("--runtime-store")
            .arg(&self.f.store)
            .arg("--pricing")
            .arg(&self.pricing)
            .args(["--case-id", "case-1", "--family-id", "family-1"])
            .args(["--split", "training", "--json"]);
        cmd
    }
    fn exported(&self) -> (Value, ReplayRecord) {
        let path = self.f.root.join(format!("record-{}.json", now()));
        let report = checked(self.export().arg("--output").arg(&path), 0);
        (
            report,
            ReplayRecord::from_json(&fs::read(&path).unwrap()).unwrap(),
        )
    }
    fn refused(&self, code: &str) {
        let output = self.export().output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn an_accepted_run_exports_a_sealed_record_labelled_from_integration() {
    let case = Case::new();
    case.automated();
    case.verified(VerificationOutcome::Passed, VerificationOutcome::Passed);
    case.integrated(IntegrationOutcome::Applied);
    let path = case.f.root.join("record.json");
    let report = checked(case.export().arg("--output").arg(&path), 0);
    assert_eq!(report["label"]["basis"], "integration");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(report.get("record").is_none(), "the file holds the record");
    let bytes = fs::read(&path).unwrap();
    let record = ReplayRecord::from_json(&bytes).unwrap();
    assert_eq!(report["input_hash"], record.input_hash());
    let input = record.input();
    let label = input.label.as_ref().unwrap();
    assert!(!label.human_validated && !label.independent && label.reviewer_id.is_none());
    assert_eq!(label.evidence_sha256.as_deref(), Some(EVIDENCE));
    assert_eq!(
        label.expected_candidate_ids.iter().collect::<Vec<_>>(),
        [&report["executed_candidate_id"].as_str().unwrap().to_owned()]
    );
    let observed = input.observations.values().next().unwrap();
    assert_eq!(observed.elapsed_ms, Some(1234));
    assert_eq!(observed.outcomes.transport, ObservedOutcome::Passed);
    assert_eq!(
        observed.outcomes.command_validation,
        ObservedOutcome::Passed
    );
    assert_eq!(observed.outcomes.functional, ObservedOutcome::Passed);
    // The event carries no usage: an empty list, never a row of zeros.
    assert!(observed.usage.is_empty());
    assert_eq!(report["observations"]["usage"], "unknown");
    // The seal detects any edit.
    let edited = String::from_utf8(bytes)
        .unwrap()
        .replace("case-1", "case-2");
    assert!(ReplayRecord::from_json(edited.as_bytes()).is_err());
    // An existing file is never overwritten.
    let again = case.export().arg("--output").arg(&path).output().unwrap();
    assert_eq!(again.status.code(), Some(2));
}

#[test]
fn transport_success_alone_or_a_partial_signal_never_labels() {
    let case = Case::new();
    case.refused("feedback.replay.unlabeled");
    case.automated();
    case.refused("feedback.replay.unlabeled");
    // Applied without a passed objective, then a passed objective without integration.
    case.integrated(IntegrationOutcome::Applied);
    case.refused("feedback.replay.unlabeled");
    let other = Case::new();
    other.automated();
    other.verified(VerificationOutcome::Passed, VerificationOutcome::Passed);
    other.refused("feedback.replay.unlabeled");
}

#[test]
fn a_human_pass_sets_human_validated_with_its_reviewer() {
    let case = Case::new();
    case.automated();
    case.human(VerificationOutcome::Passed);
    let (report, record) = case.exported();
    assert_eq!(report["label"]["basis"], "human");
    let label = record.input().label.as_ref().unwrap();
    assert!(label.human_validated);
    assert_eq!(label.reviewer_id.as_deref(), Some(REVIEWER));
    assert!(!label.independent, "no independence is attested");
    assert!(label.evidence_sha256.is_none());
}

#[test]
fn a_negative_signal_refuses_because_the_label_cannot_say_not_expected() {
    for setup in [
        (|c: &Case| c.integrated(IntegrationOutcome::Discarded)) as fn(&Case),
        |c| c.verified(VerificationOutcome::Passed, VerificationOutcome::Failed),
        |c| c.human(VerificationOutcome::Failed),
        |c| {
            c.human(VerificationOutcome::Passed);
            c.integrated(IntegrationOutcome::Discarded);
        },
    ] {
        let case = Case::new();
        case.automated();
        setup(&case);
        case.refused("feedback.replay.rejected");
    }
}

fn usage(input: u64, cached: u64, output: u64) -> HostUsage {
    HostUsage {
        input_tokens: UsageField::host_reported(input),
        cached_input_tokens: UsageField::host_reported(cached),
        cache_write_input_tokens: UsageField::UNKNOWN,
        output_tokens: UsageField::host_reported(output),
        reasoning_output_tokens: UsageField::UNKNOWN,
    }
}
fn accept(case: &Case) {
    case.verified(VerificationOutcome::Passed, VerificationOutcome::Passed);
    case.integrated(IntegrationOutcome::Applied);
}
fn validation(record: &ReplayRecord) -> SnapshotValidation {
    SnapshotValidation {
        now_unix_seconds: record.input().snapshot.observed_at_unix_seconds,
        max_age_seconds: 300,
    }
}

fn proof_verifier(fixture: &Fixture) -> StoredCapabilityProofVerifier {
    let secret: [u8; 32] = fs::read(fixture.store.join("approval.key"))
        .unwrap()
        .try_into()
        .unwrap();
    let bindings = CapabilityProofStore::open_existing(&fixture.store)
        .unwrap()
        .verifier(&secret, vec![])
        .unwrap()
        .authenticated_bindings();
    StoredCapabilityProofVerifier::open_existing(&fixture.store, secret, bindings).unwrap()
}

#[test]
fn a_recorded_usage_replays_deterministically_without_manual_edits() {
    let case = Case::new();
    case.automated_with(usage(100, 40, 5));
    accept(&case);
    let (report, record) = case.exported();
    assert_eq!(report["request_free_text_fields"][0], "task.objective");
    assert_eq!(report["replay_context"], "without_asset_authority");
    assert_eq!(report["observations"]["usage"], "host_reported");
    let policy = report["policy_id"].as_str().unwrap();
    let rows = &record.input().observations[policy].usage;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].model.as_str(), case.model);
    // Total input, cache included: the pricing subtracts the cached part itself.
    assert_eq!(
        (
            rows[0].input_tokens,
            rows[0].cached_input_tokens,
            rows[0].output_tokens
        ),
        (100, 40, 5)
    );
    let unverified = replay_deterministic(&record, policy, validation(&record)).unwrap();
    assert_eq!(
        unverified.capability_evidence(),
        CapabilityEvidenceVerification::Unverified
    );
    assert!(
        unverified
            .violations()
            .iter()
            .any(|violation| violation.code == "capability.evidence.unverified")
    );
    let verifier = proof_verifier(&case.f);
    let first =
        replay_deterministic_with_verifier(&record, policy, validation(&record), Some(&verifier))
            .unwrap();
    let second =
        replay_deterministic_with_verifier(&record, policy, validation(&record), Some(&verifier))
            .unwrap();
    assert_eq!(
        first.capability_evidence(),
        CapabilityEvidenceVerification::Verified
    );
    assert_eq!(first.trace_hash(), second.trace_hash());
    assert!(first.violations().is_empty());
    // 60 uncached at 1000, 40 cached at 100, 5 output at 5000 per million, rounded up.
    assert_eq!(first.cost_microusd(), 1);
}

#[test]
fn an_undeclared_count_or_an_absent_usage_stays_unknown_never_zero() {
    let mut partial = usage(100, 40, 5);
    partial.cached_input_tokens = UsageField::UNKNOWN;
    for automated in [Some(partial), None] {
        let case = Case::new();
        match automated {
            Some(partial) => case.automated_with(partial),
            None => case.automated(),
        }
        accept(&case);
        let (report, record) = case.exported();
        let policy = report["policy_id"].as_str().unwrap();
        assert!(record.input().observations[policy].usage.is_empty());
        assert_eq!(report["observations"]["usage"], "unknown");
        // Nothing to price the selected model with: no zero is invented.
        let verifier = proof_verifier(&case.f);
        assert!(
            replay_deterministic_with_verifier(
                &record,
                policy,
                validation(&record),
                Some(&verifier),
            )
            .is_err()
        );
    }
}

#[test]
fn without_output_the_record_is_printed() {
    let case = Case::new();
    case.automated();
    case.human(VerificationOutcome::Passed);
    let report = checked(&mut case.export(), 0);
    let record = ReplayRecord::from_json(&serde_json::to_vec(&report["record"]).unwrap()).unwrap();
    assert_eq!(report["input_hash"], record.input_hash());
}

#[test]
fn the_latest_automated_event_of_a_run_supplies_usage_and_latency() {
    let case = Case::new();
    case.automated_at('b', 111, usage(100, 40, 5));
    case.automated_at('c', 222, usage(200, 0, 9));
    accept(&case);
    let (report, record) = case.exported();
    let observed = &record.input().observations[report["policy_id"].as_str().unwrap()];
    assert_eq!(observed.elapsed_ms, Some(222));
    assert_eq!(
        (
            observed.usage[0].input_tokens,
            observed.usage[0].output_tokens
        ),
        (200, 9)
    );
}

#[test]
fn a_human_verdict_of_another_run_does_not_label_this_one() {
    let case = Case::new();
    case.automated();
    case.human_on('d', VerificationOutcome::Passed);
    case.refused("feedback.replay.unlabeled");
}

#[test]
fn contradictory_human_verdicts_on_one_run_are_ambiguous() {
    let case = Case::new();
    case.automated_at('b', 1, usage(1, 0, 1));
    case.automated_at('c', 2, usage(1, 0, 1));
    case.human_on('b', VerificationOutcome::Failed);
    case.human_on('c', VerificationOutcome::Passed);
    case.refused("feedback.replay.ambiguous");
}

#[test]
fn a_refused_or_failed_output_leaves_no_temporary_file() {
    let case = Case::new();
    case.automated();
    accept(&case);
    let path = case.f.root.join("record.json");
    checked(case.export().arg("--output").arg(&path), 0);
    let leftovers = |dir: &std::path::Path| {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .count()
    };
    assert_eq!(leftovers(&case.f.root), 0);
    let before = fs::read(&path).unwrap();
    let refused = case.export().arg("--output").arg(&path).output().unwrap();
    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(
        fs::read(&path).unwrap(),
        before,
        "the target is never overwritten"
    );
    assert_eq!(leftovers(&case.f.root), 0);
    let missing = case.f.root.join("missing").join("record.json");
    let output = case
        .export()
        .arg("--output")
        .arg(&missing)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!missing.exists());
}

#[test]
fn qualified_pricing_is_explicitly_refused_before_writing_a_lossy_v1_replay() {
    let case = Case::new();
    case.automated();
    case.verified(VerificationOutcome::Passed, VerificationOutcome::Passed);
    case.integrated(IntegrationOutcome::Applied);
    write(
        &case.pricing,
        &json!({"schema_version":2,"version":"fixture-v2","source":"synthetic","observed_at_unix_seconds":90,"models":{}}),
    );
    let path = case.f.root.join("must-not-exist.json");
    let output = case.export().arg("--output").arg(&path).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("feedback.replay.qualified_pricing_unsupported"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!path.exists());
}
