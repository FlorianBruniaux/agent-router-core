#![cfg(unix)]
// All keys, observations and human claims below are synthetic test inputs.
#[path = "support/unknown_observation.rs"]
mod unknown_observation;
mod fixture {
    #![allow(dead_code)]
    include!("../../router-backend-store/tests/support/fixture.rs");
    use router_backend_store::{AuthorityKey, StoreConfig};
    pub(super) struct Live {
        pub config: StoreConfig,
        pub artifact: BackendArtifact,
        pub evidence: PromotionEvidence,
        keys: Keys,
    }
    pub(super) fn clock() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
    fn shift(value: &mut serde_json::Value, delta: u64) {
        match value {
            serde_json::Value::Object(fields) => {
                for (key, value) in fields {
                    if key.ends_with("_unix_seconds") && value.is_u64() {
                        *value = (value.as_u64().unwrap() + delta).into();
                    } else {
                        shift(value, delta);
                    }
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    shift(value, delta);
                }
            }
            _ => {}
        }
    }
    impl Live {
        pub(super) fn new() -> Self {
            let mut fixture = Fixture::new();
            let now = clock();
            let delta = now - 120;
            fixture.artifact.created_at_unix_seconds += delta;
            for case in &mut fixture.evidence.cases {
                let mut input = case.record.input().clone();
                let mut snapshot = serde_json::to_value(&input.snapshot).unwrap();
                shift(&mut snapshot, delta);
                input.snapshot = super::unknown_observation::from_example(
                    serde_json::from_value::<HostObservation>(snapshot).unwrap(),
                );
                input.pricing.observed_at_unix_seconds += delta;
                case.record = ReplayRecord::seal(input).unwrap();
                case.evaluated_at_unix_seconds += delta;
            }
            let input = fixture.evidence.cases[0].record.input();
            let snapshot = fixture_proofs::from_observation(
                input.snapshot.clone(),
                SnapshotValidation {
                    now_unix_seconds: now,
                    max_age_seconds: 300,
                },
            )
            .unwrap();
            let catalog = Catalog::from_json(&serde_json::to_vec(&input.catalog).unwrap()).unwrap();
            fixture.context = fixture
                .router
                .context(input.request.clone(), &snapshot, &catalog)
                .unwrap();
            for case in &mut fixture.evidence.cases {
                case.proposal = proposal(
                    &fixture.keys,
                    &fixture.artifact,
                    &fixture.router,
                    &fixture.context,
                    ProposalPurpose::Evaluation(case.record.input_hash().into()),
                    110 + delta,
                    150 + delta,
                    Some("c01"),
                );
                case.label = fixture.keys.sign(
                    AuthorityRole::HumanReviewer,
                    HumanLabelStatement {
                        schema_version: 1,
                        replay_input_hash: case.record.input_hash().into(),
                        label_sha256: label_hash(case.record.input().label.as_ref().unwrap())
                            .unwrap(),
                        reviewed_at_unix_seconds: 105 + delta,
                    },
                );
            }
            fixture.evidence.criteria.dataset_hash =
                evaluation_dataset_hash(&fixture.evidence.cases).unwrap();
            fixture.evidence.criteria.registered_at_unix_seconds += delta;
            fixture.evidence.criteria_registration = fixture.keys.sign(
                AuthorityRole::GateOwner,
                CriteriaStatement {
                    schema_version: 1,
                    backend_artifact_hash: fixture.artifact.content_hash().unwrap(),
                    criteria_sha256: criteria_hash(&fixture.evidence.criteria).unwrap(),
                    registered_at_unix_seconds: 99 + delta,
                },
            );
            let evaluation = evaluate_backend_with_verifier(
                &fixture.artifact,
                &fixture.evidence.criteria,
                &fixture.evidence.criteria_registration,
                &fixture.evidence.cases,
                &fixture.keys.authorities(),
                now,
                Some(&fixture_proofs::FixtureVerifier),
            )
            .unwrap();
            for trial in [&mut fixture.evidence.shadow, &mut fixture.evidence.canary] {
                trial.statement.backend_artifact_hash = fixture.artifact.content_hash().unwrap();
                trial.statement.evaluation_sha256 = evaluation.evaluation_hash().into();
                trial.statement.started_at_unix_seconds += delta;
                trial.statement.completed_at_unix_seconds += delta;
                *trial = fixture
                    .keys
                    .sign(AuthorityRole::GateOwner, trial.statement.clone());
            }
            let config = StoreConfig {
                schema_version: 1,
                baseline_policy_hash: fixture.context.policy_hash().into(),
                scope_sha256: "9".repeat(64),
                authorities: [
                    (AuthorityRole::Backend, "backend", &fixture.keys.backend),
                    (
                        AuthorityRole::HumanReviewer,
                        "reviewer",
                        &fixture.keys.reviewer,
                    ),
                    (AuthorityRole::GateOwner, "gate", &fixture.keys.gate),
                    (AuthorityRole::Approver, "approver", &fixture.keys.approver),
                ]
                .into_iter()
                .map(|(role, id, key)| AuthorityKey {
                    role,
                    id: id.into(),
                    public_key_hex: hex::encode(key.verifying_key().as_bytes()),
                })
                .collect(),
            };
            Self {
                config,
                artifact: fixture.artifact,
                evidence: fixture.evidence,
                keys: fixture.keys,
            }
        }
        pub(super) fn approve(
            &self,
            action: ActivationAction,
            state: &str,
            target: &str,
            nonce: &str,
            expired: bool,
        ) -> Signed<ActivationApproval> {
            let now = clock();
            self.keys.sign(
                AuthorityRole::Approver,
                ActivationApproval {
                    schema_version: 1,
                    action,
                    expected_state_hash: state.into(),
                    target_hash: target.into(),
                    issued_at_unix_seconds: if expired { now - 60 } else { now },
                    expires_at_unix_seconds: if expired { now - 1 } else { now + 120 },
                    nonce_sha256: nonce.repeat(64),
                },
            )
        }
    }
}
use assert_cmd::Command;
use router_backend_policy::ActivationAction;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Output,
};

struct Files {
    _temp: tempfile::TempDir,
    root: PathBuf,
    store: PathBuf,
    hash: String,
    live: fixture::Live,
}
impl Files {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let live = fixture::Live::new();
        write(&root.join("config.json"), &live.config);
        write(&root.join("artifact.json"), &live.artifact);
        write(&root.join("evidence.json"), &live.evidence);
        let hash = live.config.content_hash().unwrap();
        Self {
            store: root.join("store"),
            root,
            _temp: temp,
            hash,
            live,
        }
    }
    fn command(&self, verb: &str) -> Command {
        let mut command = Command::cargo_bin("agent-router").unwrap();
        command
            .args(["backend-activation", verb, "--store"])
            .arg(&self.store)
            .args(["--expected-config-hash", &self.hash, "--json"]);
        command
    }
    fn init(&self) -> Value {
        parsed(
            self.command("init")
                .arg("--config")
                .arg(self.root.join("config.json"))
                .output()
                .unwrap(),
        )
    }
    fn evidence(&self, verb: &str) -> Command {
        let mut command = self.command(verb);
        command
            .arg("--artifact")
            .arg(self.root.join("artifact.json"))
            .arg("--evidence")
            .arg(self.root.join("evidence.json"));
        command
    }
}
fn write(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn parsed(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn configuration_digest_inspection_does_not_create_or_approve_a_store() {
    let files = Files::new();
    let result = parsed(
        Command::cargo_bin("agent-router")
            .unwrap()
            .args(["backend-activation", "config-hash", "--config"])
            .arg(files.root.join("config.json"))
            .arg("--json")
            .output()
            .unwrap(),
    );
    assert_eq!(result["config_hash"], files.hash);
    assert_eq!(result["approved"], false);
    assert_eq!(result["created"], false);
    assert!(!files.store.exists());
}

#[test]
fn signed_cli_lifecycle_is_explicit_redacted_and_reversible() {
    let files = Files::new();
    let initial = files.init();
    let before = fs::read(files.store.join("state.json")).unwrap();
    let review = parsed(files.evidence("review").output().unwrap());
    assert_eq!(before, fs::read(files.store.join("state.json")).unwrap());
    let approval = files.live.approve(
        ActivationAction::Activate,
        initial["state_hash"].as_str().unwrap(),
        review["promotion_hash"].as_str().unwrap(),
        "1",
        false,
    );
    write(&files.root.join("approval.json"), &approval);
    let active = parsed(
        files
            .evidence("activate")
            .arg("--approval")
            .arg(files.root.join("approval.json"))
            .output()
            .unwrap(),
    );
    assert_eq!(active["event_count"], 1);
    assert_eq!(active["active_promotion_hash"], review["promotion_hash"]);
    let output = files.command("status").output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    for marker in [
        "synthetic",
        "fixture-best",
        "fixture-second",
        "signature_hex",
        "public_key_hex",
        "objective",
    ] {
        assert!(!text.contains(marker));
    }
    let approval = files.live.approve(
        ActivationAction::Rollback,
        active["state_hash"].as_str().unwrap(),
        &files.live.config.baseline_policy_hash,
        "2",
        false,
    );
    write(&files.root.join("rollback.json"), &approval);
    let rolled_back = parsed(
        files
            .command("rollback")
            .arg("--approval")
            .arg(files.root.join("rollback.json"))
            .output()
            .unwrap(),
    );
    assert_eq!(rolled_back["event_count"], 2);
    assert!(rolled_back["active_promotion_hash"].is_null());
}

#[test]
fn external_pin_signature_expiry_and_replay_are_not_cli_options_to_bypass() {
    let files = Files::new();
    let mut wrong = Command::cargo_bin("agent-router").unwrap();
    let output = wrong
        .args(["backend-activation", "init", "--store"])
        .arg(&files.store)
        .arg("--config")
        .arg(files.root.join("config.json"))
        .args(["--expected-config-hash", &"0".repeat(64), "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!files.store.exists());
    let initial = files.init();
    let review = parsed(files.evidence("review").output().unwrap());
    for forged in [false, true] {
        let mut approval = files.live.approve(
            ActivationAction::Activate,
            initial["state_hash"].as_str().unwrap(),
            review["promotion_hash"].as_str().unwrap(),
            "3",
            !forged,
        );
        if forged {
            approval.signature_hex = "0".repeat(128);
        }
        write(&files.root.join("bad.json"), &approval);
        let before = fs::read(files.store.join("state.json")).unwrap();
        let output = files
            .evidence("activate")
            .arg("--approval")
            .arg(files.root.join("bad.json"))
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(before, fs::read(files.store.join("state.json")).unwrap());
    }
    let output = files
        .command("status")
        .args(["--now", "120"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let approval = files.live.approve(
        ActivationAction::Activate,
        initial["state_hash"].as_str().unwrap(),
        review["promotion_hash"].as_str().unwrap(),
        "4",
        false,
    );
    write(&files.root.join("valid.json"), &approval);
    parsed(
        files
            .evidence("activate")
            .arg("--approval")
            .arg(files.root.join("valid.json"))
            .output()
            .unwrap(),
    );
    let output = files
        .evidence("activate")
        .arg("--approval")
        .arg(files.root.join("valid.json"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("backend_store.conflict"));
}
