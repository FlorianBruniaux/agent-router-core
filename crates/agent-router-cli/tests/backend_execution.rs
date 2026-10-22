//! CLI selection/authority tests. Keys, reviewer labels, capability observations
//! and model metadata are synthetic. No live provider or paid call is used.
#![cfg(unix)]

#[path = "support/native_fixture.rs"]
mod native_fixture;
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
        pub(super) fn new(failure: BackendFailurePolicy) -> Self {
            let mut fixture = Fixture::with_failure(failure);
            let now = clock();
            let delta = now - 120;
            fixture.artifact.created_at_unix_seconds += delta;
            for case in &mut fixture.evidence.cases {
                let mut input = case.record.input().clone();
                let mut snapshot = serde_json::to_value(&input.snapshot).unwrap();
                shift(&mut snapshot, delta);
                input.snapshot = super::native_fixture::unknown_observation::from_example(
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
        pub(super) fn active_proposal(
            &self,
            router: &PhaseRouter,
            context: &ValidatedPhaseContext,
            state: &str,
            now: u64,
        ) -> SignedBackendProposal {
            proposal(
                &self.keys,
                &self.artifact,
                router,
                context,
                ProposalPurpose::Active(state.into()),
                now,
                now + 50,
                Some("c01"),
            )
        }
    }
}

use native_fixture::{checked, command, write};
use router_adapter_api::{HostObservation, content_digest};
use router_backend_policy::{ActivationAction, decide_active};
use router_backend_store::BackendStore;
use router_catalog::Catalog;
use router_execution_decision::{ActivationGuard, ExecutionDecision};
use router_policy::PhaseRouter;
use router_types::*;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Command,
};

struct SemanticFixture {
    files: native_fixture::Fixture,
    live: fixture::Live,
    backend: BackendStore,
    decision: ExecutionDecision,
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn rejected(command: &mut Command, expected: &str) {
    let output = command.output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

impl SemanticFixture {
    fn new(native: bool, failure: BackendFailurePolicy) -> Self {
        Self::build(native, failure, false)
    }
    fn build(native: bool, failure: BackendFailurePolicy, ambiguous: bool) -> Self {
        let body = format!(
            "printf isolated > src/result.txt\nprintf '%s' {}",
            native_fixture::shell_quote(native_fixture::STREAM)
        );
        let mut files = if native {
            native_fixture::Fixture::new(&body, 3000)
        } else {
            native_fixture::Fixture::metadata(&body, 3000)
        };
        // The fake transport itself asserts the requested alternate model.
        let fake = files.root.join("fake-claude");
        let script = fs::read_to_string(&fake)
            .unwrap()
            .replace("= fixture-best ]", "= fixture-second ]");
        fs::write(&fake, script).unwrap();
        let now = fixture::clock();
        let mut request: PhaseRouteRequest = read(&files.root.join("context.json"));
        let mut secondary = request.candidates[0].clone();
        secondary.id = "secondary".into();
        secondary.model = ModelId::parse(if ambiguous {
            "fixture-best"
        } else {
            "fixture-second"
        })
        .unwrap();
        request.candidates.push(secondary);
        let mut execution: ExecutionRequest = read(&files.root.join("request.json"));
        let snapshot: HostObservation = read(&files.root.join("snapshot.json"));
        let snapshot = files.reprovision(&snapshot, "fixture-v1");
        let catalog =
            Catalog::from_json(&fs::read(files.root.join("catalog.json")).unwrap()).unwrap();
        let assets = native_fixture::asset_inputs(
            &request,
            &snapshot,
            &catalog,
            &files.repo,
            &execution.source_state,
            now,
        );
        native_fixture::write_asset_authority(&files.root, &assets);
        let router = PhaseRouter::stable_v2();
        let context = router
            .context_with_assets(request.clone(), &snapshot, &catalog, assets, now)
            .unwrap();
        let baseline = router.route(&context).unwrap();
        if ambiguous {
            assert!(baseline.selected.is_none());
        } else {
            assert_eq!(baseline.selected.as_ref().unwrap().candidate.id, "primary");
        }
        if ambiguous {
            assert!(baseline.capability_evidence.is_empty());
            assert_eq!(baseline.schema_version, 3);
        } else {
            assert!(!baseline.capability_evidence.is_empty());
            assert_eq!(baseline.schema_version, 5);
        }
        let mut live = fixture::Live::new(failure);
        live.config.scope_sha256 = content_digest(
            &serde_json::to_vec(&(
                "agent-router:backend-execution-scope:v1",
                &execution.workspace,
                &execution.source_state,
                &execution.scope,
            ))
            .unwrap(),
        );
        let backend =
            BackendStore::create(&files.root.join("backend-store"), live.config.clone()).unwrap();
        let initial = backend.status(now).unwrap();
        let promotion = backend.review(&live.artifact, &live.evidence, now).unwrap();
        let approval = live.approve(
            ActivationAction::Activate,
            &initial.state_hash,
            &promotion.projection().promotion_hash,
            "1",
            false,
        );
        let active = backend
            .activate(&approval, &promotion, fixture::clock())
            .unwrap();
        let now = fixture::clock();
        let proposal = live.active_proposal(&router, &context, &active.state_hash, now);
        let guard = backend.read_guard(now).unwrap();
        let proof = decide_active(
            guard.state(),
            &router,
            &context,
            Some(&proposal),
            guard.authorities(),
            now,
        )
        .unwrap();
        let decision =
            ExecutionDecision::activated(&router, &context, &proof, &guard, now).unwrap();
        drop(guard);
        assert_eq!(decision.selection().candidate.id, "secondary");
        assert_ne!(decision.authorization_id(), baseline.receipt_id);
        execution.receipt_id = decision.authorization_id().into();
        execution.candidate_id = decision.selection().candidate.id.clone();
        execution.model = decision.selection().candidate.model.clone();
        write(&files.root.join("context.json"), &request);
        write(&files.root.join("request.json"), &execution);
        write(&files.root.join("receipt.json"), &baseline);
        write(
            &files.root.join("backend.json"),
            &json!({"schema_version":1,"store":"backend-store","expected_config_hash":backend.config_hash(),"expected_head":initial.state_hash,"activation_state_hash":active.state_hash,"decided_at_unix_seconds":now,"proposal":proposal}),
        );
        let mut definition: Value = read(&files.root.join("definition.json"));
        definition["backend_decision"] = json!("backend.json");
        definition["receipt"] = json!("receipt.json");
        write(&files.root.join("definition.json"), &definition);
        Self {
            files,
            live,
            backend,
            decision,
        }
    }
    fn strict() -> Self {
        Self::new(false, BackendFailurePolicy::Abstain)
    }
    fn rollback(&self) {
        let status = self.backend.status(fixture::clock()).unwrap();
        let approval = self.live.approve(
            ActivationAction::Rollback,
            &status.state_hash,
            &self.live.config.baseline_policy_hash,
            "2",
            false,
        );
        self.backend.rollback(&approval, fixture::clock()).unwrap();
    }
    fn prepare_manifest(&self) {
        let root = &self.files.root;
        let execution: ExecutionRequest = read(&root.join("request.json"));
        let template = router_workflow::seal_prompt(PromptTemplate {
            schema_version: 1,
            id: "semantic-template".into(),
            version: "v1".into(),
            template: "Report ${subject}".into(),
            variables: BTreeMap::from([("subject".into(), PromptVariableType::Text)]),
            compatible_hosts: BTreeSet::from(["claude-code".into()]),
            compatible_models: BTreeSet::from([
                ModelId::parse("fixture-best").unwrap(),
                ModelId::parse("fixture-second").unwrap(),
            ]),
            max_rendered_bytes: 4096,
            output_contract: "Evidence".into(),
            content_sha256: String::new(),
        })
        .unwrap();
        write(&root.join("prompt.json"), &template);
        let body = fs::read(root.join("prompt.json")).unwrap();
        let metadata = router_retrieval::MetadataDocument {
            schema_version: "1".into(),
            catalog_version: "fixture".into(),
            assets: vec![router_retrieval::AssetMetadata {
                id: "semantic-template".into(),
                kind: router_retrieval::AssetKind::Prompt,
                trust: SkillTrust::TrustedLocal,
                task_kinds: vec![],
                triggers: vec![],
                description: "Report".into(),
                examples: vec![],
                tags: vec![],
                paths: vec![],
                anti_triggers: vec![],
                body: Some(router_retrieval::BodyReference {
                    path: "prompt.json".into(),
                    sha256: content_digest(&body),
                }),
            }],
        };
        write(&root.join("metadata.json"), &metadata);
        let index = checked(
            command()
                .args(["index", "--metadata"])
                .arg(root.join("metadata.json"))
                .arg("--catalog")
                .arg(root.join("catalog.json"))
                .arg("--json"),
            0,
        );
        write(&root.join("index.json"), &index);
        write(
            &root.join("variables.json"),
            &BTreeMap::from([(
                "subject".to_string(),
                PromptValue::Text("synthetic-secret-input".into()),
            )]),
        );
        write(
            &root.join("options.json"),
            &json!({"schema_version":1,"workspace":execution.workspace,"source_state":execution.source_state,"target":"external_worker","allow_degradation":false,"timeout_ms":3000,"max_output_bytes":16384,"max_input_bytes":65536,"now_unix_seconds":0,"max_snapshot_age_seconds":300}),
        );
        write(
            &root.join("prepare.json"),
            &json!({"schema_version":1,"run_id":"semantic-prepared","capability_store":self.files.store,"execution_config":"sandbox.json","context":"context.json","host_snapshot":"snapshot.json","catalog":"catalog.json","policy":null,"policy_store":null,"asset_authority":"asset-authority.json","backend_decision":"backend.json","plan":"plan.json","node_id":"execute","metadata":"index.json","body_root":".","template":"prompt.json","variables":"variables.json","options":"options.json","receipt":"receipt.json"}),
        );
    }
    fn prepare(&self) -> Command {
        let mut cmd = command();
        cmd.args(["prepare", "--manifest"])
            .arg(self.files.root.join("prepare.json"))
            .arg("--json");
        cmd
    }
}

#[test]
fn asset_authority_keeps_original_observation_time_when_preparation_crosses_a_second() {
    let files = native_fixture::Fixture::metadata("exit 0", 3000);
    let observation: HostObservation = read(&files.root.join("snapshot.json"));
    let later = observation.observed_at_unix_seconds + 2;
    let snapshot = files.validated_snapshot(later);
    let request: PhaseRouteRequest = read(&files.root.join("context.json"));
    let execution: ExecutionRequest = read(&files.root.join("request.json"));
    let catalog = Catalog::from_json(&fs::read(files.root.join("catalog.json")).unwrap()).unwrap();
    let assets = native_fixture::asset_inputs(
        &request,
        &snapshot,
        &catalog,
        &files.repo,
        &execution.source_state,
        later,
    );
    assert!(
        assets
            .availability
            .document()
            .evidence
            .iter()
            .all(|evidence| {
                snapshot.observation().evidence.iter().any(|source| {
                    source.content_sha256 == evidence.source_sha256
                        && source.observed_at_unix_seconds == evidence.observed_at_unix_seconds
                })
            })
    );
}

#[test]
fn scope_inspection_matches_signed_authority_and_tracks_source_changes() {
    let fixture = SemanticFixture::strict();
    let path = fixture.files.root.join("request.json");
    let scope = || {
        native_fixture::checked(
            native_fixture::command()
                .args(["backend-activation", "scope-hash", "--request"])
                .arg(&path)
                .arg("--json"),
            0,
        )
    };
    let original = scope();
    assert_eq!(original["scope_sha256"], fixture.live.config.scope_sha256);
    assert_eq!(original["approved"], false);
    assert_eq!(original["created"], false);
    let mut request: ExecutionRequest = read(&path);
    request.source_state = "f".repeat(40);
    write(&path, &request);
    assert_ne!(scope()["scope_sha256"], original["scope_sha256"]);
}

#[test]
fn signed_alternate_preparation_and_review_preserve_the_deterministic_baseline() {
    let fixture = SemanticFixture::strict();
    fixture.prepare_manifest();
    let output_dir = fixture.files.root.join("prepared");
    let preview = checked(
        fixture.prepare().arg("--output-directory").arg(&output_dir),
        0,
    );
    assert_eq!(preview["executed"], false);
    assert!(!preview.to_string().contains("synthetic-secret-input"));
    let request: ExecutionRequest = read(&output_dir.join("request.json"));
    assert_eq!(request.candidate_id, "secondary");
    assert_eq!(request.model.as_str(), "fixture-second");
    assert_eq!(request.receipt_id, fixture.decision.authorization_id());
    let baseline: PhaseReceipt = read(&output_dir.join("receipt.json"));
    assert_eq!(baseline, *fixture.decision.baseline());
    assert_eq!(baseline.selected.unwrap().candidate.id, "primary");
    let definition: Value = read(&output_dir.join("definition.json"));
    assert_eq!(
        definition["backend_decision"],
        fixture.files.root.join("backend.json").to_str().unwrap()
    );
    let review = checked(
        command()
            .args(["run", "--definition"])
            .arg(output_dir.join("definition.json"))
            .arg("--store")
            .arg(&fixture.files.store)
            .arg("--sandbox")
            .arg(fixture.files.root.join("sandbox.json"))
            .arg("--json"),
        0,
    );
    assert_eq!(review["executed"], false);
    assert_eq!(review["request"]["model"], "fixture-second");
    assert_eq!(
        review["baseline_receipt_id"],
        fixture.decision.baseline().receipt_id
    );
    assert_eq!(
        review["execution_decision"]["selected_candidate_id"],
        "secondary"
    );
    assert_eq!(
        review["execution_decision"]["decision_id"],
        request.receipt_id
    );
    assert!(!fixture.files.store.join("worktrees").exists());
}

#[test]
fn modified_external_pin_scope_signature_and_context_are_rejected_before_launch() {
    let fixture = SemanticFixture::strict();
    fixture.prepare_manifest();
    let root = &fixture.files.root;
    let original: Value = read(&root.join("backend.json"));
    for field in [
        "expected_config_hash",
        "expected_head",
        "activation_state_hash",
    ] {
        let mut changed = original.clone();
        changed[field] = json!("0".repeat(64));
        write(&root.join("backend.json"), &changed);
        rejected(
            &mut fixture.files.run(),
            if field == "activation_state_hash" {
                "runtime.backend.history"
            } else {
                "runtime.backend.authority"
            },
        );
        assert!(!fixture.files.store.join("worktrees").exists());
    }
    let mut forged = original.clone();
    forged["proposal"]["signature_hex"] = json!("00".repeat(64));
    write(&root.join("backend.json"), &forged);
    rejected(&mut fixture.prepare(), "runtime.backend.decision");
    rejected(&mut fixture.files.run(), "runtime.backend.decision");
    write(&root.join("backend.json"), &original);
    let request: Value = read(&root.join("request.json"));
    for (field, changed, expected) in [
        ("workspace", json!(root), "runtime.backend.scope"),
        (
            "source_state",
            json!("changed-source"),
            "runtime.backend.scope",
        ),
        (
            "scope",
            json!(["other"]),
            "capability.evidence.binding_mismatch",
        ),
    ] {
        let mut mismatch = request.clone();
        mismatch[field] = changed;
        write(&root.join("request.json"), &mismatch);
        rejected(&mut fixture.files.run(), expected);
        assert!(!fixture.files.store.join("worktrees").exists());
        assert!(!fixture.files.repo.join("src/result.txt").exists());
    }
    write(&root.join("request.json"), &request);
    let mut cross_context = original;
    cross_context["proposal"]["statement"]["request_sha256"] = json!("0".repeat(64));
    write(&root.join("backend.json"), &cross_context);
    rejected(&mut fixture.files.run(), "runtime.backend.decision");
    assert!(!fixture.files.store.join("worktrees").exists());
}

#[test]
fn ambiguous_baseline_remains_intact_when_signed_backend_selects_an_eligible_candidate() {
    let fixture = SemanticFixture::build(false, BackendFailurePolicy::Abstain, true);
    assert!(fixture.decision.baseline().selected.is_none());
    fixture.prepare_manifest();
    let output = fixture.files.root.join("ambiguous");
    checked(fixture.prepare().arg("--output-directory").arg(&output), 0);
    let request: ExecutionRequest = read(&output.join("request.json"));
    assert_eq!(request.candidate_id, "secondary");
    assert_eq!(request.receipt_id, fixture.decision.authorization_id());
    let baseline: PhaseReceipt = read(&output.join("receipt.json"));
    assert_eq!(baseline, *fixture.decision.baseline());
    assert!(baseline.selected.is_none());
    let review = checked(
        command()
            .args(["run", "--definition"])
            .arg(output.join("definition.json"))
            .arg("--store")
            .arg(&fixture.files.store)
            .arg("--sandbox")
            .arg(fixture.files.root.join("sandbox.json"))
            .arg("--json"),
        0,
    );
    assert_eq!(review["executed"], false);
    assert_eq!(
        review["execution_decision"]["selected_candidate_id"],
        "secondary"
    );
    assert_eq!(review["baseline_receipt_id"], baseline.receipt_id);
}

#[test]
fn changing_store_locator_to_identical_copy_cannot_reuse_an_existing_approval() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let fixture = SemanticFixture::strict();
    let original = checked(&mut fixture.files.run(), 0);
    let clone = fixture.files.root.join("other-authority");
    fs::DirBuilder::new().mode(0o700).create(&clone).unwrap();
    for name in ["state.json", "activation.lock"] {
        fs::copy(
            fixture.files.root.join("backend-store").join(name),
            clone.join(name),
        )
        .unwrap();
        fs::set_permissions(clone.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut manifest: Value = read(&fixture.files.root.join("backend.json"));
    manifest["store"] = json!("other-authority");
    write(&fixture.files.root.join("backend.json"), &manifest);
    // Roll back A while clone B remains active: identical signed content is not
    // permission to switch the operator-approved activation authority locator.
    fixture.rollback();
    let changed = checked(&mut fixture.files.run(), 0);
    assert_eq!(
        changed["execution_decision"],
        original["execution_decision"]
    );
    assert_ne!(changed["approval_digest"], original["approval_digest"]);
    rejected(
        fixture
            .files
            .run()
            .args(["--approve", original["approval_digest"].as_str().unwrap()]),
        "runtime.approval.required_or_changed",
    );
    assert!(!fixture.files.store.join("worktrees").exists());
}

#[test]
fn rollback_keeps_historical_identity_but_blocks_review_and_approved_dispatch() {
    let fixture = SemanticFixture::strict();
    let review = checked(&mut fixture.files.run(), 0);
    fixture.rollback();
    assert_eq!(
        fixture.files.status()["run"]["receipt_id"],
        fixture.decision.authorization_id()
    );
    // Artifact inspection reopens the exact historical decision under current
    // rollback state, while doing no work and granting no execution authority.
    let history = checked(&mut fixture.files.artifacts("keep"), 0);
    assert_eq!(
        history["run"]["receipt_id"],
        fixture.decision.authorization_id()
    );
    rejected(
        &mut fixture.files.run(),
        "runtime.backend.changed_or_expired",
    );
    rejected(
        fixture
            .files
            .run()
            .args(["--approve", review["approval_digest"].as_str().unwrap()]),
        "runtime.backend.changed_or_expired",
    );
    assert!(!fixture.files.store.join("worktrees").exists());
}

#[test]
fn signed_fallback_policy_preserves_primary_without_reusing_alternate_authority() {
    let fixture = SemanticFixture::new(false, BackendFailurePolicy::DeterministicFallback);
    fixture.prepare_manifest();
    let mut manifest: Value = read(&fixture.files.root.join("backend.json"));
    manifest["proposal"]["signature_hex"] = json!("00".repeat(64));
    write(&fixture.files.root.join("backend.json"), &manifest);
    let output = fixture.files.root.join("fallback");
    checked(fixture.prepare().arg("--output-directory").arg(&output), 0);
    let request: ExecutionRequest = read(&output.join("request.json"));
    assert_eq!(request.candidate_id, "primary");
    assert_eq!(request.model.as_str(), "fixture-best");
    assert_ne!(request.receipt_id, fixture.decision.authorization_id());
    // An existing alternate request must not silently become the fallback.
    rejected(&mut fixture.files.run(), "runtime.route.invalid");
}

#[test]
#[cfg(all(feature = "claude", any(target_os = "macos", target_os = "linux")))]
#[ignore = "requires native OS sandbox and built helper; synthetic transport only"]
fn native_alternate_feedback_and_historical_verification_after_rollback() {
    let fixture = SemanticFixture::new(true, BackendFailurePolicy::Abstain);
    let review = checked(&mut fixture.files.run(), 0);
    let output = checked(
        fixture
            .files
            .run()
            .args(["--approve", review["approval_digest"].as_str().unwrap()]),
        0,
    );
    assert_eq!(output["completion"]["run"]["state"], "verifying");
    assert_eq!(output["completion"]["transport"]["exit_code"], 0);
    assert_eq!(output["feedback"]["recorded"], true);
    let exported = fixture.files.exported_feedback();
    let event = &exported["events"][0]["input"];
    assert_eq!(event["context"]["model"], "fixture-second");
    assert_eq!(
        event["binding"]["receipt_hash"],
        fixture.decision.authorization_id()
    );
    assert_eq!(
        event["binding"]["policy_hash"],
        fixture.decision.baseline().policy_hash
    );
    assert_eq!(
        event["binding"]["catalog_hash"],
        fixture.decision.baseline().catalog_hash
    );
    assert_eq!(event["objective"], "unknown");
    fixture.rollback();
    let completion = &output["completion"];
    let worktree = Path::new(completion["run"]["worktree"].as_str().unwrap());
    assert_eq!(
        fs::read(worktree.join("src/result.txt")).unwrap(),
        b"isolated"
    );
    assert!(!fixture.files.repo.join("src/result.txt").exists());
    let evidence = fixture.files.root.join("verification.json");
    write(
        &evidence,
        &json!({"verifier":"synthetic-semantic-cli-test","evidence_sha256":content_digest(b"alternate argv checked, isolated output present, original unchanged"),"artifact_sha256":completion["run"]["artifact_sha256"],"validation":"passed","objective":"passed"}),
    );
    let verified = checked(
        command()
            .args(["verify", "--definition"])
            .arg(fixture.files.root.join("definition.json"))
            .arg("--store")
            .arg(&fixture.files.store)
            .arg("--evidence")
            .arg(&evidence)
            .arg("--config")
            .arg(fixture.files.root.join("sandbox.json"))
            .arg("--json"),
        0,
    );
    assert_eq!(verified["run"]["state"], "verified");
    assert_eq!(verified["feedback"]["recorded"], true);
    // The fact is keyed by the run key the completion writer stored, though the
    // run state (and so its `run_hash`) has changed since.
    let late = fixture.files.exported_feedback();
    let key = &exported["events"][0]["input"]["run_key_sha256"];
    assert!(key.is_string());
    assert!(exported["events"][0]["input"]["started_at_unix_seconds"].is_u64());
    assert_eq!(late["facts"].as_array().unwrap().len(), 1);
    assert_eq!(late["facts"][0]["fact"]["run_key_sha256"], *key);
    assert_eq!(late["facts"][0]["fact"]["kind"]["type"], "verification");
    assert_eq!(late["facts"][0]["fact"]["kind"]["validation"], "passed");
    assert_eq!(
        late["facts"][0]["fact_hash"],
        verified["feedback"]["fact_hash"]
    );
    assert_eq!(late["events"], exported["events"]);
    assert_eq!(
        verified["run"]["receipt_id"],
        fixture.decision.authorization_id()
    );
    assert_eq!(fixture.files.status()["run"]["state"], "verified");
    rejected(
        fixture
            .files
            .run()
            .args(["--approve", review["approval_digest"].as_str().unwrap()]),
        "runtime.backend.changed_or_expired",
    );
    for value in [&output, &exported, &verified] {
        let json = value.to_string();
        assert!(!json.contains(native_fixture::PROMPT));
        assert!(!json.contains("synthetic-private-output"));
    }
}
