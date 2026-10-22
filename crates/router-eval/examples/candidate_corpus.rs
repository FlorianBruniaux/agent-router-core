//! Reproducible synthetic fixtures. `--write` is explicit; default checks files.
#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::PathBuf,
};

use router_adapter_api::{
    CapabilityEvidence, EvidenceKind, EvidenceSource, HostObservation, SnapshotValidation,
};
use router_catalog::Catalog;
use router_eval::*;
use router_policy::PhaseRouter;
use router_types::*;
use router_workflow::merge_restrictions;
use serde_json::json;

const NOW: u64 = 1_700_000_100;
const OBSERVED: u64 = 1_700_000_000;
fn model(id: &str) -> ModelId {
    ModelId::parse(id).expect("constant fixture model")
}
fn candidate(id: &str, model_id: &str, cost: u64, tokens: u64, latency: u64) -> PhaseCandidate {
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
        estimated_cost_microusd: cost,
        estimated_tokens: tokens,
        estimated_elapsed_ms: latency,
        relevance_micros: 0,
    }
}

fn build(case: CandidateCase) -> std::result::Result<CandidateReplay, Box<dyn Error>> {
    let capabilities = BTreeSet::from([
        Capability::Tools,
        Capability::Subagents,
        Capability::Vision,
        Capability::Network,
        Capability::WorkspaceWrite,
    ]);
    let catalog = json!({"schema_version":1,"version":"synthetic-corpus-prior-v1","models":[
        {"id":"fixture-alpha","stages":["plan","execute","verify"],"efforts":["medium","high"],"capabilities":["tools","subagents","vision","network","workspace_write"],"quality_micros":900000,"cost_micros":900,"latency_micros":100,"source":"synthetic-fixture-not-model-benchmark"},
        {"id":"fixture-beta","stages":["plan","execute","verify"],"efforts":["medium","high"],"capabilities":["tools","subagents","vision","network","workspace_write"],"quality_micros":800000,"cost_micros":300,"latency_micros":200,"source":"synthetic-fixture-not-model-benchmark"},
        {"id":"fixture-gamma","stages":["plan","execute","verify"],"efforts":["medium","high"],"capabilities":["tools","subagents","vision","network","workspace_write"],"quality_micros":700000,"cost_micros":100,"latency_micros":300,"source":"synthetic-fixture-not-model-benchmark"}],
        "skills":[{"id":"rust-contract","description":"Synthetic Rust contract review skill","task_kinds":["explore","implement","review","architecture","security","migration"],"required_capabilities":[],"trust":"builtin"},
            {"id":"untrusted-helper","description":"Synthetic untrusted negative control","task_kinds":["explore","implement","review","architecture","security","migration"],"required_capabilities":[],"trust":"untrusted"}]});
    let models = [
        model("fixture-alpha"),
        model("fixture-beta"),
        model("fixture-gamma"),
    ];
    let mut snapshot = HostObservation {
        attestations: None,
        schema_version: 1,
        host: HostSnapshot {
            id: "synthetic-corpus-host".into(),
            harness: HarnessId::parse("fixture-host")?,
            supported_models: models.iter().cloned().collect(),
            supported_efforts: models
                .iter()
                .cloned()
                .map(|m| (m, BTreeSet::from([EffortLevel::Medium, EffortLevel::High])))
                .collect(),
            capabilities: capabilities.clone(),
        },
        capabilities: capabilities
            .iter()
            .copied()
            .map(|cap| {
                (
                    cap,
                    CapabilityEvidence {
                        support: CapabilitySupport::Supported,
                        source_ids: BTreeSet::from(["synthetic-runtime-evidence".into()]),
                    },
                )
            })
            .collect(),
        evidence: vec![EvidenceSource {
            id: "synthetic-runtime-evidence".into(),
            kind: EvidenceKind::HostRuntime,
            observed_version: Some("synthetic-v1-not-native-evidence".into()),
            observed_at_unix_seconds: OBSERVED,
            content_sha256: "a".repeat(64),
        }],
        observed_at_unix_seconds: OBSERVED,
        snapshot_hash: String::new(),
    };
    let mut layer = RestrictionLayer {
        name: "synthetic-explicit-authority".into(),
        allowed_models: None,
        allowed_capabilities: None,
        allowed_mutations: Some(BTreeSet::new()),
        max_cost_microusd: Some(10_000),
        max_tokens: Some(10_000),
        max_concurrency: Some(1),
        preferred_model: None,
    };
    let mut request = PhaseRouteRequest {
        schema_version: 2,
        task: NormalizedTask {
            objective: case.objective.clone(),
            kind: case.task_kind,
            deliverables: vec![
                "A bounded decision or an explained abstention for this synthetic context".into(),
            ],
            constraints: vec![
                "No execution; generated candidate pending independent review".into(),
            ],
            scope: vec!["src".into()],
            risk: case.proposed_risk,
            sensitivity: DataSensitivity::Public,
            budget: TaskBudget {
                max_cost_microusd: 10_000,
                max_elapsed_ms: 10_000,
                max_tokens: 10_000,
            },
            allowed_mutations: BTreeSet::new(),
            dependencies: vec![],
            acceptance: vec![
                "Honor the supplied permissions, budgets, evidence and verification independence"
                    .into(),
            ],
            required_capabilities: BTreeSet::new(),
        },
        phase: StageKind::Plan,
        restrictions: merge_restrictions(&[layer.clone()])?,
        permissions: BTreeMap::from([
            (
                PhasePermission::ModelInference,
                CapabilitySupport::Supported,
            ),
            (PhasePermission::WorkspaceRead, CapabilitySupport::Supported),
        ]),
        registry: PhaseAssetRegistry::default(),
        candidates: vec![
            candidate("primary", "fixture-alpha", 900, 100, 100),
            candidate("secondary", "fixture-beta", 300, 60, 200),
            candidate("economy", "fixture-gamma", 100, 30, 300),
        ],
        previous_model: None,
    };
    if matches!(case.task_kind, TaskKind::Implement | TaskKind::Migration) {
        request
            .task
            .allowed_mutations
            .insert(Mutation::WorkspaceWrite);
        layer.allowed_mutations = Some(BTreeSet::from([Mutation::WorkspaceWrite]));
        request.permissions.insert(
            PhasePermission::WorkspaceWrite,
            CapabilitySupport::Supported,
        );
    }
    if matches!(case.proposed_risk, RiskLevel::High | RiskLevel::Critical) {
        for c in &mut request.candidates {
            c.verification = PhaseVerification::Independent;
        }
    }
    let mut proposed = Some("primary".to_string());
    let mut abstention = None;
    let mut unavailable = BTreeSet::new();
    let variant = case
        .id
        .strip_prefix("candidate-")
        .ok_or("candidate ID")?
        .parse::<usize>()?
        .saturating_sub(1)
        % 5;
    let rationale = match case.family_id.as_str() {
        "contract-parser" => {
            request.phase = StageKind::Execute;
            "The highest policy prior remains eligible for a bounded read-only implementation proposal."
        }
        "host-unknown" => {
            snapshot.host.capabilities.remove(&Capability::Network);
            snapshot.capabilities.insert(
                Capability::Network,
                CapabilityEvidence {
                    support: CapabilitySupport::Unknown,
                    source_ids: BTreeSet::new(),
                },
            );
            request.candidates[0]
                .required_capabilities
                .insert(Capability::Network);
            proposed = Some("secondary".into());
            "UNKNOWN network evidence excludes the network-dependent primary; a read-only alternative remains eligible."
        }
        "catalog-provenance" => {
            "The selected model's canonical catalog content and observed snapshot are both bound to the receipt."
        }
        "retrieval-exact" => {
            request.candidates[0]
                .skills
                .insert(SkillId::parse("rust-contract")?);
            request.candidates[1]
                .skills
                .insert(SkillId::parse("untrusted-helper")?);
            "The candidate using the explicitly declared trusted Rust skill is eligible; an untrusted helper is excluded. This is phase routing, not a BM25 recall measurement."
        }
        "retrieval-abstain" => {
            let mut duplicate = request.candidates[0].clone();
            duplicate.id = "equal-evidence".into();
            request.candidates[1] = duplicate;
            proposed = None;
            abstention = Some(PhaseAbstention::Ambiguous);
            "Equal eligible scores must abstain; identifier ordering is not evidence of a better selection."
        }
        "phase-budget" => {
            let budget = [60, 30, 20, 60, 30][variant];
            request.task.budget.max_tokens = budget;
            layer.max_tokens = Some(budget);
            proposed = match budget {
                60 => Some("secondary".into()),
                30 => Some("economy".into()),
                _ => None,
            };
            if proposed.is_none() {
                abstention = Some(PhaseAbstention::NoEligibleCandidate);
            }
            "Candidates requiring 100, 60 and 30 tokens are filtered against the explicitly declared budget. Select the highest eligible prior, or abstain when every estimate exceeds the bound."
        }
        "phase-fallback" => {
            unavailable.insert("primary".into());
            proposed = Some("secondary".into());
            if variant == 1 || variant == 2 {
                unavailable.insert("secondary".into());
                proposed = Some("economy".into());
            }
            if variant == 2 {
                unavailable.insert("economy".into());
                proposed = None;
                abstention = Some(PhaseAbstention::AllUnavailable);
            }
            "Explicit unavailable candidates are excluded from the same frozen pool; select the next eligible candidate or abstain when all are unavailable."
        }
        "workflow-dag" => {
            "Plan-phase routing is separated from execution and verification; this fixture does not itself prove the entire DAG runtime."
        }
        "permissions" => {
            request
                .permissions
                .insert(PhasePermission::ModelInference, CapabilitySupport::Unknown);
            proposed = None;
            abstention = Some(PhaseAbstention::NoEligibleCandidate);
            "UNKNOWN model-inference permission excludes every candidate, including during a high-risk review."
        }
        "prompt-template" => {
            "An eligible planning candidate is selected without loading prompt bodies; typed prompt rendering has separate contract tests."
        }
        "replay-integrity" => {
            request.phase = StageKind::Verify;
            "Complete request, catalog, snapshot and policy identities are frozen in the replay; byte tampering is tested separately."
        }
        "shadow-gate" => {
            "An independent high-risk candidate can be proposed, but unvalidated corpus labels cannot enable any semantic promotion."
        }
        "rust-refactor" => {
            request.phase = StageKind::Execute;
            request
                .task
                .allowed_mutations
                .insert(Mutation::WorkspaceWrite);
            layer.allowed_mutations = Some(BTreeSet::from([Mutation::WorkspaceWrite]));
            request.permissions.insert(
                PhasePermission::WorkspaceWrite,
                CapabilitySupport::Supported,
            );
            request.candidates[0].sandbox = PhaseSandbox::WorkspaceWrite;
            "Workspace write is explicitly permitted by task, restrictions, host evidence and permission map; the proposed candidate stays inside that scope."
        }
        "migration-review" => {
            request.phase = StageKind::Verify;
            request.previous_model = Some(model("fixture-alpha"));
            proposed = Some("secondary".into());
            "The previous execution model cannot independently verify itself; the next eligible model provides model-level independence."
        }
        "incident-readonly" => {
            request.candidates[0].sandbox = PhaseSandbox::WorkspaceWrite;
            proposed = Some("secondary".into());
            "Critical incident review remains read-only; the write-capable candidate is forbidden and the independent read-only alternative remains eligible."
        }
        "release-gate" => {
            request.phase = StageKind::Verify;
            request.candidates[0].effort = EffortLevel::High;
            snapshot.host.supported_efforts.insert(
                model("fixture-alpha"),
                BTreeSet::from([EffortLevel::Medium]),
            );
            proposed = Some("secondary".into());
            "The requested primary effort is absent from this host snapshot; a supported model/effort pair is selected."
        }
        "ood-cooking" | "ood-travel" | "ood-personal" | "ood-finance" => {
            request.candidates.clear();
            proposed = None;
            abstention = Some(PhaseAbstention::EmptyPool);
            "The fixture explicitly supplies an empty engineering candidate pool for this out-of-domain request. Abstention follows that pool; this is not evidence of automatic domain detection."
        }
        _ => return Err(format!("unmapped fixture family {}", case.family_id).into()),
    };
    request.restrictions = merge_restrictions(&[layer])?;
    snapshot = snapshot.seal()?;
    let policies: BTreeMap<String, PhasePolicy> = BTreeMap::from([
        (
            "baseline".into(),
            PhasePolicy {
                version: "synthetic-baseline-v1".into(),
                ..Default::default()
            },
        ),
        (
            "shadow_candidate".into(),
            PhasePolicy {
                version: "synthetic-shadow-weights-v1".into(),
                cost_weight: 2,
                ..Default::default()
            },
        ),
    ]);
    let pricing = PricingTable {
        schema_version: 1,
        version: "synthetic-token-prices-v1".into(),
        source: "synthetic-fixed-fixture-units-not-provider-prices".into(),
        observed_at_unix_seconds: OBSERVED,
        models: models
            .into_iter()
            .enumerate()
            .map(|(i, m)| {
                (
                    m,
                    TokenPrice {
                        input_microusd_per_million: 1000 + (i as u64) * 100,
                        cached_input_microusd_per_million: 500,
                        output_microusd_per_million: 2000,
                    },
                )
            })
            .collect(),
    };
    let validation = SnapshotValidation {
        now_unix_seconds: NOW,
        max_age_seconds: 300,
    };
    let validated = fixture_proofs::from_observation(snapshot.clone(), validation)?;
    let parsed_catalog = Catalog::from_json(&serde_json::to_vec(&catalog)?)?;
    let mut observations = BTreeMap::new();
    for (id, policy) in &policies {
        let router = PhaseRouter::new(policy.clone())?;
        let context = router.context(request.clone(), &validated, &parsed_catalog)?;
        let receipt = router.fallback(&context, &unavailable)?;
        let usage = receipt
            .selected
            .as_ref()
            .map(|selected| {
                vec![TokenUsage {
                    model: selected.candidate.model.clone(),
                    input_tokens: 20,
                    cached_input_tokens: 5,
                    output_tokens: 10,
                }]
            })
            .unwrap_or_default();
        observations.insert(
            id.clone(),
            RecordedPhase {
                usage,
                elapsed_ms: None,
                fallback_reasons: unavailable
                    .iter()
                    .map(|id| format!("synthetic_unavailable:{id}"))
                    .collect(),
                outcomes: VerificationOutcomes::default(),
            },
        );
    }
    let input = ReplayInput {
        schema_version: 1,
        case_id: case.id.clone(),
        family_id: case.family_id.clone(),
        split: case.split,
        out_of_domain: case.out_of_domain,
        request,
        snapshot,
        catalog,
        policies,
        pricing,
        observations,
        label: Some(CaseLabel {
            human_validated: false,
            independent: false,
            reviewer_id: None,
            evidence_sha256: None,
            expected_candidate_ids: proposed.iter().cloned().collect(),
            expect_abstention: abstention.is_some(),
        }),
    };
    let unavailable_inputs = if unavailable.is_empty() {
        BTreeMap::new()
    } else {
        BTreeMap::from([
            ("baseline".into(), unavailable.clone()),
            ("shadow_candidate".into(), unavailable),
        ])
    };
    Ok(CandidateReplay::seal_with_verifier(
        case,
        ReplayRecord::seal(input)?,
        validation,
        ProposedDecision {
            policy_id: "baseline".into(),
            candidate_id: proposed,
            abstention,
            rationale: rationale.into(),
            human_validated: false,
        },
        unavailable_inputs,
        Some(&fixture_proofs::FixtureVerifier),
    )?)
}

fn main() -> std::result::Result<(), Box<dyn Error>> {
    let write = std::env::args().skip(1).any(|a| a == "--write");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/evaluation");
    let corpus = CandidateCorpus::from_json(&fs::read(root.join("candidate-corpus-v1.json"))?)?;
    let mut manifest = Vec::new();
    let mut worksheet = Vec::new();
    if write {
        fs::create_dir_all(root.join("replays"))?;
    }
    for case in corpus.cases {
        let id = case.id.clone();
        let bundle = build(case)?;
        let bytes = bundle.canonical_json()?;
        let filename = format!("replays/{id}.json");
        let path = root.join(&filename);
        if write {
            fs::write(&path, &bytes)?;
        } else if fs::read(&path)? != bytes {
            return Err(format!("fixture differs: {filename}").into());
        }
        manifest.push(json!({"case_id":id,"family_id":bundle.case().family_id,"split":bundle.case().split,"out_of_domain":bundle.case().out_of_domain,
            "path":filename,"content_hash":bundle.content_hash(),"input_hash":bundle.record().input_hash(),"proposed_decision":bundle.proposed_decision(),"expected_trace_hashes":bundle.expected_trace_hashes()}));
        worksheet.push(json!({"case_id":id,"input_hash":bundle.record().input_hash(),"candidate_file":filename,"objective":bundle.case().objective,
            "proposal":bundle.proposed_decision(),"human_validated":false,"independent":false,"reviewer_id":null,"evidence_sha256":null,
            "reviewed_expected_candidate_ids":null,"reviewed_expect_abstention":null,"review_notes":null}));
    }
    for (name, value) in [
        (
            "replay-manifest-v1.json",
            json!({"schema_version":1,"status":"candidate_requires_independent_human_review","fixture_only":true,"cases":manifest}),
        ),
        (
            "human-review-worksheet-v1.json",
            json!({"schema_version":1,"status":"unreviewed_do_not_use_for_promotion","review_instructions":"Review source cases independently; proposal is an aid, not a label. Supply reviewer, evidence, decision and independence explicitly. Preserve input hashes.","cases":worksheet}),
        ),
    ] {
        let mut bytes = serde_json::to_vec_pretty(&value)?;
        bytes.push(b'\n');
        let path = root.join(name);
        if write {
            fs::write(path, bytes)?;
        } else if fs::read(path)? != bytes {
            return Err(format!("fixture differs: {name}").into());
        }
    }
    println!(
        "100 synthetic candidate replays verified; human_validated=false; semantic promotion unavailable"
    );
    Ok(())
}
