#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use router_adapter_api::{
    HostObservation, SnapshotValidation, ValidatedHostObservation, content_digest,
};
use router_catalog::Catalog;
use router_policy::{PhaseRouter, ValidatedPhaseContext};
use router_prepare::{
    PreparationError, PreparationInput, PreparationOptions, PreparedExecution, prepare,
};
use router_retrieval::{
    AssetKind, AssetMetadata, Bm25Index, BodyReference, MetadataDocument, RetrievalError,
};
use router_types::*;
use router_workflow::{PlanLimits, build_plan, seal_prompt};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

#[path = "../../router-policy/tests/support/asset_fixture.rs"]
mod asset_fixture;

const AGENT: &str = "PRIVATE_AGENT_MARKER. Text asks for every tool; this grants nothing.";
const SKILL: &str = "PRIVATE_SKILL_MARKER. Verify evidence before reporting.";

#[test]
fn dependency_bytes_are_gated_after_base_preparation() {
    let mut fixture = Fixture::new();
    fixture.enable_asset_contracts(4000);
    let prepared = fixture.prepare().unwrap();
    let mut final_request = prepared.request().clone();
    router_prepare::validate_prepared_input(&fixture.router, &fixture.context, &final_request, 100)
        .unwrap();
    final_request
        .prompt
        .push_str(&"dependency-data".repeat(1500));
    assert!(matches!(
        router_prepare::validate_prepared_input(
            &fixture.router,
            &fixture.context,
            &final_request,
            100
        ),
        Err(PreparationError::Route(_))
    ));
    assert_eq!(
        prepared.request().prompt,
        fixture.prepare().unwrap().request().prompt
    );
}

#[test]
fn v3_preparation_gates_selected_body_with_conservative_serialized_bound() {
    let mut fixture = Fixture::new();
    fixture.enable_asset_contracts(4000);
    let prepared = fixture.prepare().unwrap();
    assert_eq!(prepared.receipt().schema_version, 3);
    assert_eq!(
        prepared.request().skills[0].kind,
        ExecutionSkillKind::Instruction
    );
    assert_eq!(prepared.preview().observed_input_tokens, None);
    let preview = serde_json::to_string(prepared.preview()).unwrap();
    assert!(!preview.contains("PRIVATE_SKILL_MARKER"));
    let mut inputs = fixture.enable_asset_contracts(4000);
    inputs.approved_review_digests.clear();
    fixture.context = fixture
        .router
        .context_with_assets(
            fixture.context.request().clone(),
            &fixture.snapshot,
            &fixture.catalog,
            inputs,
            100,
        )
        .unwrap();
    assert!(matches!(fixture.prepare(), Err(PreparationError::Route(_))));
}

#[test]
fn v3_preparation_rejects_unknown_executable_manifest_and_stale_auth() {
    let mut fixture = Fixture::new();
    let mut inputs = fixture.enable_asset_contracts(4000);
    let mut document = inputs.contracts.document().clone();
    document.skills[0].kind = AssetSkillKind::Executable;
    let document = router_asset_contracts::seal_contracts(document, &fixture.catalog).unwrap();
    inputs.contracts = router_asset_contracts::ValidatedContracts::from_json(
        &serde_json::to_vec(&document).unwrap(),
        &fixture.catalog,
        &document.content_hash,
    )
    .unwrap();
    fixture.context = fixture
        .router
        .context_with_assets(
            fixture.context.request().clone(),
            &fixture.snapshot,
            &fixture.catalog,
            inputs,
            100,
        )
        .unwrap();
    assert!(matches!(
        fixture.prepare(),
        Err(PreparationError::Abstained)
    ));
    fixture.enable_asset_contracts(4000);
    fixture.options.now_unix_seconds = 161;
    assert!(matches!(fixture.prepare(), Err(PreparationError::Route(_))));
}

#[test]
fn v3_preparation_does_not_treat_candidate_token_estimate_as_true_input_bound() {
    let mut fixture = Fixture::new();
    fixture.enable_asset_contracts(512);
    assert!(
        fixture
            .router
            .route(&fixture.context)
            .unwrap()
            .selected
            .is_some()
    );
    assert!(matches!(fixture.prepare(), Err(PreparationError::Route(_))));
}

struct Fixture {
    root: tempfile::TempDir,
    router: PhaseRouter,
    context: ValidatedPhaseContext,
    snapshot: ValidatedHostObservation,
    catalog: Catalog,
    plan: WorkflowPlan,
    metadata: MetadataDocument,
    index: Bm25Index,
    template: PromptTemplate,
    variables: BTreeMap<String, PromptValue>,
    options: PreparationOptions,
}
impl Fixture {
    fn enable_asset_contracts(&mut self, input_budget: u64) -> router_policy::PhaseAssetInputs {
        let mut request = self.context.request().clone();
        request.candidates[0].estimated_tokens = 4500;
        request.restrictions.max_tokens = Some(10_000);
        request.restrictions.policy_hash.clear();
        request.restrictions.policy_hash =
            content_digest(&serde_json::to_vec(&request.restrictions).unwrap());
        let scope = router_policy::PhaseExecutionScope {
            workspace: self.options.workspace.clone(),
            source_state: self.options.source_state.clone(),
            scope: self
                .plan
                .nodes
                .iter()
                .find(|node| node.id == "execute")
                .unwrap()
                .scope
                .clone(),
        };
        let inputs = asset_fixture::inputs(
            &request,
            &self.snapshot,
            &self.catalog,
            scope,
            &BTreeMap::from([(SkillId::parse("fixture-skill").unwrap(), SKILL.into())]),
            input_budget,
        );
        self.context = self
            .router
            .context_with_assets(request, &self.snapshot, &self.catalog, inputs.clone(), 100)
            .unwrap();
        inputs
    }
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut request: PhaseRouteRequest = serde_json::from_slice(include_bytes!(
            "../../../fixtures/examples/phase-request.json"
        ))
        .unwrap();
        request.phase = StageKind::Execute;
        request
            .task
            .allowed_mutations
            .remove(&Mutation::WorkspaceWrite);
        request.task.budget.max_elapsed_ms = 10_000;
        request.task.budget.max_tokens = 10_000;
        request.candidates.truncate(1);
        request.candidates[0].agent = Some("fixture-agent".into());
        request.candidates[0]
            .skills
            .insert(SkillId::parse("fixture-skill").unwrap());
        request.registry.assets.push(PhaseRegisteredAsset {
            kind: PhaseAssetKind::Agent,
            id: "fixture-agent".into(),
            content_sha256: content_digest(AGENT.as_bytes()),
            trust: SkillTrust::TrustedLocal,
            license: "MIT".into(),
            permission: CapabilitySupport::Supported,
            required_capabilities: BTreeSet::new(),
            required_mutations: BTreeSet::new(),
            allowed_sandboxes: BTreeSet::from([PhaseSandbox::ReadOnly]),
            maximum_sensitivity: DataSensitivity::Secret,
        });
        let plan = build_plan(
            &request.task,
            WorkflowPreset::DirectSafe,
            PlanLimits {
                reserve_cost_microusd: 500,
                reserve_tokens: 500,
                reserve_elapsed_ms: 1000,
                ..PlanLimits::default()
            },
        )
        .unwrap();
        let observation: HostObservation = serde_json::from_slice(include_bytes!(
            "../../../fixtures/examples/phase-snapshot.json"
        ))
        .unwrap();
        let snapshot = fixture_proofs::from_observation(
            observation,
            SnapshotValidation {
                now_unix_seconds: 100,
                max_age_seconds: 100,
            },
        )
        .unwrap();
        let mut catalog: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../fixtures/examples/phase-catalog.json"
        ))
        .unwrap();
        catalog["skills"] = serde_json::json!([{
            "id":"fixture-skill", "description":"fixture instruction", "task_kinds":["explore"],
            "required_capabilities":[], "trust":"trusted_local"
        }]);
        let catalog = Catalog::from_json(&serde_json::to_vec(&catalog).unwrap()).unwrap();
        let router = PhaseRouter::stable_v2();
        let context = router.context(request, &snapshot, &catalog).unwrap();
        let template = seal_prompt(PromptTemplate {
            schema_version: 1,
            id: "fixture-prompt".into(),
            version: "v1".into(),
            template: "Summarize ${subject}; return ${count} findings.".into(),
            variables: BTreeMap::from([
                ("subject".into(), PromptVariableType::Text),
                ("count".into(), PromptVariableType::Integer),
            ]),
            compatible_hosts: BTreeSet::from(["codex".into()]),
            compatible_models: BTreeSet::from([ModelId::parse("fixture-best").unwrap()]),
            max_rendered_bytes: 4096,
            output_contract: "Evidence-bearing findings.".into(),
            content_sha256: String::new(),
        })
        .unwrap();
        let prompt_bytes = serde_json::to_vec_pretty(&template).unwrap();
        let metadata = MetadataDocument {
            schema_version: "1".into(),
            catalog_version: catalog.version().into(),
            assets: vec![
                asset(
                    AssetKind::Agent,
                    "fixture-agent",
                    "agent.txt",
                    AGENT.as_bytes(),
                ),
                asset(
                    AssetKind::Skill,
                    "fixture-skill",
                    "skill.txt",
                    SKILL.as_bytes(),
                ),
                asset(
                    AssetKind::Prompt,
                    "fixture-prompt",
                    "prompt.json",
                    &prompt_bytes,
                ),
                asset(
                    AssetKind::Skill,
                    "unselected",
                    "never-created",
                    b"never read",
                ),
            ],
        };
        fs::write(root.path().join("agent.txt"), AGENT).unwrap();
        fs::write(root.path().join("skill.txt"), SKILL).unwrap();
        fs::write(root.path().join("prompt.json"), prompt_bytes).unwrap();
        let index = Bm25Index::build_bound(metadata.clone(), context.catalog_hash()).unwrap();
        let options = PreparationOptions {
            schema_version: 1,
            workspace: root.path().canonicalize().unwrap().to_str().unwrap().into(),
            source_state: "a".repeat(40),
            target: ExecutionTarget::ExternalWorker,
            allow_degradation: false,
            timeout_ms: 500,
            max_output_bytes: 8192,
            max_input_bytes: 65536,
            now_unix_seconds: 100,
            max_snapshot_age_seconds: 100,
        };
        Self {
            root,
            router,
            context,
            snapshot,
            catalog,
            plan,
            metadata,
            index,
            template,
            variables: BTreeMap::from([
                (
                    "subject".into(),
                    PromptValue::Text("PRIVATE_VARIABLE_MARKER".into()),
                ),
                ("count".into(), PromptValue::Integer(2)),
            ]),
            options,
        }
    }
    fn prepare(&self) -> Result<PreparedExecution, PreparationError> {
        prepare(self.input())
    }
    fn input(&self) -> PreparationInput<'_> {
        PreparationInput {
            router: &self.router,
            context: &self.context,
            plan: &self.plan,
            node_id: "execute",
            index: &self.index,
            body_root: self.root.path(),
            template: &self.template,
            variables: &self.variables,
            options: &self.options,
        }
    }
    fn reindex(&mut self) {
        self.index =
            Bm25Index::build_bound(self.metadata.clone(), self.context.catalog_hash()).unwrap();
    }
    fn reroute(&mut self, request: PhaseRouteRequest) {
        self.context = self
            .router
            .context(request, &self.snapshot, &self.catalog)
            .unwrap();
    }
}
fn asset(kind: AssetKind, id: &str, path: &str, bytes: &[u8]) -> AssetMetadata {
    AssetMetadata {
        id: id.into(),
        kind,
        trust: SkillTrust::TrustedLocal,
        task_kinds: vec![TaskKind::Explore],
        triggers: vec![],
        description: "synthetic fixture".into(),
        examples: vec![],
        tags: vec![],
        paths: vec![],
        anti_triggers: vec![],
        body: Some(BodyReference {
            path: path.into(),
            sha256: content_digest(bytes),
        }),
    }
}

#[test]
fn selected_bodies_are_bound_and_preview_is_redacted_without_approval() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare().unwrap();
    assert_eq!(
        prepared.receipt(),
        &fixture.router.route(&fixture.context).unwrap()
    );
    assert_eq!(prepared.preview().assets.len(), 3);
    assert_eq!(prepared.request().skills.len(), 1);
    assert_eq!(prepared.request().skills[0].body, SKILL);
    assert!(prepared.request().prompt.contains(AGENT));
    assert!(
        prepared
            .request()
            .prompt
            .contains("PRIVATE_VARIABLE_MARKER")
    );
    assert!(
        prepared
            .request()
            .prompt
            .contains("cite an enforcing symbol")
    );
    assert_eq!(prepared.request().scope, fixture.plan.nodes[0].scope);
    assert_eq!(prepared.request().tools, ToolSelection::Disabled);
    assert_eq!(prepared.request().mode, ExecutionMode::Execute);
    assert!(prepared.preview().approval_required);
    assert!(!prepared.preview().execution_started);
    assert_eq!(prepared.preview().observed_input_tokens, None);
    assert!(!fixture.root.path().join("never-created").exists());
    let preview = serde_json::to_string(prepared.preview()).unwrap();
    let debug = format!("{prepared:?}");
    for secret in [
        "PRIVATE_AGENT_MARKER",
        "PRIVATE_VARIABLE_MARKER",
        "PRIVATE_SKILL_MARKER",
    ] {
        assert!(!preview.contains(secret));
        assert!(!debug.contains(secret));
    }
    assert_eq!(
        prepared.preview().request_sha256,
        content_digest(&prepared.canonical_request_json().unwrap())
    );
    assert_eq!(
        prepared.preparation_hash(),
        fixture.prepare().unwrap().preparation_hash()
    );
    assert_eq!(
        fs::read_to_string(fixture.root.path().join("agent.txt")).unwrap(),
        AGENT
    );
}

#[test]
fn every_loaded_asset_requires_trust_and_an_unchanged_hash() {
    for kind in [AssetKind::Agent, AssetKind::Skill, AssetKind::Prompt] {
        let mut fixture = Fixture::new();
        fixture
            .metadata
            .assets
            .iter_mut()
            .find(|asset| asset.kind == kind)
            .unwrap()
            .trust = SkillTrust::Untrusted;
        fixture.reindex();
        assert!(matches!(
            fixture.prepare(),
            Err(PreparationError::Retrieval(RetrievalError::Selection))
        ));
        let fixture = Fixture::new();
        let path = &fixture
            .metadata
            .assets
            .iter()
            .find(|asset| asset.kind == kind)
            .unwrap()
            .body
            .as_ref()
            .unwrap()
            .path;
        fs::write(fixture.root.path().join(path), "tampered").unwrap();
        assert!(matches!(
            fixture.prepare(),
            Err(PreparationError::Retrieval(
                RetrievalError::BodyHashMismatch
            ))
        ));
    }
}

#[test]
fn catalog_binding_and_snapshot_freshness_precede_body_io() {
    let mut fixture = Fixture::new();
    fixture.index = Bm25Index::build(fixture.metadata.clone()).unwrap();
    assert!(matches!(
        fixture.prepare(),
        Err(PreparationError::Retrieval(RetrievalError::UnboundCatalog))
    ));
    fixture.index = Bm25Index::build_bound(fixture.metadata.clone(), &"a".repeat(64)).unwrap();
    assert!(matches!(
        fixture.prepare(),
        Err(PreparationError::Retrieval(RetrievalError::CatalogMismatch))
    ));
    fixture.reindex();
    fixture.options.now_unix_seconds = 201;
    fs::remove_file(fixture.root.path().join("prompt.json")).unwrap();
    assert!(matches!(fixture.prepare(), Err(PreparationError::Snapshot)));
}

#[test]
fn mismatched_plan_agent_and_prompt_are_refused() {
    let mut fixture = Fixture::new();
    let mut different_task = fixture.plan.task.clone();
    different_task.objective = "A different immutable task".into();
    fixture.plan = build_plan(
        &different_task,
        WorkflowPreset::DirectSafe,
        PlanLimits::default(),
    )
    .unwrap();
    assert!(matches!(
        fixture.prepare(),
        Err(PreparationError::Binding(
            "plan task differs from routed task"
        ))
    ));
    let mut fixture = Fixture::new();
    fixture.plan.nodes[0].scope.push("outside".into());
    assert!(matches!(
        fixture.prepare(),
        Err(PreparationError::Workflow(_))
    ));
    let mut fixture = Fixture::new();
    let mut request = fixture.context.request().clone();
    request.registry.assets[0].content_sha256 = "b".repeat(64);
    fixture.reroute(request);
    assert!(matches!(
        fixture.prepare(),
        Err(PreparationError::Binding(
            "agent body differs from routed authority"
        ))
    ));
    let mut fixture = Fixture::new();
    fixture.template.output_contract = "Different output contract".into();
    fixture.template = seal_prompt(fixture.template).unwrap();
    assert!(matches!(
        fixture.prepare(),
        Err(PreparationError::Binding(
            "prompt differs from selected asset"
        ))
    ));
}

#[test]
fn typed_variables_and_total_input_budget_are_enforced() {
    let mut fixture = Fixture::new();
    fixture.variables.remove("subject");
    assert!(matches!(
        fixture.prepare(),
        Err(PreparationError::Workflow(_))
    ));
    let mut fixture = Fixture::new();
    fixture
        .variables
        .insert("count".into(), PromptValue::Text("2".into()));
    assert!(matches!(
        fixture.prepare(),
        Err(PreparationError::Workflow(_))
    ));
    let mut fixture = Fixture::new();
    fixture.options.max_input_bytes = 1;
    assert!(matches!(fixture.prepare(), Err(PreparationError::Limit)));
    let mut fixture = Fixture::new();
    fixture.options.timeout_ms = fixture.plan.nodes[0].budget.max_elapsed_ms + 1;
    assert!(matches!(
        fixture.prepare(),
        Err(PreparationError::Binding("node authority or budget"))
    ));
}

#[test]
fn changing_a_variable_or_source_changes_preparation_identity() {
    let mut fixture = Fixture::new();
    let first = fixture.prepare().unwrap();
    fixture
        .variables
        .insert("count".into(), PromptValue::Integer(3));
    let second = fixture.prepare().unwrap();
    assert_eq!(first.receipt(), second.receipt());
    assert_ne!(first.preparation_hash(), second.preparation_hash());
    assert_ne!(
        first.preview().request_sha256,
        second.preview().request_sha256
    );
    fixture.options.source_state = "b".repeat(40);
    assert_ne!(
        second.preparation_hash(),
        fixture.prepare().unwrap().preparation_hash()
    );
}

#[test]
fn preparation_identity_binds_the_validation_clock() {
    let mut fixture = Fixture::new();
    let first = fixture.prepare().unwrap();
    fixture.options.now_unix_seconds += 1;
    let second = fixture.prepare().unwrap();

    assert_eq!(first.receipt(), second.receipt());
    assert_eq!(
        first.preview().request_sha256,
        second.preview().request_sha256
    );
    assert_ne!(first.preparation_hash(), second.preparation_hash());
}

#[test]
fn native_host_tool_authority_is_preserved_and_never_inferred_from_instructions() {
    let mut fixture = Fixture::new();
    let mut request = fixture.context.request().clone();
    request.candidates[0].tool_policy = PhaseToolPolicy::NativeHost;
    fixture.reroute(request.clone());
    assert!(matches!(
        fixture.prepare(),
        Err(PreparationError::Abstained)
    ));
    request.permissions.insert(
        PhasePermission::NativeHostTools,
        CapabilitySupport::Supported,
    );
    fixture.reroute(request);
    assert_eq!(
        fixture.prepare().unwrap().request().tools,
        ToolSelection::HostPolicy
    );
}

#[test]
fn a_registered_allowlist_is_preserved_without_loading_tool_bodies() {
    let mut fixture = Fixture::new();
    let mut request = fixture.context.request().clone();
    request.candidates[0].tools.insert("read-file".into());
    request.registry.assets.push(PhaseRegisteredAsset {
        kind: PhaseAssetKind::Tool,
        id: "read-file".into(),
        content_sha256: "c".repeat(64),
        trust: SkillTrust::TrustedLocal,
        license: "MIT".into(),
        permission: CapabilitySupport::Supported,
        required_capabilities: BTreeSet::new(),
        required_mutations: BTreeSet::new(),
        allowed_sandboxes: BTreeSet::from([PhaseSandbox::ReadOnly]),
        maximum_sensitivity: DataSensitivity::Secret,
    });
    fixture.reroute(request);
    let prepared = fixture.prepare().unwrap();
    assert_eq!(
        prepared.request().tools,
        ToolSelection::AllowList(vec!["read-file".into()])
    );
    assert_eq!(prepared.preview().assets.len(), 3);
}

#[test]
fn no_agent_or_skill_does_not_load_their_metadata_or_files() {
    let mut fixture = Fixture::new();
    let mut request = fixture.context.request().clone();
    request.candidates[0].agent = None;
    request.candidates[0].skills.clear();
    fixture.reroute(request);
    fs::remove_file(fixture.root.path().join("agent.txt")).unwrap();
    fs::remove_file(fixture.root.path().join("skill.txt")).unwrap();
    let prepared = fixture.prepare().unwrap();
    assert_eq!(prepared.preview().assets.len(), 1);
    assert!(prepared.request().skills.is_empty());
    assert_eq!(prepared.request().agent, None);
}

#[test]
fn abstention_and_parent_reconfiguration_cannot_become_execution_requests() {
    let mut fixture = Fixture::new();
    let mut request = fixture.context.request().clone();
    request.permissions.remove(&PhasePermission::ModelInference);
    fixture.reroute(request);
    fs::remove_file(fixture.root.path().join("prompt.json")).unwrap();
    assert!(matches!(
        fixture.prepare(),
        Err(PreparationError::Abstained)
    ));
    let mut fixture = Fixture::new();
    fixture.options.target = ExecutionTarget::ParentConversation;
    assert!(matches!(
        fixture.prepare(),
        Err(PreparationError::Adapter(
            router_adapter_api::AdapterError::Unsupported("parent-model-change")
        ))
    ));
}

#[test]
fn agent_tool_skill_and_mutation_capabilities_survive_preparation() {
    for source in ["agent", "tool", "skill", "mutation"] {
        let mut fixture = Fixture::new();
        let mut request = fixture.context.request().clone();
        match source {
            "agent" => {
                request.registry.assets[0]
                    .required_capabilities
                    .insert(Capability::Network);
            }
            "tool" => {
                let mut tool = request.registry.assets[0].clone();
                tool.kind = PhaseAssetKind::Tool;
                tool.id = "remote-read".into();
                tool.required_capabilities.insert(Capability::Network);
                request.registry.assets.push(tool);
                request.candidates[0].tools.insert("remote-read".into());
            }
            "skill" => {
                let mut catalog: serde_json::Value =
                    serde_json::from_slice(&fixture.catalog.canonical_json().unwrap()).unwrap();
                catalog["skills"][0]["required_capabilities"] = serde_json::json!(["network"]);
                fixture.catalog =
                    Catalog::from_json(&serde_json::to_vec(&catalog).unwrap()).unwrap();
            }
            "mutation" => {
                request.registry.assets[0]
                    .required_mutations
                    .insert(Mutation::Network);
            }
            _ => unreachable!(),
        }
        fixture.reroute(request.clone());
        fixture.reindex();
        let prepared = fixture.prepare().unwrap();
        assert!(
            prepared
                .request()
                .required_capabilities
                .contains(&Capability::Network),
            "{source}"
        );
        assert!(
            prepared
                .preview()
                .required_capabilities
                .contains(&Capability::Network)
        );
        assert!(
            prepared
                .receipt()
                .selected
                .as_ref()
                .unwrap()
                .candidate
                .required_capabilities
                .is_empty()
        );
        request
            .permissions
            .insert(PhasePermission::Network, CapabilitySupport::Unsupported);
        fixture.reroute(request);
        assert!(
            matches!(fixture.prepare(), Err(PreparationError::Abstained)),
            "{source}"
        );
        assert!(
            fixture
                .router
                .execution_capabilities(
                    &fixture.context,
                    prepared.receipt().selected.as_ref().unwrap()
                )
                .is_err()
        );
    }
}

#[test]
fn effective_capabilities_require_an_exact_eligible_selection() {
    let fixture = Fixture::new();
    let receipt = fixture.router.route(&fixture.context).unwrap();
    let selected = receipt.selected.as_ref().unwrap();
    assert!(
        fixture
            .router
            .execution_capabilities(&fixture.context, selected)
            .unwrap()
            .is_empty()
    );
    let mut forged = selected.clone();
    forged.score.utility_micros += 1;
    assert!(
        fixture
            .router
            .execution_capabilities(&fixture.context, &forged)
            .is_err()
    );
    let mut forged = selected.clone();
    forged
        .candidate
        .required_capabilities
        .insert(Capability::Network);
    assert!(
        fixture
            .router
            .execution_capabilities(&fixture.context, &forged)
            .is_err()
    );
}

#[test]
fn serialized_request_limit_accounts_for_json_escaping() {
    let mut fixture = Fixture::new();
    fixture.template.max_rendered_bytes = 65536;
    fixture.template = seal_prompt(fixture.template).unwrap();
    let bytes = serde_json::to_vec(&fixture.template).unwrap();
    fs::write(fixture.root.path().join("prompt.json"), &bytes).unwrap();
    fixture
        .metadata
        .assets
        .iter_mut()
        .find(|asset| asset.kind == AssetKind::Prompt)
        .unwrap()
        .body
        .as_mut()
        .unwrap()
        .sha256 = content_digest(&bytes);
    fixture.reindex();
    fixture.options.max_input_bytes = 128 * 1024;
    // The rendered prompt fits, but serializing a JSON prompt string inside the
    // execution document adds another escaping layer beyond the parser bound.
    fixture
        .variables
        .insert("subject".into(), PromptValue::Text("\"".repeat(40000)));
    assert!(matches!(fixture.prepare(), Err(PreparationError::Limit)));
}

#[cfg(unix)]
#[test]
fn selected_symlink_is_refused_but_unselected_missing_file_is_ignored() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    fs::remove_file(fixture.root.path().join("skill.txt")).unwrap();
    symlink("agent.txt", fixture.root.path().join("skill.txt")).unwrap();
    assert!(matches!(
        fixture.prepare(),
        Err(PreparationError::Retrieval(RetrievalError::UnsafePath))
    ));
}

#[test]
fn fallback_preparation_keeps_the_proved_candidate_and_context() {
    let mut fixture = Fixture::new();
    let mut request = fixture.context.request().clone();
    let original_id = request.candidates[0].id.clone();
    let mut fallback = request.candidates[0].clone();
    fallback.id = "fallback-only".into();
    request.candidates.push(fallback);
    fixture.reroute(request);
    // Identical default alternatives abstain. An explicit exclusion selects one.
    assert!(matches!(
        fixture.prepare(),
        Err(PreparationError::Abstained)
    ));
    let receipt = fixture
        .router
        .fallback(&fixture.context, &BTreeSet::from([original_id]))
        .unwrap();
    let proof = fixture
        .router
        .validate_receipt(&fixture.context, &receipt)
        .unwrap();
    let prepared = router_prepare::prepare_with_receipt(fixture.input(), &proof).unwrap();
    assert_eq!(prepared.receipt(), &receipt);
    assert_eq!(prepared.preview().candidate_id, "fallback-only");
    let mut changed = fixture.context.request().clone();
    changed.task.objective.push_str(" altered");
    fixture.reroute(changed);
    assert!(matches!(
        router_prepare::prepare_with_receipt(fixture.input(), &proof),
        Err(PreparationError::Route(
            router_policy::PhaseRouteError::ReceiptMismatch
        ))
    ));
}

#[path = "../../router-execution-decision/tests/support/synthetic.rs"]
mod semantic_fixture;

#[test]
fn activated_preparation_uses_secondary_and_keeps_baseline_unavailable_unchanged() {
    let mut f = Fixture::new();
    let mut request = f.context.request().clone();
    let mut secondary = request.candidates[0].clone();
    secondary.id = "secondary".into();
    secondary.model = ModelId::parse("fixture-second").unwrap();
    secondary.estimated_tokens = 4500;
    request.candidates.push(secondary);
    f.reroute(request);
    f.enable_asset_contracts(4000);
    f.options.now_unix_seconds = 124;
    f.template
        .compatible_models
        .insert(ModelId::parse("fixture-second").unwrap());
    f.template = seal_prompt(f.template).unwrap();
    let body = serde_json::to_vec(&f.template).unwrap();
    let entry = f
        .metadata
        .assets
        .iter_mut()
        .find(|a| a.kind == AssetKind::Prompt)
        .unwrap();
    let reference = entry.body.as_mut().unwrap();
    reference.sha256 = content_digest(&body);
    fs::write(f.root.path().join(&reference.path), &body).unwrap();
    f.reindex();
    let promotion = semantic_fixture::Fixture::new();
    let authority =
        semantic_fixture::TestAuthority::new(promotion.active(), promotion.keys.authorities());
    let decision =
        semantic_fixture::decision(&promotion, &f.router, &f.context, &authority, 124, 150);
    let prepared = router_prepare::prepare_with_decision(f.input(), &decision).unwrap();
    assert_eq!(prepared.request().model.as_str(), "fixture-second");
    assert_eq!(prepared.request().receipt_id, decision.authorization_id());
    assert_eq!(prepared.receipt(), decision.baseline());
    assert_eq!(
        prepared.receipt().selected.as_ref().unwrap().candidate.id,
        "primary"
    );
    assert!(prepared.receipt().unavailable.is_empty());
    assert_eq!(prepared.request().skills.len(), 1);
    assert_eq!(prepared.request().tools, ToolSelection::Disabled);
    // The secondary uses the same body-integrity gate as deterministic preparation.
    let skill = f
        .metadata
        .assets
        .iter()
        .find(|a| a.kind == AssetKind::Skill)
        .unwrap();
    fs::write(
        f.root.path().join(&skill.body.as_ref().unwrap().path),
        "changed body",
    )
    .unwrap();
    assert!(router_prepare::prepare_with_decision(f.input(), &decision).is_err());
}

#[test]
fn each_preparation_failure_class_has_its_own_fixed_code() {
    let mut fixture = Fixture::new();
    fixture.enable_asset_contracts(4000);
    fixture.options.now_unix_seconds = 161;
    let route = fixture.prepare().unwrap_err();
    assert_eq!(route.code(), "prepare.route.invalid");

    let fixture = Fixture::new();
    let path = &fixture
        .metadata
        .assets
        .iter()
        .find(|asset| asset.kind == AssetKind::Skill)
        .unwrap()
        .body
        .as_ref()
        .unwrap()
        .path;
    fs::write(fixture.root.path().join(path), "tampered secret-body").unwrap();
    let retrieval = fixture.prepare().unwrap_err();
    assert_eq!(retrieval.code(), "prepare.retrieval.invalid");

    let binding = PreparationError::Binding("secret-node-name");
    let codes = [
        route.code(),
        retrieval.code(),
        PreparationError::Abstained.code(),
        PreparationError::Snapshot.code(),
        PreparationError::Limit.code(),
        PreparationError::Json.code(),
        binding.code(),
    ];
    let distinct: std::collections::BTreeSet<_> = codes.iter().collect();
    assert_eq!(distinct.len(), codes.len());
    assert!(codes.iter().all(|code| code.starts_with("prepare.")));
    assert!(!binding.code().contains("secret"));
    assert!(!retrieval.code().contains("secret"));
}
