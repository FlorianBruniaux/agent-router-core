//! Synthetic publisher, host and local asset evidence. No native execution.
#![allow(dead_code)]
#[path = "../../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
#[path = "signed_assets.rs"]
mod signed_assets;
use router_adapter_api::{SnapshotValidation, ValidatedHostObservation};
use router_catalog::{SignedAssetPayload, TrustedCatalogPublishers};
use router_catalog_store::CurrentCatalogGuard;
use router_policy::{PhaseRouter, ValidatedPhaseContext, ValidatedPhaseReceipt};
use router_prepare::{
    PreparationError, PublicSignedPreparationOptions, SignedPreparationInput,
    SignedPreparedExecution, prepare_signed_with_receipt,
};
use router_retrieval::Bm25Index;
use router_types::*;
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct Fixture {
    pub source: crate::signed_fixture::Fixture,
    pub context: ValidatedPhaseContext,
    pub index: Bm25Index,
    pub execution: WorkflowExecutionContract,
    pub options: PublicSignedPreparationOptions,
    pub variables: BTreeMap<String, PromptValue>,
    pub body_root: PathBuf,
    pub template: PromptTemplate,
    pub snapshot: ValidatedHostObservation,
    pub assets: router_policy::PhaseAssetInputs,
    pub now: u64,
}
impl Fixture {
    pub fn new() -> Self {
        Self::at(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
    }
    pub fn at(now: u64) -> Self {
        Self::at_with_unknown_auth_model(now, None)
    }
    pub fn at_with_unknown_auth_model(now: u64, unknown_auth_model: Option<&str>) -> Self {
        let mut source = crate::signed_fixture::Fixture::new();
        let mut grant = crate::signed_fixture::grant();
        grant.trust_ceiling = SkillTrust::TrustedLocal;
        source.roots = TrustedCatalogPublishers::new([grant]).unwrap();
        source.select_optional_assets();
        source.request.candidates[0].tools.clear();
        for asset in &mut source.request.registry.assets {
            asset.trust = SkillTrust::TrustedLocal;
        }
        for candidate in &mut source.request.candidates {
            candidate.estimated_tokens = 10000;
        }
        source.request.task.budget.max_tokens = 50000;
        source.request.task.budget.max_elapsed_ms = 10000;
        source.request.restrictions = router_workflow::merge_restrictions(&[RestrictionLayer {
            name: "synthetic-parent-authority".into(),
            allowed_models: None,
            allowed_capabilities: source.request.restrictions.allowed_capabilities.clone(),
            allowed_mutations: source.request.restrictions.allowed_mutations.clone(),
            max_cost_microusd: Some(10000),
            max_tokens: Some(50000),
            max_concurrency: Some(2),
            preferred_model: None,
        }])
        .unwrap();
        source.manifest.valid_from_unix_seconds = now;
        source.manifest.valid_until_unix_seconds = now + 600;
        for entry in &mut source.manifest.assets {
            entry.valid_from_unix_seconds = now;
            entry.valid_until_unix_seconds = now + 600;
            if let Some(signals) = &mut entry.signals {
                if let router_retrieval::Signal::Observed { provenance, .. } =
                    &mut signals.languages
                {
                    provenance.observed_at_unix_seconds = now;
                }
                if let router_retrieval::Signal::Observed { provenance, .. } =
                    &mut signals.required_tools
                {
                    provenance.observed_at_unix_seconds = now;
                }
            }
            if let SignedAssetPayload::Preset(preset) = &mut entry.payload {
                preset.maximum_budget = source.request.task.budget.clone();
            }
        }
        source.observation.observed_at_unix_seconds = now;
        for evidence in &mut source.observation.evidence {
            evidence.observed_at_unix_seconds = now;
        }
        let snapshot = fixture_proofs::from_observation(
            source.observation.clone().seal().unwrap(),
            SnapshotValidation {
                now_unix_seconds: now,
                max_age_seconds: 60,
            },
        )
        .unwrap();
        let head = source.activate(now);
        let guard = source
            .store
            .acquire_current(&head.head_hash, &source.roots, now)
            .unwrap();
        let access = guard.access(&source.roots, now).unwrap();
        let catalog = guard.catalog().catalog(&access).unwrap();
        let index = Bm25Index::build_v3(guard.catalog().retrieval(&access).unwrap()).unwrap();
        let bodies = BTreeMap::from([(
            SkillId::parse("fixture-skill").unwrap(),
            "inspect parser body".into(),
        )]);
        let assets = signed_assets::inputs(
            &source.request,
            &snapshot,
            &catalog,
            source.inputs.execution_scope.clone(),
            &bodies,
            6000,
            unknown_auth_model,
        );
        let context = source
            .router
            .context_with_signed_catalog(
                source.request.clone(),
                &snapshot,
                &guard,
                &source.roots,
                source.inputs.clone(),
                Some(assets.clone()),
                &index,
                now,
            )
            .unwrap();
        let plan = context.signed_plan().unwrap();
        let execution = router_workflow::seal_execution_contract(
            WorkflowExecutionContract {
                schema_version: 1,
                instance_id: "synthetic-signed-preparation".into(),
                plan_id: plan.plan_id.clone(),
                workspace: source.inputs.execution_scope.workspace.clone(),
                source_state: source.inputs.execution_scope.source_state.clone(),
                nodes: plan
                    .nodes
                    .iter()
                    .map(|node| {
                        (
                            node.id.clone(),
                            NodeExecutionContract {
                                phase: match node.id.as_str() {
                                    "plan" => StageKind::Plan,
                                    "execute" => StageKind::Execute,
                                    "verify" => StageKind::Verify,
                                    _ => panic!("fixture node"),
                                },
                                dependencies: node
                                    .dependencies
                                    .iter()
                                    .map(|id| (id.clone(), DependencyRequirement::Verified))
                                    .collect(),
                            },
                        )
                    })
                    .collect(),
                contract_sha256: String::new(),
            },
            plan,
        )
        .unwrap();
        let entry = source
            .manifest
            .assets
            .iter()
            .find(|entry| entry.id == "fixture-prompt")
            .unwrap();
        let SignedAssetPayload::Prompt(definition) = &entry.payload else {
            panic!("fixture prompt")
        };
        let template = router_workflow::seal_prompt(PromptTemplate {
            schema_version: 1,
            id: entry.id.clone(),
            version: entry.version.clone(),
            template: "Inspect ${topic}".into(),
            variables: definition.variables.clone(),
            compatible_hosts: definition.compatible_hosts.clone(),
            compatible_models: definition.compatible_models.clone(),
            max_rendered_bytes: definition.max_rendered_bytes,
            output_contract: definition.output_contract.clone(),
            content_sha256: String::new(),
        })
        .unwrap();
        let body_root = source.temp.path().join("bodies");
        for directory in ["agents", "skills", "prompts"] {
            fs::create_dir_all(body_root.join(directory)).unwrap();
        }
        fs::write(body_root.join("agents/fixture.md"), b"inspect parser body").unwrap();
        fs::write(body_root.join("skills/fixture.md"), b"inspect parser body").unwrap();
        fs::write(
            body_root.join("prompts/fixture.json"),
            serde_json::to_vec(&template).unwrap(),
        )
        .unwrap();
        let options = PublicSignedPreparationOptions {
            schema_version: 1,
            workspace: execution.workspace.clone(),
            source_state: execution.source_state.clone(),
            target: ExecutionTarget::ExternalWorker,
            allow_degradation: false,
            timeout_ms: 100,
            max_output_bytes: 1024,
            max_input_bytes: 10000,
            max_snapshot_age_seconds: 60,
        };
        drop(guard);
        Self {
            source,
            context,
            index,
            execution,
            options,
            variables: BTreeMap::from([(
                "topic".into(),
                PromptValue::Text("PRIVATE_VARIABLE_MARKER".into()),
            )]),
            body_root,
            template,
            snapshot,
            assets,
            now,
        }
    }
    pub fn router(&self) -> &PhaseRouter {
        &self.source.router
    }
    pub fn guard(&self) -> CurrentCatalogGuard {
        let head = self.source.store.status().unwrap();
        self.source
            .store
            .acquire_current(&head.head_hash, &self.source.roots, self.now)
            .unwrap()
    }
    pub fn receipt(&self) -> ValidatedPhaseReceipt {
        self.router()
            .validate_receipt(&self.context, &self.router().route(&self.context).unwrap())
            .unwrap()
    }
    pub fn input(&self) -> SignedPreparationInput<'_> {
        SignedPreparationInput {
            router: self.router(),
            context: &self.context,
            execution: &self.execution,
            node_id: "plan",
            index: &self.index,
            body_root: &self.body_root,
            variables: &self.variables,
            options: &self.options,
        }
    }
    pub fn prepare(&self) -> Result<SignedPreparedExecution, PreparationError> {
        prepare_signed_with_receipt(
            self.input(),
            &self.receipt(),
            &self.guard(),
            &self.source.roots,
        )
    }
}
