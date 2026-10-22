//! Synthetic publishers and keys only; no production roots or human approval.
#![allow(dead_code)]
#[path = "../../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use ed25519_dalek::{Signer, SigningKey};
use router_adapter_api::{
    HostObservation, SnapshotValidation, ValidatedHostObservation, content_digest,
};
use router_catalog::*;
use router_retrieval::{Bm25Index, SignalProvenance};
use router_types::*;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[13; 32])
}
fn host() -> AssetHostBinding {
    AssetHostBinding {
        harness: HarnessId::parse("codex").unwrap(),
        version: "fixture-v1".into(),
    }
}
fn provenance() -> SignalProvenance {
    SignalProvenance {
        source_id: "synthetic-signed-fixture".into(),
        source_version: "1".into(),
        source_sha256: "a".repeat(64),
        observed_at_unix_seconds: 100,
    }
}
pub fn grant() -> CatalogPublisherGrant {
    CatalogPublisherGrant {
        key_id: "fixture-publisher".into(),
        public_key: signer().verifying_key().to_bytes(),
        catalog_ids: BTreeSet::from(["fixture-catalog".into()]),
        allowed_kinds: BTreeSet::from([
            CatalogAssetKind::Model,
            CatalogAssetKind::Agent,
            CatalogAssetKind::Skill,
            CatalogAssetKind::Prompt,
            CatalogAssetKind::Tool,
            CatalogAssetKind::Host,
            CatalogAssetKind::Preset,
        ]),
        allowed_licenses: BTreeSet::from(["MIT".into()]),
        trust_ceiling: SkillTrust::VerifiedThirdParty,
    }
}
pub fn roots() -> TrustedCatalogPublishers {
    TrustedCatalogPublishers::new([grant()]).unwrap()
}
fn all_mutations() -> BTreeSet<Mutation> {
    BTreeSet::from([
        Mutation::WorkspaceWrite,
        Mutation::Network,
        Mutation::ExecuteSkills,
        Mutation::Integrate,
    ])
}
fn entry(
    id: &str,
    kind: &str,
    definition: Value,
    body: Option<(&str, &[u8])>,
) -> SignedCatalogEntry {
    let searchable = kind != "host" && kind != "preset";
    let capabilities = if kind == "model" || kind == "host" {
        json!(["tools", "subagents", "vision", "network", "workspace_write"])
    } else {
        json!([])
    };
    serde_json::from_value(json!({
        "schema_version":1,"id":id,"version":"1","provenance":{"source":"https://example.test/synthetic-catalog","revision":"fixture-revision","source_sha256":"a".repeat(64)},
        "license_expression":"MIT","authors":["Synthetic fixture publisher"],"valid_from_unix_seconds":100,"valid_until_unix_seconds":1000,"declared_trust":"builtin",
        "capabilities":capabilities,"requirements":{"capabilities":[],"mutations":[],"tools":[],"compatible_hosts":[host()]},
        "restrictions":{"allowed_mutations":all_mutations(),"allowed_sandboxes":["read_only","workspace_write"],"maximum_sensitivity":"public"},
        "context_cost_estimate":1,"deprecated_by":null,"payload_sha256":"","payload":{"kind":kind,"definition":definition},
        "search":if searchable {json!({"kind":kind,"id":id,"trust":"builtin","description":"inspect parser","body":body.map(|(path,bytes)|json!({"path":path,"sha256":content_digest(bytes)}))})} else {Value::Null},
        "signals":if searchable {json!({"asset":{"kind":kind,"id":id},"languages":{"status":"observed","value":["rust"],"provenance":provenance()},"required_tools":{"status":"observed","value":[],"provenance":provenance()},"history":{"status":"unknown"}})} else {Value::Null}
    })).unwrap()
}
fn manifest_fixture() -> (SignedCatalogManifest, Vec<u8>) {
    let prompt = router_workflow::seal_prompt(PromptTemplate {
        schema_version: 1,
        id: "fixture-prompt".into(),
        version: "1".into(),
        template: "Inspect ${topic}".into(),
        variables: BTreeMap::from([("topic".into(), PromptVariableType::Text)]),
        compatible_hosts: BTreeSet::from(["codex".into()]),
        compatible_models: BTreeSet::from([
            ModelId::parse("fixture-best").unwrap(),
            ModelId::parse("fixture-second").unwrap(),
        ]),
        max_rendered_bytes: 1024,
        output_contract: "Plain text findings".into(),
        content_sha256: String::new(),
    })
    .unwrap();
    let prompt_bytes = serde_json::to_vec(&prompt).unwrap();
    let model = json!({"id":"fixture-best","stages":["plan","execute","verify"],"efforts":["medium","high"],"capabilities":["tools","subagents","vision","network","workspace_write"],"quality_micros":800000,"cost_micros":100,"latency_micros":100,"source":"https://example.test/synthetic-catalog"});
    let skill = json!({"id":"fixture-skill","description":"inspect parser","task_kinds":["explore"],"required_capabilities":[],"trust":"builtin"});
    let registered = |id: &str, kind: &str| json!({"id":id,"kind":kind,"content_sha256":content_digest(b"inspect parser body"),"trust":"builtin","license":"MIT","permission":"unknown","required_capabilities":[],"required_mutations":[],"allowed_sandboxes":["read_only","workspace_write"],"maximum_sensitivity":"public"});
    let prompt_definition = json!({"variables":prompt.variables,"compatible_hosts":prompt.compatible_hosts,"compatible_models":prompt.compatible_models,"max_rendered_bytes":prompt.max_rendered_bytes,"output_contract":prompt.output_contract});
    let mut assets = vec![
        entry("fixture-best", "model", model, None),
        entry(
            "fixture-agent",
            "agent",
            registered("fixture-agent", "agent"),
            Some(("agents/fixture.md", b"inspect parser body")),
        ),
        entry(
            "fixture-skill",
            "skill",
            skill,
            Some(("skills/fixture.md", b"inspect parser body")),
        ),
        entry(
            "fixture-prompt",
            "prompt",
            prompt_definition,
            Some(("prompts/fixture.json", &prompt_bytes)),
        ),
        entry(
            "fixture-tool",
            "tool",
            registered("fixture-tool", "tool"),
            None,
        ),
        entry(
            "fixture-host",
            "host",
            json!({"harness":"codex","versions":["fixture-v1"],"declared_capabilities":["tools","subagents","vision","network","workspace_write"],"compatible_models":["fixture-best","fixture-second"]}),
            None,
        ),
        entry(
            "fixture-preset",
            "preset",
            json!({"preset":"plan-execute-verify","max_width":2,"max_depth":4,"max_nodes":8,"reserve_cost_microusd":1,"reserve_tokens":1,"reserve_elapsed_ms":1,"maximum_budget":{"max_cost_microusd":10000,"max_tokens":1000,"max_elapsed_ms":1000},"allowed_capabilities":["tools","subagents","vision","network","workspace_write"],"minimum_risk":"low"}),
            None,
        ),
    ];
    let mut second = assets[0].clone();
    second.id = "fixture-second".into();
    if let SignedAssetPayload::Model(model) = &mut second.payload {
        model.id = ModelId::parse("fixture-second").unwrap();
        model.quality_micros = 700000;
    }
    second.search.as_mut().unwrap().id = second.id.clone();
    second.signals.as_mut().unwrap().asset.id = second.id.clone();
    assets.push(second);
    (
        seal_signed_manifest(SignedCatalogManifest {
            schema_version: 1,
            id: "fixture-catalog".into(),
            version: "fixtures-v1".into(),
            valid_from_unix_seconds: 100,
            valid_until_unix_seconds: 1000,
            assets,
            content_sha256: String::new(),
        })
        .unwrap(),
        prompt_bytes,
    )
}
fn signed(manifest: SignedCatalogManifest) -> SignedCatalogDocument {
    let manifest = seal_signed_manifest(manifest).unwrap();
    let signature =
        signer().sign(&catalog_signing_message("fixture-publisher", &manifest).unwrap());
    SignedCatalogDocument {
        schema_version: 3,
        manifest,
        signature: CatalogPublisherSignature {
            key_id: "fixture-publisher".into(),
            signature_hex: hex::encode(signature.to_bytes()),
        },
    }
}

use router_catalog_store::{CatalogHead, CatalogStore};
use router_policy::{
    PhaseExecutionScope, PhaseRouteError, PhaseRouter, SignedPhaseInputs, ValidatedPhaseContext,
};
pub struct Fixture {
    pub temp: tempfile::TempDir,
    pub store: CatalogStore,
    pub roots: TrustedCatalogPublishers,
    pub manifest: SignedCatalogManifest,
    pub request: PhaseRouteRequest,
    pub observation: HostObservation,
    pub inputs: SignedPhaseInputs,
    pub router: PhaseRouter,
}
impl Fixture {
    pub fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap().join("store");
        let store = CatalogStore::create(&path, "synthetic-routing", "fixture-catalog").unwrap();
        let request: PhaseRouteRequest = serde_json::from_slice(include_bytes!(
            "../../../../fixtures/examples/phase-request.json"
        ))
        .unwrap();
        let observation = serde_json::from_slice(include_bytes!(
            "../../../../fixtures/examples/phase-snapshot.json"
        ))
        .unwrap();
        let inputs = SignedPhaseInputs {
            host_asset_id: "fixture-host".into(),
            preset_asset_id: "fixture-preset".into(),
            prompt_ids: request
                .candidates
                .iter()
                .map(|candidate| (candidate.id.clone(), "fixture-prompt".into()))
                .collect(),
            execution_scope: PhaseExecutionScope {
                workspace: "/synthetic/workspace".into(),
                source_state: "a".repeat(40),
                scope: vec!["src".into()],
            },
        };
        Self {
            temp,
            store,
            roots: roots(),
            manifest: manifest_fixture().0,
            request,
            observation,
            inputs,
            router: PhaseRouter::stable_v2(),
        }
    }
    pub fn entry(&mut self, kind: CatalogAssetKind, id: &str) -> &mut SignedCatalogEntry {
        self.manifest
            .assets
            .iter_mut()
            .find(|entry| entry.payload.kind() == kind && entry.id == id)
            .unwrap()
    }
    pub fn activate(&self, now: u64) -> CatalogHead {
        let bytes = signed(self.manifest.clone()).canonical_json().unwrap();
        let review = self
            .store
            .review_activate(&bytes, &self.roots, now, 20)
            .unwrap();
        self.store
            .apply(&review, review.approval_digest(), &self.roots, now)
            .unwrap()
    }
    pub fn snapshot(&self) -> ValidatedHostObservation {
        fixture_proofs::from_observation(
            self.observation.clone().seal().unwrap(),
            SnapshotValidation {
                now_unix_seconds: 100,
                max_age_seconds: 100,
            },
        )
        .unwrap()
    }
    pub fn index(&self, now: u64) -> Bm25Index {
        let head = self.store.status().unwrap();
        let guard = self
            .store
            .acquire_current(&head.head_hash, &self.roots, now)
            .unwrap();
        Bm25Index::build_v3(
            guard
                .catalog()
                .retrieval(&guard.access(&self.roots, now).unwrap())
                .unwrap(),
        )
        .unwrap()
    }
    pub fn context(&self, now: u64) -> Result<ValidatedPhaseContext, PhaseRouteError> {
        self.context_with_index(&self.index(now), now)
    }
    pub fn context_with_index(
        &self,
        index: &Bm25Index,
        now: u64,
    ) -> Result<ValidatedPhaseContext, PhaseRouteError> {
        let head = self.store.status().unwrap();
        let guard = self
            .store
            .acquire_current(&head.head_hash, &self.roots, now)
            .unwrap();
        self.router.context_with_signed_catalog(
            self.request.clone(),
            &self.snapshot(),
            &guard,
            &self.roots,
            self.inputs.clone(),
            None,
            index,
            now,
        )
    }
    pub fn select_optional_assets(&mut self) {
        let candidate = &mut self.request.candidates[0];
        candidate.agent = Some("fixture-agent".into());
        candidate
            .skills
            .insert(SkillId::parse("fixture-skill").unwrap());
        candidate.tools.insert("fixture-tool".into());
        for entry in &self.manifest.assets {
            if let SignedAssetPayload::Agent(asset) | SignedAssetPayload::Tool(asset) =
                &entry.payload
            {
                let mut asset = asset.clone();
                asset.permission = CapabilitySupport::Supported;
                asset.trust = SkillTrust::VerifiedThirdParty;
                self.request.registry.assets.push(asset);
            }
        }
    }
}
