//! Metadata-only global planning. Serialized proposals carry no execution authority.
use crate::{
    CliError, Outcome, command::PhaseArgs, execution, inspect, phases, product, read_bounded,
};
use router_policy::{
    GenerationError, GenerationNode, PhaseRouter, PlanGenerationInput, ValidatedPhaseContext,
    generate_plans,
};
use router_types::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::ExitCode,
};

const MAX_MANIFEST: usize = 1024 * 1024;
const MAX_DOCUMENT: usize = 8 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    capability_store: Option<PathBuf>,
    execution_config: Option<PathBuf>,
    node_id: String,
    context: PathBuf,
    host_snapshot: PathBuf,
    catalog: PathBuf,
    policy: Option<PathBuf>,
    asset_authority: Option<PathBuf>,
    dimensions: Option<GenerationDimensions>,
    #[serde(default)]
    evidence: BTreeMap<String, GenerationCandidateEvidence>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    plan: PathBuf,
    workflow_contract: PathBuf,
    policy: PlanGenerationPolicy,
    nodes: Vec<Node>,
    compatibility: Vec<GenerationEdgeCompatibility>,
    snapshot_max_age_seconds: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Document {
    pub schema_version: u32,
    pub input: PathBuf,
    pub source_sha256: String,
    pub planned_at_unix_seconds: u64,
    pub report: PlanGenerationReport,
    #[serde(default)]
    pub selected_proposal_hash: Option<String>,
}

pub(crate) fn error(e: GenerationError) -> CliError {
    CliError::Product(match e {
        GenerationError::Invalid(_) => "generation.invalid",
        GenerationError::Limit(_) | GenerationError::WorkLimit { .. } => "generation.limit",
        GenerationError::Binding => "generation.binding",
        GenerationError::Expired => "generation.evidence.expired",
        GenerationError::Phase(_) => "generation.phase",
        GenerationError::Workflow(_) => "generation.workflow",
    })
}
fn resolve(base: &Path, path: &Path) -> Result<PathBuf, CliError> {
    if path.as_os_str().is_empty() || path.as_os_str().len() > 4096 {
        return Err(CliError::Product("generation.path"));
    }
    std::fs::canonicalize(if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    })
    .map_err(|_| CliError::Product("generation.source.unavailable"))
}
#[derive(Default)]
struct Sources {
    bytes: usize,
    hashes: BTreeMap<PathBuf, (usize, String)>,
}
impl Sources {
    fn capture(&mut self, path: &Path, limit: usize) -> Result<Vec<u8>, CliError> {
        let remaining = MAX_SOURCE_BYTES.saturating_sub(self.bytes);
        let bytes = read_bounded(
            path,
            limit.min(remaining),
            CliError::RequestRead,
            CliError::Product("generation.source.limit"),
        )?;
        self.bytes += bytes.len();
        let hash = router_adapter_api::content_digest(&bytes);
        if self
            .hashes
            .insert(path.to_owned(), (bytes.len(), hash.clone()))
            .is_some_and(|old| old != (bytes.len(), hash))
        {
            return Err(CliError::Product("generation.source.changed"));
        }
        Ok(bytes)
    }
    fn assets(&mut self, path: &Path) -> Result<(), CliError> {
        let bytes = self.capture(path, 256 * 1024)?;
        let value =
            router_adapter_api::strict_json(&bytes).map_err(|_| CliError::RequestJsonInvalid)?;
        let base = path.parent().ok_or(CliError::RequestRead)?;
        for field in ["contracts", "availability", "policy", "requests"] {
            let raw = if matches!(field, "contracts" | "availability") {
                &value[field]["path"]
            } else {
                &value[field]
            };
            let path = raw.as_str().ok_or(CliError::RequestJsonInvalid)?;
            self.capture(&resolve(base, Path::new(path))?, 4 * 1024 * 1024)?;
        }
        // metadata and body_root are deliberately unopened before selection.
        Ok(())
    }
    fn verify(&self) -> Result<(), CliError> {
        for (path, (length, expected)) in &self.hashes {
            let bytes = read_bounded(
                path,
                *length,
                CliError::RequestRead,
                // A source that grew past its captured length changed.
                CliError::Product("generation.source.changed"),
            )?;
            if router_adapter_api::content_digest(&bytes) != *expected {
                return Err(CliError::Product("generation.source.changed"));
            }
        }
        Ok(())
    }
    fn hash(&self) -> Result<String, CliError> {
        serde_json::to_vec(&self.hashes)
            .map(|bytes| router_adapter_api::content_digest(&bytes))
            .map_err(|_| CliError::Internal)
    }
}

struct Loaded {
    path: PathBuf,
    source_sha256: String,
    manifest: Manifest,
    plan: WorkflowPlan,
    contract: WorkflowExecutionContract,
    contexts: Vec<(PhaseRouter, ValidatedPhaseContext)>,
}
impl Loaded {
    fn nodes(&self) -> Vec<GenerationNode<'_>> {
        self.manifest
            .nodes
            .iter()
            .zip(&self.contexts)
            .map(|(input, (router, context))| {
                let mut node = GenerationNode::from_context(&input.node_id, router, context);
                if let Some(dimensions) = &input.dimensions {
                    node.dimensions = dimensions.clone();
                }
                node.evidence = input.evidence.clone();
                node
            })
            .collect()
    }
    fn input<'a>(&'a self, nodes: &'a [GenerationNode<'a>], now: u64) -> PlanGenerationInput<'a> {
        PlanGenerationInput {
            plan: &self.plan,
            execution: &self.contract,
            nodes,
            compatibility: &self.manifest.compatibility,
            policy: &self.manifest.policy,
            now_unix_seconds: now,
        }
    }
}
/// Reconstruct a previously hashed proposal from only its own authenticated
/// references. This horizon is not accepted from a CLI argument and is never
/// used by fresh generation or dispatch. load_decision must still compare the
/// complete captured source set and report with the approved document.
fn historical_node_verifier(
    store: &Path,
    snapshot: &Path,
) -> Result<std::sync::Arc<dyn router_adapter_api::CapabilityProofVerifier>, CliError> {
    let observation: router_adapter_api::HostObservation =
        phases::read_json(snapshot, router_adapter_api::MAX_SNAPSHOT_BYTES)?;
    let references: std::collections::BTreeSet<_> = observation
        .capabilities
        .values()
        .filter(|evidence| evidence.support != CapabilitySupport::Unknown)
        .flat_map(|evidence| evidence.source_ids.iter())
        .collect();
    let mut sources: Vec<_> = observation
        .evidence
        .iter()
        .filter(|source| references.contains(&source.id))
        .cloned()
        .collect();
    if sources.len() != references.len() {
        return Err(CliError::Product("capability.evidence.unauthenticated"));
    }
    // Other provenance may accompany a runtime proof without granting authority.
    // The shared snapshot validator still checks every declared source.
    sources.retain(|source| source.kind == router_adapter_api::EvidenceKind::HostRuntime);
    let secret: [u8; 32] = crate::approval_key::load_existing(store)?
        .bytes()
        .try_into()
        .map_err(|_| CliError::Internal)?;
    let proofs = router_runtime::CapabilityProofStore::open_existing(store)
        .map_err(|error| CliError::Product(error.code()))?
        .verifier(&secret, vec![])
        .map_err(|error| CliError::Product(error.code()))?;
    let sequence = proofs
        .referenced_sequence(&observation.host, &sources)
        .map_err(|error| CliError::Product(error.code()))?;
    let attestation_sequence = proofs
        .referenced_attestation_sequence(
            &observation.host,
            observation
                .attestations
                .as_ref()
                .map_or(&[], |value| value.entries.as_slice()),
        )
        .map_err(|error| CliError::Product(error.code()))?;
    let sequence = sequence.max(attestation_sequence);
    crate::capability_proofs::historical_through(store, Some(sequence))
}

fn load(path: &Path, now: u64) -> Result<Loaded, CliError> {
    load_mode(path, now, false)
}
fn load_mode(path: &Path, now: u64, historical: bool) -> Result<Loaded, CliError> {
    let path = resolve(
        &std::env::current_dir().map_err(|_| CliError::RequestRead)?,
        path,
    )?;
    let base = path.parent().ok_or(CliError::RequestRead)?;
    let mut sources = Sources::default();
    let value = router_adapter_api::strict_json(&sources.capture(&path, MAX_MANIFEST)?)
        .map_err(|_| CliError::RequestJsonInvalid)?;
    let manifest: Manifest =
        serde_json::from_value(value).map_err(|_| CliError::RequestJsonInvalid)?;
    if manifest.schema_version != 1
        || manifest.nodes.is_empty()
        || manifest.nodes.len() > router_policy::MAX_GENERATION_NODES
        || manifest.snapshot_max_age_seconds == 0
        || manifest.snapshot_max_age_seconds > 300
    {
        return Err(CliError::Product("generation.manifest"));
    }
    let plan_path = resolve(base, &manifest.plan)?;
    let contract_path = resolve(base, &manifest.workflow_contract)?;
    sources.capture(&plan_path, MAX_DOCUMENT)?;
    sources.capture(&contract_path, MAX_DOCUMENT)?;
    let plan = execution::plan(&plan_path)?;
    let contract = phases::read_json(&contract_path, MAX_DOCUMENT)?;
    let mut args = vec![];
    for node in &manifest.nodes {
        let context = resolve(base, &node.context)?;
        let host_snapshot = resolve(base, &node.host_snapshot)?;
        let catalog = resolve(base, &node.catalog)?;
        sources.capture(&context, router_policy::MAX_PHASE_REQUEST_BYTES)?;
        sources.capture(&host_snapshot, router_adapter_api::MAX_SNAPSHOT_BYTES)?;
        sources.capture(&catalog, crate::MAX_CATALOG_BYTES)?;
        let policy = node.policy.as_ref().map(|p| resolve(base, p)).transpose()?;
        if let Some(p) = &policy {
            sources.capture(p, 64 * 1024)?;
        }
        let asset_authority = node
            .asset_authority
            .as_ref()
            .map(|p| resolve(base, p))
            .transpose()?;
        if let Some(p) = &asset_authority {
            sources.assets(p)?;
        }
        let (store, execution_config) = match (&node.capability_store, &node.execution_config) {
            (Some(store), Some(config)) => {
                let store = resolve(base, store)?;
                let config = resolve(base, config)?;
                sources.capture(&config, 64 * 1024)?;
                (Some(store), Some(config))
            }
            (None, None) => (None, None),
            _ => {
                return Err(CliError::Product(
                    "capability.evidence.configuration_required",
                ));
            }
        };
        args.push(PhaseArgs {
            store,
            execution_config,
            context,
            host_snapshot,
            catalog,
            policy,
            policy_store: None,
            asset_authority,
            now: Some(now),
            snapshot_max_age_seconds: manifest.snapshot_max_age_seconds,
        });
    }
    let contexts = args
        .iter()
        .map(|inputs| {
            let verifier = if historical {
                inputs
                    .store
                    .as_deref()
                    .map(|store| historical_node_verifier(store, &inputs.host_snapshot))
                    .transpose()?
            } else {
                None
            };
            phases::load_with_policy_and_verifier(inputs, None, verifier.as_deref())
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    sources.verify()?;
    Ok(Loaded {
        path,
        source_sha256: sources.hash()?,
        manifest,
        plan,
        contract,
        contexts,
    })
}
pub(crate) fn run(path: &Path, now: Option<u64>, json: bool) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    let now = inspect::current_time(now)?;
    let loaded = load(path, now)?;
    let report = generate_plans(&loaded.input(&loaded.nodes(), now)).map_err(error)?;
    let code = if report.selected.is_some() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    };
    product::json_output(
        &Document {
            schema_version: 1,
            input: loaded.path,
            source_sha256: loaded.source_sha256,
            planned_at_unix_seconds: now,
            report,
            selected_proposal_hash: None,
        },
        code,
    )
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum SourceBinding {
    Escalated(crate::escalation::SourceBinding),
    Backend(crate::execution_backend::AuthorityBinding),
    Generated {
        document: PathBuf,
        document_sha256: String,
        input: PathBuf,
        source_sha256: String,
    },
}
pub(crate) struct LoadedDecision {
    pub decision: router_execution_decision::ExecutionDecision,
    pub authority: Option<router_backend_store::BackendStore>,
    pub binding: Option<SourceBinding>,
}
impl LoadedDecision {
    pub fn authority(&self) -> Option<&dyn router_execution_decision::ActivationAuthority> {
        self.authority
            .as_ref()
            .map(|value| value as &dyn router_execution_decision::ActivationAuthority)
    }
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn load_decision(
    backend: Option<&Path>,
    generated: Option<&Path>,
    escalation: Option<&crate::escalation::LoadedProposal>,
    runtime: Option<&router_runtime::Runtime>,
    node_id: &str,
    router: &PhaseRouter,
    context: &ValidatedPhaseContext,
    baseline: &PhaseReceipt,
    scope_sha256: &str,
    historical: bool,
) -> Result<LoadedDecision, CliError> {
    if let Some(proposal) = escalation {
        if backend.is_some() || generated.is_some() {
            return Err(CliError::Product("escalation.composition.denied"));
        }
        let runtime = runtime.ok_or(CliError::Product("escalation.runtime.required"))?;
        let (decision, binding) = proposal.reconstruct(runtime, router, context, baseline)?;
        return Ok(LoadedDecision {
            decision,
            authority: None,
            binding: Some(SourceBinding::Escalated(binding)),
        });
    }
    let Some(path) = generated else {
        let loaded = crate::execution_backend::load(
            backend,
            router,
            context,
            baseline,
            scope_sha256,
            historical,
        )?;
        return Ok(LoadedDecision {
            decision: loaded.decision,
            authority: loaded.authority,
            binding: loaded.binding.map(SourceBinding::Backend),
        });
    };
    if backend.is_some() {
        return Err(CliError::Product("generation.composition.denied"));
    }
    let path = resolve(
        &std::env::current_dir().map_err(|_| CliError::RequestRead)?,
        path,
    )?;
    let raw = read_bounded(
        &path,
        MAX_DOCUMENT,
        CliError::RequestRead,
        CliError::RequestTooLarge,
    )?;
    let document: Document = serde_json::from_value(
        router_adapter_api::strict_json_limited(&raw, MAX_DOCUMENT)
            .map_err(|_| CliError::RequestJsonInvalid)?,
    )
    .map_err(|_| CliError::RequestJsonInvalid)?;
    let now = inspect::current_time(None)?;
    if document.schema_version != 1 || document.planned_at_unix_seconds > now {
        return Err(CliError::Product("generation.document"));
    }
    let input = resolve(path.parent().ok_or(CliError::RequestRead)?, &document.input)?;
    let loaded = load_mode(
        &input,
        if historical {
            document.planned_at_unix_seconds
        } else {
            now
        },
        historical,
    )?;
    if loaded.source_sha256 != document.source_sha256 {
        return Err(CliError::Product("generation.source.changed"));
    }
    let nodes = loaded.nodes();
    let input = loaded.input(&nodes, document.planned_at_unix_seconds);
    let report = generate_plans(&input).map_err(error)?;
    if report != document.report {
        return Err(CliError::Product("generation.report.changed"));
    }
    let proposal = match document.selected_proposal_hash.as_deref() {
        Some(hash) => report
            .selected
            .iter()
            .chain(&report.alternatives)
            .find(|plan| plan.proposal_hash == hash),
        None => report.selected.as_ref(),
    }
    .ok_or(CliError::Product("generation.abstained"))?;
    let proof = router_policy::validate_generated_plan(&input, proposal).map_err(error)?;
    if !historical {
        proof.validate_current(now).map_err(error)?;
    }
    let decision = router_execution_decision::ExecutionDecision::generated(
        router, context, baseline, &proof, node_id,
    )
    .map_err(|_| CliError::Product("generation.context.changed"))?;
    Ok(LoadedDecision {
        decision,
        authority: None,
        binding: Some(SourceBinding::Generated {
            document: path,
            document_sha256: router_adapter_api::content_digest(&raw),
            input: loaded.path,
            source_sha256: loaded.source_sha256,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_captured_source_that_grew_is_reported_as_changed_not_too_large() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.json");
        std::fs::write(&path, b"{}").unwrap();
        let mut sources = Sources::default();
        assert!(sources.capture(&path, 1024).is_ok());
        std::fs::write(&path, b"{\"grown\":true}").unwrap();
        match sources.verify() {
            Err(CliError::Product(code)) => assert_eq!(code, "generation.source.changed"),
            _ => panic!("expected generation.source.changed"),
        }
    }
}

#[cfg(test)]
#[path = "generation_proof_tests.rs"]
mod capability_history_tests;
