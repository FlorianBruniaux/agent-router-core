//! Explicit one-cell campaign parent. Only an exact private-channel approval
//! enables dispatch. No authentication, provider HTTP or campaign ledger here.
#[path = "campaign/public_score.rs"]
mod public_score;
#[path = "campaign/recipe.rs"]
mod recipe;
#[path = "campaign/t02_v2.rs"]
mod t02_v2;
use recipe::Packet;
use router_adapter_api::{
    authorize_execution_with_capability_acceptance, content_digest,
    execution_authorization_digest_with_capability_acceptance,
};
use router_catalog::Catalog;
use router_policy::PhaseRouter;
use router_runtime::*;
use router_types::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;
const HOST: &str = "finite-campaign-linux";
const PROMPT: &str = "Read statement.md and AGENTS.md. Follow HARNESS.md if present. Complete the task in the allowed output files.";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    schema_version: u32,
    assignment_id: String,
    configuration_sha256: String,
    account_sha256: String,
    controller_sha256: String,
    observed_campaign_stop_microcredits: u64,
    deadline_ms: u64,
    observed_tokens: u64,
    root: PathBuf,
    programs: BTreeMap<String, FiniteClientFile>,
}
impl Descriptor {
    fn validate(&self) -> Result<Packet> {
        if self.schema_version != 1
            || self.deadline_ms != 60000
            || self.observed_tokens != 6000
            || self.observed_campaign_stop_microcredits != 48000000
            || [
                &self.configuration_sha256,
                &self.account_sha256,
                &self.controller_sha256,
            ]
            .iter()
            .any(|v| !router_adapter_api::is_digest(v))
        {
            return Err("descriptor contract".into());
        }
        let packet = recipe::packets()?
            .assignments
            .into_iter()
            .find(|p| p.assignment_id == self.assignment_id)
            .ok_or("unknown assignment")?;
        let expected: BTreeSet<_> = [
            "client",
            "native",
            "helper",
            "guard",
            "profile",
            "namespace",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        if self.programs.keys().cloned().collect::<BTreeSet<_>>() != expected
            || self.root != Path::new("/task/campaign").join(&self.assignment_id)
            || self.programs.iter().any(|(name, pin)| {
                Path::new(&pin.path) != Path::new("/task/programs").join(name)
                    || !router_adapter_api::is_digest(&pin.sha256)
            })
        {
            return Err("fixed paths and pins required".into());
        }
        Ok(packet)
    }
}
fn mkdir(p: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(p)?;
    Ok(())
}
fn save(p: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(p)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn git(p: &Path, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new("/usr/bin/git")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            "-C",
        ])
        .arg(p)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        return Err("private git preparation failed".into());
    }
    Ok(())
}
fn prepare_seed(p: &Packet, path: &Path, source: &str) -> Result<PreparedRun> {
    Ok(PreparedRun {
        schema_version: 1,
        receipt_id: "a".repeat(64),
        source_state: source.into(),
        scope: vec![p.output.clone()],
        authorization_digest: "b".repeat(64),
        snapshot_hash: "c".repeat(64),
        host: HarnessId::parse("codex")?,
        requested_model: ModelId::parse(&p.model)?,
        requested_effort: serde_json::from_value(json!(p.effort))?,
        program: "finite-client".into(),
        argv: vec!["--worker".into()],
        cwd: path.to_str().ok_or("path encoding")?.into(),
        stdin: PreparedInput::new(vec![]),
        mode: ExecutionMode::Execute,
        target: ExecutionTarget::ExternalWorker,
        sandbox: ExecutionSandbox::WorkspaceWrite,
        timeout_ms: 60000,
        max_output_bytes: 65536,
        degradations: vec![],
        missing_runtime_evidence: vec![],
        parent_model_changed: false,
    })
}
fn review(
    d: &Descriptor,
    p: &Packet,
    run: &PreparedRun,
    store: &Path,
    listener: TcpListener,
    workspace: FiniteClientWorkspace,
    binding: Option<&SubscriptionControllerBinding>,
) -> Result<FiniteClientReview> {
    let broker = OwnedBroker::from_isolated_listener(listener)?;
    let state = if let Some(b) = binding {
        broker.prepare_codex_subscription_tools_state(
            store,
            run,
            &b.account_sha256,
            &b.controller_sha256,
        )?
    } else {
        broker.prepare_codex_tools_state(store, run)?
    };
    let pin = |name: &str| d.programs.get(name).cloned().ok_or("missing program");
    let manifest = FiniteClientManifest {
        schema_version: 1,
        task_id: binding
            .map_or("discovery", |b| b.assignment_id.as_str())
            .into(),
        host_snapshot_id: HOST.into(),
        client: pin("client")?,
        native: pin("native")?,
        helper: pin("helper")?,
        wrapper: pin("guard")?,
        profile: pin("profile")?,
        configuration: state.configuration().clone(),
        private_state: state.path().to_str().ok_or("path encoding")?.into(),
        native_version: "0.159.2-linux-arm64-musl".into(),
        broker_endpoint: broker.endpoint().into(),
        broker_instance_sha256: broker.instance_sha256().into(),
    };
    let public = p
        .files
        .iter()
        .map(|(n, b)| (n.clone(), content_digest(b.as_bytes())))
        .collect();
    Ok(FiniteClientReview::with_codex_state(
        manifest,
        run,
        broker,
        ResourceLimits::default(),
        state,
    )?
    .with_write_workspace(workspace)?
    .with_linux_namespace(pin("namespace")?)?
    .with_mcp_tools(
        public,
        finite_tools::Limits {
            max_calls: 8,
            max_file_bytes: 32768,
            max_output_bytes: 8192,
            max_total_output_bytes: 32768,
            max_exec_ms: 5000,
            max_total_exec_ms: 15000,
            max_session_ms: 60000,
            max_scratch_entries: 64,
            max_scratch_bytes: 16777216,
        },
    )?)
}
fn phase(p: &Packet, d: &Descriptor) -> Result<PhaseRouteRequest> {
    let mut phase: PhaseRouteRequest = serde_json::from_slice(include_bytes!(
        "../../../fixtures/examples/phase-request.json"
    ))?;
    phase.phase = StageKind::Execute;
    phase.task.kind = TaskKind::Implement;
    phase.task.objective = format!("Execute sealed public task {}", p.assignment_id);
    phase.task.deliverables = vec![p.output.clone()];
    phase.task.scope = vec![p.output.clone()];
    phase.task.acceptance = vec![format!(
        "Independent frozen evaluator {}",
        p.acceptance_sha256
    )];
    phase.task.required_capabilities = [
        Capability::Network,
        Capability::WorkspaceWrite,
        Capability::Tools,
    ]
    .into();
    phase.task.allowed_mutations = [Mutation::Network, Mutation::WorkspaceWrite].into();
    phase.task.budget.max_elapsed_ms = 60000;
    phase.task.budget.max_tokens = 6000;
    phase.restrictions.sources = vec![d.configuration_sha256.clone()];
    phase.restrictions.allowed_mutations = Some(phase.task.allowed_mutations.clone());
    phase.restrictions.allowed_capabilities = Some(phase.task.required_capabilities.clone());
    phase.restrictions.max_tokens = Some(6000);
    phase.restrictions.max_concurrency = Some(1);
    phase.restrictions.policy_hash.clear();
    phase.restrictions.policy_hash = content_digest(&serde_json::to_vec(&phase.restrictions)?);
    phase.registry.version = "sealed-campaign-finite-tools-v1".into();
    phase.registry.assets.clear();
    phase.candidates.truncate(1);
    let candidate = phase.candidates.first_mut().ok_or("missing candidate")?;
    candidate.model = ModelId::parse(&p.model)?;
    candidate.effort = serde_json::from_value(json!(p.effort))?;
    candidate.id = p.assignment_id.clone();
    candidate.estimated_cost_microusd = 0;
    candidate.estimated_tokens = 6000;
    candidate.estimated_elapsed_ms = 59000;
    candidate.tools = [
        "mcp__finite__read_file",
        "mcp__finite__write_file",
        "mcp__finite__exec",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    candidate.sandbox = PhaseSandbox::WorkspaceWrite;
    for id in &candidate.tools {
        phase.registry.assets.push(PhaseRegisteredAsset {
            kind: PhaseAssetKind::Tool,
            id: id.clone(),
            content_sha256: content_digest(include_bytes!("../src/finite_tools/transport.rs")),
            trust: SkillTrust::TrustedLocal,
            license: "FSL-1.1-ALv2".into(),
            permission: CapabilitySupport::Supported,
            required_capabilities: [Capability::Tools].into(),
            required_mutations: BTreeSet::new(),
            allowed_sandboxes: [PhaseSandbox::WorkspaceWrite].into(),
            maximum_sensitivity: DataSensitivity::Public,
        });
    }
    Ok(phase)
}
// The frozen experiment assigns one profile; utility ranking is inapplicable.
// Eligibility, permissions, capability evidence and resource bounds still apply.
fn assigned_router() -> Result<PhaseRouter> {
    Ok(PhaseRouter::new(PhasePolicy {
        version: "sealed-assignment-v1".into(),
        quality_weight: 0,
        relevance_weight: 0,
        cost_weight: 0,
        latency_weight: 0,
        max_alternatives: 0,
        ..PhasePolicy::default()
    })?)
}
// This parent dispatches only the experiment's execution cell. The independent
// evaluator is outside this worker plan; completion remains Verifying.
fn execution_plan(task: &NormalizedTask) -> Result<WorkflowPlan> {
    let mut plan = router_workflow::build_plan(
        task,
        WorkflowPreset::DirectSafe,
        router_workflow::PlanLimits::default(),
    )?;
    plan.nodes.retain(|node| node.id == "execute");
    if plan.nodes.len() != 1 {
        return Err("one execution node required".into());
    }
    plan.nodes[0].budget = task.budget.clone();
    plan.nodes[0].purpose =
        "Produce one bounded private submission for independent external evaluation".into();
    plan.plan_id.clear();
    plan.plan_id = content_digest(&serde_json::to_vec(&plan)?);
    router_workflow::validate_plan(&plan)?;
    Ok(plan)
}
fn emit(v: &Value) -> Result<()> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{}", serde_json::to_string(v)?)?;
    out.flush()?;
    Ok(())
}
fn read_line_bound<R: BufRead>(r: &mut R, max: u64) -> std::io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let n = Read::by_ref(r).take(max + 1).read_until(b'\n', &mut line)?;
    if n == 0 {
        return Ok(vec![]);
    }
    if n as u64 > max || line.last() != Some(&b'\n') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame bound",
        ));
    }
    Ok(line)
}
fn read_parent_line() -> Result<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    // Read exactly one line without prefetching later controller frames.
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        let mut bytes = Vec::new();
        let result = (|| -> std::io::Result<Vec<u8>> {
            loop {
                let mut b = [0];
                input.read_exact(&mut b)?;
                bytes.push(b[0]);
                if bytes.len() > 16384 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "approval bound",
                    ));
                }
                if b[0] == b'\n' {
                    return Ok(bytes);
                }
            }
        })();
        let _ = tx.send(result);
    });
    Ok(rx.recv_timeout(Duration::from_secs(60))??)
}
fn check_approval(v: &Value, binding: &Value, packet_sha256: &str) -> Result<()> {
    if *v
        != json!({"schema_version":1,"kind":"approve_runtime","binding":binding,"packet_sha256":packet_sha256})
    {
        return Err("approval mismatch".into());
    }
    Ok(())
}
fn approve(binding: &Value, p: &Packet) -> Result<()> {
    let raw = read_parent_line()?;
    let v = router_adapter_api::strict_json_limited(&raw, 16384)?;
    check_approval(&v, binding, &p.packet_sha256)
}
fn relay(
    peer: SubscriptionControllerPeer,
) -> Result<std::sync::mpsc::Receiver<std::io::Result<()>>> {
    let stream = peer.into_transport();
    let mut writer = stream.try_clone()?;
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = (|| -> std::io::Result<()> {
            let mut reader = BufReader::new(stream);
            loop {
                let line = read_line_bound(&mut reader, 300000)?;
                if line.is_empty() {
                    return Ok(());
                }
                let mut out = std::io::stdout().lock();
                out.write_all(&line)?;
                out.flush()?;
            }
        })();
        let _ = tx.send(result);
    });
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        while let Ok(line) = read_line_bound(&mut input, 300000) {
            if line.is_empty() || writer.write_all(&line).is_err() {
                break;
            }
        }
        let _ = writer.shutdown(std::net::Shutdown::Both);
    });
    Ok(rx)
}
fn export_output(
    runtime: &Runtime,
    packet: &Packet,
    view: &Path,
    root: &Path,
    completion: &RunCompletion,
) -> Result<Option<Value>> {
    if completion.run.state != RunState::Verifying {
        return Ok(None);
    }
    if runtime.cleanup_evidence(&packet.assignment_id)?
        != ProcessCleanupEvidence::NamespaceTerminated
    {
        return Err("output cleanup not proven".into());
    }
    let events = runtime.events()?;
    let stopped: Vec<_> = events
        .iter()
        .filter(|e| e.run_id == packet.assignment_id && e.kind == "finite_tools.stopped.v1")
        .collect();
    if stopped.len() != 1 {
        return Err("unique stopped tool evidence required".into());
    }
    let terminal: Option<finite_tools::ToolTerminal> = serde_json::from_str(&stopped[0].detail)?;
    let terminal = terminal.ok_or("missing terminal")?;
    if !terminal.complete || terminal.halted {
        return Err("incomplete terminal".into());
    }
    let output = terminal.output.ok_or("missing output")?;
    if output.relative != packet.output || output.bytes > 32768 {
        return Err("output scope".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(view.join(&packet.output))?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.mode() & 0o7022 != 0
        || before.len() != output.bytes
    {
        return Err("output identity".into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(32769)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if (before.dev(), before.ino(), before.mode(), before.len())
        != (after.dev(), after.ino(), after.mode(), after.len())
        || bytes.len() as u64 != output.bytes
        || content_digest(&bytes) != output.sha256
    {
        return Err("output changed".into());
    }
    let directory = root.join("submission");
    mkdir(&directory)?;
    save(&directory.join(&packet.output), &bytes)?;
    Ok(Some(
        json!({"relative":packet.output,"bytes":bytes.len(),"sha256":output.sha256}),
    ))
}
#[derive(Clone, Copy, PartialEq)]
enum ScoreEvaluation {
    None,
    PublicV1,
    QualificationV2,
}

async fn run(d: Descriptor, p: Packet, evaluation: ScoreEvaluation) -> Result<()> {
    if evaluation != ScoreEvaluation::None {
        public_score::check_scope(&p.assignment_id)?;
    }
    if std::env::consts::OS != "linux"
        || std::env::consts::ARCH != "aarch64"
        || fs::read_to_string("/sys/fs/cgroup/memory.max")?.trim() != "8589934592"
        || fs::read_to_string("/sys/fs/cgroup/memory.swap.max")?.trim() != "0"
    {
        return Err("qualified Linux 8 GiB required".into());
    }
    if fs::canonicalize("/task/campaign")? != Path::new("/task/campaign")
        || fs::canonicalize("/task/programs")? != Path::new("/task/programs")
    {
        return Err("fixed roots".into());
    }
    mkdir(&d.root)?;
    let source = d.root.join("candidate");
    mkdir(&source)?;
    for (name, bytes) in &p.files {
        save(&source.join(name), bytes.as_bytes())?;
    }
    git(&source, &["init", "-q"])?;
    git(&source, &["add", "--all"])?;
    git(
        &source,
        &[
            "-c",
            "user.name=Campaign parent",
            "-c",
            "user.email=campaign@example.invalid",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "sealed public task",
        ],
    )?;
    let source_hash = source_state(&source).await?;
    let phase = phase(&p, &d)?;
    let plan = execution_plan(&phase.task)?;
    let store = d.root.join("runtime");
    mkdir(&store)?;
    let registry = d.root.join("admission");
    let policy = AdmissionPolicy {
        schema_version: 1,
        global_limit: 1,
        runtimes: BTreeMap::from([(
            "campaign".into(),
            AdmissionRuntimePolicy {
                root_sha256: admission_runtime_root_hash(&store)?,
                limit: 1,
            },
        )]),
        providers: BTreeMap::from([("codex_subscription_relay".into(), 1)]),
        agents: BTreeMap::from([("worker".into(), 1)]),
        agent_mappings: vec![AdmissionAgentMapping {
            runtime_id: "campaign".into(),
            plan_owner: plan
                .nodes
                .iter()
                .find(|n| n.id == "execute")
                .ok_or("execute node")?
                .owner
                .clone(),
            candidate_agent: None,
            quota_id: "worker".into(),
        }],
    };
    let admission = AdmissionStore::create(&registry, &policy)?;
    let config = AdmissionConfig {
        schema_version: 1,
        registry,
        expected_policy_sha256: admission.policy_hash().into(),
        runtime_id: "campaign".into(),
        session_budget: None,
    };
    let runtime = Runtime::open_with_admission(
        &store,
        RuntimeLimits {
            output_retention: OutputRetentionPolicy::PrivateArtifacts {
                retention_seconds: 3600,
            },
            ..Default::default()
        },
        &config,
    )?;
    let listener = TcpListener::bind(("0.0.0.0", 0))?;
    rustix::net::sockopt::set_socket_reuseaddr(&listener, false)?;
    rustix::net::sockopt::set_socket_reuseport(&listener, false)?;
    let mode = if p.create_new {
        FiniteOutputMode::CreateNew
    } else {
        FiniteOutputMode::ReplaceExisting
    };
    let diagnostic = runtime
        .prepare_finite_output_workspace(&source, "discovery", &p.output, mode)
        .await?;
    let seed = prepare_seed(&p, diagnostic.path(), &source_hash)?;
    let discovery_review = review(
        &d,
        &p,
        &seed,
        &store,
        listener.try_clone()?,
        diagnostic,
        None,
    )?;
    let digest = discovery_review.approval_digest().to_owned();
    let diagnostic_root = d.root.join("discovery");
    mkdir(&diagnostic_root)?;
    let (snapshot, verifier) = discovery_review
        .approve(&digest)?
        .discover_linux_tools(&diagnostic_root)
        .await?;
    let runtime = runtime.with_capability_proof_verifier(Arc::new(verifier));
    let view = runtime
        .prepare_finite_output_workspace(&source, &p.assignment_id, &p.output, mode)
        .await?;
    eprintln!("campaign_stage: catalog");
    let catalog = Catalog::from_json(&serde_json::to_vec(
        &json!({"schema_version":1,"version":"operator-selected-subscription-v1","models":[{"id":p.model,"stages":["execute"],"efforts":[p.effort],"capabilities":phase.task.required_capabilities,"quality_micros":1,"cost_micros":0,"latency_micros":1,"source":"Explicit experimental assignment; not a price or availability measurement"}],"skills":[]}),
    )?)?;
    let router = assigned_router()?;
    eprintln!("campaign_stage: route");
    let context = router.context(phase, &snapshot, &catalog)?;
    let receipt = router.route(&context)?;
    let selected = receipt.selected.as_ref().ok_or("assignment not routed")?;
    let request = ExecutionRequest {
        schema_version: 1,
        receipt_id: receipt.receipt_id.clone(),
        candidate_id: selected.candidate.id.clone(),
        phase: receipt.phase,
        host: snapshot.host().harness.clone(),
        model: selected.candidate.model.clone(),
        effort: selected.candidate.effort,
        workspace: view.path().to_str().ok_or("path encoding")?.into(),
        source_state: source_hash.clone(),
        scope: vec![p.output.clone()],
        sandbox: ExecutionSandbox::WorkspaceWrite,
        required_capabilities: router.execution_capabilities(&context, selected)?,
        tools: ToolSelection::AllowList(vec![
            "mcp__finite__read_file".into(),
            "mcp__finite__write_file".into(),
            "mcp__finite__exec".into(),
        ]),
        agent: None,
        skills: vec![],
        prompt: PROMPT.into(),
        mode: ExecutionMode::Execute,
        target: ExecutionTarget::ExternalWorker,
        allow_degradation: false,
        timeout_ms: 60000,
        max_output_bytes: 65536,
    };
    eprintln!("campaign_stage: authorization");
    let auth = execution_authorization_digest_with_capability_acceptance(
        &request,
        &snapshot,
        &context.request().restrictions,
        context.capability_acceptance(),
    )?;
    let authorized = authorize_execution_with_capability_acceptance(
        request.clone(),
        &snapshot,
        &context.request().restrictions,
        context.capability_acceptance(),
        Some(&auth),
    )?;
    let mut prepared = router_adapter_api::prepared_run(
        &authorized,
        "finite-client",
        vec!["--worker".into()],
        vec![],
    )?;
    prepared.missing_runtime_evidence.clear();
    eprintln!("campaign_stage: controller");
    let (controller, peer) = OwnedSubscriptionController::pair(
        &p.assignment_id,
        &d.configuration_sha256,
        &d.account_sha256,
        &d.controller_sha256,
    )?;
    let mut binding = serde_json::to_value(controller.binding())?;
    let output_view = view.path().to_owned();
    let client = review(
        &d,
        &p,
        &prepared,
        &store,
        listener,
        view,
        Some(controller.binding()),
    )?
    .with_subscription_controller(controller)?;
    eprintln!("campaign_stage: runtime_review");
    let pending = runtime
        .review_finite_client(
            &p.assignment_id,
            &router,
            &context,
            request,
            plan,
            "execute",
            client,
        )
        .await?;
    let digest = pending.approval_digest().to_owned();
    binding["run_id"] = p.assignment_id.clone().into();
    binding["attempt"] = 1.into();
    binding["approval_digest"] = digest.clone().into();
    emit(
        &json!({"schema_version":1,"kind":"runtime_prepare","assignment_id":p.assignment_id,"model":p.model,"effort":p.effort,"condition":p.condition,"packet_sha256":p.packet_sha256,"acceptance_sha256":p.acceptance_sha256,"configuration_sha256":d.configuration_sha256,"account_sha256":d.account_sha256,"controller_sha256":d.controller_sha256,"deadline_ms":60000,"observed_tokens":6000,"observed_campaign_stop_microcredits":48000000}),
    )?;
    emit(&json!({"schema_version":1,"kind":"runtime_binding","binding":binding}))?;
    approve(&binding, &p)?;
    let approved = runtime.approve_finite_client(pending, &digest)?;
    let verifier = if evaluation != ScoreEvaluation::None {
        Some(runtime.finite_client_verifier(&approved)?)
    } else {
        None
    };
    let relay_finished = relay(peer)?;
    let result = runtime
        .execute_finite_client(
            approved,
            &adapter_codex::CodexAdapter,
            Cancellation::default(),
        )
        .await;
    let source_unchanged = source_state(&source).await? == source_hash;
    let exported = if source_unchanged {
        match result.as_ref() {
            Ok(completion) => export_output(&runtime, &p, &output_view, &d.root, completion),
            Err(_) => Ok(None),
        }
    } else {
        Err("source changed".into())
    };
    let export_failed = exported.is_err();
    let report = json!({"schema_version":1,"assignment_id":p.assignment_id,"packet_sha256":p.packet_sha256,"binding":binding,"result":result.as_ref().ok(),"runtime_failed":result.is_err(),"summary":runtime.summary(&p.assignment_id).ok(),"cleanup":runtime.cleanup_evidence(&p.assignment_id).ok(),"admission":admission.status().ok(),"events":observe_events(&store,&p.assignment_id).ok(),"attempts":runtime.attempt_evidence(&p.assignment_id).ok(),"source_unchanged":source_unchanged,"export_failed":export_failed,"submission":exported.as_ref().ok().and_then(|v|v.as_ref()),"human_acceptance":null});
    save(
        &d.root.join("runtime-result.json"),
        &serde_json::to_vec(&report)?,
    )?;
    relay_finished.recv_timeout(Duration::from_secs(10))??;
    eprintln!(
        "{}",
        serde_json::to_string(
            &json!({"kind":"campaign_terminal","assignment_id":p.assignment_id,"runtime_result_sha256":content_digest(&serde_json::to_vec(&report)?),"runtime_failed":result.is_err()})
        )?
    );
    result?;
    exported?;
    if let Some(verifier) = verifier {
        let report_bytes = serde_json::to_vec(&report)?;
        let evaluation = match evaluation {
            ScoreEvaluation::PublicV1 => public_score::evaluate(&d.root, &report_bytes, &verifier)?,
            ScoreEvaluation::QualificationV2 => {
                t02_v2::evaluate(&d.root, &report_bytes, &verifier)?
            }
            ScoreEvaluation::None => return Err("missing evaluation mode".into()),
        };
        save(
            &d.root.join("evaluation-result.json"),
            &serde_json::to_vec(&evaluation)?,
        )?;
    }
    Ok(())
}
#[tokio::main]
async fn main() {
    let result = async {
        let args: Vec<_> = std::env::args_os().collect();
        if args.len() == 2 && args[1] == "--inspect" {
            println!(
                "{}",
                serde_json::to_string(&recipe::packets()?.assignments)?
            );
            return Ok(());
        }
        if args.len() != 2
            || (args[1] != "--run"
                && args[1] != "--run-public-score"
                && args[1] != "--run-score-v2")
        {
            return Err::<(), Error>("usage".into());
        }
        let bytes = read_parent_line()?;
        let value = router_adapter_api::strict_json_limited(&bytes, 16384)?;
        let descriptor: Descriptor = serde_json::from_value(value)?;
        let packet = descriptor.validate()?;
        let evaluation = if args[1] == "--run-score-v2" {
            ScoreEvaluation::QualificationV2
        } else if args[1] == "--run-public-score" {
            ScoreEvaluation::PublicV1
        } else {
            ScoreEvaluation::None
        };
        run(descriptor, packet, evaluation).await
    }
    .await;
    if let Err(error) = result {
        if let Some(runtime) = error.downcast_ref::<RuntimeError>() {
            let code = match runtime {
                RuntimeError::Integrity(code) | RuntimeError::Invalid(code) => *code,
                RuntimeError::Sandbox => "sandbox",
                RuntimeError::CleanupUnknown => "cleanup_unknown",
                RuntimeError::Route => "route",
                RuntimeError::Scope => "scope",
                RuntimeError::SourceChanged => "source_changed",
                RuntimeError::Approval => "approval",
                _ => "runtime_refused",
            };
            eprintln!("campaign_failed: {code}");
        } else if let Some(error) = error.downcast_ref::<router_policy::PhaseRouteError>() {
            match error {
                router_policy::PhaseRouteError::Invalid(code)
                | router_policy::PhaseRouteError::Limit(code) => {
                    eprintln!("campaign_failed: phase {code}")
                }
                _ => eprintln!("campaign_failed: phase_refused"),
            }
        } else if error
            .downcast_ref::<router_adapter_api::AdapterError>()
            .is_some()
        {
            eprintln!("campaign_failed: authorization_refused");
        } else if error
            .downcast_ref::<router_catalog::CatalogError>()
            .is_some()
        {
            eprintln!("campaign_failed: catalog_refused");
        } else {
            eprintln!("campaign_failed; inspect retained private runtime evidence");
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
#[path = "../../../tests/support/capability_verifier.rs"]
mod fixture_proofs;
#[cfg(test)]
mod tests {
    use super::*;
    fn descriptor() -> Descriptor {
        Descriptor {
            schema_version: 1,
            assignment_id: "t02-Lx-r1-H0".into(),
            configuration_sha256: "a".repeat(64),
            account_sha256: "b".repeat(64),
            controller_sha256: "c".repeat(64),
            observed_campaign_stop_microcredits: 48000000,
            deadline_ms: 60000,
            observed_tokens: 6000,
            root: "/task/campaign/t02-Lx-r1-H0".into(),
            programs: [
                "client",
                "native",
                "helper",
                "guard",
                "profile",
                "namespace",
            ]
            .into_iter()
            .map(|n| {
                (
                    n.into(),
                    FiniteClientFile {
                        path: format!("/task/programs/{n}"),
                        sha256: "d".repeat(64),
                    },
                )
            })
            .collect(),
        }
    }
    #[test]
    fn all_cells_validate_with_exact_identity_and_same_limits() {
        for packet in recipe::packets().unwrap().assignments {
            let mut d = descriptor();
            d.assignment_id = packet.assignment_id.clone();
            d.root = Path::new("/task/campaign").join(&d.assignment_id);
            assert_eq!(d.validate().unwrap().packet_sha256, packet.packet_sha256);
        }
    }
    #[test]
    fn descriptor_rejects_aliases_private_paths_or_changed_limits() {
        let mut d = descriptor();
        d.assignment_id = "t02-luna-r1-H0".into();
        assert!(d.validate().is_err());
        let mut d = descriptor();
        d.root = "/home/private".into();
        assert!(d.validate().is_err());
        let mut d = descriptor();
        d.programs.get_mut("native").unwrap().path = "/home/auth.json".into();
        assert!(d.validate().is_err());
        let mut d = descriptor();
        d.deadline_ms = 60001;
        assert!(d.validate().is_err());
        let mut d = descriptor();
        d.observed_tokens = 8192;
        assert!(d.validate().is_err());
        let mut d = descriptor();
        d.observed_campaign_stop_microcredits = 48000001;
        assert!(d.validate().is_err());
        let mut d = descriptor();
        d.account_sha256.clear();
        assert!(d.validate().is_err());
        let mut v = serde_json::to_value(descriptor()).unwrap();
        v["auth_path"] = "/home/auth.json".into();
        assert!(serde_json::from_value::<Descriptor>(v).is_err());
    }
    #[test]
    fn approval_binds_complete_owner_and_packet_not_just_digest() {
        let binding = json!({"assignment_id":"t02-Lx-r1-H0","approval_digest":"a".repeat(64),"nonce":"b".repeat(64)});
        let packet = "c".repeat(64);
        let ack = json!({"schema_version":1,"kind":"approve_runtime","binding":binding,"packet_sha256":packet});
        assert!(check_approval(&ack, &binding, &packet).is_ok());
        let mut changed = ack.clone();
        changed["binding"]["nonce"] = "d".repeat(64).into();
        assert!(check_approval(&changed, &binding, &packet).is_err());
        let mut changed = ack.clone();
        changed["packet_sha256"] = "e".repeat(64).into();
        assert!(check_approval(&changed, &binding, &packet).is_err());
        let changed =
            json!({"schema_version":1,"kind":"runtime_approved","approval_digest":"a".repeat(64)});
        assert!(check_approval(&changed, &binding, &packet).is_err());
    }
    #[test]
    fn fixed_assignment_keeps_eligibility_without_inventing_quality() {
        use router_adapter_api::{
            CapabilityEvidence, EvidenceKind, EvidenceSource, HostObservation, SnapshotValidation,
        };
        for packet in recipe::packets().unwrap().assignments {
            let d = descriptor();
            let phase = phase(&packet, &d).unwrap();
            let plan = execution_plan(&phase.task).unwrap();
            assert_eq!(plan.nodes.len(), 1);
            assert_eq!(plan.nodes[0].budget.max_elapsed_ms, 60000);
            assert_eq!(plan.nodes[0].budget.max_tokens, 6000);
            assert_eq!(plan.nodes[0].verification, phase.task.acceptance);
            assert!(plan.requires_explicit_integration);
            router_workflow::validate_plan(&plan).unwrap();
            let caps = phase.task.required_capabilities.clone();
            let model = ModelId::parse(&packet.model).unwrap();
            let effort = serde_json::from_value(json!(packet.effort)).unwrap();
            let observed = HostObservation {
                schema_version: 1,
                attestations: None,
                host: HostSnapshot {
                    id: "fixture-host".into(),
                    harness: HarnessId::parse("codex").unwrap(),
                    supported_models: [model.clone()].into(),
                    supported_efforts: BTreeMap::from([(model, [effort].into())]),
                    capabilities: caps.clone(),
                },
                capabilities: caps
                    .iter()
                    .map(|c| {
                        (
                            *c,
                            CapabilityEvidence {
                                support: CapabilitySupport::Supported,
                                source_ids: ["synthetic-runtime".into()].into(),
                            },
                        )
                    })
                    .collect(),
                evidence: vec![EvidenceSource {
                    id: "synthetic-runtime".into(),
                    kind: EvidenceKind::HostRuntime,
                    observed_version: Some("fixture-v1".into()),
                    observed_at_unix_seconds: 100,
                    content_sha256: "a".repeat(64),
                }],
                observed_at_unix_seconds: 100,
                snapshot_hash: String::new(),
            }
            .seal()
            .unwrap();
            let snapshot = fixture_proofs::from_observation(
                observed,
                SnapshotValidation {
                    now_unix_seconds: 100,
                    max_age_seconds: 10,
                },
            )
            .unwrap();
            let catalog=Catalog::from_json(&serde_json::to_vec(&json!({"schema_version":1,"version":"fixture","models":[{"id":packet.model,"stages":["execute"],"efforts":[packet.effort],"capabilities":caps,"quality_micros":1,"cost_micros":0,"latency_micros":1,"source":"synthetic unit fixture"}],"skills":[]})).unwrap()).unwrap();
            let ranked = PhaseRouter::stable_v2();
            assert!(
                ranked
                    .route(&ranked.context(phase.clone(), &snapshot, &catalog).unwrap())
                    .unwrap()
                    .selected
                    .is_none()
            );
            let assigned = assigned_router().unwrap();
            let receipt = assigned
                .route(
                    &assigned
                        .context(phase.clone(), &snapshot, &catalog)
                        .unwrap(),
                )
                .unwrap();
            assert_eq!(receipt.selected.unwrap().candidate.id, packet.assignment_id);
            for failure in 0..3 {
                let mut denied = phase.clone();
                match failure {
                    0 => denied.candidates[0].estimated_tokens = 6001,
                    1 => {
                        denied
                            .permissions
                            .insert(PhasePermission::Network, CapabilitySupport::Unsupported);
                    }
                    _ => denied.restrictions.allowed_capabilities = Some(BTreeSet::new()),
                }
                denied.restrictions.policy_hash.clear();
                denied.restrictions.policy_hash =
                    content_digest(&serde_json::to_vec(&denied.restrictions).unwrap());
                assert!(
                    assigned
                        .route(&assigned.context(denied, &snapshot, &catalog).unwrap())
                        .unwrap()
                        .selected
                        .is_none()
                );
            }
        }
    }
}
