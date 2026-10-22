//! Retained Linux composition. Preparation is not OS qualification or dispatch.
use super::*;

pub(super) struct FiniteClientNamespace {
    pub(super) copy: PrivateProgram,
    pub(super) pin: FiniteClientFile,
    identity: PinnedIdentity,
}
impl FiniteClientNamespace {
    pub(super) fn check(&self) -> Result<()> {
        self.copy.verify(&self.pin.sha256)?;
        if file_identity(&self.pin, true)?.identity != self.identity.identity {
            return Err(RuntimeError::Integrity("finite client namespace identity"));
        }
        Ok(())
    }
}
impl FiniteClientReview {
    /// Retains the namespace executable and binds it into a new review. This
    /// cannot qualify Linux, enable broker networking or construct a Command.
    /// Existing reviews/proofs remain unchanged; Linux composition needs v5.
    pub fn with_linux_namespace(mut self, source: FiniteClientFile) -> Result<Self> {
        if self.owned_namespace.is_some() || self.owned_assets.is_none() {
            return Err(RuntimeError::Sandbox);
        }
        self.check_files()?;
        let state = self.owned_state.as_ref().ok_or(RuntimeError::Sandbox)?;
        file_identity(&source, true)?;
        if Path::new(&source.path).starts_with(&self.run.cwd) {
            return Err(RuntimeError::Scope);
        }
        let copy = PrivateProgram::copy(Path::new(&source.path), &source.sha256, state.path())?;
        if copy.directory().starts_with(&self.run.cwd)
            || Path::new(&self.run.cwd).starts_with(copy.directory())
        {
            return Err(RuntimeError::Scope);
        }
        let pin = FiniteClientFile {
            path: copy
                .verify(&source.sha256)?
                .to_str()
                .ok_or(RuntimeError::Invalid("namespace path"))?
                .into(),
            sha256: source.sha256,
        };
        let identity = file_identity(&pin, true)?;
        self.approval = crate::digest(
            "finite-client-linux-review-v1",
            &(
                &self.approval,
                &pin,
                &identity.identity,
                if self
                    .owned_state
                    .as_ref()
                    .is_some_and(|state| state.startup.tools)
                {
                    "linux-isolated-finite-tools-v3"
                } else {
                    "linux-isolated-broker-v2"
                },
            ),
        )?;
        self.owned_namespace = Some(FiniteClientNamespace {
            copy,
            pin,
            identity,
        });
        self.check_files()?;
        Ok(self)
    }
}

pub const LINUX_FINITE_PROFILE_V2: &[u8] =
    b"{\"kind\":\"linux-isolated-broker-v2\",\"schema_version\":1}\n";
const NATIVE_LINUX_ARM64: &str = "113aa5d5952a6fd3950a88323219747d0c91978ebee948509a540c8a460e59a3";

struct ToolsProbeView {
    staging: PathBuf,
    bootstrap: PathBuf,
    terminal: PathBuf,
    terminal_file: File,
    terminal_identity: FileIdentity,
    policy: crate::finite_tools::FilePolicy,
    binding: String,
}
#[path = "tools_probe_view.rs"]
mod tools_probe_view;

struct ProbeView {
    tools: Option<ToolsProbeView>,
    temporary: std::path::PathBuf,
    control: std::path::PathBuf,
    hidden: std::path::PathBuf,
    denied_port: u16,
    nonce: String,
}

fn composition_command(
    state: &HostState,
    probe: Option<&ProbeView>,
) -> Result<tokio::process::Command> {
    if !cfg!(target_os = "linux") || std::env::consts::ARCH != "aarch64" {
        return Err(RuntimeError::Sandbox);
    }
    state.check_owned_resources()?;
    let resources = state.finite_resources()?;
    let r = &resources.reviewed;
    let namespace = r.owned_namespace.as_ref().ok_or(RuntimeError::Sandbox)?;
    let assets = r.owned_assets.as_ref().ok_or(RuntimeError::Sandbox)?;
    let pins = &assets.pins;
    let tools = r.owned_tools.as_ref();
    if resources.startup.tools != tools.is_some()
        || r.resource_arguments != ResourceLimits::default().args()?
        || r.manifest.native.sha256 != NATIVE_LINUX_ARM64
        || r.manifest.native_version != "0.159.2-linux-arm64-musl"
        || r.run.argv != ["--worker"]
        || fs::read(&pins[4].path)?
            != if tools.is_some() {
                super::tools_state::LINUX_FINITE_TOOLS_PROFILE_V3
            } else {
                LINUX_FINITE_PROFILE_V2
            }
    {
        return Err(RuntimeError::Sandbox);
    }
    r.broker
        .isolation
        .as_ref()
        .ok_or(RuntimeError::Sandbox)?
        .check()?;
    super::isolated_network::check_listener(&r.broker.listener)?;
    let home = Path::new(&r.manifest.private_state);
    let tmp = home.join("tmp");
    let backing = probe.map_or(tmp.as_path(), |p| p.temporary.as_path());
    let mut writes = vec![];
    if tools.is_none() && r.run.sandbox == router_types::ExecutionSandbox::WorkspaceWrite {
        let workspace = r.owned_workspace.as_ref().ok_or(RuntimeError::Sandbox)?;
        // The delivered backend still implements existing-file replacement.
        // Preparing an absent output cannot silently opt into another profile.
        workspace.existing_preimage()?;
        workspace.check_identity()?;
        crate::workspace::safe_scope(Path::new(&r.run.cwd), &r.run.scope)?;
        for scope in &r.run.scope {
            let path = Path::new(&r.run.cwd).join(scope);
            if fs::canonicalize(&path)? != path {
                return Err(RuntimeError::Scope);
            }
            writes.push(path);
        }
    }
    let mut command = tokio::process::Command::new(&pins[2].path);
    command
        .args(&r.resource_arguments)
        .arg("--supervise-v1")
        .arg(namespace.copy.verify(&namespace.pin.sha256)?);
    command.args([
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--share-net",
        "--cap-drop",
        "ALL",
        "--tmpfs",
        "/",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
    ]);
    if tools.is_some() {
        command.args(["--size", "134217728", "--tmpfs", "/tmp"]);
    }
    let mut reads: Vec<_> = assets
        .copies
        .iter()
        .map(|p| p.directory().to_owned())
        .collect();
    reads.push(namespace.copy.directory().to_owned());
    for directory in &reads {
        command.arg("--ro-bind").arg(directory).arg(directory);
    }
    command
        .arg("--ro-bind")
        .arg(home)
        .arg(home)
        .arg("--bind")
        .arg(backing)
        .arg(&tmp)
        // The producer already places mutable native startup state in tmp.
        // Preserve that existing grant: Codex opens its valid installation ID
        // read/write even when it only reads it. The parent/config stay RO.
        .arg(if tools.is_some() {
            "--bind"
        } else {
            "--ro-bind"
        })
        .arg(match (tools, probe) {
            (Some(_), Some(p)) => p
                .tools
                .as_ref()
                .ok_or(RuntimeError::Sandbox)?
                .staging
                .as_path(),
            (Some(tools), None) => tools.staging.as_path(),
            (None, _) => Path::new(&r.run.cwd),
        })
        .arg(&r.run.cwd);
    if let Some(tools) = tools {
        let stage = match probe {
            Some(p) => p
                .tools
                .as_ref()
                .ok_or(RuntimeError::Sandbox)?
                .staging
                .as_path(),
            None => tools.staging.as_path(),
        };
        // Only a NEW explicit public projection is mounted writable. The
        // private Git view stays outside the worker's writable mounts.
        for name in tools
            .boot
            .sandbox
            .public
            .keys()
            .filter(|name| *name != &tools.boot.sandbox.output)
        {
            command
                .arg("--ro-bind")
                .arg(stage.join(name))
                .arg(Path::new(&r.run.cwd).join(name));
        }
        let (bootstrap, terminal) = if let Some(probe) = probe {
            let view = probe.tools.as_ref().ok_or(RuntimeError::Sandbox)?;
            (view.bootstrap.as_path(), view.terminal.as_path())
        } else {
            (
                Path::new(&tools.bootstrap.path),
                tools.terminal_path.as_path(),
            )
        };
        command
            .args([
                "--size",
                "1048576",
                "--tmpfs",
                "/router-tools",
                "--chmod",
                "700",
                "/router-tools",
                "--size",
                "16777216",
                "--tmpfs",
                "/router-tools/scratch",
                "--chmod",
                "700",
                "/router-tools/scratch",
            ])
            .arg("--ro-bind")
            .arg(bootstrap)
            .arg("/router-tools/boot.json")
            .arg("--bind")
            .arg(terminal)
            .arg("/router-tools/terminal.json")
            .arg("--ro-bind")
            .arg(&pins[0].path)
            .arg("/finite-client");
    }
    for path in &writes {
        command.arg("--bind");
        if let Some(probe) = probe {
            command.arg(probe.temporary.join("scoped-file"));
        } else {
            command.arg(path);
        }
        command.arg(path);
    }
    command
        .args(["--remount-ro", "/", "--chdir"])
        .arg(&r.run.cwd)
        .arg("--");
    if tools.is_some() {
        command
            .arg(&pins[0].path)
            .arg("--tools-owner")
            .current_dir(&r.run.cwd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("ROUTER_RUNTIME_SUPERVISION", "framed-v1")
            .env("ROUTER_RUNTIME_CONTAINMENT", "pid-namespace-v1");
        return Ok(command);
    }
    command
        .arg(&pins[3].path)
        .arg("--restrict-v1")
        .arg(r.broker.listener.local_addr()?.port().to_string())
        .arg(home)
        .arg(&r.run.cwd)
        .arg(writes.len().to_string())
        .args(&writes)
        .arg(reads.len().to_string())
        .args(&reads);
    if let Some(probe) = probe {
        command
            .arg("--probe-v1")
            .arg(probe.denied_port.to_string())
            .arg(&probe.hidden)
            .arg(
                home.join("tmp")
                    .join(probe.control.file_name().ok_or(RuntimeError::Sandbox)?),
            )
            .arg(&probe.nonce);
    }
    command
        .arg("--")
        .arg(&pins[0].path)
        .arg(if probe.is_some() {
            "--version-probe"
        } else {
            "--worker"
        });
    let context = serde_json::json!({
        "native":pins[1].path,"native_sha256":pins[1].sha256,"native_version":r.manifest.native_version,
        "home":home,"cwd":r.run.cwd,"configuration_sha256":pins[5].sha256,
        "model":r.run.requested_model,"effort":r.run.requested_effort,"stdin_sha256":content_digest(r.run.stdin.as_bytes()),
        "max_output_bytes":r.run.max_output_bytes.min(65536),
        "replacement": if probe.is_none() {r.owned_workspace.as_ref().map(|view| {let v=view.dispatch();serde_json::json!({"relative":v.relative,"preimage":v.preimage})})} else {None}
    });
    let home = home.to_str().ok_or(RuntimeError::Sandbox)?;
    command
        .current_dir(&r.run.cwd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("CODEX_HOME", home)
        .env("TMPDIR", format!("{home}/tmp"))
        .env("CODEX_SQLITE_HOME", format!("{home}/tmp"))
        .env("ROUTER_FINITE_CONTEXT", serde_json::to_string(&context)?)
        .env("ROUTER_RUNTIME_SUPERVISION", "framed-v1")
        .env("ROUTER_RUNTIME_CONTAINMENT", "pid-namespace-v1");
    Ok(command)
}

use crate::{Cancellation, NetworkAuthority, Runtime, SandboxPolicy, SandboxSupervisor};
use router_adapter_api::{
    CapabilityAttemptOutcome, CapabilityNetworkScope, CapabilityProofKey, CapabilityProofRecord,
    EvidenceKind, HarnessAdapter, ValidatedExecutionRequest, ValidatedHostObservation,
};
use router_types::{MemoryEnforcement, RunCompletion, TransportTermination};
use std::{os::unix::fs::DirBuilderExt, path::PathBuf, sync::Mutex, time::Duration};

struct LiveProof {
    root: PathBuf,
    secret: [u8; 32],
    sources: BTreeMap<Capability, EvidenceSource>,
    verifier: Option<StoredCapabilityProofVerifier>,
}
pub(crate) struct LinuxFiniteSupervisor {
    state: Mutex<Option<HostState>>,
    run: PreparedRun,
    write: Option<super::write_workspace::WriteDispatch>,
    tools: bool,
    subscription: Option<std::sync::Arc<OwnedSubscriptionController>>,
    subscription_server: Mutex<Option<super::subscription_controller::SubscriptionServer>>,
    binding: CapabilityProofBinding,
    host: HostSnapshot,
    network: std::sync::Arc<super::isolated_network::IsolatedNetwork>,
    broker: TcpListener,
    live: Mutex<LiveProof>,
}
impl LinuxFiniteSupervisor {
    fn new(client: ApprovedFiniteClient, host: HostSnapshot, store: &Path) -> Result<Self> {
        if !cfg!(target_os = "linux") || std::env::consts::ARCH != "aarch64" {
            return Err(RuntimeError::Sandbox);
        }
        let binding = client.proof_binding(&host.id)?;
        if client.reviewed.owned_namespace.is_none() {
            return Err(RuntimeError::Sandbox);
        }
        let network = client
            .reviewed
            .broker
            .isolation
            .as_ref()
            .ok_or(RuntimeError::Sandbox)?
            .clone();
        network.check()?;
        super::isolated_network::check_listener(&client.reviewed.broker.listener)?;
        let broker = client.reviewed.broker.listener.try_clone()?;
        let run = client.reviewed.run.clone();
        let write = client
            .reviewed
            .owned_workspace
            .as_ref()
            .map(FiniteClientWorkspace::dispatch);
        let root = store.join(format!(
            "finite-capability-{}",
            client.reviewed.approval_digest()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        let mut secret = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut secret)?;
        let tools = client.reviewed.owned_tools.is_some();
        let subscription = client.reviewed.owned_subscription.clone();
        Ok(Self {
            tools,
            subscription,
            subscription_server: Mutex::new(None),
            state: Mutex::new(Some(client.into_namespace_state()?)),
            run,
            write,
            binding,
            host,
            network,
            broker,
            live: Mutex::new(LiveProof {
                root,
                secret,
                sources: BTreeMap::new(),
                verifier: None,
            }),
        })
    }
    pub(crate) fn subscription(&self) -> Option<&OwnedSubscriptionController> {
        self.subscription.as_deref()
    }
    fn start_subscription(&self, cancel: Cancellation) -> Result<()> {
        if let Some(controller) = &self.subscription {
            *self
                .subscription_server
                .lock()
                .map_err(|_| RuntimeError::Approval)? =
                Some(controller.start(self.broker.try_clone()?, cancel)?);
        }
        Ok(())
    }
    pub(crate) fn subscription_observation(
        &self,
    ) -> Result<Option<super::subscription_controller::SubscriptionObservation>> {
        self.subscription
            .as_ref()
            .map(|c| c.observation())
            .transpose()
    }
    pub(crate) fn arm_subscription(&self, id: &str, approval: &str) -> Result<()> {
        if let Some(controller) = &self.subscription {
            controller.ready(id, approval)?;
        }
        Ok(())
    }
    pub(crate) fn finish_subscription(&self, proof: &str, status: &str) -> Result<()> {
        if let Some(mut server) = self
            .subscription_server
            .lock()
            .map_err(|_| RuntimeError::Approval)?
            .take()
        {
            server.stop()?;
        }
        if let Some(controller) = &self.subscription {
            controller.cleanup(proof, status)?;
        }
        Ok(())
    }
    pub(crate) fn uses_tools(&self) -> bool {
        self.tools
    }
    fn capabilities(&self) -> Vec<Capability> {
        if self.tools {
            vec![
                Capability::Network,
                Capability::WorkspaceWrite,
                Capability::Tools,
            ]
        } else if self.write.is_some() {
            vec![Capability::Network, Capability::WorkspaceWrite]
        } else {
            vec![Capability::Network]
        }
    }
    pub(crate) async fn bind_write_workspace(
        &self,
        store: &Path,
        id: &str,
        request: &router_types::ExecutionRequest,
        preparation: &crate::store::Preparation<'_>,
    ) -> Result<()> {
        let view = self.write.as_ref().ok_or(RuntimeError::Sandbox)?;
        if view.owner != store
            || view.task_id != id
            || view.path != Path::new(&request.workspace)
            || view.head != request.source_state
            || request.scope != [view.relative.clone()]
            || request.sandbox != router_types::ExecutionSandbox::WorkspaceWrite
        {
            return Err(RuntimeError::Integrity("finite write dispatch view"));
        }
        view.check_sources(Some(preparation)).await?;
        Ok(())
    }
    pub(crate) fn validate_dispatch(&self) -> Result<()> {
        self.network.check()?;
        super::isolated_network::check_listener(&self.broker)?;
        let live = self
            .live
            .lock()
            .map_err(|_| RuntimeError::Integrity("finite proof lock"))?;
        let verifier = live.verifier.as_ref().ok_or(RuntimeError::Sandbox)?;
        verifier
            .require_live()
            .map_err(|_| RuntimeError::Integrity("finite historical proof"))?;
        let now = crate::now()?;
        for capability in self.capabilities() {
            let source = live.sources.get(&capability).ok_or(RuntimeError::Sandbox)?;
            let proof = verifier
                .verify(source, capability, &self.host, now)
                .map_err(|_| RuntimeError::Integrity("finite live OS proof"))?;
            if proof.binding != self.binding
                || proof.tier != CapabilityProofTier::Proven
                || proof.observed_at_unix_seconds > now
                || proof.expires_at_unix_seconds <= now
            {
                return Err(RuntimeError::Integrity(
                    "finite OS proof identity or freshness",
                ));
            }
        }
        Ok(())
    }
    pub(crate) async fn qualify(
        &self,
        state: &mut HostState,
        snapshot: &ValidatedHostObservation,
        preparation: &crate::store::Preparation<'_>,
        store_root: &Path,
        cancel: &Cancellation,
    ) -> Result<()> {
        state.check_owned_resources()?;
        if snapshot.host() != &self.host {
            return Err(RuntimeError::Integrity("finite qualification host"));
        }
        let started = crate::now()?;
        let mut raw = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut raw)?;
        let nonce = content_digest(&raw);
        let mut scratch = HostState::create(store_root, "codex", &BTreeMap::new())?
            .ok_or(RuntimeError::Sandbox)?;
        let temporary = scratch.path().join("tmp");
        fs::DirBuilder::new().mode(0o700).create(&temporary)?;
        if self.write.is_some() {
            fs::write(temporary.join("scoped-file"), b"sacrificial write control")?;
        }
        let control = temporary.join(format!("qualification-{nonce}"));
        fs::DirBuilder::new().mode(0o700).create(&control)?;
        let hidden = scratch.path().join("private-control");
        fs::write(&hidden, b"private-controller-only")?;
        let other = TcpListener::bind(("127.0.0.1", 0))?;
        let denied_port = other.local_addr()?.port();
        drop(std::net::TcpStream::connect(other.local_addr()?)?);
        let mut view = ProbeView {
            tools: None,
            temporary: temporary.clone(),
            control: control.clone(),
            hidden,
            denied_port,
            nonce: nonce.clone(),
        };
        if self.tools {
            view.tools = Some(ToolsProbeView::prepare(state, &view)?);
        }
        let mut command = composition_command(state, Some(&view))?;
        let (probe_id, lease) = preparation.register_probe_with_host_state(true)?;
        scratch.arm_cleanup(Some(&lease), true)?;
        // The real bundle is mounted read-only. All writable temporary paths
        // resolve to scratch, which the registered probe lease owns durably.
        state.arm_cleanup(Some(&lease), true)?;
        command.env("ROUTER_RUNTIME_LEASE", lease);
        let capture = crate::process::capture(
            command,
            self.run.stdin.as_bytes().to_vec(),
            10_000,
            65536,
            100,
            cancel,
        );
        tokio::pin!(capture);
        let mut samples = Vec::new();
        let captured = loop {
            tokio::select! {
                value=&mut capture=>break value,
                _=tokio::time::sleep(Duration::from_millis(25))=>{
                    if let Ok(meta)=fs::metadata(control.join("heartbeat")) {
                        if samples.len()<64 { samples.push(meta.len()); }
                    }
                }
            }
        };
        let succeeded = captured.as_ref().is_ok_and(|v| {
            v.outcome.exit_code == Some(0)
                && !v.output_limited
                && !v.output_incomplete
                && v.outcome.termination == TransportTermination::Exited
        });
        let proof =
            preparation.resolve_probe_and_state_observed(&probe_id, Some(scratch), |proof| {
                if succeeded {
                    if proof.evidence != router_types::ProcessCleanupEvidence::NamespaceTerminated
                        || !samples.windows(2).any(|p| p[1] > p[0])
                        || fs::read(control.join("control"))? != nonce.as_bytes()
                    {
                        return Err(RuntimeError::Integrity("finite live effects"));
                    }
                    let mut lengths = Vec::new();
                    for _ in 0..3 {
                        lengths.push(fs::metadata(control.join("heartbeat"))?.len());
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    if !lengths.windows(2).all(|p| p[0] == p[1]) {
                        return Err(RuntimeError::CleanupUnknown);
                    }
                    if let Some(tools) = &view.tools {
                        tools.verify(&nonce)?;
                    }
                    if let Some(view) = &self.write {
                        if !self.tools
                            && fs::read(temporary.join("scoped-file"))? != nonce.as_bytes()
                        {
                            return Err(RuntimeError::Integrity("finite bounded write effect"));
                        }
                        state
                            .finite_resources()?
                            .reviewed
                            .owned_workspace
                            .as_ref()
                            .ok_or(RuntimeError::Sandbox)?
                            .check_for_review(store_root, &view.task_id, &self.run)?;
                    }
                }
                // Validate and rearm the read-only retained bundle while the
                // exact probe lock and unresolved durable cleanup obligation
                // are still held. A failed check must not settle the probe.
                state.finish_read_only_probe(proof)
            })?;
        drop(proof);
        let output = captured?;
        if cancel.is_cancelled() {
            return Err(RuntimeError::Cancelled);
        }
        if !succeeded {
            return Err(RuntimeError::Sandbox);
        }
        let lines: Vec<_> = output
            .stdout
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .collect();
        if lines.len() != if self.tools { 3 } else { 2 } {
            return Err(RuntimeError::Integrity("finite probe framing"));
        }
        let observed = router_adapter_api::strict_json_limited(lines[0], 8192)
            .map_err(|_| RuntimeError::Integrity("finite guard observation"))?;
        let version = router_adapter_api::strict_json_limited(lines[1], 8192)
            .map_err(|_| RuntimeError::Integrity("finite version observation"))?;
        if observed["linux_finite_probe"] != "v2"
            || observed["memory_bytes"] != 8589934592u64
            || observed["nonce"] != nonce
            || observed["workspace_write"] != (self.write.is_some() && !self.tools)
            || version
                != serde_json::json!({"finite_client_probe":"v1","native_version":"codex-cli 0.159.2"})
        {
            return Err(RuntimeError::Integrity("finite observed composition"));
        }
        if self.tools {
            let tool_effect = router_adapter_api::strict_json_limited(lines[2], 8192)
                .map_err(|_| RuntimeError::Integrity("finite tools live observation"))?;
            if tool_effect
                != serde_json::json!({"finite_tools_probe":"v1","nonce":nonce,"direct_write_refused":true,"calls":6})
            {
                return Err(RuntimeError::Integrity("finite tools observed effects"));
            }
        }
        let mut live = self
            .live
            .lock()
            .map_err(|_| RuntimeError::Integrity("finite proof lock"))?;
        let mut store = crate::CapabilityProofStore::create(&live.root)
            .map_err(|_| RuntimeError::Integrity("finite proof store"))?;
        let key = CapabilityProofKey::derive(&live.secret, store.store_id())
            .map_err(|_| RuntimeError::Integrity("finite proof key"))?;
        let ended = crate::now()?;
        for capability in self.capabilities() {
            let record = CapabilityProofRecord {
                schema_version: 1,
                proof_id: format!(
                    "finite-{nonce}-{}",
                    if capability == Capability::Network {
                        "network"
                    } else if capability == Capability::Tools {
                        "tools"
                    } else {
                        "write"
                    }
                ),
                sequence: store
                    .next_sequence(&live.secret)
                    .map_err(|_| RuntimeError::Integrity("finite proof sequence"))?,
                store_id: store.store_id().into(),
                capability,
                tier: CapabilityProofTier::Proven,
                network_scope: (capability == Capability::Network)
                    .then_some(CapabilityNetworkScope::LoopbackFetch),
                binding: self.binding.clone(),
                model_id: self.run.requested_model.to_string(),
                nonce_sha256: content_digest(nonce.as_bytes()),
                expected_effect_sha256: content_digest(&output.stdout),
                started_at_unix_seconds: started,
                ended_at_unix_seconds: ended,
                max_age_seconds: 60,
                outcome: CapabilityAttemptOutcome::Succeeded,
            };
            let authenticated = key
                .authenticate(record)
                .map_err(|_| RuntimeError::Integrity("finite proof record"))?;
            let source = EvidenceSource {
                id: authenticated.record.proof_id.clone(),
                kind: EvidenceKind::HostRuntime,
                observed_version: Some(self.binding.observed_version.clone()),
                observed_at_unix_seconds: ended,
                content_sha256: authenticated
                    .digest()
                    .map_err(|_| RuntimeError::Integrity("finite proof digest"))?,
            };
            store
                .append(&authenticated, &live.secret)
                .map_err(|_| RuntimeError::Integrity("finite proof append"))?;

            live.sources.insert(capability, source);
        }
        drop(store);
        let verifier = StoredCapabilityProofVerifier::open_existing(
            &live.root,
            live.secret,
            vec![self.binding.clone()],
        )
        .map_err(|_| RuntimeError::Integrity("finite proof verifier"))?;
        live.verifier = Some(verifier);
        drop(live);
        self.validate_dispatch()
    }
}
impl SandboxSupervisor for LinuxFiniteSupervisor {
    fn create_host_state(&self, _store: &Path, run: &PreparedRun) -> Result<Option<HostState>> {
        if prepared_digest(run)? != prepared_digest(&self.run)? {
            return Err(RuntimeError::Integrity("finite prepared dispatch"));
        }
        self.state
            .lock()
            .map_err(|_| RuntimeError::Integrity("finite state lock"))?
            .take()
            .map(Some)
            .ok_or(RuntimeError::Integrity("finite state already taken"))
    }
    fn command(
        &self,
        run: &PreparedRun,
        policy: &SandboxPolicy,
    ) -> Result<tokio::process::Command> {
        if policy.network != NetworkAuthority::ControllerBrokerOnly
            || prepared_digest(run)? != prepared_digest(&self.run)?
        {
            return Err(RuntimeError::Sandbox);
        }
        self.validate_dispatch()?;
        composition_command(policy.host_state.ok_or(RuntimeError::Sandbox)?, None)
    }
    fn pid_namespace_isolated(&self) -> bool {
        true
    }
    fn parent_lifetime_enforced(&self) -> bool {
        true
    }
    fn resource_limits_enforced(&self) -> bool {
        true
    }
    fn memory_enforcement(&self) -> MemoryEnforcement {
        MemoryEnforcement::Enforced
    }
}

struct FiniteAdapter<'a> {
    run: PreparedRun,
    inner: &'a dyn HarnessAdapter,
}
impl HarnessAdapter for FiniteAdapter<'_> {
    fn host(&self) -> &'static str {
        "codex"
    }
    fn prepare(
        &self,
        request: &ValidatedExecutionRequest,
    ) -> std::result::Result<PreparedRun, router_adapter_api::AdapterError> {
        let mut expected = router_adapter_api::prepared_run(
            request,
            "finite-client",
            vec!["--worker".into()],
            vec![],
        )?;
        expected.missing_runtime_evidence.clear();
        let expected_digest = prepared_digest(&expected)
            .map_err(|_| router_adapter_api::AdapterError::Invalid("finite expected digest"))?;
        let actual_digest = prepared_digest(&self.run)
            .map_err(|_| router_adapter_api::AdapterError::Invalid("finite actual digest"))?;
        if expected_digest != actual_digest {
            return Err(router_adapter_api::AdapterError::Invalid(
                "finite prepared contract",
            ));
        }
        Ok(self.run.clone())
    }
    fn decode_stream(
        &self,
        bytes: &[u8],
        outcome: router_types::TransportOutcome,
        max: usize,
    ) -> std::result::Result<router_types::RuntimeEvidence, router_adapter_api::AdapterError> {
        self.inner.decode_stream(bytes, outcome, max)
    }
}
impl Runtime {
    /// Dedicated local-fixture Linux execution. The constructor cannot be
    /// rebuilt from a receipt: live OS canaries run inside durable preparation.
    /// Model/provider authority is still restricted to the reviewed broker.
    pub async fn execute_finite_client(
        &self,
        approved: super::ApprovedFiniteClientRun,
        adapter: &dyn HarnessAdapter,
        cancel: Cancellation,
    ) -> Result<RunCompletion> {
        if self.admission.is_none() {
            return Err(RuntimeError::Invalid("finite client durable admission"));
        }
        self.check_finite_review(
            &approved.approved.pending.run.run_id,
            &approved.approved.pending.context,
            &approved.approved.pending.request,
            &approved.client.reviewed,
        )?;
        if adapter.host() != "codex" {
            return Err(RuntimeError::Sandbox);
        }
        let snapshot = self.snapshot(&approved.approved.pending.context)?;
        let frozen = approved.client.reviewed.run.clone();
        let supervisor =
            LinuxFiniteSupervisor::new(approved.client, snapshot.host().clone(), &self.store.root)?;
        supervisor.start_subscription(cancel.clone())?;
        let adapter = FiniteAdapter {
            run: frozen,
            inner: adapter,
        };
        Box::pin(self.execute_admitted(
            approved.approved,
            &adapter,
            &supervisor,
            cancel,
            None,
            Some(&supervisor),
        ))
        .await
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "linux_e2e.rs"]
mod e2e_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "coupling_linux_tests.rs"]
mod tools_coupling_tests;

#[path = "campaign_discovery.rs"]
mod campaign_discovery;
