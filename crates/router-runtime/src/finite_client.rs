//! Review-bound finite-client preparation. Never OS or provider admission.
use crate::private_program::PrivateProgram;
use crate::{HostState, ResourceLimits, Result, RuntimeError, StoredCapabilityProofVerifier};
use router_adapter_api::{
    CapabilityProofBinding, CapabilityProofTier, CapabilityProofVerifier, EvidenceSource,
    content_digest, is_digest,
};
use router_types::{
    Capability, ExecutionMode, ExecutionTarget, FiniteClientFile, FiniteClientManifest,
    HostSnapshot, PreparedRun,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, TcpListener},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

const MAX_CONTRACT: usize = 32 * 1024;
const MAX_BINARY: u64 = 256 * 1024 * 1024;
const MAX_CONFIGURATION: u64 = 64 * 1024;

/// Ownership of an already-bound loopback listener, not a port number from JSON.
/// This object is neither serializable nor cloneable. A preparation guard borrows it.
pub struct OwnedBroker {
    isolation: Option<std::sync::Arc<isolated_network::IsolatedNetwork>>,
    listener: TcpListener,
    endpoint: String,
    instance: String,
}
impl OwnedBroker {
    pub fn from_listener(listener: TcpListener) -> Result<Self> {
        let address = listener.local_addr()?;
        if address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || address.port() == 0 {
            return Err(RuntimeError::Sandbox);
        }
        let mut nonce = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        Ok(Self {
            isolation: None,
            listener,
            endpoint: format!("tcp://{address}"),
            instance: content_digest(&nonce),
        })
    }
    /// An exclusive wildcard listener is safe only in a verified loopback-only
    /// network namespace with no capability to change that namespace. This is
    /// a local qualification entrance, never support for a routed host.
    pub fn from_isolated_listener(listener: TcpListener) -> Result<Self> {
        let isolation = std::sync::Arc::new(isolated_network::IsolatedNetwork::capture()?);
        isolated_network::check_listener(&listener)?;
        let address = listener.local_addr()?;
        let mut nonce = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        let instance = crate::digest(
            "finite-isolated-broker-v1",
            &(
                hex::encode(nonce),
                isolation.identity(),
                address.to_string(),
            ),
        )?;
        isolation.check()?;
        Ok(Self {
            isolation: Some(isolation),
            listener,
            endpoint: format!("tcp://127.0.0.1:{}", address.port()),
            instance,
        })
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub fn instance_sha256(&self) -> &str {
        &self.instance
    }
    fn check(&self, manifest: &FiniteClientManifest) -> Result<()> {
        if manifest.broker_endpoint != self.endpoint
            || manifest.broker_instance_sha256 != self.instance
            || (self.isolation.is_none()
                && format!("tcp://{}", self.listener.local_addr()?) != self.endpoint)
        {
            return Err(RuntimeError::Integrity("finite client broker binding"));
        }
        if let Some(isolation) = &self.isolation {
            isolation.check()?;
            isolated_network::check_listener(&self.listener)?;
            if self.endpoint != format!("tcp://127.0.0.1:{}", self.listener.local_addr()?.port()) {
                return Err(RuntimeError::Sandbox);
            }
        }
        Ok(())
    }
}
mod isolated_network;

#[derive(Eq, PartialEq, serde::Serialize)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
}
impl FileIdentity {
    fn from(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            owner: metadata.uid(),
        }
    }
}
// Retaining the descriptor prevents inode reuse after unlink. It does not
// prevent another writer from changing the bytes of the same open inode.
struct PinnedIdentity {
    identity: FileIdentity,
    _file: File,
}
fn canonical(path: &str) -> Result<&Path> {
    if path.is_empty() || path.len() > 4096 || path.chars().any(char::is_control) {
        return Err(RuntimeError::Invalid("finite client path"));
    }
    let path = Path::new(path);
    if !path.is_absolute() || fs::canonicalize(path)? != path {
        return Err(RuntimeError::Sandbox);
    }
    Ok(path)
}
fn directory(path: &str, private: bool) -> Result<PinnedIdentity> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(canonical(path)?)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & if private { 0o077 } else { 0o022 } != 0
    {
        return Err(RuntimeError::Sandbox);
    }
    Ok(PinnedIdentity {
        identity: FileIdentity::from(&metadata),
        _file: file,
    })
}
pub(crate) fn retain_tool_program(pin: &FiniteClientFile) -> Result<impl Send> {
    file_identity(pin, true)
}
fn file_identity(pin: &FiniteClientFile, executable: bool) -> Result<PinnedIdentity> {
    if !is_digest(&pin.sha256) {
        return Err(RuntimeError::Invalid("finite client file digest"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(canonical(&pin.path)?)?;
    let metadata = file.metadata()?;
    let max = if executable {
        MAX_BINARY
    } else {
        MAX_CONFIGURATION
    };
    if !metadata.is_file()
        || metadata.len() > max
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o7000 != 0
        || (metadata.uid() != 0 && metadata.uid() != rustix::process::geteuid().as_raw())
        || (executable && metadata.mode() & 0o111 == 0)
    {
        return Err(RuntimeError::Sandbox);
    }
    let identity = FileIdentity::from(&metadata);
    let mut bytes = Vec::new();
    (&file).take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(RuntimeError::Limit);
    }
    if content_digest(&bytes) != pin.sha256
        || FileIdentity::from(&file.metadata()?) != identity
        || FileIdentity::from(&fs::symlink_metadata(&pin.path)?) != identity
    {
        return Err(RuntimeError::Integrity("finite client file changed"));
    }
    Ok(PinnedIdentity {
        identity,
        _file: file,
    })
}
fn token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn prepared_digest(run: &PreparedRun) -> Result<String> {
    if run.schema_version != 1
        || run.host.as_str() != "codex"
        || run.program != "finite-client"
        || run.target != ExecutionTarget::ExternalWorker
        || run.mode != ExecutionMode::Execute
        || run.parent_model_changed
        || !run.degradations.is_empty()
        || !run.missing_runtime_evidence.is_empty()
        || run.stdin.as_bytes().len() > MAX_CONTRACT
        || run.argv.len() > 64
        || run
            .argv
            .iter()
            .any(|s| s.len() > 4096 || s.chars().any(char::is_control))
        || run.scope.len() > 64
        || run.scope.iter().any(|s| {
            s.is_empty()
                || s.len() > 4096
                || s.starts_with('/')
                || s.contains('\\')
                || s.chars().any(char::is_control)
                || s.split('/').any(|part| matches!(part, "" | "." | ".."))
        })
        || run.scope.iter().collect::<BTreeSet<_>>().len() != run.scope.len()
        || run.timeout_ms == 0
        || run.timeout_ms > 60_000
        || run.max_output_bytes == 0
        || run.max_output_bytes > 1024 * 1024
        || [
            &run.receipt_id,
            &run.authorization_digest,
            &run.snapshot_hash,
        ]
        .iter()
        .any(|s| !is_digest(s))
        || !matches!(run.source_state.len(), 40 | 64)
        || !run.source_state.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(RuntimeError::Invalid("finite client prepared contract"));
    }
    canonical(&run.cwd)?;
    let bytes = serde_json::to_vec(&(run, content_digest(run.stdin.as_bytes())))?;
    if bytes.len() > MAX_CONTRACT {
        return Err(RuntimeError::Limit);
    }
    Ok(content_digest(&bytes))
}
fn pins(manifest: &FiniteClientManifest) -> [(&FiniteClientFile, bool); 6] {
    [
        (&manifest.client, true),
        (&manifest.native, true),
        (&manifest.helper, true),
        (&manifest.wrapper, true),
        (&manifest.profile, false),
        (&manifest.configuration, false),
    ]
}

// Owned copies are preparation assets, not an immutable view or OS authority.
// Their directories must be excluded from worker writes by the qualified sandbox.
struct FiniteClientAssets {
    copies: [PrivateProgram; 5],
    pins: [FiniteClientFile; 6],
    identities: [PinnedIdentity; 6],
    directories: [PinnedIdentity; 5],
}
impl FiniteClientAssets {
    fn prepare(manifest: &FiniteClientManifest, run: &PreparedRun) -> Result<Self> {
        let store = Path::new(&manifest.private_state);
        let mut copies = Vec::new();
        let mut asset_pins = Vec::new();
        let mut directories = Vec::new();
        for (pin, executable) in pins(manifest).into_iter().take(5) {
            let copy = if executable {
                PrivateProgram::copy(Path::new(&pin.path), &pin.sha256, store)?
            } else {
                PrivateProgram::copy_profile(Path::new(&pin.path), &pin.sha256, store)?
            };
            if copy.directory().starts_with(&run.cwd)
                || Path::new(&run.cwd).starts_with(copy.directory())
            {
                return Err(RuntimeError::Scope);
            }
            let path = copy
                .verify(&pin.sha256)?
                .to_str()
                .ok_or(RuntimeError::Invalid("finite client copy path"))?
                .to_owned();
            directories.push(directory(
                copy.directory()
                    .to_str()
                    .ok_or(RuntimeError::Invalid("finite client copy directory"))?,
                true,
            )?);
            asset_pins.push(FiniteClientFile {
                path,
                sha256: pin.sha256.clone(),
            });
            copies.push(copy);
        }
        // Codex consumes config.toml at the producer-owned home. Moving it to a
        // second arbitrary path would not qualify native configuration consumption.
        asset_pins.push(manifest.configuration.clone());
        let identities: Vec<PinnedIdentity> = asset_pins
            .iter()
            .enumerate()
            .map(|(index, pin)| file_identity(pin, index < 4))
            .collect::<Result<_>>()?;
        let assets = Self {
            copies: copies
                .try_into()
                .map_err(|_| RuntimeError::Invalid("finite client copy count"))?,
            pins: asset_pins
                .try_into()
                .map_err(|_| RuntimeError::Invalid("finite client asset count"))?,
            identities: identities
                .try_into()
                .map_err(|_| RuntimeError::Invalid("finite client identity count"))?,
            directories: directories
                .try_into()
                .map_err(|_| RuntimeError::Invalid("finite client directory count"))?,
        };
        assets.check()?;
        Ok(assets)
    }
    fn check(&self) -> Result<()> {
        for ((copy, pin), expected) in self.copies.iter().zip(&self.pins).zip(&self.directories) {
            copy.verify(&pin.sha256)?;
            if directory(
                copy.directory()
                    .to_str()
                    .ok_or(RuntimeError::Invalid("finite client copy directory"))?,
                true,
            )?
            .identity
                != expected.identity
            {
                return Err(RuntimeError::Integrity(
                    "finite client copy directory changed",
                ));
            }
        }
        for (index, (pin, expected)) in self.pins.iter().zip(&self.identities).enumerate() {
            if file_identity(pin, index < 4)?.identity != expected.identity {
                return Err(RuntimeError::Integrity("finite client copy changed"));
            }
        }
        Ok(())
    }
}

/// Private manifest and prepared bytes are frozen for a separate, exact review.
/// This review does not change the durable runtime's approval state.
pub struct FiniteClientReview {
    manifest: FiniteClientManifest,
    run: PreparedRun,
    run_digest: String,
    approval: String,
    broker: OwnedBroker,
    identities: Vec<PinnedIdentity>,
    state_identity: PinnedIdentity,
    workspace_identity: PinnedIdentity,
    resource_arguments: Vec<String>,
    owned_state: Option<FiniteCodexState>,
    owned_assets: Option<FiniteClientAssets>,
    owned_namespace: Option<FiniteClientNamespace>,
    owned_workspace: Option<FiniteClientWorkspace>,
    owned_tools: Option<tools_state::PreparedTools>,
    owned_subscription: Option<std::sync::Arc<OwnedSubscriptionController>>,
}
impl FiniteClientReview {
    pub fn new(
        manifest: FiniteClientManifest,
        run: &PreparedRun,
        broker: OwnedBroker,
    ) -> Result<Self> {
        Self::with_resources(manifest, run, broker, ResourceLimits::default())
    }
    /// Concrete helper arguments are validated and bound into the approval.
    pub fn with_resources(
        manifest: FiniteClientManifest,
        run: &PreparedRun,
        broker: OwnedBroker,
        limits: ResourceLimits,
    ) -> Result<Self> {
        let resource_arguments = limits.args()?;
        if manifest.schema_version != 1
            || !token(&manifest.task_id, 128)
            || !token(&manifest.host_snapshot_id, 128)
            || manifest.native_version.is_empty()
            || manifest.native_version.len() > 128
            || !manifest
                .native_version
                .bytes()
                .all(|b| b.is_ascii_graphic())
            || manifest.broker_endpoint.len() > 128
            || !is_digest(&manifest.broker_instance_sha256)
        {
            return Err(RuntimeError::Invalid("finite client manifest"));
        }
        if manifest.private_state.is_empty()
            || manifest.private_state.len() > 4096
            || pins(&manifest).iter().any(|(pin, _)| {
                pin.path.is_empty() || pin.path.len() > 4096 || !is_digest(&pin.sha256)
            })
        {
            return Err(RuntimeError::Invalid(
                "finite client manifest paths or digests",
            ));
        }
        let run_digest = prepared_digest(run)?;
        let bytes = serde_json::to_vec(&(
            "finite-client-review-v2",
            &manifest,
            &run_digest,
            &resource_arguments,
        ))?;
        if bytes.len() > MAX_CONTRACT {
            return Err(RuntimeError::Limit);
        }
        broker.check(&manifest)?;
        let state_identity = directory(&manifest.private_state, true)?;
        let workspace_identity = directory(&run.cwd, false)?;
        if Path::new(&manifest.private_state).starts_with(&run.cwd)
            || Path::new(&run.cwd).starts_with(&manifest.private_state)
        {
            return Err(RuntimeError::Scope);
        }
        let asset_pins = pins(&manifest);
        if asset_pins
            .iter()
            .map(|(p, _)| &p.path)
            .collect::<BTreeSet<_>>()
            .len()
            != asset_pins.len()
            || asset_pins
                .iter()
                .any(|(p, _)| Path::new(&p.path).starts_with(&run.cwd))
        {
            return Err(RuntimeError::Scope);
        }
        let identities: Vec<PinnedIdentity> = asset_pins
            .iter()
            .map(|(pin, executable)| file_identity(pin, *executable))
            .collect::<Result<_>>()?;
        let bytes = serde_json::to_vec(&(
            "finite-client-review-v2",
            &resource_arguments,
            &manifest,
            &run_digest,
            &state_identity.identity,
            &workspace_identity.identity,
            identities
                .iter()
                .map(|pin| &pin.identity)
                .collect::<Vec<_>>(),
        ))?;
        if bytes.len() > MAX_CONTRACT {
            return Err(RuntimeError::Limit);
        }
        Ok(Self {
            manifest,
            run: run.clone(),
            run_digest,
            approval: content_digest(&bytes),
            broker,
            identities,
            state_identity,
            workspace_identity,
            resource_arguments,
            owned_state: None,
            owned_assets: None,
            owned_namespace: None,
            owned_workspace: None,
            owned_tools: None,
            owned_subscription: None,
        })
    }
    fn check_files(&self) -> Result<()> {
        self.broker.check(&self.manifest)?;
        if let Some(namespace) = &self.owned_namespace {
            namespace.check()?;
        }
        if let Some(assets) = &self.owned_assets {
            assets.check()?;
        }
        if let Some(state) = &self.owned_state {
            state.check(&self.run, &self.broker)?;
        }
        if directory(&self.manifest.private_state, true)?.identity != self.state_identity.identity
            || directory(&self.run.cwd, false)?.identity != self.workspace_identity.identity
        {
            return Err(RuntimeError::Integrity("finite client directory changed"));
        }
        for ((pin, executable), expected) in pins(&self.manifest).iter().zip(&self.identities) {
            if file_identity(pin, *executable)?.identity != expected.identity {
                return Err(RuntimeError::Integrity("finite client file identity"));
            }
        }
        if let Some(tools) = &self.owned_tools {
            tools.check()?;
        }
        if let Some(workspace) = &self.owned_workspace {
            workspace.check_identity()?;
        }
        Ok(())
    }
    pub fn approval_digest(&self) -> &str {
        &self.approval
    }
    pub fn approve(self, approved_digest: &str) -> Result<ApprovedFiniteClient> {
        if approved_digest != self.approval {
            return Err(RuntimeError::Approval);
        }
        Ok(ApprovedFiniteClient { reviewed: self })
    }
}

/// Nonserializable preparation handle, not `ApprovedRun` or permission to execute.
pub struct ApprovedFiniteClient {
    reviewed: FiniteClientReview,
}
impl ApprovedFiniteClient {
    /// Expected pins for the existing proof store. The argument-template slot
    /// binds the complete reviewed task, native/configuration/private-state and
    /// retained broker instance, not a digest declared by an observation.
    pub fn proof_binding(&self, host_snapshot_id: &str) -> Result<CapabilityProofBinding> {
        self.reviewed.proof_binding(host_snapshot_id)
    }
    /// Reopens the live authenticated store and rechecks every input. Callers
    /// must retain the returned borrow through their preparation boundary.
    /// It does not construct a process, claim an OS canary or authorize a send.
    pub fn validate<'a>(
        &'a self,
        run: &PreparedRun,
        host: &HostSnapshot,
        source: &EvidenceSource,
        verifier: &StoredCapabilityProofVerifier,
        now: u64,
    ) -> Result<FiniteClientValidation<'a>> {
        validate_review(&self.reviewed, run, host, source, verifier, now)
    }
}

impl FiniteClientReview {
    fn proof_binding(&self, host_snapshot_id: &str) -> Result<CapabilityProofBinding> {
        let r = self;
        let m = &r.manifest;
        if host_snapshot_id != m.host_snapshot_id {
            return Err(RuntimeError::Integrity("finite client reviewed host"));
        }
        let binding = CapabilityProofBinding {
            harness_id: r.run.host.as_str().into(),
            host_snapshot_id: host_snapshot_id.into(),
            binary_sha256: m.client.sha256.clone(),
            observed_version: m.native_version.clone(),
            adapter_id: if r.owned_namespace.is_some() {
                "finite-client-contract-v5"
            } else if r.owned_assets.is_some() {
                "finite-client-contract-v4"
            } else {
                "finite-client-contract-v2"
            }
            .into(),
            argument_template_sha256: r.approval.clone(),
            sandbox_helper_sha256: m.helper.sha256.clone(),
            sandbox_wrapper_sha256: m.wrapper.sha256.clone(),
            sandbox_profile_sha256: m.profile.sha256.clone(),
            write_roots: r.run.scope.iter().cloned().collect(),
            network: true,
            os: std::env::consts::OS.into(),
        };
        binding
            .digest()
            .map_err(|_| RuntimeError::Invalid("finite client proof binding"))?;
        Ok(binding)
    }
}
fn validate_review<'a>(
    reviewed: &'a FiniteClientReview,
    run: &PreparedRun,
    host: &HostSnapshot,
    source: &EvidenceSource,
    verifier: &StoredCapabilityProofVerifier,
    now: u64,
) -> Result<FiniteClientValidation<'a>> {
    let r = reviewed;
    if prepared_digest(run)? != r.run_digest
        || host.harness != run.host
        || host.id != r.manifest.host_snapshot_id
        || !host.supported_models.contains(&run.requested_model)
        || host
            .supported_efforts
            .get(&run.requested_model)
            .is_none_or(|efforts| !efforts.contains(&run.requested_effort))
        || !host.capabilities.contains(&Capability::Network)
    {
        return Err(RuntimeError::Integrity("finite client current task"));
    }
    r.check_files()?;
    verifier
        .require_live()
        .map_err(|_| RuntimeError::Integrity("finite client historical proof"))?;
    let proof = verifier
        .verify(source, Capability::Network, host, now)
        .map_err(|_| RuntimeError::Integrity("finite client authenticated proof"))?;
    if proof.binding != reviewed.proof_binding(&host.id)?
        || proof.tier != CapabilityProofTier::Proven
        || proof.observed_at_unix_seconds > now
        || proof.expires_at_unix_seconds <= now
    {
        return Err(RuntimeError::Integrity(
            "finite client proof binding or freshness",
        ));
    }
    Ok(FiniteClientValidation { reviewed })
}

/// A borrow keeps the reviewed listener alive; it is not executable authority.
/// File checks and a later path-based exec would remain separate steps (TOCTOU).
pub struct FiniteClientValidation<'a> {
    reviewed: &'a FiniteClientReview,
}
impl FiniteClientValidation<'_> {
    pub fn broker_endpoint(&self) -> &str {
        self.reviewed.broker.endpoint()
    }
    /// Trusted controller access only. No listener is transferred to the worker.
    pub fn broker_listener(&self) -> &TcpListener {
        &self.reviewed.broker.listener
    }
}

mod subscription_controller;
#[path = "finite_client/subscription_preparation.rs"]
mod subscription_preparation;
pub use subscription_controller::{
    OwnedSubscriptionController, SubscriptionControllerBinding, SubscriptionControllerPeer,
};
use subscription_preparation::{
    SubscriptionPreparation, codex_catalog_for, codex_configuration_for,
};

/// Runtime-created, credential-free Codex home. Uses the existing HostState
/// lifecycle, and must be consumed by a review to remain alive with approval.
pub struct FiniteCodexState {
    state: HostState,
    startup: FiniteCodexStartup,
}
struct FiniteCodexStartup {
    tools: bool,
    subscription: Option<SubscriptionPreparation>,
    configuration: FiniteClientFile,
    catalog: FiniteClientFile,
    catalog_identity: PinnedIdentity,
    tmp_identity: PinnedIdentity,
    installation: FiniteClientFile,
    installation_identity: PinnedIdentity,
    installation_alias: PinnedIdentity,
}
impl FiniteCodexState {
    pub fn path(&self) -> &Path {
        self.state.path()
    }
    pub fn configuration(&self) -> &FiniteClientFile {
        &self.startup.configuration
    }
    fn check(&self, run: &PreparedRun, broker: &OwnedBroker) -> Result<()> {
        self.startup.check(self.path(), run, broker)
    }
    fn startup_binding(&self) -> Result<String> {
        self.startup.binding()
    }
    fn native_environment(&self) -> BTreeMap<String, String> {
        let home = self.path().to_string_lossy().into_owned();
        BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), home.clone()),
            ("CODEX_HOME".into(), home.clone()),
            ("TMPDIR".into(), format!("{home}/tmp")),
            ("CODEX_SQLITE_HOME".into(), format!("{home}/tmp")),
        ])
    }
}
impl FiniteCodexStartup {
    fn check(&self, home: &Path, run: &PreparedRun, broker: &OwnedBroker) -> Result<()> {
        let tmp = home.join("tmp");
        let tmp = tmp
            .to_str()
            .ok_or(RuntimeError::Invalid("finite client tmp path"))?;
        if directory(tmp, true)?.identity != self.tmp_identity.identity
            || self.configuration.sha256
                != content_digest(&codex_configuration_for(
                    run,
                    broker,
                    self.tools,
                    self.subscription.as_ref(),
                )?)
        {
            return Err(RuntimeError::Integrity("finite client owned configuration"));
        }
        if self.catalog.sha256
            != content_digest(&codex_catalog_for(
                run,
                self.tools,
                self.subscription.as_ref(),
            )?)
            || file_identity(&self.catalog, false)?.identity != self.catalog_identity.identity
        {
            return Err(RuntimeError::Integrity("finite local catalog changed"));
        }
        if file_identity(&self.installation, false)?.identity != self.installation_identity.identity
            || installation_alias(&home.join("installation_id"))?.identity
                != self.installation_alias.identity
        {
            return Err(RuntimeError::Integrity("finite client startup state"));
        }
        Ok(())
    }
    fn binding(&self) -> Result<String> {
        let base = self.fixture_binding()?;
        match &self.subscription {
            Some(subscription) => {
                crate::digest("finite-subscription-preparation-v1", &(&base, subscription))
            }
            None => Ok(base),
        }
    }
    fn fixture_binding(&self) -> Result<String> {
        if self.tools {
            return crate::digest(
                "finite-codex-tools-startup-v1",
                &(
                    &self.configuration,
                    &self.catalog,
                    &self.catalog_identity.identity,
                    &self.tmp_identity.identity,
                    &self.installation,
                    &self.installation_identity.identity,
                    &self.installation_alias.identity,
                    "/finite-client",
                    "--mcp-tools",
                    ["read_file", "write_file", "exec"],
                ),
            );
        }
        Ok(content_digest(&serde_json::to_vec(&(
            "finite-codex-startup-v2",
            &self.catalog,
            &self.catalog_identity.identity,
            &self.tmp_identity.identity,
            &self.installation,
            &self.installation_identity.identity,
            &self.installation_alias.identity,
            "tmp/installation_id",
            "CODEX_SQLITE_HOME",
        ))?))
    }
}
fn installation_alias(path: &Path) -> Result<PinnedIdentity> {
    if fs::read_link(path)? != Path::new("tmp/installation_id") {
        return Err(RuntimeError::Integrity("finite client startup alias"));
    }
    #[cfg(target_os = "linux")]
    let flags = nix::libc::O_PATH | nix::libc::O_NOFOLLOW;
    #[cfg(target_os = "macos")]
    let flags = nix::libc::O_SYMLINK;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(RuntimeError::Sandbox);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)?;
        let metadata = file.metadata()?;
        let identity = FileIdentity::from(&metadata);
        if !metadata.file_type().is_symlink()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || FileIdentity::from(&fs::symlink_metadata(path)?) != identity
            || fs::read_link(path)? != Path::new("tmp/installation_id")
        {
            return Err(RuntimeError::Integrity("finite client startup alias"));
        }
        Ok(PinnedIdentity {
            identity,
            _file: file,
        })
    }
}
// Operator-authored metadata for the coded local transport only. This is not
// vendor discovery, a real model context measurement or provider availability.
fn codex_local_catalog_mode(run: &PreparedRun, tools: bool) -> Result<Vec<u8>> {
    if !token(run.requested_model.as_str(), 128) {
        return Err(RuntimeError::Invalid("finite local catalog model"));
    }
    Ok(serde_json::to_vec(&serde_json::json!({"models":[{
        "slug":run.requested_model,"display_name":"Authored local fixture, no model",
        "description":"Operator-authored local Responses transport metadata; no real model availability claim",
        "base_instructions":if tools {"Local authored MCP qualification. Use only the three advertised finite tools. No model ran."} else {"Local authored transport qualification. Return the requested JSON only. Do not call tools."},
        "default_reasoning_level":run.requested_effort,
        "supported_reasoning_levels":[{"effort":run.requested_effort,"description":"Reviewed local fixture identifier"}],
        "shell_type":"shell_command","visibility":"none","supported_in_api":true,"priority":0,
        "support_verbosity":false,"default_verbosity":null,"apply_patch_tool_type":null,
        "truncation_policy":{"mode":"bytes","limit":32768},"experimental_supported_tools":[],
        "include_skills_usage_instructions":false,"include_plugin_usage_instructions":false,"include_apps_usage_instructions":false,
        "context_window":262144,"tool_mode":"direct"
    }]}))?)
}
fn codex_configuration_mode(
    run: &PreparedRun,
    broker: &OwnedBroker,
    tools: bool,
) -> Result<Vec<u8>> {
    // JSON string escaping is also valid for these bounded ASCII TOML strings.
    // Reject non-token model names rather than permit configuration injection.
    if !token(run.requested_model.as_str(), 128) {
        return Err(RuntimeError::Invalid("finite client configuration model"));
    }
    let model = serde_json::to_string(run.requested_model.as_str())?;
    let effort = serde_json::to_string(&run.requested_effort)?;
    let address = broker
        .endpoint
        .strip_prefix("tcp://")
        .ok_or(RuntimeError::Sandbox)?;
    let mut config = format!(
        "model = {model}\nmodel_provider = \"local_fixture\"\nmodel_reasoning_effort = {effort}\nmodel_catalog_json = \"local-model-catalog.json\"\napproval_policy = \"on-request\"\napprovals_reviewer = \"user\"\nsandbox_mode = \"read-only\"\nweb_search = \"disabled\"\n[features]\ncode_mode.enabled = false\ncode_mode_host = false\ncode_mode_only = false\nshell_tool = false\nunified_exec = false\napps = false\n[model_providers.local_fixture]\nname = \"Finite client preparation, local fixture only\"\nbase_url = \"http://{address}/v1\"\nwire_api = \"responses\"\nrequires_openai_auth = false\nsupports_websockets = false\nrequest_max_retries = 0\nstream_max_retries = 0\n"
    );
    if tools {
        config = config.replacen("[features]\n", "[agents]\nenabled = false\n[tools.experimental_request_user_input]\nenabled = false\n[tools.update_plan]\nenabled = false\n[features]\ngoals = false\nview_image = false\nmulti_agent = false\nmulti_agent_v2 = false\n", 1);
        config.push_str("\n[mcp_servers.finite]\ncommand = \"/finite-client\"\nargs = [\"--mcp-tools\"]\nenv = {}\nenv_vars = []\nenabled_tools = [\"read_file\", \"write_file\", \"exec\"]\nrequired = true\nstartup_readiness = \"connection\"\n[mcp_servers.finite.tools.read_file]\napproval_mode = \"approve\"\n[mcp_servers.finite.tools.write_file]\napproval_mode = \"approve\"\n[mcp_servers.finite.tools.exec]\napproval_mode = \"approve\"\n");
    }
    Ok(config.into_bytes())
}
impl OwnedBroker {
    /// Creates only private local files. No native invocation or provider call.
    pub fn prepare_codex_state(&self, store: &Path, run: &PreparedRun) -> Result<FiniteCodexState> {
        self.prepare_codex_state_mode(store, run, false, None)
    }
    /// Prepares the exact local MCP startup files. This does not enable the
    /// Runtime Tools entrance, invoke a native process or grant any capability.
    pub fn prepare_codex_tools_state(
        &self,
        store: &Path,
        run: &PreparedRun,
    ) -> Result<FiniteCodexState> {
        self.prepare_codex_state_mode(store, run, true, None)
    }
    fn prepare_codex_state_mode(
        &self,
        store: &Path,
        run: &PreparedRun,
        tools: bool,
        subscription: Option<SubscriptionPreparation>,
    ) -> Result<FiniteCodexState> {
        prepared_digest(run)?;
        let store_text = store
            .to_str()
            .ok_or(RuntimeError::Invalid("finite client store path"))?;
        directory(store_text, true)?;
        // Even a read-only store ancestor would let generated files alias task input.
        if store.starts_with(&run.cwd) || Path::new(&run.cwd).starts_with(store) {
            return Err(RuntimeError::Scope);
        }
        let bytes = codex_configuration_for(run, self, tools, subscription.as_ref())?;
        let state =
            HostState::create(store, "codex", &BTreeMap::new())?.ok_or(RuntimeError::Sandbox)?;
        let tmp = state.path().join("tmp");
        fs::DirBuilder::new().mode(0o700).create(&tmp)?;
        let path = state.path().join("config.toml");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        let configuration = FiniteClientFile {
            path: path
                .to_str()
                .ok_or(RuntimeError::Invalid("finite client config path"))?
                .into(),
            sha256: content_digest(&bytes),
        };
        file_identity(&configuration, false)?;
        let tmp_identity = directory(
            tmp.to_str()
                .ok_or(RuntimeError::Invalid("finite client tmp path"))?,
            true,
        )?;
        // Only this new private state is initialized; no personal installation ID
        // or credential is imported. A valid v4-shaped ID avoids native chmod.
        let mut nonce = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        let hex = content_digest(&nonce);
        let id = format!(
            "{}-{}-4{}-8{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[13..16],
            &hex[17..20],
            &hex[20..32]
        );
        let installation_path = tmp.join("installation_id");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&installation_path)?;
        file.write_all(id.as_bytes())?;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.sync_all()?;
        let installation = FiniteClientFile {
            path: installation_path
                .to_str()
                .ok_or(RuntimeError::Invalid("finite client installation path"))?
                .into(),
            sha256: content_digest(id.as_bytes()),
        };
        let catalog_bytes = codex_catalog_for(run, tools, subscription.as_ref())?;
        let catalog_path = state.path().join("local-model-catalog.json");
        let mut catalog_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&catalog_path)?;
        catalog_file.write_all(&catalog_bytes)?;
        catalog_file.sync_all()?;
        let catalog = FiniteClientFile {
            path: catalog_path
                .to_str()
                .ok_or(RuntimeError::Invalid("finite catalog path"))?
                .into(),
            sha256: content_digest(&catalog_bytes),
        };
        let catalog_identity = file_identity(&catalog, false)?;
        let installation_identity = file_identity(&installation, false)?;
        let alias = state.path().join("installation_id");
        std::os::unix::fs::symlink("tmp/installation_id", &alias)?;
        let installation_alias = installation_alias(&alias)?;
        Ok(FiniteCodexState {
            state,
            startup: FiniteCodexStartup {
                tools,
                subscription,
                configuration,
                catalog,
                catalog_identity,
                tmp_identity,
                installation,
                installation_identity,
                installation_alias,
            },
        })
    }
}
impl FiniteClientReview {
    /// Consumes the producer's state. An arbitrary manifest path cannot opt in
    /// to launch preparation or reconstruct this nonserializable owner.
    pub fn with_codex_state(
        manifest: FiniteClientManifest,
        run: &PreparedRun,
        broker: OwnedBroker,
        limits: ResourceLimits,
        state: FiniteCodexState,
    ) -> Result<Self> {
        if Path::new(&manifest.private_state) != state.path()
            || &manifest.configuration != state.configuration()
        {
            return Err(RuntimeError::Integrity("finite client state binding"));
        }
        state.check(run, &broker)?;
        let mut review = Self::with_resources(manifest, run, broker, limits)?;
        let assets = FiniteClientAssets::prepare(&review.manifest, run)?;
        let bytes = serde_json::to_vec(&(
            "finite-client-copy-review-v2",
            &state.startup_binding()?,
            &review.approval,
            &assets.pins,
            assets
                .identities
                .iter()
                .map(|pin| &pin.identity)
                .collect::<Vec<_>>(),
            assets
                .directories
                .iter()
                .map(|pin| &pin.identity)
                .collect::<Vec<_>>(),
        ))?;
        if bytes.len() > MAX_CONTRACT {
            return Err(RuntimeError::Limit);
        }
        review.approval = content_digest(&bytes);
        review.owned_assets = Some(assets);
        review.owned_state = Some(state);
        review.check_files()?;
        Ok(review)
    }
}
impl ApprovedFiniteClient {
    /// Runs only the retained helper's bounded `--probe`, with the exact reviewed
    /// limits. This is a resource preflight, not native launch, OS qualification,
    /// provider admission or a persisted capability proof. A successful probe
    /// observes applied rlimits; it does not establish task-level containment.
    /// The caller must trust the helper integration code, as for ResourceSupervisor.
    pub async fn probe_owned_resources(&self, limits: &ResourceLimits) -> Result<()> {
        let reviewed = &self.reviewed;
        if limits.args()? != reviewed.resource_arguments {
            return Err(RuntimeError::Integrity("finite client resource limits"));
        }
        reviewed.check_files()?;
        let assets = reviewed
            .owned_assets
            .as_ref()
            .ok_or(RuntimeError::Sandbox)?;
        reviewed.owned_state.as_ref().ok_or(RuntimeError::Sandbox)?;
        let helper = &assets.pins[2];
        let expected = BTreeMap::from([(
            std::path::PathBuf::from(&helper.path),
            helper.sha256.clone(),
        )]);
        let result = crate::ResourceSupervisor::probe_expected(
            Path::new(&helper.path),
            limits.clone(),
            crate::DenySandbox,
            &expected,
        )
        .await;
        // Recheck even after a refusal: a changed composition is not an OS verdict.
        reviewed.check_files()?;
        result.map(|_| ())
    }
}
impl ApprovedFiniteClient {
    /// Checks the helper's concrete current limits as well as the live contract.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_with_resources<'a>(
        &'a self,
        run: &PreparedRun,
        host: &HostSnapshot,
        source: &EvidenceSource,
        verifier: &StoredCapabilityProofVerifier,
        now: u64,
        limits: &ResourceLimits,
    ) -> Result<FiniteClientValidation<'a>> {
        if limits.args()? != self.reviewed.resource_arguments {
            return Err(RuntimeError::Integrity("finite client resource limits"));
        }
        self.validate(run, host, source, verifier, now)
    }
}

/// Private review data only. No conversion to Command, execution receipt or grant.
#[derive(serde::Serialize)]
pub struct FiniteClientInvocation {
    program: String,
    argv: Vec<String>,
    environment: BTreeMap<String, String>,
    clear_environment: bool,
    cwd: String,
}
#[derive(serde::Serialize)]
pub struct FiniteClientLaunchPlan {
    supervised: FiniteClientInvocation,
    native: FiniteClientInvocation,
    stdin_sha256: String,
    timeout_ms: u64,
    max_output_bytes: usize,
    read_only_assets: Vec<FiniteClientFile>,
}
impl FiniteClientValidation<'_> {
    /// Derives the known Seatbelt/helper composition as a private preview.
    /// This remains unavailable on other OSes and never constructs a process.
    pub fn launch_plan(&self) -> Result<FiniteClientLaunchPlan> {
        let r = self.reviewed;
        r.owned_state.as_ref().ok_or(RuntimeError::Sandbox)?;
        if !cfg!(target_os = "macos") {
            return Err(RuntimeError::Sandbox);
        }
        r.check_files()?;
        let assets = r.owned_assets.as_ref().ok_or(RuntimeError::Sandbox)?;
        let environment = r
            .owned_state
            .as_ref()
            .ok_or(RuntimeError::Sandbox)?
            .native_environment();
        let native = FiniteClientInvocation {
            program: assets.pins[1].path.clone(),
            argv: vec!["app-server".into(), "--listen".into(), "stdio://".into()],
            environment: environment.clone(),
            clear_environment: true,
            cwd: r.run.cwd.clone(),
        };
        let mut argv = r.resource_arguments.clone();
        argv.extend([
            "--supervise-v1".into(),
            assets.pins[3].path.clone(),
            "-f".into(),
            assets.pins[4].path.clone(),
            assets.pins[0].path.clone(),
        ]);
        argv.extend(r.run.argv.clone());
        let mut worker_environment = environment;
        worker_environment.insert("ROUTER_RUNTIME_SUPERVISION".into(), "framed-v1".into());
        worker_environment.insert(
            "ROUTER_RUNTIME_CONTAINMENT".into(),
            "process-group-v1".into(),
        );
        Ok(FiniteClientLaunchPlan {
            supervised: FiniteClientInvocation {
                program: assets.pins[2].path.clone(),
                argv,
                environment: worker_environment,
                clear_environment: true,
                cwd: r.run.cwd.clone(),
            },
            native,
            stdin_sha256: content_digest(r.run.stdin.as_bytes()),
            timeout_ms: r.run.timeout_ms,
            max_output_bytes: r.run.max_output_bytes,
            read_only_assets: assets.pins.to_vec(),
        })
    }
}

#[cfg(test)]
mod resource_binding_tests {
    use super::*;
    use router_types::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn same_listener_and_assets_require_new_digest_for_each_resource_change() {
        let temp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let root = temp.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        let state = root.join("state");
        for path in [&workspace, &state] {
            fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        }
        let pin = |name: &str, executable: bool| {
            let path = root.join(name);
            fs::write(&path, name).unwrap();
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(if executable { 0o500 } else { 0o400 }),
            )
            .unwrap();
            FiniteClientFile {
                path: path.to_str().unwrap().into(),
                sha256: content_digest(name.as_bytes()),
            }
        };
        let broker =
            OwnedBroker::from_listener(TcpListener::bind(("127.0.0.1", 0)).unwrap()).unwrap();
        let manifest = FiniteClientManifest {
            schema_version: 1,
            task_id: "resource-task".into(),
            host_snapshot_id: "fixture-host".into(),
            client: pin("client", true),
            native: pin("native", true),
            helper: pin("helper", true),
            wrapper: pin("wrapper", true),
            profile: pin("profile", false),
            configuration: pin("config", false),
            private_state: state.to_str().unwrap().into(),
            native_version: "fixture-1".into(),
            broker_endpoint: broker.endpoint().into(),
            broker_instance_sha256: broker.instance_sha256().into(),
        };
        let run = PreparedRun {
            schema_version: 1,
            receipt_id: "a".repeat(64),
            source_state: "b".repeat(40),
            scope: vec!["patch.txt".into()],
            authorization_digest: "c".repeat(64),
            snapshot_hash: "d".repeat(64),
            host: HarnessId::parse("codex").unwrap(),
            requested_model: ModelId::parse("fixture-model").unwrap(),
            requested_effort: EffortLevel::Low,
            program: "finite-client".into(),
            argv: vec!["--worker".into()],
            cwd: workspace.to_str().unwrap().into(),
            stdin: PreparedInput::new(b"task".to_vec()),
            mode: ExecutionMode::Execute,
            target: ExecutionTarget::ExternalWorker,
            sandbox: ExecutionSandbox::WorkspaceWrite,
            timeout_ms: 3000,
            max_output_bytes: 4096,
            degradations: vec![],
            missing_runtime_evidence: vec![],
            parent_model_changed: false,
        };
        let limits = ResourceLimits::default();
        let mut review =
            FiniteClientReview::with_resources(manifest.clone(), &run, broker, limits.clone())
                .unwrap();
        let approval = review.approval_digest().to_owned();
        for changed in [
            ResourceLimits {
                cpu_seconds: 301,
                ..limits.clone()
            },
            ResourceLimits {
                address_space_bytes: None,
                ..limits.clone()
            },
            ResourceLimits {
                max_open_files: 257,
                ..limits.clone()
            },
            ResourceLimits {
                max_processes: 257,
                ..limits.clone()
            },
            ResourceLimits {
                max_file_bytes: 1024,
                ..limits.clone()
            },
        ] {
            // Move the exact listener instance, retaining the same files and modes.
            let changed_review =
                FiniteClientReview::with_resources(manifest.clone(), &run, review.broker, changed)
                    .unwrap();
            assert_ne!(approval, changed_review.approval_digest());
            review = FiniteClientReview::with_resources(
                manifest.clone(),
                &run,
                changed_review.broker,
                limits.clone(),
            )
            .unwrap();
            assert_eq!(approval, review.approval_digest());
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "finite_client/linux_qualification.rs"]
mod linux_qualification;

#[cfg(test)]
#[path = "finite_client/ownership_tests.rs"]
mod ownership_tests;

mod namespace_state;
pub(crate) use namespace_state::FiniteClientResources;

mod runtime_binding;
mod verification;
pub(crate) use runtime_binding::bind_runtime_definition;
pub use runtime_binding::{ApprovedFiniteClientRun, PendingFiniteClientRun};
pub use verification::FiniteClientVerifier;

mod linux_backend;
use linux_backend::FiniteClientNamespace;
pub use linux_backend::LINUX_FINITE_PROFILE_V2;
pub(crate) use linux_backend::LinuxFiniteSupervisor;

mod write_workspace;
pub use write_workspace::{FiniteClientWorkspace, FiniteOutputMode};

#[cfg(all(test, target_os = "linux"))]
#[path = "finite_client/native_tools_tests.rs"]
mod native_tools_tests;

mod tools_state;
pub use tools_state::LINUX_FINITE_TOOLS_PROFILE_V3;

#[cfg(test)]
mod coupling_tests;

pub(crate) use namespace_state::StoppedToolsObservation;
