//! Producer-owned MCP preparation. Worker JSON alone grants no authority.
use super::*;
use crate::finite_tools::{FilePolicy, Limits, ToolOwnerBoot, ToolTerminal};
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;

pub const LINUX_FINITE_TOOLS_PROFILE_V3: &[u8] =
    b"{\"kind\":\"linux-isolated-finite-tools-v3\",\"schema_version\":1}\n";
const RUSTC: &str = "/usr/local/rustup/toolchains/1.85.1-aarch64-unknown-linux-gnu/bin/rustc";
const LINKER: &str = "/usr/bin/aarch64-linux-gnu-gcc-12";
struct SystemProgram {
    pin: FiniteClientFile,
    identity: FileIdentity,
    file: File,
}
impl SystemProgram {
    fn open(path: &str) -> Result<Self> {
        if fs::canonicalize(path)? != Path::new(path) {
            return Err(RuntimeError::Sandbox);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.len() > MAX_BINARY
            || meta.mode() & 0o7022 != 0
            || meta.mode() & 0o111 == 0
            || (meta.uid() != 0 && meta.uid() != rustix::process::geteuid().as_raw())
        {
            return Err(RuntimeError::Sandbox);
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_BINARY + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BINARY
            || bytes.len() as u64 != meta.len()
            || FileIdentity::from(&file.metadata()?) != FileIdentity::from(&meta)
        {
            return Err(RuntimeError::Integrity("finite system program"));
        }
        Ok(Self {
            pin: FiniteClientFile {
                path: path.into(),
                sha256: content_digest(&bytes),
            },
            identity: FileIdentity::from(&meta),
            file,
        })
    }
    fn check(&self) -> Result<()> {
        let current = Self::open(&self.pin.path)?;
        if current.pin != self.pin
            || current.identity != self.identity
            || FileIdentity::from(&self.file.metadata()?) != self.identity
        {
            return Err(RuntimeError::Integrity("finite system program changed"));
        }
        Ok(())
    }
}
pub(super) struct PreparedTools {
    pub(super) boot: ToolOwnerBoot,
    pub(super) bootstrap: FiniteClientFile,
    bootstrap_identity: PinnedIdentity,
    pub(super) terminal_path: PathBuf,
    terminal: File,
    terminal_identity: FileIdentity,
    compiler: FiniteClientFile,
    compiler_identity: PinnedIdentity,
    system: Vec<SystemProgram>,
    policy: FilePolicy,
    original_policy: Option<FilePolicy>,
    observation_state: Option<HostState>,
    pub(super) staging: PathBuf,
    staging_identity: PinnedIdentity,
}
impl PreparedTools {
    pub(super) fn check(&self) -> Result<()> {
        if file_identity(&self.bootstrap, false)?.identity != self.bootstrap_identity.identity
            || file_identity(&self.compiler, true)?.identity != self.compiler_identity.identity
            || FileIdentity::from(&self.terminal.metadata()?) != self.terminal_identity
            || FileIdentity::from(&fs::symlink_metadata(&self.terminal_path)?)
                != self.terminal_identity
            || self.terminal.metadata()?.nlink() != 1
            || self.terminal.metadata()?.len() != 0
        {
            return Err(RuntimeError::Integrity("finite tools preparation changed"));
        }
        if directory(self.staging.to_str().ok_or(RuntimeError::Scope)?, true)?.identity
            != self.staging_identity.identity
        {
            return Err(RuntimeError::Integrity("finite tools staging directory"));
        }
        self.original_policy
            .as_ref()
            .ok_or(RuntimeError::Integrity(
                "finite tools original policy taken",
            ))?
            .terminal_output()
            .map_err(|_| RuntimeError::Integrity("finite tools original view changed"))?;
        for file in &self.system {
            file.check()?;
        }
        self.policy
            .terminal_output()
            .map_err(|_| RuntimeError::Integrity("finite tools initial files"))?;
        Ok(())
    }
    /// Caller must hold the exact stopped-namespace proof through this read
    /// and subsequent disposal. Descriptor identity, never pathname JSON,
    /// authenticates the producer-created observation channel.
    pub(crate) fn terminal_observation(
        &self,
        require_complete: bool,
    ) -> Result<Option<ToolTerminal>> {
        if FileIdentity::from(&self.terminal.metadata()?) != self.terminal_identity
            || FileIdentity::from(&fs::symlink_metadata(&self.terminal_path)?)
                != self.terminal_identity
        {
            return Err(RuntimeError::Integrity("finite tools terminal identity"));
        }
        if self.terminal.metadata()?.nlink() != 1 {
            return Err(RuntimeError::Integrity("finite tools terminal links"));
        }
        let length = self.terminal.metadata()?.len();
        if length == 0 && !require_complete {
            return Ok(None);
        }
        if length == 0 || length > 16384 {
            return Err(RuntimeError::Integrity("finite tools terminal bound"));
        }
        let mut file = self.terminal.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.take(16385).read_to_end(&mut bytes)?;
        let value = router_adapter_api::strict_json_limited(&bytes, 16384)
            .map_err(|_| RuntimeError::Integrity("finite tools terminal JSON"))?;
        let observed: ToolTerminal = serde_json::from_value(value)
            .map_err(|_| RuntimeError::Integrity("finite tools terminal schema"))?;
        if observed.schema_version != 1
            || observed.binding != self.boot.binding
            || observed.journal.len() > 64
            || (require_complete && !observed.complete)
            || (observed.complete
                && (observed.halted
                    || observed.output.is_none()
                    || observed.journal.len() > self.boot.limits.max_calls as usize))
            || observed.journal.iter().enumerate().any(|(i, v)| {
                v.index as usize != i + 1
                    || !matches!(
                        v.tool.as_str(),
                        "read_file" | "write_file" | "exec" | "unknown"
                    )
                    || v.status.len() > 64
                    || v.argument_sha256.as_ref().is_some_and(|s| !is_digest(s))
                    || v.file_sha256.as_ref().is_some_and(|s| !is_digest(s))
            })
        {
            return Err(RuntimeError::Integrity("finite tools terminal binding"));
        }
        if observed.complete {
            self.policy
                .verify_terminal_output(
                    observed
                        .output
                        .as_ref()
                        .ok_or(RuntimeError::Integrity("finite tools missing output"))?,
                )
                .map_err(|_| RuntimeError::Integrity("finite tools terminal files"))?;
        }
        Ok(Some(observed))
    }
}
impl FiniteClientReview {
    /// Binds one explicit public inventory and output operation into a new
    /// review. It does not qualify the OS or authorize native execution.
    pub fn with_mcp_tools(
        mut self,
        public: BTreeMap<String, String>,
        limits: Limits,
    ) -> Result<Self> {
        if !cfg!(target_os = "linux")
            || std::env::consts::ARCH != "aarch64"
            || self.owned_tools.is_some()
            || self.resource_arguments != ResourceLimits::default().args()?
            || limits.max_session_ms > self.run.timeout_ms
            || self.run.sandbox != router_types::ExecutionSandbox::WorkspaceWrite
        {
            return Err(RuntimeError::Sandbox);
        }
        self.check_files()?;
        let state = self.owned_state.as_ref().ok_or(RuntimeError::Sandbox)?;
        if !state.startup.tools
            || fs::read(&self.manifest.profile.path)? != LINUX_FINITE_TOOLS_PROFILE_V3
        {
            return Err(RuntimeError::Sandbox);
        }
        let view = self.owned_workspace.as_ref().ok_or(RuntimeError::Sandbox)?;
        let dispatch = view.dispatch();
        let assets = self.owned_assets.as_ref().ok_or(RuntimeError::Sandbox)?;
        let namespace = self.owned_namespace.as_ref().ok_or(RuntimeError::Sandbox)?;
        let home = state.path();
        let tool_directory = home.join("finite-tools");
        fs::DirBuilder::new().mode(0o700).create(&tool_directory)?;
        // This observation-only owner is never mounted or handed to a child.
        // Retain it through artifact capture so scratch identity verification
        // remains intact after the launched native home is disposed.
        let observation_state = HostState::create(
            home.parent().ok_or(RuntimeError::Scope)?,
            "codex",
            &BTreeMap::new(),
        )?
        .ok_or(RuntimeError::Sandbox)?;
        let scratch = observation_state.path().join("observation-scratch");
        fs::DirBuilder::new().mode(0o700).create(&scratch)?;
        let original_policy = FilePolicy::open(
            Path::new(&self.run.cwd),
            &scratch,
            public.clone(),
            &dispatch.relative,
            dispatch.preimage.clone(),
            limits.clone(),
        )
        .map_err(|_| RuntimeError::Integrity("finite tools public inventory"))?;
        let staging = tool_directory.join("public-staging");
        fs::DirBuilder::new().mode(0o700).create(&staging)?;
        for (name, expected) in &public {
            // The retained original policy validated flat names, hashes and
            // identities. Copy only this explicit public inventory, never .git
            // or a private ancestor. The original view is not worker-writable.
            let path = Path::new(&self.run.cwd).join(name);
            let source = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(&path)?;
            let mode = source.metadata()?.mode() & 0o777;
            let mut bytes = Vec::new();
            source.take(32769).read_to_end(&mut bytes)?;
            if bytes.len() > 32768 || content_digest(&bytes) != *expected {
                return Err(RuntimeError::SourceChanged);
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(staging.join(name))?;
            output.write_all(&bytes)?;
            output.sync_all()?;
        }
        let staging_identity = directory(staging.to_str().ok_or(RuntimeError::Scope)?, true)?;
        let stage_scratch = tool_directory.join("staging-preparation-scratch");
        fs::DirBuilder::new().mode(0o700).create(&stage_scratch)?;
        let policy = FilePolicy::open(
            &staging,
            &stage_scratch,
            public.clone(),
            &dispatch.relative,
            dispatch.preimage.clone(),
            limits.clone(),
        )
        .map_err(|_| RuntimeError::Integrity("finite tools staged public inventory"))?;
        let system = vec![SystemProgram::open(RUSTC)?, SystemProgram::open(LINKER)?];
        let compiler_path = tool_directory.join("rustc");
        let mut source = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&assets.pins[0].path)?;
        let mut compiler = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&compiler_path)?;
        std::io::copy(
            &mut Read::by_ref(&mut source).take(MAX_BINARY + 1),
            &mut compiler,
        )?;
        compiler.sync_all()?;
        let compiler = FiniteClientFile {
            path: compiler_path.to_str().ok_or(RuntimeError::Scope)?.into(),
            sha256: assets.pins[0].sha256.clone(),
        };
        let compiler_identity = file_identity(&compiler, true)?;
        let terminal_path = tool_directory.join("terminal.json");
        let terminal = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&terminal_path)?;
        let terminal_identity = FileIdentity::from(&terminal.metadata()?);
        let binding = crate::digest(
            "finite-mcp-owner-v1",
            &(
                &self.approval,
                &staging,
                &staging_identity.identity,
                &original_policy
                    .preparation_binding()
                    .map_err(|_| RuntimeError::Integrity("finite tools original binding"))?,
                &policy
                    .preparation_binding()
                    .map_err(|_| RuntimeError::Integrity("finite tools staged binding"))?,
                &public,
                &limits,
                &compiler,
                &compiler_identity.identity,
                system
                    .iter()
                    .map(|f| (&f.pin, &f.identity))
                    .collect::<Vec<_>>(),
                &terminal_identity,
            ),
        )?;
        let mut reads: Vec<String> = assets
            .copies
            .iter()
            .map(|p| p.directory().to_string_lossy().into_owned())
            .collect();
        reads.push(namespace.copy.directory().to_string_lossy().into_owned());
        let context = serde_json::json!({"native":assets.pins[1].path,"native_sha256":assets.pins[1].sha256,"native_version":self.manifest.native_version,"home":home,"cwd":self.run.cwd,"configuration_sha256":assets.pins[5].sha256,"model":self.run.requested_model,"effort":self.run.requested_effort,"stdin_sha256":content_digest(self.run.stdin.as_bytes()),"max_output_bytes":self.run.max_output_bytes.min(65536),"replacement":null});
        let boot = ToolOwnerBoot {
            sandbox: crate::finite_tools::ExecSandbox {
                namespace: namespace.pin.clone(),
                helper: assets.pins[2].clone(),
                guard: assets.pins[3].clone(),
                compiler: compiler.clone(),
                root: PathBuf::from(&self.run.cwd),
                scratch: "/router-tools/scratch".into(),
                control: "/router-tools/control".into(),
                public,
                output: dispatch.relative,
            },
            limits,
            preimage: dispatch.preimage,
            binding,
            client: assets.pins[0].clone(),
            home: home.to_str().ok_or(RuntimeError::Scope)?.into(),
            broker_port: self.broker.listener.local_addr()?.port(),
            reads,
            context: serde_json::to_string(&context)?,
            probe: None,
        };
        let bytes = serde_json::to_vec(&boot)?;
        if bytes.len() > MAX_CONTRACT {
            return Err(RuntimeError::Limit);
        }
        let path = tool_directory.join("boot.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        let bootstrap = FiniteClientFile {
            path: path.to_str().ok_or(RuntimeError::Scope)?.into(),
            sha256: content_digest(&bytes),
        };
        let bootstrap_identity = file_identity(&bootstrap, false)?;
        self.approval = crate::digest(
            "finite-client-mcp-review-v1",
            &(
                &self.approval,
                &bootstrap,
                &bootstrap_identity.identity,
                &terminal_identity,
            ),
        )?;
        self.owned_tools = Some(PreparedTools {
            boot,
            bootstrap,
            bootstrap_identity,
            terminal_path,
            terminal,
            terminal_identity,
            compiler,
            compiler_identity,
            system,
            policy,
            original_policy: Some(original_policy),
            observation_state: Some(observation_state),
            staging,
            staging_identity,
        });
        self.check_files()?;
        Ok(self)
    }
}

/// Holds the submitted inode and observation-only scratch through capture.
/// Neither the guard nor its owners can be reconstructed from worker JSON.
pub(crate) struct VerifiedToolsOutput {
    policy: FilePolicy,
    output: crate::finite_tools::ToolOutput,
    file: File,
    _observation_state: HostState,
}
impl VerifiedToolsOutput {
    pub(crate) fn check(&self) -> Result<()> {
        let meta = self.file.metadata()?;
        if (meta.dev(), meta.ino(), meta.mode(), meta.len())
            != (
                self.output.device,
                self.output.inode,
                self.output.mode,
                self.output.bytes,
            )
        {
            return Err(RuntimeError::Integrity("finite submitted inode changed"));
        }
        self.policy
            .verify_terminal_output(&self.output)
            .map_err(|_| RuntimeError::Integrity("finite submitted artifact changed"))
    }
}
impl PreparedTools {
    pub(super) fn promote_output(
        &mut self,
        workspace: &FiniteClientWorkspace,
        observed: &ToolTerminal,
    ) -> Result<Option<VerifiedToolsOutput>> {
        if !observed.complete {
            return Ok(None);
        }
        let output = observed
            .output
            .as_ref()
            .ok_or(RuntimeError::Integrity("finite tools output absent"))?;
        let policy = self.original_policy.take().ok_or(RuntimeError::Integrity(
            "finite tools promotion already taken",
        ))?;
        policy.terminal_output().map_err(|_| {
            RuntimeError::Integrity("finite tools original changed before promotion")
        })?;
        let source = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(self.staging.join(&output.relative))?;
        let file = workspace.promote_tools_output(source, output)?;
        let meta = file.metadata()?;
        let submitted = crate::finite_tools::ToolOutput {
            relative: output.relative.clone(),
            sha256: output.sha256.clone(),
            device: meta.dev(),
            inode: meta.ino(),
            mode: meta.mode(),
            bytes: meta.len(),
        };
        let observation_state = self
            .observation_state
            .take()
            .ok_or(RuntimeError::Integrity(
                "finite tools observation owner taken",
            ))?;
        let verified = VerifiedToolsOutput {
            policy,
            output: submitted,
            file,
            _observation_state: observation_state,
        };
        verified.check()?;
        Ok(Some(verified))
    }
}
