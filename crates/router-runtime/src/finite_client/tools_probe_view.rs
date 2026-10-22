//! Fresh public-only diagnostic view. No worker-provided path grants authority.
use super::*;
use crate::finite_tools::{FilePolicy, ToolOwnerProbe, ToolTerminal};
use std::io::{Seek, SeekFrom};
impl ToolsProbeView {
    pub(super) fn prepare(state: &HostState, probe: &ProbeView) -> Result<Self> {
        state.check_owned_resources()?;
        let resources = state.finite_resources()?;
        let tools = resources
            .reviewed
            .owned_tools
            .as_ref()
            .ok_or(RuntimeError::Sandbox)?;
        let staging = probe.temporary.join("public-probe");
        fs::DirBuilder::new().mode(0o700).create(&staging)?;
        for (name, expected) in &tools.boot.sandbox.public {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(tools.staging.join(name))?;
            let mode = file.metadata()?.mode() & 0o777;
            let mut bytes = Vec::new();
            file.take(32769).read_to_end(&mut bytes)?;
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
        let scratch = probe.temporary.join("probe-observation-scratch");
        fs::DirBuilder::new().mode(0o700).create(&scratch)?;
        let policy = FilePolicy::open(
            &staging,
            &scratch,
            tools.boot.sandbox.public.clone(),
            &tools.boot.sandbox.output,
            tools.boot.preimage.clone(),
            tools.boot.limits.clone(),
        )
        .map_err(|_| RuntimeError::Integrity("finite probe inventory"))?;
        let terminal = probe.temporary.join("probe-terminal.json");
        let terminal_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&terminal)?;
        let terminal_identity = FileIdentity::from(&terminal_file.metadata()?);
        let binding = crate::digest(
            "finite-tools-probe-view-v1",
            &(
                &tools.boot.binding,
                &probe.nonce,
                policy
                    .preparation_binding()
                    .map_err(|_| RuntimeError::Integrity("finite probe binding"))?,
                &terminal_identity,
            ),
        )?;
        let mut boot = tools.boot.clone();
        boot.binding = binding.clone();
        boot.probe = Some(ToolOwnerProbe {
            denied_port: probe.denied_port,
            hidden: probe.hidden.to_str().ok_or(RuntimeError::Scope)?.into(),
            control: state
                .path()
                .join("tmp")
                .join(probe.control.file_name().ok_or(RuntimeError::Scope)?)
                .to_str()
                .ok_or(RuntimeError::Scope)?
                .into(),
            nonce: probe.nonce.clone(),
        });
        let bytes = serde_json::to_vec(&boot)?;
        if bytes.len() > MAX_CONTRACT {
            return Err(RuntimeError::Limit);
        }
        let bootstrap = probe.temporary.join("probe-boot.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&bootstrap)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(Self {
            staging,
            bootstrap,
            terminal,
            terminal_file,
            terminal_identity,
            policy,
            binding,
        })
    }
    /// The caller must retain the exact namespace-stop proof through this read.
    pub(super) fn verify(&self, nonce: &str) -> Result<()> {
        let meta = self.terminal_file.metadata()?;
        if FileIdentity::from(&meta) != self.terminal_identity
            || FileIdentity::from(&fs::symlink_metadata(&self.terminal)?) != self.terminal_identity
            || meta.nlink() != 1
            || meta.len() == 0
            || meta.len() > 16384
        {
            return Err(RuntimeError::Integrity("finite probe terminal identity"));
        }
        let mut file = self.terminal_file.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.take(16385).read_to_end(&mut bytes)?;
        let value = router_adapter_api::strict_json_limited(&bytes, 16384)
            .map_err(|_| RuntimeError::Integrity("finite probe terminal JSON"))?;
        let terminal: ToolTerminal = serde_json::from_value(value)
            .map_err(|_| RuntimeError::Integrity("finite probe terminal schema"))?;
        let names = [
            "read_file",
            "write_file",
            "write_file",
            "exec",
            "exec",
            "exec",
        ];
        if terminal.schema_version != 1
            || terminal.binding != self.binding
            || !terminal.complete
            || terminal.halted
            || terminal.journal.len() != names.len()
            || terminal
                .journal
                .iter()
                .zip(names)
                .enumerate()
                .any(|(i, (v, n))| {
                    v.index as usize != i + 1 || v.tool != n || v.status != "returned"
                })
        {
            return Err(RuntimeError::Integrity("finite probe terminal binding"));
        }
        let output = terminal
            .output
            .as_ref()
            .ok_or(RuntimeError::Integrity("finite probe output"))?;
        if output.sha256 != content_digest(nonce.as_bytes()) || output.bytes != nonce.len() as u64 {
            return Err(RuntimeError::Integrity("finite probe write effect"));
        }
        self.policy
            .verify_terminal_output(output)
            .map_err(|_| RuntimeError::Integrity("finite probe terminal files"))
    }
}
