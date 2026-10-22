use crate::{
    Cancellation, Result, RuntimeError, SandboxPolicy, SandboxSupervisor, process::capture,
};
use router_types::{MemoryEnforcement, PreparedRun};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use tokio::process::Command;

#[derive(Clone, Debug)]
pub struct ResourceLimits {
    pub cpu_seconds: u64,
    pub address_space_bytes: Option<u64>,
    pub max_open_files: u64,
    pub max_processes: u64,
    pub max_file_bytes: u64,
}
impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_seconds: 300,
            address_space_bytes: Some(8 * 1024 * 1024 * 1024),
            max_open_files: 256,
            max_processes: 256,
            max_file_bytes: 16 * 1024 * 1024,
        }
    }
}
impl ResourceLimits {
    pub(crate) fn args(&self) -> Result<Vec<String>> {
        if !(1..=86_400).contains(&self.cpu_seconds)
            || self.address_space_bytes.is_some_and(|value| {
                !(64 * 1024 * 1024..=1024 * 1024 * 1024 * 1024).contains(&value)
            })
            || !(16..=4096).contains(&self.max_open_files)
            || !(1..=4096).contains(&self.max_processes)
            || !(1024..=1024 * 1024 * 1024).contains(&self.max_file_bytes)
        {
            return Err(RuntimeError::Limit);
        }
        Ok([
            ("--cpu-seconds", self.cpu_seconds.to_string()),
            (
                "--address-space-bytes",
                self.address_space_bytes
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".into()),
            ),
            ("--max-open-files", self.max_open_files.to_string()),
            ("--max-processes", self.max_processes.to_string()),
            ("--max-file-bytes", self.max_file_bytes.to_string()),
        ]
        .into_iter()
        .flat_map(|(flag, value)| [flag.into(), value])
        .collect())
    }
}
/// Probe-bound wrapper around a native sandbox. The helper binary is trusted
/// integration code. Its bytes are hashed just before each launch, but the
/// process is then started by path, so hash and exec are separate steps: a
/// principal able to write the helper file or its directory can swap it in
/// between (TOCTOU). The check detects an earlier replacement, not a racing
/// one; install the helper (and native binaries, hashed the same way by the
/// sandboxes) where the workload and other users cannot write.
pub struct ResourceSupervisor<S> {
    inner: S,
    helper: PathBuf,
    helper_hash: String,
    limits: ResourceLimits,
}
impl<S: SandboxSupervisor> ResourceSupervisor<S> {
    pub async fn probe(helper: &Path, limits: ResourceLimits, inner: S) -> Result<Self> {
        Self::probe_inner(helper, limits, inner, None).await
    }
    pub async fn probe_expected(
        helper: &Path,
        limits: ResourceLimits,
        inner: S,
        expected: &BTreeMap<PathBuf, String>,
    ) -> Result<Self> {
        Self::probe_inner(helper, limits, inner, Some(expected)).await
    }
    async fn probe_inner(
        helper: &Path,
        limits: ResourceLimits,
        inner: S,
        expected_hashes: Option<&BTreeMap<PathBuf, String>>,
    ) -> Result<Self> {
        let bytes = read_helper(helper)?;
        let helper_hash = router_adapter_api::content_digest(&bytes);
        crate::sandbox::check_expected(helper, &helper_hash, expected_hashes)?;
        let mut command = Command::new(helper);
        command
            .args(limits.args()?)
            .arg("--probe")
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        let result = capture(command, vec![], 3_000, 8192, 0, &Cancellation::default()).await?;
        if result.stderr == b"sandbox-helper.setrlimit.address_space\n" {
            return Err(RuntimeError::ResourceUnsupported("address_space"));
        }
        let expected = format!(
            "router-sandbox-helper-v1:limits-applied:address-space={}\n",
            if limits.address_space_bytes.is_some() {
                "enforced"
            } else {
                "not-requested"
            }
        );
        if result.outcome.exit_code != Some(0) || result.stdout != expected.as_bytes() {
            return Err(RuntimeError::Sandbox);
        }
        Ok(Self {
            inner,
            helper: helper.into(),
            helper_hash,
            limits,
        })
    }
}
impl<S: SandboxSupervisor> SandboxSupervisor for ResourceSupervisor<S> {
    fn create_host_state(
        &self,
        store: &Path,
        run: &PreparedRun,
    ) -> Result<Option<crate::HostState>> {
        self.inner.create_host_state(store, run)
    }
    fn command(&self, run: &PreparedRun, policy: &SandboxPolicy) -> Result<Command> {
        if router_adapter_api::content_digest(&read_helper(&self.helper)?) != self.helper_hash {
            return Err(RuntimeError::Integrity("sandbox helper changed"));
        }
        let inner = self.inner.command(run, policy)?;
        let inner = inner.as_std();
        let mut command = Command::new(&self.helper);
        command
            .args(self.limits.args()?)
            .arg("--supervise-v1")
            .arg(inner.get_program())
            .args(inner.get_args())
            .env_clear();
        for (key, value) in inner.get_envs() {
            if let Some(value) = value {
                command.env(key, value);
            } else {
                command.env_remove(key);
            }
        }
        if let Some(cwd) = inner.get_current_dir() {
            command.current_dir(cwd);
        }
        command.env("ROUTER_RUNTIME_SUPERVISION", "framed-v1");
        command.env(
            "ROUTER_RUNTIME_CONTAINMENT",
            if self.inner.pid_namespace_isolated() {
                "pid-namespace-v1"
            } else {
                "process-group-v1"
            },
        );
        Ok(command)
    }
    fn pid_namespace_isolated(&self) -> bool {
        self.inner.pid_namespace_isolated()
    }
    fn parent_lifetime_enforced(&self) -> bool {
        true
    }
    fn resource_limits_enforced(&self) -> bool {
        true
    }
    fn memory_enforcement(&self) -> MemoryEnforcement {
        if self.limits.address_space_bytes.is_some() {
            MemoryEnforcement::Enforced
        } else {
            MemoryEnforcement::NotRequested
        }
    }
}
fn read_helper(path: &Path) -> Result<Vec<u8>> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    if !path.is_absolute() || fs::canonicalize(path)? != path {
        return Err(RuntimeError::Sandbox);
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > 32 * 1024 * 1024 {
        return Err(RuntimeError::Limit);
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(RuntimeError::Limit);
    }
    Ok(bytes)
}
