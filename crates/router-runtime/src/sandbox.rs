//! The supervisor is trusted code, never an authority deserialized from a file.
use crate::{
    Cancellation, NetworkAuthority, Result, RuntimeError, process::capture, workspace::safe_scope,
};
use router_types::{ExecutionSandbox, PreparedRun};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use tokio::process::Command;

pub struct SandboxPolicy<'a> {
    pub network: NetworkAuthority,
    pub host_state: Option<&'a crate::HostState>,
}
/// Implementors must enforce read/write/network restrictions in the child and
/// every descendant. A declared host capability or receipt is not sufficient.
pub trait SandboxSupervisor: Send + Sync {
    fn create_host_state(
        &self,
        _store: &Path,
        _run: &PreparedRun,
    ) -> Result<Option<crate::HostState>> {
        Ok(None)
    }
    fn command(&self, run: &PreparedRun, policy: &SandboxPolicy) -> Result<Command>;
    /// True only for a probe-bound sandbox whose workers enter a PID namespace.
    fn pid_namespace_isolated(&self) -> bool {
        false
    }
    /// A surviving helper observes parent EOF. Recovery additionally requires a
    /// durable lease; this flag alone is not proof that descendants have exited.
    fn parent_lifetime_enforced(&self) -> bool {
        false
    }
    fn resource_limits_enforced(&self) -> bool {
        false
    }
    fn memory_enforcement(&self) -> router_types::MemoryEnforcement {
        router_types::MemoryEnforcement::Unsupported
    }
}
pub struct DenySandbox;
impl SandboxSupervisor for DenySandbox {
    fn command(&self, _: &PreparedRun, _: &SandboxPolicy) -> Result<Command> {
        Err(RuntimeError::Sandbox)
    }
}

/// Native macOS Seatbelt, available only after live deny/allow/network probes.
/// Environment and extra readable roots are explicit trusted integration input.
pub struct SeatbeltSandbox {
    wrapper_hash: String,
    programs: BTreeMap<String, PathBuf>,
    program_hashes: BTreeMap<String, String>,
    read_roots: Vec<PathBuf>,
    environment: BTreeMap<String, String>,
    dns_resolution: DnsEvidence,
}
/// Whether a name lookup through the system resolver worked from inside a
/// `NetworkAuthority::Deny` profile. Evidence only: it never fails a probe or a run.
/// `Resolved` shows that `mach-lookup` reaches the resolver daemon, so
/// `NetworkAuthority::Deny` does not prove the absence of DNS or LaunchServices channels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsEvidence {
    /// The control lookup resolved but the sandboxed one did not. One failed
    /// lookup, not proof that no DNS channel exists.
    NotResolvedUnderProfile,
    Resolved,
    /// Not run (the default), the control lookup failed, or the check could not run.
    Unknown,
}
fn classify_dns(control: Option<bool>, sandboxed: Option<bool>) -> DnsEvidence {
    match (control, sandboxed) {
        (Some(true), Some(true)) => DnsEvidence::Resolved,
        (Some(true), Some(false)) => DnsEvidence::NotResolvedUnderProfile,
        _ => DnsEvidence::Unknown,
    }
}
const DNS_TIMEOUT_MS: u64 = 2_000;
async fn dns_evidence(wrapper_hash: &str, profile: &str) -> DnsEvidence {
    let args: Vec<String> = ["-q", "host", "-a", "name", "example.com"]
        .map(String::from)
        .into();
    let resolves = |command: Result<Command>| async move {
        let mut command = command.ok()?;
        command.env_clear();
        let output = capture(
            command,
            vec![],
            DNS_TIMEOUT_MS,
            16_384,
            0,
            &Cancellation::default(),
        )
        .await
        .ok()?;
        Some(
            output.outcome.exit_code == Some(0)
                && String::from_utf8_lossy(&output.stdout).contains("ip_address"),
        )
    };
    let mut control = Command::new("/usr/bin/dscacheutil");
    control.args(&args);
    let control = resolves(Ok(control)).await;
    let sandboxed = resolves(checked_seatbelt_command(
        wrapper_hash,
        profile,
        "/usr/bin/dscacheutil",
        &args,
    ))
    .await;
    classify_dns(control, sandboxed)
}
impl SeatbeltSandbox {
    /// DNS evidence for the `NetworkAuthority::Deny` profile. `Unknown` until
    /// `probe_dns_resolution` has been called; the normal probe never runs it.
    pub fn dns_resolution(&self) -> DnsEvidence {
        self.dns_resolution
    }
    /// On demand only. Performs ONE real outbound DNS query (`example.com`)
    /// outside the sandbox as a control and one inside the `NetworkAuthority::Deny`
    /// profile, each bounded to 2 s. `/usr/bin/dscacheutil` is a system binary
    /// outside the approved-binary hash table, so this is evidence, never an
    /// authorization input. Records and returns the result.
    pub async fn probe_dns_resolution(&mut self) -> DnsEvidence {
        let profile = seatbelt_profile(&[], &[], NetworkAuthority::Deny);
        self.dns_resolution = match profile {
            Ok(profile) => dns_evidence(&self.wrapper_hash, &profile).await,
            Err(_) => DnsEvidence::Unknown,
        };
        self.dns_resolution
    }
    pub async fn probe(
        private_dir: &Path,
        programs: BTreeMap<String, PathBuf>,
        read_roots: Vec<PathBuf>,
        environment: BTreeMap<String, String>,
    ) -> Result<Self> {
        Self::probe_inner(private_dir, programs, read_roots, environment, None).await
    }
    pub async fn probe_expected(
        private_dir: &Path,
        programs: BTreeMap<String, PathBuf>,
        read_roots: Vec<PathBuf>,
        environment: BTreeMap<String, String>,
        expected: &BTreeMap<PathBuf, String>,
    ) -> Result<Self> {
        Self::probe_inner(
            private_dir,
            programs,
            read_roots,
            environment,
            Some(expected),
        )
        .await
    }
    async fn probe_inner(
        private_dir: &Path,
        programs: BTreeMap<String, PathBuf>,
        read_roots: Vec<PathBuf>,
        environment: BTreeMap<String, String>,
        expected: Option<&BTreeMap<PathBuf, String>>,
    ) -> Result<Self> {
        if !cfg!(target_os = "macos") || !Path::new("/usr/bin/sandbox-exec").is_file() {
            return Err(RuntimeError::Sandbox);
        }
        if fs::canonicalize(private_dir)? != private_dir {
            return Err(RuntimeError::Invalid("canonical probe directory"));
        }
        validate_configuration(&programs, &read_roots, &environment)?;
        let wrapper_hash = binary_hash(Path::new("/usr/bin/sandbox-exec"))?;
        check_expected(Path::new("/usr/bin/sandbox-exec"), &wrapper_hash, expected)?;
        let program_hashes = programs
            .iter()
            .map(|(name, path)| {
                let hash = binary_hash(path)?;
                check_expected(path, &hash, expected)?;
                Ok((name.clone(), hash))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let probe = private_dir.join("sandbox-probe");
        let denied_read = private_dir.join("sandbox-canary-read");
        // Tracked before creation: every early return below still cleans up.
        let mut scratch = crate::stale::Scratch::default();
        scratch.claim(&probe)?;
        scratch.claim(&denied_read)?;
        fs::create_dir(&probe)?;
        let allowed = probe.join("allowed");
        fs::create_dir(&allowed)?;
        let denied = probe.join("denied");
        crate::stale::create_canary(&denied_read, b"synthetic-read-canary")?;
        fs::write(allowed.join("read"), b"read-control")?;
        let profile =
            seatbelt_profile(&[probe.clone()], &[allowed.clone()], NetworkAuthority::Deny)?;
        let check = async {
            let mut command = checked_seatbelt_command(
                &wrapper_hash,
                &profile,
                "/usr/bin/touch",
                &[denied.to_string_lossy().into_owned()],
            )?;
            command.env_clear();
            let output =
                capture(command, vec![], 2_000, 16_384, 0, &Cancellation::default()).await?;
            if output.outcome.exit_code == Some(0) || denied.exists() {
                return Err(RuntimeError::Invalid("sandbox canary denied write escaped"));
            }
            let mut command = checked_seatbelt_command(
                &wrapper_hash,
                &profile,
                "/usr/bin/touch",
                &[allowed.join("yes").to_string_lossy().into_owned()],
            )?;
            command.env_clear();
            let output =
                capture(command, vec![], 2_000, 16_384, 0, &Cancellation::default()).await?;
            if output.outcome.exit_code != Some(0) || !allowed.join("yes").is_file() {
                return Err(RuntimeError::Invalid("sandbox canary allowed write failed"));
            }
            let mut command = checked_seatbelt_command(
                &wrapper_hash,
                &profile,
                "/bin/cat",
                &[allowed.join("read").to_string_lossy().into_owned()],
            )?;
            command.env_clear();
            let control =
                capture(command, vec![], 2_000, 16_384, 0, &Cancellation::default()).await?;
            if control.outcome.exit_code != Some(0) || control.stdout != b"read-control" {
                return Err(RuntimeError::Invalid("sandbox canary allowed read failed"));
            }
            let mut command = checked_seatbelt_command(
                &wrapper_hash,
                &profile,
                "/bin/cat",
                &[denied_read.to_string_lossy().into_owned()],
            )?;
            command.env_clear();
            let denied_output =
                capture(command, vec![], 2_000, 16_384, 0, &Cancellation::default()).await?;
            if denied_output.outcome.exit_code == Some(0) || !denied_output.stdout.is_empty() {
                return Err(RuntimeError::Invalid("sandbox canary denied read escaped"));
            }
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            let port = listener.local_addr()?.port().to_string();
            let args = vec![
                "-z".into(),
                "-w".into(),
                "1".into(),
                "127.0.0.1".into(),
                port,
            ];
            let mut control = Command::new("/usr/bin/nc");
            control.args(&args).env_clear();
            if capture(control, vec![], 2_000, 16_384, 0, &Cancellation::default())
                .await?
                .outcome
                .exit_code
                != Some(0)
            {
                return Err(RuntimeError::Sandbox);
            }
            let mut command =
                checked_seatbelt_command(&wrapper_hash, &profile, "/usr/bin/nc", &args)?;
            command.env_clear();
            if capture(command, vec![], 2_000, 16_384, 0, &Cancellation::default())
                .await?
                .outcome
                .exit_code
                == Some(0)
            {
                return Err(RuntimeError::Sandbox);
            }
            Ok(())
        }
        .await;
        // Only the probe paths claimed by this call are removed.
        let cleanup = scratch.cleanup();
        check?;
        cleanup?;
        Ok(Self {
            wrapper_hash,
            programs,
            program_hashes,
            read_roots,
            environment,
            dns_resolution: DnsEvidence::Unknown,
        })
    }
}
impl SandboxSupervisor for SeatbeltSandbox {
    fn create_host_state(
        &self,
        store: &Path,
        run: &PreparedRun,
    ) -> Result<Option<crate::HostState>> {
        if !matches!(run.program.as_str(), "codex" | "claude") {
            return Ok(None);
        }
        let source = self
            .programs
            .get(&run.program)
            .ok_or(RuntimeError::Sandbox)?;
        let hash = self
            .program_hashes
            .get(&run.program)
            .ok_or(RuntimeError::Sandbox)?;
        crate::HostState::create_with_program(store, &run.program, &self.environment, source, hash)
    }
    fn command(&self, run: &PreparedRun, policy: &SandboxPolicy) -> Result<Command> {
        let source = self
            .programs
            .get(&run.program)
            .ok_or(RuntimeError::Sandbox)?;
        let expected_hash = self
            .program_hashes
            .get(&run.program)
            .ok_or(RuntimeError::Sandbox)?;
        let program = if matches!(run.program.as_str(), "codex" | "claude") {
            policy
                .host_state
                .ok_or(RuntimeError::Sandbox)?
                .private_program_path(&run.program, expected_hash)?
                .to_path_buf()
        } else {
            if fs::canonicalize(source)? != *source || !source.is_file() {
                return Err(RuntimeError::Sandbox);
            }
            if &binary_hash(source)? != expected_hash {
                return Err(RuntimeError::Integrity("native binary changed"));
            }
            source.clone()
        };
        let cwd = Path::new(&run.cwd);
        safe_scope(cwd, &run.scope)?;
        let mut reads = self.read_roots.clone();
        reads.push(cwd.into());
        reads.push(program.clone());
        let mut writes = if run.sandbox == ExecutionSandbox::WorkspaceWrite {
            run.scope.iter().map(|p| cwd.join(p)).collect()
        } else {
            vec![]
        };
        let mut environment = self.environment.clone();
        if let Some(state) = policy.host_state {
            state.extend(&run.program, cwd, &mut reads, &mut writes, &mut environment)?;
        } else if matches!(run.program.as_str(), "codex" | "claude") {
            return Err(RuntimeError::Sandbox);
        }
        // Seatbelt accepts scope paths that do not exist yet; a missing tail is
        // checked through its deepest existing ancestor.
        require_canonical_paths(&reads, &writes, false)?;
        let mut profile = seatbelt_profile(&reads, &writes, policy.network)?;
        if run.program == "codex" {
            // Codex synchronizes managed preferences before it starts. Keep the
            // preference grant on its domain and shared-memory reads on the
            // cfprefs service namespace. Neither grants preference writes.
            profile.push_str(
                "(allow user-preference-read (preference-domain \"com.openai.codex\"))\n",
            );
            profile.push_str(
                "(allow ipc-posix-shm-read* (ipc-posix-name-prefix \"apple.cfprefs.\"))\n",
            );
        }
        let mut command = checked_seatbelt_command(
            &self.wrapper_hash,
            &profile,
            program.to_str().ok_or(RuntimeError::Sandbox)?,
            &run.argv,
        )?;
        command
            .current_dir(cwd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        for (key, value) in &environment {
            command.env(key, value);
        }
        Ok(command)
    }
}
/// Guard shared by both sandboxes: every readable root (which includes the
/// working directory) and writable path must already be canonical, so a symlink
/// or `..` alias cannot redirect a grant, and `/` is never readable. With
/// `writes_exist` false a write path that does not exist yet passes when its
/// deepest existing ancestor is canonical; bubblewrap binds paths and needs them
/// to exist.
pub(crate) fn require_canonical_paths(
    reads: &[PathBuf],
    writes: &[PathBuf],
    writes_exist: bool,
) -> Result<()> {
    for root in reads {
        if fs::canonicalize(root)? != *root || root == Path::new("/") {
            return Err(RuntimeError::Sandbox);
        }
    }
    for root in writes {
        let mut existing = root.as_path();
        let canonical = loop {
            match fs::canonicalize(existing) {
                Ok(path) => break path,
                Err(e) if !writes_exist && e.kind() == std::io::ErrorKind::NotFound => {
                    // A dangling symlink also reads as NotFound; never climb past one.
                    if fs::symlink_metadata(existing).is_ok() {
                        return Err(RuntimeError::Sandbox);
                    }
                    existing = existing.parent().ok_or(RuntimeError::Sandbox)?;
                }
                Err(e) => return Err(e.into()),
            }
        };
        if canonical != existing {
            return Err(RuntimeError::Sandbox);
        }
    }
    Ok(())
}
fn checked_seatbelt_command(
    wrapper_hash: &str,
    profile: &str,
    program: &str,
    args: &[String],
) -> Result<Command> {
    if binary_hash(Path::new("/usr/bin/sandbox-exec"))? != wrapper_hash {
        return Err(RuntimeError::Integrity("sandbox-exec changed"));
    }
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command.arg("-p").arg(profile).arg(program).args(args);
    Ok(command)
}
fn quote(path: &Path) -> Result<String> {
    let path = path.to_str().ok_or(RuntimeError::Sandbox)?;
    if !path.starts_with('/') || path.contains(['\0', '\n', '\r']) {
        return Err(RuntimeError::Sandbox);
    }
    Ok(format!(
        "\"{}\"",
        path.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}
pub(crate) fn binary_hash(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > 256 * 1024 * 1024 {
        return Err(RuntimeError::Limit);
    }
    let mut count = 0;
    let mut hash = Sha256::new();
    let mut buffer = [0; 16_384];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count += n;
        if count > 256 * 1024 * 1024 {
            return Err(RuntimeError::Limit);
        }
        hash.update(&buffer[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}
pub(crate) fn check_expected(
    path: &Path,
    actual: &str,
    expected: Option<&BTreeMap<PathBuf, String>>,
) -> Result<()> {
    if expected.is_some_and(|values| values.get(path).map(String::as_str) != Some(actual)) {
        return Err(RuntimeError::Integrity(
            "approved binary changed or missing",
        ));
    }
    Ok(())
}
// LIMIT: `mach-lookup` is allowed globally because the loader and system
// libraries need several services. `NetworkAuthority::Deny` therefore proves only that
// socket networking is denied, not the absence of DNS (mDNSResponder) or
// LaunchServices channels; `SeatbeltSandbox::dns_resolution` records what the
// probe observed. A mach service allowlist is deferred to a native canary.
fn seatbelt_profile(
    reads: &[PathBuf],
    writes: &[PathBuf],
    network: NetworkAuthority,
) -> Result<String> {
    let mut profile = String::from(
        "(version 1)\n(deny default)\n(allow process-exec process-fork sysctl-read mach-lookup)\n(allow signal (target self))\n(allow file-read-metadata)\n(allow file-read* (literal \"/\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/usr\") (subpath \"/System\") (subpath \"/Library\") (literal \"/dev/null\") (literal \"/dev/urandom\") (literal \"/private/etc/resolv.conf\") (literal \"/private/etc/hosts\"))\n(allow file-write* (literal \"/dev/null\"))\n",
    );
    for path in reads {
        profile.push_str(&format!(
            "(allow file-read* (literal {0}) (subpath {0}))\n",
            quote(path)?
        ));
    }
    for path in writes {
        profile.push_str(&format!(
            "(allow file-write* (literal {0}) (subpath {0}))\n",
            quote(path)?
        ));
    }
    // A child may read Git metadata but may never redirect its private .git file.
    // Default APFS folds case, so every spelling of `.git` is denied.
    profile.push_str("(deny file-write* (regex #\"(^|/)\\.[Gg][Ii][Tt](/|$)\"))\n");
    profile.push_str(network.seatbelt_rule()?);
    Ok(profile)
}
// The npm entry uses /usr/bin/env node, outside the fixed child PATH. Refuse
// every Codex shebang rather than guessing an interpreter or unbound modules.
fn reject_codex_script(path: &Path) -> Result<()> {
    use std::io::Read;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(RuntimeError::Sandbox);
    }
    let mut prefix = Vec::with_capacity(2);
    file.take(2).read_to_end(&mut prefix)?;
    if prefix == b"#!" {
        return Err(RuntimeError::ScriptProgram);
    }
    Ok(())
}
pub(crate) fn validate_configuration(
    programs: &BTreeMap<String, PathBuf>,
    roots: &[PathBuf],
    environment: &BTreeMap<String, String>,
) -> Result<()> {
    if programs.is_empty() || programs.len() > 16 || roots.len() > 32 || environment.len() > 16 {
        return Err(RuntimeError::Limit);
    }
    for path in programs.values().chain(roots.iter()) {
        if fs::canonicalize(path)? != *path || path == Path::new("/") {
            return Err(RuntimeError::Sandbox);
        }
    }
    if let Some(program) = programs.get("codex") {
        reject_codex_script(program)?;
    }
    for (key, value) in environment {
        if !matches!(
            key.as_str(),
            "OPENAI_API_KEY"
                | "ANTHROPIC_API_KEY"
                | "CODEX_HOME"
                | "CLAUDE_CONFIG_DIR"
                | "HOME"
                | "SSL_CERT_FILE"
        ) || value.contains('\0')
            || value.len() > 16_384
        {
            return Err(RuntimeError::Sandbox);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_evidence_is_unknown_unless_the_control_resolved() {
        use DnsEvidence::*;
        assert_eq!(classify_dns(Some(true), Some(true)), Resolved);
        assert_eq!(
            classify_dns(Some(true), Some(false)),
            NotResolvedUnderProfile
        );
        assert_eq!(classify_dns(Some(true), None), Unknown);
        assert_eq!(classify_dns(Some(false), Some(false)), Unknown);
        assert_eq!(classify_dns(None, Some(true)), Unknown);
    }
    #[test]
    fn a_working_directory_behind_a_symlink_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        fs::create_dir_all(root.join("real/src")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let cwd = root.join("real");
        let aliased = root.join("link");
        for exist in [false, true] {
            require_canonical_paths(&[cwd.clone()], &[cwd.join("src")], exist).unwrap();
            assert!(matches!(
                require_canonical_paths(&[aliased.clone()], &[], exist),
                Err(RuntimeError::Sandbox)
            ));
            assert!(matches!(
                require_canonical_paths(&[cwd.clone()], &[aliased.join("src")], exist),
                Err(RuntimeError::Sandbox)
            ));
        }
        assert!(matches!(
            require_canonical_paths(&[PathBuf::from("/")], &[], false),
            Err(RuntimeError::Sandbox)
        ));
        // A scope path that does not exist yet is fine for Seatbelt only.
        let fresh = cwd.join("new/dir");
        require_canonical_paths(&[cwd.clone()], &[fresh.clone()], false).unwrap();
        assert!(require_canonical_paths(&[cwd], &[fresh], true).is_err());
        // A dangling symlink component is refused, not treated as missing.
        std::os::unix::fs::symlink(root.join("nowhere"), root.join("real/dangling")).unwrap();
        assert!(matches!(
            require_canonical_paths(&[], &[root.join("real/dangling/x")], false),
            Err(RuntimeError::Sandbox)
        ));
        // The alias is caught even when the missing tail hides behind it.
        assert!(matches!(
            require_canonical_paths(&[], &[aliased.join("new/dir")], false),
            Err(RuntimeError::Sandbox)
        ));
    }
    #[test]
    fn quote_escapes_and_refuses_unsafe_paths() {
        assert_eq!(quote(Path::new("/a b/c")).unwrap(), "\"/a b/c\"");
        assert_eq!(
            quote(Path::new("/a\"(allow default)\\")).unwrap(),
            "\"/a\\\"(allow default)\\\\\""
        );
        for bad in ["relative", "/a\nb", "/a\rb", "/a\0b"] {
            assert!(
                matches!(quote(Path::new(bad)), Err(RuntimeError::Sandbox)),
                "{bad:?}"
            );
        }
    }
    #[test]
    fn profile_grants_only_listed_paths_and_network_on_request() {
        let profile =
            seatbelt_profile(&["/r".into()], &["/w".into()], NetworkAuthority::Deny).unwrap();
        assert!(profile.starts_with("(version 1)\n(deny default)\n"));
        assert!(profile.contains("(allow file-read* (literal \"/r\") (subpath \"/r\"))\n"));
        assert!(profile.contains("(allow file-write* (literal \"/w\") (subpath \"/w\"))\n"));
        assert!(!profile.contains("network"));
        assert!(!profile.contains("(allow file-write* (literal \"/r\")"));
        let online = seatbelt_profile(&[], &[], NetworkAuthority::PhaseGranted).unwrap();
        assert!(online.ends_with("(allow network*)\n"));
        assert!(online.contains("(deny file-write* (regex"));
    }
    #[test]
    fn controller_broker_only_policy_fails_closed_until_seatbelt_can_scope_it() {
        assert!(matches!(
            seatbelt_profile(&[], &[], crate::NetworkAuthority::ControllerBrokerOnly),
            Err(RuntimeError::Sandbox)
        ));
    }
    #[test]
    fn profile_rejects_a_path_that_would_break_out_of_its_literal() {
        assert!(seatbelt_profile(&["rel".into()], &[], NetworkAuthority::Deny).is_err());
        assert!(
            seatbelt_profile(&[], &["/w\n(allow default)".into()], NetworkAuthority::Deny).is_err()
        );
    }
    #[test]
    fn profile_documents_the_global_mach_lookup_allowance() {
        let profile = seatbelt_profile(&[], &[], NetworkAuthority::Deny).unwrap();
        assert!(profile.contains("mach-lookup"));
    }

    #[test]
    fn profile_denies_writes_below_git_in_every_case() {
        let profile = seatbelt_profile(&[], &["/w/src".into()], NetworkAuthority::Deny).unwrap();
        let line = profile
            .lines()
            .find(|l| l.starts_with("(deny file-write* (regex"))
            .expect("git write denial");
        for spelling in [".git", ".GIT", ".Git", ".gIT"] {
            assert!(
                spelling.chars().skip(1).all(|c| line.contains(&format!(
                    "[{}{}]",
                    c.to_ascii_uppercase(),
                    c.to_ascii_lowercase()
                )) || line.contains(&format!(
                    "[{}{}]",
                    c.to_ascii_lowercase(),
                    c.to_ascii_uppercase()
                ))),
                "{spelling} is not covered by {line}"
            );
        }
    }
    #[test]
    fn codex_shebang_launchers_are_refused_with_a_fixed_code() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let script = root.join("codex.js");
        fs::write(&script, b"#!/usr/bin/env node\nprocess.exit(0);\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let programs = [("codex".into(), script.clone())].into();
        let error = validate_configuration(&programs, &[], &BTreeMap::new())
            .err()
            .map(|error| error.to_string());
        assert_eq!(error.as_deref(), Some("runtime.program.script_unsupported"));
        // Other adapters retain their existing script-host contract.
        validate_configuration(&[("claude".into(), script)].into(), &[], &BTreeMap::new()).unwrap();
        let native = fs::canonicalize("/bin/sh").unwrap();
        validate_configuration(&[("codex".into(), native)].into(), &[], &BTreeMap::new()).unwrap();
    }
}
