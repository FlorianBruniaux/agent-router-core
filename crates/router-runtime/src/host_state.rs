//! Per-attempt host files. Never import personal configuration or OAuth tokens.
use crate::{Result, RuntimeError, private_program::PrivateProgram};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Runtime-created state, held until the supervised attempt ends. No public
/// constructor: callers cannot turn an arbitrary path into a writable grant.
pub struct HostState {
    path: PathBuf,
    store: PathBuf,
    program: String,
    private_program: Option<PrivateProgram>,
    finite_client: Option<Box<crate::finite_client::FiniteClientResources>>,
    directory: OwnedDirectory,
    store_directory: OwnedDirectory,
    cleanup_attempted: bool,
    possibly_running: bool,
    writer_lease: Option<crate::leases::CleanupLease>,
    pid_namespace: bool,
}
impl HostState {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn create_with_program(
        store: &Path,
        program: &str,
        environment: &BTreeMap<String, String>,
        source: &Path,
        expected_hash: &str,
    ) -> Result<Option<Self>> {
        let Some(mut state) = Self::create(store, program, environment)? else {
            return Ok(None);
        };
        state.private_program = Some(PrivateProgram::copy(source, expected_hash, store)?);
        Ok(Some(state))
    }

    pub(crate) fn create(
        store: &Path,
        program: &str,
        environment: &BTreeMap<String, String>,
    ) -> Result<Option<Self>> {
        if !matches!(program, "codex" | "claude") {
            return Ok(None);
        }
        let store_directory = OwnedDirectory::open(store)?;
        // These built-in read roots are granted even without extra read_roots.
        let builtins: &[&str] = if cfg!(target_os = "macos") {
            &["/bin", "/sbin", "/usr", "/System", "/Library"]
        } else {
            &["/usr", "/bin", "/sbin", "/lib", "/lib64", "/proc", "/dev"]
        };
        if builtins.iter().any(|root| store.starts_with(root)) {
            return Err(RuntimeError::Sandbox);
        }
        if environment.contains_key("CODEX_HOME") || environment.contains_key("CLAUDE_CONFIG_DIR") {
            return Err(RuntimeError::Sandbox);
        }
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RuntimeError::Invalid("clock"))?
            .as_nanos();
        let path = store.join(format!(
            "host-state-{}-{}-{}",
            std::process::id(),
            stamp,
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        let directory = OwnedDirectory::open(&path)?;
        let state = Self {
            path,
            store: store.into(),
            program: program.into(),
            private_program: None,
            finite_client: None,
            directory,
            store_directory,
            cleanup_attempted: false,
            possibly_running: false,
            writer_lease: None,
            pid_namespace: false,
        };
        state.check_directories()?;
        if program == "codex" {
            if let Some(key) = environment.get("OPENAI_API_KEY") {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(nix::libc::O_NOFOLLOW)
                    .open(state.path.join("auth.json"))?;
                let bytes = serde_json::to_vec(&serde_json::json!({"OPENAI_API_KEY":key}))?;
                file.write_all(&bytes)?;
            }
        }
        Ok(Some(state))
    }
    pub(crate) fn private_program_path(&self, program: &str, expected_hash: &str) -> Result<&Path> {
        if program != self.program {
            return Err(RuntimeError::Sandbox);
        }
        self.private_program
            .as_ref()
            .ok_or(RuntimeError::Sandbox)?
            .verify(expected_hash)
    }
    pub(crate) fn extend(
        &self,
        program: &str,
        cwd: &Path,
        reads: &mut Vec<PathBuf>,
        writes: &mut Vec<PathBuf>,
        environment: &mut BTreeMap<String, String>,
    ) -> Result<()> {
        // A finite client has its own immutable startup view. The generic
        // native path would grant writes to that entire home; keep it closed.
        if self.finite_client.is_some() {
            return Err(RuntimeError::Sandbox);
        }
        self.check_directories()?;
        if program != self.program {
            return Err(RuntimeError::Sandbox);
        }
        for root in reads.iter().chain(writes.iter()) {
            // Runtime worktrees and version-probe cwd are intentional views.
            // No other store child, store root or ancestor may become readable.
            let runtime_cwd = cwd.starts_with(self.store.join("worktrees"))
                || (cwd.parent() == Some(self.store.as_path())
                    && cwd
                        .file_name()
                        .is_some_and(|n| n.as_encoded_bytes().starts_with(b"version-")));
            if self.store.starts_with(root)
                || (root.starts_with(&self.store) && !(runtime_cwd && root.starts_with(cwd)))
            {
                return Err(RuntimeError::Sandbox);
            }
        }
        if let Some(copy) = &self.private_program {
            if writes.iter().any(|root| {
                copy.directory().starts_with(root) || root.starts_with(copy.directory())
            }) {
                return Err(RuntimeError::Sandbox);
            }
            reads.push(copy.directory().into());
        }
        reads.push(self.path.clone());
        writes.push(self.path.clone());
        let variable = if program == "codex" {
            "CODEX_HOME"
        } else {
            "CLAUDE_CONFIG_DIR"
        };
        environment.insert(
            variable.into(),
            self.path
                .to_str()
                .ok_or(RuntimeError::Invalid("utf8 host state"))?
                .into(),
        );
        Ok(())
    }
    pub(crate) fn retain_finite_client(
        &mut self,
        resources: crate::finite_client::FiniteClientResources,
    ) -> Result<()> {
        if self.possibly_running || self.private_program.is_some() || self.finite_client.is_some() {
            return Err(RuntimeError::Sandbox);
        }
        resources.check(&self.path)?;
        self.finite_client = Some(Box::new(resources));
        Ok(())
    }

    pub(crate) fn finite_resources(&self) -> Result<&crate::finite_client::FiniteClientResources> {
        self.finite_client.as_deref().ok_or(RuntimeError::Sandbox)
    }

    pub(crate) fn check_owned_resources(&self) -> Result<()> {
        self.check_directories()?;
        if let Some(resources) = &self.finite_client {
            resources.check(&self.path)?;
        }
        Ok(())
    }

    fn check_directories(&self) -> Result<()> {
        self.store_directory.check(&self.store)?;
        self.directory.check(&self.path)
    }

    fn remove_owned_directory(&mut self) -> Result<()> {
        // Explicit cleanup consumes its single attempt even on refusal. Drop
        // must not retry after an error or partial deletion against a new path.
        self.cleanup_attempted = true;
        // A missing pathname cannot prove cleanup: an owned directory may have
        // been moved. Do not infer deletion from nlink either: APFS retains it
        // on an open, removed directory. Refuse absent or changed paths alike.
        self.check_directories()?;
        // Like PrivateProgram, this identity check requires exclusion of writers
        // during removal. It is not atomic against another trusted same-UID
        // writer; a future backend must stop workers and protect the store first.
        fs::remove_dir_all(&self.path)?;
        Ok(())
    }

    /// Called before capture is polled, including any cancellable spawn path.
    /// An arming failure also retains the state rather than guessing no spawn.
    pub(crate) fn arm_cleanup(&mut self, lease: Option<&Path>, pid_namespace: bool) -> Result<()> {
        if self.possibly_running {
            return Err(RuntimeError::CleanupUnknown);
        }
        self.possibly_running = true;
        self.pid_namespace = pid_namespace;
        self.check_owned_resources()?;
        let path = lease.ok_or(RuntimeError::CleanupUnknown)?;
        if path.starts_with(&self.path) {
            return Err(RuntimeError::CleanupUnknown);
        }
        self.writer_lease = Some(crate::leases::CleanupLease::pin(path)?);
        if self.finite_client.is_some() && !pid_namespace {
            return Err(RuntimeError::CleanupUnknown);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn cleanup(self) -> Result<()> {
        if !self.possibly_running {
            return self.cleanup_owned();
        }
        let proof = self
            .writer_lease
            .as_ref()
            .ok_or(RuntimeError::CleanupUnknown)?
            .proof()?;
        self.cleanup_with_proof(&proof)
    }
    /// Only a trusted backend may call this after a read-only bundle probe.
    /// Its writable paths must have used a separately owned sacrificial view.
    /// Keep the opaque namespace lock until that view is disposed and the
    /// preparation record committed. Group or pending evidence cannot rearm.
    pub(crate) fn finish_read_only_probe(
        &mut self,
        proof: &crate::leases::CleanupProof,
    ) -> Result<()> {
        if !self.possibly_running
            || !self.pid_namespace
            || proof.evidence != router_types::ProcessCleanupEvidence::NamespaceTerminated
            || !self
                .writer_lease
                .as_ref()
                .ok_or(RuntimeError::CleanupUnknown)?
                .matches(proof)?
        {
            return Err(RuntimeError::CleanupUnknown);
        }
        self.check_owned_resources()?;
        self.possibly_running = false;
        self.writer_lease = None;
        self.pid_namespace = false;
        Ok(())
    }

    /// Observe only after the exact retained namespace lease excludes writers.
    pub(crate) fn observe_finite_tools(
        &mut self,
        proof: &crate::leases::CleanupProof,
        require_complete: bool,
    ) -> Result<Option<crate::finite_client::StoppedToolsObservation>> {
        if !self.possibly_running
            || !self.pid_namespace
            || proof.evidence != router_types::ProcessCleanupEvidence::NamespaceTerminated
            || !self
                .writer_lease
                .as_ref()
                .ok_or(RuntimeError::CleanupUnknown)?
                .matches(proof)?
        {
            return Err(RuntimeError::CleanupUnknown);
        }
        match self.finite_client.as_mut() {
            Some(resources) => resources.observe_tools(require_complete),
            None => Ok(None),
        }
    }

    pub(crate) fn cleanup_with_proof(self, proof: &crate::leases::CleanupProof) -> Result<()> {
        if !self.possibly_running
            || !proof.excludes_writers()
            || (proof.evidence == router_types::ProcessCleanupEvidence::NamespaceTerminated
                && !self.pid_namespace)
            || !self
                .writer_lease
                .as_ref()
                .ok_or(RuntimeError::CleanupUnknown)?
                .matches(proof)?
        {
            return Err(RuntimeError::CleanupUnknown);
        }
        // The caller owns the opaque lock until deletion and durable settlement
        // finish. A pending helper cannot acquire it or launch after recovery.
        self.cleanup_owned()
    }
    fn cleanup_owned(mut self) -> Result<()> {
        let state_cleanup = self.remove_owned_directory();
        let program_cleanup = self
            .private_program
            .take()
            .map_or(Ok(()), PrivateProgram::cleanup);
        state_cleanup?;
        program_cleanup?;
        if let Some(resources) = self.finite_client.take() {
            resources.cleanup()?;
        }
        Ok(())
    }
}
impl Drop for HostState {
    fn drop(&mut self) {
        if self.possibly_running {
            // A dropped/failed async operation cannot prove all writers stopped.
            // Do not even remove the read-only program copy while it may be live.
            if let Some(program) = self.private_program.take() {
                program.preserve();
            }
            if let Some(resources) = self.finite_client.take() {
                // No surviving owner can release this listener or these assets
                // safely. Quarantine the complete bundle until controller exit.
                // Durable cleanup remains UNKNOWN; never reconstruct it by path.
                std::mem::forget(resources);
            }
        } else if !self.cleanup_attempted {
            let _ = self.remove_owned_directory();
        }
    }
}
// Hold an open descriptor so an unlinked original inode cannot be recycled.
// Capture mode/owner at creation; mutable contents do not change ownership.
struct OwnedDirectory {
    file: File,
    identity: (u64, u64, u32, u32),
}
impl OwnedDirectory {
    fn identity(meta: &fs::Metadata) -> (u64, u64, u32, u32) {
        (meta.dev(), meta.ino(), meta.uid(), meta.mode())
    }
    fn open(path: &Path) -> Result<Self> {
        private_directory(path)?;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
            .open(path)?;
        let directory = Self {
            identity: Self::identity(&file.metadata()?),
            file,
        };
        directory.check(path)?;
        Ok(directory)
    }
    fn check(&self, path: &Path) -> Result<()> {
        private_directory(path)?;
        if Self::identity(&fs::symlink_metadata(path)?) != self.identity
            || Self::identity(&self.file.metadata()?) != self.identity
        {
            return Err(RuntimeError::Integrity("host state directory changed"));
        }
        Ok(())
    }
}

fn private_directory(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir()
        || meta.permissions().mode() & 0o077 != 0
        || meta.uid() != rustix::process::geteuid().as_raw()
        || fs::canonicalize(path)? != path
    {
        return Err(RuntimeError::Sandbox);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SandboxPolicy, SandboxSupervisor};
    use router_types::*;

    fn native_run(cwd: &Path) -> PreparedRun {
        PreparedRun {
            schema_version: 1,
            receipt_id: "a".repeat(64),
            source_state: "b".repeat(40),
            scope: vec![],
            authorization_digest: "c".repeat(64),
            snapshot_hash: "d".repeat(64),
            host: HarnessId::parse("codex").unwrap(),
            requested_model: ModelId::parse("fixture-model").unwrap(),
            requested_effort: EffortLevel::Medium,
            program: "codex".into(),
            argv: vec![
                "-c".into(),
                r#"set -eu
if (printf denied > "$1") 2>/dev/null; then exit 61; fi
if (printf denied > "$2/denied") 2>/dev/null; then exit 62; fi
printf approved
"#
                .into(),
            ],
            cwd: cwd.to_str().unwrap().into(),
            stdin: PreparedInput::new(vec![]),
            mode: ExecutionMode::Execute,
            target: ExecutionTarget::ExternalWorker,
            sandbox: ExecutionSandbox::ReadOnly,
            timeout_ms: 3000,
            max_output_bytes: 4096,
            degradations: vec![],
            missing_runtime_evidence: vec![],
            parent_model_changed: false,
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn compile_shell_shim(path: &Path) {
        let source = path.with_extension("c");
        fs::write(
            &source,
            b"#include <unistd.h>\nint main(int argc, char **argv) { (void)argc; argv[0] = \"/bin/sh\"; execv(\"/bin/sh\", argv); return 127; }\n",
        )
        .unwrap();
        #[cfg(target_os = "macos")]
        let compiler = "/usr/bin/clang";
        #[cfg(target_os = "linux")]
        let compiler = "/usr/bin/cc";
        let output = std::process::Command::new(compiler)
            .arg(&source)
            .arg("-o")
            .arg(path)
            .output()
            .unwrap();
        assert!(output.status.success(), "local fixture compile: {output:?}");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    #[ignore = "requires native OS sandbox; runs only copied local programs"]
    async fn approved_program_copy_survives_source_replacement_and_is_read_only() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let store = root.join("store");
        let cwd = root.join("repo");
        fs::DirBuilder::new().mode(0o700).create(&store).unwrap();
        fs::create_dir(&cwd).unwrap();
        let source = root.join("fixture-program");
        compile_shell_shim(&source);
        let programs = BTreeMap::from([("codex".into(), source.clone())]);
        #[cfg(target_os = "macos")]
        let sandbox = crate::SeatbeltSandbox::probe(&store, programs, vec![], BTreeMap::new())
            .await
            .unwrap();
        #[cfg(target_os = "linux")]
        let sandbox = crate::BubblewrapSandbox::probe(
            &store,
            &fs::canonicalize("/usr/bin/bwrap").unwrap(),
            programs,
            vec![],
            BTreeMap::new(),
        )
        .await
        .unwrap();
        let run = native_run(&cwd);
        let state = sandbox.create_host_state(&store, &run).unwrap().unwrap();
        let state_path = state.path.clone();
        let mut command = sandbox
            .command(
                &run,
                &SandboxPolicy {
                    network: crate::NetworkAuthority::Deny,
                    host_state: Some(&state),
                },
            )
            .unwrap();
        let args: Vec<_> = command.as_std().get_args().collect();
        #[cfg(target_os = "macos")]
        let executable = PathBuf::from(args[2]);
        #[cfg(target_os = "linux")]
        let executable = PathBuf::from(args[args.iter().position(|arg| *arg == "--").unwrap() + 1]);
        let private_dir = executable.parent().unwrap().to_path_buf();
        command.arg("--").arg(&executable).arg(&private_dir);

        // Only this temporary source changes; the system binaries stay intact.
        let replacement = root.join("replacement-program");
        fs::copy("/usr/bin/false", &replacement).unwrap();
        fs::rename(replacement, &source).unwrap();
        let output = command.output().await.unwrap();
        assert!(
            output.status.success(),
            "copied shell shim must run: {output:?}"
        );
        assert_eq!(output.stdout, b"approved");
        assert_ne!(executable, source);
        assert!(!private_dir.starts_with(&store));
        assert_eq!(
            fs::metadata(&private_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&executable).unwrap().permissions().mode() & 0o777,
            0o500
        );
        assert!(!private_dir.join("denied").exists());
        state.cleanup().unwrap();
        assert!(!state_path.exists());
        assert!(!private_dir.exists());

        // The changed source must be rejected before a second copy is created.
        assert!(matches!(
            sandbox.create_host_state(&store, &run),
            Err(RuntimeError::Integrity(_))
        ));
    }
    #[test]
    fn private_program_refuses_missing_copy_other_host_tampering_and_write_grants() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let store = root.join("store");
        fs::DirBuilder::new().mode(0o700).create(&store).unwrap();
        let source = root.join("fixture-program");
        fs::copy("/bin/sh", &source).unwrap();
        let hash = crate::sandbox::binary_hash(&source).unwrap();
        let empty = HostState::create(&store, "codex", &BTreeMap::new())
            .unwrap()
            .unwrap();
        assert!(matches!(
            empty.private_program_path("codex", &hash),
            Err(RuntimeError::Sandbox)
        ));
        drop(empty);

        let state =
            HostState::create_with_program(&store, "codex", &BTreeMap::new(), &source, &hash)
                .unwrap()
                .unwrap();
        let executable = state
            .private_program_path("codex", &hash)
            .unwrap()
            .to_path_buf();
        let directory = executable.parent().unwrap().to_path_buf();
        assert!(matches!(
            state.private_program_path("claude", &hash),
            Err(RuntimeError::Sandbox)
        ));
        assert!(matches!(
            state.extend(
                "codex",
                &root.join("repo"),
                &mut vec![],
                &mut vec![directory.clone()],
                &mut BTreeMap::new(),
            ),
            Err(RuntimeError::Sandbox)
        ));
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            state.private_program_path("codex", &hash),
            Err(RuntimeError::Integrity(_))
        ));
        state.cleanup().unwrap();
        assert!(!directory.exists());
    }
    #[test]
    fn detached_writer_outlives_group_marker_and_prevents_home_cleanup() {
        use std::io::Write;
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};
        const CHILD_HOME: &str = "AR_CLEANUP_FIXTURE_CHILD_HOME";
        if let Some(home) = std::env::var_os(CHILD_HOME) {
            nix::unistd::setsid().unwrap();
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(Path::new(&home).join("heartbeat"))
                .unwrap();
            loop {
                file.write_all(b"x").unwrap();
                file.flush().unwrap();
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        struct Writer(Child);
        impl Drop for Writer {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let store = fs::canonicalize(temp.path()).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        let mut state = HostState::create(&store, "codex", &BTreeMap::new())
            .unwrap()
            .unwrap();
        let home = state.path.clone();
        let heartbeat = home.join("heartbeat");
        let leases = crate::leases::LeaseStorage::open(&store).unwrap();
        let (_, path) = leases.create("detached", 1).unwrap();
        state.arm_cleanup(Some(&path), false).unwrap();
        let _writer = Writer(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "host_state::tests::detached_writer_outlives_group_marker_and_prevents_home_cleanup", "--nocapture"])
            .env(CHILD_HOME, &home).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(3);
        while fs::metadata(&heartbeat).map_or(true, |m| m.len() == 0) {
            assert!(Instant::now() < deadline, "writer did not start");
            std::thread::sleep(Duration::from_millis(5));
        }
        fs::write(&path, b"router-runtime-lease-v1:group-clean\n").unwrap();
        assert!(state.cleanup().is_err());
        let first = fs::metadata(&heartbeat).unwrap().len();
        while fs::metadata(&heartbeat).unwrap().len() == first {
            assert!(
                Instant::now() < deadline,
                "detached writer stopped unexpectedly"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(home.is_dir());
        drop(_writer); // Reap the owned child before the fixture directory is removed.
    }

    #[test]
    fn exposed_host_state_requires_exact_unlocked_namespace_lease() {
        use nix::fcntl::{Flock, FlockArg};
        for case in [
            "pending",
            "namespace",
            "group",
            "active",
            "held",
            "replaced",
            "symlink",
            "wrong-proof",
            "no-namespace",
            "drop",
            "no-lease",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let store = fs::canonicalize(temp.path()).unwrap();
            fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
            let source = store.join("inert-program");
            fs::write(&source, b"inert, never executed").unwrap();
            let hash = crate::sandbox::binary_hash(&source).unwrap();
            let mut state =
                HostState::create_with_program(&store, "codex", &BTreeMap::new(), &source, &hash)
                    .unwrap()
                    .unwrap();
            let home = state.path.clone();
            fs::write(home.join("owned"), b"keep").unwrap();
            let program = state
                .private_program_path("codex", &hash)
                .unwrap()
                .to_owned();
            let leases = crate::leases::LeaseStorage::open(&store).unwrap();
            let (record, path) = leases.create("case", 1).unwrap();
            if case == "no-lease" {
                assert!(state.arm_cleanup(None, true).is_err());
            } else {
                state
                    .arm_cleanup(Some(&path), case != "no-namespace")
                    .unwrap();
            }
            let mut held = None;
            match case {
                "namespace" | "no-namespace" | "held" => {
                    fs::write(&path, b"router-runtime-lease-v1:namespace-clean\n").unwrap()
                }
                "group" => fs::write(&path, b"router-runtime-lease-v1:group-clean\n").unwrap(),
                "active" => fs::write(&path, b"router-runtime-lease-v1:active\n").unwrap(),
                "replaced" | "symlink" => {
                    fs::rename(&path, path.with_extension("original")).unwrap();
                    if case == "replaced" {
                        fs::write(&path, b"router-runtime-lease-v1:namespace-clean\n").unwrap();
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                    } else {
                        std::os::unix::fs::symlink(path.with_extension("original"), &path).unwrap();
                    }
                }
                _ => {}
            }
            if case == "held" {
                held = Some(
                    Flock::lock(File::open(&path).unwrap(), FlockArg::LockExclusiveNonblock)
                        .unwrap(),
                );
            }
            if case == "drop" || case == "no-lease" {
                drop(state);
            } else if case == "wrong-proof" {
                let (other, _) = leases.create("other", 1).unwrap();
                let proof = leases.cleanup_proof("other", 1, &other).unwrap();
                assert!(state.cleanup_with_proof(&proof).is_err());
            } else {
                let result = state.cleanup();
                assert_eq!(
                    result.is_ok(),
                    matches!(case, "pending" | "namespace"),
                    "{case}"
                );
            }
            if matches!(case, "pending" | "namespace") {
                assert!(!home.exists(), "{case}");
                assert!(!program.parent().unwrap().exists(), "{case}");
                if case == "pending" {
                    assert_eq!(
                        leases.cleanup_proof("case", 1, &record).unwrap().evidence,
                        ProcessCleanupEvidence::NotStarted
                    );
                }
            } else {
                assert_eq!(fs::read(home.join("owned")).unwrap(), b"keep", "{case}");
                assert_eq!(
                    fs::read(&program).unwrap(),
                    b"inert, never executed",
                    "{case}"
                );
                // All actors here are inert; explicitly dispose only this test's retained copy.
                fs::remove_dir_all(program.parent().unwrap()).unwrap();
            }
            drop(held);
        }
    }

    #[test]
    fn recovered_pending_lease_cannot_be_reacquired_during_cleanup() {
        use nix::fcntl::{Flock, FlockArg};
        let temp = tempfile::tempdir().unwrap();
        let store = fs::canonicalize(temp.path()).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        let mut state = HostState::create(&store, "codex", &BTreeMap::new())
            .unwrap()
            .unwrap();
        let home = state.path.clone();
        let leases = crate::leases::LeaseStorage::open(&store).unwrap();
        let (record, path) = leases.create("pending", 1).unwrap();
        state.arm_cleanup(Some(&path), false).unwrap();
        let proof = leases.cleanup_proof("pending", 1, &record).unwrap();
        assert!(Flock::lock(File::open(&path).unwrap(), FlockArg::LockExclusiveNonblock).is_err());
        state.cleanup_with_proof(&proof).unwrap();
        assert!(!home.exists());
        assert!(Flock::lock(File::open(&path).unwrap(), FlockArg::LockExclusiveNonblock).is_err());
        assert_eq!(
            fs::read(&path).unwrap(),
            b"router-runtime-lease-v1:recovered\n"
        );
        drop(proof);
        let _lock =
            Flock::lock(File::open(path).unwrap(), FlockArg::LockExclusiveNonblock).unwrap();
    }

    #[test]
    fn host_state_cleanup_preserves_substituted_home() {
        for explicit in [false, true] {
            for replacement in ["directory", "file", "symlink"] {
                let temp = tempfile::tempdir().unwrap();
                let store = fs::canonicalize(temp.path()).unwrap();
                fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
                let state = HostState::create(&store, "codex", &BTreeMap::new())
                    .unwrap()
                    .unwrap();
                let home = state.path.clone();
                fs::write(home.join("owned"), b"owned").unwrap();
                let moved = store.join("moved");
                fs::rename(&home, &moved).unwrap();
                let outside = store.join("outside");
                fs::create_dir(&outside).unwrap();
                fs::write(outside.join("foreign"), b"keep").unwrap();
                match replacement {
                    "directory" => {
                        fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
                        fs::write(home.join("foreign"), b"keep").unwrap();
                    }
                    "file" => fs::write(&home, b"keep").unwrap(),
                    _ => std::os::unix::fs::symlink(&outside, &home).unwrap(),
                }
                if explicit {
                    assert!(state.cleanup().is_err(), "must refuse {replacement}");
                } else {
                    drop(state);
                }
                assert!(
                    fs::symlink_metadata(&home).is_ok(),
                    "must preserve {replacement}"
                );
                assert_eq!(fs::read(moved.join("owned")).unwrap(), b"owned");
                assert_eq!(fs::read(outside.join("foreign")).unwrap(), b"keep");
                if replacement == "file" {
                    assert_eq!(fs::read(&home).unwrap(), b"keep");
                } else {
                    assert_eq!(fs::read(home.join("foreign")).unwrap(), b"keep");
                }
            }
        }
    }

    #[test]
    fn host_state_cleanup_preserves_substituted_store() {
        for explicit in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(temp.path()).unwrap();
            let store = root.join("store");
            fs::DirBuilder::new().mode(0o700).create(&store).unwrap();
            let state = HostState::create(&store, "codex", &BTreeMap::new())
                .unwrap()
                .unwrap();
            let home = state.path.clone();
            fs::write(home.join("owned"), b"owned").unwrap();
            let name = home.file_name().unwrap().to_owned();
            let moved = root.join("moved-store");
            fs::rename(&store, &moved).unwrap();
            fs::DirBuilder::new().mode(0o700).create(&store).unwrap();
            fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
            fs::write(home.join("foreign"), b"keep").unwrap();
            if explicit {
                assert!(state.cleanup().is_err());
            } else {
                drop(state);
            }
            assert_eq!(fs::read(home.join("foreign")).unwrap(), b"keep");
            assert_eq!(fs::read(moved.join(name).join("owned")).unwrap(), b"owned");
        }
    }

    #[test]
    fn host_state_cleanup_refuses_changed_private_modes() {
        for parent in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(temp.path()).unwrap();
            let store = root.join("store");
            fs::DirBuilder::new().mode(0o700).create(&store).unwrap();
            let state = HostState::create(&store, "codex", &BTreeMap::new())
                .unwrap()
                .unwrap();
            let home = state.path.clone();
            fs::write(home.join("owned"), b"keep").unwrap();
            fs::set_permissions(
                if parent { &store } else { &home },
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            assert!(state.cleanup().is_err());
            assert_eq!(fs::read(home.join("owned")).unwrap(), b"keep");
        }
    }

    #[test]
    fn host_state_cleanup_refuses_missing_home_even_if_already_removed() {
        for moved in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let store = fs::canonicalize(temp.path()).unwrap();
            fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
            let state = HostState::create(&store, "claude", &BTreeMap::new())
                .unwrap()
                .unwrap();
            let home = state.path.clone();
            fs::write(home.join("owned"), b"keep").unwrap();
            let destination = store.join("moved");
            if moved {
                fs::rename(&home, &destination).unwrap();
            } else {
                fs::remove_dir_all(&home).unwrap();
            }
            assert!(state.cleanup().is_err());
            assert!(!home.exists());
            if moved {
                assert_eq!(fs::read(destination.join("owned")).unwrap(), b"keep");
            }
        }
    }

    #[test]
    fn host_state_cleanup_removes_child_alias_without_touching_target() {
        for explicit in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let store = fs::canonicalize(temp.path()).unwrap();
            fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
            let state = HostState::create(&store, "claude", &BTreeMap::new())
                .unwrap()
                .unwrap();
            let home = state.path.clone();
            let outside = store.join("outside");
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("foreign"), b"keep").unwrap();
            std::os::unix::fs::symlink(&outside, home.join("alias")).unwrap();
            if explicit {
                state.cleanup().unwrap();
            } else {
                drop(state);
            }
            assert!(!home.exists());
            assert_eq!(fs::read(outside.join("foreign")).unwrap(), b"keep");
        }
    }

    #[test]
    fn host_state_drop_does_not_retry_refused_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let store = fs::canonicalize(temp.path()).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        let mut state = HostState::create(&store, "codex", &BTreeMap::new())
            .unwrap()
            .unwrap();
        let home = state.path.clone();
        fs::write(home.join("owned"), b"keep").unwrap();
        let moved = store.join("moved");
        fs::rename(&home, &moved).unwrap();
        assert!(state.remove_owned_directory().is_err());
        fs::rename(&moved, &home).unwrap();
        drop(state);
        assert_eq!(fs::read(home.join("owned")).unwrap(), b"keep");
    }

    #[test]
    fn host_state_refuses_substituted_grants_and_cleans_owned_program() {
        let temp = tempfile::tempdir().unwrap();
        let store = fs::canonicalize(temp.path()).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        let source = store.join("source");
        fs::write(&source, b"inert fixture").unwrap();
        let hash = crate::sandbox::binary_hash(&source).unwrap();
        let state =
            HostState::create_with_program(&store, "codex", &BTreeMap::new(), &source, &hash)
                .unwrap()
                .unwrap();
        let copy = state
            .private_program_path("codex", &hash)
            .unwrap()
            .to_owned();
        let home = state.path.clone();
        let moved = store.join("moved");
        fs::rename(&home, &moved).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
        fs::write(home.join("foreign"), b"keep").unwrap();
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        let mut environment = BTreeMap::new();
        assert!(
            state
                .extend("codex", &store, &mut reads, &mut writes, &mut environment)
                .is_err()
        );
        assert!(reads.is_empty());
        assert!(writes.is_empty());
        assert!(environment.is_empty());
        assert!(state.cleanup().is_err());
        assert_eq!(fs::read(home.join("foreign")).unwrap(), b"keep");
        assert!(!copy.parent().unwrap().exists());
        assert!(moved.is_dir());
    }

    #[test]
    fn host_state_is_unique_private_and_api_key_only_then_removed() {
        let temp = tempfile::tempdir().unwrap();
        let store = fs::canonicalize(temp.path()).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        let env = [("OPENAI_API_KEY".into(), "synthetic-key".into())].into();
        let state = HostState::create(&store, "codex", &env).unwrap().unwrap();
        let second = HostState::create(&store, "codex", &BTreeMap::new())
            .unwrap()
            .unwrap();
        assert_ne!(state.path, second.path);
        assert_eq!(
            fs::metadata(&state.path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let auth = state.path.join("auth.json");
        assert_eq!(
            fs::metadata(&auth).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let value: serde_json::Value = serde_json::from_slice(&fs::read(auth).unwrap()).unwrap();
        assert_eq!(value, serde_json::json!({"OPENAI_API_KEY":"synthetic-key"}));
        assert_eq!(fs::read_dir(&second.path).unwrap().count(), 0);
        let path = state.path.clone();
        state.cleanup().unwrap();
        assert!(!path.exists());
        let path = second.path.clone();
        drop(second);
        assert!(!path.exists());
    }
    #[test]
    fn host_state_refuses_aliases_and_personal_directories() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let store = root.join("store");
        fs::DirBuilder::new().mode(0o700).create(&store).unwrap();
        std::os::unix::fs::symlink(&store, root.join("alias")).unwrap();
        assert!(HostState::create(&root.join("alias"), "codex", &BTreeMap::new()).is_err());
        for name in ["CODEX_HOME", "CLAUDE_CONFIG_DIR"] {
            let env = [(name.into(), "/personal".into())].into();
            assert!(HostState::create(&store, "codex", &env).is_err());
        }
        fs::set_permissions(&store, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(HostState::create(&store, "claude", &BTreeMap::new()).is_err());
    }
    #[test]
    fn host_state_cannot_expose_store_and_adds_only_one_write_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let store = root.join("store");
        fs::DirBuilder::new().mode(0o700).create(&store).unwrap();
        let state = HostState::create(&store, "claude", &BTreeMap::new())
            .unwrap()
            .unwrap();
        let cwd = root.join("repo");
        for forbidden in [
            &root,
            &store,
            &store.join("approval.key"),
            &store.join("runtime.sqlite3"),
        ] {
            assert!(
                state
                    .extend(
                        "claude",
                        &cwd,
                        &mut vec![forbidden.clone()],
                        &mut vec![],
                        &mut BTreeMap::new()
                    )
                    .is_err()
            );
            assert!(
                state
                    .extend(
                        "claude",
                        &cwd,
                        &mut vec![],
                        &mut vec![forbidden.clone()],
                        &mut BTreeMap::new()
                    )
                    .is_err()
            );
        }
        let mut reads = vec![cwd.clone()];
        let mut writes = vec![];
        let mut env = BTreeMap::new();
        state
            .extend("claude", &cwd, &mut reads, &mut writes, &mut env)
            .unwrap();
        assert_eq!(writes, [state.path.clone()]);
        assert_eq!(reads, [cwd, state.path.clone()]);
        assert_eq!(env["CLAUDE_CONFIG_DIR"], state.path.to_str().unwrap());
        assert!(!env.contains_key("CODEX_HOME"));
    }
}
