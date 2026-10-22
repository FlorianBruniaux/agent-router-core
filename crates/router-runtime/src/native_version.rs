//! A version pin is a requirement, never evidence until this probe succeeds.
use crate::{
    Cancellation, NetworkAuthority, Result, RuntimeError, SandboxPolicy, SandboxSupervisor,
    leases::LeaseStorage, process::capture,
};
use router_adapter_api::content_digest;
use router_types::{
    ExecutionSandbox, PreparedInput, PreparedRun, ProcessCleanupEvidence, TransportOutcome,
    TransportTermination,
};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static PROBE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const TIMEOUT_MS: u64 = 5_000;
const MAX_BYTES: usize = 8_192;

struct ProbeDirectory(std::path::PathBuf);
impl Drop for ProbeDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Deliberately not serializable or Debug: a hostile version command may print
/// sensitive data. Only a host-specific strict parser should inspect stdout.
pub struct NativeVersionProbe {
    stdout: Vec<u8>,
    pub output_sha256: String,
    pub outcome: TransportOutcome,
    pub cleanup: ProcessCleanupEvidence,
}
impl NativeVersionProbe {
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }
}

/// Execute only `--version`, with no prompt, no network and a read-only sandbox.
/// The trusted supervisor rechecks the approved binary and helper identities.
/// This proves neither authentication nor model/effort availability.
pub async fn probe_native_version(
    supervisor: &dyn SandboxSupervisor,
    prepared: &PreparedRun,
    private_dir: &Path,
    cancel: &Cancellation,
) -> Result<NativeVersionProbe> {
    probe_native_version_inner(supervisor, prepared, private_dir, cancel, None).await
}

pub(crate) async fn probe_native_version_recorded(
    supervisor: &dyn SandboxSupervisor,
    prepared: &PreparedRun,
    private_dir: &Path,
    cancel: &Cancellation,
    preparation: &crate::store::Preparation<'_>,
) -> Result<NativeVersionProbe> {
    probe_native_version_inner(supervisor, prepared, private_dir, cancel, Some(preparation)).await
}

async fn probe_native_version_inner(
    supervisor: &dyn SandboxSupervisor,
    prepared: &PreparedRun,
    private_dir: &Path,
    cancel: &Cancellation,
    preparation: Option<&crate::store::Preparation<'_>>,
) -> Result<NativeVersionProbe> {
    if !supervisor.parent_lifetime_enforced() || !supervisor.resource_limits_enforced() {
        return Err(RuntimeError::Sandbox);
    }
    let meta = fs::symlink_metadata(private_dir)?;
    if !meta.is_dir()
        || meta.permissions().mode() & 0o077 != 0
        || meta.uid() != rustix::process::geteuid().as_raw()
        || fs::canonicalize(private_dir)? != private_dir
    {
        return Err(RuntimeError::Integrity("version probe directory"));
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeError::Invalid("clock"))?
        .as_nanos();
    let id = format!(
        "version-{}-{}-{}",
        std::process::id(),
        stamp,
        PROBE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    // Keep project-local configuration out of a version-only invocation. The
    // child can read this empty working directory, not the runtime store root.
    let cwd = private_dir.join(&id);
    fs::DirBuilder::new().mode(0o700).create(&cwd)?;
    // Removed on every exit, including errors and a dropped future. The
    // unique name means only this call ever creates or reads it.
    let _cwd_guard = ProbeDirectory(cwd.clone());
    let mut run = prepared.clone();
    run.argv = vec!["--version".into()];
    run.stdin = PreparedInput::new(Vec::new());
    run.cwd = cwd
        .to_str()
        .ok_or(RuntimeError::Invalid("utf8 probe path"))?
        .into();
    run.scope.clear();
    run.sandbox = ExecutionSandbox::ReadOnly;
    run.timeout_ms = TIMEOUT_MS;
    run.max_output_bytes = MAX_BYTES;
    let mut host_state = supervisor.create_host_state(private_dir, &run)?;
    let mut command = supervisor.command(
        &run,
        &SandboxPolicy {
            network: NetworkAuthority::Deny,
            host_state: host_state.as_ref(),
        },
    )?;
    let leases = LeaseStorage::open(private_dir)?;
    let registered = if let Some(preparation) = preparation {
        Some(preparation.register_probe_with_host_state(host_state.is_some())?)
    } else {
        None
    };
    let local = if registered.is_none() {
        Some(leases.create(&id, 0)?)
    } else {
        None
    };
    let path = registered
        .as_ref()
        .map(|(_, p)| p)
        .or_else(|| local.as_ref().map(|(_, p)| p))
        .ok_or(RuntimeError::Integrity("missing probe lease"))?;
    command.env("ROUTER_RUNTIME_LEASE", path);
    if let Some(state) = &mut host_state {
        state.arm_cleanup(Some(path), supervisor.pid_namespace_isolated())?;
    }
    let captured = capture(command, Vec::new(), TIMEOUT_MS, MAX_BYTES, 100, cancel).await;
    // Invalidate an unstarted lease too, so a delayed helper cannot launch after
    // a failed spawn. Active or ambiguous cleanup never authorizes execution.
    let cleanup = match (preparation, registered.as_ref(), local.as_ref()) {
        (Some(preparation), Some((id, _)), None) => {
            preparation.resolve_probe_and_state(id, host_state.take())?
        }
        (None, None, Some((record, _))) => {
            let proof = leases.cleanup_proof(&id, 0, record)?;
            if let Some(state) = host_state.take() {
                state
                    .cleanup_with_proof(&proof)
                    .map_err(|_| RuntimeError::CleanupUnknown)?;
            }
            proof.evidence
        }
        _ => return Err(RuntimeError::Integrity("probe registration")),
    };
    let captured = captured?;
    if !matches!(
        cleanup,
        ProcessCleanupEvidence::GroupTerminated | ProcessCleanupEvidence::NamespaceTerminated
    ) {
        return Err(RuntimeError::CleanupUnknown);
    }
    if captured.output_limited {
        return Err(RuntimeError::Limit);
    }
    // Capture may observe exit before cancellation arrives during stream
    // collection. Keep cleanup, output bounds and an observed timeout intact.
    if captured.outcome.termination == TransportTermination::Cancelled
        || (captured.outcome.termination == TransportTermination::Exited && cancel.is_cancelled())
    {
        return Err(RuntimeError::Cancelled);
    }
    if captured.outcome.termination != TransportTermination::Exited
        || captured.outcome.exit_code != Some(0)
        || !captured.stderr.is_empty()
    {
        return Err(RuntimeError::Process);
    }
    Ok(NativeVersionProbe {
        output_sha256: content_digest(&captured.stdout),
        stdout: captured.stdout,
        outcome: captured.outcome,
        cleanup,
    })
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use crate::HostState;
    use router_types::*;
    use std::collections::BTreeMap;
    use tokio::process::Command;

    struct LeaseFixture {
        marker: &'static str,
        namespace: bool,
        hold: bool,
    }
    impl SandboxSupervisor for LeaseFixture {
        fn create_host_state(&self, store: &Path, _: &PreparedRun) -> Result<Option<HostState>> {
            HostState::create(store, "codex", &BTreeMap::new())
        }
        fn command(&self, _: &PreparedRun, policy: &SandboxPolicy) -> Result<Command> {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", r#"printf owned > "$HOME/owned"; printf '%s\n' "$MARKER" > "$ROUTER_RUNTIME_LEASE"; printf 'fixture-version\n'; while [ "$HOLD" = 1 ]; do /bin/sleep 0.05; done"#])
                .env_clear()
                .env("HOME", policy.host_state.unwrap().path())
                .env("MARKER", self.marker)
                .env("HOLD", if self.hold { "1" } else { "0" });
            Ok(command)
        }
        fn parent_lifetime_enforced(&self) -> bool {
            true
        }
        fn resource_limits_enforced(&self) -> bool {
            true
        }
        fn pid_namespace_isolated(&self) -> bool {
            self.namespace
        }
    }
    fn run(root: &Path) -> PreparedRun {
        PreparedRun {
            schema_version: 1,
            receipt_id: "a".repeat(64),
            source_state: "b".repeat(40),
            scope: vec![],
            authorization_digest: "c".repeat(64),
            snapshot_hash: "d".repeat(64),
            host: HarnessId::parse("codex").unwrap(),
            requested_model: ModelId::parse("fixture").unwrap(),
            requested_effort: EffortLevel::Low,
            program: "codex".into(),
            argv: vec![],
            cwd: root.to_string_lossy().into_owned(),
            stdin: PreparedInput::new(vec![]),
            mode: ExecutionMode::Execute,
            target: ExecutionTarget::ExternalWorker,
            sandbox: ExecutionSandbox::ReadOnly,
            timeout_ms: 1000,
            max_output_bytes: 8192,
            degradations: vec![],
            missing_runtime_evidence: vec![],
            parent_model_changed: false,
        }
    }
    #[tokio::test]
    async fn version_cleanup_uses_matching_namespace_proof() {
        // Trusted protocol fixture only, not an OS namespace qualification.
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let supervisor = LeaseFixture {
            marker: "router-runtime-lease-v1:namespace-clean",
            namespace: true,
            hold: false,
        };
        let result =
            probe_native_version(&supervisor, &run(&root), &root, &Cancellation::default())
                .await
                .unwrap();
        assert_eq!(result.stdout(), b"fixture-version\n");
        assert_eq!(result.cleanup, ProcessCleanupEvidence::NamespaceTerminated);
        assert!(!fs::read_dir(&root).unwrap().any(|p| {
            p.unwrap()
                .file_name()
                .as_encoded_bytes()
                .starts_with(b"host-state-")
        }));
    }

    #[tokio::test]
    async fn aborted_version_future_preserves_exposed_home() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let task_root = root.clone();
        let task = tokio::spawn(async move {
            let supervisor = LeaseFixture {
                marker: "router-runtime-lease-v1:active",
                namespace: false,
                hold: true,
            };
            probe_native_version(
                &supervisor,
                &run(&task_root),
                &task_root,
                &Cancellation::default(),
            )
            .await
        });
        let ready = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if let Some(home) = fs::read_dir(&root)
                    .unwrap()
                    .map(|p| p.unwrap().path())
                    .find(|p| fs::read(p.join("owned")).is_ok_and(|bytes| bytes == b"owned"))
                {
                    break home;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        assert_eq!(fs::read(ready.unwrap().join("owned")).unwrap(), b"owned");
    }

    #[tokio::test]
    async fn version_cleanup_preserves_home_without_namespace_stop() {
        for marker in [
            "router-runtime-lease-v1:active",
            "router-runtime-lease-v1:group-clean",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(temp.path()).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let supervisor = LeaseFixture {
                marker,
                namespace: false,
                hold: false,
            };
            let result =
                probe_native_version(&supervisor, &run(&root), &root, &Cancellation::default())
                    .await;
            let homes: Vec<_> = fs::read_dir(&root)
                .unwrap()
                .map(|p| p.unwrap().path())
                .filter(|p| {
                    p.file_name()
                        .unwrap()
                        .as_encoded_bytes()
                        .starts_with(b"host-state-")
                })
                .collect();
            assert_eq!(homes.len(), 1, "must preserve state after {marker}");
            assert_eq!(fs::read(homes[0].join("owned")).unwrap(), b"owned");
            assert!(matches!(result, Err(RuntimeError::CleanupUnknown)));
        }
    }
}
