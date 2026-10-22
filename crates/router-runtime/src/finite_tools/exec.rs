//! Nested tool execution. This worker data is never Runtime approval or OS proof.
use crate::{Cancellation, ResourceLimits, Result, RuntimeError};
use router_types::{FiniteClientFile, ProcessCleanupEvidence, TransportTermination};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecSandbox {
    pub namespace: FiniteClientFile,
    pub helper: FiniteClientFile,
    pub guard: FiniteClientFile,
    pub compiler: FiniteClientFile,
    pub root: PathBuf,
    pub scratch: PathBuf,
    pub control: PathBuf,
    pub public: BTreeMap<String, String>,
    pub output: String,
}
fn flat(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn program(name: &str) -> Result<String> {
    match name {
        "python3" => Ok("/usr/bin/python3".into()),
        "rustc" => Ok("/usr/local/bin/rustc".into()),
        _ => name
            .strip_prefix(".scratch/")
            .filter(|n| flat(n))
            .map(|n| format!("/candidate/.scratch/{n}"))
            .ok_or(RuntimeError::Scope),
    }
}
impl ExecSandbox {
    /// The caller must hold a FilePolicy across every call. No result is
    /// returned before the exact helper lease excludes detached writers.
    pub async fn execute(
        &self,
        argv: &[String],
        timeout_ms: u64,
        max_output: usize,
        sequence: u32,
    ) -> Result<super::ToolResult> {
        if !cfg!(target_os = "linux")
            || argv.is_empty()
            || argv.len() > 32
            || argv
                .iter()
                .any(|s| s.is_empty() || s.len() > 4096 || s.contains('\0'))
            || argv.iter().map(String::len).sum::<usize>() > 16384
            || !(1..=20000).contains(&timeout_ms)
            || !(1..=8192).contains(&max_output)
            || !(1..=8).contains(&sequence)
            || self.public.is_empty()
            || self.public.len() > 64
            || !flat(&self.output)
        {
            return Err(RuntimeError::Limit);
        }
        for path in [&self.root, &self.scratch, &self.control] {
            if !path.is_absolute()
                || path == Path::new("/")
                || std::fs::canonicalize(path)? != *path
            {
                return Err(RuntimeError::Scope);
            }
        }
        if self.scratch.starts_with(&self.root)
            || self.control.starts_with(&self.root)
            || self.root.starts_with(&self.scratch)
            || self.root.starts_with(&self.control)
            || self.scratch == self.control
        {
            return Err(RuntimeError::Scope);
        }
        // Keep descriptor identities through stopped-namespace proof. The
        // outer owner must also exclude pathname writers during spawn/mount;
        // retaining a descriptor alone is not an atomic pathname lock.
        let _program_pins = [&self.namespace, &self.helper, &self.guard, &self.compiler]
            .into_iter()
            .map(crate::finite_client::retain_tool_program)
            .collect::<Result<Vec<_>>>()?;
        #[cfg(target_os = "linux")]
        {
            let filesystem =
                nix::sys::statfs::statfs(&self.scratch).map_err(std::io::Error::from)?;
            let capacity = u64::try_from(filesystem.block_size())
                .ok()
                .and_then(|block| block.checked_mul(filesystem.blocks()));
            if filesystem.filesystem_type() != nix::sys::statfs::TMPFS_MAGIC
                || capacity.is_none_or(|bytes| bytes == 0 || bytes > 16777216)
            {
                return Err(RuntimeError::Sandbox);
            }
        }
        if Path::new(&self.compiler.path).file_name() != Some(std::ffi::OsStr::new("rustc")) {
            return Err(RuntimeError::Scope);
        }
        let entry = program(&argv[0])?;
        let leases = crate::leases::LeaseStorage::open(&self.control)?;
        let id = format!("tool-{sequence}");
        let (mut record, lease) = leases.create(&id, 1)?;
        record.require_namespace(true);
        let mut command = tokio::process::Command::new(&self.helper.path);
        command
            .args(ResourceLimits::default().args()?)
            .arg("--supervise-v1")
            .arg(&self.namespace.path)
            .args([
                "--die-with-parent",
                "--new-session",
                "--unshare-all",
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
                "--dir",
                "/candidate",
            ]);
        let mut names: std::collections::BTreeSet<_> = self.public.keys().cloned().collect();
        if std::fs::symlink_metadata(self.root.join(&self.output)).is_ok() {
            names.insert(self.output.clone());
        }
        for name in names {
            if !flat(&name) {
                return Err(RuntimeError::Scope);
            }
            let source = self.root.join(&name);
            // FilePolicy checks the immutable hash and current owned output
            // inode before and after this callback. Recheck file safety here;
            // the mutable output must not be compared to its initial preimage.
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(&source)?;
            let meta = file.metadata()?;
            if !meta.is_file()
                || meta.nlink() != 1
                || meta.len() > 32768
                || meta.uid() != rustix::process::geteuid().as_raw()
                || meta.mode() & 0o7022 != 0
            {
                return Err(RuntimeError::Scope);
            }
            command
                .arg("--ro-bind")
                .arg(&source)
                .arg(format!("/candidate/{name}"));
        }
        command.arg("--bind").arg(&self.scratch).arg("/candidate/.scratch")
            .args(["--tmpfs","/usr/local/bin"])
            .arg("--ro-bind").arg(&self.compiler.path).arg("/usr/local/bin/rustc")
            .args(["--remount-ro","/usr/local/bin"])
            .arg("--ro-bind").arg(&self.guard.path).arg("/tool-guard")
            .args(["--remount-ro","/","--chdir","/candidate","--","/tool-guard","--tool-exec-v1","/candidate/.scratch","--"])
            .arg(entry).args(&argv[1..]).env_clear()
            .env("PATH","/usr/local/bin:/usr/local/rustup/toolchains/1.85.1-aarch64-unknown-linux-gnu/bin:/usr/bin:/bin")
            .env("HOME","/unavailable").env("TMPDIR","/candidate/.scratch").env("PYTHONDONTWRITEBYTECODE","1")
            .env("ROUTER_RUNTIME_SUPERVISION","framed-v1").env("ROUTER_RUNTIME_CONTAINMENT","pid-namespace-v1")
            .env("ROUTER_RUNTIME_LEASE",&lease);
        let started = Instant::now();
        let capture = crate::process::capture(
            command,
            vec![],
            timeout_ms,
            max_output,
            100,
            &Cancellation::default(),
        )
        .await;
        let proof = leases.cleanup_proof(&id, 1, &record)?;
        if proof.evidence != ProcessCleanupEvidence::NamespaceTerminated {
            return Err(RuntimeError::CleanupUnknown);
        }
        let captured = capture?;
        if captured.output_limited
            || captured.output_incomplete
            || captured.outcome.termination != TransportTermination::Exited
        {
            return Err(RuntimeError::Process);
        }
        Ok(super::ToolResult {
            stdout: String::from_utf8(captured.stdout).map_err(|_| RuntimeError::Process)?,
            stderr: String::from_utf8(captured.stderr).map_err(|_| RuntimeError::Process)?,
            exit_code: captured.outcome.exit_code.ok_or(RuntimeError::Process)?,
            termination: "exited".into(),
            truncated: false,
            elapsed_ms: started
                .elapsed()
                .as_millis()
                .try_into()
                .map_err(|_| RuntimeError::Limit)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entry_programs_are_absolute_and_scratch_cannot_escape() {
        assert_eq!(program("python3").unwrap(), "/usr/bin/python3");
        assert_eq!(program("rustc").unwrap(), "/usr/local/bin/rustc");
        assert_eq!(
            program(".scratch/check").unwrap(),
            "/candidate/.scratch/check"
        );
        for name in [
            "sh",
            "/bin/sh",
            "../rustc",
            ".scratch/../x",
            ".scratch/x/y",
            "",
        ] {
            assert!(program(name).is_err(), "{name}");
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the explicit Linux lab"]
    fn linux_tool_exec_refuses_uncapped_scratch_before_effect() {
        use std::os::unix::fs::DirBuilderExt;
        let root = PathBuf::from(std::env::var("AR_MCP_ROOT").unwrap()).join("uncapped");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let candidate = root.join("candidate");
        let scratch = root.join("scratch");
        let control = root.join("control");
        for p in [&candidate, &scratch, &control] {
            std::fs::DirBuilder::new().mode(0o700).create(p).unwrap();
        }
        std::fs::write(candidate.join("output.txt"), b"public").unwrap();
        let programs = PathBuf::from(std::env::var("AR_MCP_PROGRAMS").unwrap());
        let pin = |name: &str| {
            let p = programs.join(name);
            FiniteClientFile {
                path: p.to_str().unwrap().into(),
                sha256: router_adapter_api::content_digest(&std::fs::read(p).unwrap()),
            }
        };
        let sandbox = ExecSandbox {
            namespace: pin("namespace"),
            helper: pin("helper"),
            guard: pin("guard"),
            compiler: pin("compiler/rustc"),
            root: candidate,
            scratch: scratch.clone(),
            control: control.clone(),
            public: BTreeMap::from([(
                "output.txt".into(),
                router_adapter_api::content_digest(b"public"),
            )]),
            output: "output.txt".into(),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let outcome = runtime.block_on(sandbox.execute(
            &[
                "python3".into(),
                "-c".into(),
                "open('.scratch/sentinel','w').write('unexpected')".into(),
            ],
            1000,
            1024,
            1,
        ));
        assert!(outcome.is_err());
        assert!(!scratch.join("sentinel").exists());
        assert!(!control.join("leases").exists());
    }
}
