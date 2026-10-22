//! One producer-owned private write view. No process or publication authority.
use super::*;
use std::path::PathBuf;
const MAX_FILE: u64 = 32768;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FiniteOutputMode {
    ReplaceExisting,
    CreateNew,
}

pub struct FiniteClientWorkspace {
    path: PathBuf,
    parent: PathBuf,
    source: PathBuf,
    owner: PathBuf,
    task_id: String,
    head: String,
    relative: String,
    preimage: Option<String>,
    view_identity: PinnedIdentity,
    parent_identity: PinnedIdentity,
    source_identity: PinnedIdentity,
    target_identity: Option<PinnedIdentity>,
}
#[derive(Clone)]
pub(super) struct WriteDispatch {
    pub(super) path: PathBuf,
    pub(super) source: PathBuf,
    pub(super) owner: PathBuf,
    pub(super) task_id: String,
    pub(super) head: String,
    pub(super) relative: String,
    pub(super) preimage: Option<String>,
}
impl WriteDispatch {
    pub(super) async fn check_sources(
        &self,
        observer: Option<&dyn crate::workspace::CaptureObserver>,
    ) -> Result<()> {
        if crate::workspace::source_state_observed(&self.source, observer).await? != self.head
            || crate::workspace::source_state_observed(&self.path, observer).await? != self.head
        {
            return Err(RuntimeError::SourceChanged);
        }
        Ok(())
    }
}
fn flat_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn target_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.len() > MAX_FILE
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o7022 != 0
    {
        return Err(RuntimeError::Scope);
    }
    Ok(file)
}
fn target_hash(path: &Path) -> Result<String> {
    let mut bytes = vec![];
    target_file(path)?
        .take(MAX_FILE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(RuntimeError::Limit);
    }
    Ok(content_digest(&bytes))
}
fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => Err(RuntimeError::Scope),
    }
}
impl FiniteClientWorkspace {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn source_state(&self) -> &str {
        &self.head
    }
    pub fn scope(&self) -> &[String] {
        std::slice::from_ref(&self.relative)
    }
    pub fn preimage_sha256(&self) -> Option<&str> {
        self.preimage.as_deref()
    }
    pub(super) fn existing_preimage(&self) -> Result<&str> {
        self.preimage.as_deref().ok_or(RuntimeError::Sandbox)
    }
    fn check_initial_target(&self) -> Result<()> {
        for root in [&self.path, &self.source] {
            match &self.preimage {
                Some(expected) if target_hash(&root.join(&self.relative))? == *expected => {}
                Some(_) => return Err(RuntimeError::SourceChanged),
                None => absent(&root.join(&self.relative))?,
            }
        }
        Ok(())
    }
    pub(super) fn dispatch(&self) -> WriteDispatch {
        WriteDispatch {
            path: self.path.clone(),
            source: self.source.clone(),
            owner: self.owner.clone(),
            task_id: self.task_id.clone(),
            head: self.head.clone(),
            relative: self.relative.clone(),
            preimage: self.preimage.clone(),
        }
    }
    pub(super) fn check_identity(&self) -> Result<()> {
        if directory(self.path.to_str().ok_or(RuntimeError::Scope)?, true)?.identity
            != self.view_identity.identity
            || directory(self.parent.to_str().ok_or(RuntimeError::Scope)?, true)?.identity
                != self.parent_identity.identity
        {
            return Err(RuntimeError::Integrity("finite workspace identity"));
        }
        match &self.target_identity {
            Some(expected)
                if FileIdentity::from(
                    &target_file(&self.path.join(&self.relative))?.metadata()?,
                ) == expected.identity
                    && FileIdentity::from(&expected._file.metadata()?) == expected.identity => {}
            Some(_) => return Err(RuntimeError::Integrity("finite workspace target identity")),
            None => absent(&self.path.join(&self.relative))?,
        }
        Ok(())
    }
    pub(super) fn check_for_review(&self, store: &Path, id: &str, run: &PreparedRun) -> Result<()> {
        self.check_identity()?;
        if self.owner != store
            || self.task_id != id
            || self.path != Path::new(&run.cwd)
            || self.head != run.source_state
            || self.scope() != run.scope
            || run.sandbox != router_types::ExecutionSandbox::WorkspaceWrite
            || directory(self.source.to_str().ok_or(RuntimeError::Scope)?, false)?.identity
                != self.source_identity.identity
        {
            return Err(RuntimeError::Integrity("finite workspace review"));
        }
        self.check_initial_target()?;
        Ok(())
    }
    fn binding(&self) -> Result<String> {
        crate::digest(
            "finite-workspace-review-v1",
            &(
                &self.path,
                &self.parent,
                &self.source,
                &self.owner,
                &self.task_id,
                &self.head,
                &self.relative,
                &self.preimage,
                &self.view_identity.identity,
                &self.parent_identity.identity,
                &self.source_identity.identity,
                &self.target_identity.as_ref().map(|p| &p.identity),
            ),
        )
    }
    /// Discards only an unconsumed preparation. Once consumed by a review this
    /// handle is unavailable. Executed views remain retained for patch review.
    pub async fn discard(self) -> Result<()> {
        self.check_identity()?;
        if self.preimage.is_none() {
            self.check_initial_target()?;
        }
        if directory(self.source.to_str().ok_or(RuntimeError::Scope)?, false)?.identity
            != self.source_identity.identity
        {
            return Err(RuntimeError::Integrity("finite workspace source"));
        }
        crate::workspace::git(
            &self.source,
            &[
                "worktree",
                "remove",
                "--force",
                self.path.to_str().ok_or(RuntimeError::Scope)?,
            ],
            vec![],
        )
        .await?;
        Ok(())
    }
}
impl FiniteClientReview {
    /// Binds an actual producer-created view before final approval. Never
    /// relocates a frozen run or accepts an arbitrary path from a receipt.
    pub fn with_write_workspace(mut self, workspace: FiniteClientWorkspace) -> Result<Self> {
        if self.owned_workspace.is_some() || self.owned_assets.is_none() {
            return Err(RuntimeError::Sandbox);
        }
        let state = self.owned_state.as_ref().ok_or(RuntimeError::Sandbox)?;
        workspace.check_for_review(
            state.path().parent().ok_or(RuntimeError::Scope)?,
            &self.manifest.task_id,
            &self.run,
        )?;
        self.approval = crate::digest(
            "finite-client-workspace-v1",
            &(&self.approval, workspace.binding()?),
        )?;
        self.owned_workspace = Some(workspace);
        self.check_files()?;
        Ok(self)
    }
}
impl crate::Runtime {
    /// Records an explicit existing-file or absent-file output grant. Preparation
    /// never creates the output and never grants execution or publication.
    /// The current Linux backend refuses CreateNew until its tools profile is
    /// independently approved and qualified.
    pub async fn prepare_finite_output_workspace(
        &self,
        source: &Path,
        task_id: &str,
        relative: &str,
        mode: FiniteOutputMode,
    ) -> Result<FiniteClientWorkspace> {
        self.prepare_finite_workspace_inner(source, task_id, &[relative.into()], mode)
            .await
    }
    /// Copies the clean public Git snapshot into a private, detached write view
    /// before context/review construction. One existing flat file only. This
    /// grants no native execution, admission, publication or integration.
    pub async fn prepare_finite_workspace(
        &self,
        source: &Path,
        task_id: &str,
        scope: &[String],
    ) -> Result<FiniteClientWorkspace> {
        self.prepare_finite_workspace_inner(
            source,
            task_id,
            scope,
            FiniteOutputMode::ReplaceExisting,
        )
        .await
    }
    async fn prepare_finite_workspace_inner(
        &self,
        source: &Path,
        task_id: &str,
        scope: &[String],
        mode: FiniteOutputMode,
    ) -> Result<FiniteClientWorkspace> {
        if !router_adapter_api::safe_identifier(task_id)
            || task_id.len() > 96
            || scope.len() != 1
            || !flat_name(&scope[0])
            || source.starts_with(&self.store.root)
            || self.store.root.starts_with(source)
        {
            return Err(RuntimeError::Scope);
        }
        let relative = scope[0].clone();
        let source_identity = directory(source.to_str().ok_or(RuntimeError::Scope)?, false)?;
        crate::workspace::safe_scope(source, scope)?;
        let preimage = match mode {
            FiniteOutputMode::ReplaceExisting => Some(target_hash(&source.join(&relative))?),
            FiniteOutputMode::CreateNew => {
                absent(&source.join(&relative))?;
                None
            }
        };
        let head = crate::source_state(source).await?;
        let parent = self
            .store
            .root
            .parent()
            .ok_or(RuntimeError::Scope)?
            .join(format!(
                "finite-workspaces-{}",
                crate::admission_runtime_root_hash(&self.store.root)?
            ));
        if parent.starts_with(source) || source.starts_with(&parent) {
            return Err(RuntimeError::Scope);
        }
        match fs::DirBuilder::new().mode(0o700).create(&parent) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let parent_identity = directory(parent.to_str().ok_or(RuntimeError::Scope)?, true)?;
        let path = crate::workspace::create(source, &parent, task_id, &head, None).await?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let view_identity = directory(path.to_str().ok_or(RuntimeError::Scope)?, true)?;
        let target_identity = if preimage.is_some() {
            let file = target_file(&path.join(&relative))?;
            Some(PinnedIdentity {
                identity: FileIdentity::from(&file.metadata()?),
                _file: file,
            })
        } else {
            absent(&path.join(&relative))?;
            None
        };
        let view = FiniteClientWorkspace {
            path,
            parent,
            source: source.into(),
            owner: self.store.root.clone(),
            task_id: task_id.into(),
            head,
            relative,
            preimage,
            view_identity,
            parent_identity,
            source_identity,
            target_identity,
        };
        if crate::source_state(source).await? != view.head
            || crate::source_state(view.path()).await? != view.head
        {
            return Err(RuntimeError::SourceChanged);
        }
        view.check_identity()?;
        view.check_initial_target()?;
        Ok(view)
    }
}

impl FiniteClientWorkspace {
    /// Post-stop transfer into this producer-owned artifact view only. The
    /// caller authenticates the staged terminal and retains the exact lease.
    /// The original repository is never written or published here.
    pub(super) fn promote_tools_output(
        &self,
        mut source: File,
        observed: &crate::finite_tools::ToolOutput,
    ) -> Result<File> {
        use rustix::fs::{Mode, OFlags, openat};
        use std::io::{Seek, SeekFrom};
        self.check_identity()?;
        self.check_initial_target()?;
        if observed.relative != self.relative || observed.bytes > MAX_FILE {
            return Err(RuntimeError::Scope);
        }
        let before = source.metadata()?;
        if !before.is_file()
            || before.nlink() != 1
            || before.uid() != rustix::process::geteuid().as_raw()
            || (before.dev(), before.ino(), before.mode(), before.len())
                != (
                    observed.device,
                    observed.inode,
                    observed.mode,
                    observed.bytes,
                )
        {
            return Err(RuntimeError::Integrity("finite staged output identity"));
        }
        source.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        source.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != observed.bytes || content_digest(&bytes) != observed.sha256 {
            return Err(RuntimeError::Integrity("finite staged output bytes"));
        }
        let create = self.preimage.is_none();
        let flags = OFlags::RDWR
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC
            | if create {
                OFlags::CREATE | OFlags::EXCL
            } else {
                OFlags::empty()
            };
        let mut destination = File::from(
            openat(
                &self.view_identity._file,
                self.relative.as_str(),
                flags,
                // Nine permission bits fit mode_t on both Linux and macOS.
                Mode::from_raw_mode((observed.mode & 0o777) as _),
            )
            .map_err(std::io::Error::from)?,
        );
        let meta = destination.metadata()?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.mode() & 0o7022 != 0
        {
            return Err(RuntimeError::Scope);
        }
        if let Some(expected) = &self.target_identity {
            if FileIdentity::from(&meta) != expected.identity
                || FileIdentity::from(&expected._file.metadata()?) != expected.identity
            {
                return Err(RuntimeError::Integrity("finite submitted output identity"));
            }
            let mut initial = Vec::new();
            Read::by_ref(&mut destination)
                .take(MAX_FILE + 1)
                .read_to_end(&mut initial)?;
            if self.preimage.as_ref() != Some(&content_digest(&initial)) {
                return Err(RuntimeError::SourceChanged);
            }
        } else if meta.len() != 0 {
            return Err(RuntimeError::Scope);
        }
        destination.seek(SeekFrom::Start(0))?;
        destination.set_len(0)?;
        destination.write_all(&bytes)?;
        destination.sync_all()?;
        let after = destination.metadata()?;
        if FileIdentity::from(&after) != FileIdentity::from(&meta)
            || after.len() != observed.bytes
            || after.mode() != observed.mode
        {
            return Err(RuntimeError::Integrity("finite submitted output changed"));
        }
        Ok(destination)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn fixture() -> (tempfile::TempDir, crate::Runtime, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        let source = base.join("source");
        fs::DirBuilder::new().mode(0o700).create(&source).unwrap();
        fs::write(source.join("allowed.rs"), b"before\n").unwrap();
        for args in [
            vec!["init", "-q"],
            vec!["add", "allowed.rs"],
            vec![
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "-q",
                "--no-gpg-sign",
                "-m",
                "public source",
            ],
        ] {
            crate::workspace::git(&source, &args, vec![]).await.unwrap();
        }
        let runtime = crate::Runtime::open(&base.join("runtime"), Default::default()).unwrap();
        (root, runtime, source)
    }
    #[tokio::test]
    async fn explicitly_approved_creation_keeps_output_absent_until_the_write() {
        let (_root, runtime, source) = fixture().await;
        let view = runtime
            .prepare_finite_output_workspace(
                &source,
                "new-output",
                "review.json",
                FiniteOutputMode::CreateNew,
            )
            .await
            .unwrap();
        assert!(!source.join("review.json").exists());
        assert!(
            !view.path().join("review.json").exists(),
            "preparation must never precreate the approved output"
        );
        assert_eq!(view.preimage_sha256(), None);
        assert!(matches!(
            view.existing_preimage(),
            Err(RuntimeError::Sandbox)
        ));
        view.dispatch().check_sources(None).await.unwrap();
        view.discard().await.unwrap();
    }
    #[tokio::test]
    async fn creation_grant_rejects_a_preexisting_file_or_a_dangling_symlink() {
        let (_root, runtime, source) = fixture().await;
        assert!(
            runtime
                .prepare_finite_output_workspace(
                    &source,
                    "existing",
                    "allowed.rs",
                    FiniteOutputMode::CreateNew,
                )
                .await
                .is_err()
        );
        std::os::unix::fs::symlink("missing", source.join("review.json")).unwrap();
        assert!(
            runtime
                .prepare_finite_output_workspace(
                    &source,
                    "link",
                    "review.json",
                    FiniteOutputMode::CreateNew,
                )
                .await
                .is_err()
        );
        assert!(
            fs::symlink_metadata(source.join("review.json"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
    #[tokio::test]
    async fn an_appeared_creation_target_revokes_the_frozen_absence() {
        let (_root, runtime, source) = fixture().await;
        let view = runtime
            .prepare_finite_output_workspace(
                &source,
                "appeared",
                "review.json",
                FiniteOutputMode::CreateNew,
            )
            .await
            .unwrap();
        let before = view.binding().unwrap();
        fs::write(view.path().join("review.json"), b"unexpected").unwrap();
        assert!(view.check_initial_target().is_err());
        assert_eq!(
            view.binding().unwrap(),
            before,
            "changed state cannot mint a fresh approval implicitly"
        );
        assert!(!source.join("review.json").exists());
    }
    #[tokio::test]
    async fn a_new_private_output_is_captured_without_touching_the_source_index() {
        let (_root, runtime, source) = fixture().await;
        let original_index = fs::read(source.join(".git/index")).unwrap();
        let original_head = crate::source_state(&source).await.unwrap();
        let view = runtime
            .prepare_finite_output_workspace(
                &source,
                "new-patch",
                "review.json",
                FiniteOutputMode::CreateNew,
            )
            .await
            .unwrap();
        // An authored local effect tests patch capture, not native tool access.
        fs::write(view.path().join("review.json"), b"{\"findings\":[]}\n").unwrap();
        let (patch, paths) =
            crate::workspace::patch(view.path(), view.scope(), view.source_state())
                .await
                .unwrap();
        assert_eq!(paths, ["review.json"]);
        let text = String::from_utf8(patch).unwrap();
        assert!(text.contains("new file mode 100644"));
        assert!(text.contains("+{\"findings\":[]}"));
        assert_eq!(fs::read(source.join(".git/index")).unwrap(), original_index);
        assert_eq!(crate::source_state(&source).await.unwrap(), original_head);
        assert!(!source.join("review.json").exists());
    }
    #[tokio::test]
    async fn an_appeared_symlink_is_not_treated_as_an_absent_output() {
        let (_root, runtime, source) = fixture().await;
        let view = runtime
            .prepare_finite_output_workspace(
                &source,
                "appeared-link",
                "review.json",
                FiniteOutputMode::CreateNew,
            )
            .await
            .unwrap();
        std::os::unix::fs::symlink("missing", view.path().join("review.json")).unwrap();
        assert!(view.check_identity().is_err());
        assert!(view.check_initial_target().is_err());
        assert!(!source.join("review.json").exists());
    }
    #[tokio::test]
    async fn finite_workspace_is_prepared_before_review_and_keeps_original_bytes() {
        let (_root, runtime, source) = fixture().await;
        let view = runtime
            .prepare_finite_workspace(&source, "bounded", &["allowed.rs".into()])
            .await
            .unwrap();
        assert_ne!(view.path(), source);
        assert!(!view.path().starts_with(&runtime.store.root));
        assert_eq!(
            crate::source_state(view.path()).await.unwrap(),
            view.source_state()
        );
        assert_eq!(
            fs::read(view.path().join("allowed.rs")).unwrap(),
            b"before\n"
        );
        assert_eq!(fs::read(source.join("allowed.rs")).unwrap(), b"before\n");
        assert_eq!(
            view.existing_preimage().unwrap(),
            content_digest(b"before\n")
        );
        // Some serializes transparently, preserving the existing v1 approval.
        let legacy_binding = crate::digest(
            "finite-workspace-review-v1",
            &(
                &view.path,
                &view.parent,
                &view.source,
                &view.owner,
                &view.task_id,
                &view.head,
                &view.relative,
                view.existing_preimage().unwrap(),
                &view.view_identity.identity,
                &view.parent_identity.identity,
                &view.source_identity.identity,
                &view.target_identity.as_ref().unwrap().identity,
            ),
        )
        .unwrap();
        assert_eq!(view.binding().unwrap(), legacy_binding);
        let a = fs::metadata(view.path().join("allowed.rs")).unwrap();
        let b = fs::metadata(source.join("allowed.rs")).unwrap();
        assert_ne!((a.dev(), a.ino()), (b.dev(), b.ino()));
        assert_eq!(a.nlink(), 1);
    }
    #[tokio::test]
    async fn finite_workspace_binds_the_exact_view_and_refuses_stale_preimages() {
        let (_root, runtime, source) = fixture().await;
        let view = runtime
            .prepare_finite_workspace(&source, "bounded", &["allowed.rs".into()])
            .await
            .unwrap();
        let run = PreparedRun {
            schema_version: 1,
            receipt_id: "a".repeat(64),
            source_state: view.head.clone(),
            scope: view.scope().to_vec(),
            authorization_digest: "b".repeat(64),
            snapshot_hash: "c".repeat(64),
            host: router_types::HarnessId::parse("codex").unwrap(),
            requested_model: router_types::ModelId::parse("fixture").unwrap(),
            requested_effort: router_types::EffortLevel::Medium,
            program: "finite-client".into(),
            argv: vec!["--worker".into()],
            cwd: view.path.to_str().unwrap().into(),
            stdin: router_types::PreparedInput::new(vec![]),
            mode: router_types::ExecutionMode::Execute,
            target: router_types::ExecutionTarget::ExternalWorker,
            sandbox: router_types::ExecutionSandbox::WorkspaceWrite,
            timeout_ms: 1000,
            max_output_bytes: 65536,
            degradations: vec![],
            missing_runtime_evidence: vec![],
            parent_model_changed: false,
        };
        view.check_for_review(&runtime.store.root, "bounded", &run)
            .unwrap();
        assert!(
            view.check_for_review(&runtime.store.root, "another", &run)
                .is_err()
        );
        assert!(view.check_for_review(&source, "bounded", &run).is_err());
        let mut relocated = run.clone();
        relocated.cwd = source.to_str().unwrap().into();
        assert!(
            view.check_for_review(&runtime.store.root, "bounded", &relocated)
                .is_err()
        );
        fs::write(view.path.join("allowed.rs"), b"after\n").unwrap();
        assert!(
            view.check_for_review(&runtime.store.root, "bounded", &run)
                .is_err()
        );
        // Scoped mutations must not prevent identity-based cleanup afterwards.
        view.check_identity().unwrap();
        assert_eq!(fs::read(source.join("allowed.rs")).unwrap(), b"before\n");
        let path = view.path.clone();
        view.discard().await.unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn finite_workspace_rechecks_non_target_files_before_dispatch() {
        let (_root, runtime, source) = fixture().await;
        let view = runtime
            .prepare_finite_workspace(&source, "bounded", &["allowed.rs".into()])
            .await
            .unwrap();
        let dispatch = view.dispatch();
        dispatch.check_sources(None).await.unwrap();
        fs::write(view.path().join("unexpected.rs"), b"drift").unwrap();
        assert!(matches!(
            dispatch.check_sources(None).await,
            Err(RuntimeError::SourceChanged)
        ));
        assert_eq!(fs::read(source.join("allowed.rs")).unwrap(), b"before\n");
        view.discard().await.unwrap();
    }
    #[tokio::test]
    async fn finite_workspace_refuses_directories_multiple_files_and_escapes() {
        let (_root, runtime, source) = fixture().await;
        for scope in [
            vec![],
            vec!["allowed.rs".into(), "other.rs".into()],
            vec!["../outside".into()],
            vec![".git".into()],
            vec!["missing.rs".into()],
            vec!["src/file.rs".into()],
        ] {
            assert!(
                runtime
                    .prepare_finite_workspace(&source, "bad", &scope)
                    .await
                    .is_err()
            );
        }
    }
}
