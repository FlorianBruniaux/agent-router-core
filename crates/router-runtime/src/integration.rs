//! Publish a verified patch through one Git ref CAS, without writing user files.
use crate::{PendingRun, Result, Runtime, RuntimeError, digest, source_state, workspace};
use router_types::*;
use std::{collections::BTreeMap, path::Path};

const MAX_BLOB_BYTES: usize = 16 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 100_000;

impl Runtime {
    /// Reads the captured artifact and reconstructs its exact result on a private
    /// index. Objects may be written; no ref or user working file is changed.
    pub async fn review_publication(&self, pending: &PendingRun) -> Result<PatchPublicationReview> {
        let root = Path::new(&pending.request.workspace);
        let repository_sha256 = repository_identity(root, None).await?;
        let preview = self.integration_preview(pending).await?;
        if preview.changed_paths.len() > 1024
            || preview.changed_paths.iter().map(String::len).sum::<usize>() > 64 * 1024
        {
            return Err(RuntimeError::Limit);
        }
        if preview.changed_paths.is_empty() {
            return Err(RuntimeError::Verification);
        }
        let bytes =
            workspace::read_artifact(&self.store.root, &preview.run_id, &preview.artifact_sha256)?;
        if bytes.contains(&0)
            || bytes
                .split(|b| *b == b'\n')
                .any(|line| line == b"GIT binary patch")
        {
            return Err(RuntimeError::Invalid(
                "binary publication patches are not supported",
            ));
        }
        // Canonical runtime capture uses --no-renames. Refuse these extended
        // forms explicitly so destination-only metadata cannot hide a source.
        if bytes.split(|b| *b == b'\n').any(|line| {
            [
                b"rename from ".as_slice(),
                b"rename to ",
                b"copy from ",
                b"copy to ",
            ]
            .iter()
            .any(|prefix| line.starts_with(prefix))
        }) {
            return Err(RuntimeError::Invalid(
                "rename or copy publication patches are not supported",
            ));
        }
        let diff = String::from_utf8(bytes.clone())
            .map_err(|_| RuntimeError::Invalid("non-UTF8 review diff"))?;
        let verification = self
            .store
            .verification_record(&preview.run_id)?
            .ok_or(RuntimeError::Verification)?;
        if verification.artifact_sha256.as_deref() != Some(preview.artifact_sha256.as_str())
            || verification.validation != VerificationOutcome::Passed
            || verification.objective != VerificationOutcome::Passed
        {
            return Err(RuntimeError::Verification);
        }
        workspace::safe_scope(root, &preview.changed_paths)?;
        if preview
            .changed_paths
            .iter()
            .any(|p| p.chars().any(char::is_control))
        {
            return Err(RuntimeError::Scope);
        }
        // Bound full index inventory before read-tree and changed source bytes
        // before cached apply. Text additions cannot exceed patch length.
        bound_tree(root, &preview.source_state).await?;
        let before = blobs(root, &preview.source_state, &preview.changed_paths).await?;
        bound_blobs(root, &before, bytes.len()).await?;
        let private = tempfile::Builder::new()
            .prefix("integration-index-")
            .tempdir_in(&self.store.root)?;
        let index = private.path().join("index");
        workspace::git_index(root, &["read-tree", &preview.source_state], vec![], &index).await?;
        workspace::git_index(
            root,
            &["apply", "--cached", "--binary", "--whitespace=nowarn", "-"],
            bytes,
            &index,
        )
        .await?;
        let result_tree = oid(workspace::git_index(root, &["write-tree"], vec![], &index).await?)?;
        let after = blobs(root, &result_tree, &preview.changed_paths).await?;
        bound_blobs(root, &after, 0).await?;
        let mut files = Vec::new();
        for path in &preview.changed_paths {
            let before = before.get(path).cloned();
            let after = after.get(path).cloned();
            if before == after
                || before
                    .iter()
                    .chain(after.iter())
                    .any(|b| !matches!(b.mode.as_str(), "100644" | "100755"))
            {
                return Err(RuntimeError::Scope);
            }
            files.push(IntegrationFile {
                path: path.clone(),
                before,
                after,
            });
        }
        // Git independently reconstructs the displayed patch from result objects,
        // rather than trusting a separately supplied display file or worker text.
        let reconstructed = workspace::git(
            root,
            &[
                "diff",
                "--binary",
                "--no-renames",
                "--no-ext-diff",
                "--no-textconv",
                &preview.source_state,
                &result_tree,
                "--",
            ],
            vec![],
        )
        .await?;
        if reconstructed != diff.as_bytes() {
            return Err(RuntimeError::Integrity("reconstructed patch changed"));
        }
        let result_revision = oid(workspace::git_index(
            root,
            &[
                "-c",
                "user.name=Agent Router",
                "-c",
                "user.email=agent-router@example.invalid",
                "-c",
                "commit.gpgSign=false",
                "commit-tree",
                &result_tree,
                "-p",
                &preview.source_state,
            ],
            b"Agent Router verified patch\n".to_vec(),
            &index,
        )
        .await?)?;
        let mut review = PatchPublicationReview {
            schema_version: 1,
            run_id: preview.run_id,
            definition_sha256: pending.run.definition_hash.clone(),
            repository_sha256: repository_sha256.clone(),
            source_revision: preview.source_state,
            artifact_sha256: preview.artifact_sha256,
            files,
            result_tree,
            result_revision,
            verification,
            diff,
            approval_digest: String::new(),
        };
        review.approval_digest = review_digest(&review)?;
        Ok(review)
    }
    /// Validates the actual review payload at read time, including its diff.
    /// Validation is not application authority.
    pub async fn validate_publication_review(
        &self,
        pending: &PendingRun,
        review: &PatchPublicationReview,
    ) -> Result<()> {
        if review.schema_version != 1
            || review.run_id.len() > 128
            || review.diff.len() > 16 * 1024 * 1024
            || review.files.len() > 1024
            || review.files.iter().map(|f| f.path.len()).sum::<usize>() > 64 * 1024
            || review.files.iter().any(|f| {
                f.path.len() > 1024
                    || f.before.iter().chain(f.after.iter()).any(|b| {
                        !valid_oid(&b.oid) || !matches!(b.mode.as_str(), "100644" | "100755")
                    })
            })
            || ![
                &review.definition_sha256,
                &review.repository_sha256,
                &review.artifact_sha256,
                &review.approval_digest,
                &review.verification.evidence_sha256,
            ]
            .iter()
            .all(|v| router_adapter_api::is_digest(v))
            || review.verification.verifier.len() > 128
            || review.verification.artifact_sha256.as_ref() != Some(&review.artifact_sha256)
            || ![
                &review.source_revision,
                &review.result_tree,
                &review.result_revision,
            ]
            .iter()
            .all(|v| valid_oid(v))
        {
            return Err(RuntimeError::Invalid(
                "publication review bounds or version",
            ));
        }
        if review_digest(review)? != review.approval_digest
            || self.review_publication(pending).await? != *review
        {
            return Err(RuntimeError::Integrity("publication review changed"));
        }
        Ok(())
    }
    pub async fn publish_patch(
        &self,
        pending: &PendingRun,
        approval: &str,
    ) -> Result<PatchPublicationReceipt> {
        self.publish_patch_observed(pending, approval, None).await
    }
    async fn publish_patch_observed(
        &self,
        pending: &PendingRun,
        approval: &str,
        observer: Option<&dyn workspace::CaptureObserver>,
    ) -> Result<PatchPublicationReceipt> {
        self.require_integration_authority(pending)?;
        let review = self.review_publication(pending).await?;
        if review.approval_digest != approval {
            return Err(RuntimeError::Approval);
        }
        let receipt = PatchPublicationReceipt {
            schema_version: 1,
            run_id: review.run_id.clone(),
            approval_digest: review.approval_digest,
            source_revision: review.source_revision,
            result_revision: review.result_revision,
            result_tree: review.result_tree,
            target_ref: format!("refs/agent-router/integrations/{approval}"),
        };
        let detail = serde_json::to_string(&receipt)?;
        self.store.claim_integration(&receipt.run_id, &detail)?;
        // The final read is after the durable claim. A refusal here consumes the
        // claim conservatively; it must never be cleared for an automatic retry.
        if source_state(Path::new(&pending.request.workspace)).await? != receipt.source_revision {
            return Err(RuntimeError::SourceChanged);
        }
        self.integration_preview(pending).await?;
        if repository_identity(Path::new(&pending.request.workspace), None).await?
            != review.repository_sha256
        {
            return Err(RuntimeError::Integrity("repository identity changed"));
        }
        self.require_integration_authority(pending)?;
        let authority = PublicationAuthority {
            runtime: self,
            pending,
            observer,
        };
        complete_publication(
            self,
            Path::new(&pending.request.workspace),
            &receipt,
            Some(&authority),
        )
        .await?;
        if self.publication_status(pending).await?.state != PatchPublicationState::Published {
            return Err(RuntimeError::Integrity("published revision changed"));
        }
        Ok(receipt)
    }
    /// Observation only: never repairs, rolls back, or replays an intent.
    pub async fn publication_status(&self, pending: &PendingRun) -> Result<PatchPublicationStatus> {
        observe_publication(
            self,
            &pending.run.run_id,
            &pending.request.source_state,
            Path::new(&pending.request.workspace),
        )
        .await
    }
}
// The Git wrapper calls this after its async preparation and again immediately
// before spawning update-ref. It rechecks proofs, not a retained routing claim.
struct PublicationAuthority<'a> {
    runtime: &'a Runtime,
    pending: &'a PendingRun,
    observer: Option<&'a dyn workspace::CaptureObserver>,
}
impl workspace::CaptureObserver for PublicationAuthority<'_> {
    fn before_capture(&self) -> Result<()> {
        if let Some(observer) = self.observer {
            observer.before_capture()?;
        }
        // Permissions were checked on this immutable PendingRun before the
        // publication attempt. Retain fresh proof results to check their joint
        // validity after all executable hashes and log reads have completed.
        let snapshot = self.runtime.snapshot(&self.pending.context)?;
        publication_clock_valid(
            crate::now()?,
            snapshot.observation().observed_at_unix_seconds,
            self.runtime.limits.snapshot_max_age_seconds,
            snapshot
                .capability_proofs()
                .iter()
                .map(|proof| proof.expires_at_unix_seconds),
        )
    }
    fn after_capture(&self) -> Result<()> {
        if let Some(observer) = self.observer {
            observer.after_capture()?;
        }
        Ok(())
    }
}
fn publication_clock_valid(
    now: u64,
    observed: u64,
    max_age: u64,
    mut expiries: impl Iterator<Item = u64>,
) -> Result<()> {
    if now.checked_sub(observed).is_none_or(|age| age > max_age)
        || expiries.any(|expiry| now > expiry)
    {
        return Err(RuntimeError::Route);
    }
    Ok(())
}
async fn complete_publication(
    runtime: &Runtime,
    root: &Path,
    receipt: &PatchPublicationReceipt,
    observer: Option<&dyn workspace::CaptureObserver>,
) -> Result<()> {
    repository_identity(root, Some(&receipt.target_ref)).await?;
    // A null-OID create can overwrite a dangling symbolic ref in Git. Refuse
    // existing symbolic refs separately; unrelated same-user writers racing in
    // this dedicated namespace are outside the managed-publisher guarantee.
    if workspace::symbolic_ref(root, &receipt.target_ref).await? {
        return Err(RuntimeError::Integrity(
            "publication destination is symbolic",
        ));
    }
    let command = format!(
        "create {} {}\n",
        receipt.target_ref, receipt.result_revision
    );
    workspace::git_observed(
        root,
        &["update-ref", "--no-deref", "--stdin"],
        command.into_bytes(),
        observer,
    )
    .await?;
    runtime.store.event(
        &receipt.run_id,
        "integration.published",
        &serde_json::to_string(receipt)?,
    )
}
async fn observe_publication(
    runtime: &Runtime,
    run_id: &str,
    source_revision: &str,
    root: &Path,
) -> Result<PatchPublicationStatus> {
    let events = runtime.store.integration_events(run_id)?;
    let Some((kind, detail)) = events.first() else {
        return Ok(PatchPublicationStatus {
            schema_version: 1,
            state: PatchPublicationState::NotAttempted,
            receipt: None,
            observed_revision: None,
        });
    };
    if kind != "integration.intent" || events.len() > 2 {
        return Err(RuntimeError::Integrity("integration event order"));
    }
    let Ok(receipt) = serde_json::from_str::<PatchPublicationReceipt>(detail) else {
        // Legacy in-place application intent has no publication receipt.
        return Ok(PatchPublicationStatus {
            schema_version: 1,
            state: PatchPublicationState::Unknown,
            receipt: None,
            observed_revision: None,
        });
    };
    if receipt.schema_version != 1
        || receipt.run_id != run_id
        || receipt.source_revision != source_revision
        || !router_adapter_api::is_digest(&receipt.approval_digest)
        || !valid_oid(&receipt.result_revision)
        || !valid_oid(&receipt.result_tree)
        || receipt.target_ref
            != format!("refs/agent-router/integrations/{}", receipt.approval_digest)
    {
        return Err(RuntimeError::Integrity("publication intent"));
    }
    let observed_revision = match workspace::git(
        root,
        &["show-ref", "--verify", "--hash", &receipt.target_ref],
        vec![],
    )
    .await
    {
        Ok(bytes) => Some(oid(bytes)?),
        Err(RuntimeError::Process) => None,
        Err(error) => return Err(error),
    };
    let symbolic = match workspace::git(
        root,
        &["symbolic-ref", "--quiet", &receipt.target_ref],
        vec![],
    )
    .await
    {
        Ok(_) => true,
        Err(RuntimeError::Process) => false,
        Err(error) => return Err(error),
    };
    let complete = !symbolic
        && events
            .get(1)
            .is_some_and(|(k, d)| k == "integration.published" && d == detail);
    let state = if complete && observed_revision.as_ref() == Some(&receipt.result_revision) {
        PatchPublicationState::Published
    } else {
        PatchPublicationState::Unknown
    };
    Ok(PatchPublicationStatus {
        schema_version: 1,
        state,
        receipt: Some(receipt),
        observed_revision,
    })
}
async fn repository_identity(root: &Path, target: Option<&str>) -> Result<String> {
    use std::{
        fs,
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    if fs::canonicalize(root)? != root {
        return Err(RuntimeError::Scope);
    }
    let root_meta = fs::symlink_metadata(root)?;
    let dotgit = root.join(".git");
    let meta = fs::symlink_metadata(&dotgit)?;
    let pointer = if meta.is_file() {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&dotgit)?;
        if !file.metadata()?.is_file() || file.metadata()?.len() > 16_384 {
            return Err(RuntimeError::Scope);
        }
        let mut bytes = Vec::new();
        file.take(16_385).read_to_end(&mut bytes)?;
        if bytes.len() > 16_384 {
            return Err(RuntimeError::Limit);
        }
        Some(router_adapter_api::content_digest(&bytes))
    } else if meta.is_dir() && !meta.file_type().is_symlink() {
        None
    } else {
        return Err(RuntimeError::Scope);
    };
    let mut identities = Vec::new();
    for flag in ["--git-dir", "--git-common-dir"] {
        let bytes =
            workspace::git(root, &["rev-parse", "--path-format=absolute", flag], vec![]).await?;
        let path = std::str::from_utf8(&bytes)
            .map_err(|_| RuntimeError::Scope)?
            .trim_end_matches('\n');
        let path = Path::new(path);
        if !path.is_absolute() || fs::canonicalize(path)? != path {
            return Err(RuntimeError::Scope);
        }
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(RuntimeError::Scope);
        }
        check_git_storage(path, target)?;
        identities.push((path.to_owned(), meta.dev(), meta.ino()));
    }
    digest(
        "runtime-integration-repository-v1",
        &(
            root,
            root_meta.dev(),
            root_meta.ino(),
            meta.dev(),
            meta.ino(),
            pointer,
            identities,
        ),
    )
}
fn check_git_storage(git_dir: &Path, target: Option<&str>) -> Result<()> {
    use std::fs;
    for part in [
        "objects",
        "objects/info",
        "objects/pack",
        "refs",
        "refs/agent-router",
        "refs/agent-router/integrations",
        "logs",
        "logs/refs",
        "logs/refs/agent-router",
        "logs/refs/agent-router/integrations",
    ] {
        match fs::symlink_metadata(git_dir.join(part)) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err(RuntimeError::Scope),
            Err(error) => return Err(error.into()),
        }
    }
    match fs::read_dir(git_dir.join("objects")) {
        Ok(entries) => {
            for (count, entry) in entries.enumerate() {
                if count >= 512 {
                    return Err(RuntimeError::Limit);
                }
                let entry = entry?;
                let name = entry.file_name();
                let name = name.as_encoded_bytes();
                if name.len() == 2
                    && name.iter().all(u8::is_ascii_hexdigit)
                    && !entry.file_type()?.is_dir()
                {
                    return Err(RuntimeError::Scope);
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if let Some(target) = target {
        match fs::symlink_metadata(git_dir.join("logs").join(target)) {
            Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err(RuntimeError::Scope),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn review_digest(review: &PatchPublicationReview) -> Result<String> {
    let mut unsigned = review.clone();
    unsigned.approval_digest.clear();
    digest("runtime-patch-publication-v1", &unsigned)
}
fn valid_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn oid(bytes: Vec<u8>) -> Result<String> {
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| RuntimeError::Integrity("Git object identity"))?
        .trim_end_matches('\n');
    if !valid_oid(value) {
        return Err(RuntimeError::Integrity("Git object identity"));
    }
    Ok(value.into())
}
async fn bound_tree(root: &Path, tree: &str) -> Result<()> {
    let inventory = workspace::git(root, &["ls-tree", "-r", "-z", tree], vec![]).await?;
    if inventory
        .split(|b| *b == 0)
        .filter(|row| !row.is_empty())
        .count()
        > MAX_TREE_ENTRIES
    {
        return Err(RuntimeError::Limit);
    }
    Ok(())
}
async fn bound_blobs(
    root: &Path,
    blobs: &BTreeMap<String, IntegrationBlob>,
    initial: usize,
) -> Result<()> {
    let mut total = initial;
    for blob in blobs.values() {
        if !matches!(blob.mode.as_str(), "100644" | "100755") {
            return Err(RuntimeError::Scope);
        }
        let size = workspace::git(root, &["cat-file", "-s", &blob.oid], vec![]).await?;
        let size: usize = std::str::from_utf8(&size)
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .ok_or(RuntimeError::Integrity("Git blob size"))?;
        total = total.checked_add(size).ok_or(RuntimeError::Limit)?;
        if total > MAX_BLOB_BYTES {
            return Err(RuntimeError::Limit);
        }
    }
    Ok(())
}
async fn blobs(
    root: &Path,
    tree: &str,
    paths: &[String],
) -> Result<BTreeMap<String, IntegrationBlob>> {
    let mut args = vec!["--literal-pathspecs", "ls-tree", "-r", "-z", tree, "--"];
    args.extend(paths.iter().map(String::as_str));
    let bytes = workspace::git(root, &args, vec![]).await?;
    let mut values = BTreeMap::new();
    for line in bytes.split(|b| *b == 0).filter(|l| !l.is_empty()) {
        let (header, path) = line.split_at(
            line.iter()
                .position(|b| *b == b'\t')
                .ok_or(RuntimeError::Integrity("Git tree entry"))?,
        );
        let header = std::str::from_utf8(header).map_err(|_| RuntimeError::Scope)?;
        let fields: Vec<_> = header.split(' ').collect();
        let path = std::str::from_utf8(&path[1..]).map_err(|_| RuntimeError::Scope)?;
        if fields.len() != 3
            || !valid_oid(fields[2])
            || values
                .insert(
                    path.into(),
                    IntegrationBlob {
                        mode: fields[0].into(),
                        oid: fields[2].into(),
                    },
                )
                .is_some()
        {
            return Err(RuntimeError::Integrity("Git tree entry"));
        }
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuntimeLimits, store::tests::summary};
    use std::{
        fs,
        process::Command,
        sync::atomic::{AtomicUsize, Ordering},
    };
    #[test]
    fn publication_clock_rejects_first_proof_expiring_during_later_checks() {
        assert!(publication_clock_valid(120, 100, 30, [120, 200].into_iter()).is_ok());
        assert!(matches!(
            publication_clock_valid(121, 100, 30, [120, 200].into_iter()),
            Err(RuntimeError::Route)
        ));
        assert!(matches!(
            publication_clock_valid(131, 100, 30, [200].into_iter()),
            Err(RuntimeError::Route)
        ));
        assert!(matches!(
            publication_clock_valid(99, 100, 30, [200].into_iter()),
            Err(RuntimeError::Route)
        ));
    }
    struct Cut {
        after_effect: bool,
        calls: AtomicUsize,
    }
    impl workspace::CaptureObserver for Cut {
        fn before_capture(&self) -> Result<()> {
            if !self.after_effect && self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
                return Err(RuntimeError::Cancelled);
            }
            Ok(())
        }
        fn after_capture(&self) -> Result<()> {
            if self.after_effect && self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
                return Err(RuntimeError::Cancelled);
            }
            Ok(())
        }
    }
    fn git(root: &Path, args: &[&str]) -> String {
        let output = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "Git fixture failed: {args:?}");
        String::from_utf8(output.stdout).unwrap().trim_end().into()
    }
    fn fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        PatchPublicationReceipt,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap().join("repo");
        fs::create_dir(&root).unwrap();
        git(&root, &["init", "-q"]);
        fs::write(root.join("first"), "before").unwrap();
        fs::write(root.join("second"), "before").unwrap();
        git(&root, &["add", "."]);
        git(
            &root,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--no-gpg-sign",
                "-qm",
                "base",
            ],
        );
        let source = git(&root, &["rev-parse", "HEAD"]);
        fs::write(root.join("first"), "after").unwrap();
        fs::write(root.join("second"), "after").unwrap();
        git(&root, &["add", "."]);
        git(
            &root,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--no-gpg-sign",
                "-qm",
                "candidate",
            ],
        );
        let result = git(&root, &["rev-parse", "HEAD"]);
        let tree = git(&root, &["rev-parse", "HEAD^{tree}"]);
        // Fixture-only reset restores the source. Production never resets it.
        git(&root, &["reset", "--hard", &source]);
        let approval = "a".repeat(64);
        let receipt = PatchPublicationReceipt {
            schema_version: 1,
            run_id: "run".into(),
            approval_digest: approval.clone(),
            source_revision: source,
            result_revision: result,
            result_tree: tree,
            target_ref: format!("refs/agent-router/integrations/{approval}"),
        };
        (temp, root, receipt)
    }
    fn runtime(root: &Path, receipt: &PatchPublicationReceipt) -> Runtime {
        let runtime = Runtime::open(root, RuntimeLimits::default()).unwrap();
        let mut run = summary(&receipt.run_id);
        run.state = RunState::Verified;
        runtime.store.register(&run).unwrap();
        runtime
            .store
            .claim_integration(&receipt.run_id, &serde_json::to_string(receipt).unwrap())
            .unwrap();
        runtime
    }
    #[tokio::test]
    async fn interrupted_publication_remains_unknown_and_never_rolls_back_user_edits() {
        for after_effect in [false, true] {
            let (temp, root, receipt) = fixture();
            let storage = temp.path().join("runtime");
            let runtime = runtime(&storage, &receipt);
            let cut = Cut {
                after_effect,
                calls: AtomicUsize::new(0),
            };
            assert!(matches!(
                complete_publication(&runtime, &root, &receipt, Some(&cut)).await,
                Err(RuntimeError::Cancelled)
            ));
            drop(runtime);
            // Simulate one user file changing while the owner is absent.
            fs::write(root.join("first"), "concurrent user change").unwrap();
            let reopened = Runtime::open(&storage, RuntimeLimits::default()).unwrap();
            let status =
                observe_publication(&reopened, &receipt.run_id, &receipt.source_revision, &root)
                    .await
                    .unwrap();
            assert_eq!(status.state, PatchPublicationState::Unknown);
            assert_eq!(
                status.observed_revision,
                after_effect.then(|| receipt.result_revision.clone())
            );
            assert!(
                reopened
                    .store
                    .claim_integration(&receipt.run_id, &serde_json::to_string(&receipt).unwrap())
                    .is_err()
            );
            assert_eq!(
                fs::read_to_string(root.join("first")).unwrap(),
                "concurrent user change"
            );
            assert_eq!(fs::read_to_string(root.join("second")).unwrap(), "before");
            if after_effect {
                assert_eq!(
                    git(&root, &["show", &format!("{}:second", receipt.target_ref)]),
                    "after"
                );
            }
        }
    }
    #[tokio::test]
    async fn separate_runtime_stores_cannot_both_create_the_same_publication() {
        let (temp, root, receipt) = fixture();
        let a = runtime(&temp.path().join("a"), &receipt);
        let b = runtime(&temp.path().join("b"), &receipt);
        let (ra, rb) = tokio::join!(
            complete_publication(&a, &root, &receipt, None),
            complete_publication(&b, &root, &receipt, None)
        );
        assert_eq!(usize::from(ra.is_ok()) + usize::from(rb.is_ok()), 1);
        let sa = observe_publication(&a, &receipt.run_id, &receipt.source_revision, &root)
            .await
            .unwrap();
        let sb = observe_publication(&b, &receipt.run_id, &receipt.source_revision, &root)
            .await
            .unwrap();
        assert_eq!(
            usize::from(sa.state == PatchPublicationState::Published)
                + usize::from(sb.state == PatchPublicationState::Published),
            1
        );
    }
    #[tokio::test]
    async fn substituted_ref_directory_cannot_write_outside_git_metadata() {
        use std::os::unix::fs::symlink;
        let (temp, root, receipt) = fixture();
        let runtime = runtime(&temp.path().join("runtime"), &receipt);
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, root.join(".git/refs/agent-router")).unwrap();
        assert!(
            complete_publication(&runtime, &root, &receipt, None)
                .await
                .is_err()
        );
        assert_eq!(
            fs::read_dir(&outside).unwrap().count(),
            0,
            "no reference or lock may be created through the substituted directory"
        );
    }
    #[tokio::test]
    async fn publication_cannot_follow_a_symbolic_ref_to_an_unrelated_target() {
        let (temp, root, receipt) = fixture();
        let runtime = runtime(&temp.path().join("runtime"), &receipt);
        let other = "refs/heads/unrelated-empty-branch";
        git(&root, &["symbolic-ref", &receipt.target_ref, other]);
        let _ = complete_publication(&runtime, &root, &receipt, None).await;
        let output = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(&root)
            .args(["show-ref", "--verify", other])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "publication must never dereference to an unrelated branch"
        );
    }
}
