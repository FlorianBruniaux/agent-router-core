//! Explicit artifact attestation without execution or publication authority.
use super::ApprovedFiniteClientRun;
use crate::{Result, Runtime, RuntimeError, workspace};
use router_types::{
    PhaseVerification, ProcessCleanupEvidence, RunState, RunSummary, VerificationRecord,
};

/// Retained by the explicit verifier before the approved run is consumed.
/// This in-memory handle borrows its Runtime and cannot reopen another store.
/// It grants neither execution nor publication authority, even after Passed.
/// ```compile_fail
/// use router_runtime::{Runtime, FiniteClientVerifier};
/// async fn publish(runtime: &Runtime, verifier: &FiniteClientVerifier<'_>) {
///     runtime.review_publication(verifier).await;
/// }
/// ```
pub struct FiniteClientVerifier<'runtime> {
    runtime: &'runtime Runtime,
    run_id: String,
    definition_hash: String,
    approval_digest: String,
    owner: String,
    independent: bool,
}

impl Runtime {
    /// Retain explicit verification authority for this approved finite run.
    /// No snapshot is refreshed and no process, admission or verifier is run.
    pub fn finite_client_verifier<'runtime>(
        &'runtime self,
        approved: &ApprovedFiniteClientRun,
    ) -> Result<FiniteClientVerifier<'runtime>> {
        let pending = &approved.approved.pending;
        self.validate_pending_retention(pending)?;
        let run = self.store.get(&pending.run.run_id)?;
        if run.state != RunState::Queued
            || run.definition_hash != pending.run.definition_hash
            || run.approval_digest != pending.run.approval_digest
            || pending.finite_client_binding.as_deref()
                != Some(approved.client.reviewed.approval_digest())
        {
            return Err(RuntimeError::Approval);
        }
        Ok(FiniteClientVerifier {
            runtime: self,
            run_id: run.run_id,
            definition_hash: run.definition_hash,
            approval_digest: run.approval_digest,
            owner: pending.node.owner.clone(),
            independent: pending.decision.selection().candidate.verification
                == PhaseVerification::Independent,
        })
    }
}
impl FiniteClientVerifier<'_> {
    fn current(&self) -> Result<RunSummary> {
        let run = self.runtime.store.get(&self.run_id)?;
        if run.state != RunState::Verifying
            || run.definition_hash != self.definition_hash
            || run.approval_digest != self.approval_digest
            || self.runtime.cleanup_evidence(&self.run_id)?
                != ProcessCleanupEvidence::NamespaceTerminated
        {
            return Err(RuntimeError::Verification);
        }
        Ok(run)
    }
    /// Returns the bounded captured bytes whose digest is checked at read time.
    /// A separately supplied display file is never substituted for this patch.
    pub fn artifact(&self) -> Result<Vec<u8>> {
        let run = self.current()?;
        let hash = run
            .artifact_sha256
            .as_deref()
            .ok_or(RuntimeError::Verification)?;
        let bytes = workspace::read_artifact(&self.runtime.store.root, &self.run_id, hash)?;
        if bytes.is_empty() {
            return Err(RuntimeError::Verification);
        }
        Ok(bytes)
    }
    /// Records a trusted caller's attestation, not provider output or a parsed
    /// receipt. The caller owns evidence provenance and objective evaluation.
    /// UNKNOWN stays inconclusive; Passed is not a human or publication verdict.
    pub fn record(&self, record: VerificationRecord) -> Result<RunSummary> {
        self.artifact()?;
        self.runtime
            .record_verification_for(&self.run_id, &self.owner, self.independent, record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Runtime, store::tests::summary, workspace};
    use router_types::*;
    use std::fs;

    fn fixture(clean: bool) -> (tempfile::TempDir, Runtime) {
        fixture_artifact(clean, Some(b"fixture patch\n"))
    }
    fn fixture_artifact(clean: bool, bytes: Option<&[u8]>) -> (tempfile::TempDir, Runtime) {
        let temp = tempfile::tempdir().unwrap();
        let runtime = Runtime::open(&temp.path().join("runtime"), Default::default()).unwrap();
        runtime.store.register(&summary("finite")).unwrap();
        for state in [RunState::AwaitingApproval, RunState::Queued] {
            runtime
                .store
                .transition("finite", state, "fixture", None)
                .unwrap();
        }
        let prep = runtime.store.begin_preparation("finite").unwrap();
        prep.no_child_yet().unwrap();
        prep.complete().unwrap();
        drop(prep);
        let lease = runtime.store.attempt("finite", 1, true).unwrap().unwrap();
        runtime
            .store
            .transition("finite", RunState::Running, "fixture", None)
            .unwrap();
        fs::write(
            lease,
            if clean {
                b"router-runtime-lease-v1:namespace-clean\n".as_slice()
            } else {
                b"router-runtime-lease-v1:group-clean\n".as_slice()
            },
        )
        .unwrap();
        runtime.store.confirm_attempt_cleanup("finite").unwrap();
        if let Some(bytes) = bytes {
            workspace::write_artifact(&runtime.store.root, "finite", bytes).unwrap();
            runtime
                .store
                .artifact("finite", &router_adapter_api::content_digest(bytes))
                .unwrap();
        }
        runtime
            .store
            .transition("finite", RunState::SucceededTransport, "fixture", None)
            .unwrap();
        runtime
            .store
            .transition("finite", RunState::Verifying, "fixture", None)
            .unwrap();
        (temp, runtime)
    }
    fn handle(runtime: &Runtime) -> FiniteClientVerifier<'_> {
        FiniteClientVerifier {
            runtime,
            run_id: "finite".into(),
            definition_hash: "a".repeat(64),
            approval_digest: "b".repeat(64),
            owner: "worker".into(),
            independent: true,
        }
    }
    fn record() -> VerificationRecord {
        VerificationRecord {
            verifier: "external-checker".into(),
            evidence_sha256: "e".repeat(64),
            artifact_sha256: Some(router_adapter_api::content_digest(b"fixture patch\n")),
            validation: VerificationOutcome::Passed,
            objective: VerificationOutcome::Passed,
        }
    }
    #[test]
    fn finite_verifier_records_unknown_then_explicit_pass_and_refuses_replay() {
        let (_temp, runtime) = fixture(true);
        let verifier = handle(&runtime);
        assert_eq!(verifier.artifact().unwrap(), b"fixture patch\n");
        let mut unknown = record();
        unknown.objective = VerificationOutcome::Unknown;
        assert_eq!(verifier.record(unknown).unwrap().state, RunState::Verifying);
        assert_eq!(verifier.record(record()).unwrap().state, RunState::Verified);
        let before = runtime.verification_record("finite").unwrap();
        assert!(verifier.record(record()).is_err());
        assert_eq!(runtime.verification_record("finite").unwrap(), before);
        runtime.verify_integrity().unwrap();
    }
    #[test]
    fn finite_verifier_records_failure_without_turning_it_into_acceptance() {
        let (_temp, runtime) = fixture(true);
        let mut failure = record();
        failure.validation = VerificationOutcome::Failed;
        assert_eq!(
            handle(&runtime).record(failure).unwrap().state,
            RunState::VerificationFailed
        );
    }
    #[test]
    fn finite_verifier_refuses_wrong_identity_record_and_non_namespace_cleanup() {
        for variant in 0..8 {
            let (_temp, runtime) = fixture(variant != 7);
            let mut verifier = handle(&runtime);
            let mut evidence = record();
            match variant {
                0 => verifier.definition_hash = "d".repeat(64),
                1 => verifier.approval_digest = "d".repeat(64),
                2 => evidence.verifier = "worker".into(),
                3 => evidence.evidence_sha256 = "invalid".into(),
                4 => evidence.artifact_sha256 = Some("d".repeat(64)),
                5 => evidence.artifact_sha256 = None,
                6 => evidence.verifier.clear(),
                _ => (),
            }
            assert!(verifier.record(evidence).is_err(), "variant {variant}");
            assert_eq!(
                runtime.summary("finite").unwrap().state,
                RunState::Verifying
            );
            assert_eq!(runtime.verification_record("finite").unwrap(), None);
        }
    }
    #[test]
    fn finite_verifier_refuses_changed_missing_or_symlink_artifact_at_read_and_record() {
        for variant in 0..3 {
            let (_temp, runtime) = fixture(true);
            let verifier = handle(&runtime);
            assert!(verifier.artifact().is_ok());
            let path = runtime.store.root.join("artifacts/finite.patch");
            if variant == 0 {
                fs::write(path, b"substituted").unwrap();
            } else {
                fs::remove_file(&path).unwrap();
                if variant == 2 {
                    let target = runtime.store.root.join("replacement");
                    fs::write(&target, b"fixture patch\n").unwrap();
                    std::os::unix::fs::symlink(target, path).unwrap();
                }
            }
            assert!(verifier.artifact().is_err());
            assert!(verifier.record(record()).is_err());
            assert_eq!(runtime.verification_record("finite").unwrap(), None);
        }
    }
    #[test]
    fn finite_verifier_refuses_absent_digest_and_empty_captured_artifact() {
        for bytes in [None, Some(b"".as_slice())] {
            let (_temp, runtime) = fixture_artifact(true, bytes);
            let verifier = handle(&runtime);
            let mut evidence = record();
            evidence.artifact_sha256 = bytes.map(router_adapter_api::content_digest);
            assert!(verifier.artifact().is_err());
            assert!(verifier.record(evidence).is_err());
            assert_eq!(runtime.verification_record("finite").unwrap(), None);
            assert_eq!(
                runtime.summary("finite").unwrap().state,
                RunState::Verifying
            );
            runtime.verify_integrity().unwrap();
        }
    }
    #[test]
    fn finite_verifier_concurrent_attestations_only_commit_once() {
        let (_temp, runtime) = fixture(true);
        let verifier = handle(&runtime);
        std::thread::scope(|scope| {
            let first = scope.spawn(|| verifier.record(record()));
            let second = scope.spawn(|| verifier.record(record()));
            let results = [first.join().unwrap(), second.join().unwrap()];
            assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        });
        assert_eq!(runtime.summary("finite").unwrap().state, RunState::Verified);
        runtime.verify_integrity().unwrap();
    }
}
