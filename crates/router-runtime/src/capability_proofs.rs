//! Append-only authenticated capability records in the private runtime store.
//! Opening an existing store for verification never creates a file or a key.
use router_adapter_api::{
    AuthenticatedCapabilityAttestation, AuthenticatedCapabilityProof, CapabilityAttestationKey,
    CapabilityProofBinding, CapabilityProofError, CapabilityProofKey, CapabilityProofSet,
    MAX_CAPABILITY_PROOF_BYTES, MAX_CAPABILITY_PROOFS,
};
use rusqlite::{Connection, OpenFlags, params};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
use thiserror::Error;

pub const CAPABILITY_PROOF_DATABASE: &str = "capability-proofs.sqlite3";

#[derive(Debug, Error)]
pub enum CapabilityStoreError {
    #[error("capability.store.unsafe")]
    Unsafe,
    #[error("capability.store.unavailable")]
    Unavailable,
    #[error("capability.store.integrity")]
    Integrity,
    #[error(transparent)]
    Proof(#[from] CapabilityProofError),
}
impl CapabilityStoreError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unsafe => "capability.store.unsafe",
            Self::Unavailable => "capability.store.unavailable",
            Self::Integrity => "capability.store.integrity",
            Self::Proof(e) => e.code(),
        }
    }
}

pub struct CapabilityProofStore {
    db: Connection,
    store_id: String,
    schema_version: u32,
}

/// Reopens and authenticates the bounded log for every verification. A later
/// failed attempt is therefore visible at dispatch, not just at CLI loading.
/// The secret never implements Debug or serialization.
pub struct StoredCapabilityProofVerifier {
    root: std::path::PathBuf,
    store_id: String,
    secret: [u8; 32],
    expected: Vec<CapabilityProofBinding>,
    historical_sequence: Option<u64>,
}
impl StoredCapabilityProofVerifier {
    pub fn open_existing(
        root: &Path,
        secret: [u8; 32],
        expected: Vec<CapabilityProofBinding>,
    ) -> Result<Self, CapabilityStoreError> {
        let store = CapabilityProofStore::open_existing(root)?;
        store.verifier(&secret, expected.clone())?;
        Ok(Self {
            root: root.to_owned(),
            store_id: store.store_id().to_owned(),
            secret,
            expected,
            historical_sequence: None,
        })
    }
    pub(crate) fn require_live(&self) -> Result<(), CapabilityStoreError> {
        if self.historical_sequence.is_some() {
            return Err(CapabilityStoreError::Integrity);
        }
        Ok(())
    }
    pub fn through_sequence(mut self, sequence: u64) -> Self {
        self.historical_sequence = Some(sequence);
        self
    }
    pub fn snapshot(&self) -> Result<CapabilityProofSet, CapabilityStoreError> {
        let store = CapabilityProofStore::open_existing(&self.root)?;
        if store.store_id() != self.store_id {
            return Err(CapabilityStoreError::Integrity);
        }
        let verified = store.verifier(&self.secret, self.expected.clone())?;
        Ok(match self.historical_sequence {
            Some(sequence) => verified.through_sequence(sequence),
            None => verified,
        })
    }
}
impl router_adapter_api::CapabilityProofVerifier for StoredCapabilityProofVerifier {
    fn verify(
        &self,
        source: &router_adapter_api::EvidenceSource,
        capability: router_types::Capability,
        host: &router_types::HostSnapshot,
        now: u64,
    ) -> Result<router_adapter_api::VerifiedCapabilityProof, CapabilityProofError> {
        self.snapshot()
            .map_err(|error| match error {
                CapabilityStoreError::Proof(error) => error,
                _ => CapabilityProofError::Unauthenticated,
            })?
            .verify(source, capability, host, now)
    }
    fn verify_attestation(
        &self,
        reference: &router_adapter_api::CapabilityAttestationReference,
        host: &router_types::HostSnapshot,
        now: u64,
    ) -> Result<router_adapter_api::VerifiedCapabilityProof, CapabilityProofError> {
        self.snapshot()
            .map_err(|error| match error {
                CapabilityStoreError::Proof(error) => error,
                _ => CapabilityProofError::Unauthenticated,
            })?
            .verify_attestation(reference, host, now)
    }
}

fn private(path: &Path, directory: bool) -> Result<(), CapabilityStoreError> {
    let meta = fs::symlink_metadata(path).map_err(|_| CapabilityStoreError::Unavailable)?;
    if meta.file_type().is_symlink()
        || (directory && !meta.is_dir())
        || (!directory && !meta.is_file())
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err(CapabilityStoreError::Unsafe);
    }
    Ok(())
}

fn check_root(root: &Path) -> Result<(), CapabilityStoreError> {
    if !root.is_absolute() {
        return Err(CapabilityStoreError::Unsafe);
    }
    private(root, true)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let path = root.join(format!("{CAPABILITY_PROOF_DATABASE}{suffix}"));
        match fs::symlink_metadata(&path) {
            Ok(_) => private(&path, false)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(CapabilityStoreError::Unavailable),
        }
    }
    Ok(())
}

impl CapabilityProofStore {
    /// Verification path: no directory, database, identity, or key creation.
    pub fn open_existing(root: &Path) -> Result<Self, CapabilityStoreError> {
        Self::open(root, false)
    }

    /// Explicit provisioning only. Not called by inspect, routing or replay.
    /// Production canary issuance remains gated by its independent admission.
    pub fn create(root: &Path) -> Result<Self, CapabilityStoreError> {
        check_root(root)?;
        let path = root.join(CAPABILITY_PROOF_DATABASE);
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => {
                file.sync_all()
                    .map_err(|_| CapabilityStoreError::Unavailable)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(CapabilityStoreError::Unavailable),
        }
        private(&path, false)?;
        let mut db = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| CapabilityStoreError::Unavailable)?;
        db.busy_timeout(std::time::Duration::from_secs(2))
            .map_err(|_| CapabilityStoreError::Unavailable)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| CapabilityStoreError::Unavailable)?;
        let version: u32 = tx
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|_| CapabilityStoreError::Integrity)?;
        if version == 0 {
            let mut random = [0u8; 32];
            File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut random))
                .map_err(|_| CapabilityStoreError::Unavailable)?;
            tx.execute_batch("CREATE TABLE identity(id INTEGER PRIMARY KEY CHECK(id=1), store_id TEXT NOT NULL);
                CREATE TABLE capability_proofs(sequence INTEGER PRIMARY KEY, proof_id TEXT UNIQUE NOT NULL, record TEXT NOT NULL);
                CREATE TRIGGER proof_no_update BEFORE UPDATE ON capability_proofs BEGIN SELECT RAISE(ABORT,'append-only'); END;
                CREATE TRIGGER proof_no_delete BEFORE DELETE ON capability_proofs BEGIN SELECT RAISE(ABORT,'append-only'); END;
                CREATE TRIGGER identity_no_update BEFORE UPDATE ON identity BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER identity_no_delete BEFORE DELETE ON identity BEGIN SELECT RAISE(ABORT,'immutable'); END;
                PRAGMA user_version=1;").map_err(|_| CapabilityStoreError::Integrity)?;
            tx.execute("INSERT INTO identity VALUES(1,?1)", [hex::encode(random)])
                .map_err(|_| CapabilityStoreError::Integrity)?;
        } else if !matches!(version, 1 | 2) {
            return Err(CapabilityStoreError::Integrity);
        }
        tx.commit().map_err(|_| CapabilityStoreError::Unavailable)?;
        File::open(root)
            .and_then(|f| f.sync_all())
            .map_err(|_| CapabilityStoreError::Unavailable)?;
        Self::open(root, true)
    }

    fn open(root: &Path, writable: bool) -> Result<Self, CapabilityStoreError> {
        check_root(root)?;
        let path = root.join(CAPABILITY_PROOF_DATABASE);
        private(&path, false)?;
        let flags = if writable {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        };
        let db = Connection::open_with_flags(&path, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .map_err(|_| CapabilityStoreError::Unavailable)?;
        db.busy_timeout(std::time::Duration::from_secs(2))
            .map_err(|_| CapabilityStoreError::Unavailable)?;
        let version: u32 = db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|_| CapabilityStoreError::Integrity)?;
        if !matches!(version, 1 | 2) {
            return Err(CapabilityStoreError::Integrity);
        }
        let store_id: String = db.query_row("SELECT CASE WHEN length(CAST(store_id AS BLOB))=64 THEN store_id ELSE NULL END FROM identity WHERE id=1", [], |r| r.get(0)).map_err(|_| CapabilityStoreError::Integrity)?;
        if !router_adapter_api::is_digest(&store_id) {
            return Err(CapabilityStoreError::Integrity);
        }
        Ok(Self {
            db,
            store_id,
            schema_version: version,
        })
    }

    pub fn store_id(&self) -> &str {
        &self.store_id
    }

    pub fn verifier(
        &self,
        secret: &[u8; 32],
        expected: Vec<CapabilityProofBinding>,
    ) -> Result<CapabilityProofSet, CapabilityStoreError> {
        let key = CapabilityProofKey::derive(secret, &self.store_id)?;
        let attestation_key = CapabilityAttestationKey::derive(secret, &self.store_id)?;
        let (records, attestations) = self.records()?;
        Ok(
            CapabilityProofSet::authenticate(&self.store_id, &key, records, expected)?
                .with_attestations(&self.store_id, &attestation_key, attestations)?,
        )
    }

    fn records(
        &self,
    ) -> Result<
        (
            Vec<AuthenticatedCapabilityProof>,
            Vec<AuthenticatedCapabilityAttestation>,
        ),
        CapabilityStoreError,
    > {
        let mut query = self.db.prepare("SELECT sequence,CASE WHEN length(CAST(proof_id AS BLOB))<=128 THEN proof_id ELSE NULL END,length(CAST(record AS BLOB)),CASE WHEN length(CAST(record AS BLOB))<=33024 THEN record ELSE NULL END FROM capability_proofs ORDER BY sequence LIMIT ?1").map_err(|_| CapabilityStoreError::Integrity)?;
        let mut rows = query
            .query([MAX_CAPABILITY_PROOFS + 1])
            .map_err(|_| CapabilityStoreError::Integrity)?;
        let mut proofs = Vec::new();
        let mut attestations = Vec::new();
        let mut prior_sequence = 0;
        while let Some(row) = rows.next().map_err(|_| CapabilityStoreError::Integrity)? {
            if proofs.len() + attestations.len() == MAX_CAPABILITY_PROOFS {
                return Err(CapabilityProofError::Bounds.into());
            }
            let size: usize = row.get(2).map_err(|_| CapabilityStoreError::Integrity)?;
            if size > MAX_CAPABILITY_PROOF_BYTES + 256 {
                return Err(CapabilityProofError::Bounds.into());
            }
            let sequence: u64 = row.get(0).map_err(|_| CapabilityStoreError::Integrity)?;
            let id: String = row.get(1).map_err(|_| CapabilityStoreError::Integrity)?;
            let text: String = row.get(3).map_err(|_| CapabilityStoreError::Integrity)?;
            if sequence <= prior_sequence {
                return Err(CapabilityStoreError::Integrity);
            }
            prior_sequence = sequence;
            let value = router_adapter_api::strict_json(text.as_bytes())
                .map_err(|_| CapabilityStoreError::Integrity)?;
            match value["record"]["schema_version"].as_u64() {
                Some(1) => {
                    let proof = AuthenticatedCapabilityProof::from_json(text.as_bytes())?;
                    if proof.record.sequence != sequence || proof.record.proof_id != id {
                        return Err(CapabilityStoreError::Integrity);
                    }
                    proofs.push(proof);
                }
                Some(2) if self.schema_version == 2 => {
                    let proof = AuthenticatedCapabilityAttestation::from_json(text.as_bytes())?;
                    if proof.record.sequence != sequence || proof.record.record_id != id {
                        return Err(CapabilityStoreError::Integrity);
                    }
                    attestations.push(proof);
                }
                _ => return Err(CapabilityStoreError::Integrity),
            }
        }
        Ok((proofs, attestations))
    }

    /// Explicit issuing path only. Read-only opening never changes the schema.
    /// SQLite commits the version change atomically with the authenticated check.
    pub fn enable_attestations(&mut self, secret: &[u8; 32]) -> Result<(), CapabilityStoreError> {
        self.enable_attestations_with(secret, || Ok(()))
    }
    fn enable_attestations_with(
        &mut self,
        secret: &[u8; 32],
        before_commit: impl FnOnce() -> Result<(), CapabilityStoreError>,
    ) -> Result<(), CapabilityStoreError> {
        self.db
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| CapabilityStoreError::Unavailable)?;
        let result = (|| {
            self.verifier(secret, vec![])?;
            self.db
                .execute_batch("PRAGMA user_version=2")
                .map_err(|_| CapabilityStoreError::Unavailable)?;
            before_commit()?;
            self.db
                .execute_batch("COMMIT")
                .map_err(|_| CapabilityStoreError::Unavailable)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = self.db.execute_batch("ROLLBACK");
        } else {
            self.schema_version = 2;
        }
        result
    }
    pub fn next_sequence(&self, secret: &[u8; 32]) -> Result<u64, CapabilityStoreError> {
        self.verifier(secret, vec![])?
            .last_sequence()
            .checked_add(1)
            .ok_or(CapabilityStoreError::Integrity)
    }
    pub fn attestation(
        &self,
        secret: &[u8; 32],
        id: &str,
    ) -> Result<AuthenticatedCapabilityAttestation, CapabilityStoreError> {
        self.verifier(secret, vec![])?
            .attestation(id)
            .cloned()
            .ok_or(CapabilityStoreError::Unavailable)
    }

    /// Persist an already authenticated supervised attempt. This operation
    /// cannot mint a MAC, infer a capability, or launch a host.
    pub fn append(
        &mut self,
        proof: &AuthenticatedCapabilityProof,
        secret: &[u8; 32],
    ) -> Result<(), CapabilityStoreError> {
        CapabilityProofKey::derive(secret, &self.store_id)?.verify(proof)?;
        if proof.record.store_id != self.store_id {
            return Err(CapabilityProofError::Unauthenticated.into());
        }
        self.append_record(
            proof.record.sequence,
            &proof.record.proof_id,
            &serde_json::to_string(proof).map_err(|_| CapabilityStoreError::Integrity)?,
            secret,
        )
    }
    pub fn append_attestation(
        &mut self,
        proof: &AuthenticatedCapabilityAttestation,
        secret: &[u8; 32],
    ) -> Result<(), CapabilityStoreError> {
        if self.schema_version != 2 {
            return Err(CapabilityStoreError::Integrity);
        }
        CapabilityAttestationKey::derive(secret, &self.store_id)?.verify(proof)?;
        if proof.record.store_id != self.store_id {
            return Err(CapabilityProofError::Unauthenticated.into());
        }
        self.append_record(
            proof.record.sequence,
            &proof.record.record_id,
            &serde_json::to_string(proof).map_err(|_| CapabilityStoreError::Integrity)?,
            secret,
        )
    }
    fn append_record(
        &mut self,
        sequence: u64,
        id: &str,
        text: &str,
        secret: &[u8; 32],
    ) -> Result<(), CapabilityStoreError> {
        self.db
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| CapabilityStoreError::Unavailable)?;
        let result = (|| {
            let prior = self.verifier(secret, vec![])?;
            if prior.record_count() >= MAX_CAPABILITY_PROOFS {
                return Err(CapabilityProofError::Bounds.into());
            }
            if prior.last_sequence().checked_add(1) != Some(sequence) {
                return Err(CapabilityStoreError::Integrity);
            }
            self.db
                .execute(
                    "INSERT INTO capability_proofs(sequence,proof_id,record) VALUES(?1,?2,?3)",
                    params![sequence, id, text],
                )
                .map_err(|_| CapabilityStoreError::Integrity)?;
            // Includes cross-record revoke reference validation before commit.
            self.verifier(secret, vec![])?;
            Ok(())
        })();
        match result {
            Ok(()) => self
                .db
                .execute_batch("COMMIT")
                .map_err(|_| CapabilityStoreError::Unavailable),
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_types::Capability;

    #[test]
    fn identity_is_random_persistent_private_and_read_open_never_creates() {
        let temp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let root = temp.path();
        assert!(CapabilityProofStore::open_existing(root).is_err());
        assert!(!root.join(CAPABILITY_PROOF_DATABASE).exists());
        let created = CapabilityProofStore::create(root).unwrap();
        let id = created.store_id().to_owned();
        assert_eq!(id.len(), 64);
        assert_ne!(id, "0".repeat(64));
        drop(created);
        let before = fs::read(root.join(CAPABILITY_PROOF_DATABASE)).unwrap();
        let reopened = CapabilityProofStore::open_existing(root).unwrap();
        assert_eq!(reopened.store_id(), id);
        assert!(
            reopened
                .verifier(&[1; 32], vec![])
                .unwrap()
                .deciding_proofs(
                    &router_types::HostSnapshot {
                        id: "fixture".into(),
                        harness: router_types::HarnessId::parse("fixture").unwrap(),
                        supported_models: Default::default(),
                        supported_efforts: Default::default(),
                        capabilities: Default::default(),
                    },
                    100
                )
                .is_empty()
        );
        drop(reopened);
        assert_eq!(
            fs::read(root.join(CAPABILITY_PROOF_DATABASE)).unwrap(),
            before
        );
        assert_eq!(
            fs::metadata(root.join(CAPABILITY_PROOF_DATABASE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let other = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        assert_ne!(
            CapabilityProofStore::create(other.path())
                .unwrap()
                .store_id(),
            id
        );
    }

    #[test]
    fn unsafe_database_and_root_are_refused() {
        let temp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let root = temp.path();
        let store = CapabilityProofStore::create(root).unwrap();
        drop(store);
        let path = root.join(CAPABILITY_PROOF_DATABASE);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            CapabilityProofStore::open_existing(root),
            Err(CapabilityStoreError::Unsafe)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let target = root.join("target");
        fs::rename(&path, &target).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(matches!(
            CapabilityProofStore::open_existing(root),
            Err(CapabilityStoreError::Unsafe)
        ));
        fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            CapabilityProofStore::open_existing(root),
            Err(CapabilityStoreError::Unsafe)
        ));
    }
    fn attempt(store_id: &str, sequence: u64, succeeded: bool) -> AuthenticatedCapabilityProof {
        use router_adapter_api::*;
        let binding = CapabilityProofBinding {
            harness_id: "fixture-host".into(),
            host_snapshot_id: "fixture-snapshot".into(),
            binary_sha256: "2".repeat(64),
            observed_version: "fixture-1".into(),
            adapter_id: "fixture-adapter".into(),
            argument_template_sha256: "3".repeat(64),
            sandbox_helper_sha256: "4".repeat(64),
            sandbox_wrapper_sha256: "5".repeat(64),
            sandbox_profile_sha256: "6".repeat(64),
            write_roots: Default::default(),
            network: false,
            os: "fixture-os".into(),
        };
        CapabilityProofKey::derive(&[42; 32], store_id)
            .unwrap()
            .authenticate(CapabilityProofRecord {
                schema_version: 1,
                proof_id: format!("fixture-{sequence}"),
                sequence,
                store_id: store_id.into(),
                capability: router_types::Capability::WorkspaceWrite,
                tier: CapabilityProofTier::Proven,
                network_scope: None,
                binding,
                model_id: "fixture-model".into(),
                nonce_sha256: "7".repeat(64),
                expected_effect_sha256: "8".repeat(64),
                started_at_unix_seconds: 100 + sequence,
                ended_at_unix_seconds: 100 + sequence,
                max_age_seconds: 500,
                outcome: if succeeded {
                    CapabilityAttemptOutcome::Succeeded
                } else {
                    CapabilityAttemptOutcome::Failed
                },
            })
            .unwrap()
    }

    #[test]
    fn append_checks_mac_sequence_and_store_and_live_verifier_observes_revocation() {
        use router_adapter_api::CapabilityProofVerifier;
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let mut store = CapabilityProofStore::create(root.path()).unwrap();
        let first = attempt(store.store_id(), 1, true);
        let source = router_adapter_api::EvidenceSource {
            id: first.record.proof_id.clone(),
            kind: router_adapter_api::EvidenceKind::HostRuntime,
            observed_version: Some(first.record.binding.observed_version.clone()),
            observed_at_unix_seconds: 101,
            content_sha256: first.digest().unwrap(),
        };
        let host = router_types::HostSnapshot {
            id: "fixture-snapshot".into(),
            harness: router_types::HarnessId::parse("fixture-host").unwrap(),
            supported_models: Default::default(),
            supported_efforts: Default::default(),
            capabilities: Default::default(),
        };
        assert!(store.append(&first, &[43; 32]).is_err());
        assert!(store.records().unwrap().0.is_empty());
        store.append(&first, &[42; 32]).unwrap();
        assert!(store.append(&first, &[42; 32]).is_err());
        assert!(
            store
                .append(&attempt(store.store_id(), 3, true), &[42; 32])
                .is_err()
        );
        let live = StoredCapabilityProofVerifier::open_existing(
            root.path(),
            [42; 32],
            vec![first.record.binding.clone()],
        )
        .unwrap();
        assert!(
            live.verify(&source, first.record.capability, &host, 110)
                .is_ok()
        );
        store
            .append(&attempt(store.store_id(), 2, false), &[42; 32])
            .unwrap();
        assert!(matches!(
            live.verify(&source, first.record.capability, &host, 110),
            Err(CapabilityProofError::Revoked)
        ));
        // Historical reconstruction uses the run clock, before the failed canary.
        assert!(matches!(
            live.verify(&source, first.record.capability, &host, 101),
            Err(CapabilityProofError::Future)
        ));
        let historical = StoredCapabilityProofVerifier::open_existing(
            root.path(),
            [42; 32],
            vec![first.record.binding.clone()],
        )
        .unwrap()
        .through_sequence(1);
        assert!(
            historical
                .verify(&source, first.record.capability, &host, 101)
                .is_ok()
        );
        assert!(
            store
                .db
                .execute("DELETE FROM capability_proofs", [])
                .is_err()
        );
        assert!(
            store
                .db
                .execute("UPDATE capability_proofs SET proof_id='changed'", [])
                .is_err()
        );
        assert!(
            store
                .db
                .execute("UPDATE identity SET store_id='changed'", [])
                .is_err()
        );
        let other = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let mut other = CapabilityProofStore::create(other.path()).unwrap();
        assert!(other.append(&first, &[42; 32]).is_err());
        drop(store);
        assert_eq!(
            CapabilityProofStore::open_existing(root.path())
                .unwrap()
                .records()
                .unwrap()
                .0
                .len(),
            2
        );
    }

    #[test]
    fn tampered_persisted_sequence_and_mac_are_refused_on_read() {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let mut store = CapabilityProofStore::create(root.path()).unwrap();
        let proof = attempt(store.store_id(), 1, true);
        store.append(&proof, &[42; 32]).unwrap();
        store
            .db
            .execute_batch("DROP TRIGGER proof_no_update")
            .unwrap();
        store
            .db
            .execute("UPDATE capability_proofs SET sequence=2", [])
            .unwrap();
        assert!(
            store
                .verifier(&[42; 32], vec![proof.record.binding])
                .is_err()
        );
    }

    #[test]
    fn frozen_sequence_preserves_same_second_history_after_later_failure() {
        use router_adapter_api::CapabilityProofVerifier;
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let mut store = CapabilityProofStore::create(root.path()).unwrap();
        let first = attempt(store.store_id(), 1, true);
        store.append(&first, &[42; 32]).unwrap();
        let source = router_adapter_api::EvidenceSource {
            id: first.record.proof_id.clone(),
            kind: router_adapter_api::EvidenceKind::HostRuntime,
            observed_version: Some(first.record.binding.observed_version.clone()),
            observed_at_unix_seconds: 101,
            content_sha256: first.digest().unwrap(),
        };
        let host = router_types::HostSnapshot {
            id: "fixture-snapshot".into(),
            harness: router_types::HarnessId::parse("fixture-host").unwrap(),
            supported_models: Default::default(),
            supported_efforts: Default::default(),
            capabilities: Default::default(),
        };
        let live = StoredCapabilityProofVerifier::open_existing(
            root.path(),
            [42; 32],
            vec![first.record.binding.clone()],
        )
        .unwrap();
        assert!(
            live.verify(&source, first.record.capability, &host, 101)
                .is_ok()
        );
        let historical = StoredCapabilityProofVerifier::open_existing(
            root.path(),
            [42; 32],
            vec![first.record.binding.clone()],
        )
        .unwrap()
        .through_sequence(1);
        let mut failure = attempt(store.store_id(), 2, false).record;
        failure.started_at_unix_seconds = 101;
        failure.ended_at_unix_seconds = 101;
        let failure = CapabilityProofKey::derive(&[42; 32], store.store_id())
            .unwrap()
            .authenticate(failure)
            .unwrap();
        store.append(&failure, &[42; 32]).unwrap();
        assert!(matches!(
            live.verify(&source, first.record.capability, &host, 101),
            Err(CapabilityProofError::Revoked)
        ));
        assert!(
            historical
                .verify(&source, first.record.capability, &host, 101)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn final_spawn_guard_observes_revocation_after_command_preparation() {
        use router_adapter_api::CapabilityProofVerifier;
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let mut store = CapabilityProofStore::create(root.path()).unwrap();
        let proof = attempt(store.store_id(), 1, true);
        store.append(&proof, &[42; 32]).unwrap();
        let verifier = StoredCapabilityProofVerifier::open_existing(
            root.path(),
            [42; 32],
            vec![proof.record.binding.clone()],
        )
        .unwrap();
        let source = router_adapter_api::EvidenceSource {
            id: proof.record.proof_id.clone(),
            kind: router_adapter_api::EvidenceKind::HostRuntime,
            observed_version: Some(proof.record.binding.observed_version.clone()),
            observed_at_unix_seconds: 101,
            content_sha256: proof.digest().unwrap(),
        };
        let host = router_types::HostSnapshot {
            id: "fixture-snapshot".into(),
            harness: router_types::HarnessId::parse("fixture-host").unwrap(),
            supported_models: Default::default(),
            supported_efforts: Default::default(),
            capabilities: Default::default(),
        };
        assert!(
            verifier
                .verify(&source, proof.record.capability, &host, 102)
                .is_ok()
        );
        let marker = root.path().join("must-not-exist");
        let mut command = tokio::process::Command::new("/usr/bin/touch");
        command.arg(&marker);
        let final_check = || {
            verifier
                .verify(&source, proof.record.capability, &host, 103)
                .map(|_| ())
                .map_err(|_| crate::RuntimeError::Route)
        };
        let cancel = crate::Cancellation::default();
        let capture = crate::process::capture_guarded(
            command,
            vec![],
            1000,
            1024,
            10,
            &cancel,
            None,
            None,
            Some(&final_check),
        );
        // A supervised preparation step may finish after a new failed canary.
        store
            .append(&attempt(store.store_id(), 2, false), &[42; 32])
            .unwrap();
        assert!(matches!(capture.await, Err(crate::RuntimeError::Route)));
        assert!(!marker.exists(), "refusal must precede the child effect");
    }
    #[test]
    fn attestation_migration_is_explicit_atomic_and_preserves_old_rows() {
        use router_adapter_api::*;
        let temp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let mut store = CapabilityProofStore::create(temp.path()).unwrap();
        let first = attempt(store.store_id(), 1, true);
        store.append(&first, &[42; 32]).unwrap();
        let before: String = store
            .db
            .query_row(
                "SELECT record FROM capability_proofs WHERE sequence=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(store.schema_version, 1);
        assert!(
            store
                .enable_attestations_with(&[42; 32], || Err(CapabilityStoreError::Unavailable))
                .is_err()
        );
        assert_eq!(store.schema_version, 1);
        let version: u32 = store
            .db
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);
        drop(store);
        let reader = CapabilityProofStore::open_existing(temp.path()).unwrap();
        assert_eq!(reader.schema_version, 1);
        drop(reader);
        let mut store = CapabilityProofStore::create(temp.path()).unwrap();
        store.enable_attestations(&[42; 32]).unwrap();
        assert_eq!(store.schema_version, 2);
        let after: String = store
            .db
            .query_row(
                "SELECT record FROM capability_proofs WHERE sequence=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(store.verifier(&[42; 32], vec![]).unwrap().record_count(), 1);
        let key = CapabilityAttestationKey::derive(&[42; 32], store.store_id()).unwrap();
        let grant = key
            .authenticate(CapabilityAttestationRecord {
                schema_version: 2,
                record_id: "attestation-grant".into(),
                sequence: 2,
                store_id: store.store_id().into(),
                capability: Capability::WorkspaceWrite,
                binding: CapabilityAttestationBinding::from_execution_pins(
                    first.record.binding.clone(),
                ),
                operator_label: "fixture-operator".into(),
                reason: "Offline declaration".into(),
                created_at_unix_seconds: 200,
                action: CapabilityAttestationAction::Grant {
                    max_age_seconds: 100,
                },
            })
            .unwrap();
        store.append_attestation(&grant, &[42; 32]).unwrap();
        assert_eq!(store.next_sequence(&[42; 32]).unwrap(), 3);
        assert_eq!(
            store.attestation(&[42; 32], "attestation-grant").unwrap(),
            grant
        );
        let mut invalid = grant.record.clone();
        invalid.sequence = 3;
        invalid.record_id = "invalid-revoke".into();
        invalid.action = CapabilityAttestationAction::Revoke {
            record_id: "missing".into(),
            content_sha256: "9".repeat(64),
        };
        assert!(
            store
                .append_attestation(&key.authenticate(invalid).unwrap(), &[42; 32])
                .is_err()
        );
        assert_eq!(store.next_sequence(&[42; 32]).unwrap(), 3);
        let mut revoke = grant.record.clone();
        revoke.sequence = 3;
        revoke.record_id = "attestation-revoke".into();
        revoke.action = CapabilityAttestationAction::Revoke {
            record_id: grant.record.record_id.clone(),
            content_sha256: grant.digest().unwrap(),
        };
        store
            .append_attestation(&key.authenticate(revoke).unwrap(), &[42; 32])
            .unwrap();
        assert_eq!(store.verifier(&[42; 32], vec![]).unwrap().record_count(), 3);
        drop(store);
        let reader = CapabilityProofStore::open_existing(temp.path()).unwrap();
        assert_eq!(reader.schema_version, 2);
        assert_eq!(
            reader.verifier(&[42; 32], vec![]).unwrap().last_sequence(),
            3
        );
    }
}
