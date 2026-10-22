//! Local, explicitly approved current catalog authority. No execution authority,
//! publisher roots, credentials or private keys are installed by this library.
use router_adapter_api::{content_digest, is_digest};
use router_catalog::{
    CatalogAccess, CatalogVerification, SignedCatalogDocument, TrustedCatalogPublishers,
    ValidatedSignedCatalog,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
mod files;
mod json;
mod publisher_policy;

pub use publisher_policy::{PublisherPolicyAuthority, PublisherPolicyGuard};

pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_DOCUMENTS: usize = 16;
pub const MAX_REVISIONS: usize = 128;
pub const MAX_REVIEW_SECONDS: u64 = 300;
pub const MAX_PUBLISHER_POLICY_BYTES: usize = 64 * 1024;
/// Snapshot bytes kept free of activations so an active catalog can always be
/// revoked. Only a revocation may use them.
pub const REVOCATION_RESERVE_BYTES: usize = 1024 * 1024;

/// Failed operation carried by `StoreError::Io` and `StoreError::Path`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Locator,
    Traverse,
    Mkdir,
    Open,
    Create,
    Stat,
    List,
    Read,
    Write,
    Fsync,
    Rename,
    Unlink,
    Lock,
}
impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Locator => "locator",
            Self::Traverse => "traverse",
            Self::Mkdir => "mkdir",
            Self::Open => "open",
            Self::Create => "create",
            Self::Stat => "stat",
            Self::List => "list",
            Self::Read => "read",
            Self::Write => "write",
            Self::Fsync => "fsync",
            Self::Rename => "rename",
            Self::Unlink => "unlink",
            Self::Lock => "lock",
        }
    }
}
impl std::fmt::Display for Operation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("invalid catalog store input")]
    Invalid,
    #[error("catalog store integrity failure")]
    Integrity,
    #[error("catalog store authority changed or not approved")]
    Authority,
    #[error("catalog store limit exceeded")]
    Limit,
    #[error("catalog store already exists")]
    Exists,
    #[error("catalog store entry missing")]
    Missing,
    #[error("catalog store path rejected ({operation})")]
    Path {
        operation: Operation,
        errno: Option<i32>,
    },
    #[error("catalog store permissions rejected")]
    Permissions,
    #[error("catalog store busy")]
    Busy,
    #[error("catalog store compare-and-swap conflict")]
    Conflict,
    #[error("catalog store approval required or changed")]
    Approval,
    #[error("catalog store evidence expired or clock regressed")]
    Time,
    #[error("catalog store has no active catalog")]
    Revoked,
    #[error("catalog store I/O failed ({operation})")]
    Io {
        operation: Operation,
        errno: Option<i32>,
    },
    /// The new state was renamed into place but the final directory fsync
    /// failed. It may be visible now and lost after a crash. Inspect status
    /// and re-approve from the observed head; never retry blindly.
    #[error("catalog store published, durability unknown")]
    PublishedDurabilityUnknown,
    #[error("catalog store unsupported on this platform")]
    Unsupported,
    #[error("signed catalog rejected: {0}")]
    Catalog(#[from] router_catalog::SignedCatalogError),
}
impl StoreError {
    pub(crate) fn path(operation: Operation) -> Self {
        Self::Path {
            operation,
            errno: None,
        }
    }
    /// Stable machine-readable code. The operation and errno of `Io` and `Path`
    /// never change it.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Integrity => "integrity",
            Self::Authority => "authority",
            Self::Limit => "limit",
            Self::Exists => "exists",
            Self::Missing => "missing",
            Self::Path { .. } => "path",
            Self::Permissions => "permissions",
            Self::Busy => "busy",
            Self::Conflict => "conflict",
            Self::Approval => "approval",
            Self::Time => "time",
            Self::Revoked => "revoked",
            Self::Io { .. } => "io",
            Self::PublishedDurabilityUnknown => "published_durability_unknown",
            Self::Unsupported => "unsupported",
            Self::Catalog(_) => "catalog",
        }
    }
}
pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoreIdentity {
    pub schema_version: u32,
    pub store_id: String,
    pub catalog_id: String,
    /// Canonical locator digest; no machine path appears in exported status.
    pub locator_sha256: String,
}
impl StoreIdentity {
    pub fn content_hash(&self) -> Result<String> {
        hash("catalog-store-config-v1", self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CatalogHead {
    pub schema_version: u32,
    pub store_id: String,
    pub catalog_id: String,
    pub locator_sha256: String,
    pub revision: u64,
    pub previous_head: Option<String>,
    pub document_sha256: Option<String>,
    pub binding_hash: Option<String>,
    pub grants_hash: Option<String>,
    pub changed_at_unix_seconds: u64,
    pub approval_digest: Option<String>,
    pub head_hash: String,
}
impl CatalogHead {
    fn seal(mut self) -> Result<Self> {
        self.head_hash.clear();
        self.head_hash = hash("catalog-store-head-v1", &self)?;
        Ok(self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CatalogChange {
    Activate {
        document_sha256: String,
        binding_hash: String,
    },
    Revoke,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewProjection {
    pub schema_version: u32,
    pub identity: StoreIdentity,
    pub config_hash: String,
    pub expected_head_hash: String,
    pub expected_revision: u64,
    pub grants_hash: String,
    pub change: CatalogChange,
    pub reviewed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}
/// Exact approval preimage, constructed only by the store's validation path.
pub struct CatalogReview {
    projection: ReviewProjection,
    document: Option<SignedCatalogDocument>,
    approval_digest: String,
}
impl CatalogReview {
    pub fn projection(&self) -> &ReviewProjection {
        &self.projection
    }
    pub fn approval_digest(&self) -> &str {
        &self.approval_digest
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    review: ReviewProjection,
    applied_at_unix_seconds: u64,
    head: CatalogHead,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u32,
    identity: StoreIdentity,
    config_hash: String,
    documents: BTreeMap<String, SignedCatalogDocument>,
    events: Vec<Event>,
    head: CatalogHead,
    /// Head of the last pruned event. Absent until history is first pruned, so
    /// a never-pruned snapshot keeps its original bytes and hash. The retained
    /// events chain from this head instead of from genesis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    anchor: Option<CatalogHead>,
    content_sha256: String,
}
/// Borrowed mirror of `Snapshot` with an explicit digest field, so hashing and
/// encoding never clone the documents. Field order must match `Snapshot`.
#[derive(Serialize)]
struct SnapshotView<'a> {
    schema_version: u32,
    identity: &'a StoreIdentity,
    config_hash: &'a str,
    documents: &'a BTreeMap<String, SignedCatalogDocument>,
    events: &'a [Event],
    head: &'a CatalogHead,
    #[serde(skip_serializing_if = "Option::is_none")]
    anchor: Option<&'a CatalogHead>,
    content_sha256: &'a str,
}
impl Snapshot {
    fn view<'a>(&'a self, content_sha256: &'a str) -> SnapshotView<'a> {
        SnapshotView {
            schema_version: self.schema_version,
            identity: &self.identity,
            config_hash: &self.config_hash,
            documents: &self.documents,
            events: &self.events,
            head: &self.head,
            anchor: self.anchor.as_ref(),
            content_sha256,
        }
    }
    fn seal_hash(&self) -> Result<String> {
        hash("catalog-store-snapshot-v1", &self.view(""))
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        let bytes = bounded_json(&self.view(&self.seal_hash()?))?;
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(StoreError::Limit);
        }
        Ok(bytes)
    }
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.identity.schema_version != 1
            || !label(&self.identity.store_id)
            || !label(&self.identity.catalog_id)
            || !is_digest(&self.identity.locator_sha256)
            || self.identity.content_hash()? != self.config_hash
            || self.documents.len() > MAX_DOCUMENTS
            || self.events.len() > MAX_REVISIONS
        {
            return Err(StoreError::Integrity);
        }
        if self.seal_hash()? != self.content_sha256 {
            return Err(StoreError::Integrity);
        }
        for (digest, document) in &self.documents {
            if document.manifest.id != self.identity.catalog_id
                || content_digest(&document.canonical_json()?) != *digest
            {
                return Err(StoreError::Integrity);
            }
        }
        let mut current = match &self.anchor {
            None => genesis(&self.identity)?,
            Some(anchor) => {
                validate_anchor(anchor, &self.identity)?;
                anchor.clone()
            }
        };
        let mut referenced = BTreeSet::new();
        if let Some(document_sha256) = &self.head.document_sha256 {
            referenced.insert(document_sha256.clone());
        }
        for event in &self.events {
            validate_review(
                &event.review,
                &self.identity,
                &current,
                event.applied_at_unix_seconds,
            )?;
            if let CatalogChange::Activate {
                document_sha256,
                binding_hash,
            } = &event.review.change
            {
                if !is_digest(binding_hash) || !self.documents.contains_key(document_sha256) {
                    return Err(StoreError::Integrity);
                }
                referenced.insert(document_sha256.clone());
            }
            current = next_head(&event.review, event.applied_at_unix_seconds)?;
            if current != event.head {
                return Err(StoreError::Integrity);
            }
        }
        if current != self.head
            || referenced.len() != self.documents.len()
            || !referenced
                .iter()
                .all(|digest| self.documents.contains_key(digest))
        {
            return Err(StoreError::Integrity);
        }
        Ok(())
    }
}

pub struct CatalogStore {
    root: files::Root,
    identity: StoreIdentity,
    config_hash: String,
    checkpoint: Option<String>,
}
/// This non-deserializable guard retains a shared interprocess lock. A copied
/// head, DTO or historical result cannot construct it.
pub struct CurrentCatalogGuard {
    _lock: files::Guard,
    catalog: ValidatedSignedCatalog,
    head: CatalogHead,
}
impl CurrentCatalogGuard {
    pub fn head(&self) -> &CatalogHead {
        &self.head
    }
    pub fn catalog(&self) -> &ValidatedSignedCatalog {
        &self.catalog
    }
    /// Revalidate named directory/lock identity, external roots and time on use.
    /// Call again at the final dispatch gate and retain the guard through spawn.
    pub fn access<'a>(
        &'a self,
        publishers: &'a TrustedCatalogPublishers,
        now: u64,
    ) -> Result<CatalogAccess<'a>> {
        self._lock.validate_identity()?;
        if now < self.head.changed_at_unix_seconds {
            return Err(StoreError::Time);
        }
        if Some(publishers.fingerprint()?) != self.head.grants_hash {
            return Err(StoreError::Authority);
        }
        let access = CatalogAccess {
            publishers,
            now_unix_seconds: now,
            expected_binding_hash: self.catalog.binding_hash(),
        };
        self.catalog.validate_current(&access)?;
        Ok(access)
    }
    pub fn validate_publishers(
        &self,
        publishers: &TrustedCatalogPublishers,
        now: u64,
    ) -> Result<()> {
        if Some(publishers.fingerprint()?) != self.head.grants_hash {
            return Err(StoreError::Authority);
        }
        self.access(publishers, now)?;
        Ok(())
    }
}
/// Verified historical inspection only. No conversion to a current guard or
/// operational opaque catalog is exposed, including when its timestamp is fresh.
pub struct HistoricalCatalog {
    head: CatalogHead,
    document: SignedCatalogDocument,
}
impl HistoricalCatalog {
    pub fn head(&self) -> &CatalogHead {
        &self.head
    }
    pub fn document(&self) -> &SignedCatalogDocument {
        &self.document
    }
}

impl CatalogStore {
    pub fn create(path: &Path, store_id: &str, catalog_id: &str) -> Result<Self> {
        if !label(store_id) || !label(catalog_id) {
            return Err(StoreError::Invalid);
        }
        let locator = locator(path)?;
        let identity = StoreIdentity {
            schema_version: 1,
            store_id: store_id.into(),
            catalog_id: catalog_id.into(),
            locator_sha256: content_digest(locator.as_os_str().as_encoded_bytes()),
        };
        let config_hash = identity.content_hash()?;
        let root = files::Root::create(&locator)?;
        let guard = root.lock(true)?;
        let state = Snapshot {
            schema_version: 1,
            identity: identity.clone(),
            config_hash: config_hash.clone(),
            documents: BTreeMap::new(),
            events: vec![],
            head: genesis(&identity)?,
            anchor: None,
            content_sha256: String::new(),
        };
        root.commit(&guard, &state.bytes()?, None)?;
        Ok(Self {
            root,
            identity,
            config_hash,
            checkpoint: None,
        })
    }
    /// The expected config digest must come from outside this directory. An
    /// optional trusted checkpoint accepts only that head or its successors.
    pub fn open(path: &Path, expected_config_hash: &str, checkpoint: Option<&str>) -> Result<Self> {
        if !is_digest(expected_config_hash) || checkpoint.is_some_and(|v| !is_digest(v)) {
            return Err(StoreError::Invalid);
        }
        let locator = locator(path)?;
        let root = files::Root::open(&locator)?;
        let _guard = root.lock(false)?;
        let state: Snapshot = json::parse(&root.read()?)?;
        state.validate()?;
        if state.config_hash != expected_config_hash
            || state.identity.locator_sha256
                != content_digest(locator.as_os_str().as_encoded_bytes())
        {
            return Err(StoreError::Authority);
        }
        check_checkpoint(&state, checkpoint)?;
        Ok(Self {
            root,
            identity: state.identity,
            config_hash: expected_config_hash.into(),
            checkpoint: checkpoint.map(str::to_owned),
        })
    }
    pub fn identity(&self) -> &StoreIdentity {
        &self.identity
    }
    pub fn config_hash(&self) -> &str {
        &self.config_hash
    }
    fn read(&self) -> Result<(Snapshot, Vec<u8>)> {
        let bytes = self.root.read()?;
        let state: Snapshot = json::parse(&bytes)?;
        state.validate()?;
        if state.identity != self.identity || state.config_hash != self.config_hash {
            return Err(StoreError::Authority);
        }
        check_checkpoint(&state, self.checkpoint.as_deref())?;
        Ok((state, bytes))
    }
    pub fn status(&self) -> Result<CatalogHead> {
        let _lock = self.root.lock(false)?;
        Ok(self.read()?.0.head)
    }
    pub fn review_activate(
        &self,
        bytes: &[u8],
        publishers: &TrustedCatalogPublishers,
        now: u64,
        ttl_seconds: u64,
    ) -> Result<CatalogReview> {
        let document = SignedCatalogDocument::from_json(bytes)?;
        if document.manifest.id != self.identity.catalog_id {
            return Err(StoreError::Authority);
        }
        let verified = verified(&document, publishers, now)?;
        let change = CatalogChange::Activate {
            document_sha256: content_digest(&document.canonical_json()?),
            binding_hash: verified.binding_hash().into(),
        };
        self.review(change, Some(document), publishers, now, ttl_seconds)
    }
    pub fn review_revoke(
        &self,
        publishers: &TrustedCatalogPublishers,
        now: u64,
        ttl_seconds: u64,
    ) -> Result<CatalogReview> {
        self.review(CatalogChange::Revoke, None, publishers, now, ttl_seconds)
    }
    /// Reconstruct the opaque activation review from its exported projection
    /// and the exact signed document bytes, rechecking current roots and time.
    pub fn reopen_activate(
        &self,
        projection: &ReviewProjection,
        bytes: &[u8],
        publishers: &TrustedCatalogPublishers,
        now: u64,
    ) -> Result<CatalogReview> {
        let document = SignedCatalogDocument::from_json(bytes)?;
        if document.manifest.id != self.identity.catalog_id {
            return Err(StoreError::Authority);
        }
        let original = verified(&document, publishers, projection.reviewed_at_unix_seconds)?;
        let current = verified(&document, publishers, now)?;
        let change = CatalogChange::Activate {
            document_sha256: content_digest(&document.canonical_json()?),
            binding_hash: original.binding_hash().into(),
        };
        if current.binding_hash() != original.binding_hash() || projection.change != change {
            return Err(StoreError::Authority);
        }
        self.reopen(projection, change, Some(document), publishers, now)
    }
    /// Reconstruct a revoke review without trusting serialized review status.
    pub fn reopen_revoke(
        &self,
        projection: &ReviewProjection,
        publishers: &TrustedCatalogPublishers,
        now: u64,
    ) -> Result<CatalogReview> {
        self.reopen(projection, CatalogChange::Revoke, None, publishers, now)
    }
    fn reopen(
        &self,
        projection: &ReviewProjection,
        change: CatalogChange,
        document: Option<SignedCatalogDocument>,
        publishers: &TrustedCatalogPublishers,
        now: u64,
    ) -> Result<CatalogReview> {
        let _lock = self.root.lock(false)?;
        let (state, _) = self.read()?;
        validate_review(projection, &self.identity, &state.head, now)?;
        let reconstructed = ReviewProjection {
            schema_version: 1,
            identity: self.identity.clone(),
            config_hash: self.config_hash.clone(),
            expected_head_hash: state.head.head_hash.clone(),
            expected_revision: state.head.revision,
            grants_hash: publishers.fingerprint()?,
            change,
            reviewed_at_unix_seconds: projection.reviewed_at_unix_seconds,
            expires_at_unix_seconds: projection.expires_at_unix_seconds,
        };
        if &reconstructed != projection {
            return Err(StoreError::Authority);
        }
        let approval_digest = hash("catalog-store-approval-v1", projection)?;
        Ok(CatalogReview {
            projection: projection.clone(),
            document,
            approval_digest,
        })
    }
    fn review(
        &self,
        change: CatalogChange,
        document: Option<SignedCatalogDocument>,
        publishers: &TrustedCatalogPublishers,
        now: u64,
        ttl_seconds: u64,
    ) -> Result<CatalogReview> {
        if !(1..=MAX_REVIEW_SECONDS).contains(&ttl_seconds) {
            return Err(StoreError::Limit);
        }
        let _lock = self.root.lock(false)?;
        let (mut state, _) = self.read()?;
        let projection = ReviewProjection {
            schema_version: 1,
            identity: self.identity.clone(),
            config_hash: self.config_hash.clone(),
            expected_head_hash: state.head.head_hash.clone(),
            expected_revision: state.head.revision,
            grants_hash: publishers.fingerprint()?,
            change,
            reviewed_at_unix_seconds: now,
            expires_at_unix_seconds: now.checked_add(ttl_seconds).ok_or(StoreError::Limit)?,
        };
        validate_review(&projection, &self.identity, &state.head, now)?;
        // Refuse now what apply would refuse: the same staging on a scratch
        // copy, measured exactly, so an approval is never granted for a change
        // that cannot apply.
        stage(&mut state, &projection, document.as_ref(), now, BUDGET)?;
        let approval_digest = hash("catalog-store-approval-v1", &projection)?;
        Ok(CatalogReview {
            projection,
            document,
            approval_digest,
        })
    }
    pub fn apply(
        &self,
        review: &CatalogReview,
        exact_approval_digest: &str,
        publishers: &TrustedCatalogPublishers,
        now: u64,
    ) -> Result<CatalogHead> {
        if exact_approval_digest != review.approval_digest
            || review.approval_digest != hash("catalog-store-approval-v1", &review.projection)?
        {
            return Err(StoreError::Approval);
        }
        if publishers.fingerprint()? != review.projection.grants_hash {
            return Err(StoreError::Authority);
        }
        let lock = self.root.lock(true)?;
        let (mut state, preimage) = self.read()?;
        validate_review(&review.projection, &self.identity, &state.head, now)?;
        match (&review.projection.change, &review.document) {
            (
                CatalogChange::Activate {
                    document_sha256,
                    binding_hash,
                },
                Some(document),
            ) => {
                let catalog = verified(document, publishers, now)?;
                if catalog.binding_hash() != binding_hash
                    || content_digest(&document.canonical_json()?) != *document_sha256
                {
                    return Err(StoreError::Integrity);
                }
            }
            (CatalogChange::Revoke, None) => {}
            _ => return Err(StoreError::Integrity),
        }
        stage(
            &mut state,
            &review.projection,
            review.document.as_ref(),
            now,
            BUDGET,
        )?;
        let head = state.head.clone();
        let bytes = state.bytes()?;
        json::parse::<Snapshot>(&bytes)?.validate()?;
        // Revalidate the named directory and lock immediately before writing.
        lock.validate_identity()?;
        self.root.commit(&lock, &bytes, Some(&preimage))?;
        Ok(head)
    }
    pub fn acquire_current(
        &self,
        expected_head_hash: &str,
        publishers: &TrustedCatalogPublishers,
        now: u64,
    ) -> Result<CurrentCatalogGuard> {
        let lock = self.root.lock(false)?;
        let (state, _) = self.read()?;
        if state.head.head_hash != expected_head_hash {
            return Err(StoreError::Conflict);
        }
        if now < state.head.changed_at_unix_seconds {
            return Err(StoreError::Time);
        }
        if state.head.grants_hash.as_deref() != Some(publishers.fingerprint()?.as_str()) {
            return Err(StoreError::Authority);
        }
        let document_hash = state
            .head
            .document_sha256
            .as_ref()
            .ok_or(StoreError::Revoked)?;
        let document = state
            .documents
            .get(document_hash)
            .ok_or(StoreError::Integrity)?;
        let catalog = verified(document, publishers, now)?;
        if state.head.binding_hash.as_deref() != Some(catalog.binding_hash()) {
            return Err(StoreError::Authority);
        }
        let guard = CurrentCatalogGuard {
            _lock: lock,
            catalog,
            head: state.head,
        };
        guard.access(publishers, now)?;
        Ok(guard)
    }
    pub fn historical(
        &self,
        head_hash: &str,
        publishers_at_activation: &TrustedCatalogPublishers,
    ) -> Result<HistoricalCatalog> {
        let _lock = self.root.lock(false)?;
        let (state, _) = self.read()?;
        let head = state
            .events
            .iter()
            .find(|event| event.head.head_hash == head_hash)
            .map(|e| &e.head)
            .ok_or(StoreError::Missing)?;
        if head.grants_hash.as_deref() != Some(publishers_at_activation.fingerprint()?.as_str()) {
            return Err(StoreError::Authority);
        }
        let document = state
            .documents
            .get(head.document_sha256.as_ref().ok_or(StoreError::Revoked)?)
            .ok_or(StoreError::Integrity)?;
        let catalog = verified(
            document,
            publishers_at_activation,
            head.changed_at_unix_seconds,
        )?;
        if head.binding_hash.as_deref() != Some(catalog.binding_hash()) {
            return Err(StoreError::Integrity);
        }
        Ok(HistoricalCatalog {
            head: head.clone(),
            document: document.clone(),
        })
    }
}
fn verified(
    document: &SignedCatalogDocument,
    publishers: &TrustedCatalogPublishers,
    now: u64,
) -> Result<ValidatedSignedCatalog> {
    match document.verify(publishers, now)? {
        CatalogVerification::Verified(v) => Ok(v),
        CatalogVerification::Quarantined(_) => Err(StoreError::Authority),
    }
}
fn validate_review(
    review: &ReviewProjection,
    identity: &StoreIdentity,
    head: &CatalogHead,
    now: u64,
) -> Result<()> {
    if review.schema_version != 1
        || &review.identity != identity
        || review.config_hash != identity.content_hash()?
        || !is_digest(&review.grants_hash)
    {
        return Err(StoreError::Authority);
    }
    if review.expected_head_hash != head.head_hash || review.expected_revision != head.revision {
        return Err(StoreError::Conflict);
    }
    if review.reviewed_at_unix_seconds < head.changed_at_unix_seconds
        || now < review.reviewed_at_unix_seconds
        || now >= review.expires_at_unix_seconds
    {
        return Err(StoreError::Time);
    }
    if !(1..=MAX_REVIEW_SECONDS).contains(
        &review
            .expires_at_unix_seconds
            .saturating_sub(review.reviewed_at_unix_seconds),
    ) {
        return Err(StoreError::Time);
    }
    Ok(())
}
fn genesis(identity: &StoreIdentity) -> Result<CatalogHead> {
    CatalogHead {
        schema_version: 1,
        store_id: identity.store_id.clone(),
        catalog_id: identity.catalog_id.clone(),
        locator_sha256: identity.locator_sha256.clone(),
        revision: 0,
        previous_head: None,
        document_sha256: None,
        binding_hash: None,
        grants_hash: None,
        changed_at_unix_seconds: 0,
        approval_digest: None,
        head_hash: String::new(),
    }
    .seal()
}
fn next_head(review: &ReviewProjection, now: u64) -> Result<CatalogHead> {
    let (document_sha256, binding_hash) = match &review.change {
        CatalogChange::Activate {
            document_sha256,
            binding_hash,
        } => (Some(document_sha256.clone()), Some(binding_hash.clone())),
        CatalogChange::Revoke => (None, None),
    };
    CatalogHead {
        schema_version: 1,
        store_id: review.identity.store_id.clone(),
        catalog_id: review.identity.catalog_id.clone(),
        locator_sha256: review.identity.locator_sha256.clone(),
        revision: review
            .expected_revision
            .checked_add(1)
            .ok_or(StoreError::Limit)?,
        previous_head: Some(review.expected_head_hash.clone()),
        document_sha256,
        binding_hash,
        grants_hash: Some(review.grants_hash.clone()),
        changed_at_unix_seconds: now,
        approval_digest: Some(hash("catalog-store-approval-v1", review)?),
        head_hash: String::new(),
    }
    .seal()
}
/// An anchor is a sealed head of this store that at least one change produced.
fn validate_anchor(anchor: &CatalogHead, identity: &StoreIdentity) -> Result<()> {
    if anchor.schema_version != 1
        || anchor.revision == 0
        || anchor.previous_head.is_none()
        || anchor.store_id != identity.store_id
        || anchor.catalog_id != identity.catalog_id
        || anchor.locator_sha256 != identity.locator_sha256
        || anchor.clone().seal()? != *anchor
    {
        return Err(StoreError::Integrity);
    }
    Ok(())
}
struct Budget {
    max: usize,
    reserve: usize,
}
const BUDGET: Budget = Budget {
    max: MAX_SNAPSHOT_BYTES,
    reserve: REVOCATION_RESERVE_BYTES,
};
/// Append the reviewed change to `state` and bound live rows so the lifetime
/// caps never dead-end. Drops the oldest events, and any document only they
/// reference, until the snapshot fits; the last dropped head becomes the
/// snapshot anchor, so the hash chain stays verifiable. The newest event is
/// never dropped. A revocation may use the whole budget; an activation must
/// leave `reserve` bytes free. The fit is decided on the exact encoded length,
/// so `review` and `apply` agree byte for byte.
fn stage(
    state: &mut Snapshot,
    projection: &ReviewProjection,
    document: Option<&SignedCatalogDocument>,
    now: u64,
    budget: Budget,
) -> Result<()> {
    match (&projection.change, document) {
        (
            CatalogChange::Activate {
                document_sha256, ..
            },
            Some(document),
        ) => {
            state
                .documents
                .insert(document_sha256.clone(), document.clone());
        }
        (CatalogChange::Revoke, None) => {}
        _ => return Err(StoreError::Integrity),
    }
    let head = next_head(projection, now)?;
    state.events.push(Event {
        review: projection.clone(),
        applied_at_unix_seconds: now,
        head: head.clone(),
    });
    state.head = head;
    while state.events.len() > MAX_REVISIONS || state.documents.len() > MAX_DOCUMENTS {
        prune_oldest(state)?;
    }
    let limit = if matches!(projection.change, CatalogChange::Revoke) {
        budget.max
    } else {
        budget.max.saturating_sub(budget.reserve)
    };
    loop {
        let length = encoded_len(state)?;
        if length <= limit {
            return Ok(());
        }
        // Prune by estimated savings, then measure again.
        let mut freed = 0;
        while freed < length - limit {
            freed += prune_oldest(state)?;
        }
    }
}
/// Drop the oldest event and the document only it referenced. Returns the
/// bytes freed, an estimate used only to choose how much to prune.
fn prune_oldest(state: &mut Snapshot) -> Result<usize> {
    if state.events.len() <= 1 {
        return Err(StoreError::Limit);
    }
    let dropped = state.events.remove(0);
    let mut freed = bounded_json(&dropped)?.len();
    if let CatalogChange::Activate {
        document_sha256, ..
    } = &dropped.review.change
    {
        let referenced = state.head.document_sha256.as_ref() == Some(document_sha256)
            || state.events.iter().any(|kept| {
                matches!(&kept.review.change, CatalogChange::Activate { document_sha256: d, .. } if d == document_sha256)
            });
        if !referenced {
            if let Some(document) = state.documents.remove(document_sha256) {
                freed += document.canonical_json()?.len();
            }
        }
    }
    state.anchor = Some(dropped.head);
    Ok(freed)
}
/// Exact length of the encoded snapshot, without allocating it.
fn encoded_len(state: &Snapshot) -> Result<usize> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    // The seal is a 64 character hex digest.
    serde_json::to_writer(&mut count, &state.view(&"0".repeat(64)))
        .map_err(|_| StoreError::Limit)?;
    Ok(count.0)
}
fn check_checkpoint(state: &Snapshot, checkpoint: Option<&str>) -> Result<()> {
    if let Some(expected) = checkpoint {
        // Once history is pruned the chain starts at the anchor, not genesis.
        let root = match &state.anchor {
            Some(anchor) => anchor.head_hash.clone(),
            None => genesis(&state.identity)?.head_hash,
        };
        if root != expected && !state.events.iter().any(|e| e.head.head_hash == expected) {
            return Err(StoreError::Conflict);
        }
    }
    Ok(())
}
fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn locator(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(StoreError::path(Operation::Locator));
    }
    let parent = path
        .parent()
        .ok_or(StoreError::path(Operation::Locator))?
        .canonicalize()
        .map_err(|error| StoreError::Path {
            operation: Operation::Locator,
            errno: error.raw_os_error(),
        })?;
    let canonical = parent.join(
        path.file_name()
            .ok_or(StoreError::path(Operation::Locator))?,
    );
    if canonical.as_os_str() != path.as_os_str() {
        return Err(StoreError::path(Operation::Locator));
    }
    Ok(canonical)
}
fn hash(domain: &str, value: &impl Serialize) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bounded_json(value)?);
    Ok(hex::encode(hasher.finalize()))
}

fn bounded_json(value: &impl Serialize) -> Result<Vec<u8>> {
    struct Buffer(Vec<u8>);
    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0.len().saturating_add(bytes.len()) > MAX_SNAPSHOT_BYTES {
                return Err(std::io::Error::other("catalog store bound"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut buffer = Buffer(Vec::new());
    serde_json::to_writer(&mut buffer, value).map_err(|_| StoreError::Limit)?;
    Ok(buffer.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_snapshot() -> Snapshot {
        let identity = StoreIdentity {
            schema_version: 1,
            store_id: "s".into(),
            catalog_id: "c".into(),
            locator_sha256: "a".repeat(64),
        };
        Snapshot {
            schema_version: 1,
            config_hash: identity.content_hash().unwrap(),
            head: genesis(&identity).unwrap(),
            identity,
            documents: BTreeMap::new(),
            events: vec![],
            anchor: None,
            content_sha256: String::new(),
        }
    }

    #[test]
    fn borrowed_snapshot_hash_matches_the_cloning_definition() {
        for anchor in [None, Some(empty_snapshot().head)] {
            let mut state = empty_snapshot();
            state.anchor = anchor;
            let mut copy = state.clone();
            copy.content_sha256.clear();
            let expected = hash("catalog-store-snapshot-v1", &copy).unwrap();
            assert_eq!(state.seal_hash().unwrap(), expected);
            let bytes = state.bytes().unwrap();
            let parsed: Snapshot = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(parsed.content_sha256, expected);
        }
    }

    fn sealed(mut state: Snapshot) -> Snapshot {
        state.content_sha256 = state.seal_hash().unwrap();
        state
    }
    fn revoke_projection(state: &Snapshot) -> ReviewProjection {
        ReviewProjection {
            schema_version: 1,
            identity: state.identity.clone(),
            config_hash: state.config_hash.clone(),
            expected_head_hash: state.head.head_hash.clone(),
            expected_revision: state.head.revision,
            grants_hash: "b".repeat(64),
            change: CatalogChange::Revoke,
            reviewed_at_unix_seconds: 10,
            expires_at_unix_seconds: 20,
        }
    }

    #[test]
    fn a_sealed_snapshot_with_an_invalid_anchor_is_refused_by_validate_anchor() {
        let base = empty_snapshot();
        let good = next_head(&revoke_projection(&base), 10).unwrap();
        let with_anchor = |anchor: CatalogHead| {
            let mut state = base.clone();
            state.head = anchor.clone();
            state.anchor = Some(anchor);
            sealed(state)
        };
        with_anchor(good.clone()).validate().unwrap();
        let variants = {
            let mut zero = good.clone();
            zero.revision = 0;
            let mut orphan = good.clone();
            orphan.previous_head = None;
            let mut foreign = good.clone();
            foreign.store_id = "other".into();
            let mut forged = good.clone();
            forged.head_hash = "0".repeat(64);
            [
                ("revision 0", zero.seal().unwrap()),
                ("no previous head", orphan.seal().unwrap()),
                ("wrong store_id", foreign.seal().unwrap()),
                ("wrong head_hash", forged),
            ]
        };
        for (name, anchor) in variants {
            assert!(
                matches!(with_anchor(anchor).validate(), Err(StoreError::Integrity)),
                "{name}"
            );
        }
    }

    // Real signed documents and events; only the limit is small, so the
    // boundaries below are exact encoded lengths, not estimates.
    fn signed(version: &str) -> Vec<u8> {
        use ed25519_dalek::{Signer, SigningKey};
        use router_catalog::*;
        let entry: SignedCatalogEntry = serde_json::from_value(serde_json::json!({
            "schema_version":1,"id":"model","version":version,"provenance":{"source":"https://example.test/catalog","revision":"fixture","source_sha256":"a".repeat(64)},"license_expression":"MIT","authors":["Synthetic publisher"],"valid_from_unix_seconds":100,"valid_until_unix_seconds":1000,"declared_trust":"builtin","capabilities":[],
            "requirements":{"capabilities":[],"mutations":[],"tools":[],"compatible_hosts":[]},
            "restrictions":{"allowed_mutations":[],"allowed_sandboxes":["read_only"],"maximum_sensitivity":"public"},"context_cost_estimate":0,"deprecated_by":null,"payload_sha256":"",
            "payload":{"kind":"model","definition":{"id":"model","stages":["plan"],"efforts":["medium"],"capabilities":[],"quality_micros":500000,"cost_micros":1,"latency_micros":1,"source":"https://example.test/catalog"}},
            "search":{"kind":"model","id":"model","trust":"builtin","description":"synthetic","body":null},
            "signals":{"asset":{"kind":"model","id":"model"},"languages":{"status":"unknown"},"required_tools":{"status":"unknown"},"history":{"status":"unknown"}}
        }))
        .unwrap();
        let manifest = seal_signed_manifest(SignedCatalogManifest {
            schema_version: 1,
            id: "example".into(),
            version: version.into(),
            valid_from_unix_seconds: 100,
            valid_until_unix_seconds: 1000,
            assets: vec![entry],
            content_sha256: String::new(),
        })
        .unwrap();
        let signature = SigningKey::from_bytes(&[37; 32])
            .sign(&catalog_signing_message("synthetic", &manifest).unwrap());
        SignedCatalogDocument {
            schema_version: 3,
            manifest,
            signature: CatalogPublisherSignature {
                key_id: "synthetic".into(),
                signature_hex: hex::encode(signature.to_bytes()),
            },
        }
        .canonical_json()
        .unwrap()
    }

    #[test]
    fn exact_budget_boundaries_hold_and_revocation_fits_where_activation_is_refused() {
        use ed25519_dalek::SigningKey;
        use router_catalog::*;
        let roots = TrustedCatalogPublishers::new([CatalogPublisherGrant {
            key_id: "synthetic".into(),
            public_key: SigningKey::from_bytes(&[37; 32]).verifying_key().to_bytes(),
            catalog_ids: BTreeSet::from(["example".into()]),
            allowed_kinds: BTreeSet::from([CatalogAssetKind::Model]),
            allowed_licenses: BTreeSet::from(["MIT".into()]),
            trust_ceiling: router_types::SkillTrust::VerifiedThirdParty,
        }])
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap().join("store");
        let store = CatalogStore::create(&path, "local", "example").unwrap();
        for version in ["A", "B"] {
            let review = store
                .review_activate(&signed(version), &roots, 110, 20)
                .unwrap();
            store
                .apply(&review, review.approval_digest(), &roots, 110)
                .unwrap();
        }
        let (state, bytes) = store.read().unwrap();
        assert_eq!(encoded_len(&state).unwrap(), bytes.len());
        let activate = store
            .review_activate(&signed("C"), &roots, 110, 20)
            .unwrap();
        let revoke = store.review_revoke(&roots, 110, 20).unwrap();
        let staged = |review: &CatalogReview, max: usize, reserve: usize| {
            let mut copy = state.clone();
            stage(
                &mut copy,
                review.projection(),
                review.document.as_ref(),
                110,
                Budget { max, reserve },
            )
            .map(|()| copy)
        };
        // Smallest max at which an activation fits with a reserve.
        let reserve = 1000;
        let fits = |max: usize| staged(&activate, max, reserve).is_ok();
        let (mut low, mut high) = (0, 4 * bytes.len());
        assert!(fits(high) && !fits(low));
        while high - low > 1 {
            let middle = (low + high) / 2;
            if fits(middle) {
                high = middle;
            } else {
                low = middle;
            }
        }
        let minimal = staged(&activate, high, reserve).unwrap();
        // Exact: the accepted state uses at most max - reserve, and one byte
        // less is refused with Limit, not by a later check.
        assert!(minimal.bytes().unwrap().len() <= high - reserve);
        assert!(matches!(
            staged(&activate, high - 1, reserve),
            Err(StoreError::Limit)
        ));
        // At that refused budget a revocation of the same snapshot still fits.
        let revoked = staged(&revoke, high - 1, reserve).unwrap();
        assert!(revoked.bytes().unwrap().len() < high);
        assert_eq!(revoked.head.document_sha256, None);
        json::parse::<Snapshot>(&revoked.bytes().unwrap())
            .unwrap()
            .validate()
            .unwrap();
    }
}
