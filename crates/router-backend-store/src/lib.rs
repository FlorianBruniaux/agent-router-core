//! Durable, explicitly approved backend state. No private signing key, network,
//! provider call, automatic activation, global configuration or model execution.
#![forbid(unsafe_code)]
mod files;
mod json;
use json::parse;

use router_backend_policy::{
    ActivationAction, ActivationApproval, ActivationEvent, AuthorityRole, BackendActivationState,
    BackendArtifact, PromotionError, PromotionEvidence, Signed, TrustedAuthorities,
    ValidatedBackendPromotion, evaluate_promotion_with_verifier,
};
use router_execution_decision::{ActivationAuthority, ActivationGuard, DecisionError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_EVENTS: usize = router_backend_policy::MAX_ACTIVATION_EVENTS;
/// Every activation must be rolled back before the next, so each promotion
/// costs at least two events. The event cap therefore bounds promotions by
/// count, but not by size: retained promotions can reach `MAX_SNAPSHOT_BYTES`
/// first, which `review` refuses before anything is signed.
pub const MAX_PROMOTIONS: usize = MAX_EVENTS / 2;
/// Upper bound of a serialized activation event apart from its signer id: five
/// 64 character hashes, a 128 character signature, field names and integers
/// measure under 1 KiB, so this leaves headroom.
const EVENT_FIXED_BYTES: usize = 1024;
/// `review` keeps room for the activation event `apply` appends and for the
/// rollback event that must always be able to revoke it. No approval exists at
/// review time, so each event is bounded by its fixed part plus the longest
/// configured signer id. `apply` re-checks the rollback room on every
/// activation, because the snapshot may have grown since the review.
const REVOCATION_EVENTS: usize = 2;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("backend_store.invalid")]
    Invalid,
    #[error("backend_store.limit")]
    Limit,
    #[error("backend_store.integrity")]
    Integrity,
    #[error("backend_store.configuration")]
    Configuration,
    #[error("backend_store.anchor")]
    Anchor,
    #[error("backend_store.conflict")]
    Conflict,
    #[error("backend_store.busy")]
    Busy,
    #[error("backend_store.exists")]
    Exists,
    #[error("backend_store.missing")]
    Missing,
    #[error("backend_store.permissions")]
    Permissions,
    #[error("backend_store.path")]
    Path,
    #[error("backend_store.io")]
    Io,
    #[error("backend_store.clock")]
    Clock,
    /// The snapshot rename succeeded but the directory sync failed: the new head
    /// may already be published and its durability is UNKNOWN. Reopen and read
    /// the head before any retry; never generate another approval blindly.
    #[error("backend_store.published_durability_unknown")]
    PublishedDurabilityUnknown,
    #[error("backend_store.platform.unsupported")]
    Unsupported,
    #[error("backend_store.promotion")]
    Promotion(#[from] PromotionError),
}
pub type Result<T> = std::result::Result<T, StoreError>;

/// Public verification material only. Its trust comes from an independently
/// supplied expected configuration digest, never from this document's contents.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityKey {
    pub role: AuthorityRole,
    pub id: String,
    pub public_key_hex: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    pub schema_version: u32,
    pub baseline_policy_hash: String,
    pub scope_sha256: String,
    pub authorities: Vec<AuthorityKey>,
}
impl StoreConfig {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 64 * 1024 {
            return Err(StoreError::Limit);
        }
        let config: Self = parse(bytes)?;
        config.canonical()
    }
    fn canonical(&self) -> Result<Self> {
        if self.schema_version != 1
            || !valid_hash(&self.baseline_policy_hash)
            || !valid_hash(&self.scope_sha256)
            || self.authorities.len() > 128
        {
            return Err(StoreError::Configuration);
        }
        let mut config = self.clone();
        config
            .authorities
            .sort_by(|a, b| (&a.role, &a.id).cmp(&(&b.role, &b.id)));
        config.trusted()?;
        Ok(config)
    }
    fn trusted(&self) -> Result<TrustedAuthorities> {
        let entries = self
            .authorities
            .iter()
            .map(|key| {
                if !valid_hash(&key.public_key_hex) {
                    return Err(StoreError::Configuration);
                }
                let bytes =
                    hex::decode(&key.public_key_hex).map_err(|_| StoreError::Configuration)?;
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| StoreError::Configuration)?;
                Ok((key.role, key.id.clone(), bytes))
            })
            .collect::<Result<Vec<_>>>()?;
        if entries
            .iter()
            .map(|entry| entry.0)
            .collect::<BTreeSet<_>>()
            .len()
            != 4
        {
            return Err(StoreError::Configuration);
        }
        TrustedAuthorities::new(entries).map_err(|_| StoreError::Configuration)
    }
    pub fn content_hash(&self) -> Result<String> {
        hash("agent-router:backend-store-config:v1\0", &self.canonical()?)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PromotionRecord {
    artifact: BackendArtifact,
    evidence: PromotionEvidence,
    validated_at_unix_seconds: u64,
    promotion_hash: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u32,
    config: StoreConfig,
    config_hash: String,
    promotions: BTreeMap<String, PromotionRecord>,
    events: Vec<ActivationEvent>,
    head: String,
    document_hash: String,
}
impl Snapshot {
    fn digest(&self) -> Result<String> {
        hash(
            "agent-router:backend-store-snapshot:v1\0",
            &(
                self.schema_version,
                &self.config,
                &self.config_hash,
                &self.promotions,
                &self.events,
                &self.head,
            ),
        )
    }
    fn encode(&mut self, limit: usize) -> Result<Vec<u8>> {
        self.document_hash = self.digest()?;
        let bytes = serde_json::to_vec(self).map_err(|_| StoreError::Invalid)?;
        if bytes.len() > limit {
            return Err(StoreError::Limit);
        }
        Ok(bytes)
    }
}

/// Safe CLI projection. No source labels, model identities, prompts, public or
/// private key material, raw signatures or external observations are exported.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StoreStatus {
    pub schema_version: u32,
    pub config_hash: String,
    pub state_hash: String,
    pub baseline_policy_hash: String,
    pub scope_sha256: String,
    pub authority_fingerprint: String,
    pub event_count: usize,
    pub promotion_count: usize,
    pub active_promotion_hash: Option<String>,
    pub active_artifact_hash: Option<String>,
    pub active_expires_at_unix_seconds: Option<u64>,
    pub active_expired: Option<bool>,
    pub external_anchor_checked: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PromotionReview {
    pub schema_version: u32,
    pub config_hash: String,
    pub promotion_hash: String,
    pub artifact_hash: String,
    pub expires_at_unix_seconds: u64,
    pub heldout_cases: usize,
    pub heldout_families: usize,
}
/// Non-deserializable review, reconstructed from signed evidence each time.
/// Retains private evidence for an explicit later activation, never in Debug.
pub struct ReviewedPromotion {
    record: PromotionRecord,
    projection: PromotionReview,
}
impl ReviewedPromotion {
    pub fn projection(&self) -> &PromotionReview {
        &self.projection
    }
}

pub struct BackendStore {
    capability_verifier: Option<std::sync::Arc<dyn router_adapter_api::CapabilityProofVerifier>>,
    root: files::Root,
    config_hash: String,
    // Optional independently retained checkpoint. Accepted signed successors
    // may append, but a history that loses this checkpoint is rejected.
    anchor: Option<String>,
    snapshot_limit: usize,
    promotion_limit: usize,
}
pub struct StoreGuard {
    _lock: files::Guard,
    state: BackendActivationState,
    authorities: TrustedAuthorities,
    status: StoreStatus,
}
/// Verified historical view for reconstructing an old decision. This does not
/// implement ActivationAuthority and cannot supply current dispatch authority.
pub struct HistoricalActivation {
    _lock: files::Guard,
    state: BackendActivationState,
    authorities: TrustedAuthorities,
    original_time: u64,
}
impl ActivationGuard for HistoricalActivation {
    fn state(&self) -> &BackendActivationState {
        &self.state
    }
    fn authorities(&self) -> &TrustedAuthorities {
        &self.authorities
    }
}
impl HistoricalActivation {
    pub fn original_time(&self) -> u64 {
        self.original_time
    }
}
impl ActivationGuard for StoreGuard {
    fn state(&self) -> &BackendActivationState {
        &self.state
    }
    fn authorities(&self) -> &TrustedAuthorities {
        &self.authorities
    }
}
impl StoreGuard {
    pub fn status(&self) -> &StoreStatus {
        &self.status
    }
}
impl ActivationAuthority for BackendStore {
    fn acquire(&self) -> std::result::Result<Box<dyn ActivationGuard + '_>, DecisionError> {
        self.read_guard(now().map_err(|_| DecisionError::AuthorityUnavailable)?)
            .map(|guard| Box::new(guard) as Box<dyn ActivationGuard>)
            .map_err(|_| DecisionError::AuthorityUnavailable)
    }
}
impl BackendStore {
    /// Creates only a new final directory below an existing no-symlink parent.
    /// Config is an explicit parent input; this never generates signing keys.
    pub fn create(path: &Path, config: StoreConfig) -> Result<Self> {
        let config = config.canonical()?;
        let config_hash = config.content_hash()?;
        let state =
            BackendActivationState::new(&config.baseline_policy_hash, &config.scope_sha256)?;
        let root = files::Root::create(path)?;
        let _lock = root.lock(true)?;
        let mut snapshot = Snapshot {
            schema_version: 1,
            config,
            config_hash: config_hash.clone(),
            promotions: BTreeMap::new(),
            events: vec![],
            head: state.state_hash().into(),
            document_hash: String::new(),
        };
        root.commit(&snapshot.encode(MAX_SNAPSHOT_BYTES)?, None)?;
        Ok(Self {
            capability_verifier: None,
            root,
            config_hash,
            anchor: None,
            snapshot_limit: MAX_SNAPSHOT_BYTES,
            promotion_limit: MAX_PROMOTIONS,
        })
    }
    /// The expected config hash and optional history checkpoint come from
    /// parent authority outside the store, never auto-read from its own JSON.
    pub fn open(
        path: &Path,
        expected_config_hash: &str,
        expected_head: Option<&str>,
    ) -> Result<Self> {
        Self::open_with_capability_verifier(path, expected_config_hash, expected_head, None)
    }
    pub fn open_with_capability_verifier(
        path: &Path,
        expected_config_hash: &str,
        expected_head: Option<&str>,
        capability_verifier: Option<
            std::sync::Arc<dyn router_adapter_api::CapabilityProofVerifier>,
        >,
    ) -> Result<Self> {
        if !valid_hash(expected_config_hash) || expected_head.is_some_and(|h| !valid_hash(h)) {
            return Err(StoreError::Configuration);
        }
        let store = Self {
            capability_verifier,
            root: files::Root::open(path)?,
            config_hash: expected_config_hash.into(),
            anchor: expected_head.map(str::to_owned),
            snapshot_limit: MAX_SNAPSHOT_BYTES,
            promotion_limit: MAX_PROMOTIONS,
        };
        store.read_guard(now()?)?;
        Ok(store)
    }
    /// Explicit authenticated capability evidence for every replay performed
    /// by review, activation, current reads and historical reconstruction.
    pub fn with_capability_proof_verifier(
        mut self,
        verifier: std::sync::Arc<dyn router_adapter_api::CapabilityProofVerifier>,
    ) -> Self {
        self.capability_verifier = Some(verifier);
        self
    }
    /// Lowers the encoded snapshot bound enforced by `review` and `apply`,
    /// intended for tests. It only ever lowers: a later call cannot raise it
    /// above the current bound or `MAX_SNAPSHOT_BYTES`. Reading is unaffected.
    #[must_use]
    pub fn with_snapshot_limit(mut self, limit: usize) -> Self {
        self.snapshot_limit = self.snapshot_limit.min(limit);
        self
    }
    /// Lowers the retained promotion count enforced by `review` and `apply`,
    /// intended for tests. It only ever lowers, never above `MAX_PROMOTIONS`.
    #[must_use]
    pub fn with_promotion_limit(mut self, limit: usize) -> Self {
        self.promotion_limit = self.promotion_limit.min(limit);
        self
    }
    pub fn config_hash(&self) -> &str {
        &self.config_hash
    }
    pub fn read_guard(&self, now: u64) -> Result<StoreGuard> {
        let lock = self.root.lock(false)?;
        let (_, _, state, authorities, status) = self.load(now)?;
        Ok(StoreGuard {
            _lock: lock,
            state,
            authorities,
            status,
        })
    }
    pub fn status(&self, now: u64) -> Result<StoreStatus> {
        Ok(self.read_guard(now)?.status)
    }
    /// Reconstruct a verified predecessor for history/reopen only. The supplied
    /// time must lie in that head's seconds-resolution interval. Equal-second
    /// transitions are ordered by their exact heads, never by invented subsecond
    /// timestamps. Execution must separately
    /// acquire current authority from this BackendStore immediately at spawn.
    pub fn historical_guard(
        &self,
        state_hash: &str,
        original_time: u64,
    ) -> Result<HistoricalActivation> {
        if !valid_hash(state_hash) {
            return Err(StoreError::Invalid);
        }
        let _lock = self.root.lock(false)?;
        let current_time = now()?;
        if original_time > current_time {
            return Err(StoreError::Clock);
        }
        let (_, snapshot, _, authorities, _) = self.load(current_time)?;
        let genesis = BackendActivationState::new(
            &snapshot.config.baseline_policy_hash,
            &snapshot.config.scope_sha256,
        )?;
        let length = if state_hash == genesis.state_hash() {
            0
        } else {
            snapshot
                .events
                .iter()
                .position(|event| event.resulting_state_hash == state_hash)
                .map(|index| index + 1)
                .ok_or(StoreError::Anchor)?
        };
        let start = length
            .checked_sub(1)
            .map_or(0, |index| snapshot.events[index].recorded_at_unix_seconds);
        let next = snapshot
            .events
            .get(length)
            .map(|event| event.recorded_at_unix_seconds);
        if original_time < start || next.is_some_and(|end| original_time > end) {
            return Err(StoreError::Clock);
        }
        let events = &snapshot.events[..length];
        let ids = events
            .iter()
            .filter(|event| event.approval.statement.action == ActivationAction::Activate)
            .map(|event| &event.approval.statement.target_hash)
            .collect::<BTreeSet<_>>();
        let mut promotions = BTreeMap::new();
        for id in ids {
            let record = snapshot.promotions.get(id).ok_or(StoreError::Integrity)?;
            promotions.insert(
                id.clone(),
                evaluate_promotion_with_verifier(
                    &record.artifact,
                    &record.evidence,
                    &authorities,
                    record.validated_at_unix_seconds,
                    self.capability_verifier.as_deref(),
                )?,
            );
        }
        let state = BackendActivationState::restore(
            &snapshot.config.baseline_policy_hash,
            &snapshot.config.scope_sha256,
            events,
            &promotions,
            &authorities,
            state_hash,
            original_time,
        )?;
        Ok(HistoricalActivation {
            _lock,
            state,
            authorities,
            original_time,
        })
    }
    /// Pure evaluation under the current pinned trust configuration. Does not
    /// store evidence, alter activation history or consume an approval nonce.
    pub fn review(
        &self,
        artifact: &BackendArtifact,
        evidence: &PromotionEvidence,
        now: u64,
    ) -> Result<ReviewedPromotion> {
        let lock = self.root.lock(false)?;
        let (_, snapshot, state, authorities, _) = self.load(now)?;
        if artifact.routing_policy_hash != state.baseline_policy_hash() {
            return Err(StoreError::Configuration);
        }
        if serde_json::to_vec(&(artifact, evidence))
            .map_err(|_| StoreError::Invalid)?
            .len()
            > router_backend_policy::MAX_DOCUMENT_BYTES
        {
            return Err(StoreError::Limit);
        }
        let accepted = evaluate_promotion_with_verifier(
            artifact,
            evidence,
            &authorities,
            now,
            self.capability_verifier.as_deref(),
        )?;
        // Refuse early: simulate the snapshot `apply` would encode with this
        // promotion retained, so no approval is signed for an unappliable change.
        if !snapshot.promotions.contains_key(accepted.promotion_hash()) {
            if snapshot.promotions.len() >= self.promotion_limit {
                return Err(StoreError::Limit);
            }
            let mut simulated = snapshot;
            simulated.promotions.insert(
                accepted.promotion_hash().into(),
                PromotionRecord {
                    artifact: artifact.clone(),
                    evidence: evidence.clone(),
                    validated_at_unix_seconds: now,
                    promotion_hash: accepted.promotion_hash().into(),
                },
            );
            let reserve = REVOCATION_EVENTS * event_room(&simulated.config);
            simulated.encode(self.snapshot_limit.saturating_sub(reserve))?;
        }
        drop(lock);
        let projection = PromotionReview {
            schema_version: 1,
            config_hash: self.config_hash.clone(),
            promotion_hash: accepted.promotion_hash().into(),
            artifact_hash: artifact.content_hash()?,
            expires_at_unix_seconds: accepted.expires_at_unix_seconds(),
            heldout_cases: accepted.report().baseline.cases,
            heldout_families: accepted.family_reports().len(),
        };
        Ok(ReviewedPromotion {
            record: PromotionRecord {
                artifact: artifact.clone(),
                evidence: evidence.clone(),
                validated_at_unix_seconds: now,
                promotion_hash: accepted.promotion_hash().into(),
            },
            projection,
        })
    }
    pub fn activate(
        &self,
        approval: &Signed<ActivationApproval>,
        reviewed: &ReviewedPromotion,
        now: u64,
    ) -> Result<StoreStatus> {
        if approval.statement.action != ActivationAction::Activate
            || reviewed.projection.config_hash != self.config_hash
        {
            return Err(StoreError::Configuration);
        }
        self.apply(approval, Some(reviewed), now)
    }
    pub fn rollback(&self, approval: &Signed<ActivationApproval>, now: u64) -> Result<StoreStatus> {
        if approval.statement.action != ActivationAction::Rollback {
            return Err(StoreError::Configuration);
        }
        self.apply(approval, None, now)
    }
    fn apply(
        &self,
        approval: &Signed<ActivationApproval>,
        review: Option<&ReviewedPromotion>,
        now: u64,
    ) -> Result<StoreStatus> {
        let _lock = self.root.lock(true)?;
        let (before, mut snapshot, mut state, authorities, _) = self.load(now)?;
        if approval.statement.expected_state_hash != state.state_hash() {
            return Err(StoreError::Conflict);
        }
        if snapshot.events.len() >= MAX_EVENTS {
            return Err(StoreError::Limit);
        }
        let accepted = review
            .map(|review| {
                evaluate_promotion_with_verifier(
                    &review.record.artifact,
                    &review.record.evidence,
                    &authorities,
                    now,
                    self.capability_verifier.as_deref(),
                )
            })
            .transpose()?;
        state.apply(approval, accepted.as_ref(), &authorities, now)?;
        if let (Some(review), Some(accepted)) = (review, accepted.as_ref()) {
            if let Some(existing) = snapshot.promotions.get(accepted.promotion_hash()) {
                if existing.artifact != review.record.artifact
                    || existing.evidence != review.record.evidence
                {
                    return Err(StoreError::Integrity);
                }
            } else {
                if snapshot.promotions.len() >= self.promotion_limit {
                    return Err(StoreError::Limit);
                }
                let mut record = review.record.clone();
                record.validated_at_unix_seconds = now;
                snapshot
                    .promotions
                    .insert(accepted.promotion_hash().into(), record);
            }
        }
        snapshot.events = state.events().to_vec();
        snapshot.head = state.state_hash().into();
        // An activation leaves room for its own rollback, whatever the review
        // saw and whether or not the promotion was already retained. A rollback
        // uses the full bound so revocation is never blocked by size.
        let limit = if review.is_some() {
            self.snapshot_limit
                .saturating_sub(event_room(&snapshot.config))
        } else {
            self.snapshot_limit
        };
        self.root.commit(&snapshot.encode(limit)?, Some(&before))?;
        status(&snapshot, &state, &authorities, self.anchor.is_some(), now)
    }
    #[allow(clippy::type_complexity)]
    fn load(
        &self,
        now: u64,
    ) -> Result<(
        Vec<u8>,
        Snapshot,
        BackendActivationState,
        TrustedAuthorities,
        StoreStatus,
    )> {
        let bytes = self.root.read()?;
        let snapshot: Snapshot = parse(&bytes)?;
        if snapshot.schema_version != 1
            || snapshot.events.len() > MAX_EVENTS
            || snapshot.promotions.len() > MAX_PROMOTIONS
            || snapshot.document_hash != snapshot.digest()?
            || !valid_hash(&snapshot.head)
        {
            return Err(StoreError::Integrity);
        }
        if snapshot.config_hash != self.config_hash
            || snapshot.config.content_hash()? != self.config_hash
        {
            return Err(StoreError::Configuration);
        }
        let authorities = snapshot.config.trusted()?;
        let mut promotions = BTreeMap::new();
        for (id, record) in &snapshot.promotions {
            if record.validated_at_unix_seconds > now
                || record.artifact.routing_policy_hash != snapshot.config.baseline_policy_hash
            {
                return Err(StoreError::Integrity);
            }
            let validated = evaluate_promotion_with_verifier(
                &record.artifact,
                &record.evidence,
                &authorities,
                record.validated_at_unix_seconds,
                self.capability_verifier.as_deref(),
            )?;
            if id != validated.promotion_hash() || record.promotion_hash != *id {
                return Err(StoreError::Integrity);
            }
            let first_use = snapshot
                .events
                .iter()
                .find(|event| {
                    event.approval.statement.action == ActivationAction::Activate
                        && event.approval.statement.target_hash == *id
                })
                .ok_or(StoreError::Integrity)?;
            if first_use.recorded_at_unix_seconds != record.validated_at_unix_seconds {
                return Err(StoreError::Integrity);
            }
            promotions.insert(id.clone(), validated);
        }
        let state = BackendActivationState::restore(
            &snapshot.config.baseline_policy_hash,
            &snapshot.config.scope_sha256,
            &snapshot.events,
            &promotions,
            &authorities,
            &snapshot.head,
            now,
        )?;
        if let Some(anchor) = &self.anchor {
            let genesis = BackendActivationState::new(
                &snapshot.config.baseline_policy_hash,
                &snapshot.config.scope_sha256,
            )?;
            if anchor != genesis.state_hash()
                && anchor != state.state_hash()
                && !state
                    .events()
                    .iter()
                    .any(|event| &event.resulting_state_hash == anchor)
            {
                return Err(StoreError::Anchor);
            }
        }
        let status = status(&snapshot, &state, &authorities, self.anchor.is_some(), now)?;
        Ok((bytes, snapshot, state, authorities, status))
    }
}
fn status(
    snapshot: &Snapshot,
    state: &BackendActivationState,
    authorities: &TrustedAuthorities,
    anchor: bool,
    now: u64,
) -> Result<StoreStatus> {
    let active = state.active_promotion();
    Ok(StoreStatus {
        schema_version: 1,
        config_hash: snapshot.config_hash.clone(),
        state_hash: state.state_hash().into(),
        baseline_policy_hash: snapshot.config.baseline_policy_hash.clone(),
        scope_sha256: snapshot.config.scope_sha256.clone(),
        authority_fingerprint: authorities.fingerprint()?,
        event_count: state.events().len(),
        promotion_count: snapshot.promotions.len(),
        active_promotion_hash: active.map(|p| p.promotion_hash().into()),
        active_artifact_hash: active.map(|p| p.artifact().content_hash()).transpose()?,
        active_expires_at_unix_seconds: active
            .map(ValidatedBackendPromotion::expires_at_unix_seconds),
        active_expired: active.map(|p| p.expires_at_unix_seconds() <= now),
        external_anchor_checked: anchor,
    })
}
/// Bound of one serialized activation event under this configuration.
fn event_room(config: &StoreConfig) -> usize {
    let longest_id = config.authorities.iter().map(|key| key.id.len()).max();
    EVENT_FIXED_BYTES + longest_id.unwrap_or(0)
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hash<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| StoreError::Invalid)?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(StoreError::Limit);
    }
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    Ok(hex::encode(hash.finalize()))
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| StoreError::Clock)
}
