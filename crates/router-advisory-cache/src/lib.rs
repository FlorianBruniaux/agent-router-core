//! Opt-in advisory cache of backend proposals. A hit only nominates a candidate
//! alias: the caller still resolves it through a fresh `BoundedDecisionContext`.
//! No receipt, grant, permission, outcome, prompt, task text or body is stored,
//! and the MAC key is never persisted. Any doubt is a miss, never an error that
//! blocks routing.
#![forbid(unsafe_code)]
mod files;

use hmac::{Hmac, Mac};
use router_decision::BoundedDecisionContext;
use router_types::{BackendProposal, PhaseSelection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

pub const MAX_ENTRY_BYTES: usize = 16 * 1024;
pub const MAX_ENTRIES: usize = 1024;
pub const MAX_TTL_SECONDS: u64 = 24 * 60 * 60;
pub const MIN_MAC_KEY_BYTES: usize = 16;
const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("advisory_cache.invalid")]
    Invalid,
    #[error("advisory_cache.limit")]
    Limit,
    #[error("advisory_cache.exists")]
    Exists,
    #[error("advisory_cache.permissions")]
    Permissions,
    #[error("advisory_cache.path")]
    Path,
    #[error("advisory_cache.busy")]
    Busy,
    #[error("advisory_cache.io")]
    Io,
    #[error("advisory_cache.platform.unsupported")]
    Unsupported,
}
pub type Result<T> = std::result::Result<T, CacheError>;

/// Caller-supplied MAC key. Never serialized, never printed.
pub struct MacKey(Zeroizing<Vec<u8>>);
impl MacKey {
    pub fn new(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MIN_MAC_KEY_BYTES {
            return Err(CacheError::Invalid);
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }
}
impl std::fmt::Debug for MacKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacKey(redacted)")
    }
}

/// Facts the cache entry is bound to, besides the exact redacted request bytes
/// and the alias table. All values come from the caller's validated inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheBinding {
    pub host: String,
    pub host_version: String,
    pub snapshot_digest: String,
    pub policy_hash: String,
    pub catalog_hash: String,
    pub backend: String,
    pub router_version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissReason {
    Absent,
    Expired,
    Malformed,
    Mismatch,
    Unauthenticated,
    Unavailable,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Lookup {
    Hit(BackendProposal),
    Miss(MissReason),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    schema_version: u32,
    key: String,
    created_unix: u64,
    expires_unix: u64,
    proposal: BackendProposal,
    mac: String,
}

fn field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// Cache key: SHA-256 over length-prefixed fields, including the exact bytes of
/// the redacted request (so a one byte difference selects another entry) and
/// the digest of the alias table.
pub fn cache_key(binding: &CacheBinding, context: &BoundedDecisionContext) -> Result<String> {
    let request =
        serde_json::to_vec(context.redacted_request()).map_err(|_| CacheError::Invalid)?;
    let aliases = context.alias_digest().map_err(|_| CacheError::Invalid)?;
    let mut hasher = Sha256::new();
    hasher.update(b"advisory-cache-key-v1\0");
    for value in [
        binding.host.as_bytes(),
        binding.host_version.as_bytes(),
        binding.snapshot_digest.as_bytes(),
        binding.policy_hash.as_bytes(),
        binding.catalog_hash.as_bytes(),
        binding.backend.as_bytes(),
        binding.router_version.as_bytes(),
        request.as_slice(),
        aliases.as_bytes(),
    ] {
        field(&mut hasher, value);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn mac_for(
    key: &[u8],
    cache_key: &str,
    created: u64,
    expires: u64,
    proposal: &BackendProposal,
) -> Result<Hmac<Sha256>> {
    let proposal = serde_json::to_vec(proposal).map_err(|_| CacheError::Invalid)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| CacheError::Invalid)?;
    for value in [
        b"advisory-cache-entry-v1".as_slice(),
        cache_key.as_bytes(),
        &created.to_be_bytes(),
        &expires.to_be_bytes(),
        &proposal,
    ] {
        mac.update(&(value.len() as u64).to_be_bytes());
        mac.update(value);
    }
    Ok(mac)
}

fn valid_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Parses and authenticates one entry against the key it is stored under.
/// `Expired` also covers `now < created_unix`: an authenticated entry dated in
/// the future (clock skew) is not live, so a full-directory sweep removes it.
fn decode(
    mac_key: &MacKey,
    cache_key: &str,
    bytes: &[u8],
    now_unix: u64,
) -> std::result::Result<BackendProposal, MissReason> {
    let entry = serde_json::from_slice::<Entry>(bytes).map_err(|_| MissReason::Malformed)?;
    if entry.schema_version != SCHEMA_VERSION || entry.key != cache_key {
        return Err(MissReason::Mismatch);
    }
    let claimed = hex::decode(&entry.mac).map_err(|_| MissReason::Unauthenticated)?;
    let mac = mac_for(
        &mac_key.0,
        &entry.key,
        entry.created_unix,
        entry.expires_unix,
        &entry.proposal,
    )
    .map_err(|_| MissReason::Unauthenticated)?;
    // verify_slice compares in constant time.
    if mac.verify_slice(&claimed).is_err() {
        return Err(MissReason::Unauthenticated);
    }
    if entry.expires_unix <= entry.created_unix
        || entry.expires_unix - entry.created_unix > MAX_TTL_SECONDS
        || now_unix >= entry.expires_unix
        || now_unix < entry.created_unix
    {
        return Err(MissReason::Expired);
    }
    Ok(entry.proposal)
}

pub struct AdvisoryCache {
    root: files::Root,
}
impl AdvisoryCache {
    /// Creates the private directory. The parent must exist and be traversable
    /// without symlinks.
    pub fn create(path: &Path) -> Result<Self> {
        Ok(Self {
            root: files::Root::create(path)?,
        })
    }
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            root: files::Root::open(path)?,
        })
    }

    /// Stores a proposal. A live existing entry is kept and reported as `Exists`.
    pub fn store(
        &self,
        mac_key: &MacKey,
        cache_key: &str,
        proposal: &BackendProposal,
        now_unix: u64,
        ttl_seconds: u64,
    ) -> Result<()> {
        if !valid_key(cache_key) || ttl_seconds == 0 || ttl_seconds > MAX_TTL_SECONDS {
            return Err(CacheError::Invalid);
        }
        let expires = now_unix
            .checked_add(ttl_seconds)
            .ok_or(CacheError::Invalid)?;
        let mac = mac_for(&mac_key.0, cache_key, now_unix, expires, proposal)?;
        let entry = Entry {
            schema_version: SCHEMA_VERSION,
            key: cache_key.into(),
            created_unix: now_unix,
            expires_unix: expires,
            proposal: proposal.clone(),
            mac: hex::encode(mac.finalize().into_bytes()),
        };
        let bytes = serde_json::to_vec(&entry).map_err(|_| CacheError::Invalid)?;
        // A live, authenticated entry is kept (`Exists`). An expired, malformed,
        // unauthenticated or unreadable one must not block the key forever.
        // When the directory is full, only entries that are authenticated and
        // expired, or unauthenticated, are swept. The cache stays advisory:
        // sweeping never deletes a live entry.
        self.root.publish(
            &format!("{cache_key}.json"),
            &bytes,
            &|existing| decode(mac_key, cache_key, existing, now_unix).is_err(),
            &|key, existing| {
                matches!(
                    decode(mac_key, key, existing, now_unix),
                    Err(MissReason::Expired | MissReason::Unauthenticated)
                )
            },
        )
    }

    /// Every failure mode is a miss. A hit is still only a proposal.
    pub fn lookup(&self, mac_key: &MacKey, cache_key: &str, now_unix: u64) -> Lookup {
        if !valid_key(cache_key) {
            return Lookup::Miss(MissReason::Malformed);
        }
        match self.root.read(&format!("{cache_key}.json")) {
            Ok(Some(bytes)) => match decode(mac_key, cache_key, &bytes, now_unix) {
                Ok(proposal) => Lookup::Hit(proposal),
                Err(reason) => Lookup::Miss(reason),
            },
            Ok(None) => Lookup::Miss(MissReason::Absent),
            Err(_) => Lookup::Miss(MissReason::Unavailable),
        }
    }

    /// Looks up the entry for `context` and revalidates it against that fresh
    /// context. `None` means route without advice; the full candidate set was
    /// already evaluated by `BoundedDecisionContext::from_phase`.
    pub fn advise<'a>(
        &self,
        mac_key: &MacKey,
        binding: &CacheBinding,
        context: &'a BoundedDecisionContext,
        now_unix: u64,
        minimum_confidence: u32,
    ) -> std::result::Result<Option<&'a PhaseSelection>, MissReason> {
        let key = cache_key(binding, context).map_err(|_| MissReason::Malformed)?;
        match self.lookup(mac_key, &key, now_unix) {
            Lookup::Miss(reason) => Err(reason),
            Lookup::Hit(proposal) => context
                .selection_for(&proposal, minimum_confidence)
                .map_err(|_| MissReason::Rejected),
        }
    }
}

#[cfg(test)]
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 test cases 1 and 2.
    #[test]
    fn hmac_sha256_matches_rfc_4231() {
        assert_eq!(
            hex::encode(hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
