use crate::{PromotionError, Result, Signed, label};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityRole {
    Backend,
    HumanReviewer,
    GateOwner,
    Approver,
}

/// Constructed by the trusted application, never deserialized from a proposal.
pub struct TrustedAuthorities {
    keys: BTreeMap<(AuthorityRole, String), VerifyingKey>,
}
impl TrustedAuthorities {
    /// Canonical fingerprint of role, identifier and actual public-key bytes.
    /// Keys still come exclusively from trusted application configuration.
    pub fn fingerprint(&self) -> Result<String> {
        let roots: Vec<_> = self
            .keys
            .iter()
            .map(|((role, id), key)| (role, id, hex::encode(key.as_bytes())))
            .collect();
        crate::digest("agent-router:backend-authorities:v1\0", &roots)
    }
    pub fn new(
        entries: impl IntoIterator<Item = (AuthorityRole, String, [u8; 32])>,
    ) -> Result<Self> {
        let mut keys = BTreeMap::new();
        let mut physical = BTreeSet::new();
        for (role, id, bytes) in entries {
            if keys.len() >= 128
                || !label(&id)
                || !physical.insert(bytes)
                || keys.contains_key(&(role, id.clone()))
            {
                return Err(PromotionError::Authority);
            }
            let key = VerifyingKey::from_bytes(&bytes).map_err(|_| PromotionError::Signature)?;
            if key.is_weak() {
                return Err(PromotionError::Signature);
            }
            keys.insert((role, id), key);
        }
        if keys.is_empty() {
            return Err(PromotionError::Authority);
        }
        Ok(Self { keys })
    }
    pub(crate) fn verify<T: Serialize>(
        &self,
        role: AuthorityRole,
        signed: &Signed<T>,
    ) -> Result<()> {
        if !label(&signed.key_id) {
            return Err(PromotionError::Authority);
        }
        let key = self
            .keys
            .get(&(role, signed.key_id.clone()))
            .ok_or(PromotionError::Authority)?;
        if signed.signature_hex.len() != 128
            || !signed
                .signature_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(PromotionError::Signature);
        }
        let bytes = hex::decode(&signed.signature_hex).map_err(|_| PromotionError::Signature)?;
        let signature = Signature::from_slice(&bytes).map_err(|_| PromotionError::Signature)?;
        key.verify_strict(
            &signing_message(role, &signed.key_id, &signed.statement)?,
            &signature,
        )
        .map_err(|_| PromotionError::Signature)
    }
}

/// Role-separated canonical signing preimage. Keys remain outside the document.
pub fn signing_message<T: Serialize>(
    role: AuthorityRole,
    key_id: &str,
    statement: &T,
) -> Result<Vec<u8>> {
    if !label(key_id) {
        return Err(PromotionError::Invalid);
    }
    let mut bytes = b"agent-router:backend-policy-signature:v1\0".to_vec();
    bytes.extend(
        serde_json::to_vec(&(role, key_id, statement)).map_err(|_| PromotionError::Invalid)?,
    );
    if bytes.len() > crate::MAX_DOCUMENT_BYTES {
        return Err(PromotionError::Limit);
    }
    Ok(bytes)
}

pub(crate) fn fresh(issued: u64, expires: u64, maximum_age: u64, now: u64) -> Result<()> {
    if issued > now || expires <= now || expires <= issued || expires - issued > maximum_age {
        return Err(PromotionError::Freshness);
    }
    Ok(())
}
