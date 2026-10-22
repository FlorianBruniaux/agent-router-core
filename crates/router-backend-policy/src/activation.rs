use crate::{crypto::fresh, *};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationEvent {
    pub sequence: u64,
    pub recorded_at_unix_seconds: u64,
    pub previous_state_hash: String,
    pub approval: Signed<ActivationApproval>,
    pub resulting_state_hash: String,
}

/// Application-owned state. Persistence/CAS and trusted head retention belong
/// to the caller; restoring arbitrary serialized fields cannot activate a backend.
pub struct BackendActivationState {
    baseline_policy_hash: String,
    scope_sha256: String,
    pub(crate) active: Option<ValidatedBackendPromotion>,
    state_hash: String,
    events: Vec<ActivationEvent>,
    used_nonces: BTreeSet<String>,
    versions: BTreeMap<(String, String), String>,
    last_seen: u64,
    authority_hash: Option<String>,
}
impl BackendActivationState {
    /// The scope digest is externally chosen/pinned, not accepted from approval
    /// documents. It prevents approvals crossing installation/authority scopes.
    pub fn new(baseline_policy_hash: &str, scope_sha256: &str) -> Result<Self> {
        if !valid_hash(baseline_policy_hash) || !valid_hash(scope_sha256) {
            return Err(PromotionError::Invalid);
        }
        let state_hash = digest(
            "agent-router:backend-state-genesis:v1\0",
            &(baseline_policy_hash, scope_sha256),
        )?;
        Ok(Self {
            baseline_policy_hash: baseline_policy_hash.into(),
            scope_sha256: scope_sha256.into(),
            active: None,
            state_hash,
            events: vec![],
            used_nonces: BTreeSet::new(),
            versions: BTreeMap::new(),
            last_seen: 0,
            authority_hash: None,
        })
    }
    pub fn state_hash(&self) -> &str {
        &self.state_hash
    }
    pub fn baseline_policy_hash(&self) -> &str {
        &self.baseline_policy_hash
    }
    pub fn events(&self) -> &[ActivationEvent] {
        &self.events
    }
    pub fn active_promotion(&self) -> Option<&ValidatedBackendPromotion> {
        self.active.as_ref()
    }
    pub(crate) fn validate_authorities(&self, authorities: &TrustedAuthorities) -> Result<()> {
        let current = authorities.fingerprint()?;
        if self
            .authority_hash
            .as_ref()
            .is_some_and(|expected| expected != &current)
        {
            return Err(PromotionError::Authority);
        }
        Ok(())
    }

    pub fn apply(
        &mut self,
        approval: &Signed<ActivationApproval>,
        promotion: Option<&ValidatedBackendPromotion>,
        authorities: &TrustedAuthorities,
        now: u64,
    ) -> Result<()> {
        if self.events.len() >= MAX_ACTIVATION_EVENTS {
            return Err(PromotionError::Limit);
        }
        if now < self.last_seen {
            return Err(PromotionError::Freshness);
        }
        self.validate_authorities(authorities)?;
        authorities.verify(AuthorityRole::Approver, approval)?;
        let action = &approval.statement;
        if action.schema_version != 1
            || action.expected_state_hash != self.state_hash
            || !valid_hash(&action.target_hash)
            || !valid_hash(&action.nonce_sha256)
            || self.used_nonces.contains(&action.nonce_sha256)
        {
            return Err(PromotionError::State);
        }
        fresh(
            action.issued_at_unix_seconds,
            action.expires_at_unix_seconds,
            86_400,
            now,
        )?;
        let next = match action.action {
            ActivationAction::Activate => {
                let accepted = promotion.ok_or(PromotionError::Gate)?;
                if self.active.is_some()
                    || action.target_hash != accepted.promotion_hash
                    || accepted.ready_at > now
                    || accepted.expires_at_unix_seconds() <= now
                    || accepted.artifact().routing_policy_hash != self.baseline_policy_hash
                {
                    return Err(PromotionError::Gate);
                }
                if accepted.authority_hash() != authorities.fingerprint()? {
                    return Err(PromotionError::Authority);
                }
                let version = (
                    accepted.artifact().backend_id.clone(),
                    accepted.artifact().version.clone(),
                );
                let artifact_hash = accepted.artifact().content_hash()?;
                if self
                    .versions
                    .get(&version)
                    .is_some_and(|previous| previous != &artifact_hash)
                {
                    return Err(PromotionError::Integrity);
                }
                Some(accepted.clone())
            }
            ActivationAction::Rollback => {
                if self.active.is_none()
                    || promotion.is_some()
                    || action.target_hash != self.baseline_policy_hash
                {
                    return Err(PromotionError::State);
                }
                None
            }
        };
        let authority_hash = authorities.fingerprint()?;
        let next_hash = digest(
            "agent-router:backend-state-transition:v1\0",
            &(
                &self.state_hash,
                &self.scope_sha256,
                self.events.len() + 1,
                now,
                approval,
                next.as_ref().map(|accepted| &accepted.promotion_hash),
                &authority_hash,
            ),
        )?;
        let event = ActivationEvent {
            sequence: self.events.len() as u64 + 1,
            recorded_at_unix_seconds: now,
            previous_state_hash: self.state_hash.clone(),
            approval: approval.clone(),
            resulting_state_hash: next_hash.clone(),
        };
        if let Some(accepted) = &next {
            self.versions.insert(
                (
                    accepted.artifact().backend_id.clone(),
                    accepted.artifact().version.clone(),
                ),
                accepted.artifact().content_hash()?,
            );
        }
        self.used_nonces.insert(action.nonce_sha256.clone());
        self.active = next;
        self.state_hash = next_hash;
        self.last_seen = now;
        self.authority_hash = Some(authority_hash);
        self.events.push(event);
        Ok(())
    }

    /// Reverify every signed transition and every opaque supplied promotion.
    /// Expected head must come from separately trusted storage/CAS; a hash in
    /// the untrusted history cannot prevent history truncation/replacement.
    pub fn restore(
        baseline_policy_hash: &str,
        scope_sha256: &str,
        events: &[ActivationEvent],
        promotions: &BTreeMap<String, ValidatedBackendPromotion>,
        authorities: &TrustedAuthorities,
        expected_head: &str,
        now: u64,
    ) -> Result<Self> {
        if events.len() > MAX_ACTIVATION_EVENTS || !valid_hash(expected_head) {
            return Err(PromotionError::Limit);
        }
        let mut state = Self::new(baseline_policy_hash, scope_sha256)?;
        for event in events {
            if event.recorded_at_unix_seconds > now {
                return Err(PromotionError::Freshness);
            }
            let promotion = match event.approval.statement.action {
                ActivationAction::Activate => promotions.get(&event.approval.statement.target_hash),
                ActivationAction::Rollback => None,
            };
            state.apply(
                &event.approval,
                promotion,
                authorities,
                event.recorded_at_unix_seconds,
            )?;
            if state.events.last() != Some(event) {
                return Err(PromotionError::Integrity);
            }
        }
        if state.state_hash != expected_head {
            return Err(PromotionError::Integrity);
        }
        Ok(state)
    }
    pub(crate) fn fresh_at(&self, now: u64) -> Result<()> {
        if now < self.last_seen {
            Err(PromotionError::Freshness)
        } else {
            Ok(())
        }
    }
}
