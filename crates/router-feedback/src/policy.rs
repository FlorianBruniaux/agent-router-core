use std::collections::BTreeSet;

use ed25519_dalek::{Signature, VerifyingKey};
use router_eval::{PairedTrace, PromotionCriteria, ShadowReport};
use router_types::PhasePolicy;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

use crate::store::{ensure_clock, read_consent, scrub, snapshot_in, timestamp};
use crate::{FeedbackError, FeedbackStore, LearningRules, Result, hash, valid_hash};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyState {
    Proposed,
    ReplayAccepted,
    ShadowAccepted,
    CanaryAccepted,
    Active,
    Retired,
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyArtifact {
    pub schema_version: u32,
    pub artifact_id: String,
    pub policy_hash: String,
    pub policy: PhasePolicy,
    pub baseline_artifact_id: Option<String>,
    pub statistics_hash: Option<String>,
    pub rules: Option<LearningRules>,
    pub created_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRecord {
    pub artifact: PolicyArtifact,
    pub state: PolicyState,
    pub events: Vec<PolicyEvent>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialStage {
    Shadow,
    Canary,
}

/// External trial evidence is attested, not manufactured by this local store.
/// The signed activation binds this exact evidence. No production job is run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrialEvidence {
    pub stage: TrialStage,
    pub evidence_sha256: String,
    pub reviewer_sha256: String,
    pub independent: bool,
    pub cases: u32,
    pub hard_constraint_violations: u32,
    pub subgroup_regressions: u32,
    pub accepted: bool,
    pub started_at_unix_seconds: u64,
    pub completed_at_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Activate,
    Rollback,
    Quarantine,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyApproval {
    pub schema_version: u32,
    pub action: PolicyAction,
    pub artifact_id: String,
    pub expected_active_artifact_id: String,
    pub gate_hash: String,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub nonce_sha256: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvent {
    pub sequence: u64,
    pub artifact_id: String,
    pub state: PolicyState,
    pub recorded_at_unix_seconds: u64,
    pub evidence_hash: String,
    pub trial: Option<TrialEvidence>,
    pub approval: Option<SignedPolicyApproval>,
    pub previous_hash: String,
    pub event_hash: String,
}

/// Canonical bytes to sign with an Ed25519 key. The signature field is omitted.
pub fn approval_message(approval: &SignedPolicyApproval) -> Result<Vec<u8>> {
    let mut value = approval.clone();
    value.signature_hex.clear();
    let mut bytes = b"agent-router:policy-approval:v1\0".to_vec();
    bytes.extend(serde_json::to_vec(&value)?);
    Ok(bytes)
}

pub fn parse_signed_approval(bytes: &[u8]) -> Result<SignedPolicyApproval> {
    if bytes.len() > crate::MAX_INPUT_BYTES {
        return Err(FeedbackError::Limit);
    }
    let value = router_adapter_api::strict_json(bytes)
        .map_err(|_| FeedbackError::Invalid("approval JSON"))?;
    Ok(serde_json::from_value(value)?)
}

pub fn policy_hash(policy: &PhasePolicy) -> Result<String> {
    hash("phase-policy-v2", policy)
}

impl FeedbackStore {
    /// One explicit deterministic baseline, never inferred from feedback.
    pub fn register_baseline(&self, policy: PhasePolicy, now: u64) -> Result<PolicyArtifact> {
        validate_policy(&policy)?;
        timestamp(now)?;
        let artifact = seal_artifact(PolicyArtifact {
            schema_version: 1,
            artifact_id: String::new(),
            policy_hash: policy_hash(&policy)?,
            policy,
            baseline_artifact_id: None,
            statistics_hash: None,
            rules: None,
            created_at_unix_seconds: now,
        })?;
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        ensure_clock(&tx, now)?;
        if let Some(id) = setting(&tx, "baseline")? {
            let existing = load_artifact(&tx, &id)?.0;
            if existing.policy == artifact.policy {
                return Ok(existing);
            }
            return Err(FeedbackError::Gate("baseline already registered"));
        }
        insert_artifact(&tx, &artifact, PolicyState::Active)?;
        tx.execute(
            "INSERT INTO settings VALUES('baseline',?1)",
            [&artifact.artifact_id],
        )?;
        tx.execute(
            "INSERT INTO settings VALUES('active',?1)",
            [&artifact.artifact_id],
        )?;
        append_event(
            &tx,
            &artifact.artifact_id,
            PolicyState::Active,
            now,
            &artifact.policy_hash,
            None,
            None,
        )?;
        tx.commit()?;
        Ok(artifact)
    }

    /// Suggests bounded score weights only. Safety thresholds cannot decrease,
    /// no permissions/constraints exist in the patchable policy surface.
    pub fn propose_policy(
        &self,
        policy: PhasePolicy,
        rules: LearningRules,
        now: u64,
    ) -> Result<PolicyArtifact> {
        rules.validate()?;
        validate_policy(&policy)?;
        timestamp(now)?;
        let mut db = self.lock()?;
        // Expiry is committed and scrubbed first, so a refused gate below still
        // enforces retention. The store lock is held from here to the write
        // commit: the samples the gate counts are the ones `statistics_hash`
        // commits to, and no other writer can change them in between.
        let (events, removed) = {
            let tx = db.transaction()?;
            let (events, _, removed) = snapshot_in(&tx, now, true)?;
            tx.commit()?;
            (events, removed)
        };
        if removed > 0 {
            scrub(&db)?;
        }
        let stats = crate::learning::statistics(&events)?;
        if stats.objective.verified_samples() < u64::from(rules.minimum_verified_samples) {
            return Err(FeedbackError::Gate("insufficient verified samples"));
        }
        let tx = db.transaction()?;
        ensure_clock(&tx, now)?;
        if !read_consent(&tx)?.preferences.learning_enabled {
            return Err(FeedbackError::LearningDisabled);
        }
        let id = setting(&tx, "active")?.ok_or(FeedbackError::Gate("baseline required"))?;
        let baseline = load_artifact(&tx, &id)?.0;
        validate_delta(&baseline.policy, &policy, &rules)?;
        let candidate_hash = policy_hash(&policy)?;
        for existing in all_ids(&tx)? {
            let existing = load_artifact(&tx, &existing)?.0;
            if existing.policy.version == policy.version && existing.policy_hash != candidate_hash {
                return Err(FeedbackError::Integrity(
                    "policy version reused with different content",
                ));
            }
        }
        let artifact = seal_artifact(PolicyArtifact {
            schema_version: 1,
            artifact_id: String::new(),
            policy_hash: policy_hash(&policy)?,
            policy,
            baseline_artifact_id: Some(id),
            statistics_hash: Some(stats.content_hash),
            rules: Some(rules),
            created_at_unix_seconds: now,
        })?;
        let count: usize = tx.query_row("SELECT COUNT(*) FROM policies", [], |r| r.get(0))?;
        if count >= 128 {
            return Err(FeedbackError::Limit);
        }
        if let Ok((existing, _)) = load_artifact(&tx, &artifact.artifact_id) {
            return Ok(existing);
        }
        insert_artifact(&tx, &artifact, PolicyState::Proposed)?;
        append_event(
            &tx,
            &artifact.artifact_id,
            PolicyState::Proposed,
            now,
            artifact
                .statistics_hash
                .as_deref()
                .ok_or(FeedbackError::Integrity("statistics"))?,
            None,
            None,
        )?;
        tx.commit()?;
        Ok(artifact)
    }

    /// Recomputes router-eval gates from non-deserializable, audited traces.
    /// A JSON report claiming success cannot authorize promotion.
    pub fn evaluate_proposal(
        &self,
        id: &str,
        pairs: &[PairedTrace],
        criteria: &PromotionCriteria,
        now: u64,
    ) -> Result<ShadowReport> {
        self.require_learning()?;
        timestamp(now)?;
        let report = router_eval::compare_shadow(pairs, Some(criteria))?;
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        ensure_clock(&tx, now)?;
        if !read_consent(&tx)?.preferences.learning_enabled {
            return Err(FeedbackError::LearningDisabled);
        }
        let (artifact, state) = load_artifact(&tx, id)?;
        if state != PolicyState::Proposed {
            return Err(FeedbackError::Gate("proposal stage"));
        }
        let baseline = load_artifact(
            &tx,
            artifact
                .baseline_artifact_id
                .as_deref()
                .ok_or(FeedbackError::Gate("baseline"))?,
        )?
        .0;
        if pairs.iter().any(|p| {
            p.baseline.receipt().policy_hash != baseline.policy_hash
                || p.semantic.receipt().policy_hash != artifact.policy_hash
        }) {
            return Err(FeedbackError::Gate("evaluation policy identity"));
        }
        if now < artifact.created_at_unix_seconds {
            return Err(FeedbackError::Invalid("evaluation time"));
        }
        if report.semantic_enabled {
            set_state(&tx, id, PolicyState::ReplayAccepted)?;
            append_event(
                &tx,
                id,
                PolicyState::ReplayAccepted,
                now,
                &hash("feedback-evaluation-v1", &report)?,
                None,
                None,
            )?;
        }
        tx.commit()?;
        Ok(report)
    }

    pub fn record_trial(
        &self,
        id: &str,
        evidence: TrialEvidence,
        now: u64,
    ) -> Result<PolicyRecord> {
        self.require_learning()?;
        timestamp(now)?;
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        ensure_clock(&tx, now)?;
        if !read_consent(&tx)?.preferences.learning_enabled {
            return Err(FeedbackError::LearningDisabled);
        }
        let (artifact, state) = load_artifact(&tx, id)?;
        let rules = artifact
            .rules
            .as_ref()
            .ok_or(FeedbackError::Gate("candidate required"))?;
        let previous = last_event_time(&tx, id)?;
        if !valid_hash(&evidence.evidence_sha256)
            || !valid_hash(&evidence.reviewer_sha256)
            || !evidence.independent
            || !evidence.accepted
            || evidence.cases == 0
            || evidence.cases > 10_000
            || evidence.hard_constraint_violations != 0
            || evidence.subgroup_regressions != 0
            || evidence.started_at_unix_seconds < previous
            || evidence.completed_at_unix_seconds < evidence.started_at_unix_seconds
            || now < evidence.completed_at_unix_seconds
        {
            return Err(FeedbackError::Gate("trial evidence"));
        }
        let next = match (state, evidence.stage) {
            (PolicyState::ReplayAccepted, TrialStage::Shadow)
                if evidence.cases >= rules.minimum_verified_samples =>
            {
                PolicyState::ShadowAccepted
            }
            (PolicyState::ShadowAccepted, TrialStage::Canary)
                if evidence.cases <= rules.maximum_canary_cases =>
            {
                PolicyState::CanaryAccepted
            }
            _ => return Err(FeedbackError::Gate("trial stage or bound")),
        };
        set_state(&tx, id, next)?;
        append_event(
            &tx,
            id,
            next,
            now,
            &hash("feedback-trial-v1", &evidence)?,
            Some(evidence),
            None,
        )?;
        tx.commit()?;
        drop(db);
        self.policy(id)
    }

    pub fn policy(&self, id: &str) -> Result<PolicyRecord> {
        let db = self.lock()?;
        let (artifact, state) = load_artifact(&db, id)?;
        Ok(PolicyRecord {
            artifact,
            state,
            events: policy_events(&db)?
                .into_iter()
                .filter(|e| e.artifact_id == id)
                .collect(),
        })
    }
    pub fn policies(&self) -> Result<Vec<PolicyArtifact>> {
        let db = self.lock()?;
        let ids = all_ids(&db)?;
        ids.iter().map(|id| Ok(load_artifact(&db, id)?.0)).collect()
    }
    pub fn active_policy(&self) -> Result<Option<PolicyArtifact>> {
        let db = self.lock()?;
        setting(&db, "active")?
            .map(|id| Ok(load_artifact(&db, &id)?.0))
            .transpose()
    }
    /// Binds the complete current evidence history, candidate and active policy.
    pub fn promotion_digest(&self, id: &str) -> Result<String> {
        let db = self.lock()?;
        gate_hash(&db, id)
    }

    /// Caller supplies a separately trusted public-key allowlist. Keys from an
    /// approval file alone never establish trust. No runtime job is executed.
    pub fn apply_signed_action(
        &self,
        approval: &SignedPolicyApproval,
        trusted_keys: &BTreeSet<String>,
        now: u64,
    ) -> Result<PolicyRecord> {
        timestamp(now)?;
        verify_signature(approval, trusted_keys, now)?;
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        ensure_clock(&tx, now)?;
        let active = setting(&tx, "active")?.ok_or(FeedbackError::Gate("baseline required"))?;
        if active != approval.expected_active_artifact_id
            || gate_hash(&tx, &approval.artifact_id)? != approval.gate_hash
        {
            return Err(FeedbackError::Gate("stale approval"));
        }
        if policy_events(&tx)?
            .iter()
            .filter_map(|e| e.approval.as_ref())
            .any(|a| a.nonce_sha256 == approval.nonce_sha256)
        {
            return Err(FeedbackError::Gate("approval already used"));
        }
        let (artifact, state) = load_artifact(&tx, &approval.artifact_id)?;
        let evidence_hash = hash("feedback-signed-approval-v1", approval)?;
        match approval.action {
            PolicyAction::Activate => {
                if !read_consent(&tx)?.preferences.learning_enabled {
                    return Err(FeedbackError::LearningDisabled);
                }
                if state != PolicyState::CanaryAccepted
                    || artifact.baseline_artifact_id.as_deref() != Some(active.as_str())
                {
                    return Err(FeedbackError::Gate(
                        "activation requires current baseline and complete gates",
                    ));
                }
                set_state(&tx, &active, PolicyState::Retired)?;
                append_event(
                    &tx,
                    &active,
                    PolicyState::Retired,
                    now,
                    &evidence_hash,
                    None,
                    Some(approval.clone()),
                )?;
                set_state(&tx, &artifact.artifact_id, PolicyState::Active)?;
                set_active(&tx, &artifact.artifact_id)?;
                append_event(
                    &tx,
                    &artifact.artifact_id,
                    PolicyState::Active,
                    now,
                    &evidence_hash,
                    None,
                    Some(approval.clone()),
                )?;
            }
            PolicyAction::Rollback => {
                // Roll back exactly one accepted predecessor; never revive a quarantined policy.
                let current = load_artifact(&tx, &active)?.0;
                if state != PolicyState::Retired
                    || current.baseline_artifact_id.as_deref()
                        != Some(artifact.artifact_id.as_str())
                {
                    return Err(FeedbackError::Gate("last accepted predecessor required"));
                }
                set_state(&tx, &active, PolicyState::Retired)?;
                append_event(
                    &tx,
                    &active,
                    PolicyState::Retired,
                    now,
                    &evidence_hash,
                    None,
                    Some(approval.clone()),
                )?;
                set_state(&tx, &artifact.artifact_id, PolicyState::Active)?;
                set_active(&tx, &artifact.artifact_id)?;
                append_event(
                    &tx,
                    &artifact.artifact_id,
                    PolicyState::Active,
                    now,
                    &evidence_hash,
                    None,
                    Some(approval.clone()),
                )?;
            }
            PolicyAction::Quarantine => {
                if artifact.baseline_artifact_id.is_none() {
                    return Err(FeedbackError::Gate("cannot quarantine sole baseline"));
                }
                if active == artifact.artifact_id {
                    let previous = artifact
                        .baseline_artifact_id
                        .as_deref()
                        .ok_or(FeedbackError::Gate("predecessor"))?;
                    if load_artifact(&tx, previous)?.1 != PolicyState::Retired {
                        return Err(FeedbackError::Gate("accepted predecessor required"));
                    }
                    set_state(&tx, previous, PolicyState::Active)?;
                    set_active(&tx, previous)?;
                    append_event(
                        &tx,
                        previous,
                        PolicyState::Active,
                        now,
                        &evidence_hash,
                        None,
                        Some(approval.clone()),
                    )?;
                }
                set_state(&tx, &artifact.artifact_id, PolicyState::Quarantined)?;
                append_event(
                    &tx,
                    &artifact.artifact_id,
                    PolicyState::Quarantined,
                    now,
                    &evidence_hash,
                    None,
                    Some(approval.clone()),
                )?;
            }
        }
        tx.commit()?;
        drop(db);
        self.policy(&artifact.artifact_id)
    }
}

fn validate_policy(policy: &PhasePolicy) -> Result<()> {
    router_policy::PhaseRouter::new(policy.clone())
        .map_err(|_| FeedbackError::Invalid("phase policy"))?;
    if !crate::identifier(&policy.version) {
        return Err(FeedbackError::Invalid("policy version"));
    }
    Ok(())
}
fn validate_delta(
    base: &PhasePolicy,
    candidate: &PhasePolicy,
    rules: &LearningRules,
) -> Result<()> {
    if base.version == candidate.version
        || base.schema_version != candidate.schema_version
        || base.max_alternatives != candidate.max_alternatives
        || candidate.minimum_utility_micros < base.minimum_utility_micros
        || candidate.ambiguity_margin_micros < base.ambiguity_margin_micros
        || [
            (base.quality_weight, candidate.quality_weight),
            (base.relevance_weight, candidate.relevance_weight),
            (base.cost_weight, candidate.cost_weight),
            (base.latency_weight, candidate.latency_weight),
        ]
        .into_iter()
        .any(|(a, b)| a.abs_diff(b) > rules.maximum_weight_delta)
    {
        return Err(FeedbackError::Gate(
            "unbounded or weakening policy proposal",
        ));
    }
    Ok(())
}
fn seal_artifact(mut artifact: PolicyArtifact) -> Result<PolicyArtifact> {
    artifact.artifact_id.clear();
    artifact.artifact_id = hash("feedback-policy-artifact-v1", &artifact)?;
    Ok(artifact)
}
fn load_artifact(db: &Connection, id: &str) -> Result<(PolicyArtifact, PolicyState)> {
    if !valid_hash(id) {
        return Err(FeedbackError::Invalid("artifact identity"));
    }
    let value: Option<(String, String)> = db
        .query_row(
            "SELECT artifact,state FROM policies WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (text, state) = value.ok_or(FeedbackError::NotFound)?;
    if text.len() > 32 * 1024 {
        return Err(FeedbackError::Limit);
    }
    let artifact: PolicyArtifact = serde_json::from_str(&text)?;
    let state: PolicyState = serde_json::from_str(&state)?;
    validate_policy(&artifact.policy)?;
    if artifact.schema_version != 1
        || artifact.artifact_id != id
        || artifact.policy_hash != policy_hash(&artifact.policy)?
        || seal_artifact(artifact.clone())?.artifact_id != id
    {
        return Err(FeedbackError::Integrity("policy artifact"));
    }
    Ok((artifact, state))
}
fn insert_artifact(
    tx: &Transaction<'_>,
    artifact: &PolicyArtifact,
    state: PolicyState,
) -> Result<()> {
    tx.execute(
        "INSERT INTO policies VALUES(?1,?2,?3)",
        params![
            artifact.artifact_id,
            serde_json::to_string(artifact)?,
            serde_json::to_string(&state)?
        ],
    )?;
    Ok(())
}
fn set_state(tx: &Transaction<'_>, id: &str, state: PolicyState) -> Result<()> {
    tx.execute(
        "UPDATE policies SET state=?2 WHERE id=?1",
        params![id, serde_json::to_string(&state)?],
    )?;
    Ok(())
}
fn set_active(tx: &Transaction<'_>, id: &str) -> Result<()> {
    tx.execute("INSERT OR REPLACE INTO settings VALUES('active',?1)", [id])?;
    Ok(())
}
fn setting(db: &Connection, key: &str) -> Result<Option<String>> {
    Ok(db
        .query_row("SELECT value FROM settings WHERE key=?1", [key], |r| {
            r.get(0)
        })
        .optional()?)
}
fn gate_hash(db: &Connection, id: &str) -> Result<String> {
    let (artifact, state) = load_artifact(db, id)?;
    let events: Vec<_> = policy_events(db)?
        .into_iter()
        .filter(|e| e.artifact_id == id)
        .collect();
    hash(
        "feedback-promotion-gate-v1",
        &(artifact, state, events, setting(db, "active")?),
    )
}
fn append_event(
    tx: &Transaction<'_>,
    id: &str,
    state: PolicyState,
    now: u64,
    evidence_hash: &str,
    trial: Option<TrialEvidence>,
    approval: Option<SignedPolicyApproval>,
) -> Result<()> {
    let previous = policy_events(tx)?.pop();
    let sequence = previous.as_ref().map_or(1, |e| e.sequence + 1);
    if sequence > 10_000 {
        return Err(FeedbackError::Limit);
    }
    if previous
        .as_ref()
        .is_some_and(|e| now < e.recorded_at_unix_seconds)
    {
        return Err(FeedbackError::Invalid("policy clock moved backwards"));
    }
    let mut event = PolicyEvent {
        sequence,
        artifact_id: id.into(),
        state,
        recorded_at_unix_seconds: now,
        evidence_hash: evidence_hash.into(),
        trial,
        approval,
        previous_hash: previous.map_or_else(String::new, |e| e.event_hash),
        event_hash: String::new(),
    };
    event.event_hash = policy_event_hash(&event)?;
    tx.execute(
        "INSERT INTO policy_events(sequence,artifact_id,event) VALUES(?1,?2,?3)",
        params![sequence, id, serde_json::to_string(&event)?],
    )?;
    Ok(())
}
fn policy_event_hash(event: &PolicyEvent) -> Result<String> {
    let mut e = event.clone();
    e.event_hash.clear();
    hash("feedback-policy-event-v1", &e)
}
fn policy_events(db: &Connection) -> Result<Vec<PolicyEvent>> {
    let count: usize = db.query_row("SELECT COUNT(*) FROM policy_events", [], |r| r.get(0))?;
    if count > 10_000 {
        return Err(FeedbackError::Limit);
    }
    let mut q =
        db.prepare("SELECT sequence,artifact_id,event FROM policy_events ORDER BY sequence")?;
    let rows = q
        .query_map([], |r| {
            Ok((
                r.get::<_, u64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut events = Vec::new();
    let mut previous = String::new();
    for (sequence, id, text) in rows {
        if text.len() > 32 * 1024 {
            return Err(FeedbackError::Limit);
        }
        let e: PolicyEvent = serde_json::from_str(&text)?;
        if e.sequence != sequence
            || e.artifact_id != id
            || e.previous_hash != previous
            || e.sequence != events.len() as u64 + 1
            || e.event_hash != policy_event_hash(&e)?
            || !valid_hash(&e.evidence_hash)
        {
            return Err(FeedbackError::Integrity("policy event"));
        }
        previous = e.event_hash.clone();
        events.push(e);
    }
    Ok(events)
}
fn last_event_time(db: &Connection, id: &str) -> Result<u64> {
    policy_events(db)?
        .into_iter()
        .rev()
        .find(|e| e.artifact_id == id)
        .map(|e| e.recorded_at_unix_seconds)
        .ok_or(FeedbackError::Integrity("missing policy history"))
}
fn all_ids(db: &Connection) -> Result<Vec<String>> {
    let mut query = db.prepare("SELECT id FROM policies ORDER BY id")?;
    let ids = query
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if ids.len() > 128 {
        return Err(FeedbackError::Limit);
    }
    Ok(ids)
}
pub(crate) fn verify_policies(db: &Connection) -> Result<()> {
    let events = policy_events(db)?;
    for id in all_ids(db)? {
        let (artifact, state) = load_artifact(db, &id)?;
        if let Some(base) = artifact.baseline_artifact_id.as_deref() {
            let baseline = load_artifact(db, base)?.0;
            let rules = artifact
                .rules
                .as_ref()
                .ok_or(FeedbackError::Integrity("missing rules"))?;
            rules.validate()?;
            validate_delta(&baseline.policy, &artifact.policy, rules)?;
            if !artifact
                .statistics_hash
                .as_ref()
                .is_some_and(|s| valid_hash(s))
            {
                return Err(FeedbackError::Integrity("statistics binding"));
            }
        }
        if let Some(last) = events.iter().rev().find(|e| e.artifact_id == id) {
            if last.state != state {
                return Err(FeedbackError::Integrity("policy state"));
            }
        } else if artifact.baseline_artifact_id.is_some() {
            return Err(FeedbackError::Integrity("missing policy events"));
        }
    }
    if let Some(id) = setting(db, "active")? {
        if load_artifact(db, &id)?.1 != PolicyState::Active {
            return Err(FeedbackError::Integrity("active policy"));
        }
    }
    Ok(())
}
fn verify_signature(a: &SignedPolicyApproval, keys: &BTreeSet<String>, now: u64) -> Result<()> {
    if a.schema_version != 1
        || keys.is_empty()
        || keys.len() > 32
        || a.signature_hex.len() != 128
        || !valid_hash(&a.public_key_hex)
        || keys.iter().any(|key| !valid_hash(key))
        || !keys.contains(&a.public_key_hex)
        || !valid_hash(&a.artifact_id)
        || !valid_hash(&a.expected_active_artifact_id)
        || !valid_hash(&a.gate_hash)
        || !valid_hash(&a.nonce_sha256)
        || a.issued_at_unix_seconds > now
        || a.expires_at_unix_seconds < now
        || a.expires_at_unix_seconds
            .saturating_sub(a.issued_at_unix_seconds)
            > 86400
    {
        return Err(FeedbackError::Signature);
    }
    let public: [u8; 32] = hex::decode(&a.public_key_hex)
        .map_err(|_| FeedbackError::Signature)?
        .try_into()
        .map_err(|_| FeedbackError::Signature)?;
    let signature = Signature::from_slice(
        &hex::decode(&a.signature_hex).map_err(|_| FeedbackError::Signature)?,
    )
    .map_err(|_| FeedbackError::Signature)?;
    let key = VerifyingKey::from_bytes(&public).map_err(|_| FeedbackError::Signature)?;
    key.verify_strict(&approval_message(a)?, &signature)
        .map_err(|_| FeedbackError::Signature)
}
