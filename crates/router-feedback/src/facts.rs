//! Late facts: verification and integration outcomes learned after the automated
//! verdict. Appended once per `(run key, kind)`; nothing is ever rewritten.
use router_types::{FeedbackFact, FeedbackFactEvent, FeedbackFactKind, VerificationOutcome};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::{
    FeedbackError, FeedbackStore, MAX_EVENTS, MAX_INPUT_BYTES, Result, hash,
    store::{ensure_clock, expire, read_consent, scrub, timestamp},
    valid_hash,
};

pub(crate) fn validate_fact(fact: &FeedbackFact) -> Result<()> {
    if fact.schema_version != 1 || !valid_hash(&fact.run_key_sha256) {
        return Err(FeedbackError::Invalid("fact binding"));
    }
    if let FeedbackFactKind::Verification {
        validation,
        objective,
        evidence_sha256,
    } = &fact.kind
    {
        // An inconclusive record may be replaced by the runtime, so it is not a fact.
        if !valid_hash(evidence_sha256)
            || (*validation == VerificationOutcome::Unknown
                && *objective == VerificationOutcome::Unknown)
            || *objective == VerificationOutcome::Passed
                && *validation != VerificationOutcome::Passed
        {
            return Err(FeedbackError::Invalid("verification fact"));
        }
    }
    Ok(())
}

pub(crate) fn fact_hash(event: &FeedbackFactEvent) -> Result<String> {
    hash(
        "feedback-fact-v1",
        &(
            event.sequence,
            event.consent_revision,
            event.recorded_at_unix_seconds,
            &event.fact,
        ),
    )
}

impl FeedbackStore {
    /// Same consent, clock and retention rules as `record`. A fact does not need
    /// a matching automated event: that event may have failed to record.
    pub fn record_fact(&self, fact: FeedbackFact, now: u64) -> Result<FeedbackFactEvent> {
        validate_fact(&fact)?;
        timestamp(now)?;
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let consent = read_consent(&tx)?;
        if !consent.preferences.collection_enabled {
            return Err(FeedbackError::Consent);
        }
        ensure_clock(&tx, now)?;
        if now < consent.updated_at_unix_seconds
            || fact.observed_at_unix_seconds > now
            || fact.observed_at_unix_seconds < consent.updated_at_unix_seconds
            || now - fact.observed_at_unix_seconds > consent.preferences.retention_seconds
        {
            return Err(FeedbackError::Invalid("observation time"));
        }
        let expired = expire(&tx, &consent, now)?;
        let kind = fact.kind.name();
        if let Some(text) = tx
            .query_row(
                "SELECT fact FROM facts WHERE run_key=?1 AND kind=?2",
                params![fact.run_key_sha256, kind],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            let existing: FeedbackFactEvent = serde_json::from_str(&text)?;
            if existing.fact != fact {
                return Err(FeedbackError::Integrity("immutable fact"));
            }
            if existing.fact_hash != fact_hash(&existing)? {
                return Err(FeedbackError::Integrity("fact"));
            }
            tx.commit()?;
            if expired > 0 {
                scrub(&db)?;
            }
            return Ok(existing);
        }
        let count: usize = tx.query_row("SELECT COUNT(*) FROM facts", [], |r| r.get(0))?;
        if count >= MAX_EVENTS {
            return Err(FeedbackError::Limit);
        }
        let sequence: u64 = tx.query_row(
            "SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='facts'),0)+1",
            [],
            |r| r.get(0),
        )?;
        let mut event = FeedbackFactEvent {
            sequence,
            consent_revision: consent.revision,
            recorded_at_unix_seconds: now,
            fact,
            fact_hash: String::new(),
        };
        event.fact_hash = fact_hash(&event)?;
        tx.execute(
            "INSERT INTO facts(sequence,run_key,kind,observed_at,fact) VALUES(?1,?2,?3,?4,?5)",
            params![
                sequence,
                event.fact.run_key_sha256,
                kind,
                event.fact.observed_at_unix_seconds,
                serde_json::to_string(&event)?
            ],
        )?;
        tx.commit()?;
        if expired > 0 {
            scrub(&db)?;
        }
        Ok(event)
    }

    pub fn facts(&self, now: u64) -> Result<Vec<FeedbackFactEvent>> {
        timestamp(now)?;
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let consent = read_consent(&tx)?;
        ensure_clock(&tx, now)?;
        if now < consent.updated_at_unix_seconds {
            return Err(FeedbackError::Invalid("clock moved backwards"));
        }
        let removed = expire(&tx, &consent, now)?;
        let facts = read_facts(&tx)?;
        tx.commit()?;
        if removed > 0 {
            scrub(&db)?;
        }
        Ok(facts)
    }
}

/// Re-validates every row, like `read_events`.
pub(crate) fn read_facts(db: &Connection) -> Result<Vec<FeedbackFactEvent>> {
    let count: usize = db.query_row("SELECT COUNT(*) FROM facts", [], |r| r.get(0))?;
    if count > MAX_EVENTS {
        return Err(FeedbackError::Limit);
    }
    let mut query =
        db.prepare("SELECT sequence,run_key,kind,observed_at,fact FROM facts ORDER BY sequence")?;
    let rows = query
        .query_map([], |r| {
            Ok((
                r.get::<_, u64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, u64>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(sequence, run_key, kind, observed, text)| {
            if text.len() > MAX_INPUT_BYTES + 1024 {
                return Err(FeedbackError::Limit);
            }
            let e: FeedbackFactEvent = serde_json::from_str(&text)?;
            validate_fact(&e.fact)?;
            if e.fact_hash != fact_hash(&e)?
                || sequence != e.sequence
                || run_key != e.fact.run_key_sha256
                || kind != e.fact.kind.name()
                || observed != e.fact.observed_at_unix_seconds
                || e.recorded_at_unix_seconds < observed
            {
                return Err(FeedbackError::Integrity("fact"));
            }
            Ok(e)
        })
        .collect()
}

/// Latest recording time, for the clock watermark.
pub(crate) fn latest_recorded_at(db: &Connection) -> Result<Option<u64>> {
    let text: Option<String> = db
        .query_row(
            "SELECT fact FROM facts ORDER BY sequence DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    text.map(|text| {
        serde_json::from_str::<FeedbackFactEvent>(&text)
            .map(|e| e.recorded_at_unix_seconds)
            .map_err(FeedbackError::from)
    })
    .transpose()
}

pub(crate) fn expire_facts(tx: &Transaction<'_>, cutoff: u64) -> Result<usize> {
    Ok(tx.execute("DELETE FROM facts WHERE observed_at < ?1", [cutoff])?)
}
