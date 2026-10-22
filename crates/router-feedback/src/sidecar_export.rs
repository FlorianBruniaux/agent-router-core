//! An explicit single-event export projection held under the current store lock.
use crate::{
    FeedbackError, FeedbackStore, Result, hash, valid_hash, validate_input, validate_preferences,
};
use router_types::*;
use rusqlite::{Connection, OptionalExtension};
use std::sync::MutexGuard;

/// Not serializable: the authority is a live store lock, not a JSON claim.
/// Holding it serializes configure/purge with the one explicitly requested send.
pub struct SidecarExportGuard<'a> {
    store: &'a FeedbackStore,
    _connection: MutexGuard<'a, Connection>,
    projection: SidecarExportProjection,
    valid_until_unix_seconds: u64,
}
pub enum SidecarExportProjection {
    Outcome(SidecarOutcome),
    Feedback(SidecarHumanFeedback),
}
impl Drop for SidecarExportGuard<'_> {
    fn drop(&mut self) {
        // Runs before `_connection` is released.
        if let Ok(mut holder) = self.store.export_holder.lock() {
            *holder = None;
        }
    }
}
impl SidecarExportGuard<'_> {
    /// Exclusive retention boundary. Bound the complete outbound exchange to it.
    pub fn valid_until_unix_seconds(&self) -> u64 {
        self.valid_until_unix_seconds
    }
    pub fn projection(&self) -> &SidecarExportProjection {
        &self.projection
    }
}
impl FeedbackStore {
    /// Authorize exactly this event at its current consent revision. This method
    /// makes no network call. The caller separately authorizes the destination.
    /// The live guard must outlive the bounded network exchange. Calling any store
    /// method from the thread holding it returns `Locked` instead of deadlocking.
    pub fn authorize_sidecar_export(
        &self,
        sequence: u64,
        expected_event_hash: &str,
        expected_revision: u64,
        now: u64,
    ) -> Result<SidecarExportGuard<'_>> {
        if sequence == 0 || expected_revision == 0 || !valid_hash(expected_event_hash) {
            return Err(FeedbackError::Invalid("export binding"));
        }
        crate::store::timestamp(now)?;
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let consent = crate::store::read_consent(&tx)?;
        validate_preferences(&consent.preferences)?;
        if !consent.preferences.collection_enabled {
            return Err(FeedbackError::Consent);
        }
        if !consent.preferences.learning_enabled {
            return Err(FeedbackError::LearningDisabled);
        }
        if consent.revision != expected_revision {
            return Err(FeedbackError::Consent);
        }
        crate::store::ensure_clock(&tx, now)?;
        // Check length before retrieving the text rather than loading every event.
        let length: Option<usize> = tx
            .query_row(
                "SELECT length(CAST(event AS BLOB)) FROM feedback WHERE sequence=?1",
                [sequence],
                |r| r.get(0),
            )
            .optional()?;
        if length.is_none() {
            return Err(FeedbackError::NotFound);
        }
        if length.is_some_and(|n| n > crate::MAX_INPUT_BYTES + 1024) {
            return Err(FeedbackError::Limit);
        }
        let (run, origin, observed, text): (String, String, u64, String) = tx.query_row(
            "SELECT run_hash,origin,observed_at,event FROM feedback WHERE sequence=?1",
            [sequence],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        let event: FeedbackEvent = serde_json::from_value(
            router_adapter_api::strict_json(text.as_bytes())
                .map_err(|_| FeedbackError::Integrity("event JSON"))?,
        )?;
        validate_input(&event.input)?;
        if event.sequence != sequence
            || event.event_hash != expected_event_hash
            || event.event_hash != crate::store::event_hash(&event)?
            || run != event.input.binding.run_hash
            || origin != serde_json::to_string(&event.input.origin)?
            || observed != event.input.observed_at_unix_seconds
            || event.recorded_at_unix_seconds < observed
        {
            return Err(FeedbackError::Integrity("event"));
        }
        if event.consent_revision != expected_revision
            || now < consent.updated_at_unix_seconds
            || observed < consent.updated_at_unix_seconds
            || observed > now
            || event.recorded_at_unix_seconds > now
            || now - observed > consent.preferences.retention_seconds
        {
            return Err(FeedbackError::Consent);
        }
        let projection = project(&event)?;
        tx.commit()?;
        *self
            .export_holder
            .lock()
            .map_err(|_| FeedbackError::Integrity("lock poisoned"))? =
            Some(std::thread::current().id());
        Ok(SidecarExportGuard {
            store: self,
            _connection: db,
            projection,
            valid_until_unix_seconds: observed + consent.preferences.retention_seconds + 1,
        })
    }
}
fn project(event: &FeedbackEvent) -> Result<SidecarExportProjection> {
    let i = &event.input;
    let b = &i.binding;
    let observation = SidecarObservation {
        event_sha256: event.event_hash.clone(),
        consent_revision: event.consent_revision,
        observed_at_unix_seconds: i.observed_at_unix_seconds,
        task_sha256: b.task_hash.clone(),
        run_sha256: b.run_hash.clone(),
        receipt_sha256: b.receipt_hash.clone(),
        policy_sha256: b.policy_hash.clone(),
        catalog_sha256: b.catalog_hash.clone(),
        snapshot_sha256: b.snapshot_hash.clone(),
        provenance_sha256: b.provenance_sha256.clone(),
        context_sha256: hash("sidecar-context-v1", &i.context)?,
        model_sha256: hash("sidecar-model-v1", &i.context.model)?,
        harness_sha256: hash("sidecar-harness-v1", &i.context.harness)?,
        task_kind: i.context.task_kind,
        risk: i.context.risk,
        effort: i.context.effort,
        transport: i.transport,
        validation: i.validation,
        objective: i.objective,
        verification_evidence_sha256: i.verification_evidence_sha256.clone(),
        failure: i.failure,
        // The token split is report input for the local store only; the
        // exported measurements keep their earlier shape.
        measurements: FeedbackMeasurements {
            usage_scope: None,
            usage: None,
            ..i.measurements.clone()
        },
    };
    Ok(match (&i.origin, &i.human) {
        (FeedbackOrigin::Automated, None) => {
            SidecarExportProjection::Outcome(SidecarOutcome { observation })
        }
        (FeedbackOrigin::Human, Some(h)) => {
            SidecarExportProjection::Feedback(SidecarHumanFeedback {
                observation,
                human: SidecarHumanVerdict {
                    success: h.success,
                    quality: h.quality,
                    perceived_cost: h.perceived_cost,
                    correction_required: h.correction_required,
                    reviewer_sha256: h.reviewer_sha256.clone(),
                },
            })
        }
        _ => return Err(FeedbackError::Invalid("origin")),
    })
}
