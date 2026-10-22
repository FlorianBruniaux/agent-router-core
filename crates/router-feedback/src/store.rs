use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::{Mutex, MutexGuard},
    thread::ThreadId,
};

use nix::fcntl::{Flock, FlockArg};
use router_types::{
    FeedbackConsent, FeedbackEvent, FeedbackExport, FeedbackInput, FeedbackPreferences,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::{
    DriftFinding, FeedbackError, FeedbackStatistics, LearningRules, MAX_EVENTS, Result,
    facts::{expire_facts, latest_recorded_at, read_facts},
    hash, validate_input, validate_preferences,
};

pub struct FeedbackStore {
    pub(crate) db: Mutex<Connection>,
    /// Thread holding a `SidecarExportGuard`. Its own re-entry would block on
    /// `db` forever, so `lock` refuses it with `Locked`.
    pub(crate) export_holder: Mutex<Option<ThreadId>>,
    _lock: Flock<File>,
}

impl FeedbackStore {
    /// An explicit existing parent directory is required. Nothing is written to
    /// a global configuration, receipt, prompt or runtime database.
    pub fn open(root: &Path) -> Result<Self> {
        if !root.is_absolute() || root.file_name().is_none() {
            return Err(FeedbackError::Invalid("storage path"));
        }
        if !root.exists() {
            fs::DirBuilder::new().mode(0o700).create(root)?;
        }
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(FeedbackError::Invalid("private storage directory"));
        }
        let root = fs::canonicalize(root)?;
        let lock = Flock::lock(
            private_file(&root.join("feedback.lock"))?,
            FlockArg::LockExclusiveNonblock,
        )
        .map_err(|_| FeedbackError::Locked)?;
        let db_path = root.join("feedback.sqlite3");
        drop(private_file(&db_path)?);
        for suffix in ["-wal", "-shm"] {
            let sidecar = root.join(format!("feedback.sqlite3{suffix}"));
            if sidecar.exists() || fs::symlink_metadata(&sidecar).is_ok() {
                drop(private_file(&sidecar)?);
            }
        }
        let mut db = Connection::open_with_flags(
            db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        db.pragma_update(None, "secure_delete", "ON")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        let version: u32 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > 2 {
            return Err(FeedbackError::Integrity("future schema"));
        }
        if version == 0 {
            let tx = db.transaction()?;
            tx.execute_batch("CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE feedback(sequence INTEGER PRIMARY KEY AUTOINCREMENT, run_hash TEXT NOT NULL, origin TEXT NOT NULL, observed_at INTEGER NOT NULL, event TEXT NOT NULL, UNIQUE(run_hash,origin));
                CREATE TRIGGER feedback_immutable BEFORE UPDATE ON feedback BEGIN SELECT RAISE(ABORT,'immutable feedback'); END;
                CREATE TABLE policies(id TEXT PRIMARY KEY, artifact TEXT NOT NULL, state TEXT NOT NULL);
                CREATE TRIGGER policy_artifacts_immutable BEFORE UPDATE OF artifact ON policies BEGIN SELECT RAISE(ABORT,'immutable policy artifact'); END;
                CREATE TABLE policy_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT, artifact_id TEXT NOT NULL REFERENCES policies(id), event TEXT NOT NULL);
                CREATE TRIGGER policy_events_immutable BEFORE UPDATE ON policy_events BEGIN SELECT RAISE(ABORT,'immutable policy event'); END;
                PRAGMA user_version=1;")?;
            let consent = FeedbackConsent {
                preferences: FeedbackPreferences::default(),
                revision: 0,
                updated_at_unix_seconds: 0,
            };
            tx.execute(
                "INSERT INTO settings VALUES('consent',?1)",
                [serde_json::to_string(&consent)?],
            )?;
            tx.commit()?;
        }
        let version: u32 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version == 1 {
            // Additive: events are neither read nor rewritten.
            let tx = db.transaction()?;
            tx.execute_batch("CREATE TABLE facts(sequence INTEGER PRIMARY KEY AUTOINCREMENT, run_key TEXT NOT NULL, kind TEXT NOT NULL, observed_at INTEGER NOT NULL, fact TEXT NOT NULL, UNIQUE(run_key,kind));
                CREATE TRIGGER facts_immutable BEFORE UPDATE ON facts BEGIN SELECT RAISE(ABORT,'immutable fact'); END;
                PRAGMA user_version=2;")?;
            tx.commit()?;
        }
        for suffix in ["", "-wal", "-shm"] {
            let path = root.join(format!("feedback.sqlite3{suffix}"));
            if path.exists() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            }
        }
        let store = Self {
            db: Mutex::new(db),
            export_holder: Mutex::new(None),
            _lock: lock,
        };
        store.verify_storage()?;
        Ok(store)
    }
    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        if *self
            .export_holder
            .lock()
            .map_err(|_| FeedbackError::Integrity("lock poisoned"))?
            == Some(std::thread::current().id())
        {
            return Err(FeedbackError::Locked);
        }
        self.db
            .lock()
            .map_err(|_| FeedbackError::Integrity("lock poisoned"))
    }
    pub fn consent(&self) -> Result<FeedbackConsent> {
        let db = self.lock()?;
        read_consent(&db)
    }

    pub fn configure(&self, preferences: FeedbackPreferences, now: u64) -> Result<FeedbackConsent> {
        validate_preferences(&preferences)?;
        timestamp(now)?;
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let previous = read_consent(&tx)?;
        ensure_clock(&tx, now)?;
        if now < previous.updated_at_unix_seconds {
            return Err(FeedbackError::Invalid("clock moved backwards"));
        }
        let consent = FeedbackConsent {
            preferences,
            revision: previous
                .revision
                .checked_add(1)
                .ok_or(FeedbackError::Limit)?,
            updated_at_unix_seconds: now,
        };
        write_consent(&tx, &consent)?;
        if !consent.preferences.collection_enabled {
            tx.execute("DELETE FROM feedback", [])?;
            tx.execute("DELETE FROM facts", [])?;
        }
        if !consent.preferences.learning_enabled {
            // Opt-out discards learned artifacts and restores the explicitly registered deterministic baseline.
            reset_learning(&tx)?;
        }
        expire(&tx, &consent, now)?;
        tx.commit()?;
        scrub(&db)?;
        Ok(consent)
    }
    pub fn record(&self, input: FeedbackInput, now: u64) -> Result<FeedbackEvent> {
        validate_input(&input)?;
        timestamp(now)?;
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let consent = read_consent(&tx)?;
        if !consent.preferences.collection_enabled {
            return Err(FeedbackError::Consent);
        }
        ensure_clock(&tx, now)?;
        if now < consent.updated_at_unix_seconds
            || input.observed_at_unix_seconds > now
            || input.observed_at_unix_seconds < consent.updated_at_unix_seconds
            || now - input.observed_at_unix_seconds > consent.preferences.retention_seconds
        {
            return Err(FeedbackError::Invalid("observation time"));
        }
        let expired = expire(&tx, &consent, now)?;
        let origin = serde_json::to_string(&input.origin)?;
        if let Some(text) = tx
            .query_row(
                "SELECT event FROM feedback WHERE run_hash=?1 AND origin=?2",
                params![input.binding.run_hash, origin],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            let existing: FeedbackEvent = serde_json::from_str(&text)?;
            if existing.input == input {
                if existing.event_hash != event_hash(&existing)? {
                    return Err(FeedbackError::Integrity("event"));
                }
                tx.commit()?;
                if expired > 0 {
                    scrub(&db)?;
                }
                return Ok(existing);
            }
            return Err(FeedbackError::Integrity("immutable run verdict"));
        }
        // Human and automated verdicts refer to the same frozen route/context.
        if let Some(text) = tx
            .query_row(
                "SELECT event FROM feedback WHERE run_hash=?1",
                [&input.binding.run_hash],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            let existing: FeedbackEvent = serde_json::from_str(&text)?;
            if existing.input.binding != input.binding || existing.input.context != input.context {
                return Err(FeedbackError::Integrity("run binding changed"));
            }
        }
        let count: usize = tx.query_row("SELECT COUNT(*) FROM feedback", [], |r| r.get(0))?;
        if count >= MAX_EVENTS {
            return Err(FeedbackError::Limit);
        }
        let sequence: u64 = tx.query_row(
            "SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='feedback'),0)+1",
            [],
            |r| r.get(0),
        )?;
        let mut event = FeedbackEvent {
            sequence,
            consent_revision: consent.revision,
            recorded_at_unix_seconds: now,
            input,
            event_hash: String::new(),
        };
        event.event_hash = event_hash(&event)?;
        tx.execute("INSERT INTO feedback(sequence,run_hash,origin,observed_at,event) VALUES(?1,?2,?3,?4,?5)",params![sequence,event.input.binding.run_hash,origin,event.input.observed_at_unix_seconds,serde_json::to_string(&event)?])?;
        tx.commit()?;
        if expired > 0 {
            scrub(&db)?;
        }
        Ok(event)
    }
    pub fn events(&self, now: u64) -> Result<Vec<FeedbackEvent>> {
        Ok(self.event_snapshot(now, false)?.0)
    }
    fn event_snapshot(
        &self,
        now: u64,
        learning: bool,
    ) -> Result<(Vec<FeedbackEvent>, FeedbackConsent)> {
        timestamp(now)?;
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let (events, consent, removed) = snapshot_in(&tx, now, learning)?;
        tx.commit()?;
        if removed > 0 {
            scrub(&db)?;
        }
        Ok((events, consent))
    }
    pub fn export(&self, now: u64) -> Result<FeedbackExport> {
        timestamp(now)?;
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let (events, consent, removed) = snapshot_in(&tx, now, false)?;
        let facts = read_facts(&tx)?;
        tx.commit()?;
        if removed > 0 {
            scrub(&db)?;
        }
        let mut export = FeedbackExport {
            schema_version: 1,
            exported_at_unix_seconds: now,
            consent,
            events,
            facts,
            content_hash: String::new(),
        };
        export.content_hash = hash("feedback-export-v1", &export)?;
        Ok(export)
    }
    /// Deletes feedback, facts, policies, audit records and resets consent/settings.
    /// Only a non-personal clock watermark survives, preventing clock replay.
    /// The count covers events and facts.
    pub fn purge_all(&self, now: u64) -> Result<usize> {
        timestamp(now)?;
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        ensure_clock(&tx, now)?;
        let removed =
            tx.execute("DELETE FROM feedback", [])? + tx.execute("DELETE FROM facts", [])?;
        tx.execute("DELETE FROM policy_events", [])?;
        tx.execute("DELETE FROM policies", [])?;
        tx.execute("DELETE FROM settings", [])?;
        tx.execute(
            "INSERT INTO settings VALUES('last_seen_time',?1)",
            [now.to_string()],
        )?;
        write_consent(
            &tx,
            &FeedbackConsent {
                preferences: FeedbackPreferences::default(),
                revision: 0,
                updated_at_unix_seconds: now,
            },
        )?;
        tx.execute("DELETE FROM sqlite_sequence", [])?;
        tx.commit()?;
        scrub(&db)?;
        Ok(removed)
    }
    pub fn purge_expired(&self, now: u64) -> Result<usize> {
        timestamp(now)?;
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        ensure_clock(&tx, now)?;
        let consent = read_consent(&tx)?;
        if now < consent.updated_at_unix_seconds {
            return Err(FeedbackError::Invalid("clock moved backwards"));
        }
        let count = expire(&tx, &consent, now)?;
        tx.commit()?;
        if count > 0 {
            scrub(&db)?;
        }
        Ok(count)
    }
    pub fn statistics(&self, now: u64) -> Result<FeedbackStatistics> {
        crate::learning::statistics(&self.event_snapshot(now, true)?.0)
    }
    pub fn drift(&self, rules: &LearningRules, now: u64) -> Result<Vec<DriftFinding>> {
        crate::learning::drift(&self.event_snapshot(now, true)?.0, rules, now)
    }
    pub(crate) fn require_learning(&self) -> Result<()> {
        if !self.consent()?.preferences.learning_enabled {
            return Err(FeedbackError::LearningDisabled);
        }
        Ok(())
    }
    fn verify_storage(&self) -> Result<()> {
        let db = self.lock()?;
        let consent = read_consent(&db)?;
        validate_preferences(&consent.preferences)?;
        read_events(&db)?;
        read_facts(&db)?;
        crate::policy::verify_policies(&db)?;
        Ok(())
    }
}

/// Expires and reads events inside the caller's transaction, so a caller that
/// then writes derives its decision from the same snapshot it commits against.
/// The count of expired rows lets the caller `scrub` after commit.
pub(crate) fn snapshot_in(
    tx: &Transaction<'_>,
    now: u64,
    learning: bool,
) -> Result<(Vec<FeedbackEvent>, FeedbackConsent, usize)> {
    let consent = read_consent(tx)?;
    if learning && !consent.preferences.learning_enabled {
        return Err(FeedbackError::LearningDisabled);
    }
    ensure_clock(tx, now)?;
    if now < consent.updated_at_unix_seconds {
        return Err(FeedbackError::Invalid("clock moved backwards"));
    }
    let removed = expire(tx, &consent, now)?;
    let events = read_events(tx)?;
    Ok((events, consent, removed))
}

pub(crate) fn read_consent(db: &Connection) -> Result<FeedbackConsent> {
    let text: String = db.query_row("SELECT value FROM settings WHERE key='consent'", [], |r| {
        r.get(0)
    })?;
    Ok(serde_json::from_str(&text)?)
}
fn write_consent(tx: &Transaction<'_>, consent: &FeedbackConsent) -> Result<()> {
    tx.execute(
        "INSERT OR REPLACE INTO settings VALUES('consent',?1)",
        [serde_json::to_string(consent)?],
    )?;
    Ok(())
}
pub(crate) fn expire(tx: &Transaction<'_>, consent: &FeedbackConsent, now: u64) -> Result<usize> {
    let cutoff = now.saturating_sub(consent.preferences.retention_seconds);
    Ok(
        tx.execute("DELETE FROM feedback WHERE observed_at < ?1", [cutoff])?
            + expire_facts(tx, cutoff)?,
    )
}
pub(crate) fn ensure_clock(db: &Connection, now: u64) -> Result<()> {
    let previous: Option<String> = db
        .query_row(
            "SELECT value FROM settings WHERE key='last_seen_time'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(previous) = previous {
        let previous = previous
            .parse::<u64>()
            .map_err(|_| FeedbackError::Integrity("clock watermark"))?;
        if now < previous {
            return Err(FeedbackError::Invalid("clock moved backwards"));
        }
    }
    let text: Option<String> = db
        .query_row(
            "SELECT event FROM feedback ORDER BY sequence DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(text) = text {
        let event: FeedbackEvent = serde_json::from_str(&text)?;
        if now < event.recorded_at_unix_seconds {
            return Err(FeedbackError::Invalid("clock moved backwards"));
        }
    }
    if latest_recorded_at(db)?.is_some_and(|recorded| now < recorded) {
        return Err(FeedbackError::Invalid("clock moved backwards"));
    }
    db.execute(
        "INSERT OR REPLACE INTO settings VALUES('last_seen_time',?1)",
        [now.to_string()],
    )?;
    Ok(())
}
pub(crate) fn read_events(db: &Connection) -> Result<Vec<FeedbackEvent>> {
    let count: usize = db.query_row("SELECT COUNT(*) FROM feedback", [], |r| r.get(0))?;
    if count > MAX_EVENTS {
        return Err(FeedbackError::Limit);
    }
    let mut query = db.prepare(
        "SELECT sequence,run_hash,origin,observed_at,event FROM feedback ORDER BY sequence",
    )?;
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
        .map(|(sequence, run, origin, observed, text)| {
            if text.len() > crate::MAX_INPUT_BYTES + 1024 {
                return Err(FeedbackError::Limit);
            }
            let e: FeedbackEvent = serde_json::from_str(&text)?;
            validate_input(&e.input)?;
            if e.event_hash != event_hash(&e)?
                || sequence != e.sequence
                || run != e.input.binding.run_hash
                || origin != serde_json::to_string(&e.input.origin)?
                || observed != e.input.observed_at_unix_seconds
                || e.recorded_at_unix_seconds < observed
            {
                return Err(FeedbackError::Integrity("event"));
            }
            Ok(e)
        })
        .collect()
}
pub(crate) fn event_hash(event: &FeedbackEvent) -> Result<String> {
    hash(
        "feedback-event-v1",
        &(
            event.sequence,
            event.consent_revision,
            event.recorded_at_unix_seconds,
            &event.input,
        ),
    )
}
pub(crate) fn timestamp(now: u64) -> Result<()> {
    if now > i64::MAX as u64 {
        return Err(FeedbackError::Invalid("timestamp"));
    }
    Ok(())
}
fn private_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > 512 * 1024 * 1024
    {
        return Err(FeedbackError::Invalid("private regular file"));
    }
    Ok(file)
}
pub(crate) fn scrub(db: &Connection) -> Result<()> {
    db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")?;
    Ok(())
}
fn reset_learning(tx: &Transaction<'_>) -> Result<()> {
    let baseline: Option<String> = tx
        .query_row("SELECT value FROM settings WHERE key='baseline'", [], |r| {
            r.get(0)
        })
        .optional()?;
    tx.execute("DELETE FROM policy_events", [])?;
    if let Some(baseline) = baseline {
        tx.execute("DELETE FROM policies WHERE id<>?1", [&baseline])?;
        tx.execute(
            "UPDATE policies SET state='\"active\"' WHERE id=?1",
            [&baseline],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO settings VALUES('active',?1)",
            [&baseline],
        )?;
    } else {
        tx.execute("DELETE FROM policies", [])?;
        tx.execute("DELETE FROM settings WHERE key='active'", [])?;
    }
    Ok(())
}
