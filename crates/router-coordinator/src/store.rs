use crate::{CoordinatorError, Result, hash};
use nix::fcntl::{Flock, FlockArg};
use router_types::*;
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};
pub(crate) struct Store {
    db: Mutex<Connection>,
    pub root: PathBuf,
    _owner: Flock<File>,
}
#[derive(serde::Serialize)]
struct Event<'a> {
    sequence: u64,
    instance: &'a str,
    kind: &'a str,
    detail: &'a str,
    previous: &'a str,
}
impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        if !root.is_absolute() || root.file_name().is_none() {
            return Err(CoordinatorError::Invalid("storage path"));
        }
        if !root.exists() {
            fs::DirBuilder::new().mode(0o700).create(root)?;
        }
        private_dir(root)?;
        let root = fs::canonicalize(root)?;
        let owner = Flock::lock(
            private_file(&root.join("coordinator.lock"))?,
            FlockArg::LockExclusiveNonblock,
        )
        .map_err(|_| CoordinatorError::Locked)?;
        private_database(&root.join("coordinator.sqlite3"))?;
        let mut db = Connection::open(root.join("coordinator.sqlite3"))?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        let version: u32 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > 2 {
            return Err(CoordinatorError::Integrity);
        }
        if version == 0 {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute_batch("CREATE TABLE workflows(instance TEXT PRIMARY KEY,definition_hash TEXT NOT NULL,runtime_root TEXT NOT NULL,cancelled INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE steps(instance TEXT NOT NULL REFERENCES workflows(instance),node TEXT NOT NULL,generation INTEGER NOT NULL,run_id TEXT NOT NULL UNIQUE,definition_hash TEXT NOT NULL,cost INTEGER NOT NULL,tokens INTEGER NOT NULL,PRIMARY KEY(instance,node,generation));
                CREATE TABLE events(sequence INTEGER PRIMARY KEY,instance TEXT NOT NULL REFERENCES workflows(instance),kind TEXT NOT NULL,detail TEXT NOT NULL,previous TEXT NOT NULL,hash TEXT NOT NULL);
                CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'append-only'); END;
                CREATE TRIGGER events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'append-only'); END;PRAGMA user_version=1;")?;
            tx.commit()?;
        }
        if version < 2 {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute_batch("CREATE TABLE controls(id TEXT PRIMARY KEY,instance TEXT NOT NULL REFERENCES workflows(instance),run_id TEXT NOT NULL,record TEXT NOT NULL,state TEXT NOT NULL);PRAGMA user_version=2;")?;
            tx.commit()?;
        }
        for suffix in ["", "-wal", "-shm"] {
            let path = root.join(format!("coordinator.sqlite3{suffix}"));
            if path.exists() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            }
        }
        verify(&db)?;
        Ok(Self {
            db: Mutex::new(db),
            root,
            _owner: owner,
        })
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.db.lock().map_err(|_| CoordinatorError::Integrity)
    }
    pub fn register(&self, definition: &WorkflowDefinition, runtime: &Path) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let prior: Option<(String, String)> = tx
            .query_row(
                "SELECT definition_hash,runtime_root FROM workflows WHERE instance=?1",
                [&definition.execution.instance_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let runtime = runtime
            .to_str()
            .ok_or(CoordinatorError::Invalid("runtime path"))?;
        if let Some((hash, path)) = prior {
            if hash != definition.definition_sha256 || path != runtime {
                return Err(CoordinatorError::Integrity);
            }
            return Ok(());
        }
        tx.execute(
            "INSERT INTO workflows(instance,definition_hash,runtime_root) VALUES(?1,?2,?3)",
            params![
                definition.execution.instance_id,
                definition.definition_sha256,
                runtime
            ],
        )?;
        append(
            &tx,
            &definition.execution.instance_id,
            "registered",
            &definition.definition_sha256,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn check(&self, definition: &WorkflowDefinition) -> Result<bool> {
        let db = self.lock()?;
        check(&db, definition)
    }
    pub fn check_budget(
        &self,
        definition: &WorkflowDefinition,
        node: &str,
        generation: u32,
        cost: u64,
        tokens: u64,
    ) -> Result<()> {
        let db = self.lock()?;
        if check(&db, definition)? {
            return Err(CoordinatorError::Cancelled);
        }
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM steps WHERE instance=?1 AND node=?2 AND generation=?3)",
            params![definition.execution.instance_id, node, generation],
            |row| row.get(0),
        )?;
        if exists {
            return Ok(());
        }
        let (used_cost, used_tokens): (u64,u64) = db.query_row(
            "SELECT COALESCE(SUM(cost),0),COALESCE(SUM(tokens),0) FROM steps WHERE instance=?1 AND node=?2",
            params![definition.execution.instance_id,node], |row| Ok((row.get(0)?,row.get(1)?)))?;
        let budget = &definition
            .plan
            .nodes
            .iter()
            .find(|n| n.id == node)
            .ok_or(CoordinatorError::Invalid("node"))?
            .budget;
        if used_cost
            .checked_add(cost)
            .is_none_or(|v| v > budget.max_cost_microusd)
            || used_tokens
                .checked_add(tokens)
                .is_none_or(|v| v > budget.max_tokens)
        {
            return Err(CoordinatorError::Limit);
        }
        Ok(())
    }
    pub fn bind_step(
        &self,
        definition: &WorkflowDefinition,
        node: &str,
        generation: u32,
        run: &RunSummary,
        cost: u64,
        tokens: u64,
    ) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if check(&tx, definition)? {
            return Err(CoordinatorError::Cancelled);
        }
        let existing:Option<(String,String)>=tx.query_row("SELECT run_id,definition_hash FROM steps WHERE instance=?1 AND node=?2 AND generation=?3",params![definition.execution.instance_id,node,generation],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((id, hash)) = existing {
            if id != run.run_id || hash != run.definition_hash {
                return Err(CoordinatorError::Integrity);
            }
            return Ok(());
        }
        let (used_cost,used_tokens):(u64,u64)=tx.query_row("SELECT COALESCE(SUM(cost),0),COALESCE(SUM(tokens),0) FROM steps WHERE instance=?1 AND node=?2",params![definition.execution.instance_id,node],|r|Ok((r.get(0)?,r.get(1)?)))?;
        let budget = &definition
            .plan
            .nodes
            .iter()
            .find(|n| n.id == node)
            .ok_or(CoordinatorError::Invalid("node"))?
            .budget;
        if used_cost
            .checked_add(cost)
            .is_none_or(|v| v > budget.max_cost_microusd)
            || used_tokens
                .checked_add(tokens)
                .is_none_or(|v| v > budget.max_tokens)
        {
            return Err(CoordinatorError::Limit);
        }
        tx.execute(
            "INSERT INTO steps VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                definition.execution.instance_id,
                node,
                generation,
                run.run_id,
                run.definition_hash,
                i64::try_from(cost).map_err(|_| CoordinatorError::Limit)?,
                i64::try_from(tokens).map_err(|_| CoordinatorError::Limit)?
            ],
        )?;
        append(
            &tx,
            &definition.execution.instance_id,
            "step.reviewed",
            &hash(
                "coordinator-step-v1",
                &(
                    node,
                    generation,
                    &run.run_id,
                    &run.definition_hash,
                    cost,
                    tokens,
                ),
            )?,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn steps(&self, instance: &str) -> Result<Vec<(String, u32, String)>> {
        steps(&*self.lock()?, instance)
    }
    pub fn controls(&self, instance: &str) -> Result<Vec<(String, String, Control)>> {
        let db = self.lock()?;
        let mut query=db.prepare("SELECT id,run_id,record FROM controls WHERE instance=?1 AND state='pending' ORDER BY rowid LIMIT 64")?;
        let rows = query.query_map([instance], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        rows.map(|row| {
            let (id, run, record) = row?;
            Ok((id, run, serde_json::from_str(&record)?))
        })
        .collect()
    }
    pub fn finish_control(&self, instance: &str, id: &str, applied: bool) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE controls SET state=?3 WHERE instance=?1 AND id=?2 AND state='pending'",
            params![instance, id, if applied { "applied" } else { "rejected" }],
        )?;
        append(
            &tx,
            instance,
            if applied {
                "control.applied"
            } else {
                "control.rejected"
            },
            id,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn event(&self, instance: &str, kind: &str, detail: &str) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        append(&tx, instance, kind, detail)?;
        tx.commit()?;
        Ok(())
    }
}
fn check(db: &Connection, definition: &WorkflowDefinition) -> Result<bool> {
    let (hash, cancelled): (String, bool) = db.query_row(
        "SELECT definition_hash,cancelled FROM workflows WHERE instance=?1",
        [&definition.execution.instance_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if hash != definition.definition_sha256 {
        return Err(CoordinatorError::Integrity);
    }
    Ok(cancelled)
}
pub(crate) fn steps(db: &Connection, instance: &str) -> Result<Vec<(String, u32, String)>> {
    let mut query = db.prepare(
        "SELECT node,generation,run_id FROM steps WHERE instance=?1 ORDER BY node,generation",
    )?;
    let rows = query.query_map([instance], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    rows.map(|r| Ok(r?)).collect()
}
fn append(db: &Connection, instance: &str, kind: &str, detail: &str) -> Result<()> {
    let last: Option<(u64, String)> = db
        .query_row(
            "SELECT sequence,hash FROM events ORDER BY sequence DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (sequence, previous) = last.map(|(s, h)| (s + 1, h)).unwrap_or((1, String::new()));
    let event = Event {
        sequence,
        instance,
        kind,
        detail,
        previous: &previous,
    };
    let digest = hash("coordinator-event-v1", &event)?;
    db.execute(
        "INSERT INTO events VALUES(?1,?2,?3,?4,?5,?6)",
        params![sequence, instance, kind, detail, previous, digest],
    )?;
    Ok(())
}
fn verify(db: &Connection) -> Result<()> {
    let mut query = db.prepare(
        "SELECT sequence,instance,kind,detail,previous,hash FROM events ORDER BY sequence",
    )?;
    let mut rows = query.query([])?;
    let mut previous = String::new();
    let mut sequence = 0_u64;
    while let Some(row) = rows.next()? {
        let next: u64 = row.get(0)?;
        let instance: String = row.get(1)?;
        let kind: String = row.get(2)?;
        let detail: String = row.get(3)?;
        let prior: String = row.get(4)?;
        let expected: String = row.get(5)?;
        if next != sequence + 1
            || prior != previous
            || hash(
                "coordinator-event-v1",
                &Event {
                    sequence: next,
                    instance: &instance,
                    kind: &kind,
                    detail: &detail,
                    previous: &prior,
                },
            )? != expected
        {
            return Err(CoordinatorError::Integrity);
        }
        sequence = next;
        previous = expected;
    }
    Ok(())
}
fn private_dir(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.permissions().mode() & 0o077 != 0 {
        return Err(CoordinatorError::Invalid("private storage"));
    }
    Ok(())
}
// Closing any auxiliary FD for an existing database discards this process's
// POSIX locks, including locks held by other live SQLite connections. Inspect
// existing inodes without opening them; create_new can only create a new inode.
fn private_database(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)?
            .metadata()?,
        Err(error) => return Err(error.into()),
    };
    if !meta.is_file() || meta.file_type().is_symlink() || meta.permissions().mode() & 0o077 != 0 {
        return Err(CoordinatorError::Invalid("private file"));
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
    let meta = file.metadata()?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        return Err(CoordinatorError::Invalid("private file"));
    }
    Ok(file)
}
fn control(root: &Path, writable: bool) -> Result<Connection> {
    private_dir(root)?;
    let path = root.join("coordinator.sqlite3");
    let meta = fs::symlink_metadata(&path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.permissions().mode() & 0o077 != 0 {
        return Err(CoordinatorError::Invalid("private database"));
    }
    let db = Connection::open_with_flags(
        path,
        if writable {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        },
    )?;
    db.busy_timeout(std::time::Duration::from_secs(2))?;
    if db.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))? != 2 {
        return Err(CoordinatorError::Integrity);
    }
    verify(&db)?;
    Ok(db)
}
pub fn request_cancel(root: &Path, instance: &str) -> Result<()> {
    let mut db = control(root, true)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let (cancelled, runtime): (bool, String) = tx.query_row(
        "SELECT cancelled,runtime_root FROM workflows WHERE instance=?1",
        [instance],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if !cancelled {
        tx.execute(
            "UPDATE workflows SET cancelled=1 WHERE instance=?1",
            [instance],
        )?;
        append(&tx, instance, "cancel.requested", "")?;
    }
    let registered = steps(&tx, instance)?;
    tx.commit()?;
    // `cancelled=1` is already committed, so one failing run must not leave the
    // later runs uncancelled: visit every run and report the first error.
    let mut first_error = None;
    for (_, _, run) in registered {
        if let Err(error) = cancel_run(Path::new(&runtime), &run) {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}
fn cancel_run(runtime: &Path, run: &str) -> Result<()> {
    let current = router_runtime::observe(runtime, run)?;
    if matches!(
        current.state,
        RunState::Planned
            | RunState::AwaitingApproval
            | RunState::Queued
            | RunState::Preparing
            | RunState::Running
    ) {
        match router_runtime::request_cancel(runtime, run) {
            Ok(()) | Err(router_runtime::RuntimeError::Transition) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub(crate) fn check_recorded(
    root: &Path,
    definition: &WorkflowDefinition,
    runtime: &Path,
    node: &str,
    generation: u32,
    run: &RunSummary,
) -> Result<()> {
    let db = control(root, false)?;
    check(&db, definition)?; // Cancellation does not erase historical material.
    let pinned: String = db.query_row(
        "SELECT runtime_root FROM workflows WHERE instance=?1",
        [&definition.execution.instance_id],
        |row| row.get(0),
    )?;
    if Path::new(&pinned) != runtime {
        return Err(CoordinatorError::Integrity);
    }
    let saved: (String, String) = db.query_row(
        "SELECT run_id,definition_hash FROM steps WHERE instance=?1 AND node=?2 AND generation=?3",
        params![definition.execution.instance_id, node, generation],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if saved != (run.run_id.clone(), run.definition_hash.clone()) {
        return Err(CoordinatorError::Integrity);
    }
    Ok(())
}

pub fn observe(root: &Path, definition: &WorkflowDefinition) -> Result<WorkflowStatus> {
    crate::validate_definition(definition)?;
    let db = control(root, false)?;
    let cancelled = check(&db, definition)?;
    let runtime: String = db.query_row(
        "SELECT runtime_root FROM workflows WHERE instance=?1",
        [&definition.execution.instance_id],
        |r| r.get(0),
    )?;
    let runs = steps(&db, &definition.execution.instance_id)?;
    let mut nodes = Vec::new();
    for node in &definition.plan.nodes {
        let latest = runs
            .iter()
            .filter(|(n, _, _)| n == &node.id)
            .max_by_key(|(_, g, _)| g);
        nodes.push(match latest {
            Some((_, generation, id)) => WorkflowNodeStatus {
                node_id: node.id.clone(),
                generation: *generation,
                run_id: Some(id.clone()),
                state: Some(router_runtime::observe(Path::new(&runtime), id)?.state),
            },
            None => WorkflowNodeStatus {
                node_id: node.id.clone(),
                generation: 0,
                run_id: None,
                state: None,
            },
        });
    }
    let all_verified = nodes.iter().all(|n| n.state == Some(RunState::Verified));
    Ok(WorkflowStatus {
        instance_id: definition.execution.instance_id.clone(),
        definition_sha256: definition.definition_sha256.clone(),
        nodes,
        all_verified,
        cancelled,
    })
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Control {
    Approve {
        digest: String,
    },
    Verify {
        digest: String,
        record: VerificationRecord,
    },
}
fn control_target(
    db: &Connection,
    instance: &str,
    node: &str,
    generation: u32,
) -> Result<(String, String)> {
    let (runtime, cancelled): (String, bool) = db.query_row(
        "SELECT runtime_root,cancelled FROM workflows WHERE instance=?1",
        [instance],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if cancelled {
        return Err(CoordinatorError::Cancelled);
    }
    let run: String = db.query_row(
        "SELECT run_id FROM steps WHERE instance=?1 AND node=?2 AND generation=?3",
        params![instance, node, generation],
        |r| r.get(0),
    )?;
    Ok((runtime, run))
}
fn control_state(db: &Connection, id: &str) -> Result<Option<String>> {
    Ok(db
        .query_row("SELECT state FROM controls WHERE id=?1", [id], |row| {
            row.get(0)
        })
        .optional()?)
}
fn request_control(
    root: &Path,
    instance: &str,
    node: &str,
    generation: u32,
    control: Control,
) -> Result<String> {
    let mut db = control_connection(root)?;
    let serialized = serde_json::to_string(&control)?;
    if serialized.len() > 4096 {
        return Err(CoordinatorError::Limit);
    }
    let digest = match &control {
        Control::Approve { digest } | Control::Verify { digest, .. } => digest,
    };
    let mut observed: Option<RunSummary> = None;
    for _ in 0..2 {
        // The runtime store is another database with a whole-chain check, so it
        // is observed before the coordinator write transaction, never inside
        // it. The observation is a snapshot either way: the owner checks digest
        // and state again when it applies the control.
        let (runtime, run) = control_target(&db, instance, node, generation)?;
        let id = hash("coordinator-control-v1", &(instance, &run, &control))?;
        // A rejected control is terminal: the same request is a new attempt and
        // is validated again below instead of returning the dead id.
        let live = |state: &Option<String>| state.as_deref().is_some_and(|s| s != "rejected");
        if observed.is_none() && !live(&control_state(&db, &id)?) {
            observed = Some(router_runtime::observe(Path::new(&runtime), &run)?);
        }
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        // Under the write lock, confirm what the snapshot above relied on.
        if control_target(&tx, instance, node, generation)? != (runtime, run.clone()) {
            return Err(CoordinatorError::Integrity);
        }
        let existing = control_state(&tx, &id)?;
        if live(&existing) {
            return Ok(id);
        }
        let Some(current) = observed.as_ref() else {
            // The control was rejected after the snapshot: observe, then retry.
            continue;
        };
        if digest != &current.approval_digest
            || !matches!(
                (&control, current.state),
                (
                    Control::Approve { .. },
                    RunState::AwaitingApproval | RunState::Queued
                ) | (Control::Verify { .. }, RunState::Verifying)
            )
        {
            return Err(CoordinatorError::Invalid("control authority or state"));
        }
        let pending: u32 = tx.query_row(
            "SELECT count(*) FROM controls WHERE instance=?1 AND state='pending'",
            [instance],
            |r| r.get(0),
        )?;
        if pending >= 64 {
            return Err(CoordinatorError::Limit);
        }
        let changed = if existing.is_some() {
            tx.execute(
                "UPDATE controls SET state='pending' WHERE id=?1 AND state='rejected'",
                [&id],
            )?
        } else {
            tx.execute(
                "INSERT OR IGNORE INTO controls VALUES(?1,?2,?3,?4,'pending')",
                params![id, instance, run, serialized],
            )?
        };
        if changed > 0 {
            append(&tx, instance, "control.requested", &id)?;
        }
        tx.commit()?;
        return Ok(id);
    }
    Err(CoordinatorError::Locked)
}
fn control_connection(root: &Path) -> Result<Connection> {
    control(root, true)
}
pub fn request_approval(
    root: &Path,
    instance: &str,
    node: &str,
    generation: u32,
    digest: &str,
) -> Result<String> {
    request_control(
        root,
        instance,
        node,
        generation,
        Control::Approve {
            digest: digest.into(),
        },
    )
}
pub fn request_verification(
    root: &Path,
    instance: &str,
    node: &str,
    generation: u32,
    digest: &str,
    record: VerificationRecord,
) -> Result<String> {
    request_control(
        root,
        instance,
        node,
        generation,
        Control::Verify {
            digest: digest.into(),
            record,
        },
    )
}
