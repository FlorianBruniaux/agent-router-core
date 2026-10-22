use crate::{
    Result, RuntimeError, digest,
    leases::{LeaseRecord, LeaseStorage},
};
use nix::fcntl::{Flock, FlockArg};
use router_types::{
    ExecutionRequest, ModelId, OutputArtifacts, OutputArtifactsState, OutputRetentionPolicy,
    RunFailure, RunState, RunSummary, RuntimeEvent, WorkflowExecutionContract,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

mod admission;
mod escalation;
mod observation;
pub use observation::{observe_run, observe_run_v2, observe_run_v3};
mod preparation;
pub(crate) use escalation::EscalationHistory;
pub(crate) use preparation::Preparation;

/// Highest schema this build reads and writes. Migrations below end at this
/// version; the passive doctor pins its table layout to the same value.
pub(crate) const SCHEMA_VERSION: u32 = 9;

pub(crate) struct Store {
    db: Mutex<Connection>,
    pub root: PathBuf,
    leases: LeaseStorage,
    /// Trust point of the event chain, always locked after `db` (ADR 0018).
    verified: Mutex<VerifiedChain>,
    _lock: Flock<File>,
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        if !root.is_absolute() || root.file_name().is_none() {
            return Err(RuntimeError::Invalid("storage path"));
        }
        if !root.exists() {
            fs::DirBuilder::new().mode(0o700).create(root)?;
        }
        let meta = fs::symlink_metadata(root)?;
        if !meta.is_dir() || meta.file_type().is_symlink() || meta.permissions().mode() & 0o077 != 0
        {
            return Err(RuntimeError::Invalid("private storage directory"));
        }
        let root = fs::canonicalize(root)?;
        let lock_file = private_file(&root.join("runtime.lock"))?;
        let lock = Flock::lock(lock_file, FlockArg::LockExclusiveNonblock)
            .map_err(|_| RuntimeError::Locked)?;
        let path = root.join("runtime.sqlite3");
        private_database(&path)?;
        let mut db = Connection::open(&path)?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        let version: u32 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(RuntimeError::Integrity("future schema"));
        }
        if version == 0 {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute_batch("CREATE TABLE runs(run_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, node_id TEXT NOT NULL, summary TEXT NOT NULL, UNIQUE(plan_id,node_id));
                CREATE TABLE run_attempts(run_id TEXT NOT NULL REFERENCES runs(run_id), attempt INTEGER NOT NULL, status TEXT NOT NULL, PRIMARY KEY(run_id,attempt));
                CREATE TABLE events(sequence INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id), kind TEXT NOT NULL, state TEXT NOT NULL, detail TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL);
                CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'append-only'); END;
                CREATE TRIGGER events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'append-only'); END;
                CREATE TABLE writer_locks(run_id TEXT PRIMARY KEY REFERENCES runs(run_id), workspace TEXT NOT NULL, scope TEXT NOT NULL);
                CREATE TABLE artifacts(run_id TEXT NOT NULL REFERENCES runs(run_id), sha256 TEXT NOT NULL, kind TEXT NOT NULL, PRIMARY KEY(run_id,kind));
                CREATE TABLE verifications(run_id TEXT PRIMARY KEY REFERENCES runs(run_id), record TEXT NOT NULL);
                PRAGMA user_version=1;")?;
            tx.commit()?;
        }
        if version < 2 {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute_batch("CREATE TABLE control_requests(run_id TEXT PRIMARY KEY REFERENCES runs(run_id), cancel_requested INTEGER NOT NULL CHECK(cancel_requested=1)); PRAGMA user_version=2;")?;
            tx.commit()?;
        }
        if version < 3 {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute_batch("CREATE TABLE output_artifacts(run_id TEXT NOT NULL REFERENCES runs(run_id), attempt INTEGER NOT NULL, expires_at INTEGER NOT NULL, state TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(run_id,attempt)); CREATE INDEX output_expiration ON output_artifacts(state,expires_at); CREATE TABLE output_files(run_id TEXT NOT NULL, attempt INTEGER NOT NULL, stream TEXT NOT NULL CHECK(stream IN ('stdout','stderr')), identity TEXT NOT NULL, PRIMARY KEY(run_id,attempt,stream), FOREIGN KEY(run_id,attempt) REFERENCES output_artifacts(run_id,attempt)); PRAGMA user_version=3;")?;
            tx.commit()?;
        }
        if version < 4 {
            // SQLite table rebuild removes plan-global uniqueness. Historical
            // runs remain unbound: a shared plan hash is never an instance ID.
            db.pragma_update(None, "foreign_keys", "OFF")?;
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute_batch("CREATE TABLE runs_v4(run_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, node_id TEXT NOT NULL, summary TEXT NOT NULL);
                INSERT INTO runs_v4 SELECT run_id,plan_id,node_id,summary FROM runs;
                DROP TABLE runs;
                ALTER TABLE runs_v4 RENAME TO runs;
                CREATE TABLE workflow_instances(instance_id TEXT PRIMARY KEY, contract_hash TEXT NOT NULL, record TEXT NOT NULL);
                CREATE TABLE workflow_node_runs(instance_id TEXT NOT NULL REFERENCES workflow_instances(instance_id), node_id TEXT NOT NULL, generation INTEGER NOT NULL, run_id TEXT NOT NULL UNIQUE REFERENCES runs(run_id), model TEXT NOT NULL, agent TEXT, PRIMARY KEY(instance_id,node_id,generation));
                PRAGMA user_version=4;")?;
            let violations: bool = tx.prepare("PRAGMA foreign_key_check")?.exists([])?;
            if violations {
                return Err(RuntimeError::Integrity("migration foreign keys"));
            }
            tx.commit()?;
            db.pragma_update(None, "foreign_keys", "ON")?;
        }
        if version < 5 {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute_batch("CREATE TABLE declared_artifacts(artifact_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id), attempt INTEGER NOT NULL, label TEXT NOT NULL, record TEXT NOT NULL, identity TEXT, UNIQUE(run_id,attempt,label)); PRAGMA user_version=5;")?;
            tx.commit()?;
        }
        if version < 6 {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute_batch("CREATE TABLE attempt_leases(run_id TEXT NOT NULL REFERENCES runs(run_id), attempt INTEGER NOT NULL, record TEXT NOT NULL, resolved INTEGER NOT NULL DEFAULT 0 CHECK(resolved IN (0,1)), evidence TEXT, PRIMARY KEY(run_id,attempt)); CREATE TABLE cleanup_blocks(run_id TEXT PRIMARY KEY REFERENCES runs(run_id)); PRAGMA user_version=6;")?;
            tx.commit()?;
        }
        if version < 7 {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute_batch("CREATE TABLE workflow_plan_authority(instance_id TEXT PRIMARY KEY REFERENCES workflow_instances(instance_id), pin TEXT NOT NULL); INSERT INTO workflow_plan_authority SELECT instance_id,'legacy' FROM workflow_instances; PRAGMA user_version=7;")?;
            tx.commit()?;
        }
        if version < 8 {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute_batch("CREATE TABLE preparation_cycles(run_id TEXT NOT NULL REFERENCES runs(run_id), sequence INTEGER NOT NULL, record TEXT NOT NULL, PRIMARY KEY(run_id,sequence)); PRAGMA user_version=8;")?;
            tx.commit()?;
        }
        if version < 9 {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute_batch("CREATE TABLE admission_binding(id INTEGER PRIMARY KEY CHECK(id=1),binding TEXT NOT NULL); CREATE TABLE admission_intents(run_id TEXT PRIMARY KEY REFERENCES runs(run_id),record TEXT NOT NULL); PRAGMA user_version=9;")?;
            tx.commit()?;
        }
        for suffix in ["", "-wal", "-shm"] {
            let path = root.join(format!("runtime.sqlite3{suffix}"));
            if path.exists() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            }
        }
        let store = Self {
            db: Mutex::new(db),
            leases: LeaseStorage::open(&root)?,
            verified: Mutex::new(VerifiedChain::default()),
            root,
            _lock: lock,
        };
        store.verify_events()?;
        store.recover()?;
        Ok(store)
    }
    pub(crate) fn verify_plan_pin(
        &self,
        workflow: Option<&router_types::WorkflowRunBinding>,
        generated: Option<&router_types::GeneratedDecisionBinding>,
    ) -> Result<()> {
        let db = self.lock()?;
        let proof = verify_plan_pin(&db, &*self.verified()?, workflow, generated)?;
        self.advance(proof)
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.db
            .lock()
            .map_err(|_| RuntimeError::Integrity("storage lock poisoned"))
    }
    fn verified(&self) -> Result<std::sync::MutexGuard<'_, VerifiedChain>> {
        self.verified
            .lock()
            .map_err(|_| RuntimeError::Integrity("storage lock poisoned"))
    }
    /// Opens a transaction and verifies the chain tail before returning it,
    /// so no write of the transaction precedes the check. The trust point
    /// moves at once: it covers committed rows only and survives a rollback.
    fn verified_transaction<'db>(
        &self,
        db: &'db mut Connection,
        behavior: rusqlite::TransactionBehavior,
    ) -> Result<Transaction<'db>> {
        let tx = db.transaction_with_behavior(behavior)?;
        let proof = verify_tail(&tx, &*self.verified()?)?;
        self.advance(Some(proof))?;
        Ok(tx)
    }
    /// Callers hold `db` from verification to here, so no other proof can
    /// have moved the point in between.
    fn advance(&self, proof: Option<ChainProof>) -> Result<()> {
        let Some(proof) = proof else {
            return Ok(());
        };
        let mut verified = self.verified()?;
        if verified.point.sequence != proof.base {
            return Err(RuntimeError::Integrity("event chain"));
        }
        verified.point = proof.point;
        for anchor in proof.anchors {
            verified.anchors.insert(anchor.instance_id.clone(), anchor);
        }
        Ok(())
    }
    pub(crate) fn diagnose_snapshot(
        &self,
    ) -> router_doctor::Result<router_doctor::DatabaseSnapshotReport> {
        let connection = self.lock().map_err(|_| router_doctor::DoctorError::Read)?;
        router_doctor::diagnose_database_snapshot(&connection)
    }
    #[cfg(test)]
    pub fn register(&self, summary: &RunSummary) -> Result<RunSummary> {
        self.register_inner(summary, None, None, 5, None)
    }
    pub fn register_workflow(
        &self,
        summary: &RunSummary,
        contract: Option<&WorkflowExecutionContract>,
        request: &ExecutionRequest,
        max_attempts: u32,
        generated: Option<&router_types::GeneratedDecisionBinding>,
    ) -> Result<RunSummary> {
        self.register_inner(summary, contract, Some(request), max_attempts, generated)
    }
    fn register_inner(
        &self,
        summary: &RunSummary,
        contract: Option<&WorkflowExecutionContract>,
        request: Option<&ExecutionRequest>,
        max_attempts: u32,
        generated: Option<&router_types::GeneratedDecisionBinding>,
    ) -> Result<RunSummary> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(existing) = load_opt(&tx, &summary.run_id)? {
            if existing.definition_hash != summary.definition_hash {
                return Err(RuntimeError::Integrity("definition changed"));
            }
            // Nothing was written yet: the proof covers committed rows only.
            let proof = verify_plan_pin(
                &tx,
                &*self.verified()?,
                summary.workflow.as_ref(),
                generated,
            )?;
            drop(tx);
            self.advance(proof)?;
            return Ok(existing);
        }
        let mut initial_generated_pin = None;
        if let Some(binding) = &summary.workflow {
            let contract = contract.ok_or(RuntimeError::Integrity("missing workflow contract"))?;
            let existing: Option<String> = tx
                .query_row(
                    "SELECT contract_hash FROM workflow_instances WHERE instance_id=?1",
                    [&binding.instance_id],
                    |row| row.get(0),
                )
                .optional()?;
            if existing
                .as_ref()
                .is_some_and(|hash| hash != &binding.contract_sha256)
            {
                return Err(RuntimeError::Integrity("execution instance changed"));
            }
            if existing.is_none() {
                tx.execute(
                    "INSERT INTO workflow_instances VALUES(?1,?2,?3)",
                    params![
                        binding.instance_id,
                        binding.contract_sha256,
                        serde_json::to_string(contract)?
                    ],
                )?;
                let pin = plan_pin(generated)?;
                tx.execute(
                    "INSERT INTO workflow_plan_authority VALUES(?1,?2)",
                    params![binding.instance_id, pin],
                )?;
                if generated.is_some() {
                    initial_generated_pin = Some(PlanAuthorityAnchor {
                        schema_version: 1,
                        instance_id: binding.instance_id.clone(),
                        contract_sha256: binding.contract_sha256.clone(),
                        pin,
                    });
                }
            }
            // An existing instance must retain its original pin. Missing data
            // is corruption, never permission to replace the global proposal.
            let previous = workflow_node(&tx, &binding.instance_id, &summary.node_id)?;
            match previous {
                None if binding.generation == 0 => {}
                Some((run, _, _))
                    if run
                        .workflow
                        .as_ref()
                        .is_some_and(|old| old.generation + 1 == binding.generation)
                        && retryable(&run)
                        && workflow_attempts(&tx, &run)? < max_attempts =>
                {
                    // A registered consumer freezes producer generation. A future
                    // coordinator must schedule fallback before reviewing consumers.
                    for (node, execution) in &contract.nodes {
                        if execution.dependencies.contains_key(&summary.node_id)
                            && workflow_node(&tx, &binding.instance_id, node)?.is_some()
                        {
                            return Err(RuntimeError::Invalid(
                                "dependency generation already bound",
                            ));
                        }
                    }
                }
                _ => {
                    return Err(RuntimeError::Invalid(
                        "node generation requires bounded retryable predecessor",
                    ));
                }
            }
        } else if contract.is_some() || generated.is_some() {
            return Err(RuntimeError::Integrity("missing workflow binding"));
        }
        tx.execute(
            "INSERT INTO runs(run_id,plan_id,node_id,summary) VALUES(?1,?2,?3,?4)",
            params![
                summary.run_id,
                summary.plan_id,
                summary.node_id,
                serde_json::to_string(summary)?
            ],
        )?;
        if let Some(binding) = &summary.workflow {
            let request = request.ok_or(RuntimeError::Integrity("missing node identity"))?;
            tx.execute(
                "INSERT INTO workflow_node_runs VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    binding.instance_id,
                    summary.node_id,
                    binding.generation,
                    summary.run_id,
                    serde_json::to_string(&request.model)?,
                    request.agent
                ],
            )?;
        }
        append(&tx, summary, "planned", "")?;
        if let Some(anchor) = initial_generated_pin {
            append(
                &tx,
                summary,
                "workflow.plan.authority.v1",
                &serde_json::to_string(&anchor)?,
            )?;
        }
        // The tail includes this transaction's own events: advance after commit.
        let proof = verify_plan_pin(
            &tx,
            &*self.verified()?,
            summary.workflow.as_ref(),
            generated,
        )?;
        tx.commit()?;
        self.advance(proof)?;
        Ok(summary.clone())
    }
    pub fn get(&self, id: &str) -> Result<RunSummary> {
        load_opt(&*self.lock()?, id)?.ok_or(RuntimeError::NotFound)
    }
    pub fn reserve_declared_artifact(
        &self,
        metadata: &router_types::DeclaredArtifact,
    ) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let run = load_opt(&tx, &metadata.run_id)?.ok_or(RuntimeError::NotFound)?;
        if run.state != RunState::SucceededTransport
            || run.workflow.as_ref() != Some(&metadata.workflow)
            || run.node_id != metadata.node_id
            || run.attempts != metadata.attempt
            || run.artifact_contract_sha256.is_none()
            || metadata.state != router_types::DeclaredArtifactState::Pending
        {
            return Err(RuntimeError::Integrity("declared output authority"));
        }
        tx.execute(
            "INSERT INTO declared_artifacts VALUES(?1,?2,?3,?4,?5,NULL)",
            params![
                metadata.artifact_id,
                metadata.run_id,
                metadata.attempt,
                metadata.label,
                serde_json::to_string(metadata)?
            ],
        )?;
        append(&tx, &run, "artifact.declared", &metadata.artifact_id)?;
        tx.commit()?;
        Ok(())
    }
    pub fn declared_artifact_identity(
        &self,
        id: &str,
        identity: &crate::outputs::FileIdentity,
    ) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if tx.execute(
            "UPDATE declared_artifacts SET identity=?2 WHERE artifact_id=?1 AND identity IS NULL",
            params![id, serde_json::to_string(identity)?],
        )? != 1
        {
            return Err(RuntimeError::Integrity("result identity registration"));
        }
        tx.commit()?;
        Ok(())
    }
    pub fn declared_artifact(
        &self,
        id: &str,
    ) -> Result<(
        router_types::DeclaredArtifact,
        Option<crate::outputs::FileIdentity>,
    )> {
        let value: Option<(String, Option<String>)> = self
            .lock()?
            .query_row(
                "SELECT record,identity FROM declared_artifacts WHERE artifact_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (record, identity) = value.ok_or(RuntimeError::NotFound)?;
        Ok((
            serde_json::from_str(&record)?,
            identity.map(|v| serde_json::from_str(&v)).transpose()?,
        ))
    }
    pub fn declared_artifacts(&self, run: &str) -> Result<Vec<router_types::DeclaredArtifact>> {
        let db = self.lock()?;
        load_opt(&db, run)?.ok_or(RuntimeError::NotFound)?;
        let mut query = db.prepare(
            "SELECT record FROM declared_artifacts WHERE run_id=?1 ORDER BY attempt,label",
        )?;
        let records = query.query_map([run], |r| r.get::<_, String>(0))?;
        records.map(|v| Ok(serde_json::from_str(&v?)?)).collect()
    }
    pub fn declared_artifact_state(
        &self,
        id: &str,
        next: router_types::DeclaredArtifactState,
    ) -> Result<router_types::DeclaredArtifact> {
        use router_types::DeclaredArtifactState::*;
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let record: String = tx.query_row(
            "SELECT record FROM declared_artifacts WHERE artifact_id=?1",
            [id],
            |r| r.get(0),
        )?;
        let mut metadata: router_types::DeclaredArtifact = serde_json::from_str(&record)?;
        if metadata.state != next
            && !matches!(
                (metadata.state, next),
                (Pending, Retained | Purging) | (Retained, Purging) | (Purging, Purged)
            )
        {
            return Err(RuntimeError::Transition);
        }
        metadata.state = next;
        tx.execute(
            "UPDATE declared_artifacts SET record=?2 WHERE artifact_id=?1",
            params![id, serde_json::to_string(&metadata)?],
        )?;
        let run = load_opt(&tx, &metadata.run_id)?.ok_or(RuntimeError::NotFound)?;
        append(
            &tx,
            &run,
            "artifact.state",
            &digest("runtime-declared-artifact-v1", &metadata)?,
        )?;
        tx.commit()?;
        Ok(metadata)
    }
    pub fn reserve_output_artifacts(&self, metadata: &OutputArtifacts) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let run = load_opt(&tx, &metadata.run_id)?.ok_or(RuntimeError::NotFound)?;
        if metadata.state != OutputArtifactsState::Pending
            || metadata.attempt != run.attempts
            || run.output_retention == OutputRetentionPolicy::Disabled
        {
            return Err(RuntimeError::Integrity("output retention authority"));
        }
        tx.execute(
            "INSERT INTO output_artifacts VALUES(?1,?2,?3,?4,?5)",
            params![
                metadata.run_id,
                metadata.attempt,
                i64::try_from(metadata.expires_at_unix_seconds).map_err(|_| RuntimeError::Limit)?,
                "pending",
                serde_json::to_string(metadata)?
            ],
        )?;
        append(
            &tx,
            &run,
            "outputs.pending",
            &digest("runtime-output-artifacts-v1", metadata)?,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn output_artifacts(&self, id: &str) -> Result<Vec<OutputArtifacts>> {
        let db = self.lock()?;
        load_opt(&db, id)?.ok_or(RuntimeError::NotFound)?;
        let mut query = db.prepare(
            "SELECT record FROM output_artifacts WHERE run_id=?1 ORDER BY attempt LIMIT 6",
        )?;
        let records = query
            .query_map([id], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if records.len() > 5 {
            return Err(RuntimeError::Limit);
        }
        records
            .into_iter()
            .map(|record| serde_json::from_str(&record).map_err(Into::into))
            .collect()
    }
    pub fn register_output_file(
        &self,
        id: &str,
        attempt: u32,
        stream: &str,
        identity: &crate::outputs::FileIdentity,
    ) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let run = load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
        tx.execute(
            "INSERT INTO output_files VALUES(?1,?2,?3,?4)",
            params![id, attempt, stream, serde_json::to_string(identity)?],
        )?;
        append(
            &tx,
            &run,
            "outputs.file_owned",
            &digest("runtime-output-file-v1", &(attempt, stream, identity))?,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn output_file_identities(
        &self,
        id: &str,
        attempt: u32,
    ) -> Result<std::collections::BTreeMap<String, crate::outputs::FileIdentity>> {
        let db = self.lock()?;
        let mut query=db.prepare("SELECT stream,identity FROM output_files WHERE run_id=?1 AND attempt=?2 ORDER BY stream LIMIT 3")?;
        let rows = query
            .query_map(params![id, attempt], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if rows.len() > 2 {
            return Err(RuntimeError::Integrity("output files"));
        }
        rows.into_iter()
            .map(|(stream, value)| Ok((stream, serde_json::from_str(&value)?)))
            .collect()
    }
    pub fn expired_output_artifacts(&self, now: u64, limit: usize) -> Result<Vec<OutputArtifacts>> {
        if limit == 0 || limit > 100 {
            return Err(RuntimeError::Limit);
        }
        let db = self.lock()?;
        let mut query=db.prepare("SELECT record FROM output_artifacts WHERE state!='purged' AND expires_at<=?1 ORDER BY expires_at,run_id,attempt LIMIT ?2")?;
        let records = query
            .query_map(
                params![i64::try_from(now).map_err(|_| RuntimeError::Limit)?, limit],
                |row| row.get::<_, String>(0),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        records
            .into_iter()
            .map(|record| serde_json::from_str(&record).map_err(Into::into))
            .collect()
    }
    pub fn output_artifacts_state(
        &self,
        id: &str,
        attempt: u32,
        next: OutputArtifactsState,
    ) -> Result<OutputArtifacts> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let run = load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
        let record: Option<String> = tx
            .query_row(
                "SELECT record FROM output_artifacts WHERE run_id=?1 AND attempt=?2",
                params![id, attempt],
                |row| row.get(0),
            )
            .optional()?;
        let mut metadata: OutputArtifacts =
            serde_json::from_str(&record.ok_or(RuntimeError::NotFound)?)?;
        use OutputArtifactsState::*;
        if metadata.state == next {
            return Ok(metadata);
        }
        if !matches!(
            (metadata.state, next),
            (Pending, Retained | Purging) | (Retained, Purging) | (Purging, Purged)
        ) {
            return Err(RuntimeError::Transition);
        }
        metadata.state = next;
        let state = match next {
            Pending => "pending",
            Retained => "retained",
            Purging => "purging",
            Purged => "purged",
        };
        tx.execute(
            "UPDATE output_artifacts SET state=?3, record=?4 WHERE run_id=?1 AND attempt=?2",
            params![id, attempt, state, serde_json::to_string(&metadata)?],
        )?;
        append(
            &tx,
            &run,
            &format!("outputs.{state}"),
            &digest("runtime-output-artifacts-v1", &metadata)?,
        )?;
        tx.commit()?;
        Ok(metadata)
    }
    pub fn workflow_node(
        &self,
        instance: &str,
        node: &str,
    ) -> Result<Option<(RunSummary, ModelId, Option<String>)>> {
        workflow_node(&*self.lock()?, instance, node)
    }
    pub fn cancel_requested(&self, id: &str) -> Result<bool> {
        Ok(self
            .lock()?
            .query_row(
                "SELECT 1 FROM control_requests WHERE run_id=?1",
                [id],
                |row| row.get::<_, u32>(0),
            )
            .optional()?
            .is_some())
    }
    pub fn transition(
        &self,
        id: &str,
        next: RunState,
        detail: &str,
        failure: Option<RunFailure>,
    ) -> Result<RunSummary> {
        self.transition_inner(id, next, detail, failure, false)
    }
    pub fn transition_queued(
        &self,
        id: &str,
        next: RunState,
        detail: &str,
        failure: Option<RunFailure>,
    ) -> Result<RunSummary> {
        self.transition_inner(id, next, detail, failure, true)
    }
    fn transition_inner(
        &self,
        id: &str,
        next: RunState,
        detail: &str,
        failure: Option<RunFailure>,
        require_queued: bool,
    ) -> Result<RunSummary> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut run = load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
        if require_queued && run.state == RunState::Cancelled {
            return Err(RuntimeError::Cancelled);
        }
        if !run.state.permits(next) || (require_queued && run.state != RunState::Queued) {
            append(
                &tx,
                &run,
                "integrity.invalid_transition",
                &format!("requested:{next:?}"),
            )?;
            tx.commit()?;
            return Err(RuntimeError::Transition);
        }
        apply_transition(&tx, &mut run, next, detail, failure)?;
        tx.commit()?;
        Ok(run)
    }
    /// The verifier's record and the state change it implies commit together:
    /// the state is checked, the record is stored, and the transition (when
    /// `next` is set) is applied in one IMMEDIATE transaction. Only an absent
    /// or inconclusive earlier record can be replaced; a conclusive one is
    /// refused and stays intact.
    pub fn record_verification(
        &self,
        id: &str,
        record: &router_types::VerificationRecord,
        next: Option<(RunState, Option<RunFailure>)>,
    ) -> Result<RunSummary> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut run = load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
        if run.state != RunState::Verifying || record.artifact_sha256 != run.artifact_sha256 {
            return Err(RuntimeError::Verification);
        }
        if next
            .as_ref()
            .is_some_and(|(state, _)| !run.state.permits(*state))
        {
            return Err(RuntimeError::Transition);
        }
        // A conclusive record is never replaced. An inconclusive one may be, so
        // a verifier that could not decide can record again while Verifying.
        let existing: Option<String> = tx
            .query_row(
                "SELECT record FROM verifications WHERE run_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            let old: router_types::VerificationRecord = serde_json::from_str(&existing)?;
            if !is_inconclusive(&old) {
                return Err(RuntimeError::Verification);
            }
        }
        tx.execute(
            "INSERT OR REPLACE INTO verifications VALUES(?1,?2)",
            params![id, serde_json::to_string(record)?],
        )?;
        append(&tx, &run, "verification.recorded", &record.evidence_sha256)?;
        if let Some((state, failure)) = next {
            apply_transition(&tx, &mut run, state, "explicit_verification", failure)?;
        }
        tx.commit()?;
        Ok(run)
    }
    pub fn event(&self, id: &str, kind: &str, detail: &str) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let run = load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
        append(&tx, &run, kind, detail)?;
        tx.commit()?;
        Ok(())
    }
    /// Consumes application authority before any externally visible effect.
    /// An incomplete intent is deliberately never cleared or replayed.
    pub(crate) fn claim_integration(&self, id: &str, detail: &str) -> Result<()> {
        let mut db = self.lock()?;
        let tx = self.verified_transaction(&mut db, rusqlite::TransactionBehavior::Immediate)?;
        let run = load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
        if run.state != RunState::Verified {
            return Err(RuntimeError::Verification);
        }
        if tx.prepare("SELECT 1 FROM events WHERE run_id=?1 AND kind IN ('integration.intent','integration.applied','integration.published')")?.exists([id])? {
            return Err(RuntimeError::Integrity("integration already attempted"));
        }
        append(&tx, &run, "integration.intent", detail)?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn integration_events(&self, id: &str) -> Result<Vec<(String, String)>> {
        let mut db = self.lock()?;
        let tx = self.verified_transaction(&mut db, rusqlite::TransactionBehavior::Deferred)?;
        load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
        let values = tx.prepare("SELECT kind,detail FROM events WHERE run_id=?1 AND kind IN ('integration.intent','integration.published') ORDER BY sequence LIMIT 3")?
            .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        tx.commit()?;
        Ok(values)
    }
    pub fn require_cleanup_complete(&self) -> Result<()> {
        if cleanup_blocked(&*self.lock()?, None)? {
            return Err(RuntimeError::CleanupUnknown);
        }
        Ok(())
    }
    pub fn cleanup_evidence(&self, id: &str) -> Result<router_types::ProcessCleanupEvidence> {
        cleanup_evidence(&*self.lock()?, id)
    }
    #[cfg(test)]
    pub fn attempt(&self, id: &str, max: u32, supervised: bool) -> Result<Option<PathBuf>> {
        self.attempt_with_host_state(id, max, supervised, false)
    }
    pub(crate) fn attempt_with_host_state(
        &self,
        id: &str,
        max: u32,
        supervised: bool,
        host_state: bool,
    ) -> Result<Option<PathBuf>> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut run = load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
        if run.state != RunState::Preparing || workflow_attempts(&tx, &run)? >= max {
            return Err(RuntimeError::Limit);
        }
        if cleanup_blocked(&tx, None)? {
            return Err(RuntimeError::CleanupUnknown);
        }
        preparation::require_complete(&tx, &run)?;
        run.attempts += 1;
        let mut created = None;
        let stored = (|| {
            if supervised {
                let (mut record, path) = match self.create_lease(&tx, id, run.attempts) {
                    Ok(created) => created,
                    Err(error) => {
                        // O_EXCL may have succeeded before a later write or sync
                        // failed. An already existing file is never ours to remove.
                        let already = matches!(
                            &error,
                            RuntimeError::Io(e) if e.kind() == std::io::ErrorKind::AlreadyExists
                        );
                        if !already {
                            self.remove_partial_lease(id, run.attempts);
                        }
                        return Err(error);
                    }
                };
                record.require_namespace(host_state);
                created = Some(path);
                tx.execute(
                    "INSERT INTO attempt_leases(run_id,attempt,record) VALUES(?1,?2,?3)",
                    params![id, run.attempts, serde_json::to_string(&record)?],
                )?;
            }
            tx.execute(
                "INSERT INTO run_attempts VALUES(?1,?2,'started')",
                params![id, run.attempts],
            )?;
            save(&tx, &run)?;
            append(&tx, &run, "attempt.started", "")?;
            tx.commit()?;
            Ok::<(), RuntimeError>(())
        })();
        // The lease file is created before the journal commits. A failed or
        // rolled back attempt must not leave it, or the next attempt with the
        // same number would fail with EEXIST forever. Fail closed: a missing
        // file with a committed record reads as CleanupUnknown.
        if let Err(error) = stored {
            if let Some(path) = created {
                let _ = fs::remove_file(path);
            }
            return Err(error);
        }
        Ok(created)
    }
    /// Creates the lease file. `EEXIST` with no committed row for the pair is
    /// the residue of a crash between the file create and the journal commit
    /// of an earlier try; it is reclaimed once, only when provably unbound and
    /// unused. Every other existing file keeps the refusal.
    fn create_lease(
        &self,
        tx: &Transaction<'_>,
        id: &str,
        attempt: u32,
    ) -> Result<(LeaseRecord, PathBuf)> {
        match self.leases.create(id, attempt) {
            Err(RuntimeError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let bound = tx
                    .prepare("SELECT 1 FROM attempt_leases WHERE run_id=?1 AND attempt=?2")?
                    .exists(params![id, attempt])?;
                // Any doubt or failure while reclaiming keeps the original
                // refusal, so the caller never treats the file as its own.
                if bound || !matches!(self.leases.reclaim_uncommitted(id, attempt), Ok(true)) {
                    return Err(RuntimeError::Io(e));
                }
                append(
                    tx,
                    &load_opt(tx, id)?.ok_or(RuntimeError::NotFound)?,
                    "attempt.lease_orphan_reclaimed",
                    &attempt.to_string(),
                )?;
                self.leases.create(id, attempt)
            }
            other => other,
        }
    }
    /// Best effort removal of a lease file left by a failed `LeaseStorage::create`,
    /// only when it is a single-link regular file of this user.
    fn remove_partial_lease(&self, id: &str, attempt: u32) {
        let Ok(digest) = digest("runtime-lease-v1", &(id, attempt)) else {
            return;
        };
        remove_owned_regular_file(&self.root.join("leases").join(format!("{digest}.lease")));
    }
    #[cfg(test)]
    pub fn confirm_attempt_cleanup(&self, id: &str) -> Result<()> {
        self.confirm_attempt_cleanup_and_state(id, None)
    }
    pub(crate) fn confirm_attempt_cleanup_and_state(
        &self,
        id: &str,
        state: Option<crate::HostState>,
    ) -> Result<()> {
        self.confirm_attempt_cleanup_and_state_observed(id, state, |_, _| Ok(()))
    }
    /// Runs a bounded observation under the exact cleanup lease and store
    /// transaction, before disposing the private owner or settling authority.
    pub(crate) fn confirm_attempt_cleanup_and_state_observed<F>(
        &self,
        id: &str,
        state: Option<crate::HostState>,
        observe: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut crate::HostState, &crate::leases::CleanupProof) -> Result<()>,
    {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let run = load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
        let record: Option<String> = tx
            .query_row(
                "SELECT record FROM attempt_leases WHERE run_id=?1 AND attempt=?2",
                params![id, run.attempts],
                |r| r.get(0),
            )
            .optional()?;
        if record.is_none() && state.is_none() {
            return Ok(());
        }
        let proof = record
            .ok_or(RuntimeError::CleanupUnknown)
            .and_then(|record| {
                serde_json::from_str::<LeaseRecord>(&record)
                    .map_err(|_| RuntimeError::CleanupUnknown)
            })
            .and_then(|mut record| {
                let proof = self.leases.cleanup_proof(id, run.attempts, &record)?;
                if record.needs_host_cleanup() && state.is_none() {
                    return Err(RuntimeError::CleanupUnknown);
                }
                if let Some(mut state) = state {
                    observe(&mut state, &proof)?;
                    state.cleanup_with_proof(&proof)?;
                    record.host_state_cleaned();
                    tx.execute(
                        "UPDATE attempt_leases SET record=?3 WHERE run_id=?1 AND attempt=?2",
                        params![id, run.attempts, serde_json::to_string(&record)?],
                    )?;
                }
                Ok(proof)
            });
        match proof {
            Ok(proof) => {
                let evidence = serde_json::to_string(&proof.evidence)?;
                tx.execute("UPDATE attempt_leases SET resolved=1,evidence=?3 WHERE run_id=?1 AND attempt=?2",params![id,run.attempts,evidence])?;
                append(&tx, &run, "process.cleanup_confirmed", &evidence)?;
                tx.commit()?;
                Ok(())
            }
            Err(_) => {
                tx.execute("INSERT OR IGNORE INTO cleanup_blocks VALUES(?1)", [id])?;
                append(&tx, &run, "process.cleanup_unknown", "authority_retained")?;
                tx.commit()?;
                Err(RuntimeError::CleanupUnknown)
            }
        }
    }
    pub fn finish_attempt(&self, id: &str, status: &str) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let run = load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
        tx.execute(
            "UPDATE run_attempts SET status=?3 WHERE run_id=?1 AND attempt=?2",
            params![id, run.attempts, status],
        )?;
        append(&tx, &run, "attempt.finished", status)?;
        tx.commit()?;
        Ok(())
    }
    /// Re-arms the run for a fresh approval. With `expected`, it refuses inside
    /// the same transaction (and persists nothing) when the resulting approval
    /// digest is not the one the caller approved.
    pub fn retry_expecting(&self, id: &str, max: u32, expected: Option<&str>) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let run = retry_projection(retry_guard(&tx, id, max)?)?;
        if expected.is_some_and(|digest| digest != run.approval_digest) {
            return Err(RuntimeError::Approval);
        }
        tx.execute("DELETE FROM control_requests WHERE run_id=?1", [id])?;
        save(&tx, &run)?;
        append(&tx, &run, "retry.awaiting_fresh_approval", "")?;
        tx.commit()?;
        Ok(())
    }
    /// The run exactly as `retry_expecting` would persist it, with the same guards and the
    /// same approval digest, without writing anything.
    pub fn retry_preview(&self, id: &str, max: u32) -> Result<RunSummary> {
        let db = self.lock()?;
        retry_projection(retry_guard(&db, id, max)?)
    }

    /// Workspaces and scopes are compared after LEXICAL normalization only:
    /// repeated or trailing slashes and `.` components. Symlinked workspaces or
    /// nested ones (`/repo` vs `/repo/sub`) are not detected, as before. `..` is
    /// refused. A `writer_locks` row persisted with `..` in its workspace (written
    /// by an older build) now makes every new `writer_lock` fail with
    /// `Integrity("writer lock workspace")` until that row is released.
    pub fn writer_lock(&self, id: &str, workspace: &str, scope: &[String]) -> Result<()> {
        let workspace = lexical_path(workspace).ok_or(RuntimeError::Scope)?;
        if scope.iter().any(|entry| lexical_path(entry).is_none()) {
            return Err(RuntimeError::Scope);
        }
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut query = tx.prepare("SELECT workspace,scope FROM writer_locks WHERE run_id<>?1")?;
        let rows = query
            .query_map(params![id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (other_workspace, other) in rows {
            let other_workspace = lexical_path(&other_workspace)
                .ok_or(RuntimeError::Integrity("writer lock workspace"))?;
            if other_workspace != workspace {
                continue;
            }
            let other: Vec<String> = serde_json::from_str(&other)?;
            if scope.iter().any(|a| other.iter().any(|b| overlaps(a, b))) {
                return Err(RuntimeError::Scope);
            }
        }
        drop(query);
        tx.execute(
            "INSERT OR REPLACE INTO writer_locks VALUES(?1,?2,?3)",
            params![id, workspace, serde_json::to_string(scope)?],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn worktree(&self, id: &str, path: Option<&str>) -> Result<()> {
        self.mutate(id, "worktree", |run| {
            run.worktree = path.map(str::to_owned);
        })
    }
    pub fn artifact(&self, id: &str, hash: &str) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut run = load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
        run.artifact_sha256 = Some(hash.into());
        tx.execute(
            "INSERT OR REPLACE INTO artifacts VALUES(?1,?2,'patch')",
            params![id, hash],
        )?;
        save(&tx, &run)?;
        append(&tx, &run, "artifact", hash)?;
        tx.commit()?;
        Ok(())
    }
    pub fn verification_record(
        &self,
        id: &str,
    ) -> Result<Option<router_types::VerificationRecord>> {
        let db = self.lock()?;
        load_opt(&db, id)?.ok_or(RuntimeError::NotFound)?;
        let value: Option<String> = db
            .query_row(
                "SELECT record FROM verifications WHERE run_id=?1",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        value.map(|v| Ok(serde_json::from_str(&v)?)).transpose()
    }
    fn mutate(&self, id: &str, kind: &str, f: impl FnOnce(&mut RunSummary)) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut run = load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
        f(&mut run);
        save(&tx, &run)?;
        append(&tx, &run, kind, "")?;
        tx.commit()?;
        Ok(())
    }
    pub fn events(&self) -> Result<Vec<RuntimeEvent>> {
        read_events(&*self.lock()?)
    }
    /// Whether `run_id` recorded one event of this kind and detail, without
    /// materializing the whole event log.
    pub fn has_event(&self, run_id: &str, kind: &str, detail: &str) -> Result<bool> {
        Ok(self
            .lock()?
            .prepare("SELECT 1 FROM events WHERE run_id=?1 AND kind=?2 AND detail=?3")?
            .exists(params![run_id, kind, detail])?)
    }
    /// Writes through the real `append` in one transaction, so a test can
    /// cross a row cap without thousands of synchronous commits.
    #[cfg(test)]
    pub(crate) fn append_events_for_test(&self, id: &str, count: usize) {
        let mut db = self.lock().unwrap();
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let run = load_opt(&tx, id).unwrap().unwrap();
        for _ in 0..count {
            append(&tx, &run, "test.event", "").unwrap();
        }
        tx.commit().unwrap();
    }
    /// Full replay of the chain. It must extend the owner's trust point
    /// before it replaces it.
    pub fn verify_events(&self) -> Result<()> {
        let db = self.lock()?;
        // One read snapshot: the new point is the last row this replay saw.
        let tx = db.unchecked_transaction()?;
        let replayed = verify_chain(&tx, &mut 0)?;
        let mut verified = self.verified()?;
        // A consistent replay can still be a recomputed rewrite, or a
        // truncation below the point: the verified row must keep its hash.
        if verified.point.sequence > 0 {
            let hash: Option<String> = tx
                .query_row(
                    "SELECT event_hash FROM events WHERE sequence=?1",
                    [verified.point.sequence],
                    |r| r.get(0),
                )
                .optional()?;
            if hash.as_deref() != Some(verified.point.hash.as_str()) {
                return Err(RuntimeError::Integrity("event chain"));
            }
        }
        if verified
            .anchors
            .iter()
            .any(|(instance, anchor)| replayed.anchors.get(instance) != Some(anchor))
        {
            return Err(RuntimeError::Integrity("workflow plan authority changed"));
        }
        drop(tx);
        *verified = replayed;
        Ok(())
    }
    fn recover(&self) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let values = {
            let mut q = tx.prepare("SELECT summary FROM runs ORDER BY run_id")?;
            q.query_map([], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut cleanup_locks = Vec::new();
        for value in values {
            let mut run: RunSummary = serde_json::from_str(&value)?;
            if matches!(run.state, RunState::Preparing | RunState::Running)
                || cleanup_blocked(&tx, Some(&run.run_id))?
            {
                let lease: Option<(String, bool)> = tx
                    .query_row(
                        "SELECT record,resolved FROM attempt_leases WHERE run_id=?1 AND attempt=?2",
                        params![run.run_id, run.attempts],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                let preparation_safe = preparation::recover(self, &tx, &run, &mut cleanup_locks)?;
                let model_safe = if let Some((record, resolved)) = lease {
                    if resolved {
                        true
                    } else {
                        match serde_json::from_str::<LeaseRecord>(&record)
                            .ok()
                            .and_then(|record| {
                                self.leases
                                    .recovery_proof(&run.run_id, run.attempts, &record)
                                    .ok()
                            }) {
                            Some(lock) => {
                                tx.execute("UPDATE attempt_leases SET resolved=1,evidence=?3 WHERE run_id=?1 AND attempt=?2",params![run.run_id,run.attempts,serde_json::to_string(&lock.evidence)?])?;
                                cleanup_locks.push(lock);
                                true
                            }
                            None => false,
                        }
                    }
                } else {
                    // No new model was launched in this preparation. The
                    // cycle gate separately proves every earlier child.
                    preparation::no_model_started(&tx, &run)?
                };
                let safe =
                    preparation_safe && model_safe && admission::finalization_safe(&tx, &run)?;
                let interrupted = matches!(run.state, RunState::Preparing | RunState::Running);
                if interrupted {
                    run.state = RunState::Failed;
                    run.failure = Some(RunFailure::Interrupted);
                    save(&tx, &run)?;
                }
                if interrupted || safe {
                    append(
                        &tx,
                        &run,
                        "recovery.interrupted",
                        if safe {
                            "cleanup_confirmed_no_replay"
                        } else {
                            "cleanup_unknown_authority_retained"
                        },
                    )?;
                }
                if safe {
                    tx.execute("DELETE FROM writer_locks WHERE run_id=?1", [&run.run_id])?;
                    tx.execute("DELETE FROM cleanup_blocks WHERE run_id=?1", [&run.run_id])?;
                } else {
                    tx.execute(
                        "INSERT OR IGNORE INTO cleanup_blocks VALUES(?1)",
                        [&run.run_id],
                    )?;
                }
            } else if run.state == RunState::SucceededTransport {
                run.state = RunState::Verifying;
                save(&tx, &run)?;
                append(&tx, &run, "recovery.verification_required", "")?;
            }
        }
        tx.commit()?;
        drop(cleanup_locks);
        Ok(())
    }
}
/// Neither a pass on both axes nor a failure on either: no state change.
fn is_inconclusive(record: &router_types::VerificationRecord) -> bool {
    use router_types::VerificationOutcome::{Failed, Passed};
    !(record.validation == Passed && record.objective == Passed)
        && record.validation != Failed
        && record.objective != Failed
}
/// The permitted-transition body shared by every state change: the caller has
/// already checked `permits` inside the transaction it commits.
fn apply_transition(
    tx: &Transaction<'_>,
    run: &mut RunSummary,
    next: RunState,
    detail: &str,
    failure: Option<RunFailure>,
) -> Result<()> {
    let id = run.run_id.clone();
    run.state = next;
    run.failure = failure;
    save(tx, run)?;
    append(tx, run, "transition", detail)?;
    if next.terminal()
        && ((!preparation::terminal_safe(tx, run)? || !admission::finalization_safe(tx, run)?)
            || tx
                .prepare("SELECT 1 FROM attempt_leases WHERE run_id=?1 AND resolved=0")?
                .exists([&id])?)
    {
        tx.execute("INSERT OR IGNORE INTO cleanup_blocks VALUES(?1)", [&id])?;
    }
    if next.terminal() && !cleanup_blocked(tx, Some(&id))? {
        tx.execute("DELETE FROM writer_locks WHERE run_id=?1", [&id])?;
    }
    Ok(())
}
fn cleanup_blocked(db: &Connection, id: Option<&str>) -> Result<bool> {
    Ok(match id {
        Some(id) => db
            .prepare("SELECT 1 FROM cleanup_blocks WHERE run_id=?1")?
            .exists([id])?,
        None => db
            .prepare("SELECT 1 FROM cleanup_blocks LIMIT 1")?
            .exists([])?,
    })
}
fn load_opt(db: &Connection, id: &str) -> Result<Option<RunSummary>> {
    let text: Option<String> = db
        .query_row("SELECT summary FROM runs WHERE run_id=?1", [id], |r| {
            r.get(0)
        })
        .optional()?;
    Ok(text.map(|value| serde_json::from_str(&value)).transpose()?)
}
fn save(tx: &Transaction<'_>, run: &RunSummary) -> Result<()> {
    tx.execute(
        "UPDATE runs SET summary=?2 WHERE run_id=?1",
        params![run.run_id, serde_json::to_string(run)?],
    )?;
    Ok(())
}
fn append(tx: &Transaction<'_>, run: &RunSummary, kind: &str, detail: &str) -> Result<()> {
    let max_detail = if matches!(
        kind,
        "attempt.evidence.v1"
            | "attempt.bound.v1"
            | "escalation.claim.v1"
            | "preparation.cycle.v1"
            | "admission.intent.v1"
    ) {
        16_384
    } else {
        2048
    };
    if detail.len() > max_detail || kind.len() > 128 {
        return Err(RuntimeError::Limit);
    }
    let (sequence, previous_hash): (u64, String) = tx
        .query_row(
            "SELECT sequence,event_hash FROM events ORDER BY sequence DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .unwrap_or((0, String::new()));
    let mut event = RuntimeEvent {
        sequence: sequence + 1,
        run_id: run.run_id.clone(),
        kind: kind.into(),
        state: run.state,
        detail: detail.into(),
        previous_hash,
        event_hash: String::new(),
    };
    event.event_hash = event_digest(&event)?;
    tx.execute(
        "INSERT INTO events VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            event.sequence,
            event.run_id,
            event.kind,
            serde_json::to_string(&event.state)?,
            event.detail,
            event.previous_hash,
            event.event_hash
        ],
    )?;
    Ok(())
}
fn event_digest(event: &RuntimeEvent) -> Result<String> {
    digest(
        "runtime-event-v1",
        &(
            event.sequence,
            &event.run_id,
            &event.kind,
            event.state,
            &event.detail,
            &event.previous_hash,
        ),
    )
}
fn remove_owned_regular_file(path: &Path) {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    // Ownership is judged against the private lease directory holding the file.
    let owner = path
        .parent()
        .and_then(|dir| fs::symlink_metadata(dir).ok())
        .map(|dir| dir.uid());
    if meta.is_file() && meta.nlink() == 1 && owner == Some(meta.uid()) {
        let _ = fs::remove_file(path);
    }
}
/// Lexical normal form: repeated and trailing slashes and `.` components
/// vanish. `..` cannot be resolved without the filesystem, so it is refused.
fn lexical_path(path: &str) -> Option<String> {
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => return None,
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    Some(if path.starts_with('/') {
        format!("/{joined}")
    } else {
        joined
    })
}
/// Component-wise overlap: equal paths or one an ancestor of the other, after
/// lexical normalization. A path that cannot be normalized overlaps everything.
pub(crate) fn overlaps(a: &str, b: &str) -> bool {
    let (Some(a), Some(b)) = (lexical_path(a), lexical_path(b)) else {
        return true;
    };
    let a: Vec<_> = a.split('/').filter(|p| !p.is_empty()).collect();
    let b: Vec<_> = b.split('/').filter(|p| !p.is_empty()).collect();
    let shared = a.len().min(b.len());
    a[..shared] == b[..shared]
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
        return Err(RuntimeError::Invalid("private regular file"));
    }
    Ok(())
}

pub(crate) fn private_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.permissions().mode() & 0o077 != 0 {
        return Err(RuntimeError::Invalid("private regular file"));
    }
    Ok(file)
}

/// Inventory the existing durable attempts without acquiring ownership, recovery,
/// schema migration or writing feedback. All reads and chain verification share
/// one transaction. SQLite may create private WAL/SHM coordination files.
/// The ceiling bounds memory and verification work explicitly.
pub fn measurement_inventory(root: &Path) -> Result<router_types::FeedbackRuntimeInventory> {
    use router_types::{FeedbackRuntimeInventory, FeedbackRuntimeRun};
    use std::collections::{BTreeMap, BTreeSet};
    const MAX_RUNS: usize = 10_000;
    const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
    let mut db = control_connection(root, false)?;
    let tx = db.transaction()?;
    let (count, bytes): (usize, u64) = tx.query_row(
        "SELECT COUNT(*),COALESCE(SUM(length(CAST(summary AS BLOB))),0) FROM runs",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (event_count, event_bytes): (usize, u64) = tx.query_row(
        "SELECT COUNT(*),COALESCE(SUM(length(CAST(detail AS BLOB))+length(run_id)+length(kind)+256),0) FROM events", [],
        |row| Ok((row.get(0)?, row.get(1)?)))?;
    if count > MAX_RUNS
        || bytes > MAX_JOURNAL_BYTES
        || event_count > 100_000
        || event_bytes > MAX_JOURNAL_BYTES
    {
        return Err(RuntimeError::Limit);
    }
    let attempt_count: usize =
        tx.query_row("SELECT COUNT(*) FROM run_attempts", [], |row| row.get(0))?;
    if attempt_count > MAX_RUNS * 5 {
        return Err(RuntimeError::Limit);
    }
    verify_events(&tx)?;
    let events = read_events(&tx)?;
    let mut query = tx.prepare("SELECT summary FROM runs ORDER BY run_id")?;
    let runs = query
        .query_map([], |row| row.get::<_, String>(0))?
        .map(|row| Ok(serde_json::from_str::<RunSummary>(&row?)?))
        .collect::<Result<Vec<_>>>()?;
    drop(query);
    let by_id: BTreeMap<_, _> = runs.iter().map(|run| (run.run_id.as_str(), run)).collect();
    let mut predecessors = BTreeMap::new();
    let mut starts: BTreeMap<&str, u32> = BTreeMap::new();
    let mut last_states = BTreeMap::new();
    let mut initial_source_states = BTreeMap::new();
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Claim {
        decision_id: String,
        target_run_id: String,
        target_definition_hash: String,
    }
    for event in &events {
        let source = by_id
            .get(event.run_id.as_str())
            .ok_or(RuntimeError::Integrity("measurement run missing"))?;
        last_states.insert(event.run_id.as_str(), event.state);
        if event.kind == "attempt.evidence.v1" {
            let evidence: router_types::AttemptEvidence = serde_json::from_str(&event.detail)?;
            if evidence.identity.run_id != source.run_id
                || evidence.definition_hash != source.definition_hash
            {
                return Err(RuntimeError::Integrity("measurement attempt binding"));
            }
            if let Some(prior) =
                initial_source_states.insert(source.run_id.as_str(), evidence.source_state.clone())
            {
                if prior != evidence.source_state {
                    return Err(RuntimeError::Integrity("measurement source changed"));
                }
            }
        }
        if event.kind == "attempt.started" {
            *starts.entry(event.run_id.as_str()).or_default() += 1;
        }
        if event.kind == "escalation.claim.v1" {
            let claim: Claim = serde_json::from_str(&event.detail)?;
            let target = by_id
                .get(claim.target_run_id.as_str())
                .ok_or(RuntimeError::Integrity("measurement orphan escalation"))?;
            if claim.decision_id != target.receipt_id
                || claim.target_definition_hash != target.definition_hash
                || source.plan_id != target.plan_id
                || source.node_id != target.node_id
                || predecessors
                    .insert(target.run_id.as_str(), source.run_id.as_str())
                    .is_some()
            {
                return Err(RuntimeError::Integrity("measurement escalation lineage"));
            }
        }
    }
    let run_key = |run: &RunSummary| -> Result<String> {
        Ok(router_adapter_api::content_digest(&serde_json::to_vec(&(
            &run.run_id,
            &run.definition_hash,
            &run.approval_digest,
        ))?))
    };
    let mut projected = Vec::new();
    for run in &runs {
        let mut query = tx
            .prepare("SELECT attempt FROM run_attempts WHERE run_id=?1 ORDER BY attempt LIMIT 7")?;
        let ordinals = query
            .query_map([&run.run_id], |row| row.get::<_, u32>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if ordinals.len() > 5
            || run.attempts as usize != ordinals.len()
            || ordinals.iter().copied().ne(1..=run.attempts)
            || starts.get(run.run_id.as_str()).copied().unwrap_or(0) != run.attempts
            || last_states.get(run.run_id.as_str()) != Some(&run.state)
        {
            return Err(RuntimeError::Integrity("measurement attempts"));
        }
        let mut ancestor = run.run_id.as_str();
        let mut seen = BTreeSet::new();
        while let Some(parent) = predecessors.get(ancestor) {
            if !seen.insert(ancestor) || seen.len() > 6 {
                return Err(RuntimeError::Integrity(
                    "measurement lineage cycle or limit",
                ));
            }
            ancestor = parent;
        }
        let occurrence = match &run.workflow {
            Some(binding) => digest(
                "feedback-workflow-occurrence-v1",
                &(&binding.instance_id, &run.node_id),
            )?,
            None => digest(
                "feedback-run-occurrence-v1",
                &(&by_id[ancestor].run_id, &by_id[ancestor].definition_hash),
            )?,
        };
        let mut aliases = BTreeSet::from([run_key(run)?]);
        if let Some(source_state) = initial_source_states.get(run.run_id.as_str()) {
            let mut original = run.clone();
            original.approval_digest = digest(
                "runtime-approval-v1",
                &(&run.run_id, &run.definition_hash, source_state),
            )?;
            aliases.insert(run_key(&original)?);
        }
        // These identities recover historical joins, never historical usage.
        for ordinal in 2..=run.attempts {
            let mut retry = run.clone();
            retry.approval_digest = digest(
                "runtime-retry-approval-v1",
                &(&run.run_id, &run.definition_hash, ordinal - 1),
            )?;
            aliases.insert(run_key(&retry)?);
        }
        projected.push(FeedbackRuntimeRun {
            feedback_run_keys_sha256: aliases.into_iter().collect(),
            run_key_sha256: run_key(run)?,
            occurrence_sha256: occurrence,
            predecessor_run_key_sha256: predecessors
                .get(run.run_id.as_str())
                .map(|id| run_key(by_id[id]))
                .transpose()?,
            attempts: run.attempts,
            state: run.state,
        });
    }
    if projected
        .iter()
        .map(|run| run.attempts as usize)
        .sum::<usize>()
        != attempt_count
    {
        return Err(RuntimeError::Integrity("measurement orphan attempt"));
    }
    let journal_sha256 = digest(
        "feedback-runtime-inventory-v1",
        &(&projected, events.last().map(|event| &event.event_hash)),
    )?;
    tx.commit()?;
    Ok(FeedbackRuntimeInventory {
        schema_version: 1,
        journal_sha256,
        runs: projected,
    })
}

/// Observation/control deliberately does not acquire the supervision flock.
/// Control is a durable request; only the live owner may signal its own child.
pub fn observe(root: &Path, id: &str) -> Result<RunSummary> {
    let db = control_connection(root, false)?;
    verify_events(&db)?;
    load_opt(&db, id)?.ok_or(RuntimeError::NotFound)
}
/// Read-only evidence inspection is available while the supervision owner runs.
pub fn observe_cleanup(root: &Path, id: &str) -> Result<router_types::ProcessCleanupEvidence> {
    let db = control_connection(root, false)?;
    verify_events(&db)?;
    cleanup_evidence(&db, id)
}
fn cleanup_evidence(db: &Connection, id: &str) -> Result<router_types::ProcessCleanupEvidence> {
    let run = load_opt(db, id)?.ok_or(RuntimeError::NotFound)?;
    if db.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))? < 6 {
        return Ok(router_types::ProcessCleanupEvidence::Unknown);
    }
    if cleanup_blocked(db, Some(id))?
        || (db.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))? >= 8
            && !preparation::terminal_safe(db, &run)?)
        || (db.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))? >= 9
            && !admission::finalization_safe(db, &run)?)
    {
        return Ok(router_types::ProcessCleanupEvidence::Unknown);
    }
    let evidence: Option<Option<String>> = db
        .query_row(
            "SELECT evidence FROM attempt_leases WHERE run_id=?1 AND attempt=?2",
            params![id, run.attempts],
            |r| r.get(0),
        )
        .optional()?;
    Ok(match evidence.flatten() {
        Some(value) => serde_json::from_str(&value)?,
        None => router_types::ProcessCleanupEvidence::Unknown,
    })
}
pub fn observe_events(root: &Path, id: &str) -> Result<Vec<RuntimeEvent>> {
    let db = control_connection(root, false)?;
    verify_events(&db)?;
    load_opt(&db, id)?.ok_or(RuntimeError::NotFound)?;
    Ok(read_events(&db)?
        .into_iter()
        .filter(|event| event.run_id == id)
        .collect())
}
pub fn request_cancel(root: &Path, id: &str) -> Result<()> {
    let mut db = control_connection(root, true)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    verify_events(&tx)?;
    let mut run = load_opt(&tx, id)?.ok_or(RuntimeError::NotFound)?;
    if run.state == RunState::Cancelled {
        return Ok(());
    }
    if !matches!(
        run.state,
        RunState::Planned
            | RunState::AwaitingApproval
            | RunState::Queued
            | RunState::Preparing
            | RunState::Running
    ) {
        return Err(RuntimeError::Transition);
    }
    if tx.execute("INSERT OR IGNORE INTO control_requests VALUES(?1,1)", [id])? > 0 {
        append(&tx, &run, "control.cancel_requested", "")?;
    }
    if matches!(
        run.state,
        RunState::Planned | RunState::AwaitingApproval | RunState::Queued
    ) {
        run.state = RunState::Cancelled;
        run.failure = None;
        save(&tx, &run)?;
        tx.execute("DELETE FROM writer_locks WHERE run_id=?1", [id])?;
        append(&tx, &run, "control.cancelled_before_start", "")?;
    }
    tx.commit()?;
    Ok(())
}
fn control_connection(root: &Path, writable: bool) -> Result<Connection> {
    let root_meta = fs::symlink_metadata(root)?;
    let path = root.join("runtime.sqlite3");
    let meta = fs::symlink_metadata(&path)?;
    if !root.is_absolute()
        || !root_meta.is_dir()
        || root_meta.file_type().is_symlink()
        || root_meta.permissions().mode() & 0o077 != 0
        || !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err(RuntimeError::Invalid("private storage"));
    }
    let flags = if writable {
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let db = Connection::open_with_flags(path, flags)?;
    db.busy_timeout(std::time::Duration::from_secs(2))?;
    if !matches!(
        db.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))?,
        2..=SCHEMA_VERSION
    ) {
        return Err(RuntimeError::Integrity("control schema"));
    }
    Ok(db)
}

fn event_from_row(r: &rusqlite::Row<'_>) -> Result<RuntimeEvent> {
    Ok(RuntimeEvent {
        sequence: r.get(0)?,
        run_id: r.get(1)?,
        kind: r.get(2)?,
        state: serde_json::from_str(&r.get::<_, String>(3)?)?,
        detail: r.get(4)?,
        previous_hash: r.get(5)?,
        event_hash: r.get(6)?,
    })
}
fn read_events(db: &Connection) -> Result<Vec<RuntimeEvent>> {
    let mut q=db.prepare("SELECT sequence,run_id,kind,state,detail,previous_hash,event_hash FROM events ORDER BY sequence")?;
    let mut rows = q.query([])?;
    let mut events = Vec::new();
    while let Some(row) = rows.next()? {
        events.push(event_from_row(row)?);
    }
    Ok(events)
}
#[cfg(test)]
thread_local! {
    static VERIFIED_ROWS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
/// Test-only count of event rows read by chain verification on this thread.
fn count_verified_row() {
    #[cfg(test)]
    VERIFIED_ROWS.with(|rows| rows.set(rows.get() + 1));
}
fn verify_events(db: &Connection) -> Result<()> {
    verify_chain(db, &mut 0).map(drop)
}
pub(crate) fn verify_diagnostic_events(db: &Connection, queries: &mut usize) -> Result<()> {
    verify_chain(db, queries).map(drop)
}
const EVENT_COLUMNS: &str =
    "SELECT sequence,run_id,kind,state,detail,previous_hash,event_hash FROM events";
/// Full replay from the first event. Returns the last verified event and the
/// plan authority anchors, so the owner can continue from there.
fn verify_chain(db: &Connection, queries: &mut usize) -> Result<VerifiedChain> {
    *queries += 1;
    let mut q = db.prepare(&format!("{EVENT_COLUMNS} ORDER BY sequence"))?;
    let point = verify_rows(q.query([])?, ChainPoint::default(), None)?;
    drop(q);
    // Older schemas have no generated authority. Their legacy records remain
    // readable; the v7 migration never infers a generated pin from mutable data.
    *queries += 1;
    let anchors = if db.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))? >= 7 {
        verify_authority_pins(db, queries)?
    } else {
        std::collections::BTreeMap::new()
    };
    Ok(VerifiedChain { point, anchors })
}
/// Rows are verified as they stream out of SQLite: no row count is refused
/// and memory stays constant. Work is bounded by the caller's snapshot size.
fn verify_rows(
    mut rows: rusqlite::Rows<'_>,
    mut point: ChainPoint,
    mut anchors: Option<&mut Vec<PlanAuthorityAnchor>>,
) -> Result<ChainPoint> {
    while let Some(row) = rows.next()? {
        count_verified_row();
        let event = event_from_row(row)?;
        if Some(event.sequence) != point.sequence.checked_add(1)
            || event.previous_hash != point.hash
            || event.event_hash != event_digest(&event)?
        {
            return Err(RuntimeError::Integrity("event chain"));
        }
        if event.kind == AUTHORITY_ANCHOR {
            if let Some(anchors) = anchors.as_deref_mut() {
                anchors.push(parse_anchor(&event.detail)?);
            }
        }
        point = ChainPoint {
            sequence: event.sequence,
            hash: event.event_hash,
        };
    }
    Ok(point)
}
/// Verifies only what follows the owner's trust point. The trust point row is
/// reread and rehashed, so rewriting it or truncating through it fails, and
/// the chain start is checked so rows cannot be slipped in before sequence 1.
/// Rows before the trust point are not reread: see ADR 0018.
fn verify_tail(db: &Connection, verified: &VerifiedChain) -> Result<ChainProof> {
    let base = &verified.point;
    if base.sequence > 0 {
        let mut q = db.prepare(&format!("{EVENT_COLUMNS} WHERE sequence=?1"))?;
        let mut rows = q.query([base.sequence])?;
        let Some(row) = rows.next()? else {
            return Err(RuntimeError::Integrity("event chain"));
        };
        count_verified_row();
        let event = event_from_row(row)?;
        if event.event_hash != base.hash || event_digest(&event)? != base.hash {
            return Err(RuntimeError::Integrity("event chain"));
        }
    }
    let first: Option<i64> = db.query_row("SELECT min(sequence) FROM events", [], |r| r.get(0))?;
    if first.is_some_and(|first| first != 1) {
        return Err(RuntimeError::Integrity("event chain"));
    }
    let mut anchors = Vec::new();
    let mut q = db.prepare(&format!(
        "{EVENT_COLUMNS} WHERE sequence>?1 ORDER BY sequence"
    ))?;
    let point = verify_rows(q.query([base.sequence])?, base.clone(), Some(&mut anchors))?;
    for (index, anchor) in anchors.iter().enumerate() {
        if verified.anchors.contains_key(&anchor.instance_id)
            || anchors[..index]
                .iter()
                .any(|other| other.instance_id == anchor.instance_id)
        {
            return Err(RuntimeError::Integrity("workflow plan authority anchor"));
        }
        // The full replay refuses an anchor without its matching instance.
        verify_instance_authority(db, &anchor.instance_id, Some(anchor))?;
    }
    Ok(ChainProof {
        base: base.sequence,
        point,
        anchors,
    })
}

#[derive(Clone, Default)]
struct ChainPoint {
    sequence: u64,
    hash: String,
}
/// The last event the flock owner has verified, with the plan authority
/// anchors recorded up to it. Observers have no such point.
#[derive(Default)]
struct VerifiedChain {
    point: ChainPoint,
    anchors: std::collections::BTreeMap<String, PlanAuthorityAnchor>,
}
/// A verified tail not yet applied to the owner's `VerifiedChain`. Apply it
/// only once every row it covers is committed.
struct ChainProof {
    base: u64,
    point: ChainPoint,
    anchors: Vec<PlanAuthorityAnchor>,
}

const AUTHORITY_ANCHOR: &str = "workflow.plan.authority.v1";

#[derive(PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanAuthorityAnchor {
    schema_version: u8,
    instance_id: String,
    contract_sha256: String,
    pin: String,
}

fn parse_anchor(detail: &str) -> Result<PlanAuthorityAnchor> {
    if detail.len() > 2048 {
        return Err(RuntimeError::Limit);
    }
    let anchor: PlanAuthorityAnchor = serde_json::from_str(detail)
        .map_err(|_| RuntimeError::Integrity("workflow plan authority anchor"))?;
    if anchor.schema_version != 1
        || anchor.pin == "legacy"
        || !router_adapter_api::is_digest(&anchor.pin)
        || !router_adapter_api::is_digest(&anchor.contract_sha256)
    {
        return Err(RuntimeError::Integrity("workflow plan authority anchor"));
    }
    Ok(anchor)
}
/// One workflow instance row against its event anchor.
fn authority_matches(
    contract: &str,
    pin: Option<&str>,
    anchor: Option<&PlanAuthorityAnchor>,
) -> bool {
    match (pin, anchor) {
        (Some("legacy"), None) => true,
        (Some(pin), Some(anchor)) => pin == anchor.pin && contract == anchor.contract_sha256,
        _ => false,
    }
}
/// The instance-scoped form of `verify_authority_pins`, for one instance and
/// the anchor the owner holds for it. Other instances are checked at the next
/// full verification (ADR 0018).
fn verify_instance_authority(
    db: &Connection,
    instance: &str,
    anchor: Option<&PlanAuthorityAnchor>,
) -> Result<()> {
    let row: Option<(String, Option<String>)> = db
        .query_row(
            "SELECT w.contract_hash,p.pin FROM workflow_instances w LEFT JOIN workflow_plan_authority p ON p.instance_id=w.instance_id WHERE w.instance_id=?1",
            [instance],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let authority = match &row {
        Some((contract, pin)) => authority_matches(contract, pin.as_deref(), anchor),
        None => anchor.is_none(),
    };
    if !authority {
        return Err(RuntimeError::Integrity("workflow plan authority changed"));
    }
    Ok(())
}

fn verify_authority_pins(
    db: &Connection,
    queries: &mut usize,
) -> Result<std::collections::BTreeMap<String, PlanAuthorityAnchor>> {
    *queries += 1;
    let mut anchors = std::collections::BTreeMap::new();
    let mut query = db.prepare(&format!(
        "SELECT detail FROM events WHERE kind='{AUTHORITY_ANCHOR}' ORDER BY sequence"
    ))?;
    for row in query.query_map([], |r| r.get::<_, String>(0))? {
        let anchor = parse_anchor(&row?)?;
        if anchors.insert(anchor.instance_id.clone(), anchor).is_some() {
            return Err(RuntimeError::Integrity("workflow plan authority anchor"));
        }
    }
    *queries += 1;
    let mut query = db.prepare("SELECT w.instance_id,w.contract_hash,p.pin FROM workflow_instances w LEFT JOIN workflow_plan_authority p ON p.instance_id=w.instance_id")?;
    let mut matched = 0usize;
    for row in query.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
        ))
    })? {
        let (instance, contract, pin) = row?;
        let anchor = anchors.get(&instance);
        if !authority_matches(&contract, pin.as_deref(), anchor) {
            return Err(RuntimeError::Integrity("workflow plan authority changed"));
        }
        matched += usize::from(anchor.is_some());
    }
    // Instance IDs are unique, so every anchor must have matched one instance.
    if matched != anchors.len() {
        return Err(RuntimeError::Integrity("workflow plan authority changed"));
    }
    Ok(anchors)
}

fn retry_guard(db: &Connection, id: &str, max: u32) -> Result<RunSummary> {
    if cleanup_blocked(db, None)? {
        return Err(RuntimeError::CleanupUnknown);
    }
    let run = load_opt(db, id)?.ok_or(RuntimeError::NotFound)?;
    admission::require_released(db, &run)?;
    let obsolete = if let Some(binding) = &run.workflow {
        workflow_node(db, &binding.instance_id, &run.node_id)?
            .is_none_or(|(current, _, _)| current.run_id != run.run_id)
    } else {
        false
    };
    let claimed = db
        .prepare("SELECT 1 FROM events WHERE run_id=?1 AND kind='escalation.claim.v1'")?
        .exists([id])?;
    if !retryable(&run) || workflow_attempts(db, &run)? >= max || obsolete || claimed {
        return Err(RuntimeError::Invalid(
            "retry requires a bounded read-only attempt",
        ));
    }
    Ok(run)
}
fn retry_projection(mut run: RunSummary) -> Result<RunSummary> {
    run.state = RunState::AwaitingApproval;
    run.failure = None;
    run.approval_digest = digest(
        "runtime-retry-approval-v1",
        &(&run.run_id, &run.definition_hash, run.attempts),
    )?;
    Ok(run)
}
fn retryable(run: &RunSummary) -> bool {
    matches!(run.state, RunState::Failed | RunState::TimedOut)
        && run.worktree.is_none()
        && matches!(
            run.failure,
            Some(
                RunFailure::RateLimit
                    | RunFailure::Timeout
                    | RunFailure::Crash
                    | RunFailure::Network
                    | RunFailure::Interrupted
                    | RunFailure::Spawn
            )
        )
}
fn workflow_node(
    db: &Connection,
    instance: &str,
    node: &str,
) -> Result<Option<(RunSummary, ModelId, Option<String>)>> {
    let value: Option<(String, String, Option<String>)> = db.query_row(
        "SELECT r.summary,n.model,n.agent FROM workflow_node_runs n JOIN runs r ON r.run_id=n.run_id WHERE n.instance_id=?1 AND n.node_id=?2 ORDER BY n.generation DESC LIMIT 1",
        params![instance,node], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
    value
        .map(|(summary, model, agent)| {
            Ok((
                serde_json::from_str(&summary)?,
                serde_json::from_str(&model)?,
                agent,
            ))
        })
        .transpose()
}
fn workflow_attempts(db: &Connection, run: &RunSummary) -> Result<u32> {
    let Some(binding) = &run.workflow else {
        return Ok(run.attempts);
    };
    let mut query = db.prepare("SELECT r.summary FROM workflow_node_runs n JOIN runs r ON r.run_id=n.run_id WHERE n.instance_id=?1 AND n.node_id=?2")?;
    let rows = query.query_map(params![binding.instance_id, run.node_id], |row| {
        row.get::<_, String>(0)
    })?;
    let mut attempts = 0_u32;
    for row in rows {
        attempts = attempts
            .checked_add(serde_json::from_str::<RunSummary>(&row?)?.attempts)
            .ok_or(RuntimeError::Limit)?;
    }
    Ok(attempts)
}

fn plan_pin(generated: Option<&router_types::GeneratedDecisionBinding>) -> Result<String> {
    generated.map_or(Ok("legacy".into()), |g| {
        digest(
            "runtime-global-plan-pin-v1",
            &(
                g.schema_version,
                &g.instance_id,
                &g.workflow_plan_id,
                &g.execution_contract_sha256,
                &g.input_hash,
                &g.proposal_hash,
            ),
        )
    })
}
/// The owner's plan pin check: the chain tail, then the authority of the one
/// instance it authorizes.
fn verify_plan_pin(
    db: &Connection,
    verified: &VerifiedChain,
    workflow: Option<&router_types::WorkflowRunBinding>,
    generated: Option<&router_types::GeneratedDecisionBinding>,
) -> Result<Option<ChainProof>> {
    let Some(workflow) = workflow else {
        return if generated.is_none() {
            Ok(None)
        } else {
            Err(RuntimeError::Integrity("generated plan missing instance"))
        };
    };
    if generated.is_some_and(|g| {
        g.instance_id != workflow.instance_id
            || g.execution_contract_sha256 != workflow.contract_sha256
    }) {
        return Err(RuntimeError::Integrity("generated plan instance"));
    }
    let pin: Option<String> = db
        .query_row(
            "SELECT pin FROM workflow_plan_authority WHERE instance_id=?1",
            [&workflow.instance_id],
            |r| r.get(0),
        )
        .optional()?;
    let proof = verify_tail(db, verified)?;
    let anchor = proof
        .anchors
        .iter()
        .find(|anchor| anchor.instance_id == workflow.instance_id)
        .or_else(|| verified.anchors.get(&workflow.instance_id));
    verify_instance_authority(db, &workflow.instance_id, anchor)?;
    if pin.as_deref() != Some(plan_pin(generated)?.as_str()) {
        return Err(RuntimeError::Integrity("workflow plan authority changed"));
    }
    Ok(Some(proof))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn summary(id: &str) -> RunSummary {
        RunSummary {
            run_id: id.into(),
            definition_hash: "a".repeat(64),
            approval_digest: "b".repeat(64),
            receipt_id: "c".repeat(64),
            plan_id: format!("plan-{id}"),
            node_id: "execute".into(),
            state: RunState::Planned,
            attempts: 0,
            failure: None,
            worktree: None,
            artifact_sha256: None,
            output_retention: OutputRetentionPolicy::Disabled,
            workflow: None,
            artifact_contract_sha256: None,
        }
    }
    #[test]
    fn interrupted_preparation_without_child_evidence_stays_quarantined() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let store = Store::open(&root).unwrap();
        store.register(&summary("run")).unwrap();
        store.register(&summary("next")).unwrap();
        for state in [
            RunState::AwaitingApproval,
            RunState::Queued,
            RunState::Preparing,
        ] {
            store.transition("run", state, "legacy", None).unwrap();
        }
        store
            .writer_lock("run", "/fixture/repo", &["src".into()])
            .unwrap();
        // Legacy version probes have a lease, but no durable binding to the run.
        // There is no main attempt yet. Preparing alone proves no child cleanup.
        let (_, path) = store.leases.create("unbound-version-probe", 0).unwrap();
        let held = Flock::lock(File::open(path).unwrap(), FlockArg::LockExclusiveNonblock).unwrap();
        drop(store);
        let store = Store::open(&root).unwrap();
        assert!(matches!(
            store.require_cleanup_complete(),
            Err(RuntimeError::CleanupUnknown)
        ));
        assert!(matches!(
            store.writer_lock("next", "/fixture/repo", &["src".into()]),
            Err(RuntimeError::Scope)
        ));
        assert_eq!(store.get("run").unwrap().attempts, 0);
        drop(held);
        drop(store);
        let store = Store::open(&root).unwrap();
        // An unlocked, unbound file cannot retrospectively establish provenance.
        assert!(matches!(
            store.require_cleanup_complete(),
            Err(RuntimeError::CleanupUnknown)
        ));
    }
    #[test]
    fn schema_three_migration_preserves_history_without_inventing_instances() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let store = Store::open(&root).unwrap();
        let before = store.register(&summary("old")).unwrap();
        let events = store.events().unwrap();
        drop(store);
        let db = Connection::open(root.join("runtime.sqlite3")).unwrap();
        db.execute_batch("PRAGMA foreign_keys=OFF;
            DROP TABLE admission_intents; DROP TABLE admission_binding; DROP TABLE preparation_cycles; DROP TABLE workflow_plan_authority; DROP TABLE attempt_leases; DROP TABLE cleanup_blocks; DROP TABLE declared_artifacts; DROP TABLE workflow_node_runs; DROP TABLE workflow_instances;
            CREATE TABLE old_runs(run_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, node_id TEXT NOT NULL, summary TEXT NOT NULL, UNIQUE(plan_id,node_id));
            INSERT INTO old_runs SELECT * FROM runs; DROP TABLE runs; ALTER TABLE old_runs RENAME TO runs;
            PRAGMA user_version=3;").unwrap();
        drop(db);
        let store = Store::open(&root).unwrap();
        assert_eq!(store.get("old").unwrap(), before);
        assert_eq!(store.events().unwrap(), events);
        assert!(store.get("old").unwrap().workflow.is_none());
        let db = store.lock().unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM workflow_instances", [], |r| r
                .get::<_, u32>(0))
                .unwrap(),
            0
        );
        assert!(
            !db.prepare("PRAGMA foreign_key_check")
                .unwrap()
                .exists([])
                .unwrap()
        );
        assert!(
            db.execute("UPDATE events SET detail='changed'", [])
                .is_err()
        );
        drop(db);
        let mut unrelated = summary("new");
        unrelated.plan_id = before.plan_id.clone();
        store.register(&unrelated).unwrap();
        assert_eq!(observe(&root, "old").unwrap(), before);
    }
    #[test]
    fn invalid_transition_is_atomic_and_emits_integrity_event() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("data")).unwrap();
        store.register(&summary("run")).unwrap();
        assert!(matches!(
            store.transition("run", RunState::Running, "", None),
            Err(RuntimeError::Transition)
        ));
        assert_eq!(store.get("run").unwrap().state, RunState::Planned);
        assert_eq!(
            store.events().unwrap().last().unwrap().kind,
            "integrity.invalid_transition"
        );
        store.verify_events().unwrap();
    }
    #[test]
    fn pre_evidence_attempts_are_not_backfilled_when_reopened() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("history");
        let store = Store::open(&root).unwrap();
        store.register(&summary("legacy")).unwrap();
        for state in [RunState::AwaitingApproval, RunState::Queued] {
            store.transition("legacy", state, "legacy", None).unwrap();
        }
        let prep = store.begin_preparation("legacy").unwrap();
        prep.no_child_yet().unwrap();
        prep.complete().unwrap();
        store.attempt("legacy", 2, false).unwrap();
        store
            .transition("legacy", RunState::Running, "legacy", None)
            .unwrap();
        store.finish_attempt("legacy", "Exited").unwrap();
        store
            .transition(
                "legacy",
                RunState::Failed,
                "legacy",
                Some(RunFailure::Crash),
            )
            .unwrap();
        let original = store.events().unwrap();
        drop(store);
        let store = Store::open(&root).unwrap();
        let history = store.escalation_history("legacy").unwrap();
        assert_eq!(history.attempts.len(), 1);
        assert!(
            !history
                .events
                .iter()
                .any(|e| e.kind == "attempt.evidence.v1")
        );
        assert_eq!(store.events().unwrap(), original);
    }
    #[test]
    fn planned_cancellation_is_immediate_idempotent_and_releases_writer_locks() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let store = Store::open(&root).unwrap();
        store.register(&summary("run")).unwrap();
        store.register(&summary("next")).unwrap();
        store
            .writer_lock("run", "/fixture/repo", &["src".into()])
            .unwrap();
        assert!(RunState::Planned.permits(RunState::Cancelled));
        request_cancel(&root, "run").unwrap();
        assert_eq!(observe(&root, "run").unwrap().state, RunState::Cancelled);
        let count = store.events().unwrap().len();
        request_cancel(&root, "run").unwrap();
        assert_eq!(store.events().unwrap().len(), count);
        store
            .writer_lock("next", "/fixture/repo", &["src".into()])
            .unwrap();
        assert!(matches!(
            store.transition_queued("run", RunState::Preparing, "", None),
            Err(RuntimeError::Cancelled)
        ));
        assert_eq!(store.events().unwrap().len(), count);
        store.verify_events().unwrap();
    }
    #[test]
    fn recovery_classifies_interrupted_and_preserves_verified_steps() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let store = Store::open(&root).unwrap();
        store.register(&summary("run")).unwrap();
        for state in [
            RunState::AwaitingApproval,
            RunState::Queued,
            RunState::Preparing,
            RunState::Running,
        ] {
            store.transition("run", state, "", None).unwrap();
        }
        drop(store);
        let store = Store::open(&root).unwrap();
        assert_eq!(
            store.get("run").unwrap().failure,
            Some(RunFailure::Interrupted)
        );
        assert_eq!(store.get("run").unwrap().state, RunState::Failed);
        assert!(matches!(
            store.require_cleanup_complete(),
            Err(RuntimeError::CleanupUnknown)
        ));
        store.verify_events().unwrap();
    }
    #[test]
    fn stopped_observer_runs_before_cleanup_and_failure_retains_authority() {
        for refuse in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(temp.path()).unwrap().join("runtime");
            let store = Store::open(&root).unwrap();
            store.register(&summary("run")).unwrap();
            for state in [RunState::AwaitingApproval, RunState::Queued] {
                store.transition("run", state, "", None).unwrap();
            }
            let prep = store.begin_preparation("run").unwrap();
            prep.no_child_yet().unwrap();
            prep.complete().unwrap();
            drop(prep);
            let path = store
                .attempt_with_host_state("run", 1, true, true)
                .unwrap()
                .unwrap();
            let mut state =
                crate::HostState::create(&root, "codex", &std::collections::BTreeMap::new())
                    .unwrap()
                    .unwrap();
            let home = state.path().to_owned();
            state.arm_cleanup(Some(&path), true).unwrap();
            fs::write(&path, b"router-runtime-lease-v1:namespace-clean\n").unwrap();
            let mut called = false;
            let result = store.confirm_attempt_cleanup_and_state_observed(
                "run",
                Some(state),
                |state, proof| {
                    called = true;
                    assert!(state.path().is_dir());
                    assert_eq!(
                        proof.evidence,
                        router_types::ProcessCleanupEvidence::NamespaceTerminated
                    );
                    if refuse {
                        Err(RuntimeError::Integrity("observer refused"))
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(called);
            if refuse {
                assert!(matches!(result, Err(RuntimeError::CleanupUnknown)));
                assert!(home.exists());
                assert!(store.require_cleanup_complete().is_err());
            } else {
                result.unwrap();
                assert!(!home.exists());
                store.require_cleanup_complete().unwrap();
            }
        }
    }
    #[test]
    fn confirmed_host_cleanup_clears_only_its_durable_obligation() {
        for marker in ["pending", "namespace-clean"] {
            let temp = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(temp.path()).unwrap().join("runtime");
            let store = Store::open(&root).unwrap();
            store.register(&summary("run")).unwrap();
            for state in [RunState::AwaitingApproval, RunState::Queued] {
                store.transition("run", state, "", None).unwrap();
            }
            let prep = store.begin_preparation("run").unwrap();
            prep.no_child_yet().unwrap();
            prep.complete().unwrap();
            drop(prep);
            let path = store
                .attempt_with_host_state("run", 1, true, true)
                .unwrap()
                .unwrap();
            let mut state =
                crate::HostState::create(&root, "codex", &std::collections::BTreeMap::new())
                    .unwrap()
                    .unwrap();
            let home = state.path().to_owned();
            state.arm_cleanup(Some(&path), true).unwrap();
            fs::write(&path, format!("router-runtime-lease-v1:{marker}\n")).unwrap();
            store
                .confirm_attempt_cleanup_and_state("run", Some(state))
                .unwrap();
            assert!(!home.exists());
            let record: String = store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT record FROM attempt_leases WHERE run_id='run'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(
                !serde_json::from_str::<LeaseRecord>(&record)
                    .unwrap()
                    .needs_host_cleanup()
            );
            store
                .transition("run", RunState::Cancelled, "fixture-complete", None)
                .unwrap();
            drop(store);
            Store::open(&root)
                .unwrap()
                .require_cleanup_complete()
                .unwrap();
        }
    }

    #[test]
    fn group_only_cleanup_retains_host_state_and_durable_authority() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap().join("runtime");
        let store = Store::open(&root).unwrap();
        store.register(&summary("run")).unwrap();
        for state in [RunState::AwaitingApproval, RunState::Queued] {
            store.transition("run", state, "", None).unwrap();
        }
        store
            .writer_lock("run", "/fixture", &["src".into()])
            .unwrap();
        let prep = store.begin_preparation("run").unwrap();
        prep.no_child_yet().unwrap();
        prep.complete().unwrap();
        drop(prep);
        let path = store
            .attempt_with_host_state("run", 1, true, true)
            .unwrap()
            .unwrap();
        let mut state =
            crate::HostState::create(&root, "codex", &std::collections::BTreeMap::new())
                .unwrap()
                .unwrap();
        let home = state.path().to_owned();
        state.arm_cleanup(Some(&path), false).unwrap();
        fs::write(&path, b"router-runtime-lease-v1:group-clean\n").unwrap();
        assert!(matches!(
            store.confirm_attempt_cleanup_and_state("run", Some(state)),
            Err(RuntimeError::CleanupUnknown)
        ));
        assert!(home.exists());
        assert!(matches!(
            store.require_cleanup_complete(),
            Err(RuntimeError::CleanupUnknown)
        ));
        assert!(
            store
                .lock()
                .unwrap()
                .prepare("SELECT 1 FROM writer_locks WHERE run_id='run'")
                .unwrap()
                .exists([])
                .unwrap()
        );
        store.verify_events().unwrap();
        drop(store);
        let store = Store::open(&root).unwrap();
        assert!(matches!(
            store.require_cleanup_complete(),
            Err(RuntimeError::CleanupUnknown)
        ));
    }

    #[test]
    fn refused_home_cleanup_remains_quarantined_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap().join("runtime");
        let store = Store::open(&root).unwrap();
        store.register(&summary("run")).unwrap();
        for state in [RunState::AwaitingApproval, RunState::Queued] {
            store.transition("run", state, "", None).unwrap();
        }
        store
            .writer_lock("run", "/fixture", &["src".into()])
            .unwrap();
        let prep = store.begin_preparation("run").unwrap();
        prep.no_child_yet().unwrap();
        prep.complete().unwrap();
        drop(prep);
        let path = store
            .attempt_with_host_state("run", 1, true, true)
            .unwrap()
            .unwrap();
        let mut state =
            crate::HostState::create(&root, "codex", &std::collections::BTreeMap::new())
                .unwrap()
                .unwrap();
        let home = state.path().to_owned();
        state.arm_cleanup(Some(&path), false).unwrap();
        fs::rename(&home, root.join("moved-home")).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
        fs::write(home.join("foreign"), b"keep").unwrap();
        assert!(matches!(
            store.confirm_attempt_cleanup_and_state("run", Some(state)),
            Err(RuntimeError::CleanupUnknown)
        ));
        assert_eq!(fs::read(home.join("foreign")).unwrap(), b"keep");
        assert!(matches!(
            store.require_cleanup_complete(),
            Err(RuntimeError::CleanupUnknown)
        ));
        assert!(
            store
                .lock()
                .unwrap()
                .prepare("SELECT 1 FROM writer_locks WHERE run_id='run'")
                .unwrap()
                .exists([])
                .unwrap()
        );
        store.verify_events().unwrap();
        drop(store);
        let store = Store::open(&root).unwrap();
        assert!(matches!(
            store.require_cleanup_complete(),
            Err(RuntimeError::CleanupUnknown)
        ));
    }

    #[test]
    fn recovery_requires_private_lease_proof_before_releasing_writer_authority() {
        for status in [
            "pending",
            "group-clean",
            "namespace-clean",
            "active",
            "corrupt",
            "absent",
            "symlink",
            "held",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("data");
            let store = Store::open(&root).unwrap();
            store.register(&summary("run")).unwrap();
            store.register(&summary("next")).unwrap();
            for state in [RunState::AwaitingApproval, RunState::Queued] {
                store.transition("run", state, "", None).unwrap();
            }
            store
                .writer_lock("run", "/fixture/repo", &["src".into()])
                .unwrap();
            let prep = store.begin_preparation("run").unwrap();
            prep.no_child_yet().unwrap();
            prep.complete().unwrap();
            let path = store.attempt("run", 2, true).unwrap().unwrap();
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
            store
                .transition("run", RunState::Running, "", None)
                .unwrap();
            let held = match status {
                "absent" => {
                    fs::remove_file(&path).unwrap();
                    None
                }
                "symlink" => {
                    fs::remove_file(&path).unwrap();
                    std::os::unix::fs::symlink(temp.path().join("unowned"), &path).unwrap();
                    None
                }
                "held" => Some(
                    Flock::lock(File::open(&path).unwrap(), FlockArg::LockExclusiveNonblock)
                        .unwrap(),
                ),
                _ => {
                    fs::write(&path, format!("router-runtime-lease-v1:{status}\n")).unwrap();
                    None
                }
            };
            drop(store);
            let store = Store::open(&root).unwrap();
            assert_eq!(
                store.get("run").unwrap().failure,
                Some(RunFailure::Interrupted)
            );
            let expected = match status {
                "pending" => Some(router_types::ProcessCleanupEvidence::NotStarted),
                "group-clean" => Some(router_types::ProcessCleanupEvidence::GroupTerminated),
                "namespace-clean" => {
                    Some(router_types::ProcessCleanupEvidence::NamespaceTerminated)
                }
                _ => None,
            };
            if let Some(expected) = expected {
                store.require_cleanup_complete().unwrap();
                assert_eq!(store.cleanup_evidence("run").unwrap(), expected);
                store
                    .writer_lock("next", "/fixture/repo", &["src".into()])
                    .unwrap();
                if status == "pending" {
                    assert_eq!(
                        fs::read(&path).unwrap(),
                        b"router-runtime-lease-v1:recovered\n"
                    );
                }
            } else {
                assert!(
                    matches!(
                        store.require_cleanup_complete(),
                        Err(RuntimeError::CleanupUnknown)
                    ),
                    "{status}"
                );
                assert!(
                    matches!(
                        store.writer_lock("next", "/fixture/repo", &["src".into()]),
                        Err(RuntimeError::Scope)
                    ),
                    "{status}"
                );
                assert!(
                    matches!(
                        store.retry_expecting("run", 2, None),
                        Err(RuntimeError::CleanupUnknown)
                    ),
                    "{status}"
                );
            }
            assert!(!temp.path().join("unowned").exists());
            drop(held);
        }
    }
    #[test]
    fn unsafe_normal_completion_retains_writer_lock_and_later_proof_reconciles() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let store = Store::open(&root).unwrap();
        store.register(&summary("run")).unwrap();
        store.register(&summary("next")).unwrap();
        for state in [RunState::AwaitingApproval, RunState::Queued] {
            store.transition("run", state, "", None).unwrap();
        }
        store
            .writer_lock("run", "/fixture/repo", &["src".into()])
            .unwrap();
        let prep = store.begin_preparation("run").unwrap();
        prep.no_child_yet().unwrap();
        prep.complete().unwrap();
        let path = store.attempt("run", 2, true).unwrap().unwrap();
        fs::write(&path, b"router-runtime-lease-v1:active\n").unwrap();
        store
            .transition("run", RunState::Running, "", None)
            .unwrap();
        assert!(matches!(
            store.confirm_attempt_cleanup("run"),
            Err(RuntimeError::CleanupUnknown)
        ));
        store
            .transition(
                "run",
                RunState::Failed,
                "cleanup_unknown",
                Some(RunFailure::Interrupted),
            )
            .unwrap();
        assert!(matches!(
            store.writer_lock("next", "/fixture/repo", &["src".into()]),
            Err(RuntimeError::Scope)
        ));
        fs::write(&path, b"router-runtime-lease-v1:group-clean\n").unwrap();
        drop(store);
        let store = Store::open(&root).unwrap();
        store.require_cleanup_complete().unwrap();
        store
            .writer_lock("next", "/fixture/repo", &["src".into()])
            .unwrap();
        assert_eq!(store.get("run").unwrap().attempts, 1);
    }
    #[test]
    fn corrupt_lease_record_cannot_release_a_writer_on_error_transition() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("data")).unwrap();
        store.register(&summary("run")).unwrap();
        store.register(&summary("next")).unwrap();
        for state in [RunState::AwaitingApproval, RunState::Queued] {
            store.transition("run", state, "", None).unwrap();
        }
        store
            .writer_lock("run", "/fixture/repo", &["src".into()])
            .unwrap();
        let prep = store.begin_preparation("run").unwrap();
        prep.no_child_yet().unwrap();
        prep.complete().unwrap();
        store.attempt("run", 2, true).unwrap();
        store
            .transition("run", RunState::Running, "", None)
            .unwrap();
        store
            .lock()
            .unwrap()
            .execute("UPDATE attempt_leases SET record='invalid-json'", [])
            .unwrap();
        assert!(matches!(
            store.confirm_attempt_cleanup("run"),
            Err(RuntimeError::CleanupUnknown)
        ));
        store
            .transition(
                "run",
                RunState::Failed,
                "cleanup_unknown",
                Some(RunFailure::Interrupted),
            )
            .unwrap();
        assert!(matches!(
            store.writer_lock("next", "/fixture/repo", &["src".into()]),
            Err(RuntimeError::Scope)
        ));
        assert!(matches!(
            store.require_cleanup_complete(),
            Err(RuntimeError::CleanupUnknown)
        ));
        assert_eq!(
            observe_cleanup(&store.root, "run").unwrap(),
            router_types::ProcessCleanupEvidence::Unknown
        );
    }
    #[test]
    fn exclusive_lock_private_files_append_only_and_tamper_detection() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let store = Store::open(&root).unwrap();
        assert!(matches!(Store::open(&root), Err(RuntimeError::Locked)));
        store.register(&summary("run")).unwrap();
        let db = store.lock().unwrap();
        assert!(
            db.execute("UPDATE events SET detail='changed'", [])
                .is_err()
        );
        assert!(db.execute("DELETE FROM events", []).is_err());
        assert_eq!(
            db.pragma_query_value(None, "journal_mode", |r| r.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        drop(db);
        assert_eq!(
            fs::metadata(root.join("runtime.sqlite3"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
        drop(store);
        let db = Connection::open(root.join("runtime.sqlite3")).unwrap();
        db.execute_batch("DROP TRIGGER events_no_update; UPDATE events SET detail='tampered';")
            .unwrap();
        drop(db);
        assert!(matches!(
            Store::open(&root),
            Err(RuntimeError::Integrity("event chain"))
        ));
    }
    #[test]
    fn overlapping_writers_are_rejected_across_workflows() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("data")).unwrap();
        store.register(&summary("one")).unwrap();
        store.register(&summary("two")).unwrap();
        store
            .writer_lock("one", "/fixture/repo", &["src".into()])
            .unwrap();
        assert!(matches!(
            store.writer_lock("two", "/fixture/repo", &["src/nested/file".into()]),
            Err(RuntimeError::Scope)
        ));
        store
            .writer_lock("two", "/fixture/repo", &["tests".into()])
            .unwrap();
    }
    #[test]
    fn writer_lock_compares_normalized_workspaces_and_component_scopes() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("data")).unwrap();
        for id in ["one", "two", "three"] {
            store.register(&summary(id)).unwrap();
        }
        store.writer_lock("one", "/repo", &["src/".into()]).unwrap();
        for (workspace, scope) in [
            ("/repo/", "src/a"),
            ("/repo//", "src//x"),
            ("/repo/./", "src/./x"),
            ("/repo", "./src"),
            ("/repo", "src"),
        ] {
            assert!(
                matches!(
                    store.writer_lock("two", workspace, &[scope.into()]),
                    Err(RuntimeError::Scope)
                ),
                "{workspace} {scope}"
            );
        }
        // A sibling that merely shares a string prefix is not an overlap.
        store
            .writer_lock("two", "/repo/", &["src2".into()])
            .unwrap();
        // Unresolvable components are refused rather than compared.
        assert!(matches!(
            store.writer_lock("three", "/repo", &["src/../tests".into()]),
            Err(RuntimeError::Scope)
        ));
        assert!(matches!(
            store.writer_lock("three", "/repo/../other", &["docs".into()]),
            Err(RuntimeError::Scope)
        ));
        assert!(overlaps("src/", "src/a"));
        assert!(!overlaps("src", "srcs"));
    }
    #[test]
    fn partial_lease_removal_only_touches_owned_regular_files() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("a.lease");
        fs::write(&file, b"pending").unwrap();
        remove_owned_regular_file(&file);
        assert!(!file.exists());
        let target = temp.path().join("target");
        fs::write(&target, b"keep").unwrap();
        let link = temp.path().join("b.lease");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        remove_owned_regular_file(&link);
        assert!(link.symlink_metadata().is_ok() && target.exists());
        let dir = temp.path().join("c.lease");
        fs::create_dir(&dir).unwrap();
        remove_owned_regular_file(&dir);
        assert!(dir.is_dir());
        let first = temp.path().join("d.lease");
        fs::write(&first, b"x").unwrap();
        fs::hard_link(&first, temp.path().join("e.lease")).unwrap();
        remove_owned_regular_file(&first);
        assert!(first.exists());
        remove_owned_regular_file(&temp.path().join("missing.lease"));
    }
    #[test]
    fn existing_lease_file_is_not_removed_when_create_reports_exists() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().join("data");
        let store = Store::open(&root).unwrap();
        store.register(&summary("run")).unwrap();
        for state in [RunState::AwaitingApproval, RunState::Queued] {
            store.transition("run", state, "", None).unwrap();
        }
        let prep = store.begin_preparation("run").unwrap();
        prep.no_child_yet().unwrap();
        prep.complete().unwrap();
        drop(prep);
        let (_, path) = store.leases.create("run", 1).unwrap();
        // Not a pending marker, so it is not a provable uncommitted orphan.
        fs::write(&path, b"router-runtime-lease-v1:active\n").unwrap();
        assert!(matches!(
            store.attempt("run", 3, true),
            Err(RuntimeError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists
        ));
        assert!(path.exists(), "a pre-existing lease must survive");
    }
    #[test]
    fn repeated_cancel_request_appends_one_event() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().join("data");
        let store = Store::open(&root).unwrap();
        store.register(&summary("run")).unwrap();
        for state in [
            RunState::AwaitingApproval,
            RunState::Queued,
            RunState::Preparing,
        ] {
            store.transition("run", state, "", None).unwrap();
        }
        request_cancel(&root, "run").unwrap();
        let before = store.events().unwrap();
        request_cancel(&root, "run").unwrap();
        request_cancel(&root, "run").unwrap();
        assert_eq!(store.events().unwrap(), before);
        assert_eq!(
            before
                .iter()
                .filter(|event| event.kind == "control.cancel_requested")
                .count(),
            1
        );
    }
    #[test]
    fn failed_attempt_commit_leaves_no_lease_file_and_can_be_retried() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().join("data");
        let store = Store::open(&root).unwrap();
        store.register(&summary("run")).unwrap();
        for state in [RunState::AwaitingApproval, RunState::Queued] {
            store.transition("run", state, "", None).unwrap();
        }
        let prep = store.begin_preparation("run").unwrap();
        prep.no_child_yet().unwrap();
        prep.complete().unwrap();
        drop(prep);
        // Fault injection: a conflicting row makes the INSERT that follows the
        // lease creation fail, so the transaction rolls back after the file exists.
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO attempt_leases(run_id,attempt,record) VALUES('run',1,'{}')",
                [],
            )
            .unwrap();
        assert!(matches!(
            store.attempt("run", 3, true),
            Err(RuntimeError::Storage(_))
        ));
        let leftovers = fs::read_dir(root.join("leases")).unwrap().count();
        assert_eq!(leftovers, 0, "rolled back attempt left a lease file");
        assert_eq!(store.get("run").unwrap().attempts, 0);
        store
            .lock()
            .unwrap()
            .execute("DELETE FROM attempt_leases", [])
            .unwrap();
        let path = store.attempt("run", 3, true).unwrap().unwrap();
        assert!(path.exists());
        assert_eq!(store.get("run").unwrap().attempts, 1);
    }
    fn preparing_run(store: &Store, id: &str) {
        store.register(&summary(id)).unwrap();
        for state in [RunState::AwaitingApproval, RunState::Queued] {
            store.transition(id, state, "", None).unwrap();
        }
        let prep = store.begin_preparation(id).unwrap();
        prep.no_child_yet().unwrap();
        prep.complete().unwrap();
    }
    #[test]
    fn retry_reclaims_a_proven_orphan_lease_but_refuses_anything_else() {
        use std::os::unix::fs::symlink;
        for shape in ["orphan", "wrong-content", "hard-linked", "symlink", "held"] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("data");
            let store = Store::open(&root).unwrap();
            preparing_run(&store, "run");
            // A kill between the O_EXCL create and the SQLite commit leaves a
            // lease file for attempt 1 and no attempt_leases row.
            let (_, path) = store.leases.create("run", 1).unwrap();
            let mut held = None;
            match shape {
                "orphan" => {}
                "wrong-content" => fs::write(&path, b"router-runtime-lease-v1:active\n").unwrap(),
                "hard-linked" => fs::hard_link(&path, temp.path().join("alias")).unwrap(),
                "symlink" => {
                    fs::remove_file(&path).unwrap();
                    symlink(temp.path().join("elsewhere"), &path).unwrap();
                }
                _ => {
                    held = Some(
                        Flock::lock(File::open(&path).unwrap(), FlockArg::LockExclusiveNonblock)
                            .unwrap(),
                    )
                }
            }
            let result = store.attempt("run", 2, true);
            drop(held);
            if shape == "orphan" {
                let fresh = result.unwrap().unwrap();
                assert_eq!(fresh, path);
                assert_eq!(store.get("run").unwrap().attempts, 1);
                let rows: i64 = store
                    .lock()
                    .unwrap()
                    .query_row("SELECT COUNT(*) FROM attempt_leases", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(rows, 1);
                assert_eq!(
                    fs::read(&fresh).unwrap(),
                    b"router-runtime-lease-v1:pending\n"
                );
                assert!(store.events().unwrap().iter().any(|e| {
                    e.run_id == "run"
                        && e.kind == "attempt.lease_orphan_reclaimed"
                        && e.detail == "1"
                }));
                store.verify_events().unwrap();
            } else {
                assert!(
                    matches!(&result, Err(RuntimeError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists),
                    "{shape}: {result:?}"
                );
                assert_eq!(store.get("run").unwrap().attempts, 0);
                // The refused file is left exactly as found.
                assert!(fs::symlink_metadata(&path).is_ok());
            }
        }
    }
    #[test]
    fn a_failing_reclaim_keeps_the_existing_file_and_the_original_error() {
        use std::os::unix::fs::PermissionsExt;
        for shape in ["unreadable", "directory", "unlink-denied"] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("data");
            let store = Store::open(&root).unwrap();
            preparing_run(&store, "run");
            let (_, path) = store.leases.create("run", 1).unwrap();
            let leases = root.join("leases");
            if shape == "unreadable" {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
            } else if shape == "unlink-denied" {
                // A provable orphan whose unlink then fails: the error must not
                // leak out as anything but the original refusal.
                fs::set_permissions(&leases, fs::Permissions::from_mode(0o500)).unwrap();
            } else {
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
            }
            let result = store.attempt("run", 2, true);
            fs::set_permissions(&leases, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(
                matches!(&result, Err(RuntimeError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists),
                "{shape}: {result:?}"
            );
            assert!(fs::symlink_metadata(&path).is_ok(), "{shape}: file removed");
            assert_eq!(store.get("run").unwrap().attempts, 0);
        }
    }
    #[test]
    fn a_committed_lease_row_is_never_reclaimed_as_an_orphan() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let store = Store::open(&root).unwrap();
        preparing_run(&store, "run");
        let path = store.attempt("run", 3, true).unwrap().unwrap();
        // Rewind the counter so attempt 1 is requested again while its row exists.
        {
            let mut db = store.lock().unwrap();
            let tx = db.transaction().unwrap();
            let mut run = load_opt(&tx, "run").unwrap().unwrap();
            run.attempts = 0;
            save(&tx, &run).unwrap();
            tx.commit().unwrap();
        }
        store.attempt("run", 3, true).unwrap_err();
        assert!(path.exists());
    }
    #[test]
    fn recovery_visits_runs_in_run_id_order_not_insertion_order() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let store = Store::open(&root).unwrap();
        for id in ["run-c", "run-a", "run-b"] {
            store.register(&summary(id)).unwrap();
            for state in [
                RunState::AwaitingApproval,
                RunState::Queued,
                RunState::Preparing,
            ] {
                store.transition(id, state, "", None).unwrap();
            }
        }
        drop(store);
        let store = Store::open(&root).unwrap();
        let order: Vec<String> = store
            .events()
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == "recovery.interrupted")
            .map(|e| e.run_id)
            .collect();
        assert_eq!(order, ["run-a", "run-b", "run-c"]);
    }

    fn verified_rows() -> u64 {
        VERIFIED_ROWS.with(std::cell::Cell::get)
    }
    /// A legacy workflow instance, so `verify_plan_pin` checks the chain.
    fn legacy_instance(store: &Store) -> router_types::WorkflowRunBinding {
        store
            .lock()
            .unwrap()
            .execute_batch("INSERT INTO workflow_instances VALUES('instance','contract','{}'); INSERT INTO workflow_plan_authority VALUES('instance','legacy');")
            .unwrap();
        router_types::WorkflowRunBinding {
            instance_id: "instance".into(),
            contract_sha256: "contract".into(),
            generation: 0,
        }
    }
    fn tamper(store: &Store, sql: &str) {
        Connection::open(store.root.join("runtime.sqlite3"))
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }
    #[test]
    fn owner_chain_checks_do_not_reread_verified_history() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("data")).unwrap();
        let binding = legacy_instance(&store);
        store.register(&summary("bulk")).unwrap();
        store.register(&summary("run")).unwrap();
        store.append_events_for_test("bulk", 10_000);
        // The first check after the bulk append reads each new row once.
        store.verify_plan_pin(Some(&binding), None).unwrap();
        let before = verified_rows();
        for i in 0..20 {
            store.register(&summary(&format!("next-{i}"))).unwrap();
            store.verify_plan_pin(Some(&binding), None).unwrap();
            store.escalation_history("run").unwrap();
        }
        // Per iteration: the trust point row twice plus one new event.
        let read = verified_rows() - before;
        assert!(read <= 20 * 3, "20 checks reread {read} rows");
        // The public full verification still replays the whole chain.
        let before = verified_rows();
        store.verify_events().unwrap();
        assert!(verified_rows() - before >= 10_022);
    }
    #[test]
    fn owner_detects_rewrite_of_its_last_verified_event() {
        for recompute in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let store = Store::open(&temp.path().join("data")).unwrap();
            store.register(&summary("run")).unwrap();
            store.escalation_history("run").unwrap();
            let mut last = store.events().unwrap().pop().unwrap();
            last.detail = "tampered".into();
            // A recomputed digest keeps the rewritten last row self-consistent:
            // only the trust point's remembered hash can refuse it.
            let hash = if recompute {
                event_digest(&last).unwrap()
            } else {
                last.event_hash.clone()
            };
            tamper(
                &store,
                &format!(
                    "DROP TRIGGER events_no_update; UPDATE events SET detail='tampered',event_hash='{hash}' WHERE sequence={};",
                    last.sequence
                ),
            );
            assert!(matches!(
                store.escalation_history("run"),
                Err(RuntimeError::Integrity("event chain"))
            ));
        }
    }
    #[test]
    fn owner_detects_truncation_insertion_and_reordering() {
        for sql in [
            "DROP TRIGGER events_no_delete; DELETE FROM events WHERE sequence=2;",
            "DROP TRIGGER events_no_delete; DELETE FROM events;",
            "INSERT INTO events SELECT 0,run_id,kind,state,detail,previous_hash,event_hash FROM events WHERE sequence=1;",
            "DROP TRIGGER events_no_update; UPDATE events SET sequence=sequence+100 WHERE sequence>2; UPDATE events SET sequence=CASE sequence WHEN 103 THEN 4 ELSE 3 END WHERE sequence>100;",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let store = Store::open(&temp.path().join("data")).unwrap();
            store.register(&summary("run")).unwrap();
            store.register(&summary("other")).unwrap();
            store.escalation_history("run").unwrap();
            // Two unverified rows after the trust point at sequence 2.
            store.register(&summary("third")).unwrap();
            store.register(&summary("fourth")).unwrap();
            tamper(&store, sql);
            assert!(
                matches!(
                    store.escalation_history("run"),
                    Err(RuntimeError::Integrity("event chain"))
                ),
                "{sql}"
            );
        }
    }
    #[test]
    fn old_event_rewrite_is_found_by_full_verification_and_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let store = Store::open(&root).unwrap();
        for id in ["run", "other", "third"] {
            store.register(&summary(id)).unwrap();
        }
        store.escalation_history("run").unwrap();
        tamper(
            &store,
            "DROP TRIGGER events_no_update; UPDATE events SET detail='tampered' WHERE sequence=1;",
        );
        // ADR 0018: rows before the trust point are not reread by the owner.
        store.escalation_history("run").unwrap();
        // `Runtime::verify_integrity` delegates to this full replay.
        assert!(matches!(
            store.verify_events(),
            Err(RuntimeError::Integrity("event chain"))
        ));
        drop(store);
        assert!(matches!(
            Store::open(&root),
            Err(RuntimeError::Integrity("event chain"))
        ));
    }
    /// Recomputes every event hash after `edit`, so the whole chain replays.
    fn rewrite_chain(store: &Store, edit: impl Fn(&mut RuntimeEvent)) {
        let db = Connection::open(store.root.join("runtime.sqlite3")).unwrap();
        let mut events = read_events(&db).unwrap();
        let mut previous = String::new();
        for event in &mut events {
            edit(event);
            event.previous_hash = previous;
            event.event_hash = event_digest(event).unwrap();
            previous = event.event_hash.clone();
        }
        db.execute_batch("DROP TRIGGER IF EXISTS events_no_update;")
            .unwrap();
        for event in &events {
            db.execute(
                "UPDATE events SET detail=?2,previous_hash=?3,event_hash=?4 WHERE sequence=?1",
                params![
                    event.sequence,
                    event.detail,
                    event.previous_hash,
                    event.event_hash
                ],
            )
            .unwrap();
        }
    }
    #[test]
    fn full_verification_refuses_a_chain_that_lost_the_trust_point() {
        for truncate in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let store = Store::open(&temp.path().join("data")).unwrap();
            for id in ["run", "other", "third"] {
                store.register(&summary(id)).unwrap();
            }
            store.escalation_history("run").unwrap();
            if truncate {
                // Rows 1 and 2 still replay; the trust point row is gone.
                tamper(
                    &store,
                    "DROP TRIGGER events_no_delete; DELETE FROM events WHERE sequence=3;",
                );
            } else {
                rewrite_chain(&store, |event| {
                    if event.sequence == 1 {
                        event.detail = "tampered".into();
                    }
                });
            }
            // A consistent replay must not replace the remembered point.
            for _ in 0..2 {
                assert!(matches!(
                    store.verify_events(),
                    Err(RuntimeError::Integrity("event chain"))
                ));
            }
            assert!(store.escalation_history("run").is_err());
        }
    }
    const CONTRACT: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const PIN: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    fn append_anchor(store: &Store, instance: &str) {
        let mut db = store.lock().unwrap();
        let tx = db.transaction().unwrap();
        let run = load_opt(&tx, "run").unwrap().unwrap();
        let anchor = PlanAuthorityAnchor {
            schema_version: 1,
            instance_id: instance.into(),
            contract_sha256: CONTRACT.into(),
            pin: PIN.into(),
        };
        append(
            &tx,
            &run,
            AUTHORITY_ANCHOR,
            &serde_json::to_string(&anchor).unwrap(),
        )
        .unwrap();
        tx.commit().unwrap();
    }
    fn anchored_instance(store: &Store, instance: &str) {
        store
            .lock()
            .unwrap()
            .execute_batch(&format!("INSERT INTO workflow_instances VALUES('{instance}','{CONTRACT}','{{}}'); INSERT INTO workflow_plan_authority VALUES('{instance}','{PIN}');"))
            .unwrap();
        append_anchor(store, instance);
    }
    #[test]
    fn tail_refuses_duplicate_and_orphan_authority_anchors() {
        type Setup = fn(&Store);
        let cases: [(&str, Setup, &str); 3] = [
            (
                "duplicate in the tail",
                |store| {
                    anchored_instance(store, "gen");
                    append_anchor(store, "gen");
                },
                "workflow plan authority anchor",
            ),
            (
                "duplicate of a remembered anchor",
                |store| {
                    anchored_instance(store, "gen");
                    store.escalation_history("run").unwrap();
                    append_anchor(store, "gen");
                },
                "workflow plan authority anchor",
            ),
            (
                "anchor without an instance",
                |store| append_anchor(store, "orphan"),
                "workflow plan authority changed",
            ),
        ];
        for (name, setup, error) in cases {
            let temp = tempfile::tempdir().unwrap();
            let store = Store::open(&temp.path().join("data")).unwrap();
            store.register(&summary("run")).unwrap();
            store.escalation_history("run").unwrap();
            setup(&store);
            let result = store.escalation_history("run");
            assert!(
                matches!(result, Err(RuntimeError::Integrity(found)) if found == error),
                "{name}: {:?}",
                result.map(|_| ())
            );
            // The full replay refuses the same chain.
            assert!(store.verify_events().is_err(), "{name}");
        }
    }
    /// A run bound to the legacy workflow instance of `legacy_instance`.
    fn workflow_run(store: &Store, id: &str) {
        let mut run = summary(id);
        run.workflow = Some(legacy_instance(store));
        let mut db = store.lock().unwrap();
        let tx = db.transaction().unwrap();
        tx.execute(
            "INSERT INTO runs(run_id,plan_id,node_id,summary) VALUES(?1,?2,?3,?4)",
            params![
                id,
                run.plan_id,
                run.node_id,
                serde_json::to_string(&run).unwrap()
            ],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO workflow_node_runs VALUES('instance',?1,0,?2,'\"model\"',NULL)",
            params![run.node_id, id],
        )
        .unwrap();
        append(&tx, &run, "planned", "").unwrap();
        tx.commit().unwrap();
    }
    #[test]
    fn escalation_refuses_a_changed_pin_of_its_instance_before_claiming() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("data")).unwrap();
        workflow_run(&store, "run");
        let ledger = store.escalation_history("run").unwrap().ledger_hash;
        tamper(
            &store,
            &format!(
                "UPDATE workflow_plan_authority SET pin='{PIN}' WHERE instance_id='instance';"
            ),
        );
        assert!(matches!(
            store.escalation_event("run", &ledger, "escalation.claim.v1", "claim"),
            Err(RuntimeError::Integrity("workflow plan authority changed"))
        ));
        assert!(
            !store
                .has_event("run", "escalation.claim.v1", "claim")
                .unwrap()
        );
        assert!(matches!(
            store.escalation_history("run"),
            Err(RuntimeError::Integrity("workflow plan authority changed"))
        ));
    }
    #[test]
    #[ignore = "timing measurement: cargo test -p router-runtime --lib measure_owner -- --ignored --nocapture"]
    fn measure_owner_chain_checks_against_history() {
        for history in [1_000, 10_000, 100_000] {
            let temp = tempfile::tempdir().unwrap();
            let store = Store::open(&temp.path().join("data")).unwrap();
            let binding = legacy_instance(&store);
            store.register(&summary("bulk")).unwrap();
            store.register(&summary("run")).unwrap();
            store.append_events_for_test("bulk", history);
            store.verify_plan_pin(Some(&binding), None).unwrap();
            let start = std::time::Instant::now();
            for _ in 0..100 {
                store.verify_plan_pin(Some(&binding), None).unwrap();
            }
            let pin = start.elapsed();
            let start = std::time::Instant::now();
            for i in 0..100 {
                store.register(&summary(&format!("next-{i}"))).unwrap();
                store.verify_plan_pin(Some(&binding), None).unwrap();
            }
            let register = start.elapsed();
            let start = std::time::Instant::now();
            for _ in 0..100 {
                store.escalation_history("run").unwrap();
            }
            let escalation = start.elapsed();
            // `history` still materializes every event before filtering by run.
            let start = std::time::Instant::now();
            for _ in 0..100 {
                store.events().unwrap();
            }
            let events = start.elapsed();
            eprintln!(
                "history={history} verify_plan_pin x100={pin:?} (register+verify_plan_pin) x100={register:?} escalation_history x100={escalation:?} events x100={events:?}"
            );
        }
    }
}

#[cfg(test)]
mod measurement_tests {
    use super::*;

    fn attempted(store: &Store, id: &str, end: RunState) {
        for state in [RunState::AwaitingApproval, RunState::Queued] {
            store.transition(id, state, "fixture", None).unwrap();
        }
        let prep = store.begin_preparation(id).unwrap();
        prep.no_child_yet().unwrap();
        prep.complete().unwrap();
        store.attempt(id, 5, false).unwrap();
        store
            .transition(id, RunState::Running, "fixture", None)
            .unwrap();
        store.finish_attempt(id, "fixture").unwrap();
        store.transition(id, end, "fixture", None).unwrap();
    }
    fn claim(store: &Store, source: &str, target: &str) {
        let run = store.get(target).unwrap();
        store
            .event(
                source,
                "escalation.claim.v1",
                &serde_json::json!({
                    "decision_id": run.receipt_id, "target_run_id": target,
                    "target_definition_hash": run.definition_hash,
                })
                .to_string(),
            )
            .unwrap();
    }
    #[test]
    fn measurement_snapshot_keeps_cancelled_attempts_and_escalation_occurrences() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        let store = Store::open(&root).unwrap();
        for id in ["first", "escalated", "repeated", "abandoned"] {
            let mut run = tests::summary(id);
            run.plan_id = "same-task-plan".into();
            store.register(&run).unwrap();
            attempted(
                &store,
                id,
                if id == "abandoned" {
                    RunState::Cancelled
                } else {
                    RunState::Failed
                },
            );
        }
        claim(&store, "first", "escalated");
        let before = store.events().unwrap();
        let first = measurement_inventory(&root).unwrap();
        assert_eq!(first, measurement_inventory(&root).unwrap());
        assert_eq!(before, store.events().unwrap());
        assert_eq!(first.runs.iter().map(|run| run.attempts).sum::<u32>(), 4);
        // Sorted by run id: abandoned, escalated, first, repeated.
        assert_eq!(first.runs[0].state, RunState::Cancelled);
        assert_eq!(
            first.runs[1].occurrence_sha256,
            first.runs[2].occurrence_sha256
        );
        assert_ne!(
            first.runs[2].occurrence_sha256,
            first.runs[3].occurrence_sha256
        );
        assert_eq!(
            first.runs[1].predecessor_run_key_sha256.as_ref(),
            Some(&first.runs[2].run_key_sha256)
        );
        claim(&store, "escalated", "first");
        assert!(
            measurement_inventory(&root).is_err(),
            "cycle must not produce task totals"
        );
    }
    #[test]
    fn measurement_refuses_tampered_attempts_or_journal() {
        for tamper in [
            "DELETE FROM run_attempts",
            "DROP TRIGGER events_no_update; UPDATE events SET detail='changed' WHERE sequence=1",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("runtime");
            let store = Store::open(&root).unwrap();
            store.register(&tests::summary("one")).unwrap();
            attempted(&store, "one", RunState::Cancelled);
            let db = Connection::open(root.join("runtime.sqlite3")).unwrap();
            db.execute_batch(tamper).unwrap();
            assert!(measurement_inventory(&root).is_err());
        }
    }
    #[test]
    fn measurement_refuses_attempt_rows_without_a_registered_run() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        let store = Store::open(&root).unwrap();
        let db = Connection::open(root.join("runtime.sqlite3")).unwrap();
        db.execute_batch(
            "PRAGMA foreign_keys=OFF; INSERT INTO run_attempts VALUES('orphan',1,'started');",
        )
        .unwrap();
        assert!(
            measurement_inventory(&root).is_err(),
            "orphan attempt must not disappear from totals"
        );
        drop(store);
    }

    #[test]
    fn measurement_can_create_private_wal_coordination_files_without_mutating_domain_state() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        let store = Store::open(&root).unwrap();
        store.register(&tests::summary("one")).unwrap();
        let journal = store.events().unwrap();
        drop(store);
        assert!(!root.join("runtime.sqlite3-wal").exists());
        assert!(!root.join("runtime.sqlite3-shm").exists());
        let before = fs::read(root.join("runtime.sqlite3")).unwrap();
        let report = measurement_inventory(&root).unwrap();
        assert_eq!(report.runs.len(), 1);
        assert_eq!(before, fs::read(root.join("runtime.sqlite3")).unwrap());
        assert_eq!(journal, observe_events(&root, "one").unwrap());
        for suffix in ["-wal", "-shm"] {
            let metadata = fs::metadata(root.join(format!("runtime.sqlite3{suffix}"))).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o077, 0);
        }
        assert_eq!(
            fs::metadata(root.join("runtime.sqlite3-wal"))
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn measurement_refuses_orphan_escalation_without_creating_a_run() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        let store = Store::open(&root).unwrap();
        store.register(&tests::summary("source")).unwrap();
        store
            .event(
                "source",
                "escalation.claim.v1",
                &serde_json::json!({
                    "decision_id": "c".repeat(64), "target_run_id": "absent",
                    "target_definition_hash": "a".repeat(64),
                })
                .to_string(),
            )
            .unwrap();
        assert!(measurement_inventory(&root).is_err());
        assert!(store.get("absent").is_err());
    }
}
