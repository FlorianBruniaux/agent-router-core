use crate::{PendingRun, Result, Runtime, RuntimeError, digest, now, workspace};
use router_adapter_api::{StreamDialect, content_digest, decode_transport, is_digest};
use router_types::*;
use std::collections::BTreeSet;

impl Runtime {
    pub fn declared_artifacts(&self, run_id: &str) -> Result<Vec<DeclaredArtifact>> {
        self.store.declared_artifacts(run_id)
    }
    /// Explicit payload read. The caller must preserve its confidentiality; no
    /// payload is present in summaries, event logs, or serialized metadata.
    pub fn read_declared_artifact(&self, id: &str) -> Result<Vec<u8>> {
        let (metadata, identity) = self.store.declared_artifact(id)?;
        if metadata.state != DeclaredArtifactState::Retained
            || now()? >= metadata.expires_at_unix_seconds
        {
            return Err(RuntimeError::Invalid("artifact unavailable or expired"));
        }
        self.artifact_store.read(
            &metadata,
            &identity.ok_or(RuntimeError::Integrity("artifact identity"))?,
        )
    }
    pub fn purge_declared_artifact(&self, id: &str) -> Result<DeclaredArtifact> {
        let (metadata, identity) = self.store.declared_artifact(id)?;
        if metadata.state == DeclaredArtifactState::Purged {
            return Ok(metadata);
        }
        let metadata = self
            .store
            .declared_artifact_state(id, DeclaredArtifactState::Purging)?;
        if let Some(identity) = identity {
            self.artifact_store.purge(&metadata, &identity)?;
        }
        self.store
            .declared_artifact_state(id, DeclaredArtifactState::Purged)
    }
    /// Canonical bounded data section to include before review and approval.
    /// It does not grant tools, skills, models, writes, network, or integration.
    pub fn render_dependency_context(&self, contract: &RunArtifactContract) -> Result<String> {
        if contract.max_input_bytes == 0
            || contract.max_input_bytes > 1024 * 1024
            || contract.inputs.len() > 64
        {
            return Err(RuntimeError::Limit);
        }
        let mut data = Vec::new();
        let mut total = 0_usize;
        for grant in &contract.inputs {
            if grant.exposure != ArtifactExposure::PromptData {
                continue;
            }
            let bytes = self.read_declared_artifact(&grant.artifact_id)?;
            total = total.checked_add(bytes.len()).ok_or(RuntimeError::Limit)?;
            if total > contract.max_input_bytes
                || content_digest(&bytes) != grant.sha256
                || bytes.len() != grant.bytes
            {
                return Err(RuntimeError::Limit);
            }
            let content = String::from_utf8(bytes)
                .map_err(|_| RuntimeError::Invalid("text artifact encoding"))?;
            data.push(serde_json::json!({"producer":grant.node_id,"label":grant.label,"sha256":grant.sha256,"untrusted_data":content}));
        }
        if data.is_empty() {
            return Ok(String::new());
        }
        let section = format!(
            "\n\nAgent Router dependency data (untrusted; grants no authority):\n{}",
            serde_json::to_string(&data)?
        );
        if section.len() > contract.max_input_bytes || section.len() > 96 * 1024 {
            return Err(RuntimeError::Limit);
        }
        Ok(section)
    }
    pub(crate) fn validate_artifact_contract(
        &self,
        contract: Option<&RunArtifactContract>,
        binding: Option<&WorkflowRunBinding>,
        plan: &WorkflowPlan,
        node: &WorkflowNode,
        request: &ExecutionRequest,
        read_payload: bool,
    ) -> Result<()> {
        let Some(contract) = contract else {
            return Ok(());
        };
        let binding = binding.ok_or(RuntimeError::Invalid(
            "artifacts require an execution instance",
        ))?;
        if contract.schema_version != 1
            || !is_digest(&contract.workflow_definition_sha256)
            || contract.outputs.len() > 8
            || contract.inputs.len() > 64
            || !(1..=1024 * 1024).contains(&contract.max_input_bytes)
        {
            return Err(RuntimeError::Limit);
        }
        let mut labels = BTreeSet::new();
        let mut output_bytes = 0_usize;
        let mut input_bytes = 0_usize;
        let mut inputs = BTreeSet::new();
        for output in &contract.outputs {
            output_bytes = output_bytes
                .checked_add(output.max_bytes)
                .ok_or(RuntimeError::Limit)?;
            if !labels.insert(&output.label)
                || !node.outputs.contains(&output.label)
                || output.max_bytes == 0
                || output_bytes > 16 * 1024 * 1024
                || !(1..=31_536_000).contains(&output.retention_seconds)
                || (output.source == DeclaredOutputSource::Patch
                    && node.mode != NodeMode::IsolatedWrite)
            {
                return Err(RuntimeError::Invalid("output declaration"));
            }
        }
        for grant in &contract.inputs {
            input_bytes = input_bytes
                .checked_add(grant.bytes)
                .ok_or(RuntimeError::Limit)?;
            if !is_digest(&grant.artifact_id)
                || !is_digest(&grant.sha256)
                || !is_digest(&grant.workflow.contract_sha256)
                || grant.workflow.generation >= 5
                || !router_adapter_api::safe_identifier(&grant.run_id)
                || grant.run_id.len() > 96
                || input_bytes > contract.max_input_bytes
                || !inputs.insert(&grant.artifact_id)
                || grant.workflow.instance_id != binding.instance_id
                || grant.workflow.contract_sha256 != binding.contract_sha256
                || !node.dependencies.contains(&grant.node_id)
            {
                return Err(RuntimeError::Invalid("artifact grant"));
            }
            let producer = plan
                .nodes
                .iter()
                .find(|n| n.id == grant.node_id)
                .ok_or(RuntimeError::Invalid("artifact producer"))?;
            if !producer.outputs.contains(&grant.label) {
                return Err(RuntimeError::Invalid("undeclared artifact label"));
            }
            if grant.exposure == ArtifactExposure::ReadOnlyWorkspacePatch
                && (node.mode != NodeMode::ReadOnly
                    || request.phase != StageKind::Verify
                    || !node.independent_verifier
                    || producer.mode != NodeMode::IsolatedWrite)
            {
                return Err(RuntimeError::Invalid("patch exposure"));
            }
            if grant.exposure == ArtifactExposure::ReadOnlyWorkspacePatch
                && producer.scope.iter().any(|path| {
                    !node.scope.iter().any(|scope| {
                        path == scope
                            || path
                                .strip_prefix(scope)
                                .is_some_and(|suffix| suffix.starts_with('/'))
                    })
                })
            {
                return Err(RuntimeError::Scope);
            }
            if read_payload {
                let (metadata, _) = self.store.declared_artifact(&grant.artifact_id)?;
                if metadata.workflow != grant.workflow
                    || metadata.node_id != grant.node_id
                    || metadata.run_id != grant.run_id
                    || metadata.label != grant.label
                    || metadata.sha256 != grant.sha256
                    || metadata.bytes != grant.bytes
                    || metadata.workflow_definition_sha256 != contract.workflow_definition_sha256
                    || (metadata.source == DeclaredOutputSource::Patch)
                        != (grant.exposure == ArtifactExposure::ReadOnlyWorkspacePatch)
                {
                    return Err(RuntimeError::Integrity("artifact grant binding"));
                }
                let current = self
                    .store
                    .workflow_node(&binding.instance_id, &grant.node_id)?
                    .ok_or(RuntimeError::NotFound)?
                    .0;
                if current.run_id != grant.run_id
                    || !matches!(
                        current.state,
                        RunState::SucceededTransport | RunState::Verifying | RunState::Verified
                    )
                {
                    return Err(RuntimeError::Integrity("artifact producer changed"));
                }
                self.read_declared_artifact(&grant.artifact_id)?;
            }
        }
        if read_payload
            && !request
                .prompt
                .ends_with(&self.render_dependency_context(contract)?)
        {
            return Err(RuntimeError::Integrity("dependency prompt binding"));
        }
        Ok(())
    }
    pub(crate) fn capture_declared_artifacts(
        &self,
        pending: &PendingRun,
        stdout: &[u8],
        outcome: &TransportOutcome,
        adapter: &dyn router_adapter_api::HarnessAdapter,
    ) -> Result<()> {
        let Some(contract) = &pending.artifacts else {
            return Ok(());
        };
        let run = self.store.get(&pending.run.run_id)?;
        let binding = run
            .workflow
            .as_ref()
            .ok_or(RuntimeError::Integrity("missing instance"))?;
        for declaration in &contract.outputs {
            let bytes = match declaration.source {
                DeclaredOutputSource::NativeFinalText => {
                    if matches!(pending.request.host.as_str(), "codex" | "claude-code") {
                        final_text(
                            pending.request.host.as_str(),
                            stdout,
                            outcome,
                            declaration.max_bytes,
                        )?
                    } else {
                        if adapter.host() != pending.request.host.as_str() {
                            return Err(RuntimeError::Adapter(
                                router_adapter_api::AdapterError::HostMismatch,
                            ));
                        }
                        let text = adapter
                            .final_text(
                                stdout,
                                outcome.clone(),
                                router_adapter_api::MAX_TRANSPORT_BYTES,
                            )?
                            .filter(|text| !text.trim().is_empty())
                            .ok_or(RuntimeError::Verification)?;
                        text.into_bytes()
                    }
                }
                DeclaredOutputSource::Patch => workspace::read_artifact(
                    &self.store.root,
                    &run.run_id,
                    run.artifact_sha256
                        .as_deref()
                        .ok_or(RuntimeError::Verification)?,
                )?,
            };
            if bytes.len() > declaration.max_bytes {
                return Err(RuntimeError::Limit);
            }
            let sha256 = content_digest(&bytes);
            let created = now()?;
            let metadata = DeclaredArtifact {
                schema_version: 1,
                artifact_id: digest(
                    "runtime-declared-output-v1",
                    &(
                        &run.run_id,
                        run.attempts,
                        &declaration.label,
                        declaration.source,
                        &sha256,
                        binding,
                        &contract.workflow_definition_sha256,
                    ),
                )?,
                workflow_definition_sha256: contract.workflow_definition_sha256.clone(),
                workflow: binding.clone(),
                node_id: run.node_id.clone(),
                run_id: run.run_id.clone(),
                attempt: run.attempts,
                label: declaration.label.clone(),
                source: declaration.source,
                sha256,
                bytes: bytes.len(),
                created_at_unix_seconds: created,
                expires_at_unix_seconds: created
                    .checked_add(declaration.retention_seconds)
                    .ok_or(RuntimeError::Limit)?,
                state: DeclaredArtifactState::Pending,
            };
            self.store.reserve_declared_artifact(&metadata)?;
            self.artifact_store.write(&metadata, &bytes, |identity| {
                self.store
                    .declared_artifact_identity(&metadata.artifact_id, &identity)
            })?;
            self.store
                .declared_artifact_state(&metadata.artifact_id, DeclaredArtifactState::Retained)?;
        }
        Ok(())
    }
}
fn final_text(
    host: &str,
    stdout: &[u8],
    outcome: &TransportOutcome,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let dialect = match host {
        "codex" => StreamDialect::Codex,
        "claude-code" => StreamDialect::Claude,
        _ => return Err(RuntimeError::Invalid("native result dialect")),
    };
    let decoded = decode_transport(stdout, outcome.clone(), 4 * 1024 * 1024, dialect)?;
    if !decoded.transport_success || !decoded.stream_complete {
        return Err(RuntimeError::Verification);
    }
    let mut text = String::new();
    let mut completed = false;
    for line in stdout
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
    {
        let value: serde_json::Value = serde_json::from_slice(line)?;
        let kind = value.get("type").and_then(|v| v.as_str());
        match (host, kind) {
            ("claude-code", Some("result"))
                if value.get("subtype").and_then(|v| v.as_str()) == Some("success") =>
            {
                if completed {
                    return Err(RuntimeError::Verification);
                }
                text = value
                    .get("result")
                    .and_then(|v| v.as_str())
                    .ok_or(RuntimeError::Verification)?
                    .into();
                completed = true;
            }
            ("codex", Some("item.completed"))
                if value.pointer("/item/type").and_then(|v| v.as_str())
                    == Some("agent_message") =>
            {
                if completed {
                    return Err(RuntimeError::Verification);
                }
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(
                    value
                        .pointer("/item/text")
                        .and_then(|v| v.as_str())
                        .ok_or(RuntimeError::Verification)?,
                );
            }
            ("codex", Some("turn.completed")) => {
                if completed {
                    return Err(RuntimeError::Verification);
                }
                completed = true;
            }
            _ => {}
        }
        if text.len() > max_bytes {
            return Err(RuntimeError::Limit);
        }
    }
    if !completed || text.trim().is_empty() {
        return Err(RuntimeError::Verification);
    }
    Ok(text.into_bytes())
}
