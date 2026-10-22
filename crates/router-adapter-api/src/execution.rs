//! Shared preparation gates. The runtime must authenticate inputs, recompute the
//! route receipt and establish approval before supplying an approval digest.

use std::{
    collections::BTreeSet,
    path::{Component, Path},
};

use router_types::{
    AdapterDegradation, Capability, EffectiveRestrictions, ExecutionMode, ExecutionRequest,
    ExecutionSandbox, ExecutionSkillKind, ExecutionTarget, HostUsage, ModelId, Mutation,
    ObservedModel, PreparedInput, PreparedRun, RuntimeEvidence, SkillTrust, ToolSelection,
    TransportEvent, TransportEventKind, TransportOutcome, TransportTermination, UsageField,
    VerificationOutcome,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{ValidatedHostObservation, strict_json};

pub const MAX_EXECUTION_INPUT_BYTES: usize = 128 * 1024;
pub const MAX_TRANSPORT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TRANSPORT_EVENTS: usize = 2048;

/// A cause observed in documented native metadata, never in model/tool text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFailureKind {
    Authentication,
    RateLimit,
    Network,
}

/// Redacted evidence. No deserializer or arbitrary constructor can turn a
/// supplied class label into a validated native observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeFailureEvidence {
    kind: NativeFailureKind,
    code: &'static str,
    source_sha256: String,
}
impl NativeFailureEvidence {
    pub fn kind(&self) -> NativeFailureKind {
        self.kind
    }
    pub fn code(&self) -> &'static str {
        self.code
    }
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFailureProtocol {
    Claude,
    Codex,
    OpenCode,
    Copilot,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum AdapterError {
    #[error("capability.attestation.network_admission_required")]
    NetworkAdmissionRequired,
    #[error("adapter.input.invalid: {0}")]
    Invalid(&'static str),
    #[error("adapter.host.mismatch")]
    HostMismatch,
    #[error("adapter.model.unsupported")]
    ModelUnsupported,
    #[error("adapter.effort.unsupported")]
    EffortUnsupported,
    #[error("adapter.capability.unknown_or_denied")]
    CapabilityDenied,
    #[error("adapter.permission.denied")]
    PermissionDenied,
    #[error("adapter.approval.required_or_mismatched")]
    ApprovalRequired,
    #[error("adapter.unsupported: {0}")]
    Unsupported(&'static str),
    #[error("adapter.output.limit")]
    OutputLimit,
    #[error("adapter.protocol.invalid")]
    Protocol,
}

/// Cannot be deserialised from an untrusted receipt or a provider response.
#[derive(Clone, Debug)]
pub struct ValidatedExecutionRequest {
    request: ExecutionRequest,
    snapshot_hash: String,
    authorization_digest: String,
}

impl ValidatedExecutionRequest {
    pub fn request(&self) -> &ExecutionRequest {
        &self.request
    }
    pub fn snapshot_hash(&self) -> &str {
        &self.snapshot_hash
    }
    pub fn authorization_digest(&self) -> &str {
        &self.authorization_digest
    }
}

pub trait HarnessAdapter {
    fn host(&self) -> &'static str;
    /// Classify only a complete, validated native stdout stream after an
    /// observed nonzero exit. Stderr is deliberately absent from this API.
    /// None means the runtime must retain its generic crash classification.
    fn classify_failure(
        &self,
        _bytes: &[u8],
        _outcome: TransportOutcome,
        _max_bytes: usize,
    ) -> Result<Option<NativeFailureEvidence>, AdapterError> {
        Ok(None)
    }
    fn requires_native_version(&self) -> bool {
        false
    }
    /// Compare a freshly supervised --version response to the approved pin.
    fn validate_native_version(&self, _stdout: &[u8]) -> Result<(), AdapterError> {
        Err(AdapterError::Unsupported("native-version"))
    }
    /// Native adapters that can compare a proof's version pin at dispatch.
    fn supports_native_version_pin(&self) -> bool {
        false
    }
    /// Compare a fresh bounded native version response to authenticated evidence.
    fn validate_native_version_pin(
        &self,
        stdout: &[u8],
        expected: &str,
    ) -> Result<(), AdapterError> {
        self.validate_native_version(stdout)?;
        let _ = expected;
        Err(AdapterError::Unsupported("capability-version-pin"))
    }
    /// Complete native answer text for an explicitly declared private artifact.
    /// Implementations must exclude tools, reasoning and incomplete streams.
    fn final_text(
        &self,
        _bytes: &[u8],
        _outcome: TransportOutcome,
        _max_bytes: usize,
    ) -> Result<Option<String>, AdapterError> {
        Err(AdapterError::Unsupported("native-final-text"))
    }
    fn prepare(&self, request: &ValidatedExecutionRequest) -> Result<PreparedRun, AdapterError>;
    fn decode_stream(
        &self,
        bytes: &[u8],
        outcome: TransportOutcome,
        max_bytes: usize,
    ) -> Result<RuntimeEvidence, AdapterError>;
}

/// Shared Copilot root-envelope predicate for decoding and classification.
/// `agentId` is an optional native string. Explicit null is not root evidence.
pub fn copilot_root_event(value: &serde_json::Value) -> bool {
    value.get("agentId").is_none()
        && ["parent_tool_use_id", "subagent_type"]
            .iter()
            .all(|key| value.get(key).is_none_or(|v| v.is_null()))
        && ["/data/initiator", "/data/parentToolCallId"]
            .iter()
            .all(|key| value.pointer(key).is_none())
        && value
            .pointer("/data/interactionType")
            .is_none_or(|v| matches!(v.as_str(), Some("conversation-agent" | "conversation-user")))
}

/// Conservative failure metadata extraction for the documented native
/// protocols. Adapters also run their complete transport decoder first.
///
/// Provenance and source hashes are recorded in tests/native_failures.md.
/// This is evidence from an approved native transport, not authentication of a
/// provider or permission to retry. Unknown/contradictory events remain unknown.
pub fn classify_native_failure(
    bytes: &[u8],
    outcome: TransportOutcome,
    max_bytes: usize,
    protocol: NativeFailureProtocol,
) -> Result<Option<NativeFailureEvidence>, AdapterError> {
    if max_bytes == 0 || max_bytes > MAX_TRANSPORT_BYTES || bytes.len() > max_bytes {
        return Err(AdapterError::OutputLimit);
    }
    if outcome.termination != TransportTermination::Exited || outcome.exit_code == Some(0) {
        return Ok(None);
    }
    let exit_code = outcome
        .exit_code
        .ok_or(AdapterError::Invalid("transport status"))?;
    let mut observed = None;
    let mut conflicting = false;
    let mut terminal = false;
    let mut session = None::<String>;
    for (sequence, line) in bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .enumerate()
    {
        if sequence >= MAX_TRANSPORT_EVENTS || line.len() > 256 * 1024 {
            return Err(AdapterError::OutputLimit);
        }
        let value = strict_json(line).map_err(|_| AdapterError::Protocol)?;
        let kind = value
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or(AdapterError::Protocol)?;
        // Native task/subagent events cannot classify the parent worker.
        let root = if matches!(protocol, NativeFailureProtocol::Copilot) {
            copilot_root_event(&value)
        } else {
            native_root_event(&value)
        };
        if !root {
            continue;
        }
        let mut found = None;
        match protocol {
            NativeFailureProtocol::Codex => {
                // ThreadErrorEvent contains only message:String. Never inspect
                // that text or invented fields such as status/code/retryable.
            }
            NativeFailureProtocol::Claude => {
                if matches!(kind, "assistant" | "result")
                    || (kind == "system"
                        && value.get("subtype").and_then(|v| v.as_str()) == Some("init"))
                {
                    bind_failure_session(&mut session, value.get("session_id"))?;
                }
                match kind {
                    "assistant" => {
                        terminal = false;
                        if value.get("parent_tool_use_id").is_none()
                            || value.pointer("/message/type").and_then(|v| v.as_str())
                                != Some("message")
                            || value.pointer("/message/role").and_then(|v| v.as_str())
                                != Some("assistant")
                        {
                            return Err(AdapterError::Protocol);
                        }
                        found = match value.get("error").and_then(|v| v.as_str()) {
                            Some("authentication_failed" | "oauth_org_not_allowed") => Some((
                                NativeFailureKind::Authentication,
                                "claude.assistant.authentication",
                            )),
                            Some("rate_limit") => {
                                Some((NativeFailureKind::RateLimit, "claude.assistant.rate_limit"))
                            }
                            _ => None,
                        };
                        // A new non-error assistant turn can be recovery. An
                        // unsupported native error cannot inherit an old class.
                        if found.is_none() {
                            observed = None;
                            conflicting = false;
                        }
                    }
                    "result" => {
                        terminal = value.get("is_error").and_then(|v| v.as_bool()) == Some(true)
                            && matches!(
                                value.get("subtype").and_then(|v| v.as_str()),
                                Some("success" | "error_during_execution")
                            );
                        if !terminal {
                            observed = None;
                        }
                        if terminal
                            && value.get("subtype").and_then(|v| v.as_str()) == Some("success")
                        {
                            found = match value.get("api_error_status").and_then(|v| v.as_u64()) {
                                Some(401) => Some((
                                    NativeFailureKind::Authentication,
                                    "claude.result.http_401",
                                )),
                                Some(429) => {
                                    Some((NativeFailureKind::RateLimit, "claude.result.http_429"))
                                }
                                _ => None,
                            };
                            // A present unsupported or malformed terminal status
                            // cannot inherit an older assistant's cause.
                            if found.is_none() && value.get("api_error_status").is_some() {
                                observed = None;
                                conflicting = true;
                            }
                        }
                    }
                    _ => {
                        terminal = false;
                    }
                }
            }
            NativeFailureProtocol::OpenCode => {
                bind_failure_session(&mut session, value.get("sessionID"))?;
                if value.get("timestamp").and_then(|v| v.as_u64()).is_none() {
                    return Err(AdapterError::Protocol);
                }
                if kind == "error" {
                    terminal = true;
                    let error = value.get("error").ok_or(AdapterError::Protocol)?;
                    let name = error
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or(AdapterError::Protocol)?;
                    let data = error
                        .get("data")
                        .and_then(|v| v.as_object())
                        .ok_or(AdapterError::Protocol)?;
                    if data.get("message").and_then(|v| v.as_str()).is_none() {
                        return Err(AdapterError::Protocol);
                    }
                    found = match name {
                        "ProviderAuthError"
                            if data
                                .get("providerID")
                                .and_then(|v| v.as_str())
                                .is_some_and(safe_identifier) =>
                        {
                            Some((NativeFailureKind::Authentication, "opencode.provider_auth"))
                        }
                        "APIError"
                            if data.get("isRetryable").and_then(|v| v.as_bool()).is_some() =>
                        {
                            match data.get("statusCode").and_then(|v| v.as_u64()) {
                                Some(401 | 403) => Some((
                                    NativeFailureKind::Authentication,
                                    "opencode.api.authentication",
                                )),
                                Some(429) => {
                                    Some((NativeFailureKind::RateLimit, "opencode.api.http_429"))
                                }
                                None if !data.contains_key("statusCode")
                                    && data.get("isRetryable").and_then(|v| v.as_bool())
                                        == Some(true)
                                    && error
                                        .pointer("/data/metadata/code")
                                        .and_then(|v| v.as_str())
                                        == Some("ECONNRESET") =>
                                {
                                    Some((
                                        NativeFailureKind::Network,
                                        "opencode.api.connection_reset",
                                    ))
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    };
                    if found.is_none() {
                        conflicting = true;
                    }
                } else {
                    // No classification survives a later successful or new
                    // step/message/tool event, including unknown future events.
                    terminal = false;
                    observed = None;
                    conflicting = false;
                }
            }
            NativeFailureProtocol::Copilot => {
                if kind == "result" {
                    bind_failure_session(&mut session, value.get("sessionId"))?;
                    terminal = value.get("exitCode").and_then(|v| v.as_i64())
                        == Some(i64::from(exit_code));
                    if !terminal {
                        return Err(AdapterError::Protocol);
                    }
                } else {
                    if value
                        .get("id")
                        .and_then(|v| v.as_str())
                        .is_none_or(|v| !safe_identifier(v))
                        || value
                            .get("timestamp")
                            .and_then(|v| v.as_str())
                            .is_none_or(|v| v.is_empty() || v.len() > 64)
                        || !value
                            .get("parentId")
                            .is_some_and(|v| v.is_null() || v.as_str().is_some_and(safe_identifier))
                    {
                        return Err(AdapterError::Protocol);
                    }
                    if kind == "session.start" {
                        bind_failure_session(&mut session, value.pointer("/data/sessionId"))?;
                    }
                    if kind == "session.error" {
                        if value
                            .pointer("/data/message")
                            .and_then(|v| v.as_str())
                            .is_none()
                        {
                            return Err(AdapterError::Protocol);
                        }
                        found = match (
                            value.pointer("/data/errorType").and_then(|v| v.as_str()),
                            value.pointer("/data/statusCode").and_then(|v| v.as_u64()),
                        ) {
                            (Some("authentication" | "authorization"), Some(401 | 403)) => Some((
                                NativeFailureKind::Authentication,
                                "copilot.session.authentication",
                            )),
                            (Some("rate_limit"), Some(429)) => {
                                Some((NativeFailureKind::RateLimit, "copilot.session.http_429"))
                            }
                            _ => None,
                        };
                        if found.is_none() {
                            conflicting = true;
                        }
                    } else {
                        // Later activity, including deltas and unknown future
                        // events, cannot carry an older cause into a new result.
                        observed = None;
                        conflicting = false;
                    }
                    terminal = false;
                }
            }
        }
        if let Some((kind, code)) = found {
            if observed.as_ref().is_some_and(|(prior, _)| *prior != kind) {
                conflicting = true;
            }
            observed = Some((kind, code));
        }
    }
    Ok(observed
        .filter(|_| terminal && !conflicting)
        .map(|(kind, code)| NativeFailureEvidence {
            kind,
            code,
            source_sha256: content_digest(bytes),
        }))
}

fn bind_failure_session(
    session: &mut Option<String>,
    value: Option<&serde_json::Value>,
) -> Result<(), AdapterError> {
    let current = value
        .and_then(|v| v.as_str())
        .filter(|v| safe_identifier(v))
        .ok_or(AdapterError::Protocol)?;
    if session.as_ref().is_some_and(|prior| prior != current) {
        return Err(AdapterError::Protocol);
    }
    session.get_or_insert_with(|| current.to_owned());
    Ok(())
}

pub fn execution_authorization_digest(
    request: &ExecutionRequest,
    snapshot: &ValidatedHostObservation,
    restrictions: &EffectiveRestrictions,
) -> Result<String, AdapterError> {
    execution_authorization_digest_with_capability_acceptance(
        request,
        snapshot,
        restrictions,
        &crate::CapabilityAcceptance::proven_only(),
    )
}
pub fn execution_authorization_digest_with_capability_acceptance(
    request: &ExecutionRequest,
    snapshot: &ValidatedHostObservation,
    restrictions: &EffectiveRestrictions,
    acceptance: &crate::CapabilityAcceptance,
) -> Result<String, AdapterError> {
    let mut hash = Sha256::new();
    if acceptance.accepted().is_empty() {
        hash.update(b"agent-router:execution-authorization:v1\0");
        hash.update(
            serde_json::to_vec(&(request, snapshot.hash(), restrictions))
                .map_err(|_| AdapterError::Invalid("serialization"))?,
        );
    } else {
        hash.update(b"agent-router:execution-authorization:v2\0");
        hash.update(
            serde_json::to_vec(&(
                request,
                snapshot.hash(),
                restrictions,
                acceptance.policy_hash(),
                acceptance.accepted(),
                snapshot.capability_proofs(),
            ))
            .map_err(|_| AdapterError::Invalid("serialization"))?,
        );
    }
    Ok(hex::encode(hash.finalize()))
}
pub fn authorize_execution(
    request: ExecutionRequest,
    snapshot: &ValidatedHostObservation,
    restrictions: &EffectiveRestrictions,
    approved_digest: Option<&str>,
) -> Result<ValidatedExecutionRequest, AdapterError> {
    authorize_execution_with_capability_acceptance(
        request,
        snapshot,
        restrictions,
        &crate::CapabilityAcceptance::proven_only(),
        approved_digest,
    )
}
pub fn authorize_execution_with_capability_acceptance(
    request: ExecutionRequest,
    snapshot: &ValidatedHostObservation,
    restrictions: &EffectiveRestrictions,
    acceptance: &crate::CapabilityAcceptance,
    approved_digest: Option<&str>,
) -> Result<ValidatedExecutionRequest, AdapterError> {
    validate_request(&request)?;
    if restrictions.schema_version != 1 || !is_digest(&restrictions.policy_hash) {
        return Err(AdapterError::Invalid("restrictions"));
    }
    if request.host != snapshot.host().harness {
        return Err(AdapterError::HostMismatch);
    }
    if !snapshot.host().supported_models.contains(&request.model)
        || restrictions
            .allowed_models
            .as_ref()
            .is_some_and(|models| !models.contains(&request.model))
    {
        return Err(AdapterError::ModelUnsupported);
    }
    if !snapshot
        .host()
        .supported_efforts
        .get(&request.model)
        .is_some_and(|efforts| efforts.contains(&request.effort))
    {
        return Err(AdapterError::EffortUnsupported);
    }
    let mut required = request.required_capabilities.clone();
    if !matches!(request.tools, ToolSelection::Disabled) {
        required.insert(Capability::Tools);
    }
    if request.sandbox == ExecutionSandbox::WorkspaceWrite {
        required.insert(Capability::WorkspaceWrite);
    }
    for capability in &required {
        if *capability == Capability::Network
            && snapshot.capability_proofs().iter().any(|proof| {
                proof.capability == *capability
                    && proof.tier == crate::CapabilityProofTier::Attested
            })
        {
            return Err(AdapterError::NetworkAdmissionRequired);
        }
        if !snapshot.permits_capability(*capability, acceptance)
            || restrictions
                .allowed_capabilities
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(capability))
        {
            return Err(AdapterError::CapabilityDenied);
        }
    }
    for (needed, mutation) in [
        (
            request.sandbox == ExecutionSandbox::WorkspaceWrite,
            Mutation::WorkspaceWrite,
        ),
        (required.contains(&Capability::Network), Mutation::Network),
    ] {
        if needed
            && !restrictions
                .allowed_mutations
                .as_ref()
                .is_some_and(|allowed| allowed.contains(&mutation))
        {
            return Err(AdapterError::PermissionDenied);
        }
    }
    let authorization_digest = execution_authorization_digest_with_capability_acceptance(
        &request,
        snapshot,
        restrictions,
        acceptance,
    )?;
    if request.mode == ExecutionMode::Execute
        && approved_digest != Some(authorization_digest.as_str())
    {
        return Err(AdapterError::ApprovalRequired);
    }
    Ok(ValidatedExecutionRequest {
        request,
        snapshot_hash: snapshot.hash().into(),
        authorization_digest,
    })
}

fn validate_request(request: &ExecutionRequest) -> Result<(), AdapterError> {
    if request.schema_version != 1
        || !is_digest(&request.receipt_id)
        || !safe_identifier(&request.candidate_id)
        || !safe_identifier(request.model.as_str())
        || matches!(
            request.model.as_str(),
            "opus" | "sonnet" | "haiku" | "fable"
        )
        || !matches!(request.source_state.len(), 40 | 64)
        || !request
            .source_state
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(AdapterError::Invalid("identity"));
    }
    let workspace = Path::new(&request.workspace);
    if !workspace.is_absolute()
        || workspace.components().count() < 2
        || workspace
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        || request.workspace.contains(['\0', '\n', '\r'])
    {
        return Err(AdapterError::Invalid("workspace"));
    }
    if request.scope.len() > 256
        || (request.sandbox == ExecutionSandbox::WorkspaceWrite && request.scope.is_empty())
    {
        return Err(AdapterError::Invalid("scope"));
    }
    let mut scopes = BTreeSet::new();
    for scope in &request.scope {
        if scope.is_empty()
            || scope.len() > 1024
            || scope.contains(['\0', '\n', '\r', '\\'])
            || !Path::new(scope)
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
            // Path::components() normalizes `a//b`, `a/./b` and `a/`; only the
            // canonical spelling is accepted so the duplicate check is exact.
            || scope
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !scopes.insert(scope)
        {
            return Err(AdapterError::Invalid("scope"));
        }
    }
    if request.target == ExecutionTarget::ParentConversation {
        return Err(AdapterError::Unsupported("parent-model-change"));
    }
    if request
        .agent
        .as_ref()
        .is_some_and(|agent| !safe_identifier(agent))
    {
        return Err(AdapterError::Invalid("agent"));
    }
    if let ToolSelection::AllowList(tools) = &request.tools {
        let unique: BTreeSet<_> = tools.iter().collect();
        if tools.is_empty()
            || tools.len() > 64
            || unique.len() != tools.len()
            || tools.iter().any(|tool| !safe_identifier(tool))
        {
            return Err(AdapterError::Invalid("tools"));
        }
    }
    if request.prompt.trim().is_empty()
        || request.prompt.contains('\0')
        || request.skills.len() > 16
        || request.timeout_ms == 0
        || request.timeout_ms > 86_400_000
        || request.max_output_bytes == 0
        || request.max_output_bytes > MAX_TRANSPORT_BYTES
    {
        return Err(AdapterError::Invalid("bounds"));
    }
    let mut size = request.prompt.len();
    let mut skills = BTreeSet::new();
    for skill in &request.skills {
        if skill.kind != ExecutionSkillKind::Instruction {
            return Err(AdapterError::Unsupported("executable-skill"));
        }
        if !matches!(
            skill.trust,
            SkillTrust::Builtin | SkillTrust::TrustedLocal | SkillTrust::VerifiedThirdParty
        ) {
            return Err(AdapterError::PermissionDenied);
        }
        if !safe_identifier(skill.id.as_str())
            || !skills.insert(&skill.id)
            || skill.body.contains('\0')
            || !is_digest(&skill.content_sha256)
            || content_digest(skill.body.as_bytes()) != skill.content_sha256
        {
            return Err(AdapterError::Invalid("skill"));
        }
        size = size
            .checked_add(skill.body.len())
            .ok_or(AdapterError::Invalid("bounds"))?;
    }
    if size > MAX_EXECUTION_INPUT_BYTES {
        return Err(AdapterError::Invalid("bounds"));
    }
    Ok(())
}

pub fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}

pub fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
pub fn content_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn worker_degradations(
    request: &ExecutionRequest,
    native_agent: bool,
) -> Result<Vec<AdapterDegradation>, AdapterError> {
    let mut result = Vec::new();
    if request.target == ExecutionTarget::NativeSubagent {
        if !request.allow_degradation {
            return Err(AdapterError::Unsupported("native-subagent-dispatch"));
        }
        result.push(AdapterDegradation {
            code: "target.external_worker".into(),
            requested: "native_subagent".into(),
            applied: "external_worker".into(),
        });
    }
    if request.agent.is_some() && !native_agent {
        if !request.allow_degradation {
            return Err(AdapterError::Unsupported("named-agent"));
        }
        result.push(AdapterDegradation {
            code: "agent.prompt_role".into(),
            requested: request.agent.clone().unwrap_or_default(),
            applied: "generic_worker_with_role_instruction".into(),
        });
    }
    Ok(result)
}

pub fn prepared_run(
    validated: &ValidatedExecutionRequest,
    program: &str,
    argv: Vec<String>,
    degradations: Vec<AdapterDegradation>,
) -> Result<PreparedRun, AdapterError> {
    let request = validated.request();
    let mut input = request.prompt.clone();
    if let Some(agent) = &request.agent {
        input.push_str(&format!("\n\nRequested role: {agent}\n"));
    }
    for skill in &request.skills {
        input.push_str(&format!(
            "\n\nSelected instruction {} (sha256={}):\n{}\n",
            skill.id, skill.content_sha256, skill.body
        ));
    }
    if input.len() > MAX_EXECUTION_INPUT_BYTES {
        return Err(AdapterError::Invalid("rendered prompt bounds"));
    }
    Ok(PreparedRun {
        schema_version: 1,
        receipt_id: request.receipt_id.clone(),
        authorization_digest: validated.authorization_digest.clone(),
        source_state: request.source_state.clone(),
        scope: request.scope.clone(),
        snapshot_hash: validated.snapshot_hash.clone(),
        host: request.host.clone(),
        requested_model: request.model.clone(),
        requested_effort: request.effort,
        program: program.into(),
        argv,
        cwd: request.workspace.clone(),
        stdin: PreparedInput::new(input.into_bytes()),
        mode: request.mode,
        target: ExecutionTarget::ExternalWorker,
        sandbox: request.sandbox,
        timeout_ms: request.timeout_ms,
        max_output_bytes: request.max_output_bytes,
        degradations,
        missing_runtime_evidence: vec![
            "sandbox.enforced_by_supervisor_and_host_not_proven_by_preparation".into(),
            "model.execution.not_observed".into(),
            "objective.not_verified".into(),
        ],
        parent_model_changed: false,
    })
}

/// True unless the native event belongs to a subagent, task or sampling turn.
pub fn native_root_event(value: &serde_json::Value) -> bool {
    ["parent_tool_use_id", "agentId", "subagent_type"]
        .iter()
        .all(|key| value.get(key).is_none_or(|v| v.is_null()))
        && ["/data/initiator", "/data/parentToolCallId"]
            .iter()
            .all(|key| value.pointer(key).is_none())
        && value
            .pointer("/data/interactionType")
            .is_none_or(|v| matches!(v.as_str(), Some("conversation-agent" | "conversation-user")))
}

/// True only when `line` is the segment that ends `bytes`. A content match such
/// as `bad\nbad` must not excuse an earlier malformed line.
pub fn is_final_segment(bytes: &[u8], line: &[u8]) -> bool {
    line.as_ptr() as usize + line.len() == bytes.as_ptr() as usize + bytes.len()
}

#[derive(Clone, Copy)]
pub enum StreamDialect {
    Codex,
    Claude,
}

pub fn decode_transport(
    bytes: &[u8],
    outcome: TransportOutcome,
    max_bytes: usize,
    dialect: StreamDialect,
) -> Result<RuntimeEvidence, AdapterError> {
    if max_bytes == 0 || max_bytes > MAX_TRANSPORT_BYTES || bytes.len() > max_bytes {
        return Err(AdapterError::OutputLimit);
    }
    if outcome.termination == TransportTermination::Exited && outcome.exit_code.is_none() {
        return Err(AdapterError::Invalid("transport status"));
    }
    let mut events = Vec::new();
    let mut models = Vec::new();
    let mut stream_complete = true;
    let mut usage = UsageCollector::default();
    for (sequence, line) in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        if sequence >= MAX_TRANSPORT_EVENTS || line.len() > 256 * 1024 {
            return Err(AdapterError::OutputLimit);
        }
        let value = match strict_json(line) {
            Ok(value) => value,
            Err(_)
                if outcome.termination != TransportTermination::Exited
                    && !bytes.ends_with(b"\n")
                    && is_final_segment(bytes, line) =>
            {
                stream_complete = false;
                break;
            }
            Err(_) => return Err(AdapterError::Protocol),
        };
        let kind = value
            .get("type")
            .and_then(|value| value.as_str())
            .ok_or(AdapterError::Protocol)?;
        let event = match (dialect, kind) {
            (StreamDialect::Codex, "thread.started") => TransportEventKind::SessionStarted,
            (StreamDialect::Codex, "turn.started") => TransportEventKind::TurnStarted,
            (StreamDialect::Codex, "turn.completed") => {
                usage.codex_turn(&value);
                TransportEventKind::TurnCompleted
            }
            (StreamDialect::Codex, "turn.failed" | "error") => TransportEventKind::HostError,
            (StreamDialect::Codex, "item.completed")
                if value.pointer("/item/type").and_then(|v| v.as_str())
                    == Some("agent_message") =>
            {
                TransportEventKind::AssistantMessage
            }
            (StreamDialect::Codex, "item.started" | "item.completed" | "item.updated") => {
                TransportEventKind::ToolActivity
            }
            (StreamDialect::Claude, "system")
                if value.get("subtype").and_then(|v| v.as_str()) == Some("init") =>
            {
                TransportEventKind::SessionStarted
            }
            (StreamDialect::Claude, "assistant") => {
                // A subagent's model is never attributed to the root worker.
                if native_root_event(&value)
                    && value.pointer("/message/role").and_then(|v| v.as_str()) == Some("assistant")
                    && value.pointer("/message/type").and_then(|v| v.as_str()) == Some("message")
                {
                    if let Some(model) = value
                        .pointer("/message/model")
                        .and_then(|v| v.as_str())
                        .filter(|id| safe_identifier(id))
                    {
                        let model = ModelId::parse(model).map_err(|_| AdapterError::Protocol)?;
                        if !models
                            .iter()
                            .any(|observed: &ObservedModel| observed.model == model)
                        {
                            models.push(ObservedModel {
                                model,
                                source: "supervised-native-assistant-message.model".into(),
                                source_sha256: content_digest(line),
                            });
                        }
                    }
                }
                TransportEventKind::AssistantMessage
            }
            (StreamDialect::Claude, "result")
                if value.get("is_error").and_then(|v| v.as_bool()) == Some(true) =>
            {
                TransportEventKind::HostError
            }
            (StreamDialect::Claude, "result")
                if value.get("is_error").and_then(|v| v.as_bool()) == Some(false) =>
            {
                // A subagent result is never attributed to the root worker.
                if native_root_event(&value) {
                    usage.claude_result(&value);
                }
                TransportEventKind::TurnCompleted
            }
            (StreamDialect::Claude, "result") => return Err(AdapterError::Protocol),
            (StreamDialect::Claude, "user") => TransportEventKind::ToolActivity,
            _ => TransportEventKind::Ignored,
        };
        events.push(TransportEvent {
            sequence,
            kind: event,
        });
    }
    models.sort_by(|left, right| left.model.cmp(&right.model));
    stream_complete &= events.iter().any(|event| {
        matches!(
            event.kind,
            TransportEventKind::TurnCompleted | TransportEventKind::HostError
        )
    });
    let mut missing_evidence = vec![
        "validation.not_run".into(),
        "objective.not_verified".into(),
        "effort.runtime_unknown".into(),
    ];
    if models.is_empty() {
        missing_evidence.push("model.runtime_unknown".into());
    }
    if !stream_complete {
        missing_evidence.push("stream.truncated".into());
    }
    // Usage from a truncated stream, a killed process or a host error is
    // partial or unreliable, so none is reported.
    let usable_usage = stream_complete
        && outcome.termination == TransportTermination::Exited
        && outcome.exit_code == Some(0)
        && !events
            .iter()
            .any(|event| event.kind == TransportEventKind::HostError);
    Ok(RuntimeEvidence {
        schema_version: 1,
        transport_success: outcome.termination == TransportTermination::Exited
            && outcome.exit_code == Some(0),
        transport: outcome,
        stream_complete,
        validation: VerificationOutcome::Unknown,
        objective: VerificationOutcome::Unknown,
        executed_models: models,
        executed_effort: None,
        events,
        missing_evidence,
        host_usage: if usable_usage { usage.finish() } else { None },
    })
}

/// One declared count: absent, valid, or present but unusable.
enum Count {
    Absent,
    Valid(u64),
    Invalid,
}

fn count(value: Option<&serde_json::Value>, key: &str) -> Count {
    match value.and_then(|v| v.get(key)) {
        None | Some(serde_json::Value::Null) => Count::Absent,
        // Negative, fractional and oversized numbers are refused, not clamped.
        Some(v) => match v.as_u64().filter(|n| *n <= HostUsage::MAX_TOKENS) {
            Some(n) => Count::Valid(n),
            None => Count::Invalid,
        },
    }
}

/// Accumulator for one field. Input that omits the field or
/// declares it unusably makes the field UNKNOWN: a partial sum would
/// understate.
#[derive(Default)]
struct Sum {
    total: u64,
    seen: u32,
    spoiled: bool,
}

impl Sum {
    fn add(&mut self, count: Count) {
        match count {
            Count::Valid(n) => match self.total.checked_add(n) {
                Some(total) if total <= HostUsage::MAX_TOKENS => {
                    self.total = total;
                    self.seen += 1;
                }
                _ => self.spoiled = true,
            },
            Count::Absent | Count::Invalid => self.spoiled = true,
        }
    }
    fn value(&self) -> Option<u64> {
        (!self.spoiled && self.seen > 0).then_some(self.total)
    }
}

/// Collects the usage a host declares in its own stream. Reads counts only:
/// no assistant text, cost or model name is copied out.
#[derive(Default)]
struct UsageCollector {
    input: Sum,
    cached_input: Sum,
    cache_write_input: Sum,
    output: Sum,
    reasoning_output: Sum,
    /// Claude only: a second root `result` makes cumulative or per-turn
    /// semantics ambiguous, so usage becomes UNKNOWN.
    claude_results: u32,
    /// Codex: more than one `turn.completed` is ambiguous in the same way.
    codex_turns: u32,
}

impl UsageCollector {
    /// Codex `turn.completed.usage`, stored as declared. Codex is assumed to
    /// report cached input and cache writes inside `input_tokens`, and reasoning
    /// inside `output_tokens` (see `HostUsage`). A second turn makes usage UNKNOWN.
    fn codex_turn(&mut self, event: &serde_json::Value) {
        self.codex_turns += 1;
        let usage = event.get("usage").filter(|u| u.is_object());
        self.input.add(count(usage, "input_tokens"));
        self.cached_input.add(count(usage, "cached_input_tokens"));
        self.cache_write_input
            .add(count(usage, "cache_write_input_tokens"));
        self.output.add(count(usage, "output_tokens"));
        self.reasoning_output
            .add(count(usage, "reasoning_output_tokens"));
    }

    /// Claude root `result.usage`. The API reports cache reads and writes
    /// next to `input_tokens`, not inside it, so the normalized `input_tokens`
    /// is the sum of the three. One unusable cache count makes `input_tokens`
    /// and both cache fields UNKNOWN. An absent cache count adds nothing to the
    /// input. No reasoning field is documented, so it stays UNKNOWN.
    fn claude_result(&mut self, event: &serde_json::Value) {
        self.claude_results += 1;
        let usage = event.get("usage").filter(|u| u.is_object());
        let write = count(usage, "cache_creation_input_tokens");
        let read = count(usage, "cache_read_input_tokens");
        let cache_ok = !matches!(write, Count::Invalid) && !matches!(read, Count::Invalid);
        let declared = |c: &Count| if let Count::Valid(n) = c { *n } else { 0 };
        match (count(usage, "input_tokens"), cache_ok) {
            (Count::Valid(base), true) => {
                let total = base
                    .saturating_add(declared(&write))
                    .saturating_add(declared(&read));
                self.input.add(Count::Valid(total));
            }
            _ => self.input.add(Count::Invalid),
        }
        if cache_ok {
            self.cached_input.add(read);
            self.cache_write_input.add(write);
        } else {
            self.cached_input.add(Count::Invalid);
            self.cache_write_input.add(Count::Invalid);
        }
        self.output.add(count(usage, "output_tokens"));
    }

    fn finish(self) -> Option<HostUsage> {
        if self.claude_results > 1 || self.codex_turns > 1 {
            return None;
        }
        let field = |sum: &Sum| {
            sum.value()
                .map_or(UsageField::UNKNOWN, UsageField::host_reported)
        };
        let usage = HostUsage {
            input_tokens: field(&self.input),
            cached_input_tokens: field(&self.cached_input),
            cache_write_input_tokens: field(&self.cache_write_input),
            output_tokens: field(&self.output),
            reasoning_output_tokens: field(&self.reasoning_output),
        };
        [
            usage.input_tokens,
            usage.cached_input_tokens,
            usage.cache_write_input_tokens,
            usage.output_tokens,
            usage.reasoning_output_tokens,
        ]
        .iter()
        .any(|f| f.tokens.is_some())
        .then_some(usage)
    }
}
