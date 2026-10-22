#![forbid(unsafe_code)]
//! Copilot CLI JSONL transport. Authentication and OS confinement are supplied
//! by the caller; no model, permission, hook or parent session is activated here.
mod stream;
use router_adapter_api::{
    AdapterError, HarnessAdapter, ValidatedExecutionRequest, content_digest, prepared_run,
    strict_json, worker_degradations,
};
use router_types::{
    EffortLevel, ExecutionSandbox, PreparedRun, RuntimeEvidence, ToolSelection, TransportOutcome,
};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_SOURCE_PACKAGE: &str = "@github/copilot@1.0.44/package/app.js";
pub const PROTOCOL_SOURCE_SHA256: &str =
    "473255d34d10e49702e781686cd04cfbda89bbe42cfd494c820f7d0e02d6b857";
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CopilotProtocol {
    CliJsonlV1,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CopilotConfig {
    pub schema_version: u32,
    /// An expected version is not an observation; verify the approved executable.
    pub expected_cli_version: String,
    pub protocol: CopilotProtocol,
}
#[derive(Clone, Debug)]
pub struct CopilotAdapter {
    config: CopilotConfig,
}
impl CopilotAdapter {
    pub fn new(config: CopilotConfig) -> Result<Self, AdapterError> {
        let version = &config.expected_cli_version;
        if config.schema_version != 1
            || version.is_empty()
            || version.len() > 96
            || !version.bytes().next().is_some_and(|b| b.is_ascii_digit())
            || !version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+-_".contains(&b))
        {
            return Err(AdapterError::Invalid("copilot configuration"));
        }
        Ok(Self { config })
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self, AdapterError> {
        if bytes.len() > 4096 {
            return Err(AdapterError::Invalid("copilot configuration bounds"));
        }
        let value =
            strict_json(bytes).map_err(|_| AdapterError::Invalid("copilot configuration"))?;
        Self::new(
            serde_json::from_value(value)
                .map_err(|_| AdapterError::Invalid("copilot configuration"))?,
        )
    }
    pub fn config(&self) -> &CopilotConfig {
        &self.config
    }
    pub fn config_hash(&self) -> Result<String, AdapterError> {
        let bytes = serde_json::to_vec(&("adapter-copilot-config-v1", &self.config))
            .map_err(|_| AdapterError::Invalid("serialization"))?;
        Ok(content_digest(&bytes))
    }
    /// The same strict parser as decode_stream, retaining only the last root message.
    /// Returned content is untrusted and must not enter ordinary audit or preview logs.
    pub fn final_text(
        &self,
        bytes: &[u8],
        outcome: TransportOutcome,
        max_bytes: usize,
    ) -> Result<Option<String>, AdapterError> {
        stream::final_text(bytes, outcome, max_bytes)
    }
}

/// Exact Commander --version template from the pinned CLI source, not `version`.
pub fn parse_version(bytes: &[u8]) -> Result<String, AdapterError> {
    if bytes.len() > 256 {
        return Err(AdapterError::Invalid("copilot version output"));
    }
    let output =
        std::str::from_utf8(bytes).map_err(|_| AdapterError::Invalid("copilot version output"))?;
    let output = output.replace("\r\n", "\n");
    let value = output
        .strip_prefix("GitHub Copilot CLI ")
        .and_then(|v| v.strip_suffix(".\nRun 'copilot update' to check for updates.\n"))
        .filter(|v| {
            !v.is_empty()
                && v.len() <= 96
                && v.bytes().next().is_some_and(|b| b.is_ascii_digit())
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".+-_".contains(&b))
        })
        .ok_or(AdapterError::Invalid("copilot version output"))?;
    Ok(value.to_owned())
}
fn known_tool(value: &str) -> bool {
    matches!(
        value,
        "bash"
            | "powershell"
            | "list_bash"
            | "list_powershell"
            | "read_bash"
            | "read_powershell"
            | "stop_bash"
            | "stop_powershell"
            | "write_bash"
            | "write_powershell"
            | "apply_patch"
            | "create"
            | "edit"
            | "view"
            | "list_agents"
            | "read_agent"
            | "task"
            | "write_agent"
            | "glob"
            | "grep"
            | "rg"
            | "skill"
            | "web_fetch"
    )
}
impl HarnessAdapter for CopilotAdapter {
    fn supports_native_version_pin(&self) -> bool {
        true
    }
    fn validate_native_version_pin(
        &self,
        stdout: &[u8],
        expected: &str,
    ) -> Result<(), AdapterError> {
        if parse_version(stdout)? != expected {
            return Err(AdapterError::Invalid("copilot.capability.version.mismatch"));
        }
        Ok(())
    }
    fn requires_native_version(&self) -> bool {
        true
    }
    fn validate_native_version(&self, stdout: &[u8]) -> Result<(), AdapterError> {
        if parse_version(stdout)? != self.config.expected_cli_version {
            return Err(AdapterError::Invalid("copilot.version.mismatch"));
        }
        Ok(())
    }
    fn final_text(
        &self,
        bytes: &[u8],
        outcome: TransportOutcome,
        max_bytes: usize,
    ) -> Result<Option<String>, AdapterError> {
        CopilotAdapter::final_text(self, bytes, outcome, max_bytes)
    }
    fn host(&self) -> &'static str {
        "copilot"
    }
    fn prepare(&self, validated: &ValidatedExecutionRequest) -> Result<PreparedRun, AdapterError> {
        let request = validated.request();
        if request.host.as_str() != self.host() {
            return Err(AdapterError::HostMismatch);
        }
        if matches!(request.model.as_str(), "auto" | "default") {
            return Err(AdapterError::Unsupported("automatic-model-alias"));
        }
        let effort = match request.effort {
            EffortLevel::Low => "low",
            EffortLevel::Medium => "medium",
            EffortLevel::High => "high",
            EffortLevel::Xhigh => "xhigh",
            EffortLevel::Max => "max",
            _ => return Err(AdapterError::EffortUnsupported),
        };
        let mut argv = vec![
            "--model".into(),
            request.model.to_string(),
            "--effort".into(),
            effort.into(),
            "--output-format".into(),
            "json".into(),
            "--no-color".into(),
            "--no-auto-update".into(),
            "--no-remote-export".into(),
            "--no-ask-user".into(),
            "--no-bash-env".into(),
            "--no-custom-instructions".into(),
            "--log-level".into(),
            "none".into(),
            "-C".into(),
            request.workspace.clone(),
        ];
        if request.sandbox == ExecutionSandbox::ReadOnly {
            argv.extend(["--mode".into(), "plan".into()]);
        }
        match &request.tools {
            ToolSelection::HostPolicy => {}
            ToolSelection::AllowList(tools)
                if !tools.is_empty() && tools.iter().all(|t| known_tool(t)) =>
            {
                argv.extend(["--available-tools".into(), tools.join(",")]);
            }
            _ => return Err(AdapterError::Unsupported("copilot.tool-selection")),
        }
        let degradations = worker_degradations(request, false)?;
        let mut run = prepared_run(validated, "copilot", argv, degradations)?;
        run.missing_runtime_evidence.extend([
            "native.cli_version_requires_fresh_binary_bound_probe".into(),
            "native.sandbox_requires_supervisor_confinement".into(),
            "native.session_persistence_not_disabled".into(),
        ]);
        Ok(run)
    }
    fn classify_failure(
        &self,
        bytes: &[u8],
        outcome: TransportOutcome,
        max_bytes: usize,
    ) -> Result<Option<router_adapter_api::NativeFailureEvidence>, AdapterError> {
        if !self
            .decode_stream(bytes, outcome.clone(), max_bytes)?
            .stream_complete
        {
            return Ok(None);
        }
        router_adapter_api::classify_native_failure(
            bytes,
            outcome,
            max_bytes,
            router_adapter_api::NativeFailureProtocol::Copilot,
        )
    }

    fn decode_stream(
        &self,
        bytes: &[u8],
        outcome: TransportOutcome,
        max_bytes: usize,
    ) -> Result<RuntimeEvidence, AdapterError> {
        stream::decode(bytes, outcome, max_bytes)
    }
}
