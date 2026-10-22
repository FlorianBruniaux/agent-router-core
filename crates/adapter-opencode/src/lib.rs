#![forbid(unsafe_code)]
//! Explicit OpenCode run-v1 transport for the existing supervised runtime.
//! This library launches nothing and cannot prove a configured CLI is installed.
mod stream;
use router_adapter_api::{
    AdapterError, HarnessAdapter, ValidatedExecutionRequest, content_digest, prepared_run,
    safe_identifier, strict_json, worker_degradations,
};
use router_types::{
    EffortLevel, ModelId, PreparedRun, RuntimeEvidence, ToolSelection, TransportOutcome,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PROTOCOL_SOURCE_COMMIT: &str = "b471c2b4495747353af768fbf2e0790c9d820ce2";
pub const PROTOCOL_SOURCE_SHA256: &str =
    "bde848ca17f30834beb4ef0dfecb3b819730746ec2023c1ac55ecef7ca25dd37";
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenCodeProtocol {
    RunV1,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeConfig {
    pub schema_version: u32,
    /// Operator pin; the caller must verify the actual approved binary/version.
    pub expected_cli_version: String,
    pub protocol: OpenCodeProtocol,
    /// Explicit provider-specific mappings. No universal effort mapping exists.
    pub model_variants: BTreeMap<ModelId, BTreeMap<EffortLevel, String>>,
}
#[derive(Clone, Debug)]
pub struct OpenCodeAdapter {
    config: OpenCodeConfig,
}
impl OpenCodeAdapter {
    pub fn new(config: OpenCodeConfig) -> Result<Self, AdapterError> {
        if config.schema_version != 1
            || !version(&config.expected_cli_version)
            || config.model_variants.is_empty()
            || config.model_variants.len() > 64
        {
            return Err(AdapterError::Invalid("opencode configuration"));
        }
        for (model, variants) in &config.model_variants {
            if !qualified_model(model.as_str())
                || variants.is_empty()
                || variants.len() > 9
                || variants.values().any(|v| !variant(v))
            {
                return Err(AdapterError::Invalid("opencode model variants"));
            }
        }
        Ok(Self { config })
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self, AdapterError> {
        if bytes.len() > 64 * 1024 {
            return Err(AdapterError::Invalid("opencode configuration bounds"));
        }
        let value =
            strict_json(bytes).map_err(|_| AdapterError::Invalid("opencode configuration"))?;
        Self::new(
            serde_json::from_value(value)
                .map_err(|_| AdapterError::Invalid("opencode configuration"))?,
        )
    }
    pub fn config(&self) -> &OpenCodeConfig {
        &self.config
    }
    pub fn config_hash(&self) -> Result<String, AdapterError> {
        let bytes = serde_json::to_vec(&("adapter-opencode-config-v1", &self.config))
            .map_err(|_| AdapterError::Invalid("serialization"))?;
        Ok(content_digest(&bytes))
    }
    /// Extract only the final completed message through the same bounded decoder.
    /// The caller must treat this content as untrusted, potentially confidential data.
    pub fn final_text(
        &self,
        bytes: &[u8],
        outcome: TransportOutcome,
        max_bytes: usize,
    ) -> Result<Option<String>, AdapterError> {
        stream::final_text(bytes, outcome, max_bytes)
    }
}

/// Parse the exact single-line yargs version output. This grants no capabilities.
pub fn parse_version(bytes: &[u8]) -> Result<String, AdapterError> {
    if bytes.len() > 128 {
        return Err(AdapterError::Invalid("opencode version output"));
    }
    let output =
        std::str::from_utf8(bytes).map_err(|_| AdapterError::Invalid("opencode version output"))?;
    let value = output
        .strip_suffix("\r\n")
        .or_else(|| output.strip_suffix('\n'))
        .filter(|v| version(v))
        .ok_or(AdapterError::Invalid("opencode version output"))?;
    Ok(value.to_owned())
}
fn version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.bytes().next().is_some_and(|b| b.is_ascii_digit())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+-_".contains(&b))
}
fn variant(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn qualified_model(value: &str) -> bool {
    safe_identifier(value)
        && value.split_once('/').is_some_and(|(provider, model)| {
            !provider.is_empty()
                && !model.is_empty()
                && model != "auto"
                && model != "default"
                && !model.contains('/')
        })
}
impl HarnessAdapter for OpenCodeAdapter {
    fn supports_native_version_pin(&self) -> bool {
        true
    }
    fn validate_native_version_pin(
        &self,
        stdout: &[u8],
        expected: &str,
    ) -> Result<(), AdapterError> {
        if parse_version(stdout)? != expected {
            return Err(AdapterError::Invalid(
                "opencode.capability.version.mismatch",
            ));
        }
        Ok(())
    }
    fn requires_native_version(&self) -> bool {
        true
    }
    fn validate_native_version(&self, stdout: &[u8]) -> Result<(), AdapterError> {
        if parse_version(stdout)? != self.config.expected_cli_version {
            return Err(AdapterError::Invalid("opencode.version.mismatch"));
        }
        Ok(())
    }
    fn final_text(
        &self,
        bytes: &[u8],
        outcome: TransportOutcome,
        max_bytes: usize,
    ) -> Result<Option<String>, AdapterError> {
        OpenCodeAdapter::final_text(self, bytes, outcome, max_bytes)
    }
    fn host(&self) -> &'static str {
        "opencode"
    }
    fn prepare(&self, validated: &ValidatedExecutionRequest) -> Result<PreparedRun, AdapterError> {
        let request = validated.request();
        if request.host.as_str() != self.host() {
            return Err(AdapterError::HostMismatch);
        }
        if !matches!(request.tools, ToolSelection::HostPolicy) {
            return Err(AdapterError::Unsupported("opencode.tool-selection"));
        }
        let variant = self
            .config
            .model_variants
            .get(&request.model)
            .and_then(|v| v.get(&request.effort))
            .ok_or(AdapterError::EffortUnsupported)?;
        let argv = vec![
            "run".into(),
            "--model".into(),
            request.model.to_string(),
            "--variant".into(),
            variant.clone(),
            "--format".into(),
            "json".into(),
            "--dir".into(),
            request.workspace.clone(),
        ];
        let degradations = worker_degradations(request, false)?;
        let mut run = prepared_run(validated, "opencode", argv, degradations)?;
        run.missing_runtime_evidence.extend([
            "native.cli_version_requires_fresh_binary_bound_probe".into(),
            "native.variant_execution_not_observed".into(),
            "native.sandbox_requires_supervisor_confinement".into(),
            "native.session_persistence_and_share_policy_not_controlled_by_adapter".into(),
        ]);
        Ok(run)
    }
    fn classify_failure(
        &self,
        bytes: &[u8],
        outcome: TransportOutcome,
        max_bytes: usize,
    ) -> Result<Option<router_adapter_api::NativeFailureEvidence>, AdapterError> {
        self.decode_stream(bytes, outcome.clone(), max_bytes)?;
        router_adapter_api::classify_native_failure(
            bytes,
            outcome,
            max_bytes,
            router_adapter_api::NativeFailureProtocol::OpenCode,
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
