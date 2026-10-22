//! Native Codex CLI preparation. Process supervision belongs to router-runtime.

use router_adapter_api::{
    AdapterError, HarnessAdapter, StreamDialect, ValidatedExecutionRequest, decode_transport,
    prepared_run, worker_degradations,
};
use router_types::{
    ExecutionSandbox, PreparedRun, RuntimeEvidence, ToolSelection, TransportOutcome,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct CodexAdapter;

impl HarnessAdapter for CodexAdapter {
    fn supports_native_version_pin(&self) -> bool {
        true
    }

    fn validate_native_version_pin(
        &self,
        stdout: &[u8],
        expected: &str,
    ) -> Result<(), AdapterError> {
        if stdout.len() > 256 || expected.is_empty() || expected.len() > 128 {
            return Err(AdapterError::Invalid("codex.version.invalid"));
        }
        let text = std::str::from_utf8(stdout)
            .map_err(|_| AdapterError::Invalid("codex.version.invalid"))?;
        let text = text
            .strip_suffix("\r\n")
            .or_else(|| text.strip_suffix('\n'))
            .unwrap_or(text);
        let version = text
            .strip_prefix("codex-cli ")
            .and_then(|text| text.strip_suffix(""))
            .ok_or(AdapterError::Invalid("codex.version.invalid"))?;
        if version != expected || !version.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(AdapterError::Invalid("codex.version.mismatch"));
        }
        Ok(())
    }

    fn host(&self) -> &'static str {
        "codex"
    }

    fn prepare(&self, validated: &ValidatedExecutionRequest) -> Result<PreparedRun, AdapterError> {
        let request = validated.request();
        if request.host.as_str() != self.host() {
            return Err(AdapterError::HostMismatch);
        }
        // The observed CLI has no per-run tool allowlist. Never broaden a subset.
        if !matches!(request.tools, ToolSelection::HostPolicy) {
            return Err(AdapterError::Unsupported("tool-selection"));
        }
        let degradations = worker_degradations(request, false)?;
        let effort =
            serde_json::to_string(&request.effort).map_err(|_| AdapterError::Invalid("effort"))?;
        let sandbox = match request.sandbox {
            ExecutionSandbox::ReadOnly => "read-only",
            ExecutionSandbox::WorkspaceWrite => "workspace-write",
        };
        let argv = vec![
            "exec".into(),
            "--model".into(),
            request.model.to_string(),
            "--config".into(),
            format!("model_reasoning_effort={effort}"),
            "--sandbox".into(),
            sandbox.into(),
            "--json".into(),
            "--ephemeral".into(),
            "--color".into(),
            "never".into(),
            "--cd".into(),
            request.workspace.clone(),
            "-".into(),
        ];
        prepared_run(validated, "codex", argv, degradations)
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
            router_adapter_api::NativeFailureProtocol::Codex,
        )
    }

    fn decode_stream(
        &self,
        bytes: &[u8],
        outcome: TransportOutcome,
        max_bytes: usize,
    ) -> Result<RuntimeEvidence, AdapterError> {
        decode_transport(bytes, outcome, max_bytes, StreamDialect::Codex)
    }
}

#[cfg(test)]
mod capability_version_tests {
    use super::*;
    #[test]
    fn native_version_pin_requires_exact_bounded_single_line() {
        let adapter = CodexAdapter;
        assert!(
            adapter
                .validate_native_version_pin(b"codex-cli 1.2.3\n", "1.2.3")
                .is_ok()
        );
        assert!(
            adapter
                .validate_native_version_pin(b"codex-cli 1.2.4\n", "1.2.3")
                .is_err()
        );
        assert!(
            adapter
                .validate_native_version_pin(b"codex-cli 1.2.3\nignored", "1.2.3")
                .is_err()
        );
        assert!(
            adapter
                .validate_native_version_pin(&vec![b'x'; 257], "1.2.3")
                .is_err()
        );
    }
}
