//! Native Claude CLI preparation, with no process or permission-granting code.

use router_adapter_api::{
    AdapterError, HarnessAdapter, StreamDialect, ValidatedExecutionRequest, decode_transport,
    prepared_run, worker_degradations,
};
use router_types::{
    EffortLevel, ExecutionSandbox, PreparedRun, RuntimeEvidence, ToolSelection, TransportOutcome,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct ClaudeAdapter;

impl HarnessAdapter for ClaudeAdapter {
    fn supports_native_version_pin(&self) -> bool {
        true
    }

    fn validate_native_version_pin(
        &self,
        stdout: &[u8],
        expected: &str,
    ) -> Result<(), AdapterError> {
        if stdout.len() > 256 || expected.is_empty() || expected.len() > 128 {
            return Err(AdapterError::Invalid("claude.version.invalid"));
        }
        let text = std::str::from_utf8(stdout)
            .map_err(|_| AdapterError::Invalid("claude.version.invalid"))?;
        let text = text
            .strip_suffix("\r\n")
            .or_else(|| text.strip_suffix('\n'))
            .unwrap_or(text);
        let version = text
            .strip_prefix("")
            .and_then(|text| text.strip_suffix(" (Claude Code)"))
            .ok_or(AdapterError::Invalid("claude.version.invalid"))?;
        if version != expected || !version.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(AdapterError::Invalid("claude.version.mismatch"));
        }
        Ok(())
    }

    fn host(&self) -> &'static str {
        "claude-code"
    }

    fn prepare(&self, validated: &ValidatedExecutionRequest) -> Result<PreparedRun, AdapterError> {
        let request = validated.request();
        if request.host.as_str() != self.host() {
            return Err(AdapterError::HostMismatch);
        }
        let effort = match request.effort {
            EffortLevel::Low => "low",
            EffortLevel::Medium => "medium",
            EffortLevel::High => "high",
            EffortLevel::Xhigh => "xhigh",
            EffortLevel::Max => "max",
            _ => return Err(AdapterError::Unsupported("effort-native-flag")),
        };
        // A registry role is not proof that a same-named host agent is installed.
        let degradations = worker_degradations(request, false)?;
        let permission_mode = match request.sandbox {
            ExecutionSandbox::ReadOnly => "plan",
            ExecutionSandbox::WorkspaceWrite => "manual",
        };
        let mut argv = vec![
            "--print".into(),
            "--output-format".into(),
            "stream-json".into(),
            "--verbose".into(),
            "--input-format".into(),
            "text".into(),
            "--model".into(),
            request.model.to_string(),
            "--effort".into(),
            effort.into(),
            "--permission-mode".into(),
            permission_mode.into(),
            "--permission-prompts".into(),
            "none".into(),
            "--no-session-persistence".into(),
        ];
        match &request.tools {
            ToolSelection::HostPolicy => {}
            ToolSelection::Disabled => argv.extend(["--tools".into(), String::new()]),
            ToolSelection::AllowList(tools) => argv.extend(["--tools".into(), tools.join(",")]),
        }
        prepared_run(validated, "claude", argv, degradations)
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
            router_adapter_api::NativeFailureProtocol::Claude,
        )
    }

    fn decode_stream(
        &self,
        bytes: &[u8],
        outcome: TransportOutcome,
        max_bytes: usize,
    ) -> Result<RuntimeEvidence, AdapterError> {
        decode_transport(bytes, outcome, max_bytes, StreamDialect::Claude)
    }
}

#[cfg(test)]
mod capability_version_tests {
    use super::*;
    #[test]
    fn native_version_pin_requires_exact_bounded_single_line() {
        let adapter = ClaudeAdapter;
        assert!(
            adapter
                .validate_native_version_pin(b"1.2.3 (Claude Code)\n", "1.2.3")
                .is_ok()
        );
        assert!(
            adapter
                .validate_native_version_pin(b"1.2.4 (Claude Code)\n", "1.2.3")
                .is_err()
        );
        assert!(
            adapter
                .validate_native_version_pin(b"1.2.3 (Claude Code)\nignored", "1.2.3")
                .is_err()
        );
        assert!(
            adapter
                .validate_native_version_pin(&vec![b'x'; 257], "1.2.3")
                .is_err()
        );
    }
}
