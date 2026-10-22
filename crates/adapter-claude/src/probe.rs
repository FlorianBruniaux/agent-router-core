//! Passive projection of explicitly supplied native stream evidence. No files,
//! credentials, network, executable discovery or provider invocation are read.

use std::collections::{BTreeMap, BTreeSet};

use router_adapter_api::{
    ALL_CAPABILITIES, CapabilityEvidence, EvidenceKind, EvidenceSource, HostObservation, HostProbe,
    MAX_SNAPSHOT_MODELS, MAX_TRANSPORT_BYTES, ProbeError, content_digest, native_root_event,
    safe_identifier, strict_json,
};
use router_types::{CapabilitySupport, HarnessId, HostSnapshot, ModelId};

pub struct ClaudeStreamProbe<'a> {
    bytes: &'a [u8],
}

impl<'a> ClaudeStreamProbe<'a> {
    pub fn from_native_stream(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl HostProbe for ClaudeStreamProbe<'_> {
    fn probe(&self, observed_at_unix_seconds: u64) -> Result<HostObservation, ProbeError> {
        if self.bytes.is_empty() {
            return Err(ProbeError::Unavailable);
        }
        if self.bytes.len() > MAX_TRANSPORT_BYTES {
            return Err(ProbeError::CacheTooLarge);
        }
        let mut version = None;
        let mut initialized_model = None;
        let mut models = BTreeSet::new();
        let mut count = 0;
        for line in self
            .bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            count += 1;
            if count > 2048 || line.len() > 256 * 1024 {
                return Err(ProbeError::CacheTooLarge);
            }
            let value = strict_json(line).map_err(|_| ProbeError::InvalidCache("native stream"))?;
            match value.get("type").and_then(|value| value.as_str()) {
                Some("system")
                    if value.get("subtype").and_then(|value| value.as_str()) == Some("init") =>
                {
                    if version.is_some() {
                        return Err(ProbeError::InvalidCache("duplicate init"));
                    }
                    version = value
                        .get("claude_code_version")
                        .and_then(|value| value.as_str())
                        .filter(|version| safe_identifier(version))
                        .map(str::to_owned);
                    initialized_model = value
                        .get("model")
                        .and_then(|value| value.as_str())
                        .filter(|model| safe_identifier(model))
                        .map(str::to_owned);
                    if version.is_none() || initialized_model.is_none() {
                        return Err(ProbeError::InvalidCache("native init"));
                    }
                }
                // Sidechain (subagent) models are not models the root host serves.
                Some("assistant")
                    if native_root_event(&value)
                        && value
                            .pointer("/message/role")
                            .and_then(|value| value.as_str())
                            == Some("assistant")
                        && value
                            .pointer("/message/type")
                            .and_then(|value| value.as_str())
                            == Some("message") =>
                {
                    if let Some(model) = value
                        .pointer("/message/model")
                        .and_then(|value| value.as_str())
                        .filter(|model| safe_identifier(model))
                    {
                        models.insert(
                            ModelId::parse(model).map_err(|_| ProbeError::InvalidCache("model"))?,
                        );
                        if models.len() > MAX_SNAPSHOT_MODELS {
                            return Err(ProbeError::InvalidCache("model bounds"));
                        }
                    }
                }
                Some(_) => {}
                None => return Err(ProbeError::InvalidCache("native event type")),
            }
        }
        if initialized_model.is_none() {
            return Err(ProbeError::InvalidCache("missing native init"));
        }
        // The init model is a configured label and never proves a model. Only
        // root assistant `message.model` values are observed; no alias is
        // resolved and no date suffix is stripped. Effort and tools stay unknown.
        if models.is_empty() {
            return Err(ProbeError::InvalidCache("model not observed"));
        }
        let source_id = "claude-native-stream".to_string();
        let evidence = vec![EvidenceSource {
            id: source_id.clone(),
            kind: EvidenceKind::ClaudeNativeStream,
            observed_version: version.clone(),
            observed_at_unix_seconds,
            content_sha256: content_digest(self.bytes),
        }];
        let capabilities = ALL_CAPABILITIES
            .into_iter()
            .map(|capability| {
                (
                    capability,
                    CapabilityEvidence {
                        support: CapabilitySupport::Unknown,
                        source_ids: BTreeSet::new(),
                    },
                )
            })
            .collect();
        HostObservation {
            attestations: None,
            schema_version: 1,
            host: HostSnapshot {
                id: format!("claude-native:{}", content_digest(self.bytes)),
                harness: HarnessId::parse("claude-code")
                    .map_err(|_| ProbeError::InvalidCache("host"))?,
                supported_models: models,
                supported_efforts: BTreeMap::new(),
                capabilities: BTreeSet::new(),
            },
            capabilities,
            evidence,
            observed_at_unix_seconds,
            snapshot_hash: String::new(),
        }
        .seal()
        .map_err(ProbeError::Snapshot)
    }
}
