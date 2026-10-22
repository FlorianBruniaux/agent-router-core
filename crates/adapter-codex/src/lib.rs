#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::Read,
    path::PathBuf,
};

use router_adapter_api::{
    ALL_CAPABILITIES, CapabilityEvidence, EvidenceKind, EvidenceSource, HostObservation, HostProbe,
    MAX_SNAPSHOT_MODELS, ProbeError, SNAPSHOT_SCHEMA_VERSION, strict_json,
};
use router_types::{CapabilitySupport, EffortLevel, HarnessId, HostSnapshot, ModelId};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const MAX_MODEL_CACHE_BYTES: usize = 4 * 1024 * 1024;
const SOURCE_ID: &str = "codex-model-cache";

#[derive(Clone, Debug)]
pub struct CodexProbeConfig {
    pub model_cache_path: PathBuf,
    /// An independently observed host version. None means the host version is
    /// unknown; the cache's client version remains only cache provenance.
    pub observed_version: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CodexProbe {
    config: CodexProbeConfig,
}

impl CodexProbe {
    pub fn new(config: CodexProbeConfig) -> Self {
        Self { config }
    }
}

#[derive(Deserialize)]
struct ModelCache {
    fetched_at: String,
    client_version: String,
    models: Vec<CachedModel>,
}

#[derive(Deserialize)]
struct CachedModel {
    slug: String,
    supported_reasoning_levels: Vec<CachedEffort>,
}

#[derive(Deserialize)]
struct CachedEffort {
    effort: EffortLevel,
}

impl HostProbe for CodexProbe {
    /// Reads one regular file. No Codex subprocess, network, configuration read,
    /// credential lookup, session creation, or write occurs here.
    fn probe(&self, observed_at_unix_seconds: u64) -> Result<HostObservation, ProbeError> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // A FIFO must not block before the regular-file check. The final
            // path component must also be the selected file, not a symlink.
            options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
        }
        let file = options
            .open(&self.config.model_cache_path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    ProbeError::Unavailable
                } else {
                    ProbeError::Read
                }
            })?;
        if !file.metadata().map_err(|_| ProbeError::Read)?.is_file() {
            return Err(ProbeError::InvalidCache("not a regular file"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_MODEL_CACHE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ProbeError::Read)?;
        if bytes.len() > MAX_MODEL_CACHE_BYTES {
            return Err(ProbeError::CacheTooLarge);
        }
        let cache: ModelCache = serde_json::from_value(
            strict_json(&bytes).map_err(|_| ProbeError::InvalidCache("json"))?,
        )
        .map_err(|_| ProbeError::InvalidCache("schema"))?;
        if cache.models.is_empty() || cache.models.len() > MAX_SNAPSHOT_MODELS {
            return Err(ProbeError::InvalidCache("model bounds"));
        }
        if self
            .config
            .observed_version
            .as_ref()
            .is_some_and(|version| version != &cache.client_version)
        {
            return Err(ProbeError::VersionMismatch);
        }
        let source_timestamp = parse_cache_timestamp(&cache.fetched_at)?;
        let mut supported_models = BTreeSet::new();
        let mut supported_efforts = BTreeMap::new();
        for model in cache.models {
            let id =
                ModelId::parse(model.slug).map_err(|_| ProbeError::InvalidCache("model id"))?;
            if !supported_models.insert(id.clone()) {
                return Err(ProbeError::InvalidCache("duplicate model"));
            }
            if model.supported_reasoning_levels.is_empty()
                || model.supported_reasoning_levels.len() > 8
            {
                return Err(ProbeError::InvalidCache("effort bounds"));
            }
            let mut efforts = BTreeSet::new();
            for level in model.supported_reasoning_levels {
                if !efforts.insert(level.effort) {
                    return Err(ProbeError::InvalidCache("duplicate effort"));
                }
            }
            supported_efforts.insert(id, efforts);
        }
        let source_ids = BTreeSet::from([SOURCE_ID.to_owned()]);
        let observation = HostObservation {
            attestations: None,
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            host: HostSnapshot {
                id: "codex-local-cache".into(),
                harness: HarnessId::parse("codex")
                    .map_err(|_| ProbeError::InvalidCache("harness"))?,
                supported_models,
                supported_efforts,
                capabilities: BTreeSet::new(),
            },
            capabilities: ALL_CAPABILITIES
                .into_iter()
                .map(|capability| {
                    (
                        capability,
                        CapabilityEvidence {
                            support: CapabilitySupport::Unknown,
                            source_ids: source_ids.clone(),
                        },
                    )
                })
                .collect(),
            evidence: vec![EvidenceSource {
                id: SOURCE_ID.into(),
                kind: EvidenceKind::CodexModelCache,
                observed_version: Some(cache.client_version),
                observed_at_unix_seconds: source_timestamp,
                content_sha256: hex::encode(Sha256::digest(&bytes)),
            }],
            observed_at_unix_seconds,
            snapshot_hash: String::new(),
        };
        observation.seal().map_err(Into::into)
    }
}

/// The observed cache format uses UTC RFC3339 timestamps. Offset timestamps and
/// leap seconds are rejected rather than interpreted using local timezone state.
fn parse_cache_timestamp(value: &str) -> Result<u64, ProbeError> {
    let invalid = || ProbeError::InvalidCache("timestamp");
    let bytes = value.as_bytes();
    if !(20..=30).contains(&bytes.len())
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes.last() != Some(&b'Z')
    {
        return Err(invalid());
    }
    if bytes.len() > 20
        && (bytes[19] != b'.'
            || bytes.len() < 22
            || !bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit))
    {
        return Err(invalid());
    }
    let number = |start: usize, end: usize| -> Result<u64, ProbeError> {
        bytes[start..end].iter().try_fold(0, |number, byte| {
            if byte.is_ascii_digit() {
                Ok(number * 10 + u64::from(byte - b'0'))
            } else {
                Err(invalid())
            }
        })
    };
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    if year < 1970 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return Err(invalid());
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > month_days[month as usize - 1] {
        return Err(invalid());
    }
    let leap_years_before = |year: u64| (year - 1) / 4 - (year - 1) / 100 + (year - 1) / 400;
    let days = (year - 1970) * 365 + leap_years_before(year) - leap_years_before(1970)
        + month_days[..month as usize - 1].iter().sum::<u64>()
        + day
        - 1;
    Ok(days * 86_400 + hour * 3600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::parse_cache_timestamp;

    #[test]
    fn timestamp_dates_and_fractional_seconds_are_utc() {
        assert_eq!(parse_cache_timestamp("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            parse_cache_timestamp("2000-03-01T00:00:00Z").unwrap(),
            951_868_800
        );
        assert_eq!(
            parse_cache_timestamp("2024-02-29T23:59:59.123456Z").unwrap(),
            1_709_251_199
        );
        for invalid in [
            "2023-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-09-01T24:00:00Z",
            "2026-09-01T00:00:60Z",
            "2026-09-01T00:00:00.Z",
            "2026-09-01T00:00:00+02:00",
            "1969-12-31T23:59:59Z",
            "2026-00-00T00:00:00Z",
            "é",
        ] {
            assert!(parse_cache_timestamp(invalid).is_err(), "{invalid}");
        }
    }
}
mod execution;
pub use execution::CodexAdapter;
