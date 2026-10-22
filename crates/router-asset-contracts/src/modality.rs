//! Typed, bounded contracts for non-text modalities (image, audio, file) and
//! for digest-checked JSON output. Validation is pure: the caller supplies the
//! bytes or metadata, nothing here reads a disk, a network or a model.
//!
//! These contracts do not transport anything. A validated input is not
//! forwarded to a model, and execution stays refused while `ExecutionRequest`
//! carries text only: `router-policy` rejects a nonempty `required_features`
//! at execution time (`asset_phases.rs`), pinned behaviorally by
//! `model_audio_or_format_availability_does_not_invent_adapter_input_support`
//! in `router-policy/tests/asset_phases.rs`. The sibling branch that rejects
//! `output_schema_sha256` (`router-policy/src/asset_phases.rs:349`) has no
//! behavioral test of its own. A passing
//! validation is integrity evidence about bytes, never native support evidence
//! for a model. `Modality::Image`, `Audio` and `File` correspond to
//! `AssetFeature::ImageInput`, `AudioInput` and `FileInput`; audio output has
//! no contract here.
//!
//! What a check does and does not prove:
//!
//! - The media type is declared by the caller and compared byte for byte with a
//!   canonical allow-list (lowercase, no parameters); it is never checked
//!   against the content. `Image/PNG` or `image/png; charset=x` is refused
//!   rather than normalized, so the value approved is the value validated.
//! - The expected sha256 sits in the contract, and `schema_sha256` and
//!   `claimed_sha256` come from the caller or producer. A match detects
//!   corruption, not substitution by whoever supplies both sides.
//! - JSON output is not validated against its schema. It is only checked to
//!   have unique keys, to be an object and to match the claimed digest.
//! - Refusal order for input bytes is media type, empty input, size, digest,
//!   so the digest is never computed over an unlisted or oversized input. Empty
//!   input versus size is not observable, since `max_bytes` is at least 1.
//!   Output order is schema binding, claimed-digest form, size, digest, JSON
//!   shape. Each observable pair is pinned by
//!   `checks_run_in_the_documented_order`.
//! - `image/svg+xml` is refused in every contract: it is XML that can carry
//!   scripts and external references. The `File` family is an explicit
//!   allow-list of data formats for the same reason, so `text/html`,
//!   `application/xml` or `application/javascript` are refused. The repository
//!   declares no file format list (only `AssetFeature::FileInput`), so
//!   `FILE_MEDIA_TYPES` is a local fail-closed choice, not an inherited one.
use crate::{ContractError, Result, is_digest};
use router_adapter_api::{content_digest, strict_json};
use serde::{Deserialize, Serialize};

pub const MAX_MODALITY_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_JSON_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_MEDIA_TYPES: usize = 16;
pub const MAX_MEDIA_TYPE_LEN: usize = 127;
/// Data-only formats accepted for `Modality::File`; everything else is refused.
pub const FILE_MEDIA_TYPES: [&str; 4] = [
    "application/pdf",
    "text/plain",
    "text/csv",
    "application/json",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    Image,
    Audio,
    File,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputContract {
    pub schema_version: u32,
    pub modality: Modality,
    pub allowed_media_types: Vec<String>,
    pub max_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JsonOutputContract {
    pub schema_version: u32,
    pub schema_sha256: String,
    pub max_bytes: u64,
}

/// Result of `InputContract::validate_bytes`; constructible only by validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedInput {
    modality: Modality,
    media_type: String,
    bytes: u64,
    sha256: String,
}
impl ValidatedInput {
    pub fn modality(&self) -> Modality {
        self.modality
    }
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// A JSON object with unique keys whose bytes matched the digest the caller
/// claimed. It is not validated against the schema and the digests are not
/// independently trusted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestCheckedJsonObject {
    schema_sha256: String,
    bytes: u64,
    sha256: String,
}
impl DigestCheckedJsonObject {
    pub fn schema_sha256(&self) -> &str {
        &self.schema_sha256
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$&^_.+-".contains(&b))
}

fn canonical_media_type(value: &str) -> bool {
    let Some((kind, subtype)) = value.split_once('/') else {
        return false;
    };
    value.len() <= MAX_MEDIA_TYPE_LEN && token(kind) && token(subtype)
}

fn allowed_for(modality: Modality, media_type: &str) -> bool {
    if media_type == "image/svg+xml" {
        return false;
    }
    match modality {
        Modality::Image => media_type.starts_with("image/"),
        Modality::Audio => media_type.starts_with("audio/"),
        Modality::File => FILE_MEDIA_TYPES.contains(&media_type),
    }
}

impl InputContract {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.allowed_media_types.is_empty()
            || self.allowed_media_types.len() > MAX_MEDIA_TYPES
            || !is_digest(&self.sha256)
            || !(1..=MAX_MODALITY_BYTES).contains(&self.max_bytes)
        {
            return Err(ContractError::Schema);
        }
        for (index, media_type) in self.allowed_media_types.iter().enumerate() {
            if !canonical_media_type(media_type)
                || !allowed_for(self.modality, media_type)
                || self.allowed_media_types[..index].contains(media_type)
            {
                return Err(ContractError::Schema);
            }
        }
        Ok(())
    }

    /// Checks caller-supplied metadata and bytes in a fixed order: media type,
    /// empty input, size, then digest.
    pub fn validate_bytes(&self, media_type: &str, bytes: &[u8]) -> Result<ValidatedInput> {
        self.validate()?;
        if !self.allowed_media_types.iter().any(|m| m == media_type) {
            return Err(ContractError::Binding);
        }
        if bytes.is_empty() {
            return Err(ContractError::Schema);
        }
        if bytes.len() as u64 > self.max_bytes {
            return Err(ContractError::Limit);
        }
        let actual = content_digest(bytes);
        if actual != self.sha256 {
            return Err(ContractError::Integrity);
        }
        Ok(ValidatedInput {
            modality: self.modality,
            media_type: media_type.to_owned(),
            bytes: bytes.len() as u64,
            sha256: actual,
        })
    }
}

pub fn parse_input_contract(bytes: &[u8]) -> Result<InputContract> {
    if bytes.len() > crate::MAX_DOCUMENT_BYTES {
        return Err(ContractError::Limit);
    }
    let contract: InputContract =
        serde_json::from_value(strict_json(bytes).map_err(|_| ContractError::Schema)?)
            .map_err(|_| ContractError::Schema)?;
    contract.validate()?;
    Ok(contract)
}

impl JsonOutputContract {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || !is_digest(&self.schema_sha256)
            || !(1..=MAX_JSON_OUTPUT_BYTES).contains(&self.max_bytes)
        {
            return Err(ContractError::Schema);
        }
        Ok(())
    }

    /// The output must name the schema digest this contract is bound to, be a
    /// JSON object with unique keys within the size bound, and hash to the
    /// digest the producer claimed. Order: schema binding, claimed digest
    /// form, size, digest, then JSON shape. The schema is not evaluated.
    pub fn validate_output(
        &self,
        schema_sha256: &str,
        claimed_sha256: &str,
        output: &[u8],
    ) -> Result<DigestCheckedJsonObject> {
        self.validate()?;
        if schema_sha256 != self.schema_sha256 {
            return Err(ContractError::Binding);
        }
        if !is_digest(claimed_sha256) {
            return Err(ContractError::Schema);
        }
        if output.len() as u64 > self.max_bytes {
            return Err(ContractError::Limit);
        }
        let actual = content_digest(output);
        if actual != claimed_sha256 {
            return Err(ContractError::Integrity);
        }
        match strict_json(output) {
            Ok(serde_json::Value::Object(_)) => Ok(DigestCheckedJsonObject {
                schema_sha256: self.schema_sha256.clone(),
                bytes: output.len() as u64,
                sha256: actual,
            }),
            _ => Err(ContractError::Schema),
        }
    }
}

pub fn parse_json_output_contract(bytes: &[u8]) -> Result<JsonOutputContract> {
    if bytes.len() > crate::MAX_DOCUMENT_BYTES {
        return Err(ContractError::Limit);
    }
    let contract: JsonOutputContract =
        serde_json::from_value(strict_json(bytes).map_err(|_| ContractError::Schema)?)
            .map_err(|_| ContractError::Schema)?;
    contract.validate()?;
    Ok(contract)
}
