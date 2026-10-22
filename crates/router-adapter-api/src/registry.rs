//! Inert validation of adapter descriptors (`integrations/*/adapter.json`).
//!
//! This module parses caller-supplied bytes only. It never reads the file
//! system, loads, resolves or executes an `entry_point`, installs anything or
//! verifies a signature. A descriptor that validates is data, not authority:
//! `activation` must be `none` and capability claims stay UNKNOWN.

use std::collections::{BTreeMap, BTreeSet};

use router_types::{Capability, CapabilitySupport};
use serde::Deserialize;
use thiserror::Error;

use crate::{ALL_CAPABILITIES, strict_json};

pub const DESCRIPTOR_SCHEMA_VERSION: u32 = 1;
pub const DESCRIPTOR_KIND: &str = "agent-router-adapter-descriptor";
pub const DESCRIPTOR_CONTRACT: &str = "HarnessAdapter";
pub const MAX_DESCRIPTOR_BYTES: usize = 16 * 1024;
pub const MAX_DESCRIPTORS: usize = 32;
const MAX_NAME_BYTES: usize = 64;
const MAX_ENTRY_POINT_BYTES: usize = 256;
const MAX_VERSION_BYTES: usize = 128;
const MAX_REQUIRES: usize = 16;

/// Names that no adapter may use as host or crate. This list is a choice of
/// this slice (ADR 0016), not derived from an external registry. Comparison is
/// done on the normalized form, see [`normalize_name`].
pub const RESERVED_NAMES: [&str; 11] = [
    "router",
    "agent-router",
    "native",
    "core",
    "builtin",
    "none",
    "unknown",
    "default",
    "all",
    "system",
    "local",
];
/// Host and crate names starting with one of these prefixes (normalized form)
/// are reserved for the product.
pub const RESERVED_PREFIXES: [&str; 2] = ["router_", "agent_router"];
/// Minimum `requires` set. A descriptor may add entries but never drop these:
/// they mirror the execution gate (receipt, bound authorization, sandbox).
pub const REQUIRED_GATES: [&str; 3] = [
    "validated-phase-receipt",
    "bound-authorization",
    "supervised-sandbox",
];

/// Cargo treats `-` and `_` as the same character in a library name, so every
/// reserved and conflict comparison uses this form.
pub fn normalize_name(name: &str) -> String {
    name.replace('-', "_")
}

fn is_reserved(name: &str) -> bool {
    let normalized = normalize_name(name);
    RESERVED_NAMES
        .iter()
        .any(|reserved| normalize_name(reserved) == normalized)
        || RESERVED_PREFIXES
            .iter()
            .any(|prefix| normalized.starts_with(prefix))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum AdapterMode {
    DryRun,
    Shadow,
    Execute,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdapterTarget {
    ExternalWorker,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDescriptor {
    schema_version: u32,
    kind: String,
    host: String,
    #[serde(rename = "crate")]
    crate_name: String,
    contract: String,
    observed_client_version: String,
    entry_point: String,
    modes: Vec<AdapterMode>,
    target: AdapterTarget,
    activation: String,
    native_plugin_manifest: bool,
    requires: Vec<String>,
    /// Optional. A descriptor may only restate UNKNOWN; support is evidence.
    #[serde(default)]
    capabilities: BTreeMap<Capability, CapabilitySupport>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RegistryError {
    #[error("descriptor.too_large")]
    TooLarge,
    #[error("descriptor.set.too_large")]
    TooManyDescriptors,
    #[error("descriptor.json.invalid")]
    InvalidJson,
    #[error("descriptor.invalid: {0}")]
    Invalid(&'static str),
    #[error("descriptor.activation.not_none")]
    ActivationNotNone,
    #[error("descriptor.name.reserved")]
    ReservedName,
    #[error("descriptor.capability.claimed")]
    CapabilityClaimed,
    #[error("descriptor.conflict: {0}")]
    Conflict(&'static str),
}

impl RegistryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooLarge => "descriptor.too_large",
            Self::TooManyDescriptors => "descriptor.set.too_large",
            Self::InvalidJson => "descriptor.json.invalid",
            Self::Invalid(_) => "descriptor.invalid",
            Self::ActivationNotNone => "descriptor.activation.not_none",
            Self::ReservedName => "descriptor.name.reserved",
            Self::CapabilityClaimed => "descriptor.capability.claimed",
            Self::Conflict(_) => "descriptor.conflict",
        }
    }
}

/// A descriptor that passed structural validation. Inert: holding one grants
/// no activation, and `entry_point` is text that is never resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterDescriptor {
    host: String,
    crate_name: String,
    observed_client_version: String,
    entry_point: String,
    target: AdapterTarget,
    modes: BTreeSet<AdapterMode>,
    native_plugin_manifest: bool,
    requires: BTreeSet<String>,
    capabilities: BTreeMap<Capability, CapabilitySupport>,
}

impl AdapterDescriptor {
    pub fn parse(bytes: &[u8]) -> Result<Self, RegistryError> {
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(RegistryError::TooLarge);
        }
        // strict_json rejects repeated object keys; deny_unknown_fields
        // rejects unlisted fields, so nothing is ignored silently.
        let value = strict_json(bytes).map_err(|_| RegistryError::InvalidJson)?;
        let raw: RawDescriptor =
            serde_json::from_value(value).map_err(|_| RegistryError::InvalidJson)?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: RawDescriptor) -> Result<Self, RegistryError> {
        if raw.schema_version != DESCRIPTOR_SCHEMA_VERSION {
            return Err(RegistryError::Invalid("schema_version"));
        }
        if raw.kind != DESCRIPTOR_KIND {
            return Err(RegistryError::Invalid("kind"));
        }
        if raw.contract != DESCRIPTOR_CONTRACT {
            return Err(RegistryError::Invalid("contract"));
        }
        if raw.activation != "none" {
            return Err(RegistryError::ActivationNotNone);
        }
        if !valid_name(&raw.host) {
            return Err(RegistryError::Invalid("host"));
        }
        if !valid_name(&raw.crate_name) {
            return Err(RegistryError::Invalid("crate"));
        }
        if is_reserved(&raw.host) || is_reserved(&raw.crate_name) {
            return Err(RegistryError::ReservedName);
        }
        if raw.native_plugin_manifest {
            // Native plugin proof is a separate criterion; not accepted here.
            return Err(RegistryError::Invalid("native_plugin_manifest"));
        }
        let version = &raw.observed_client_version;
        if version.is_empty()
            || version.len() > MAX_VERSION_BYTES
            || !version.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(RegistryError::Invalid("observed_client_version"));
        }
        if !valid_entry_point(&raw.entry_point) {
            return Err(RegistryError::Invalid("entry_point"));
        }
        // The entry point must live in the declared crate. `host` is only a
        // label: without a signature (out of slice) it is not an identity.
        let entry_crate = raw.entry_point.split("::").next().unwrap_or_default();
        if entry_crate != normalize_name(&raw.crate_name) {
            return Err(RegistryError::Invalid("entry_point crate mismatch"));
        }
        let modes: BTreeSet<AdapterMode> = raw.modes.iter().copied().collect();
        if modes.is_empty() || modes.len() != raw.modes.len() {
            return Err(RegistryError::Invalid("modes"));
        }
        let requires: BTreeSet<String> = raw.requires.iter().cloned().collect();
        if requires.len() != raw.requires.len()
            || requires.len() > MAX_REQUIRES
            || !requires.iter().all(|item| valid_name(item))
        {
            return Err(RegistryError::Invalid("requires"));
        }
        if !REQUIRED_GATES.iter().all(|gate| requires.contains(*gate)) {
            return Err(RegistryError::Invalid("requires minimum"));
        }
        if raw
            .capabilities
            .values()
            .any(|support| *support != CapabilitySupport::Unknown)
        {
            return Err(RegistryError::CapabilityClaimed);
        }
        // Complete matrix: anything not stated is UNKNOWN.
        let capabilities = ALL_CAPABILITIES
            .into_iter()
            .map(|capability| (capability, CapabilitySupport::Unknown))
            .collect();
        Ok(Self {
            host: raw.host,
            crate_name: raw.crate_name,
            observed_client_version: raw.observed_client_version,
            entry_point: raw.entry_point,
            target: raw.target,
            modes,
            native_plugin_manifest: raw.native_plugin_manifest,
            requires,
            capabilities,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn crate_name(&self) -> &str {
        &self.crate_name
    }

    pub fn observed_client_version(&self) -> &str {
        &self.observed_client_version
    }

    /// Text only. Never loaded, resolved or executed by this crate.
    pub fn entry_point(&self) -> &str {
        &self.entry_point
    }

    pub fn target(&self) -> AdapterTarget {
        self.target
    }

    pub fn modes(&self) -> &BTreeSet<AdapterMode> {
        &self.modes
    }

    pub fn native_plugin_manifest(&self) -> bool {
        self.native_plugin_manifest
    }

    pub fn requires(&self) -> &BTreeSet<String> {
        &self.requires
    }

    /// Always UNKNOWN for every capability.
    pub fn capabilities(&self) -> &BTreeMap<Capability, CapabilitySupport> {
        &self.capabilities
    }
}

/// A conflict-free set of validated descriptors, ordered by normalized host.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdapterRegistry {
    descriptors: BTreeMap<String, AdapterDescriptor>,
}

impl AdapterRegistry {
    /// Parses every document and refuses the whole set on the first error.
    pub fn from_documents(documents: &[&[u8]]) -> Result<Self, RegistryError> {
        if documents.len() > MAX_DESCRIPTORS {
            return Err(RegistryError::TooManyDescriptors);
        }
        let mut descriptors = BTreeMap::new();
        let mut crates = BTreeSet::new();
        for document in documents {
            let descriptor = AdapterDescriptor::parse(document)?;
            // The entry point is bound to the crate, so a crate conflict also
            // covers entry points.
            let host = normalize_name(descriptor.host());
            if descriptors.contains_key(&host) {
                return Err(RegistryError::Conflict("host"));
            }
            if !crates.insert(normalize_name(descriptor.crate_name())) {
                return Err(RegistryError::Conflict("crate"));
            }
            descriptors.insert(host, descriptor);
        }
        Ok(Self { descriptors })
    }

    pub fn get(&self, host: &str) -> Option<&AdapterDescriptor> {
        self.descriptors.get(&normalize_name(host))
    }

    pub fn iter(&self) -> impl Iterator<Item = &AdapterDescriptor> {
        self.descriptors.values()
    }

    pub fn len(&self) -> usize {
        self.descriptors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.descriptors.is_empty()
    }
}

/// Lowercase ASCII letters, digits, `-` and `_`; must start with a letter.
fn valid_name(value: &str) -> bool {
    value.len() <= MAX_NAME_BYTES
        && value.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// A Rust-style path of at least two `::` separated identifiers. This refuses
/// absolute paths (`/x`, `C:\x`, a leading `::`), `..`, `.`, separators and
/// whitespace by construction, so the value cannot name a file.
fn valid_entry_point(value: &str) -> bool {
    if value.len() > MAX_ENTRY_POINT_BYTES {
        return false;
    }
    let segments: Vec<&str> = value.split("::").collect();
    segments.len() >= 2
        && segments.iter().all(|segment| {
            segment
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}
