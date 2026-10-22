//! Private finite-client preparation contract. Data alone grants no launch authority.
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FiniteClientFile {
    pub path: String,
    pub sha256: String,
}

/// A private review manifest, not a public observation or runtime receipt.
/// Debug is intentionally absent: configuration paths and task identifiers are private.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FiniteClientManifest {
    pub schema_version: u32,
    pub task_id: String,
    pub host_snapshot_id: String,
    pub client: FiniteClientFile,
    pub native: FiniteClientFile,
    pub helper: FiniteClientFile,
    pub wrapper: FiniteClientFile,
    pub profile: FiniteClientFile,
    pub configuration: FiniteClientFile,
    pub private_state: String,
    pub native_version: String,
    pub broker_endpoint: String,
    pub broker_instance_sha256: String,
}
