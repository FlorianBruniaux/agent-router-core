//! Preserve model metadata while declining to assert unproved runtime capabilities.
#![allow(dead_code)]

use router_adapter_api::HostObservation;
use router_types::CapabilitySupport;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};

pub fn from_example(mut observation: HostObservation) -> HostObservation {
    observation.host.capabilities.clear();
    for evidence in observation.capabilities.values_mut() {
        evidence.support = CapabilitySupport::Unknown;
        evidence.source_ids.clear();
    }
    observation.seal().expect("fixture observation")
}

/// A stable per-test-binary file for CLI commands that consume the example.
/// The temporary directory stays alive until the test process exits.
pub fn example_path() -> &'static Path {
    static SNAPSHOT: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();
    &SNAPSHOT
        .get_or_init(|| {
            let directory = tempfile::tempdir().expect("fixture directory");
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/examples/phase-snapshot.json");
            let observation: HostObservation =
                serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
            let path = directory.path().join("snapshot.json");
            fs::write(
                &path,
                serde_json::to_vec(&from_example(observation)).unwrap(),
            )
            .unwrap();
            (directory, path)
        })
        .1
}
