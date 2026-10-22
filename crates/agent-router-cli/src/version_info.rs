//! `version --json`: what this binary is and which contract versions it speaks.
//! Nothing here reads the environment at run time, so the output is fixed by the build.
use std::{collections::BTreeMap, process::ExitCode};

use serde::Serialize;

use crate::{
    CliError, Outcome,
    contracts::{CONTRACTS, SchemaVersion},
    product::json_output,
};

/// Every Cargo feature of this crate except `default`, with whether it is on.
/// A unit test keeps this list equal to the `[features]` table.
const FEATURES: [(&str, bool); 7] = [
    ("claude", cfg!(feature = "claude")),
    ("codex", cfg!(feature = "codex")),
    ("copilot", cfg!(feature = "copilot")),
    ("local-api", cfg!(feature = "local-api")),
    ("local-sidecar", cfg!(feature = "local-sidecar")),
    ("opencode", cfg!(feature = "opencode")),
    ("semantic-retrieval", cfg!(feature = "semantic-retrieval")),
];

#[derive(Serialize)]
struct VersionInfo {
    schema_version: u32,
    version: &'static str,
    target: &'static str,
    features: Vec<&'static str>,
    contracts: BTreeMap<&'static str, ContractInfo>,
}

#[derive(Serialize)]
struct ContractInfo {
    command: &'static str,
    schema_versions: &'static [SchemaVersion],
}

pub(crate) fn run() -> Result<Outcome, CliError> {
    json_output(
        &VersionInfo {
            schema_version: 1,
            version: env!("CARGO_PKG_VERSION"),
            target: env!("AGENT_ROUTER_TARGET"),
            features: FEATURES
                .iter()
                .filter(|(_, enabled)| *enabled)
                .map(|(name, _)| *name)
                .collect(),
            contracts: CONTRACTS
                .iter()
                .map(|contract| {
                    (
                        contract.name,
                        ContractInfo {
                            command: contract.command,
                            schema_versions: contract.versions,
                        },
                    )
                })
                .collect(),
        },
        ExitCode::SUCCESS,
    )
}

#[cfg(test)]
mod tests {
    use super::FEATURES;

    #[test]
    fn the_feature_list_matches_the_manifest() {
        let manifest: toml::Table = include_str!("../Cargo.toml").parse().unwrap();
        let mut declared: Vec<&str> = manifest["features"]
            .as_table()
            .unwrap()
            .keys()
            .map(String::as_str)
            .filter(|name| *name != "default")
            .collect();
        declared.sort_unstable();
        let listed: Vec<&str> = FEATURES.iter().map(|(name, _)| *name).collect();
        assert_eq!(listed, declared);
    }
}
