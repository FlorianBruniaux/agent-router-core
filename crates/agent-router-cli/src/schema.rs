//! `schema`: prints the JSON Schema of a named output contract. The documents
//! are embedded files, so the output is fixed by the binary and needs no I/O.
use std::process::ExitCode;

use serde::Serialize;

use crate::{
    CliError, Outcome,
    contracts::{CONTRACTS, SchemaVersion, find},
    product::json_output,
};

#[derive(Serialize)]
struct Listing {
    schema_version: u32,
    schemas: Vec<Entry>,
}

#[derive(Serialize)]
struct Entry {
    name: &'static str,
    command: &'static str,
    schema_versions: &'static [SchemaVersion],
}

pub(crate) fn run(name: Option<&str>, list: bool) -> Result<Outcome, CliError> {
    if list {
        return json_output(
            &Listing {
                schema_version: 1,
                schemas: CONTRACTS
                    .iter()
                    .map(|contract| Entry {
                        name: contract.name,
                        command: contract.command,
                        schema_versions: contract.versions,
                    })
                    .collect(),
            },
            ExitCode::SUCCESS,
        );
    }
    let contract = name
        .and_then(find)
        .ok_or(CliError::Product("schema.unknown"))?;
    Ok(Outcome {
        output: contract.schema.to_owned(),
        exit_code: ExitCode::SUCCESS,
    })
}
