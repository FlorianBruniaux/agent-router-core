use crate::{
    CliError, Outcome, command::AuditCommand, inspect, phases::read_json, product::json_output,
    read_bounded,
};
use router_doctor::{AuditInput, DoctorError, MAX_ARTIFACTS, MAX_FILE_BYTES, MAX_TOTAL_BYTES};
use router_types::{AuditArtifactKind, DiagnosticState};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

fn error(error: DoctorError) -> CliError {
    CliError::Product(match error {
        DoctorError::Invalid => "doctor.input.invalid",
        DoctorError::Path => "doctor.path.rejected",
        DoctorError::Read => "doctor.file.unavailable",
        DoctorError::Limit => "doctor.input.limit",
        DoctorError::DatabaseTooLarge => "doctor.database.too_large",
        DoctorError::Schema => "doctor.schema.invalid",
        DoctorError::Integrity => "doctor.audit.integrity",
        DoctorError::Unsupported => "doctor.platform.unsupported",
    })
}
pub(crate) fn doctor(
    path: Option<&Path>,
    runtime_root: Option<&Path>,
    now: Option<u64>,
    deep: bool,
    json: bool,
) -> Result<Outcome, CliError> {
    if !json {
        return Err(CliError::JsonOutputRequired);
    }
    if let Some(root) = runtime_root {
        let result = router_runtime::diagnose_runtime_storage(root, inspect::current_time(now)?)
            .map_err(error)?;
        return json_output(&result, diagnostic_exit(result.overall));
    }
    let path = path.ok_or(CliError::InvalidCommand)?;
    if deep {
        let request = read_json(path, 256 * 1024)?;
        let result =
            router_doctor::diagnose_deep(&request, inspect::current_time(now)?).map_err(error)?;
        return json_output(&result, diagnostic_exit(result.overall));
    }
    let request = read_json(path, 256 * 1024)?;
    let result = router_doctor::diagnose(&request, inspect::current_time(now)?).map_err(error)?;
    json_output(&result, diagnostic_exit(result.overall))
}
fn diagnostic_exit(state: DiagnosticState) -> ExitCode {
    match state {
        DiagnosticState::Pass => ExitCode::SUCCESS,
        DiagnosticState::Fail => ExitCode::from(2),
        _ => ExitCode::from(3),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditFile {
    kind: AuditArtifactKind,
    path: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditFiles {
    schema_version: u32,
    inputs: Vec<AuditFile>,
}

pub(crate) fn audit(command: AuditCommand) -> Result<Outcome, CliError> {
    match command {
        AuditCommand::Export { inputs, json } => {
            if !json {
                return Err(CliError::JsonOutputRequired);
            }
            let files: AuditFiles = read_json(&inputs, 128 * 1024)?;
            if files.schema_version != 1
                || files.inputs.is_empty()
                || files.inputs.len() > MAX_ARTIFACTS
            {
                return Err(CliError::Product("doctor.input.invalid"));
            }
            let mut total = 0usize;
            let mut contents = Vec::new();
            for file in &files.inputs {
                let bytes = read_bounded(
                    &file.path,
                    MAX_FILE_BYTES,
                    CliError::RequestRead,
                    CliError::RequestTooLarge,
                )?;
                total = total
                    .checked_add(bytes.len())
                    .ok_or(CliError::RequestTooLarge)?;
                if total > MAX_TOTAL_BYTES {
                    return Err(CliError::RequestTooLarge);
                }
                contents.push(bytes);
            }
            let inputs: Vec<_> = files
                .inputs
                .iter()
                .zip(&contents)
                .map(|(file, bytes)| AuditInput {
                    kind: file.kind,
                    bytes,
                })
                .collect();
            let bundle = router_doctor::build_audit_bundle(&inputs).map_err(error)?;
            json_output(&bundle, ExitCode::SUCCESS)
        }
        AuditCommand::Verify {
            bundle,
            expected_root,
            json,
        } => {
            if !json {
                return Err(CliError::JsonOutputRequired);
            }
            // Allowlist projections and per-record hashes can expand a valid
            // bounded input set. Keep bundle transport separately bounded.
            let bundle: router_types::AuditBundle = read_json(&bundle, 32 * 1024 * 1024)?;
            router_doctor::verify_audit_bundle(&bundle, expected_root.as_deref()).map_err(error)?;
            json_output(
                &serde_json::json!({"schema_version":1,"valid":true,"root_hash":bundle.root_hash,"trusted_root_matched":expected_root.is_some(),"signature_verified":false}),
                ExitCode::SUCCESS,
            )
        }
    }
}
