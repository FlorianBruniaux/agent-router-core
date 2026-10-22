//! F12a resource-stop diagnostic using producer-owned copies and state.
//! Runs only a trusted helper --probe. Never submits native RPC or a model turn,
//! stores a capability proof, or converts a launch preview to a command.
use router_adapter_api::content_digest;
use router_runtime::{FiniteClientReview, OwnedBroker, ResourceLimits, Result, RuntimeError};
use router_types::*;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    net::TcpListener,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const NATIVE_PIN: &str = "16593cc2f422d5f398a8e40f550ebbaf1245392528957be342c295920a300704";
fn pin(path: &Path) -> Result<FiniteClientFile> {
    let path = fs::canonicalize(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(&path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > 256 * 1024 * 1024 {
        return Err(RuntimeError::Limit);
    }
    let mut bytes = vec![];
    file.take(256 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 256 * 1024 * 1024 {
        return Err(RuntimeError::Limit);
    }
    Ok(FiniteClientFile {
        path: path
            .to_str()
            .ok_or(RuntimeError::Invalid("diagnostic path"))?
            .into(),
        sha256: content_digest(&bytes),
    })
}
fn projection(result: &Result<()>) -> Value {
    let memory = match result {
        Err(RuntimeError::ResourceUnsupported("address_space")) => "NO_GO_REQUESTED_LIMIT_REFUSED",
        Ok(()) => "RLIMIT_PROBE_PASSED_ENFORCEMENT_UNQUALIFIED",
        Err(_) => "UNKNOWN_PROBE_FAILED",
    };
    json!({
        "schema_version": 1,
        "evidence_kind": "finite_client_owned_resource_preflight_diagnostic",
        "authority": "diagnostic_only_no_product_approval_or_capability_proof",
        "F12a": "NO_GO",
        "requirements": {
            "memory": memory,
            "broker_exact_port": "NOT_ATTEMPTED",
            "asset_write_exclusion": "NOT_ATTEMPTED",
            "copied_wrapper_compatibility": "NOT_ATTEMPTED",
            "mach_dns": "NOT_ATTEMPTED",
            "task_descendant_containment": "NOT_ATTEMPTED",
            "physical_send_admission": "NOT_ATTEMPTED"
        },
        "native_launch": "NOT_ATTEMPTED",
        "model_turn": "NOT_ATTEMPTED",
        "provider_send": "NOT_ATTEMPTED",
        "product_broker_authority": "UNSUPPORTED",
        "process_limit_scope": "per_user_not_per_task",
        "proof_freshness": "NOT_APPLICABLE_NO_PROOF_STORED"
    })
}
async fn diagnostic() -> Result<Value> {
    if !cfg!(target_os = "macos") {
        return Err(RuntimeError::Sandbox);
    }
    let helper = pin(&PathBuf::from(
        std::env::var_os("AR_SANDBOX_HELPER").ok_or(RuntimeError::Invalid("helper path"))?,
    ))?;
    let native = pin(&PathBuf::from(
        std::env::var_os("AR_CODEX_NATIVE").ok_or(RuntimeError::Invalid("native path"))?,
    ))?;
    if native.sha256 != NATIVE_PIN {
        return Err(RuntimeError::Integrity("native pin"));
    }
    let client = pin(&std::env::current_exe()?)?;
    let wrapper = pin(Path::new("/usr/bin/sandbox-exec"))?;
    let temp = tempfile::Builder::new()
        .prefix("ar-f12a-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let root = temp.path().canonicalize()?;
    let workspace = root.join("workspace");
    let store = root.join("preparation");
    for dir in [&workspace, &store] {
        fs::DirBuilder::new().mode(0o700).create(dir)?;
    }
    // No profile is executed. Bind an explicit deny candidate without granting
    // access to the copied assets or falsely declaring a qualified OS template.
    let profile_path = root.join("profile.sb");
    fs::write(&profile_path, b"(version 1)\n(deny default)\n")?;
    fs::set_permissions(&profile_path, fs::Permissions::from_mode(0o400))?;
    let profile = pin(&profile_path)?;
    let run = PreparedRun {
        schema_version: 1,
        receipt_id: "a".repeat(64),
        source_state: "b".repeat(40),
        scope: vec!["patch.txt".into()],
        authorization_digest: "c".repeat(64),
        snapshot_hash: "d".repeat(64),
        host: HarnessId::parse("codex").map_err(|_| RuntimeError::Invalid("diagnostic host"))?,
        requested_model: ModelId::parse("gpt-6.1-sol")
            .map_err(|_| RuntimeError::Invalid("diagnostic model"))?,
        requested_effort: EffortLevel::Low,
        program: "finite-client".into(),
        argv: vec!["--diagnostic-never-launch".into()],
        cwd: workspace
            .to_str()
            .ok_or(RuntimeError::Invalid("workspace path"))?
            .into(),
        stdin: PreparedInput::new(b"F12a resource probe only".to_vec()),
        mode: ExecutionMode::Execute,
        target: ExecutionTarget::ExternalWorker,
        sandbox: ExecutionSandbox::WorkspaceWrite,
        timeout_ms: 3000,
        max_output_bytes: 8192,
        degradations: vec![],
        missing_runtime_evidence: vec![],
        parent_model_changed: false,
    };
    let broker = OwnedBroker::from_listener(TcpListener::bind(("127.0.0.1", 0))?)?;
    let state = broker.prepare_codex_state(&store, &run)?;
    let configuration_hash = state.configuration().sha256.clone();
    let manifest = FiniteClientManifest {
        schema_version: 1,
        task_id: "f12a-resource-stop".into(),
        host_snapshot_id: "diagnostic-not-host-proof".into(),
        client: client.clone(),
        native: native.clone(),
        helper: helper.clone(),
        wrapper: wrapper.clone(),
        profile: profile.clone(),
        configuration: state.configuration().clone(),
        private_state: state
            .path()
            .to_str()
            .ok_or(RuntimeError::Invalid("state path"))?
            .into(),
        native_version: "pinned-diagnostic-not-invoked".into(),
        broker_endpoint: broker.endpoint().into(),
        broker_instance_sha256: broker.instance_sha256().into(),
    };
    let limits = ResourceLimits::default();
    let review =
        FiniteClientReview::with_codex_state(manifest, &run, broker, limits.clone(), state)?;
    let digest = review.approval_digest().to_owned();
    // Preparation-only approval to probe the helper; never Runtime::approve.
    let approved = review.approve(&digest)?;
    let result = approved.probe_owned_resources(&limits).await;
    let mut report = projection(&result);
    report["os"] = json!(std::env::consts::OS);
    report["architecture"] = json!(std::env::consts::ARCH);
    report["review_sha256"] = json!(digest);
    report["source_asset_sha256"] = json!({"client":client.sha256,"native":native.sha256,"helper":helper.sha256,"wrapper":wrapper.sha256,"profile":profile.sha256,"configuration":configuration_hash});
    report["requested_limits"] = json!({"cpu_seconds":limits.cpu_seconds,"address_space_bytes":limits.address_space_bytes,"max_open_files":limits.max_open_files,"max_processes":limits.max_processes,"max_file_bytes":limits.max_file_bytes});
    // Unexpected errors retain the partial diagnostic projection privately at
    // the caller; they are not reported as a successful qualification.
    if let Err(error) = &result {
        report["probe_error"] = json!(error.to_string());
    }
    Ok(report)
}
#[tokio::main(flavor = "current_thread")]
async fn main() {
    match diagnostic().await {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn applied_limits_alone_never_qualify_native_execution() {
        for result in [
            Ok(()),
            Err(RuntimeError::ResourceUnsupported("address_space")),
            Err(RuntimeError::Sandbox),
        ] {
            let report = projection(&result);
            assert_eq!(report["F12a"], "NO_GO");
            for key in ["native_launch", "model_turn", "provider_send"] {
                assert_eq!(report[key], "NOT_ATTEMPTED");
            }
            assert_eq!(
                report["requirements"]["asset_write_exclusion"],
                "NOT_ATTEMPTED"
            );
        }
    }
}
