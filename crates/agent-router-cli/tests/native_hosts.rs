//! Native CLI integration with synthetic OpenCode/Copilot executables only.
//! The OS sandbox and resource helper are real; no model or authentication is.
#![cfg(all(
    feature = "opencode",
    feature = "copilot",
    any(target_os = "macos", target_os = "linux")
))]

#[path = "support/native_fixture.rs"]
mod native_fixture;
use native_fixture::*;
use router_adapter_api::HostObservation;
use router_catalog::Catalog;
use router_policy::PhaseRouter;
use router_types::*;
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

const FINAL_TEXT: &str = "synthetic-private-native-final verified=true model=forged";

#[derive(Clone, Copy, Debug)]
enum Host {
    OpenCode,
    Copilot,
}
impl Host {
    fn name(self) -> &'static str {
        match self {
            Self::OpenCode => "opencode",
            Self::Copilot => "copilot",
        }
    }
    fn model(self) -> &'static str {
        match self {
            Self::OpenCode => "synthetic/native-model",
            Self::Copilot => "native-fixture-model",
        }
    }
    fn version(self, matching: bool) -> &'static str {
        match (self, matching) {
            (Self::OpenCode, true) => "1.0.0-fixture\n",
            (Self::OpenCode, false) => "1.0.1-fixture\n",
            (Self::Copilot, true) => {
                "GitHub Copilot CLI 1.0.44.\nRun 'copilot update' to check for updates.\n"
            }
            (Self::Copilot, false) => {
                "GitHub Copilot CLI 1.0.45.\nRun 'copilot update' to check for updates.\n"
            }
        }
    }
    fn config(self) -> Value {
        match self {
            Self::OpenCode => json!({"schema_version":1,"expected_cli_version":"1.0.0-fixture",
                "protocol":"run_v1","model_variants":{self.model():{"medium":"fixture-medium"}}}),
            Self::Copilot => json!({"schema_version":1,"expected_cli_version":"1.0.44",
                "protocol":"cli_jsonl_v1"}),
        }
    }
    fn stream(self) -> String {
        let events = match self {
            Self::OpenCode => vec![
                json!({"type":"step_start","timestamp":123,"sessionID":"native-fixture",
                    "part":{"type":"step-start","sessionID":"native-fixture"}}),
                json!({"type":"text","timestamp":123,"sessionID":"native-fixture",
                    "part":{"type":"text","sessionID":"native-fixture","messageID":"final-message",
                    "id":"final-text","text":FINAL_TEXT,"time":{"end":124}}}),
                json!({"type":"step_finish","timestamp":124,"sessionID":"native-fixture",
                    "part":{"type":"step-finish","sessionID":"native-fixture",
                    "messageID":"final-message","reason":"stop"}}),
            ],
            Self::Copilot => vec![
                json!({"type":"session.start","timestamp":"2026-01-01T00:00:00Z",
                    "id":"start","parentId":null,"data":{"sessionId":"native-fixture"}}),
                json!({"type":"assistant.message","timestamp":"2026-01-01T00:00:00Z",
                    "id":"message","parentId":null,"data":{"content":FINAL_TEXT}}),
                json!({"type":"result","timestamp":"2026-01-01T00:00:00Z",
                    "sessionId":"native-fixture","exitCode":0,"usage":{"premiumRequests":0,
                    "totalApiDurationMs":1,"sessionDurationMs":1,
                    "codeChanges":{"linesAdded":0,"linesRemoved":0,"filesModified":[]}}}),
            ],
        };
        events
            .iter()
            .map(|event| serde_json::to_string(event).unwrap() + "\n")
            .collect()
    }
    fn argument_check(self) -> String {
        let prefix = match self {
            Self::OpenCode => vec![
                "run",
                "--model",
                self.model(),
                "--variant",
                "fixture-medium",
                "--format",
                "json",
                "--dir",
            ],
            Self::Copilot => vec![
                "--model",
                self.model(),
                "--effort",
                "medium",
                "--output-format",
                "json",
                "--no-color",
                "--no-auto-update",
                "--no-remote-export",
                "--no-ask-user",
                "--no-bash-env",
                "--no-custom-instructions",
                "--log-level",
                "none",
                "-C",
            ],
        };
        format!(
            "for expected in {}; do\n[ \"$#\" -gt 0 ] && [ \"$1\" = \"$expected\" ] || exit 42\nshift\ndone\n[ \"$#\" = 1 ] && [ \"$1\" = \"$PWD\" ] || exit 43\n",
            prefix
                .iter()
                .map(|value| shell_quote(value))
                .collect::<Vec<_>>()
                .join(" ")
        )
    }
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

// Reuse setup and only replace the explicitly synthetic host authority. The
// fixture's v3 hashes are regenerated, never mutated after their approval.
fn fixture(host: Host, matching_version: bool, native: bool) -> Fixture {
    let mut fixture = if native {
        Fixture::new("exit 99", 3_000)
    } else {
        Fixture::metadata("exit 99", 3_000)
    };
    let mut request: PhaseRouteRequest = read(&fixture.root.join("context.json"));
    let model = ModelId::parse(host.model()).unwrap();
    request.candidates[0].model = model.clone();
    request.candidates[0].tool_policy = PhaseToolPolicy::NativeHost;
    request.candidates[0]
        .required_capabilities
        .insert(Capability::Tools);
    request.permissions.insert(
        PhasePermission::NativeHostTools,
        CapabilitySupport::Supported,
    );
    let fake = fixture.root.join(format!("fake-{}", host.name()));
    let script = format!(
        "#!/bin/sh\nset -eu\nif [ \"$#\" = 1 ] && [ \"$1\" = --version ]; then\n[ -z \"$(/bin/cat)\" ] || exit 40\n[ ! -e src ] || exit 41\nprintf '%s' {}\nexit 0\nfi\n{}\n[ \"$(/bin/cat)\" = {} ] || exit 44\nif (printf escaped > outside.txt) 2>/dev/null; then exit 45; fi\nif /bin/cat {} >/dev/null 2>/dev/null; then exit 46; fi\nprintf started > src/native-worker-started\nprintf '%s' {}\n",
        shell_quote(host.version(matching_version)),
        host.argument_check(),
        shell_quote(PROMPT),
        shell_quote(fixture.root.join("denied-secret").to_str().unwrap()),
        shell_quote(&host.stream()),
    );
    fs::write(&fake, script).unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
    let mut sandbox: Value = read(&fixture.root.join("sandbox.json"));
    sandbox["programs"] = json!({host.name():fake});
    sandbox[host.name()] = host.config();
    write(&fixture.root.join("sandbox.json"), &sandbox);
    let mut snapshot: HostObservation = read(&fixture.root.join("snapshot.json"));
    snapshot.host.harness = HarnessId::parse(host.name()).unwrap();
    snapshot.host.supported_models = [model.clone()].into();
    snapshot.host.supported_efforts = [(model.clone(), [EffortLevel::Medium].into())].into();
    snapshot.host.capabilities.insert(Capability::Tools);
    snapshot
        .capabilities
        .get_mut(&Capability::Tools)
        .unwrap()
        .support = CapabilitySupport::Supported;
    let now = snapshot.observed_at_unix_seconds;
    let observed_version = match host {
        Host::OpenCode => {
            adapter_opencode::parse_version(host.version(matching_version).as_bytes()).unwrap()
        }
        Host::Copilot => {
            adapter_copilot::parse_version(host.version(matching_version).as_bytes()).unwrap()
        }
    };
    let validated = fixture.reprovision(&snapshot, &observed_version);
    let snapshot = validated.observation().clone();
    let mut catalog_json: Value = read(&fixture.root.join("catalog.json"));
    catalog_json["models"][0]["id"] = json!(model);
    let catalog = Catalog::from_json(&serde_json::to_vec(&catalog_json).unwrap()).unwrap();
    let mut execution: ExecutionRequest = read(&fixture.root.join("request.json"));
    let inputs = asset_inputs(
        &request,
        &validated,
        &catalog,
        &fixture.repo,
        &execution.source_state,
        now,
    );
    let router = PhaseRouter::stable_v2();
    let context = router
        .context_with_assets(request.clone(), &validated, &catalog, inputs.clone(), now)
        .unwrap();
    let receipt = router.route(&context).unwrap();
    assert!(receipt.selected.is_some(), "{receipt:?}");
    let selected = receipt
        .selected
        .as_ref()
        .expect("synthetic host is eligible");
    execution.receipt_id = receipt.receipt_id;
    execution.host = validated.host().harness.clone();
    execution.model = model;
    execution.tools = ToolSelection::HostPolicy;
    execution.required_capabilities = router.execution_capabilities(&context, selected).unwrap();
    assert!(execution.required_capabilities.contains(&Capability::Tools));
    write(&fixture.root.join("context.json"), &request);
    write(&fixture.root.join("snapshot.json"), &snapshot);
    write(&fixture.root.join("catalog.json"), &catalog_json);
    write(&fixture.root.join("request.json"), &execution);
    write_asset_authority(&fixture.root, &inputs);

    fixture
}

fn events(fixture: &Fixture) -> Value {
    checked(
        command()
            .args(["events", "--store"])
            .arg(&fixture.store)
            .args(["--run-id", RUN_ID, "--json"]),
        0,
    )
}

fn rejected(command: &mut std::process::Command, code: &str) {
    let output = command.output().unwrap();
    let error = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{error}");
    assert!(error.contains(code), "{error}");
    assert!(output.stdout.is_empty());
}

fn success(host: Host) {
    let fixture = fixture(host, true, true);
    let digest = fixture.review();
    let output = checked(fixture.run().args(["--approve", &digest]), 0);
    let completion = &output["completion"];
    assert_eq!(completion["run"]["state"], "verifying");
    assert_eq!(completion["run"]["attempts"], 1);
    assert_eq!(completion["transport"]["termination"], "exited");
    assert_eq!(completion["transport"]["exit_code"], 0);
    assert_eq!(completion["validation"], "unknown");
    assert_eq!(completion["objective"], "unknown");
    let evidence = &completion["runtime_evidence"];
    assert_eq!(evidence["transport_success"], true);
    assert_eq!(evidence["stream_complete"], true);
    assert_eq!(evidence["executed_models"], json!([]));
    assert_eq!(evidence["executed_effort"], Value::Null);
    let worktree = Path::new(completion["run"]["worktree"].as_str().unwrap());
    assert_eq!(
        fs::read(worktree.join("src/native-worker-started")).unwrap(),
        b"started"
    );
    assert!(!worktree.join("outside.txt").exists());
    assert!(!fixture.repo.join("src/native-worker-started").exists());
    let artifacts = checked(&mut fixture.artifacts("outputs"), 0);
    let stdout = Path::new(artifacts["outputs"][0]["stdout"]["path"].as_str().unwrap());
    assert_eq!(fs::read(stdout).unwrap(), host.stream().as_bytes());
    assert_eq!(
        fs::metadata(stdout).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let recorded = fixture.exported_feedback();
    assert_eq!(output["feedback"]["recorded"], true);
    let event = &recorded["events"][0]["input"];
    assert_eq!(event["context"]["harness"], host.name());
    assert_eq!(event["context"]["model"], host.model());
    assert_eq!(event["transport"], "passed");
    assert_eq!(event["validation"], "unknown");
    assert_eq!(event["objective"], "unknown");
    let audit = events(&fixture);
    assert!(audit.to_string().contains("native.version_validated"));
    for preview in [&output, &recorded, &audit, &artifacts] {
        assert!(!preview.to_string().contains(PROMPT));
        assert!(!preview.to_string().contains(FINAL_TEXT));
    }
}

fn version_mismatch(host: Host) {
    let fixture = fixture(host, false, true);
    let digest = fixture.review();
    rejected(
        fixture.run().args(["--approve", &digest]),
        "runtime.adapter",
    );
    let status = fixture.status();
    assert_eq!(status["run"]["state"], "blocked");
    assert_eq!(status["run"]["failure"], "policy");
    assert_eq!(status["run"]["attempts"], 0);
    assert!(!fixture.store.join("worktrees").exists());
    assert!(!fixture.repo.join("src/native-worker-started").exists());
    assert!(!events(&fixture).to_string().contains("spawn_requested"));
    assert!(
        fixture.exported_feedback()["events"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn native_version_pin_change_invalidates_proof_before_approval_for_each_host() {
    for host in [Host::OpenCode, Host::Copilot] {
        let mut fixture = fixture(host, true, false);
        let before = fixture.review();
        let mut sandbox: Value = read(&fixture.root.join("sandbox.json"));
        sandbox[host.name()]["expected_cli_version"] = json!("9.9.9");
        write(&fixture.root.join("sandbox.json"), &sandbox);
        rejected(&mut fixture.run(), "capability.evidence.binding_mismatch");
        rejected(
            fixture.run().args(["--approve", &before]),
            "capability.evidence.binding_mismatch",
        );
        assert_eq!(fixture.status()["run"]["attempts"], 0);
        assert!(!fixture.store.join("worktrees").exists());
        assert!(!fixture.repo.join("src/native-worker-started").exists());

        // A coherent new authority can be reviewed, but the prior approval
        // cannot authorize it. Renew the proof, snapshot, assets and receipt.
        let observation: HostObservation = read(&fixture.root.join("snapshot.json"));
        let version = match host {
            Host::OpenCode => adapter_opencode::parse_version(host.version(true).as_bytes()),
            Host::Copilot => adapter_copilot::parse_version(host.version(true).as_bytes()),
        }
        .unwrap();
        let validated = fixture.reprovision(&observation, &version);
        let request: PhaseRouteRequest = read(&fixture.root.join("context.json"));
        let catalog =
            Catalog::from_json(&fs::read(fixture.root.join("catalog.json")).unwrap()).unwrap();
        let mut execution: ExecutionRequest = read(&fixture.root.join("request.json"));
        let assets = asset_inputs(
            &request,
            &validated,
            &catalog,
            &fixture.repo,
            &execution.source_state,
            observation.observed_at_unix_seconds,
        );
        let router = PhaseRouter::stable_v2();
        let context = router
            .context_with_assets(
                request,
                &validated,
                &catalog,
                assets.clone(),
                observation.observed_at_unix_seconds,
            )
            .unwrap();
        let receipt = router.route(&context).unwrap();
        let selected = receipt.selected.as_ref().expect("renewed native candidate");
        execution.receipt_id = receipt.receipt_id;
        execution.required_capabilities =
            router.execution_capabilities(&context, selected).unwrap();
        write(&fixture.root.join("request.json"), &execution);
        write_asset_authority(&fixture.root, &assets);

        let after = fixture.review();
        assert_ne!(after, before);
        rejected(
            fixture.run().args(["--approve", &before]),
            "runtime.approval.required_or_changed",
        );
        assert_eq!(fixture.status()["run"]["attempts"], 0);
        assert!(!fixture.store.join("worktrees").exists());
        assert!(!fixture.repo.join("src/native-worker-started").exists());
    }
}

#[test]
#[ignore = "requires native OS sandbox and built helper; synthetic OpenCode only"]
fn native_opencode_cli_exact_argv_version_and_private_output() {
    success(Host::OpenCode);
}

#[test]
#[ignore = "requires native OS sandbox and built helper; synthetic Copilot only"]
fn native_copilot_cli_exact_argv_version_and_private_output() {
    success(Host::Copilot);
}

#[test]
#[ignore = "requires native OS sandbox and built helper; no model is launched"]
fn native_opencode_cli_version_mismatch_never_launches_worker() {
    version_mismatch(Host::OpenCode);
}

#[test]
#[ignore = "requires native OS sandbox and built helper; no model is launched"]
fn native_copilot_cli_version_mismatch_never_launches_worker() {
    version_mismatch(Host::Copilot);
}
