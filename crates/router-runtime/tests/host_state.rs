//! Native local canary, no provider process or credentials.
use router_runtime::{NetworkAuthority, SandboxPolicy, SandboxSupervisor};
use router_types::*;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

fn compile_shell_shim(root: &Path) -> PathBuf {
    let source = root.join("shell-shim.c");
    let program = root.join("shell-shim");
    fs::write(
        &source,
        b"#include <unistd.h>\nint main(int argc, char **argv) { (void)argc; argv[0] = \"/bin/sh\"; execv(\"/bin/sh\", argv); return 127; }\n",
    )
    .unwrap();
    #[cfg(target_os = "macos")]
    let compiler = "/usr/bin/clang";
    #[cfg(target_os = "linux")]
    let compiler = "/usr/bin/cc";
    let output = std::process::Command::new(compiler)
        .arg(&source)
        .arg("-o")
        .arg(&program)
        .output()
        .unwrap();
    assert!(output.status.success(), "local fixture compile: {output:?}");
    program
}

fn run(root: &Path, program: &str) -> PreparedRun {
    PreparedRun {
        schema_version: 1,
        receipt_id: "a".repeat(64),
        source_state: "b".repeat(40),
        scope: vec![],
        authorization_digest: "c".repeat(64),
        snapshot_hash: "d".repeat(64),
        host: HarnessId::parse(if program == "codex" {
            "codex"
        } else {
            "claude-code"
        })
        .unwrap(),
        requested_model: ModelId::parse("fixture-model").unwrap(),
        requested_effort: EffortLevel::Medium,
        program: program.into(),
        argv: vec![],
        cwd: root.to_str().unwrap().into(),
        stdin: PreparedInput::new(vec![]),
        mode: ExecutionMode::Execute,
        target: ExecutionTarget::ExternalWorker,
        sandbox: ExecutionSandbox::ReadOnly,
        timeout_ms: 3000,
        max_output_bytes: 4096,
        degradations: vec![],
        missing_runtime_evidence: vec![],
        parent_model_changed: false,
    }
}

#[tokio::test]
#[ignore = "requires native OS sandbox; no live model"]
async fn read_only_host_state_allows_state_but_denies_workspace_and_store() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let store = root.join("store");
    let cwd = root.join("repo");
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&cwd).unwrap();
    fs::write(store.join("approval.key"), b"synthetic-key").unwrap();
    fs::write(store.join("runtime.sqlite3"), b"synthetic-store").unwrap();
    let shim = compile_shell_shim(&root);
    let programs = ["codex", "claude"]
        .into_iter()
        .map(|name| (name.into(), shim.clone()))
        .collect();
    #[cfg(target_os = "macos")]
    let sandbox = router_runtime::SeatbeltSandbox::probe(&store, programs, vec![], BTreeMap::new())
        .await
        .unwrap();
    #[cfg(target_os = "linux")]
    let sandbox = router_runtime::BubblewrapSandbox::probe(
        &store,
        &fs::canonicalize("/usr/bin/bwrap").unwrap(),
        programs,
        vec![],
        BTreeMap::new(),
    )
    .await
    .unwrap();
    for (program, name) in [("codex", "CODEX_HOME"), ("claude", "CLAUDE_CONFIG_DIR")] {
        let mut run = run(&cwd, program);
        run.argv = vec![
            "-c".into(),
            format!(
                r#"set -eu
state="${name}"
printf private > "$state/probe"
[ "$(cat "$state/probe")" = private ]
if cat "$state/../approval.key" >/dev/null 2>&1; then exit 61; fi
if cat "$state/../runtime.sqlite3" >/dev/null 2>&1; then exit 62; fi
if (printf denied > denied) 2>/dev/null; then exit 63; fi
if (printf denied > "$state/../denied") 2>/dev/null; then exit 64; fi
printf '%s' "$state"
"#
            ),
        ];
        let state = sandbox.create_host_state(&store, &run).unwrap();
        let mut command = sandbox
            .command(
                &run,
                &SandboxPolicy {
                    network: NetworkAuthority::Deny,
                    host_state: state.as_ref(),
                },
            )
            .unwrap();
        #[cfg(target_os = "macos")]
        {
            let profile = command
                .as_std()
                .get_args()
                .nth(1)
                .unwrap()
                .to_str()
                .unwrap();
            let rule = "(allow user-preference-read (preference-domain \"com.openai.codex\"))";
            assert_eq!(profile.contains(rule), program == "codex");
            assert!(!profile.contains("(allow user-preference-read)"));
            let shm = "(allow ipc-posix-shm-read* (ipc-posix-name-prefix \"apple.cfprefs.\"))";
            assert_eq!(profile.contains(shm), program == "codex");
            assert!(!profile.contains("(allow ipc-posix-shm-read*)"));
        }
        let output = command.output().await.unwrap();
        assert!(output.status.success(), "synthetic canary: {:?}", output);
        let path = std::path::PathBuf::from(String::from_utf8(output.stdout).unwrap());
        assert!(path.starts_with(&store));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(!cwd.join("denied").exists());
        assert!(!store.join("denied").exists());
        drop(state);
        assert!(!path.exists());
    }
}
