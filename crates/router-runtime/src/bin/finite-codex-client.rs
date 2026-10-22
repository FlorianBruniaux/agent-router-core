#![forbid(unsafe_code)]
//! Worker entry used only inside the reviewed Linux composition.
use router_adapter_api::{content_digest, is_digest};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::{Command, Stdio},
};

#[path = "finite-codex-client/replacement.rs"]
mod replacement;
#[path = "finite-codex-client/tools_probe.rs"]
mod tools_probe;

const MAX_CONTEXT: usize = 8192;
const MAX_PROMPT: usize = 32768;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    native: String,
    native_sha256: String,
    native_version: String,
    home: String,
    cwd: String,
    configuration_sha256: String,
    model: String,
    effort: String,
    stdin_sha256: String,
    max_output_bytes: usize,
    replacement: Option<ReplacementTarget>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplacementTarget {
    relative: String,
    preimage: String,
}

fn parse_context(bytes: &[u8]) -> Result<Context, &'static str> {
    if bytes.len() > MAX_CONTEXT {
        return Err("context.bound");
    }
    let value =
        router_adapter_api::strict_json_limited(bytes, MAX_CONTEXT).map_err(|_| "context.json")?;
    let c: Context = serde_json::from_value(value).map_err(|_| "context.shape")?;
    if [&c.native_sha256, &c.configuration_sha256, &c.stdin_sha256]
        .iter()
        .any(|s| !is_digest(s))
        || [&c.native, &c.home, &c.cwd].iter().any(|s| {
            s.len() > 4096
                || s.chars().any(char::is_control)
                || !Path::new(s).is_absolute()
                || s.as_str() == "/"
        })
        || !(128..=65536).contains(&c.max_output_bytes)
        || c.replacement.as_ref().is_some_and(|target| {
            target.relative.is_empty()
                || target.relative.len() > 128
                || target.relative.starts_with('.')
                || !target
                    .relative
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || !is_digest(&target.preimage)
        })
        || c.model.is_empty()
        || c.model.len() > 128
        || !c
            .model
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        || c.native_version.is_empty()
        || c.native_version.len() > 128
        || !c.native_version.bytes().all(|b| b.is_ascii_graphic())
        || serde_json::from_value::<router_types::EffortLevel>(serde_json::Value::String(
            c.effort.clone(),
        ))
        .is_err()
    {
        return Err("context.binding");
    }
    Ok(c)
}
fn file_hash(path: &Path, bound: u64) -> Result<String, &'static str> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "file.open")?;
    let meta = file.metadata().map_err(|_| "file.metadata")?;
    if !meta.is_file() || meta.len() > bound {
        return Err("file.bound");
    }
    let mut bytes = Vec::new();
    file.take(bound + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "file.read")?;
    if bytes.len() as u64 > bound {
        return Err("file.bound");
    }
    Ok(content_digest(&bytes))
}
fn version_matches(recorded: &str, stdout: &[u8]) -> bool {
    recorded == "0.159.2-linux-arm64-musl" && stdout == b"codex-cli 0.159.2\n"
}
fn execute(probe: bool) -> Result<i32, &'static str> {
    let raw = std::env::var("ROUTER_FINITE_CONTEXT").map_err(|_| "context.missing")?;
    let c = parse_context(raw.as_bytes())?;
    for path in [&c.native, &c.home, &c.cwd] {
        if fs::canonicalize(path).map_err(|_| "path.canonical")? != Path::new(path) {
            return Err("path.canonical");
        }
    }
    if Path::new(&c.native).starts_with(&c.cwd)
        || Path::new(&c.home).starts_with(&c.cwd)
        || Path::new(&c.cwd).starts_with(&c.home)
        || file_hash(Path::new(&c.native), 256 * 1024 * 1024)? != c.native_sha256
        || file_hash(&Path::new(&c.home).join("config.toml"), 65536)? != c.configuration_sha256
    {
        return Err("file.binding");
    }
    let mut prompt = Vec::new();
    std::io::stdin()
        .take(MAX_PROMPT as u64 + 1)
        .read_to_end(&mut prompt)
        .map_err(|_| "stdin.read")?;
    if prompt.len() > MAX_PROMPT || content_digest(&prompt) != c.stdin_sha256 {
        return Err("stdin.binding");
    }
    let environment = BTreeMap::from([
        ("PATH", "/usr/bin:/bin".to_owned()),
        ("HOME", c.home.clone()),
        ("CODEX_HOME", c.home.clone()),
        ("TMPDIR", format!("{}/tmp", c.home)),
        ("CODEX_SQLITE_HOME", format!("{}/tmp", c.home)),
    ]);
    let mut command = Command::new(&c.native);
    command
        .current_dir(&c.cwd)
        .env_clear()
        .envs(environment)
        .stderr(Stdio::inherit());
    if probe {
        let mut child = command
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|_| "version.spawn")?;
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .ok_or("version.stdout")?
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| "version.read")?;
        if bytes.len() > 8192 {
            let _ = child.kill();
            let _ = child.wait();
            return Err("version.bound");
        }
        let status = child.wait().map_err(|_| "version.wait")?;
        if !status.success() || !version_matches(&c.native_version, &bytes) {
            return Err("version.mismatch");
        }
        let expected = "codex-cli 0.159.2";
        println!(
            "{}",
            serde_json::json!({"finite_client_probe":"v1","native_version":expected})
        );
        return Ok(0);
    }
    command
        .args([
            "exec",
            "--json",
            "--skip-git-repo-check",
            "--ephemeral",
            "--sandbox",
            "read-only",
            "--model",
            &c.model,
            "--config",
            &format!("model_reasoning_effort=\"{}\"", c.effort),
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(if c.replacement.is_some() {
            Stdio::piped()
        } else {
            Stdio::inherit()
        });
    let mut child = command.spawn().map_err(|_| "native.spawn")?;
    child
        .stdin
        .take()
        .ok_or("native.stdin")?
        .write_all(&prompt)
        .map_err(|_| "native.input")?;
    if let Some(target) = &c.replacement {
        let mut bytes = vec![];
        child
            .stdout
            .take()
            .ok_or("native.stdout")?
            .take(c.max_output_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "native.read")?;
        if bytes.len() > c.max_output_bytes {
            let _ = child.kill();
            let _ = child.wait();
            return Err("native.output.bound");
        }
        let status = child.wait().map_err(|_| "native.wait")?;
        // Keep the genuine transcript available for the runtime decoder. No
        // native stream or host-reported usage can grant publication authority.
        std::io::stdout()
            .write_all(&bytes)
            .map_err(|_| "native.stdout")?;
        if !status.success() {
            return Ok(status.code().unwrap_or(125));
        }
        replacement::apply(
            Path::new(&c.cwd),
            &target.relative,
            &target.preimage,
            &bytes,
        )?;
        Ok(0)
    } else {
        Ok(child
            .wait()
            .map_err(|_| "native.wait")?
            .code()
            .unwrap_or(125))
    }
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if std::env::args_os()
        .next()
        .is_some_and(|p| Path::new(&p).file_name() == Some(std::ffi::OsStr::new("rustc")))
    {
        use std::os::unix::process::CommandExt;
        if !cfg!(target_os = "linux")
            || args.len() > 31
            || args.iter().any(|s| s.len() > 4096 || s.contains('\0'))
            || args.iter().map(String::len).sum::<usize>() > 16384
        {
            eprintln!("finite-client:compiler.arguments");
            std::process::exit(125);
        }
        let _error =
            Command::new("/usr/local/rustup/toolchains/1.85.1-aarch64-unknown-linux-gnu/bin/rustc")
                .args(["-C", "linker=/usr/bin/aarch64-linux-gnu-gcc-12"])
                .args(&args)
                .exec();
        eprintln!("finite-client:compiler.exec");
        std::process::exit(125);
    }

    if args.as_slice() == ["--tools-owner"] {
        // Worker bootstrap is never a Runtime approval or capability proof.
        let result = (|| -> Result<i32, &'static str> {
            let path = Path::new("/router-tools/boot.json");
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(path)
                .map_err(|_| "owner.bootstrap")?;
            if !file.metadata().map_err(|_| "owner.bootstrap")?.is_file() {
                return Err("owner.bootstrap");
            }
            let mut bytes = Vec::new();
            file.take(65537)
                .read_to_end(&mut bytes)
                .map_err(|_| "owner.bootstrap")?;
            let value = router_adapter_api::strict_json_limited(&bytes, 65536)
                .map_err(|_| "owner.bootstrap")?;
            let boot = serde_json::from_value(value).map_err(|_| "owner.bootstrap")?;
            router_runtime::finite_tools::run_owner(boot).map_err(|error| match error {
                router_runtime::finite_tools::FiniteToolError::Refused(code) => code,
                router_runtime::finite_tools::FiniteToolError::Execution => "owner.execution",
            })
        })();
        match result {
            Ok(code) => std::process::exit(code),
            Err(code) => {
                eprintln!("finite-client:{code}");
                std::process::exit(125);
            }
        }
    }
    if args.as_slice() == ["--mcp-tools"] {
        // Absolute bound for this fixed bridge process, including a stalled
        // stdin/stdout pipe. Namespace and descendant cleanup remain with the
        // existing outer helper, never with this transport deadline.
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(90));
            std::process::exit(125);
        });
        std::process::exit(if router_runtime::finite_tools::bridge_stdio().is_ok() {
            0
        } else {
            125
        });
    }
    if args.as_slice() == ["--tools-probe-peer"] {
        match tools_probe::execute() {
            Ok(code) => std::process::exit(code),
            Err(code) => {
                eprintln!("finite-client:{code}");
                std::process::exit(125);
            }
        }
    }
    let mode = match args.as_slice() {
        [mode] if mode == "--worker" => false,
        [mode] if mode == "--version-probe" => true,
        _ => {
            eprintln!("finite-client:arguments");
            std::process::exit(125);
        }
    };
    match execute(mode) {
        Ok(code) => std::process::exit(code),
        Err(code) => {
            eprintln!("finite-client:{code}");
            std::process::exit(125);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> serde_json::Value {
        serde_json::json!({
            "native":"/tmp/native", "native_sha256":"a".repeat(64), "native_version":"0.159.2-linux-arm64-musl",
            "home":"/tmp/private-home", "cwd":"/tmp/public-work", "configuration_sha256":"b".repeat(64),
            "model":"gpt-6-luna", "effort":"medium", "stdin_sha256":"c".repeat(64), "max_output_bytes":65536
        })
    }
    #[test]
    fn bounded_context_accepts_the_reviewed_fields_without_reading_any_file() {
        let c = parse_context(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
        assert_eq!(c.model, "gpt-6-luna");
        assert_eq!(c.effort, "medium");
    }
    #[test]
    fn unsafe_context_is_refused_before_native_access() {
        for change in 0..7 {
            let mut v = fixture();
            match change {
                0 => v["native_sha256"] = "bad".into(),
                1 => v["model"] = "bad\nmodel".into(),
                2 => v["effort"] = "unbounded".into(),
                3 => v["native"] = "relative".into(),
                4 => v["extra"] = "ignored authority".into(),
                5 => v["home"] = "/".into(),
                _ => v["stdin_sha256"] = "bad".into(),
            }
            assert!(
                parse_context(&serde_json::to_vec(&v).unwrap()).is_err(),
                "change {change}"
            );
        }
        assert!(parse_context(&vec![b' '; 8193]).is_err());
        let mut text = serde_json::to_string(&fixture()).unwrap();
        text.pop();
        text.push_str(",\"model\":\"different\"}");
        assert!(parse_context(text.as_bytes()).is_err());
    }
    #[test]
    fn replacement_context_refuses_escapes_and_unbounded_output_before_native_access() {
        for relative in ["../outside", "/outside", "nested/file", ".git", "bad\nname"] {
            let mut v = fixture();
            v["replacement"] = serde_json::json!({"relative":relative,"preimage":"a".repeat(64)});
            assert!(parse_context(&serde_json::to_vec(&v).unwrap()).is_err());
        }
        for bound in [0, 127, 65537] {
            let mut v = fixture();
            v["max_output_bytes"] = bound.into();
            assert!(parse_context(&serde_json::to_vec(&v).unwrap()).is_err());
        }
        let mut v = fixture();
        v["replacement"] = serde_json::json!({"relative":"approved.rs","preimage":"a".repeat(64)});
        assert!(parse_context(&serde_json::to_vec(&v).unwrap()).is_ok());
    }
    #[test]
    fn version_probe_refuses_unreviewed_annotations_and_whitespace() {
        assert!(version_matches(
            "0.159.2-linux-arm64-musl",
            b"codex-cli 0.159.2\n"
        ));
        for (version, bytes) in [
            ("0.159.2-arbitrary", b"codex-cli 0.159.2\n".as_slice()),
            (
                "0.159.2-linux-arm64-musl",
                b" codex-cli 0.159.2\n".as_slice(),
            ),
            (
                "0.159.2-linux-arm64-musl",
                b"codex-cli 0.159.2\n\n".as_slice(),
            ),
        ] {
            assert!(!version_matches(version, bytes));
        }
    }
}
