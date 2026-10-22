//! `serve`: route-only local API. Bodies are inline JSON; nothing here reads a
//! caller-supplied path, executes, records feedback or opens a catalog store.

use std::{
    io::Write,
    path::Path,
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use router_local_api::{HandlerError, Limits, RouteHandler, RouteInput, Server};
use router_types::RouteRequest;

use crate::{CliError, MAX_CATALOG_BYTES, MAX_REQUEST_BYTES, Outcome, catalogs, decide, inspect};

/// The `route` command's `--snapshot-max-age-seconds` default.
const SNAPSHOT_MAX_AGE_SECONDS: u64 = 86_400;

/// Exit status after a second signal, as after SIGINT in a shell.
const EXIT_FORCED: i32 = 130;

struct RouteOnly;

impl RouteHandler for RouteOnly {
    fn route(&self, input: RouteInput<'_>) -> Result<Vec<u8>, HandlerError> {
        route_inline(&input, None)
            .map(|outcome| outcome.output.into_bytes())
            .map_err(|error| HandlerError {
                status: match error {
                    CliError::Internal | CliError::DecisionRender => 500,
                    _ => 400,
                },
                code: error.code(),
            })
    }
}

/// Same steps and bounds as `agent-router route --json`, on inline documents.
fn route_inline(input: &RouteInput<'_>, now: Option<u64>) -> Result<Outcome, CliError> {
    if input.request.len() > MAX_REQUEST_BYTES {
        return Err(CliError::RequestTooLarge);
    }
    if input.catalog.len() > MAX_CATALOG_BYTES {
        return Err(CliError::CatalogTooLarge);
    }
    let request: RouteRequest =
        serde_json::from_slice(input.request).map_err(|_| CliError::RequestJsonInvalid)?;
    let snapshot = input
        .host_snapshot
        .map(|bytes| {
            if bytes.len() > router_adapter_api::MAX_SNAPSHOT_BYTES {
                return Err(CliError::SnapshotTooLarge);
            }
            inspect::parse_snapshot(bytes, now, SNAPSHOT_MAX_AGE_SECONDS)
        })
        .transpose()?;
    let (catalog, embedded) = catalogs::load_bytes(input.catalog, now, SNAPSHOT_MAX_AGE_SECONDS)?;
    decide(request, &catalog, snapshot, embedded)
}

pub(crate) fn run(
    state_dir: &Path,
    max_connections: usize,
    request_deadline_ms: u64,
) -> Result<Outcome, CliError> {
    let limits = Limits {
        max_connections,
        request_deadline: Duration::from_millis(request_deadline_ms),
        ..Limits::default()
    };
    let shutdown = Arc::new(AtomicBool::new(false));
    // Handlers are installed before the socket exists, so a signal sent after
    // the listening line always reaches them.
    install_signal_handlers(&shutdown)?;
    let server = Server::bind(state_dir, limits, RouteOnly)
        .map_err(|error| CliError::Product(error.code()))?;
    let announcement = serde_json::json!({
        "schema_version": 1,
        "event": "listening",
        "socket": server.socket_path().to_string_lossy(),
    });
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{announcement}")
        .and_then(|()| stdout.flush())
        .map_err(|_| CliError::Internal)?;
    drop(stdout);
    server
        .serve(&shutdown)
        .map_err(|error| CliError::Product(error.code()))?;
    Ok(Outcome {
        output: String::new(),
        exit_code: ExitCode::SUCCESS,
    })
}

fn install_signal_handlers(shutdown: &Arc<AtomicBool>) -> Result<(), CliError> {
    use tokio::signal::unix::{SignalKind, signal};

    let flag = Arc::clone(shutdown);
    let (ready, registered) = mpsc::channel();
    thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            let _ = ready.send(false);
            return;
        };
        runtime.block_on(async move {
            let (Ok(mut interrupt), Ok(mut terminate)) = (
                signal(SignalKind::interrupt()),
                signal(SignalKind::terminate()),
            ) else {
                let _ = ready.send(false);
                return;
            };
            let _ = ready.send(true);
            next_signal(&mut interrupt, &mut terminate).await;
            flag.store(true, Ordering::Release);
            // A second signal means the graceful stop is stuck: leave at once. The
            // socket stays behind and the next start replaces it as stale.
            next_signal(&mut interrupt, &mut terminate).await;
            std::process::exit(EXIT_FORCED);
        });
    });
    match registered.recv() {
        Ok(true) => Ok(()),
        _ => Err(CliError::Internal),
    }
}

/// Resolves on the next SIGINT or SIGTERM.
async fn next_signal(
    interrupt: &mut tokio::signal::unix::Signal,
    terminate: &mut tokio::signal::unix::Signal,
) {
    std::future::poll_fn(|cx| {
        if interrupt.poll_recv(cx).is_ready() || terminate.poll_recv(cx).is_ready() {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn root(path: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path)
    }

    fn bytes(path: &str) -> Vec<u8> {
        fs::read(root(path)).expect("fixture")
    }

    /// `agent-router route --json` on files vs the API core on the same bytes.
    fn assert_identical(
        request: &str,
        catalog: &str,
        snapshot: Option<&str>,
        now: Option<u64>,
    ) -> String {
        let cli = crate::route(
            &root(request),
            &root(catalog),
            true,
            snapshot.map(root).as_deref(),
            SNAPSHOT_MAX_AGE_SECONDS,
            now,
            None,
        )
        .map_err(CliError::code)
        .expect("cli route");
        let (request, catalog) = (bytes(request), bytes(catalog));
        let snapshot = snapshot.map(bytes);
        let api = route_inline(
            &RouteInput {
                request: &request,
                catalog: &catalog,
                host_snapshot: snapshot.as_deref(),
            },
            now,
        )
        .map_err(CliError::code)
        .expect("api route");
        assert_eq!(api.output.as_bytes(), cli.output.as_bytes());
        cli.output
    }

    const CATALOG: &str = "assets/catalogs/codex-core-v1.json";

    #[test]
    fn selected_decision_is_byte_identical_to_the_cli() {
        let output = assert_identical(
            "tests/fixtures/requests/codex-implementation.json",
            CATALOG,
            None,
            None,
        );
        assert!(output.contains("\"selected\""), "{output}");
    }

    #[test]
    fn no_route_decision_is_byte_identical_to_the_cli() {
        let output = assert_identical(
            "tests/fixtures/requests/no-compatible-plan.json",
            CATALOG,
            None,
            None,
        );
        assert!(output.contains("\"no_route\""), "{output}");
    }

    #[test]
    fn explicit_host_snapshot_is_byte_identical_to_the_cli() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("snapshot.json");
        let mut snapshot: router_adapter_api::HostObservation =
            serde_json::from_slice(&bytes("fixtures/examples/phase-snapshot.json")).unwrap();
        snapshot.host.capabilities.clear();
        for evidence in snapshot.capabilities.values_mut() {
            evidence.support = router_types::CapabilitySupport::Unknown;
        }
        let snapshot = snapshot.seal().unwrap();
        fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        let output = assert_identical(
            "tests/fixtures/requests/codex-implementation.json",
            CATALOG,
            Some(path.to_str().unwrap()),
            Some(100),
        );
        assert!(output.contains(&snapshot.snapshot_hash), "{output}");
    }

    fn call(
        request: &[u8],
        catalog: &[u8],
        snapshot: Option<&[u8]>,
    ) -> Result<Outcome, &'static str> {
        route_inline(
            &RouteInput {
                request,
                catalog,
                host_snapshot: snapshot,
            },
            Some(100),
        )
        .map_err(CliError::code)
    }

    #[test]
    fn invalid_and_oversized_documents_are_rejected_with_cli_codes() {
        let request = bytes("tests/fixtures/requests/codex-implementation.json");
        let catalog = bytes(CATALOG);
        assert!(call(&request, &catalog, None).is_ok());
        assert_eq!(
            call(b"{}", &catalog, None).err(),
            Some("request.json.invalid")
        );
        assert_eq!(call(&request, b"{}", None).err(), Some("catalog.invalid"));
        assert_eq!(
            call(&request, &catalog, Some(b"{}")).err(),
            Some("snapshot.json.invalid")
        );
        let huge = vec![b' '; MAX_REQUEST_BYTES + 1];
        assert_eq!(call(&huge, &catalog, None).err(), Some("request.too_large"));
        let huge = vec![b' '; MAX_CATALOG_BYTES + 1];
        assert_eq!(call(&request, &huge, None).err(), Some("catalog.too_large"));
    }
}
