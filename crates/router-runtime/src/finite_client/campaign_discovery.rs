//! Fresh tools-only discovery. No provider transport, credentials or model call.
use super::*;
use router_adapter_api::{CapabilityEvidence, HostObservation, SnapshotValidation};
use router_types::{CapabilitySupport, ProcessCleanupEvidence};
use std::collections::BTreeMap;

impl ApprovedFiniteClient {
    /// Execute the already-reviewed fixed OS canaries, consuming their owners.
    /// Returns fresh capability evidence only, never execution authority.
    /// On unknown cleanup, retain all private resources and refuse the snapshot.
    pub async fn discover_linux_tools(
        self,
        root: &Path,
    ) -> Result<(ValidatedHostObservation, StoredCapabilityProofVerifier)> {
        if !cfg!(target_os = "linux")
            || std::env::consts::ARCH != "aarch64"
            || self.reviewed.owned_tools.is_none()
            || self.reviewed.owned_subscription.is_some()
        {
            return Err(RuntimeError::Sandbox);
        }
        directory(root.to_str().ok_or(RuntimeError::Scope)?, true)?;
        if fs::read_dir(root)?.next().is_some() {
            return Err(RuntimeError::Scope);
        }
        let run = self.reviewed.run.clone();
        let snapshot_id = self.reviewed.manifest.host_snapshot_id.clone();
        let binding = self.proof_binding(&snapshot_id)?;
        let broker = self.reviewed.broker.listener.try_clone()?;
        let mut state = self.into_namespace_state()?;
        let home = state.path().to_owned();
        let control = home.join("tmp/discovery");
        fs::DirBuilder::new().mode(0o700).create(&control)?;
        let hidden = root.join("controller-private");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&hidden)?
            .write_all(b"private canary")?;
        let other = TcpListener::bind(("127.0.0.1", 0))?;
        drop(std::net::TcpStream::connect(other.local_addr()?)?);
        let mut entropy = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut entropy)?;
        let nonce = content_digest(&entropy);
        let mut view = ProbeView {
            tools: None,
            temporary: home.join("tmp"),
            control: control.clone(),
            hidden,
            denied_port: other.local_addr()?.port(),
            nonce: nonce.clone(),
        };
        view.tools = Some(ToolsProbeView::prepare(&state, &view)?);
        let mut command = composition_command(&state, Some(&view))?;
        let leases = crate::leases::LeaseStorage::open(root)?;
        let (mut record, path) = leases.create("discovery", 1)?;
        record.require_namespace(true);
        state.arm_cleanup(Some(&path), true)?;
        command.env("ROUTER_RUNTIME_LEASE", path);
        let responder = DiscoveryResponder::start(broker)?;
        let started = crate::now()?;
        let captured =
            crate::process::capture(command, vec![], 10000, 65536, 100, &Cancellation::default())
                .await;
        let responded = responder.finish();
        if let Ok(capture) = &captured {
            for (name, bytes) in [
                ("probe.stdout", &capture.stdout),
                ("probe.stderr", &capture.stderr),
            ] {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(nix::libc::O_NOFOLLOW)
                    .open(root.join(name))?;
                file.write_all(bytes)?;
                file.sync_all()?;
            }
        }
        // The exact retained lock excludes detached writers before observation.
        let proof = leases.cleanup_proof("discovery", 1, &record)?;
        if proof.evidence != ProcessCleanupEvidence::NamespaceTerminated {
            return Err(RuntimeError::CleanupUnknown);
        }
        let checked = (|| -> Result<Vec<u8>> {
            responded?;
            let capture = captured?;
            if capture.outcome.exit_code != Some(0)
                || capture.output_limited
                || capture.output_incomplete
                || capture.outcome.termination != TransportTermination::Exited
            {
                return Err(RuntimeError::Sandbox);
            }
            let a = fs::metadata(control.join("heartbeat"))?.len();
            std::thread::sleep(Duration::from_millis(60));
            let b = fs::metadata(control.join("heartbeat"))?.len();
            if a <= 1 || a != b || fs::read(control.join("control"))? != nonce.as_bytes() {
                return Err(RuntimeError::Integrity("discovery live effects"));
            }
            view.tools
                .as_ref()
                .ok_or(RuntimeError::Sandbox)?
                .verify(&nonce)?;
            let lines: Vec<_> = capture
                .stdout
                .split(|b| *b == b'\n')
                .filter(|l| !l.is_empty())
                .collect();
            if lines.len() != 3 {
                return Err(RuntimeError::Integrity("discovery frames"));
            }
            let observed = router_adapter_api::strict_json_limited(lines[0], 8192)
                .map_err(|_| RuntimeError::Integrity("discovery JSON"))?;
            let version = router_adapter_api::strict_json_limited(lines[1], 8192)
                .map_err(|_| RuntimeError::Integrity("discovery JSON"))?;
            let tools = router_adapter_api::strict_json_limited(lines[2], 8192)
                .map_err(|_| RuntimeError::Integrity("discovery JSON"))?;
            if observed["linux_finite_probe"] != "v2"
                || observed["memory_bytes"] != 8589934592u64
                || observed["nonce"] != nonce
                || observed["workspace_write"] != false
                || version
                    != serde_json::json!({"finite_client_probe":"v1","native_version":"codex-cli 0.159.2"})
                || tools
                    != serde_json::json!({"finite_tools_probe":"v1","nonce":nonce,"direct_write_refused":true,"calls":6})
            {
                return Err(RuntimeError::Integrity("discovery observations"));
            }
            Ok(capture.stdout)
        })();
        // Even failed canaries clean only while this exact namespace lock is held.
        state.cleanup_with_proof(&proof)?;
        drop(proof);
        let output = checked?;
        let proof_root = root.join("baseline-proofs");
        fs::DirBuilder::new().mode(0o700).create(&proof_root)?;
        let err = |_| RuntimeError::Integrity("discovery proof store");
        let mut store = crate::CapabilityProofStore::create(&proof_root).map_err(err)?;
        let mut secret = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut secret)?;
        let key = CapabilityProofKey::derive(&secret, store.store_id())
            .map_err(|_| RuntimeError::Integrity("discovery key"))?;
        let now = crate::now()?;
        let capabilities = [
            Capability::Network,
            Capability::WorkspaceWrite,
            Capability::Tools,
        ];
        let mut sources = Vec::new();
        let mut evidence = BTreeMap::new();
        for (i, capability) in capabilities.into_iter().enumerate() {
            let record = CapabilityProofRecord {
                schema_version: 1,
                proof_id: format!("discovery-{nonce}-{i}"),
                sequence: store.next_sequence(&secret).map_err(err)?,
                store_id: store.store_id().into(),
                capability,
                tier: CapabilityProofTier::Proven,
                network_scope: (capability == Capability::Network)
                    .then_some(CapabilityNetworkScope::LoopbackFetch),
                binding: binding.clone(),
                model_id: run.requested_model.to_string(),
                nonce_sha256: content_digest(nonce.as_bytes()),
                expected_effect_sha256: content_digest(&output),
                started_at_unix_seconds: started,
                ended_at_unix_seconds: now,
                max_age_seconds: 300,
                outcome: CapabilityAttemptOutcome::Succeeded,
            };
            let auth = key
                .authenticate(record)
                .map_err(|_| RuntimeError::Integrity("discovery proof"))?;
            let source = EvidenceSource {
                id: auth.record.proof_id.clone(),
                kind: EvidenceKind::HostRuntime,
                observed_version: Some(binding.observed_version.clone()),
                observed_at_unix_seconds: now,
                content_sha256: auth
                    .digest()
                    .map_err(|_| RuntimeError::Integrity("discovery proof digest"))?,
            };
            store.append(&auth, &secret).map_err(err)?;
            evidence.insert(
                capability,
                CapabilityEvidence {
                    support: CapabilitySupport::Supported,
                    source_ids: [source.id.clone()].into(),
                },
            );
            sources.push(source);
        }
        drop(store);
        let verifier =
            StoredCapabilityProofVerifier::open_existing(&proof_root, secret, vec![binding])
                .map_err(err)?;
        let host = HostSnapshot {
            id: snapshot_id,
            harness: run.host.clone(),
            supported_models: [run.requested_model.clone()].into(),
            supported_efforts: BTreeMap::from([(
                run.requested_model,
                [run.requested_effort].into(),
            )]),
            capabilities: capabilities.into(),
        };
        let observation = HostObservation {
            schema_version: 1,
            host,
            capabilities: evidence,
            evidence: sources,
            observed_at_unix_seconds: now,
            snapshot_hash: String::new(),
            attestations: None,
        }
        .seal()
        .map_err(|_| RuntimeError::Integrity("discovery snapshot"))?;
        let snapshot = ValidatedHostObservation::from_observation_with_verifier(
            observation,
            SnapshotValidation {
                now_unix_seconds: now,
                max_age_seconds: 300,
            },
            Some(&verifier),
        )
        .map_err(|_| RuntimeError::Integrity("discovery snapshot verification"))?;
        Ok((snapshot, verifier))
    }
}

/// Single fixed network canary. No provider parser, forwarding or credentials.
struct DiscoveryResponder {
    cancel: Cancellation,
    worker: Option<std::thread::JoinHandle<Result<()>>>,
}
impl DiscoveryResponder {
    fn start(listener: TcpListener) -> Result<Self> {
        listener.set_nonblocking(true)?;
        let cancel = Cancellation::default();
        let stopping = cancel.clone();
        let worker = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let result = (|| {
                while !stopping.is_cancelled() && std::time::Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut socket, _)) => {
                            socket.set_nonblocking(false)?;
                            socket.set_read_timeout(Some(Duration::from_secs(1)))?;
                            socket.set_write_timeout(Some(Duration::from_secs(1)))?;
                            const REQUEST: &[u8] =
                                b"GET /__router_probe__ HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
                            let mut request = [0; REQUEST.len()];
                            let read_deadline = std::time::Instant::now() + Duration::from_secs(1);
                            let mut read = 0;
                            while read < request.len() {
                                let remaining = read_deadline
                                    .checked_duration_since(std::time::Instant::now())
                                    .filter(|d| !d.is_zero())
                                    .ok_or(RuntimeError::Integrity("discovery probe timeout"))?;
                                socket.set_read_timeout(Some(remaining))?;
                                let n = socket.read(&mut request[read..])?;
                                if n == 0 {
                                    return Err(RuntimeError::Integrity("discovery probe EOF"));
                                }
                                read += n;
                            }
                            if request != REQUEST {
                                return Err(RuntimeError::Integrity("discovery probe request"));
                            }
                            socket.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")?;
                            return Ok(());
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                Err(RuntimeError::Integrity("discovery probe absent"))
            })();
            listener.set_nonblocking(false)?;
            result
        });
        Ok(Self {
            cancel,
            worker: Some(worker),
        })
    }
    fn finish(mut self) -> Result<()> {
        self.cancel.cancel();
        self.worker
            .take()
            .ok_or(RuntimeError::Sandbox)?
            .join()
            .map_err(|_| RuntimeError::Integrity("discovery responder panic"))?
    }
}
impl Drop for DiscoveryResponder {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_responder_accepts_only_fixed_probe_and_releases_listener() {
        for (request, success) in [
            (
                b"GET /__router_probe__ HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n".as_slice(),
                true,
            ),
            (
                b"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n{}".as_slice(),
                false,
            ),
        ] {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let endpoint = listener.local_addr().unwrap();
            let responder = DiscoveryResponder::start(listener.try_clone().unwrap()).unwrap();
            let mut stream = std::net::TcpStream::connect(endpoint).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream.write_all(request).unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            let mut response = Vec::new();
            let _ = stream.read_to_end(&mut response);
            assert_eq!(responder.finish().is_ok(), success);
            assert_eq!(response.starts_with(b"HTTP/1.0 200 OK"), success);
            if !success {
                assert!(response.is_empty());
            }
            // No responder remains to consume the actual runtime connection.
            let _new = std::net::TcpStream::connect(endpoint).unwrap();
            listener.accept().unwrap();
        }
    }
    #[test]
    fn absent_discovery_probe_stops_without_waiting_for_deadline() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let responder = DiscoveryResponder::start(listener).unwrap();
        let started = std::time::Instant::now();
        assert!(responder.finish().is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
