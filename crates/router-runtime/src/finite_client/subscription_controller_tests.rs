use super::*;
use std::io::{BufRead, BufReader};
use std::time::Duration;
fn pair() -> (OwnedSubscriptionController, SubscriptionControllerPeer) {
    OwnedSubscriptionController::pair(
        "t02-Lm-r1-H0",
        &"a".repeat(64),
        &"b".repeat(64),
        &"c".repeat(64),
    )
    .unwrap()
}
#[test]
fn independently_owned_channels_never_share_review_identity() {
    let (one, _) = pair();
    let (two, _) = pair();
    assert_ne!(one.binding().nonce, two.binding().nonce);
    assert_ne!(
        one.binding().channel_instance_sha256,
        two.binding().channel_instance_sha256
    );
    assert!(
        OwnedSubscriptionController::pair(
            "../private",
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64)
        )
        .is_err()
    );
}

#[test]
fn controller_ready_requires_exact_parent_ack_before_dispatch() {
    let (controller, peer) = pair();
    let peer = peer.into_transport();
    peer.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let host = std::thread::spawn(move || {
        let mut reader = BufReader::new(peer);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let ready: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(ready["kind"], "runtime_ready");
        assert_eq!(ready["binding"]["run_id"], "run-one");
        let mut binding = ready["binding"].clone();
        binding["nonce"] = "foreign".into();
        writeln!(
            reader.get_mut(),
            "{}",
            json!({"schema_version":1,"kind":"controller_ready","binding":binding})
        )
        .unwrap();
    });
    assert!(controller.ready("run-one", &"d".repeat(64)).is_err());
    host.join().unwrap();
}

#[test]
fn subscription_frames_reach_worker_only_on_exact_channel_and_persisted_barrier() {
    let (controller, peer) = pair();
    let controller = Arc::new(controller);
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let cancel = Cancellation::default();
    let mut server = controller.start(listener, cancel.clone()).unwrap();
    let (sent, received) = std::sync::mpsc::channel();
    let host = std::thread::spawn(move || {
        let mut io = peer.into_transport();
        io.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let stop = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(2);
        let ready = read_json(&mut io, deadline, &stop).unwrap();
        let binding = ready["binding"].clone();
        send_json(
            &mut io,
            &json!({"schema_version":1,"kind":"controller_ready","binding":binding}),
            deadline,
            &stop,
        )
        .unwrap();
        let request = read_json(&mut io, deadline, &stop).unwrap();
        assert_eq!(request["id"], 1);
        send_json(
            &mut io,
            &json!({"schema_version":1,"id":1,"kind":"chunk","data":"ZGF0YTogaGVsbG8KCg=="}),
            deadline,
            &stop,
        )
        .unwrap();
        send_json(
            &mut io,
            &json!({"schema_version":1,"id":1,"kind":"terminal","complete":true,
            "request_body_sha256":content_digest(&serde_json::to_vec(&request["body"]).unwrap()),
            "observed_response_model":"gpt-6-luna","usage":{"total_tokens":5},"cumulative_usage":{"total_tokens":5},
            "cumulative_equivalent_microcredits":1,"stop_reason":null}),
            deadline,
            &stop,
        )
        .unwrap();
        received.recv_timeout(Duration::from_secs(1)).unwrap();
        send_json(&mut io,&json!({"schema_version":1,"kind":"controller_request_finished","binding":binding,"id":1,"continue":false,"reason":"observed_campaign_budget"}),deadline,&stop).unwrap();
        let cleanup = read_json(&mut io, deadline, &stop).unwrap();
        assert_eq!(cleanup["kind"], "runtime_cleanup");
        assert_eq!(cleanup["cleanup"], "namespace_terminated");
        assert_eq!(cleanup["binding"], binding);
        send_json(&mut io,&json!({"schema_version":1,"kind":"controller_finished","binding":binding,"execution_authorized":false}),deadline,&stop).unwrap();
    });
    controller.ready("run-one", &"d".repeat(64)).unwrap();
    let mut worker = TcpStream::connect(address).unwrap();
    worker
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let body =
        br#"{"model":"gpt-6-luna","reasoning":{"effort":"medium"},"stream":true,"store":false}"#;
    write!(
        worker,
        "POST /v1/responses HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .unwrap();
    worker.write_all(body).unwrap();
    let mut received = Vec::new();
    let mut byte = [0];
    while !received.ends_with(b"data: hello\n\n") {
        worker.read_exact(&mut byte).unwrap();
        received.push(byte[0]);
    }
    assert!(
        matches!(worker.read(&mut byte),Err(e) if retry_io(&e)),
        "HTTP must remain open until durable barrier"
    );
    sent.send(()).unwrap();
    assert_eq!(worker.read(&mut byte).unwrap(), 0);
    assert!(cancel.is_cancelled());
    server.stop().unwrap();
    controller.cleanup(&"e".repeat(64), "interrupted").unwrap();
    host.join().unwrap();
    assert_eq!(controller.observation().unwrap().known_prefix_tokens, 5);
    assert!(!controller.observation().unwrap().usage_unknown);
}

#[test]
fn malformed_chunks_are_refused_instead_of_reaching_worker() {
    assert_eq!(decode_chunk("aGVsbG8=").unwrap(), b"hello");
    for bad in [
        "", "aGVsbG8", "aGVsbG9=", "Zg==AAAA", "AA=A", "____", "Zg==\n",
    ] {
        assert!(decode_chunk(bad).is_err(), "{bad}");
    }
}

#[test]
fn abrupt_parent_eof_refuses_ack_and_never_arms_session() {
    let (controller, peer) = pair();
    drop(peer);
    assert!(controller.ready("run-one", &"d".repeat(64)).is_err());
    assert!(controller.deadline().is_err());
}

#[test]
fn worker_exec_cannot_inherit_parent_controller_descriptors() {
    use std::os::fd::AsRawFd;
    let (controller, peer) = pair();
    let flags = nix::fcntl::fcntl(
        controller.io.lock().unwrap().as_raw_fd(),
        nix::fcntl::FcntlArg::F_GETFD,
    )
    .unwrap();
    let peer_flags = nix::fcntl::fcntl(peer.0.as_raw_fd(), nix::fcntl::FcntlArg::F_GETFD).unwrap();
    assert_ne!(flags & nix::fcntl::FdFlag::FD_CLOEXEC.bits(), 0);
    assert_ne!(peer_flags & nix::fcntl::FdFlag::FD_CLOEXEC.bits(), 0);
}

#[test]
fn unknown_usage_stops_worker_but_preserves_cleanup_handshake() {
    let (controller, peer) = pair();
    let controller = Arc::new(controller);
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let cancel = Cancellation::default();
    let mut server = controller.start(listener, cancel.clone()).unwrap();
    let host = std::thread::spawn(move || {
        let mut io = peer.into_transport();
        let stop = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(2);
        let ready = read_json(&mut io, deadline, &stop).unwrap();
        let binding = ready["binding"].clone();
        send_json(
            &mut io,
            &json!({"schema_version":1,"kind":"controller_ready","binding":binding}),
            deadline,
            &stop,
        )
        .unwrap();
        let request = read_json(&mut io, deadline, &stop).unwrap();
        assert_eq!(request["id"], 1);
        send_json(
            &mut io,
            &json!({"schema_version":1,"id":1,"kind":"chunk","data":"ZGF0YTogaGVsbG8KCg=="}),
            deadline,
            &stop,
        )
        .unwrap();
        send_json(&mut io,&json!({"schema_version":1,"id":1,"kind":"terminal","complete":false,"usage":null,"stop_reason":"unknown"}),deadline,&stop).unwrap();
        send_json(&mut io,&json!({"schema_version":1,"kind":"controller_request_finished","binding":binding,"id":1,"continue":false,"reason":"unknown"}),deadline,&stop).unwrap();
        let cleanup = read_json(&mut io, deadline, &stop).unwrap();
        assert_eq!(cleanup["kind"], "runtime_cleanup");
        send_json(&mut io,&json!({"schema_version":1,"kind":"controller_finished","binding":binding,"execution_authorized":false}),deadline,&stop).unwrap();
    });
    controller.ready("run-one", &"d".repeat(64)).unwrap();
    let mut worker = TcpStream::connect(address).unwrap();
    worker
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let body =
        br#"{"model":"gpt-6-luna","reasoning":{"effort":"medium"},"stream":true,"store":false}"#;
    write!(
        worker,
        "POST /v1/responses HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .unwrap();
    worker.write_all(body).unwrap();
    let mut bytes = Vec::new();
    worker.read_to_end(&mut bytes).unwrap();
    assert!(cancel.is_cancelled());
    server.stop().unwrap();
    controller.cleanup(&"e".repeat(64), "interrupted").unwrap();
    host.join().unwrap();
}

#[test]
#[ignore = "explicit public host-driver handshake, no native worker or provider"]
fn actual_host_driver_acknowledges_private_runtime_prelude() {
    let dir = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let root = dir.path().canonicalize().unwrap();
    let driver = std::env::var("AR_SUBSCRIPTION_HOST_DRIVER").unwrap();
    let descriptor = root.join("descriptor.json");
    fs::write(&descriptor,serde_json::to_vec(&json!({"qualification_only":true,"assignment_id":"t02-Lx-r1-H0","model":"gpt-6-luna","effort":"xhigh","marker":"R2-LOCAL-TOOLS-V1","output_file":"lib.rs","output_content":"public fixture only\n","account_sha256":"b".repeat(64),"budget_microcredits":200000000u64,"evidence_directory":root})).unwrap()).unwrap();
    let prepare = std::process::Command::new("python3")
        .args(["-B", &driver, "prepare", descriptor.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        prepare.status.success(),
        "{}",
        String::from_utf8_lossy(&prepare.stderr)
    );
    let configuration: Value = serde_json::from_slice(&prepare.stdout).unwrap();
    let (controller, peer) = OwnedSubscriptionController::pair(
        "t02-Lx-r1-H0",
        configuration["configuration_sha256"].as_str().unwrap(),
        &"b".repeat(64),
        configuration["controller_sha256"].as_str().unwrap(),
    )
    .unwrap();
    let mut binding = serde_json::to_value(controller.binding()).unwrap();
    binding["run_id"] = "probe".into();
    binding["approval_digest"] = "d".repeat(64).into();
    binding["attempt"] = 1.into();
    let expected = root.join("expected.json");
    fs::write(&expected, serde_json::to_vec(&binding).unwrap()).unwrap();
    let mut child = std::process::Command::new("python3")
        .args([
            "-B",
            &driver,
            "run",
            descriptor.to_str().unwrap(),
            expected.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let stream = peer.into_transport();
    let mut read = stream.try_clone().unwrap();
    let mut write = stream;
    let a = std::thread::spawn(move || relay(&mut read, &mut input));
    let b = std::thread::spawn(move || {
        let result = relay(&mut output, &mut write);
        let _ = write.shutdown(Shutdown::Write);
        result
    });
    let ready = controller.ready("probe", &"d".repeat(64));
    if let Err(error) = &ready {
        eprintln!("prelude failed: {error}");
    }
    if ready.is_ok() {
        controller.cleanup(&"e".repeat(64), "interrupted").unwrap();
    }
    drop(controller);
    let forwarded = a.join().unwrap();
    let returned = b.join().unwrap();
    let result = child.wait_with_output().unwrap();
    eprintln!("private bridge bytes: forwarded={forwarded:?}, returned={returned:?}");
    assert!(
        ready.is_ok(),
        "ready failed; host diagnostic: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn relay<R: Read, W: Write>(input: &mut R, output: &mut W) -> std::io::Result<u64> {
    let mut bytes = [0; 8192];
    let mut count = 0;
    loop {
        let n = input.read(&mut bytes)?;
        if n == 0 {
            return Ok(count);
        }
        output.write_all(&bytes[..n])?;
        output.flush()?;
        count += n as u64;
    }
}
