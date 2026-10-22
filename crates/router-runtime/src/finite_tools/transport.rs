//! Fixed stdio-to-owner bridge. Protocol data never selects a socket path.
use super::FiniteToolError;
use std::{
    io::{BufRead, Write},
    os::unix::net::UnixStream,
};

const MESSAGE: usize = 65536;
const MESSAGES: usize = 256;

fn frames(mut input: impl BufRead, mut output: impl Write) -> Result<(), FiniteToolError> {
    use std::io::Read;
    for _ in 0..MESSAGES {
        let mut line = Vec::new();
        let n = input
            .by_ref()
            .take((MESSAGE + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| FiniteToolError::Refused("bridge.read"))?;
        if n == 0 {
            return Ok(());
        }
        if line.len() > MESSAGE || line.last() != Some(&b'\n') {
            return Err(FiniteToolError::Refused("bridge.frame_bound"));
        }
        output
            .write_all(&line)
            .and_then(|()| output.flush())
            .map_err(|_| FiniteToolError::Refused("bridge.write"))?;
    }
    // The limit is terminal; do not read one more possibly unbounded message.
    Err(FiniteToolError::Refused("bridge.message_bound"))
}

pub(super) fn relay(
    input: impl BufRead + Send + 'static,
    output: impl Write,
    stream: UnixStream,
) -> Result<(), FiniteToolError> {
    use std::{io::BufReader, net::Shutdown, time::Duration};
    let deadline = Some(Duration::from_secs(90));
    stream
        .set_read_timeout(deadline)
        .and_then(|()| stream.set_write_timeout(deadline))
        .map_err(|_| FiniteToolError::Refused("bridge.timeout"))?;
    let mut send = stream
        .try_clone()
        .map_err(|_| FiniteToolError::Refused("bridge.clone"))?;
    // This input-only reader owns no filesystem, process or dispatch authority.
    // If the peer closes while stdin is idle, main returns without waiting on
    // that reader. The fixed bridge process exits and the outer owner covers it.
    use std::sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    };
    let input_status = Arc::new(AtomicU8::new(0));
    let completed = input_status.clone();
    let sender = std::thread::spawn(move || {
        let result = frames(input, &mut send);
        completed.store(if result.is_ok() { 1 } else { 2 }, Ordering::SeqCst);
        let _ = send.shutdown(Shutdown::Write);
        result
    });
    let result = frames(
        BufReader::new(stream.try_clone().map_err(|_| FiniteToolError::Execution)?),
        output,
    );
    let _ = stream.shutdown(Shutdown::Both);
    if sender.is_finished() {
        sender.join().map_err(|_| FiniteToolError::Execution)??;
    }
    result?;
    if input_status.load(Ordering::SeqCst) != 1 {
        return Err(FiniteToolError::Refused("bridge.input_incomplete"));
    }
    Ok(())
}

/// Fixed native MCP subprocess entry. This does not construct runtime authority.
pub fn bridge_stdio() -> Result<(), FiniteToolError> {
    let stream = UnixStream::connect("/router-tools/rpc.sock")
        .map_err(|_| FiniteToolError::Refused("bridge.connect"))?;
    relay(
        std::io::BufReader::new(std::io::stdin()),
        std::io::stdout(),
        stream,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};
    #[test]
    fn bridge_transfers_actual_mcp_replies_and_stops_at_eof() {
        let (client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            super::super::serve_mcp(
                BufReader::new(server.try_clone().unwrap()),
                server,
                |_, _| unreachable!(),
            )
            .unwrap();
        });
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"real-bridge\",\"version\":\"1\"}}}\n";
        let mut output = Vec::new();
        relay(Cursor::new(input), &mut output, client).unwrap();
        worker.join().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["id"], 7);
        assert_eq!(value["result"]["serverInfo"]["name"], "agent-router-finite");
    }
    #[test]
    fn peer_eof_while_input_is_idle_is_never_a_successful_bridge() {
        struct Idle(std::sync::mpsc::Receiver<()>);
        impl std::io::Read for Idle {
            fn read(&mut self, _out: &mut [u8]) -> std::io::Result<usize> {
                let _ = self.0.recv();
                Ok(0)
            }
        }
        let (send, recv) = std::sync::mpsc::channel();
        let (client, server) = UnixStream::pair().unwrap();
        server.shutdown(std::net::Shutdown::Both).unwrap();
        let outcome = relay(BufReader::new(Idle(recv)), Vec::new(), client);
        send.send(()).unwrap();
        assert!(outcome.is_err());
    }
}
