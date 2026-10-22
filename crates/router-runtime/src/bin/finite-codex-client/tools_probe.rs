//! Fixed no-model live canary. Configuration alone never calls this entry.
use super::*;
use std::{
    io::{BufRead, BufReader},
    net::Shutdown,
    os::unix::net::UnixStream,
    time::Duration,
};
fn send(stream: &mut UnixStream, value: serde_json::Value) -> Result<(), &'static str> {
    let mut bytes = serde_json::to_vec(&value).map_err(|_| "probe.encode")?;
    if bytes.len() > 65535 {
        return Err("probe.bound");
    }
    bytes.push(b'\n');
    stream.write_all(&bytes).map_err(|_| "probe.write")
}
fn reply(reader: &mut BufReader<UnixStream>, id: u64) -> Result<serde_json::Value, &'static str> {
    let mut bytes = Vec::new();
    Read::by_ref(reader)
        .take(65537)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| "probe.read")?;
    let value =
        router_adapter_api::strict_json_limited(&bytes, 65536).map_err(|_| "probe.reply")?;
    if value["jsonrpc"] != "2.0" || value["id"] != id || value.get("error").is_some() {
        return Err("probe.reply_binding");
    }
    Ok(value["result"].clone())
}
fn call(
    stream: &mut UnixStream,
    reader: &mut BufReader<UnixStream>,
    id: u64,
    name: &str,
    args: serde_json::Value,
) -> Result<serde_json::Value, &'static str> {
    send(
        stream,
        serde_json::json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":args,"_meta":{"callId":"owned-live-probe"}}}),
    )?;
    let value = reply(reader, id)?;
    if value["isError"] != false {
        return Err("probe.tool_refused");
    }
    let text = value["content"]
        .as_array()
        .filter(|a| a.len() == 1)
        .and_then(|a| a[0]["text"].as_str())
        .ok_or("probe.content")?;
    let result = router_adapter_api::strict_json_limited(text.as_bytes(), 65536)
        .map_err(|_| "probe.result")?;
    if result["exit_code"] != 0 || result["termination"] != "exited" || result["truncated"] != false
    {
        return Err("probe.tool_failed");
    }
    Ok(result)
}
pub(super) fn execute() -> Result<i32, &'static str> {
    let nonce = std::env::var("ROUTER_FINITE_PROBE_NONCE").map_err(|_| "probe.nonce")?;
    if !is_digest(&nonce) {
        return Err("probe.nonce");
    }
    let output = std::env::var("ROUTER_FINITE_PROBE_OUTPUT").map_err(|_| "probe.output")?;
    let read = std::env::var("ROUTER_FINITE_PROBE_READ").map_err(|_| "probe.public")?;
    let expected = std::env::var("ROUTER_FINITE_PROBE_READ_SHA256").map_err(|_| "probe.public")?;
    let create = std::env::var("ROUTER_FINITE_PROBE_CREATE").map_err(|_| "probe.create")? == "true";
    let timeout: u64 = std::env::var("ROUTER_FINITE_PROBE_EXEC_MS")
        .map_err(|_| "probe.timeout")?
        .parse()
        .map_err(|_| "probe.timeout")?;
    if [output.as_str(), read.as_str()].iter().any(|s| {
        s.is_empty()
            || s.starts_with('.')
            || s.len() > 128
            || !s
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    }) || !is_digest(&expected)
        || timeout == 0
        || timeout > 20000
    {
        return Err("probe.shape");
    }
    if Path::new(&output).exists() == create {
        return Err("probe.preimage");
    }
    let direct = OpenOptions::new().write(true).create(create).open(&output);
    match direct {
        Ok(_) => return Err("probe.direct_write"),
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(nix::libc::EACCES | nix::libc::EPERM | nix::libc::EROFS)
            ) => {}
        Err(_) => return Err("probe.direct_write_control"),
    }
    if super::execute(true)? != 0 {
        return Err("probe.native_version");
    }
    let mut stream = UnixStream::connect("/router-tools/rpc.sock").map_err(|_| "probe.connect")?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| "probe.deadline")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| "probe.deadline")?;
    let mut reader = BufReader::new(stream.try_clone().map_err(|_| "probe.clone")?);
    send(
        &mut stream,
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"owned-live-probe","version":"1"}}}),
    )?;
    let init = reply(&mut reader, 1)?;
    if init["protocolVersion"] != "2025-06-18" {
        return Err("probe.version");
    }
    send(
        &mut stream,
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )?;
    send(
        &mut stream,
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    )?;
    let tools = reply(&mut reader, 2)?;
    let names: std::collections::BTreeSet<_> = tools["tools"]
        .as_array()
        .ok_or("probe.catalog")?
        .iter()
        .map(|v| v["name"].as_str().unwrap_or(""))
        .collect();
    if names != std::collections::BTreeSet::from(["exec", "read_file", "write_file"])
        || tools["tools"].as_array().ok_or("probe.catalog")?.len() != 3
    {
        return Err("probe.catalog");
    }
    let result = call(
        &mut stream,
        &mut reader,
        3,
        "read_file",
        serde_json::json!({"path":read}),
    )?;
    if content_digest(
        result["stdout"]
            .as_str()
            .ok_or("probe.read_content")?
            .as_bytes(),
    ) != expected
    {
        return Err("probe.read_content");
    }
    call(
        &mut stream,
        &mut reader,
        4,
        "write_file",
        serde_json::json!({"path":output,"content":nonce,"create_new":create}),
    )?;
    let source = format!(
        "fn main() {{ let a=std::fs::metadata(\".scratch/nested-heartbeat\").unwrap().len(); std::thread::sleep(std::time::Duration::from_millis(50)); assert!(a>1); assert_eq!(std::fs::metadata(\".scratch/nested-heartbeat\").unwrap().len(),a); println!(\"{nonce}\"); }}"
    );
    call(
        &mut stream,
        &mut reader,
        5,
        "write_file",
        serde_json::json!({"path":".scratch/probe.rs","content":source,"create_new":true}),
    )?;
    let python = format!(
        "import errno,mmap,os,resource,socket,time\nassert resource.getrlimit(resource.RLIMIT_AS)==(8589934592,8589934592)\nwith mmap.mmap(-1,16777216,prot=0): pass\ntry: mmap.mmap(-1,9663676416,prot=0);raise AssertionError('unbounded memory')\nexcept OSError as e: assert e.errno==errno.ENOMEM\nfor action in [lambda:open({output:?},'w'),lambda:socket.socket(socket.AF_INET,socket.SOCK_STREAM),lambda:socket.socket(socket.AF_UNIX,socket.SOCK_STREAM),lambda:socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)]:\n try: action();raise AssertionError('boundary failed')\n except OSError as e: assert e.errno in (errno.EPERM,errno.EACCES,errno.EROFS)\nfor p in ['/work','/router-tools','/router-secret-home']:\n try: os.stat(p);raise AssertionError('private mount')\n except OSError as e: assert e.errno==errno.ENOENT\nf=os.open('.scratch/nested-heartbeat',os.O_CREAT|os.O_WRONLY,0o600)\np=os.fork()\nif p==0:\n os.setsid()\n while True:\n  os.write(f,b'x');time.sleep(0.005)\ntime.sleep(0.1)\nprint({nonce:?})\n"
    );
    let result = call(
        &mut stream,
        &mut reader,
        6,
        "exec",
        serde_json::json!({"argv":["python3","-B","-c",python],"timeout_ms":timeout}),
    )?;
    if result["stdout"] != format!("{nonce}\n") {
        return Err("probe.python_effect");
    }
    call(
        &mut stream,
        &mut reader,
        7,
        "exec",
        serde_json::json!({"argv":["rustc",".scratch/probe.rs","-o",".scratch/probe"],"timeout_ms":timeout}),
    )?;
    let result = call(
        &mut stream,
        &mut reader,
        8,
        "exec",
        serde_json::json!({"argv":[".scratch/probe"],"timeout_ms":timeout}),
    )?;
    if result["stdout"] != format!("{nonce}\n") {
        return Err("probe.compiler_effect");
    }
    let _ = stream.shutdown(Shutdown::Write);
    println!(
        "{}",
        serde_json::json!({"finite_tools_probe":"v1","nonce":nonce,"direct_write_refused":true,"calls":6})
    );
    Ok(0)
}
