//! Pure bounded MCP JSONL codec. No process, filesystem or socket access.
use serde_json::{Value, json};
use std::io::{BufRead, Read, Write};

const MAX_MESSAGE: usize = 65536;
const MAX_MESSAGES: usize = 256;

fn keys(value: &Value, required: &[&str], optional: &[&str]) -> Result<(), &'static str> {
    let object = value.as_object().ok_or("mcp.object")?;
    if required.iter().any(|k| !object.contains_key(*k))
        || object
            .keys()
            .any(|k| !required.contains(&k.as_str()) && !optional.contains(&k.as_str()))
    {
        return Err("mcp.fields");
    }
    Ok(())
}

// Legacy Codex sends request/trace context here. It is bounded, discarded,
// and never merged with tool arguments or interpreted as execution authority.
fn metadata(params: &Value) -> Result<(), &'static str> {
    let Some(meta) = params.get("_meta") else {
        return Ok(());
    };
    if !meta.is_object() {
        return Err("mcp.metadata_shape");
    }
    fn walk(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), &'static str> {
        *nodes += 1;
        if depth > 8 || *nodes > 128 {
            return Err("mcp.metadata_bound");
        }
        match value {
            Value::String(text) if text.len() > 1024 => return Err("mcp.metadata_bound"),
            Value::Array(values) => {
                for value in values {
                    walk(value, depth + 1, nodes)?;
                }
            }
            Value::Object(fields) => {
                for (key, value) in fields {
                    if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
                        return Err("mcp.metadata_bound");
                    }
                    walk(value, depth + 1, nodes)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    walk(meta, 0, &mut 0)?;
    if serde_json::to_vec(meta)
        .map_err(|_| "mcp.metadata_encode")?
        .len()
        > 4096
    {
        return Err("mcp.metadata_bound");
    }
    Ok(())
}

fn scalar_id(value: &Value) -> bool {
    value.as_i64().is_some()
        || value.as_u64().is_some()
        || value.as_str().is_some_and(|id| {
            !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_graphic())
        })
}

fn path(value: &Value) -> bool {
    value.as_str().is_some_and(|name| {
        let flat = name.strip_prefix(".scratch/").unwrap_or(name);
        !flat.is_empty()
            && flat.len() <= 128
            && !flat.starts_with('.')
            && flat
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    })
}

fn arguments(name: &str, args: &Value) -> Result<(), &'static str> {
    match name {
        "read_file" => {
            keys(args, &["path"], &[])?;
            if !path(&args["path"]) {
                return Err("mcp.path");
            }
        }
        "write_file" => {
            keys(args, &["path", "content"], &["create_new"])?;
            if !path(&args["path"])
                || args["content"].as_str().is_none_or(|s| s.len() > 32768)
                || args
                    .get("create_new")
                    .is_some_and(|value| !value.is_boolean())
            {
                return Err("mcp.write_bound");
            }
        }
        "exec" => {
            keys(args, &["argv"], &["timeout_ms"])?;
            let argv = args["argv"].as_array().ok_or("mcp.argv")?;
            if argv.is_empty()
                || argv.len() > 32
                || argv.iter().any(|v| {
                    !v.as_str()
                        .is_some_and(|s| !s.is_empty() && s.len() <= 4096 && !s.contains('\0'))
                })
                || argv
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::len)
                    .sum::<usize>()
                    > 16384
                || args
                    .get("timeout_ms")
                    .is_some_and(|v| !v.as_u64().is_some_and(|n| (1..=20000).contains(&n)))
            {
                return Err("mcp.argv_bound");
            }
        }
        _ => return Err("mcp.tool"),
    }
    Ok(())
}

fn tools() -> Value {
    let name = json!({"type":"string","minLength":1,"maxLength":137});
    json!([
        {"name":"read_file","description":"Read one approved public or scratch file.",
         "inputSchema":{"type":"object","properties":{"path":name},"required":["path"],"additionalProperties":false}},
        {"name":"write_file","description":"Write one explicitly approved output or scratch file.",
         "inputSchema":{"type":"object","properties":{"path":name,"content":{"type":"string","maxLength":32768},"create_new":{"type":"boolean","default":false}},
            "required":["path","content"],"additionalProperties":false}},
        {"name":"exec","description":"Run a bounded local check under the tool owner's sandbox.",
         "inputSchema":{"type":"object","properties":{
            "argv":{"type":"array","minItems":1,"maxItems":32,"items":{"type":"string","minLength":1,"maxLength":4096}},
            "timeout_ms":{"type":"integer","minimum":1,"maximum":20000}},"required":["argv"],"additionalProperties":false}}
    ])
}

fn reply(writer: &mut impl Write, id: &Value, result: Value) -> Result<(), &'static str> {
    let raw = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result}))
        .map_err(|_| "mcp.encode")?;
    if raw.len() > MAX_MESSAGE {
        return Err("mcp.response_bound");
    }
    writer
        .write_all(&raw)
        .and_then(|()| writer.write_all(b"\n"))
        .and_then(|()| writer.flush())
        .map_err(|_| "mcp.write")
}

pub fn serve(
    mut reader: impl BufRead,
    mut writer: impl Write,
    mut dispatch: impl FnMut(&str, Value) -> Result<Value, &'static str>,
) -> Result<(), &'static str> {
    let mut initialized = false;
    let mut ready = false;
    let mut count = 0;
    loop {
        let mut line = Vec::new();
        let read = reader
            .by_ref()
            .take((MAX_MESSAGE + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| "mcp.read")?;
        if read == 0 {
            return Ok(());
        }
        count += 1;
        if count > MAX_MESSAGES || line.len() > MAX_MESSAGE || line.last() != Some(&b'\n') {
            return Err("mcp.message_bound");
        }
        let message =
            router_adapter_api::strict_json_limited(&line, MAX_MESSAGE).map_err(|_| "mcp.json")?;
        keys(&message, &["jsonrpc", "method"], &["id", "params"])?;
        if message["jsonrpc"] != "2.0" {
            return Err("mcp.version");
        }
        let method = message["method"].as_str().ok_or("mcp.method")?;
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
        if method == "notifications/initialized" {
            keys(&params, &[], &[])?;
            if !initialized || ready || message.get("id").is_some() {
                return Err("mcp.state");
            }
            ready = true;
            continue;
        }
        let id = message.get("id").filter(|v| scalar_id(v)).ok_or("mcp.id")?;
        match method {
            "initialize" => {
                if initialized {
                    return Err("mcp.state");
                }
                keys(
                    &params,
                    &["protocolVersion", "capabilities", "clientInfo"],
                    &[],
                )?;
                let version = params["protocolVersion"]
                    .as_str()
                    .ok_or("mcp.protocol_version")?;
                if !["2024-11-05", "2025-03-26", "2025-06-18"].contains(&version)
                    || !params["capabilities"].is_object()
                {
                    return Err("mcp.initialize");
                }
                keys(&params["clientInfo"], &["name", "version"], &["title"])?;
                if ["name", "version"].iter().any(|k| {
                    !params["clientInfo"][k].as_str().is_some_and(|s| {
                        !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
                    })
                }) {
                    return Err("mcp.client_info");
                }
                reply(
                    &mut writer,
                    id,
                    json!({"protocolVersion":version,"capabilities":{"tools":{"listChanged":false}},
                    "serverInfo":{"name":"agent-router-finite","version":"1"}}),
                )?;
                initialized = true;
            }
            "ping" => {
                if !initialized {
                    return Err("mcp.state");
                }
                keys(&params, &[], &[])?;
                reply(&mut writer, id, json!({}))?;
            }
            "tools/list" => {
                if !ready {
                    return Err("mcp.state");
                }
                keys(&params, &[], &["_meta"])?;
                metadata(&params)?;
                reply(&mut writer, id, json!({"tools":tools()}))?;
            }
            "tools/call" => {
                if !ready {
                    return Err("mcp.state");
                }
                keys(&params, &["name", "arguments"], &["_meta"])?;
                metadata(&params)?;
                let name = params["name"].as_str().ok_or("mcp.tool")?;
                arguments(name, &params["arguments"])?;
                let result = match dispatch(name, params["arguments"].clone()) {
                    Ok(value) => {
                        let text =
                            serde_json::to_string(&value).map_err(|_| "mcp.result_encode")?;
                        if text.len() > MAX_MESSAGE / 2 {
                            return Err("mcp.result_bound");
                        }
                        json!({"content":[{"type":"text","text":text}],"isError":false})
                    }
                    Err(_) => {
                        json!({"content":[{"type":"text","text":"Tool request refused."}],"isError":true})
                    }
                };
                reply(&mut writer, id, result)?;
            }
            _ => return Err("mcp.method"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;

    fn init(version: &str) -> Value {
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":version,"capabilities":{},"clientInfo":{"name":"Codex","version":"0.159.2"}}})
    }
    fn ready() -> Value {
        json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    }
    fn request(id: u64, method: &str, params: Value) -> Value {
        json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
    }
    fn input(values: &[Value]) -> Vec<u8> {
        values
            .iter()
            .map(|v| serde_json::to_string(v).unwrap() + "\n")
            .collect::<String>()
            .into_bytes()
    }
    fn output(raw: &[u8]) -> Vec<Value> {
        String::from_utf8_lossy(raw)
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect()
    }

    #[test]
    fn initialize_versions_and_exact_tool_catalog_round_trip() {
        for version in ["2024-11-05", "2025-03-26", "2025-06-18"] {
            let bytes = input(&[
                init(version),
                ready(),
                request(2, "ping", json!({})),
                request(3, "tools/list", json!({})),
            ]);
            let mut out = vec![];
            let result = serve(Cursor::new(bytes), &mut out, |_, _| {
                panic!("discovery must not dispatch tools")
            });
            assert!(result.is_ok());
            let responses = output(&out);
            assert_eq!(
                responses.len(),
                3,
                "notifications must not generate responses"
            );
            assert_eq!(responses[0]["result"]["protocolVersion"], version);
            let tools = responses[2]["result"]["tools"].as_array().unwrap();
            assert_eq!(
                tools
                    .iter()
                    .map(|v| v["name"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                vec!["read_file", "write_file", "exec"]
            );
            for tool in tools {
                assert_eq!(tool["inputSchema"]["additionalProperties"], false);
            }
        }
    }

    #[test]
    fn actual_dispatch_results_flow_red_then_write_then_green() {
        let feedback = json!({"name":"exec","arguments":{"argv":["python3","-B","feedback.py"]}});
        let bytes = input(&[
            init("2025-06-18"),
            ready(),
            request(2, "tools/call", feedback.clone()),
            request(
                3,
                "tools/call",
                json!({"name":"write_file","arguments":{"path":"review.json","content":"operator-control"}}),
            ),
            request(4, "tools/call", feedback),
        ]);
        let mut out = vec![];
        let mut written = false;
        let mut calls = 0;
        let result = serve(Cursor::new(bytes), &mut out, |name, args| {
            calls += 1;
            if name == "write_file" {
                assert_eq!(args["path"], "review.json");
                written = args["content"] == "operator-control";
            } else {
                assert_eq!(name, "exec");
                assert_eq!(args["argv"], json!(["python3", "-B", "feedback.py"]));
            }
            Ok(json!({"stdout":if written {"green"}else{"red"},"stderr":"",
                "exit_code":if name=="exec" && !written {1}else{0},"termination":"exited","truncated":false}))
        });
        assert!(result.is_ok());
        assert_eq!(
            calls, 3,
            "each tool request must reach the injected owner exactly once"
        );
        let responses = output(&out);
        let actual: Vec<_> = responses[1..]
            .iter()
            .map(|r| {
                assert_eq!(
                    r["result"]["isError"], false,
                    "feedback exit 1 is a successful tool invocation"
                );
                serde_json::from_str::<Value>(r["result"]["content"][0]["text"].as_str().unwrap())
                    .unwrap()["exit_code"]
                    .clone()
            })
            .collect();
        assert_eq!(actual, vec![json!(1), json!(0), json!(0)]);
    }

    #[test]
    fn malformed_duplicate_fields_and_complex_ids_are_rejected_without_dispatch() {
        for raw in [
            r#"{"jsonrpc":"2.0","id":1,"id":2,"method":"initialize"}"#,
            r#"{"jsonrpc":"2.0","id":{"secret":"CANARY"},"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","extra":"CANARY"}"#,
            "{invalid}",
        ] {
            let mut out = vec![];
            assert!(
                serve(Cursor::new(format!("{raw}\n")), &mut out, |_, _| panic!(
                    "invalid request dispatched"
                ))
                .is_err()
            );
            assert!(!String::from_utf8_lossy(&out).contains("CANARY"));
        }
    }

    #[test]
    fn unknown_or_uninitialized_methods_and_bad_tool_args_never_dispatch() {
        let cases = [
            vec![request(1, "tools/list", json!({}))],
            vec![
                init("2025-06-18"),
                ready(),
                request(2, "unknown", json!({})),
            ],
            vec![
                init("2025-06-18"),
                ready(),
                request(
                    2,
                    "tools/call",
                    json!({"name":"exec","arguments":{"argv":[],"secret":"CANARY"}}),
                ),
            ],
            vec![
                init("2025-06-18"),
                ready(),
                request(2, "tools/call", json!({"name":"shell","arguments":{}})),
            ],
            vec![
                init("2025-06-18"),
                ready(),
                json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"exec","arguments":{"argv":["python3"]}}}),
            ],
        ];
        for messages in cases {
            let mut out = vec![];
            assert!(
                serve(Cursor::new(input(&messages)), &mut out, |_, _| panic!(
                    "invalid request dispatched"
                ))
                .is_err()
            );
            assert!(!String::from_utf8_lossy(&out).contains("CANARY"));
        }
    }

    #[test]
    fn oversized_messages_and_message_flood_stop_before_tool_dispatch() {
        let mut out = vec![];
        assert!(
            serve(Cursor::new(vec![b'x'; 65537]), &mut out, |_, _| panic!(
                "oversized request dispatched"
            ))
            .is_err()
        );
        let mut messages = vec![init("2025-06-18"), ready()];
        messages.extend((0..255).map(|_| request(3, "ping", json!({}))));
        assert!(
            serve(Cursor::new(input(&messages)), &mut vec![], |_, _| panic!(
                "ping dispatched"
            ))
            .is_err()
        );
    }

    #[test]
    fn dispatch_refusal_returns_static_tool_error_and_never_echoes_arguments() {
        let bytes = input(&[
            init("2025-06-18"),
            ready(),
            request(
                2,
                "tools/call",
                json!({"name":"read_file","arguments":{"path":"private-canary"}}),
            ),
        ]);
        let mut out = vec![];
        assert!(serve(Cursor::new(bytes), &mut out, |_, _| Err("owner.refused")).is_ok());
        let responses = output(&out);
        assert_eq!(responses[1]["result"]["isError"], true);
        assert!(!String::from_utf8_lossy(&out).contains("private-canary"));
    }

    #[test]
    fn explicit_creation_flag_is_forwarded_and_boolean_only() {
        let bytes = input(&[
            init("2025-06-18"),
            ready(),
            request(
                2,
                "tools/call",
                json!({"name":"write_file","arguments":{"path":"review.json","content":"new","create_new":true}}),
            ),
        ]);
        let mut observed = false;
        let result = serve(Cursor::new(bytes), &mut vec![], |name, args| {
            assert_eq!(name, "write_file");
            observed = args["create_new"] == true;
            Ok(json!({}))
        });
        assert!(
            result.is_ok(),
            "explicit approved creation was rejected at codec boundary"
        );
        assert!(observed);
        let bad = input(&[
            init("2025-06-18"),
            ready(),
            request(
                2,
                "tools/call",
                json!({"name":"write_file","arguments":{"path":"review.json","content":"new","create_new":"true"}}),
            ),
        ]);
        assert!(
            serve(Cursor::new(bad), &mut vec![], |_, _| panic!(
                "invalid flag dispatched"
            ))
            .is_err()
        );
    }
    #[test]
    fn native_metadata_is_context_only_and_never_replaces_tool_arguments() {
        let frames = [
            init("2025-06-18"),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"traceparent":"00-authored-parent-context","tracestate":"authored=context"}}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"public.txt"},"_meta":{"callId":"call-01","threadId":"thread-01","sessionId":"session-01","windowId":"window-01","itemId":"item-01","plugin_id":"fixture","path":"../private","arguments":{"path":"../private"},"approval_digest":"not-authority","progressToken":1}}}),
        ];
        let input: Vec<u8> = frames
            .iter()
            .flat_map(|v| {
                let mut b = serde_json::to_vec(v).unwrap();
                b.push(b'\n');
                b
            })
            .collect();
        let mut calls = 0;
        let mut output = Vec::new();
        serve(std::io::Cursor::new(input), &mut output, |name, args| {
            calls += 1;
            assert_eq!(name, "read_file");
            assert_eq!(args, json!({"path":"public.txt"}));
            Ok(json!({"content":"public"}))
        })
        .unwrap();
        assert_eq!(calls, 1);
        let replies: Vec<Value> = output
            .split(|b| *b == b'\n')
            .filter(|b| !b.is_empty())
            .map(|b| serde_json::from_slice(b).unwrap())
            .collect();
        assert_eq!(replies.len(), 3);
        assert_eq!(replies[2]["result"]["isError"], false);
    }

    #[test]
    fn metadata_is_bounded_before_dispatch_and_is_never_an_extra_argument() {
        let mut deep = json!({});
        for _ in 0..12 {
            deep = json!({"next":deep});
        }
        for metadata in [
            Value::Null,
            json!("not-object"),
            json!({"long":"x".repeat(5000)}),
            json!({"a":"x".repeat(900),"b":"x".repeat(900),"c":"x".repeat(900),"d":"x".repeat(900),"e":"x".repeat(900)}),
            json!({"many":vec![0;129]}),
            deep,
        ] {
            let bytes = input(&[
                init("2025-06-18"),
                ready(),
                request(
                    2,
                    "tools/call",
                    json!({"name":"read_file","arguments":{"path":"public.txt"},"_meta":metadata}),
                ),
            ]);
            assert!(
                serve(Cursor::new(bytes), Vec::new(), |_, _| panic!(
                    "invalid metadata dispatched"
                ))
                .is_err()
            );
        }
        let bytes = input(&[
            init("2025-06-18"),
            ready(),
            request(
                2,
                "tools/call",
                json!({"name":"read_file","arguments":{"path":"public.txt","_meta":{}},"_meta":{"callId":"id"}}),
            ),
        ]);
        assert!(
            serve(Cursor::new(bytes), Vec::new(), |_, _| panic!(
                "extra argument dispatched"
            ))
            .is_err()
        );
    }
}
