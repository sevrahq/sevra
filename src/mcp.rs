//! `sevra mcp` — a stdio MCP server over the hub's read surface (the
//! supported secondary reach path; the CLI stays primary). An agent that
//! speaks MCP but cannot run a CLI — a chat app, a remote agent with no local
//! files — points its client at `{"command":"sevra","args":["mcp"]}` and
//! reaches the signed-in account's brains.
//!
//! A faithful port of the hub's MCP core: newline-delimited JSON-RPC 2.0 on
//! stdin/stdout; the same four read-only tools (list_brains / search_brain /
//! get_record / graph) over the same hub GET endpoints, with the same result
//! and isError shapes. The tool surface is deliberately TIGHT — a small
//! schema sidesteps MCP's tool-schema context bloat, the exact failure mode
//! the CLI-first policy guards against.
//!
//! stdout carries ONLY protocol frames: one compact JSON object per line,
//! flushed per message (stdout is block-buffered on a pipe and the client is
//! waiting on the reply). Every diagnostic goes to stderr. The hub client is
//! injected as a trait so the protocol core is testable without a network.

use std::io::{BufRead, Write};

use serde_json::{json, Map, Value};

use crate::commands::enc;
use crate::config::Config;
use crate::hub;
use crate::output::set_json_mode;

/// Latest protocol rev we author against; we echo the client's requested
/// version when it's one we recognize (standard MCP negotiation), else offer
/// this.
const PREFERRED_PROTOCOL: &str = "2025-06-18";
const KNOWN_PROTOCOLS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];
const SERVER_NAME: &str = "sevra-brain";

const INSTRUCTIONS: &str = "A Sevra brain over MCP: a db.md store (plain-file records + sources). \
     Prefer the `dbmd` CLI for local/write-heavy work; these tools are the read/reach surface. \
     Start with list_brains.";

/// One hub read-API answer. `body` is `Value::Null` when the response carried
/// no JSON.
struct HubGet {
    status: u16,
    body: Value,
}

/// The subset of the hub read API the tools need. Injected so the core is
/// testable without a network. `Err` means an internal failure (a bug), which
/// the shell surfaces as JSON-RPC -32603 — the real client never returns it:
/// transport trouble becomes a 502-shaped `Ok` the model can read.
trait McpHubClient {
    fn get(&self, path: &str) -> Result<HubGet, String>;
}

fn log(msg: &str) {
    eprintln!("sevra mcp: {msg}");
}

// --- tool definitions (the tight surface) ------------------------------------

fn tools() -> Value {
    json!([
        {
            "name": "list_brains",
            "description": "List the brains you can access (id, slug, name, scope). Call this first to get a brain id for the other tools.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
        },
        {
            "name": "search_brain",
            "description": "Search a brain's records and sources. Full-text `q` (ranked) and/or structured filters (type, layer, meta_type, tag). Returns a catalog of matches (path, title, summary) — retrieve full text with get_record.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "brain": { "type": "string", "description": "Brain id (ULID) or, if you own it, its slug." },
                    "q": { "type": "string", "description": "Full-text query over summary + title + body." },
                    "type": { "type": "string", "description": "Frontmatter `type` (e.g. client, meeting)." },
                    "layer": { "type": "string", "enum": ["source", "record"], "description": "sources (evidence) vs records (agent-authored)." },
                    "meta_type": { "type": "string", "enum": ["fact", "operational", "conclusion"], "description": "record meta-type." },
                    "tag": { "type": "string", "description": "A tag in the record's `tags` array." },
                    "limit": { "type": "number", "description": "Max results (1–200, default 20)." },
                },
                "required": ["brain"],
                "additionalProperties": false,
            },
        },
        {
            "name": "get_record",
            "description": "Fetch one record/source in full (frontmatter + body) by its db.md id or its store path. The @brain/id resolution.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "brain": { "type": "string", "description": "Brain id or slug." },
                    "id": { "type": "string", "description": "The db.md frontmatter id (stable across rename)." },
                    "path": { "type": "string", "description": "Store-relative path, e.g. records/clients/lumio.md." },
                },
                "required": ["brain"],
                "additionalProperties": false,
            },
        },
        {
            "name": "graph",
            "description": "The wiki-link neighborhood of a record: what it links to (outlinks) and what links to it (backlinks), each with the neighbor's title/summary and whether the link resolves.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "brain": { "type": "string", "description": "Brain id or slug." },
                    "path": { "type": "string", "description": "Store-relative path of the record." },
                    "dir": { "type": "string", "enum": ["in", "out", "both"], "description": "Direction (default both)." },
                },
                "required": ["brain", "path"],
                "additionalProperties": false,
            },
        },
    ])
}

// --- helpers -----------------------------------------------------------------

fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn err(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// A tool result: MCP wants tool-execution failures as isError results (so
/// the model sees them), not JSON-RPC errors. Content is a text block of the
/// JSON, pretty-printed for the model.
fn tool_result(data: &Value, is_error: bool) -> Value {
    json!({
        "content": [{ "type": "text", "text": serde_json::to_string_pretty(data).unwrap() }],
        "isError": is_error,
    })
}

/// A non-empty string argument (absent, non-string, and "" all read as None).
fn str_arg(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// Query string from ordered pairs, skipping absent/empty values. Returns ""
/// or "?k=v&…", both halves percent-encoded.
fn qs(pairs: &[(&str, Option<String>)]) -> String {
    let parts: Vec<String> = pairs
        .iter()
        .filter_map(|(k, v)| {
            v.as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| format!("{}={}", enc(k), enc(s)))
        })
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    }
}

// --- tool dispatch -----------------------------------------------------------

/// Dispatch one tool call to the hub API. Returns an MCP tool result — a hub
/// error becomes an isError result the model can read; `Err` is reserved for
/// an internal client failure (surfaced as -32603 by the shell).
fn call_tool(name: &str, args: &Value, client: &dyn McpHubClient) -> Result<Value, String> {
    let brain = str_arg(args.get("brain"));
    if name != "list_brains" && brain.is_none() {
        return Ok(tool_result(
            &json!({ "error": "`brain` is required" }),
            true,
        ));
    }
    let b = enc(brain.unwrap_or(""));
    let owned = |key: &str| str_arg(args.get(key)).map(String::from);

    let res = match name {
        "list_brains" => client.get("/api/hub/brains")?,
        "search_brain" => {
            // A non-number limit falls back to 20; Rust's f64 Display matches
            // JS String(n) for the honest cases (20 → "20", 2.5 → "2.5").
            let limit = args.get("limit").and_then(Value::as_f64).unwrap_or(20.0);
            client.get(&format!(
                "/api/hub/brains/{b}/query{}",
                qs(&[
                    ("q", owned("q")),
                    ("type", owned("type")),
                    ("layer", owned("layer")),
                    ("meta-type", owned("meta_type")),
                    ("tag", owned("tag")),
                    ("limit", Some(format!("{limit}"))),
                ])
            ))?
        }
        "get_record" => {
            let id = owned("id");
            let path = owned("path");
            if id.is_none() && path.is_none() {
                return Ok(tool_result(
                    &json!({ "error": "one of `id` or `path` is required" }),
                    true,
                ));
            }
            client.get(&format!(
                "/api/hub/brains/{b}/resolve{}",
                qs(&[("id", id), ("path", path)])
            ))?
        }
        "graph" => {
            let path = owned("path");
            if path.is_none() {
                return Ok(tool_result(&json!({ "error": "`path` is required" }), true));
            }
            client.get(&format!(
                "/api/hub/brains/{b}/graph{}",
                qs(&[("path", path), ("dir", owned("dir"))])
            ))?
        }
        _ => {
            return Ok(tool_result(
                &json!({ "error": format!("unknown tool: {name}") }),
                true,
            ))
        }
    };

    let is_error = res.status >= 400;
    let data = if is_error {
        // { status, ...body } — the hub's own error fields ride along.
        let mut merged = Map::new();
        merged.insert("status".into(), json!(res.status));
        if let Value::Object(body) = res.body {
            for (k, v) in body {
                merged.insert(k, v);
            }
        }
        Value::Object(merged)
    } else {
        res.body
    };
    Ok(tool_result(&data, is_error))
}

// --- JSON-RPC entry point ----------------------------------------------------

/// Handle one JSON-RPC message. `Ok(None)` = a notification (no id — e.g.
/// notifications/initialized), which gets no reply.
fn handle_mcp_request(msg: &Value, client: &dyn McpHubClient) -> Result<Option<Value>, String> {
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let is_notification = id.is_null();
    let params = msg.get("params");

    match msg.get("method").and_then(Value::as_str) {
        Some("initialize") => {
            let requested = str_arg(params.and_then(|p| p.get("protocolVersion")));
            let protocol_version = match requested {
                Some(v) if KNOWN_PROTOCOLS.contains(&v) => v,
                _ => PREFERRED_PROTOCOL,
            };
            Ok(Some(ok(
                id,
                json!({
                    "protocolVersion": protocol_version,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION") },
                    "instructions": INSTRUCTIONS,
                }),
            )))
        }
        Some("notifications/initialized") | Some("notifications/cancelled") => Ok(None),
        Some("ping") => Ok(Some(ok(id, json!({})))),
        Some("tools/list") => Ok(Some(ok(id, json!({ "tools": tools() })))),
        Some("tools/call") => {
            let Some(name) = str_arg(params.and_then(|p| p.get("name"))) else {
                return Ok(Some(err(id, -32602, "tools/call requires a tool name")));
            };
            let empty = json!({});
            let args = params.and_then(|p| p.get("arguments")).unwrap_or(&empty);
            let result = call_tool(name, args, client)?;
            Ok(Some(ok(id, result)))
        }
        _ => {
            // A notification we don't recognize: stay silent. A request:
            // method-not-found.
            if is_notification {
                return Ok(None);
            }
            let shown = match msg.get("method") {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Null) | None => "(none)".into(),
                Some(v) => v.to_string(),
            };
            Ok(Some(err(id, -32601, &format!("method not found: {shown}"))))
        }
    }
}

/// One stdin line → at most one response frame. Parse failures answer
/// -32700; an internal handler failure answers -32603 (requests only —
/// notifications stay silent even when handling them failed).
fn handle_line(line: &str, client: &dyn McpHubClient) -> Option<Value> {
    let Ok(msg) = serde_json::from_str::<Value>(line) else {
        return Some(err(Value::Null, -32700, "Parse error"));
    };
    match handle_mcp_request(&msg, client) {
        Ok(resp) => resp,
        Err(e) => {
            log(&format!("handler error: {e}"));
            let id = msg.get("id").cloned().unwrap_or(Value::Null);
            if id.is_null() {
                None
            } else {
                Some(err(id, -32603, "Internal error"))
            }
        }
    }
}

// --- the stdio shell ---------------------------------------------------------

/// The real client: every tool is a GET against the hub read API, bearer-
/// authed with the resolved credential (`config::load()`: SEVRA_API_KEY over
/// the stored login). No credential → unauthenticated, public brains only.
struct ApiClient<'a> {
    cfg: &'a Config,
}

impl McpHubClient for ApiClient<'_> {
    fn get(&self, path: &str) -> Result<HubGet, String> {
        match hub::try_request(self.cfg, "GET", path, None, self.cfg.key.is_some()) {
            Ok(r) => Ok(HubGet {
                status: r.status,
                body: r.body.unwrap_or(Value::Null),
            }),
            // Transport failure → a 502-shaped body the tool layer marks
            // isError, so the model sees it (never a process abort).
            Err(t) => Ok(HubGet {
                status: 502,
                body: json!({ "error": t }),
            }),
        }
    }
}

/// `sevra mcp`: serve until stdin closes. Exits 0 when the client hangs up.
pub fn serve(cfg: &Config) {
    // stdout is the protocol stream: the --json contract is meaningless here,
    // and any fail() (bad hub URL, malformed key) must land on stderr only.
    set_json_mode(false);
    // Fail fast at launch — a misconfigured hub or a corrupt key should show
    // up in the client's server log, not abort mid-session on the first call.
    hub::assert_safe_hub(&cfg.hub);
    match &cfg.key {
        Some(key) => {
            let _ = hub::clean_key(key);
        }
        None => log(
            "warning: not signed in — only public brains are reachable (run `sevra login`, or set SEVRA_API_KEY)",
        ),
    }
    log(&format!("ready (hub={})", cfg.hub));

    let client = ApiClient { cfg };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(resp) = handle_line(line, &client) {
            // One compact frame per line, flushed immediately: on a pipe,
            // stdout is block-buffered and the client is waiting on this
            // reply — an unflushed partial write would hang the session.
            if writeln!(out, "{resp}").and_then(|()| out.flush()).is_err() {
                break; // client closed the read end
            }
        }
    }
}

// --- tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// Canned-answer hub client, recording every path it was asked for.
    struct Mock {
        calls: RefCell<Vec<String>>,
        response: Result<(u16, Value), String>,
    }

    impl Mock {
        fn with(status: u16, body: Value) -> Self {
            Mock {
                calls: RefCell::new(Vec::new()),
                response: Ok((status, body)),
            }
        }
        fn failing(msg: &str) -> Self {
            Mock {
                calls: RefCell::new(Vec::new()),
                response: Err(msg.to_string()),
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl McpHubClient for Mock {
        fn get(&self, path: &str) -> Result<HubGet, String> {
            self.calls.borrow_mut().push(path.to_string());
            match &self.response {
                Ok((status, body)) => Ok(HubGet {
                    status: *status,
                    body: body.clone(),
                }),
                Err(e) => Err(e.clone()),
            }
        }
    }

    fn handle(msg: Value, client: &dyn McpHubClient) -> Option<Value> {
        handle_mcp_request(&msg, client).expect("no internal error")
    }

    /// The pretty-JSON text block of a tool result, parsed back to a Value.
    fn tool_text(resp: &Value) -> Value {
        let text = resp["result"]["content"][0]["text"]
            .as_str()
            .expect("a text content block");
        assert_eq!(resp["result"]["content"][0]["type"], "text");
        serde_json::from_str(text).expect("text is JSON")
    }

    #[test]
    fn initialize_echoes_a_known_protocol_version() {
        let mock = Mock::with(200, json!({}));
        let resp = handle(
            json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize",
                    "params": { "protocolVersion": "2025-03-26" } }),
            &mock,
        )
        .unwrap();
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 0);
        assert_eq!(resp["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(resp["result"]["serverInfo"]["name"], "sevra-brain");
        assert_eq!(
            resp["result"]["serverInfo"]["version"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(
            resp["result"]["capabilities"]["tools"]["listChanged"],
            false
        );
        assert!(resp["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("list_brains"));
        assert!(mock.calls().is_empty(), "initialize touches no network");
    }

    #[test]
    fn initialize_offers_the_preferred_protocol_when_unknown_or_absent() {
        let mock = Mock::with(200, json!({}));
        for params in [json!({ "protocolVersion": "1999-01-01" }), json!({})] {
            let resp = handle(
                json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params }),
                &mock,
            )
            .unwrap();
            assert_eq!(resp["result"]["protocolVersion"], "2025-06-18");
        }
    }

    #[test]
    fn notifications_get_no_reply() {
        let mock = Mock::with(200, json!({}));
        for method in ["notifications/initialized", "notifications/cancelled"] {
            assert!(handle(json!({ "jsonrpc": "2.0", "method": method }), &mock).is_none());
        }
        // An unrecognized notification (no id) stays silent too.
        assert!(handle(json!({ "jsonrpc": "2.0", "method": "wat" }), &mock).is_none());
    }

    #[test]
    fn ping_answers_empty_and_idless_requests_still_answer() {
        let mock = Mock::with(200, json!({}));
        let resp = handle(
            json!({ "jsonrpc": "2.0", "id": 3, "method": "ping" }),
            &mock,
        )
        .unwrap();
        assert_eq!(resp["result"], json!({}));
        // Core methods answer even without an id (the reply carries id null),
        // matching the reference: only unknown methods honor notification
        // silence.
        let resp = handle(json!({ "jsonrpc": "2.0", "method": "ping" }), &mock).unwrap();
        assert_eq!(resp["id"], Value::Null);
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let mock = Mock::with(200, json!({}));
        let resp = handle(
            json!({ "jsonrpc": "2.0", "id": 4, "method": "resources/list" }),
            &mock,
        )
        .unwrap();
        assert_eq!(resp["error"]["code"], -32601);
        assert_eq!(resp["error"]["message"], "method not found: resources/list");
    }

    #[test]
    fn tools_list_is_the_tight_read_surface() {
        let mock = Mock::with(200, json!({}));
        let resp = handle(
            json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/list" }),
            &mock,
        )
        .unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            ["list_brains", "search_brain", "get_record", "graph"]
        );
        for tool in tools {
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
            assert!(tool["description"].as_str().unwrap().len() > 20);
        }
        assert_eq!(tools[1]["inputSchema"]["required"], json!(["brain"]));
        assert_eq!(
            tools[3]["inputSchema"]["required"],
            json!(["brain", "path"])
        );
    }

    #[test]
    fn tools_call_requires_a_tool_name() {
        let mock = Mock::with(200, json!({}));
        let resp = handle(
            json!({ "jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {} }),
            &mock,
        )
        .unwrap();
        assert_eq!(resp["error"]["code"], -32602);
    }

    #[test]
    fn list_brains_happy_path() {
        let body = json!({ "brains": [{ "id": "01b", "slug": "work" }] });
        let mock = Mock::with(200, body.clone());
        let resp = handle(
            json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                    "params": { "name": "list_brains", "arguments": {} } }),
            &mock,
        )
        .unwrap();
        assert_eq!(mock.calls(), ["/api/hub/brains"]);
        assert_eq!(resp["result"]["isError"], false);
        assert_eq!(tool_text(&resp), body);
    }

    #[test]
    fn search_brain_builds_the_hub_query() {
        let mock = Mock::with(200, json!({ "results": [] }));
        handle(
            json!({ "jsonrpc": "2.0", "id": 8, "method": "tools/call",
                    "params": { "name": "search_brain", "arguments": {
                        "brain": "01abc", "q": "boiler contract", "type": "client",
                        "layer": "record", "meta_type": "fact", "tag": "x", "limit": 5 } } }),
            &mock,
        )
        .unwrap();
        assert_eq!(
            mock.calls(),
            ["/api/hub/brains/01abc/query?q=boiler%20contract&type=client&layer=record&meta-type=fact&tag=x&limit=5"]
        );
        // Absent filters are skipped; the limit defaults to 20.
        let mock = Mock::with(200, json!({ "results": [] }));
        handle(
            json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/call",
                    "params": { "name": "search_brain", "arguments": { "brain": "b" } } }),
            &mock,
        )
        .unwrap();
        assert_eq!(mock.calls(), ["/api/hub/brains/b/query?limit=20"]);
    }

    #[test]
    fn get_record_resolves_by_id_or_path_and_requires_one() {
        let mock = Mock::with(200, json!({ "document": {} }));
        handle(
            json!({ "jsonrpc": "2.0", "id": 10, "method": "tools/call",
                    "params": { "name": "get_record", "arguments": { "brain": "b", "id": "01x" } } }),
            &mock,
        )
        .unwrap();
        handle(
            json!({ "jsonrpc": "2.0", "id": 11, "method": "tools/call",
                    "params": { "name": "get_record",
                                "arguments": { "brain": "b", "path": "records/a.md" } } }),
            &mock,
        )
        .unwrap();
        assert_eq!(
            mock.calls(),
            [
                "/api/hub/brains/b/resolve?id=01x",
                "/api/hub/brains/b/resolve?path=records%2Fa.md"
            ]
        );
        // Neither id nor path: a tool-level isError, and no hub call.
        let mock = Mock::with(200, json!({}));
        let resp = handle(
            json!({ "jsonrpc": "2.0", "id": 12, "method": "tools/call",
                    "params": { "name": "get_record", "arguments": { "brain": "b" } } }),
            &mock,
        )
        .unwrap();
        assert_eq!(resp["result"]["isError"], true);
        assert_eq!(
            tool_text(&resp),
            json!({ "error": "one of `id` or `path` is required" })
        );
        assert!(mock.calls().is_empty());
    }

    #[test]
    fn graph_requires_a_path_and_carries_dir() {
        let mock = Mock::with(200, json!({ "backlinks": [], "outlinks": [] }));
        handle(
            json!({ "jsonrpc": "2.0", "id": 13, "method": "tools/call",
                    "params": { "name": "graph",
                                "arguments": { "brain": "b", "path": "records/a.md", "dir": "in" } } }),
            &mock,
        )
        .unwrap();
        assert_eq!(
            mock.calls(),
            ["/api/hub/brains/b/graph?path=records%2Fa.md&dir=in"]
        );
        let mock = Mock::with(200, json!({}));
        let resp = handle(
            json!({ "jsonrpc": "2.0", "id": 14, "method": "tools/call",
                    "params": { "name": "graph", "arguments": { "brain": "b" } } }),
            &mock,
        )
        .unwrap();
        assert_eq!(resp["result"]["isError"], true);
        assert_eq!(tool_text(&resp), json!({ "error": "`path` is required" }));
    }

    #[test]
    fn missing_brain_and_unknown_tool_are_tool_errors_not_rpc_errors() {
        let mock = Mock::with(200, json!({}));
        // Missing brain (and "" reads as missing).
        for args in [json!({}), json!({ "brain": "" })] {
            let resp = handle(
                json!({ "jsonrpc": "2.0", "id": 15, "method": "tools/call",
                        "params": { "name": "search_brain", "arguments": args } }),
                &mock,
            )
            .unwrap();
            assert!(resp["error"].is_null(), "a tool error, not a JSON-RPC one");
            assert_eq!(resp["result"]["isError"], true);
            assert_eq!(tool_text(&resp), json!({ "error": "`brain` is required" }));
        }
        // Unknown tool. (The brain check runs first, as in the reference: an
        // unknown tool WITHOUT a brain reads as "`brain` is required".)
        let resp = handle(
            json!({ "jsonrpc": "2.0", "id": 16, "method": "tools/call",
                    "params": { "name": "drop_table", "arguments": { "brain": "b" } } }),
            &mock,
        )
        .unwrap();
        assert_eq!(resp["result"]["isError"], true);
        assert_eq!(
            tool_text(&resp),
            json!({ "error": "unknown tool: drop_table" })
        );
        assert!(mock.calls().is_empty(), "nothing reached the hub");
    }

    #[test]
    fn hub_errors_become_is_error_results_with_the_status() {
        let mock = Mock::with(404, json!({ "error": "brain not found" }));
        let resp = handle(
            json!({ "jsonrpc": "2.0", "id": 17, "method": "tools/call",
                    "params": { "name": "list_brains", "arguments": {} } }),
            &mock,
        )
        .unwrap();
        assert_eq!(resp["result"]["isError"], true);
        assert_eq!(
            tool_text(&resp),
            json!({ "status": 404, "error": "brain not found" })
        );
    }

    #[test]
    fn brain_references_are_url_encoded_into_the_path() {
        let mock = Mock::with(200, json!({}));
        handle(
            json!({ "jsonrpc": "2.0", "id": 18, "method": "tools/call",
                    "params": { "name": "search_brain", "arguments": { "brain": "a/b c" } } }),
            &mock,
        )
        .unwrap();
        assert!(mock.calls()[0].starts_with("/api/hub/brains/a%2Fb%20c/query"));
    }

    #[test]
    fn parse_errors_answer_32700_with_a_null_id() {
        let mock = Mock::with(200, json!({}));
        let resp = handle_line("{not json", &mock).unwrap();
        assert_eq!(resp["error"]["code"], -32700);
        assert_eq!(resp["error"]["message"], "Parse error");
        assert_eq!(resp["id"], Value::Null);
    }

    #[test]
    fn internal_errors_answer_32603_for_requests_and_silence_for_notifications() {
        let mock = Mock::failing("boom");
        let line = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"list_brains","arguments":{}}}"#;
        let resp = handle_line(line, &mock).unwrap();
        assert_eq!(resp["error"]["code"], -32603);
        assert_eq!(resp["error"]["message"], "Internal error");
        assert_eq!(resp["id"], 9);
        // The same failure on an id-less message writes nothing.
        let line = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_brains","arguments":{}}}"#;
        assert!(handle_line(line, &mock).is_none());
    }
}
