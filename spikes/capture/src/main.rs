// SPDX-License-Identifier: Apache-2.0

//! Spike WP3.0a: a local logging proxy for gateway facts.
//!
//! Usage: `spike-capture <upstream-base-url> <log.jsonl>`. It prints
//! `listening http://127.0.0.1:<port>` and forwards every request to the upstream unchanged.
//!
//! What it records is **structure only**, so that no prompt text or credential ends up in the
//! log:
//! * method, path and query;
//! * header names and values, with credentials (`authorization`, `x-api-key`, cookies) replaced
//!   by their length and scheme;
//! * a JSON skeleton of the body: keys, types, lengths and array sizes. Only short, structural
//!   values are kept verbatim (model, type, role, tool names, `cache_control`, thinking config),
//!   plus the first 48 characters of `system[0].text` (the attribution block, plan v2 §2.5);
//! * the response status and headers, and per-type counts of SSE events;
//! * for error responses, the error type and the first 160 characters of the message.

use std::convert::Infallible;
use std::io::Write as _;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures_util::StreamExt as _;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{Map, Value, json};
use tokio::net::TcpListener;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Body = BoxBody<Bytes, BoxError>;

const SECRET_HEADERS: &[&str] = &["authorization", "x-api-key", "cookie", "set-cookie", "proxy-authorization"];
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "host",
    "content-length",
];
/// Keys whose short string values are structural and kept verbatim.
const KEEP_VALUES: &[&str] = &[
    "model", "type", "role", "name", "stop_reason", "tool_choice", "budget_tokens", "effort", "ttl", "stream",
    "max_tokens", "store", "id_prefix",
];

#[derive(Clone)]
struct Ctx {
    upstream: String,
    client: reqwest::Client,
    log: Arc<Mutex<std::fs::File>>,
}

impl Ctx {
    fn log(&self, entry: Value) {
        if let Ok(mut f) = self.log.lock() {
            let _ = writeln!(f, "{entry}");
        }
    }
}

fn headers(map: &HeaderMap) -> Value {
    let mut out = Map::new();
    for (name, value) in map {
        let n = name.as_str().to_ascii_lowercase();
        let v = value.to_str().unwrap_or("<non-utf8>");
        let shown = if SECRET_HEADERS.contains(&n.as_str()) {
            let scheme = v.split_whitespace().next().filter(|_| v.contains(' ')).unwrap_or("");
            format!("<redacted len={} scheme={scheme}>", v.len())
        } else {
            v.to_owned()
        };
        match out.get_mut(&n) {
            Some(Value::Array(list)) => list.push(Value::String(shown)),
            Some(existing) => {
                let first = existing.take();
                *existing = Value::Array(vec![first, Value::String(shown)]);
            }
            None => {
                out.insert(n, Value::String(shown));
            }
        }
    }
    Value::Object(out)
}

/// A structural skeleton of a JSON value: never free text.
fn skeleton(value: &Value, key: &str, path: &str) -> Value {
    match value {
        Value::Null => json!("null"),
        Value::Bool(b) => json!(b),
        Value::Number(n) => {
            if KEEP_VALUES.contains(&key) {
                json!(n)
            } else {
                json!("num")
            }
        }
        Value::String(s) => {
            if path == "system/0/text" {
                json!({ "str_len": s.len(), "prefix": s.chars().take(48).collect::<String>() })
            } else if KEEP_VALUES.contains(&key) && s.len() <= 80 {
                json!(s)
            } else {
                json!({ "str_len": s.len() })
            }
        }
        Value::Array(items) => {
            let mut out = Map::new();
            out.insert("arr_len".into(), json!(items.len()));
            if let Some(first) = items.first() {
                out.insert("first".into(), skeleton(first, key, &format!("{path}/0")));
            }
            if items.len() > 1 {
                if let Some(last) = items.last() {
                    out.insert("last".into(), skeleton(last, key, &format!("{path}/{}", items.len() - 1)));
                }
                // Item kinds across the whole array (roles and block types).
                let kinds: Vec<String> = items
                    .iter()
                    .map(|i| {
                        i.get("role")
                            .or_else(|| i.get("type"))
                            .and_then(Value::as_str)
                            .unwrap_or("?")
                            .to_owned()
                    })
                    .collect();
                out.insert("kinds".into(), json!(kinds));
            }
            Value::Object(out)
        }
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                let child = if key == "metadata" {
                    // Metadata values may identify the user; keep only their shape.
                    json!({ "str_len": v.as_str().map_or(0, str::len) })
                } else {
                    skeleton(v, k, &format!("{path}/{k}"))
                };
                out.insert(k.clone(), child);
            }
            Value::Object(out)
        }
    }
}

fn body_skeleton(bytes: &[u8]) -> Value {
    if bytes.is_empty() {
        return json!("empty");
    }
    match serde_json::from_slice::<Value>(bytes) {
        Ok(v) => skeleton(&v, "", ""),
        Err(_) => json!({ "non_json_len": bytes.len() }),
    }
}

fn plain(status: u16, text: &'static str) -> Response<Body> {
    let mut r = Response::new(BodyExt::boxed(
        Full::new(Bytes::from_static(text.as_bytes())).map_err(|never| match never {}),
    ));
    *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::BAD_GATEWAY);
    r
}

async fn handle(req: Request<Incoming>, ctx: Ctx) -> Result<Response<Body>, Infallible> {
    let (parts, body) = req.into_parts();
    let bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return Ok(plain(400, "bad request body")),
    };
    let path = parts.uri.path().to_owned();
    let query = parts.uri.query().unwrap_or("").to_owned();
    ctx.log(json!({
        "dir": "request",
        "method": parts.method.as_str(),
        "path": path,
        "query": query,
        "headers": headers(&parts.headers),
        "body": body_skeleton(&bytes),
    }));

    let url = format!(
        "{}{}",
        ctx.upstream,
        parts.uri.path_and_query().map_or("/", |p| p.as_str())
    );
    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut out = ctx.client.request(method, url);
    for (name, value) in &parts.headers {
        if !HOP_BY_HOP.contains(&name.as_str()) {
            out = out.header(name.as_str(), value.as_bytes());
        }
    }
    let response = match out.body(bytes).send().await {
        Ok(r) => r,
        Err(e) => {
            ctx.log(json!({ "dir": "error", "path": path, "upstream_error": e.to_string() }));
            return Ok(plain(502, "upstream unreachable"));
        }
    };
    let status = response.status().as_u16();
    let mut resp_headers = HeaderMap::new();
    for (name, value) in response.headers() {
        if let (Ok(n), Ok(v)) = (
            hyper::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            hyper::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            resp_headers.append(n, v);
        }
    }
    let is_sse = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/event-stream"));
    ctx.log(json!({ "dir": "response", "path": path, "status": status, "headers": headers(&resp_headers) }));

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, BoxError>>(64);
    let pump_ctx = ctx.clone();
    tokio::spawn(async move {
        let mut stream = response.bytes_stream();
        let mut events: Map<String, Value> = Map::new();
        let mut order: Vec<String> = Vec::new();
        let mut collected = Vec::new();
        let mut line_buf = String::new();
        while let Some(chunk) = stream.next().await {
            let Ok(chunk) = chunk else {
                pump_ctx.log(json!({ "dir": "stream_error", "path": path }));
                break;
            };
            if is_sse {
                line_buf.push_str(&String::from_utf8_lossy(&chunk));
                while let Some(nl) = line_buf.find('\n') {
                    let line: String = line_buf.drain(..=nl).collect();
                    if let Some(name) = line.strip_prefix("event:") {
                        let name = name.trim().to_owned();
                        if !events.contains_key(&name) {
                            order.push(name.clone());
                        }
                        let n = events.get(&name).and_then(Value::as_u64).unwrap_or(0) + 1;
                        events.insert(name, json!(n));
                    }
                }
            } else if status >= 400 && collected.len() < 64 * 1024 {
                collected.extend_from_slice(&chunk);
            }
            if tx.send(Ok(Frame::data(chunk))).await.is_err() {
                break;
            }
        }
        let mut summary = json!({ "dir": "response_end", "path": path, "sse_events": events, "sse_order": order });
        if !collected.is_empty() {
            if let Ok(v) = serde_json::from_slice::<Value>(&collected) {
                summary["error_type"] = v.pointer("/error/type").cloned().unwrap_or(Value::Null);
                summary["error_message_prefix"] = json!(
                    v.pointer("/error/message")
                        .and_then(Value::as_str)
                        .map(|m| m.chars().take(160).collect::<String>())
                );
            }
        }
        pump_ctx.log(summary);
    });
    let stream = futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|item| (item, rx)) });
    let mut builder = Response::builder().status(status);
    for (name, value) in &resp_headers {
        if !HOP_BY_HOP.contains(&name.as_str()) {
            builder = builder.header(name, value);
        }
    }
    Ok(builder
        .body(BodyExt::boxed(StreamBody::new(stream)))
        .unwrap_or_else(|_| plain(502, "bad upstream response")))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(upstream), Some(log_path)) = (args.first(), args.get(1)) else {
        eprintln!("usage: spike-capture <upstream-base-url> <log.jsonl>");
        std::process::exit(2);
    };
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .expect("open log");
    let ctx = Ctx {
        upstream: upstream.trim_end_matches('/').to_owned(),
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client"),
        log: Arc::new(Mutex::new(log)),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    println!("listening http://{}", listener.local_addr().expect("addr"));
    let _ = std::io::stdout().flush();
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| handle(req, ctx.clone()));
            let _ = http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
        });
    }
}
