// SPDX-License-Identifier: Apache-2.0

//! Spike WP3.0b: what does a byte-exact passthrough proxy cost on hyper 1 + tokio?
//!
//! Three local actors on 127.0.0.1:
//! * a **mock provider** that reads the whole request and streams an Anthropic-style SSE
//!   response (200 `content_block_delta` events, about 30 KB) frame by frame;
//! * a **passthrough proxy**, the shape ADR-0013 proposes: collect the request body under a
//!   size limit (codecs need the original bytes), forward through a pooled hyper client with
//!   hop-by-hop headers removed, and relay the response body frame by frame without buffering;
//! * a **client** sending POSTs with a 1.7 MB JSON body (about a 400k-token history), either
//!   straight to the provider or through the proxy, measuring time to first byte (TTFB) and to
//!   the last byte.
//!
//! Overhead = proxy quantile - direct quantile. Budget under test (plan v2 §10.2 item 4):
//! passthrough p95 <= 12.5 ms, half of the 25 ms local-overhead SLO.
//!
//! Run: `cargo run --release` inside `spikes/passthrough`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::HOST;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Body = BoxBody<Bytes, BoxError>;
type HttpClient = Client<HttpConnector, Full<Bytes>>;

const BODY_BYTES: usize = 1_700_000;
const SSE_EVENTS: usize = 200;
const MAX_REQUEST: usize = 32 * 1024 * 1024;
const WARMUP: usize = 30;
const SEQUENTIAL: usize = 400;
const CONCURRENCY: usize = 8;
const PER_TASK: usize = 60;

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "content-length",
];

fn client() -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    Client::builder(TokioExecutor::new()).build(connector)
}

async fn listen() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    (listener, addr)
}

fn spawn_server<F, Fut>(listener: TcpListener, handler: F)
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<Response<Body>, Infallible>> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { continue };
            let _ = stream.set_nodelay(true);
            let handler = handler.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| handler(req));
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
}

/// The mock provider: read the request, then stream SSE frames.
async fn provider(req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
    let _request = req.into_body().collect().await.map(|c| c.to_bytes().len());
    let frames = (0..SSE_EVENTS).map(|i| {
        let event = format!(
            "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"token {i} of the reply \"}}}}\n\n"
        );
        Ok::<_, BoxError>(Frame::data(Bytes::from(event)))
    });
    let body = StreamBody::new(futures_util::stream::iter(frames));
    Ok(Response::builder()
        .header("content-type", "text/event-stream")
        .body(BodyExt::boxed(body))
        .expect("response"))
}

/// The passthrough proxy (ADR-0013 shape).
async fn proxy(req: Request<Incoming>, client: HttpClient, upstream: SocketAddr) -> Result<Response<Body>, Infallible> {
    let (parts, body) = req.into_parts();
    let bytes = match Limited::new(body, MAX_REQUEST).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Ok(Response::builder()
                .status(413)
                .body(BodyExt::boxed(Full::new(Bytes::new()).map_err(|never| match never {})))
                .expect("413"));
        }
    };
    let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let mut out = Request::builder()
        .method(parts.method)
        .uri(format!("http://{upstream}{path}"));
    for (name, value) in &parts.headers {
        if name != HOST && !HOP_BY_HOP.contains(&name.as_str()) {
            out = out.header(name, value);
        }
    }
    let upstream_response = client.request(out.body(Full::new(bytes)).expect("request")).await;
    match upstream_response {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            Ok(Response::from_parts(parts, body.map_err(|e| Box::new(e) as BoxError).boxed()))
        }
        Err(_) => Ok(Response::builder()
            .status(502)
            .body(BodyExt::boxed(Full::new(Bytes::new()).map_err(|never| match never {})))
            .expect("502")),
    }
}

fn request_body() -> Bytes {
    // A long chat history: ~1.7 MB of JSON, roughly 400k tokens.
    let mut out = String::from("{\"model\":\"m\",\"max_tokens\":4096,\"stream\":true,\"messages\":[");
    let mut n = 0usize;
    while out.len() < BODY_BYTES {
        if n > 0 {
            out.push(',');
        }
        let role = if n % 2 == 0 { "user" } else { "assistant" };
        out.push_str(&format!(
            "{{\"role\":\"{role}\",\"content\":\"message {n}: {}\"}}",
            "lorem ipsum dolor sit amet ".repeat(30)
        ));
        n += 1;
    }
    out.push_str("]}");
    Bytes::from(out)
}

#[derive(Clone, Copy)]
struct Sample {
    ttfb: Duration,
    total: Duration,
}

async fn one(client: &HttpClient, target: SocketAddr, body: Bytes) -> Sample {
    let request = Request::builder()
        .method("POST")
        .uri(format!("http://{target}/v1/messages?beta=true"))
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .header("anthropic-beta", "interleaved-thinking-2025-05-14")
        .header("x-claude-code-session-id", "spike")
        .body(Full::new(body))
        .expect("request");
    let start = Instant::now();
    let response = client.request(request).await.expect("response");
    let mut body = response.into_body();
    let mut ttfb = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.expect("frame");
        if frame.is_data() && ttfb.is_none() {
            ttfb = Some(start.elapsed());
        }
    }
    Sample {
        ttfb: ttfb.unwrap_or_else(|| start.elapsed()),
        total: start.elapsed(),
    }
}

fn quantile(sorted: &[Duration], permille: usize) -> Duration {
    let rank = (sorted.len() * permille).div_ceil(1000).saturating_sub(1);
    sorted.get(rank).copied().unwrap_or_default()
}

fn ms(d: Duration) -> String {
    format!("{:.2} ms", d.as_secs_f64() * 1000.0)
}

fn report(scenario: &str, direct: &[Sample], proxied: &[Sample]) {
    println!("\n#### {scenario}\n");
    println!("| measure | direct p50 | direct p95 | direct p99 | proxy p50 | proxy p95 | proxy p99 | overhead p50 | overhead p95 | overhead p99 |");
    println!("|---|---|---|---|---|---|---|---|---|---|");
    for (name, pick) in [("TTFB", (|s: &Sample| s.ttfb) as fn(&Sample) -> Duration), ("last byte", |s: &Sample| s.total)] {
        let mut d: Vec<Duration> = direct.iter().map(pick).collect();
        let mut p: Vec<Duration> = proxied.iter().map(pick).collect();
        d.sort();
        p.sort();
        let q = |v: &[Duration], m| quantile(v, m);
        let over = |m| q(&p, m).saturating_sub(q(&d, m));
        println!(
            "| {name} | {} | {} | {} | {} | {} | {} | **{}** | **{}** | **{}** |",
            ms(q(&d, 500)),
            ms(q(&d, 950)),
            ms(q(&d, 990)),
            ms(q(&p, 500)),
            ms(q(&p, 950)),
            ms(q(&p, 990)),
            ms(over(500)),
            ms(over(950)),
            ms(over(990)),
        );
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let (provider_listener, provider_addr) = listen().await;
    spawn_server(provider_listener, provider);
    let (proxy_listener, proxy_addr) = listen().await;
    let upstream_client = client();
    spawn_server(proxy_listener, move |req| proxy(req, upstream_client.clone(), provider_addr));

    let body = request_body();
    let c = client();
    println!(
        "### Passthrough spike ({} / {}), request body {} bytes, {SSE_EVENTS} SSE events",
        std::env::consts::OS,
        std::env::consts::ARCH,
        body.len()
    );
    for _ in 0..WARMUP {
        one(&c, provider_addr, body.clone()).await;
        one(&c, proxy_addr, body.clone()).await;
    }

    let (mut direct, mut proxied) = (Vec::new(), Vec::new());
    for _ in 0..SEQUENTIAL {
        direct.push(one(&c, provider_addr, body.clone()).await);
        proxied.push(one(&c, proxy_addr, body.clone()).await);
    }
    report(&format!("sequential, n = {SEQUENTIAL} each, interleaved"), &direct, &proxied);

    let mut runs = Vec::new();
    for target in [provider_addr, proxy_addr] {
        let mut tasks = Vec::new();
        for _ in 0..CONCURRENCY {
            let c = c.clone();
            let body = body.clone();
            tasks.push(tokio::spawn(async move {
                let mut out = Vec::new();
                for _ in 0..PER_TASK {
                    out.push(one(&c, target, body.clone()).await);
                }
                out
            }));
        }
        let mut all = Vec::new();
        for t in tasks {
            all.extend(t.await.expect("task"));
        }
        runs.push(all);
    }
    report(
        &format!("{CONCURRENCY} concurrent clients (parallel subagents), n = {} each", CONCURRENCY * PER_TASK),
        &runs[0],
        &runs[1],
    );
}
