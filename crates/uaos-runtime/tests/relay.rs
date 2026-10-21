// SPDX-License-Identifier: Apache-2.0

//! The relay (runtime contract §7): byte-exact forwarding for any chunking, metering against the
//! reservation, and every way a stream is cut.
//!
//! The streams are synthetic, shaped like the Anthropic Messages stream and the `OpenAI` Responses
//! and chat streams. The codec here is a test codec; the dialect codecs are M2's.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;
use http::header::{CONTENT_ENCODING, HeaderValue};
use http_body_util::BodyExt as _;
use hyper::body::{Body, Frame};
use proptest::prelude::*;
use tokio::sync::mpsc;
use uaos_contracts::event::Actor;
use uaos_contracts::id::{PoolId, ReservationId, TypedId};
use uaos_contracts::money::NanoUsd;
use uaos_ledger::{InFlight, Ledger, MemorySink, Reservation};
use uaos_module_api::{
    Code, CodecError, DialectCodec, EndpointDecl, FrameKind, RoleMap, SseEvent, StructuralView, UsageReport, ViewNode,
    ViewText,
};
use uaos_runtime::{CutReason, DeclaredPrice, Relay, RelayEnd, RelayError, RelayLimits, RelayReport, Stop, StopReason};

/// 50 input tokens at 100 and 100 output tokens at 1,000 nano-USD: exactly the reservation.
const CEILING: i64 = 105_000;

/// A test codec: the Anthropic and `OpenAI` frame names, usage under `usage`, `message.usage` or
/// `response.usage`. It records every event it is shown.
#[derive(Debug)]
struct Dialect {
    dims: Vec<Code>,
    seen: Mutex<Vec<(Option<String>, Vec<u8>)>>,
    /// Report a dimension it does not declare.
    rogue: bool,
    /// Classify every event as content (no metering).
    content_only: bool,
}

impl Dialect {
    fn new() -> Self {
        Self {
            dims: vec![code("input_tokens"), code("output_tokens")],
            seen: Mutex::new(Vec::new()),
            rogue: false,
            content_only: false,
        }
    }

    fn seen(&self) -> Vec<(Option<String>, Vec<u8>)> {
        self.seen.lock().unwrap().clone()
    }
}

fn code(s: &str) -> Code {
    Code::new(s).unwrap()
}

fn usage_node<'v, 'a>(root: ViewNode<'v, 'a>) -> Option<ViewNode<'v, 'a>> {
    if let Some(usage) = root.member("usage").ok()? {
        return Some(usage);
    }
    for wrapper in ["message", "response"] {
        if let Some(inner) = root.member(wrapper).ok()?
            && let Some(usage) = inner.member("usage").ok()?
        {
            return Some(usage);
        }
    }
    None
}

fn count(node: ViewNode<'_, '_>, key: &str) -> Option<u64> {
    match node.member(key).ok()??.number_text()? {
        ViewText::Plain(text) => text.parse().ok(),
        ViewText::Masked => None,
    }
}

impl DialectCodec for Dialect {
    fn endpoints(&self) -> &[EndpointDecl] {
        &[]
    }

    fn dimensions(&self) -> &[Code] {
        &self.dims
    }

    fn roles(&self, _view: &StructuralView<'_, '_>, _out: &mut RoleMap) -> Result<(), CodecError> {
        Ok(())
    }

    fn frame(&self, event: &SseEvent<'_>) -> FrameKind {
        self.seen
            .lock()
            .unwrap()
            .push((event.event.map(str::to_owned), event.data.to_vec()));
        if self.content_only {
            return FrameKind::Content;
        }
        match event.event {
            Some("message_start" | "message_delta" | "response.completed") => FrameKind::Usage,
            Some("ping") => FrameKind::Ping,
            Some("message_stop") => FrameKind::End,
            Some("error") => FrameKind::Error,
            None if event.data == b"[DONE]" => FrameKind::End,
            None if event.data.windows(7).any(|w| w == b"\"usage\"") => FrameKind::Usage,
            Some(_) | None => FrameKind::Content,
        }
    }

    fn usage(&self, view: &StructuralView<'_, '_>) -> Option<UsageReport> {
        let node = usage_node(view.root())?;
        let mut report = UsageReport::new();
        for (key, dim) in [("input_tokens", "input_tokens"), ("output_tokens", "output_tokens")] {
            if let Some(n) = count(node, key) {
                report = report.dim(code(dim), n).ok()?;
            }
        }
        if self.rogue {
            report = report.dim(code("cache_tokens"), 1).ok()?;
        }
        (!report.dims().is_empty()).then_some(report)
    }
}

/// An upstream body fed through a bounded channel; it records being dropped.
struct Upstream {
    rx: mpsc::Receiver<Result<Bytes, io::Error>>,
    dropped: Arc<AtomicBool>,
}

impl Body for Upstream {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        self.rx.poll_recv(cx).map(|item| item.map(|r| r.map(Frame::data)))
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

/// What a test sends the upstream after the start.
type Feed = mpsc::Sender<Result<Bytes, io::Error>>;

/// An upstream that sends `chunks`, then ends unless `keep_open`.
fn upstream(chunks: &[&[u8]], keep_open: bool) -> (Upstream, Arc<AtomicBool>, Option<Feed>) {
    // Room for what a test sends after the start, such as an upstream error.
    let (tx, rx) = mpsc::channel(chunks.len() + 4);
    for chunk in chunks {
        tx.try_send(Ok(Bytes::copy_from_slice(chunk))).unwrap();
    }
    let dropped = Arc::new(AtomicBool::new(false));
    let body = Upstream {
        rx,
        dropped: Arc::clone(&dropped),
    };
    (body, dropped, keep_open.then_some(tx))
}

fn reservation(amount: i64) -> Reservation<InFlight> {
    let mut ledger = Ledger::default();
    let mut sink = MemorySink::default();
    let pool = PoolId::from_parts(1, [1; 10]);
    ledger
        .allocate(
            &mut sink,
            pool,
            NanoUsd::new(amount.saturating_mul(10)),
            &Actor::System,
            uaos_contracts::budget::IdempotencyKey::new("fund").unwrap(),
        )
        .unwrap();
    ledger
        .reserve(
            &mut sink,
            pool,
            ReservationId::from_parts(1, [2; 10]),
            NanoUsd::new(amount),
            &Actor::System,
        )
        .unwrap()
        .begin()
}

fn price() -> Arc<DeclaredPrice> {
    Arc::new(
        DeclaredPrice::new([
            (code("input_tokens"), NanoUsd::new(100)),
            (code("output_tokens"), NanoUsd::new(1_000)),
        ])
        .unwrap(),
    )
}

fn relay(codec: &Arc<Dialect>, stop: &Stop, limits: RelayLimits) -> Relay {
    let codec: Arc<dyn DialectCodec> = codec.clone();
    Relay::new(codec, price(), &reservation(CEILING), stop.clone(), limits)
}

/// Everything the client receives, and the error the body ended in, if any.
async fn drain<B>(body: &mut B) -> (Vec<u8>, Option<RelayError>)
where
    B: Body<Data = Bytes, Error = RelayError> + Unpin,
{
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    out.extend_from_slice(&data);
                }
            }
            Err(error) => return (out, Some(error)),
        }
    }
    (out, None)
}

async fn report(rx: tokio::sync::oneshot::Receiver<RelayReport>) -> RelayReport {
    tokio::time::timeout(Duration::from_secs(5), rx).await.unwrap().unwrap()
}

const START: &[u8] = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":50,\"output_tokens\":1}}}\n\n";
const DELTA: &[u8] = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"\u{130}stanbul'da \u{131}l\u{131}k bir g\u{fc}n\"}}\n\n".as_bytes();
const PING: &[u8] = b"event: ping\ndata: {\"type\":\"ping\"}\n\n";
const DELTA_100: &[u8] = b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":100}}\n\n";
const DELTA_101: &[u8] = b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":101}}\n\n";
const STOP: &[u8] = b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

// ── Within budget ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_stream_within_its_reservation_is_relayed_byte_for_byte() {
    let codec = Arc::new(Dialect::new());
    let stop = Stop::running();
    let parts = [START, DELTA, PING, DELTA_100, STOP];
    let (up, _dropped, _) = upstream(&parts, false);
    let (mut body, rx) = relay(&codec, &stop, RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert_eq!(error, None);
    assert_eq!(out, concat(&parts), "the relay changed the stream's bytes");
    let report = report(rx).await;
    assert_eq!(report.end, RelayEnd::Completed);
    assert_eq!(report.forwarded_bytes, u64::try_from(out.len()).unwrap());
    assert_eq!(report.segments, 5);
    assert_eq!(
        report.usage,
        vec![(code("input_tokens"), 50), (code("output_tokens"), 100)]
    );
    assert_eq!(
        report.cost,
        Some(NanoUsd::new(CEILING)),
        "a cost equal to the ceiling is within budget"
    );
    assert!(!stop.is_engaged());
}

#[tokio::test]
async fn openai_shaped_streams_are_relayed_and_metered() {
    let responses: [&[u8]; 3] = [
        b"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"r1\"}}\n\n",
        "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"\u{c7}a a \u{e9}t\u{e9}\"}\n\n".as_bytes(),
        b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\",\"usage\":{\"input_tokens\":50,\"output_tokens\":100}}}\n\n",
    ];
    let chat: [&[u8]; 3] = [
        "data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"Stra\u{df}e\"}}]}\n\n".as_bytes(),
        b"data: {\"id\":\"c1\",\"choices\":[],\"usage\":{\"input_tokens\":50,\"output_tokens\":100}}\n\n",
        b"data: [DONE]\n\n",
    ];
    for parts in [&responses[..], &chat[..]] {
        let codec = Arc::new(Dialect::new());
        let (up, _, _) = upstream(parts, false);
        let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
            .sse(up, &HeaderMap::new())
            .unwrap();
        let (out, error) = drain(&mut body).await;
        assert_eq!((out, error), (concat(parts), None));
        assert_eq!(report(rx).await.cost, Some(NanoUsd::new(CEILING)));
    }
}

// ── Over budget ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn one_unit_over_the_ceiling_is_never_forwarded() {
    let codec = Arc::new(Dialect::new());
    let stop = Stop::running();
    let (up, _dropped, _) = upstream(&[START, DELTA, DELTA_101, STOP], false);
    let (mut body, rx) = relay(&codec, &stop, RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert!(
        !out.windows(19).any(|w| w == b"\"output_tokens\":101"),
        "a usage report over the ceiling was forwarded"
    );
    assert_eq!(
        out,
        concat(&[START, DELTA]),
        "a usage report over the ceiling was forwarded"
    );
    assert_eq!(error, Some(RelayError::Cut(CutReason::BudgetOverrun)));
    let report = report(rx).await;
    assert_eq!(report.end, RelayEnd::Cut(CutReason::BudgetOverrun));
    assert_eq!(report.cost, Some(NanoUsd::new(CEILING + 1_000)));
    assert_eq!(
        report.usage,
        vec![(code("input_tokens"), 50), (code("output_tokens"), 101)]
    );
}

#[tokio::test]
async fn an_overrun_stops_the_kernel() {
    let codec = Arc::new(Dialect::new());
    let stop = Stop::running();
    let (up, _, _) = upstream(&[START, DELTA_101], false);
    let (mut body, _rx) = relay(&codec, &stop, RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let _drained = drain(&mut body).await;
    assert_eq!(
        stop.reason(),
        Some(StopReason::BudgetOverrun),
        "an overrun left the kernel running"
    );
    assert_eq!(stop.unrecorded().map(|e| e.reason()), Some(StopReason::BudgetOverrun));
}

#[tokio::test]
async fn a_trailing_event_without_a_blank_line_is_metered_too() {
    let codec = Arc::new(Dialect::new());
    let tail = &DELTA_101[..DELTA_101.len() - 2];
    let (up, _, _) = upstream(&[START, tail], false);
    let (mut body, _rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert_eq!(out, START.to_vec());
    assert_eq!(error, Some(RelayError::Cut(CutReason::BudgetOverrun)));
}

#[tokio::test]
async fn a_cut_drops_the_upstream_at_once() {
    let codec = Arc::new(Dialect::new());
    let (up, dropped, _keep) = upstream(&[START, DELTA_101], true);
    let (mut body, _rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let first = body.frame().await.unwrap().unwrap();
    assert_eq!(first.into_data().unwrap(), Bytes::from_static(START));
    assert!(!dropped.load(Ordering::SeqCst));
    let cut = body.frame().await.unwrap();
    assert!(cut.is_err());
    assert!(dropped.load(Ordering::SeqCst), "a cut kept the upstream");
}

#[tokio::test]
async fn a_cut_without_a_terminal_frame_ends_in_an_error() {
    let codec = Arc::new(Dialect::new());
    let (up, _, _) = upstream(&[START, DELTA_101], false);
    let (mut body, _rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (_, error) = drain(&mut body).await;
    assert!(error.is_some(), "a cut ended cleanly, as if the answer were complete");
    assert!(body.is_end_stream());
}

#[tokio::test]
async fn a_cut_with_a_terminal_frame_ends_with_it() {
    let codec = Arc::new(Dialect::new());
    let terminal =
        Bytes::from_static(b"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"uaos_cut\"}}\n\n");
    let (up, _, _) = upstream(&[START, DELTA_101], false);
    let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .terminal(terminal.clone())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert_eq!(error, None);
    assert_eq!(out, [START, &terminal[..]].concat());
    let report = report(rx).await;
    assert_eq!(
        report.forwarded_bytes,
        u64::try_from(START.len()).unwrap(),
        "the terminal frame was counted as upstream bytes"
    );
}

// ── The stop ────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_stop_cuts_a_waiting_stream() {
    let codec = Arc::new(Dialect::new());
    let stop = Stop::running();
    let (up, dropped, _keep) = upstream(&[START], true);
    let (mut body, rx) = relay(&codec, &stop, RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let first = body.frame().await.unwrap().unwrap();
    assert_eq!(first.into_data().unwrap(), Bytes::from_static(START));
    let (next, ()) = tokio::join!(tokio::time::timeout(Duration::from_secs(5), body.frame()), async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _engaged = stop.engage(StopReason::Operator);
    });
    let next = next.expect("a stop did not cut a waiting stream");
    assert_eq!(
        next.map(|f| f.map(|_| ())),
        Some(Err(RelayError::Cut(CutReason::Stopped(StopReason::Operator))))
    );
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(
        report(rx).await.end,
        RelayEnd::Cut(CutReason::Stopped(StopReason::Operator))
    );
}

#[tokio::test]
async fn a_stop_engaged_first_forwards_nothing() {
    let codec = Arc::new(Dialect::new());
    let stop = Stop::running();
    let _engaged = stop.engage(StopReason::DiskFull);
    let (up, _, _) = upstream(&[START, DELTA], false);
    let (mut body, _rx) = relay(&codec, &stop, RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert!(out.is_empty(), "a stopped kernel forwarded a byte");
    assert_eq!(error, Some(RelayError::Cut(CutReason::Stopped(StopReason::DiskFull))));
}

// ── Bounds and failures ─────────────────────────────────────────────────────────────────────

async fn cut_reason(parts: &[&[u8]], codec: Dialect, limits: RelayLimits) -> Option<RelayError> {
    let codec = Arc::new(codec);
    let (up, _, _) = upstream(parts, false);
    let (mut body, _rx) = relay(&codec, &Stop::running(), limits)
        .sse(up, &HeaderMap::new())
        .unwrap();
    drain(&mut body).await.1
}

#[tokio::test]
async fn an_event_past_its_bound_cuts() {
    let limits = RelayLimits {
        max_event_bytes: 64,
        ..RelayLimits::default()
    };
    assert_eq!(
        cut_reason(&[DELTA], Dialect::new(), limits).await,
        Some(RelayError::Cut(CutReason::EventTooLarge)),
        "an event past its bound was forwarded"
    );
}

#[tokio::test]
async fn a_body_past_its_bound_cuts() {
    let limits = RelayLimits {
        max_body_bytes: 200,
        ..RelayLimits::default()
    };
    assert_eq!(
        cut_reason(&[START, DELTA, PING], Dialect::new(), limits).await,
        Some(RelayError::Cut(CutReason::BodyTooLarge))
    );
}

#[tokio::test(start_paused = true)]
async fn an_idle_upstream_cuts() {
    let codec = Arc::new(Dialect::new());
    let (up, dropped, _keep) = upstream(&[PING], true);
    let (mut body, _rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert_eq!(out, PING.to_vec());
    assert_eq!(error, Some(RelayError::Cut(CutReason::Idle)));
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn usage_that_cannot_be_read_or_priced_cuts() {
    let duplicate: &[u8] =
        b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":1,\"output_tokens\":1}}\n\n";
    assert_eq!(
        cut_reason(&[duplicate], Dialect::new(), RelayLimits::default()).await,
        Some(RelayError::Cut(CutReason::UnreadableUsage)),
        "a duplicated usage key was metered"
    );
    let not_json: &[u8] = b"event: message_delta\ndata: {\"usage\":\n\n";
    assert_eq!(
        cut_reason(&[not_json], Dialect::new(), RelayLimits::default()).await,
        Some(RelayError::Cut(CutReason::UnreadableUsage))
    );
    let rogue = Dialect {
        rogue: true,
        ..Dialect::new()
    };
    assert_eq!(
        cut_reason(&[START], rogue, RelayLimits::default()).await,
        Some(RelayError::Cut(CutReason::UnreadableUsage)),
        "an undeclared dimension was metered"
    );
    let no_report: &[u8] = b"event: message_delta\ndata: {\"type\":\"message_delta\"}\n\n";
    assert_eq!(
        cut_reason(&[no_report], Dialect::new(), RelayLimits::default()).await,
        Some(RelayError::Cut(CutReason::UnreadableUsage))
    );
    let bad_name: &[u8] = b"event: \xFF\ndata: {}\n\n";
    assert_eq!(
        cut_reason(&[bad_name], Dialect::new(), RelayLimits::default()).await,
        Some(RelayError::Cut(CutReason::Malformed))
    );
}

#[tokio::test]
async fn an_unpriced_dimension_cuts() {
    let codec: Arc<dyn DialectCodec> = Arc::new(Dialect::new());
    let only_output = Arc::new(DeclaredPrice::new([(code("output_tokens"), NanoUsd::new(1_000))]).unwrap());
    let (up, _, _) = upstream(&[START], false);
    let (mut body, _rx) = Relay::new(
        codec,
        only_output,
        &reservation(CEILING),
        Stop::running(),
        RelayLimits::default(),
    )
    .sse(up, &HeaderMap::new())
    .unwrap();
    assert_eq!(drain(&mut body).await.1, Some(RelayError::Cut(CutReason::Unpriced)));
    assert_eq!(
        CutReason::Unpriced.error_code(),
        uaos_contracts::error::codes::BUDGET_UNKNOWN_PRICING
    );
}

#[tokio::test]
async fn a_failed_upstream_cuts() {
    let codec = Arc::new(Dialect::new());
    let (up, _, keep) = upstream(&[START], true);
    keep.unwrap().try_send(Err(io::Error::other("reset"))).unwrap();
    let (mut body, _rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert_eq!(out, START.to_vec());
    assert_eq!(error, Some(RelayError::Cut(CutReason::UpstreamFailed)));
}

#[test]
fn a_compressed_event_stream_is_refused_before_any_byte() {
    let codec = Arc::new(Dialect::new());
    for coding in ["gzip", "br", "identity, gzip"] {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static(coding));
        let (up, _, _) = upstream(&[START], false);
        let refused = relay(&codec, &Stop::running(), RelayLimits::default()).sse(up, &headers);
        assert_eq!(refused.err(), Some(RelayError::Compressed), "{coding}");
    }
    let mut identity = HeaderMap::new();
    identity.insert(CONTENT_ENCODING, HeaderValue::from_static("Identity"));
    let (up, _, _) = upstream(&[START], false);
    assert!(
        relay(&codec, &Stop::running(), RelayLimits::default())
            .sse(up, &identity)
            .is_ok()
    );
}

#[tokio::test]
async fn a_dropped_client_body_drops_the_upstream() {
    let codec = Arc::new(Dialect::new());
    let (up, dropped, _keep) = upstream(&[START], true);
    let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let _first = body.frame().await.unwrap().unwrap();
    drop(body);
    assert!(dropped.load(Ordering::SeqCst), "a client that left kept the upstream");
    let report = report(rx).await;
    assert_eq!(report.end, RelayEnd::ClientGone);
    assert_eq!(report.forwarded_bytes, u64::try_from(START.len()).unwrap());
}

#[tokio::test]
async fn bytes_mode_relays_untouched_under_the_same_stop() {
    let codec = Arc::new(Dialect::new());
    let stop = Stop::running();
    let parts: [&[u8]; 2] = [b"{\"id\":\"msg_1\",", b"\"usage\":{\"output_tokens\":999999}}"];
    let (up, _, _) = upstream(&parts, false);
    let (mut body, rx) = relay(&codec, &stop, RelayLimits::default()).bytes(up);
    let (out, error) = drain(&mut body).await;
    assert_eq!((out, error), (concat(&parts), None));
    let report = report(rx).await;
    assert_eq!(
        (report.end, report.cost),
        (RelayEnd::Completed, None),
        "bytes mode metered"
    );
    let _engaged = stop.engage(StopReason::Operator);
    let (up, _, _) = upstream(&parts, false);
    let (mut body, _rx) = relay(&codec, &stop, RelayLimits::default()).bytes(up);
    let (out, error) = drain(&mut body).await;
    assert!(out.is_empty());
    assert_eq!(error, Some(RelayError::Cut(CutReason::Stopped(StopReason::Operator))));
}

// ── Any chunking, the seven-locale corpus ───────────────────────────────────────────────────

/// Content in the seven GA locales, chosen for the classic byte hazards (ADR-0020): Turkish
/// dotted and dotless i, German sharp s, precomposed and decomposed accents, Arabic tashkeel and
/// implicit direction marks.
const CORPUS: [&str; 9] = [
    "The quick brown fox",
    "\u{130}stanbul'da \u{131}l\u{131}k: I\u{131} \u{130}i",
    "Stra\u{df}e \u{b7} STRASSE \u{b7} \u{1e9e}",
    "\u{c7}a a \u{e9}t\u{e9} d\u{e9}j\u{e0} vu",
    "e\u{301}te\u{301} (NFD)",
    "\u{bf}A\u{f1}adir? \u{a1}S\u{ed}!",
    "Perch\u{e9} \u{e8} cos\u{ec}",
    "\u{645}\u{64e}\u{631}\u{652}\u{62d}\u{64e}\u{628}\u{64b}\u{627} \u{200f}\u{61c}",
    "{\"type\":\"x\",\"text\":\"\u{1f600}\"}",
];

const ENDINGS: [&str; 3] = ["\n", "\r\n", "\r"];

#[derive(Debug, Clone)]
struct GenEvent {
    comment: bool,
    name: Option<&'static str>,
    data: Vec<usize>,
    id: bool,
}

fn gen_event() -> impl Strategy<Value = GenEvent> {
    (
        any::<bool>(),
        prop::option::of(prop::sample::select(vec!["content_block_delta", "ping", "x"])),
        prop::collection::vec(0..CORPUS.len(), 0..3),
        any::<bool>(),
    )
        .prop_map(|(comment, name, data, id)| GenEvent {
            comment,
            name,
            data,
            id,
        })
}

/// Serializes events with a line ending drawn per line, a byte-order mark maybe, and maybe a
/// last event that no blank line ends.
fn serialize(events: &[GenEvent], endings: &[usize], bom: bool, open_tail: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if bom {
        out.extend_from_slice(b"\xEF\xBB\xBF");
    }
    let mut n = 0;
    let mut line = |out: &mut Vec<u8>, text: &str| {
        out.extend_from_slice(text.as_bytes());
        out.extend_from_slice(ENDINGS[endings[n % endings.len()]].as_bytes());
        n += 1;
    };
    for (i, event) in events.iter().enumerate() {
        if event.comment {
            line(&mut out, ": keep-alive");
        }
        if let Some(name) = event.name {
            line(&mut out, &format!("event: {name}"));
        }
        for d in &event.data {
            line(&mut out, &format!("data: {}", CORPUS[*d]));
        }
        if event.id {
            line(&mut out, "id: 7");
        }
        if !(open_tail && i + 1 == events.len()) {
            line(&mut out, "");
        }
    }
    out
}

/// The WHATWG event-stream algorithm over a whole body: an independent reading to compare the
/// relay with. A last event that no blank line ends is dispatched, as a lenient client would.
fn reference(body: &[u8]) -> Vec<(Option<String>, Vec<u8>)> {
    let body = body.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(body);
    let mut lines: Vec<&[u8]> = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < body.len() {
        match body[i] {
            b'\n' => {
                lines.push(&body[start..i]);
                i += 1;
                start = i;
            }
            b'\r' => {
                lines.push(&body[start..i]);
                i += if body.get(i + 1) == Some(&b'\n') { 2 } else { 1 };
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < body.len() {
        lines.push(&body[start..]);
    }
    let mut out = Vec::new();
    let mut event: Option<String> = None;
    let mut data: Option<Vec<u8>> = None;
    for line in lines {
        if line.is_empty() {
            if let Some(d) = data.take() {
                out.push((event.take(), d));
            }
            event = None;
            continue;
        }
        if line[0] == b':' {
            continue;
        }
        let (name, value) = match line.iter().position(|b| *b == b':') {
            Some(c) => (&line[..c], line[c + 1..].strip_prefix(b" ").unwrap_or(&line[c + 1..])),
            None => (line, &line[line.len()..]),
        };
        match name {
            b"event" => event = Some(String::from_utf8(value.to_vec()).unwrap()),
            b"data" => match data.as_mut() {
                Some(d) => {
                    d.push(b'\n');
                    d.extend_from_slice(value);
                }
                None => data = Some(value.to_vec()),
            },
            _ => {}
        }
    }
    if let Some(d) = data {
        out.push((event, d));
    }
    out
}

fn chunked(body: &[u8], sizes: &[usize]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let (mut at, mut n) = (0, 0);
    while at < body.len() {
        let size = sizes[n % sizes.len()].min(body.len() - at);
        out.push(body[at..at + size].to_vec());
        at += size;
        n += 1;
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// For any events, line endings and chunking (CRLF split across chunks, a byte-order mark
    /// split across chunks, comments, multi-line data, the seven-locale corpus): the bytes the
    /// client receives are the bytes the provider sent, and the events the codec is shown are
    /// the ones an event-stream parser reads from the whole body.
    #[test]
    fn any_chunking_relays_the_same_bytes_and_events(
        events in prop::collection::vec(gen_event(), 0..8),
        endings in prop::collection::vec(0..ENDINGS.len(), 1..6),
        bom in any::<bool>(),
        open_tail in any::<bool>(),
        sizes in prop::collection::vec(1_usize..12, 1..6),
    ) {
        let body = serialize(&events, &endings, bom, open_tail);
        let pieces = chunked(&body, &sizes);
        let parts: Vec<&[u8]> = pieces.iter().map(Vec::as_slice).collect();
        let codec = Arc::new(Dialect { content_only: true, ..Dialect::new() });
        let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        let (out, error) = runtime.block_on(async {
            let (up, _, _) = upstream(&parts, false);
            let (mut body, _rx) = relay(&codec, &Stop::running(), RelayLimits::default())
                .sse(up, &HeaderMap::new())
                .unwrap();
            drain(&mut body).await
        });
        prop_assert_eq!(error, None);
        prop_assert_eq!(out, body.clone(), "the relay changed the stream's bytes");
        prop_assert_eq!(codec.seen(), reference(&body), "the relay saw different events than an event-stream parser");
    }
}
