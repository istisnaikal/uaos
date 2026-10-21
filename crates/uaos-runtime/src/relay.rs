// SPDX-License-Identifier: Apache-2.0

//! The relay: a provider's response to the client, metered against the Operation's reservation
//! (contract §7).
//!
//! [`RelayBody`] is a hyper body that the client's connection pulls. No task runs it and no
//! channel feeds it, so the client's socket is the backpressure. It holds at most one incomplete
//! event and forwards each event's exact bytes. Every usage report is priced, and the first one
//! past the reservation cuts the stream. A cut forwards nothing more of the upstream, drops it,
//! and ends in the caller's terminal frame or in an error: never in a clean end that a client
//! could take for a complete answer.
//!
//! A priced cost is final only when the stream completed and the dialect's end came at or after
//! its last usage report. Otherwise it is a lower bound on what the provider bills, and
//! [`RelayReport::settlement`] settles the reservation in full (review H1).

use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;
use http::header::CONTENT_ENCODING;
use hyper::body::{Body, Frame, SizeHint};
use tokio::sync::oneshot;
use tokio::time::{Instant, Sleep};
use uaos_contracts::error::{ErrorCode, codes};
use uaos_contracts::money::NanoUsd;
use uaos_ledger::{InFlight, Reservation, Usage};
use uaos_module_api::{Code, DialectCodec, FrameKind, Mask, SseEvent, StructuralView, UsageReport};

use crate::price::{Price, PriceError};
use crate::sse::{self, Segment, Splitter};
use crate::stop::{Stop, StopReason};

/// The relay's bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    /// The longest event, in bytes.
    pub max_event_bytes: usize,
    /// The most bytes one response may stream.
    pub max_body_bytes: u64,
    /// How long the upstream may send nothing while the relay waits for it before the stream is
    /// cut. The time counts from when the relay starts waiting, so a slow client never causes
    /// an idle cut. A timeout too large to add to the clock disables the cut.
    pub idle_timeout: Duration,
}

impl Default for RelayLimits {
    /// `[CONSCIOUS ASSUMPTION]` 1 MiB per event, 64 MiB per response, 600 s idle. A reasoning
    /// model can be silent for minutes before its first token, and not every dialect sends
    /// keep-alives; WP3.0d measures the real gaps.
    fn default() -> Self {
        Self {
            max_event_bytes: 1024 * 1024,
            max_body_bytes: 64 * 1024 * 1024,
            idle_timeout: Duration::from_secs(600),
        }
    }
}

/// Why a stream was cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CutReason {
    /// A usage report's cost passed the reservation. The kernel stop is engaged too.
    BudgetOverrun,
    /// A usage report's cost passed nano-USD's range, so it is past any reservation. The
    /// kernel stop is engaged too; the report keeps the last cost in range.
    CostOutOfRange,
    /// The kernel stop was engaged.
    Stopped(StopReason),
    /// A billing dimension has no price.
    Unpriced,
    /// A usage frame could not be read: not JSON, no report, or an undeclared dimension.
    UnreadableUsage,
    /// The stream is not a well-formed event stream.
    Malformed,
    /// An event passed `max_event_bytes`.
    EventTooLarge,
    /// The response passed `max_body_bytes`.
    BodyTooLarge,
    /// The upstream sent nothing for `idle_timeout`.
    Idle,
    /// The upstream body failed.
    UpstreamFailed,
}

impl CutReason {
    /// The reported code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BudgetOverrun => "budget_overrun",
            Self::CostOutOfRange => "cost_out_of_range",
            Self::Stopped(_) => "stopped",
            Self::Unpriced => "unpriced",
            Self::UnreadableUsage => "unreadable_usage",
            Self::Malformed => "malformed",
            Self::EventTooLarge => "event_too_large",
            Self::BodyTooLarge => "body_too_large",
            Self::Idle => "idle",
            Self::UpstreamFailed => "upstream_failed",
        }
    }

    /// The registered error code (contract §7.4). Only the stream that overran gets
    /// `BUDGET_STREAM_OVERRUN`; every stream cut by the stop it engaged gets `RUNTIME_STOPPED`.
    #[must_use]
    pub const fn error_code(self) -> ErrorCode {
        match self {
            Self::BudgetOverrun | Self::CostOutOfRange => codes::BUDGET_STREAM_OVERRUN,
            Self::Stopped(_) => codes::RUNTIME_STOPPED,
            Self::Unpriced => codes::BUDGET_UNKNOWN_PRICING,
            Self::UnreadableUsage | Self::Malformed | Self::EventTooLarge | Self::BodyTooLarge => {
                codes::EGRESS_UNUSABLE_RESPONSE
            }
            Self::Idle | Self::UpstreamFailed => codes::EGRESS_INTERRUPTED,
        }
    }

    /// Whether this cut engages the kernel stop.
    #[must_use]
    pub const fn engages_stop(self) -> bool {
        matches!(self, Self::BudgetOverrun | Self::CostOutOfRange)
    }
}

/// How a stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEnd {
    /// The upstream ended and everything was forwarded.
    Completed,
    /// The stream was cut.
    Cut(CutReason),
    /// The client went away; the upstream was dropped with it.
    ClientGone,
}

/// What a relay did, for settlement and explanation. Counts and codes only: no content (I-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayReport {
    /// How it ended.
    pub end: RelayEnd,
    /// Upstream bytes forwarded to the client. A terminal frame is not counted.
    pub forwarded_bytes: u64,
    /// Event-stream segments forwarded: events, comments and keep-alives. In bytes mode, the
    /// upstream frames forwarded.
    pub segments: u64,
    /// The usage reported, merged per dimension by its highest count.
    pub usage: Vec<(Code, u64)>,
    /// What that usage cost, once a report was priced.
    pub cost: Option<NanoUsd>,
    /// Whether `cost` is final: the stream completed, and the dialect's end came at or after
    /// its last usage report. Otherwise `cost` is a running total, a lower bound on the bill.
    pub usage_final: bool,
    /// The reservation the relay metered against.
    pub ceiling: NanoUsd,
}

impl RelayReport {
    /// What to settle the Operation's reservation with (contract §7.5):
    /// - a final cost, as reported;
    /// - a cost past the reservation, as reported: the provider billed at least that much, and
    ///   the ledger records the overrun (S1);
    /// - anything else, the full reservation, estimated: a stream that did not finish may have
    ///   been billed for every token up to the clamped `max_tokens`.
    #[must_use]
    pub fn settlement(&self) -> Usage {
        match self.cost {
            Some(cost) if self.usage_final || cost > self.ceiling => Usage::Reported(cost),
            _ => Usage::Unknown,
        }
    }
}

/// The error the client's body ends in, or a relay that could not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RelayError {
    /// The stream was cut and no terminal frame was given.
    #[error("the stream was cut ({})", .0.code())]
    Cut(CutReason),
    /// The upstream body is compressed, and an event stream must be observed to be metered (D-29).
    #[error("a compressed event stream cannot be metered")]
    Compressed,
}

/// Builds a relay for one Operation. Not `Clone`: one relay meters one reservation, and a
/// second relay over the same reservation would meter against the whole ceiling again.
pub struct Relay {
    codec: Arc<dyn DialectCodec>,
    price: Arc<dyn Price>,
    ceiling: NanoUsd,
    stop: Stop,
    limits: RelayLimits,
    terminal: Option<Bytes>,
}

impl fmt::Debug for Relay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Relay")
            .field("ceiling", &self.ceiling)
            .field("limits", &self.limits)
            .field("terminal", &self.terminal.as_ref().map(Bytes::len))
            .finish_non_exhaustive()
    }
}

impl Relay {
    /// A relay whose ceiling is `reservation`'s amount: the ledger's reservation for this
    /// Operation, already in flight.
    #[must_use]
    pub fn new(
        codec: Arc<dyn DialectCodec>,
        price: Arc<dyn Price>,
        reservation: &Reservation<InFlight>,
        stop: Stop,
        limits: RelayLimits,
    ) -> Self {
        Self {
            codec,
            price,
            ceiling: reservation.amount(),
            stop,
            limits,
            terminal: None,
        }
    }

    /// The frame a cut ends in: the dialect's error event (PR-7). Without one, a cut ends the
    /// client's body in an error.
    #[must_use]
    pub fn terminal(mut self, frame: Bytes) -> Self {
        self.terminal = Some(frame);
        self
    }

    /// Relays an event stream, metering every usage report.
    ///
    /// # Errors
    /// [`RelayError::Compressed`] before any byte if `headers` name a content coding other than
    /// `identity`.
    pub fn sse<B>(
        self,
        upstream: B,
        headers: &HeaderMap,
    ) -> Result<(RelayBody<B>, oneshot::Receiver<RelayReport>), RelayError> {
        let compressed = headers
            .get_all(CONTENT_ENCODING)
            .iter()
            .any(|v| v.to_str().map_or(true, |s| !s.trim().eq_ignore_ascii_case("identity")));
        if compressed {
            return Err(RelayError::Compressed);
        }
        let meter = Meter {
            splitter: Splitter::new(self.limits.max_event_bytes),
            codec: Arc::clone(&self.codec),
            price: Arc::clone(&self.price),
            ceiling: self.ceiling,
            usage: Vec::new(),
            cost: None,
            ended: false,
        };
        Ok(self.body(upstream, Some(meter)))
    }

    /// Relays a body that is not an event stream: frames untouched, under the same bounds and
    /// the same stop, unmetered (contract §7.1). A cut always ends it in an error: an event
    /// appended to a partial body would read as more body.
    #[must_use]
    pub fn bytes<B>(mut self, upstream: B) -> (RelayBody<B>, oneshot::Receiver<RelayReport>) {
        self.terminal = None;
        self.body(upstream, None)
    }

    fn body<B>(self, upstream: B, meter: Option<Meter>) -> (RelayBody<B>, oneshot::Receiver<RelayReport>) {
        let (tx, rx) = oneshot::channel();
        let body = RelayBody {
            upstream: Some(upstream),
            meter,
            stopped: Some(Box::pin(self.stop.watch().stopped())),
            stop: self.stop,
            idle: None,
            waiting: false,
            ceiling: self.ceiling,
            limits: self.limits,
            received: 0,
            ready: VecDeque::new(),
            staged: Vec::new(),
            terminal: self.terminal,
            phase: Phase::Streaming,
            forwarded_bytes: 0,
            segments: 0,
            report: Some(tx),
        };
        (body, rx)
    }
}

/// Reads and prices the usage events report.
struct Meter {
    splitter: Splitter,
    codec: Arc<dyn DialectCodec>,
    price: Arc<dyn Price>,
    ceiling: NanoUsd,
    usage: Vec<(Code, u64)>,
    cost: Option<NanoUsd>,
    /// The dialect's end came at or after the last usage report.
    ended: bool,
}

impl Meter {
    /// Whether `segment` may be forwarded.
    fn check(&mut self, segment: &Segment) -> Result<(), CutReason> {
        let fields = sse::fields(segment.parsed());
        let Some(data) = fields.data else {
            // A comment or a keep-alive: no event is dispatched.
            return Ok(());
        };
        // An empty event name is the default type, as no name is (WHATWG).
        let event = match fields.event {
            None | Some(b"") => None,
            Some(name) => Some(std::str::from_utf8(name).map_err(|_| CutReason::Malformed)?),
        };
        let kind = self.codec.frame(&SseEvent::new(event, &data));
        if kind == FrameKind::Ping {
            return Ok(());
        }
        // Every other event is read, whatever its kind: a dialect may report usage on its last
        // frame (review M2). A usage frame must yield a report.
        match self.read(&data)? {
            Some(report) => {
                self.meter(&report)?;
                self.ended = kind == FrameKind::End;
            }
            None if kind == FrameKind::Usage => return Err(CutReason::UnreadableUsage),
            None => {}
        }
        if kind == FrameKind::End {
            self.ended = true;
        }
        Ok(())
    }

    /// The usage an event's data reports, if any. Data shaped like a JSON object must parse,
    /// and `uaos-json` refuses duplicate keys, so neither a repeated usage key nor a broken
    /// object slips past metering while a client reads it (T19).
    fn read(&self, data: &[u8]) -> Result<Option<UsageReport>, CutReason> {
        if data.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
            return Ok(None);
        }
        let tape = uaos_json::parse(data, &uaos_json::Limits::DEFAULT).map_err(|_| CutReason::UnreadableUsage)?;
        let mut mask = Mask::new();
        mask.seal(&tape).map_err(|_| CutReason::UnreadableUsage)?;
        Ok(self.codec.usage(&StructuralView::new(&tape, &mask)))
    }

    fn meter(&mut self, report: &UsageReport) -> Result<(), CutReason> {
        report
            .check(self.codec.dimensions())
            .map_err(|_| CutReason::UnreadableUsage)?;
        for (name, count) in report.dims() {
            match self.usage.iter_mut().find(|(merged, _)| merged == name) {
                Some((_, held)) => *held = (*held).max(*count),
                None => self.usage.push((name.clone(), *count)),
            }
        }
        let cost = match self.price.cost(&self.usage) {
            Ok(cost) => cost,
            // A cost past nano-USD's range is past any ceiling (review L1).
            Err(PriceError::Overflow) => return Err(CutReason::CostOutOfRange),
            Err(_) => return Err(CutReason::Unpriced),
        };
        self.cost = Some(cost);
        if cost > self.ceiling {
            return Err(CutReason::BudgetOverrun);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Reading the upstream.
    Streaming,
    /// The upstream is done or dropped; forwarding what was cleared, then ending.
    Ending(RelayEnd),
    /// The terminal frame went out; ending cleanly next.
    Closing(RelayEnd),
    /// Nothing more.
    Done,
}

/// The client's body. See the module docs.
pub struct RelayBody<B> {
    upstream: Option<B>,
    meter: Option<Meter>,
    stop: Stop,
    /// The stop's watch, until it resolves.
    stopped: Option<Pin<Box<dyn Future<Output = StopReason> + Send>>>,
    idle: Option<Pin<Box<Sleep>>>,
    /// The relay is waiting on the upstream, and the idle deadline runs.
    waiting: bool,
    ceiling: NanoUsd,
    limits: RelayLimits,
    received: u64,
    /// Segments cleared to forward, in order.
    ready: VecDeque<Bytes>,
    /// Reused scratch for one chunk's segments.
    staged: Vec<Segment>,
    terminal: Option<Bytes>,
    phase: Phase,
    forwarded_bytes: u64,
    segments: u64,
    report: Option<oneshot::Sender<RelayReport>>,
}

impl<B> fmt::Debug for RelayBody<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Counts only: the bytes are upstream content.
        f.debug_struct("RelayBody")
            .field("phase", &self.phase)
            .field("received", &self.received)
            .field("forwarded_bytes", &self.forwarded_bytes)
            .field("segments", &self.segments)
            .finish_non_exhaustive()
    }
}

impl<B> RelayBody<B> {
    /// Cuts the stream: nothing more of the upstream is forwarded, and the upstream is dropped
    /// before the client's body yields again (§7.4).
    fn cut(&mut self, reason: CutReason) {
        self.ready.clear();
        self.upstream = None;
        if reason.engages_stop() {
            // The state actor journals the record through `Stop::unrecorded` (PR-6b).
            let _engaged = self.stop.engage(StopReason::BudgetOverrun);
        }
        self.phase = Phase::Ending(RelayEnd::Cut(reason));
    }

    fn feed(&mut self, data: Bytes) {
        self.received = self
            .received
            .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        if self.received > self.limits.max_body_bytes {
            self.cut(CutReason::BodyTooLarge);
            return;
        }
        let Some(meter) = self.meter.as_mut() else {
            if !data.is_empty() {
                self.ready.push_back(data);
            }
            return;
        };
        self.staged.clear();
        let split = meter.splitter.push(&data, &mut self.staged);
        let mut verdict = split.map_err(|_| CutReason::EventTooLarge);
        for segment in self.staged.drain(..) {
            if let Err(reason) = meter.check(&segment) {
                verdict = Err(reason);
                break;
            }
            self.ready.push_back(segment.bytes);
        }
        if let Err(reason) = verdict {
            self.cut(reason);
        }
    }

    /// The upstream ended cleanly.
    fn complete(&mut self) {
        self.upstream = None;
        if let Some(meter) = self.meter.as_mut()
            && let Some(tail) = meter.splitter.finish()
        {
            if let Err(reason) = meter.check(&tail) {
                self.cut(reason);
                return;
            }
            self.ready.push_back(tail.bytes);
        }
        self.phase = Phase::Ending(RelayEnd::Completed);
    }

    /// The stop's reason once it is engaged. Polls the watch so a waiting body wakes on a stop,
    /// and never polls it again after it resolved.
    fn poll_stop(&mut self, cx: &mut Context<'_>) -> Option<StopReason> {
        let Some(stopped) = self.stopped.as_mut() else {
            return self.stop.reason();
        };
        match stopped.as_mut().poll(cx) {
            Poll::Ready(reason) => {
                self.stopped = None;
                Some(reason)
            }
            Poll::Pending => None,
        }
    }

    /// Whether the upstream has sent nothing for the idle timeout since the relay began waiting
    /// on it. The deadline is set when a wait begins, inside the runtime that polls the body.
    fn idle_expired(&mut self, cx: &mut Context<'_>) -> bool {
        if !self.waiting {
            let Some(deadline) = Instant::now().checked_add(self.limits.idle_timeout) else {
                // Too far to reach: no idle cut.
                return false;
            };
            self.waiting = true;
            match self.idle.as_mut() {
                Some(sleep) => sleep.as_mut().reset(deadline),
                None => self.idle = Some(Box::pin(tokio::time::sleep_until(deadline))),
            }
        }
        self.idle
            .as_mut()
            .is_some_and(|sleep| sleep.as_mut().poll(cx).is_ready())
    }

    /// The upstream sent a frame: the next wait starts a new deadline.
    fn touch(&mut self) {
        self.waiting = false;
    }

    fn send_report(&mut self, end: RelayEnd) {
        if let Some(tx) = self.report.take() {
            let (usage, cost, ended) = self
                .meter
                .as_ref()
                .map_or((Vec::new(), None, false), |m| (m.usage.clone(), m.cost, m.ended));
            // The receiver may be gone; the report then has no reader.
            let _unread = tx.send(RelayReport {
                end,
                forwarded_bytes: self.forwarded_bytes,
                segments: self.segments,
                usage,
                cost,
                usage_final: end == RelayEnd::Completed && ended,
                ceiling: self.ceiling,
            });
        }
    }

    fn forward(&mut self, bytes: Bytes) -> Poll<Option<Result<Frame<Bytes>, RelayError>>> {
        self.forwarded_bytes = self
            .forwarded_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        self.segments += 1;
        Poll::Ready(Some(Ok(Frame::data(bytes))))
    }
}

impl<B> Body for RelayBody<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = RelayError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, RelayError>>> {
        let this = self.get_mut();
        loop {
            match this.phase {
                Phase::Done => return Poll::Ready(None),
                Phase::Closing(end) => {
                    this.phase = Phase::Done;
                    this.send_report(end);
                    return Poll::Ready(None);
                }
                Phase::Ending(end) => {
                    // Only a completed stream still holds cleared segments (a cut clears them).
                    // A stop engaged now turns it into a cut: nothing more is forwarded, and the
                    // client is not told the answer was complete.
                    if !this.ready.is_empty() {
                        if let Some(reason) = this.poll_stop(cx) {
                            this.cut(CutReason::Stopped(reason));
                            continue;
                        }
                        if let Some(bytes) = this.ready.pop_front() {
                            return this.forward(bytes);
                        }
                    }
                    let RelayEnd::Cut(reason) = end else {
                        this.phase = Phase::Done;
                        this.send_report(end);
                        return Poll::Ready(None);
                    };
                    if let Some(frame) = this.terminal.take() {
                        this.phase = Phase::Closing(end);
                        return Poll::Ready(Some(Ok(Frame::data(frame))));
                    }
                    // No terminal frame: the error tells the client the answer is not complete.
                    this.phase = Phase::Done;
                    this.send_report(end);
                    return Poll::Ready(Some(Err(RelayError::Cut(reason))));
                }
                Phase::Streaming => {}
            }
            // The stop comes first: from it on, nothing is forwarded or read (§3 rule 2).
            if let Some(reason) = this.poll_stop(cx) {
                this.cut(CutReason::Stopped(reason));
                continue;
            }
            if let Some(bytes) = this.ready.pop_front() {
                return this.forward(bytes);
            }
            let Some(upstream) = this.upstream.as_mut() else {
                this.complete();
                continue;
            };
            match Pin::new(upstream).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    this.touch();
                    // Trailers carry no body bytes and are not forwarded.
                    if let Ok(data) = frame.into_data() {
                        this.feed(data);
                    }
                }
                Poll::Ready(Some(Err(_))) => this.cut(CutReason::UpstreamFailed),
                Poll::Ready(None) => this.complete(),
                Poll::Pending => {
                    if this.idle_expired(cx) {
                        this.cut(CutReason::Idle);
                        continue;
                    }
                    return Poll::Pending;
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.phase == Phase::Done
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

impl<B> Drop for RelayBody<B> {
    fn drop(&mut self) {
        let end = match self.phase {
            Phase::Streaming => RelayEnd::ClientGone,
            // The client left before the last cleared segments reached it.
            Phase::Ending(RelayEnd::Completed) if !self.ready.is_empty() => RelayEnd::ClientGone,
            Phase::Ending(end) | Phase::Closing(end) => end,
            Phase::Done => return,
        };
        // The upstream goes with the body; the report says how it ended.
        self.upstream = None;
        self.send_report(end);
    }
}
