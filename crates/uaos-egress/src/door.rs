// SPDX-License-Identifier: Apache-2.0

//! The door: the single outbound client (I-07).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::uri::{Authority, PathAndQuery};
use http::{Method, Request, StatusCode, Uri};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::rt::Executor;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioTimer;
use rustls::crypto::aws_lc_rs;
use rustls::{ClientConfig, RootCertStore};
use uaos_contracts::id::OperationId;
use uaos_platform::Clock;

use crate::EgressError;
use crate::connect::{Connector, CounterSnapshot, Counters, Target, bump};
use crate::resolve::Resolve;
use crate::upstream::{Scheme, Trust, Upstream, UpstreamError, UpstreamId};

/// Operations remembered by the replay guard (I-08 bounded).
pub const REPLAY_WINDOW: usize = 65_536;
/// Idle pooled connections kept per upstream (I-08 bounded).
pub const MAX_IDLE_PER_UPSTREAM: usize = 8;

/// Time and failure limits of the door.
///
/// What the door does not bound, and the runtime does: how many requests are in flight at once
/// (admission control and the per-upstream concurrency limit), and how long and how large a
/// response body may stream (the relay's idle watchdog and byte limits).
#[derive(Debug, Clone, Copy)]
pub struct DoorLimits {
    /// Name resolution, the TCP connect to each address, and the TLS handshake, each.
    pub connect_timeout: Duration,
    /// From sending the request to receiving the response headers. Streaming bodies are timed
    /// by the runtime's idle watchdog, never here.
    pub response_timeout: Duration,
    /// Consecutive transport failures (unreachable or timed out) that open an upstream's
    /// circuit.
    pub breaker_threshold: u32,
    /// How long an open circuit refuses attempts. After it, exactly one probe is let through;
    /// the rest are refused until the probe settles.
    pub breaker_cooldown: Duration,
    /// Largest request body the door sends.
    pub max_request_body: usize,
    /// How long an idle pooled connection is kept.
    pub idle_timeout: Duration,
}

impl Default for DoorLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            response_timeout: Duration::from_secs(600),
            breaker_threshold: 5,
            breaker_cooldown: Duration::from_secs(30),
            max_request_body: 32 * 1024 * 1024,
            idle_timeout: Duration::from_secs(60),
        }
    }
}

/// One request through the door. Built by the runtime from a scanned, authorized Operation.
#[derive(Debug)]
pub struct EgressRequest {
    /// The Operation the request belongs to; must equal the binding passed to [`Door::send`].
    pub op_id: OperationId,
    /// Declared destination.
    pub upstream: UpstreamId,
    /// Method.
    pub method: Method,
    /// Path and query on the upstream; must start with `/`.
    pub path: PathAndQuery,
    /// Headers to forward. Hop-by-hop headers, `host` and `content-length` are removed (the door
    /// frames the body itself); credential-bearing headers are refused; nothing is added except
    /// the credential.
    pub headers: HeaderMap,
    /// The scanned body, sent byte for byte.
    pub body: Bytes,
}

/// The provider credential the door injects last, after the final scan (I-05).
///
/// Its value is marked sensitive when the credential is built and is never printed: `Debug`
/// shows only the header name.
pub struct Credential {
    header: HeaderName,
    value: HeaderValue,
}

impl Credential {
    /// A credential carried in `header` (for example `x-api-key` or `authorization`).
    #[must_use]
    pub fn new(header: HeaderName, mut value: HeaderValue) -> Self {
        value.set_sensitive(true);
        Self { header, value }
    }

    /// The header that carries it.
    #[must_use]
    pub fn header(&self) -> &HeaderName {
        &self.header
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("header", &self.header)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// The upstream's response; the body streams frame by frame.
#[derive(Debug)]
pub struct EgressResponse {
    /// Status.
    pub status: StatusCode,
    /// Headers, hop-by-hop headers removed.
    pub headers: HeaderMap,
    /// Body, not yet read.
    pub body: Incoming,
}

/// Headers that describe one connection, not the message (RFC 9110 §7.6.1).
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Headers known to carry credentials. A request from the runtime never carries one of them:
/// the client's own key to UAOS (a `uaos_sk_` sub-key in `authorization`), cookies and provider
/// keys would otherwise reach the provider. Credentials in other headers or in the query string
/// are not caught here; the runtime's final scan covers the body, and the request is built from
/// the client's own request (review WP3.A5, round 2, L6).
pub const CREDENTIAL_HEADERS: [&str; 9] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "openai-organization",
    "x-amz-security-token",
    "ocp-apim-subscription-key",
];

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

/// An upstream's circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Breaker {
    /// Attempts pass; `failures` consecutive transport failures so far.
    Closed { failures: u32 },
    /// Attempts are refused until the monotonic instant `until`.
    Open { until: u64 },
    /// One probe is in flight after a cooldown; every other attempt is refused.
    Probing,
}

impl Default for Breaker {
    fn default() -> Self {
        Self::Closed { failures: 0 }
    }
}

/// How an admitted attempt ended, for the breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// A response arrived (any status).
    Answered,
    /// Unreachable or timed out: evidence the upstream is down.
    TransportFailure,
    /// Refused or blocked by the door's own rules: no evidence about the upstream.
    NotAttempted,
}

impl Outcome {
    fn of(error: &EgressError) -> Self {
        match error {
            EgressError::Unreachable(_) | EgressError::Timeout => Self::TransportFailure,
            _ => Self::NotAttempted,
        }
    }
}

/// An attempt the breaker admitted. It is settled exactly once: by [`Admitted::settle`] or, if
/// the caller drops the future while the request is in flight, on drop as not attempted, so a
/// cancelled probe can never leave the circuit probing forever (review WP3.A5, round 2, H1).
struct Admitted<'a> {
    door: &'a Door,
    upstream: &'a UpstreamId,
    probe: bool,
    settled: bool,
}

impl Admitted<'_> {
    fn settle(mut self, outcome: Outcome) {
        self.settled = true;
        self.door.breaker_record(self.upstream, self.probe, outcome);
    }
}

impl Drop for Admitted<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.door
                .breaker_record(self.upstream, self.probe, Outcome::NotAttempted);
        }
    }
}

#[derive(Debug, Default)]
struct Replay {
    seen: BTreeSet<OperationId>,
    order: VecDeque<OperationId>,
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // Each guarded value is updated by single statements; a panicking holder leaves it whole.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The egress door. Exactly one exists per daemon and only the runtime holds it (ADR-0010).
/// The runtime builds it in one private module (ADR-0013 Amendment 1B; review WP3.A5 M1).
#[derive(Debug)]
pub struct Door {
    client: Client<Connector, Full<Bytes>>,
    upstreams: BTreeMap<UpstreamId, Upstream>,
    counters: Arc<Counters>,
    clock: Arc<dyn Clock>,
    limits: DoorLimits,
    breakers: Breakers,
    replay: Mutex<Replay>,
}

impl Door {
    /// Builds the door. Makes no network contact: resolution and connections happen per
    /// request. With [`Trust::System`] it reads the operating system's root certificates from
    /// the local store.
    ///
    /// `executor` drives connection tasks; the runtime passes its supervisor's, so the
    /// supervisor stays the only spawner.
    ///
    /// # Errors
    /// [`EgressError::Upstream`] for an invalid or duplicate declaration;
    /// [`EgressError::Tls`] if the TLS configuration cannot be built or no system root can be
    /// read.
    pub fn new<E>(
        upstreams: Vec<Upstream>,
        resolver: Arc<dyn Resolve>,
        clock: Arc<dyn Clock>,
        executor: E,
        limits: DoorLimits,
    ) -> Result<Self, EgressError>
    where
        E: Executor<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> + Send + Sync + Clone + 'static,
    {
        let mut system_roots = None;
        let mut by_id = BTreeMap::new();
        let mut targets = BTreeMap::new();
        for up in upstreams {
            up.validate().map_err(EgressError::Upstream)?;
            let tls = match up.scheme {
                Scheme::Https => Some(Connector::tls_for(tls_config(&up.trust, &mut system_roots)?)),
                Scheme::Http => None,
            };
            let key = (up.host.as_str().to_owned(), up.port);
            let target = Arc::new(Target {
                upstream: up.clone(),
                tls,
            });
            if targets.insert(key, target).is_some() || by_id.insert(up.id.clone(), up).is_some() {
                return Err(EgressError::Upstream(UpstreamError::Duplicate));
            }
        }
        let counters = Arc::new(Counters::default());
        let connector = Connector {
            targets: Arc::new(targets),
            resolver,
            counters: Arc::clone(&counters),
            connect_timeout: limits.connect_timeout,
        };
        let client = Client::builder(executor)
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(limits.idle_timeout)
            .pool_max_idle_per_host(MAX_IDLE_PER_UPSTREAM)
            // The door never retries, not even a request hyper-util considers unsent: the breaker
            // must see each attempt, and the runtime decides about retries.
            .retry_canceled_requests(false)
            .build(connector);
        Ok(Self {
            client,
            upstreams: by_id,
            counters,
            clock,
            limits,
            breakers: Breakers::default(),
            replay: Mutex::new(Replay::default()),
        })
    }

    /// External-contact counters.
    #[must_use]
    pub fn counters(&self) -> CounterSnapshot {
        self.counters.snapshot()
    }

    /// Sends one request for the Operation `binding`.
    ///
    /// Refused before any contact when the request belongs to another Operation, the upstream
    /// is undeclared, the body is too large, the path does not start with `/`, the request
    /// carries a credential-bearing header, the upstream's circuit is open, or the Operation
    /// already sent. Only the last consumes the Operation: once a request is handed to the
    /// client, even a failed one, a retry needs a new Operation. The URI is built from the
    /// upstream's own name and port, so nothing in the request can redirect it. The credential
    /// is inserted last. Redirects are returned, never followed.
    ///
    /// # Errors
    /// [`EgressError`].
    pub async fn send(
        &self,
        binding: OperationId,
        request: EgressRequest,
        credential: Option<Credential>,
    ) -> Result<EgressResponse, EgressError> {
        let refuse = |why| {
            bump(&self.counters.refused);
            Err(EgressError::Refused(why))
        };
        if request.op_id != binding {
            return refuse("the request belongs to another Operation");
        }
        let Some(up) = self.upstreams.get(&request.upstream) else {
            return refuse("unknown upstream");
        };
        if request.body.len() > self.limits.max_request_body {
            return refuse("request body larger than the door's limit");
        }
        if !request.path.as_str().starts_with('/') {
            return refuse("request path must start with /");
        }
        let mut headers = request.headers;
        // Checked before anything is stripped, so a credential header that is also hop-by-hop
        // (`proxy-authorization`) or listed in `connection` is refused, not silently dropped.
        if CREDENTIAL_HEADERS.iter().any(|name| headers.contains_key(*name)) {
            return refuse("the request carries a credential-bearing header");
        }
        strip_hop_by_hop(&mut headers);
        headers.remove(header::HOST);
        headers.remove(header::CONTENT_LENGTH);
        let Ok(authority) = Authority::try_from(format!("{}:{}", up.host, up.port)) else {
            return refuse("upstream name does not form an authority");
        };
        let uri = Uri::builder()
            .scheme(match up.scheme {
                Scheme::Https => "https",
                Scheme::Http => "http",
            })
            .authority(authority)
            .path_and_query(request.path)
            .build();
        let Ok(uri) = uri else {
            return refuse("request path does not form a URI");
        };
        let Ok(mut outbound) = Request::builder()
            .method(request.method)
            .uri(uri)
            .body(Full::new(request.body))
        else {
            return refuse("request could not be built");
        };
        *outbound.headers_mut() = headers;
        let admitted = match self.breaker_admits(&request.upstream) {
            Ok(probe) => Admitted {
                door: self,
                upstream: &request.upstream,
                probe,
                settled: false,
            },
            Err(retry_after) => {
                bump(&self.counters.refused);
                return Err(EgressError::CircuitOpen { retry_after });
            }
        };
        if !self.first_send(binding) {
            admitted.settle(Outcome::NotAttempted);
            return refuse("the Operation already sent a request");
        }
        if let Some(c) = credential {
            outbound.headers_mut().insert(c.header, c.value);
        }

        bump(&self.counters.sent);
        let result = tokio::time::timeout(self.limits.response_timeout, self.client.request(outbound)).await;
        let response = match result {
            Err(_) => {
                admitted.settle(Outcome::TransportFailure);
                return Err(EgressError::Timeout);
            }
            Ok(Err(e)) => {
                let error = EgressError::from_client(&e);
                admitted.settle(Outcome::of(&error));
                return Err(error);
            }
            Ok(Ok(r)) => r,
        };
        admitted.settle(Outcome::Answered);
        let (parts, body) = response.into_parts();
        let mut headers = parts.headers;
        strip_hop_by_hop(&mut headers);
        Ok(EgressResponse {
            status: parts.status,
            headers,
            body,
        })
    }

    /// Records `op` as sent; `false` if it already was (within [`REPLAY_WINDOW`]).
    fn first_send(&self, op: OperationId) -> bool {
        let mut replay = locked(&self.replay);
        if !replay.seen.insert(op) {
            return false;
        }
        replay.order.push_back(op);
        if replay.order.len() > REPLAY_WINDOW
            && let Some(oldest) = replay.order.pop_front()
        {
            replay.seen.remove(&oldest);
        }
        true
    }

    fn breaker_admits(&self, id: &UpstreamId) -> Result<bool, Duration> {
        self.breakers
            .admits(id, self.clock.mono().0, self.limits.breaker_cooldown)
    }

    fn breaker_record(&self, id: &UpstreamId, probe: bool, outcome: Outcome) {
        self.breakers.record(
            id,
            probe,
            outcome,
            self.clock.mono().0,
            self.limits.breaker_threshold,
            self.limits.breaker_cooldown,
        );
    }
}

/// Every upstream's circuit, keyed by id (bounded by the declared upstreams).
#[derive(Debug, Default)]
struct Breakers(Mutex<BTreeMap<UpstreamId, Breaker>>);

impl Breakers {
    /// `Ok(probe)` if the attempt may go, where `probe` says it is the single attempt let
    /// through after a cooldown; `Err(retry_after)` while the circuit is open or a probe is in
    /// flight. `now` is monotonic nanoseconds.
    fn admits(&self, id: &UpstreamId, now: u64, cooldown: Duration) -> Result<bool, Duration> {
        let mut breakers = locked(&self.0);
        let breaker = breakers.entry(id.clone()).or_default();
        match *breaker {
            Breaker::Closed { .. } => Ok(false),
            Breaker::Open { until } if until > now => Err(Duration::from_nanos(until - now)),
            Breaker::Open { .. } => {
                *breaker = Breaker::Probing;
                Ok(true)
            }
            Breaker::Probing => Err(cooldown),
        }
    }

    /// Settles an admitted attempt. Only transport failures count against the upstream. A
    /// probe that fails reopens the circuit for another cooldown; a probe that never reached
    /// the upstream (refused or blocked by the door, or dropped by its caller) lets the next
    /// attempt probe instead.
    fn record(&self, id: &UpstreamId, probe: bool, outcome: Outcome, now: u64, threshold: u32, cooldown: Duration) {
        let cooldown = u64::try_from(cooldown.as_nanos()).unwrap_or(u64::MAX);
        let mut breakers = locked(&self.0);
        let breaker = breakers.entry(id.clone()).or_default();
        *breaker = match (outcome, probe, *breaker) {
            (Outcome::Answered, _, _) => Breaker::default(),
            (Outcome::TransportFailure, true, _) => Breaker::Open {
                until: now.saturating_add(cooldown),
            },
            (Outcome::NotAttempted, true, _) => Breaker::Open { until: now },
            (Outcome::TransportFailure, false, Breaker::Closed { failures }) => {
                let failures = failures.saturating_add(1);
                if failures >= threshold {
                    Breaker::Open {
                        until: now.saturating_add(cooldown),
                    }
                } else {
                    Breaker::Closed { failures }
                }
            }
            (_, false, current) => current,
        };
    }
}

/// TLS 1.2+ on aws-lc-rs, HTTP/1.1 only, with the upstream's certificate trust. The system's
/// roots are read once per door and shared by every upstream that uses them.
fn tls_config(trust: &Trust, system_roots: &mut Option<Arc<RootCertStore>>) -> Result<ClientConfig, EgressError> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| EgressError::Tls("no safe protocol versions"))?;
    let roots = match trust {
        Trust::System => {
            if let Some(roots) = system_roots {
                Arc::clone(roots)
            } else {
                let roots = Arc::new(load_system_roots()?);
                *system_roots = Some(Arc::clone(&roots));
                roots
            }
        }
        Trust::Roots(roots) => {
            if roots.is_empty() {
                return Err(EgressError::Tls("an upstream declares no root certificate to trust"));
            }
            let mut store = RootCertStore::empty();
            for root in roots {
                store
                    .add(root.clone())
                    .map_err(|_| EgressError::Tls("a configured root certificate is invalid"))?;
            }
            Arc::new(store)
        }
    };
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// The operating system's root certificates, read from its local store. Certificates that do
/// not parse are skipped; none at all is an error.
fn load_system_roots() -> Result<RootCertStore, EgressError> {
    let found = rustls_native_certs::load_native_certs();
    let mut store = RootCertStore::empty();
    let (_added, _unparsable) = store.add_parsable_certificates(found.certs);
    if store.is_empty() {
        return Err(EgressError::Tls(
            "no root certificate could be read from the system store",
        ));
    }
    Ok(store)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test fixtures abort on failure")]

    use super::*;
    use crate::addr::Blocked;

    /// Only an unreachable upstream or a timeout counts against it (round 2, L5).
    #[test]
    fn only_transport_failures_count_against_an_upstream() {
        assert_eq!(Outcome::of(&EgressError::Unreachable("x")), Outcome::TransportFailure);
        assert_eq!(Outcome::of(&EgressError::Timeout), Outcome::TransportFailure);
        for e in [
            EgressError::Refused("x"),
            EgressError::Blocked(Blocked::Loopback),
            EgressError::CircuitOpen {
                retry_after: Duration::ZERO,
            },
            EgressError::Tls("x"),
        ] {
            assert_eq!(Outcome::of(&e), Outcome::NotAttempted, "{e:?}");
        }
    }

    /// The breaker's states: closed, open until its cooldown ends, one probe, and back.
    #[test]
    fn the_breaker_lets_one_probe_through_and_settles_it() {
        let breakers = Breakers::default();
        let id = UpstreamId::new("x");
        let cooldown = Duration::from_secs(30);
        let (threshold, mut now) = (2, 1_000_u64);
        breakers.record(&id, false, Outcome::TransportFailure, now, threshold, cooldown);
        assert_eq!(
            breakers.admits(&id, now, cooldown),
            Ok(false),
            "one failure keeps it closed"
        );
        breakers.record(&id, false, Outcome::NotAttempted, now, threshold, cooldown);
        breakers.record(&id, false, Outcome::TransportFailure, now, threshold, cooldown);
        assert!(breakers.admits(&id, now, cooldown).is_err(), "the threshold opens it");
        now += 31_000_000_000;
        assert_eq!(
            breakers.admits(&id, now, cooldown),
            Ok(true),
            "the first attempt after the cooldown probes"
        );
        assert!(breakers.admits(&id, now, cooldown).is_err(), "only one probe at a time");
        breakers.record(&id, true, Outcome::NotAttempted, now, threshold, cooldown);
        assert_eq!(
            breakers.admits(&id, now, cooldown),
            Ok(true),
            "a probe that never reached it lets the next one probe"
        );
        breakers.record(&id, true, Outcome::TransportFailure, now, threshold, cooldown);
        assert!(
            breakers.admits(&id, now, cooldown).is_err(),
            "a failed probe reopens it"
        );
        now += 31_000_000_000;
        assert_eq!(breakers.admits(&id, now, cooldown), Ok(true));
        breakers.record(&id, true, Outcome::Answered, now, threshold, cooldown);
        assert_eq!(
            breakers.admits(&id, now, cooldown),
            Ok(false),
            "an answered probe closes it"
        );
    }
}
