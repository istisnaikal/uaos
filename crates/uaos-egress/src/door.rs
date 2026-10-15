// SPDX-License-Identifier: Apache-2.0

//! The door: the single outbound client (I-07).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::uri::PathAndQuery;
use http::{Method, Request, StatusCode, Uri};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::rt::Executor;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioTimer;
use rustls::ClientConfig;
use rustls::crypto::aws_lc_rs;
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
#[derive(Debug, Clone, Copy)]
pub struct DoorLimits {
    /// TCP connect, and separately the TLS handshake.
    pub connect_timeout: Duration,
    /// From sending the request to receiving the response headers. Streaming bodies are timed
    /// by the runtime's idle watchdog, never here.
    pub response_timeout: Duration,
    /// Consecutive transport failures that open an upstream's circuit.
    pub breaker_threshold: u32,
    /// How long an open circuit refuses attempts before one is let through.
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
    /// Path and query on the upstream.
    pub path: PathAndQuery,
    /// Headers to forward. Hop-by-hop headers and `host` are removed; nothing is added except
    /// the credential.
    pub headers: HeaderMap,
    /// The scanned body, sent byte for byte.
    pub body: Bytes,
}

/// The provider credential the door injects last, after the final scan (I-05).
#[derive(Debug)]
pub struct Credential {
    /// Header that carries it (for example `x-api-key` or `authorization`).
    pub header: HeaderName,
    /// Its value; marked sensitive so it is never printed.
    pub value: HeaderValue,
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

/// Headers that describe one connection, not the message (RFC 9110 §7.6.1), plus `host`, which
/// the door sets from the upstream.
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

#[derive(Debug, Default)]
struct Breaker {
    failures: u32,
    open_until_mono: Option<u64>,
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

/// The egress door. Exactly one exists per daemon, built by the composition root and handed
/// only to the runtime (ADR-0010).
#[derive(Debug)]
pub struct Door {
    client: Client<Connector, Full<Bytes>>,
    upstreams: BTreeMap<UpstreamId, Upstream>,
    counters: Arc<Counters>,
    clock: Arc<dyn Clock>,
    limits: DoorLimits,
    breakers: Mutex<BTreeMap<UpstreamId, Breaker>>,
    replay: Mutex<Replay>,
}

impl Door {
    /// Builds the door. Makes no contact: resolution and connections happen per request.
    ///
    /// `executor` drives connection tasks; the runtime passes its supervisor's, so the
    /// supervisor stays the only spawner.
    ///
    /// # Errors
    /// [`EgressError::Upstream`] for an invalid or duplicate declaration;
    /// [`EgressError::Tls`] if the TLS configuration cannot be built.
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
        let mut by_id = BTreeMap::new();
        let mut targets = BTreeMap::new();
        for up in upstreams {
            up.validate().map_err(EgressError::Upstream)?;
            let tls = match up.scheme {
                Scheme::Https => Some(Connector::tls_for(tls_config(&up.trust)?)),
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
            .build(connector);
        Ok(Self {
            client,
            upstreams: by_id,
            counters,
            clock,
            limits,
            breakers: Mutex::new(BTreeMap::new()),
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
    /// Refused before any contact when the request belongs to another Operation, the Operation
    /// already sent, the upstream is undeclared, the body is too large, the request already
    /// carries the credential's header, or the upstream's circuit is open. The credential is
    /// inserted last and marked sensitive. Redirects are returned, never followed.
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
        let mut headers = request.headers;
        strip_hop_by_hop(&mut headers);
        headers.remove(header::HOST);
        if let Some(c) = &credential
            && headers.contains_key(&c.header)
        {
            return refuse("the request already carries the credential's header");
        }
        if let Err(retry_after) = self.breaker_admits(&request.upstream) {
            return Err(EgressError::CircuitOpen { retry_after });
        }
        if !self.first_send(binding) {
            return refuse("the Operation already sent a request");
        }

        let scheme = match up.scheme {
            Scheme::Https => "https",
            Scheme::Http => "http",
        };
        let uri: Uri = format!("{scheme}://{}:{}{}", up.host, up.port, request.path)
            .parse()
            .map_err(|_| EgressError::Refused("request path does not form a URI"))?;
        let mut outbound = Request::builder()
            .method(request.method)
            .uri(uri)
            .body(Full::new(request.body))
            .map_err(|_| EgressError::Refused("request could not be built"))?;
        *outbound.headers_mut() = headers;
        if let Some(mut c) = credential {
            c.value.set_sensitive(true);
            outbound.headers_mut().insert(c.header, c.value);
        }

        bump(&self.counters.sent);
        let result = tokio::time::timeout(self.limits.response_timeout, self.client.request(outbound)).await;
        let response = match result {
            Err(_) => {
                self.breaker_record(&request.upstream, false);
                return Err(EgressError::Timeout);
            }
            Ok(Err(e)) => {
                self.breaker_record(&request.upstream, false);
                return Err(EgressError::from_client(&e));
            }
            Ok(Ok(r)) => r,
        };
        self.breaker_record(&request.upstream, true);
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

    /// `Err(retry_after)` while the upstream's circuit is open. Once the cooldown has passed,
    /// attempts are let through again; one more failure reopens it.
    fn breaker_admits(&self, id: &UpstreamId) -> Result<(), Duration> {
        let now = self.clock.mono().0;
        let breakers = locked(&self.breakers);
        match breakers.get(id).and_then(|b| b.open_until_mono) {
            Some(until) if until > now => Err(Duration::from_nanos(until - now)),
            _ => Ok(()),
        }
    }

    fn breaker_record(&self, id: &UpstreamId, success: bool) {
        let now = self.clock.mono().0;
        let mut breakers = locked(&self.breakers);
        let b = breakers.entry(id.clone()).or_default();
        if success {
            *b = Breaker::default();
            return;
        }
        b.failures = b.failures.saturating_add(1);
        if b.failures >= self.limits.breaker_threshold {
            let cooldown = u64::try_from(self.limits.breaker_cooldown.as_nanos()).unwrap_or(u64::MAX);
            b.open_until_mono = Some(now.saturating_add(cooldown));
        }
    }
}

/// TLS 1.2+ on aws-lc-rs, HTTP/1.1 only, with the upstream's certificate trust.
fn tls_config(trust: &Trust) -> Result<ClientConfig, EgressError> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| EgressError::Tls("no safe protocol versions"))?;
    let mut config = match trust {
        Trust::Platform => {
            use rustls_platform_verifier::BuilderVerifierExt as _;
            builder
                .with_platform_verifier()
                .map_err(|_| EgressError::Tls("the platform certificate verifier is unavailable"))?
                .with_no_client_auth()
        }
        Trust::Roots(roots) => {
            let mut store = rustls::RootCertStore::empty();
            for root in roots {
                store
                    .add(root.clone())
                    .map_err(|_| EgressError::Tls("a configured root certificate is invalid"))?;
            }
            builder.with_root_certificates(store).with_no_client_auth()
        }
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}
