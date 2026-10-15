// SPDX-License-Identifier: Apache-2.0

//! The egress door against a loopback TLS mock provider (ADR-0013, threat T5).
//!
//! The mock presents a certificate from a throwaway test authority for `mock.provider.test`;
//! the door trusts only that authority and dials the pinned loopback address, which the
//! upstream declares private. Every test reads what the mock actually received.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::disallowed_methods,
    reason = "test harness: fixtures abort on failure; the mock server needs real sockets and tasks"
)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use uaos_contracts::id::{OperationId, TypedId};
use uaos_contracts::time::WallTime;
use uaos_egress::addr::Blocked;
use uaos_egress::resolve::Resolution;
use uaos_egress::{
    Credential, Door, DoorLimits, EgressError, EgressRequest, HostName, Resolve, Scheme, Trust, Upstream,
    UpstreamError, UpstreamId,
};
use uaos_platform::sim::SimClock;

const MOCK_HOST: &str = "mock.provider.test";

#[derive(Debug, Clone)]
struct Seen {
    path: String,
    headers: HeaderMap,
    body: Bytes,
}

struct Mock {
    port: u16,
    authority: CertificateDer<'static>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

/// A TLS server for `mock.provider.test` on 127.0.0.1 that records requests and answers
/// with `status` and, for redirects, a `location`.
async fn mock(status: StatusCode) -> Mock {
    let issued = rcgen::generate_simple_self_signed(vec![MOCK_HOST.to_owned()]).unwrap();
    let cert = issued.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(issued.signing_key.serialize_der()));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let (acceptor, log) = (acceptor.clone(), Arc::clone(&log));
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let service = service_fn(move |req: Request<Incoming>| {
                    let log = Arc::clone(&log);
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body
                            .collect()
                            .await
                            .map(http_body_util::Collected::to_bytes)
                            .unwrap_or_default();
                        log.lock().unwrap().push(Seen {
                            path: parts.uri.path().to_owned(),
                            headers: parts.headers,
                            body,
                        });
                        let mut response = Response::builder().status(status);
                        if status.is_redirection() {
                            response = response.header("location", "https://elsewhere.example/v1/messages");
                        }
                        Ok::<_, std::convert::Infallible>(
                            response
                                .header("connection", "keep-alive")
                                .header("x-request-id", "req_mock")
                                .body(Full::new(Bytes::from_static(b"event: ping\ndata: {}\n\n")))
                                .unwrap(),
                        )
                    }
                });
                let _done = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    Mock {
        port,
        authority: cert,
        seen,
    }
}

/// A resolver answering from a fixed table.
#[derive(Debug, Default)]
struct Table(BTreeMap<String, Vec<IpAddr>>);

impl Resolve for Table {
    fn resolve<'a>(&'a self, host: &'a HostName, _port: u16) -> Resolution<'a> {
        let found = self.0.get(host.as_str()).cloned().unwrap_or_default();
        Box::pin(async move { Ok(found) })
    }
}

fn mock_upstream(port: u16, authority: CertificateDer<'static>) -> Upstream {
    Upstream {
        id: UpstreamId::new("mock"),
        host: HostName::parse(MOCK_HOST).unwrap(),
        port,
        scheme: Scheme::Https,
        pinned: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        allow_private: true,
        trust: Trust::Roots(vec![authority]),
    }
}

fn clock() -> Arc<SimClock> {
    Arc::new(SimClock::new(
        WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap(),
    ))
}

fn door(upstreams: Vec<Upstream>, resolver: Table, limits: DoorLimits) -> Door {
    Door::new(upstreams, Arc::new(resolver), clock(), TokioExecutor::new(), limits).unwrap()
}

fn op(n: u64) -> OperationId {
    OperationId::from_parts(n, [n.to_le_bytes()[0]; 10])
}

fn request(op_id: OperationId, upstream: &str) -> EgressRequest {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
    headers.insert("connection", HeaderValue::from_static("x-hop"));
    headers.insert("x-hop", HeaderValue::from_static("per-connection"));
    headers.insert("host", HeaderValue::from_static("evil.example"));
    headers.insert("te", HeaderValue::from_static("trailers"));
    EgressRequest {
        op_id,
        upstream: UpstreamId::new(upstream),
        method: Method::POST,
        path: "/v1/messages?beta=true".parse().unwrap(),
        headers,
        body: Bytes::from_static(br#"{"model":"m","messages":[]}"#),
    }
}

fn credential() -> Credential {
    Credential {
        header: HeaderName::from_static("x-api-key"),
        value: HeaderValue::from_static("provider-credential-for-tests"),
    }
}

#[tokio::test]
async fn a_request_reaches_the_declared_upstream_with_only_its_credential_added() {
    let mock = mock(StatusCode::OK).await;
    let door = door(
        vec![mock_upstream(mock.port, mock.authority.clone())],
        Table::default(),
        DoorLimits::default(),
    );
    let response = door
        .send(op(1), request(op(1), "mock"), Some(credential()))
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode::OK);
    assert!(
        response.headers.get("connection").is_none(),
        "hop-by-hop response headers are removed"
    );
    assert_eq!(response.headers.get("x-request-id").unwrap(), "req_mock");
    let body = response.body.collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"event: ping\ndata: {}\n\n");

    let seen = mock.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let got = &seen[0];
    assert_eq!(got.path, "/v1/messages");
    assert_eq!(
        &got.body[..],
        br#"{"model":"m","messages":[]}"#,
        "the body is sent byte for byte"
    );
    assert_eq!(got.headers.get("x-api-key").unwrap(), "provider-credential-for-tests");
    assert_eq!(got.headers.get("anthropic-version").unwrap(), "2023-06-01");
    assert_eq!(
        got.headers.get("host").unwrap(),
        format!("{MOCK_HOST}:{}", mock.port).as_str()
    );
    for gone in ["x-hop", "te"] {
        assert!(
            got.headers.get(gone).is_none(),
            "hop-by-hop header {gone} reached the provider"
        );
    }
    assert!(
        got.headers.keys().all(|k| !k.as_str().contains("uaos")),
        "the door added a UAOS header"
    );
    let counters = door.counters();
    assert_eq!((counters.resolves, counters.connects, counters.sent), (0, 1, 1));
}

#[tokio::test]
async fn one_operation_sends_once_and_only_its_own_request() {
    let mock = mock(StatusCode::OK).await;
    let door = door(
        vec![mock_upstream(mock.port, mock.authority.clone())],
        Table::default(),
        DoorLimits::default(),
    );
    door.send(op(1), request(op(1), "mock"), None).await.unwrap();
    assert_eq!(
        door.send(op(1), request(op(1), "mock"), None).await.unwrap_err(),
        EgressError::Refused("the Operation already sent a request")
    );
    assert_eq!(
        door.send(op(2), request(op(3), "mock"), None).await.unwrap_err(),
        EgressError::Refused("the request belongs to another Operation")
    );
    let mut carrying = request(op(4), "mock");
    carrying
        .headers
        .insert("x-api-key", HeaderValue::from_static("agent-supplied"));
    assert_eq!(
        door.send(op(4), carrying, Some(credential())).await.unwrap_err(),
        EgressError::Refused("the request already carries the credential's header")
    );
    assert_eq!(
        door.send(op(5), request(op(5), "nowhere"), None).await.unwrap_err(),
        EgressError::Refused("unknown upstream")
    );
    assert_eq!(mock.seen.lock().unwrap().len(), 1, "refusals happen before any contact");
    assert_eq!(door.counters().refused, 4);
}

#[tokio::test]
async fn a_redirect_is_returned_never_followed() {
    let mock = mock(StatusCode::FOUND).await;
    let door = door(
        vec![mock_upstream(mock.port, mock.authority.clone())],
        Table::default(),
        DoorLimits::default(),
    );
    let response = door.send(op(1), request(op(1), "mock"), None).await.unwrap();
    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(
        response.headers.get("location").unwrap(),
        "https://elsewhere.example/v1/messages"
    );
    assert_eq!(mock.seen.lock().unwrap().len(), 1, "the door followed a redirect");
    assert_eq!(door.counters().connects, 1);
}

#[tokio::test]
async fn private_answers_are_refused_unless_the_upstream_is_declared_private() {
    let mut table = Table::default();
    table
        .0
        .insert("localhost".into(), vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    table.0.insert(
        "rebind.example".into(),
        vec!["10.0.0.7".parse().unwrap(), "169.254.169.254".parse().unwrap()],
    );
    let named = |id: &str, host: &str| Upstream {
        id: UpstreamId::new(id),
        host: HostName::parse(host).unwrap(),
        port: 443,
        scheme: Scheme::Https,
        pinned: Vec::new(),
        allow_private: false,
        trust: Trust::Roots(Vec::new()),
    };
    let door = door(
        vec![named("loop", "localhost"), named("rebind", "rebind.example")],
        table,
        DoorLimits::default(),
    );
    assert_eq!(
        door.send(op(1), request(op(1), "loop"), None).await.unwrap_err(),
        EgressError::Blocked(Blocked::Loopback),
        "the door dialled a private range"
    );
    assert_eq!(
        door.send(op(2), request(op(2), "rebind"), None).await.unwrap_err(),
        EgressError::Blocked(Blocked::Private)
    );
    let c = door.counters();
    assert_eq!(
        (c.resolves, c.blocked, c.connects),
        (2, 3, 0),
        "blocked answers are never dialled"
    );
}

#[test]
fn building_the_door_contacts_nothing() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = runtime.enter();
    let upstream = Upstream::https("anthropic", HostName::parse("api.anthropic.com").unwrap());
    let door = door(vec![upstream], Table::default(), DoorLimits::default());
    let c = door.counters();
    assert_eq!((c.resolves, c.connects, c.blocked, c.sent), (0, 0, 0, 0));
}

#[test]
fn plaintext_and_duplicate_upstreams_are_refused_at_declaration() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = runtime.enter();
    let mut plain = Upstream::https("p", HostName::parse("api.example.com").unwrap());
    plain.scheme = Scheme::Http;
    let refused = Door::new(
        vec![plain],
        Arc::new(Table::default()),
        clock(),
        TokioExecutor::new(),
        DoorLimits::default(),
    );
    assert_eq!(
        refused.unwrap_err(),
        EgressError::Upstream(UpstreamError::PlaintextToPublic)
    );
    let twice = Door::new(
        vec![
            Upstream::https("a", HostName::parse("api.example.com").unwrap()),
            Upstream::https("a", HostName::parse("other.example.com").unwrap()),
        ],
        Arc::new(Table::default()),
        clock(),
        TokioExecutor::new(),
        DoorLimits::default(),
    );
    assert_eq!(twice.unwrap_err(), EgressError::Upstream(UpstreamError::Duplicate));
}

#[tokio::test]
async fn the_circuit_opens_after_repeated_failures() {
    // A port nothing listens on.
    let closed = {
        let l = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        l.local_addr().unwrap().port()
    };
    let issued = rcgen::generate_simple_self_signed(vec![MOCK_HOST.to_owned()]).unwrap();
    let limits = DoorLimits {
        connect_timeout: Duration::from_secs(2),
        breaker_threshold: 2,
        ..DoorLimits::default()
    };
    let door = door(
        vec![mock_upstream(closed, issued.cert.der().clone())],
        Table::default(),
        limits,
    );
    for n in 1..=2 {
        assert!(matches!(
            door.send(op(n), request(op(n), "mock"), None).await.unwrap_err(),
            EgressError::Unreachable(_)
        ));
    }
    let connects = door.counters().connects;
    assert!(matches!(
        door.send(op(3), request(op(3), "mock"), None).await.unwrap_err(),
        EgressError::CircuitOpen { .. }
    ));
    assert_eq!(door.counters().connects, connects, "an open circuit makes no contact");
}

#[tokio::test]
async fn a_certificate_from_another_authority_is_refused() {
    let mock = mock(StatusCode::OK).await;
    let stranger = rcgen::generate_simple_self_signed(vec![MOCK_HOST.to_owned()]).unwrap();
    let door = door(
        vec![mock_upstream(mock.port, stranger.cert.der().clone())],
        Table::default(),
        DoorLimits::default(),
    );
    assert_eq!(
        door.send(op(1), request(op(1), "mock"), Some(credential()))
            .await
            .unwrap_err(),
        EgressError::Unreachable("TLS handshake or certificate check failed")
    );
    assert!(
        mock.seen.lock().unwrap().is_empty(),
        "nothing, credential included, reached an unverified peer"
    );
}
