// SPDX-License-Identifier: Apache-2.0

//! # UAOS egress: the one door
//!
//! Every outbound byte UAOS sends on a user's behalf leaves through [`Door::send`] (I-07). The
//! standard and tokio entry points that open sockets, send UDP, resolve names or build another
//! HTTP client are banned elsewhere in `clippy.toml`, with this crate as their only owner, and
//! `arch.toml` lets only the runtime depend on it. Those bans cover the listed entry points; a
//! dependency that opens sockets on its own is kept out by `arch.toml` and supply-chain review,
//! not by the bans.
//!
//! What the door guarantees (ADR-0013, threat T5):
//! * **Declared destinations only.** It connects to configured upstreams, named by DNS names;
//!   address literals in any spelling are refused ([`host`]).
//! * **It owns DNS.** It resolves, classifies every answer, and dials the classified address
//!   itself. Private, loopback, link-local, metadata and other special-purpose ranges are
//!   refused, including inside IPv4-mapped, NAT64 and 6to4 forms ([`addr`]). An upstream
//!   declared private may also reach loopback, private and unique-local addresses, never
//!   link-local; plain HTTP is dialled only at pinned local addresses and never resolved.
//! * **No fetches during TLS.** Certificates are verified against the system's roots by rustls
//!   itself, so a server's certificate cannot make UAOS fetch an issuer or revocation URL of its
//!   choosing ([`Trust::System`]).
//! * **No redirects.** A redirect is returned to the caller as a response, never followed.
//! * **Nothing added.** Hop-by-hop headers, `host` and `content-length` are removed, a request
//!   that carries a credential-bearing header is refused, and no UAOS header is added. The only
//!   insertion is the provider credential, placed last, after the runtime's final scan, and
//!   marked sensitive so it is never printed (I-05).
//! * **One send per Operation.** A request bound to another Operation, or a second request for
//!   the same Operation, is refused before any contact (ADR-0010's binding check).
//! * **No contact by default.** Building the door contacts nothing; [`Door::counters`] lets a
//!   test prove zero resolutions and connections (I-14).
//! * **Bounded.** Idle connections per upstream, the replay window, resolution, connect,
//!   handshake and response-header timeouts, addresses tried and request body size are limited
//!   (I-08). Concurrent requests and response bodies are bounded by the runtime
//!   ([`DoorLimits`]).
//!
//! What it does not do: retries (hyper-util's transparent retry is switched off), routing,
//! pricing and redaction belong to the runtime and its stages; the door carries out one
//! authorized, scanned request.

pub mod addr;
mod connect;
mod door;
pub mod host;
pub mod resolve;
pub mod upstream;

pub use connect::{CounterSnapshot, MAX_ADDRESSES_TRIED, Stream};
pub use door::{
    CREDENTIAL_HEADERS, Credential, Door, DoorLimits, EgressRequest, EgressResponse, MAX_IDLE_PER_UPSTREAM,
    PROBE_RECHECK, REPLAY_WINDOW,
};
pub use host::{HostError, HostName};
pub use resolve::{Resolve, SystemResolver};
pub use upstream::{Scheme, Trust, Upstream, UpstreamError, UpstreamId};

use std::time::Duration;

use uaos_contracts::error::{ErrorCode, codes};

/// Egress failure. Every variant maps to a registered code ([`EgressError::code`]); none carries
/// request content, paths or credentials.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EgressError {
    /// Every address the name resolved to was refused.
    #[error("destination refused: it resolved only to {0:?} addresses")]
    Blocked(addr::Blocked),
    /// Resolution, connection or TLS failed.
    #[error("provider unreachable: {0}")]
    Unreachable(&'static str),
    /// No response headers within the limit, or a connect or handshake timed out.
    #[error("provider did not answer in time")]
    Timeout,
    /// The upstream's circuit is open.
    #[error("recent attempts failed; retry after {retry_after:?}")]
    CircuitOpen {
        /// A hint, not a promise: the time left in the cooldown, or, while a probe is in flight,
        /// [`PROBE_RECHECK`].
        retry_after: Duration,
    },
    /// The door's own rules refused the request before any contact.
    #[error("refused by the egress door: {0}")]
    Refused(&'static str),
    /// An upstream declaration is invalid.
    #[error("invalid upstream: {0}")]
    Upstream(UpstreamError),
    /// The TLS configuration could not be built.
    #[error("TLS configuration: {0}")]
    Tls(&'static str),
}

impl EgressError {
    /// The registered error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Blocked(_) => codes::EGRESS_BLOCKED,
            Self::Unreachable(_) => codes::EGRESS_UNREACHABLE,
            Self::Timeout => codes::EGRESS_TIMEOUT,
            Self::CircuitOpen { .. } => codes::EGRESS_CIRCUIT_OPEN,
            Self::Refused(_) => codes::EGRESS_REFUSED,
            Self::Upstream(_) | Self::Tls(_) => codes::CONFIG_INVALID,
        }
    }

    /// Maps a client failure, keeping a connector's own verdict (for example `Blocked`).
    fn from_client(e: &hyper_util::client::legacy::Error) -> Self {
        let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
        while let Some(s) = source {
            if let Some(own) = s.downcast_ref::<Self>() {
                return own.clone();
            }
            source = s.source();
        }
        if e.is_connect() {
            Self::Unreachable("connection failed")
        } else {
            Self::Unreachable("the connection failed before a response arrived")
        }
    }
}
