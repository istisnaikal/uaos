// SPDX-License-Identifier: Apache-2.0

//! Upstreams: the destinations the door may contact, declared in configuration and never
//! derived from request content.

use std::fmt;
use std::net::IpAddr;

use rustls_pki_types::CertificateDer;

use crate::host::HostName;

/// The name routes use for an upstream (for example `anthropic`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UpstreamId(String);

impl UpstreamId {
    /// Wraps a configured name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UpstreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Transport to the upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// TLS. The only scheme allowed toward public addresses.
    Https,
    /// Plain TCP, allowed only for a declared private upstream (a server on this machine or
    /// network that the user chose to trust).
    Http,
}

/// Which certificates the door accepts for an HTTPS upstream.
#[derive(Debug, Clone)]
pub enum Trust {
    /// The operating system's trust store, through its own verifier (revocation included).
    Platform,
    /// Only these roots. For tests and for private upstreams with their own authority.
    Roots(Vec<CertificateDer<'static>>),
}

/// One destination the door may contact.
#[derive(Debug, Clone)]
pub struct Upstream {
    /// The name routes use.
    pub id: UpstreamId,
    /// DNS name: the SNI and certificate name, and what is resolved unless addresses are pinned.
    pub host: HostName,
    /// TCP port.
    pub port: u16,
    /// Transport.
    pub scheme: Scheme,
    /// Addresses to dial instead of resolving `host`. They are classified like resolved ones.
    pub pinned: Vec<IpAddr>,
    /// Permit private and special-purpose addresses. Off by default; it must be declared, and
    /// plain HTTP requires it.
    pub allow_private: bool,
    /// Accepted certificates.
    pub trust: Trust,
}

/// Why an upstream declaration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamError {
    /// Plain HTTP toward an upstream that may resolve to public addresses.
    #[error("plain HTTP is allowed only for an upstream declared private")]
    PlaintextToPublic,
    /// Port 0.
    #[error("port 0 is not a destination")]
    Port,
    /// Two upstreams share an id, or a host and port.
    #[error("two upstreams share an id, or a host and port")]
    Duplicate,
}

impl Upstream {
    /// An HTTPS upstream on port 443, verified against the platform trust store.
    #[must_use]
    pub fn https(id: impl Into<String>, host: HostName) -> Self {
        Self {
            id: UpstreamId::new(id),
            host,
            port: 443,
            scheme: Scheme::Https,
            pinned: Vec::new(),
            allow_private: false,
            trust: Trust::Platform,
        }
    }

    /// Checks the declaration's own rules.
    ///
    /// # Errors
    /// [`UpstreamError`].
    pub fn validate(&self) -> Result<(), UpstreamError> {
        if self.port == 0 {
            return Err(UpstreamError::Port);
        }
        if self.scheme == Scheme::Http && !self.allow_private {
            return Err(UpstreamError::PlaintextToPublic);
        }
        Ok(())
    }
}
