// SPDX-License-Identifier: Apache-2.0

//! `uaos.adapter/1` (contract §7, ADR-0014): a dialect codec describes its endpoints and assigns
//! roles through selectors; the kernel splices. A codec never computes a byte offset.

use std::collections::{BTreeMap, BTreeSet};

use uaos_json::NodeId;

use crate::code::Code;
use crate::selector::{Selector, SelectorError};
use crate::view::StructuralView;

/// A role a part of a request plays (ADR-0014 Decision 2). Roles only restrict edits; they never
/// exempt content from detection or the final scan (Decision 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Role {
    /// Thinking or reasoning blocks, signatures, encrypted reasoning: never edited or rehydrated.
    Signed,
    /// Fields forwarded untouched: never edited.
    Opaque,
    /// Values that change between turns without changing meaning: outside lineage digests.
    Volatile,
    /// The last user message with a block other than a tool result: tags are read and appends
    /// land only here.
    NewestHumanTurn,
    /// Assistant turns and tool inputs: detectors never run; only the inverse rehydration map.
    ProviderProduced,
    /// Entry `n` of the `system` array: never added, removed, reordered or merged; entry 0 never
    /// touched.
    SystemEntry(u16),
    /// A `role: "system"` message inside `messages`.
    SystemMessage,
}

/// The roles a codec assigned, by node. A node's roles govern its whole subtree, so a role check
/// walks the node's ancestors: O(depth).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleMap {
    roles: BTreeMap<NodeId, BTreeSet<Role>>,
}

impl RoleMap {
    /// An empty map.
    #[must_use]
    pub const fn new() -> Self {
        Self { roles: BTreeMap::new() }
    }

    /// Gives `role` to every node `selector` selects in `view`; returns how many it selected.
    ///
    /// # Errors
    /// As [`Selector::resolve`].
    pub fn assign(
        &mut self,
        view: &StructuralView<'_, '_>,
        selector: &Selector,
        role: Role,
    ) -> Result<usize, SelectorError> {
        let ids = selector.resolve(view)?;
        for id in &ids {
            self.roles.entry(*id).or_default().insert(role);
        }
        Ok(ids.len())
    }

    /// The roles given to `id` itself.
    #[must_use]
    pub fn roles_of(&self, id: NodeId) -> BTreeSet<Role> {
        self.roles.get(&id).cloned().unwrap_or_default()
    }

    /// The roles that govern `id`: its own and every ancestor's.
    #[must_use]
    pub fn governing(&self, view: &StructuralView<'_, '_>, id: NodeId) -> BTreeSet<Role> {
        let mut roles = BTreeSet::new();
        let mut node = view.node(id);
        while let Some(n) = node {
            if let Some(own) = self.roles.get(&n.id()) {
                roles.extend(own.iter().copied());
            }
            node = n.parent();
        }
        roles
    }

    /// Every node with a role, in document order.
    pub fn nodes(&self) -> impl Iterator<Item = (NodeId, &BTreeSet<Role>)> {
        self.roles.iter().map(|(id, roles)| (*id, roles))
    }
}

/// An HTTP method a dialect declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Method {
    /// `GET`.
    Get,
    /// `HEAD`.
    Head,
    /// `POST`.
    Post,
    /// `DELETE`.
    Delete,
}

/// A path that does not fit [`PathPattern`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a path pattern starts with `/`, is at most 128 bytes, has no query and may end in `*`")]
pub struct PathError;

/// A path an endpoint matches: exactly, or as a prefix when it ends in `*`. Matching is on the
/// path only, never the query string (D-28).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathPattern(String);

impl PathPattern {
    /// Checks and wraps a pattern.
    ///
    /// # Errors
    /// [`PathError`] unless it starts with `/`, is at most 128 bytes of printable ASCII, has no
    /// `?` or `#`, and holds `*` at most once, at the end.
    pub fn new(pattern: impl Into<String>) -> Result<Self, PathError> {
        let pattern = pattern.into();
        let body = pattern.strip_suffix('*').unwrap_or(&pattern);
        let ok = pattern.starts_with('/')
            && pattern.len() <= 128
            && pattern.bytes().all(|b| b.is_ascii_graphic())
            && !body.contains(['?', '#', '*']);
        if ok { Ok(Self(pattern)) } else { Err(PathError) }
    }

    /// Whether `path` (without its query) matches.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        match self.0.strip_suffix('*') {
            Some(prefix) => path.starts_with(prefix),
            None => path == self.0,
        }
    }

    /// The pattern.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How the kernel treats an endpoint (D-28).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EndpointClass {
    /// The full pipeline: detection, policy, budget, journal, final scan.
    Governed,
    /// No content: forwarded with metadata checks only.
    Metadata,
    /// Refused, with the dialect's own error shape.
    Denied,
}

/// One endpoint a dialect serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointDecl {
    /// Its method.
    pub method: Method,
    /// Its path.
    pub path: PathPattern,
    /// Its class.
    pub class: EndpointClass,
}

/// One server-sent event of a response stream; `data` is one complete JSON document.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SseEvent<'a> {
    /// The `event:` field, if any.
    pub event: Option<&'a str>,
    /// The `data:` field.
    pub data: &'a [u8],
}

impl std::fmt::Debug for SseEvent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SseEvent")
            .field("event", &self.event)
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// What a stream frame is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum FrameKind {
    /// Content.
    Content,
    /// Usage figures.
    Usage,
    /// A keep-alive ping, never held.
    Ping,
    /// An error inside the stream.
    Error,
    /// The end of the stream.
    End,
    /// Anything else, forwarded untouched.
    Other,
}

/// The billing dimensions a response reports (ADR-0016, M2): at most 8, each a declared code and
/// a count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsageReport {
    dims: Vec<(Code, u64)>,
}

impl UsageReport {
    /// An empty report.
    #[must_use]
    pub const fn new() -> Self {
        Self { dims: Vec::new() }
    }

    /// Adds a dimension.
    ///
    /// # Errors
    /// The report, unchanged, once it holds 8 dimensions.
    pub fn dim(mut self, name: Code, count: u64) -> Result<Self, Self> {
        if self.dims.len() >= 8 {
            return Err(self);
        }
        self.dims.push((name, count));
        Ok(self)
    }

    /// Its dimensions.
    #[must_use]
    pub fn dims(&self) -> &[(Code, u64)] {
        &self.dims
    }
}

/// A codec that cannot read a request or a response.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CodecError {
    /// The body does not have the dialect's shape; the request is refused with the dialect's
    /// error, never forwarded unread.
    #[error("the body does not have the dialect's shape")]
    Malformed,
    /// A selector failed.
    #[error(transparent)]
    Selector(#[from] SelectorError),
}

/// A dialect codec (`uaos.adapter/1`): describes, never edits.
pub trait DialectCodec: Send + Sync + 'static {
    /// The endpoints it serves, each with its class.
    fn endpoints(&self) -> &[EndpointDecl];

    /// Assigns roles to a request's parts, through selectors only.
    ///
    /// # Errors
    /// [`CodecError`]: the kernel then refuses the request; with no roles there is no safe splice.
    fn roles(&self, view: &StructuralView<'_, '_>, out: &mut RoleMap) -> Result<(), CodecError>;

    /// Classifies one stream frame.
    fn frame(&self, event: &SseEvent<'_>) -> FrameKind;

    /// The usage a response reports, if it reports any.
    fn usage(&self, view: &StructuralView<'_, '_>) -> Option<UsageReport>;
}
