// SPDX-License-Identifier: Apache-2.0

//! `uaos.adapter/1` (contract §7, ADR-0014): a dialect codec describes its endpoints and assigns
//! roles through selectors; the kernel splices. A codec never computes a byte offset.

use std::collections::{BTreeMap, BTreeSet};

use uaos_json::NodeId;

use crate::code::Code;
use crate::manifest::HookPoint;
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
    /// The newest turn's `tool_result` block: the only place a `tool.result` strip lands.
    NewestToolResult,
}

impl Role {
    /// Whether an edit may never touch content with this role (ADR-0014 Decision 2): signed,
    /// opaque and provider-produced content, and the system prompt.
    #[must_use]
    pub const fn forbids_edit(self) -> bool {
        matches!(
            self,
            Self::Signed | Self::Opaque | Self::ProviderProduced | Self::SystemEntry(_) | Self::SystemMessage
        )
    }
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

    /// The roles that govern `id`: its own and every ancestor's. `None` if `id` is not in `view`:
    /// the caller then refuses the edit, because an empty set would be the most permissive answer.
    #[must_use]
    pub fn governing(&self, view: &StructuralView<'_, '_>, id: NodeId) -> Option<BTreeSet<Role>> {
        let mut roles = BTreeSet::new();
        let mut node = Some(view.node(id)?);
        while let Some(n) = node {
            if let Some(own) = self.roles.get(&n.id()) {
                roles.extend(own.iter().copied());
            }
            node = n.parent();
        }
        Some(roles)
    }

    /// The roles an edit of `id` touches: those of `id`, of its ancestors and of every node in
    /// its subtree. `None` if `id` is not in `view`. Removing a node removes its subtree, so a
    /// forbidden role anywhere inside it forbids the edit; a walk up through `parent` alone
    /// would miss it.
    #[must_use]
    pub fn touching(&self, view: &StructuralView<'_, '_>, id: NodeId) -> Option<BTreeSet<Role>> {
        let node = view.node(id)?;
        let mut roles = self.governing(view, id)?;
        for (_, inside) in self.roles.range(id..node.subtree_end()) {
            roles.extend(inside.iter().copied());
        }
        Some(roles)
    }

    /// Whether a module's `Strip` may remove `id` at `point`: `id` lies inside the point's anchor
    /// (the newest human turn at `ingress.parsed`, the newest tool result at `tool.result`), and
    /// nothing the removal touches carries a role that forbids edits. False at any other point
    /// and outside the view.
    #[must_use]
    pub fn may_strip(&self, view: &StructuralView<'_, '_>, id: NodeId, point: HookPoint) -> bool {
        let anchor = match point {
            HookPoint::IngressParsed => Role::NewestHumanTurn,
            HookPoint::ToolResult => Role::NewestToolResult,
            _ => return false,
        };
        let inside_anchor = self.governing(view, id).is_some_and(|roles| roles.contains(&anchor));
        inside_anchor
            && self
                .touching(view, id)
                .is_some_and(|roles| !roles.iter().any(|role| role.forbids_edit()))
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
#[error(
    "a path pattern is a canonical path of at most 128 bytes (no query, no percent-encoding, no \
     backslash, no empty or dot segment) that may end in `*`"
)]
pub struct PathError;

/// Whether `path` is canonical: it starts with `/`, is printable ASCII, and has no query or
/// fragment, no percent-encoding, no path parameter (`;`), no backslash, no `.` or `..` segment and no empty segment but
/// a trailing one. A path that is not canonical never matches, so an encoded or dotted spelling
/// can never reach a class meant for another endpoint.
fn canonical(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    let segments: Vec<&str> = rest.split('/').collect();
    let last = segments.len().saturating_sub(1);
    path.bytes().all(|b| b.is_ascii_graphic())
        && !path.contains(['?', '#', '%', ';', '\\'])
        && segments
            .iter()
            .enumerate()
            .all(|(i, segment)| !matches!(*segment, "." | "..") && (!segment.is_empty() || i == last))
}

/// A path an endpoint matches: exactly, or by segments when it ends in `*` (`/v1/models*` matches
/// `/v1/models` and `/v1/models/x`, never `/v1/models-x`). Matching is on the path only, never
/// the query string (D-28), and only on canonical paths.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathPattern(String);

impl PathPattern {
    /// Checks and wraps a pattern.
    ///
    /// # Errors
    /// [`PathError`] unless it is at most 128 bytes, canonical apart from an optional final `*`,
    /// and holds `*` at most once, at the end.
    pub fn new(pattern: impl Into<String>) -> Result<Self, PathError> {
        let pattern = pattern.into();
        let body = pattern.strip_suffix('*').unwrap_or(&pattern);
        let ok = pattern.len() <= 128 && canonical(body) && !body.contains('*');
        if ok { Ok(Self(pattern)) } else { Err(PathError) }
    }

    /// Whether `path` (without its query) matches.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        if !canonical(path) {
            return false;
        }
        match self.0.strip_suffix('*') {
            Some(prefix) => path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || prefix.ends_with('/') || rest.starts_with('/')),
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

impl EndpointClass {
    /// How restrictive the class is: on overlapping patterns the most restrictive wins.
    const fn strictness(self) -> u8 {
        match self {
            Self::Metadata => 0,
            Self::Governed => 1,
            Self::Denied => 2,
        }
    }
}

/// The class of a request to `method` and `path` (without its query), from a dialect's
/// endpoints (D-28). A path that is not canonical, or that no endpoint matches, is
/// [`EndpointClass::Denied`]; where several endpoints match, the most restrictive class wins.
/// No request is ever forwarded with fewer checks than its endpoint's class asks for.
#[must_use]
pub fn classify(endpoints: &[EndpointDecl], method: Method, path: &str) -> EndpointClass {
    if !canonical(path) {
        return EndpointClass::Denied;
    }
    endpoints
        .iter()
        .filter(|e| e.method == method && e.path.matches(path))
        .map(|e| e.class)
        .max_by_key(|class| class.strictness())
        .unwrap_or(EndpointClass::Denied)
}

/// One endpoint a dialect serves. `#[non_exhaustive]`: built with [`EndpointDecl::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EndpointDecl {
    /// Its method.
    pub method: Method,
    /// Its path.
    pub path: PathPattern,
    /// Its class.
    pub class: EndpointClass,
}

impl EndpointDecl {
    /// An endpoint.
    #[must_use]
    pub const fn new(method: Method, path: PathPattern, class: EndpointClass) -> Self {
        Self { method, path, class }
    }
}

/// One server-sent event of a response stream; `data` is one complete JSON document. Built by
/// the host; `#[non_exhaustive]` (contract §9).
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SseEvent<'a> {
    /// The `event:` field, if any.
    pub event: Option<&'a str>,
    /// The `data:` field.
    pub data: &'a [u8],
}

impl<'a> SseEvent<'a> {
    /// An event.
    #[must_use]
    pub const fn new(event: Option<&'a str>, data: &'a [u8]) -> Self {
        Self { event, data }
    }
}

impl std::fmt::Debug for SseEvent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Lengths only: both fields are upstream content.
        f.debug_struct("SseEvent")
            .field("event_len", &self.event.map(str::len))
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
