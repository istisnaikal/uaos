// SPDX-License-Identifier: Apache-2.0

//! Selectors (ADR-0014 Decision 6): the only way a codec or a module names parts of a request.
//! These primitives and no more; growing them needs ADR-0014 amended.
//!
//! A selector resolves to node ids taken from the tape itself, in document order and without
//! repeats, so it can never name anything outside the view. Its size is bounded (steps, nesting,
//! keys, the values a predicate lists), and each step visits a node at most once, even when the
//! nodes selected so far are nested inside one another. Resolving therefore costs
//! O(steps × nodes), times a predicate's bounded cost, whatever the document's shape.
//!
//! **Masked content is unknown, never probed.** A masked string equals no value and a masked key
//! is no name, so a predicate's answer is the same whatever the masked text is.

use std::collections::BTreeSet;
use std::fmt;

use uaos_json::{Kind, NodeId};

use crate::view::{StructuralView, ViewNode, ViewText};

/// The most steps a selector may have.
pub const MAX_SELECTOR_STEPS: usize = 16;
/// The deepest a predicate may nest.
pub const MAX_PREDICATE_DEPTH: usize = 4;
/// The most values one predicate may list.
pub const MAX_PREDICATE_VALUES: usize = 32;
/// The longest key or value a selector names, in bytes.
pub const MAX_SELECTOR_TEXT: usize = 256;

/// A selector that is too long, nests too deep, or names an empty or overlong key or value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SelectorError {
    /// More than [`MAX_SELECTOR_STEPS`] steps.
    #[error("a selector has at most {MAX_SELECTOR_STEPS} steps")]
    TooLong,
    /// A predicate nested deeper than [`MAX_PREDICATE_DEPTH`].
    #[error("predicates nest at most {MAX_PREDICATE_DEPTH} deep")]
    TooDeep,
    /// An empty key, or a key or value over [`MAX_SELECTOR_TEXT`] bytes.
    #[error("a selector key is 1 to {MAX_SELECTOR_TEXT} bytes, and a value at most {MAX_SELECTOR_TEXT}")]
    Key,
    /// More than [`MAX_PREDICATE_VALUES`] values in one predicate.
    #[error("a predicate lists at most {MAX_PREDICATE_VALUES} values")]
    TooManyValues,
    /// A key or string in the view that does not decode, which a tape never holds.
    #[error("the view holds content that does not decode")]
    Undecodable,
}

/// A test of one node.
#[derive(Clone, PartialEq, Eq)]
pub enum Predicate {
    /// An object whose member `key` is a string in `values`.
    MemberIn {
        /// The member.
        key: String,
        /// The accepted values.
        values: BTreeSet<String>,
    },
    /// An object whose member `key` is not a string in `values` (absent or masked counts as not
    /// in).
    MemberNotIn {
        /// The member.
        key: String,
        /// The refused values.
        values: BTreeSet<String>,
    },
    /// An object whose member `key` is a string, or an array with an element that matches
    /// `element`.
    StringOrArrayWith {
        /// The member.
        key: String,
        /// The test an element must pass.
        element: Box<Predicate>,
    },
}

impl Predicate {
    fn depth(&self) -> usize {
        match self {
            Self::MemberIn { .. } | Self::MemberNotIn { .. } => 1,
            Self::StringOrArrayWith { element, .. } => 1 + element.depth(),
        }
    }

    /// Checks its keys and values, at every level.
    fn check(&self) -> Result<(), SelectorError> {
        let key_ok = |key: &str| !key.is_empty() && key.len() <= MAX_SELECTOR_TEXT;
        match self {
            Self::MemberIn { key, values } | Self::MemberNotIn { key, values } => {
                if !key_ok(key) || values.iter().any(|v| v.len() > MAX_SELECTOR_TEXT) {
                    return Err(SelectorError::Key);
                }
                if values.len() > MAX_PREDICATE_VALUES {
                    return Err(SelectorError::TooManyValues);
                }
                Ok(())
            }
            Self::StringOrArrayWith { key, element } => {
                if !key_ok(key) {
                    return Err(SelectorError::Key);
                }
                element.check()
            }
        }
    }

    fn matches(&self, node: &ViewNode<'_, '_>) -> Result<bool, SelectorError> {
        if node.kind() != Kind::Object {
            return Ok(false);
        }
        let member = |key: &str| node.member(key).map_err(|_| SelectorError::Undecodable);
        // Decoded once; a masked or non-string member is in no set.
        let in_values = |member: Option<ViewNode<'_, '_>>, values: &BTreeSet<String>| -> Result<bool, SelectorError> {
            let Some(member) = member else {
                return Ok(false);
            };
            match member.text().map_err(|_| SelectorError::Undecodable)? {
                Some(ViewText::Plain(text)) => Ok(values.contains(text.as_ref())),
                Some(ViewText::Masked) | None => Ok(false),
            }
        };
        match self {
            Self::MemberIn { key, values } => in_values(member(key)?, values),
            Self::MemberNotIn { key, values } => Ok(!in_values(member(key)?, values)?),
            Self::StringOrArrayWith { key, element } => match member(key)? {
                Some(m) if m.kind() == Kind::String => Ok(true),
                Some(m) if m.kind() == Kind::Array => {
                    for item in m.children() {
                        if element.matches(&item)? {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                }
                _ => Ok(false),
            },
        }
    }
}

impl fmt::Debug for Predicate {
    // Sizes only: a module may have copied keys and values from content (I-11).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemberIn { key, values } => f
                .debug_struct("MemberIn")
                .field("key_len", &key.len())
                .field("values", &values.len())
                .finish(),
            Self::MemberNotIn { key, values } => f
                .debug_struct("MemberNotIn")
                .field("key_len", &key.len())
                .field("values", &values.len())
                .finish(),
            Self::StringOrArrayWith { key, element } => f
                .debug_struct("StringOrArrayWith")
                .field("key_len", &key.len())
                .field("element", element)
                .finish(),
        }
    }
}

/// One step of a selector, applied to every node selected so far.
#[derive(Clone, PartialEq, Eq)]
pub enum Step {
    /// Each object's member `key`.
    Key(String),
    /// Each container's elements (or members).
    Each,
    /// Keeps the nodes that pass the predicate.
    Where(Predicate),
    /// Every member named `key` anywhere below, at any depth.
    AnyDepthKey(String),
    /// Keeps only the last node selected so far, in document order.
    Last,
}

impl fmt::Debug for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(key) => f.debug_struct("Key").field("len", &key.len()).finish(),
            Self::Each => f.write_str("Each"),
            Self::Where(predicate) => f.debug_tuple("Where").field(predicate).finish(),
            Self::AnyDepthKey(key) => f.debug_struct("AnyDepthKey").field("len", &key.len()).finish(),
            Self::Last => f.write_str("Last"),
        }
    }
}

/// A bounded path through a request's structure.
#[derive(Clone, PartialEq, Eq)]
pub struct Selector {
    steps: Vec<Step>,
}

impl fmt::Debug for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Selector").field("steps", &self.steps).finish()
    }
}

impl Selector {
    /// A selector from its steps.
    ///
    /// # Errors
    /// [`SelectorError`] if it has too many steps, nests too deep, or names a bad key or value,
    /// or too many values.
    pub fn new(steps: Vec<Step>) -> Result<Self, SelectorError> {
        if steps.len() > MAX_SELECTOR_STEPS {
            return Err(SelectorError::TooLong);
        }
        let key_ok = |key: &str| !key.is_empty() && key.len() <= MAX_SELECTOR_TEXT;
        for step in &steps {
            match step {
                Step::Key(key) | Step::AnyDepthKey(key) if !key_ok(key) => return Err(SelectorError::Key),
                Step::Where(predicate) => {
                    if predicate.depth() > MAX_PREDICATE_DEPTH {
                        return Err(SelectorError::TooDeep);
                    }
                    predicate.check()?;
                }
                _ => {}
            }
        }
        Ok(Self { steps })
    }

    /// Its steps.
    #[must_use]
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// The nodes it selects in `view`: ids from the tape itself, in document order, no repeats.
    ///
    /// # Errors
    /// [`SelectorError::Undecodable`] for content that does not decode, which a tape never holds.
    pub fn resolve(&self, view: &StructuralView<'_, '_>) -> Result<Vec<NodeId>, SelectorError> {
        let mut current: BTreeSet<NodeId> = BTreeSet::from([view.root().id()]);
        for step in &self.steps {
            let nodes = current.iter().filter_map(|id| view.node(*id));
            current = match step {
                Step::Key(key) => {
                    let mut next = BTreeSet::new();
                    for node in nodes.filter(|n| n.kind() == Kind::Object) {
                        if let Some(m) = node.member(key).map_err(|_| SelectorError::Undecodable)? {
                            next.insert(m.id());
                        }
                    }
                    next
                }
                Step::Each => nodes
                    .filter(|n| n.kind().is_container())
                    .flat_map(|n| n.children().map(|c| c.id()).collect::<Vec<_>>())
                    .collect(),
                Step::Where(predicate) => {
                    let mut kept = BTreeSet::new();
                    for node in nodes {
                        if predicate.matches(&node)? {
                            kept.insert(node.id());
                        }
                    }
                    kept
                }
                Step::AnyDepthKey(key) => {
                    let mut found = BTreeSet::new();
                    // Nodes come in document order: one inside a subtree already walked adds
                    // nothing, so it is skipped and no node is visited twice.
                    let mut walked_to: Option<NodeId> = None;
                    for node in nodes {
                        if walked_to.is_some_and(|end| node.id() < end) {
                            continue;
                        }
                        walked_to = Some(node.subtree_end());
                        for below in node.descendants() {
                            if below.key_is(key).map_err(|_| SelectorError::Undecodable)? {
                                found.insert(below.id());
                            }
                        }
                    }
                    found
                }
                Step::Last => current.last().copied().into_iter().collect(),
            };
        }
        Ok(current.into_iter().collect())
    }
}
