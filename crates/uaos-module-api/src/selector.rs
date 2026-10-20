// SPDX-License-Identifier: Apache-2.0

//! Selectors (ADR-0014 Decision 6): the only way a codec or a module names parts of a request.
//! These primitives and no more; growing them needs ADR-0014 amended.
//!
//! A selector resolves to node ids taken from the tape itself, in document order and without
//! repeats, so it can never name anything outside the view.

use std::collections::BTreeSet;

use uaos_json::{Kind, NodeId};

use crate::view::{StructuralView, ViewNode};

/// The most steps a selector may have.
pub const MAX_SELECTOR_STEPS: usize = 16;
/// The deepest a predicate may nest.
pub const MAX_PREDICATE_DEPTH: usize = 4;
/// The longest key a selector names, in bytes.
const MAX_SELECTOR_KEY: usize = 64;

/// A selector that is too long, nests too deep, or names an empty or overlong key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SelectorError {
    /// More than [`MAX_SELECTOR_STEPS`] steps.
    #[error("a selector has at most {MAX_SELECTOR_STEPS} steps")]
    TooLong,
    /// A predicate nested deeper than [`MAX_PREDICATE_DEPTH`].
    #[error("predicates nest at most {MAX_PREDICATE_DEPTH} deep")]
    TooDeep,
    /// An empty key, or one over 64 bytes.
    #[error("a selector key is 1 to 64 bytes")]
    Key,
    /// A key or string in the view that does not decode, which a tape never holds.
    #[error("the view holds content that does not decode")]
    Undecodable,
}

/// A test of one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    /// An object whose member `key` is a string in `values`.
    MemberIn {
        /// The member.
        key: String,
        /// The accepted values.
        values: BTreeSet<String>,
    },
    /// An object whose member `key` is not a string in `values` (absent counts as not in).
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

    fn keys(&self) -> Vec<&str> {
        match self {
            Self::MemberIn { key, .. } | Self::MemberNotIn { key, .. } => vec![key],
            Self::StringOrArrayWith { key, element } => {
                let mut keys = element.keys();
                keys.push(key);
                keys
            }
        }
    }

    fn matches(&self, node: &ViewNode<'_, '_>) -> Result<bool, SelectorError> {
        if node.kind() != Kind::Object {
            return Ok(false);
        }
        let member = |key: &str| node.member(key).map_err(|_| SelectorError::Undecodable);
        let in_values = |member: Option<ViewNode<'_, '_>>, values: &BTreeSet<String>| -> Result<bool, SelectorError> {
            let Some(member) = member else {
                return Ok(false);
            };
            for value in values {
                if member.is_string(value).map_err(|_| SelectorError::Undecodable)? {
                    return Ok(true);
                }
            }
            Ok(false)
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

/// One step of a selector, applied to every node selected so far.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// A bounded path through a request's structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    steps: Vec<Step>,
}

impl Selector {
    /// A selector from its steps.
    ///
    /// # Errors
    /// [`SelectorError`] if it has too many steps, nests too deep or names a bad key.
    pub fn new(steps: Vec<Step>) -> Result<Self, SelectorError> {
        if steps.len() > MAX_SELECTOR_STEPS {
            return Err(SelectorError::TooLong);
        }
        let key_ok = |key: &str| !key.is_empty() && key.len() <= MAX_SELECTOR_KEY;
        for step in &steps {
            match step {
                Step::Key(key) | Step::AnyDepthKey(key) if !key_ok(key) => return Err(SelectorError::Key),
                Step::Where(predicate) => {
                    if predicate.depth() > MAX_PREDICATE_DEPTH {
                        return Err(SelectorError::TooDeep);
                    }
                    if !predicate.keys().into_iter().all(key_ok) {
                        return Err(SelectorError::Key);
                    }
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
                    for node in nodes {
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
