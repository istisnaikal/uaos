// SPDX-License-Identifier: Apache-2.0

//! The structural view a codec or a module reads (ADR-0014 Decision 2; contract §2 rule 5): the
//! request's tape, with every string value detection flagged read as masked. No raw view exists
//! at RC-1.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt;

use uaos_json::{JsonError, Kind, Node, NodeId, Tape};

/// A read-only view over a parsed request, with the detection overlay.
#[derive(Clone, Copy)]
pub struct StructuralView<'v, 'a> {
    tape: &'v Tape<'a>,
    masked: &'v BTreeSet<NodeId>,
}

impl<'v, 'a> StructuralView<'v, 'a> {
    /// A view over `tape` in which the string nodes in `masked` (those holding a detection
    /// finding) read as [`ViewText::Masked`]. The host builds it.
    #[must_use]
    pub const fn new(tape: &'v Tape<'a>, masked: &'v BTreeSet<NodeId>) -> Self {
        Self { tape, masked }
    }

    /// The root value.
    #[must_use]
    pub const fn root(&self) -> ViewNode<'v, 'a> {
        ViewNode {
            node: self.tape.root(),
            masked: self.masked,
        }
    }

    /// The node at `id`.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<ViewNode<'v, 'a>> {
        self.tape.node(id).map(|node| ViewNode {
            node,
            masked: self.masked,
        })
    }

    /// Whether the string at `id` is masked.
    #[must_use]
    pub fn is_masked(&self, id: NodeId) -> bool {
        self.masked.contains(&id)
    }
}

impl fmt::Debug for StructuralView<'_, '_> {
    // Counts only: the view is content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StructuralView")
            .field("nodes", &self.tape.stats().nodes)
            .field("masked", &self.masked.len())
            .finish()
    }
}

/// A string value as a view shows it.
#[derive(Clone, PartialEq, Eq)]
pub enum ViewText<'a> {
    /// The decoded value.
    Plain(Cow<'a, str>),
    /// A value detection flagged: only the fact that it is masked is visible.
    Masked,
}

impl fmt::Debug for ViewText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(text) => f.debug_struct("Plain").field("len", &text.len()).finish(),
            Self::Masked => f.write_str("Masked"),
        }
    }
}

/// One value in a view.
#[derive(Clone, Copy)]
pub struct ViewNode<'v, 'a> {
    node: Node<'v, 'a>,
    masked: &'v BTreeSet<NodeId>,
}

impl<'v, 'a> ViewNode<'v, 'a> {
    const fn wrap(&self, node: Node<'v, 'a>) -> Self {
        Self {
            node,
            masked: self.masked,
        }
    }

    /// Its id on the tape.
    #[must_use]
    pub const fn id(&self) -> NodeId {
        self.node.id()
    }

    /// Its kind.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.node.kind()
    }

    /// Its parent, if it is not the root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        self.node.parent().map(|n| self.wrap(n))
    }

    /// Its children, in order.
    pub fn children(&self) -> impl Iterator<Item = Self> + use<'v, 'a> {
        let masked = self.masked;
        self.node.children().map(move |node| Self { node, masked })
    }

    /// Every value below it, in pre-order, itself excluded.
    pub fn descendants(&self) -> impl Iterator<Item = Self> + use<'v, 'a> {
        let masked = self.masked;
        self.node.descendants().map(move |node| Self { node, masked })
    }

    /// Its key, if it is an object member. Keys are structure and are not masked.
    ///
    /// # Errors
    /// A key that does not decode, which a tape never holds.
    pub fn key(&self) -> Result<Option<Cow<'a, str>>, JsonError> {
        self.node.key()
    }

    /// Whether its key is `name`.
    ///
    /// # Errors
    /// As [`ViewNode::key`].
    pub fn key_is(&self, name: &str) -> Result<bool, JsonError> {
        self.node.key_is(name)
    }

    /// For an object, its member `name`.
    ///
    /// # Errors
    /// As [`ViewNode::key`].
    pub fn member(&self, name: &str) -> Result<Option<Self>, JsonError> {
        Ok(self.node.member(name)?.map(|n| self.wrap(n)))
    }

    /// For a string, its value, masked if detection flagged it.
    ///
    /// # Errors
    /// Content that does not decode, which a tape never holds.
    pub fn text(&self) -> Result<Option<ViewText<'a>>, JsonError> {
        if self.node.kind() != Kind::String {
            return Ok(None);
        }
        if self.masked.contains(&self.node.id()) {
            return Ok(Some(ViewText::Masked));
        }
        Ok(self.node.str_value()?.map(ViewText::Plain))
    }

    /// For a number, its text.
    #[must_use]
    pub fn number_text(&self) -> Option<&'a str> {
        self.node.number_text()
    }

    /// Whether it is the string `value`, unmasked.
    ///
    /// # Errors
    /// As [`ViewNode::text`].
    pub fn is_string(&self, value: &str) -> Result<bool, JsonError> {
        Ok(matches!(self.text()?, Some(ViewText::Plain(text)) if text == value))
    }
}

impl fmt::Debug for ViewNode<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ViewNode")
            .field("id", &self.node.id().get())
            .field("kind", &self.node.kind())
            .finish()
    }
}
