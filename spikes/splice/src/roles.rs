// SPDX-License-Identifier: Apache-2.0

//! Declarative selectors over the tape (ADR-0014): a codec says *where* things are; it never
//! computes a byte offset and never edits. The kernel resolves selectors to node sets.
//!
//! The selector language is deliberately small. If the Messages dialect needs more than this to
//! describe its roles, ADR-0014's "declarative selectors" claim is in trouble; the spike records
//! exactly what was needed.

use crate::tape::{Kind, Tape};

#[derive(Clone, Copy, Debug)]
pub enum Step {
    /// The object member with this key.
    Key(&'static str),
    /// Every element of an array.
    Each,
    /// Every descendant (any depth) that is an object member with this key.
    Deep(&'static str),
}

#[derive(Clone, Copy, Debug)]
pub enum Pred {
    /// The node is an object whose member `key` is a string in `values`.
    Is(&'static str, &'static [&'static str]),
    /// The node is an object whose member `key` is a string NOT in `values` (absent counts as
    /// "not in").
    IsNot(&'static str, &'static [&'static str]),
    /// The node is an object whose member `key` is either a string, or an array with at least
    /// one element satisfying the inner predicate.
    StrOrAny(&'static str, &'static Pred),
}

#[derive(Clone, Copy, Debug)]
pub struct Selector {
    pub steps: &'static [Step],
    pub filter: &'static [Pred],
    /// Keep only the last match.
    pub last: bool,
}

pub fn resolve(t: &Tape<'_>, sel: &Selector) -> Vec<usize> {
    let mut cur = vec![t.root()];
    for step in sel.steps {
        let mut next = Vec::new();
        for &n in &cur {
            match *step {
                Step::Key(k) => next.extend(t.get(n, k)),
                Step::Each => {
                    if t.nodes[n].kind == Kind::Arr {
                        next.extend(t.children(n));
                    }
                }
                Step::Deep(k) => {
                    let end = t.nodes[n].after as usize;
                    for d in n + 1..end {
                        if t.nodes[t.nodes[d].parent as usize].kind == Kind::Obj && t.key(d).as_deref() == Some(k) {
                            next.push(d);
                        }
                    }
                }
            }
        }
        cur = next;
    }
    cur.retain(|&n| sel.filter.iter().all(|p| holds(t, n, p)));
    if sel.last {
        cur.split_off(cur.len().saturating_sub(1))
    } else {
        cur
    }
}

fn holds(t: &Tape<'_>, n: usize, p: &Pred) -> bool {
    match *p {
        Pred::Is(k, vals) => t.get(n, k).and_then(|c| t.str_value(c)).is_some_and(|v| vals.contains(&v.as_ref())),
        Pred::IsNot(k, vals) => !t.get(n, k).and_then(|c| t.str_value(c)).is_some_and(|v| vals.contains(&v.as_ref())),
        Pred::StrOrAny(k, inner) => match t.get(n, k) {
            Some(c) if t.nodes[c].kind == Kind::Str => true,
            Some(c) if t.nodes[c].kind == Kind::Arr => t.children(c).any(|e| holds(t, e, inner)),
            _ => false,
        },
    }
}

/// The roles of ADR-0014 (with Revision 1's `system_message`), as node sets.
#[derive(Debug, Default)]
pub struct RoleMap {
    pub signed: Vec<usize>,
    pub opaque: Vec<usize>,
    pub volatile: Vec<usize>,
    pub system_entries: Vec<usize>,
    pub system_messages: Vec<usize>,
    pub provider_produced: Vec<usize>,
    pub newest_human_turn: Option<usize>,
    /// Chunk elements: each element of `system`, `tools` and `messages`.
    pub chunks: Vec<usize>,
}

/// The Anthropic Messages dialect, described only with selectors.
pub mod messages {
    use super::{Pred, Selector, Step};

    pub const SIGNED: Selector = Selector {
        steps: &[Step::Key("messages"), Step::Each, Step::Key("content"), Step::Each],
        filter: &[Pred::Is("type", &["thinking", "redacted_thinking"])],
        last: false,
    };
    pub const OPAQUE: [Selector; 2] = [
        Selector { steps: &[Step::Key("metadata")], filter: &[], last: false },
        Selector { steps: &[Step::Key("safeguards")], filter: &[], last: false },
    ];
    pub const VOLATILE: Selector = Selector { steps: &[Step::Deep("cache_control")], filter: &[], last: false };
    pub const SYSTEM_ENTRIES: Selector = Selector { steps: &[Step::Key("system"), Step::Each], filter: &[], last: false };
    pub const SYSTEM_MESSAGES: Selector = Selector {
        steps: &[Step::Key("messages"), Step::Each],
        filter: &[Pred::Is("role", &["system"])],
        last: false,
    };
    pub const PROVIDER_PRODUCED: Selector = Selector {
        steps: &[Step::Key("messages"), Step::Each],
        filter: &[Pred::Is("role", &["assistant"])],
        last: false,
    };
    /// ADR-0014 Revision 1: the last `user` message carrying at least one block that is not a
    /// tool result (a plain string content counts as human text).
    pub const NEWEST_HUMAN_TURN: Selector = Selector {
        steps: &[Step::Key("messages"), Step::Each],
        filter: &[
            Pred::Is("role", &["user"]),
            Pred::StrOrAny("content", &Pred::IsNot("type", &["tool_result"])),
        ],
        last: true,
    };
    pub const CHUNKS: [Selector; 3] = [
        Selector { steps: &[Step::Key("system"), Step::Each], filter: &[], last: false },
        Selector { steps: &[Step::Key("tools"), Step::Each], filter: &[], last: false },
        Selector { steps: &[Step::Key("messages"), Step::Each], filter: &[], last: false },
    ];
}

pub fn messages_roles(t: &Tape<'_>) -> RoleMap {
    use messages as m;
    RoleMap {
        signed: resolve(t, &m::SIGNED),
        opaque: m::OPAQUE.iter().flat_map(|s| resolve(t, s)).collect(),
        volatile: resolve(t, &m::VOLATILE),
        system_entries: resolve(t, &m::SYSTEM_ENTRIES),
        system_messages: resolve(t, &m::SYSTEM_MESSAGES),
        provider_produced: resolve(t, &m::PROVIDER_PRODUCED),
        newest_human_turn: resolve(t, &m::NEWEST_HUMAN_TURN).first().copied(),
        chunks: m::CHUNKS.iter().flat_map(|s| resolve(t, s)).collect(),
    }
}
