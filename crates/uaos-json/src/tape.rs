// SPDX-License-Identifier: Apache-2.0

//! The parser and the tape (contract §3–§6). One forward pass, no recursion: an explicit stack
//! of open containers, bounded by the depth limit, replaces the call stack. Every value becomes
//! one 24-byte node, appended in pre-order; a container's end and subtree end are filled in when
//! it closes, and an object's keys are checked for duplicates at that moment.

use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;

use crate::decode::{Unescape, hex4, is_high_surrogate, is_low_surrogate, low_surrogate_at};
use crate::error::{ErrorKind, JsonError, Violation};
use crate::node::{Descendants, Kind, Node, NodeId, Span};
use crate::{Limits, to_u32, to_usize};

/// The parent of the root.
pub(crate) const NONE: u32 = u32::MAX;
/// The node is a member of an object; `key_start` and `key_len` hold its key.
pub(crate) const HAS_KEY: u8 = 1;
/// The member key holds an escape.
pub(crate) const KEY_ESCAPED: u8 = 2;
/// The string's content holds an escape.
pub(crate) const STR_ESCAPED: u8 = 4;
const KNOWN_FLAGS: u8 = HAS_KEY | KEY_ESCAPED | STR_ESCAPED;

const BOM: &[u8] = b"\xEF\xBB\xBF";

/// One value on the tape. Private: the layout may change, the invariants may not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RawNode {
    pub(crate) start: u32,
    pub(crate) end: u32,
    pub(crate) parent: u32,
    pub(crate) after: u32,
    pub(crate) key_start: u32,
    pub(crate) key_len: u16,
    pub(crate) kind: Kind,
    pub(crate) flags: u8,
}

const _: () = assert!(
    std::mem::size_of::<RawNode>() == 24 && std::mem::align_of::<RawNode>() == 4,
    "the tape's node is 24 bytes (contract §5)"
);

/// A member key, read before its value.
#[derive(Clone, Copy)]
struct Key {
    start: u32,
    len: u16,
    escaped: bool,
}

impl RawNode {
    fn new(kind: Kind, start: usize, parent: u32, key: Option<Key>, flags: u8) -> Self {
        let (key_start, key_len, key_flags) = key.map_or((0, 0, 0), |key| {
            let escaped = if key.escaped { KEY_ESCAPED } else { 0 };
            (key.start, key.len, HAS_KEY | escaped)
        });
        Self {
            start: to_u32(start),
            end: to_u32(start),
            parent,
            after: 0,
            key_start,
            key_len,
            kind,
            flags: flags | key_flags,
        }
    }
}

/// A parsed document: every value, in pre-order, over the input it borrows.
pub struct Tape<'a> {
    input: &'a str,
    nodes: Vec<RawNode>,
    root: RawNode,
    deepest: u16,
}

/// What a tape holds, for callers to report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TapeStats {
    /// Values on the tape.
    pub nodes: u32,
    /// The most containers open at once.
    pub max_depth: u16,
    /// The input's length in bytes.
    pub input_bytes: u32,
    /// Heap the tape holds, in bytes.
    pub heap_bytes: usize,
}

/// Parses one complete JSON document (contract §4): a single value, optionally surrounded by
/// whitespace.
///
/// # Errors
///
/// The first rule the input breaks, with the byte offset where it breaks. The checks run in
/// order: size, byte-order mark, UTF-8, then structure.
pub fn parse<'a>(raw: &'a [u8], limits: &Limits) -> Result<Tape<'a>, JsonError> {
    if raw.len() > to_usize(limits.max_bytes()) {
        return Err(JsonError::new(ErrorKind::TooLarge, to_usize(limits.max_bytes())));
    }
    reject_bom(raw)?;
    let input = std::str::from_utf8(raw).map_err(|e| JsonError::new(ErrorKind::InvalidUtf8, e.valid_up_to()))?;
    let mut parser = Parser::new(input.as_bytes(), *limits)?;
    parser.run()?;
    Tape::new(input, parser.nodes, parser.deepest)
}

fn reject_bom(raw: &[u8]) -> Result<(), JsonError> {
    if raw.starts_with(BOM) {
        return Err(JsonError::new(ErrorKind::ByteOrderMark, 0));
    }
    Ok(())
}

/// What the parser does next.
enum Step {
    /// A value starts here; inside an object, after this key.
    Value(usize, Option<Key>),
    /// A value ended just before here (or an empty container's closing bracket is here).
    After(usize),
}

struct Parser<'a> {
    bytes: &'a [u8],
    limits: Limits,
    nodes: Vec<RawNode>,
    /// The open containers, innermost last.
    stack: Vec<u32>,
    /// Member indices of the object being closed, reused for every object.
    scratch: Vec<u32>,
    deepest: u16,
}

impl<'a> Parser<'a> {
    fn new(bytes: &'a [u8], limits: Limits) -> Result<Self, JsonError> {
        // About one node per 128 input bytes for real transcripts (12,280 nodes in 1.70 MB),
        // rounded up to a power of two and never above the limit (contract §6).
        let max = to_usize(limits.max_nodes());
        let initial = (bytes.len() / 128 + 1).next_power_of_two().max(16).min(max);
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(initial)
            .map_err(|_| JsonError::new(ErrorKind::OutOfMemory, 0))?;
        Ok(Self {
            bytes,
            limits,
            nodes,
            stack: Vec::with_capacity(usize::from(limits.max_depth())),
            scratch: Vec::new(),
            deepest: 0,
        })
    }

    fn run(&mut self) -> Result<(), JsonError> {
        let start = skip_ws(self.bytes, 0);
        if start == self.bytes.len() {
            return Err(JsonError::new(ErrorKind::Empty, self.bytes.len()));
        }
        let mut step = Step::Value(start, None);
        loop {
            step = match step {
                Step::Value(at, key) => self.value(at, key)?,
                Step::After(at) => match self.after_value(at)? {
                    Some(next) => next,
                    None => return Ok(()),
                },
            };
        }
    }

    /// Records the value starting at `at`.
    fn value(&mut self, at: usize, key: Option<Key>) -> Result<Step, JsonError> {
        let Some(&byte) = self.bytes.get(at) else {
            return Err(JsonError::new(ErrorKind::UnexpectedEnd, at));
        };
        if self.nodes.len() >= to_usize(self.limits.max_nodes()) {
            return Err(JsonError::new(ErrorKind::TooManyNodes, at));
        }
        let parent = self.stack.last().copied().unwrap_or(NONE);
        let (kind, end, flags) = match byte {
            b'{' | b'[' => return self.open(at, byte, parent, key),
            b'"' => {
                let (end, escaped) = scan_string(self.bytes, at)?;
                (Kind::String, end, if escaped { STR_ESCAPED } else { 0 })
            }
            b'-' | b'0'..=b'9' => (Kind::Number, scan_number(self.bytes, at)?, 0),
            b't' => (Kind::True, literal(self.bytes, at, b"true")?, 0),
            b'f' => (Kind::False, literal(self.bytes, at, b"false")?, 0),
            b'n' => (Kind::Null, literal(self.bytes, at, b"null")?, 0),
            _ => return Err(JsonError::new(ErrorKind::ExpectedValue, at)),
        };
        let mut node = RawNode::new(kind, at, parent, key, flags);
        node.end = to_u32(end);
        node.after = to_u32(self.nodes.len() + 1);
        self.push(node, at)?;
        Ok(Step::After(end))
    }

    /// Opens the object or array whose bracket is at `at`.
    fn open(&mut self, at: usize, byte: u8, parent: u32, key: Option<Key>) -> Result<Step, JsonError> {
        if self.stack.len() >= usize::from(self.limits.max_depth()) {
            return Err(JsonError::new(ErrorKind::DepthExceeded, at));
        }
        let (kind, close) = if byte == b'{' {
            (Kind::Object, b'}')
        } else {
            (Kind::Array, b']')
        };
        let id = to_u32(self.nodes.len());
        // `end` and `after` are filled in when the container closes.
        self.push(RawNode::new(kind, at, parent, key, 0), at)?;
        self.stack.push(id);
        let depth = u16::try_from(self.stack.len()).unwrap_or(u16::MAX);
        self.deepest = self.deepest.max(depth);
        let next = skip_ws(self.bytes, at + 1);
        if self.bytes.get(next) == Some(&close) {
            return Ok(Step::After(next));
        }
        if kind == Kind::Object {
            let (key, value_at) = self.read_key(next)?;
            return Ok(Step::Value(value_at, Some(key)));
        }
        Ok(Step::Value(next, None))
    }

    /// After a value: a comma leads to the next one, a closing bracket closes its container.
    /// `None` once the root is complete.
    fn after_value(&mut self, mut at: usize) -> Result<Option<Step>, JsonError> {
        loop {
            let Some(&open) = self.stack.last() else {
                if skip_ws(self.bytes, at) != self.bytes.len() {
                    return Err(JsonError::new(ErrorKind::TrailingData, skip_ws(self.bytes, at)));
                }
                return Ok(None);
            };
            at = skip_ws(self.bytes, at);
            let kind = self.nodes.get(to_usize(open)).map_or(Kind::Array, |node| node.kind);
            let close = if kind == Kind::Object { b'}' } else { b']' };
            match self.bytes.get(at) {
                Some(b',') => {
                    let next = skip_ws(self.bytes, at + 1);
                    if kind == Kind::Object {
                        let (key, value_at) = self.read_key(next)?;
                        return Ok(Some(Step::Value(value_at, Some(key))));
                    }
                    return Ok(Some(Step::Value(next, None)));
                }
                Some(&byte) if byte == close => {
                    self.stack.pop();
                    self.close(open, at)?;
                    at += 1;
                }
                Some(_) => return Err(JsonError::new(ErrorKind::ExpectedCommaOrClose, at)),
                None => return Err(JsonError::new(ErrorKind::UnexpectedEnd, at)),
            }
        }
    }

    /// Closes the container `open` at its closing bracket `at`.
    fn close(&mut self, open: u32, at: usize) -> Result<(), JsonError> {
        let after = to_u32(self.nodes.len());
        let kind = match self.nodes.get_mut(to_usize(open)) {
            Some(node) => {
                node.end = to_u32(at + 1);
                node.after = after;
                node.kind
            }
            None => return Err(JsonError::new(ErrorKind::UnexpectedEnd, at)),
        };
        if kind == Kind::Object {
            self.check_duplicate_keys(open)?;
        }
        Ok(())
    }

    /// Reads a member key and its colon at `at`; returns the key and where its value starts.
    fn read_key(&self, at: usize) -> Result<(Key, usize), JsonError> {
        match self.bytes.get(at) {
            Some(b'"') => {}
            Some(_) => return Err(JsonError::new(ErrorKind::ExpectedKey, at)),
            None => return Err(JsonError::new(ErrorKind::UnexpectedEnd, at)),
        }
        let (end, escaped) = scan_string(self.bytes, at)?;
        let len = u16::try_from(end.saturating_sub(at + 2)).map_err(|_| JsonError::new(ErrorKind::KeyTooLong, at))?;
        let colon = skip_ws(self.bytes, end);
        match self.bytes.get(colon) {
            Some(b':') => {}
            Some(_) => return Err(JsonError::new(ErrorKind::ExpectedColon, colon)),
            None => return Err(JsonError::new(ErrorKind::UnexpectedEnd, colon)),
        }
        let key = Key {
            start: to_u32(at),
            len,
            escaped,
        };
        Ok((key, skip_ws(self.bytes, colon + 1)))
    }

    /// Appends a node, growing the tape by doubling up to the node limit (contract §6).
    fn push(&mut self, node: RawNode, at: usize) -> Result<(), JsonError> {
        if self.nodes.len() == self.nodes.capacity() {
            let max = to_usize(self.limits.max_nodes());
            let target = self.nodes.capacity().saturating_mul(2).max(16).min(max);
            let additional = target.saturating_sub(self.nodes.len()).max(1);
            self.nodes
                .try_reserve_exact(additional)
                .map_err(|_| JsonError::new(ErrorKind::OutOfMemory, at))?;
        }
        self.nodes.push(node);
        Ok(())
    }

    /// Refuses an object whose members share a key once decoded. Sorts the member indices by
    /// key, then compares neighbours: O(m log m), no allocation beyond the reused scratch.
    fn check_duplicate_keys(&mut self, open: u32) -> Result<(), JsonError> {
        let mut members = std::mem::take(&mut self.scratch);
        members.clear();
        let after = self.nodes.get(to_usize(open)).map_or(open, |node| node.after);
        let mut child = open + 1;
        while child < after {
            members.push(child);
            child = self
                .nodes
                .get(to_usize(child))
                .map_or(after, |node| node.after.max(child + 1));
        }
        let found = find_duplicate(self.bytes, &self.nodes, &mut members);
        self.scratch = members;
        found
    }
}

fn find_duplicate(bytes: &[u8], nodes: &[RawNode], members: &mut [u32]) -> Result<(), JsonError> {
    if members.len() < 2 {
        return Ok(());
    }
    let broken = Cell::new(false);
    let order = |x: &u32, y: &u32| match (nodes.get(to_usize(*x)), nodes.get(to_usize(*y))) {
        (Some(a), Some(b)) => compare_keys(bytes, a, b, &broken).then(a.key_start.cmp(&b.key_start)),
        _ => x.cmp(y),
    };
    members.sort_unstable_by(order);
    // Report the duplicate a streaming reader meets first: the earliest second occurrence.
    let mut first_repeat: Option<u32> = None;
    for pair in members.windows(2) {
        if let [x, y] = pair
            && let (Some(a), Some(b)) = (nodes.get(to_usize(*x)), nodes.get(to_usize(*y)))
            && compare_keys(bytes, a, b, &broken) == Ordering::Equal
        {
            let later = a.key_start.max(b.key_start);
            first_repeat = Some(first_repeat.map_or(later, |seen| seen.min(later)));
        }
    }
    if broken.get() {
        let at = members
            .iter()
            .filter_map(|&id| nodes.get(to_usize(id)))
            .map(|node| node.key_start)
            .min()
            .unwrap_or(0);
        return Err(JsonError::new(ErrorKind::InvalidEscape, to_usize(at)));
    }
    match first_repeat {
        Some(at) => Err(JsonError::new(ErrorKind::DuplicateKey, to_usize(at))),
        None => Ok(()),
    }
}

/// Orders two members by their decoded keys. Keys without escapes compare as bytes (their raw
/// bytes are their decoded bytes); an escaped key is streamed through the decoder.
fn compare_keys(bytes: &[u8], a: &RawNode, b: &RawNode, broken: &Cell<bool>) -> Ordering {
    let left = key_content(bytes, a);
    let right = key_content(bytes, b);
    if a.flags & KEY_ESCAPED != 0 || b.flags & KEY_ESCAPED != 0 {
        let mut left_decoded = Unescape::new(left);
        let mut right_decoded = Unescape::new(right);
        let order = left_decoded.by_ref().cmp(right_decoded.by_ref());
        if left_decoded.broken() || right_decoded.broken() {
            broken.set(true);
        }
        return order;
    }
    left.cmp(right)
}

fn key_content<'b>(bytes: &'b [u8], node: &RawNode) -> &'b [u8] {
    let start = to_usize(node.key_start) + 1;
    bytes.get(start..start + usize::from(node.key_len)).unwrap_or_default()
}

fn skip_ws(bytes: &[u8], mut at: usize) -> usize {
    while matches!(bytes.get(at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        at += 1;
    }
    at
}

fn literal(bytes: &[u8], at: usize, text: &[u8]) -> Result<usize, JsonError> {
    if bytes.get(at..at + text.len()) == Some(text) {
        Ok(at + text.len())
    } else {
        Err(JsonError::new(ErrorKind::InvalidLiteral, at))
    }
}

/// Scans the string whose opening quote is at `open`. Returns the offset after its closing
/// quote and whether it holds an escape.
fn scan_string(bytes: &[u8], open: usize) -> Result<(usize, bool), JsonError> {
    let mut at = open + 1;
    let mut escaped = false;
    loop {
        // Jump to the next quote or backslash, then prove the run between holds no raw
        // control byte (one vectorizable pass).
        let rest = bytes.get(at..).unwrap_or_default();
        let next = memchr::memchr2(b'"', b'\\', rest).map_or(bytes.len(), |found| at + found);
        let run = bytes.get(at..next).unwrap_or_default();
        if let Some(found) = run.iter().position(|&byte| byte < 0x20) {
            return Err(JsonError::new(ErrorKind::ControlCharacter, at + found));
        }
        at = next;
        match bytes.get(at) {
            None => return Err(JsonError::new(ErrorKind::UnterminatedString, open)),
            Some(b'"') => return Ok((at + 1, escaped)),
            Some(_) => {
                escaped = true;
                at = scan_escape(bytes, open, at)?;
            }
        }
    }
}

/// Checks the escape whose backslash is at `at`; returns the offset after it.
fn scan_escape(bytes: &[u8], open: usize, at: usize) -> Result<usize, JsonError> {
    match bytes.get(at + 1) {
        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => Ok(at + 2),
        Some(b'u') => {
            let unit = hex4(bytes, at + 2).ok_or(JsonError::new(ErrorKind::InvalidUnicodeEscape, at))?;
            let paired = is_high_surrogate(unit) && low_surrogate_at(bytes, at + 6).is_some();
            if paired {
                return Ok(at + 12);
            }
            let lone = is_high_surrogate(unit) || is_low_surrogate(unit);
            if lone {
                return Err(JsonError::new(ErrorKind::LoneSurrogate, at));
            }
            Ok(at + 6)
        }
        Some(_) => Err(JsonError::new(ErrorKind::InvalidEscape, at)),
        None => Err(JsonError::new(ErrorKind::UnterminatedString, open)),
    }
}

/// Scans the number starting at `start` (RFC 8259 §6, grammar only); returns its end.
fn scan_number(bytes: &[u8], start: usize) -> Result<usize, JsonError> {
    let invalid = || JsonError::new(ErrorKind::InvalidNumber, start);
    let mut j = start;
    if bytes.get(j) == Some(&b'-') {
        j += 1;
    }
    match bytes.get(j) {
        Some(b'0') => j += 1,
        Some(b'1'..=b'9') => j = skip_digits(bytes, j),
        _ => return Err(invalid()),
    }
    // Only a leading zero can be followed by a digit here: `01`.
    if is_digit(bytes.get(j)) {
        return Err(invalid());
    }
    if bytes.get(j) == Some(&b'.') {
        j += 1;
        if !is_digit(bytes.get(j)) {
            return Err(invalid());
        }
        j = skip_digits(bytes, j);
    }
    if matches!(bytes.get(j), Some(b'e' | b'E')) {
        j += 1;
        if matches!(bytes.get(j), Some(b'+' | b'-')) {
            j += 1;
        }
        if !is_digit(bytes.get(j)) {
            return Err(invalid());
        }
        j = skip_digits(bytes, j);
    }
    Ok(j)
}

fn skip_digits(bytes: &[u8], mut at: usize) -> usize {
    while is_digit(bytes.get(at)) {
        at += 1;
    }
    at
}

fn is_digit(byte: Option<&u8>) -> bool {
    byte.is_some_and(u8::is_ascii_digit)
}

impl<'a> Tape<'a> {
    fn new(input: &'a str, nodes: Vec<RawNode>, deepest: u16) -> Result<Self, JsonError> {
        let root = nodes
            .first()
            .copied()
            .ok_or(JsonError::new(ErrorKind::Empty, input.len()))?;
        Ok(Self {
            input,
            nodes,
            root,
            deepest,
        })
    }

    /// The input, validated as UTF-8.
    #[must_use]
    pub const fn input(&self) -> &'a str {
        self.input
    }

    /// The root value.
    #[must_use]
    pub const fn root(&self) -> Node<'_, 'a> {
        Node::new(self, 0, self.root)
    }

    /// The node at `id`.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<Node<'_, 'a>> {
        self.nodes.get(id.index()).map(|raw| Node::new(self, id.get(), *raw))
    }

    /// Every node, in pre-order (the root first).
    #[must_use]
    pub fn nodes(&self) -> Descendants<'_, 'a> {
        Descendants::new(self, 0, to_u32(self.nodes.len()))
    }

    /// Counts and sizes, for callers to report.
    #[must_use]
    pub fn stats(&self) -> TapeStats {
        TapeStats {
            nodes: to_u32(self.nodes.len()),
            max_depth: self.deepest,
            input_bytes: to_u32(self.input.len()),
            heap_bytes: self.nodes.capacity().saturating_mul(std::mem::size_of::<RawNode>()),
        }
    }

    /// The text a span covers; empty if the span lies outside the input.
    pub(crate) fn slice(&self, span: Span) -> &'a str {
        self.input.get(span.range()).unwrap_or_default()
    }

    /// Re-checks every structural invariant of the contract (§5) from scratch. For tests and
    /// fuzzing; a tape [`parse`] returns always passes.
    ///
    /// # Errors
    ///
    /// The first invariant broken, and the node where it breaks.
    pub fn verify(&self) -> Result<(), Violation> {
        let count = self.nodes.len();
        if count == 0 || count > to_usize(Limits::MAX_NODES_CEILING) {
            return Err(Violation::new(0, "node count out of range"));
        }
        if self.root.parent != NONE || self.root.flags & HAS_KEY != 0 {
            return Err(Violation::new(0, "the root has a parent or a key"));
        }
        if to_usize(self.root.after) != count {
            return Err(Violation::new(0, "the root's subtree is not the whole tape"));
        }
        let mut levels: Vec<u16> = Vec::with_capacity(count);
        let mut deepest = 0_u16;
        for (index, node) in self.nodes.iter().enumerate() {
            self.verify_node(index, node)?;
            let level = if index == 0 {
                0
            } else {
                levels
                    .get(to_usize(node.parent))
                    .map_or(0, |parent| parent.saturating_add(1))
            };
            levels.push(level);
            if node.kind.is_container() {
                deepest = deepest.max(level.saturating_add(1));
                self.verify_children(index, node)?;
            }
            if node.kind == Kind::Object {
                self.verify_unique_keys(index)?;
            }
        }
        if deepest != self.deepest {
            return Err(Violation::new(0, "the recorded depth is not the deepest nesting"));
        }
        Ok(())
    }

    /// Invariants 1 and 3 to 6 for one node.
    fn verify_node(&self, index: usize, node: &RawNode) -> Result<(), Violation> {
        let bytes = self.input.as_bytes();
        let fail = |rule| Err(Violation::new(index, rule));
        if node.flags & !KNOWN_FLAGS != 0 {
            return fail("unknown flag bits set");
        }
        if node.start >= node.end || to_usize(node.end) > bytes.len() {
            return fail("span empty or outside the input");
        }
        let after = to_usize(node.after);
        if after <= index || after > self.nodes.len() {
            return fail("subtree end out of range");
        }
        if !node.kind.is_container() && after != index + 1 {
            return fail("a scalar's subtree is not itself");
        }
        if !self.kind_matches_bytes(node) {
            return fail("kind does not match the bytes");
        }
        let content = Span {
            start: node.start.saturating_add(1),
            end: node.end.saturating_sub(1),
        };
        let escaped = node.kind == Kind::String && self.slice(content).contains('\\');
        if (node.flags & STR_ESCAPED != 0) != escaped {
            return fail("string escape flag does not match the content");
        }
        if index == 0 {
            return Ok(());
        }
        let Some(parent) = self.nodes.get(to_usize(node.parent)) else {
            return fail("parent out of range");
        };
        if to_usize(node.parent) >= index || !parent.kind.is_container() {
            return fail("parent is not an earlier container");
        }
        if node.start <= parent.start || node.end >= parent.end || node.after > parent.after {
            return fail("not inside its parent");
        }
        self.verify_key(index, node, parent)
    }

    /// Invariant 5 and the key half of invariant 6.
    fn verify_key(&self, index: usize, node: &RawNode, parent: &RawNode) -> Result<(), Violation> {
        let fail = |rule| Err(Violation::new(index, rule));
        let has_key = node.flags & HAS_KEY != 0;
        if has_key != (parent.kind == Kind::Object) {
            return fail("a member key exactly when the parent is an object");
        }
        if !has_key {
            if node.key_start != 0 || node.key_len != 0 || node.flags & KEY_ESCAPED != 0 {
                return fail("key fields set outside an object");
            }
            return Ok(());
        }
        let quoted = Span {
            start: node.key_start,
            end: node.key_start.saturating_add(u32::from(node.key_len)).saturating_add(2),
        };
        if quoted.start <= parent.start || quoted.end > node.start {
            return fail("key not between its parent's bracket and its value");
        }
        let text = self.slice(quoted);
        let is_quoted = text.len() >= 2 && text.starts_with('"') && text.ends_with('"');
        if !is_quoted {
            return fail("key not quoted");
        }
        let content = Span {
            start: quoted.start.saturating_add(1),
            end: quoted.end.saturating_sub(1),
        };
        if (node.flags & KEY_ESCAPED != 0) != self.slice(content).contains('\\') {
            return fail("key escape flag does not match the key");
        }
        Ok(())
    }

    /// Invariant 4.
    fn kind_matches_bytes(&self, node: &RawNode) -> bool {
        let text = self.slice(Span {
            start: node.start,
            end: node.end,
        });
        let bytes = text.as_bytes();
        let (first, last) = (bytes.first(), bytes.last());
        match node.kind {
            Kind::Object => first == Some(&b'{') && last == Some(&b'}'),
            Kind::Array => first == Some(&b'[') && last == Some(&b']'),
            Kind::String => bytes.len() >= 2 && first == Some(&b'"') && last == Some(&b'"'),
            Kind::Number => matches!(first, Some(b'-' | b'0'..=b'9')) && last.is_some_and(u8::is_ascii_digit),
            Kind::True => text == "true",
            Kind::False => text == "false",
            Kind::Null => text == "null",
        }
    }

    /// Invariants 2 and 3 for a container's children: they chain through `after`, in order,
    /// disjoint, and end exactly at the container's subtree end.
    fn verify_children(&self, index: usize, node: &RawNode) -> Result<(), Violation> {
        let fail = |at: usize, rule| Err(Violation::new(at, rule));
        let mut child = index + 1;
        let mut free_from = node.start.saturating_add(1);
        while child < to_usize(node.after) {
            let Some(raw) = self.nodes.get(child) else {
                return fail(child, "child out of range");
            };
            if to_usize(raw.parent) != index {
                return fail(child, "child's parent is not its container");
            }
            let begins = if raw.flags & HAS_KEY != 0 {
                raw.key_start
            } else {
                raw.start
            };
            if begins < free_from {
                return fail(child, "siblings overlap or are out of order");
            }
            free_from = raw.end;
            let next = to_usize(raw.after);
            if next <= child {
                return fail(child, "subtree end does not move forward");
            }
            child = next;
        }
        if child != to_usize(node.after) {
            return fail(index, "children do not end at the subtree end");
        }
        Ok(())
    }

    /// Invariant 7, independently of the parser's sort: a set of decoded keys.
    fn verify_unique_keys(&self, index: usize) -> Result<(), Violation> {
        let Some(object) = self.node(NodeId::new(to_u32(index))) else {
            return Err(Violation::new(index, "object out of range"));
        };
        let mut seen = BTreeSet::new();
        for member in object.children() {
            let at = member.id().index();
            let key = member
                .key()
                .map_err(|_| Violation::new(at, "a key does not decode"))?
                .ok_or(Violation::new(at, "a member has no key"))?;
            if !seen.insert(key) {
                return Err(Violation::new(at, "duplicate key"));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Tape<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Sizes only: the input may hold secrets.
        f.debug_struct("Tape")
            .field("input_len", &self.input.len())
            .field("nodes", &self.nodes.len())
            .field("max_depth", &self.deepest)
            .finish_non_exhaustive()
    }
}
