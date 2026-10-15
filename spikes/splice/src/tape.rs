// SPDX-License-Identifier: Apache-2.0

//! A structural JSON tape: one pass over the raw bytes, every value recorded as a node with its
//! byte span, its parent, its key (inside objects) and the index of the first node after its
//! subtree. Nothing is copied or decoded unless asked for. Fail-closed: invalid UTF-8, any
//! grammar violation, a lone surrogate escape, a duplicate key (compared after decoding) or a
//! limit breach rejects the whole document.

use std::borrow::Cow;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Obj,
    Arr,
    Str,
    Num,
    Lit,
}

#[derive(Clone, Debug)]
pub struct Node {
    pub kind: Kind,
    /// First byte of the value (bracket, quote, sign or digit, literal).
    pub start: usize,
    /// One past the last byte of the value.
    pub end: usize,
    /// Parent node, `NONE` for the root.
    pub parent: u32,
    /// Raw span of the key string including its quotes, when the parent is an object.
    pub key: Option<(usize, usize)>,
    /// Index of the first node after this subtree (children of `i` are `i+1 .. after`).
    pub after: u32,
    /// Position among its siblings.
    pub index: u32,
}

pub const NONE: u32 = u32::MAX;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_depth: usize,
    pub max_nodes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_depth: 128, max_nodes: 4_000_000 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapeError {
    Utf8,
    Syntax(&'static str, usize),
    Depth,
    TooManyNodes,
    DuplicateKey(usize),
}

pub struct Tape<'a> {
    pub raw: &'a [u8],
    pub nodes: Vec<Node>,
}

struct Frame {
    node: usize,
    is_obj: bool,
    count: u32,
    key_base: usize,
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

fn skip_ws(raw: &[u8], mut i: usize) -> usize {
    while i < raw.len() && is_ws(raw[i]) {
        i += 1;
    }
    i
}

fn hex4(raw: &[u8], i: usize) -> Option<u16> {
    let s = raw.get(i..i + 4)?;
    let mut v: u16 = 0;
    for &c in s {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        v = v * 16 + u16::from(d);
    }
    Some(v)
}

/// `i` is at the opening quote; returns the index after the closing quote.
fn scan_string(raw: &[u8], i: usize) -> Result<usize, TapeError> {
    let mut j = i + 1;
    loop {
        // SIMD jump to the next quote or backslash, then one vectorizable pass proving the run
        // holds no raw control character.
        let next = memchr::memchr2(b'"', b'\\', &raw[j..]).map_or(raw.len(), |p| j + p);
        if let Some(p) = raw[j..next].iter().position(|&b| b < 0x20) {
            return Err(TapeError::Syntax("control character in string", j + p));
        }
        j = next;
        match raw.get(j) {
            None => return Err(TapeError::Syntax("unterminated string", i)),
            Some(b'"') => return Ok(j + 1),
            Some(b'\\') => match raw.get(j + 1) {
                Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => j += 2,
                Some(b'u') => {
                    let cu = hex4(raw, j + 2).ok_or(TapeError::Syntax("bad unicode escape", j))?;
                    j += 6;
                    if (0xD800..0xDC00).contains(&cu) {
                        // A high surrogate must be followed by an escaped low surrogate.
                        let ok = raw.get(j) == Some(&b'\\')
                            && raw.get(j + 1) == Some(&b'u')
                            && hex4(raw, j + 2).is_some_and(|lo| (0xDC00..0xE000).contains(&lo));
                        if !ok {
                            return Err(TapeError::Syntax("lone high surrogate", j));
                        }
                        j += 6;
                    } else if (0xDC00..0xE000).contains(&cu) {
                        return Err(TapeError::Syntax("lone low surrogate", j));
                    }
                }
                _ => return Err(TapeError::Syntax("bad escape", j)),
            },
            Some(_) => return Err(TapeError::Syntax("control character in string", j)),
        }
    }
}

fn scan_number(raw: &[u8], i: usize) -> Result<usize, TapeError> {
    let mut j = i;
    let digit = |k: usize| raw.get(k).is_some_and(u8::is_ascii_digit);
    if raw.get(j) == Some(&b'-') {
        j += 1;
    }
    match raw.get(j) {
        Some(b'0') => j += 1,
        Some(b'1'..=b'9') => {
            while digit(j) {
                j += 1;
            }
        }
        _ => return Err(TapeError::Syntax("bad number", i)),
    }
    if raw.get(j) == Some(&b'.') {
        j += 1;
        if !digit(j) {
            return Err(TapeError::Syntax("bad fraction", i));
        }
        while digit(j) {
            j += 1;
        }
    }
    if matches!(raw.get(j), Some(b'e' | b'E')) {
        j += 1;
        if matches!(raw.get(j), Some(b'+' | b'-')) {
            j += 1;
        }
        if !digit(j) {
            return Err(TapeError::Syntax("bad exponent", i));
        }
        while digit(j) {
            j += 1;
        }
    }
    Ok(j)
}

/// Decodes a raw JSON string span (including quotes). The tape has validated it.
pub fn decode(raw: &[u8], span: (usize, usize)) -> Cow<'_, str> {
    let inner = &raw[span.0 + 1..span.1 - 1];
    if !inner.contains(&b'\\') {
        return Cow::Borrowed(std::str::from_utf8(inner).unwrap_or_default());
    }
    let mut out = String::with_capacity(inner.len());
    let mut i = 0;
    while i < inner.len() {
        let c = inner[i];
        if c != b'\\' {
            let run_end = inner[i..].iter().position(|&b| b == b'\\').map_or(inner.len(), |p| i + p);
            out.push_str(std::str::from_utf8(&inner[i..run_end]).unwrap_or_default());
            i = run_end;
            continue;
        }
        match inner[i + 1] {
            b'"' => out.push('"'),
            b'\\' => out.push('\\'),
            b'/' => out.push('/'),
            b'b' => out.push('\u{8}'),
            b'f' => out.push('\u{c}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            _ => {
                let hi = hex4(inner, i + 2).unwrap_or(0);
                if (0xD800..0xDC00).contains(&hi) {
                    let lo = hex4(inner, i + 8).unwrap_or(0);
                    let cp = 0x10000 + ((u32::from(hi) - 0xD800) << 10) + (u32::from(lo) - 0xDC00);
                    out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                    i += 12;
                } else {
                    out.push(char::from_u32(u32::from(hi)).unwrap_or('\u{fffd}'));
                    i += 6;
                }
                continue;
            }
        }
        i += 2;
    }
    Cow::Owned(out)
}

/// Encodes a string as a JSON string literal (the kernel's one encoder).
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl<'a> Tape<'a> {
    pub fn parse(raw: &'a [u8], limits: Limits) -> Result<Self, TapeError> {
        std::str::from_utf8(raw).map_err(|_| TapeError::Utf8)?;
        let mut nodes: Vec<Node> = Vec::with_capacity(raw.len() / 24 + 16);
        let mut stack: Vec<Frame> = Vec::new();
        let mut keys: Vec<(usize, usize)> = Vec::new();
        let mut pending_key: Option<(usize, usize)> = None;
        let mut i = skip_ws(raw, 0);

        let read_key = |raw: &[u8], i: usize| -> Result<((usize, usize), usize), TapeError> {
            if raw.get(i) != Some(&b'"') {
                return Err(TapeError::Syntax("key expected", i));
            }
            let end = scan_string(raw, i)?;
            let j = skip_ws(raw, end);
            if raw.get(j) != Some(&b':') {
                return Err(TapeError::Syntax("':' expected", j));
            }
            Ok(((i, end), skip_ws(raw, j + 1)))
        };

        loop {
            // ── a value starts at `i` ──
            if nodes.len() >= limits.max_nodes {
                return Err(TapeError::TooManyNodes);
            }
            let (parent, index) = stack.last().map_or((NONE, 0), |f| (f.node as u32, f.count));
            let b = *raw.get(i).ok_or(TapeError::Syntax("value expected", i))?;
            let key = pending_key.take();
            match b {
                b'{' | b'[' => {
                    if stack.len() >= limits.max_depth {
                        return Err(TapeError::Depth);
                    }
                    let is_obj = b == b'{';
                    let node = nodes.len();
                    nodes.push(Node {
                        kind: if is_obj { Kind::Obj } else { Kind::Arr },
                        start: i,
                        end: 0,
                        parent,
                        key,
                        after: 0,
                        index,
                    });
                    stack.push(Frame { node, is_obj, count: 0, key_base: keys.len() });
                    i = skip_ws(raw, i + 1);
                    let close = if is_obj { b'}' } else { b']' };
                    if raw.get(i) == Some(&close) {
                        // Empty container: fall through to the closing logic below.
                    } else {
                        if is_obj {
                            let (k, next) = read_key(raw, i)?;
                            keys.push(k);
                            pending_key = Some(k);
                            i = next;
                        }
                        continue;
                    }
                }
                b'"' => {
                    let end = scan_string(raw, i)?;
                    nodes.push(Node { kind: Kind::Str, start: i, end, parent, key, after: 0, index });
                    i = end;
                }
                b'-' | b'0'..=b'9' => {
                    let end = scan_number(raw, i)?;
                    nodes.push(Node { kind: Kind::Num, start: i, end, parent, key, after: 0, index });
                    i = end;
                }
                b't' | b'f' | b'n' => {
                    let lit: &[u8] = match b {
                        b't' => b"true",
                        b'f' => b"false",
                        _ => b"null",
                    };
                    if raw.get(i..i + lit.len()) != Some(lit) {
                        return Err(TapeError::Syntax("bad literal", i));
                    }
                    let end = i + lit.len();
                    nodes.push(Node { kind: Kind::Lit, start: i, end, parent, key, after: 0, index });
                    i = end;
                }
                _ => return Err(TapeError::Syntax("value expected", i)),
            }
            let count = nodes.len() as u32;
            if let Some(last) = nodes.last_mut()
                && last.kind != Kind::Obj
                && last.kind != Kind::Arr
            {
                last.after = count;
            }

            // ── after a value: commas and closings ──
            loop {
                i = skip_ws(raw, i);
                let Some(frame) = stack.last_mut() else {
                    if i != raw.len() {
                        return Err(TapeError::Syntax("trailing data", i));
                    }
                    return Ok(Tape { raw, nodes });
                };
                let close = if frame.is_obj { b'}' } else { b']' };
                match raw.get(i) {
                    Some(b',') => {
                        frame.count += 1;
                        i = skip_ws(raw, i + 1);
                        if frame.is_obj {
                            let (k, next) = read_key(raw, i)?;
                            keys.push(k);
                            pending_key = Some(k);
                            i = next;
                        }
                        break;
                    }
                    Some(&c) if c == close => {
                        let frame = stack.pop().unwrap_or(Frame { node: 0, is_obj: false, count: 0, key_base: 0 });
                        nodes[frame.node].end = i + 1;
                        nodes[frame.node].after = nodes.len() as u32;
                        if frame.is_obj {
                            check_duplicates(raw, &keys[frame.key_base..])?;
                            keys.truncate(frame.key_base);
                        }
                        i += 1;
                    }
                    _ => return Err(TapeError::Syntax("',' or closing bracket expected", i)),
                }
            }
        }
    }

    pub fn root(&self) -> usize {
        0
    }

    pub fn children(&self, i: usize) -> impl Iterator<Item = usize> + '_ {
        let end = self.nodes[i].after as usize;
        let mut j = i + 1;
        std::iter::from_fn(move || {
            if j >= end {
                return None;
            }
            let here = j;
            j = self.nodes[j].after as usize;
            Some(here)
        })
    }

    pub fn key(&self, i: usize) -> Option<Cow<'a, str>> {
        self.nodes[i].key.map(|k| decode(self.raw, k))
    }

    pub fn get(&self, i: usize, name: &str) -> Option<usize> {
        if self.nodes[i].kind != Kind::Obj {
            return None;
        }
        self.children(i).find(|&c| self.key(c).as_deref() == Some(name))
    }

    pub fn str_value(&self, i: usize) -> Option<Cow<'a, str>> {
        (self.nodes[i].kind == Kind::Str).then(|| decode(self.raw, (self.nodes[i].start, self.nodes[i].end)))
    }

    pub fn span(&self, i: usize) -> (usize, usize) {
        (self.nodes[i].start, self.nodes[i].end)
    }
}

fn check_duplicates(raw: &[u8], keys: &[(usize, usize)]) -> Result<(), TapeError> {
    if keys.len() < 2 {
        return Ok(());
    }
    if keys.len() <= 16 {
        for a in 0..keys.len() {
            for b in a + 1..keys.len() {
                if decode(raw, keys[a]) == decode(raw, keys[b]) {
                    return Err(TapeError::DuplicateKey(keys[b].0));
                }
            }
        }
        return Ok(());
    }
    let mut seen = std::collections::BTreeSet::new();
    for &k in keys {
        if !seen.insert(decode(raw, k)) {
            return Err(TapeError::DuplicateKey(k.0));
        }
    }
    Ok(())
}
