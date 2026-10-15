// SPDX-License-Identifier: Apache-2.0

//! The kernel side of ADR-0014 in miniature: it owns every edit. Transforms are computed once
//! per chunk value and pinned by a digest that excludes volatile fields (plan v2 §2.3: outputs
//! pinned per chunk digest, so a later turn reproduces exactly the values sent before, whatever
//! formatting the client uses). Every edit is checked against the roles before one splice pass.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hasher};

use crate::roles::{self, RoleMap};
use crate::tape::{self, Kind, Limits, Tape, TapeError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditClass {
    /// Deterministic secret placeholder (allowed in system entries >= 1 and system messages).
    SecretSplice,
    /// Tag removal: newest human turn only.
    TagStrip,
    /// Append-only injection: newest human turn only.
    Append,
    /// Replay of a pinned edit on a history chunk (the same values as when it was newest).
    Pinned,
}

#[derive(Clone, Debug)]
pub struct Edit {
    pub start: usize,
    pub end: usize,
    pub bytes: Vec<u8>,
    pub class: EditClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelError {
    Tape(TapeError),
    Forbidden(&'static str, usize),
    Overlap(usize),
    PinMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Seg {
    Key(String),
    Index(u32),
}

#[derive(Clone, Debug)]
enum Op {
    Replace { path: Vec<Seg>, original: String, replacement: String, class: EditClass },
    Append { path: Vec<Seg>, json: String },
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub detect: bool,
    pub strip_tags: bool,
    pub inject: bool,
    /// Design switch for the counterfactual runs: replay pinned transforms on history chunks.
    pub pin: bool,
    /// Design switch for the counterfactual runs: exclude volatile members from chunk digests.
    pub volatile_aware: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub chunks_new: usize,
    pub chunks_replayed: usize,
    pub edits: usize,
}

pub struct Kernel {
    pins: HashMap<u64, Vec<Op>>,
    cfg: Config,
    pub stats: Stats,
}

const SECRET_PREFIX: &str = "sk-ant-api03-";
const TAGS: [&str; 3] = ["@notal", "@devam", "@oyung"];

impl Kernel {
    pub fn new(cfg: Config) -> Self {
        Self { pins: HashMap::new(), cfg, stats: Stats::default() }
    }

    pub fn process(&mut self, raw: &[u8]) -> Result<Vec<u8>, KernelError> {
        let t = Tape::parse(raw, Limits::default()).map_err(KernelError::Tape)?;
        let roles = roles::messages_roles(&t);
        let mut volatile = vec![false; t.nodes.len()];
        if self.cfg.volatile_aware {
            for &v in &roles.volatile {
                volatile[v] = true;
            }
        }
        let mut in_signed = vec![false; t.nodes.len()];
        for &s in &roles.signed {
            for flag in &mut in_signed[s..t.nodes[s].after as usize] {
                *flag = true;
            }
        }
        let produced: Vec<usize> = roles.provider_produced.clone();

        let mut edits = Vec::new();
        for &chunk in &roles.chunks {
            let digest = value_digest(&t, chunk, &volatile);
            if let Some(ops) = self.pins.get(&digest).filter(|_| self.cfg.pin) {
                self.stats.chunks_replayed += 1;
                for op in ops {
                    edits.push(apply(&t, chunk, op, true)?);
                }
                continue;
            }
            self.stats.chunks_new += 1;
            let mut ops = Vec::new();
            let newest = roles.newest_human_turn == Some(chunk);
            if !produced.contains(&chunk) {
                for s in chunk + 1..t.nodes[chunk].after as usize {
                    if t.nodes[s].kind != Kind::Str || in_signed[s] {
                        continue;
                    }
                    let original = t.str_value(s).unwrap_or_default().into_owned();
                    let mut value = original.clone();
                    let mut class = EditClass::SecretSplice;
                    if self.cfg.detect {
                        value = redact(&value);
                    }
                    if newest && self.cfg.strip_tags && is_human_text(&t, s) {
                        let stripped = strip_tags(&value);
                        if stripped != value {
                            class = EditClass::TagStrip;
                            value = stripped;
                        }
                    }
                    if value != original {
                        ops.push(Op::Replace { path: path_from(&t, chunk, s), original, replacement: value, class });
                    }
                }
            }
            if newest && self.cfg.inject {
                if let Some(content) = t.get(chunk, "content").filter(|&c| t.nodes[c].kind == Kind::Arr) {
                    let note = format!("[uaos note] context pinned for chunk {digest:016x}");
                    let json = format!("{{\"type\":\"text\",\"text\":{}}}", tape::encode(&note));
                    ops.push(Op::Append { path: path_from(&t, chunk, content), json });
                }
            }
            for op in &ops {
                edits.push(apply(&t, chunk, op, false)?);
            }
            self.pins.insert(digest, ops);
        }
        self.stats.edits += edits.len();
        validate(&t, &roles, &mut edits)?;
        Ok(splice(raw, &edits))
    }
}

/// Attempts an arbitrary edit against the roles (used by the negative tests).
pub fn check_edit(raw: &[u8], edit: Edit) -> Result<(), KernelError> {
    let t = Tape::parse(raw, Limits::default()).map_err(KernelError::Tape)?;
    let roles = roles::messages_roles(&t);
    validate(&t, &roles, &mut vec![edit])
}

fn is_human_text(t: &Tape<'_>, s: usize) -> bool {
    // A plain-string `content`, or the `text` of a block whose type is "text".
    let p = t.nodes[s].parent as usize;
    match t.key(s).as_deref() {
        Some("content") => true,
        Some("text") => t.get(p, "type").and_then(|ty| t.str_value(ty)).as_deref() == Some("text"),
        _ => false,
    }
}

fn path_from(t: &Tape<'_>, chunk: usize, mut n: usize) -> Vec<Seg> {
    let mut segs = Vec::new();
    while n != chunk {
        let p = t.nodes[n].parent as usize;
        segs.push(match t.nodes[p].kind {
            Kind::Obj => Seg::Key(t.key(n).unwrap_or_default().into_owned()),
            _ => Seg::Index(t.nodes[n].index),
        });
        n = p;
    }
    segs.reverse();
    segs
}

fn locate(t: &Tape<'_>, chunk: usize, path: &[Seg]) -> Option<usize> {
    let mut n = chunk;
    for seg in path {
        n = match seg {
            Seg::Key(k) => t.get(n, k)?,
            Seg::Index(i) => t.children(n).nth(*i as usize)?,
        };
    }
    Some(n)
}

fn apply(t: &Tape<'_>, chunk: usize, op: &Op, replay: bool) -> Result<Edit, KernelError> {
    match op {
        Op::Replace { path, original, replacement, class } => {
            let n = locate(t, chunk, path).ok_or(KernelError::PinMismatch)?;
            if t.str_value(n).as_deref() != Some(original.as_str()) {
                return Err(KernelError::PinMismatch);
            }
            let (start, end) = t.span(n);
            Ok(Edit {
                start,
                end,
                bytes: tape::encode(replacement).into_bytes(),
                class: if replay { EditClass::Pinned } else { *class },
            })
        }
        Op::Append { path, json } => {
            let n = locate(t, chunk, path).ok_or(KernelError::PinMismatch)?;
            let at = t.nodes[n].end - 1;
            let sep = if t.children(n).next().is_some() { "," } else { "" };
            Ok(Edit {
                start: at,
                end: at,
                bytes: format!("{sep}{json}").into_bytes(),
                class: if replay { EditClass::Pinned } else { EditClass::Append },
            })
        }
    }
}

fn within(e: &Edit, span: (usize, usize)) -> bool {
    e.start >= span.0 && e.end <= span.1 && !(e.start == e.end && (e.start == span.0 || e.start == span.1))
}

fn validate(t: &Tape<'_>, roles: &RoleMap, edits: &mut [Edit]) -> Result<(), KernelError> {
    edits.sort_by_key(|e| (e.start, e.end));
    for w in edits.windows(2) {
        if w[0].end > w[1].start {
            return Err(KernelError::Overlap(w[1].start));
        }
    }
    let spans = |v: &[usize]| v.iter().map(|&n| t.span(n)).collect::<Vec<_>>();
    let signed = spans(&roles.signed);
    let opaque = spans(&roles.opaque);
    let produced = spans(&roles.provider_produced);
    let sys_msgs = spans(&roles.system_messages);
    let newest = roles.newest_human_turn.map(|n| t.span(n));
    for e in edits.iter() {
        if signed.iter().any(|&s| within(e, s)) {
            return Err(KernelError::Forbidden("edit inside a signed block", e.start));
        }
        if opaque.iter().any(|&s| within(e, s)) {
            return Err(KernelError::Forbidden("edit inside an opaque field", e.start));
        }
        if produced.iter().any(|&s| within(e, s)) {
            return Err(KernelError::Forbidden("edit inside provider-produced content", e.start));
        }
        for (idx, &entry) in roles.system_entries.iter().enumerate() {
            if within(e, t.span(entry)) {
                if idx == 0 {
                    return Err(KernelError::Forbidden("edit inside system[0]", e.start));
                }
                if !matches!(e.class, EditClass::SecretSplice | EditClass::Pinned) {
                    return Err(KernelError::Forbidden("non-secret edit inside a system entry", e.start));
                }
            }
        }
        if sys_msgs.iter().any(|&s| within(e, s)) && !matches!(e.class, EditClass::SecretSplice | EditClass::Pinned) {
            return Err(KernelError::Forbidden("non-secret edit inside a system message", e.start));
        }
        if matches!(e.class, EditClass::TagStrip | EditClass::Append) && !newest.is_some_and(|s| within(e, s)) {
            return Err(KernelError::Forbidden("tag strip or append outside the newest human turn", e.start));
        }
    }
    Ok(())
}

fn splice(raw: &[u8], edits: &[Edit]) -> Vec<u8> {
    let extra: usize = edits.iter().map(|e| e.bytes.len()).sum();
    let mut out = Vec::with_capacity(raw.len() + extra);
    let mut at = 0;
    for e in edits {
        out.extend_from_slice(&raw[at..e.start]);
        out.extend_from_slice(&e.bytes);
        at = e.end;
    }
    out.extend_from_slice(&raw[at..]);
    out
}

/// Canonical value digest of a subtree: object members sorted by decoded key, strings decoded,
/// numbers and literals by their text, volatile members skipped.
pub fn value_digest(t: &Tape<'_>, n: usize, volatile: &[bool]) -> u64 {
    let mut h = DefaultHasher::new();
    hash_value(t, n, volatile, &mut h);
    h.finish()
}

fn hash_value(t: &Tape<'_>, n: usize, volatile: &[bool], h: &mut DefaultHasher) {
    let node = &t.nodes[n];
    match node.kind {
        Kind::Obj => {
            h.write_u8(b'{');
            let mut members: Vec<(std::borrow::Cow<'_, str>, usize)> =
                t.children(n).filter(|&c| !volatile[c]).map(|c| (t.key(c).unwrap_or_default(), c)).collect();
            members.sort();
            for (k, c) in members {
                h.write_usize(k.len());
                h.write(k.as_bytes());
                hash_value(t, c, volatile, h);
            }
            h.write_u8(b'}');
        }
        Kind::Arr => {
            h.write_u8(b'[');
            for c in t.children(n) {
                hash_value(t, c, volatile, h);
            }
            h.write_u8(b']');
        }
        Kind::Str => {
            let s = t.str_value(n).unwrap_or_default();
            h.write_u8(b's');
            h.write_usize(s.len());
            h.write(s.as_bytes());
        }
        Kind::Num | Kind::Lit => {
            h.write_u8(if node.kind == Kind::Num { b'n' } else { b'l' });
            h.write(&t.raw[node.start..node.end]);
        }
    }
}

fn redact(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find(SECRET_PREFIX) {
        let body_len = rest[at + SECRET_PREFIX.len()..]
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
            .count();
        let end = at + SECRET_PREFIX.len() + body_len;
        out.push_str(&rest[..at]);
        if body_len >= 20 {
            let mut h = DefaultHasher::new();
            h.write(rest[at..end].as_bytes());
            out.push_str(&format!("[REDACTED:anthropic_api_key:{:016x}]", h.finish()));
        } else {
            out.push_str(&rest[at..end]);
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

fn strip_tags(s: &str) -> String {
    let mut out = s.to_owned();
    for tag in TAGS {
        loop {
            let Some(at) = find_tag(&out, tag) else { break };
            let mut end = at + tag.len();
            if out[end..].starts_with(' ') {
                end += 1;
            }
            out.replace_range(at..end, "");
        }
    }
    out
}

fn find_tag(s: &str, tag: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = s[from..].find(tag) {
        let at = from + rel;
        let before_ok = at == 0 || s[..at].ends_with(' ') || s[..at].ends_with('\n');
        let after = &s[at + tag.len()..];
        let after_ok = after.is_empty() || after.starts_with(' ') || after.starts_with('\n');
        if before_ok && after_ok {
            return Some(at);
        }
        from = at + tag.len();
    }
    None
}
