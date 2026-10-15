// SPDX-License-Identifier: Apache-2.0

//! A synthetic Claude-Code-shaped client and a provider that checks what the real one checks.
//!
//! The client is shaped by the 2026-10-13 capture (CAP-5/6/7): three system blocks with the
//! attribution block first and a 1 h `cache_control` on the second, 29 tools, adaptive thinking,
//! `max_tokens` 128000, a `metadata` and a `safeguards` field, mid-conversation
//! `role: "system"` messages, and a `cache_control` breakpoint that moves to the newest message
//! every turn. Each turn the client re-serializes its WHOLE history in a randomly chosen style
//! (key order, whitespace, escaping), because providers compare values, not bytes.
//!
//! The provider checks value-prefix stability turn over turn, the way the binding check does:
//! `system`, `tools` and every earlier message must have the same values (ignoring
//! `cache_control`) as last turn's outbound request, and its own assistant turns, thinking
//! signatures included, must come back exactly.

use serde_json::{Map, Value, json};

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    pub fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
    pub fn word(&mut self) -> &'static str {
        const W: [&str; 24] = [
            "kernel", "ledger", "journal", "agent", "budget", "policy", "redact", "tape", "splice",
            "turn", "value", "prefix", "stream", "chunk", "pocket", "session", "module", "hook", "door",
            "çalış", "değer", "ışık", "naïve", "日本",
        ];
        W[self.below(W.len() as u64) as usize]
    }
    pub fn sentence(&mut self, words: usize) -> String {
        (0..words).map(|_| self.word()).collect::<Vec<_>>().join(" ")
    }
}

/// A canary secret in the toy detector's format, assembled at run time.
pub fn canary(rng: &mut Rng) -> String {
    let alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let body: String = (0..32).map(|_| alphabet[rng.below(alphabet.len() as u64) as usize] as char).collect();
    format!("{}{}", ["sk-", "ant-", "api03-"].concat(), body)
}

#[derive(Clone, Copy, Debug)]
pub struct Style {
    pub shuffle: bool,
    pub pretty: bool,
    pub escape_slash: bool,
    pub escape_non_ascii: bool,
    pub escape_some_ascii: bool,
}

impl Style {
    pub fn random(rng: &mut Rng) -> Self {
        Self {
            shuffle: rng.chance(50),
            pretty: rng.chance(30),
            escape_slash: rng.chance(20),
            escape_non_ascii: rng.chance(30),
            escape_some_ascii: rng.chance(10),
        }
    }
    pub fn compact() -> Self {
        Self { shuffle: false, pretty: false, escape_slash: false, escape_non_ascii: false, escape_some_ascii: false }
    }
}

pub fn serialize(v: &Value, st: Style, rng: &mut Rng) -> Vec<u8> {
    let mut out = String::new();
    write(v, st, rng, &mut out, 0);
    out.into_bytes()
}

fn unicode_escape(out: &mut String, unit: u32) {
    // Built at run time: "\" + "u" + four hex digits.
    out.push('\\');
    out.push('u');
    out.push_str(&format!("{unit:04x}"));
}

fn write_str(s: &str, st: Style, rng: &mut Rng, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '/' if st.escape_slash => out.push_str("\\/"),
            c if (c as u32) < 0x20 => unicode_escape(out, c as u32),
            c if (c as u32) > 0x7F && st.escape_non_ascii => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    unicode_escape(out, u32::from(*unit));
                }
            }
            c if c.is_ascii_alphanumeric() && st.escape_some_ascii && rng.chance(5) => unicode_escape(out, c as u32),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn newline(st: Style, out: &mut String, depth: usize) {
    if st.pretty {
        out.push('\n');
        for _ in 0..depth {
            out.push_str("  ");
        }
    }
}

fn write(v: &Value, st: Style, rng: &mut Rng, out: &mut String, depth: usize) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_str(s, st, rng, out),
        Value::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(st, out, depth + 1);
                write(e, st, rng, out, depth + 1);
            }
            if !a.is_empty() {
                newline(st, out, depth);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut entries: Vec<(&String, &Value)> = m.iter().collect();
            if st.shuffle {
                for i in (1..entries.len()).rev() {
                    let j = rng.below(i as u64 + 1) as usize;
                    entries.swap(i, j);
                }
            }
            out.push('{');
            for (i, (k, val)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(st, out, depth + 1);
                write_str(k, st, rng, out);
                out.push(':');
                if st.pretty {
                    out.push(' ');
                }
                write(val, st, rng, out, depth + 1);
            }
            if !entries.is_empty() {
                newline(st, out, depth);
            }
            out.push('}');
        }
    }
}

/// Removes every `cache_control` member (volatile: outside the provider's prefix check).
pub fn strip_volatile(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter().filter(|(k, _)| k.as_str() != "cache_control").map(|(k, x)| (k.clone(), strip_volatile(x))).collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(strip_volatile).collect()),
        other => other.clone(),
    }
}

pub struct Client {
    pub system: Value,
    pub tools: Value,
    pub history: Vec<Value>,
    pending_tool_use: Option<String>,
}

impl Client {
    pub fn new(rng: &mut Rng) -> Self {
        let attribution = "x-anthropic-billing-header: cc_version=2.1.296.abc; cc_entrypoint=cli;    ";
        let system = json!([
            {"type": "text", "text": &attribution[..74]},
            {"type": "text", "text": format!("You are Claude Code. {}", rng.sentence(40)), "cache_control": {"type": "ephemeral", "ttl": "1h"}},
            {"type": "text", "text": format!("<env>cwd: /home/dev/projects/demo\nplatform: linux\n{}</env>", rng.sentence(12))},
        ]);
        let tools: Vec<Value> = (0..29)
            .map(|i| {
                json!({
                    "name": format!("Tool{i}"),
                    "description": rng.sentence(45),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": rng.sentence(8)},
                            "limit": {"type": "integer", "minimum": 0, "maximum": 2000},
                            "flags": {"type": "array", "items": {"type": "string"}}
                        },
                        "required": ["path"]
                    }
                })
            })
            .collect();
        Self { system, tools: Value::Array(tools), history: Vec::new(), pending_tool_use: None }
    }

    /// Adds this turn's client content to the history (originals: tags and secrets included).
    pub fn take_turn(&mut self, rng: &mut Rng, big_tool_output: usize) {
        if !self.history.is_empty() && rng.chance(10) {
            let mut text = format!("<system-reminder>{}</system-reminder>", rng.sentence(10));
            if rng.chance(25) {
                text.push_str(&format!(" leaked: {}", canary(rng)));
            }
            self.history.push(json!({"role": "system", "content": text}));
        }
        let mut blocks = Vec::new();
        if let Some(id) = self.pending_tool_use.take() {
            let mut out = rng.sentence(30 + big_tool_output);
            if rng.chance(30) {
                out.push_str(&format!("\nANTHROPIC_API_KEY={}\n", canary(rng)));
            }
            blocks.push(json!({"type": "tool_result", "tool_use_id": id, "content": out}));
            if rng.chance(30) {
                blocks.push(json!({"type": "text", "text": human_text(rng)}));
            }
            self.history.push(json!({"role": "user", "content": blocks}));
        } else if rng.chance(15) {
            self.history.push(json!({"role": "user", "content": human_text(rng)}));
        } else {
            blocks.push(json!({"type": "text", "text": human_text(rng)}));
            self.history.push(json!({"role": "user", "content": blocks}));
        }
    }

    /// The request this turn, with the moving cache breakpoint on the newest message.
    pub fn request(&self) -> Value {
        let mut messages = self.history.clone();
        if let Some(last) = messages.last_mut() {
            match last.get_mut("content") {
                Some(Value::Array(blocks)) => {
                    if let Some(Value::Object(b)) = blocks.last_mut() {
                        b.insert("cache_control".into(), json!({"type": "ephemeral"}));
                    }
                }
                Some(Value::String(_)) | None | Some(_) => {}
            }
        }
        let mut m = Map::new();
        m.insert("model".into(), json!("claude-opus-5-5"));
        m.insert("max_tokens".into(), json!(128000));
        m.insert("thinking".into(), json!({"type": "adaptive"}));
        m.insert("stream".into(), json!(true));
        m.insert("system".into(), self.system.clone());
        m.insert("tools".into(), self.tools.clone());
        m.insert("metadata".into(), json!({"user_id": "user_0123456789abcdef"}));
        m.insert("safeguards".into(), json!({"os": "linux", "terminal": "xterm-256color", "shell": "/bin/bash"}));
        m.insert("messages".into(), Value::Array(messages));
        Value::Object(m)
    }

    pub fn receive(&mut self, assistant: Value) {
        self.pending_tool_use = assistant["content"]
            .as_array()
            .and_then(|c| c.iter().find(|b| b["type"] == "tool_use"))
            .and_then(|b| b["id"].as_str())
            .map(str::to_owned);
        self.history.push(assistant);
    }
}

fn human_text(rng: &mut Rng) -> String {
    let mut t = rng.sentence(12);
    if rng.chance(40) {
        let tag = ["@notal", "@devam", "@oyung"][rng.below(3) as usize];
        t = format!("{tag} {t}");
    }
    if rng.chance(20) {
        t.push_str(&format!(" my key is {} please use it", canary(rng)));
    }
    t
}

pub fn assistant_turn(rng: &mut Rng, turn: usize) -> Value {
    let sig: String = (0..240).map(|_| b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[rng.below(64) as usize] as char).collect();
    let mut content = vec![
        json!({"type": "thinking", "thinking": format!("turn {turn}: {}", rng.sentence(20)), "signature": sig}),
        json!({"type": "text", "text": rng.sentence(15)}),
    ];
    if rng.chance(50) {
        content.push(json!({"type": "tool_use", "id": format!("toolu_{turn:04}_{:08x}", rng.next() as u32), "name": "Tool3", "input": {"path": "/src/main.rs", "limit": 200}}));
    }
    json!({"role": "assistant", "content": content})
}

/// What the provider remembers from the previous turn's outbound request.
pub struct Provider {
    prev: Option<Value>,
    produced: Vec<Value>,
}

impl Provider {
    pub fn new() -> Self {
        Self { prev: None, produced: Vec::new() }
    }

    /// Checks value-prefix stability; returns a description of the first violation.
    pub fn check(&mut self, outbound: &[u8]) -> Result<(), String> {
        let now: Value = serde_json::from_slice(outbound).map_err(|e| format!("outbound is not JSON: {e}"))?;
        if let Some(prev) = &self.prev {
            for field in ["system", "tools"] {
                if strip_volatile(&now[field]) != strip_volatile(&prev[field]) {
                    return Err(format!("`{field}` values changed"));
                }
            }
            let (p, n) = (prev["messages"].as_array(), now["messages"].as_array());
            let (Some(p), Some(n)) = (p, n) else { return Err("messages missing".into()) };
            if n.len() < p.len() {
                return Err("history shrank".into());
            }
            for (i, (a, b)) in p.iter().zip(n.iter()).enumerate() {
                if strip_volatile(a) != strip_volatile(b) {
                    return Err(format!("message {i} changed value between turns"));
                }
            }
        }
        // Every assistant turn the provider produced must come back exactly (thinking included).
        let msgs = now["messages"].as_array().cloned().unwrap_or_default();
        let returned: Vec<&Value> = msgs.iter().filter(|m| m["role"] == "assistant").collect();
        for (i, (mine, back)) in self.produced.iter().zip(returned.iter()).enumerate() {
            if strip_volatile(mine) != strip_volatile(back) {
                return Err(format!("assistant turn {i} came back altered"));
            }
        }
        self.prev = Some(now);
        Ok(())
    }

    pub fn produced(&mut self, assistant: &Value) {
        self.produced.push(assistant.clone());
    }
}

/// True when any decoded string of the document contains the canary prefix.
pub fn leaks_secret(outbound: &[u8]) -> bool {
    fn walk(v: &Value) -> bool {
        match v {
            Value::String(s) => s.contains(&["sk-", "ant-", "api03-"].concat()),
            Value::Array(a) => a.iter().any(walk),
            Value::Object(m) => m.iter().any(|(k, x)| k.contains("sk-ant") || walk(x)),
            _ => false,
        }
    }
    serde_json::from_slice::<Value>(outbound).map(|v| walk(&v)).unwrap_or(true)
}
